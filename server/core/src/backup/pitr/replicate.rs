//! Mirroring the archive to the replication regions of its S3 location, repairing the
//! region copies, and reporting how far every region's copy is from the primary's.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use kubidm_proto::backup::{
    PitrManifest, ReplicationConfig, ReplicationRegionConfig, WalSegment, PITR_MANIFEST_KEY,
};
use kubidmd_lib::prelude::duration_from_epoch_now;
use kubidmd_lib::repl::wal::parse_recovery_target_time;

use super::store::PitrStore;
use super::{
    select_segments_to_delete, BaseLocation, PitrArchive, PitrError, PitrLocation, PitrSettings,
    PitrSyncReport,
};
use crate::backup::{S3ClientWrapper, METADATA_SUFFIX};

/// The objects of one S3 location, by prefix-relative key, with their size.
type ObjectSizes = BTreeMap<String, u64>;

/// How many sidecars a deep comparison reads at once.
const DEEP_CHECK_CONCURRENCY: usize = 16;

/// How a region's copies of the segments a manifest names compare with the primary's.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RegionSegments {
    /// Segments whose copy, object and sidecar, matches the primary's.
    pub intact: usize,
    /// Segments whose object or sidecar the region lacks.
    pub missing: Vec<String>,
    /// Segments the region lacks that the primary archived so recently that the next
    /// archive run is still due to copy them, see [`replication_tolerance`].
    pub pending: Vec<String>,
    /// Segments whose copy differs from the primary's, with how.
    pub damaged: Vec<(String, String)>,
    /// Segments the primary itself lacks, or whose sidecar it can not read, with why. They
    /// can be neither compared nor copied: a problem of the primary, not of the region.
    pub unavailable_on_primary: Vec<(String, String)>,
}

impl RegionSegments {
    /// The segments to copy to the region again.
    fn to_copy(&self) -> impl Iterator<Item = &String> {
        self.missing
            .iter()
            .chain(self.pending.iter())
            .chain(self.damaged.iter().map(|(segment_id, _)| segment_id))
    }
}

/// What a deep comparison found for one segment.
enum SidecarCheck {
    Intact,
    Differs(String),
    PrimaryUnreadable(String),
}

/// Compare the region's copies of `segments` with the primary's. A copy is intact when its
/// object and its sidecar exist and the object has the size of the primary's object; with
/// `deep`, the sidecars must also agree on checksum and size, as for backups, which reads
/// both sidecars of every segment, [`DEEP_CHECK_CONCURRENCY`] at a time. Nothing is
/// downloaded: a copy whose bytes were changed without changing their size and sidecar is
/// only caught by a recovery from the region, which checks every segment it reads.
///
/// A segment the primary lacks is reported as such, never as a problem of the region.
async fn compare_segments(
    primary: &S3ClientWrapper,
    primary_objects: &ObjectSizes,
    region: &S3ClientWrapper,
    region_objects: &ObjectSizes,
    segments: &[WalSegment],
    deep: bool,
) -> RegionSegments {
    let mut compared = RegionSegments::default();
    let mut to_check = Vec::new();
    for segment in segments {
        let key = segment.object_key();
        let sidecar = format!("{key}{METADATA_SUFFIX}");
        let Some(primary_size) = primary_objects.get(&key) else {
            compared.unavailable_on_primary.push((
                segment.segment_id.clone(),
                "the primary location does not hold it".to_string(),
            ));
            continue;
        };
        if !primary_objects.contains_key(&sidecar) {
            compared.unavailable_on_primary.push((
                segment.segment_id.clone(),
                format!("the primary location does not hold its {METADATA_SUFFIX}"),
            ));
            continue;
        }
        let Some(region_size) = region_objects.get(&key) else {
            compared.missing.push(segment.segment_id.clone());
            continue;
        };
        if !region_objects.contains_key(&sidecar) {
            compared.missing.push(segment.segment_id.clone());
            continue;
        }
        if primary_size != region_size {
            compared.damaged.push((
                segment.segment_id.clone(),
                format!("holds {region_size} bytes, the primary {primary_size}"),
            ));
            continue;
        }
        if deep {
            to_check.push((segment.segment_id.clone(), key));
        } else {
            compared.intact += 1;
        }
    }

    // Owned items: a stream of futures that borrow their item is not `Send` for every
    // lifetime, which the archive task needs.
    let checked: Vec<(String, SidecarCheck)> = stream::iter(to_check)
        .map(|(segment_id, key)| async move {
            let check = match primary.get_backup_metadata(&key).await {
                Ok(metadata) => {
                    match S3ClientWrapper::replica_differs(region, &key, &metadata).await {
                        Ok(None) => SidecarCheck::Intact,
                        Ok(Some(reason)) => SidecarCheck::Differs(reason),
                        Err(err) => SidecarCheck::Differs(format!("could not be checked: {err}")),
                    }
                }
                Err(err) => SidecarCheck::PrimaryUnreadable(format!(
                    "its sidecar can not be read on the primary: {err}"
                )),
            };
            (segment_id, check)
        })
        .buffer_unordered(DEEP_CHECK_CONCURRENCY)
        .collect()
        .await;
    for (segment_id, check) in checked {
        match check {
            SidecarCheck::Intact => compared.intact += 1,
            SidecarCheck::Differs(reason) => compared.damaged.push((segment_id, reason)),
            SidecarCheck::PrimaryUnreadable(reason) => {
                compared.unavailable_on_primary.push((segment_id, reason))
            }
        }
    }
    // Segment ids sort in CID order.
    compared.damaged.sort();
    compared.unavailable_on_primary.sort();
    compared
}

/// Load the manifest of `store`. A manifest that can not be read or does not match its
/// checksum is reported as damaged rather than failing: it is rewritten from the primary.
async fn load_region_manifest(store: &PitrStore) -> Result<RegionManifestRead, PitrError> {
    match store.load_manifest().await {
        Ok(Some(manifest)) => Ok(RegionManifestRead::Present(manifest)),
        Ok(None) => Ok(RegionManifestRead::Missing),
        Err(PitrError::Manifest(reason)) => Ok(RegionManifestRead::Damaged(reason)),
        Err(err) => Err(err),
    }
}

enum RegionManifestRead {
    Present(PitrManifest),
    Missing,
    Damaged(String),
}

impl PitrArchive {
    /// The store of the replication region `region`, built once and reused by every
    /// synchronisation.
    async fn region_store(&self, region: &ReplicationRegionConfig) -> Result<PitrStore, PitrError> {
        let mut stores = self.region_stores.lock().await;
        if let Some(store) = stores.get(region.name()) {
            return Ok(store.clone());
        }
        let store = PitrStore::S3 {
            client: Box::new(S3ClientWrapper::for_region(region).await?),
        };
        stores.insert(region.name().to_string(), store.clone());
        Ok(store)
    }

    /// Mirror the archive to every region of [`PitrSettings::replication`].
    ///
    /// The segments a region misses are copied from the primary (checked against the
    /// primary's checksum; stored bytes and sidecar unchanged, so encrypted segments stay
    /// encrypted and the region never needs the key). The region's manifest is then the
    /// primary's merged with what only the region still records, so that a region keeps
    /// the history a primary that lost its archive no longer has, and the region applies
    /// the retention rules of the primary to its own copy: base backups it no longer holds
    /// drop out, and segments older than `retention_days` that its oldest base backup does
    /// not need are deleted after the manifest stops naming them.
    ///
    /// Abandoned history and gaps a region records that the primary does not (a recovery
    /// from that region while the primary was unreachable) are merged into the primary
    /// manifest first. A region that fails is logged and retried by the next
    /// synchronisation; it never fails the archiving itself.
    ///
    /// Only the listings are compared here, which the manifest lock this runs under can
    /// afford; [`Self::check_region_copies`] compares the sidecars, without the lock.
    pub(super) async fn replicate(
        &self,
        store: &PitrStore,
        manifest: &mut PitrManifest,
        now: Duration,
        report: &mut PitrSyncReport,
    ) {
        let (Some(replication), PitrStore::S3 { client }) = (self.settings.replication(), store)
        else {
            return;
        };
        let primary_objects = match client.list_object_sizes().await {
            Ok(objects) => objects,
            Err(err) => {
                report.region_errors += replication.regions.len();
                error!(%err, "Unable to list the WAL archive to replicate it; the next synchronisation retries");
                return;
            }
        };
        for region in &replication.regions {
            // Where the region keeps its copies of the base backups, for its retention. When
            // the base backups are in another S3 location without this region, the region's
            // index keeps every base it learnt about, which only delays its retention.
            let region_bases = self
                .settings
                .for_region(region.name())
                .map(|settings| settings.bases)
                .inspect_err(|err| debug!(%err, region = %region.name(), "No base backups to prune the region index with"))
                .ok();
            let target = RegionTarget {
                config: region,
                bases: region_bases.as_ref(),
                now,
                retention: self.settings.wal.retention(),
                primary_objects: &primary_objects,
            };
            let result = match self.region_store(region).await {
                Ok(region_store) => {
                    replicate_to_region(client, store, &region_store, manifest, &target).await
                }
                Err(err) => Err(err),
            };
            match result {
                Ok(copies) => {
                    report.replicated += copies.copied;
                    if copies.failed > 0 {
                        report.region_errors += 1;
                    }
                }
                Err(err) => {
                    report.region_errors += 1;
                    error!(
                        %err,
                        region = %region.name(),
                        bucket = %region.bucket,
                        "Unable to replicate the WAL archive to the region; the next \
                         synchronisation retries"
                    );
                }
            }
        }
    }

    /// Once per `sync_interval_seconds` of the replication: compare the sidecars of every
    /// segment `manifest` names with the copies of every region, and copy the segments a
    /// region holds a differing copy of again. Run without the manifest lock, since it
    /// reads two sidecars per segment and region; it changes no manifest, so the archive
    /// runs, and base backup registration, never wait on it.
    pub(super) async fn check_region_copies(
        &self,
        store: &PitrStore,
        manifest: &PitrManifest,
        now: Duration,
        report: &mut PitrSyncReport,
    ) {
        let (Some(replication), PitrStore::S3 { client }) = (self.settings.replication(), store)
        else {
            return;
        };
        {
            let mut last = self
                .last_deep_check
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let due = last.is_none_or(|last| {
                now >= last + Duration::from_secs(replication.sync_interval_seconds.max(1))
            });
            if !due {
                return;
            }
            *last = Some(now);
        }
        let primary_objects = match client.list_object_sizes().await {
            Ok(objects) => objects,
            Err(err) => {
                report.region_errors += replication.regions.len();
                error!(%err, "Unable to list the WAL archive to check its region copies");
                return;
            }
        };
        for region in &replication.regions {
            let result = async {
                let region_store = self.region_store(region).await?;
                let PitrStore::S3 {
                    client: region_client,
                } = &region_store
                else {
                    return Err(PitrError::Config("region store is not S3".to_string()));
                };
                let region_objects = region_client.list_object_sizes().await?;
                let compared = compare_segments(
                    client,
                    &primary_objects,
                    region_client,
                    &region_objects,
                    &manifest.segments,
                    true,
                )
                .await;
                Ok(copy_segments(client, region_client, region.name(), manifest, &compared).await)
            }
            .await;
            match result {
                Ok(copies) => {
                    report.replicated += copies.copied;
                    if copies.failed > 0 {
                        report.region_errors += 1;
                    }
                }
                Err(err) => {
                    report.region_errors += 1;
                    error!(
                        %err,
                        region = %region.name(),
                        "Unable to check the region's copies of the WAL archive; the next \
                         check retries"
                    );
                }
            }
        }
    }
}

/// What [`copy_segments`] did.
#[derive(Debug, Default)]
struct SegmentCopies {
    copied: usize,
    failed: usize,
}

/// Copy the segments `compared` found missing or differing from the primary to `region`,
/// and log what it found. A copy that fails is logged and does not stop the others; the
/// next run retries it. A segment the primary lacks is never copied.
async fn copy_segments(
    primary: &S3ClientWrapper,
    region: &S3ClientWrapper,
    region_name: &str,
    manifest: &PitrManifest,
    compared: &RegionSegments,
) -> SegmentCopies {
    for (segment_id, reason) in &compared.unavailable_on_primary {
        error!(
            segment = %segment_id,
            %reason,
            "A WAL segment the archive manifest names is not available on the primary \
             location; it can not be replicated, and recovering past it needs a copy from a \
             region that holds it or a new base backup"
        );
    }
    for (segment_id, reason) in &compared.damaged {
        warn!(
            region = %region_name,
            segment = %segment_id,
            %reason,
            "The region's copy of a WAL segment differs from the primary's; copying it again"
        );
    }
    let mut copies = SegmentCopies::default();
    for segment_id in compared.to_copy() {
        let Some(segment) = manifest.segment(segment_id) else {
            continue;
        };
        match primary.copy_backup_to(region, &segment.object_key()).await {
            Ok(()) => copies.copied += 1,
            Err(err) => {
                copies.failed += 1;
                error!(
                    %err,
                    region = %region_name,
                    segment = %segment_id,
                    "Unable to copy a WAL segment to the region; the next synchronisation \
                     retries"
                );
            }
        }
    }
    if copies.copied > 0 {
        info!(region = %region_name, copied = copies.copied, "WAL segments replicated");
    }
    copies
}

/// A replication region the archive is mirrored to.
struct RegionTarget<'a> {
    config: &'a ReplicationRegionConfig,
    /// Where the region holds its copies of the base backups, when known.
    bases: Option<&'a BaseLocation>,
    now: Duration,
    retention: Duration,
    /// The objects of the primary location.
    primary_objects: &'a ObjectSizes,
}

/// Mirror the archive of `primary` (whose manifest is `manifest`) to `target`, see
/// [`PitrArchive::replicate`]. Returns what was copied.
///
/// A segment copy the region misses, or holds a differing copy of, is copied again, and a
/// region manifest that can not be read is written again from the primary's. A copy that
/// fails does not keep the region's manifest from being updated for the others.
async fn replicate_to_region(
    primary: &S3ClientWrapper,
    store: &PitrStore,
    region_store: &PitrStore,
    manifest: &mut PitrManifest,
    target: &RegionTarget<'_>,
) -> Result<SegmentCopies, PitrError> {
    let region_name = target.config.name();
    let PitrStore::S3 { client: region } = region_store else {
        return Err(PitrError::Config("region store is not S3".to_string()));
    };

    let region_manifest = match load_region_manifest(region_store).await? {
        RegionManifestRead::Present(region_manifest) => Some(region_manifest),
        RegionManifestRead::Missing => None,
        RegionManifestRead::Damaged(reason) => {
            warn!(
                region = %region_name,
                %reason,
                "The WAL archive manifest of the region is damaged; it is written again from \
                 the primary's, without what only the region recorded"
            );
            None
        }
    };
    if let Some(region_manifest) = &region_manifest {
        // The same archive: the region lags behind or is ahead by a change of identity.
        if !manifest.knows_server(region_manifest.server_uuid)
            && !region_manifest.knows_server(manifest.server_uuid)
        {
            return Err(PitrError::Manifest(format!(
                "{PITR_MANIFEST_KEY} in region {region_name} ({}) belongs to server {}, this \
                 server is {}; refusing to mix archives",
                region.location(),
                region_manifest.server_uuid,
                manifest.server_uuid
            )));
        }
        // Only markers that still concern the primary's history are kept, as its own
        // synchronisation would prune the others right away.
        let markers_before = (manifest.timeline_breaks.clone(), manifest.gaps.clone());
        manifest.merge_markers(region_manifest);
        manifest.prune_timeline_breaks();
        manifest.prune_gaps();
        if (&manifest.timeline_breaks, &manifest.gaps) != (&markers_before.0, &markers_before.1) {
            info!(
                region = %region_name,
                "Abandoned history or gaps recorded in the region merged into the WAL archive"
            );
            store.save_manifest(manifest, target.now).await?;
        }
    }

    // Segments first, so that the region's manifest never names a segment it lacks. A
    // copy that is missing or differs from the primary's is copied (again).
    let region_objects = region.list_object_sizes().await?;
    let compared = compare_segments(
        primary,
        target.primary_objects,
        region,
        &region_objects,
        &manifest.segments,
        false,
    )
    .await;
    let copies = copy_segments(primary, region, region_name, manifest, &compared).await;

    // The region's view: the primary's manifest plus what only the region still records,
    // with the primary's retention rules applied to the region's own copies.
    let mut mirrored = manifest.clone();
    if let Some(region_manifest) = &region_manifest {
        mirrored.merge_from(region_manifest);
    }
    if let Some(bases) = target.bases {
        match bases.list_keys().await {
            Ok(held) => mirrored.retain_base_backups(&held),
            Err(err) => warn!(
                %err,
                region = %region_name,
                "Unable to list the base backups of the region; its index keeps them for now"
            ),
        }
    }
    // A segment the primary still lists stays, or the next run would copy it again.
    let expired: Vec<WalSegment> =
        select_segments_to_delete(&mirrored, target.now, target.retention)
            .into_iter()
            .filter(|id| !manifest.has_segment(id))
            .filter_map(|id| mirrored.segment(&id).cloned())
            .collect();
    for segment in &expired {
        mirrored.remove_segment(&segment.segment_id);
    }
    mirrored.prune_timeline_breaks();
    mirrored.prune_gaps();

    let up_to_date = region_manifest.is_some_and(|mut region_manifest| {
        region_manifest.updated_at.clone_from(&mirrored.updated_at);
        region_manifest == mirrored
    });
    if !up_to_date {
        region_store
            .save_manifest(&mut mirrored, target.now)
            .await?;
    }

    for segment in &expired {
        match region.delete_backup(&segment.object_key()).await {
            Ok(()) => info!(
                region = %region_name,
                segment = %segment.segment_id,
                "Expired WAL segment deleted from the region"
            ),
            Err(err) => warn!(
                %err,
                region = %region_name,
                segment = %segment.segment_id,
                "Unable to delete an expired WAL segment from the region"
            ),
        }
    }

    Ok(copies)
}

/// How far a region's copy of the archive may lag behind the primary's and still count as
/// healthy: the replication's `sync_interval_seconds` plus two segment intervals. An
/// archive run copies what a region misses every `segment_interval_seconds`, and a segment
/// is archived at most two segment intervals after its last record, so a segment that
/// ended less than this ago may simply not have reached the region yet.
pub fn replication_tolerance(replication: &ReplicationConfig, settings: &PitrSettings) -> Duration {
    Duration::from_secs(replication.sync_interval_seconds) + 2 * settings.wal.segment_interval()
}

/// The state of a region's copy of the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionManifestState {
    /// The region holds no manifest.
    Missing,
    /// The region's manifest can not be read, or does not match its checksum.
    Damaged(String),
    /// The region's manifest, updated at `updated_at`, misses `segments` segments or
    /// `markers` gaps or abandoned histories of the primary's.
    Behind {
        updated_at: String,
        segments: usize,
        markers: usize,
    },
    /// The region's manifest, updated at `updated_at`, misses only what the primary
    /// archived within the [`replication_tolerance`]: `segments` segments and `markers`
    /// gaps or abandoned histories, which the next archive run is due to copy.
    Pending {
        updated_at: String,
        segments: usize,
        markers: usize,
    },
    /// The region's manifest, updated at `updated_at`, records everything the primary's
    /// does.
    Current { updated_at: String },
}

/// How a replication region's copy of the WAL archive compares with the primary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalRegionHealth {
    /// The name of the region.
    pub region: String,
    pub bucket: String,
    pub manifest: RegionManifestState,
    pub segments: RegionSegments,
    /// How much older the newest segment the region's manifest names is than the
    /// primary's newest: what a recovery from the region can not reach. None when the
    /// region has no readable manifest.
    pub lag: Option<Duration>,
    /// Why the region could not be checked.
    pub error: Option<String>,
}

impl WalRegionHealth {
    /// Whether the region holds a manifest and an intact copy of every segment, up to
    /// what the primary archived within the [`replication_tolerance`].
    pub fn is_healthy(&self) -> bool {
        self.error.is_none()
            && matches!(
                self.manifest,
                RegionManifestState::Current { .. } | RegionManifestState::Pending { .. }
            )
            && self.segments.missing.is_empty()
            && self.segments.damaged.is_empty()
    }
}

/// The replication health of the WAL archive: the primary's manifest and every region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalReplicationHealth {
    /// The primary location of the archive.
    pub location: String,
    /// Whether the primary holds a manifest. Without one nothing was archived yet, which
    /// is healthy: there is nothing to replicate.
    pub archived: bool,
    /// When the primary's manifest was last updated.
    pub updated_at: String,
    /// The segments the primary's manifest names.
    pub segments: usize,
    /// Segments the primary's manifest names that the primary itself lacks or can not
    /// read, with why. No region can be given them; they are a problem of the primary.
    pub unavailable_on_primary: Vec<(String, String)>,
    /// Whether the sidecars were compared too (`--deep`).
    pub deep: bool,
    /// The lag a region may have and still be healthy, see [`replication_tolerance`].
    pub tolerance: Duration,
    pub regions: Vec<WalRegionHealth>,
}

impl WalReplicationHealth {
    pub fn is_healthy(&self) -> bool {
        self.unavailable_on_primary.is_empty()
            && self.regions.iter().all(WalRegionHealth::is_healthy)
    }
}

/// The replication health of the archive at `settings` at `now`, as `replicate-status`
/// reports it: for every region of [`PitrSettings::replication`], whether it holds a
/// current manifest, which segments it misses or holds a differing copy of, and how far
/// its manifest lags behind. What the primary archived within the
/// [`replication_tolerance`] and a region does not hold yet is pending, not missing. The
/// listings are compared, which takes a few requests per region; with `deep`, the
/// sidecars of every segment as well, as for backups, two reads per segment and region.
/// Nothing is copied. None when the archive is not replicated. Fails only when the
/// primary archive can not be read.
pub async fn check_wal_replication(
    settings: &PitrSettings,
    deep: bool,
    now: Duration,
) -> Result<Option<WalReplicationHealth>, PitrError> {
    let (Some(replication), PitrLocation::S3(_)) = (settings.replication(), &settings.location)
    else {
        return Ok(None);
    };
    let store = PitrStore::open(&settings.location).await?;
    let PitrStore::S3 { client: primary } = &store else {
        return Ok(None);
    };
    let tolerance = replication_tolerance(replication, settings);
    let mut health = WalReplicationHealth {
        location: settings.location.to_string(),
        archived: false,
        updated_at: String::new(),
        segments: 0,
        unavailable_on_primary: Vec::new(),
        deep,
        tolerance,
        regions: Vec::new(),
    };
    let Some(manifest) = store.load_manifest().await? else {
        return Ok(Some(health));
    };
    health.archived = true;
    health.updated_at.clone_from(&manifest.updated_at);
    health.segments = manifest.segments.len();
    let primary_objects = primary.list_object_sizes().await?;

    let mut unavailable = BTreeMap::new();
    for region in &replication.regions {
        let mut region_health = WalRegionHealth {
            region: region.name().to_string(),
            bucket: region.bucket.clone(),
            manifest: RegionManifestState::Missing,
            segments: RegionSegments::default(),
            lag: None,
            error: None,
        };
        let target = RegionCheck {
            primary,
            primary_objects: &primary_objects,
            manifest: &manifest,
            deep,
            now,
            tolerance,
        };
        if let Err(err) = check_region(&target, region, &mut region_health).await {
            region_health.error = Some(err.to_string());
        }
        unavailable.extend(
            region_health
                .segments
                .unavailable_on_primary
                .iter()
                .cloned(),
        );
        health.regions.push(region_health);
    }
    health.unavailable_on_primary = unavailable.into_iter().collect();
    Ok(Some(health))
}

/// What [`check_region`] compares a region with.
struct RegionCheck<'a> {
    primary: &'a S3ClientWrapper,
    primary_objects: &'a ObjectSizes,
    manifest: &'a PitrManifest,
    deep: bool,
    now: Duration,
    tolerance: Duration,
}

impl RegionCheck<'_> {
    /// Whether the region may simply not have received the segment `segment_id` yet.
    fn is_recent(&self, segment_id: &str) -> bool {
        self.manifest
            .segment(segment_id)
            .is_some_and(|segment| self.now.saturating_sub(segment.end_ts) <= self.tolerance)
    }

    /// Whether the primary's manifest changed within the tolerance.
    fn manifest_is_recent(&self) -> bool {
        parse_recovery_target_time(&self.manifest.updated_at)
            .is_ok_and(|updated| self.now.saturating_sub(updated) <= self.tolerance)
    }
}

/// Fill in `health` for `region`. Fails when the region can not be reached or listed.
async fn check_region(
    target: &RegionCheck<'_>,
    region: &ReplicationRegionConfig,
    health: &mut WalRegionHealth,
) -> Result<(), PitrError> {
    let manifest = target.manifest;
    let client = S3ClientWrapper::for_region(region).await?;
    let region_objects = client.list_object_sizes().await?;
    health.segments = compare_segments(
        target.primary,
        target.primary_objects,
        &client,
        &region_objects,
        &manifest.segments,
        target.deep,
    )
    .await;
    let store = PitrStore::S3 {
        client: Box::new(client),
    };
    let region_manifest = load_region_manifest(&store).await?;
    // A copy the region lacks is pending when the primary archived it so recently that
    // the region may not have been given it yet: never when the region's manifest already
    // names it.
    let (pending, missing) = std::mem::take(&mut health.segments.missing)
        .into_iter()
        .partition(|segment_id| {
            target.is_recent(segment_id)
                && !matches!(&region_manifest, RegionManifestRead::Present(region) if region.has_segment(segment_id))
        });
    health.segments.pending = pending;
    health.segments.missing = missing;
    health.manifest = match region_manifest {
        RegionManifestRead::Missing => RegionManifestState::Missing,
        RegionManifestRead::Damaged(reason) => RegionManifestState::Damaged(reason),
        RegionManifestRead::Present(region_manifest) => {
            let newest = |manifest: &PitrManifest| {
                manifest.segments.iter().map(|segment| segment.end_ts).max()
            };
            health.lag = Some(match (newest(manifest), newest(&region_manifest)) {
                (Some(primary), Some(region)) => primary.saturating_sub(region),
                (Some(primary), None) => primary,
                (None, _) => Duration::ZERO,
            });
            let unrecorded: Vec<&WalSegment> = manifest
                .segments
                .iter()
                .filter(|segment| !region_manifest.has_segment(&segment.segment_id))
                .collect();
            let markers = manifest
                .timeline_breaks
                .iter()
                .filter(|known| !region_manifest.timeline_breaks.contains(known))
                .count()
                + manifest
                    .gaps
                    .iter()
                    .filter(|gap| {
                        !region_manifest.gaps.iter().any(|known| {
                            known.from_ts == gap.from_ts && known.until_ts == gap.until_ts
                        })
                    })
                    .count();
            let updated_at = region_manifest.updated_at.clone();
            let segments = unrecorded.len();
            let recent = unrecorded
                .iter()
                .all(|segment| target.is_recent(&segment.segment_id))
                && (markers == 0 || target.manifest_is_recent());
            if segments == 0 && markers == 0 {
                RegionManifestState::Current { updated_at }
            } else if recent {
                RegionManifestState::Pending {
                    updated_at,
                    segments,
                    markers,
                }
            } else {
                RegionManifestState::Behind {
                    updated_at,
                    segments,
                    markers,
                }
            }
        }
    };
    Ok(())
}

/// The text `replicate-status` prints for the WAL archive. `detailed` names every missing
/// or differing segment.
pub fn format_wal_replication_report(health: &WalReplicationHealth, detailed: bool) -> String {
    let mut out = String::new();
    let healthy = health
        .regions
        .iter()
        .filter(|region| region.is_healthy())
        .count();
    let status = if health.is_healthy() {
        "Completed"
    } else {
        "Degraded"
    };
    // Writing to a String can not fail; the results are ignored on purpose.
    let _ = writeln!(out, "WAL archive replication: {status}");
    let _ = writeln!(out, "  Primary: {}", health.location);
    if !health.archived {
        let _ = writeln!(
            out,
            "  Manifest: not yet archived (no {PITR_MANIFEST_KEY}); nothing to replicate"
        );
        return out;
    }
    let _ = writeln!(
        out,
        "  Manifest: updated {}, {} segments",
        if health.updated_at.is_empty() {
            "-"
        } else {
            &health.updated_at
        },
        health.segments
    );
    if !health.unavailable_on_primary.is_empty() {
        let _ = writeln!(
            out,
            "  {} segments the manifest names are not available on the primary; no region can \
             be given them",
            health.unavailable_on_primary.len()
        );
        if detailed {
            for (segment_id, reason) in &health.unavailable_on_primary {
                let _ = writeln!(out, "    {segment_id}: {reason}");
            }
        }
    }
    let _ = writeln!(
        out,
        "  Compared: {}; lag tolerated: {}s",
        if health.deep {
            "listings and sidecars"
        } else {
            "listings (--deep compares the sidecars too)"
        },
        health.tolerance.as_secs()
    );
    let _ = writeln!(
        out,
        "  Regions: {healthy} healthy, {} unhealthy",
        health.regions.len() - healthy
    );
    if health.regions.is_empty() {
        return out;
    }

    let manifest_state = |region: &WalRegionHealth| -> &'static str {
        match (&region.error, &region.manifest) {
            (Some(_), _) => "unreachable",
            (None, RegionManifestState::Missing) => "missing",
            (None, RegionManifestState::Damaged(_)) => "damaged",
            (None, RegionManifestState::Behind { .. }) => "behind",
            (None, RegionManifestState::Pending { .. }) => "pending",
            (None, RegionManifestState::Current { .. }) => "current",
        }
    };
    let lag = |region: &WalRegionHealth| -> String {
        region
            .lag
            .map(|lag| format!("{}s", lag.as_secs()))
            .unwrap_or_else(|| "-".to_string())
    };
    let intact = |region: &WalRegionHealth| -> String {
        format!("{}/{}", region.segments.intact, health.segments)
    };
    let width = |header: &str, values: &mut dyn Iterator<Item = usize>| -> usize {
        values.max().unwrap_or(0).max(header.len())
    };
    let region_width = width("REGION", &mut health.regions.iter().map(|r| r.region.len()));
    let bucket_width = width("BUCKET", &mut health.regions.iter().map(|r| r.bucket.len()));
    let manifest_width = width(
        "MANIFEST",
        &mut health.regions.iter().map(|r| manifest_state(r).len()),
    );
    let intact_width = width(
        "SEGMENTS",
        &mut health.regions.iter().map(|r| intact(r).len()),
    );

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  {:<region_width$}  {:<bucket_width$}  {:<manifest_width$}  {:>intact_width$}  {:>7}  {:>7}  LAG",
        "REGION", "BUCKET", "MANIFEST", "SEGMENTS", "MISSING", "DAMAGED"
    );
    for region in &health.regions {
        let _ = writeln!(
            out,
            "  {:<region_width$}  {:<bucket_width$}  {:<manifest_width$}  {:>intact_width$}  {:>7}  {:>7}  {}",
            region.region,
            region.bucket,
            manifest_state(region),
            intact(region),
            region.segments.missing.len(),
            region.segments.damaged.len(),
            lag(region)
        );
        if let Some(error) = &region.error {
            let _ = writeln!(out, "    Failed: {error}");
            continue;
        }
        match &region.manifest {
            RegionManifestState::Missing => {
                let _ = writeln!(out, "    The region holds no {PITR_MANIFEST_KEY}");
            }
            RegionManifestState::Damaged(reason) => {
                let _ = writeln!(out, "    The region's manifest is damaged: {reason}");
            }
            RegionManifestState::Behind {
                updated_at,
                segments,
                markers,
            } => {
                let _ = writeln!(
                    out,
                    "    {PITR_MANIFEST_KEY} (updated {updated_at}) misses {segments} segments \
                     and {markers} gaps or abandoned histories of the primary's"
                );
            }
            RegionManifestState::Pending {
                updated_at,
                segments,
                markers,
            } => {
                let _ = writeln!(
                    out,
                    "    {PITR_MANIFEST_KEY} (updated {updated_at}) does not record yet {segments} \
                     segments and {markers} gaps or abandoned histories the primary archived \
                     within the last {}s; the next archive run copies them",
                    health.tolerance.as_secs()
                );
            }
            RegionManifestState::Current { updated_at } => {
                if detailed {
                    let _ = writeln!(out, "    {PITR_MANIFEST_KEY} updated {updated_at}");
                }
            }
        }
        if !region.segments.missing.is_empty() || !region.segments.damaged.is_empty() {
            let _ = writeln!(
                out,
                "    {} of {} segments not replicated intact",
                region.segments.missing.len() + region.segments.damaged.len(),
                health.segments
            );
        }
        if detailed {
            for segment_id in &region.segments.missing {
                let _ = writeln!(out, "      {segment_id} is missing");
            }
            for segment_id in &region.segments.pending {
                let _ = writeln!(out, "      {segment_id} is not copied yet");
            }
            for (segment_id, reason) in &region.segments.damaged {
                let _ = writeln!(out, "      {segment_id} {reason}");
            }
        }
    }
    out
}

/// The WAL archive part of `replicate-status`: prints the report and returns whether every
/// region is healthy, or None when the archive is not replicated (nothing is printed when
/// WAL archiving is not enabled at all).
pub async fn wal_replication_status(
    settings: Option<&PitrSettings>,
    detailed: bool,
    deep: bool,
) -> Option<bool> {
    let settings = settings?;
    match check_wal_replication(settings, deep, duration_from_epoch_now()).await {
        Ok(Some(health)) => {
            print!("{}", format_wal_replication_report(&health, detailed));
            Some(health.is_healthy())
        }
        Ok(None) => {
            println!(
                "WAL archive replication: not configured (the archive at {} is not replicated)",
                settings.location
            );
            None
        }
        Err(err) => {
            error!(%err, "Unable to check the replication of the WAL archive");
            println!(
                "WAL archive replication: unable to read the archive at {}: {err}",
                settings.location
            );
            Some(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use kubidm_proto::backup::{
        BackupCompression, BackupEncryptionConfig, ReplicationConfig, WalArchiveConfig,
    };
    use kubidmd_lib::be::SharedWalArchiver;
    use kubidmd_lib::repl::wal::{segment_file_name, WalArchiver};
    use uuid::Uuid;

    use super::super::test_util::segment;
    use super::*;
    use crate::backup::s3::fake_s3;

    type Objects = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

    fn region_of(fake: &fake_s3::FakeS3, bucket: &str) -> ReplicationRegionConfig {
        let s3 = fake.config(bucket);
        ReplicationRegionConfig {
            name: Some("dr".to_string()),
            region: "us-east-1".to_string(),
            endpoint: s3.endpoint.clone(),
            bucket: s3.bucket.clone(),
            path_prefix: None,
            credentials: s3.credentials.clone(),
            server_side_encryption: None,
            storage_class: "STANDARD".to_string(),
            kms_key_id: None,
        }
    }

    fn put(objects: &Objects, path: &str, data: &[u8]) {
        objects
            .lock()
            .expect("objects")
            .insert(path.to_string(), data.to_vec());
    }

    /// Long after every segment of the tests ended: nothing is pending any more.
    const LATE: Duration = Duration::from_secs(100_000);

    async fn check(settings: &PitrSettings, deep: bool, now: Duration) -> WalReplicationHealth {
        check_wal_replication(settings, deep, now)
            .await
            .expect("check")
            .expect("replicated")
    }

    /// A replicated archive whose region copies go missing or get damaged: the status
    /// reports each problem, and the replication of the next archive runs repairs them.
    #[tokio::test]
    async fn test_region_copies_of_the_wal_archive_are_reported_and_repaired() {
        let objects: Objects = Arc::new(Mutex::new(BTreeMap::new()));
        let fake = fake_s3::FakeS3::start(fake_s3::store(Arc::clone(&objects))).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let server = Uuid::new_v4();

        let mut primary_s3 = fake.config("primary");
        primary_s3.replication = Some(ReplicationConfig {
            enabled: true,
            regions: vec![region_of(&fake, "replica")],
            sync_interval_seconds: 300,
        });
        let wal = WalArchiveConfig {
            enabled: true,
            local_path: Some(dir.path().join("wal")),
            ..WalArchiveConfig::default()
        };
        let settings = PitrSettings {
            wal: wal.clone(),
            local_dir: dir.path().join("wal"),
            location: PitrLocation::S3(primary_s3.clone()),
            bases: BaseLocation::Local(dir.path().join("backups")),
            encryption: BackupEncryptionConfig::default(),
        };
        let archiver: SharedWalArchiver = Arc::new(std::sync::Mutex::new(
            WalArchiver::open(wal, server, dir.path().join("wal"), None).expect("archiver"),
        ));
        let archive = PitrArchive::new(settings.clone(), archiver);

        // Before the first archive run there is nothing to replicate, which is healthy.
        let health = check(&settings, false, LATE).await;
        assert!(!health.archived);
        assert!(health.is_healthy(), "{health:#?}");
        let text = format_wal_replication_report(&health, false);
        assert!(text.contains("not yet archived"), "{text}");

        // The primary archive: two segments and the manifest naming them.
        let store = PitrStore::open(&settings.location).await.expect("store");
        let PitrStore::S3 { client: primary } = &store else {
            panic!("S3 store expected");
        };
        let mut manifest = PitrManifest::new(server);
        for (n, start) in [100, 200].into_iter().enumerate() {
            let mut archived = segment(
                &segment_file_name(server, Duration::from_secs(start)),
                start,
                start + 50,
            );
            archived.server_uuid = server;
            primary
                .upload_backup(
                    format!("segment {n}").as_bytes(),
                    &archived.object_key(),
                    "t",
                    BackupCompression::Gzip,
                    None,
                )
                .await
                .expect("upload");
            manifest.add_segment(archived);
        }
        store
            .save_manifest(&mut manifest, Duration::from_secs(300))
            .await
            .expect("save");
        let keys: Vec<String> = manifest
            .segments
            .iter()
            .map(WalSegment::object_key)
            .collect();
        let ids: Vec<String> = manifest
            .segments
            .iter()
            .map(|s| s.segment_id.clone())
            .collect();

        // Nothing replicated yet: right after the archive run that is only pending, later
        // it is missing.
        let health = check(&settings, false, Duration::from_secs(400)).await;
        let region = &health.regions[0];
        assert_eq!(region.segments.pending, ids);
        assert!(region.segments.missing.is_empty());
        let health = check(&settings, true, LATE).await;
        assert!(!health.is_healthy());
        assert_eq!(health.segments, 2);
        let region = &health.regions[0];
        assert_eq!(region.manifest, RegionManifestState::Missing);
        assert_eq!(region.segments.missing, ids);
        assert_eq!(region.lag, None);

        // A run mirrors everything.
        let mut report = PitrSyncReport::default();
        archive
            .replicate(&store, &mut manifest, Duration::from_secs(400), &mut report)
            .await;
        assert_eq!((report.replicated, report.region_errors), (2, 0));
        let health = check(&settings, true, LATE).await;
        assert!(health.is_healthy(), "{health:#?}");
        assert_eq!(health.regions[0].segments.intact, 2);
        assert_eq!(health.regions[0].lag, Some(Duration::ZERO));
        assert!(format_wal_replication_report(&health, false)
            .starts_with("WAL archive replication: Completed\n"));

        // The region loses the sidecar of one segment, gets a truncated copy of the other,
        // and its manifest is damaged.
        objects
            .lock()
            .expect("objects")
            .remove(&format!("/replica/{}{METADATA_SUFFIX}", keys[1]));
        put(&objects, &format!("/replica/{}", keys[0]), b"seg");
        put(
            &objects,
            &format!("/replica/{PITR_MANIFEST_KEY}"),
            b"{ damaged",
        );
        let health = check(&settings, false, LATE).await;
        let region = &health.regions[0];
        assert!(!health.is_healthy());
        assert!(matches!(region.manifest, RegionManifestState::Damaged(_)));
        assert_eq!(region.segments.missing, vec![ids[1].clone()]);
        assert_eq!(region.segments.damaged.len(), 1);
        assert_eq!(region.segments.damaged[0].0, ids[0]);
        let text = format_wal_replication_report(&health, true);
        assert!(
            text.starts_with("WAL archive replication: Degraded\n"),
            "{text}"
        );
        assert!(
            text.contains("2 of 2 segments not replicated intact"),
            "{text}"
        );
        assert!(text.contains(&format!("{} is missing", ids[1])), "{text}");
        assert!(text.contains("The region's manifest is damaged"), "{text}");

        // The next run compares the listings, which is enough to repair all three.
        let mut report = PitrSyncReport::default();
        archive
            .replicate(&store, &mut manifest, Duration::from_secs(500), &mut report)
            .await;
        assert_eq!((report.replicated, report.region_errors), (2, 0));
        let health = check(&settings, true, LATE).await;
        assert!(health.is_healthy(), "{health:#?}");

        // A copy replaced by one of the same size only shows in the sidecars: the status
        // compares them with --deep only, and the archive once per sync interval, outside
        // the manifest lock.
        let replace_sidecar = |n: usize| {
            put(&objects, &format!("/replica/{}", keys[n]), b"segment X");
            let sidecar_path = format!("/replica/{}{METADATA_SUFFIX}", keys[n]);
            let sidecar = objects.lock().expect("objects")[&sidecar_path].clone();
            let mut sidecar: serde_json::Value = serde_json::from_slice(&sidecar).expect("sidecar");
            sidecar["checksum_sha256"] = serde_json::Value::String("0".repeat(64));
            put(
                &objects,
                &sidecar_path,
                &serde_json::to_vec(&sidecar).expect("json"),
            );
        };
        replace_sidecar(1);
        assert!(check(&settings, false, LATE).await.is_healthy());
        let health = check(&settings, true, LATE).await;
        assert_eq!(health.regions[0].segments.damaged.len(), 1);
        assert!(format_wal_replication_report(&health, false).contains("listings and sidecars"));
        let mut report = PitrSyncReport::default();
        archive
            .check_region_copies(&store, &manifest, Duration::from_secs(600), &mut report)
            .await;
        assert_eq!(report.replicated, 1);
        assert!(check(&settings, true, LATE).await.is_healthy());
        replace_sidecar(0);
        let mut report = PitrSyncReport::default();
        archive
            .check_region_copies(&store, &manifest, Duration::from_secs(700), &mut report)
            .await;
        assert_eq!(report.replicated, 0, "not due yet");
        archive
            .check_region_copies(&store, &manifest, Duration::from_secs(900), &mut report)
            .await;
        assert_eq!(report.replicated, 1);
        assert!(check(&settings, true, LATE).await.is_healthy());

        // The region's manifest misses only a segment archived within the tolerance: it
        // is pending, which is healthy, until it is too old.
        let mut newer = segment(
            &segment_file_name(server, Duration::from_secs(1000)),
            1000,
            1050,
        );
        newer.server_uuid = server;
        primary
            .upload_backup(
                b"segment 2",
                &newer.object_key(),
                "t",
                BackupCompression::Gzip,
                None,
            )
            .await
            .expect("upload");
        manifest.add_segment(newer.clone());
        store
            .save_manifest(&mut manifest, Duration::from_secs(1060))
            .await
            .expect("save");
        let health = check(&settings, false, Duration::from_secs(1100)).await;
        let region = &health.regions[0];
        assert!(
            matches!(
                region.manifest,
                RegionManifestState::Pending { segments: 1, .. }
            ),
            "{region:#?}"
        );
        assert_eq!(region.segments.pending, vec![newer.segment_id.clone()]);
        assert!(health.is_healthy(), "{health:#?}");
        let health = check(&settings, false, LATE).await;
        assert!(matches!(
            health.regions[0].manifest,
            RegionManifestState::Behind { segments: 1, .. }
        ));
        assert!(!health.is_healthy());

        // The primary loses a segment the region holds: a problem of the primary, which
        // neither marks the region's copy damaged nor stops the replication of the others.
        objects
            .lock()
            .expect("objects")
            .remove(&format!("/primary/{}", keys[0]));
        let health = check(&settings, true, LATE).await;
        assert_eq!(health.unavailable_on_primary.len(), 1, "{health:#?}");
        assert_eq!(health.unavailable_on_primary[0].0, ids[0]);
        assert!(health.regions[0].segments.damaged.is_empty(), "{health:#?}");
        assert!(!health.is_healthy());
        let text = format_wal_replication_report(&health, true);
        assert!(text.contains("not available on the primary"), "{text}");
        let mut report = PitrSyncReport::default();
        archive
            .replicate(
                &store,
                &mut manifest,
                Duration::from_secs(1200),
                &mut report,
            )
            .await;
        assert_eq!((report.replicated, report.region_errors), (1, 0));
        archive
            .check_region_copies(&store, &manifest, Duration::from_secs(1300), &mut report)
            .await;
        assert_eq!((report.replicated, report.region_errors), (1, 0));
        let health = check(&settings, true, LATE).await;
        assert!(health.regions[0].is_healthy(), "{health:#?}");
        assert!(matches!(
            health.regions[0].manifest,
            RegionManifestState::Current { .. }
        ));
    }
}
