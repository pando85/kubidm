//! Mirroring the archive to the replication regions of its S3 location, repairing the
//! region copies, and reporting how far every region's copy is from the primary's.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

use kubidm_proto::backup::{PitrManifest, ReplicationRegionConfig, WalSegment, PITR_MANIFEST_KEY};

use super::store::PitrStore;
use super::{
    select_segments_to_delete, BaseLocation, PitrArchive, PitrError, PitrLocation, PitrSettings,
    PitrSyncReport,
};
use crate::backup::{S3ClientWrapper, METADATA_SUFFIX};

/// The objects of one S3 location, by prefix-relative key, with their size.
type ObjectSizes = BTreeMap<String, u64>;

/// How a region's copies of the segments a manifest names compare with the primary's.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RegionSegments {
    /// Segments whose copy, object and sidecar, matches the primary's.
    pub intact: usize,
    /// Segments whose object or sidecar the region lacks.
    pub missing: Vec<String>,
    /// Segments whose copy differs from the primary's, with how.
    pub damaged: Vec<(String, String)>,
}

impl RegionSegments {
    /// The segments to copy to the region again.
    fn to_copy(&self) -> impl Iterator<Item = &String> {
        self.missing
            .iter()
            .chain(self.damaged.iter().map(|(segment_id, _)| segment_id))
    }
}

/// Compare the region's copies of `segments` with the primary's. A copy is intact when its
/// object and its sidecar exist and the object has the size of the primary's object; with
/// `deep`, the sidecars must also agree on checksum and size, as for backups, which reads
/// both sidecars of every segment. Nothing is downloaded: a copy whose bytes were changed
/// without changing their size and sidecar is only caught by a recovery from the region,
/// which checks every segment it reads.
async fn compare_segments(
    primary: &S3ClientWrapper,
    primary_objects: &ObjectSizes,
    region: &S3ClientWrapper,
    region_objects: &ObjectSizes,
    segments: &[WalSegment],
    deep: bool,
) -> RegionSegments {
    let mut compared = RegionSegments::default();
    for segment in segments {
        let key = segment.object_key();
        let sidecar = format!("{key}{METADATA_SUFFIX}");
        let Some(region_size) = region_objects.get(&key) else {
            compared.missing.push(segment.segment_id.clone());
            continue;
        };
        if !region_objects.contains_key(&sidecar) {
            compared.missing.push(segment.segment_id.clone());
            continue;
        }
        if let Some(primary_size) = primary_objects.get(&key) {
            if primary_size != region_size {
                compared.damaged.push((
                    segment.segment_id.clone(),
                    format!("holds {region_size} bytes, the primary {primary_size}"),
                ));
                continue;
            }
        }
        if deep {
            let differs = match primary.get_backup_metadata(&key).await {
                Ok(metadata) => S3ClientWrapper::replica_differs(region, &key, &metadata)
                    .await
                    .unwrap_or_else(|err| Some(format!("could not be checked: {err}"))),
                Err(err) => Some(format!("could not be compared with the primary: {err}")),
            };
            if let Some(reason) = differs {
                compared.damaged.push((segment.segment_id.clone(), reason));
                continue;
            }
        }
        compared.intact += 1;
    }
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
        // The sidecars of every segment are compared once per sync interval of the
        // replication, as for backups; the listings every run.
        let deep = {
            let mut last = self
                .last_deep_check
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let due = last.is_none_or(|last| {
                now >= last + Duration::from_secs(replication.sync_interval_seconds.max(1))
            });
            if due {
                *last = Some(now);
            }
            due
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
                deep,
            };
            let result = match self.region_store(region).await {
                Ok(region_store) => {
                    replicate_to_region(client, store, &region_store, manifest, &target).await
                }
                Err(err) => Err(err),
            };
            match result {
                Ok(copied) => report.replicated += copied,
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
    /// Whether to compare the sidecars of the segments as well.
    deep: bool,
}

/// Mirror the archive of `primary` (whose manifest is `manifest`) to `target`, see
/// [`PitrArchive::replicate`]. Returns the number of segments copied.
///
/// A segment copy the region misses, or holds a differing copy of, is copied again, and a
/// region manifest that can not be read is written again from the primary's.
async fn replicate_to_region(
    primary: &S3ClientWrapper,
    store: &PitrStore,
    region_store: &PitrStore,
    manifest: &mut PitrManifest,
    target: &RegionTarget<'_>,
) -> Result<usize, PitrError> {
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
        target.deep,
    )
    .await;
    for (segment_id, reason) in &compared.damaged {
        warn!(
            region = %region_name,
            segment = %segment_id,
            %reason,
            "The region's copy of a WAL segment differs from the primary's; copying it again"
        );
    }
    let mut copied = 0;
    for segment_id in compared.to_copy() {
        if let Some(segment) = manifest.segment(segment_id) {
            primary
                .copy_backup_to(region, &segment.object_key())
                .await?;
            copied += 1;
        }
    }

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

    if copied > 0 {
        info!(region = %region_name, copied, "WAL segments replicated");
    }
    Ok(copied)
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
    /// Whether the region holds a current manifest and an intact copy of every segment.
    pub fn is_healthy(&self) -> bool {
        self.error.is_none()
            && matches!(self.manifest, RegionManifestState::Current { .. })
            && self.segments.missing.is_empty()
            && self.segments.damaged.is_empty()
    }
}

/// The replication health of the WAL archive: the primary's manifest and every region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalReplicationHealth {
    /// The primary location of the archive.
    pub location: String,
    /// When the primary's manifest was last updated.
    pub updated_at: String,
    /// The segments the primary's manifest names.
    pub segments: usize,
    pub regions: Vec<WalRegionHealth>,
}

impl WalReplicationHealth {
    pub fn is_healthy(&self) -> bool {
        self.regions.iter().all(WalRegionHealth::is_healthy)
    }
}

/// The replication health of the archive at `settings`, as `replicate-status` reports it:
/// for every region of [`PitrSettings::replication`], whether it holds a current manifest,
/// which segments it misses or holds a differing copy of (sidecars compared, as for
/// backups), and how far its manifest lags behind. Nothing is copied. None when the archive
/// is not replicated. Fails only when the primary archive can not be read.
pub async fn check_wal_replication(
    settings: &PitrSettings,
) -> Result<Option<WalReplicationHealth>, PitrError> {
    let (Some(replication), PitrLocation::S3(_)) = (settings.replication(), &settings.location)
    else {
        return Ok(None);
    };
    let store = PitrStore::open(&settings.location).await?;
    let PitrStore::S3 { client: primary } = &store else {
        return Ok(None);
    };
    let manifest = store.load_manifest().await?.ok_or_else(|| {
        PitrError::NotRecoverable(format!(
            "no {PITR_MANIFEST_KEY} at {}; nothing has been archived",
            settings.location
        ))
    })?;
    let primary_objects = primary.list_object_sizes().await?;

    let mut regions = Vec::with_capacity(replication.regions.len());
    for region in &replication.regions {
        let mut health = WalRegionHealth {
            region: region.name().to_string(),
            bucket: region.bucket.clone(),
            manifest: RegionManifestState::Missing,
            segments: RegionSegments::default(),
            lag: None,
            error: None,
        };
        if let Err(err) =
            check_region(primary, &primary_objects, &manifest, region, &mut health).await
        {
            health.error = Some(err.to_string());
        }
        regions.push(health);
    }
    Ok(Some(WalReplicationHealth {
        location: settings.location.to_string(),
        updated_at: manifest.updated_at.clone(),
        segments: manifest.segments.len(),
        regions,
    }))
}

/// Fill in `health` for `region`. Fails when the region can not be reached or listed.
async fn check_region(
    primary: &S3ClientWrapper,
    primary_objects: &ObjectSizes,
    manifest: &PitrManifest,
    region: &ReplicationRegionConfig,
    health: &mut WalRegionHealth,
) -> Result<(), PitrError> {
    let client = S3ClientWrapper::for_region(region).await?;
    let region_objects = client.list_object_sizes().await?;
    health.segments = compare_segments(
        primary,
        primary_objects,
        &client,
        &region_objects,
        &manifest.segments,
        true,
    )
    .await;
    let store = PitrStore::S3 {
        client: Box::new(client),
    };
    health.manifest = match load_region_manifest(&store).await? {
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
            let segments = manifest
                .segments
                .iter()
                .filter(|segment| !region_manifest.has_segment(&segment.segment_id))
                .count();
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
            if segments == 0 && markers == 0 {
                RegionManifestState::Current { updated_at }
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
) -> Option<bool> {
    let settings = settings?;
    match check_wal_replication(settings).await {
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

        // Nothing replicated yet.
        let health = check_wal_replication(&settings)
            .await
            .expect("check")
            .expect("replicated");
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
        let health = check_wal_replication(&settings)
            .await
            .expect("check")
            .expect("replicated");
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
        let health = check_wal_replication(&settings)
            .await
            .expect("check")
            .expect("replicated");
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

        // The next run, within the sync interval, compares the listings only, which is
        // enough to repair all three.
        let mut report = PitrSyncReport::default();
        archive
            .replicate(&store, &mut manifest, Duration::from_secs(500), &mut report)
            .await;
        assert_eq!((report.replicated, report.region_errors), (2, 0));
        let health = check_wal_replication(&settings)
            .await
            .expect("check")
            .expect("replicated");
        assert!(health.is_healthy(), "{health:#?}");

        // A copy replaced by one of the same size only shows in the sidecars, which the
        // status compares, and the replication once per sync interval.
        put(&objects, &format!("/replica/{}", keys[1]), b"segment X");
        let sidecar_path = format!("/replica/{}{METADATA_SUFFIX}", keys[1]);
        let sidecar = objects.lock().expect("objects")[&sidecar_path].clone();
        let mut sidecar: serde_json::Value = serde_json::from_slice(&sidecar).expect("sidecar");
        sidecar["checksum_sha256"] = serde_json::Value::String("0".repeat(64));
        put(
            &objects,
            &sidecar_path,
            &serde_json::to_vec(&sidecar).expect("json"),
        );
        let health = check_wal_replication(&settings)
            .await
            .expect("check")
            .expect("replicated");
        assert_eq!(health.regions[0].segments.damaged.len(), 1);
        let mut report = PitrSyncReport::default();
        archive
            .replicate(&store, &mut manifest, Duration::from_secs(600), &mut report)
            .await;
        assert_eq!(report.replicated, 0, "not due yet");
        archive
            .replicate(&store, &mut manifest, Duration::from_secs(700), &mut report)
            .await;
        assert_eq!(report.replicated, 1);
        let health = check_wal_replication(&settings)
            .await
            .expect("check")
            .expect("replicated");
        assert!(health.is_healthy(), "{health:#?}");
    }
}
