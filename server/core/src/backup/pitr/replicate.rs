//! Mirroring the archive to the replication regions of its S3 location.

use std::collections::BTreeSet;
use std::time::Duration;

use kubidm_proto::backup::{
    PitrManifest, ReplicationRegionConfig, WalSegment, PITR_MANIFEST_KEY, WAL_SEGMENT_KEY_PREFIX,
};

use super::store::PitrStore;
use super::{select_segments_to_delete, BaseLocation, PitrArchive, PitrError, PitrSyncReport};
use crate::backup::S3ClientWrapper;

impl PitrArchive {
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
        for region in &replication.regions {
            // Where the region keeps its copies of the base backups, for its retention. When
            // the base backups are in another S3 location without this region, the region's
            // index keeps every base it learnt about, which only delays its retention.
            let region_bases = self
                .settings
                .for_region(&region.region)
                .map(|settings| settings.bases)
                .inspect_err(|err| debug!(%err, region = %region.region, "No base backups to prune the region index with"))
                .ok();
            let target = RegionTarget {
                config: region,
                bases: region_bases.as_ref(),
                now,
                retention: self.settings.wal.retention(),
            };
            match replicate_to_region(client, store, manifest, &target).await {
                Ok(copied) => report.replicated += copied,
                Err(err) => {
                    report.region_errors += 1;
                    error!(
                        %err,
                        region = %region.region,
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
}

/// Mirror the archive of `primary` (whose manifest is `manifest`) to `target`, see
/// [`PitrArchive::replicate`]. Returns the number of segments copied.
async fn replicate_to_region(
    primary: &S3ClientWrapper,
    store: &PitrStore,
    manifest: &mut PitrManifest,
    target: &RegionTarget<'_>,
) -> Result<usize, PitrError> {
    let region_name = &target.config.region;
    let region_store = PitrStore::S3 {
        client: Box::new(S3ClientWrapper::for_region(target.config).await?),
    };
    let PitrStore::S3 { client: region } = &region_store else {
        return Err(PitrError::Config("region store is not S3".to_string()));
    };

    let region_manifest = region_store.load_manifest().await?;
    if let Some(region_manifest) = &region_manifest {
        if region_manifest.server_uuid != manifest.server_uuid {
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
            store.save_manifest(manifest).await?;
        }
    }

    // Segments first, so that the region's manifest never names a segment it lacks.
    let present: BTreeSet<String> = region
        .list_backups()
        .await?
        .into_iter()
        .filter(|key| key.starts_with(WAL_SEGMENT_KEY_PREFIX))
        .collect();
    let mut copied = 0;
    for segment in &manifest.segments {
        let key = segment.object_key();
        if !present.contains(&key) {
            primary.copy_backup_to(region, &key).await?;
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
        mirrored.retain_base_backups(&bases.list_keys().await?);
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
        region_store.save_manifest(&mut mirrored).await?;
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
