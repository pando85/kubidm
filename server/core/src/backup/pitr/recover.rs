//! Recovery: planning, reading the archive, and the `pitr-list` and `recover` commands.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use kubidm_proto::backup::{
    is_encrypted_backup_name, PitrBaseBackup, PitrManifest, PitrTimelineBreak, WalSegment,
    PITR_MANIFEST_KEY,
};
use kubidm_proto::internal::OperationError;
use kubidmd_lib::be::WalApplyReport;
use kubidmd_lib::prelude::duration_from_epoch_now;
use kubidmd_lib::repl::wal::{
    format_ts_rfc3339, list_segments, parse_recovery_target_cid, parse_recovery_target_time,
    parse_segment, select_records, WalEntryRecord,
};

use super::store::{PitrStore, SegmentKeys};
use super::{blocking, PitrError, PitrSettings};
use crate::config::Configuration;

/// What the operator asked `recover` to reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryTargetSpec {
    /// An RFC3339 timestamp.
    Time(String),
    /// A CID as the server prints it.
    Cid(String),
    Latest,
}

impl fmt::Display for RecoveryTargetSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecoveryTargetSpec::Time(t) => write!(f, "time {t}"),
            RecoveryTargetSpec::Cid(c) => write!(f, "transaction {c}"),
            RecoveryTargetSpec::Latest => write!(f, "latest"),
        }
    }
}

/// The CID timestamp a target resolves to against a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub ts: Duration,
    /// Set when the target lies after the last archived record, so that the result is the
    /// latest recoverable state rather than the exact point asked for.
    pub clamped_to_latest: bool,
}

pub fn resolve_target(
    manifest: &PitrManifest,
    target: &RecoveryTargetSpec,
) -> Result<ResolvedTarget, PitrError> {
    let (earliest, latest) = manifest.recoverable_window().ok_or_else(|| {
        PitrError::NotRecoverable(
            "the archive holds no base backup; recovery becomes possible after the first \
             online backup taken with WAL archiving enabled"
                .to_string(),
        )
    })?;

    let ts = match target {
        RecoveryTargetSpec::Time(timestamp) => parse_recovery_target_time(timestamp)
            .map_err(|err| PitrError::Target(err.to_string()))?,
        RecoveryTargetSpec::Cid(cid) => {
            let cid =
                parse_recovery_target_cid(cid).map_err(|err| PitrError::Target(err.to_string()))?;
            if cid.s_uuid != manifest.server_uuid {
                return Err(PitrError::Target(format!(
                    "CID belongs to server {}, the archive belongs to server {}",
                    cid.s_uuid, manifest.server_uuid
                )));
            }
            cid.ts
        }
        RecoveryTargetSpec::Latest => latest,
    };

    if ts < earliest {
        return Err(PitrError::NotRecoverable(format!(
            "target {} is before the oldest base backup ({})",
            format_ts_rfc3339(ts),
            format_ts_rfc3339(earliest)
        )));
    }

    Ok(ResolvedTarget {
        ts,
        clamped_to_latest: ts > latest,
    })
}

/// The base backup and segments a recovery to `target` uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub target: ResolvedTarget,
    pub base: PitrBaseBackup,
    pub segments: Vec<WalSegment>,
}

pub fn plan_recovery(
    manifest: &PitrManifest,
    target: &RecoveryTargetSpec,
) -> Result<RecoveryPlan, PitrError> {
    let resolved = resolve_target(manifest, target)?;
    let base = manifest
        .base_backup_for(resolved.ts)
        .cloned()
        .ok_or_else(|| {
            PitrError::NotRecoverable(format!(
                "no base backup at or before {}",
                format_ts_rfc3339(resolved.ts)
            ))
        })?;
    if let Some(gap) = manifest.gap_blocking(base.watermark_ts, resolved.ts) {
        let latest = manifest
            .latest_recoverable_ts()
            .map(format_ts_rfc3339)
            .unwrap_or_else(|| "none".to_string());
        return Err(PitrError::NotRecoverable(format!(
            "the archive is missing the transactions from {} to {} ({}); replaying base backup \
             {} up to {} would skip them. Choose a target before the gap (the latest \
             recoverable point is {latest}), or one after a base backup taken after the gap",
            format_ts_rfc3339(gap.from_ts),
            format_ts_rfc3339(gap.until_ts),
            gap.reason,
            base.key,
            format_ts_rfc3339(resolved.ts),
        )));
    }
    let segments = manifest
        .segments_between(base.watermark_ts, resolved.ts)
        .into_iter()
        .cloned()
        .collect();
    Ok(RecoveryPlan {
        target: resolved,
        base,
        segments,
    })
}

/// The records of `file_entries` a recovery to `plan` replays: after the base watermark,
/// at or before the target, and not part of history a restore or recovery abandoned.
pub fn records_to_replay<'a>(
    manifest: &'a PitrManifest,
    plan: &'a RecoveryPlan,
    file_entries: &'a [WalEntryRecord],
) -> impl Iterator<Item = &'a WalEntryRecord> + 'a {
    select_records(file_entries, plan.base.watermark_ts, plan.target.ts)
        .filter(|record| !manifest.is_abandoned(record.ts()))
}

/// The outcome of `recover`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryOutcome {
    pub plan: RecoveryPlan,
    pub records: usize,
    /// The CID timestamp the database represents after recovery: the last record applied,
    /// or the base watermark when no record followed it.
    pub recovered_ts: Duration,
    pub dry_run: bool,
    pub apply: Option<WalApplyReport>,
}

/// The archive as recovery sees it: the manifest, plus the closed segments of the same
/// server still in the local WAL directory that were never archived (the server stopped
/// before its next synchronisation, or their upload failed).
struct OpenedArchive {
    /// The settings the archive is read with: those of the configuration, or those of the
    /// replication region it is read from.
    settings: PitrSettings,
    /// The settings of the primary archive, when the archive is read from a region.
    primary: Option<PitrSettings>,
    store: PitrStore,
    manifest: PitrManifest,
    /// Ids of the segments that are only in the local WAL directory.
    local_only: BTreeSet<String>,
}

/// Open the archive described by `config`, or its copy in the replication region `region`,
/// and load its manifest.
async fn open_archive(
    config: &Configuration,
    region: Option<&str>,
) -> Result<OpenedArchive, PitrError> {
    let configured = PitrSettings::from_config(config)?.ok_or_else(|| {
        PitrError::Config(
            "online_backup.wal_archive is not enabled; it tells the command where the archive is"
                .to_string(),
        )
    })?;
    let (settings, primary) = match region {
        Some(name) => (configured.for_region(name)?, Some(configured)),
        None => (configured, None),
    };
    let store = PitrStore::open(&settings.location).await?;
    let mut manifest = store.load_manifest().await?.ok_or_else(|| {
        PitrError::NotRecoverable(format!(
            "no {PITR_MANIFEST_KEY} at {}; nothing has been archived",
            settings.location
        ))
    })?;

    // A region prunes its base backups on its own; recovery from it can only start from
    // the base backups it actually holds.
    if primary.is_some() {
        let held = settings.bases.list_keys().await?;
        let indexed = manifest.base_backups.len();
        manifest.retain_base_backups(&held);
        if manifest.base_backups.len() != indexed {
            warn!(
                missing = indexed - manifest.base_backups.len(),
                bases = %settings.bases,
                "Base backups indexed by the archive are missing in the region and are not used"
            );
        }
    }

    let mut local_only = BTreeSet::new();
    let local_segments = {
        let local_dir = settings.local_dir.clone();
        blocking(move || Ok(list_segments(&local_dir)?)).await?
    };
    for segment in local_segments {
        if segment.server_uuid != manifest.server_uuid || manifest.has_segment(&segment.segment_id)
        {
            continue;
        }
        local_only.insert(segment.segment_id.clone());
        manifest.add_segment(segment);
    }

    Ok(OpenedArchive {
        settings,
        primary,
        store,
        manifest,
        local_only,
    })
}

/// `kubidmd database pitr-list`: print the base backups, segments and the recoverable
/// window. Returns false when nothing is recoverable or the archive could not be read.
pub async fn pitr_list_server_core(config: &Configuration, region: Option<&str>) -> bool {
    let OpenedArchive {
        settings,
        manifest,
        local_only,
        ..
    } = match open_archive(config, region).await {
        Ok(opened) => opened,
        Err(err) => {
            error!(%err, "Unable to read the PITR archive");
            println!("PITR archive: unavailable ({err})");
            return false;
        }
    };

    match region {
        Some(region) => println!("PITR archive at {} (region {region}):", settings.location),
        None => println!("PITR archive at {}:", settings.location),
    }
    println!("  Server:       {}", manifest.server_uuid);
    println!("  Base backups: {}", settings.bases);
    if !manifest.updated_at.is_empty() {
        println!("  Updated:      {}", manifest.updated_at);
    }

    println!();
    if manifest.base_backups.is_empty() {
        println!("Base backups: (none)");
    } else {
        let key_width = manifest
            .base_backups
            .iter()
            .map(|b| b.key.len())
            .max()
            .unwrap_or(0)
            .max("KEY".len());
        println!("Base backups:");
        println!(
            "  {:<key_width$}  {:<35}  {:<35}  VERSION",
            "KEY", "TAKEN", "WATERMARK"
        );
        for base in &manifest.base_backups {
            println!(
                "  {:<key_width$}  {:<35}  {:<35}  {}{}",
                base.key,
                base.timestamp,
                format_ts_rfc3339(base.watermark_ts),
                base.server_version,
                if is_encrypted_backup_name(&base.key) {
                    "  (encrypted)"
                } else {
                    ""
                }
            );
        }
    }

    println!();
    if manifest.segments.is_empty() {
        println!("WAL segments: (none)");
    } else {
        let key_width = manifest
            .segments
            .iter()
            .map(|s| s.segment_id.len())
            .max()
            .unwrap_or(0)
            .max("SEGMENT".len());
        println!("WAL segments:");
        println!(
            "  {:<key_width$}  {:<35}  {:<35}  {:>8}  {:>12}",
            "SEGMENT", "FROM", "TO", "RECORDS", "SIZE_BYTES"
        );
        for segment in &manifest.segments {
            let note = if local_only.contains(&segment.segment_id) {
                "  (local, not archived yet)".to_string()
            } else if let Some(key) = &segment.encryption_key {
                format!("  (encrypted, key '{key}')")
            } else {
                String::new()
            };
            println!(
                "  {:<key_width$}  {:<35}  {:<35}  {:>8}  {:>12}{note}",
                segment.segment_id,
                format_ts_rfc3339(segment.start_ts),
                format_ts_rfc3339(segment.end_ts),
                segment.entry_count,
                segment.size_bytes,
            );
        }
    }

    if !manifest.gaps.is_empty() {
        println!();
        println!("Gaps (recovery can not replay across them):");
        for gap in &manifest.gaps {
            println!(
                "  {} to {} ({})",
                format_ts_rfc3339(gap.from_ts),
                format_ts_rfc3339(gap.until_ts),
                gap.reason
            );
        }
    }

    if !manifest.timeline_breaks.is_empty() {
        println!();
        println!("Abandoned history (never replayed):");
        for timeline_break in &manifest.timeline_breaks {
            println!(
                "  after {} up to {} ({} at {})",
                format_ts_rfc3339(timeline_break.after_ts),
                format_ts_rfc3339(timeline_break.until_ts),
                timeline_break.reason,
                timeline_break.at
            );
        }
    }

    println!();
    match manifest.recoverable_window() {
        Some((earliest, latest)) => {
            println!(
                "Recoverable window: {} to {}",
                format_ts_rfc3339(earliest),
                format_ts_rfc3339(latest)
            );
            true
        }
        None => {
            println!("Recoverable window: none (no base backup has been indexed)");
            false
        }
    }
}

/// Fetch and parse the segments of `plan`, returning the records to replay in CID order.
async fn load_records(
    opened: &OpenedArchive,
    plan: &RecoveryPlan,
) -> Result<Vec<WalEntryRecord>, PitrError> {
    let mut records: Vec<WalEntryRecord> = Vec::new();
    let mut keys = SegmentKeys::new(&opened.settings.encryption);
    for segment in &plan.segments {
        if segment.server_version != env!("KUBIDM_PKG_SERIES") {
            return Err(PitrError::NotRecoverable(format!(
                "segment {} was written by server version {} and can not be replayed by version {}",
                segment.segment_id,
                segment.server_version,
                env!("KUBIDM_PKG_SERIES")
            )));
        }
        let data = opened
            .store
            .fetch_segment(
                &opened.settings.local_dir,
                segment,
                opened.local_only.contains(&segment.segment_id),
                &mut keys,
            )
            .await?;
        let compression = segment.compression;
        let file = blocking(move || Ok(parse_segment(&data, compression)?)).await?;
        if file.server_uuid != opened.manifest.server_uuid {
            return Err(PitrError::NotRecoverable(format!(
                "segment {} belongs to server {}, the archive belongs to {}",
                segment.segment_id, file.server_uuid, opened.manifest.server_uuid
            )));
        }
        records.extend(records_to_replay(&opened.manifest, plan, &file.entries).cloned());
    }
    records.sort_by_key(|record| (record.cid_ts, record.entry_id));
    Ok(records)
}

fn print_plan(opened: &OpenedArchive, plan: &RecoveryPlan, records: usize, recovered_ts: Duration) {
    eprintln!("Recovery plan:");
    eprintln!("  Archive:      {}", opened.settings.location);
    eprintln!("  Target:       {}", format_ts_rfc3339(plan.target.ts));
    if plan.target.clamped_to_latest {
        eprintln!(
            "                (after the last archived record; the result is the latest recoverable state)"
        );
    }
    if opened.manifest.is_abandoned(plan.target.ts) {
        eprintln!(
            "                (inside history an earlier restore or recovery abandoned; the result is the state it restored)"
        );
    }
    eprintln!(
        "  Base backup:  {} at {} (watermark {})",
        plan.base.key,
        opened.settings.bases,
        format_ts_rfc3339(plan.base.watermark_ts)
    );
    if plan.segments.is_empty() {
        eprintln!("  Segments:     none (the base backup already represents the target)");
    } else {
        eprintln!("  Segments:     {}", plan.segments.len());
        for segment in &plan.segments {
            eprintln!(
                "    {} ({} to {}, {} records){}",
                segment.segment_id,
                format_ts_rfc3339(segment.start_ts),
                format_ts_rfc3339(segment.end_ts),
                segment.entry_count,
                if opened.local_only.contains(&segment.segment_id) {
                    ", local"
                } else if segment.encryption_key.is_some() {
                    ", encrypted"
                } else {
                    ""
                }
            );
        }
    }
    eprintln!("  Records:      {records} to replay");
    eprintln!("  Result:       {}", format_ts_rfc3339(recovered_ts));
}

/// `kubidmd database recover`: recover the database described by `config` to `target`.
///
/// Offline only, like `restore`. The newest base backup at or before the target is
/// restored into the configured database and the WAL records between its watermark and
/// the target are applied in the same database transaction, so a failure leaves the
/// database untouched. The database is then reindexed, booted and verified exactly as
/// `verify-backup --level full` does, and the history after the recovered point is
/// recorded as abandoned in the manifest. `dry_run` prints the plan and changes nothing.
pub async fn pitr_recover_server_core(
    config: &Configuration,
    target: &RecoveryTargetSpec,
    dry_run: bool,
    region: Option<&str>,
) -> Result<RecoveryOutcome, PitrError> {
    let opened = open_archive(config, region).await?;
    let plan = plan_recovery(&opened.manifest, target)?;

    if plan.base.server_version != env!("KUBIDM_PKG_SERIES") {
        return Err(PitrError::NotRecoverable(format!(
            "base backup {} was written by server version {} and can not be restored by version {}",
            plan.base.key,
            plan.base.server_version,
            env!("KUBIDM_PKG_SERIES")
        )));
    }

    // Reading segments changes nothing, so the dry run can report the exact record count.
    let records = load_records(&opened, &plan).await?;
    let recovered_ts = records
        .last()
        .map(WalEntryRecord::ts)
        .unwrap_or(plan.base.watermark_ts);
    print_plan(&opened, &plan, records.len(), recovered_ts);

    if dry_run {
        eprintln!("Dry run: no changes were made.");
        return Ok(RecoveryOutcome {
            plan,
            records: records.len(),
            recovered_ts,
            dry_run: true,
            apply: None,
        });
    }

    let db_path = config
        .db_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "(in memory)".to_string());

    let base = opened.settings.bases.fetch(&plan.base).await?;

    info!(
        "Restoring base backup {} and replaying {} WAL records into {db_path}",
        plan.base.key,
        records.len()
    );
    let apply = crate::restore_and_replay(config, base.path(), &records)
        .await
        .map_err(|err| {
            error!(
                ?err,
                "Recovery failed; the database at {db_path} was not changed unless the error \
                 says otherwise"
            );
            PitrError::Operation(err)
        })?
        .apply;
    drop(base);

    if let Some(report) = &apply {
        info!(
            applied = report.applied,
            created = report.created,
            modified = report.modified,
            deleted = report.deleted,
            "WAL records replayed"
        );
    }

    info!("Verifying the recovered database ...");
    let consistency_errors = crate::verify_booted_database(config)
        .await
        .map_err(PitrError::Operation)?;
    if !consistency_errors.is_empty() {
        for err in &consistency_errors {
            error!(?err, "Recovered database consistency error");
        }
        error!(
            "RECOVERY INCOMPLETE: the recovered database at {db_path} failed its consistency \
             verification. Do not start the server on it; recover to another point or restore a backup."
        );
        return Err(PitrError::Operation(OperationError::ConsistencyError(
            consistency_errors,
        )));
    }

    record_timeline_break(&opened.settings, recovered_ts, "recover")
        .await
        .inspect_err(|err| {
            error!(
                %err,
                "The database at {db_path} WAS recovered, but the abandoned history could not \
                 be recorded in the archive. A later recovery past this point could replay it: \
                 take a new online backup right after starting the server, and recover only to \
                 points after it."
            );
        })?;

    // Recovered from a region: the primary archive, which the recovered server archives
    // into, must learn about the abandoned history too. It is often unreachable when a
    // region is used, so this is best effort; the server merges what the region recorded
    // into the primary archive at its first synchronisation that reaches both.
    if let Some(primary) = &opened.primary {
        if let Err(err) = record_timeline_break(primary, recovered_ts, "recover").await {
            warn!(
                %err,
                "The abandoned history was recorded in the region, but not in the primary WAL \
                 archive at {}. The server merges it into the primary archive once it reaches \
                 both; until then take a new online backup right after starting the server.",
                primary.location
            );
        }
    }

    eprintln!(
        "Recovered {db_path} to {} ({} records replayed on {})",
        format_ts_rfc3339(recovered_ts),
        records.len(),
        plan.base.key
    );

    Ok(RecoveryOutcome {
        plan,
        records: records.len(),
        recovered_ts,
        dry_run: false,
        apply,
    })
}

/// Record in the archive that the database was restored or recovered to `after_ts`, so
/// that everything archived after that point up to now is never replayed again. `until_ts`
/// also covers any CID the archive holds, in case the clock of the old server was ahead.
pub(super) async fn record_timeline_break(
    settings: &PitrSettings,
    after_ts: Duration,
    reason: &str,
) -> Result<(), PitrError> {
    let store = PitrStore::open(&settings.location).await?;
    let Some(mut manifest) = store.load_manifest().await? else {
        // Nothing was ever archived, so there is no history to abandon.
        return Ok(());
    };
    let now = duration_from_epoch_now();
    let local_segments = {
        let local_dir = settings.local_dir.clone();
        blocking(move || Ok(list_segments(&local_dir)?)).await?
    };
    let until_ts = manifest
        .segments
        .iter()
        .chain(local_segments.iter())
        .map(|s| s.end_ts)
        .chain(manifest.base_backups.iter().map(|b| b.watermark_ts))
        .fold(now, Duration::max);
    manifest.add_timeline_break(PitrTimelineBreak {
        after_ts,
        until_ts,
        at: format_ts_rfc3339(now),
        reason: reason.to_string(),
    });
    store.save_manifest(&mut manifest).await?;
    info!(
        after = %format_ts_rfc3339(after_ts),
        until = %format_ts_rfc3339(until_ts),
        "Abandoned history recorded in the PITR archive"
    );
    Ok(())
}

/// After `kubidmd database restore` or `restore-s3`: when WAL archiving is configured,
/// record that the history after the watermark of the restored backup was abandoned.
/// Without WAL archiving this does nothing.
pub async fn note_restore(config: &Configuration, watermark: Duration) -> Result<(), PitrError> {
    let Some(settings) = PitrSettings::from_config(config)? else {
        return Ok(());
    };
    record_timeline_break(&settings, watermark, "restore").await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Arc, Mutex};

    use kubidm_proto::backup::{BackupEncryptionConfig, WalArchiveConfig};
    use kubidmd_lib::be::SharedWalArchiver;
    use kubidmd_lib::repl::cid::Cid;
    use kubidmd_lib::repl::wal::{WalArchiver, WalOperationRecord};
    use uuid::Uuid;

    use super::super::test_util::*;
    use super::super::{BaseLocation, PitrArchive, PitrLocation};
    use crate::backup::is_encrypted_artifact;

    #[test]
    fn test_resolve_target() {
        let m = manifest();

        let latest = resolve_target(&m, &RecoveryTargetSpec::Latest).unwrap();
        assert_eq!(latest.ts, Duration::from_secs(600));
        assert!(!latest.clamped_to_latest);

        let t = resolve_target(
            &m,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(250))),
        )
        .unwrap();
        assert_eq!(t.ts, Duration::from_secs(250));
        assert!(!t.clamped_to_latest);

        // After the last record: allowed, flagged.
        let t = resolve_target(
            &m,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(700))),
        )
        .unwrap();
        assert!(t.clamped_to_latest);

        // Before the oldest base: refused.
        assert!(matches!(
            resolve_target(
                &m,
                &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(50)))
            ),
            Err(PitrError::NotRecoverable(_))
        ));

        // Garbage: refused.
        assert!(matches!(
            resolve_target(&m, &RecoveryTargetSpec::Time("yesterday".to_string())),
            Err(PitrError::Target(_))
        ));

        // A CID of this server resolves to its timestamp; another server's is refused.
        let cid = Cid {
            ts: Duration::from_secs(300),
            s_uuid: Uuid::nil(),
        };
        let t = resolve_target(&m, &RecoveryTargetSpec::Cid(cid.to_string())).unwrap();
        assert_eq!(t.ts, Duration::from_secs(300));
        let foreign = Cid {
            ts: Duration::from_secs(300),
            s_uuid: Uuid::new_v4(),
        };
        assert!(matches!(
            resolve_target(&m, &RecoveryTargetSpec::Cid(foreign.to_string())),
            Err(PitrError::Target(_))
        ));

        // No base backup at all: nothing is recoverable.
        let empty = PitrManifest::new(Uuid::nil());
        assert!(matches!(
            resolve_target(&empty, &RecoveryTargetSpec::Latest),
            Err(PitrError::NotRecoverable(_))
        ));
    }

    #[test]
    fn test_plan_recovery_selects_base_and_segments() {
        let m = manifest();

        let plan = plan_recovery(
            &m,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(250))),
        )
        .unwrap();
        assert_eq!(plan.base.key, "backup-1");
        let ids: Vec<&str> = plan
            .segments
            .iter()
            .map(|s| s.segment_id.as_str())
            .collect();
        assert_eq!(ids, vec!["s1", "s2"]);

        // At exactly the watermark of backup-2 that base is used; s2 straddles the
        // watermark and is read, its records filtered.
        let plan = plan_recovery(
            &m,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(400))),
        )
        .unwrap();
        assert_eq!(plan.base.key, "backup-2");
        let ids: Vec<&str> = plan
            .segments
            .iter()
            .map(|s| s.segment_id.as_str())
            .collect();
        assert_eq!(ids, vec!["s2"]);

        let plan = plan_recovery(&m, &RecoveryTargetSpec::Latest).unwrap();
        assert_eq!(plan.base.key, "backup-2");
        let ids: Vec<&str> = plan
            .segments
            .iter()
            .map(|s| s.segment_id.as_str())
            .collect();
        assert_eq!(ids, vec!["s2", "s3"]);
    }

    #[test]
    fn test_records_to_replay_skip_watermark_target_and_abandoned_history() {
        let mut m = manifest();
        let record = |secs: u64| WalEntryRecord {
            cid_ts: Duration::from_secs(secs).as_nanos() as u64,
            cid_server: Uuid::nil(),
            entry_id: secs,
            entry_uuid: Uuid::new_v4(),
            operation: WalOperationRecord::Delete,
        };
        let entries: Vec<WalEntryRecord> = [90, 100, 150, 250, 350, 500]
            .into_iter()
            .map(record)
            .collect();

        let plan = plan_recovery(
            &m,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(350))),
        )
        .unwrap();
        let ids: Vec<u64> = records_to_replay(&m, &plan, &entries)
            .map(|r| r.entry_id)
            .collect();
        assert_eq!(ids, vec![150, 250, 350]);

        // A recovery to 160 abandoned (160, 300]: the record at 250 is never replayed and
        // backup-2 (400) is untouched since it lies after the abandoned range.
        m.add_timeline_break(PitrTimelineBreak {
            after_ts: Duration::from_secs(160),
            until_ts: Duration::from_secs(300),
            at: String::new(),
            reason: "recover".to_string(),
        });
        let plan = plan_recovery(
            &m,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(350))),
        )
        .unwrap();
        assert_eq!(plan.base.key, "backup-1");
        let ids: Vec<u64> = records_to_replay(&m, &plan, &entries)
            .map(|r| r.entry_id)
            .collect();
        assert_eq!(ids, vec![150, 350]);
    }

    fn opened(settings: &PitrSettings, manifest: PitrManifest) -> OpenedArchive {
        let PitrLocation::Local(dir) = &settings.location else {
            panic!("local settings expected");
        };
        OpenedArchive {
            settings: settings.clone(),
            primary: None,
            store: PitrStore::Local { dir: dir.clone() },
            manifest,
            local_only: BTreeSet::new(),
        }
    }

    #[tokio::test]
    async fn test_local_archive_encrypts_segments_and_recovery_decrypts_them() {
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        let backup_dir = dir.path().join("backups");
        fs::create_dir_all(&backup_dir).unwrap();
        let passphrase = dir.path().join("passphrase");
        fs::write(&passphrase, "unit test wal passphrase\n").unwrap();
        let wrong_passphrase = dir.path().join("wrong-passphrase");
        fs::write(&wrong_passphrase, "another passphrase\n").unwrap();

        let server = Uuid::new_v4();
        let wal_cfg = WalArchiveConfig {
            enabled: true,
            s3: None,
            retention_days: 1,
            segment_size_bytes: 1024 * 1024,
            segment_interval_seconds: 60,
            local_path: Some(wal_dir.clone()),
        };
        let archiver: SharedWalArchiver = Arc::new(Mutex::new(
            WalArchiver::new(wal_cfg.clone(), server, wal_dir.clone()).unwrap(),
        ));
        let bases = BaseLocation::Local(backup_dir.clone());
        let plain_settings = PitrSettings {
            wal: wal_cfg,
            local_dir: wal_dir.clone(),
            location: PitrLocation::Local(wal_dir.clone()),
            bases: bases.clone(),
            encryption: BackupEncryptionConfig::default(),
        };
        let encrypted_settings = PitrSettings {
            encryption: fast_encryption(&passphrase),
            ..plain_settings.clone()
        };
        let store = PitrStore::open(&plain_settings.location).await.unwrap();

        // Before encryption is enabled: a base and a plain segment, kept as it is.
        let plain_archive = PitrArchive::new(plain_settings.clone(), archiver.clone());
        let key = "backup-2024-01-01T00:00:00Z.json.gz.enc";
        fs::write(backup_dir.join(key), b"base").unwrap();
        plain_archive
            .register_base_backup(&bases, key, "2024-01-01T00:00:00Z", &report(1000, server))
            .await
            .unwrap();
        append_create(&archiver, server, 1100, b"credential before encryption");
        plain_archive
            .sync(Duration::from_secs(1100), true)
            .await
            .unwrap();
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.segments.len(), 1);
        assert!(manifest.segments[0].encryption_key.is_none());
        assert_eq!(list_segments(&wal_dir).unwrap().len(), 1);

        // The key source is unavailable: nothing is archived in plaintext, the new segment
        // stays where the backend wrote it, and the run fails.
        let unavailable = PitrArchive::new(
            PitrSettings {
                encryption: fast_encryption(&dir.path().join("missing-passphrase")),
                ..plain_settings.clone()
            },
            archiver.clone(),
        );
        append_create(&archiver, server, 1200, b"credential after encryption");
        assert!(matches!(
            unavailable.sync(Duration::from_secs(1200), true).await,
            Err(PitrError::Encryption(_))
        ));
        assert_eq!(list_segments(&wal_dir).unwrap().len(), 2);
        assert_eq!(
            store.load_manifest().await.unwrap().unwrap().segments.len(),
            1
        );

        // With the key: both segments, the one archived before encryption was enabled
        // included, are sealed into `<segment>.enc` and their plaintext copies removed.
        let archive = PitrArchive::new(encrypted_settings.clone(), archiver.clone());
        let report_sync = archive
            .sync(Duration::from_secs(1300), false)
            .await
            .unwrap();
        assert_eq!(report_sync.archived, 2);
        let manifest = store.load_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.segments.len(), 2);
        for segment in &manifest.segments {
            assert_eq!(segment.encryption_key.as_deref(), Some("unit-wal-key"));
            let stored = wal_dir.join(segment.stored_name());
            assert!(stored.to_string_lossy().ends_with(".json.gz.enc"));
            assert!(is_encrypted_artifact(&fs::read(&stored).unwrap()));
            assert!(!wal_dir.join(&segment.segment_id).exists());
        }
        assert!(list_segments(&wal_dir).unwrap().is_empty());
        // A further run has nothing to do.
        let report_sync = archive
            .sync(Duration::from_secs(1400), false)
            .await
            .unwrap();
        assert_eq!(report_sync.archived, 0);

        // Recovery decrypts the segments and checks them against the plaintext checksums.
        let plan = plan_recovery(&manifest, &RecoveryTargetSpec::Latest).unwrap();
        assert_eq!(plan.segments.len(), 2);
        let records = load_records(&opened(&encrypted_settings, manifest.clone()), &plan)
            .await
            .unwrap();
        let payloads: Vec<&[u8]> = records
            .iter()
            .map(|record| match &record.operation {
                WalOperationRecord::Create { entry_data } => entry_data.as_slice(),
                other => panic!("unexpected record {other:?}"),
            })
            .collect();
        assert_eq!(
            payloads,
            vec![
                b"credential before encryption".as_slice(),
                b"credential after encryption".as_slice()
            ]
        );

        // Without encryption enabled, or with another key, recovery refuses with a message
        // naming the key the segment needs.
        match load_records(&opened(&plain_settings, manifest.clone()), &plan).await {
            Err(PitrError::Encryption(msg)) => {
                assert!(
                    msg.contains("unit-wal-key") && msg.contains("not enabled"),
                    "{msg}"
                )
            }
            other => panic!("expected an encryption error, got {other:?}"),
        }
        let wrong_key = PitrSettings {
            encryption: fast_encryption(&wrong_passphrase),
            ..plain_settings.clone()
        };
        assert!(matches!(
            load_records(&opened(&wrong_key, manifest.clone()), &plan).await,
            Err(PitrError::Encryption(_))
        ));

        // A plain file in place of an encrypted segment is refused.
        let swapped = wal_dir.join(manifest.segments[0].stored_name());
        let original = fs::read(&swapped).unwrap();
        fs::write(&swapped, b"not encrypted").unwrap();
        assert!(matches!(
            load_records(&opened(&encrypted_settings, manifest.clone()), &plan).await,
            Err(PitrError::NotRecoverable(msg)) if msg.contains("not an encrypted container")
        ));
        fs::write(&swapped, original).unwrap();

        // Retention deletes the encrypted copy.
        store
            .delete_segment(&wal_dir, &manifest.segments[0])
            .await
            .unwrap();
        assert!(!swapped.exists());
    }
}
