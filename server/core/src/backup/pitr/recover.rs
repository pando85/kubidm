//! Recovery: planning, reading the archive, and the `pitr-list` and `recover` commands.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::time::Duration;

use kubidm_proto::backup::{
    is_encrypted_backup_name, PitrBaseBackup, PitrManifest, PitrServerUuidChange,
    PitrTimelineBreak, WalSegment, PITR_MANIFEST_KEY,
};
use kubidm_proto::internal::OperationError;
use kubidmd_lib::be::WalApplyReport;
use kubidmd_lib::prelude::duration_from_epoch_now;
use kubidmd_lib::repl::wal::{
    clear_local_events, defer_restore, format_ts_rfc3339, list_segments, parse_recovery_target_cid,
    parse_recovery_target_time, parse_segment, read_local_events, scan_segments, WalEntryRecord,
    WalOperationRecord, WalPendingEvents, WalRestore,
};
use uuid::Uuid;

use super::archive::{manifest_gap, manifest_uuid_change};
use super::store::{PitrStore, SegmentKeys};
use super::{blocking, PitrError, PitrLocation, PitrSettings};
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
            if !manifest.knows_server(cid.s_uuid) {
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
    if let Some(change) = manifest.identity_change_blocking(&base, resolved.ts) {
        let latest = manifest
            .latest_recoverable_ts()
            .map(format_ts_rfc3339)
            .unwrap_or_else(|| "none".to_string());
        return Err(PitrError::NotRecoverable(format!(
            "the server changed its identity from {} to {} at {} ({}); the state after it \
             does not follow from base backup {} and the history before it. Choose a target \
             before the change (the latest recoverable point is {latest}), or one after a base \
             backup taken after it",
            change.from_server_uuid,
            change.to_server_uuid,
            format_ts_rfc3339(change.at_ts),
            change.reason,
            base.key,
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

/// Whether a recovery to `plan` replays `record`: it lies after the base watermark, at or
/// before the target, and not in history a restore or recovery abandoned.
pub fn is_replayed(manifest: &PitrManifest, plan: &RecoveryPlan, record: &WalEntryRecord) -> bool {
    record.ts() > plan.base.watermark_ts
        && record.ts() <= plan.target.ts
        && !manifest.is_abandoned(record.ts())
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
    /// Whether the WAL archive records the history the recovery abandoned. When it does
    /// not, the database was still recovered, and the server records it once it reaches
    /// the archive, when the recovery could hand it over.
    pub archive_updated: bool,
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

    // Recovery can only start from the base backups the location actually holds: a region
    // prunes its copies on its own, and a base may have been deleted, or lost its sidecar,
    // since it was indexed. When they can not be listed, the index is used as it is and
    // fetching a missing base fails the recovery.
    match settings.bases.list_keys().await {
        Ok(held) => {
            let indexed = manifest.base_backups.len();
            manifest.retain_base_backups(&held);
            if manifest.base_backups.len() != indexed {
                warn!(
                    missing = indexed - manifest.base_backups.len(),
                    bases = %settings.bases,
                    "Base backups indexed by the archive are missing or incomplete and are not \
                     used"
                );
            }
        }
        Err(err) => warn!(
            %err,
            bases = %settings.bases,
            "Unable to list the base backups; using every base the archive indexes"
        ),
    }

    // Gaps and changes of identity the server noticed and no manifest records yet still
    // bound what can be recovered.
    let local_events = {
        let local_dir = settings.local_dir.clone();
        blocking(move || Ok(read_local_events(&local_dir))).await?
    };
    fold_local_events(&mut manifest, &local_events, duration_from_epoch_now());

    let mut local_only = BTreeSet::new();
    let local_segments = {
        let local_dir = settings.local_dir.clone();
        blocking(move || Ok(list_segments(&local_dir)?)).await?
    };
    for segment in local_segments {
        if !manifest.knows_server(segment.server_uuid) || manifest.has_segment(&segment.segment_id)
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

/// Add the events a server left in its WAL directory to `manifest`: the restores the
/// archive did not record yet first, since everything else happened after them. A gap
/// whose end is unknown ends at `now`. A change of identity that does not follow from the
/// manifest's is kept as a boundary only.
pub(super) fn fold_local_events(
    manifest: &mut PitrManifest,
    events: &WalPendingEvents,
    now: Duration,
) {
    for restore in &events.restores {
        apply_restore(manifest, restore);
    }
    for gap in &events.gaps {
        manifest.add_gap(manifest_gap(gap, now));
    }
    let changes = PitrManifest {
        server_uuid_changes: events
            .server_uuid_changes
            .iter()
            .map(manifest_uuid_change)
            .collect(),
        ..PitrManifest::new(manifest.server_uuid)
    };
    manifest.merge_markers(&changes);
}

/// Record `restore` in `manifest`: what the stopped server left behind, the abandoned
/// history, and the change of identity to the restored database's server uuid. Recording a
/// restore the manifest already records changes nothing. Returns the change of identity
/// recorded, if any.
pub(super) fn apply_restore(
    manifest: &mut PitrManifest,
    restore: &WalRestore,
) -> Option<PitrServerUuidChange> {
    let at = format_ts_rfc3339(restore.at);
    if manifest
        .timeline_breaks
        .iter()
        .any(|known| known.after_ts == restore.after_ts && known.at == at)
    {
        return None;
    }

    // What the stopped server left in the WAL directory and no manifest records yet: the
    // gaps (its unclosed segment included, which ends at the restore, inside the abandoned
    // history) and its changes of identity. They belong to the history before the restore,
    // and the server started on the restored database must not report them as its own.
    fold_local_events(manifest, &restore.abandoned, restore.at);

    // The abandoned history also covers any CID the archive holds, in case the clock of
    // the old server was ahead.
    let until_ts = manifest
        .segments
        .iter()
        .map(|s| s.end_ts)
        .chain(manifest.base_backups.iter().map(|b| b.watermark_ts))
        .fold(restore.until_ts, Duration::max);
    manifest.add_timeline_break(PitrTimelineBreak {
        after_ts: restore.after_ts,
        until_ts,
        at,
        reason: restore.reason.clone(),
    });
    if restore.server_uuid == manifest.server_uuid {
        return None;
    }
    let change = PitrServerUuidChange {
        from_server_uuid: manifest.server_uuid,
        to_server_uuid: restore.server_uuid,
        at_ts: until_ts + Duration::from_nanos(1),
        reason: restore.reason.clone(),
    };
    // It starts from the manifest's identity, so it always applies.
    if let Err(err) = manifest.apply_server_uuid_change(&change) {
        error!(%err, "Unable to record the change of server uuid of the restore");
        return None;
    }
    warn!(
        from = %change.from_server_uuid,
        to = %change.to_server_uuid,
        "The database carries another server uuid than the archive; the archive continues \
         under it"
    );
    Some(change)
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

/// The records a recovery replays, reduced while the segments are read, one at a time:
/// replay overwrites every entry with its latest state by uuid, so only that state is
/// kept, and memory follows the number of entries changed rather than the size of the
/// archive.
#[derive(Debug, Default)]
struct ReplaySet {
    latest: BTreeMap<Uuid, WalEntryRecord>,
    /// The records in the replay range, before the reduction.
    total: usize,
    /// The CID timestamp of the last of them.
    last_ts: Option<Duration>,
}

impl ReplaySet {
    fn add(&mut self, record: WalEntryRecord) -> Result<(), PitrError> {
        if record.operation == WalOperationRecord::Truncate {
            return Err(PitrError::NotRecoverable(format!(
                "the archive holds a replication refresh at {} in the range to replay; the \
                 refresh also replaced the identity of the database, which the archive does not \
                 hold. Recover from a base backup taken after it.",
                format_ts_rfc3339(record.ts())
            )));
        }
        self.total += 1;
        self.last_ts = self.last_ts.max(Some(record.ts()));
        let key = |record: &WalEntryRecord| (record.cid_ts, record.entry_id);
        let merged = match self.latest.remove(&record.entry_uuid) {
            None => record,
            Some(known) if key(&known) <= key(&record) => Self::merge(known, record),
            Some(known) => Self::merge(record, known),
        };
        self.latest.insert(merged.entry_uuid, merged);
        Ok(())
    }

    /// The state `older` then `newer` leave an entry in. An entry created after the base
    /// backup stays a create when it is changed again.
    fn merge(older: WalEntryRecord, newer: WalEntryRecord) -> WalEntryRecord {
        match (older.operation, newer.operation) {
            (
                WalOperationRecord::Create { .. },
                WalOperationRecord::Modify { entry_data }
                | WalOperationRecord::Create { entry_data },
            ) => WalEntryRecord {
                operation: WalOperationRecord::Create { entry_data },
                ..newer
            },
            (_, operation) => WalEntryRecord { operation, ..newer },
        }
    }

    /// The records to apply, in CID order.
    fn into_records(self) -> Vec<WalEntryRecord> {
        let mut records: Vec<WalEntryRecord> = self.latest.into_values().collect();
        records.sort_by_key(|record| (record.cid_ts, record.entry_id));
        records
    }
}

/// Fetch and parse the segments of `plan`, one at a time, and collect the records to
/// replay.
async fn load_records(opened: &OpenedArchive, plan: &RecoveryPlan) -> Result<ReplaySet, PitrError> {
    let mut records = ReplaySet::default();
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
        if !opened.manifest.knows_server(file.server_uuid) {
            return Err(PitrError::NotRecoverable(format!(
                "segment {} belongs to server {}, the archive belongs to {}",
                segment.segment_id, file.server_uuid, opened.manifest.server_uuid
            )));
        }
        for record in file.entries {
            if is_replayed(&opened.manifest, plan, &record) {
                records.add(record)?;
            }
        }
    }
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
    let replay = load_records(&opened, &plan).await?;
    let record_count = replay.total;
    let recovered_ts = replay.last_ts.unwrap_or(plan.base.watermark_ts);
    print_plan(&opened, &plan, record_count, recovered_ts);

    if dry_run {
        eprintln!("Dry run: no changes were made.");
        return Ok(RecoveryOutcome {
            plan,
            records: record_count,
            recovered_ts,
            dry_run: true,
            apply: None,
            archive_updated: false,
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
        plan.base.key, record_count
    );
    let committed = crate::backup::restore::restore_and_replay_commit(
        config,
        base.path(),
        replay.into_records(),
    )
    .await
    .map_err(|err| {
        error!(
            ?err,
            "Recovery failed; the database at {db_path} was not changed"
        );
        PitrError::Operation(err)
    })?;
    drop(base);
    let apply = committed.outcome.apply.clone();
    if let Some(report) = &apply {
        info!(
            applied = report.applied,
            created = report.created,
            modified = report.modified,
            deleted = report.deleted,
            "WAL records replayed"
        );
    }

    // The database holds the recovered state from here on: the history after it is
    // abandoned whether or not the steps that follow succeed, so it is recorded first.
    let restored = RestoredDatabase {
        after_ts: recovered_ts,
        server_uuid: committed.outcome.server_uuid,
        reason: "recover",
        now: duration_from_epoch_now(),
    };
    let archive_updated = match record_abandoned_history(&opened, &restored).await {
        Ok(AbandonedHistory::Recorded) => true,
        Ok(AbandonedHistory::Deferred(err)) => {
            warn!(
                %err,
                "The database at {db_path} WAS recovered, but the WAL archive could not be \
                 updated; do not recover it again. The server records the abandoned history in \
                 the archive at its first synchronisation that reaches it."
            );
            false
        }
        Err(err) => {
            error!(
                %err,
                "The database at {db_path} WAS recovered, but the abandoned history could not \
                 be recorded in the WAL archive nor handed to the server; do not recover it \
                 again. A later recovery past this point could replay it: take a new online \
                 backup right after starting the server, and recover only to points after it."
            );
            false
        }
    };

    finish_recovery(config, committed, &db_path, recovered_ts).await?;

    eprintln!(
        "Recovered {db_path} to {} ({} records replayed on {})",
        format_ts_rfc3339(recovered_ts),
        record_count,
        plan.base.key
    );

    Ok(RecoveryOutcome {
        plan,
        records: record_count,
        recovered_ts,
        dry_run: false,
        apply,
        archive_updated,
    })
}

/// The steps of a recovery after its commit: reindex, boot and verify the database
/// recovered to `recovered_ts` at `db_path`.
async fn finish_recovery(
    config: &Configuration,
    committed: crate::backup::restore::CommittedRestore,
    db_path: &str,
    recovered_ts: Duration,
) -> Result<(), PitrError> {
    let recovered_ts = format_ts_rfc3339(recovered_ts);
    committed.reindex(config).await.inspect_err(|err| {
        error!(
            ?err,
            "RECOVERY INCOMPLETE: the database at {db_path} WAS recovered to {recovered_ts}, but \
             reindexing it failed; run `kubidmd database reindex` before starting the server."
        );
    })?;
    info!("Verifying the recovered database ...");
    let consistency_errors = crate::verify_booted_database(config)
        .await
        .inspect_err(|err| {
            error!(
                ?err,
                "RECOVERY INCOMPLETE: the database at {db_path} WAS recovered to \
                 {recovered_ts}, but it could not be verified. Do not start the server on it; \
                 recover to another point or restore a backup."
            );
        })?;
    if consistency_errors.is_empty() {
        return Ok(());
    }
    for err in &consistency_errors {
        error!(?err, "Recovered database consistency error");
    }
    error!(
        "RECOVERY INCOMPLETE: the database at {db_path} WAS recovered to {recovered_ts}, but it \
         failed its verification. Do not start the server on it; recover to another point or \
         restore a backup."
    );
    Err(PitrError::Operation(OperationError::ConsistencyError(
        consistency_errors,
    )))
}

/// Record the history a recovery abandoned in the archive the recovered server archives
/// into and, when the recovery read a replication region, in that region too.
async fn record_abandoned_history(
    opened: &OpenedArchive,
    restored: &RestoredDatabase<'_>,
) -> Result<AbandonedHistory, PitrError> {
    let archive = opened.primary.as_ref().unwrap_or(&opened.settings);
    let restore = prepare_restore(&archive.local_dir, restored).await?;

    // The region the recovery read from. The server mirrors the primary's record to it at
    // its first synchronisation as well; recording it here keeps the region right while
    // the primary is unreachable.
    if opened.primary.is_some() {
        if let Err(err) = record_restore(&opened.settings.location, &restore).await {
            warn!(
                %err,
                region = %opened.settings.location,
                "The abandoned history could not be recorded in the region; the server \
                 mirrors it there once it reaches it"
            );
        }
    }

    let recorded = record_restore(&archive.location, &restore).await;
    settle_restore(&archive.local_dir, restore, recorded).await
}

/// What a restore or recovery did to the database, for the archive.
pub(super) struct RestoredDatabase<'a> {
    /// The CID timestamp the database was restored or recovered to.
    pub after_ts: Duration,
    /// The server uuid the database carries now.
    pub server_uuid: Uuid,
    /// The command, for display.
    pub reason: &'a str,
    pub now: Duration,
}

/// Where the history a restore or recovery abandoned was recorded.
#[derive(Debug)]
pub enum AbandonedHistory {
    /// In the archive.
    Recorded,
    /// The archive could not be updated, for the reason given. The restore was handed to
    /// the server through its WAL directory instead: its first synchronisation that
    /// reaches the archive records it, before archiving anything else.
    Deferred(PitrError),
}

/// The restore described by `restored`, with what the stopped server left in `local_dir`:
/// the events no manifest records yet, and the end of its last unarchived segment.
///
/// A segment whose sidecar can not be read does not stop the restore from being recorded:
/// the abandoned history already reaches to the time of the restore, past anything the
/// stopped server wrote, and the server's next synchronisation rebuilds the sidecar or
/// sets the segment aside.
async fn prepare_restore(
    local_dir: &Path,
    restored: &RestoredDatabase<'_>,
) -> Result<WalRestore, PitrError> {
    let local_dir = local_dir.to_path_buf();
    let (abandoned, scan) =
        blocking(move || Ok((read_local_events(&local_dir), scan_segments(&local_dir)?))).await?;
    if !scan.unreadable.is_empty() {
        warn!(
            segments = %scan.unreadable.join(", "),
            "The sidecars of these WAL segments are not readable; the restore abandons \
             them with the rest of the history, and the server rebuilds the sidecars or sets \
             the segments aside"
        );
    }
    let local_segments = scan.segments;
    // The identity the history in the WAL directory starts with: the one before the first
    // restore or change of identity it records, or else the one of its oldest segment.
    let local_server_uuid = local_segments.first().map(|oldest| {
        abandoned
            .restores
            .first()
            .and_then(|restore| restore.local_server_uuid)
            .or_else(|| {
                abandoned
                    .server_uuid_changes
                    .first()
                    .map(|change| change.from)
            })
            .unwrap_or(oldest.server_uuid)
    });
    Ok(WalRestore {
        after_ts: restored.after_ts,
        until_ts: local_segments
            .iter()
            .map(|s| s.end_ts)
            .fold(restored.now, Duration::max),
        server_uuid: restored.server_uuid,
        local_server_uuid,
        at: restored.now,
        reason: restored.reason.to_string(),
        abandoned,
    })
}

/// Record `restore` in the archive at `location`. An archive with no manifest yet archived
/// no history, but the stopped server may have left some in its WAL directory: the
/// archive then starts with the restore, under the identity of that history, so that it
/// is archived as abandoned. When it left none, nothing is recorded. Returns the change of
/// identity recorded, if any.
async fn record_restore(
    location: &PitrLocation,
    restore: &WalRestore,
) -> Result<Option<PitrServerUuidChange>, PitrError> {
    let store = PitrStore::open(location).await?;
    let mut manifest = match store.load_manifest().await? {
        Some(manifest) => manifest,
        None => match restore.local_server_uuid {
            Some(server_uuid) => PitrManifest::new(server_uuid),
            None => return Ok(None),
        },
    };
    let change = apply_restore(&mut manifest, restore);
    store.save_manifest(&mut manifest, restore.at).await?;
    info!(
        after = %format_ts_rfc3339(restore.after_ts),
        archive = %location,
        "Abandoned history recorded in the PITR archive"
    );
    Ok(change)
}

/// After `restore` was `recorded` in the archive the server archives into (or not):
/// forget the events of the stopped server it took over, or hand it to the server's first
/// synchronisation through `local_dir`. Fails only when neither worked.
async fn settle_restore(
    local_dir: &Path,
    restore: WalRestore,
    recorded: Result<Option<PitrServerUuidChange>, PitrError>,
) -> Result<AbandonedHistory, PitrError> {
    let local_dir = local_dir.to_path_buf();
    match recorded {
        Ok(_) => {
            if !restore.abandoned.is_empty() {
                blocking(move || Ok(clear_local_events(&local_dir)?)).await?;
            }
            Ok(AbandonedHistory::Recorded)
        }
        Err(err) => match blocking(move || Ok(defer_restore(&local_dir, restore)?)).await {
            Ok(()) => Ok(AbandonedHistory::Deferred(err)),
            Err(defer_err) => {
                error!(
                    %defer_err,
                    "Unable to hand the abandoned history to the server through its WAL \
                     directory"
                );
                Err(err)
            }
        },
    }
}

/// Record in the archive at `settings` that the database was restored or recovered to
/// `restored.after_ts`, so that everything archived after that point up to now is never
/// replayed again. When the database now carries another server uuid than the archive (a
/// backup taken before a replication refresh, or one of another server), the archive
/// continues under that identity from the end of the abandoned history on, and the change
/// is a boundary no base backup of another identity replays across.
///
/// When the archive can not be updated, the restore is handed to the server instead, see
/// [`AbandonedHistory::Deferred`]. Fails only when that did not work either.
pub(super) async fn record_timeline_break(
    settings: &PitrSettings,
    restored: &RestoredDatabase<'_>,
) -> Result<AbandonedHistory, PitrError> {
    let restore = prepare_restore(&settings.local_dir, restored).await?;
    let recorded = record_restore(&settings.location, &restore).await;
    settle_restore(&settings.local_dir, restore, recorded).await
}

/// After `kubidmd database restore` or `restore-s3`: when WAL archiving is configured,
/// record that the history after the watermark of the restored backup was abandoned.
/// Without WAL archiving this does nothing.
pub async fn note_restore(
    config: &Configuration,
    watermark: Duration,
    server_uuid: Uuid,
) -> Result<AbandonedHistory, PitrError> {
    let Some(settings) = PitrSettings::from_config(config)? else {
        return Ok(AbandonedHistory::Recorded);
    };
    let restored = RestoredDatabase {
        after_ts: watermark,
        server_uuid,
        reason: "restore",
        now: duration_from_epoch_now(),
    };
    record_timeline_break(&settings, &restored).await
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
    fn test_recovery_honours_gaps_only_the_wal_directory_records() {
        use kubidmd_lib::repl::wal::{WalGap, WalGapReason};
        // The server noticed a hole at 300 but could not record it before it stopped.
        let mut m = manifest();
        let events = WalPendingEvents {
            gaps: vec![WalGap {
                from_ts: Duration::from_secs(300),
                until_ts: None,
                reason: WalGapReason::UnclosedSegment,
            }],
            ..WalPendingEvents::default()
        };
        fold_local_events(&mut m, &events, Duration::from_secs(350));
        assert!(plan_recovery(
            &m,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(320)))
        )
        .is_err());
        plan_recovery(
            &m,
            &RecoveryTargetSpec::Time(format_ts_rfc3339(Duration::from_secs(250))),
        )
        .unwrap();
    }

    #[test]
    fn test_replay_set_keeps_only_the_latest_state_of_each_entry() {
        let created = Uuid::new_v4();
        let changed = Uuid::new_v4();
        let removed = Uuid::new_v4();
        let record = |secs: u64, entry_uuid: Uuid, operation: WalOperationRecord| WalEntryRecord {
            cid_ts: Duration::from_secs(secs).as_nanos() as u64,
            cid_server: Uuid::nil(),
            entry_id: 1,
            entry_uuid,
            operation,
        };
        let data = |bytes: &[u8]| bytes.to_vec();
        let mut replay = ReplaySet::default();
        for added in [
            record(
                10,
                created,
                WalOperationRecord::Create {
                    entry_data: data(b"c1"),
                },
            ),
            // Out of order: an older state never replaces a newer one.
            record(
                30,
                changed,
                WalOperationRecord::Modify {
                    entry_data: data(b"m3"),
                },
            ),
            record(
                20,
                changed,
                WalOperationRecord::Modify {
                    entry_data: data(b"m2"),
                },
            ),
            record(
                40,
                created,
                WalOperationRecord::Modify {
                    entry_data: data(b"c4"),
                },
            ),
            record(
                50,
                removed,
                WalOperationRecord::Modify {
                    entry_data: data(b"r5"),
                },
            ),
            record(60, removed, WalOperationRecord::Delete),
        ] {
            replay.add(added).unwrap();
        }
        assert_eq!(replay.total, 6);
        assert_eq!(replay.last_ts, Some(Duration::from_secs(60)));
        let records = replay.into_records();
        let states: Vec<(Uuid, u64, WalOperationRecord)> = records
            .into_iter()
            .map(|r| (r.entry_uuid, r.ts().as_secs(), r.operation))
            .collect();
        assert_eq!(
            states,
            vec![
                (
                    changed,
                    30,
                    WalOperationRecord::Modify {
                        entry_data: data(b"m3")
                    }
                ),
                // Created after the base backup and changed since: still a create.
                (
                    created,
                    40,
                    WalOperationRecord::Create {
                        entry_data: data(b"c4")
                    }
                ),
                (removed, 60, WalOperationRecord::Delete),
            ]
        );

        // A replication refresh is refused with a message saying what to do.
        let mut replay = ReplaySet::default();
        let err = replay
            .add(record(70, Uuid::nil(), WalOperationRecord::Truncate))
            .unwrap_err();
        assert!(err.to_string().contains("replication refresh"), "{err}");
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
    fn test_replay_skips_watermark_target_and_abandoned_history() {
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
        let ids: Vec<u64> = entries
            .iter()
            .filter(|record| is_replayed(&m, &plan, record))
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
        let ids: Vec<u64> = entries
            .iter()
            .filter(|record| is_replayed(&m, &plan, record))
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
            .register_base_backup_at(
                Duration::from_secs(1000),
                &bases,
                key,
                "2024-01-01T00:00:00Z",
                &report(1000, server),
            )
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
            .unwrap()
            .into_records();
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
