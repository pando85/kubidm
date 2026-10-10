//! Write-ahead log (WAL) archiving for point-in-time recovery (PITR).
//!
//! The archive is *state based*: for every entry a committed write transaction changed,
//! the backend records the full serialised entry (the same `DbEntry` JSON that `id2entry`
//! stores) under the transaction's CID; for every entry it removed, a delete record. Replay
//! is therefore a deterministic overwrite of entries keyed by their UUID, never a replay of
//! operations, and applying a record twice is harmless.
//!
//! Records are grouped into segments. A segment is closed ("rolled") once its records reach
//! `segment_size_bytes` or once it is `segment_interval_seconds` old, and a transaction is
//! never split across two segments. A closed segment is written to the local WAL directory
//! as a gzip compressed JSON file together with a `.meta.json` sidecar that describes it
//! ([`WalSegment`]) so that it can be indexed without being read.
//!
//! This module is synchronous and knows nothing about S3. Uploading closed segments,
//! retention and the recovery commands live in the server core.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use flate2::write::GzEncoder;
use flate2::Compression;
use kubidm_proto::backup::{BackupCompression, WalArchiveConfig, WalSegment};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::repl::cid::Cid;

/// Version of the segment file format. Bumped whenever [`WalSegmentFile`] changes shape.
pub const WAL_SEGMENT_FORMAT_VERSION: u32 = 1;
/// Suffix of a segment file. Segments are always gzip compressed JSON.
pub const WAL_SEGMENT_SUFFIX: &str = ".json.gz";
/// Suffix of the sidecar that describes a segment file.
pub const WAL_SEGMENT_META_SUFFIX: &str = ".meta.json";
/// Prefix of every segment file name.
pub const WAL_SEGMENT_PREFIX: &str = "wal-";
/// Suffix of a segment that is still being written. Never listed or uploaded.
const WAL_TMP_SUFFIX: &str = ".tmp";
/// Marker present in the WAL directory while a segment holds records that only live in
/// memory. Finding it at startup means the previous run stopped without closing that
/// segment, so its records are missing from the archive.
pub const WAL_OPEN_SEGMENT_MARKER: &str = ".open-segment.json";
/// The archive events (gaps) the archive index does not record yet. They are kept on disk
/// from the moment they are noticed until a synchronisation recorded them, so that a crash,
/// or a run of crashes, never forgets one.
pub const WAL_PENDING_EVENTS_FILE: &str = ".pending-events.json";
/// Fixed per record overhead assumed when measuring a segment against `segment_size_bytes`.
const RECORD_OVERHEAD_BYTES: u64 = 96;
/// How many closed segments that could not be written yet are kept in memory. When the
/// WAL directory stays unwritable, the oldest one beyond this is dropped and recorded as a
/// gap, so that memory stays bounded at a few `segment_size_bytes`.
pub const WAL_MAX_UNWRITTEN_SEGMENTS: usize = 4;

/// One archived change: the state of entry `entry_uuid` after the transaction `cid`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalEntryRecord {
    /// Nanoseconds since the epoch of the transaction CID.
    pub cid_ts: u64,
    pub cid_server: Uuid,
    /// The `id2entry` id the entry had on the archiving server. Informational only: a
    /// restored backup renumbers entries, so replay resolves entries by `entry_uuid`.
    pub entry_id: u64,
    pub entry_uuid: Uuid,
    pub operation: WalOperationRecord,
}

impl WalEntryRecord {
    pub fn ts(&self) -> Duration {
        Duration::from_nanos(self.cid_ts)
    }

    pub fn cid(&self) -> Cid {
        Cid {
            ts: self.ts(),
            s_uuid: self.cid_server,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalOperationRecord {
    /// The entry was created; `entry_data` is its full serialised state.
    Create { entry_data: Vec<u8> },
    /// The entry was changed; `entry_data` is its full serialised state.
    Modify { entry_data: Vec<u8> },
    /// The entry was removed from `id2entry` (a reaped tombstone).
    Delete,
    /// Every entry was removed before the records that follow in the same transaction
    /// were written (a replication refresh).
    Truncate,
}

/// A change staged by a write transaction, archived if and when the transaction commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalPendingOp {
    Create {
        entry_uuid: Uuid,
        entry_data: Vec<u8>,
    },
    Modify {
        entry_uuid: Uuid,
        entry_data: Vec<u8>,
    },
    Delete {
        entry_uuid: Uuid,
    },
}

/// The content of a segment file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalSegmentFile {
    pub format_version: u32,
    pub segment_id: String,
    pub server_uuid: Uuid,
    /// Server version that wrote the segment.
    pub server_version: String,
    pub start_ts: Duration,
    pub end_ts: Duration,
    /// In CID order.
    pub entries: Vec<WalEntryRecord>,
}

#[derive(Debug)]
pub enum WalError {
    IoError(std::io::Error),
    SerializationError(String),
    InvalidSegment(String),
    ConfigError(String),
}

impl std::fmt::Display for WalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalError::IoError(e) => write!(f, "WAL IO error: {}", e),
            WalError::SerializationError(msg) => write!(f, "WAL serialization error: {}", msg),
            WalError::InvalidSegment(msg) => write!(f, "Invalid WAL segment: {}", msg),
            WalError::ConfigError(msg) => write!(f, "WAL config error: {}", msg),
        }
    }
}

impl std::error::Error for WalError {}

impl From<std::io::Error> for WalError {
    fn from(e: std::io::Error) -> Self {
        WalError::IoError(e)
    }
}

impl From<serde_json::Error> for WalError {
    fn from(e: serde_json::Error) -> Self {
        WalError::SerializationError(e.to_string())
    }
}

/// CID timestamps whose records are missing from the archive: a transaction that could
/// not be recorded, or the open segment of a run that stopped without closing it.
/// Recovery can not replay across a gap; only a base backup taken after it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalGap {
    /// The first CID timestamp that may be missing.
    pub from_ts: Duration,
    /// The last CID timestamp that may be missing. None when it is unknown, in which case
    /// every CID up to the moment the gap is reported may be missing.
    pub until_ts: Option<Duration>,
    /// Why the records are missing, for the operator.
    pub reason: WalGapReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalGapReason {
    /// A committed transaction could not be recorded.
    ArchiveFailure,
    /// The previous run stopped without closing its open segment.
    UnclosedSegment,
    /// A closed segment could not be written for too long and was dropped.
    UnwritableSegment,
}

impl std::fmt::Display for WalGapReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalGapReason::ArchiveFailure => write!(f, "a committed transaction was not archived"),
            WalGapReason::UnclosedSegment => {
                write!(f, "the server stopped without archiving its open segment")
            }
            WalGapReason::UnwritableSegment => {
                write!(f, "a closed segment could not be written and was dropped")
            }
        }
    }
}

/// What the archiver noticed that the archive index must record: the content of
/// [`WAL_PENDING_EVENTS_FILE`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalPendingEvents {
    /// Gaps, oldest first.
    #[serde(default)]
    pub gaps: Vec<WalGap>,
    /// Changes of the server identity, in the order they happened.
    #[serde(default)]
    pub server_uuid_changes: Vec<WalServerUuidChange>,
}

impl WalPendingEvents {
    pub fn is_empty(&self) -> bool {
        self.gaps.is_empty() && self.server_uuid_changes.is_empty()
    }

    /// Remove the events of `recorded`, each once.
    fn remove(&mut self, recorded: &WalPendingEvents) {
        for gap in &recorded.gaps {
            if let Some(index) = self.gaps.iter().position(|known| known == gap) {
                self.gaps.remove(index);
            }
        }
        for change in &recorded.server_uuid_changes {
            if let Some(index) = self
                .server_uuid_changes
                .iter()
                .position(|known| known == change)
            {
                self.server_uuid_changes.remove(index);
            }
        }
    }
}

/// The database took a new server uuid: from `at_ts` on, its transactions belong to
/// `to`. A replication refresh does this, as it replaces the whole database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalServerUuidChange {
    pub from: Uuid,
    pub to: Uuid,
    /// The CID timestamp of the transaction that changed it.
    pub at_ts: Duration,
}

/// Content of [`WAL_OPEN_SEGMENT_MARKER`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct OpenSegmentMarker {
    start_ts: Duration,
}

/// What the archiver did since it started. Every failure counted here is also logged when
/// it happens, with the running count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalArchiverStats {
    /// Records appended to a segment (closed or still open).
    pub records_archived: u64,
    /// Segments written to the WAL directory.
    pub segments_closed: u64,
    /// Transactions whose records could not be archived. Each one is a hole in the WAL
    /// that only a new base backup closes.
    pub failures: u64,
    /// Attempts to write a closed segment that failed. The records stay in memory and the
    /// write is retried, so nothing is lost unless the server stops first.
    pub flush_failures: u64,
    /// Closed segments dropped because they could not be written for too long. Each one
    /// is a hole in the WAL.
    pub dropped_segments: u64,
}

/// Collects the records of committed transactions into segments and writes closed
/// segments to a local directory.
pub struct WalArchiver {
    config: WalArchiveConfig,
    server_uuid: Uuid,
    segments_path: PathBuf,
    /// The segment that takes the records of the next transactions.
    current_segment: Option<WalSegmentBuilder>,
    /// Closed segments not written yet, oldest first.
    sealed: VecDeque<SealedSegment>,
    /// The start of every segment taken out by [`Self::take_writes`] and not handed back
    /// to [`Self::finish_writes`] yet, by segment id.
    in_flight: BTreeMap<String, Duration>,
    /// After a failed write, commits do not try again before this CID time; the archive
    /// synchronisation always does.
    retry_after: Option<Duration>,
    /// The start the open segment marker on disk records, when there is one.
    marker_start: Option<Duration>,
    stats: WalArchiverStats,
    /// Events not yet recorded by the archive index, mirrored in
    /// [`WAL_PENDING_EVENTS_FILE`].
    pending: WalPendingEvents,
    /// CID timestamp of the last record appended, the lower bound of a gap whose
    /// transaction carried no CID.
    last_ts: Option<Duration>,
}

struct WalSegmentBuilder {
    /// The server whose transactions the segment holds.
    server_uuid: Uuid,
    entries: Vec<WalEntryRecord>,
    start_ts: Duration,
    current_size: u64,
}

impl WalSegmentBuilder {
    fn seal(self) -> SealedSegment {
        let start_ts = self
            .entries
            .first()
            .map(WalEntryRecord::ts)
            .unwrap_or(self.start_ts);
        let end_ts = self
            .entries
            .last()
            .map(WalEntryRecord::ts)
            .unwrap_or(start_ts);
        SealedSegment {
            file: WalSegmentFile {
                format_version: WAL_SEGMENT_FORMAT_VERSION,
                segment_id: segment_file_name(self.server_uuid, start_ts),
                server_uuid: self.server_uuid,
                server_version: env!("KUBIDM_PKG_SERIES").to_string(),
                start_ts,
                end_ts,
                entries: self.entries,
            },
        }
    }
}

/// A closed segment that is not written yet.
pub struct SealedSegment {
    file: WalSegmentFile,
}

/// Closed segments taken out of the archiver by [`WalArchiver::take_writes`], so that they
/// are serialised, compressed and written without holding the archiver lock.
pub struct WalSegmentWrites {
    dir: PathBuf,
    segments: Vec<SealedSegment>,
}

impl WalSegmentWrites {
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Write every segment. Hand the outcome back to [`WalArchiver::finish_writes`].
    pub fn write(self) -> WalSegmentWritten {
        let results = self
            .segments
            .into_iter()
            .map(|sealed| match write_segment_file(&self.dir, &sealed.file) {
                Ok(segment) => Ok(segment),
                Err(err) => Err((Box::new(sealed), err)),
            })
            .collect();
        WalSegmentWritten { results }
    }
}

/// The outcome of [`WalSegmentWrites::write`].
pub struct WalSegmentWritten {
    results: Vec<Result<WalSegment, (Box<SealedSegment>, WalError)>>,
}

/// Lock `archiver`. A thread that panicked while holding the lock does not stop the
/// archiving: every archiver method leaves it consistent before it can fail, so the
/// poisoned lock is taken over.
pub fn lock_archiver(archiver: &Mutex<WalArchiver>) -> MutexGuard<'_, WalArchiver> {
    archiver
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Write the closed segments of `archiver` without holding its lock while they are
/// serialised, compressed and written, so that commits and the archive task never wait
/// on that work. Unless `force`, nothing is tried before the retry delay of an earlier
/// failure ran out (`now` is the clock). Returns the last segment written.
pub fn write_closed_segments(
    archiver: &Mutex<WalArchiver>,
    now: Duration,
    force: bool,
) -> Result<Option<WalSegment>, WalError> {
    let writes = lock_archiver(archiver).take_writes(now, force);
    if writes.is_empty() {
        return Ok(None);
    }
    let written = writes.write();
    lock_archiver(archiver).finish_writes(written, now)
}

impl WalArchiver {
    /// Create an archiver writing to `segments_path`, which is created when it does not
    /// exist and probed for writability so that a misconfiguration fails at startup
    /// rather than at the first commit.
    pub fn new(
        config: WalArchiveConfig,
        server_uuid: Uuid,
        segments_path: PathBuf,
    ) -> Result<Self, WalError> {
        config.validate().map_err(WalError::ConfigError)?;

        fs::create_dir_all(&segments_path)?;
        if !segments_path.is_dir() {
            return Err(WalError::ConfigError(format!(
                "{} is not a directory",
                segments_path.display()
            )));
        }
        let probe = segments_path.join(".write-probe");
        fs::write(&probe, b"").map_err(|err| {
            WalError::ConfigError(format!(
                "WAL directory {} is not writable: {err}",
                segments_path.display()
            ))
        })?;
        let _ = fs::remove_file(&probe);

        // Events an earlier run noticed and no synchronisation recorded yet.
        let mut pending = read_pending_events(&segments_path);

        // A marker left behind means the previous run stopped with records that were never
        // written to a segment. The gap is made durable before the marker goes, so that a
        // crash before the next synchronisation still reports it.
        let marker_path = segments_path.join(WAL_OPEN_SEGMENT_MARKER);
        if let Some(gap) = read_marker_gap(&segments_path) {
            error!(
                from = %format_ts_rfc3339(gap.from_ts),
                "WAL ARCHIVE HOLE: the previous run stopped without archiving its open segment. \
                 Point-in-time recovery can not replay the transactions committed since then \
                 until a new base backup is taken."
            );
            pending.gaps.push(gap);
            write_pending_events(&segments_path, &pending)?;
            fs::remove_file(&marker_path)?;
        }

        info!(
            path = %segments_path.display(),
            segment_size_bytes = config.segment_size_bytes,
            segment_interval_seconds = config.segment_interval_seconds,
            "WAL archiving enabled"
        );

        Ok(Self {
            config,
            server_uuid,
            segments_path,
            current_segment: None,
            sealed: VecDeque::new(),
            in_flight: BTreeMap::new(),
            retry_after: None,
            marker_start: None,
            stats: WalArchiverStats::default(),
            pending,
            last_ts: None,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn config(&self) -> &WalArchiveConfig {
        &self.config
    }

    pub fn server_uuid(&self) -> Uuid {
        self.server_uuid
    }

    pub fn segments_path(&self) -> &Path {
        &self.segments_path
    }

    pub fn stats(&self) -> WalArchiverStats {
        self.stats
    }

    /// Whether records only live in memory: in the open segment, or in a closed one that
    /// is not written yet.
    pub fn has_pending_records(&self) -> bool {
        self.in_memory_start().is_some()
    }

    /// Number of records that only live in memory.
    pub fn pending_record_count(&self) -> usize {
        self.current_segment
            .iter()
            .map(|segment| segment.entries.len())
            .chain(self.sealed.iter().map(|sealed| sealed.file.entries.len()))
            .sum()
    }

    /// The CID time of the oldest record that only lives in memory, including the
    /// segments being written right now.
    fn in_memory_start(&self) -> Option<Duration> {
        self.current_segment
            .iter()
            .filter(|segment| !segment.entries.is_empty())
            .map(|segment| segment.start_ts)
            .chain(self.sealed.iter().map(|sealed| sealed.file.start_ts))
            .chain(self.in_flight.values().copied())
            .min()
    }

    /// Count a transaction whose records were lost and remember the gap it leaves. Called
    /// by the backend when staging or appending failed. `cid_ts` is the CID timestamp of
    /// the transaction, when it is known.
    pub fn note_failure(&mut self, cid_ts: Option<Duration>) {
        self.stats.failures += 1;
        self.add_gap(WalGap {
            from_ts: cid_ts.or(self.last_ts).unwrap_or(Duration::ZERO),
            until_ts: cid_ts,
            reason: WalGapReason::ArchiveFailure,
        });
    }

    /// The database took the server uuid `to` in the transaction at `cid_ts` (a
    /// replication refresh). The open segment is closed, since a segment holds the
    /// transactions of one server; the records that follow go to segments of `to`, and the
    /// change is kept on disk until the archive index records it as a boundary recovery
    /// never replays across.
    pub fn change_server_uuid(&mut self, to: Uuid, cid_ts: Option<Duration>) {
        if to == self.server_uuid {
            return;
        }
        self.seal_current();
        let change = WalServerUuidChange {
            from: self.server_uuid,
            to,
            at_ts: cid_ts.or(self.last_ts).unwrap_or(Duration::ZERO),
        };
        warn!(
            from = %change.from,
            to = %change.to,
            at = %format_ts_rfc3339(change.at_ts),
            "The server uuid changed; the WAL archive continues under the new one, and \
             point-in-time recovery past this point needs a base backup taken after it"
        );
        self.server_uuid = to;
        self.pending.server_uuid_changes.push(change);
        self.persist_pending();
    }

    /// Remember `gap` until the archive index records it, on disk first.
    fn add_gap(&mut self, gap: WalGap) {
        self.pending.gaps.push(gap);
        self.persist_pending();
    }

    /// Write the pending events to [`WAL_PENDING_EVENTS_FILE`]. A failure is logged; the
    /// events stay in memory and are written again with the next event or at shutdown.
    fn persist_pending(&mut self) {
        if let Err(err) = write_pending_events(&self.segments_path, &self.pending) {
            error!(
                %err,
                "Unable to keep the WAL archive gaps on disk; a crash before the next \
                 archive synchronisation would forget them"
            );
        }
    }

    /// The events the archive index must record. Once it did, hand them to
    /// [`Self::acknowledge_events`]; until then they stay pending, on disk as well.
    pub fn pending_events(&self) -> WalPendingEvents {
        self.pending.clone()
    }

    /// Forget the events of `recorded`, which the archive index now records. Events noticed
    /// since they were taken stay pending.
    pub fn acknowledge_events(&mut self, recorded: &WalPendingEvents) -> Result<(), WalError> {
        if recorded.is_empty() {
            return Ok(());
        }
        self.pending.remove(recorded);
        write_pending_events(&self.segments_path, &self.pending)
    }

    /// At the end of a run: make sure the events the archive index does not record yet
    /// are on disk, so that the next [`WalArchiver::new`] reports them again. Call after the
    /// last flush.
    pub fn defer_gaps_to_next_start(&mut self) -> Result<(), WalError> {
        write_pending_events(&self.segments_path, &self.pending)
    }

    /// Make the open segment marker match the records that only live in memory: present
    /// with the start of the oldest of them, absent when there are none. A failure is
    /// logged and retried with the next change.
    fn sync_marker(&mut self) {
        let wanted = self.in_memory_start();
        if wanted == self.marker_start {
            return;
        }
        let result = match wanted {
            Some(start_ts) => serde_json::to_vec(&OpenSegmentMarker { start_ts })
                .map_err(WalError::from)
                .and_then(|data| {
                    write_file_durably(&self.segments_path, WAL_OPEN_SEGMENT_MARKER, &data)
                }),
            None => match fs::remove_file(self.segments_path.join(WAL_OPEN_SEGMENT_MARKER)) {
                Ok(()) => sync_dir(&self.segments_path),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err.into()),
            },
        };
        match result {
            Ok(()) => self.marker_start = wanted,
            Err(err) => warn!(
                %err,
                "Unable to update the WAL open segment marker; a crash before the records in \
                 memory are written may go unnoticed"
            ),
        }
    }

    #[cfg(test)]
    pub fn record_create(
        &mut self,
        cid: &Cid,
        entry_id: u64,
        entry_uuid: Uuid,
        entry_data: Vec<u8>,
    ) -> Result<Option<WalSegment>, WalError> {
        self.append_transaction(
            cid,
            false,
            [(
                entry_id,
                WalPendingOp::Create {
                    entry_uuid,
                    entry_data,
                },
            )],
        )
    }

    #[cfg(test)]
    pub fn record_modify(
        &mut self,
        cid: &Cid,
        entry_id: u64,
        entry_uuid: Uuid,
        entry_data: Vec<u8>,
    ) -> Result<Option<WalSegment>, WalError> {
        self.append_transaction(
            cid,
            false,
            [(
                entry_id,
                WalPendingOp::Modify {
                    entry_uuid,
                    entry_data,
                },
            )],
        )
    }

    #[cfg(test)]
    pub fn record_delete(
        &mut self,
        cid: &Cid,
        entry_id: u64,
        entry_uuid: Uuid,
    ) -> Result<Option<WalSegment>, WalError> {
        self.append_transaction(
            cid,
            false,
            [(entry_id, WalPendingOp::Delete { entry_uuid })],
        )
    }

    /// Append the changes of one committed transaction and write the segments that it
    /// closed, holding the caller's lock throughout. See [`Self::stage_transaction`];
    /// [`write_closed_segments`] does the writing without the lock. Returns the last
    /// segment written by this call, if any.
    pub fn append_transaction<I>(
        &mut self,
        cid: &Cid,
        truncate: bool,
        ops: I,
    ) -> Result<Option<WalSegment>, WalError>
    where
        I: IntoIterator<Item = (u64, WalPendingOp)>,
    {
        self.stage_transaction(cid, truncate, ops);
        self.write_due(cid.ts, false)
    }

    /// Append the changes of one committed transaction. All records share `cid` and land
    /// in the same segment. The current segment is closed first when it is older than the
    /// segment interval (the transaction CID is the clock), and closed afterwards when the
    /// appended records took it over the size limit. Closed segments wait in memory until
    /// they are written ([`Self::take_writes`]).
    pub fn stage_transaction<I>(&mut self, cid: &Cid, truncate: bool, ops: I)
    where
        I: IntoIterator<Item = (u64, WalPendingOp)>,
    {
        if !self.is_enabled() {
            return;
        }
        self.seal_if_stale(cid.ts);

        let mut records: Vec<WalEntryRecord> = Vec::new();
        if truncate {
            records.push(WalEntryRecord {
                cid_ts: cid.ts.as_nanos() as u64,
                cid_server: cid.s_uuid,
                entry_id: 0,
                entry_uuid: Uuid::nil(),
                operation: WalOperationRecord::Truncate,
            });
        }
        for (entry_id, op) in ops {
            let (entry_uuid, operation) = match op {
                WalPendingOp::Create {
                    entry_uuid,
                    entry_data,
                } => (entry_uuid, WalOperationRecord::Create { entry_data }),
                WalPendingOp::Modify {
                    entry_uuid,
                    entry_data,
                } => (entry_uuid, WalOperationRecord::Modify { entry_data }),
                WalPendingOp::Delete { entry_uuid } => (entry_uuid, WalOperationRecord::Delete),
            };
            records.push(WalEntryRecord {
                cid_ts: cid.ts.as_nanos() as u64,
                cid_server: cid.s_uuid,
                entry_id,
                entry_uuid,
                operation,
            });
        }
        if records.is_empty() {
            return;
        }

        let server_uuid = self.server_uuid;
        let segment = self
            .current_segment
            .get_or_insert_with(|| WalSegmentBuilder {
                server_uuid,
                entries: Vec::new(),
                start_ts: cid.ts,
                current_size: 0,
            });
        for record in records {
            segment.current_size += estimate_record_size(&record);
            segment.entries.push(record);
            self.stats.records_archived += 1;
        }
        self.last_ts = Some(cid.ts);

        if segment.current_size >= self.config.segment_size_bytes {
            self.seal_current();
        }
        // The records only live in memory until their segment is written.
        self.sync_marker();
    }

    /// Close the current segment when it was opened at least one segment interval before
    /// `now`. Returns whether it was closed.
    pub fn seal_if_stale(&mut self, now: Duration) -> bool {
        let stale = self.current_segment.as_ref().is_some_and(|segment| {
            !segment.entries.is_empty() && now >= segment.start_ts + self.config.segment_interval()
        });
        stale && self.seal_current()
    }

    /// Close the current segment; it is written by the next [`Self::take_writes`]. Returns
    /// whether there was a segment with records to close.
    pub fn seal_current(&mut self) -> bool {
        match self.current_segment.take() {
            Some(builder) if !builder.entries.is_empty() => {
                self.sealed.push_back(builder.seal());
                self.drop_unwritable_backlog();
                true
            }
            _ => false,
        }
    }

    /// Take the closed segments out to be written, unless a failed write asked commits to
    /// wait (`now` is the clock) and `force` is false. Every segment taken must be handed
    /// back to [`Self::finish_writes`].
    pub fn take_writes(&mut self, now: Duration, force: bool) -> WalSegmentWrites {
        let waiting = self
            .retry_after
            .is_some_and(|retry_after| now < retry_after);
        let segments: Vec<SealedSegment> = if force || !waiting {
            self.sealed.drain(..).collect()
        } else {
            Vec::new()
        };
        for sealed in &segments {
            self.in_flight
                .insert(sealed.file.segment_id.clone(), sealed.file.start_ts);
        }
        WalSegmentWrites {
            dir: self.segments_path.clone(),
            segments,
        }
    }

    /// Account for segments written outside the lock. A segment that could not be written
    /// goes back in line, and commits wait one segment interval before trying again.
    /// Returns the last segment written, or the first error.
    pub fn finish_writes(
        &mut self,
        written: WalSegmentWritten,
        now: Duration,
    ) -> Result<Option<WalSegment>, WalError> {
        let mut last = None;
        let mut first_err = None;
        for result in written.results {
            match result {
                Ok(segment) => {
                    self.in_flight.remove(&segment.segment_id);
                    self.stats.segments_closed += 1;
                    info!(
                        segment = %segment.segment_id,
                        entries = segment.entry_count,
                        size_bytes = segment.size_bytes,
                        "WAL segment closed"
                    );
                    last = Some(segment);
                }
                Err((sealed, err)) => {
                    self.in_flight.remove(&sealed.file.segment_id);
                    self.stats.flush_failures += 1;
                    error!(
                        %err,
                        segment = %sealed.file.segment_id,
                        flush_failures = self.stats.flush_failures,
                        "Unable to write a closed WAL segment to {}; its records are kept in \
                         memory and the write is retried",
                        self.segments_path.display()
                    );
                    let index = self
                        .sealed
                        .iter()
                        .position(|queued| queued.file.start_ts > sealed.file.start_ts)
                        .unwrap_or(self.sealed.len());
                    self.sealed.insert(index, *sealed);
                    first_err.get_or_insert(err);
                }
            }
        }
        if first_err.is_some() {
            self.retry_after = Some(now + self.config.segment_interval());
            self.drop_unwritable_backlog();
        } else {
            self.retry_after = None;
        }
        self.sync_marker();
        match first_err {
            Some(err) => Err(err),
            None => Ok(last),
        }
    }

    /// Write the closed segments while holding the caller's lock. See
    /// [`write_closed_segments`].
    fn write_due(&mut self, now: Duration, force: bool) -> Result<Option<WalSegment>, WalError> {
        let writes = self.take_writes(now, force);
        if writes.is_empty() {
            return Ok(None);
        }
        let written = writes.write();
        self.finish_writes(written, now)
    }

    /// Drop the oldest closed segments beyond [`WAL_MAX_UNWRITTEN_SEGMENTS`] and record
    /// each as a gap: writing keeps failing, and holding them would grow memory without
    /// bound.
    fn drop_unwritable_backlog(&mut self) {
        while self.sealed.len() > WAL_MAX_UNWRITTEN_SEGMENTS {
            let Some(dropped) = self.sealed.pop_front() else {
                break;
            };
            self.stats.dropped_segments += 1;
            error!(
                segment = %dropped.file.segment_id,
                records = dropped.file.entries.len(),
                from = %format_ts_rfc3339(dropped.file.start_ts),
                until = %format_ts_rfc3339(dropped.file.end_ts),
                "WAL ARCHIVE HOLE: a closed segment could not be written to {} for too long and \
                 was dropped; point-in-time recovery can not replay its transactions until a \
                 new base backup is taken",
                self.segments_path.display()
            );
            self.add_gap(WalGap {
                from_ts: dropped.file.start_ts,
                until_ts: Some(dropped.file.end_ts),
                reason: WalGapReason::UnwritableSegment,
            });
        }
        self.sync_marker();
    }

    /// Close the current segment when it is stale and write every closed segment, holding
    /// the caller's lock. Returns the last segment written.
    pub fn flush_if_stale(&mut self, now: Duration) -> Result<Option<WalSegment>, WalError> {
        self.seal_if_stale(now);
        self.write_due(now, true)
    }

    /// Close the current segment and write every closed segment to the WAL directory,
    /// holding the caller's lock. Returns the last segment written, or None when no
    /// record was pending. A segment that can not be written stays in memory, so that a
    /// later call retries it.
    pub fn flush_current_segment(&mut self) -> Result<Option<WalSegment>, WalError> {
        self.seal_current();
        let now = self.last_ts.unwrap_or_default();
        self.write_due(now, true)
    }
}

fn estimate_record_size(record: &WalEntryRecord) -> u64 {
    let data_len = match &record.operation {
        WalOperationRecord::Create { entry_data } | WalOperationRecord::Modify { entry_data } => {
            entry_data.len() as u64
        }
        WalOperationRecord::Delete | WalOperationRecord::Truncate => 0,
    };
    RECORD_OVERHEAD_BYTES + data_len
}

/// The file name of the segment of `server_uuid` starting at `start_ts`. The timestamp
/// is zero padded so that lexical order is CID order.
pub fn segment_file_name(server_uuid: Uuid, start_ts: Duration) -> String {
    format!(
        "{WAL_SEGMENT_PREFIX}{server_uuid}-{:020}{WAL_SEGMENT_SUFFIX}",
        start_ts.as_nanos()
    )
}

/// The server and start of the segment whose file name is `name`, when `name` is exactly
/// a name [`segment_file_name`] produces. Segment ids read from sidecars and manifests are
/// checked with it before they are joined to a path, so that none can name a file outside
/// the WAL directory.
pub fn parse_segment_file_name(name: &str) -> Option<(Uuid, Duration)> {
    let rest = name
        .strip_prefix(WAL_SEGMENT_PREFIX)?
        .strip_suffix(WAL_SEGMENT_SUFFIX)?;
    let (server_uuid, start_nanos) = rest.rsplit_once('-')?;
    let server_uuid = Uuid::parse_str(server_uuid).ok()?;
    let start_ts = Duration::from_nanos(start_nanos.parse().ok()?);
    (segment_file_name(server_uuid, start_ts) == name).then_some((server_uuid, start_ts))
}

/// Whether `name` is the file name of a closed segment.
pub fn is_wal_segment_name(name: &str) -> bool {
    parse_segment_file_name(name).is_some()
}

fn check_segment_id(segment_id: &str) -> Result<(), WalError> {
    if is_wal_segment_name(segment_id) {
        Ok(())
    } else {
        Err(WalError::InvalidSegment(format!(
            "'{segment_id}' is not a WAL segment name"
        )))
    }
}

/// The sidecar path of the segment `segment_id` in `dir`.
pub fn segment_meta_path(dir: &Path, segment_id: &str) -> PathBuf {
    dir.join(format!("{segment_id}{WAL_SEGMENT_META_SUFFIX}"))
}

/// Atomically replace `dir/name` with `data`: written to a temporary file that is synced
/// before it is renamed, then the directory is synced, so that after a crash the file is
/// either the old or the new content, never a torn one.
pub fn write_file_durably(dir: &Path, name: &str, data: &[u8]) -> Result<(), WalError> {
    let path = dir.join(name);
    let tmp = dir.join(format!("{name}{WAL_TMP_SUFFIX}"));
    let mut file = fs::File::create(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, &path)?;
    sync_dir(dir)
}

/// Sync the directory `dir`, so that a rename or removal in it survives a crash.
pub fn sync_dir(dir: &Path) -> Result<(), WalError> {
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// The events left in [`WAL_PENDING_EVENTS_FILE`] in `dir`. A file that can not be read is
/// reported as a gap over all of history, since what it held is unknown.
pub fn read_pending_events(dir: &Path) -> WalPendingEvents {
    let path = dir.join(WAL_PENDING_EVENTS_FILE);
    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return WalPendingEvents::default()
        }
        Err(err) => {
            error!(%err, path = %path.display(), "Unable to read the pending WAL archive events");
            return unreadable_pending_events();
        }
    };
    serde_json::from_slice(&data).unwrap_or_else(|err| {
        error!(%err, path = %path.display(), "Unable to parse the pending WAL archive events");
        unreadable_pending_events()
    })
}

fn unreadable_pending_events() -> WalPendingEvents {
    WalPendingEvents {
        gaps: vec![WalGap {
            from_ts: Duration::ZERO,
            until_ts: None,
            reason: WalGapReason::ArchiveFailure,
        }],
        server_uuid_changes: Vec::new(),
    }
}

/// Write `events` to [`WAL_PENDING_EVENTS_FILE`] in `dir`, or remove the file when there
/// are none.
pub fn write_pending_events(dir: &Path, events: &WalPendingEvents) -> Result<(), WalError> {
    if events.is_empty() {
        return match fs::remove_file(dir.join(WAL_PENDING_EVENTS_FILE)) {
            Ok(()) => sync_dir(dir),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        };
    }
    write_file_durably(dir, WAL_PENDING_EVENTS_FILE, &serde_json::to_vec(events)?)
}

/// The events left in `dir` by a server that is not running: those it never had recorded,
/// and the gap of the open segment it stopped without closing.
pub fn read_local_events(dir: &Path) -> WalPendingEvents {
    let mut events = read_pending_events(dir);
    events.gaps.extend(read_marker_gap(dir));
    events
}

/// Forget the events [`read_local_events`] returned, once the archive index records them.
pub fn clear_local_events(dir: &Path) -> Result<(), WalError> {
    write_pending_events(dir, &WalPendingEvents::default())?;
    match fs::remove_file(dir.join(WAL_OPEN_SEGMENT_MARKER)) {
        Ok(()) => sync_dir(dir),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Hand `change` to the next archiver started on `dir`, for an offline command that put a
/// database with another server uuid in place.
pub fn add_pending_server_uuid_change(
    dir: &Path,
    change: WalServerUuidChange,
) -> Result<(), WalError> {
    fs::create_dir_all(dir)?;
    let mut events = read_pending_events(dir);
    if !events.server_uuid_changes.contains(&change) {
        events.server_uuid_changes.push(change);
    }
    write_pending_events(dir, &events)
}

/// The gap the open segment marker left in `dir` by a run that stopped without closing
/// its segment, if there is one. Its end is unknown.
pub fn read_marker_gap(dir: &Path) -> Option<WalGap> {
    let marker_path = dir.join(WAL_OPEN_SEGMENT_MARKER);
    if !marker_path.exists() {
        return None;
    }
    let from_ts = fs::read(&marker_path)
        .ok()
        .and_then(|data| serde_json::from_slice::<OpenSegmentMarker>(&data).ok())
        .map(|marker| marker.start_ts)
        .unwrap_or(Duration::ZERO);
    Some(WalGap {
        from_ts,
        until_ts: None,
        reason: WalGapReason::UnclosedSegment,
    })
}

/// Serialise, compress, checksum and atomically write `file` and its sidecar into `dir`.
/// Both are synced to disk before the sidecar exists, so that a sidecar never describes a
/// segment file a crash tore.
pub fn write_segment_file(dir: &Path, file: &WalSegmentFile) -> Result<WalSegment, WalError> {
    check_segment_id(&file.segment_id)?;
    let serialized = serde_json::to_vec(file)?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&serialized)?;
    let compressed = encoder.finish()?;
    let segment = describe_segment(file, &compressed);

    write_file_durably(dir, &file.segment_id, &compressed)?;
    write_file_durably(
        dir,
        &format!("{}{WAL_SEGMENT_META_SUFFIX}", file.segment_id),
        &serde_json::to_vec_pretty(&segment)?,
    )?;

    debug!(segment = %file.segment_id, "WAL segment written");
    Ok(segment)
}

/// The sidecar of the segment `file` whose compressed content is `compressed`.
fn describe_segment(file: &WalSegmentFile, compressed: &[u8]) -> WalSegment {
    WalSegment {
        segment_id: file.segment_id.clone(),
        server_uuid: file.server_uuid,
        start_ts: file.start_ts,
        end_ts: file.end_ts,
        first_cid: file
            .entries
            .first()
            .map(|r| r.cid().to_string())
            .unwrap_or_default(),
        last_cid: file
            .entries
            .last()
            .map(|r| r.cid().to_string())
            .unwrap_or_default(),
        entry_count: file.entries.len() as u64,
        checksum_sha256: hex::encode(Sha256::digest(compressed)),
        size_bytes: compressed.len() as u64,
        compression: BackupCompression::Gzip,
        server_version: file.server_version.clone(),
        created_at: format_ts_rfc3339(file.end_ts),
        // The backend always writes the plaintext segment; the archive encrypts it.
        encryption_key: None,
    }
}

/// The closed segments of a WAL directory.
#[derive(Debug, Default)]
pub struct WalSegmentScan {
    /// From their sidecars, in CID order.
    pub segments: Vec<WalSegment>,
    /// Ids of the segments whose sidecar can not be read.
    pub unreadable: Vec<String>,
}

/// The closed segments in `dir`, from their sidecars, in CID order. A segment file
/// without a sidecar, a sidecar without its segment file, a file still being written, and
/// a sidecar whose name is not the one of the segment it describes are skipped. A sidecar
/// that can not be read is an error, since its segment would silently be missing.
pub fn list_segments(dir: &Path) -> Result<Vec<WalSegment>, WalError> {
    let scan = scan_segments(dir)?;
    match scan.unreadable.first() {
        Some(segment_id) => Err(WalError::InvalidSegment(format!(
            "the sidecar of segment {segment_id} in {} is not readable",
            dir.display()
        ))),
        None => Ok(scan.segments),
    }
}

/// [`list_segments`], reporting the segments whose sidecar can not be read instead of
/// failing.
pub fn scan_segments(dir: &Path) -> Result<WalSegmentScan, WalError> {
    let mut scan = WalSegmentScan::default();
    if !dir.exists() {
        return Ok(scan);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(segment_id) = name.strip_suffix(WAL_SEGMENT_META_SUFFIX) else {
            continue;
        };
        if !path.is_file() {
            continue;
        }
        if !is_wal_segment_name(segment_id) {
            warn!(path = %path.display(), "Not a WAL segment sidecar, skipping");
            continue;
        }
        let segment: WalSegment = match fs::read(&path)
            .map_err(WalError::from)
            .and_then(|data| serde_json::from_slice(&data).map_err(WalError::from))
        {
            Ok(segment) => segment,
            Err(err) => {
                error!(%err, path = %path.display(), "WAL segment sidecar is not readable");
                scan.unreadable.push(segment_id.to_string());
                continue;
            }
        };
        if segment.segment_id != segment_id {
            warn!(
                path = %path.display(),
                segment = %segment.segment_id,
                "WAL sidecar describes another segment than its name, skipping"
            );
            continue;
        }
        if !dir.join(segment_id).is_file() {
            debug!(
                segment = %segment.segment_id,
                "WAL sidecar without segment file, skipping"
            );
            continue;
        }
        scan.segments.push(segment);
    }
    scan.segments.sort_by(|a, b| {
        a.start_ts
            .cmp(&b.start_ts)
            .then(a.segment_id.cmp(&b.segment_id))
    });
    scan.unreadable.sort();
    Ok(scan)
}

/// Write the sidecar of the segment `segment_id` in `dir` again from the segment file,
/// when the file is a complete segment (its gzip trailer checks the content).
pub fn rebuild_sidecar(dir: &Path, segment_id: &str) -> Result<WalSegment, WalError> {
    check_segment_id(segment_id)?;
    let compressed = fs::read(dir.join(segment_id))?;
    let file = parse_segment(&compressed, BackupCompression::Gzip)?;
    if file.segment_id != segment_id {
        return Err(WalError::InvalidSegment(format!(
            "segment file {segment_id} holds segment {}",
            file.segment_id
        )));
    }
    let segment = describe_segment(&file, &compressed);
    write_file_durably(
        dir,
        &format!("{segment_id}{WAL_SEGMENT_META_SUFFIX}"),
        &serde_json::to_vec_pretty(&segment)?,
    )?;
    Ok(segment)
}

/// Suffix of a segment file or sidecar moved aside because it is damaged.
pub const WAL_QUARANTINE_SUFFIX: &str = ".corrupt";

/// Move the segment `segment_id` and its sidecar aside in `dir`, so that a damaged segment
/// no longer holds up the ones after it. The files are kept for inspection.
pub fn quarantine_segment(dir: &Path, segment_id: &str) -> Result<(), WalError> {
    check_segment_id(segment_id)?;
    for name in [
        segment_id.to_string(),
        format!("{segment_id}{WAL_SEGMENT_META_SUFFIX}"),
    ] {
        let path = dir.join(&name);
        if path.exists() {
            fs::rename(&path, dir.join(format!("{name}{WAL_QUARANTINE_SUFFIX}")))?;
        }
    }
    sync_dir(dir)
}

/// Remove the segment `segment_id` and its sidecar from `dir`.
pub fn remove_segment(dir: &Path, segment_id: &str) -> Result<(), WalError> {
    check_segment_id(segment_id)?;
    let segment_path = dir.join(segment_id);
    if segment_path.exists() {
        fs::remove_file(&segment_path)?;
    }
    let meta_path = segment_meta_path(dir, segment_id);
    if meta_path.exists() {
        fs::remove_file(&meta_path)?;
    }
    Ok(())
}

/// Parse the content of a segment file.
pub fn parse_segment(
    data: &[u8],
    compression: BackupCompression,
) -> Result<WalSegmentFile, WalError> {
    let decompressed = match compression {
        BackupCompression::Gzip => {
            let mut decoder = flate2::read::GzDecoder::new(data);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            decompressed
        }
        BackupCompression::NoCompression => data.to_vec(),
    };

    let file: WalSegmentFile = serde_json::from_slice(&decompressed)?;
    if file.format_version != WAL_SEGMENT_FORMAT_VERSION {
        return Err(WalError::InvalidSegment(format!(
            "segment {} has format version {}, this server reads version {}",
            file.segment_id, file.format_version, WAL_SEGMENT_FORMAT_VERSION
        )));
    }
    Ok(file)
}

/// Read and parse the segment file at `path`.
#[cfg(test)]
pub fn read_segment_file(path: &Path) -> Result<WalSegmentFile, WalError> {
    let data = fs::read(path)?;
    parse_segment(&data, BackupCompression::identify_file(path))
}

/// The records of `records` with `after_ts < cid_ts <= up_to_ts`, in their original order.
pub fn select_records<'a>(
    records: &'a [WalEntryRecord],
    after_ts: Duration,
    up_to_ts: Duration,
) -> impl Iterator<Item = &'a WalEntryRecord> + 'a {
    records
        .iter()
        .filter(move |record| record.ts() > after_ts && record.ts() <= up_to_ts)
}

/// Parse an RFC3339 recovery target into a duration since the epoch.
pub fn parse_recovery_target_time(timestamp: &str) -> Result<Duration, WalError> {
    let dt = OffsetDateTime::parse(timestamp, &Rfc3339)
        .map_err(|e| WalError::InvalidSegment(format!("Invalid timestamp format: {}", e)))?;
    let nanos = dt.unix_timestamp_nanos();
    if nanos < 0 {
        return Err(WalError::InvalidSegment(format!(
            "Timestamp {timestamp} is before the epoch"
        )));
    }
    Ok(Duration::from_nanos(nanos as u64))
}

/// Parse a CID as printed by the server (`<nanos>-<server uuid>`).
pub fn parse_recovery_target_cid(cid_str: &str) -> Result<Cid, WalError> {
    let Some((ts_str, uuid_str)) = cid_str.split_once('-') else {
        return Err(WalError::InvalidSegment(format!(
            "Invalid CID format: {}",
            cid_str
        )));
    };

    let ts_nanos: u64 = ts_str
        .parse()
        .map_err(|_| WalError::InvalidSegment("Invalid timestamp in CID".to_string()))?;

    let s_uuid = Uuid::parse_str(uuid_str)
        .map_err(|_| WalError::InvalidSegment("Invalid UUID in CID".to_string()))?;

    Ok(Cid {
        ts: Duration::from_nanos(ts_nanos),
        s_uuid,
    })
}

/// Render a duration since the epoch as an RFC3339 UTC timestamp.
pub fn format_ts_rfc3339(ts: Duration) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(ts.as_nanos() as i128)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| format!("{}ns", ts.as_nanos()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> WalArchiveConfig {
        WalArchiveConfig {
            enabled: true,
            s3: None,
            retention_days: 7,
            segment_size_bytes: 1024 * 1024,
            segment_interval_seconds: 300,
            local_path: None,
        }
    }

    fn cid(server: Uuid, secs: u64) -> Cid {
        Cid {
            ts: Duration::from_secs(secs),
            s_uuid: server,
        }
    }

    fn archiver(config: WalArchiveConfig, server: Uuid) -> (tempfile::TempDir, WalArchiver) {
        let dir = tempfile::tempdir().unwrap();
        let archiver = WalArchiver::new(config, server, dir.path().join("wal")).unwrap();
        (dir, archiver)
    }

    #[test]
    fn test_archiver_new_creates_and_probes_directory() {
        let server = Uuid::new_v4();
        let (dir, mut archiver) = archiver(test_config(), server);
        assert!(archiver.segments_path().is_dir());
        assert!(archiver.is_enabled());
        assert_eq!(archiver.server_uuid(), server);
        assert!(!archiver.has_pending_records());
        assert!(dir.path().join("wal").is_dir());
        assert!(!dir.path().join("wal").join(".write-probe").exists());
        assert!(archiver.flush_current_segment().unwrap().is_none());

        let invalid = WalArchiveConfig {
            segment_size_bytes: 0,
            ..test_config()
        };
        assert!(matches!(
            WalArchiver::new(invalid, server, dir.path().join("wal2")),
            Err(WalError::ConfigError(_))
        ));

        // A file where the directory should be is rejected.
        std::fs::write(dir.path().join("file"), b"x").unwrap();
        assert!(WalArchiver::new(test_config(), server, dir.path().join("file")).is_err());
    }

    #[test]
    fn test_disabled_archiver_records_nothing() {
        let server = Uuid::new_v4();
        let (_dir, mut archiver) = archiver(
            WalArchiveConfig {
                enabled: false,
                ..test_config()
            },
            server,
        );
        assert!(archiver
            .record_create(&cid(server, 1), 1, Uuid::new_v4(), vec![1])
            .unwrap()
            .is_none());
        assert!(!archiver.has_pending_records());
        assert_eq!(archiver.stats().records_archived, 0);
    }

    #[test]
    fn test_segment_roundtrip_preserves_records_cid_and_bytes() {
        let server = Uuid::new_v4();
        let (_dir, mut archiver) = archiver(test_config(), server);
        let u1 = Uuid::new_v4();
        let u2 = Uuid::new_v4();
        let txn1 = cid(server, 10);
        let txn2 = cid(server, 11);

        assert!(archiver
            .record_create(&txn1, 1, u1, b"entry-1".to_vec())
            .unwrap()
            .is_none());
        assert!(archiver
            .append_transaction(
                &txn2,
                false,
                vec![
                    (
                        1,
                        WalPendingOp::Modify {
                            entry_uuid: u1,
                            entry_data: b"entry-1-v2".to_vec()
                        }
                    ),
                    (2, WalPendingOp::Delete { entry_uuid: u2 }),
                ],
            )
            .unwrap()
            .is_none());
        assert_eq!(archiver.pending_record_count(), 3);
        assert_eq!(archiver.stats().records_archived, 3);

        let segment = archiver.flush_current_segment().unwrap().unwrap();
        assert!(!archiver.has_pending_records());
        assert_eq!(archiver.stats().segments_closed, 1);
        assert_eq!(segment.server_uuid, server);
        assert_eq!(segment.start_ts, Duration::from_secs(10));
        assert_eq!(segment.end_ts, Duration::from_secs(11));
        assert_eq!(segment.entry_count, 3);
        assert_eq!(segment.first_cid, txn1.to_string());
        assert_eq!(segment.last_cid, txn2.to_string());
        assert_eq!(segment.compression, BackupCompression::Gzip);
        assert_eq!(segment.server_version, env!("KUBIDM_PKG_SERIES"));
        assert_eq!(
            segment.segment_id,
            segment_file_name(server, Duration::from_secs(10))
        );
        assert!(is_wal_segment_name(&segment.segment_id));

        let path = archiver.segments_path().join(&segment.segment_id);
        let data = std::fs::read(&path).unwrap();
        assert_eq!(data.len() as u64, segment.size_bytes);
        assert_eq!(hex::encode(Sha256::digest(&data)), segment.checksum_sha256);

        let file = read_segment_file(&path).unwrap();
        assert_eq!(file.format_version, WAL_SEGMENT_FORMAT_VERSION);
        assert_eq!(file.entries.len(), 3);
        assert_eq!(file.entries[0].cid(), txn1);
        assert_eq!(file.entries[0].entry_uuid, u1);
        assert_eq!(file.entries[0].entry_id, 1);
        assert_eq!(
            file.entries[0].operation,
            WalOperationRecord::Create {
                entry_data: b"entry-1".to_vec()
            }
        );
        assert_eq!(file.entries[1].cid(), txn2);
        assert_eq!(
            file.entries[1].operation,
            WalOperationRecord::Modify {
                entry_data: b"entry-1-v2".to_vec()
            }
        );
        assert_eq!(file.entries[2].entry_uuid, u2);
        assert_eq!(file.entries[2].operation, WalOperationRecord::Delete);

        // The sidecar describes the same segment and the listing finds it.
        let listed = list_segments(archiver.segments_path()).unwrap();
        assert_eq!(listed, vec![segment.clone()]);

        remove_segment(archiver.segments_path(), &segment.segment_id).unwrap();
        assert!(list_segments(archiver.segments_path()).unwrap().is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn test_truncate_record_comes_first() {
        let server = Uuid::new_v4();
        let (_dir, mut archiver) = archiver(test_config(), server);
        let u1 = Uuid::new_v4();
        archiver
            .append_transaction(
                &cid(server, 5),
                true,
                vec![(
                    1,
                    WalPendingOp::Create {
                        entry_uuid: u1,
                        entry_data: b"e".to_vec(),
                    },
                )],
            )
            .unwrap();
        let segment = archiver.flush_current_segment().unwrap().unwrap();
        let file = read_segment_file(&archiver.segments_path().join(segment.segment_id)).unwrap();
        assert_eq!(file.entries.len(), 2);
        assert_eq!(file.entries[0].operation, WalOperationRecord::Truncate);
        assert_eq!(file.entries[0].entry_uuid, Uuid::nil());
        assert!(matches!(
            file.entries[1].operation,
            WalOperationRecord::Create { .. }
        ));
    }

    #[test]
    fn test_segment_rolls_by_size_after_whole_transaction() {
        let server = Uuid::new_v4();
        let (_dir, mut archiver) = archiver(
            WalArchiveConfig {
                segment_size_bytes: 300,
                ..test_config()
            },
            server,
        );

        // One transaction with two records of 100 bytes each: 2 * (96 + 100) >= 300, so
        // the segment is closed right after the transaction, holding both records.
        let rolled = archiver
            .append_transaction(
                &cid(server, 1),
                false,
                vec![
                    (
                        1,
                        WalPendingOp::Create {
                            entry_uuid: Uuid::new_v4(),
                            entry_data: vec![1; 100],
                        },
                    ),
                    (
                        2,
                        WalPendingOp::Create {
                            entry_uuid: Uuid::new_v4(),
                            entry_data: vec![2; 100],
                        },
                    ),
                ],
            )
            .unwrap()
            .expect("segment must roll by size");
        assert_eq!(rolled.entry_count, 2);
        assert!(!archiver.has_pending_records());

        // A small transaction stays pending.
        assert!(archiver
            .record_delete(&cid(server, 2), 3, Uuid::new_v4())
            .unwrap()
            .is_none());
        assert!(archiver.has_pending_records());
        assert_eq!(archiver.stats().segments_closed, 1);
    }

    #[test]
    fn test_segment_rolls_by_time() {
        let server = Uuid::new_v4();
        let (_dir, mut archiver) = archiver(
            WalArchiveConfig {
                segment_interval_seconds: 60,
                ..test_config()
            },
            server,
        );

        archiver
            .record_create(&cid(server, 100), 1, Uuid::new_v4(), vec![1])
            .unwrap();
        archiver
            .record_create(&cid(server, 130), 2, Uuid::new_v4(), vec![2])
            .unwrap();

        // Not stale yet.
        assert!(archiver
            .flush_if_stale(Duration::from_secs(159))
            .unwrap()
            .is_none());
        assert_eq!(archiver.pending_record_count(), 2);

        // A transaction one interval after the segment opened closes it first; the new
        // transaction opens the next segment.
        let rolled = archiver
            .record_create(&cid(server, 160), 3, Uuid::new_v4(), vec![3])
            .unwrap()
            .expect("segment must roll by time");
        assert_eq!(rolled.entry_count, 2);
        assert_eq!(rolled.start_ts, Duration::from_secs(100));
        assert_eq!(rolled.end_ts, Duration::from_secs(130));
        assert_eq!(archiver.pending_record_count(), 1);

        // The periodic check closes a stale segment without a new transaction.
        let rolled = archiver
            .flush_if_stale(Duration::from_secs(220))
            .unwrap()
            .expect("stale segment must be flushed");
        assert_eq!(rolled.entry_count, 1);
        assert_eq!(rolled.start_ts, Duration::from_secs(160));
        assert!(!archiver.has_pending_records());

        let listed = list_segments(archiver.segments_path()).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed[0].start_ts < listed[1].start_ts);
    }

    #[test]
    fn test_unclosed_segment_is_reported_as_a_gap_at_the_next_start() {
        let server = Uuid::new_v4();
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        let marker = wal_dir.join(WAL_OPEN_SEGMENT_MARKER);

        let mut archiver = WalArchiver::new(test_config(), server, wal_dir.clone()).unwrap();
        assert!(archiver.pending_events().is_empty());
        assert!(!marker.exists());

        // The first record of a segment leaves the marker behind until the segment closes.
        archiver
            .record_create(&cid(server, 10), 1, Uuid::new_v4(), vec![1])
            .unwrap();
        assert!(marker.exists());
        archiver
            .record_create(&cid(server, 11), 2, Uuid::new_v4(), vec![2])
            .unwrap();
        archiver.flush_current_segment().unwrap().unwrap();
        assert!(!marker.exists());

        // A run that stops with records in memory leaves the marker; the next start
        // reports everything from the first of those records on as missing, and keeps
        // that gap on disk instead of the marker.
        archiver
            .record_create(&cid(server, 20), 3, Uuid::new_v4(), vec![3])
            .unwrap();
        drop(archiver);
        let mut restarted = WalArchiver::new(test_config(), server, wal_dir.clone()).unwrap();
        assert!(!marker.exists());
        assert!(wal_dir.join(WAL_PENDING_EVENTS_FILE).is_file());
        let unclosed = WalGap {
            from_ts: Duration::from_secs(20),
            until_ts: None,
            reason: WalGapReason::UnclosedSegment,
        };
        assert_eq!(restarted.pending_events().gaps, vec![unclosed]);

        // Recorded gaps are acknowledged; one noticed meanwhile stays pending.
        let recorded = restarted.pending_events();
        restarted.note_failure(Some(Duration::from_secs(30)));
        restarted.acknowledge_events(&recorded).unwrap();
        assert_eq!(
            restarted.pending_events().gaps,
            vec![WalGap {
                from_ts: Duration::from_secs(30),
                until_ts: Some(Duration::from_secs(30)),
                reason: WalGapReason::ArchiveFailure,
            }]
        );
        assert_eq!(restarted.stats().failures, 1);
        let recorded = restarted.pending_events();
        restarted.acknowledge_events(&recorded).unwrap();
        assert!(restarted.pending_events().is_empty());
        assert!(!wal_dir.join(WAL_PENDING_EVENTS_FILE).exists());
    }

    #[test]
    fn test_gaps_survive_repeated_crashes_before_they_are_recorded() {
        let server = Uuid::new_v4();
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");

        // Crash with records of 100 in memory.
        let mut archiver = WalArchiver::new(test_config(), server, wal_dir.clone()).unwrap();
        archiver
            .record_create(&cid(server, 100), 1, Uuid::new_v4(), vec![1])
            .unwrap();
        drop(archiver);

        // The next run reports [100, ...) but never records it (the archive is
        // unreachable), commits at 200, and crashes again before closing that segment.
        let mut second = WalArchiver::new(test_config(), server, wal_dir.clone()).unwrap();
        assert_eq!(second.pending_events().gaps.len(), 1);
        second
            .record_create(&cid(server, 200), 2, Uuid::new_v4(), vec![2])
            .unwrap();
        second.note_failure(Some(Duration::from_secs(250)));
        drop(second);

        // Every hole is still reported: the first one was not replaced by the later marker.
        let third = WalArchiver::new(test_config(), server, wal_dir).unwrap();
        let starts: Vec<(Duration, WalGapReason)> = third
            .pending_events()
            .gaps
            .iter()
            .map(|gap| (gap.from_ts, gap.reason))
            .collect();
        assert_eq!(
            starts,
            vec![
                (Duration::from_secs(100), WalGapReason::UnclosedSegment),
                (Duration::from_secs(250), WalGapReason::ArchiveFailure),
                (Duration::from_secs(200), WalGapReason::UnclosedSegment),
            ]
        );
    }

    #[test]
    fn test_unreadable_pending_events_are_reported_as_a_gap_over_all_history() {
        let server = Uuid::new_v4();
        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(wal_dir.join(WAL_PENDING_EVENTS_FILE), b"{ torn").unwrap();
        let archiver = WalArchiver::new(test_config(), server, wal_dir).unwrap();
        let gaps = archiver.pending_events().gaps;
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].from_ts, Duration::ZERO);
        assert_eq!(gaps[0].until_ts, None);
    }

    #[test]
    fn test_failure_without_cid_starts_the_gap_at_the_last_record() {
        let server = Uuid::new_v4();
        let (_dir, mut archiver) = archiver(test_config(), server);
        archiver.note_failure(None);
        assert_eq!(archiver.pending_events().gaps[0].from_ts, Duration::ZERO);

        archiver
            .record_create(&cid(server, 40), 1, Uuid::new_v4(), vec![1])
            .unwrap();
        archiver.note_failure(None);
        let gaps = archiver.pending_events().gaps;
        assert_eq!(gaps[1].from_ts, Duration::from_secs(40));
        assert_eq!(gaps[1].until_ts, None);
    }

    /// Make every write to the WAL directory of `archiver` fail: the directory is replaced
    /// by a file. Returns the function that puts the directory back.
    fn break_wal_dir(archiver: &WalArchiver) -> impl FnOnce() {
        let dir = archiver.segments_path().to_path_buf();
        let aside = dir.with_extension("aside");
        fs::rename(&dir, &aside).unwrap();
        fs::write(&dir, b"not a directory").unwrap();
        move || {
            fs::remove_file(&dir).unwrap();
            fs::rename(&aside, &dir).unwrap();
        }
    }

    #[test]
    fn test_failed_flush_keeps_the_records_and_retries() {
        let server = Uuid::new_v4();
        let (_dir, mut archiver) = archiver(
            WalArchiveConfig {
                segment_size_bytes: 1,
                segment_interval_seconds: 60,
                ..test_config()
            },
            server,
        );
        let repair = break_wal_dir(&archiver);

        // The size limit is reached, the write fails, nothing is lost or reported as lost.
        let rolled = archiver
            .record_create(&cid(server, 5), 1, Uuid::new_v4(), vec![1])
            .unwrap_err();
        assert!(matches!(rolled, WalError::IoError(_)));
        assert_eq!(archiver.pending_record_count(), 1);
        assert_eq!(archiver.stats().flush_failures, 1);
        assert_eq!(archiver.stats().failures, 0);
        assert!(archiver.pending_events().is_empty());

        // Commits within the retry delay do not try again: each one costs no compression of
        // the backlog. They are kept as separate closed segments.
        for secs in 6..8 {
            assert!(archiver
                .record_create(&cid(server, secs), secs, Uuid::new_v4(), vec![1])
                .unwrap()
                .is_none());
        }
        assert_eq!(archiver.stats().flush_failures, 1);
        assert_eq!(archiver.pending_record_count(), 3);

        // A forced write (the archive synchronisation) always tries, each segment once.
        assert!(archiver.flush_current_segment().is_err());
        assert_eq!(archiver.stats().flush_failures, 4);
        assert_eq!(archiver.pending_record_count(), 3);

        // Once the obstacle is gone, the next commit after the delay writes every segment.
        repair();
        let rolled = archiver
            .record_create(&cid(server, 70), 70, Uuid::new_v4(), vec![2])
            .unwrap()
            .expect("the retried segments must be written");
        assert_eq!(rolled.start_ts, Duration::from_secs(70));
        assert!(!archiver.has_pending_records());
        let listed = list_segments(archiver.segments_path()).unwrap();
        assert_eq!(listed.len(), 4);
        assert!(!archiver
            .segments_path()
            .join(WAL_OPEN_SEGMENT_MARKER)
            .exists());
    }

    #[test]
    fn test_unwritable_backlog_is_bounded_and_recorded_as_gaps() {
        let server = Uuid::new_v4();
        let (_dir, mut archiver) = archiver(
            WalArchiveConfig {
                segment_size_bytes: 1,
                ..test_config()
            },
            server,
        );
        let repair = break_wal_dir(&archiver);

        // Every transaction closes a segment that can not be written. Beyond the limit,
        // the oldest is dropped and its range becomes a gap.
        let extra = 3;
        let total = WAL_MAX_UNWRITTEN_SEGMENTS as u64 + extra;
        for secs in 1..=total {
            let _ = archiver.record_create(&cid(server, secs), secs, Uuid::new_v4(), vec![1]);
        }
        assert_eq!(archiver.pending_record_count(), WAL_MAX_UNWRITTEN_SEGMENTS);
        assert_eq!(archiver.stats().dropped_segments, extra);
        let gaps = archiver.pending_events().gaps;
        assert_eq!(
            gaps,
            (1..=extra)
                .map(|secs| WalGap {
                    from_ts: Duration::from_secs(secs),
                    until_ts: Some(Duration::from_secs(secs)),
                    reason: WalGapReason::UnwritableSegment,
                })
                .collect::<Vec<_>>()
        );

        // The kept segments are written once the directory is back; the gaps are on disk.
        repair();
        archiver.flush_current_segment().unwrap();
        assert!(!archiver.has_pending_records());
        assert_eq!(
            list_segments(archiver.segments_path()).unwrap().len(),
            WAL_MAX_UNWRITTEN_SEGMENTS
        );
        archiver.defer_gaps_to_next_start().unwrap();
        assert_eq!(
            read_pending_events(archiver.segments_path()).gaps.len(),
            extra as usize
        );
    }

    #[test]
    fn test_segments_are_written_outside_the_archiver_lock() {
        let server = Uuid::new_v4();
        let (_dir, mut archiver) = archiver(
            WalArchiveConfig {
                segment_size_bytes: 1,
                ..test_config()
            },
            server,
        );
        archiver.stage_transaction(
            &cid(server, 1),
            false,
            [(
                1,
                WalPendingOp::Create {
                    entry_uuid: Uuid::new_v4(),
                    entry_data: vec![1],
                },
            )],
        );
        let shared = Mutex::new(archiver);
        // While the closed segment is out being written, the lock is free and the records
        // are still covered by the open segment marker.
        let writes = lock_archiver(&shared).take_writes(Duration::from_secs(1), false);
        assert!(!writes.is_empty());
        {
            let archiver = lock_archiver(&shared);
            assert!(archiver.has_pending_records());
            assert!(archiver
                .segments_path()
                .join(WAL_OPEN_SEGMENT_MARKER)
                .exists());
        }
        let written = writes.write();
        let segment = lock_archiver(&shared)
            .finish_writes(written, Duration::from_secs(1))
            .unwrap()
            .unwrap();
        let archiver = lock_archiver(&shared);
        assert_eq!(segment.entry_count, 1);
        assert!(!archiver.has_pending_records());
        assert!(!archiver
            .segments_path()
            .join(WAL_OPEN_SEGMENT_MARKER)
            .exists());
        // Nothing left: the helper has nothing to do.
        drop(archiver);
        assert!(
            write_closed_segments(&shared, Duration::from_secs(2), false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_list_segments_skips_incomplete_files() {
        let dir = tempfile::tempdir().unwrap();
        assert!(list_segments(&dir.path().join("missing"))
            .unwrap()
            .is_empty());

        let server = Uuid::new_v4();
        let file = WalSegmentFile {
            format_version: WAL_SEGMENT_FORMAT_VERSION,
            segment_id: segment_file_name(server, Duration::from_secs(1)),
            server_uuid: server,
            server_version: "test".to_string(),
            start_ts: Duration::from_secs(1),
            end_ts: Duration::from_secs(1),
            entries: vec![],
        };
        let segment = write_segment_file(dir.path(), &file).unwrap();
        assert_eq!(list_segments(dir.path()).unwrap().len(), 1);

        // A sidecar whose segment file vanished is skipped.
        std::fs::remove_file(dir.path().join(&segment.segment_id)).unwrap();
        assert!(list_segments(dir.path()).unwrap().is_empty());

        // A segment file without a sidecar is skipped too.
        std::fs::remove_file(segment_meta_path(dir.path(), &segment.segment_id)).unwrap();
        std::fs::write(dir.path().join(&segment.segment_id), b"x").unwrap();
        assert!(list_segments(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn test_segment_ids_from_files_never_leave_the_wal_directory() {
        let server = Uuid::new_v4();
        let name = segment_file_name(server, Duration::from_secs(7));
        assert_eq!(
            parse_segment_file_name(&name),
            Some((server, Duration::from_secs(7)))
        );
        for bad in [
            "../kubidm.db",
            "wal-../../etc/passwd.json.gz",
            &format!("../{name}"),
            &format!("{name}/x"),
            &name.replace(".json.gz", ".json"),
            &name.replace('-', "_"),
        ] {
            assert!(!is_wal_segment_name(bad), "{bad}");
        }

        let dir = tempfile::tempdir().unwrap();
        let wal_dir = dir.path().join("wal");
        fs::create_dir_all(&wal_dir).unwrap();
        let outside = dir.path().join("kubidm.db");
        fs::write(&outside, b"database").unwrap();

        // A sidecar naming a file outside the directory is not listed, and nothing removes
        // or quarantines a file by such a name.
        let mut forged = describe_segment(
            &WalSegmentFile {
                format_version: WAL_SEGMENT_FORMAT_VERSION,
                segment_id: name.clone(),
                server_uuid: server,
                server_version: "test".to_string(),
                start_ts: Duration::from_secs(7),
                end_ts: Duration::from_secs(7),
                entries: vec![],
            },
            b"x",
        );
        forged.segment_id = "../kubidm.db".to_string();
        fs::write(
            wal_dir.join(format!("{name}{WAL_SEGMENT_META_SUFFIX}")),
            serde_json::to_vec(&forged).unwrap(),
        )
        .unwrap();
        fs::write(wal_dir.join(&name), b"x").unwrap();
        assert!(list_segments(&wal_dir).unwrap().is_empty());
        assert!(remove_segment(&wal_dir, "../kubidm.db").is_err());
        assert!(quarantine_segment(&wal_dir, "../kubidm.db").is_err());
        assert!(outside.is_file());
    }

    #[test]
    fn test_damaged_sidecars_are_reported_rebuilt_and_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let server = Uuid::new_v4();
        let write = |secs: u64| {
            write_segment_file(
                dir.path(),
                &WalSegmentFile {
                    format_version: WAL_SEGMENT_FORMAT_VERSION,
                    segment_id: segment_file_name(server, Duration::from_secs(secs)),
                    server_uuid: server,
                    server_version: "test".to_string(),
                    start_ts: Duration::from_secs(secs),
                    end_ts: Duration::from_secs(secs + 1),
                    entries: vec![],
                },
            )
            .unwrap()
        };
        let intact = write(1);
        let torn = write(2);
        let lost = write(3);
        fs::write(segment_meta_path(dir.path(), &torn.segment_id), b"{").unwrap();
        fs::write(segment_meta_path(dir.path(), &lost.segment_id), b"{").unwrap();
        fs::write(dir.path().join(&lost.segment_id), b"torn").unwrap();

        // Listing fails loudly; scanning reports the unreadable sidecars.
        assert!(list_segments(dir.path()).is_err());
        let scan = scan_segments(dir.path()).unwrap();
        assert_eq!(scan.segments, vec![intact.clone()]);
        assert_eq!(
            scan.unreadable,
            vec![torn.segment_id.clone(), lost.segment_id.clone()]
        );

        // A complete segment file gets its sidecar back; a torn one can only go aside.
        assert_eq!(rebuild_sidecar(dir.path(), &torn.segment_id).unwrap(), torn);
        assert!(rebuild_sidecar(dir.path(), &lost.segment_id).is_err());
        quarantine_segment(dir.path(), &lost.segment_id).unwrap();
        assert!(dir
            .path()
            .join(format!("{}{WAL_QUARANTINE_SUFFIX}", lost.segment_id))
            .is_file());
        assert_eq!(list_segments(dir.path()).unwrap(), vec![intact, torn]);
    }

    #[test]
    fn test_parse_segment_rejects_other_format_versions() {
        let server = Uuid::new_v4();
        let file = WalSegmentFile {
            format_version: WAL_SEGMENT_FORMAT_VERSION + 1,
            segment_id: "x".to_string(),
            server_uuid: server,
            server_version: "test".to_string(),
            start_ts: Duration::ZERO,
            end_ts: Duration::ZERO,
            entries: vec![],
        };
        let data = serde_json::to_vec(&file).unwrap();
        assert!(matches!(
            parse_segment(&data, BackupCompression::NoCompression),
            Err(WalError::InvalidSegment(_))
        ));
        assert!(matches!(
            parse_segment(b"garbage", BackupCompression::NoCompression),
            Err(WalError::SerializationError(_))
        ));
    }

    #[test]
    fn test_select_records_is_exclusive_inclusive() {
        let server = Uuid::new_v4();
        let records: Vec<WalEntryRecord> = [10u64, 20, 30, 40]
            .iter()
            .map(|secs| WalEntryRecord {
                cid_ts: Duration::from_secs(*secs).as_nanos() as u64,
                cid_server: server,
                entry_id: *secs,
                entry_uuid: Uuid::new_v4(),
                operation: WalOperationRecord::Delete,
            })
            .collect();

        let selected: Vec<u64> =
            select_records(&records, Duration::from_secs(20), Duration::from_secs(40))
                .map(|r| r.entry_id)
                .collect();
        assert_eq!(selected, vec![30, 40]);

        let selected: Vec<u64> =
            select_records(&records, Duration::from_secs(0), Duration::from_secs(25))
                .map(|r| r.entry_id)
                .collect();
        assert_eq!(selected, vec![10, 20]);

        assert_eq!(
            select_records(&records, Duration::from_secs(40), Duration::from_secs(50)).count(),
            0
        );
    }

    #[test]
    fn test_parse_recovery_target_time() {
        let ts = parse_recovery_target_time("2024-01-15T10:30:00Z").unwrap();
        assert_eq!(ts, Duration::from_secs(1705314600));
        let ts = parse_recovery_target_time("2024-01-15T10:30:00.123456Z").unwrap();
        assert_eq!(ts.subsec_nanos(), 123_456_000);
        let ts = parse_recovery_target_time("2024-01-15T10:30:00+05:00").unwrap();
        assert_eq!(ts, Duration::from_secs(1705314600 - 5 * 3600));
        assert!(parse_recovery_target_time("not-a-timestamp").is_err());
        assert!(parse_recovery_target_time("1960-01-01T00:00:00Z").is_err());

        assert_eq!(
            format_ts_rfc3339(Duration::from_secs(1705314600)),
            "2024-01-15T10:30:00Z"
        );
    }

    #[test]
    fn test_parse_recovery_target_cid() {
        let uuid = Uuid::new_v4();
        let c = Cid {
            ts: Duration::from_nanos(1000),
            s_uuid: uuid,
        };
        let parsed = parse_recovery_target_cid(&c.to_string()).unwrap();
        assert_eq!(parsed, c);
        assert!(parse_recovery_target_cid("invalid-cid").is_err());
        assert!(parse_recovery_target_cid("1000").is_err());
        assert!(parse_recovery_target_cid("abc-00000000-0000-0000-0000-000000000000").is_err());
    }

    #[test]
    fn test_wal_error_display() {
        let error = WalError::IoError(std::io::Error::new(std::io::ErrorKind::NotFound, "test"));
        assert!(error.to_string().contains("IO error"));
        let error = WalError::SerializationError("test".to_string());
        assert!(error.to_string().contains("serialization error"));
        let error = WalError::InvalidSegment("test".to_string());
        assert!(error.to_string().contains("Invalid WAL segment"));
        let error = WalError::ConfigError("test".to_string());
        assert!(error.to_string().contains("config error"));
        let wal_error: WalError = serde_json::from_str::<WalEntryRecord>("x")
            .unwrap_err()
            .into();
        assert!(matches!(wal_error, WalError::SerializationError(_)));
    }
}
