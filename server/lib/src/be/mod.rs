//! The backend. This contains the "low level" storage and query code, which is
//! implemented as a json-like kv document database. This has no rules about content
//! of the server, which are all enforced at higher levels. The role of the backend
//! is to persist content safely to disk, load that content, and execute queries
//! utilising indexes in the most effective way possible.

use crate::{
    be::{
        dbentry::{DbBackup, DbEntry},
        dbrepl::DbReplMeta,
    },
    entry::Entry,
    filter::{Filter, FilterPlan, FilterResolved, FilterValidResolved},
    prelude::*,
    repl::{
        cid::Cid,
        proto::ReplCidRange,
        ruv::{
            ReplicationUpdateVector, ReplicationUpdateVectorReadTransaction,
            ReplicationUpdateVectorTransaction, ReplicationUpdateVectorWriteTransaction,
        },
        wal::{
            lock_archiver, write_closed_segments, WalArchiver, WalEntryRecord, WalOperationRecord,
            WalPendingOp,
        },
    },
    utils::trigraph_iter,
    value::{IndexType, Value},
};
use concread::cowcell::*;
use hashbrown::{HashMap, HashSet};
use idlset::{v2::IDLBitRange, AndNot};
use kubidm_proto::{
    backup::{BackupCompression, WalArchiveConfig},
    internal::{ConsistencyError, OperationError},
};
use std::{
    collections::BTreeMap,
    io::prelude::*,
    ops::DerefMut,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use tracing::{trace, trace_span};
use uuid::Uuid;

use flate2::{write::GzEncoder, Compression};

pub(crate) mod dbentry;
pub(crate) mod dbrepl;
pub(crate) mod dbvalue;

mod idl_arc_sqlite;
mod idl_sqlite;
pub(crate) mod idxkey;
pub(crate) mod keystorage;

pub(crate) use self::idxkey::{IdxKey, IdxKeyRef, IdxKeyToRef, IdxSlope};
use crate::be::idl_arc_sqlite::{
    IdlArcSqlite, IdlArcSqliteReadTransaction, IdlArcSqliteTransaction,
    IdlArcSqliteWriteTransaction,
};
use kubidm_proto::internal::FsType;

// Currently disabled due to improvements in idlset for intersection handling.
const FILTER_SEARCH_TEST_THRESHOLD: usize = 0;
const FILTER_EXISTS_TEST_THRESHOLD: usize = 0;
const FILTER_SUBSTR_TEST_THRESHOLD: usize = 4;

#[derive(Debug, Clone)]
/// Limits on the resources a single event can consume. These are defined per-event
/// as they are derived from the userAuthToken based on that individual session
pub struct Limits {
    pub unindexed_allow: bool,
    pub search_max_results: usize,
    pub search_max_filter_test: usize,
    pub filter_max_elements: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            unindexed_allow: false,
            search_max_results: DEFAULT_LIMIT_SEARCH_MAX_RESULTS as usize,
            search_max_filter_test: DEFAULT_LIMIT_SEARCH_MAX_FILTER_TEST as usize,
            filter_max_elements: DEFAULT_LIMIT_FILTER_MAX_ELEMENTS as usize,
        }
    }
}

impl Limits {
    pub fn unlimited() -> Self {
        Limits {
            unindexed_allow: true,
            search_max_results: usize::MAX >> 1,
            search_max_filter_test: usize::MAX >> 1,
            filter_max_elements: usize::MAX,
        }
    }

    pub fn api_token() -> Self {
        Limits {
            unindexed_allow: false,
            search_max_results: DEFAULT_LIMIT_API_SEARCH_MAX_RESULTS as usize,
            search_max_filter_test: DEFAULT_LIMIT_API_SEARCH_MAX_FILTER_TEST as usize,
            filter_max_elements: DEFAULT_LIMIT_FILTER_MAX_ELEMENTS as usize,
        }
    }
}

/// The result of a key value request containing the list of entry IDs that
/// match the filter/query condition.
#[derive(Debug, Clone)]
pub enum IdList {
    /// The value is not indexed, and must be assumed that all entries may match.
    AllIds,
    /// The index is "fuzzy" like a bloom filter (perhaps superset is a better description) -
    /// it contains all elements that do match, but may have extra elements that don't.
    /// This requires the caller to perform a filter test to assert that all
    /// returned entries match all assertions within the filter.
    Partial(IDLBitRange),
    /// The set was indexed and is below the filter test threshold. This is because it's
    /// now faster to test with the filter than to continue to access indexes at this point.
    /// Like a partial set, this is a super set of the entries that match the query.
    PartialThreshold(IDLBitRange),
    /// The value is indexed and accurately represents the set of entries that precisely match.
    Indexed(IDLBitRange),
}

#[derive(Debug)]
pub struct IdRawEntry {
    id: u64,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct IdxMeta {
    pub idxkeys: HashMap<IdxKey, IdxSlope>,
}

impl IdxMeta {
    pub fn new(idxkeys: HashMap<IdxKey, IdxSlope>) -> Self {
        IdxMeta { idxkeys }
    }
}

/// The outcome of a structural check of a backup artifact.
///
/// A structural check only proves that the artifact parses as a backup, carries entries
/// and was written by a server of this version. It does not prove the backup can be
/// restored. That requires restoring it into a scratch database and verifying the result.
#[derive(Debug, Clone)]
pub struct BackupStructuralReport {
    /// Number of entries the artifact carries.
    pub entry_count: usize,
    /// Server version that wrote the artifact, when the backup format records it.
    pub version: Option<String>,
    /// UUID of the server that wrote the artifact, when the backup format records it.
    pub db_s_uuid: Option<Uuid>,
    /// The CID timestamp watermark of the artifact: the timestamp of the last transaction
    /// it contains. Point-in-time recovery replays the WAL records above it.
    pub db_ts_max: Option<Duration>,
    /// Human readable reasons the artifact can not be restored by this server.
    pub errors: Vec<String>,
    /// The size, in bytes, of the artifact once decompressed (and decrypted): what its
    /// entries take as JSON, read up to where parsing stopped. A restored database is of
    /// that order, plus its indexes.
    pub uncompressed_size: u64,
}

/// Counts the bytes read through it.
struct CountingReader<R> {
    inner: R,
    count: u64,
}

impl<R: std::io::Read> std::io::Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.count = self.count.saturating_add(read as u64);
        Ok(read)
    }
}

impl BackupStructuralReport {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Parse a backup artifact and check its format, entry count and server version
/// without touching any database. An artifact that does not parse is reported as invalid,
/// with the parser's message (line and column) as its error.
pub fn verify_backup_structure<IN>(
    input: IN,
    compression: BackupCompression,
) -> BackupStructuralReport
where
    IN: std::io::Read,
{
    let (dbbak_option, uncompressed_size): (Result<DbBackup, serde_json::Error>, u64) =
        match compression {
            BackupCompression::NoCompression => {
                let mut counting = CountingReader {
                    inner: input,
                    count: 0,
                };
                (serde_json::from_reader(&mut counting), counting.count)
            }
            BackupCompression::Gzip => {
                let mut counting = CountingReader {
                    inner: flate2::read::GzDecoder::new(input),
                    count: 0,
                };
                (serde_json::from_reader(&mut counting), counting.count)
            }
        };

    let dbbak = match dbbak_option {
        Ok(dbbak) => dbbak,
        Err(err) => {
            error!(?err, "Backup artifact could not be parsed");
            return BackupStructuralReport {
                entry_count: 0,
                version: None,
                db_s_uuid: None,
                db_ts_max: None,
                errors: vec![format!(
                    "artifact could not be parsed as a kubidm backup: {err}"
                )],
                uncompressed_size,
            };
        }
    };

    let (entry_count, version, db_s_uuid, db_ts_max) = match &dbbak {
        DbBackup::V1(entries) => (entries.len(), None, None, None),
        DbBackup::V2 {
            entries,
            db_s_uuid,
            db_ts_max,
            ..
        }
        | DbBackup::V3 {
            entries,
            db_s_uuid,
            db_ts_max,
            ..
        }
        | DbBackup::V4 {
            entries,
            db_s_uuid,
            db_ts_max,
            ..
        } => (entries.len(), None, Some(*db_s_uuid), Some(*db_ts_max)),
        DbBackup::V5 {
            version,
            entries,
            db_s_uuid,
            db_ts_max,
            ..
        } => (
            entries.len(),
            Some(version.clone()),
            Some(*db_s_uuid),
            Some(*db_ts_max),
        ),
    };

    let mut errors = Vec::new();

    // Mirror the checks that `restore` applies, so that a structurally valid backup
    // is at least one that `restore` will accept.
    match version.as_deref() {
        Some(env!("KUBIDM_PKG_SERIES")) => {}
        Some(version) => errors.push(format!(
            "Backup was written by server version {} and can not be restored on version {}",
            version,
            env!("KUBIDM_PKG_SERIES")
        )),
        None => errors.push(
            "Backup was written by an older server version that records no version and can not be restored"
                .to_string(),
        ),
    }

    if entry_count == 0 {
        errors.push("Backup contains no entries".to_string());
    }

    BackupStructuralReport {
        entry_count,
        version,
        db_s_uuid,
        db_ts_max,
        errors,
        uncompressed_size,
    }
}

/// Whether a committing transaction leaves something for the WAL archive to record: records
/// (`pending`), a truncation, a record that could not be staged, which is recorded as a gap,
/// or a new server uuid. The archive is then told before the database commits, so that the
/// open segment marker covers the transaction should the server stop between the commit and
/// its archiving.
fn wal_commit_archives(
    pending: bool,
    truncate: bool,
    stage_failed: bool,
    server_uuid_changed: bool,
) -> bool {
    pending || truncate || stage_failed || server_uuid_changed
}

#[derive(Clone)]
pub struct BackendConfig {
    path: PathBuf,
    pool_size: u32,
    db_name: &'static str,
    fstype: FsType,
    // Cachesizes?
    arcsize: Option<usize>,
    /// WAL archiving for point-in-time recovery. None or disabled: nothing is archived.
    wal_archive: Option<WalArchiveConfig>,
}

impl BackendConfig {
    pub fn new(
        path: Option<&Path>,
        pool_size: u32,
        fstype: FsType,
        arcsize: Option<usize>,
    ) -> Self {
        BackendConfig {
            pool_size,
            // This means if path is None, that "" implies an sqlite in memory/ram only database.
            path: path.unwrap_or_else(|| Path::new("")).to_path_buf(),
            db_name: "main",
            fstype,
            arcsize,
            wal_archive: None,
        }
    }

    /// Enable WAL archiving with `wal_archive`. Segments are written to its `local_path`,
    /// which must be set.
    pub fn with_wal_archive(mut self, wal_archive: Option<WalArchiveConfig>) -> Self {
        self.wal_archive = wal_archive;
        self
    }

    pub(crate) fn new_test(db_name: &'static str) -> Self {
        BackendConfig {
            pool_size: 1,
            path: PathBuf::from(""),
            db_name,
            fstype: FsType::Generic,
            arcsize: Some(2048),
            wal_archive: None,
        }
    }

    /// The directory WAL segments are written to when archiving is enabled. The caller
    /// resolves it (the server core derives the default from the database path), so that
    /// there is one place that does.
    fn wal_segments_path(&self) -> Result<Option<PathBuf>, OperationError> {
        let Some(wal_archive) = self.wal_archive.as_ref().filter(|w| w.enabled) else {
            return Ok(None);
        };
        match &wal_archive.local_path {
            Some(local_path) => Ok(Some(local_path.clone())),
            None => {
                error!("WAL archiving is enabled without a WAL directory (wal_archive.local_path)");
                Err(OperationError::InvalidState)
            }
        }
    }
}

/// The archiver shared by the backend and the server core's upload task.
pub type SharedWalArchiver = Arc<Mutex<WalArchiver>>;

/// Lock `archiver`, see [`lock_archiver`].
pub fn lock_wal(archiver: &SharedWalArchiver) -> MutexGuard<'_, WalArchiver> {
    lock_archiver(archiver)
}

/// What [`BackendWriteTransaction::wal_apply`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalApplyReport {
    /// Records applied.
    pub applied: usize,
    pub created: usize,
    pub modified: usize,
    pub deleted: usize,
    /// The CID of the last record applied: the point the database now represents.
    pub last_cid: Option<Cid>,
}

#[derive(Clone)]
pub struct Backend {
    /// This is the actual datastorage layer.
    idlayer: Arc<IdlArcSqlite>,
    /// This is a copy-on-write cache of the index metadata that has been
    /// extracted from attributes set, in the correct format for the backend
    /// to consume. We use it to extract indexes from entries during write paths
    /// and to allow the front end to know what indexes exist during a read.
    idxmeta: Arc<CowCell<IdxMeta>>,
    /// The current state of the replication update vector. This is effectively a
    /// time series index of the full list of all changelog entries and what entries
    /// that are part of that change.
    ruv: Arc<ReplicationUpdateVector>,
    /// The WAL archiver, when point-in-time recovery is enabled. Every write transaction
    /// hands it the entries it changed once the database commit has succeeded.
    wal: Option<SharedWalArchiver>,
    cfg: BackendConfig,
}

pub struct BackendReadTransaction<'a> {
    idlayer: IdlArcSqliteReadTransaction<'a>,
    idxmeta: CowCellReadTxn<IdxMeta>,
    ruv: ReplicationUpdateVectorReadTransaction<'a>,
}

unsafe impl Sync for BackendReadTransaction<'_> {}

unsafe impl Send for BackendReadTransaction<'_> {}

pub struct BackendWriteTransaction<'a> {
    idlayer: IdlArcSqliteWriteTransaction<'a>,
    idxmeta_wr: CowCellWriteTxn<'a, IdxMeta>,
    ruv: ReplicationUpdateVectorWriteTransaction<'a>,
    /// The WAL archiver of the backend, when point-in-time recovery is enabled.
    wal: Option<SharedWalArchiver>,
    /// The final state of every entry this transaction wrote or removed, keyed by
    /// `id2entry` id. Handed to the archiver only once the database commit succeeded.
    wal_pending: BTreeMap<u64, WalPendingOp>,
    /// Whether this transaction removed every entry before writing `wal_pending`.
    wal_truncate: bool,
    /// The server uuid this transaction gave the database, when it changed it.
    wal_server_uuid: Option<Uuid>,
    /// The CID the archived records are tagged with. Set by the operations that carry a
    /// CID and, authoritatively, by the query server at commit.
    wal_cid: Option<Cid>,
    /// Whether staging a record failed, in which case the transaction leaves a hole in
    /// the archive that is reported at commit.
    wal_stage_failed: bool,
}

impl IdRawEntry {
    fn into_dbentry(self) -> Result<(u64, DbEntry), OperationError> {
        serde_json::from_slice(self.data.as_slice())
            .map_err(|e| {
                admin_error!(?e, "Serde JSON Error");
                OperationError::SerdeJsonError
            })
            .map(|dbe| (self.id, dbe))
    }

    fn into_entry(self) -> Result<EntrySealedCommitted, OperationError> {
        let db_e = serde_json::from_slice(self.data.as_slice()).map_err(|e| {
            admin_error!(?e, id = %self.id, "Serde JSON Error");
            let raw_str = String::from_utf8_lossy(self.data.as_slice());
            debug!(raw = %raw_str);
            OperationError::SerdeJsonError
        })?;
        // let id = u64::try_from(self.id).map_err(|_| OperationError::InvalidEntryId)?;
        Entry::from_dbentry(db_e, self.id).map_err(|err| {
            admin_error!(
                entry_id = self.id,
                entry_uuid = ?err.entry_uuid,
                entry_name = ?err.entry_name,
                reason = %err,
                "Unable to load entry from the database, it is corrupted"
            );
            OperationError::CorruptedEntry(self.id)
        })
    }
}

pub trait BackendTransaction {
    type IdlLayerType: IdlArcSqliteTransaction;
    fn get_idlayer(&mut self) -> &mut Self::IdlLayerType;

    type RuvType: ReplicationUpdateVectorTransaction;
    fn get_ruv(&mut self) -> &mut Self::RuvType;

    fn get_idxmeta_ref(&self) -> &IdxMeta;

    /// Recursively apply a filter, transforming into IdList's on the way. This builds a query
    /// execution log, so that it can be examined how an operation proceeded.
    #[allow(clippy::cognitive_complexity)]
    fn filter2idl(
        &mut self,
        filt: &FilterResolved,
        thres: usize,
    ) -> Result<(IdList, FilterPlan), OperationError> {
        Ok(match filt {
            FilterResolved::Eq(attr, value, idx) => {
                if idx.is_some() {
                    // Get the idx_key
                    let idx_key = value.get_idx_eq_key();
                    // Get the idl for this
                    match self
                        .get_idlayer()
                        .get_idl(attr, IndexType::Equality, &idx_key)?
                    {
                        Some(idl) => (
                            IdList::Indexed(idl),
                            FilterPlan::EqIndexed(attr.clone(), idx_key),
                        ),
                        None => (IdList::AllIds, FilterPlan::EqCorrupt(attr.clone())),
                    }
                } else {
                    // Schema believes this is not indexed
                    (IdList::AllIds, FilterPlan::EqUnindexed(attr.clone()))
                }
            }
            FilterResolved::Stw(attr, subvalue, idx)
            | FilterResolved::Enw(attr, subvalue, idx)
            | FilterResolved::Cnt(attr, subvalue, idx) => {
                // Get the idx_key. Not all types support this, so may return "none".
                trace!(?idx, ?subvalue, ?attr);
                if let (true, Some(idx_key)) = (idx.is_some(), subvalue.get_idx_sub_key()) {
                    self.filter2idl_sub(attr, idx_key)?
                } else {
                    // Schema believes this is not indexed
                    (IdList::AllIds, FilterPlan::SubUnindexed(attr.clone()))
                }
            }
            FilterResolved::Pres(attr, idx) => {
                if idx.is_some() {
                    // Get the idl for this
                    match self.get_idlayer().get_idl(attr, IndexType::Presence, "_")? {
                        Some(idl) => (IdList::Indexed(idl), FilterPlan::PresIndexed(attr.clone())),
                        None => (IdList::AllIds, FilterPlan::PresCorrupt(attr.clone())),
                    }
                } else {
                    // Schema believes this is not indexed
                    (IdList::AllIds, FilterPlan::PresUnindexed(attr.clone()))
                }
            }
            FilterResolved::LessThan(attr, _subvalue, idx) => {
                if idx.is_some() {
                    // TODO: Temporary but we get the PRESENCE index for Ordering operations to
                    // reduce the amount of entries we need to filter in memory. In future we need
                    // a true ordering index, but that's a large block of work on it's own. For now
                    // this already helps a lot for in memory processing.
                    match self.get_idlayer().get_idl(attr, IndexType::Presence, "_")? {
                        Some(idl) => (
                            IdList::Partial(idl),
                            FilterPlan::LessThanIndexed(attr.clone()),
                        ),
                        None => (IdList::AllIds, FilterPlan::LessThanCorrupt(attr.clone())),
                    }
                } else {
                    (IdList::AllIds, FilterPlan::LessThanUnindexed(attr.clone()))
                }
            }
            FilterResolved::Or(l, _) => {
                // Importantly if this has no inner elements, this returns
                // an empty list.
                let mut plan = Vec::with_capacity(0);
                let mut result = IDLBitRange::new();
                let mut partial = false;
                let mut threshold = false;
                // For each filter in l
                for f in l.iter() {
                    // get their idls
                    match self.filter2idl(f, thres)? {
                        (IdList::Indexed(idl), fp) => {
                            plan.push(fp);
                            // now union them (if possible)
                            result = result | idl;
                        }
                        (IdList::Partial(idl), fp) => {
                            plan.push(fp);
                            // now union them (if possible)
                            result = result | idl;
                            partial = true;
                        }
                        (IdList::PartialThreshold(idl), fp) => {
                            plan.push(fp);
                            // now union them (if possible)
                            result = result | idl;
                            partial = true;
                            threshold = true;
                        }
                        (IdList::AllIds, fp) => {
                            plan.push(fp);
                            // If we find anything unindexed, the whole term is unindexed.
                            filter_trace!("Term {:?} is AllIds, shortcut return", f);
                            let setplan = FilterPlan::OrUnindexed(plan);
                            return Ok((IdList::AllIds, setplan));
                        }
                    }
                } // end or.iter()
                  // If we got here, every term must have been indexed or partial indexed.
                if partial {
                    if threshold {
                        let setplan = FilterPlan::OrPartialThreshold(plan);
                        (IdList::PartialThreshold(result), setplan)
                    } else {
                        let setplan = FilterPlan::OrPartial(plan);
                        (IdList::Partial(result), setplan)
                    }
                } else {
                    let setplan = FilterPlan::OrIndexed(plan);
                    (IdList::Indexed(result), setplan)
                }
            }
            FilterResolved::And(l, _) => {
                // This algorithm is a little annoying. I couldn't get it to work with iter and
                // folds due to the logic needed ...

                // First, setup the two filter lists. We always apply AndNot after positive
                // and terms.
                let (f_andnot, f_rem): (Vec<_>, Vec<_>) = l.iter().partition(|f| f.is_andnot());

                // We make this an iter, so everything comes off in order. if we used pop it means we
                // pull from the tail, which is the WORST item to start with!
                let mut f_rem_iter = f_rem.iter();

                // Setup the initial result.
                let (mut cand_idl, fp) = match f_rem_iter.next() {
                    Some(f) => self.filter2idl(f, thres)?,
                    None => {
                        filter_warn!(
                            "And filter was empty, or contains only AndNot, can not evaluate."
                        );
                        return Ok((IdList::Indexed(IDLBitRange::new()), FilterPlan::Invalid));
                    }
                };

                // Setup the counter of terms we have left to evaluate.
                // This is used so that we shortcut return ONLY when we really do have
                // more terms remaining.
                let mut f_rem_count = f_rem.len() + f_andnot.len() - 1;

                // Setup the query plan tracker
                let mut plan = vec![fp];

                match &cand_idl {
                    IdList::Indexed(idl) | IdList::Partial(idl) | IdList::PartialThreshold(idl) => {
                        // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                        // But we only do this when there are actually multiple elements in the and,
                        // because an and with 1 element now is FULLY resolved.
                        if idl.below_threshold(thres) && f_rem_count > 0 {
                            let setplan = FilterPlan::AndPartialThreshold(plan);
                            return Ok((IdList::PartialThreshold(idl.clone()), setplan));
                        } else if idl.is_empty() {
                            // Regardless of the input state, if it's empty, this can never
                            // be satisfied, so return we are indexed and complete.
                            let setplan = FilterPlan::AndEmptyCand(plan);
                            return Ok((IdList::Indexed(IDLBitRange::new()), setplan));
                        }
                    }
                    IdList::AllIds => {}
                }

                // Now, for all remaining,
                for f in f_rem_iter {
                    f_rem_count -= 1;
                    let (inter, fp) = self.filter2idl(f, thres)?;
                    plan.push(fp);
                    cand_idl = match (cand_idl, inter) {
                        (IdList::Indexed(ia), IdList::Indexed(ib)) => {
                            let r = ia & ib;
                            if r.below_threshold(thres) && f_rem_count > 0 {
                                // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IdList::PartialThreshold(r), setplan));
                            } else if r.is_empty() {
                                // Regardless of the input state, if it's empty, this can never
                                // be satisfied, so return we are indexed and complete.
                                let setplan = FilterPlan::AndEmptyCand(plan);
                                return Ok((IdList::Indexed(IDLBitRange::new()), setplan));
                            } else {
                                IdList::Indexed(r)
                            }
                        }
                        (IdList::Indexed(ia), IdList::Partial(ib))
                        | (IdList::Partial(ia), IdList::Indexed(ib))
                        | (IdList::Partial(ia), IdList::Partial(ib)) => {
                            let r = ia & ib;
                            if r.below_threshold(thres) && f_rem_count > 0 {
                                // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IdList::PartialThreshold(r), setplan));
                            } else {
                                IdList::Partial(r)
                            }
                        }
                        (IdList::Indexed(ia), IdList::PartialThreshold(ib))
                        | (IdList::PartialThreshold(ia), IdList::Indexed(ib))
                        | (IdList::PartialThreshold(ia), IdList::PartialThreshold(ib))
                        | (IdList::PartialThreshold(ia), IdList::Partial(ib))
                        | (IdList::Partial(ia), IdList::PartialThreshold(ib)) => {
                            let r = ia & ib;
                            if r.below_threshold(thres) && f_rem_count > 0 {
                                // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IdList::PartialThreshold(r), setplan));
                            } else {
                                IdList::PartialThreshold(r)
                            }
                        }
                        (IdList::Indexed(i), IdList::AllIds)
                        | (IdList::AllIds, IdList::Indexed(i))
                        | (IdList::Partial(i), IdList::AllIds)
                        | (IdList::AllIds, IdList::Partial(i)) => IdList::Partial(i),
                        (IdList::PartialThreshold(i), IdList::AllIds)
                        | (IdList::AllIds, IdList::PartialThreshold(i)) => {
                            IdList::PartialThreshold(i)
                        }
                        (IdList::AllIds, IdList::AllIds) => IdList::AllIds,
                    };
                }

                // debug!("partial cand set ==> {:?}", cand_idl);

                for f in f_andnot.iter() {
                    f_rem_count -= 1;
                    let FilterResolved::AndNot(f_in, _) = f else {
                        filter_error!("Invalid server state, a cand filter leaked to andnot set!");
                        return Err(OperationError::InvalidState);
                    };
                    let (inter, fp) = self.filter2idl(f_in, thres)?;
                    // It's an and not, so we need to wrap the plan accordingly.
                    plan.push(FilterPlan::AndNot(Box::new(fp)));
                    cand_idl = match (cand_idl, inter) {
                        (IdList::Indexed(ia), IdList::Indexed(ib)) => {
                            let r = ia.andnot(ib);
                            /*
                            // Don't trigger threshold on and nots if fully indexed.
                            if r.below_threshold(thres) {
                                // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                                return Ok(IdList::PartialThreshold(r));
                            } else {
                                IdList::Indexed(r)
                            }
                            */
                            IdList::Indexed(r)
                        }
                        (IdList::Indexed(ia), IdList::Partial(ib))
                        | (IdList::Partial(ia), IdList::Indexed(ib))
                        | (IdList::Partial(ia), IdList::Partial(ib)) => {
                            let r = ia.andnot(ib);
                            // DO trigger threshold on partials, because we have to apply the filter
                            // test anyway, so we may as well shortcut at this point.
                            if r.below_threshold(thres) && f_rem_count > 0 {
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IdList::PartialThreshold(r), setplan));
                            } else {
                                IdList::Partial(r)
                            }
                        }
                        (IdList::Indexed(ia), IdList::PartialThreshold(ib))
                        | (IdList::PartialThreshold(ia), IdList::Indexed(ib))
                        | (IdList::PartialThreshold(ia), IdList::PartialThreshold(ib))
                        | (IdList::PartialThreshold(ia), IdList::Partial(ib))
                        | (IdList::Partial(ia), IdList::PartialThreshold(ib)) => {
                            let r = ia.andnot(ib);
                            // DO trigger threshold on partials, because we have to apply the filter
                            // test anyway, so we may as well shortcut at this point.
                            if r.below_threshold(thres) && f_rem_count > 0 {
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IdList::PartialThreshold(r), setplan));
                            } else {
                                IdList::PartialThreshold(r)
                            }
                        }

                        (IdList::Indexed(_), IdList::AllIds)
                        | (IdList::AllIds, IdList::Indexed(_))
                        | (IdList::Partial(_), IdList::AllIds)
                        | (IdList::AllIds, IdList::Partial(_))
                        | (IdList::PartialThreshold(_), IdList::AllIds)
                        | (IdList::AllIds, IdList::PartialThreshold(_)) => {
                            // We could actually generate allids here
                            // and then try to reduce the and-not set, but
                            // for now we just return all ids.
                            IdList::AllIds
                        }
                        (IdList::AllIds, IdList::AllIds) => IdList::AllIds,
                    };
                }

                // What state is the final cand idl in?
                let setplan = match cand_idl {
                    IdList::Indexed(_) => FilterPlan::AndIndexed(plan),
                    IdList::Partial(_) | IdList::PartialThreshold(_) => {
                        FilterPlan::AndPartial(plan)
                    }
                    IdList::AllIds => FilterPlan::AndUnindexed(plan),
                };

                // Finally, return the result.
                // debug!("final cand set ==> {:?}", cand_idl);
                (cand_idl, setplan)
            } // end and
            FilterResolved::Inclusion(l, _) => {
                // For inclusion to be valid, every term must have *at least* one element present.
                // This really relies on indexing, and so it's internal only - generally only
                // for fully indexed existence queries, such as from refint.

                // This has a lot in common with an And and Or but not really quite either.
                let mut plan = Vec::with_capacity(0);
                let mut result = IDLBitRange::new();
                // For each filter in l
                for f in l.iter() {
                    // get their idls
                    match self.filter2idl(f, thres)? {
                        (IdList::Indexed(idl), fp) => {
                            plan.push(fp);
                            if idl.is_empty() {
                                // It's empty, so something is missing. Bail fast.
                                filter_trace!("Inclusion is unable to proceed - an empty (missing) item was found!");
                                let setplan = FilterPlan::InclusionIndexed(plan);
                                return Ok((IdList::Indexed(IDLBitRange::new()), setplan));
                            } else {
                                result = result | idl;
                            }
                        }
                        (_, fp) => {
                            plan.push(fp);
                            let setplan = FilterPlan::InclusionInvalid(plan);
                            error!(
                                ?setplan,
                                "Inclusion is unable to proceed - all terms must be fully indexed!"
                            );
                            return Ok((IdList::Partial(IDLBitRange::new()), setplan));
                        }
                    }
                } // end or.iter()
                  // If we got here, every term must have been indexed
                let setplan = FilterPlan::InclusionIndexed(plan);
                (IdList::Indexed(result), setplan)
            }
            // So why does this return empty? Normally we actually process an AndNot in the context
            // of an "AND" query, but if it's used anywhere else IE the root filter, then there is
            // no other set to exclude - therefore it's empty set. Additionally, even in an OR query
            // the AndNot will be skipped as an empty set for the same reason.
            FilterResolved::AndNot(_f, _) => {
                // get the idl for f
                // now do andnot?
                filter_error!("Requested a top level or isolated AndNot, returning empty");
                (IdList::Indexed(IDLBitRange::new()), FilterPlan::Invalid)
            }
            FilterResolved::Invalid(_) => {
                // Indexed since it is always false and we don't want to influence filter testing
                (IdList::Indexed(IDLBitRange::new()), FilterPlan::Invalid)
            }
        })
    }

    fn filter2idl_sub(
        &mut self,
        attr: &Attribute,
        sub_idx_key: String,
    ) -> Result<(IdList, FilterPlan), OperationError> {
        // Now given that idx_key, we will iterate over the possible graphemes.
        let mut grapheme_iter = trigraph_iter(&sub_idx_key);

        // Substrings are always partial because we have to split the keys up
        // and we don't pay attention to starts/ends with conditions. We need
        // the caller to check those conditions manually at run time. This lets
        // the index focus on trigraph indexes only rather than needing to
        // worry about those other bits. In a way substring indexes are "fuzzy".

        let mut idl = match grapheme_iter.next() {
            Some(idx_key) => {
                match self
                    .get_idlayer()
                    .get_idl(attr, IndexType::SubString, idx_key)?
                {
                    Some(idl) => idl,
                    None => return Ok((IdList::AllIds, FilterPlan::SubCorrupt(attr.clone()))),
                }
            }
            None => {
                // If there are no graphemes this means the attempt is for an empty string, so
                // we return an empty result set.
                return Ok((IdList::Indexed(IDLBitRange::new()), FilterPlan::Invalid));
            }
        };

        if idl.len() > FILTER_SUBSTR_TEST_THRESHOLD {
            for idx_key in grapheme_iter {
                // Get the idl for this
                match self
                    .get_idlayer()
                    .get_idl(attr, IndexType::SubString, idx_key)?
                {
                    Some(r_idl) => {
                        // Do an *and* operation between what we found and our working idl.
                        idl = r_idl & idl;
                    }
                    None => {
                        // if something didn't match, then we simply bail out after zeroing the current IDL.
                        idl = IDLBitRange::new();
                    }
                };

                if idl.len() < FILTER_SUBSTR_TEST_THRESHOLD {
                    break;
                }
            }
        } else {
            drop(grapheme_iter);
        }

        // We exhausted the grapheme iter, exit with what we found.
        Ok((
            IdList::Partial(idl),
            FilterPlan::SubIndexed(attr.clone(), sub_idx_key),
        ))
    }

    #[instrument(level = "debug", name = "be::search", skip_all)]
    fn search(
        &mut self,
        erl: &Limits,
        filt: &Filter<FilterValidResolved>,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        // Unlike DS, even if we don't get the index back, we can just pass
        // to the in-memory filter test and be done.

        trace!(filter_optimised = ?filt);

        let (idl, fplan) = trace_span!("be::search -> filter2idl")
            .in_scope(|| self.filter2idl(filt.to_inner(), FILTER_SEARCH_TEST_THRESHOLD))?;

        debug!(search_filter_executed_plan = %fplan);

        match &idl {
            IdList::AllIds => {
                if !erl.unindexed_allow {
                    admin_error!(
                        "filter (search) is fully unindexed, and not allowed by resource limits"
                    );
                    return Err(OperationError::ResourceLimit);
                }
            }
            IdList::Partial(idl_br) => {
                // if idl_br.len() > erl.search_max_filter_test {
                if !idl_br.below_threshold(erl.search_max_filter_test) {
                    admin_error!("filter (search) is partial indexed and greater than search_max_filter_test allowed by resource limits");
                    return Err(OperationError::ResourceLimit);
                }
            }
            IdList::PartialThreshold(_) => {
                // Since we opted for this, this is not the fault
                // of the user and we should not penalise them by limiting on partial.
            }
            IdList::Indexed(idl_br) => {
                // We know this is resolved here, so we can attempt the limit
                // check. This has to fold the whole index, but you know, class=pres is
                // indexed ...
                // if idl_br.len() > erl.search_max_results {
                if !idl_br.below_threshold(erl.search_max_results) {
                    admin_error!("filter (search) is indexed and greater than search_max_results allowed by resource limits");
                    return Err(OperationError::ResourceLimit);
                }
            }
        };

        let entries = self.get_idlayer().get_identry(&idl).map_err(|e| {
            admin_error!(?e, "get_identry failed");
            e
        })?;

        let mut entries_filtered = match idl {
            IdList::AllIds => trace_span!("be::search<entry::ftest::allids>").in_scope(|| {
                entries
                    .into_iter()
                    .filter(|e| e.entry_match_no_index(filt))
                    .collect()
            }),
            IdList::Partial(_) => trace_span!("be::search<entry::ftest::partial>").in_scope(|| {
                entries
                    .into_iter()
                    .filter(|e| e.entry_match_no_index(filt))
                    .collect()
            }),
            IdList::PartialThreshold(_) => trace_span!("be::search<entry::ftest::thresh>")
                .in_scope(|| {
                    entries
                        .into_iter()
                        .filter(|e| e.entry_match_no_index(filt))
                        .collect()
                }),
            // Since the index fully resolved, we can shortcut the filter test step here!
            IdList::Indexed(_) => {
                filter_trace!("filter (search) was fully indexed 👏");
                entries
            }
        };

        // If the idl was not indexed, apply the resource limit now. Avoid the needless match since the
        // if statement is quick.
        if entries_filtered.len() > erl.search_max_results {
            admin_error!("filter (search) is resolved and greater than search_max_results allowed by resource limits");
            return Err(OperationError::ResourceLimit);
        }

        // Trim any excess capacity if needed
        entries_filtered.shrink_to_fit();

        Ok(entries_filtered)
    }

    /// Given a filter, assert some condition exists.
    /// Basically, this is a specialised case of search, where we don't need to
    /// load any candidates if they match. This is heavily used in uuid
    /// refint and attr uniqueness.
    #[instrument(level = "debug", name = "be::exists", skip_all)]
    fn exists(
        &mut self,
        erl: &Limits,
        filt: &Filter<FilterValidResolved>,
    ) -> Result<bool, OperationError> {
        trace!(filter_optimised = ?filt);

        // Using the indexes, resolve the IdList here, or AllIds.
        // Also get if the filter was 100% resolved or not.
        let (idl, fplan) = trace_span!("be::exists -> filter2idl")
            .in_scope(|| self.filter2idl(filt.to_inner(), FILTER_EXISTS_TEST_THRESHOLD))?;

        debug!(exist_filter_executed_plan = %fplan);

        // Apply limits to the IdList.
        match &idl {
            IdList::AllIds => {
                if !erl.unindexed_allow {
                    admin_error!(
                        "filter (exists) is fully unindexed, and not allowed by resource limits"
                    );
                    return Err(OperationError::ResourceLimit);
                }
            }
            IdList::Partial(idl_br) => {
                if !idl_br.below_threshold(erl.search_max_filter_test) {
                    admin_error!("filter (exists) is partial indexed and greater than search_max_filter_test allowed by resource limits");
                    return Err(OperationError::ResourceLimit);
                }
            }
            IdList::PartialThreshold(_) => {
                // Since we opted for this, this is not the fault
                // of the user and we should not penalise them.
            }
            IdList::Indexed(_) => {}
        }

        // Now, check the idl -- if it's fully resolved, we can skip this because the query
        // was fully indexed.
        match &idl {
            IdList::Indexed(idl) => Ok(!idl.is_empty()),
            _ => {
                let entries = self.get_idlayer().get_identry(&idl).map_err(|e| {
                    admin_error!(?e, "get_identry failed");
                    e
                })?;

                // if not 100% resolved query, apply the filter test.
                let entries_filtered: Vec<_> =
                    trace_span!("be::exists<entry::ftest>").in_scope(|| {
                        entries
                            .into_iter()
                            .filter(|e| e.entry_match_no_index(filt))
                            .collect()
                    });

                Ok(!entries_filtered.is_empty())
            }
        } // end match idl
    }

    fn retrieve_range(
        &mut self,
        ranges: &BTreeMap<Uuid, ReplCidRange>,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        // First pass the ranges to the ruv to resolve to an absolute set of
        // entry id's.

        let idl = self.get_ruv().range_to_idl(ranges);
        // Because of how this works, I think that it's not possible for the idl
        // to have any missing ids.
        //
        // If it was possible, we could just & with allids to remove the extraneous
        // values.

        if idl.is_empty() {
            // return no entries.
            return Ok(Vec::with_capacity(0));
        }

        // Make it an id list fr the backend.
        let id_list = IdList::Indexed(idl);

        self.get_idlayer().get_identry(&id_list).map_err(|e| {
            admin_error!(?e, "get_identry failed");
            e
        })
    }

    fn verify(&mut self) -> Vec<Result<(), ConsistencyError>> {
        self.get_idlayer().verify()
    }

    fn verify_entry_index(&mut self, e: &EntrySealedCommitted) -> Result<(), ConsistencyError> {
        // First, check our references in name2uuid, uuid2spn and uuid2rdn
        if e.mask_recycled_ts().is_some() {
            let e_uuid = e.get_uuid();
            // We only check these on live entries.
            let (n2u_add, n2u_rem) = Entry::idx_name2uuid_diff(None, Some(e));

            let (Some(n2u_set), None) = (n2u_add, n2u_rem) else {
                admin_error!("Invalid idx_name2uuid_diff state");
                return Err(ConsistencyError::BackendIndexSync);
            };

            // If the set.len > 1, check each item.
            n2u_set
                .iter()
                .try_for_each(|name| match self.get_idlayer().name2uuid(name) {
                    Ok(Some(idx_uuid)) => {
                        if idx_uuid == e_uuid {
                            Ok(())
                        } else {
                            admin_error!("Invalid name2uuid state -> incorrect uuid association");
                            Err(ConsistencyError::BackendIndexSync)
                        }
                    }
                    r => {
                        admin_error!(state = ?r, "Invalid name2uuid state");
                        Err(ConsistencyError::BackendIndexSync)
                    }
                })?;

            let spn = e.get_uuid2spn();
            match self.get_idlayer().uuid2spn(e_uuid) {
                Ok(Some(idx_spn)) => {
                    if spn != idx_spn {
                        admin_error!("Invalid uuid2spn state -> incorrect idx spn value");
                        return Err(ConsistencyError::BackendIndexSync);
                    }
                }
                r => {
                    admin_error!(state = ?r, ?e_uuid, "Invalid uuid2spn state");
                    trace!(entry = ?e);
                    return Err(ConsistencyError::BackendIndexSync);
                }
            };

            let rdn = e.get_uuid2rdn();
            match self.get_idlayer().uuid2rdn(e_uuid) {
                Ok(Some(idx_rdn)) => {
                    if rdn != idx_rdn {
                        admin_error!("Invalid uuid2rdn state -> incorrect idx rdn value");
                        return Err(ConsistencyError::BackendIndexSync);
                    }
                }
                r => {
                    admin_error!(state = ?r, "Invalid uuid2rdn state");
                    return Err(ConsistencyError::BackendIndexSync);
                }
            };
        }

        // Check the other entry:attr indexes are valid
        //
        // This is actually pretty hard to check, because we can check a value *should*
        // exist, but not that a value should NOT be present in the index. Thought needed ...

        // Got here? Ok!
        Ok(())
    }

    fn verify_indexes(&mut self) -> Vec<Result<(), ConsistencyError>> {
        let idl = IdList::AllIds;
        let entries = match self.get_idlayer().get_identry(&idl) {
            Ok(s) => s,
            Err(e) => {
                admin_error!(?e, "get_identry failure");
                return vec![Err(ConsistencyError::Unknown)];
            }
        };

        let r = entries.iter().try_for_each(|e| self.verify_entry_index(e));

        if r.is_err() {
            vec![r]
        } else {
            Vec::with_capacity(0)
        }
    }

    fn verify_ruv(&mut self, results: &mut Vec<Result<(), ConsistencyError>>) {
        // The way we verify this is building a whole second RUV and then comparing it.
        let idl = IdList::AllIds;
        let entries = match self.get_idlayer().get_identry(&idl) {
            Ok(ent) => ent,
            Err(e) => {
                results.push(Err(ConsistencyError::Unknown));
                admin_error!(?e, "get_identry failed");
                return;
            }
        };

        self.get_ruv().verify(&entries, results);
    }

    fn backup<OUT>(
        &mut self,
        mut output: OUT,
        compression: BackupCompression,
    ) -> Result<(), OperationError>
    where
        OUT: std::io::Write,
    {
        let repl_meta = self.get_ruv().to_db_backup_ruv();

        // load all entries into RAM, may need to change this later
        // if the size of the database compared to RAM is an issue
        let idl = IdList::AllIds;
        let idlayer = self.get_idlayer();
        let raw_entries: Vec<IdRawEntry> = idlayer.get_identry_raw(&idl)?;

        let mut entries: Vec<DbEntry> = Vec::with_capacity(raw_entries.len());

        for id_ent in raw_entries.iter() {
            // Validate semantic correctness by attempting conversion through Entry::from_dbentry.
            // This consumes the deserialized entry, so we deserialize again below for storage.
            let validation_entry: DbEntry = serde_json::from_slice(id_ent.data.as_slice())
                .map_err(|_| OperationError::SerdeJsonError)?;

            if let Err(err) = Entry::from_dbentry(validation_entry, id_ent.id) {
                // Identify the problematic entry so that an operator can find it.
                admin_error!(
                    entry_id = id_ent.id,
                    entry_uuid = ?err.entry_uuid,
                    entry_name = ?err.entry_name,
                    reason = %err,
                    "Backup semantic validation failed: entry deserialized but Entry::from_dbentry rejected it"
                );
                return Err(OperationError::DB0005BackupEntrySemanticInvalid {
                    entry_id: id_ent.id,
                });
            }

            // Deserialize again for storage (validation consumed the first copy)
            let db_entry: DbEntry = serde_json::from_slice(id_ent.data.as_slice())
                .map_err(|_| OperationError::SerdeJsonError)?;
            entries.push(db_entry);
        }

        let db_s_uuid = idlayer
            .get_db_s_uuid()
            .and_then(|u| u.ok_or(OperationError::InvalidDbState))?;
        let db_d_uuid = idlayer
            .get_db_d_uuid()
            .and_then(|u| u.ok_or(OperationError::InvalidDbState))?;
        let db_ts_max = idlayer
            .get_db_ts_max()
            .and_then(|u| u.ok_or(OperationError::InvalidDbState))?;

        let keyhandles = idlayer.get_key_handles()?;

        let bak = DbBackup::V5 {
            // remember env is evaled at compile time.
            version: env!("KUBIDM_PKG_SERIES").to_string(),
            db_s_uuid,
            db_d_uuid,
            db_ts_max,
            keyhandles,
            repl_meta,
            entries,
        };

        let serialized_entries_str = serde_json::to_string(&bak).map_err(|e| {
            admin_error!(?e, "serde error");
            OperationError::SerdeJsonError
        })?;

        match compression {
            BackupCompression::NoCompression => {
                output
                    .write(serialized_entries_str.as_bytes())
                    .map_err(|e| {
                        error!(?e, "fs::write error");
                        OperationError::FsError
                    })?;
            }
            BackupCompression::Gzip => {
                let mut encoder = GzEncoder::new(&mut output, Compression::best());
                encoder
                    .write_all(serialized_entries_str.as_bytes())
                    .map_err(|e| {
                        error!(?e, "Gzip compression error writing backup");
                        OperationError::FsError
                    })?;
            }
        }

        output.flush().map_err(|err| {
            error!(?err, "Unable to flush backup output stream");
            OperationError::FsError
        })?;

        Ok(())
    }

    fn name2uuid(&mut self, name: &str) -> Result<Option<Uuid>, OperationError> {
        self.get_idlayer().name2uuid(name)
    }

    fn externalid2uuid(&mut self, name: &str) -> Result<Option<Uuid>, OperationError> {
        self.get_idlayer().externalid2uuid(name)
    }

    fn uuid2spn(&mut self, uuid: Uuid) -> Result<Option<Value>, OperationError> {
        self.get_idlayer().uuid2spn(uuid)
    }

    fn uuid2rdn(&mut self, uuid: Uuid) -> Result<Option<String>, OperationError> {
        self.get_idlayer().uuid2rdn(uuid)
    }
}

impl<'a> BackendTransaction for BackendReadTransaction<'a> {
    type IdlLayerType = IdlArcSqliteReadTransaction<'a>;
    type RuvType = ReplicationUpdateVectorReadTransaction<'a>;

    fn get_idlayer(&mut self) -> &mut IdlArcSqliteReadTransaction<'a> {
        &mut self.idlayer
    }

    fn get_ruv(&mut self) -> &mut ReplicationUpdateVectorReadTransaction<'a> {
        &mut self.ruv
    }

    fn get_idxmeta_ref(&self) -> &IdxMeta {
        &self.idxmeta
    }
}

impl BackendReadTransaction<'_> {
    pub fn list_indexes(&mut self) -> Result<Vec<String>, OperationError> {
        self.get_idlayer().list_idxs()
    }

    pub fn list_id2entry(&mut self) -> Result<Vec<(u64, String)>, OperationError> {
        self.get_idlayer().list_id2entry()
    }

    pub fn list_index_content(
        &mut self,
        index_name: &str,
    ) -> Result<Vec<(String, IDLBitRange)>, OperationError> {
        self.get_idlayer().list_index_content(index_name)
    }

    pub fn get_id2entry(&mut self, id: u64) -> Result<(u64, String), OperationError> {
        self.get_idlayer().get_id2entry(id)
    }

    pub fn list_quarantined(&mut self) -> Result<Vec<(u64, String)>, OperationError> {
        self.get_idlayer().list_quarantined()
    }
}

impl<'a> BackendTransaction for BackendWriteTransaction<'a> {
    type IdlLayerType = IdlArcSqliteWriteTransaction<'a>;
    type RuvType = ReplicationUpdateVectorWriteTransaction<'a>;

    fn get_idlayer(&mut self) -> &mut IdlArcSqliteWriteTransaction<'a> {
        &mut self.idlayer
    }

    fn get_ruv(&mut self) -> &mut ReplicationUpdateVectorWriteTransaction<'a> {
        &mut self.ruv
    }

    fn get_idxmeta_ref(&self) -> &IdxMeta {
        &self.idxmeta_wr
    }
}

impl<'a> BackendWriteTransaction<'a> {
    pub(crate) fn get_ruv_write(&mut self) -> &mut ReplicationUpdateVectorWriteTransaction<'a> {
        &mut self.ruv
    }

    #[instrument(level = "debug", name = "be::create", skip_all)]
    pub fn create(
        &mut self,
        cid: &Cid,
        entries: Vec<EntrySealedNew>,
    ) -> Result<Vec<EntrySealedCommitted>, OperationError> {
        if entries.is_empty() {
            admin_error!("No entries provided to BE to create, invalid server call!");
            return Err(OperationError::EmptyRequest);
        }

        // Check that every entry has a change associated
        // that matches the cid?
        entries.iter().try_for_each(|e| {
            if e.get_changestate().contains_tail_cid(cid) {
                Ok(())
            } else {
                admin_error!(
                    "Entry changelog does not contain a change related to this transaction"
                );
                Err(OperationError::ReplEntryNotChanged)
            }
        })?;

        // Now, assign id's to all the new entries.

        let mut id_max = self.idlayer.get_id2entry_max_id()?;
        let c_entries: Vec<_> = entries
            .into_iter()
            .map(|e| {
                id_max += 1;
                e.into_sealed_committed_id(id_max)
            })
            .collect();

        // All good, lets update the RUV.
        // This auto compresses.
        let ruv_idl = IDLBitRange::from_iter(c_entries.iter().map(|e| e.get_id()));

        // We don't need to skip this like in mod since creates always go to the ruv
        self.get_ruv().insert_change(cid, ruv_idl)?;

        self.idlayer.write_identries(c_entries.iter())?;

        self.idlayer.set_id2entry_max_id(id_max);

        for e in c_entries.iter() {
            self.wal_stage_write(Some(cid), e, true);
        }

        // Now update the indexes as required.
        for e in c_entries.iter() {
            self.entry_index(None, Some(e))?
        }

        Ok(c_entries)
    }

    #[instrument(level = "debug", name = "be::create", skip_all)]
    /// This is similar to create, but used in the replication path as it records all
    /// the CID's in the entry to the RUV, but without applying the current CID as
    /// a new value in the RUV. We *do not* want to apply the current CID in the RUV
    /// related to this entry as that could cause an infinite replication loop!
    pub fn refresh(
        &mut self,
        entries: Vec<EntrySealedNew>,
    ) -> Result<Vec<EntrySealedCommitted>, OperationError> {
        if entries.is_empty() {
            admin_error!("No entries provided to BE to create, invalid server call!");
            return Err(OperationError::EmptyRequest);
        }

        // Assign id's to all the new entries.
        let mut id_max = self.idlayer.get_id2entry_max_id()?;
        let c_entries: Vec<_> = entries
            .into_iter()
            .map(|e| {
                id_max += 1;
                e.into_sealed_committed_id(id_max)
            })
            .collect();

        self.idlayer.write_identries(c_entries.iter())?;

        self.idlayer.set_id2entry_max_id(id_max);

        for e in c_entries.iter() {
            self.wal_stage_write(None, e, true);
        }

        // Update the RUV with all the changestates of the affected entries.
        for e in c_entries.iter() {
            self.get_ruv().update_entry_changestate(e)?;
        }

        // Now update the indexes as required.
        for e in c_entries.iter() {
            self.entry_index(None, Some(e))?
        }

        Ok(c_entries)
    }

    #[instrument(level = "debug", name = "be::modify", skip_all)]
    pub fn modify(
        &mut self,
        cid: &Cid,
        pre_entries: &[Arc<EntrySealedCommitted>],
        post_entries: &[EntrySealedCommitted],
    ) -> Result<(), OperationError> {
        if post_entries.is_empty() || pre_entries.is_empty() {
            admin_error!("No entries provided to BE to modify, invalid server call!");
            return Err(OperationError::EmptyRequest);
        }

        assert_eq!(post_entries.len(), pre_entries.len());

        let post_entries_iter = post_entries.iter().filter(|e| {
            trace!(?cid);
            trace!(changestate = ?e.get_changestate());
            // If True - This means that at least one attribute that *is* replicated was changed
            // on this entry, so we need to update and add this to the RUV!
            //
            // If False - This means that the entry in question was updated but the changes are all
            // non-replicated so we DO NOT update the RUV here!
            e.get_changestate().contains_tail_cid(cid)
        });

        // All good, lets update the RUV.
        // This auto compresses.
        let ruv_idl = IDLBitRange::from_iter(post_entries_iter.map(|e| e.get_id()));

        if !ruv_idl.is_empty() {
            self.get_ruv().insert_change(cid, ruv_idl)?;
        }

        // Now, given the list of id's, update them
        self.get_idlayer().write_identries(post_entries.iter())?;

        for e in post_entries.iter() {
            self.wal_stage_write(Some(cid), e, false);
        }

        // Finally, we now reindex all the changed entries. We do this by iterating and zipping
        // over the set, because we know the list is in the same order.
        pre_entries
            .iter()
            .zip(post_entries.iter())
            .try_for_each(|(pre, post)| self.entry_index(Some(pre.as_ref()), Some(post)))
    }

    #[instrument(level = "debug", name = "be::incremental_prepare", skip_all)]
    pub fn incremental_prepare(
        &mut self,
        entry_meta: &[EntryIncrementalNew],
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        let mut ret_entries = Vec::with_capacity(entry_meta.len());
        let id_max_pre = self.idlayer.get_id2entry_max_id()?;
        let mut id_max = id_max_pre;

        for ctx_ent in entry_meta.iter() {
            let ctx_ent_uuid = ctx_ent.get_uuid();
            let idx_key = ctx_ent_uuid.as_hyphenated().to_string();

            let idl =
                self.get_idlayer()
                    .get_idl(&Attribute::Uuid, IndexType::Equality, &idx_key)?;

            let entry = match idl {
                Some(idl) if idl.is_empty() => {
                    // Create the stub entry, we just need it to have an id number
                    // allocated.
                    id_max += 1;

                    let stub_entry = Arc::new(EntrySealedCommitted::stub_sealed_committed_id(
                        id_max, ctx_ent,
                    ));
                    // Now, the stub entry needs to be indexed. If not, uuid2spn
                    // isn't created, so subsequent index diffs don't work correctly.
                    self.entry_index(None, Some(stub_entry.as_ref()))?;

                    // Okay, entry ready to go.
                    stub_entry
                }
                Some(idl) if idl.len() == 1 => {
                    // Get the entry from this idl.
                    let mut entries = self
                        .get_idlayer()
                        .get_identry(&IdList::Indexed(idl))
                        .map_err(|e| {
                            admin_error!(?e, "get_identry failed");
                            e
                        })?;

                    if let Some(entry) = entries.pop() {
                        // Return it.
                        entry
                    } else {
                        error!("Invalid entry state, index was unable to locate entry");
                        return Err(OperationError::InvalidDbState);
                    }
                    // Done, entry is ready to go
                }
                Some(idl) => {
                    // BUG - duplicate uuid!
                    error!(uuid = ?ctx_ent_uuid, "Invalid IDL state, uuid index must have only a single or no values. Contains {:?}", idl);
                    return Err(OperationError::InvalidDbState);
                }
                None => {
                    // BUG - corrupt index.
                    error!(uuid = ?ctx_ent_uuid, "Invalid IDL state, uuid index must be present");
                    return Err(OperationError::InvalidDbState);
                }
            };

            ret_entries.push(entry);
        }

        if id_max != id_max_pre {
            self.idlayer.set_id2entry_max_id(id_max);
        }

        Ok(ret_entries)
    }

    #[instrument(level = "debug", name = "be::incremental_apply", skip_all)]
    pub fn incremental_apply(
        &mut self,
        update_entries: &[(EntrySealedCommitted, Arc<EntrySealedCommitted>)],
        create_entries: Vec<EntrySealedNew>,
    ) -> Result<(), OperationError> {
        // For the values in create_cands, create these with similar code to the refresh
        // path.
        if !create_entries.is_empty() {
            // Assign id's to all the new entries.
            let mut id_max = self.idlayer.get_id2entry_max_id()?;
            let c_entries: Vec<_> = create_entries
                .into_iter()
                .map(|e| {
                    id_max += 1;
                    e.into_sealed_committed_id(id_max)
                })
                .collect();

            self.idlayer.write_identries(c_entries.iter())?;

            self.idlayer.set_id2entry_max_id(id_max);

            for e in c_entries.iter() {
                self.wal_stage_write(None, e, true);
            }

            // Update the RUV with all the changestates of the affected entries.
            for e in c_entries.iter() {
                self.get_ruv().update_entry_changestate(e)?;
            }

            // Now update the indexes as required.
            for e in c_entries.iter() {
                self.entry_index(None, Some(e))?
            }
        }

        // Otherwise this is a cid-less copy of modify.
        if !update_entries.is_empty() {
            self.get_idlayer()
                .write_identries(update_entries.iter().map(|(up, _)| up))?;

            for (e, _) in update_entries.iter() {
                self.wal_stage_write(None, e, false);
            }

            for (e, _) in update_entries.iter() {
                self.get_ruv().update_entry_changestate(e)?;
            }

            for (post, pre) in update_entries.iter() {
                self.entry_index(Some(pre.as_ref()), Some(post))?
            }
        }

        Ok(())
    }

    #[instrument(level = "debug", name = "be::reap_tombstones", skip_all)]
    pub fn reap_tombstones(&mut self, cid: &Cid, trim_cid: &Cid) -> Result<usize, OperationError> {
        debug_assert!(cid > trim_cid);
        // Mark a new maximum for the RUV by inserting an empty change. This
        // is important to keep the changestate always advancing.
        self.get_ruv().insert_change(cid, IDLBitRange::default())?;

        // We plan to clear the RUV up to this cid. So we need to build an IDL
        // of all the entries we need to examine.
        let idl = self.get_ruv().trim_up_to(trim_cid).map_err(|e| {
            admin_error!(
                ?e,
                "During tombstone cleanup, failed to trim RUV to {:?}",
                trim_cid
            );
            e
        })?;

        let entries = self
            .get_idlayer()
            .get_identry(&IdList::Indexed(idl))
            .map_err(|e| {
                admin_error!(?e, "get_identry failed");
                e
            })?;

        if entries.is_empty() {
            admin_debug!("No entries affected - reap_tombstones operation success");
            return Ok(0);
        }

        // Now that we have a list of entries we need to partition them into
        // two sets. The entries that are tombstoned and ready to reap_tombstones, and
        // the entries that need to have their change logs trimmed.
        //
        // Remember, these tombstones can be reaped because they were tombstoned at time
        // point 'cid', and since we are now "past" that minimum cid, then other servers
        // will also be trimming these out.
        //
        // Note unlike a changelog impl, we don't need to trim changestates here. We
        // only need the RUV trimmed so that we know if other servers are laggin behind!

        // What entries are tombstones and ready to be deleted?

        let (tombstones, leftover): (Vec<_>, Vec<_>) = entries
            .into_iter()
            .partition(|e| e.get_changestate().can_delete(trim_cid));

        let ruv_idls = self.get_ruv().ruv_idls();

        // Assert that anything leftover still either is *alive* OR is a tombstone
        // and has entries in the RUV!

        if !leftover
            .iter()
            .all(|e| e.get_changestate().is_live() || ruv_idls.contains(e.get_id()))
        {
            admin_error!("Left over entries may be orphaned due to missing RUV entries");
            return Err(OperationError::ReplInvalidRUVState);
        }

        // Now setup to reap_tombstones the tombstones. Remember, in the post cleanup, it's could
        // now have been trimmed to a point we can purge them!

        // Assert the id's exist on the entry.
        let id_list: IDLBitRange = tombstones.iter().map(|e| e.get_id()).collect();

        // Ensure nothing here exists in the RUV index, else it means
        // we didn't trim properly, or some other state violation has occurred.
        if !((&ruv_idls & &id_list).is_empty()) {
            admin_error!("RUV still contains entries that are going to be removed.");
            return Err(OperationError::ReplInvalidRUVState);
        }

        // Now, given the list of id's, reap_tombstones them.
        let sz = id_list.len();
        self.get_idlayer().delete_identry(id_list.into_iter())?;

        for e in tombstones.iter() {
            self.wal_stage_delete(Some(cid), e);
        }

        // Finally, purge the indexes from the entries we removed. These still have
        // indexes due to class=tombstone.
        tombstones
            .iter()
            .try_for_each(|e| self.entry_index(Some(e), None))?;

        Ok(sz)
    }

    #[instrument(level = "debug", name = "be::update_idxmeta", skip_all)]
    pub fn update_idxmeta(&mut self, idxkeys: Vec<IdxKey>) -> Result<(), OperationError> {
        if self.is_idx_slopeyness_generated()? {
            trace!("Indexing slopes available");
        } else {
            warn!("No indexing slopes available. You should consider reindexing to generate these");
        };

        // TODO: I think anytime we update idx meta is when we should reindex in memory
        // indexes.
        // Probably needs to be similar to create_idxs so we iterate over the set of
        // purely in memory idxs.

        // Setup idxkeys here. By default we set these all to "max slope" aka
        // all indexes are "equal" but also worse case unless analysed. If they
        // have been analysed, we can set the slope factor into here.
        let mut idxkeys = idxkeys
            .into_iter()
            .map(|k| self.get_idx_slope(&k).map(|slope| (k, slope)))
            .collect::<Result<HashMap<_, _>, _>>()?;

        std::mem::swap(&mut self.idxmeta_wr.deref_mut().idxkeys, &mut idxkeys);
        Ok(())
    }

    // Should take a mut index set, and then we write the whole thing back
    // in a single stripe.
    //
    // So we need a cache, which we load indexes into as we do ops, then we
    // modify them.
    //
    // At the end, we flush those cchange outs in a single run.
    // For create this is probably a
    // TODO: Can this be improved?
    #[allow(clippy::cognitive_complexity)]
    fn entry_index(
        &mut self,
        pre: Option<&EntrySealedCommitted>,
        post: Option<&EntrySealedCommitted>,
    ) -> Result<(), OperationError> {
        let (e_uuid, e_id, uuid_same) = match (pre, post) {
            (None, None) => {
                admin_error!("Invalid call to entry_index - no entries provided");
                return Err(OperationError::InvalidState);
            }
            (Some(pre), None) => {
                trace!("Attempting to remove entry indexes");
                (pre.get_uuid(), pre.get_id(), true)
            }
            (None, Some(post)) => {
                trace!("Attempting to create entry indexes");
                (post.get_uuid(), post.get_id(), true)
            }
            (Some(pre), Some(post)) => {
                trace!("Attempting to modify entry indexes");
                assert_eq!(pre.get_id(), post.get_id());
                (
                    post.get_uuid(),
                    post.get_id(),
                    pre.get_uuid() == post.get_uuid(),
                )
            }
        };

        // Update the names/uuid maps. These have to mask out entries
        // that are recycled or tombstones, so these pretend as "deleted"
        // and can trigger correct actions.

        let mask_pre = pre.and_then(|e| e.mask_recycled_ts());
        let mask_pre = if !uuid_same {
            // Okay, so if the uuids are different this is probably from
            // a replication conflict.  We can't just use the normal none/some
            // check from the Entry::idx functions as they only yield partial
            // changes. Because the uuid is changing, we have to treat pre
            // as a deleting entry, regardless of what state post is in.
            let uuid = mask_pre.map(|e| e.get_uuid()).ok_or_else(|| {
                admin_error!("Invalid entry state - possible memory corruption");
                OperationError::InvalidState
            })?;

            let (n2u_add, n2u_rem) = Entry::idx_name2uuid_diff(mask_pre, None);
            // There will never be content to add.
            assert!(n2u_add.is_none());

            let (eid2u_add, eid2u_rem) = Entry::idx_externalid2uuid_diff(mask_pre, None);
            // There will never be content to add.
            assert!(eid2u_add.is_none());

            let u2s_act = Entry::idx_uuid2spn_diff(mask_pre, None);
            let u2r_act = Entry::idx_uuid2rdn_diff(mask_pre, None);

            trace!(?n2u_rem, ?eid2u_rem, ?u2s_act, ?u2r_act,);

            // Write the changes out to the backend
            if let Some(rem) = n2u_rem {
                self.idlayer.write_name2uuid_rem(rem)?
            }

            if let Some(rem) = eid2u_rem {
                self.idlayer.write_externalid2uuid_rem(rem)?
            }

            match u2s_act {
                None => {}
                Some(Ok(k)) => self.idlayer.write_uuid2spn(uuid, Some(k))?,
                Some(Err(_)) => self.idlayer.write_uuid2spn(uuid, None)?,
            }

            match u2r_act {
                None => {}
                Some(Ok(k)) => self.idlayer.write_uuid2rdn(uuid, Some(k))?,
                Some(Err(_)) => self.idlayer.write_uuid2rdn(uuid, None)?,
            }
            // Return none, mask_pre is now completed.
            None
        } else {
            // Return the state.
            mask_pre
        };

        let mask_post = post.and_then(|e| e.mask_recycled_ts());
        let (n2u_add, n2u_rem) = Entry::idx_name2uuid_diff(mask_pre, mask_post);
        let (eid2u_add, eid2u_rem) = Entry::idx_externalid2uuid_diff(mask_pre, mask_post);

        let u2s_act = Entry::idx_uuid2spn_diff(mask_pre, mask_post);
        let u2r_act = Entry::idx_uuid2rdn_diff(mask_pre, mask_post);

        trace!(
            ?n2u_add,
            ?n2u_rem,
            ?eid2u_add,
            ?eid2u_rem,
            ?u2s_act,
            ?u2r_act
        );

        // Write the changes out to the backend
        if let Some(add) = n2u_add {
            self.idlayer.write_name2uuid_add(e_uuid, add)?
        }
        if let Some(rem) = n2u_rem {
            self.idlayer.write_name2uuid_rem(rem)?
        }

        if let Some(add) = eid2u_add {
            self.idlayer.write_externalid2uuid_add(e_uuid, add)?
        }
        if let Some(rem) = eid2u_rem {
            self.idlayer.write_externalid2uuid_rem(rem)?
        }

        match u2s_act {
            None => {}
            Some(Ok(k)) => self.idlayer.write_uuid2spn(e_uuid, Some(k))?,
            Some(Err(_)) => self.idlayer.write_uuid2spn(e_uuid, None)?,
        }

        match u2r_act {
            None => {}
            Some(Ok(k)) => self.idlayer.write_uuid2rdn(e_uuid, Some(k))?,
            Some(Err(_)) => self.idlayer.write_uuid2rdn(e_uuid, None)?,
        }

        // Extremely Cursed - Okay, we know that self.idxmeta will NOT be changed
        // in this function, but we need to borrow self as mut for the caches in
        // get_idl to work. As a result, this causes a double borrow. To work around
        // this we discard the lifetime on idxmeta, because we know that it will
        // remain constant for the life of the operation.

        let idxmeta = unsafe { &(*(&self.idxmeta_wr.idxkeys as *const _)) };

        let idx_diff = Entry::idx_diff(idxmeta, pre, post);

        idx_diff.into_iter()
            .try_for_each(|act| {
                match act {
                    Ok((attr, itype, idx_key)) => {
                        trace!("Adding {:?} idx -> {:?}: {:?}", itype, attr, idx_key);
                        match self.idlayer.get_idl(attr, itype, &idx_key)? {
                            Some(mut idl) => {
                                idl.insert_id(e_id);
                                if cfg!(debug_assertions)
                                    && *attr == Attribute::Uuid && itype == IndexType::Equality {
                                        // This means a duplicate UUID has appeared in the index.
                                        if idl.len() > 1 {
                                            trace!(duplicate_idl = ?idl, ?idx_key);
                                        }
                                        debug_assert!(idl.len() <= 1);
                                }
                                self.idlayer.write_idl(attr, itype, &idx_key, &idl)
                            }
                            None => {
                                warn!(
                                    "WARNING: index {:?} {:?} was not found. YOU MUST REINDEX YOUR DATABASE",
                                    attr, itype
                                );
                                Ok(())
                            }
                        }
                    }
                    Err((attr, itype, idx_key)) => {
                        trace!("Removing {:?} idx -> {:?}: {:?}", itype, attr, idx_key);
                        match self.idlayer.get_idl(attr, itype, &idx_key)? {
                            Some(mut idl) => {
                                idl.remove_id(e_id);
                                if cfg!(debug_assertions) && *attr == Attribute::Uuid && itype == IndexType::Equality {
                                        // This means a duplicate UUID has appeared in the index.
                                        if idl.len() > 1 {
                                            trace!(duplicate_idl = ?idl, ?idx_key);
                                        }
                                        debug_assert!(idl.len() <= 1);
                                }
                                self.idlayer.write_idl(attr, itype, &idx_key, &idl)
                            }
                            None => {
                                warn!(
                                    "WARNING: index {:?} {:?} was not found. YOU MUST REINDEX YOUR DATABASE",
                                    attr, itype
                                );
                                Ok(())
                            }
                        }
                    }
                }
            })
        // End try_for_each
    }

    #[allow(dead_code)]
    fn missing_idxs(&mut self) -> Result<Vec<(Attribute, IndexType)>, OperationError> {
        let idx_table_list = self.get_idlayer().list_idxs()?;

        // Turn the vec to a real set
        let idx_table_set: HashSet<_> = idx_table_list.into_iter().collect();

        let missing: Vec<_> = self
            .idxmeta_wr
            .idxkeys
            .keys()
            .filter_map(|ikey| {
                // what would the table name be?
                let tname = format!("idx_{}_{}", ikey.itype.as_idx_str(), ikey.attr.as_str());
                trace!("Checking for {}", tname);

                if idx_table_set.contains(&tname) {
                    None
                } else {
                    Some((ikey.attr.clone(), ikey.itype))
                }
            })
            .collect();
        Ok(missing)
    }

    fn create_idxs(&mut self) -> Result<(), OperationError> {
        // Create name2uuid and uuid2name
        trace!("Creating index -> name2uuid");
        self.idlayer.create_name2uuid()?;

        trace!("Creating index -> externalid2uuid");
        self.idlayer.create_externalid2uuid()?;

        trace!("Creating index -> uuid2spn");
        self.idlayer.create_uuid2spn()?;

        trace!("Creating index -> uuid2rdn");
        self.idlayer.create_uuid2rdn()?;

        self.idxmeta_wr
            .idxkeys
            .keys()
            .try_for_each(|ikey| self.idlayer.create_idx(&ikey.attr, ikey.itype))
    }

    pub fn upgrade_reindex(&mut self, v: i64) -> Result<(), OperationError> {
        let dbv = self.get_db_index_version()?;
        admin_debug!(?dbv, ?v, "upgrade_reindex");
        if dbv < v {
            self.reindex(false)?;
            self.set_db_index_version(v)
        } else {
            Ok(())
        }
    }

    #[instrument(level = "info", skip_all)]
    pub fn reindex(&mut self, immediate: bool) -> Result<(), OperationError> {
        let notice_immediate = immediate || (cfg!(not(test)) && cfg!(not(debug_assertions)));

        info!(
            immediate = notice_immediate,
            "System reindex: started - this may take a long time!"
        );

        // Purge the idxs
        // TODO: Purge in memory idxs.
        self.idlayer.danger_purge_idxs()?;

        // Using the index metadata on the txn, create all our idx tables
        // TODO: Needs to create all the in memory indexes.
        self.create_idxs()?;

        // Now, we need to iterate over everything in id2entry and index them
        // Future idea: Do this in batches of X amount to limit memory
        // consumption.
        let idl = IdList::AllIds;
        let entries = self.idlayer.get_identry(&idl).inspect_err(|err| {
            error!(?err, "get_identry failure");
        })?;

        let mut count = 0;

        // This is the longest phase of reindexing, so we have a "progress" display here.
        entries
            .iter()
            .try_for_each(|e| {
                if immediate {
                    count += 1;
                    if count % 2500 == 0 {
                        eprint!("{count}");
                    } else if count % 250 == 0 {
                        eprint!(".");
                    }
                }

                self.entry_index(None, Some(e))
            })
            .inspect_err(|err| {
                error!(?err, "reindex failed");
            })?;

        if immediate {
            eprintln!(" done ✅");
        }

        info!(immediate, "Reindexed {count} entries");

        info!("Optimising Indexes: started");
        self.idlayer.optimise_dirty_idls();
        info!("Optimising Indexes: complete ✅");
        info!("Calculating Index Optimisation Slopes: started");
        self.idlayer.analyse_idx_slopes().inspect_err(|err| {
            error!(?err, "index optimisation failed");
        })?;
        info!("Calculating Index Optimisation Slopes: complete ✅");
        info!("System reindex: complete 🎉");
        Ok(())
    }

    /// ⚠️  - This function will destroy all indexes in the database.
    ///
    /// It should only be called internally by the backend in limited and
    /// specific situations.
    fn danger_purge_idxs(&mut self) -> Result<(), OperationError> {
        self.get_idlayer().danger_purge_idxs()
    }

    /// ⚠️  - This function will destroy all entries and indexes in the database.
    ///
    /// It should only be called internally by the backend in limited and
    /// specific situations.
    pub(crate) fn danger_delete_all_db_content(&mut self) -> Result<(), OperationError> {
        // Everything staged so far is gone with the content; the archive records the
        // truncation ahead of whatever this transaction writes afterwards.
        if self.wal.is_some() {
            self.wal_pending.clear();
            self.wal_truncate = true;
        }
        self.get_ruv().clear();
        self.get_idlayer()
            .danger_purge_id2entry()
            .and_then(|_| self.danger_purge_idxs())
    }

    #[cfg(test)]
    pub fn load_test_idl(
        &mut self,
        attr: &Attribute,
        itype: IndexType,
        idx_key: &str,
    ) -> Result<Option<IDLBitRange>, OperationError> {
        self.get_idlayer().get_idl(attr, itype, idx_key)
    }

    fn is_idx_slopeyness_generated(&mut self) -> Result<bool, OperationError> {
        self.get_idlayer().is_idx_slopeyness_generated()
    }

    fn get_idx_slope(&mut self, ikey: &IdxKey) -> Result<IdxSlope, OperationError> {
        // Do we have the slopeyness?
        let slope = self
            .get_idlayer()
            .get_idx_slope(ikey)?
            .unwrap_or_else(|| get_idx_slope_default(ikey));
        trace!("index slope - {:?} -> {:?}", ikey, slope);
        Ok(slope)
    }

    pub fn restore<IN>(
        &mut self,
        input: IN,
        compression: BackupCompression,
    ) -> Result<(), OperationError>
    where
        IN: std::io::Read,
    {
        // load all entries into RAM, may need to change this later
        // if the size of the database compared to RAM is an issue

        let dbbak_option: Result<DbBackup, serde_json::Error> = match compression {
            BackupCompression::NoCompression => serde_json::from_reader(input),
            BackupCompression::Gzip => {
                let decoder = flate2::read::GzDecoder::new(input);
                serde_json::from_reader(decoder)
            }
        };

        let dbbak = dbbak_option.map_err(|err| {
            error!(?err, "serde_json error");
            OperationError::SerdeJsonError
        })?;

        self.danger_delete_all_db_content().inspect_err(|err| {
            error!(?err, "delete_all_db_content failed");
        })?;

        let idlayer = self.get_idlayer();

        let (dbentries, repl_meta, maybe_version) = match dbbak {
            DbBackup::V1(dbentries) => (dbentries, None, None),
            DbBackup::V2 {
                db_s_uuid,
                db_d_uuid,
                db_ts_max,
                entries,
            } => {
                // Do stuff.
                idlayer.write_db_s_uuid(db_s_uuid)?;
                idlayer.write_db_d_uuid(db_d_uuid)?;
                idlayer.set_db_ts_max(db_ts_max)?;
                (entries, None, None)
            }
            DbBackup::V3 {
                db_s_uuid,
                db_d_uuid,
                db_ts_max,
                keyhandles,
                entries,
            } => {
                // Do stuff.
                idlayer.write_db_s_uuid(db_s_uuid)?;
                idlayer.write_db_d_uuid(db_d_uuid)?;
                idlayer.set_db_ts_max(db_ts_max)?;
                idlayer.set_key_handles(keyhandles)?;
                (entries, None, None)
            }
            DbBackup::V4 {
                db_s_uuid,
                db_d_uuid,
                db_ts_max,
                keyhandles,
                repl_meta,
                entries,
            } => {
                // Do stuff.
                idlayer.write_db_s_uuid(db_s_uuid)?;
                idlayer.write_db_d_uuid(db_d_uuid)?;
                idlayer.set_db_ts_max(db_ts_max)?;
                idlayer.set_key_handles(keyhandles)?;
                (entries, Some(repl_meta), None)
            }
            DbBackup::V5 {
                version,
                db_s_uuid,
                db_d_uuid,
                db_ts_max,
                keyhandles,
                repl_meta,
                entries,
            } => {
                // Do stuff.
                idlayer.write_db_s_uuid(db_s_uuid)?;
                idlayer.write_db_d_uuid(db_d_uuid)?;
                idlayer.set_db_ts_max(db_ts_max)?;
                idlayer.set_key_handles(keyhandles)?;
                (entries, Some(repl_meta), Some(version))
            }
        };

        if let Some(version) = maybe_version {
            if version != env!("KUBIDM_PKG_SERIES") {
                error!("The provided backup data is from server version {} and is unable to be restored on this instance ({})", version, env!("KUBIDM_PKG_SERIES"));
                return Err(OperationError::DB0001MismatchedRestoreVersion);
            }
        } else {
            error!("The provided backup data is from an older server version and is unable to be restored.");
            return Err(OperationError::DB0002MismatchedRestoreVersion);
        };

        // Rebuild the RUV from the backup.
        match repl_meta {
            Some(DbReplMeta::V1 { ruv: db_ruv }) => {
                self.get_ruv()
                    .restore(db_ruv.into_iter().map(|db_cid| db_cid.into()))?;
            }
            None => {
                warn!("Unable to restore replication metadata, this server may need a refresh.");
            }
        }

        info!("Restoring {} entries ...", dbentries.len());

        // Now, we setup all the entries with new ids.
        let mut id_max = 0;
        let identries: Result<Vec<IdRawEntry>, _> = dbentries
            .iter()
            .map(|e| {
                id_max += 1;
                let data = serde_json::to_vec(&e).map_err(|_| OperationError::SerdeCborError)?;
                Ok(IdRawEntry { id: id_max, data })
            })
            .collect();

        let idlayer = self.get_idlayer();

        idlayer.write_identries_raw(identries?.into_iter())?;

        info!("Restored {} entries", dbentries.len());

        let vr = self.verify();
        if vr.is_empty() {
            Ok(())
        } else {
            Err(OperationError::ConsistencyError(
                vr.into_iter().filter_map(|v| v.err()).collect(),
            ))
        }
    }

    /// If any RUV elements are present in the DB, load them now. This provides us with
    /// the RUV boundaries and change points from previous operations of the server, so
    /// that ruv_rebuild can "fill in" the gaps.
    ///
    /// # SAFETY
    ///
    /// Note that you should only call this function during the server startup
    /// to reload the RUV data from the entries of the database.
    ///
    /// Before calling this, the in memory ruv MUST be clear.
    #[instrument(level = "debug", name = "be::ruv_rebuild", skip_all)]
    fn ruv_reload(&mut self) -> Result<(), OperationError> {
        let idlayer = self.get_idlayer();

        let db_ruv = idlayer.get_db_ruv()?;

        // Setup the CID's that existed previously. We don't need to know what entries
        // they affect, we just need them to ensure that we have ranges for replication
        // comparison to take effect properly.
        self.get_ruv().restore(db_ruv)?;

        // Then populate the RUV with the data from the entries.
        self.ruv_rebuild()
    }

    #[instrument(level = "debug", name = "be::ruv_rebuild", skip_all)]
    fn ruv_rebuild(&mut self) -> Result<(), OperationError> {
        // Rebuild the ruv!
        // For now this has to read from all the entries in the DB, but in the future
        // we'll actually store this properly (?). If it turns out this is really fast
        // we may just rebuild this always on startup.

        // NOTE: An important detail is that we don't rely on indexes here!

        let idl = IdList::AllIds;
        let entries = self.get_idlayer().get_identry(&idl).map_err(|e| {
            admin_error!(?e, "get_identry failed");
            e
        })?;

        self.get_ruv().rebuild(&entries)?;

        Ok(())
    }

    pub fn quarantine_entry(&mut self, id: u64) -> Result<(), OperationError> {
        self.get_idlayer().quarantine_entry(id)?;
        // We have to set the index version to 0 so that on next start we force
        // a reindex to automatically occur.
        self.set_db_index_version(0)
    }

    pub fn restore_quarantined(&mut self, id: u64) -> Result<(), OperationError> {
        self.get_idlayer().restore_quarantined(id)?;
        // We have to set the index version to 0 so that on next start we force
        // a reindex to automatically occur.
        self.set_db_index_version(0)
    }

    #[cfg(any(test, debug_assertions))]
    pub fn clear_cache(&mut self) -> Result<(), OperationError> {
        self.get_idlayer().clear_cache()
    }

    pub fn commit(self) -> Result<(), OperationError> {
        let BackendWriteTransaction {
            mut idlayer,
            idxmeta_wr,
            ruv,
            wal,
            wal_pending,
            wal_truncate,
            wal_server_uuid,
            wal_cid,
            wal_stage_failed,
        } = self;

        // The archive is told before the database commits a transaction it must archive,
        // so that an unclean stop between the commit and its archiving is noticed.
        let archives = wal_commit_archives(
            !wal_pending.is_empty(),
            wal_truncate,
            wal_stage_failed,
            wal_server_uuid.is_some(),
        );
        let prepared = match (&wal, &wal_cid) {
            (Some(wal), Some(cid)) if archives => {
                lock_wal(wal).prepare_commit(cid.ts);
                Some(wal)
            }
            _ => None,
        };

        // write the ruv content back to the db.
        let committed = idlayer
            .write_db_ruv(ruv.added(), ruv.removed())
            .and_then(|()| idlayer.commit());
        if let Err(err) = committed {
            if let Some(wal) = prepared {
                lock_wal(wal).abandon_commit();
            }
            return Err(err);
        }
        ruv.commit();
        idxmeta_wr.commit();

        // The database commit succeeded. Only now does the archive learn about this
        // transaction, so the WAL never contains uncommitted state. A failure here is
        // reported loudly but does not fail the write: the data is safely committed, and
        // what is lost is the ability to recover this transaction from the archive until
        // the next base backup covers it.
        if let Some(wal) = wal {
            Self::wal_archive_committed(
                &wal,
                wal_cid.as_ref(),
                wal_truncate,
                wal_server_uuid,
                wal_pending,
                wal_stage_failed,
            );
        }

        Ok(())
    }

    fn wal_archive_committed(
        wal: &SharedWalArchiver,
        wal_cid: Option<&Cid>,
        wal_truncate: bool,
        wal_server_uuid: Option<Uuid>,
        wal_pending: BTreeMap<u64, WalPendingOp>,
        wal_stage_failed: bool,
    ) {
        if !wal_commit_archives(
            !wal_pending.is_empty(),
            wal_truncate,
            wal_stage_failed,
            wal_server_uuid.is_some(),
        ) {
            // Nothing to archive, but the database now records this transaction as its
            // last one: the journal of the open segment notes it, so that an unclean stop
            // right after it is known to have lost nothing.
            if let Some(cid) = wal_cid {
                lock_wal(wal).note_commit(cid.ts);
            }
            return;
        }

        {
            let mut archiver = lock_wal(wal);

            // The records of this transaction already belong to the new identity.
            if let Some(server_uuid) = wal_server_uuid {
                archiver.change_server_uuid(server_uuid, wal_cid.map(|cid| cid.ts));
            }

            if wal_stage_failed {
                archiver.note_failure(wal_cid.map(|cid| cid.ts));
                error!(
                    "WAL ARCHIVE HOLE: a committed transaction could not be fully recorded; \
                     point-in-time recovery can not reproduce it. Take a new base backup."
                );
            }

            let Some(cid) = wal_cid else {
                archiver.note_failure(None);
                error!(
                    records = wal_pending.len(),
                    "WAL ARCHIVE HOLE: a committed transaction carried no CID and its records \
                     were dropped; point-in-time recovery can not reproduce it. Take a new base \
                     backup."
                );
                return;
            };

            let record_count = wal_pending.len();
            archiver.stage_transaction(cid, wal_truncate, wal_pending);
            trace!(%cid, records = record_count, "WAL records archived");
        }

        // A segment this transaction closed is compressed and written without the archiver
        // lock, so that the archive task is never held up by it. A failure is logged and
        // retried; the records stay in memory meanwhile.
        if let Some(cid) = wal_cid {
            let _ = write_closed_segments(wal, cid.ts, false);
        }
    }

    /// Tag the records this transaction archives with `cid`. The query server calls this
    /// at commit so that changes applied without a CID of their own, such as replicated
    /// entries, are archived under the transaction that made them visible locally.
    pub fn set_wal_cid(&mut self, cid: &Cid) {
        if self.wal.is_some() {
            self.wal_cid = Some(cid.clone());
        }
    }

    /// Stage the serialised state of `e` for the archive. `create` only records intent;
    /// replay treats creates and modifies alike.
    fn wal_stage_write(&mut self, cid: Option<&Cid>, e: &EntrySealedCommitted, create: bool) {
        if self.wal.is_none() {
            return;
        }
        if let Some(cid) = cid {
            self.wal_cid = Some(cid.clone());
        }
        let entry_uuid = e.get_uuid();
        let entry_data = match serde_json::to_vec(&e.to_dbentry()) {
            Ok(data) => data,
            Err(err) => {
                error!(
                    ?err,
                    ?entry_uuid,
                    "Unable to serialise entry for the WAL archive"
                );
                self.wal_stage_failed = true;
                return;
            }
        };
        // An entry created earlier in this transaction stays a create when a later step
        // of the same transaction (a plugin, for example) modifies it again.
        let created_in_txn = matches!(
            self.wal_pending.get(&e.get_id()),
            Some(WalPendingOp::Create { .. })
        );
        let op = if (create && !self.wal_pending.contains_key(&e.get_id())) || created_in_txn {
            WalPendingOp::Create {
                entry_uuid,
                entry_data,
            }
        } else {
            WalPendingOp::Modify {
                entry_uuid,
                entry_data,
            }
        };
        self.wal_pending.insert(e.get_id(), op);
    }

    /// Stage the removal of `e` for the archive.
    fn wal_stage_delete(&mut self, cid: Option<&Cid>, e: &EntrySealedCommitted) {
        if self.wal.is_none() {
            return;
        }
        if let Some(cid) = cid {
            self.wal_cid = Some(cid.clone());
        }
        self.wal_pending.insert(
            e.get_id(),
            WalPendingOp::Delete {
                entry_uuid: e.get_uuid(),
            },
        );
    }

    #[cfg(test)]
    pub(crate) fn wal_pending_len(&self) -> usize {
        self.wal_pending.len()
    }

    /// Apply archived WAL records to this database for point-in-time recovery.
    ///
    /// The database is expected to hold a restored base backup. Records are applied in
    /// CID order; each one overwrites (or removes) the entry with its UUID, since the
    /// restore renumbered the `id2entry` ids. Entries unknown to the database are
    /// created under fresh ids. The indexes are purged, as `restore` does, so the caller
    /// must reindex after committing. The RUV is rebuilt from the entries at the next
    /// start, exactly as after a restore.
    pub fn wal_apply(
        &mut self,
        mut records: Vec<WalEntryRecord>,
    ) -> Result<WalApplyReport, OperationError> {
        records.sort_by_key(|record| (record.cid_ts, record.entry_id));

        // The ids the restored database assigned to each entry, read from the raw rows
        // without loading every entry.
        let mut uuid_to_id: BTreeMap<Uuid, u64> = BTreeMap::new();
        let mut id_max_in_use = 0;
        for raw in self.get_idlayer().get_identry_raw(&IdList::AllIds)? {
            let entry_uuid = serde_json::from_slice::<DbEntry>(&raw.data)
                .ok()
                .and_then(|entry| entry.stored_uuid())
                .ok_or_else(|| {
                    admin_error!(entry_id = raw.id, "Restored entry has no readable uuid");
                    OperationError::CorruptedEntry(raw.id)
                })?;
            uuid_to_id.insert(entry_uuid, raw.id);
            id_max_in_use = id_max_in_use.max(raw.id);
        }

        let mut report = WalApplyReport::default();
        // The final state of every entry the records touch: Some(bytes) to write, None to
        // remove.
        let mut final_state: BTreeMap<Uuid, Option<Vec<u8>>> = BTreeMap::new();

        for record in records {
            report.last_cid = Some(record.cid());
            match record.operation {
                WalOperationRecord::Truncate => {
                    // A replication refresh: it also replaced the domain and server uuids
                    // and the key material, which the archive does not hold. Replaying the
                    // entries alone would mix the refreshed directory with the identity of
                    // the base, so recovery needs a base taken after the refresh.
                    admin_error!(
                        cid = ?report.last_cid,
                        "The WAL records include a replication refresh; recovery can not \
                         replay across it. Recover from a base backup taken after it."
                    );
                    return Err(OperationError::InvalidState);
                }
                WalOperationRecord::Create { entry_data } => {
                    final_state.insert(record.entry_uuid, Some(entry_data));
                    report.created += 1;
                }
                WalOperationRecord::Modify { entry_data } => {
                    final_state.insert(record.entry_uuid, Some(entry_data));
                    report.modified += 1;
                }
                WalOperationRecord::Delete => {
                    final_state.insert(record.entry_uuid, None);
                    report.deleted += 1;
                }
            }
            report.applied += 1;
        }

        // The cached maximum id is not refreshed by a raw restore in the same transaction,
        // so take the highest id actually in use as well.
        let id_max_cached = self.get_idlayer().get_id2entry_max_id()?;
        let mut id_max = id_max_in_use.max(id_max_cached);
        let mut writes: Vec<IdRawEntry> = Vec::new();
        let mut deletes: Vec<u64> = Vec::new();

        for (entry_uuid, state) in final_state {
            match state {
                Some(data) => {
                    // Reject bytes that are not an entry before they reach the database.
                    let parsed: DbEntry = serde_json::from_slice(&data).map_err(|err| {
                        admin_error!(?err, ?entry_uuid, "WAL record does not hold a valid entry");
                        OperationError::SerdeJsonError
                    })?;
                    let id = match uuid_to_id.get(&entry_uuid) {
                        Some(id) => *id,
                        None => {
                            id_max += 1;
                            uuid_to_id.insert(entry_uuid, id_max);
                            id_max
                        }
                    };
                    Entry::from_dbentry(parsed, id).map_err(|err| {
                        admin_error!(
                            entry_id = id,
                            ?entry_uuid,
                            reason = %err,
                            "WAL record holds an entry this server can not load"
                        );
                        OperationError::CorruptedEntry(id)
                    })?;
                    writes.push(IdRawEntry { id, data });
                }
                None => {
                    if let Some(id) = uuid_to_id.remove(&entry_uuid) {
                        deletes.push(id);
                    }
                }
            }
        }

        // The indexes describe the base backup, not the replayed state. Drop them so the
        // reindex that follows rebuilds them, as after a restore.
        self.danger_purge_idxs()?;

        let idlayer = self.get_idlayer();
        if !writes.is_empty() {
            idlayer.write_identries_raw(writes.into_iter())?;
        }
        if !deletes.is_empty() {
            idlayer.delete_identry(deletes.into_iter())?;
        }
        if id_max > id_max_cached {
            idlayer.set_id2entry_max_id(id_max);
        }

        // Keep CID generation monotonic on the recovered server.
        if let Some(last_cid) = &report.last_cid {
            let current = self.get_idlayer().get_db_ts_max()?.unwrap_or_default();
            if last_cid.ts > current {
                self.set_db_ts_max(last_cid.ts)?;
            }
        }

        let vr = self.verify();
        if vr.is_empty() {
            Ok(report)
        } else {
            Err(OperationError::ConsistencyError(
                vr.into_iter().filter_map(|v| v.err()).collect(),
            ))
        }
    }

    pub(crate) fn reset_db_s_uuid(&mut self) -> Result<Uuid, OperationError> {
        // The value is missing. Generate a new one and store it.
        let nsid = Uuid::new_v4();
        self.get_idlayer().write_db_s_uuid(nsid).map_err(|err| {
            error!(?err, "Unable to persist server uuid");
            err
        })?;
        // The archive learns about the new identity when this transaction commits.
        if self.wal.is_some() {
            self.wal_server_uuid = Some(nsid);
        }
        Ok(nsid)
    }
    pub fn get_db_s_uuid(&mut self) -> Result<Uuid, OperationError> {
        let res = self.get_idlayer().get_db_s_uuid().map_err(|err| {
            error!(?err, "Failed to read server uuid");
            err
        })?;
        match res {
            Some(s_uuid) => Ok(s_uuid),
            None => self.reset_db_s_uuid(),
        }
    }

    /// This generates a new domain UUID and stores it into the database,
    /// returning the new UUID
    fn reset_db_d_uuid(&mut self) -> Result<Uuid, OperationError> {
        let nsid = Uuid::new_v4();
        self.get_idlayer().write_db_d_uuid(nsid).map_err(|err| {
            error!(?err, "Unable to persist domain uuid");
            err
        })?;
        Ok(nsid)
    }

    /// Manually set a new domain UUID and store it into the DB. This is used
    /// as part of a replication refresh.
    pub fn set_db_d_uuid(&mut self, nsid: Uuid) -> Result<(), OperationError> {
        self.get_idlayer().write_db_d_uuid(nsid)
    }

    /// This pulls the domain UUID from the database
    pub fn get_db_d_uuid(&mut self) -> Result<Uuid, OperationError> {
        let res = self.get_idlayer().get_db_d_uuid().map_err(|err| {
            error!(?err, "Failed to read domain uuid");
            err
        })?;
        match res {
            Some(d_uuid) => Ok(d_uuid),
            None => self.reset_db_d_uuid(),
        }
    }

    pub fn set_db_ts_max(&mut self, ts: Duration) -> Result<(), OperationError> {
        self.get_idlayer().set_db_ts_max(ts)
    }

    pub fn get_db_ts_max(&mut self, ts: Duration) -> Result<Duration, OperationError> {
        // if none, return ts. If found, return it.
        match self.get_idlayer().get_db_ts_max()? {
            Some(dts) => Ok(dts),
            None => Ok(ts),
        }
    }

    fn get_db_index_version(&mut self) -> Result<i64, OperationError> {
        self.get_idlayer().get_db_index_version()
    }

    fn set_db_index_version(&mut self, v: i64) -> Result<(), OperationError> {
        self.get_idlayer().set_db_index_version(v)
    }
}

// We have a number of hardcoded, "obvious" slopes that should
// exist. We return these when the analysis has not been run, as
// these are values that are generally "good enough" for most applications
fn get_idx_slope_default(ikey: &IdxKey) -> IdxSlope {
    match (ikey.attr.as_str(), &ikey.itype) {
        (ATTR_NAME, IndexType::Equality)
        | (ATTR_SPN, IndexType::Equality)
        | (ATTR_UUID, IndexType::Equality) => 1,
        (ATTR_CLASS, IndexType::Equality) => 180,
        (_, IndexType::Equality) => 45,
        (_, IndexType::SubString) => 90,
        (_, IndexType::Presence) => 90,
        (_, IndexType::Ordering) => 120,
    }
}

// In the future this will do the routing between the chosen backends etc.
impl Backend {
    #[instrument(level = "debug", name = "be::new", skip_all)]
    pub fn new(
        mut cfg: BackendConfig,
        // path: &str,
        // mut pool_size: u32,
        // fstype: FsType,
        idxkeys: Vec<IdxKey>,
        vacuum: bool,
    ) -> Result<Self, OperationError> {
        debug!(db_tickets = ?cfg.pool_size, profile = %env!("KUBIDM_PROFILE_NAME"), cpu_flags = %env!("KUBIDM_CPU_FLAGS"));

        // If in memory, reduce pool to 1
        if cfg.path.as_os_str().is_empty() {
            cfg.pool_size = 1;
        }

        // Setup idxkeys here. By default we set these all to "max slope" aka
        // all indexes are "equal" but also worse case unless analysed.
        //
        // During startup this will be "fixed" as the schema core will call reload_idxmeta
        // which will trigger a reload of the analysis data (if present).
        let idxkeys: HashMap<_, _> = idxkeys
            .into_iter()
            .map(|ikey| {
                let slope = get_idx_slope_default(&ikey);
                (ikey, slope)
            })
            .collect();

        // Load the replication update vector here. Initially we build an in memory
        // RUV, and then we load it from the DB.
        let ruv = Arc::new(ReplicationUpdateVector::default());

        // this has a ::memory() type, but will path == "" work?
        let idlayer = Arc::new(IdlArcSqlite::new(&cfg, vacuum)?);
        let mut be = Backend {
            cfg,
            idlayer,
            ruv,
            wal: None,
            idxmeta: Arc::new(CowCell::new(IdxMeta::new(idxkeys))),
        };

        // Now complete our setup with a txn
        // In this case we can use an empty idx meta because we don't
        // access any parts of
        // the indexing subsystem here.
        let mut idl_write = be.idlayer.write()?;
        idl_write
            .setup()
            .and_then(|_| idl_write.commit())
            .map_err(|e| {
                admin_error!(?e, "Failed to setup idlayer");
                e
            })?;

        // Load/generate any in memory indexes.
        // I think here we don't actually care about in memory indexes until
        // later?

        // Now rebuild the ruv.
        let wal_segments_path = be.cfg.wal_segments_path()?;
        let mut be_write = be.write()?;
        let wal_identity = match wal_segments_path.as_ref() {
            Some(_) => Some((
                be_write.get_db_s_uuid()?,
                be_write.get_idlayer().get_db_ts_max()?,
            )),
            None => None,
        };
        be_write
            .ruv_reload()
            .and_then(|_| be_write.commit())
            .map_err(|e| {
                admin_error!(?e, "Failed to reload ruv");
                e
            })?;

        // WAL archiving starts only once the database is set up, so that the server uuid
        // the segments are tagged with is the one the database carries.
        if let (Some(segments_path), Some((s_uuid, db_ts_max)), Some(wal_cfg)) =
            (wal_segments_path, wal_identity, be.cfg.wal_archive.clone())
        {
            let archiver =
                WalArchiver::open(wal_cfg, s_uuid, segments_path, db_ts_max).map_err(|err| {
                    admin_error!(%err, "Failed to start WAL archiving");
                    OperationError::FsError
                })?;
            be.wal = Some(Arc::new(Mutex::new(archiver)));
        }

        Ok(be)
    }

    /// The WAL archiver, when point-in-time recovery is enabled on this backend.
    pub fn wal_archiver(&self) -> Option<SharedWalArchiver> {
        self.wal.clone()
    }

    pub fn get_pool_size(&self) -> u32 {
        debug_assert!(self.cfg.pool_size > 0);
        self.cfg.pool_size
    }

    pub fn try_quiesce(&self) {
        self.idlayer.try_quiesce();
    }

    pub fn read(&self) -> Result<BackendReadTransaction<'_>, OperationError> {
        Ok(BackendReadTransaction {
            idlayer: self.idlayer.read()?,
            idxmeta: self.idxmeta.read(),
            ruv: self.ruv.read(),
        })
    }

    pub fn write(&self) -> Result<BackendWriteTransaction<'_>, OperationError> {
        Ok(BackendWriteTransaction {
            idlayer: self.idlayer.write()?,
            idxmeta_wr: self.idxmeta.write(),
            ruv: self.ruv.write(),
            wal: self.wal.clone(),
            wal_pending: BTreeMap::new(),
            wal_truncate: false,
            wal_server_uuid: None,
            wal_cid: None,
            wal_stage_failed: false,
        })
    }
}

// What are the possible actions we'll receive here?

#[cfg(test)]
mod tests {
    use super::{
        super::entry::{Entry, EntryInit, EntryNew},
        Backend, BackendConfig, BackendTransaction, BackendWriteTransaction, DbBackup, DbEntry,
        IdList, IdxKey, Limits, OperationError,
    };
    use crate::{
        be::{
            dbentry::DbEntryVers,
            dbrepl::DbEntryChangeState,
            dbvalue::{DbCidV1, DbValueSetV2},
        },
        prelude::*,
        repl::cid::Cid,
        repl::wal::{WalEntryRecord, WalOperationRecord},
        value::{IndexType, PartialValue, Value},
    };
    use idlset::v2::IDLBitRange;
    use kubidm_proto::backup::{BackupCompression, WalArchiveConfig};
    use std::{
        iter::FromIterator,
        sync::{Arc, LazyLock},
        time::Duration,
    };

    static CID_ZERO: LazyLock<Cid> = LazyLock::new(Cid::new_zero);
    static CID_ONE: LazyLock<Cid> = LazyLock::new(|| Cid::new_count(1));
    static CID_TWO: LazyLock<Cid> = LazyLock::new(|| Cid::new_count(2));
    static CID_THREE: LazyLock<Cid> = LazyLock::new(|| Cid::new_count(3));
    static CID_ADV: LazyLock<Cid> = LazyLock::new(|| Cid::new_count(10));

    macro_rules! run_test {
        ($test_fn:expr) => {{
            sketching::test_init();

            // This is a demo idxmeta, purely for testing.
            let idxmeta = vec![
                IdxKey {
                    attr: Attribute::Name.into(),
                    itype: IndexType::Equality,
                },
                IdxKey {
                    attr: Attribute::Name.into(),
                    itype: IndexType::Presence,
                },
                IdxKey {
                    attr: Attribute::Name.into(),
                    itype: IndexType::SubString,
                },
                IdxKey {
                    attr: Attribute::Uuid.into(),
                    itype: IndexType::Equality,
                },
                IdxKey {
                    attr: Attribute::Uuid.into(),
                    itype: IndexType::Presence,
                },
                IdxKey {
                    attr: Attribute::TestAttr.into(),
                    itype: IndexType::Equality,
                },
                IdxKey {
                    attr: Attribute::TestNumber.into(),
                    itype: IndexType::Equality,
                },
            ];

            let be = Backend::new(BackendConfig::new_test("main"), idxmeta, false)
                .expect("Failed to setup backend");

            let mut be_txn = be.write().unwrap();

            let r = $test_fn(&mut be_txn);
            // Commit, to guarantee it worked.
            assert!(be_txn.commit().is_ok());
            r
        }};
    }

    macro_rules! entry_exists {
        ($be:expr, $ent:expr) => {{
            let ei = $ent.clone().into_sealed_committed();
            let filt = ei
                .filter_from_attrs(&[Attribute::Uuid.into()])
                .expect("failed to generate filter")
                .into_valid_resolved();
            let lims = Limits::unlimited();
            let entries = $be.search(&lims, &filt).expect("failed to search");
            entries.first().is_some()
        }};
    }

    macro_rules! entry_attr_pres {
        ($be:expr, $ent:expr, $attr:expr) => {{
            let ei = $ent.clone().into_sealed_committed();
            let filt = ei
                .filter_from_attrs(&[Attribute::UserId.into()])
                .expect("failed to generate filter")
                .into_valid_resolved();
            let lims = Limits::unlimited();
            let entries = $be.search(&lims, &filt).expect("failed to search");
            match entries.first() {
                Some(ent) => ent.attribute_pres($attr),
                None => false,
            }
        }};
    }

    macro_rules! idl_state {
        ($be:expr, $attr:expr, $itype:expr, $idx_key:expr, $expect:expr) => {{
            let t_idl = $be
                .load_test_idl(&$attr, $itype, &$idx_key.to_string())
                .expect("IdList Load failed");
            let t = $expect.map(|v: Vec<u64>| IDLBitRange::from_iter(v));
            assert_eq!(t_idl, t);
        }};
    }

    #[test]
    fn test_be_simple_create() {
        run_test!(|be: &mut BackendWriteTransaction| {
            trace!("Simple Create");

            let empty_result = be.create(&CID_ZERO, Vec::with_capacity(0));
            trace!("{:?}", empty_result);
            assert_eq!(empty_result, Err(OperationError::EmptyRequest));

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava(Attribute::UserId, Value::from("william"));
            e.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );
            let e = e.into_sealed_new();

            let single_result = be.create(&CID_ZERO, vec![e.clone()]);

            assert!(single_result.is_ok());

            // Construct a filter
            assert!(entry_exists!(be, e));
        });
    }

    #[test]
    fn test_be_simple_search() {
        run_test!(|be: &mut BackendWriteTransaction| {
            trace!("Simple Search");

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava(Attribute::UserId, Value::from("claire"));
            e.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );
            let e = e.into_sealed_new();

            let single_result = be.create(&CID_ZERO, vec![e]);
            assert!(single_result.is_ok());
            // Test a simple EQ search

            let filt = filter_resolved!(f_eq(Attribute::UserId, PartialValue::new_utf8s("claire")));

            let lims = Limits::unlimited();

            let r = be.search(&lims, &filt);
            assert!(r.expect("Search failed!").len() == 1);

            // Test empty search

            // Test class pres

            // Search with no results
        });
    }

    #[test]
    fn test_be_search_with_invalid() {
        run_test!(|be: &mut BackendWriteTransaction| {
            trace!("Simple Search");

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava(Attribute::UserId, Value::from("bagel"));
            e.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );
            let e = e.into_sealed_new();

            let single_result = be.create(&CID_ZERO, vec![e]);
            assert!(single_result.is_ok());

            // Test Search with or condition including invalid attribute
            let filt = filter_resolved!(f_or(vec![
                f_eq(Attribute::UserId, PartialValue::new_utf8s("bagel")),
                f_invalid(Attribute::UserId)
            ]));

            let lims = Limits::unlimited();

            let r = be.search(&lims, &filt);
            assert!(r.expect("Search failed!").len() == 1);

            // Test Search with or condition including invalid attribute
            let filt = filter_resolved!(f_and(vec![
                f_eq(Attribute::UserId, PartialValue::new_utf8s("bagel")),
                f_invalid(Attribute::UserId)
            ]));

            let lims = Limits::unlimited();

            let r = be.search(&lims, &filt);
            assert!(r.expect("Search failed!").is_empty());
        });
    }

    #[test]
    fn test_be_simple_modify() {
        run_test!(|be: &mut BackendWriteTransaction| {
            trace!("Simple Modify");
            let lims = Limits::unlimited();
            // First create some entries (3?)
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::UserId, Value::from("william"));
            e1.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava(Attribute::UserId, Value::from("alice"));
            e2.add_ava(
                Attribute::Uuid,
                Value::from("4b6228ab-1dbe-42a4-a9f5-f6368222438e"),
            );

            let ve1 = e1.clone().into_sealed_new();
            let ve2 = e2.clone().into_sealed_new();

            assert!(be.create(&CID_ZERO, vec![ve1, ve2]).is_ok());
            assert!(entry_exists!(be, e1));
            assert!(entry_exists!(be, e2));

            // You need to now retrieve the entries back out to get the entry id's
            let mut results = be
                .search(&lims, &filter_resolved!(f_pres(Attribute::UserId)))
                .expect("Failed to search");

            // Get these out to usable entries.
            let r1 = results.remove(0);
            let r2 = results.remove(0);

            let mut r1 = r1.as_ref().clone().into_invalid();
            let mut r2 = r2.as_ref().clone().into_invalid();

            // Modify no id (err)
            // This is now impossible due to the state machine design.
            // However, with some unsafe ....
            let ue1 = e1.clone().into_sealed_committed();
            assert!(be
                .modify(&CID_ZERO, &[Arc::new(ue1.clone())], &[ue1])
                .is_err());
            // Modify none
            assert!(be.modify(&CID_ZERO, &[], &[]).is_err());

            // Make some changes to r1, r2.
            let pre1 = Arc::new(r1.clone().into_sealed_committed());
            let pre2 = Arc::new(r2.clone().into_sealed_committed());
            r1.add_ava(Attribute::TestAttr, Value::from("modified"));
            r2.add_ava(Attribute::TestAttr, Value::from("modified"));

            // Now ... cheat.

            let vr1 = r1.into_sealed_committed();
            let vr2 = r2.into_sealed_committed();

            // Modify single
            assert!(be
                .modify(&CID_ZERO, &[pre1], std::slice::from_ref(&vr1))
                .is_ok());
            // Assert no other changes
            assert!(entry_attr_pres!(be, vr1, Attribute::TestAttr));
            assert!(!entry_attr_pres!(be, vr2, Attribute::TestAttr));

            // Modify both
            assert!(be
                .modify(
                    &CID_ZERO,
                    &[Arc::new(vr1.clone()), pre2],
                    &[vr1.clone(), vr2.clone()]
                )
                .is_ok());

            assert!(entry_attr_pres!(be, vr1, Attribute::TestAttr));
            assert!(entry_attr_pres!(be, vr2, Attribute::TestAttr));
        });
    }

    #[test]
    fn test_be_simple_delete() {
        run_test!(|be: &mut BackendWriteTransaction| {
            trace!("Simple Delete");
            let lims = Limits::unlimited();

            // First create some entries (3?)
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::UserId, Value::from("william"));
            e1.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava(Attribute::UserId, Value::from("alice"));
            e2.add_ava(
                Attribute::Uuid,
                Value::from("4b6228ab-1dbe-42a4-a9f5-f6368222438e"),
            );

            let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
            e3.add_ava(Attribute::UserId, Value::from("lucy"));
            e3.add_ava(
                Attribute::Uuid,
                Value::from("7b23c99d-c06b-4a9a-a958-3afa56383e1d"),
            );

            let ve1 = e1.clone().into_sealed_new();
            let ve2 = e2.clone().into_sealed_new();
            let ve3 = e3.clone().into_sealed_new();

            assert!(be.create(&CID_ZERO, vec![ve1, ve2, ve3]).is_ok());
            assert!(entry_exists!(be, e1));
            assert!(entry_exists!(be, e2));
            assert!(entry_exists!(be, e3));

            // You need to now retrieve the entries back out to get the entry id's
            let mut results = be
                .search(&lims, &filter_resolved!(f_pres(Attribute::UserId)))
                .expect("Failed to search");

            // Get these out to usable entries.
            let r1 = results.remove(0);
            let r2 = results.remove(0);
            let r3 = results.remove(0);

            // Deletes nothing, all entries are live.
            assert!(matches!(be.reap_tombstones(&CID_ADV, &CID_ZERO), Ok(0)));

            // Put them into the tombstone state, and write that down.
            // This sets up the RUV with the changes.
            let r1_ts = r1.to_tombstone(CID_ONE.clone()).into_sealed_committed();

            assert!(be
                .modify(&CID_ONE, &[r1], std::slice::from_ref(&r1_ts))
                .is_ok());

            let r2_ts = r2.to_tombstone(CID_TWO.clone()).into_sealed_committed();
            let r3_ts = r3.to_tombstone(CID_TWO.clone()).into_sealed_committed();

            assert!(be
                .modify(&CID_TWO, &[r2, r3], &[r2_ts.clone(), r3_ts.clone()])
                .is_ok());

            // The entry are now tombstones, but is still in the ruv. This is because we
            // targeted CID_ZERO, not ONE.
            assert!(matches!(be.reap_tombstones(&CID_ADV, &CID_ZERO), Ok(0)));

            assert!(entry_exists!(be, r1_ts));
            assert!(entry_exists!(be, r2_ts));
            assert!(entry_exists!(be, r3_ts));

            assert!(matches!(be.reap_tombstones(&CID_ADV, &CID_ONE), Ok(0)));

            assert!(entry_exists!(be, r1_ts));
            assert!(entry_exists!(be, r2_ts));
            assert!(entry_exists!(be, r3_ts));

            assert!(matches!(be.reap_tombstones(&CID_ADV, &CID_TWO), Ok(1)));

            assert!(!entry_exists!(be, r1_ts));
            assert!(entry_exists!(be, r2_ts));
            assert!(entry_exists!(be, r3_ts));

            assert!(matches!(be.reap_tombstones(&CID_ADV, &CID_THREE), Ok(2)));

            assert!(!entry_exists!(be, r1_ts));
            assert!(!entry_exists!(be, r2_ts));
            assert!(!entry_exists!(be, r3_ts));

            // Nothing left
            assert!(matches!(be.reap_tombstones(&CID_ADV, &CID_THREE), Ok(0)));

            assert!(!entry_exists!(be, r1_ts));
            assert!(!entry_exists!(be, r2_ts));
            assert!(!entry_exists!(be, r3_ts));
        });
    }

    #[test]
    fn test_be_backup_restore() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // Important! Need db metadata setup!
            be.reset_db_s_uuid().unwrap();
            be.reset_db_d_uuid().unwrap();
            be.set_db_ts_max(Duration::from_secs(1)).unwrap();

            // First create some entries (3?)
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::UserId, Value::from("william"));
            e1.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava(Attribute::UserId, Value::from("alice"));
            e2.add_ava(
                Attribute::Uuid,
                Value::from("4b6228ab-1dbe-42a4-a9f5-f6368222438e"),
            );

            let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
            e3.add_ava(Attribute::UserId, Value::from("lucy"));
            e3.add_ava(
                Attribute::Uuid,
                Value::from("7b23c99d-c06b-4a9a-a958-3afa56383e1d"),
            );

            let ve1 = e1.clone().into_sealed_new();
            let ve2 = e2.clone().into_sealed_new();
            let ve3 = e3.clone().into_sealed_new();

            assert!(be.create(&CID_ZERO, vec![ve1, ve2, ve3]).is_ok());
            assert!(entry_exists!(be, e1));
            assert!(entry_exists!(be, e2));
            assert!(entry_exists!(be, e3));

            let mut buf = std::io::Cursor::new(Vec::new());

            be.backup(&mut buf, BackupCompression::Gzip)
                .expect("Backup failed!");

            buf.set_position(0);

            be.restore(&mut buf, BackupCompression::Gzip)
                .expect("Restore failed!");

            assert!(be.verify().is_empty());
        });
    }

    #[test]
    fn test_be_backup_restore_tampered() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // Important! Need db metadata setup!
            be.reset_db_s_uuid().unwrap();
            be.reset_db_d_uuid().unwrap();
            be.set_db_ts_max(Duration::from_secs(1)).unwrap();
            // First create some entries (3?)
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::UserId, Value::from("william"));
            e1.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava(Attribute::UserId, Value::from("alice"));
            e2.add_ava(
                Attribute::Uuid,
                Value::from("4b6228ab-1dbe-42a4-a9f5-f6368222438e"),
            );

            let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
            e3.add_ava(Attribute::UserId, Value::from("lucy"));
            e3.add_ava(
                Attribute::Uuid,
                Value::from("7b23c99d-c06b-4a9a-a958-3afa56383e1d"),
            );

            let ve1 = e1.clone().into_sealed_new();
            let ve2 = e2.clone().into_sealed_new();
            let ve3 = e3.clone().into_sealed_new();

            assert!(be.create(&CID_ZERO, vec![ve1, ve2, ve3]).is_ok());
            assert!(entry_exists!(be, e1));
            assert!(entry_exists!(be, e2));
            assert!(entry_exists!(be, e3));

            let mut buf = std::io::Cursor::new(Vec::new());

            be.backup(&mut buf, BackupCompression::NoCompression)
                .expect("Backup failed!");

            // Rewind
            buf.set_position(0);

            // Now here, we need to tamper with the data.
            let mut dbbak: DbBackup = serde_json::from_reader(&mut buf).unwrap();

            match &mut dbbak {
                DbBackup::V5 {
                    version: _,
                    db_s_uuid: _,
                    db_d_uuid: _,
                    db_ts_max: _,
                    keyhandles: _,
                    repl_meta: _,
                    entries,
                } => {
                    let _ = entries.pop();
                }
                _ => {
                    // We no longer use these format versions!
                    unreachable!()
                }
            };

            buf.get_mut().clear();
            buf.set_position(0);

            serde_json::to_writer(&mut buf, &dbbak).unwrap();

            // Rewind
            buf.set_position(0);

            be.restore(&mut buf, BackupCompression::NoCompression)
                .expect("Restore failed!");

            assert!(be.verify().is_empty());
        });
    }

    #[test]
    fn test_be_backup_semantic_validation_rejects_invalid_entry() {
        run_test!(|be: &mut BackendWriteTransaction| {
            be.reset_db_s_uuid().unwrap();
            be.reset_db_d_uuid().unwrap();
            be.set_db_ts_max(Duration::from_secs(1)).unwrap();

            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::UserId, Value::from("william"));
            e1.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );

            let ve1 = e1.clone().into_sealed_new();
            assert!(be.create(&CID_ZERO, vec![ve1]).is_ok());

            let mut buf = std::io::Cursor::new(Vec::new());
            be.backup(&mut buf, BackupCompression::NoCompression)
                .expect("Initial backup failed!");

            buf.set_position(0);
            let mut dbbak: DbBackup = serde_json::from_reader(&mut buf).unwrap();

            let sid = Uuid::new_v4();
            let mut bad_attrs = std::collections::BTreeMap::new();
            bad_attrs.insert(Attribute::Uuid, DbValueSetV2::Uuid(vec![Uuid::new_v4()]));
            bad_attrs.insert(
                Attribute::Description,
                DbValueSetV2::PhoneNumber(
                    "+1234567890".to_string(),
                    vec!["+1234567890".to_string()],
                ),
            );

            let bad_entry = DbEntry {
                ent: DbEntryVers::V3 {
                    changestate: DbEntryChangeState::V1Live {
                        at: DbCidV1 {
                            timestamp: Duration::from_secs(0),
                            server_id: sid,
                        },
                        changes: std::collections::BTreeMap::new(),
                    },
                    attrs: bad_attrs,
                },
            };

            match &mut dbbak {
                DbBackup::V5 { entries, .. } => {
                    entries.push(bad_entry);
                }
                _ => unreachable!(),
            };

            buf.get_mut().clear();
            buf.set_position(0);
            serde_json::to_writer(&mut buf, &dbbak).unwrap();
            buf.set_position(0);

            be.restore(&mut buf, BackupCompression::NoCompression)
                .expect("Restore failed!");

            let mut backup_buf = std::io::Cursor::new(Vec::new());
            let result = be.backup(&mut backup_buf, BackupCompression::NoCompression);

            assert!(
                matches!(
                    result,
                    Err(OperationError::DB0005BackupEntrySemanticInvalid { .. })
                ),
                "Expected DB0005BackupEntrySemanticInvalid, got: {:?}",
                result
            );
        });
    }

    #[test]
    fn test_be_sid_generation_and_reset() {
        run_test!(|be: &mut BackendWriteTransaction| {
            let sid1 = be.get_db_s_uuid().unwrap();
            let sid2 = be.get_db_s_uuid().unwrap();
            assert_eq!(sid1, sid2);
            let sid3 = be.reset_db_s_uuid().unwrap();
            assert!(sid1 != sid3);
            let sid4 = be.get_db_s_uuid().unwrap();
            assert_eq!(sid3, sid4);
        });
    }

    #[test]
    fn test_be_reindex_empty() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // Add some test data?
            let missing = be.missing_idxs().unwrap();
            assert_eq!(missing.len(), 7);
            assert!(be.reindex(false).is_ok());
            let missing = be.missing_idxs().unwrap();
            debug!("{:?}", missing);
            assert!(missing.is_empty());
        });
    }

    #[test]
    fn test_be_reindex_data() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // Add some test data?
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::Name, Value::new_iname("william"));
            e1.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );
            let e1 = e1.into_sealed_new();

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava(Attribute::Name, Value::new_iname("claire"));
            e2.add_ava(
                Attribute::Uuid,
                Value::from("bd651620-00dd-426b-aaa0-4494f7b7906f"),
            );
            let e2 = e2.into_sealed_new();

            be.create(&CID_ZERO, vec![e1, e2]).unwrap();

            // purge indexes
            be.danger_purge_idxs().unwrap();
            // Check they are gone
            let missing = be.missing_idxs().unwrap();
            assert_eq!(missing.len(), 7);
            assert!(be.reindex(false).is_ok());
            let missing = be.missing_idxs().unwrap();
            debug!("{:?}", missing);
            assert!(missing.is_empty());
            // check name and uuid ids on eq, sub, pres

            idl_state!(
                be,
                Attribute::Name,
                IndexType::Equality,
                "william",
                Some(vec![1])
            );

            idl_state!(
                be,
                Attribute::Name,
                IndexType::Equality,
                "claire",
                Some(vec![2])
            );

            for sub in [
                "w", "m", "wi", "il", "ll", "li", "ia", "am", "wil", "ill", "lli", "lia", "iam",
            ] {
                idl_state!(
                    be,
                    Attribute::Name,
                    IndexType::SubString,
                    sub,
                    Some(vec![1])
                );
            }

            for sub in [
                "c", "r", "e", "cl", "la", "ai", "ir", "re", "cla", "lai", "air", "ire",
            ] {
                idl_state!(
                    be,
                    Attribute::Name,
                    IndexType::SubString,
                    sub,
                    Some(vec![2])
                );
            }

            for sub in ["i", "a", "l"] {
                idl_state!(
                    be,
                    Attribute::Name,
                    IndexType::SubString,
                    sub,
                    Some(vec![1, 2])
                );
            }

            idl_state!(
                be,
                Attribute::Name,
                IndexType::Presence,
                "_",
                Some(vec![1, 2])
            );

            idl_state!(
                be,
                Attribute::Uuid,
                IndexType::Equality,
                "db237e8a-0079-4b8c-8a56-593b22aa44d1",
                Some(vec![1])
            );

            idl_state!(
                be,
                Attribute::Uuid,
                IndexType::Equality,
                "bd651620-00dd-426b-aaa0-4494f7b7906f",
                Some(vec![2])
            );

            idl_state!(
                be,
                Attribute::Uuid,
                IndexType::Presence,
                "_",
                Some(vec![1, 2])
            );

            // Show what happens with empty

            idl_state!(
                be,
                Attribute::Name,
                IndexType::Equality,
                "not-exist",
                Some(Vec::with_capacity(0))
            );

            idl_state!(
                be,
                Attribute::Uuid,
                IndexType::Equality,
                "fake-0079-4b8c-8a56-593b22aa44d1",
                Some(Vec::with_capacity(0))
            );

            let uuid_p_idl = be
                .load_test_idl(&Attribute::from("not_indexed"), IndexType::Presence, "_")
                .unwrap(); // unwrap the result
            assert_eq!(uuid_p_idl, None);

            // Check name2uuid
            let claire_uuid = uuid!("bd651620-00dd-426b-aaa0-4494f7b7906f");
            let william_uuid = uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1");

            assert_eq!(be.name2uuid("claire"), Ok(Some(claire_uuid)));
            assert_eq!(be.name2uuid("william"), Ok(Some(william_uuid)));
            assert_eq!(
                be.name2uuid("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
                Ok(None)
            );
            // check uuid2spn
            assert_eq!(
                be.uuid2spn(claire_uuid),
                Ok(Some(Value::new_iname("claire")))
            );
            assert_eq!(
                be.uuid2spn(william_uuid),
                Ok(Some(Value::new_iname("william")))
            );
            // check uuid2rdn
            assert_eq!(
                be.uuid2rdn(claire_uuid),
                Ok(Some("name=claire".to_string()))
            );
            assert_eq!(
                be.uuid2rdn(william_uuid),
                Ok(Some("name=william".to_string()))
            );
        });
    }

    #[test]
    fn test_be_index_create_delete_simple() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // First, setup our index tables!
            assert!(be.reindex(false).is_ok());
            // Test that on entry create, the indexes are made correctly.
            // this is a similar case to reindex.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::Name, Value::from("william"));
            e1.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );
            let e1 = e1.into_sealed_new();

            let rset = be.create(&CID_ZERO, vec![e1]).unwrap();
            let mut rset: Vec<_> = rset.into_iter().map(Arc::new).collect();
            let e1 = rset.pop().unwrap();

            idl_state!(
                be,
                Attribute::Name.as_ref(),
                IndexType::Equality,
                "william",
                Some(vec![1])
            );

            idl_state!(
                be,
                Attribute::Name.as_ref(),
                IndexType::Presence,
                "_",
                Some(vec![1])
            );

            idl_state!(
                be,
                Attribute::Uuid.as_ref(),
                IndexType::Equality,
                "db237e8a-0079-4b8c-8a56-593b22aa44d1",
                Some(vec![1])
            );

            idl_state!(
                be,
                Attribute::Uuid.as_ref(),
                IndexType::Presence,
                "_",
                Some(vec![1])
            );

            let william_uuid = uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1");
            assert_eq!(be.name2uuid("william"), Ok(Some(william_uuid)));
            assert_eq!(be.uuid2spn(william_uuid), Ok(Some(Value::from("william"))));
            assert_eq!(
                be.uuid2rdn(william_uuid),
                Ok(Some("name=william".to_string()))
            );

            // == Now we reap_tombstones, and assert we removed the items.
            let e1_ts = e1.to_tombstone(CID_ONE.clone()).into_sealed_committed();
            assert!(be.modify(&CID_ONE, &[e1], &[e1_ts]).is_ok());
            be.reap_tombstones(&CID_ADV, &CID_TWO).unwrap();

            idl_state!(
                be,
                Attribute::Name.as_ref(),
                IndexType::Equality,
                "william",
                Some(Vec::with_capacity(0))
            );

            idl_state!(
                be,
                Attribute::Name.as_ref(),
                IndexType::Presence,
                "_",
                Some(Vec::with_capacity(0))
            );

            idl_state!(
                be,
                Attribute::Uuid.as_ref(),
                IndexType::Equality,
                "db237e8a-0079-4b8c-8a56-593b22aa44d1",
                Some(Vec::with_capacity(0))
            );

            idl_state!(
                be,
                Attribute::Uuid.as_ref(),
                IndexType::Presence,
                "_",
                Some(Vec::with_capacity(0))
            );

            assert_eq!(be.name2uuid("william"), Ok(None));
            assert_eq!(be.uuid2spn(william_uuid), Ok(None));
            assert_eq!(be.uuid2rdn(william_uuid), Ok(None));
        })
    }

    #[test]
    fn test_be_index_create_delete_multi() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // delete multiple entries at a time, without deleting others
            // First, setup our index tables!
            assert!(be.reindex(false).is_ok());
            // Test that on entry create, the indexes are made correctly.
            // this is a similar case to reindex.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::Name, Value::new_iname("william"));
            e1.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );
            let e1 = e1.into_sealed_new();

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava(Attribute::Name, Value::new_iname("claire"));
            e2.add_ava(
                Attribute::Uuid,
                Value::from("bd651620-00dd-426b-aaa0-4494f7b7906f"),
            );
            let e2 = e2.into_sealed_new();

            let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
            e3.add_ava(Attribute::UserId, Value::new_iname("lucy"));
            e3.add_ava(
                Attribute::Uuid,
                Value::from("7b23c99d-c06b-4a9a-a958-3afa56383e1d"),
            );
            let e3 = e3.into_sealed_new();

            let mut rset = be.create(&CID_ZERO, vec![e1, e2, e3]).unwrap();
            rset.remove(1);
            let mut rset: Vec<_> = rset.into_iter().map(Arc::new).collect();
            let e1 = rset.pop().unwrap();
            let e3 = rset.pop().unwrap();

            // Now remove e1, e3.
            let e1_ts = e1.to_tombstone(CID_ONE.clone()).into_sealed_committed();
            let e3_ts = e3.to_tombstone(CID_ONE.clone()).into_sealed_committed();
            assert!(be.modify(&CID_ONE, &[e1, e3], &[e1_ts, e3_ts]).is_ok());
            be.reap_tombstones(&CID_ADV, &CID_TWO).unwrap();

            idl_state!(
                be,
                Attribute::Name.as_ref(),
                IndexType::Equality,
                "claire",
                Some(vec![2])
            );

            idl_state!(
                be,
                Attribute::Name.as_ref(),
                IndexType::Presence,
                "_",
                Some(vec![2])
            );

            idl_state!(
                be,
                Attribute::Uuid.as_ref(),
                IndexType::Equality,
                "bd651620-00dd-426b-aaa0-4494f7b7906f",
                Some(vec![2])
            );

            idl_state!(
                be,
                Attribute::Uuid.as_ref(),
                IndexType::Presence,
                "_",
                Some(vec![2])
            );

            let claire_uuid = uuid!("bd651620-00dd-426b-aaa0-4494f7b7906f");
            let william_uuid = uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1");
            let lucy_uuid = uuid!("7b23c99d-c06b-4a9a-a958-3afa56383e1d");

            assert_eq!(be.name2uuid("claire"), Ok(Some(claire_uuid)));
            let x = be.uuid2spn(claire_uuid);
            trace!(?x);
            assert_eq!(
                be.uuid2spn(claire_uuid),
                Ok(Some(Value::new_iname("claire")))
            );
            assert_eq!(
                be.uuid2rdn(claire_uuid),
                Ok(Some("name=claire".to_string()))
            );

            assert_eq!(be.name2uuid("william"), Ok(None));
            assert_eq!(be.uuid2spn(william_uuid), Ok(None));
            assert_eq!(be.uuid2rdn(william_uuid), Ok(None));

            assert_eq!(be.name2uuid("lucy"), Ok(None));
            assert_eq!(be.uuid2spn(lucy_uuid), Ok(None));
            assert_eq!(be.uuid2rdn(lucy_uuid), Ok(None));
        })
    }

    #[test]
    fn test_be_index_modify_simple() {
        run_test!(|be: &mut BackendWriteTransaction| {
            assert!(be.reindex(false).is_ok());
            // modify with one type, ensuring we clean the indexes behind
            // us. For the test to be "accurate" we must add one attr, remove one attr
            // and change one attr.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::Name, Value::new_iname("william"));
            e1.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );
            e1.add_ava(Attribute::TestAttr, Value::from("test"));
            let e1 = e1.into_sealed_new();

            let rset = be.create(&CID_ZERO, vec![e1]).unwrap();
            let rset: Vec<_> = rset.into_iter().map(Arc::new).collect();
            // Now, alter the new entry.
            let mut ce1 = rset[0].as_ref().clone().into_invalid();
            // add something.
            ce1.add_ava(Attribute::TestNumber, Value::from("test"));
            // remove something.
            ce1.purge_ava(Attribute::TestAttr);
            // mod something.
            ce1.purge_ava(Attribute::Name);
            ce1.add_ava(Attribute::Name, Value::new_iname("claire"));

            let ce1 = ce1.into_sealed_committed();

            be.modify(&CID_ZERO, &rset, &[ce1]).unwrap();

            // Now check the idls
            idl_state!(
                be,
                Attribute::Name.as_ref(),
                IndexType::Equality,
                "claire",
                Some(vec![1])
            );

            idl_state!(
                be,
                Attribute::Name.as_ref(),
                IndexType::Presence,
                "_",
                Some(vec![1])
            );

            idl_state!(
                be,
                Attribute::TestNumber.as_ref(),
                IndexType::Equality,
                "test",
                Some(vec![1])
            );

            idl_state!(
                be,
                Attribute::TestAttr,
                IndexType::Equality,
                "test",
                Some(vec![])
            );

            let william_uuid = uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1");
            assert_eq!(be.name2uuid("william"), Ok(None));
            assert_eq!(be.name2uuid("claire"), Ok(Some(william_uuid)));
            assert_eq!(
                be.uuid2spn(william_uuid),
                Ok(Some(Value::new_iname("claire")))
            );
            assert_eq!(
                be.uuid2rdn(william_uuid),
                Ok(Some("name=claire".to_string()))
            );
        })
    }

    #[test]
    fn test_be_index_modify_rename() {
        run_test!(|be: &mut BackendWriteTransaction| {
            assert!(be.reindex(false).is_ok());
            // test when we change name AND uuid
            // This will be needing to be correct for conflicts when we add
            // replication support!
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::Name, Value::new_iname("william"));
            e1.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );
            let e1 = e1.into_sealed_new();

            let rset = be.create(&CID_ZERO, vec![e1]).unwrap();
            let rset: Vec<_> = rset.into_iter().map(Arc::new).collect();
            // Now, alter the new entry.
            let mut ce1 = rset[0].as_ref().clone().into_invalid();
            ce1.purge_ava(Attribute::Name);
            ce1.purge_ava(Attribute::Uuid);
            ce1.add_ava(Attribute::Name, Value::new_iname("claire"));
            ce1.add_ava(
                Attribute::Uuid,
                Value::from("04091a7a-6ce4-42d2-abf5-c2ce244ac9e8"),
            );
            let ce1 = ce1.into_sealed_committed();

            be.modify(&CID_ZERO, &rset, &[ce1]).unwrap();

            idl_state!(
                be,
                Attribute::Name.as_ref(),
                IndexType::Equality,
                "claire",
                Some(vec![1])
            );

            idl_state!(
                be,
                Attribute::Uuid.as_ref(),
                IndexType::Equality,
                "04091a7a-6ce4-42d2-abf5-c2ce244ac9e8",
                Some(vec![1])
            );

            idl_state!(
                be,
                Attribute::Name.as_ref(),
                IndexType::Presence,
                "_",
                Some(vec![1])
            );
            idl_state!(
                be,
                Attribute::Uuid.as_ref(),
                IndexType::Presence,
                "_",
                Some(vec![1])
            );

            idl_state!(
                be,
                Attribute::Uuid.as_ref(),
                IndexType::Equality,
                "db237e8a-0079-4b8c-8a56-593b22aa44d1",
                Some(Vec::with_capacity(0))
            );
            idl_state!(
                be,
                Attribute::Name.as_ref(),
                IndexType::Equality,
                "william",
                Some(Vec::with_capacity(0))
            );

            let claire_uuid = uuid!("04091a7a-6ce4-42d2-abf5-c2ce244ac9e8");
            let william_uuid = uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1");
            assert_eq!(be.name2uuid("william"), Ok(None));
            assert_eq!(be.name2uuid("claire"), Ok(Some(claire_uuid)));
            assert_eq!(be.uuid2spn(william_uuid), Ok(None));
            assert_eq!(be.uuid2rdn(william_uuid), Ok(None));
            assert_eq!(
                be.uuid2spn(claire_uuid),
                Ok(Some(Value::new_iname("claire")))
            );
            assert_eq!(
                be.uuid2rdn(claire_uuid),
                Ok(Some("name=claire".to_string()))
            );
        })
    }

    #[test]
    fn test_be_index_search_simple() {
        run_test!(|be: &mut BackendWriteTransaction| {
            assert!(be.reindex(false).is_ok());

            // Create a test entry with some indexed / unindexed values.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::Name, Value::new_iname("william"));
            e1.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );
            e1.add_ava(Attribute::NoIndex, Value::from("william"));
            e1.add_ava(Attribute::OtherNoIndex, Value::from("william"));
            let e1 = e1.into_sealed_new();

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava(Attribute::Name, Value::new_iname("claire"));
            e2.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d2"),
            );
            let e2 = e2.into_sealed_new();

            let _rset = be.create(&CID_ZERO, vec![e1, e2]).unwrap();
            // Test fully unindexed
            let f_un =
                filter_resolved!(f_eq(Attribute::NoIndex, PartialValue::new_utf8s("william")));

            let (r, _plan) = be.filter2idl(f_un.to_inner(), 0).unwrap();
            match r {
                IdList::AllIds => {}
                _ => {
                    panic!("");
                }
            }

            // Test that a fully indexed search works
            let feq = filter_resolved!(f_eq(Attribute::Name, PartialValue::new_utf8s("william")));

            let (r, _plan) = be.filter2idl(feq.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert_eq!(idl, IDLBitRange::from_iter(vec![1]));
                }
                _ => {
                    panic!("");
                }
            }

            // Test and/or
            //   full index and
            let f_in_and = filter_resolved!(f_and!([
                f_eq(Attribute::Name, PartialValue::new_utf8s("william")),
                f_eq(
                    Attribute::Uuid,
                    PartialValue::new_utf8s("db237e8a-0079-4b8c-8a56-593b22aa44d1")
                )
            ]));

            let (r, _plan) = be.filter2idl(f_in_and.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert_eq!(idl, IDLBitRange::from_iter(vec![1]));
                }
                _ => {
                    panic!("");
                }
            }

            //   partial index and
            let f_p1 = filter_resolved!(f_and!([
                f_eq(Attribute::Name, PartialValue::new_utf8s("william")),
                f_eq(Attribute::NoIndex, PartialValue::new_utf8s("william"))
            ]));

            let f_p2 = filter_resolved!(f_and!([
                f_eq(Attribute::Name, PartialValue::new_utf8s("william")),
                f_eq(Attribute::NoIndex, PartialValue::new_utf8s("william"))
            ]));

            let (r, _plan) = be.filter2idl(f_p1.to_inner(), 0).unwrap();
            match r {
                IdList::Partial(idl) => {
                    assert_eq!(idl, IDLBitRange::from_iter(vec![1]));
                }
                _ => unreachable!(),
            }

            let (r, _plan) = be.filter2idl(f_p2.to_inner(), 0).unwrap();
            match r {
                IdList::Partial(idl) => {
                    assert_eq!(idl, IDLBitRange::from_iter(vec![1]));
                }
                _ => unreachable!(),
            }

            // Substrings are always partial
            let f_p3 = filter_resolved!(f_sub(Attribute::Name, PartialValue::new_utf8s("wil")));

            let (r, plan) = be.filter2idl(f_p3.to_inner(), 0).unwrap();
            trace!(?r, ?plan);
            match r {
                IdList::Partial(idl) => {
                    assert_eq!(idl, IDLBitRange::from_iter(vec![1]));
                }
                _ => unreachable!(),
            }

            //   no index and
            let f_no_and = filter_resolved!(f_and!([
                f_eq(Attribute::NoIndex, PartialValue::new_utf8s("william")),
                f_eq(Attribute::OtherNoIndex, PartialValue::new_utf8s("william"))
            ]));

            let (r, _plan) = be.filter2idl(f_no_and.to_inner(), 0).unwrap();
            match r {
                IdList::AllIds => {}
                _ => {
                    panic!("");
                }
            }

            //   full index or
            let f_in_or = filter_resolved!(f_or!([f_eq(
                Attribute::Name,
                PartialValue::new_utf8s("william")
            )]));

            let (r, _plan) = be.filter2idl(f_in_or.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert_eq!(idl, IDLBitRange::from_iter(vec![1]));
                }
                _ => {
                    panic!("");
                }
            }
            //   partial (aka allids) or
            let f_un_or = filter_resolved!(f_or!([f_eq(
                Attribute::NoIndex,
                PartialValue::new_utf8s("william")
            )]));

            let (r, _plan) = be.filter2idl(f_un_or.to_inner(), 0).unwrap();
            match r {
                IdList::AllIds => {}
                _ => {
                    panic!("");
                }
            }

            // Test root andnot
            let f_r_andnot = filter_resolved!(f_andnot(f_eq(
                Attribute::Name,
                PartialValue::new_utf8s("william")
            )));

            let (r, _plan) = be.filter2idl(f_r_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert_eq!(idl, IDLBitRange::from_iter(Vec::with_capacity(0)));
                }
                _ => {
                    panic!("");
                }
            }

            // test andnot as only in and
            let f_and_andnot = filter_resolved!(f_and!([f_andnot(f_eq(
                Attribute::Name,
                PartialValue::new_utf8s("william")
            ))]));

            let (r, _plan) = be.filter2idl(f_and_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert_eq!(idl, IDLBitRange::from_iter(Vec::with_capacity(0)));
                }
                _ => {
                    panic!("");
                }
            }
            // test andnot as only in or
            let f_or_andnot = filter_resolved!(f_or!([f_andnot(f_eq(
                Attribute::Name,
                PartialValue::new_utf8s("william")
            ))]));

            let (r, _plan) = be.filter2idl(f_or_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert_eq!(idl, IDLBitRange::from_iter(Vec::with_capacity(0)));
                }
                _ => {
                    panic!("");
                }
            }

            // test andnot in and (first) with name
            let f_and_andnot = filter_resolved!(f_and!([
                f_andnot(f_eq(Attribute::Name, PartialValue::new_utf8s("claire"))),
                f_pres(Attribute::Name)
            ]));

            let (r, _plan) = be.filter2idl(f_and_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    debug!("{:?}", idl);
                    assert_eq!(idl, IDLBitRange::from_iter(vec![1]));
                }
                _ => {
                    panic!("");
                }
            }
            // test andnot in and (last) with name
            let f_and_andnot = filter_resolved!(f_and!([
                f_pres(Attribute::Name),
                f_andnot(f_eq(Attribute::Name, PartialValue::new_utf8s("claire")))
            ]));

            let (r, _plan) = be.filter2idl(f_and_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert_eq!(idl, IDLBitRange::from_iter(vec![1]));
                }
                _ => {
                    panic!("");
                }
            }
            // test andnot in and (first) with no-index
            let f_and_andnot = filter_resolved!(f_and!([
                f_andnot(f_eq(Attribute::Name, PartialValue::new_utf8s("claire"))),
                f_pres(Attribute::NoIndex)
            ]));

            let (r, _plan) = be.filter2idl(f_and_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::AllIds => {}
                _ => {
                    panic!("");
                }
            }
            // test andnot in and (last) with no-index
            let f_and_andnot = filter_resolved!(f_and!([
                f_pres(Attribute::NoIndex),
                f_andnot(f_eq(Attribute::Name, PartialValue::new_utf8s("claire")))
            ]));

            let (r, _plan) = be.filter2idl(f_and_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::AllIds => {}
                _ => {
                    panic!("");
                }
            }

            //   empty or
            let f_e_or = filter_resolved!(f_or!([]));

            let (r, _plan) = be.filter2idl(f_e_or.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert_eq!(idl, IDLBitRange::from_iter(vec![]));
                }
                _ => {
                    panic!("");
                }
            }

            let f_e_and = filter_resolved!(f_and!([]));

            let (r, _plan) = be.filter2idl(f_e_and.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert_eq!(idl, IDLBitRange::from_iter(vec![]));
                }
                _ => {
                    panic!("");
                }
            }
        })
    }

    #[test]
    fn test_be_index_search_missing() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // Test where the index is in schema but not created (purge idxs)
            // should fall back to an empty set because we can't satisfy the term
            be.danger_purge_idxs().unwrap();
            debug!("{:?}", be.missing_idxs().unwrap());
            let f_eq = filter_resolved!(f_eq(Attribute::Name, PartialValue::new_utf8s("william")));

            let (r, _plan) = be.filter2idl(f_eq.to_inner(), 0).unwrap();
            match r {
                IdList::AllIds => {}
                _ => {
                    panic!("");
                }
            }
        })
    }

    #[test]
    fn test_be_index_slope_generation() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // Create some test entry with some indexed / unindexed values.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::Name, Value::new_iname("william"));
            e1.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );
            e1.add_ava(Attribute::TestAttr, Value::from("dupe"));
            e1.add_ava(Attribute::TestNumber, Value::from("1"));
            let e1 = e1.into_sealed_new();

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava(Attribute::Name, Value::new_iname("claire"));
            e2.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d2"),
            );
            e2.add_ava(Attribute::TestAttr, Value::from("dupe"));
            e2.add_ava(Attribute::TestNumber, Value::from("1"));
            let e2 = e2.into_sealed_new();

            let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
            e3.add_ava(Attribute::Name, Value::new_iname("benny"));
            e3.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d3"),
            );
            e3.add_ava(Attribute::TestAttr, Value::from("dupe"));
            e3.add_ava(Attribute::TestNumber, Value::from("2"));
            let e3 = e3.into_sealed_new();

            let _rset = be.create(&CID_ZERO, vec![e1, e2, e3]).unwrap();

            // If the slopes haven't been generated yet, there are some hardcoded values
            // that we can use instead. They aren't generated until a first re-index.
            assert!(!be.is_idx_slopeyness_generated().unwrap());

            let ta_eq_slope = be
                .get_idx_slope(&IdxKey::new(Attribute::TestAttr, IndexType::Equality))
                .unwrap();
            assert_eq!(ta_eq_slope, 45);

            let tb_eq_slope = be
                .get_idx_slope(&IdxKey::new(Attribute::TestNumber, IndexType::Equality))
                .unwrap();
            assert_eq!(tb_eq_slope, 45);

            let name_eq_slope = be
                .get_idx_slope(&IdxKey::new(Attribute::Name, IndexType::Equality))
                .unwrap();
            assert_eq!(name_eq_slope, 1);
            let uuid_eq_slope = be
                .get_idx_slope(&IdxKey::new(Attribute::Uuid, IndexType::Equality))
                .unwrap();
            assert_eq!(uuid_eq_slope, 1);

            let name_pres_slope = be
                .get_idx_slope(&IdxKey::new(Attribute::Name, IndexType::Presence))
                .unwrap();
            assert_eq!(name_pres_slope, 90);
            let uuid_pres_slope = be
                .get_idx_slope(&IdxKey::new(Attribute::Uuid, IndexType::Presence))
                .unwrap();
            assert_eq!(uuid_pres_slope, 90);
            // Check the slopes are what we expect for hardcoded values.

            // Now check slope generation for the values. Today these are calculated
            // at reindex time, so we now perform the re-index.
            assert!(be.reindex(false).is_ok());
            assert!(be.is_idx_slopeyness_generated().unwrap());

            let ta_eq_slope = be
                .get_idx_slope(&IdxKey::new(Attribute::TestAttr, IndexType::Equality))
                .unwrap();
            assert_eq!(ta_eq_slope, 200);

            let tb_eq_slope = be
                .get_idx_slope(&IdxKey::new(Attribute::TestNumber, IndexType::Equality))
                .unwrap();
            assert_eq!(tb_eq_slope, 133);

            let name_eq_slope = be
                .get_idx_slope(&IdxKey::new(Attribute::Name, IndexType::Equality))
                .unwrap();
            assert_eq!(name_eq_slope, 51);
            let uuid_eq_slope = be
                .get_idx_slope(&IdxKey::new(Attribute::Uuid, IndexType::Equality))
                .unwrap();
            assert_eq!(uuid_eq_slope, 51);

            let name_pres_slope = be
                .get_idx_slope(&IdxKey::new(Attribute::Name, IndexType::Presence))
                .unwrap();
            assert_eq!(name_pres_slope, 200);
            let uuid_pres_slope = be
                .get_idx_slope(&IdxKey::new(Attribute::Uuid, IndexType::Presence))
                .unwrap();
            assert_eq!(uuid_pres_slope, 200);
        })
    }

    #[test]
    fn test_be_limits_allids() {
        run_test!(|be: &mut BackendWriteTransaction| {
            let mut lim_allow_allids = Limits::unlimited();
            lim_allow_allids.unindexed_allow = true;

            let mut lim_deny_allids = Limits::unlimited();
            lim_deny_allids.unindexed_allow = false;

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava(Attribute::UserId, Value::from("william"));
            e.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );
            e.add_ava(Attribute::NonExist, Value::from("x"));
            let e = e.into_sealed_new();
            let single_result = be.create(&CID_ZERO, vec![e.clone()]);

            assert!(single_result.is_ok());
            let filt = e
                .filter_from_attrs(&[Attribute::NonExist])
                .expect("failed to generate filter")
                .into_valid_resolved();
            // check allow on allids
            let res = be.search(&lim_allow_allids, &filt);
            assert!(res.is_ok());
            let res = be.exists(&lim_allow_allids, &filt);
            assert!(res.is_ok());

            // check deny on allids
            let res = be.search(&lim_deny_allids, &filt);
            assert_eq!(res, Err(OperationError::ResourceLimit));
            let res = be.exists(&lim_deny_allids, &filt);
            assert_eq!(res, Err(OperationError::ResourceLimit));
        })
    }

    #[test]
    fn test_be_limits_results_max() {
        run_test!(|be: &mut BackendWriteTransaction| {
            let mut lim_allow = Limits::unlimited();
            lim_allow.search_max_results = usize::MAX;

            let mut lim_deny = Limits::unlimited();
            lim_deny.search_max_results = 0;

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava(Attribute::UserId, Value::from("william"));
            e.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );
            e.add_ava(Attribute::NonExist, Value::from("x"));
            let e = e.into_sealed_new();
            let single_result = be.create(&CID_ZERO, vec![e.clone()]);
            assert!(single_result.is_ok());

            let filt = e
                .filter_from_attrs(&[Attribute::NonExist])
                .expect("failed to generate filter")
                .into_valid_resolved();

            // --> This is the all ids path (unindexed)
            // check allow on entry max
            let res = be.search(&lim_allow, &filt);
            assert!(res.is_ok());
            let res = be.exists(&lim_allow, &filt);
            assert!(res.is_ok());

            // check deny on entry max
            let res = be.search(&lim_deny, &filt);
            assert_eq!(res, Err(OperationError::ResourceLimit));
            // we don't limit on exists because we never load the entries.
            let res = be.exists(&lim_deny, &filt);
            assert!(res.is_ok());

            // --> This will shortcut due to indexing.
            assert!(be.reindex(false).is_ok());
            let res = be.search(&lim_deny, &filt);
            assert_eq!(res, Err(OperationError::ResourceLimit));
            // we don't limit on exists because we never load the entries.
            let res = be.exists(&lim_deny, &filt);
            assert!(res.is_ok());
        })
    }

    #[test]
    fn test_be_limits_partial_filter() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // This relies on how we do partials, so it could be a bit sensitive.
            // A partial is generated after an allids + indexed in a single and
            // as we require both conditions to exist. Allids comes from unindexed
            // terms. we need to ensure we don't hit partial threshold too.
            //
            // This means we need an and query where the first term is allids
            // and the second is indexed, but without the filter shortcutting.
            //
            // To achieve this we need a monstrously evil query.
            //
            let mut lim_allow = Limits::unlimited();
            lim_allow.search_max_filter_test = usize::MAX;

            let mut lim_deny = Limits::unlimited();
            lim_deny.search_max_filter_test = 0;

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava(Attribute::Name, Value::new_iname("william"));
            e.add_ava(
                Attribute::Uuid,
                Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
            );
            e.add_ava(Attribute::NonExist, Value::from("x"));
            e.add_ava(Attribute::NonExist, Value::from("y"));
            let e = e.into_sealed_new();
            let single_result = be.create(&CID_ZERO, vec![e]);
            assert!(single_result.is_ok());

            // Reindex so we have things in place for our query
            assert!(be.reindex(false).is_ok());

            // 🚨 This is evil!
            // The and allows us to hit "allids + indexed -> partial".
            // the or terms prevent re-arrangement. They can't be folded or dead
            // term elimed either.
            //
            // This means the f_or nonexist will become allids and the second will be indexed
            // due to f_eq userid in both with the result of william.
            //
            // This creates a partial, and because it's the first iteration in the loop, this
            // doesn't encounter partial threshold testing.
            let filt = filter_resolved!(f_and!([
                f_or!([
                    f_eq(Attribute::NonExist, PartialValue::new_utf8s("x")),
                    f_eq(Attribute::NonExist, PartialValue::new_utf8s("y"))
                ]),
                f_or!([
                    f_eq(Attribute::Name, PartialValue::new_utf8s("claire")),
                    f_eq(Attribute::Name, PartialValue::new_utf8s("william"))
                ]),
            ]));

            let res = be.search(&lim_allow, &filt);
            assert!(res.is_ok());
            let res = be.exists(&lim_allow, &filt);
            assert!(res.is_ok());

            // check deny on entry max
            let res = be.search(&lim_deny, &filt);
            assert_eq!(res, Err(OperationError::ResourceLimit));
            // we don't limit on exists because we never load the entries.
            let res = be.exists(&lim_deny, &filt);
            assert_eq!(res, Err(OperationError::ResourceLimit));
        })
    }

    #[test]
    fn test_be_multiple_create() {
        sketching::test_init();

        // This is a demo idxmeta, purely for testing.
        let idxmeta = vec![IdxKey {
            attr: Attribute::Uuid,
            itype: IndexType::Equality,
        }];

        let be_a = Backend::new(BackendConfig::new_test("main"), idxmeta.clone(), false)
            .expect("Failed to setup backend");

        let be_b = Backend::new(BackendConfig::new_test("db_2"), idxmeta, false)
            .expect("Failed to setup backend");

        let mut be_a_txn = be_a.write().unwrap();
        let mut be_b_txn = be_b.write().unwrap();

        assert!(be_a_txn.get_db_s_uuid() != be_b_txn.get_db_s_uuid());

        // Create into A
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();
        e.add_ava(Attribute::UserId, Value::from("william"));
        e.add_ava(
            Attribute::Uuid,
            Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"),
        );
        let e = e.into_sealed_new();

        let single_result = be_a_txn.create(&CID_ZERO, vec![e]);

        assert!(single_result.is_ok());

        // Assert it's in A but not B.
        let filt = filter_resolved!(f_eq(Attribute::UserId, PartialValue::new_utf8s("william")));

        let lims = Limits::unlimited();

        let r = be_a_txn.search(&lims, &filt);
        assert!(r.expect("Search failed!").len() == 1);

        let r = be_b_txn.search(&lims, &filt);
        assert!(r.expect("Search failed!").is_empty());

        // Create into B
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();
        e.add_ava(Attribute::UserId, Value::from("claire"));
        e.add_ava(
            Attribute::Uuid,
            Value::from("0c680959-0944-47d6-9dea-53304d124266"),
        );
        let e = e.into_sealed_new();

        let single_result = be_b_txn.create(&CID_ZERO, vec![e]);

        assert!(single_result.is_ok());

        // Assert it's in B but not A
        let filt = filter_resolved!(f_eq(Attribute::UserId, PartialValue::new_utf8s("claire")));

        let lims = Limits::unlimited();

        let r = be_a_txn.search(&lims, &filt);
        assert!(r.expect("Search failed!").is_empty());

        let r = be_b_txn.search(&lims, &filt);
        assert!(r.expect("Search failed!").len() == 1);
    }

    // === WAL archiving for point-in-time recovery ===

    fn wal_test_idxmeta() -> Vec<IdxKey> {
        vec![
            IdxKey {
                attr: Attribute::Name,
                itype: IndexType::Equality,
            },
            IdxKey {
                attr: Attribute::Uuid,
                itype: IndexType::Equality,
            },
            IdxKey {
                attr: Attribute::Uuid,
                itype: IndexType::Presence,
            },
        ]
    }

    /// A backend with WAL archiving enabled, writing segments below `dir`.
    fn wal_backend(dir: &std::path::Path, segment_size_bytes: u64) -> Backend {
        sketching::test_init();
        let wal_cfg = WalArchiveConfig {
            enabled: true,
            s3: None,
            retention_days: 7,
            segment_size_bytes,
            segment_interval_seconds: 3600,
            local_path: Some(dir.join("wal")),
            ..WalArchiveConfig::default()
        };
        let cfg = BackendConfig::new_test("main").with_wal_archive(Some(wal_cfg));
        Backend::new(cfg, wal_test_idxmeta(), false).expect("Failed to setup backend")
    }

    fn wal_test_entry(name: &str, uuid: &str) -> Entry<EntryInit, EntryNew> {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();
        e.add_ava(Attribute::UserId, Value::from(name));
        e.add_ava(Attribute::Uuid, Value::from(uuid));
        e
    }

    fn wal_entry_bytes(e: &EntrySealedCommitted) -> Vec<u8> {
        serde_json::to_vec(&e.to_dbentry()).unwrap()
    }

    #[test]
    fn test_be_wal_disabled_backend_has_no_archiver() {
        sketching::test_init();
        let be = Backend::new(BackendConfig::new_test("main"), wal_test_idxmeta(), false)
            .expect("Failed to setup backend");
        assert!(be.wal_archiver().is_none());

        // Enabled on an in-memory database without a local path is a startup error.
        let cfg = BackendConfig::new_test("main").with_wal_archive(Some(WalArchiveConfig {
            enabled: true,
            ..WalArchiveConfig::default()
        }));
        assert!(Backend::new(cfg, wal_test_idxmeta(), false).is_err());

        // Disabled with a local path archives nothing.
        let dir = tempfile::tempdir().unwrap();
        let cfg = BackendConfig::new_test("main").with_wal_archive(Some(WalArchiveConfig {
            enabled: false,
            local_path: Some(dir.path().join("wal")),
            ..WalArchiveConfig::default()
        }));
        let be = Backend::new(cfg, wal_test_idxmeta(), false).unwrap();
        assert!(be.wal_archiver().is_none());
        assert!(!dir.path().join("wal").exists());
    }

    /// A transaction whose only archive event is a record that failed to stage, or a new
    /// server uuid, is covered by the open segment marker before the database commits it
    /// too: a stop between the commit and the archiving would otherwise leave no trace of
    /// it, and recovery would replay across it.
    #[test]
    fn test_be_wal_every_archived_commit_is_announced() {
        assert!(!super::wal_commit_archives(false, false, false, false));
        for (pending, truncate, stage_failed, server_uuid_changed) in [
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, true),
        ] {
            assert!(super::wal_commit_archives(
                pending,
                truncate,
                stage_failed,
                server_uuid_changed
            ));
        }
    }

    #[test]
    fn test_be_wal_server_uuid_change_starts_a_new_identity_in_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        let be = wal_backend(dir.path(), 1024 * 1024);
        let archiver = be.wal_archiver().expect("WAL archiving must be enabled");
        let old_uuid = archiver.lock().unwrap().server_uuid();

        // A write under the old identity, still in the open segment.
        let mut be_txn = be.write().unwrap();
        be_txn
            .create(
                &CID_ZERO,
                vec![
                    wal_test_entry("william", "db237e8a-0079-4b8c-8a56-593b22aa44d1")
                        .into_sealed_new(),
                ],
            )
            .unwrap();
        be_txn.commit().unwrap();

        // A refresh resets the server uuid. Until the commit the archive knows nothing.
        let mut be_txn = be.write().unwrap();
        let new_uuid = be_txn.reset_db_s_uuid().unwrap();
        be_txn.set_wal_cid(&CID_TWO);
        assert_eq!(archiver.lock().unwrap().server_uuid(), old_uuid);
        be_txn.commit().unwrap();

        // The segment of the old identity is closed under it, the archiver goes on under
        // the new one, and the change waits on disk for the archive index.
        let archiver = archiver.lock().unwrap();
        assert_eq!(archiver.server_uuid(), new_uuid);
        assert!(!archiver.has_pending_records());
        let segments = crate::repl::wal::list_segments(&dir.path().join("wal")).unwrap();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].server_uuid, old_uuid);
        let changes =
            crate::repl::wal::read_pending_events(&dir.path().join("wal")).server_uuid_changes;
        assert_eq!(
            changes,
            vec![crate::repl::wal::WalServerUuidChange {
                from: old_uuid,
                to: new_uuid,
                at_ts: CID_TWO.ts,
            }]
        );
    }

    #[test]
    fn test_be_wal_records_committed_writes_and_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let be = wal_backend(dir.path(), 1024 * 1024);
        let archiver = be.wal_archiver().expect("WAL archiving must be enabled");
        let s_uuid = archiver.lock().unwrap().server_uuid();
        assert!(dir.path().join("wal").is_dir());

        // The backend start up transactions archive nothing.
        assert!(!archiver.lock().unwrap().has_pending_records());

        let e1 = wal_test_entry("william", "db237e8a-0079-4b8c-8a56-593b22aa44d1");
        let e2 = wal_test_entry("alice", "4b6228ab-1dbe-42a4-a9f5-f6368222438e");

        // Transaction 1: create two entries. Nothing reaches the archiver before commit.
        let mut be_txn = be.write().unwrap();
        let created = be_txn
            .create(
                &CID_ZERO,
                vec![e1.clone().into_sealed_new(), e2.clone().into_sealed_new()],
            )
            .unwrap();
        assert_eq!(be_txn.wal_pending_len(), 2);
        assert!(!archiver.lock().unwrap().has_pending_records());
        be_txn.commit().unwrap();
        assert_eq!(archiver.lock().unwrap().pending_record_count(), 2);

        let c1 = created
            .iter()
            .find(|e| e.get_uuid() == uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            .unwrap()
            .clone();

        // Transaction 2: tombstone e1 (a modify).
        let mut be_txn = be.write().unwrap();
        let pre = Arc::new(c1.clone());
        let c1_ts = c1
            .clone()
            .to_tombstone(CID_TWO.clone())
            .into_sealed_committed();
        be_txn
            .modify(&CID_TWO, &[pre], std::slice::from_ref(&c1_ts))
            .unwrap();
        be_txn.commit().unwrap();
        assert_eq!(archiver.lock().unwrap().pending_record_count(), 3);

        // Transaction 3: reap the tombstone (a delete).
        let mut be_txn = be.write().unwrap();
        assert_eq!(be_txn.reap_tombstones(&CID_ADV, &CID_THREE).unwrap(), 1);
        be_txn.commit().unwrap();
        assert_eq!(archiver.lock().unwrap().pending_record_count(), 4);

        // An aborted transaction records nothing, even though it staged a write.
        {
            let mut be_txn = be.write().unwrap();
            let e3 = wal_test_entry("lucy", "7b23c99d-c06b-4a9a-a958-3afa56383e1d");
            be_txn
                .create(&CID_ZERO, vec![e3.into_sealed_new()])
                .unwrap();
            assert_eq!(be_txn.wal_pending_len(), 1);
            drop(be_txn);
        }
        assert_eq!(archiver.lock().unwrap().pending_record_count(), 4);
        assert_eq!(archiver.lock().unwrap().stats().failures, 0);

        // Close the segment and read it back.
        let segment = archiver
            .lock()
            .unwrap()
            .flush_current_segment()
            .unwrap()
            .expect("records must produce a segment");
        assert_eq!(segment.server_uuid, s_uuid);
        assert_eq!(segment.entry_count, 4);
        assert_eq!(segment.start_ts, CID_ZERO.ts);
        assert_eq!(segment.end_ts, CID_ADV.ts);

        let file =
            crate::repl::wal::read_segment_file(&dir.path().join("wal").join(&segment.segment_id))
                .unwrap();
        let records = &file.entries;
        assert_eq!(records.len(), 4);

        // Creates: the same bytes id2entry stores, under the transaction CID.
        for created_entry in created.iter() {
            let record = records
                .iter()
                .find(|r| {
                    r.entry_uuid == created_entry.get_uuid()
                        && matches!(r.operation, WalOperationRecord::Create { .. })
                })
                .expect("create must be recorded");
            assert_eq!(record.cid(), *CID_ZERO);
            assert_eq!(record.entry_id, created_entry.get_id());
            assert_eq!(
                record.operation,
                WalOperationRecord::Create {
                    entry_data: wal_entry_bytes(created_entry)
                }
            );
        }

        // The modify carries the tombstone state.
        let modify = records
            .iter()
            .find(|r| matches!(r.operation, WalOperationRecord::Modify { .. }))
            .unwrap();
        assert_eq!(modify.cid(), *CID_TWO);
        assert_eq!(modify.entry_uuid, c1.get_uuid());
        assert_eq!(
            modify.operation,
            WalOperationRecord::Modify {
                entry_data: wal_entry_bytes(&c1_ts)
            }
        );

        // The delete names the reaped entry.
        let delete = records
            .iter()
            .find(|r| r.operation == WalOperationRecord::Delete)
            .unwrap();
        assert_eq!(delete.cid(), *CID_ADV);
        assert_eq!(delete.entry_uuid, c1.get_uuid());
        assert_eq!(delete.entry_id, c1.get_id());

        // Records are in CID order.
        assert!(records.windows(2).all(|w| w[0].cid_ts <= w[1].cid_ts));
    }

    #[test]
    fn test_be_wal_segment_rolls_by_size_at_commit() {
        let dir = tempfile::tempdir().unwrap();
        // Small enough that the first transaction closes a segment.
        let be = wal_backend(dir.path(), 1);
        let archiver = be.wal_archiver().unwrap();

        let mut be_txn = be.write().unwrap();
        let e1 = wal_test_entry("william", "db237e8a-0079-4b8c-8a56-593b22aa44d1");
        be_txn
            .create(&CID_ZERO, vec![e1.into_sealed_new()])
            .unwrap();
        be_txn.commit().unwrap();

        let locked = archiver.lock().unwrap();
        assert!(!locked.has_pending_records());
        assert_eq!(locked.stats().segments_closed, 1);
        assert_eq!(locked.stats().records_archived, 1);
        let segments = crate::repl::wal::list_segments(locked.segments_path()).unwrap();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].entry_count, 1);
    }

    #[test]
    fn test_be_wal_create_then_modify_in_one_transaction_stays_a_create() {
        let dir = tempfile::tempdir().unwrap();
        let be = wal_backend(dir.path(), 1024 * 1024);
        let archiver = be.wal_archiver().unwrap();

        let mut be_txn = be.write().unwrap();
        let e1 = wal_test_entry("william", "db237e8a-0079-4b8c-8a56-593b22aa44d1");
        let created = be_txn
            .create(&CID_ZERO, vec![e1.into_sealed_new()])
            .unwrap();
        let c1 = created[0].clone();
        let mut modified = wal_test_entry("william", "db237e8a-0079-4b8c-8a56-593b22aa44d1");
        modified.add_ava(Attribute::DisplayName, Value::new_utf8s("William"));
        let modified = modified
            .into_sealed_new()
            .into_sealed_committed_id(c1.get_id());
        be_txn
            .modify(&CID_ZERO, &[Arc::new(c1)], std::slice::from_ref(&modified))
            .unwrap();
        assert_eq!(be_txn.wal_pending_len(), 1);
        be_txn.commit().unwrap();

        let segment = archiver
            .lock()
            .unwrap()
            .flush_current_segment()
            .unwrap()
            .unwrap();
        let file =
            crate::repl::wal::read_segment_file(&dir.path().join("wal").join(&segment.segment_id))
                .unwrap();
        assert_eq!(file.entries.len(), 1);
        assert_eq!(
            file.entries[0].operation,
            WalOperationRecord::Create {
                entry_data: wal_entry_bytes(&modified)
            },
            "the record holds the final state and keeps the create"
        );
    }

    #[test]
    fn test_be_wal_apply_replays_state_by_uuid() {
        let dir = tempfile::tempdir().unwrap();
        let be = wal_backend(dir.path(), 1024 * 1024);
        let archiver = be.wal_archiver().unwrap();

        let e1 = wal_test_entry("william", "db237e8a-0079-4b8c-8a56-593b22aa44d1");
        let e2 = wal_test_entry("alice", "4b6228ab-1dbe-42a4-a9f5-f6368222438e");
        let e3 = wal_test_entry("lucy", "7b23c99d-c06b-4a9a-a958-3afa56383e1d");

        // Base state: e1 and e2 exist.
        let mut be_txn = be.write().unwrap();
        be_txn.reset_db_s_uuid().unwrap();
        be_txn.reset_db_d_uuid().unwrap();
        be_txn.set_db_ts_max(CID_ZERO.ts).unwrap();
        let created = be_txn
            .create(
                &CID_ZERO,
                vec![e1.clone().into_sealed_new(), e2.clone().into_sealed_new()],
            )
            .unwrap();
        be_txn.commit().unwrap();
        let mut backup = std::io::Cursor::new(Vec::new());
        {
            let mut be_read = be.read().unwrap();
            be_read
                .backup(&mut backup, BackupCompression::NoCompression)
                .unwrap();
        }
        // The base backup holds everything so far; its records are not replayed.
        archiver.lock().unwrap().flush_current_segment().unwrap();

        // After the base: e3 created, e1 tombstoned then reaped, e2 modified.
        let c1 = created
            .iter()
            .find(|e| e.get_uuid() == uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            .unwrap()
            .clone();
        let c2 = created
            .iter()
            .find(|e| e.get_uuid() == uuid!("4b6228ab-1dbe-42a4-a9f5-f6368222438e"))
            .unwrap()
            .clone();

        // e3 arrives through the replication (refresh) path, which carries no CID of its
        // own; the query server tags the transaction at commit.
        let mut be_txn = be.write().unwrap();
        be_txn.refresh(vec![e3.clone().into_sealed_new()]).unwrap();
        let c1_ts = c1
            .clone()
            .to_tombstone(CID_TWO.clone())
            .into_sealed_committed();
        be_txn
            .modify(
                &CID_TWO,
                &[Arc::new(c1.clone())],
                std::slice::from_ref(&c1_ts),
            )
            .unwrap();
        be_txn.set_wal_cid(&CID_TWO);
        be_txn.commit().unwrap();

        let mut be_txn = be.write().unwrap();
        let mut c2_mod = wal_test_entry("alice", "4b6228ab-1dbe-42a4-a9f5-f6368222438e");
        c2_mod.add_ava(Attribute::DisplayName, Value::new_utf8s("Alice Modified"));
        let c2_mod = c2_mod
            .into_sealed_new()
            .into_sealed_committed_id(c2.get_id());
        be_txn
            .modify(
                &CID_THREE,
                &[Arc::new(c2.clone())],
                std::slice::from_ref(&c2_mod),
            )
            .unwrap();
        be_txn.commit().unwrap();

        let mut be_txn = be.write().unwrap();
        assert_eq!(be_txn.reap_tombstones(&CID_ADV, &CID_THREE).unwrap(), 1);
        be_txn.commit().unwrap();

        archiver.lock().unwrap().flush_current_segment().unwrap();
        let segments = crate::repl::wal::list_segments(&dir.path().join("wal")).unwrap();
        assert_eq!(segments.len(), 2);
        let after_base = crate::repl::wal::read_segment_file(
            &dir.path().join("wal").join(&segments[1].segment_id),
        )
        .unwrap();
        // Records up to the base watermark (CID_ZERO) are already in the backup.
        let to_apply: Vec<WalEntryRecord> = crate::repl::wal::select_records(
            &after_base.entries,
            CID_ZERO.ts,
            Duration::from_secs(u64::MAX / 2),
        )
        .cloned()
        .collect();
        assert_eq!(to_apply.len(), 4);
        // A restore numbers the entries afresh, here exactly as the source did. Make the
        // ids the records carry differ from the restored ones, so that only a replay that
        // resolves entries by uuid passes.
        let to_apply: Vec<WalEntryRecord> = to_apply
            .into_iter()
            .map(|mut record| {
                record.entry_id += 100;
                record
            })
            .collect();

        // Recover: restore the base into a fresh backend, apply the records, reindex, and
        // compare with the live state.
        sketching::test_init();
        let recovered =
            Backend::new(BackendConfig::new_test("main"), wal_test_idxmeta(), false).unwrap();
        let mut rec_txn = recovered.write().unwrap();
        backup.set_position(0);
        rec_txn
            .restore(&mut backup, BackupCompression::NoCompression)
            .unwrap();
        let report = rec_txn.wal_apply(to_apply.clone()).unwrap();
        assert_eq!(report.applied, 4);
        assert_eq!(report.created, 1);
        assert_eq!(report.modified, 2);
        assert_eq!(report.deleted, 1);
        assert_eq!(report.last_cid, Some(CID_ADV.clone()));
        assert_eq!(
            rec_txn.get_db_ts_max(Duration::ZERO).unwrap(),
            CID_ADV.ts,
            "db_ts_max must advance to the last applied CID"
        );
        rec_txn.reindex(false).unwrap();
        rec_txn.commit().unwrap();

        let mut rec_txn = recovered.write().unwrap();
        assert!(!entry_exists!(rec_txn, e1), "reaped entry must be gone");
        assert!(entry_exists!(rec_txn, e2));
        assert!(
            entry_exists!(rec_txn, e3),
            "entry created after the base must exist"
        );
        let lims = Limits::unlimited();
        let alice = rec_txn
            .search(
                &lims,
                &filter_resolved!(f_eq(
                    Attribute::Uuid,
                    PartialValue::Uuid(uuid!("4b6228ab-1dbe-42a4-a9f5-f6368222438e"))
                )),
            )
            .unwrap();
        assert_eq!(alice.len(), 1);
        assert!(
            alice[0].attribute_equality(
                Attribute::DisplayName,
                &PartialValue::new_utf8s("Alice Modified")
            ),
            "modified state must be the replayed one"
        );
        assert!(rec_txn.verify().is_empty());

        // Applying the same records again is a no-op in state terms.
        let report = rec_txn.wal_apply(to_apply.clone()).unwrap();
        assert_eq!(report.applied, 4);
        rec_txn.reindex(false).unwrap();
        assert!(entry_exists!(rec_txn, e3));
        assert!(!entry_exists!(rec_txn, e1));
        rec_txn.commit().unwrap();

        // A truncate record is a replication refresh, which also replaced the identity of
        // the database: it is refused, and nothing is applied.
        let mut rec_txn = recovered.write().unwrap();
        let truncate_then_create = vec![
            WalEntryRecord {
                cid_ts: CID_ADV.ts.as_nanos() as u64 + 1,
                cid_server: CID_ADV.s_uuid,
                entry_id: 0,
                entry_uuid: Uuid::nil(),
                operation: WalOperationRecord::Truncate,
            },
            WalEntryRecord {
                cid_ts: CID_ADV.ts.as_nanos() as u64 + 1,
                cid_server: CID_ADV.s_uuid,
                entry_id: 1,
                entry_uuid: c1.get_uuid(),
                operation: WalOperationRecord::Create {
                    entry_data: wal_entry_bytes(&c1),
                },
            },
        ];
        assert_eq!(
            rec_txn.wal_apply(truncate_then_create),
            Err(OperationError::InvalidState)
        );
        drop(rec_txn);
        let mut rec_txn = recovered.write().unwrap();
        rec_txn.reindex(false).unwrap();
        assert!(entry_exists!(rec_txn, e2));
        assert!(entry_exists!(rec_txn, e3));
        rec_txn.commit().unwrap();

        // Bytes that are not an entry are rejected before anything is written.
        let mut rec_txn = recovered.write().unwrap();
        let garbage = vec![WalEntryRecord {
            cid_ts: 1,
            cid_server: Uuid::nil(),
            entry_id: 1,
            entry_uuid: Uuid::new_v4(),
            operation: WalOperationRecord::Create {
                entry_data: b"garbage".to_vec(),
            },
        }];
        assert!(rec_txn.wal_apply(garbage).is_err());
    }
}
