//! Point-in-time recovery (PITR) on top of the backend's WAL archive.
//!
//! The backend (`kubidmd_lib::repl::wal`) writes closed WAL segments to a local directory.
//! This module owns everything above that:
//!
//! - the periodic task that closes stale segments, uploads closed segments to S3 (or keeps
//!   them in the local directory when no S3 location is configured), applies retention and
//!   keeps the `pitr-manifest.json` index accurate;
//! - registering every successful online base backup in the manifest together with its CID
//!   watermark, so that recovery can pair a base with the segments that follow it;
//! - recording the history a restore or a recovery abandons, so that a later recovery never
//!   replays it;
//! - the `kubidmd database pitr-list` and `kubidmd database recover` commands.
//!
//! Recovery restores the newest base backup whose watermark is at or before the target,
//! then replays every archived record with a CID above the watermark and at or below the
//! target, in CID order, in the same database transaction as the restore.
//!
//! Segments hold the full state of every changed entry, credentials included, so they get
//! the protection of the backups:
//!
//! - with `[online_backup.encryption]` enabled, a closed segment is sealed with the backup
//!   encryption scheme before it is archived (uploaded to S3, or kept as `<segment>.enc` in
//!   the local WAL directory) and the plaintext copy is removed; recovery decrypts it;
//! - when the S3 location of the archive replicates its backups to regions, the archive
//!   (segments, then the manifest) is mirrored to every region after each synchronisation,
//!   and `recover --region` / `pitr-list --region` read a region's copy.
//!
//! The manifest is never encrypted: it holds CID ranges, checksums, object keys and key
//! identifiers, no directory content.
//!
//! Layout: `settings` resolves the locations from the configuration, `store` reads and
//! writes them, `archive` is the running server's task, `replicate` mirrors the archive to
//! the replication regions and `recover` holds the recovery commands.

mod archive;
mod recover;
mod replicate;
mod settings;
mod store;
#[cfg(test)]
mod test_util;

pub use archive::*;
pub use recover::*;
pub use settings::*;

use std::fmt;

use kubidm_proto::internal::OperationError;
use kubidmd_lib::repl::wal::WalError;

use crate::backup::S3BackupError;

#[derive(Debug)]
pub enum PitrError {
    Config(String),
    Wal(WalError),
    S3(S3BackupError),
    Io(std::io::Error),
    Manifest(String),
    Target(String),
    NotRecoverable(String),
    Operation(OperationError),
    /// The backup encryption key could not be obtained, or does not open a segment.
    Encryption(String),
}

impl fmt::Display for PitrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PitrError::Config(msg) => write!(f, "PITR configuration error: {msg}"),
            PitrError::Wal(err) => write!(f, "{err}"),
            PitrError::S3(err) => write!(f, "{err}"),
            PitrError::Io(err) => write!(f, "PITR IO error: {err}"),
            PitrError::Manifest(msg) => write!(f, "PITR manifest error: {msg}"),
            PitrError::Target(msg) => write!(f, "invalid recovery target: {msg}"),
            PitrError::NotRecoverable(msg) => write!(f, "not recoverable: {msg}"),
            PitrError::Operation(err) => write!(f, "PITR database error: {err:?}"),
            PitrError::Encryption(msg) => write!(f, "PITR encryption error: {msg}"),
        }
    }
}

impl std::error::Error for PitrError {}

impl From<WalError> for PitrError {
    fn from(err: WalError) -> Self {
        PitrError::Wal(err)
    }
}

impl From<S3BackupError> for PitrError {
    fn from(err: S3BackupError) -> Self {
        PitrError::S3(err)
    }
}

impl From<std::io::Error> for PitrError {
    fn from(err: std::io::Error) -> Self {
        PitrError::Io(err)
    }
}

impl From<OperationError> for PitrError {
    fn from(err: OperationError) -> Self {
        PitrError::Operation(err)
    }
}

/// Run file I/O, segment parsing and cryptography on the blocking thread pool, so that the
/// archive task and the recovery commands never stall the async runtime.
async fn blocking<T, F>(work: F) -> Result<T, PitrError>
where
    F: FnOnce() -> Result<T, PitrError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|err| PitrError::Io(std::io::Error::other(err)))?
}
