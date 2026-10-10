//! Verification of a backup immediately after it has been written.
//!
//! Writing a backup only proves that the backend produced bytes without an error. Before
//! a backup is announced as a success, kept by retention or uploaded, it is parsed again
//! with the same structural checks as `kubidmd database verify-backup --level structural`.
//! The artifact is checked exactly as stored: an encrypted backup is decrypted with the
//! key it was written with, which also proves that the key can open it. The name it is
//! stored under counts as it does on restore: a plain backup's compression is taken from
//! its name, and a plain backup must not carry the encrypted suffix.
//!
//! A local artifact is written to a hidden temporary file next to its destination, synced
//! to disk and verified there, and only then renamed to its final name. One that fails is
//! kept for forensics under an `.invalid` suffix. Neither name is ever recognised as a
//! backup by the matcher in [`super::retention`], so a broken, interrupted or partially
//! written backup can neither count towards nor prune the retained good ones.

use std::ffi::OsString;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use kubidm_proto::backup::BackupCompression;
use kubidmd_lib::be::{verify_backup_structure, BackupStructuralReport};

use super::artifact::open_backup_bytes;
use super::encryption::BackupEncryptor;

/// Suffix appended to the file name of a freshly written local backup that failed
/// verification.
pub const INVALID_BACKUP_SUFFIX: &str = ".invalid";

/// Why a freshly written backup was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupVerifyError {
    /// Human readable reasons, never empty.
    pub reasons: Vec<String>,
    /// Where the rejected local artifact was moved to, when it was a file and the rename
    /// succeeded.
    pub quarantined_to: Option<PathBuf>,
}

impl fmt::Display for BackupVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reasons.join("; "))?;
        if let Some(path) = &self.quarantined_to {
            write!(f, " (artifact kept as {})", path.display())?;
        }
        Ok(())
    }
}

/// Suffix of the hidden temporary file a local backup is written to, see
/// [`partial_backup_path`].
pub const PARTIAL_BACKUP_SUFFIX: &str = ".partial";

/// Upper bound on the numbered `.invalid.N` quarantine names tried for one path.
const MAX_QUARANTINE_ATTEMPTS: usize = 1000;

/// The path a rejected backup at `path` is moved to: the same file name with
/// [`INVALID_BACKUP_SUFFIX`] appended.
pub fn invalid_backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(ToOwned::to_owned).unwrap_or_default();
    name.push(INVALID_BACKUP_SUFFIX);
    path.with_file_name(name)
}

/// The temporary file a local backup destined for `dest` is written to before it is
/// verified and renamed into place: `.<name>.partial` in the same directory, so that the
/// rename is atomic. The leading dot hides it, and it never matches the backup name
/// pattern, so a backup that is still being written, or was interrupted by a crash, is
/// never counted or listed as a backup.
pub fn partial_backup_path(dest: &Path) -> PathBuf {
    let mut name = OsString::from(".");
    name.push(dest.file_name().unwrap_or_default());
    name.push(PARTIAL_BACKUP_SUFFIX);
    dest.with_file_name(name)
}

/// A quarantine path for `path` that does not exist yet: [`invalid_backup_path`], or when
/// an earlier rejected artifact already holds that name (an operator retrying a manual
/// backup to the same destination), `<name>.invalid.1`, `.2`, ... so that every forensic
/// copy is kept. `None` when [`MAX_QUARANTINE_ATTEMPTS`] names are all taken.
fn available_invalid_backup_path(path: &Path) -> Option<PathBuf> {
    let base = invalid_backup_path(path);
    if !base.exists() {
        return Some(base);
    }
    (1..MAX_QUARANTINE_ATTEMPTS)
        .map(|n| {
            let mut name = base.file_name().map(ToOwned::to_owned).unwrap_or_default();
            name.push(format!(".{n}"));
            base.with_file_name(name)
        })
        .find(|candidate| !candidate.exists())
}

/// Structurally verify a backup artifact exactly as it is stored or about to be stored:
/// `data` is the complete artifact, `name` the file name or object key it is stored under
/// (None when it has none, such as a backup written to stdout), `compression` the
/// compression it was produced with and `encryptor` the key it was sealed with, if any.
/// This is the check applied to in-memory backups before they leave the server, such as
/// an S3 upload.
///
/// The artifact must match the configuration it was produced under: with an `encryptor`
/// it has to be an encrypted container that this key opens and whose header records
/// `compression`; without one it has to be a plain backup. It must also open under its
/// `name` the way restore and `verify-backup` open it: a plain artifact must not be named
/// as an encrypted one, and the compression its name announces must be the one it was
/// written with, since restore takes a plain backup's compression from its name.
pub fn verify_backup_output(
    data: &[u8],
    name: Option<&Path>,
    compression: BackupCompression,
    encryptor: Option<&BackupEncryptor>,
) -> Result<BackupStructuralReport, BackupVerifyError> {
    let reject = |reason: String| BackupVerifyError {
        reasons: vec![reason],
        quarantined_to: None,
    };

    let opened = open_backup_bytes(
        data.to_vec(),
        name.unwrap_or(Path::new("")),
        encryptor,
        true,
    )
    .map_err(|err| reject(format!("artifact could not be opened: {err}")))?;

    if opened.encryption.is_some() && opened.compression != compression {
        return Err(reject(format!(
            "encrypted artifact records {} but the backup was written with {compression}",
            opened.compression
        )));
    }

    if let Some(name) = name {
        if opened.encryption.is_none() && opened.compression != compression {
            return Err(reject(format!(
                "{} is named as a {} backup but was written with {compression}; restore \
                 and verify-backup take the compression of a plain backup from its name, \
                 so it could not be restored",
                name.display(),
                opened.compression
            )));
        }
    }

    match verify_backup_structure(opened.reader, compression) {
        Ok(report) if report.is_valid() => Ok(report),
        Ok(report) => Err(BackupVerifyError {
            reasons: report.errors,
            quarantined_to: None,
        }),
        Err(err) => Err(reject(format!(
            "artifact could not be parsed as a kubidm backup: {err:?}"
        ))),
    }
}

/// [`verify_backup_output`] for async callers: the decryption, decompression and parsing
/// of the whole backup run on the blocking thread pool so that they never stall the async
/// runtime. `data` is shared rather than copied so that the caller can still upload it.
pub async fn verify_backup_output_async(
    data: Bytes,
    name: Option<&Path>,
    compression: BackupCompression,
    encryptor: Option<&BackupEncryptor>,
) -> Result<BackupStructuralReport, BackupVerifyError> {
    let name = name.map(Path::to_path_buf);
    let encryptor = encryptor.cloned();
    tokio::task::spawn_blocking(move || {
        verify_backup_output(&data, name.as_deref(), compression, encryptor.as_ref())
    })
    .await
    .unwrap_or_else(|err| Err(verification_task_failed(&err)))
}

/// Read the artifact at `path` back and verify it as if it were stored under `name`.
fn verify_local_file(
    path: &Path,
    name: &Path,
    compression: BackupCompression,
    encryptor: Option<&BackupEncryptor>,
) -> Result<BackupStructuralReport, BackupVerifyError> {
    std::fs::read(path)
        .map_err(|err| BackupVerifyError {
            reasons: vec![format!(
                "unable to reopen {} for verification: {err}",
                path.display()
            )],
            quarantined_to: None,
        })
        .and_then(|data| verify_backup_output(&data, Some(name), compression, encryptor))
}

/// Move the rejected artifact at `path` to a free quarantine name derived from `name`,
/// recording where it went, or why it could not be moved, in `err`.
fn quarantine(path: &Path, name: &Path, mut err: BackupVerifyError) -> BackupVerifyError {
    let Some(invalid) = available_invalid_backup_path(name) else {
        err.reasons.push(format!(
            "unable to quarantine {}: {MAX_QUARANTINE_ATTEMPTS} rejected copies already exist",
            path.display()
        ));
        return err;
    };
    match std::fs::rename(path, &invalid) {
        Ok(()) => err.quarantined_to = Some(invalid),
        Err(rename_err) => err.reasons.push(format!(
            "unable to rename {} to {}: {rename_err}",
            path.display(),
            invalid.display()
        )),
    }
    err
}

/// Remove the temporary file of a backup that failed before it could be verified,
/// recording a failure to do so in `err`.
fn discard_partial(partial: &Path, mut err: BackupVerifyError) -> BackupVerifyError {
    if let Err(remove_err) = std::fs::remove_file(partial) {
        if remove_err.kind() != std::io::ErrorKind::NotFound {
            err.reasons.push(format!(
                "unable to remove {}: {remove_err}",
                partial.display()
            ));
        }
    }
    err
}

/// Write `artifact`, a complete backup, to `dest` such that a backup name only ever
/// holds a complete, durable and verified backup.
///
/// The artifact is written to [`partial_backup_path`], created exclusively so that two
/// backups to the same destination can never interleave their bytes, locked until the
/// backup ends so that retention never removes it, and synced to disk.
/// It is then read back and verified as [`verify_backup_output`] does, under the rules of
/// its final name, renamed to `dest` and the directory synced, so that the rename
/// survives a power loss. A destination that already exists is never overwritten. When
/// the write fails the temporary file is removed; when the verification fails it is
/// quarantined under [`invalid_backup_path`] of `dest` for inspection.
pub fn write_verified_local_backup(
    dest: &Path,
    artifact: &[u8],
    compression: BackupCompression,
    encryptor: Option<&BackupEncryptor>,
) -> Result<BackupStructuralReport, BackupVerifyError> {
    let reject = |reason: String| BackupVerifyError {
        reasons: vec![reason],
        quarantined_to: None,
    };

    if dest.exists() {
        return Err(reject(format!(
            "{} already exists, will not overwrite it",
            dest.display()
        )));
    }

    let partial = partial_backup_path(dest);
    // Not removed on failure: it belongs to another backup to the same destination.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|err| {
            reject(if err.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "{} already exists: another backup to {} is running, or one was \
                     interrupted (killed, or the host lost power) and left it behind; when no \
                     backup is running, delete it and try again",
                    partial.display(),
                    dest.display()
                )
            } else {
                format!("unable to create {}: {err}", partial.display())
            })
        })?;
    // Held until the backup is renamed into place or given up: retention never removes a
    // partial file that is locked, see `prune_local_backups`. A filesystem without locks
    // leaves the partial file unprotected, and retention then keeps it too.
    if let Err(err) = file.lock() {
        warn!(
            "Unable to lock {}; a concurrent retention run will not remove it: {err}",
            partial.display()
        );
    }
    let written = file.write_all(artifact).and_then(|()| file.sync_all());
    if let Err(err) = written {
        return Err(discard_partial(
            &partial,
            reject(format!("unable to write {}: {err}", partial.display())),
        ));
    }

    let report = verify_local_file(&partial, dest, compression, encryptor)
        .map_err(|err| quarantine(&partial, dest, err))?;

    if dest.exists() {
        return Err(discard_partial(
            &partial,
            reject(format!(
                "{} appeared while the backup was written, will not overwrite it",
                dest.display()
            )),
        ));
    }
    if let Err(err) = std::fs::rename(&partial, dest) {
        return Err(discard_partial(
            &partial,
            reject(format!(
                "unable to rename {} to {}: {err}",
                partial.display(),
                dest.display()
            )),
        ));
    }
    if let Err(err) = sync_parent_dir(dest) {
        // The backup is complete and verified under its name; only its durability across
        // a power loss is in doubt.
        warn!(
            "Unable to sync the directory of {} to disk: {err}",
            dest.display()
        );
    }

    Ok(report)
}

/// Make the directory entries of the directory holding `path` durable.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    match path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        Some(dir) => std::fs::File::open(dir)?.sync_all(),
        None => std::fs::File::open(".")?.sync_all(),
    }
}

/// Directories can not be opened for syncing on this platform.
#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// [`write_verified_local_backup`] for async callers: the write, the read back, the
/// verification and the rename run on the blocking thread pool. Once started they run to
/// completion even when the caller is dropped, so a cancelled backup still either ends up
/// complete under its name or not at all.
pub async fn write_verified_local_backup_async(
    dest: &Path,
    artifact: Bytes,
    compression: BackupCompression,
    encryptor: Option<&BackupEncryptor>,
) -> Result<BackupStructuralReport, BackupVerifyError> {
    let dest = dest.to_path_buf();
    let encryptor = encryptor.cloned();
    tokio::task::spawn_blocking(move || {
        write_verified_local_backup(&dest, &artifact, compression, encryptor.as_ref())
    })
    .await
    .unwrap_or_else(|err| Err(verification_task_failed(&err)))
}

/// The rejection of a verification whose blocking task panicked or was cancelled.
fn verification_task_failed(err: &tokio::task::JoinError) -> BackupVerifyError {
    BackupVerifyError {
        reasons: vec![format!("the verification task failed: {err}")],
        quarantined_to: None,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use kubidm_proto::backup::BACKUP_ENCRYPTED_SUFFIX;

    use super::*;
    use crate::backup::artifact::backup_identity;
    use crate::backup::encryption::test_encryptor;

    fn encryptor(passphrase: &[u8]) -> BackupEncryptor {
        test_encryptor(passphrase)
    }

    /// The smallest artifact `verify_backup_structure` accepts: a V5 backup written by this
    /// server series that carries one (empty) live entry.
    fn minimal_valid_backup() -> Vec<u8> {
        let series = env!("KUBIDM_PKG_SERIES");
        format!(
            r#"{{
              "version": "{series}",
              "db_s_uuid": "00000000-0000-0000-0000-000000000001",
              "db_d_uuid": "00000000-0000-0000-0000-000000000002",
              "db_ts_max": {{"secs": 1, "nanos": 0}},
              "keyhandles": {{}},
              "repl_meta": {{"V1": {{"ruv": []}}}},
              "entries": [
                {{"ent": {{"V3": {{
                  "changestate": {{"V1Live": {{
                    "at": {{"t": {{"secs": 1, "nanos": 0}}, "s": "00000000-0000-0000-0000-000000000001"}},
                    "changes": {{}}
                  }}}},
                  "attrs": {{}}
                }}}}}}
              ]
            }}"#
        )
        .into_bytes()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(bytes).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    #[test]
    fn test_invalid_backup_path_appends_suffix() {
        let path = Path::new("/var/backups/backup-2024-01-01T22:00:00Z.json.gz");
        assert_eq!(
            invalid_backup_path(path),
            PathBuf::from("/var/backups/backup-2024-01-01T22:00:00Z.json.gz.invalid")
        );
        assert!(!crate::backup::is_backup_artifact_name(
            "backup-2024-01-01T22:00:00Z.json.gz.invalid"
        ));

        let encrypted = Path::new("/var/backups/backup-2024-01-01T22:00:00Z.json.gz.enc");
        assert_eq!(
            invalid_backup_path(encrypted),
            PathBuf::from("/var/backups/backup-2024-01-01T22:00:00Z.json.gz.enc.invalid")
        );
        assert!(!crate::backup::is_backup_artifact_name(
            "backup-2024-01-01T22:00:00Z.json.gz.enc.invalid"
        ));
    }

    /// Write `artifact` to `dest` with [`write_verified_local_backup`], without encryption.
    fn write(
        dest: &Path,
        artifact: &[u8],
        compression: BackupCompression,
    ) -> Result<BackupStructuralReport, BackupVerifyError> {
        write_verified_local_backup(dest, artifact, compression, None)
    }

    #[test]
    fn test_write_verified_local_backup_accepts_valid_plain_and_gzip_backups() {
        let dir = tempfile::tempdir().expect("tempdir");

        let plain = dir.path().join("backup-plain.json");
        let report = write(
            &plain,
            &minimal_valid_backup(),
            BackupCompression::NoCompression,
        )
        .expect("a valid backup must pass");
        assert_eq!(report.entry_count, 1);
        assert_eq!(report.version.as_deref(), Some(env!("KUBIDM_PKG_SERIES")));
        assert!(plain.exists(), "a valid backup is put in place");
        assert!(!invalid_backup_path(&plain).exists());

        let gz = dir.path().join("backup-gzip.json.gz");
        let report = write(&gz, &gzip(&minimal_valid_backup()), BackupCompression::Gzip)
            .expect("a valid gzip backup must pass");
        assert_eq!(report.entry_count, 1);
        assert!(gz.exists());
    }

    #[test]
    fn test_write_verified_local_backup_quarantines_garbage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("backup-garbage.json");

        let err = write(
            &path,
            b"this is not a backup",
            BackupCompression::NoCompression,
        )
        .expect_err("garbage must be rejected");
        let invalid = invalid_backup_path(&path);
        assert_eq!(err.quarantined_to.as_deref(), Some(invalid.as_path()));
        assert!(!err.reasons.is_empty());
        assert!(
            !path.exists(),
            "the rejected artifact must not get its name"
        );
        assert_eq!(
            std::fs::read(&invalid).expect("read quarantined"),
            b"this is not a backup",
            "the rejected artifact is kept for forensics"
        );
    }

    #[test]
    fn test_write_verified_local_backup_quarantines_compression_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("backup-mismatch.json.gz");

        // Plain JSON written where gzip was expected.
        let err = write(&path, &minimal_valid_backup(), BackupCompression::Gzip)
            .expect_err("a compression mismatch must be rejected");
        assert!(err.quarantined_to.is_some());
        assert!(!path.exists());
        assert!(invalid_backup_path(&path).exists());
    }

    #[test]
    fn test_write_verified_local_backup_quarantines_structurally_invalid_report() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("backup-empty.json");

        // A V1 backup: parses, but has no version and no entries.
        let err = write(&path, b"[]", BackupCompression::NoCompression)
            .expect_err("an unrestorable backup must be rejected");
        assert!(err
            .reasons
            .iter()
            .any(|reason| reason.contains("no entries")));
        assert!(invalid_backup_path(&path).exists());
    }

    #[test]
    fn test_write_verified_local_backup_keeps_every_rejected_copy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("backup-retry.json");
        let invalid = invalid_backup_path(&path);

        let first = write(&path, b"first attempt", BackupCompression::NoCompression)
            .expect_err("garbage must be rejected");
        assert_eq!(first.quarantined_to.as_deref(), Some(invalid.as_path()));

        // An operator retries the same destination and it fails again: the earlier
        // forensic copy must not be overwritten.
        let second = write(&path, b"second attempt", BackupCompression::NoCompression)
            .expect_err("garbage must be rejected");
        let numbered = dir.path().join("backup-retry.json.invalid.1");
        assert_eq!(second.quarantined_to.as_deref(), Some(numbered.as_path()));

        assert_eq!(std::fs::read(&invalid).expect("read"), b"first attempt");
        assert_eq!(std::fs::read(&numbered).expect("read"), b"second attempt");
        assert!(!path.exists());
    }

    #[test]
    fn test_verify_backup_output_in_memory() {
        let report = verify_backup_output(
            &minimal_valid_backup(),
            None,
            BackupCompression::NoCompression,
            None,
        )
        .expect("a valid in-memory backup must pass");
        assert_eq!(report.entry_count, 1);

        let err = verify_backup_output(b"garbage", None, BackupCompression::NoCompression, None)
            .expect_err("garbage must be rejected");
        assert!(err.quarantined_to.is_none());
        assert!(err.to_string().contains("could not be parsed"));
        // The parser says where it stopped.
        assert!(err.to_string().contains("line 1 column 1"), "{err}");
    }

    #[test]
    fn test_verify_backup_output_encrypted_round_trip() {
        let enc = encryptor(b"pw");
        for (compression, plaintext) in [
            (BackupCompression::NoCompression, minimal_valid_backup()),
            (BackupCompression::Gzip, gzip(&minimal_valid_backup())),
        ] {
            let sealed = enc
                .encrypt(&plaintext, compression, &backup_identity(Path::new("")))
                .expect("encrypt");
            let report = verify_backup_output(&sealed, None, compression, Some(&enc))
                .expect("an encrypted backup verified with its key must pass");
            assert_eq!(report.entry_count, 1);
            assert_eq!(report.version.as_deref(), Some(env!("KUBIDM_PKG_SERIES")));
        }
    }

    #[test]
    fn test_verify_backup_output_rejects_configuration_mismatches() {
        let enc = encryptor(b"pw");
        let sealed = enc
            .encrypt(
                &gzip(&minimal_valid_backup()),
                BackupCompression::Gzip,
                &backup_identity(Path::new("")),
            )
            .expect("encrypt");

        // Encrypted artifact, no key.
        let err = verify_backup_output(&sealed, None, BackupCompression::Gzip, None)
            .expect_err("an encrypted artifact without a key must be rejected");
        assert!(
            err.to_string().contains(enc.key_identifier()),
            "the key identifier must be named: {err}"
        );

        // Encrypted artifact, wrong key.
        let err = verify_backup_output(
            &sealed,
            None,
            BackupCompression::Gzip,
            Some(&encryptor(b"no")),
        )
        .expect_err("a wrong key must be rejected");
        assert!(err.to_string().contains("decryption failed"), "{err}");

        // Encrypted artifact whose header disagrees with the compression it should have.
        let err = verify_backup_output(&sealed, None, BackupCompression::NoCompression, Some(&enc))
            .expect_err("a compression mismatch must be rejected");
        assert!(err.to_string().contains("records Gzip"), "{err}");

        // Plain artifact although encryption is configured.
        let err = verify_backup_output(
            &minimal_valid_backup(),
            None,
            BackupCompression::NoCompression,
            Some(&enc),
        )
        .expect_err("a plain artifact must be rejected when encryption is on");
        assert!(err.to_string().contains("not encrypted"), "{err}");

        // Encrypted garbage: decrypts, but is not a backup.
        let sealed_garbage = enc
            .encrypt(
                b"not a backup",
                BackupCompression::NoCompression,
                &backup_identity(Path::new("")),
            )
            .expect("encrypt");
        let err = verify_backup_output(
            &sealed_garbage,
            None,
            BackupCompression::NoCompression,
            Some(&enc),
        )
        .expect_err("encrypted garbage must be rejected");
        assert!(err.to_string().contains("could not be parsed"), "{err}");
    }

    #[test]
    fn test_write_verified_local_backup_keeps_valid_and_quarantines_unopenable_encrypted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let enc = encryptor(b"pw");
        let sealed = enc
            .encrypt(
                &gzip(&minimal_valid_backup()),
                BackupCompression::Gzip,
                &backup_identity(Path::new("")),
            )
            .expect("encrypt");

        let good = dir
            .path()
            .join(format!("backup-good.json.gz{BACKUP_ENCRYPTED_SUFFIX}"));
        let report =
            write_verified_local_backup(&good, &sealed, BackupCompression::Gzip, Some(&enc))
                .expect("a valid encrypted backup must pass");
        assert_eq!(report.entry_count, 1);
        assert!(good.exists(), "a valid backup is put in place");

        // The same artifact checked with another key is quarantined with the encrypted
        // name plus the invalid suffix.
        let other = dir
            .path()
            .join(format!("backup-other.json.gz{BACKUP_ENCRYPTED_SUFFIX}"));
        let err = write_verified_local_backup(
            &other,
            &sealed,
            BackupCompression::Gzip,
            Some(&encryptor(b"no")),
        )
        .expect_err("a wrong key must be rejected");
        let quarantined = invalid_backup_path(&other);
        assert_eq!(err.quarantined_to.as_deref(), Some(quarantined.as_path()));
        assert!(!other.exists());
        assert!(quarantined.exists());
        assert!(quarantined
            .to_string_lossy()
            .ends_with(".json.gz.enc.invalid"));
    }

    #[test]
    fn test_verify_backup_output_applies_the_rules_of_the_name() {
        // A gzip backup under a plain name: restore would parse it as plain JSON.
        let gz = gzip(&minimal_valid_backup());
        let err = verify_backup_output(
            &gz,
            Some(Path::new("kubidm.json")),
            BackupCompression::Gzip,
            None,
        )
        .expect_err("a gzip backup named as plain must be rejected");
        assert!(
            err.to_string().contains("named as a No Compression backup"),
            "{err}"
        );
        assert!(verify_backup_output(
            &gz,
            Some(Path::new("kubidm.json.gz")),
            BackupCompression::Gzip,
            None
        )
        .is_ok());

        // A plain backup under an encrypted name: restore refuses it.
        let err = verify_backup_output(
            &gz,
            Some(Path::new("kubidm.json.gz.enc")),
            BackupCompression::Gzip,
            None,
        )
        .expect_err("a plain backup named as encrypted must be rejected");
        assert!(
            err.to_string().contains("not an encrypted container"),
            "{err}"
        );

        // An encrypted backup records its compression; its name does not matter.
        let enc = encryptor(b"pw");
        let sealed = enc
            .encrypt(
                &gz,
                BackupCompression::Gzip,
                &backup_identity(Path::new("kubidm.json")),
            )
            .expect("encrypt");
        assert!(verify_backup_output(
            &sealed,
            Some(Path::new("kubidm.json")),
            BackupCompression::Gzip,
            Some(&enc)
        )
        .is_ok());
    }

    #[test]
    fn test_partial_backup_path_is_hidden_and_never_a_backup_name() {
        let dest = Path::new("/var/backups/backup-2024-01-01T22:00:00Z.json.gz.enc");
        let partial = partial_backup_path(dest);
        assert_eq!(
            partial,
            PathBuf::from("/var/backups/.backup-2024-01-01T22:00:00Z.json.gz.enc.partial")
        );
        assert!(!crate::backup::is_backup_artifact_name(
            &partial.file_name().expect("name").to_string_lossy()
        ));
    }

    #[test]
    fn test_write_verified_local_backup_puts_a_verified_backup_in_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("backup-2024-01-01T22:00:00Z.json.gz");
        let artifact = gzip(&minimal_valid_backup());

        let report = write_verified_local_backup(&dest, &artifact, BackupCompression::Gzip, None)
            .expect("a valid backup must be written");
        assert_eq!(report.entry_count, 1);
        assert_eq!(std::fs::read(&dest).expect("read"), artifact);
        assert!(!partial_backup_path(&dest).exists());
        assert_eq!(
            std::fs::read_dir(dir.path()).expect("read_dir").count(),
            1,
            "only the backup itself is left"
        );

        // An existing destination is never overwritten.
        let err = write_verified_local_backup(&dest, b"other", BackupCompression::Gzip, None)
            .expect_err("an existing destination must be refused");
        assert!(err.to_string().contains("already exists"), "{err}");
        assert_eq!(std::fs::read(&dest).expect("read"), artifact);
    }

    #[test]
    fn test_write_verified_local_backup_never_names_a_rejected_backup() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Garbage, and a gzip artifact under a plain name, are both rejected: the
        // destination never exists, the temporary file is gone, and the rejected bytes
        // are kept under the destination's quarantine name.
        let cases = [
            ("backup-2024-01-01T22:00:00Z.json.gz", b"garbage".to_vec()),
            (
                "backup-2024-01-02T22:00:00Z.json",
                gzip(&minimal_valid_backup()),
            ),
        ];
        for (name, artifact) in cases {
            let dest = dir.path().join(name);
            let err = write_verified_local_backup(&dest, &artifact, BackupCompression::Gzip, None)
                .expect_err("a rejected backup must fail");
            assert!(!dest.exists(), "{name} must not hold a rejected backup");
            assert!(!partial_backup_path(&dest).exists());
            let quarantined = invalid_backup_path(&dest);
            assert_eq!(err.quarantined_to.as_deref(), Some(quarantined.as_path()));
            assert_eq!(std::fs::read(&quarantined).expect("read"), artifact);
        }
    }

    #[test]
    fn test_write_verified_local_backup_does_not_interleave_with_another_writer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("kubidm.json.gz");
        // Another backup to the same destination is in progress.
        let partial = partial_backup_path(&dest);
        std::fs::write(&partial, b"in progress").expect("write");

        let err = write_verified_local_backup(
            &dest,
            &gzip(&minimal_valid_backup()),
            BackupCompression::Gzip,
            None,
        )
        .expect_err("a concurrent writer must make this backup fail");
        // The error names the file, and says it may be left by an interrupted backup.
        assert!(err.to_string().contains("interrupted"), "{err}");
        assert!(
            err.to_string().contains(&partial.display().to_string()),
            "{err}"
        );
        assert!(!dest.exists());
        assert_eq!(
            std::fs::read(&partial).expect("read"),
            b"in progress",
            "the other writer's file is left alone"
        );
    }
}
