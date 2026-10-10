//! Verification of a backup immediately after it has been written.
//!
//! Writing a backup only proves that the backend produced bytes without an error. Before
//! a backup is announced as a success, kept by retention or uploaded, it is parsed again
//! with the same structural checks as `kubidmd database verify-backup --level structural`.
//! The artifact is checked exactly as stored: an encrypted backup is decrypted with the
//! key it was written with, which also proves that the key can open it. A local artifact
//! that fails is kept for forensics under an `.invalid` suffix, which the backup name
//! matcher in [`super::retention`] never recognises as a backup, so a broken backup can
//! neither count towards nor prune the retained good ones.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

/// Upper bound on the numbered `.invalid.N` quarantine names tried for one path.
const MAX_QUARANTINE_ATTEMPTS: usize = 1000;

/// The path a rejected backup at `path` is moved to: the same file name with
/// [`INVALID_BACKUP_SUFFIX`] appended.
pub fn invalid_backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(ToOwned::to_owned).unwrap_or_default();
    name.push(INVALID_BACKUP_SUFFIX);
    path.with_file_name(name)
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
/// `data` is the complete artifact, `compression` the compression it was produced with and
/// `encryptor` the key it was sealed with, if any. This is the check applied to in-memory
/// backups before they leave the server, such as an S3 upload.
///
/// The artifact must match the configuration it was produced under: with an `encryptor`
/// it has to be an encrypted container that this key opens and whose header records
/// `compression`; without one it has to be a plain backup.
pub fn verify_backup_output(
    data: &[u8],
    compression: BackupCompression,
    encryptor: Option<&BackupEncryptor>,
) -> Result<BackupStructuralReport, BackupVerifyError> {
    let reject = |reason: String| BackupVerifyError {
        reasons: vec![reason],
        quarantined_to: None,
    };

    let opened = open_backup_bytes(data.to_vec(), Path::new(""), encryptor, true)
        .map_err(|err| reject(format!("artifact could not be opened: {err}")))?;

    if opened.encryption.is_some() && opened.compression != compression {
        return Err(reject(format!(
            "encrypted artifact records {} but the backup was written with {compression}",
            opened.compression
        )));
    }

    // A plain artifact has no header to tell its compression from, so the parser is told
    // the compression the backup was written with and a mismatch fails to parse.
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
/// runtime. `data` is shared rather than moved so that the caller can still upload it.
pub async fn verify_backup_output_async(
    data: Arc<Vec<u8>>,
    compression: BackupCompression,
    encryptor: Option<&BackupEncryptor>,
) -> Result<BackupStructuralReport, BackupVerifyError> {
    let encryptor = encryptor.cloned();
    tokio::task::spawn_blocking(move || {
        verify_backup_output(&data, compression, encryptor.as_ref())
    })
    .await
    .unwrap_or_else(|err| Err(verification_task_failed(&err)))
}

/// Reopen the backup that was just written to `path` and structurally verify it with the
/// `compression` and the `encryptor` it was written with. On failure the file is renamed
/// to [`invalid_backup_path`] so that it is kept but never treated as a backup again.
pub fn finalize_local_backup(
    path: &Path,
    compression: BackupCompression,
    encryptor: Option<&BackupEncryptor>,
) -> Result<BackupStructuralReport, BackupVerifyError> {
    let verified = std::fs::read(path)
        .map_err(|err| BackupVerifyError {
            reasons: vec![format!(
                "unable to reopen {} for verification: {err}",
                path.display()
            )],
            quarantined_to: None,
        })
        .and_then(|data| verify_backup_output(&data, compression, encryptor));

    verified.map_err(|mut err| {
        let Some(invalid) = available_invalid_backup_path(path) else {
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
    })
}

/// [`finalize_local_backup`] for async callers: reading the artifact back, decrypting,
/// decompressing and parsing it, and quarantining a rejected one run on the blocking thread
/// pool so that they never stall the async runtime.
pub async fn finalize_local_backup_async(
    path: &Path,
    compression: BackupCompression,
    encryptor: Option<&BackupEncryptor>,
) -> Result<BackupStructuralReport, BackupVerifyError> {
    let path = path.to_path_buf();
    let encryptor = encryptor.cloned();
    tokio::task::spawn_blocking(move || {
        finalize_local_backup(&path, compression, encryptor.as_ref())
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
    use kubidm_proto::backup::{
        BackupEncryptionConfig, EncryptionKeySource, KeyDerivationParams, BACKUP_ENCRYPTED_SUFFIX,
    };

    use super::*;
    use crate::backup::encryption::MIN_KDF_M_COST;

    fn encryptor(passphrase: &[u8]) -> BackupEncryptor {
        BackupEncryptor::with_key_material(
            BackupEncryptionConfig {
                enabled: true,
                key_source: EncryptionKeySource::Passphrase,
                key_derivation: KeyDerivationParams {
                    m_cost: MIN_KDF_M_COST,
                    t_cost: 1,
                    p_cost: 1,
                },
                key_identifier: None,
                passphrase_file: None,
            },
            passphrase.to_vec(),
        )
        .expect("encryptor")
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

    #[test]
    fn test_finalize_accepts_valid_plain_and_gzip_backups() {
        let dir = tempfile::tempdir().expect("tempdir");

        let plain = dir.path().join("backup-plain.json");
        std::fs::write(&plain, minimal_valid_backup()).expect("write");
        let report = finalize_local_backup(&plain, BackupCompression::NoCompression, None)
            .expect("a valid backup must pass");
        assert_eq!(report.entry_count, 1);
        assert_eq!(report.version.as_deref(), Some(env!("KUBIDM_PKG_SERIES")));
        assert!(plain.exists(), "a valid backup is left in place");
        assert!(!invalid_backup_path(&plain).exists());

        let gz = dir.path().join("backup-gzip.json.gz");
        std::fs::write(&gz, gzip(&minimal_valid_backup())).expect("write");
        let report = finalize_local_backup(&gz, BackupCompression::Gzip, None)
            .expect("a valid gzip backup must pass");
        assert_eq!(report.entry_count, 1);
        assert!(gz.exists());
    }

    #[test]
    fn test_finalize_quarantines_garbage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("backup-garbage.json");
        std::fs::write(&path, b"this is not a backup").expect("write");

        let err = finalize_local_backup(&path, BackupCompression::NoCompression, None)
            .expect_err("garbage must be rejected");
        let invalid = invalid_backup_path(&path);
        assert_eq!(err.quarantined_to.as_deref(), Some(invalid.as_path()));
        assert!(!err.reasons.is_empty());
        assert!(
            !path.exists(),
            "the rejected artifact must not keep its name"
        );
        assert_eq!(
            std::fs::read(&invalid).expect("read quarantined"),
            b"this is not a backup",
            "the rejected artifact is kept for forensics"
        );
    }

    #[test]
    fn test_finalize_quarantines_compression_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("backup-mismatch.json.gz");
        // Plain JSON written where gzip was expected.
        std::fs::write(&path, minimal_valid_backup()).expect("write");

        let err = finalize_local_backup(&path, BackupCompression::Gzip, None)
            .expect_err("a compression mismatch must be rejected");
        assert!(err.quarantined_to.is_some());
        assert!(!path.exists());
        assert!(invalid_backup_path(&path).exists());
    }

    #[test]
    fn test_finalize_quarantines_structurally_invalid_report() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("backup-empty.json");
        // A V1 backup: parses, but has no version and no entries.
        std::fs::write(&path, b"[]").expect("write");

        let err = finalize_local_backup(&path, BackupCompression::NoCompression, None)
            .expect_err("an unrestorable backup must be rejected");
        assert!(err
            .reasons
            .iter()
            .any(|reason| reason.contains("no entries")));
        assert!(invalid_backup_path(&path).exists());
    }

    #[test]
    fn test_finalize_reports_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("backup-missing.json");

        let err = finalize_local_backup(&path, BackupCompression::NoCompression, None)
            .expect_err("a missing file must be rejected");
        assert!(err.quarantined_to.is_none());
        assert!(
            err.reasons.len() >= 2,
            "reopen and rename failures are both reported"
        );
    }

    #[test]
    fn test_finalize_keeps_every_rejected_copy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("backup-retry.json");
        let invalid = invalid_backup_path(&path);

        std::fs::write(&path, b"first attempt").expect("write");
        let first = finalize_local_backup(&path, BackupCompression::NoCompression, None)
            .expect_err("garbage must be rejected");
        assert_eq!(first.quarantined_to.as_deref(), Some(invalid.as_path()));

        // An operator retries the same destination and it fails again: the earlier
        // forensic copy must not be overwritten.
        std::fs::write(&path, b"second attempt").expect("write");
        let second = finalize_local_backup(&path, BackupCompression::NoCompression, None)
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
            BackupCompression::NoCompression,
            None,
        )
        .expect("a valid in-memory backup must pass");
        assert_eq!(report.entry_count, 1);

        let err = verify_backup_output(b"garbage", BackupCompression::NoCompression, None)
            .expect_err("garbage must be rejected");
        assert!(err.quarantined_to.is_none());
        assert!(err.to_string().contains("could not be parsed"));
    }

    #[test]
    fn test_verify_backup_output_encrypted_round_trip() {
        let enc = encryptor(b"pw");
        for (compression, plaintext) in [
            (BackupCompression::NoCompression, minimal_valid_backup()),
            (BackupCompression::Gzip, gzip(&minimal_valid_backup())),
        ] {
            let sealed = enc.encrypt(&plaintext, compression).expect("encrypt");
            let report = verify_backup_output(&sealed, compression, Some(&enc))
                .expect("an encrypted backup verified with its key must pass");
            assert_eq!(report.entry_count, 1);
            assert_eq!(report.version.as_deref(), Some(env!("KUBIDM_PKG_SERIES")));
        }
    }

    #[test]
    fn test_verify_backup_output_rejects_configuration_mismatches() {
        let enc = encryptor(b"pw");
        let sealed = enc
            .encrypt(&gzip(&minimal_valid_backup()), BackupCompression::Gzip)
            .expect("encrypt");

        // Encrypted artifact, no key.
        let err = verify_backup_output(&sealed, BackupCompression::Gzip, None)
            .expect_err("an encrypted artifact without a key must be rejected");
        assert!(
            err.to_string().contains(enc.key_identifier()),
            "the key identifier must be named: {err}"
        );

        // Encrypted artifact, wrong key.
        let err = verify_backup_output(&sealed, BackupCompression::Gzip, Some(&encryptor(b"no")))
            .expect_err("a wrong key must be rejected");
        assert!(err.to_string().contains("decryption failed"), "{err}");

        // Encrypted artifact whose header disagrees with the compression it should have.
        let err = verify_backup_output(&sealed, BackupCompression::NoCompression, Some(&enc))
            .expect_err("a compression mismatch must be rejected");
        assert!(err.to_string().contains("records Gzip"), "{err}");

        // Plain artifact although encryption is configured.
        let err = verify_backup_output(
            &minimal_valid_backup(),
            BackupCompression::NoCompression,
            Some(&enc),
        )
        .expect_err("a plain artifact must be rejected when encryption is on");
        assert!(err.to_string().contains("not encrypted"), "{err}");

        // Encrypted garbage: decrypts, but is not a backup.
        let sealed_garbage = enc
            .encrypt(b"not a backup", BackupCompression::NoCompression)
            .expect("encrypt");
        let err = verify_backup_output(
            &sealed_garbage,
            BackupCompression::NoCompression,
            Some(&enc),
        )
        .expect_err("encrypted garbage must be rejected");
        assert!(err.to_string().contains("could not be parsed"), "{err}");
    }

    #[test]
    fn test_finalize_encrypted_backup_keeps_valid_and_quarantines_unopenable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let enc = encryptor(b"pw");

        let good = dir
            .path()
            .join(format!("backup-good.json.gz{BACKUP_ENCRYPTED_SUFFIX}"));
        std::fs::write(
            &good,
            enc.encrypt(&gzip(&minimal_valid_backup()), BackupCompression::Gzip)
                .expect("encrypt"),
        )
        .expect("write");
        let report = finalize_local_backup(&good, BackupCompression::Gzip, Some(&enc))
            .expect("a valid encrypted backup must pass");
        assert_eq!(report.entry_count, 1);
        assert!(good.exists(), "a valid backup is left in place");

        // The same artifact checked with another key is quarantined with the encrypted
        // name plus the invalid suffix.
        let other = dir
            .path()
            .join(format!("backup-other.json.gz{BACKUP_ENCRYPTED_SUFFIX}"));
        std::fs::copy(&good, &other).expect("copy");
        let err = finalize_local_backup(&other, BackupCompression::Gzip, Some(&encryptor(b"no")))
            .expect_err("a wrong key must be rejected");
        let quarantined = invalid_backup_path(&other);
        assert_eq!(err.quarantined_to.as_deref(), Some(quarantined.as_path()));
        assert!(!other.exists());
        assert!(quarantined.exists());
        assert!(quarantined
            .to_string_lossy()
            .ends_with(".json.gz.enc.invalid"));
    }
}
