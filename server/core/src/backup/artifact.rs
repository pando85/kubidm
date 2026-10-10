//! Opening and sealing backup artifacts independently of where they are stored.
//!
//! Every reader of a backup (restore, verification, the post-write check) goes through
//! [`open_backup_bytes`] or [`open_backup_file`]: the encrypted container is recognised by
//! its magic first, decrypted with the key the configuration names, and only the plaintext
//! is handed to the compression detection and the parser. Every writer goes through
//! [`seal_backup`], which leaves a plain backup untouched and encrypts it otherwise.

use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use kubidm_proto::backup::{
    is_encrypted_backup_name, BackupCompression, BackupEncryptionConfig, BackupEncryptionHeader,
    BACKUP_ENCRYPTED_SUFFIX, BACKUP_ENCRYPTION_MAGIC,
};

use super::encryption::{
    is_encrypted_artifact, read_encryption_header, BackupEncryptionError, BackupEncryptor,
};

/// A backup artifact resolved to the plaintext a restore can parse.
pub struct OpenedBackup {
    /// The serialised backup, still compressed when `compression` says so.
    pub reader: Box<dyn Read + Send>,
    /// Compression of `reader`: from the encryption header for an encrypted artifact,
    /// from the file name otherwise.
    pub compression: BackupCompression,
    /// The encryption header when the artifact was encrypted.
    pub encryption: Option<BackupEncryptionHeader>,
}

impl fmt::Debug for OpenedBackup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedBackup")
            .field("compression", &self.compression)
            .field("encryption", &self.encryption)
            .finish_non_exhaustive()
    }
}

impl OpenedBackup {
    /// The key identifier recorded in the artifact, when it is encrypted.
    pub fn key_identifier(&self) -> Option<&str> {
        self.encryption
            .as_ref()
            .map(|header| header.key_identifier.as_str())
    }
}

/// Why a backup artifact could not be opened.
#[derive(Debug)]
pub enum BackupOpenError {
    /// The artifact could not be read from storage.
    Io {
        path: String,
        source: std::io::Error,
    },
    /// The artifact is encrypted but backup encryption is not enabled, so there is no key
    /// to open it with.
    EncryptedWithoutKey { key_identifier: String },
    /// The artifact is encrypted and the configured key could not be obtained.
    KeyUnavailable {
        key_identifier: String,
        source: BackupEncryptionError,
    },
    /// The artifact is not encrypted although the configuration encrypts backups. Only the
    /// post-write verification treats this as an error.
    NotEncrypted,
    /// The artifact is named as an encrypted backup (`.enc`) but is not an encrypted
    /// container. Whoever can write to the backup store could otherwise swap an encrypted
    /// backup for an unauthenticated plain one.
    PlainUnderEncryptedName { name: String },
    /// The container is malformed or the key does not open it.
    Decrypt(BackupEncryptionError),
}

impl fmt::Display for BackupOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackupOpenError::Io { path, source } => write!(f, "unable to read {path}: {source}"),
            BackupOpenError::EncryptedWithoutKey { key_identifier } => write!(
                f,
                "the backup is encrypted with key '{key_identifier}' but backup encryption is \
                 not enabled in the configuration; enable [online_backup.encryption] with the \
                 key that wrote it"
            ),
            BackupOpenError::KeyUnavailable {
                key_identifier,
                source,
            } => write!(
                f,
                "the backup is encrypted with key '{key_identifier}' and the configured key \
                 could not be obtained: {source}"
            ),
            BackupOpenError::NotEncrypted => write!(
                f,
                "the backup is not encrypted although backup encryption is enabled"
            ),
            BackupOpenError::PlainUnderEncryptedName { name } => write!(
                f,
                "{name} is named as an encrypted backup ({BACKUP_ENCRYPTED_SUFFIX}) but is not \
                 an encrypted container; it may have been replaced, so it is refused"
            ),
            BackupOpenError::Decrypt(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for BackupOpenError {}

/// Turn a serialised, compressed backup into the bytes that are stored: unchanged without
/// an encryptor, the encrypted container with one.
pub fn seal_backup(
    plaintext: Vec<u8>,
    compression: BackupCompression,
    encryptor: Option<&BackupEncryptor>,
) -> Result<Vec<u8>, BackupEncryptionError> {
    match encryptor {
        Some(encryptor) => encryptor.encrypt(&plaintext, compression),
        None => Ok(plaintext),
    }
}

/// Open an artifact held in memory. `name` is the file name or object key the artifact
/// is stored under; it only matters for the compression of a plain artifact.
///
/// With `strict` set, the artifact must match the configuration: an encrypted artifact
/// needs an encryptor and a plain artifact must not come with one. This is what the
/// post-write verification wants. Without it, a plain artifact always opens, so that a
/// deployment that has turned encryption on can still restore its older plain backups.
pub fn open_backup_bytes(
    data: Vec<u8>,
    name: &Path,
    encryptor: Option<&BackupEncryptor>,
    strict: bool,
) -> Result<OpenedBackup, BackupOpenError> {
    if !is_encrypted_artifact(&data) {
        if strict && encryptor.is_some() {
            return Err(BackupOpenError::NotEncrypted);
        }
        check_plain_name(name)?;
        return Ok(OpenedBackup {
            reader: Box::new(Cursor::new(data)),
            compression: BackupCompression::identify_file(name),
            encryption: None,
        });
    }

    let Some(encryptor) = encryptor else {
        let (header, _) = read_encryption_header(&data).map_err(BackupOpenError::Decrypt)?;
        return Err(BackupOpenError::EncryptedWithoutKey {
            key_identifier: header.key_identifier,
        });
    };

    let (plaintext, header) = encryptor.decrypt(&data).map_err(BackupOpenError::Decrypt)?;
    Ok(OpenedBackup {
        reader: Box::new(Cursor::new(plaintext)),
        compression: if header.compressed {
            BackupCompression::Gzip
        } else {
            BackupCompression::NoCompression
        },
        encryption: Some(header),
    })
}

/// A plain artifact must not carry the encrypted suffix, see
/// [`BackupOpenError::PlainUnderEncryptedName`].
fn check_plain_name(name: &Path) -> Result<(), BackupOpenError> {
    match name.file_name().and_then(|name| name.to_str()) {
        Some(file_name) if is_encrypted_backup_name(file_name) => {
            Err(BackupOpenError::PlainUnderEncryptedName {
                name: name.display().to_string(),
            })
        }
        _ => Ok(()),
    }
}

/// The first bytes of `file`, as many as the encrypted container magic has (fewer when the
/// file is shorter).
fn peek_prefix(file: &mut File) -> std::io::Result<Vec<u8>> {
    let mut prefix = Vec::with_capacity(BACKUP_ENCRYPTION_MAGIC.len());
    file.take(BACKUP_ENCRYPTION_MAGIC.len() as u64)
        .read_to_end(&mut prefix)?;
    Ok(prefix)
}

/// Open the artifact stored at `path`. A plain artifact is streamed from the file, an
/// encrypted one is read whole and decrypted. Never strict, see [`open_backup_bytes`].
pub fn open_backup_file(
    path: &Path,
    encryptor: Option<&BackupEncryptor>,
) -> Result<OpenedBackup, BackupOpenError> {
    let io_err = |source| BackupOpenError::Io {
        path: path.display().to_string(),
        source,
    };

    let mut file = File::open(path).map_err(io_err)?;

    // Peek at the magic so that a plain artifact is streamed rather than loaded.
    let prefix = peek_prefix(&mut file).map_err(io_err)?;

    if !is_encrypted_artifact(&prefix) {
        check_plain_name(path)?;
        return Ok(OpenedBackup {
            reader: Box::new(Cursor::new(prefix).chain(file)),
            compression: BackupCompression::identify_file(path),
            encryption: None,
        });
    }

    let mut data = prefix;
    file.read_to_end(&mut data).map_err(io_err)?;
    open_backup_bytes(data, path, encryptor, false)
}

/// The key an encrypted artifact at `path` needs, resolved from `encryption` only when the
/// artifact is actually encrypted, then [`open_backup_file`]. This is the entry point of
/// the restore and verification commands, which hold a configuration rather than a key.
pub async fn open_backup_file_with_config(
    path: &Path,
    encryption: Option<&BackupEncryptionConfig>,
) -> Result<OpenedBackup, BackupOpenError> {
    let io_err = |source| BackupOpenError::Io {
        path: path.display().to_string(),
        source,
    };

    let mut file = File::open(path).map_err(io_err)?;
    let prefix = peek_prefix(&mut file).map_err(io_err)?;
    drop(file);

    if !is_encrypted_artifact(&prefix) {
        let opened = open_backup_file(path, None)?;
        if encryption.is_some_and(|config| config.enabled) {
            // Kept working so that backups from before encryption was enabled restore, but
            // a plain artifact is not authenticated: say so.
            warn!(
                "{} is not encrypted although backup encryption is enabled; its integrity is \
                 not protected by the encryption key. Only restore it if you know where it \
                 comes from",
                path.display()
            );
        }
        return Ok(opened);
    }

    let encryptor = match encryption {
        Some(config) if config.enabled => BackupEncryptor::from_config(config).await,
        _ => Ok(None),
    };

    match encryptor {
        Ok(encryptor) => open_backup_file(path, encryptor.as_ref()),
        Err(source) => {
            let data = std::fs::read(path).map_err(io_err)?;
            let (header, _) = read_encryption_header(&data).map_err(BackupOpenError::Decrypt)?;
            Err(BackupOpenError::KeyUnavailable {
                key_identifier: header.key_identifier,
                source,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use kubidm_proto::backup::{EncryptionKeySource, KeyDerivationParams};

    use super::*;
    use crate::backup::encryption::MIN_KDF_M_COST;

    fn config(passphrase_file: Option<&Path>) -> BackupEncryptionConfig {
        BackupEncryptionConfig {
            enabled: true,
            key_source: EncryptionKeySource::Passphrase,
            key_derivation: KeyDerivationParams {
                m_cost: MIN_KDF_M_COST,
                t_cost: 1,
                p_cost: 1,
            },
            key_identifier: None,
            passphrase_file: passphrase_file.map(Path::to_path_buf),
        }
    }

    fn encryptor(passphrase: &[u8]) -> BackupEncryptor {
        BackupEncryptor::with_key_material(config(None), passphrase.to_vec()).unwrap()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn read_all(mut reader: Box<dyn Read + Send>) -> Vec<u8> {
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn test_seal_backup_passes_plain_through_and_encrypts_otherwise() {
        let plain = b"{\"entries\": []}".to_vec();
        assert_eq!(
            seal_backup(plain.clone(), BackupCompression::NoCompression, None).unwrap(),
            plain
        );

        let enc = encryptor(b"pw");
        let sealed =
            seal_backup(plain.clone(), BackupCompression::NoCompression, Some(&enc)).unwrap();
        assert!(is_encrypted_artifact(&sealed));
        assert_eq!(enc.decrypt(&sealed).unwrap().0, plain);
    }

    #[test]
    fn test_open_backup_bytes_plain_uses_name_for_compression() {
        let opened = open_backup_bytes(
            b"{}".to_vec(),
            Path::new("backup-2024-01-01T22:00:00Z.json"),
            None,
            false,
        )
        .unwrap();
        assert_eq!(opened.compression, BackupCompression::NoCompression);
        assert!(opened.encryption.is_none());
        assert_eq!(read_all(opened.reader), b"{}");

        let opened = open_backup_bytes(
            gzip(b"{}"),
            Path::new("backup-2024-01-01T22:00:00Z.json.gz"),
            Some(&encryptor(b"pw")),
            false,
        )
        .unwrap();
        assert_eq!(opened.compression, BackupCompression::Gzip);
        assert!(opened.key_identifier().is_none());

        // A plain artifact named as an encrypted one is refused, strict or not.
        for encryptor in [None, Some(encryptor(b"pw"))] {
            match open_backup_bytes(
                b"{}".to_vec(),
                Path::new("backup-2024-01-01T22:00:00Z.json.enc"),
                encryptor.as_ref(),
                false,
            ) {
                Err(BackupOpenError::PlainUnderEncryptedName { name }) => {
                    assert!(name.ends_with(".json.enc"), "{name}")
                }
                other => panic!("expected PlainUnderEncryptedName, got {other:?}"),
            }
        }

        // Strict mode refuses a plain artifact when encryption is configured.
        assert!(matches!(
            open_backup_bytes(
                b"{}".to_vec(),
                Path::new("backup.json"),
                Some(&encryptor(b"pw")),
                true,
            ),
            Err(BackupOpenError::NotEncrypted)
        ));
    }

    #[test]
    fn test_open_backup_bytes_encrypted_uses_header_for_compression() {
        let enc = encryptor(b"pw");
        for (compression, plaintext) in [
            (BackupCompression::NoCompression, b"{}".to_vec()),
            (BackupCompression::Gzip, gzip(b"{}")),
        ] {
            let sealed = enc.encrypt(&plaintext, compression).unwrap();
            // The name deliberately lies about the compression: the header wins.
            let opened =
                open_backup_bytes(sealed, Path::new("renamed.bin"), Some(&enc), true).unwrap();
            assert_eq!(opened.compression, compression);
            assert_eq!(opened.key_identifier(), Some(enc.key_identifier()));
            assert_eq!(read_all(opened.reader), plaintext);
        }
    }

    #[test]
    fn test_open_backup_bytes_encrypted_without_key_names_the_key() {
        let enc = encryptor(b"pw");
        let sealed = enc
            .encrypt(b"{}", BackupCompression::NoCompression)
            .unwrap();
        match open_backup_bytes(sealed, Path::new("backup.json.enc"), None, false) {
            Err(BackupOpenError::EncryptedWithoutKey { key_identifier }) => {
                assert_eq!(key_identifier, enc.key_identifier());
            }
            other => panic!("expected EncryptedWithoutKey, got {other:?}"),
        }

        let wrong = encryptor(b"other");
        let sealed = enc
            .encrypt(b"{}", BackupCompression::NoCompression)
            .unwrap();
        match open_backup_bytes(sealed, Path::new("backup.json.enc"), Some(&wrong), false) {
            Err(BackupOpenError::Decrypt(BackupEncryptionError::DecryptionFailed {
                artifact_key,
                configured_key,
            })) => {
                assert_eq!(artifact_key, enc.key_identifier());
                assert_eq!(configured_key, wrong.key_identifier());
            }
            other => panic!("expected DecryptionFailed, got {other:?}"),
        }

        // A truncated container that is not even a full header.
        let mut garbage = BACKUP_ENCRYPTION_MAGIC.to_vec();
        garbage.extend_from_slice(&[0, 0]);
        assert!(matches!(
            open_backup_bytes(garbage, Path::new("x.enc"), None, false),
            Err(BackupOpenError::Decrypt(
                BackupEncryptionError::InvalidHeader
            ))
        ));
    }

    #[tokio::test]
    async fn test_open_backup_file_streams_plain_and_decrypts_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let enc = encryptor(b"pw");

        let plain = dir.path().join("backup-2024-01-01T22:00:00Z.json.gz");
        std::fs::write(&plain, gzip(b"{\"plain\": true}")).unwrap();
        let opened = open_backup_file(&plain, Some(&enc)).unwrap();
        assert_eq!(opened.compression, BackupCompression::Gzip);
        assert!(opened.encryption.is_none());
        assert_eq!(read_all(opened.reader), gzip(b"{\"plain\": true}"));

        // A plain artifact swapped in under an encrypted name is refused.
        let swapped = dir.path().join("backup-2024-01-01T22:00:00Z.json.gz.enc");
        std::fs::write(&swapped, gzip(b"{\"plain\": true}")).unwrap();
        assert!(matches!(
            open_backup_file(&swapped, Some(&enc)),
            Err(BackupOpenError::PlainUnderEncryptedName { .. })
        ));
        assert!(matches!(
            open_backup_file_with_config(&swapped, None).await,
            Err(BackupOpenError::PlainUnderEncryptedName { .. })
        ));
        std::fs::remove_file(&swapped).unwrap();

        // Files shorter than the magic are plain too.
        let tiny = dir.path().join("tiny.json");
        std::fs::write(&tiny, b"[]").unwrap();
        let opened = open_backup_file(&tiny, None).unwrap();
        assert_eq!(read_all(opened.reader), b"[]");

        let encrypted = dir.path().join("backup-2024-01-01T22:00:00Z.json.gz.enc");
        std::fs::write(
            &encrypted,
            enc.encrypt(&gzip(b"{\"enc\": true}"), BackupCompression::Gzip)
                .unwrap(),
        )
        .unwrap();
        let opened = open_backup_file(&encrypted, Some(&enc)).unwrap();
        assert_eq!(opened.compression, BackupCompression::Gzip);
        assert_eq!(opened.key_identifier(), Some(enc.key_identifier()));
        assert_eq!(read_all(opened.reader), gzip(b"{\"enc\": true}"));

        assert!(matches!(
            open_backup_file(&encrypted, None),
            Err(BackupOpenError::EncryptedWithoutKey { .. })
        ));
        match open_backup_file(&dir.path().join("missing.json"), None) {
            Err(BackupOpenError::Io { path, .. }) => assert!(path.ends_with("missing.json")),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_open_backup_file_with_config_resolves_the_key_lazily() {
        let dir = tempfile::tempdir().unwrap();
        let passphrase_path = dir.path().join("passphrase");
        std::fs::write(&passphrase_path, "pw\n").unwrap();
        let enc = encryptor(b"pw");

        let plain = dir.path().join("backup-2024-01-01T22:00:00Z.json");
        std::fs::write(&plain, b"{}").unwrap();
        let encrypted = dir.path().join("backup-2024-01-01T22:00:00Z.json.enc");
        std::fs::write(
            &encrypted,
            enc.encrypt(b"{}", BackupCompression::NoCompression)
                .unwrap(),
        )
        .unwrap();

        // A plain artifact opens whatever the configuration says, even when the configured
        // key source does not exist: the key is only resolved for encrypted artifacts.
        let unresolvable = config(Some(&dir.path().join("missing")));
        let opened = open_backup_file_with_config(&plain, Some(&unresolvable))
            .await
            .unwrap();
        assert!(opened.encryption.is_none());
        let opened = open_backup_file_with_config(&plain, None).await.unwrap();
        assert_eq!(read_all(opened.reader), b"{}");

        // The encrypted artifact needs the configured key.
        let good = config(Some(&passphrase_path));
        let opened = open_backup_file_with_config(&encrypted, Some(&good))
            .await
            .unwrap();
        assert_eq!(opened.key_identifier(), Some(enc.key_identifier()));
        assert_eq!(read_all(opened.reader), b"{}");

        // No configuration, or a disabled one: the key identifier is named.
        for config in [None, Some(BackupEncryptionConfig::default())] {
            match open_backup_file_with_config(&encrypted, config.as_ref()).await {
                Err(BackupOpenError::EncryptedWithoutKey { key_identifier }) => {
                    assert_eq!(key_identifier, enc.key_identifier());
                }
                other => panic!("expected EncryptedWithoutKey, got {other:?}"),
            }
        }

        // Enabled but the key can not be obtained.
        match open_backup_file_with_config(&encrypted, Some(&unresolvable)).await {
            Err(BackupOpenError::KeyUnavailable {
                key_identifier,
                source,
            }) => {
                assert_eq!(key_identifier, enc.key_identifier());
                assert!(matches!(source, BackupEncryptionError::KeySourceError(_)));
            }
            other => panic!("expected KeyUnavailable, got {other:?}"),
        }

        // Wrong passphrase.
        std::fs::write(&passphrase_path, "wrong\n").unwrap();
        assert!(matches!(
            open_backup_file_with_config(&encrypted, Some(&good)).await,
            Err(BackupOpenError::Decrypt(
                BackupEncryptionError::DecryptionFailed { .. }
            ))
        ));
    }

    #[test]
    fn test_open_error_display() {
        let err = BackupOpenError::EncryptedWithoutKey {
            key_identifier: "k1".to_string(),
        }
        .to_string();
        assert!(
            err.contains("'k1'") && err.contains("[online_backup.encryption]"),
            "{err}"
        );

        let err = BackupOpenError::KeyUnavailable {
            key_identifier: "k1".to_string(),
            source: BackupEncryptionError::KeySourceError("boom".to_string()),
        }
        .to_string();
        assert!(err.contains("'k1'") && err.contains("boom"), "{err}");
    }
}
