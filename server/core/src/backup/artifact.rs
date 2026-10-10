//! Opening and sealing backup artifacts independently of where they are stored.
//!
//! Every reader of a backup (restore, verification, the post-write check) goes through
//! [`open_backup_bytes`] or [`open_backup_file`]: the encrypted container is recognised by
//! its magic first, decrypted with the key the configuration names, and only the plaintext
//! is handed to the compression detection and the parser. Every writer goes through
//! [`seal_backup_async`], which leaves a plain backup untouched and encrypts it otherwise.
//!
//! An encrypted backup records the timestamp of the name it is written under (see
//! [`backup_identity`]), and is only opened under a timestamped name when that name carries
//! the same timestamp: an older backup copied over a newer name is refused.

use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use kubidm_proto::backup::{
    is_encrypted_backup_name, BackupArtifactIdentity, BackupCompression, BackupEncryptionConfig,
    BackupEncryptionHeader, BACKUP_ENCRYPTED_SUFFIX, BACKUP_ENCRYPTION_MAGIC,
};

use super::encryption::{
    is_encrypted_artifact, read_encryption_header, BackupEncryptionError, BackupEncryptor,
    MAX_HEADER_LEN,
};
use super::retention::backup_name_timestamp;

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

/// What a backup stored under `name` (a path, file name or object key) is sealed and
/// opened as: the backup taken at the timestamp of an automatically generated name, or any
/// backup for another name, which does not claim when it was taken. Only the last path
/// component counts, so the copies of a backup in other directories, buckets or prefixes
/// under the same name are the same artifact.
pub fn backup_identity(name: &Path) -> BackupArtifactIdentity {
    let taken_at = name
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .and_then(backup_name_timestamp)
        .map(str::to_string);
    BackupArtifactIdentity::Backup { taken_at }
}

/// Turn a serialised, compressed backup or WAL segment into the bytes that are stored:
/// unchanged without an encryptor, the encrypted container recording `artifact` with one.
fn seal_backup(
    plaintext: Vec<u8>,
    compression: BackupCompression,
    encryptor: Option<&BackupEncryptor>,
    artifact: &BackupArtifactIdentity,
) -> Result<Vec<u8>, BackupEncryptionError> {
    match encryptor {
        Some(encryptor) => encryptor.encrypt(&plaintext, compression, artifact),
        None => Ok(plaintext),
    }
}

/// Seal a backup (see [`backup_identity`]) or WAL segment
/// ([`BackupArtifactIdentity::wal_segment`]) for storage: unchanged without an encryptor,
/// encrypted with one. The Argon2id key derivation and the encryption of the whole
/// artifact run on the blocking thread pool so that they never stall the async runtime.
pub async fn seal_backup_async(
    plaintext: Vec<u8>,
    compression: BackupCompression,
    encryptor: Option<&BackupEncryptor>,
    artifact: BackupArtifactIdentity,
) -> Result<Vec<u8>, BackupEncryptionError> {
    let Some(encryptor) = encryptor.cloned() else {
        return Ok(plaintext);
    };
    tokio::task::spawn_blocking(move || {
        seal_backup(plaintext, compression, Some(&encryptor), &artifact)
    })
    .await
    .map_err(|err| {
        BackupEncryptionError::EncryptionFailed(format!("the encryption task failed: {err}"))
    })?
}

/// Open an artifact held in memory. `name` is the file name or object key the artifact
/// is stored under: it gives the compression of a plain artifact, and an encrypted one
/// must have been sealed as [`backup_identity`] of it. An empty name claims no timestamp.
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

    let (plaintext, header) = encryptor
        .decrypt(&data, &backup_identity(name))
        .map_err(BackupOpenError::Decrypt)?;
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

/// The start of a stored artifact, read with the file opened once.
enum ArtifactHead {
    /// A plain artifact, ready to be streamed from the file.
    Plain(OpenedBackup),
    /// An encrypted artifact: its parsed header, the bytes read so far (magic, length and
    /// header) and the file positioned right behind them, at the ciphertext.
    Encrypted {
        file: File,
        head: Vec<u8>,
        header: BackupEncryptionHeader,
    },
}

fn io_error(path: &Path) -> impl Fn(std::io::Error) -> BackupOpenError + '_ {
    move |source| BackupOpenError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Open the artifact at `path` and read as little of it as tells what it is: the magic,
/// and for an encrypted container its header, so that the key it needs is known without
/// reading the whole artifact.
fn read_artifact_head(path: &Path) -> Result<ArtifactHead, BackupOpenError> {
    let io_err = io_error(path);
    let mut file = File::open(path).map_err(&io_err)?;

    // Peek at the magic so that a plain artifact is streamed rather than loaded.
    let mut head = Vec::with_capacity(BACKUP_ENCRYPTION_MAGIC.len());
    (&mut file)
        .take(BACKUP_ENCRYPTION_MAGIC.len() as u64)
        .read_to_end(&mut head)
        .map_err(&io_err)?;

    if !is_encrypted_artifact(&head) {
        check_plain_name(path)?;
        return Ok(ArtifactHead::Plain(OpenedBackup {
            reader: Box::new(Cursor::new(head).chain(file)),
            compression: BackupCompression::identify_file(path),
            encryption: None,
        }));
    }

    // The header length, then the header itself unless the length is out of bounds, in
    // which case the parser refuses it without the bytes.
    (&mut file)
        .take(4)
        .read_to_end(&mut head)
        .map_err(&io_err)?;
    let header_len = head
        .get(BACKUP_ENCRYPTION_MAGIC.len()..)
        .and_then(|len| <[u8; 4]>::try_from(len).ok())
        .map(u32::from_le_bytes)
        .filter(|len| *len as usize <= MAX_HEADER_LEN)
        .unwrap_or(0);
    (&mut file)
        .take(u64::from(header_len))
        .read_to_end(&mut head)
        .map_err(&io_err)?;
    let (header, _) = read_encryption_header(&head).map_err(BackupOpenError::Decrypt)?;
    Ok(ArtifactHead::Encrypted { file, head, header })
}

/// Read the rest of an encrypted artifact behind its `head` and decrypt it.
fn open_encrypted_rest(
    path: &Path,
    mut file: File,
    mut data: Vec<u8>,
    encryptor: &BackupEncryptor,
) -> Result<OpenedBackup, BackupOpenError> {
    file.read_to_end(&mut data).map_err(io_error(path))?;
    open_backup_bytes(data, path, Some(encryptor), false)
}

/// Open the artifact stored at `path`. A plain artifact is streamed from the file, an
/// encrypted one is read whole and decrypted. Never strict, see [`open_backup_bytes`].
pub fn open_backup_file(
    path: &Path,
    encryptor: Option<&BackupEncryptor>,
) -> Result<OpenedBackup, BackupOpenError> {
    match read_artifact_head(path)? {
        ArtifactHead::Plain(opened) => Ok(opened),
        ArtifactHead::Encrypted { file, head, header } => match encryptor {
            Some(encryptor) => open_encrypted_rest(path, file, head, encryptor),
            None => Err(BackupOpenError::EncryptedWithoutKey {
                key_identifier: header.key_identifier,
            }),
        },
    }
}

/// The key an encrypted artifact at `path` needs, resolved from `encryption` only when the
/// artifact is actually encrypted, then [`open_backup_file`]. This is the entry point of
/// the restore and verification commands, which hold a configuration rather than a key.
///
/// The file is opened once. Only its header is read before the key is resolved, so a key
/// that can not be obtained is reported without reading the artifact. The file is read,
/// and an encrypted artifact decrypted, on the blocking thread pool so that neither the
/// I/O nor the Argon2id key derivation and decryption stall the async runtime.
pub async fn open_backup_file_with_config(
    path: &Path,
    encryption: Option<&BackupEncryptionConfig>,
) -> Result<OpenedBackup, BackupOpenError> {
    let owned_path = path.to_path_buf();
    let head = off_runtime(path, move || read_artifact_head(&owned_path)).await?;

    let (file, head, header) = match head {
        ArtifactHead::Plain(opened) => {
            if encryption.is_some_and(|config| config.enabled) {
                // Kept working so that backups from before encryption was enabled restore,
                // but a plain artifact is not authenticated: say so.
                warn!(
                    "{} is not encrypted although backup encryption is enabled; its integrity \
                     is not protected by the encryption key. Only restore it if you know where \
                     it comes from",
                    path.display()
                );
            }
            return Ok(opened);
        }
        ArtifactHead::Encrypted { file, head, header } => (file, head, header),
    };

    let encryptor = match encryption {
        Some(config) if config.enabled => {
            BackupEncryptor::from_config(config)
                .await
                .map_err(|source| BackupOpenError::KeyUnavailable {
                    key_identifier: header.key_identifier.clone(),
                    source,
                })?
        }
        _ => None,
    };
    let Some(encryptor) = encryptor else {
        return Err(BackupOpenError::EncryptedWithoutKey {
            key_identifier: header.key_identifier,
        });
    };

    let owned_path = path.to_path_buf();
    off_runtime(path, move || {
        open_encrypted_rest(&owned_path, file, head, &encryptor)
    })
    .await
}

/// Run blocking work on an artifact at `path` on the blocking thread pool.
async fn off_runtime<T, F>(path: &Path, work: F) -> Result<T, BackupOpenError>
where
    F: FnOnce() -> Result<T, BackupOpenError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|err| BackupOpenError::Io {
            path: path.display().to_string(),
            source: std::io::Error::other(err),
        })?
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use kubidm_proto::backup::EncryptionKeySource;

    use super::*;
    use crate::backup::encryption::{test_encryptor, test_kdf};

    fn config(passphrase_file: Option<&Path>) -> BackupEncryptionConfig {
        BackupEncryptionConfig {
            enabled: true,
            key_source: EncryptionKeySource::Passphrase,
            key_derivation: test_kdf(),
            key_identifier: None,
            passphrase_file: passphrase_file.map(Path::to_path_buf),
        }
    }

    fn encryptor(passphrase: &[u8]) -> BackupEncryptor {
        test_encryptor(passphrase)
    }

    /// The identity of a backup whose name claims no timestamp.
    fn unnamed() -> BackupArtifactIdentity {
        BackupArtifactIdentity::Backup { taken_at: None }
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
            seal_backup(
                plain.clone(),
                BackupCompression::NoCompression,
                None,
                &unnamed()
            )
            .unwrap(),
            plain
        );

        let enc = encryptor(b"pw");
        let sealed = seal_backup(
            plain.clone(),
            BackupCompression::NoCompression,
            Some(&enc),
            &unnamed(),
        )
        .unwrap();
        assert!(is_encrypted_artifact(&sealed));
        assert_eq!(enc.decrypt(&sealed, &unnamed()).unwrap().0, plain);
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
            let sealed = enc.encrypt(&plaintext, compression, &unnamed()).unwrap();
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
            .encrypt(b"{}", BackupCompression::NoCompression, &unnamed())
            .unwrap();
        match open_backup_bytes(sealed, Path::new("backup.json.enc"), None, false) {
            Err(BackupOpenError::EncryptedWithoutKey { key_identifier }) => {
                assert_eq!(key_identifier, enc.key_identifier());
            }
            other => panic!("expected EncryptedWithoutKey, got {other:?}"),
        }

        let wrong = encryptor(b"other");
        let sealed = enc
            .encrypt(b"{}", BackupCompression::NoCompression, &unnamed())
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
            enc.encrypt(
                &gzip(b"{\"enc\": true}"),
                BackupCompression::Gzip,
                &backup_identity(&encrypted),
            )
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
            enc.encrypt(
                b"{}",
                BackupCompression::NoCompression,
                &backup_identity(&encrypted),
            )
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
    fn test_backup_identity_of_names() {
        for (name, taken_at) in [
            (
                "backup-2026-10-01T00:00:00Z.json.gz.enc",
                Some("2026-10-01T00:00:00Z"),
            ),
            (
                "/var/backups/backup-2026-10-01T00:00:00.123Z.json",
                Some("2026-10-01T00:00:00.123Z"),
            ),
            (
                "prefix/backup-2026-10-01T00:00:00Z.json.enc",
                Some("2026-10-01T00:00:00Z"),
            ),
            ("kubidm-before-upgrade.json.gz.enc", None),
            ("backup.json.gz.enc", None),
            ("backup-2026-10-01T00:00:00Z.json.gz.enc.invalid", None),
            ("", None),
        ] {
            assert_eq!(
                backup_identity(Path::new(name)),
                BackupArtifactIdentity::Backup {
                    taken_at: taken_at.map(str::to_string)
                },
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn test_older_backup_copied_under_a_newer_name_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let passphrase_path = dir.path().join("passphrase");
        std::fs::write(&passphrase_path, "pw\n").unwrap();
        let enc = encryptor(b"pw");

        let january = dir.path().join("backup-2026-01-01T00:00:00Z.json.gz.enc");
        let sealed = seal_backup_async(
            gzip(b"{\"january\": true}"),
            BackupCompression::Gzip,
            Some(&enc),
            backup_identity(&january),
        )
        .await
        .unwrap();
        std::fs::write(&january, &sealed).unwrap();
        assert!(open_backup_file(&january, Some(&enc)).is_ok());

        // The January backup copied over the October name decrypts fine, but is not the
        // backup the name claims: restoring it would silently roll the directory back.
        let october = dir.path().join("backup-2026-10-01T00:00:00Z.json.gz.enc");
        std::fs::write(&october, &sealed).unwrap();
        for result in [
            open_backup_file(&october, Some(&enc)),
            open_backup_file_with_config(&october, Some(&config(Some(&passphrase_path)))).await,
            open_backup_bytes(sealed.clone(), &october, Some(&enc), false),
        ] {
            match result {
                Err(BackupOpenError::Decrypt(BackupEncryptionError::ArtifactMismatch {
                    expected,
                    recorded,
                })) => {
                    assert_eq!(expected, backup_identity(&october));
                    assert_eq!(recorded, backup_identity(&january));
                }
                other => panic!("expected ArtifactMismatch, got {other:?}"),
            }
        }

        // A copy under a name that claims no time (a download, an operator's copy) opens
        // and still tells when the backup was taken.
        let copy = dir.path().join("kubidm-latest.json.gz.enc");
        std::fs::write(&copy, &sealed).unwrap();
        let opened = open_backup_file(&copy, Some(&enc)).unwrap();
        assert_eq!(
            opened.encryption.map(|header| header.artifact),
            Some(backup_identity(&january))
        );

        // A WAL segment is never a backup.
        let segment = seal_backup_async(
            gzip(b"{}"),
            BackupCompression::Gzip,
            Some(&enc),
            BackupArtifactIdentity::wal_segment("seg-1"),
        )
        .await
        .unwrap();
        assert!(matches!(
            open_backup_bytes(segment, &copy, Some(&enc), false),
            Err(BackupOpenError::Decrypt(
                BackupEncryptionError::ArtifactMismatch { .. }
            ))
        ));
    }

    #[tokio::test]
    async fn test_encrypted_artifact_needs_only_its_header_to_name_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let enc = encryptor(b"pw");
        let sealed = seal_backup_async(
            b"{}".to_vec(),
            BackupCompression::NoCompression,
            Some(&enc),
            unnamed(),
        )
        .await
        .unwrap();
        let (_, ciphertext_start) = read_encryption_header(&sealed).unwrap();

        // Only the header is stored: whatever follows it is never needed to tell which key
        // the artifact needs.
        let head_only = dir.path().join("head-only.json.enc");
        std::fs::write(&head_only, &sealed[..ciphertext_start]).unwrap();
        let unresolvable = config(Some(&dir.path().join("missing")));
        match open_backup_file_with_config(&head_only, Some(&unresolvable)).await {
            Err(BackupOpenError::KeyUnavailable { key_identifier, .. }) => {
                assert_eq!(key_identifier, enc.key_identifier())
            }
            other => panic!("expected KeyUnavailable, got {other:?}"),
        }
        for result in [
            open_backup_file_with_config(&head_only, None).await,
            open_backup_file(&head_only, None),
        ] {
            assert!(matches!(
                result,
                Err(BackupOpenError::EncryptedWithoutKey { .. })
            ));
        }
        // With the key, the missing ciphertext fails the authentication.
        assert!(matches!(
            open_backup_file(&head_only, Some(&enc)),
            Err(BackupOpenError::Decrypt(
                BackupEncryptionError::DecryptionFailed { .. }
            ))
        ));

        // A header cut short, or a length beyond the bound, is a malformed container.
        for bytes in [
            sealed[..ciphertext_start - 1].to_vec(),
            [BACKUP_ENCRYPTION_MAGIC, &u32::MAX.to_le_bytes()].concat(),
            BACKUP_ENCRYPTION_MAGIC[..].to_vec(),
        ] {
            let broken = dir.path().join("broken.json.enc");
            std::fs::write(&broken, &bytes).unwrap();
            assert!(matches!(
                open_backup_file(&broken, Some(&enc)),
                Err(BackupOpenError::Decrypt(
                    BackupEncryptionError::InvalidHeader
                ))
            ));
        }
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
