//! Client-side encryption of backup artifacts.
//!
//! A backup is serialised and compressed exactly as without encryption, and the result is
//! then sealed into a self-describing container:
//!
//! ```text
//! MAGIC | header length (u32, little endian) | header (JSON) | AES-256-GCM ciphertext
//! ```
//!
//! The header ([`BackupEncryptionHeader`]) carries the salt, the Argon2id parameters, the
//! nonce, the key identifier and whether the plaintext is gzip compressed. Together with
//! the secret from the configured [`EncryptionKeySource`] this is everything a restore
//! needs, so a cold restore on a fresh host only requires the server configuration and the
//! passphrase, key file or key endpoint it names.
//!
//! Every key source yields *key material* (a passphrase, the bytes of a key file or the body
//! of an HTTP response). The material is never used as the cipher key directly: the cipher
//! key is derived from it with Argon2id and the per-artifact salt stored in the header, so
//! two backups made with the same material never share a key or a nonce.

use std::fmt;
use std::fs;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use crypto_glue::aes256::key_from_slice;
use crypto_glue::aes256gcm::{Aead, Aes256Gcm, Aes256GcmNonce, KeyInit};
use kubidm_proto::backup::{
    BackupCompression, BackupEncryptionConfig, BackupEncryptionHeader, EncryptionKeySource,
    KeyDerivationParams, BACKUP_ENCRYPTION_KEY_LEN, BACKUP_ENCRYPTION_MAGIC,
    BACKUP_ENCRYPTION_NONCE_LEN, BACKUP_ENCRYPTION_SALT_LEN,
};
use rand::Rng;
use reqwest::Client;
use url::Url;

/// Environment variable holding the passphrase for `key_source = "Passphrase"` when no
/// `passphrase_file` is configured.
pub const PASSPHRASE_ENV: &str = "KUBIDM_BACKUP_PASSPHRASE";

/// Lowest accepted Argon2id memory cost, in KiB (8 MiB).
pub const MIN_KDF_M_COST: u32 = 8 * 1024;
/// Highest accepted Argon2id memory cost, in KiB (4 GiB).
pub const MAX_KDF_M_COST: u32 = 4 * 1024 * 1024;
/// Highest accepted Argon2id iteration count.
pub const MAX_KDF_T_COST: u32 = 64;
/// Highest accepted Argon2id parallelism.
pub const MAX_KDF_P_COST: u32 = 64;

/// Fixed salt of the key fingerprint that identifies key material when no `key_identifier`
/// is configured. The fingerprint goes through the same KDF as the cipher key so that it
/// does not offer a cheaper way to test passphrase guesses than the ciphertext itself.
const KEY_FINGERPRINT_SALT: &[u8; BACKUP_ENCRYPTION_SALT_LEN] = b"kubidm-bk-keyid1";
/// Number of hex characters of a key fingerprint.
const KEY_FINGERPRINT_LEN: usize = 16;

#[derive(Debug)]
pub enum BackupEncryptionError {
    /// The data does not start with the encrypted backup magic.
    InvalidMagic,
    /// The container is truncated or its header does not parse.
    InvalidHeader,
    EncryptionFailed(String),
    /// The authenticated decryption failed: wrong key, or the ciphertext was modified.
    DecryptionFailed {
        /// Key identifier recorded in the artifact.
        artifact_key: String,
        /// Identifier of the key that was tried.
        configured_key: String,
    },
    /// The configured `key_identifier` differs from the one recorded in the artifact.
    KeyIdentifierMismatch {
        artifact_key: String,
        configured_key: String,
    },
    KeyDerivationFailed(String),
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidSaltLength,
    /// The key material could not be obtained from the configured source.
    KeySourceError(String),
    IoError(std::io::Error),
    HttpError(String),
    SerializeError(String),
}

impl fmt::Display for BackupEncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackupEncryptionError::InvalidMagic => {
                write!(f, "data is not an encrypted kubidm backup")
            }
            BackupEncryptionError::InvalidHeader => {
                write!(f, "invalid or truncated backup encryption header")
            }
            BackupEncryptionError::EncryptionFailed(msg) => write!(f, "encryption failed: {msg}"),
            BackupEncryptionError::DecryptionFailed {
                artifact_key,
                configured_key,
            } => write!(
                f,
                "decryption failed: the artifact was encrypted with key '{artifact_key}' and the \
                 configured key '{configured_key}' does not decrypt it (wrong key, or the \
                 artifact was modified)"
            ),
            BackupEncryptionError::KeyIdentifierMismatch {
                artifact_key,
                configured_key,
            } => write!(
                f,
                "the artifact was encrypted with key '{artifact_key}' but the configured \
                 key_identifier is '{configured_key}'"
            ),
            BackupEncryptionError::KeyDerivationFailed(msg) => {
                write!(f, "key derivation failed: {msg}")
            }
            BackupEncryptionError::InvalidKeyLength => write!(f, "invalid key length"),
            BackupEncryptionError::InvalidNonceLength => write!(f, "invalid nonce length"),
            BackupEncryptionError::InvalidSaltLength => write!(f, "invalid salt length"),
            BackupEncryptionError::KeySourceError(msg) => {
                write!(f, "unable to obtain the backup encryption key: {msg}")
            }
            BackupEncryptionError::IoError(e) => write!(f, "IO error: {e}"),
            BackupEncryptionError::HttpError(msg) => write!(f, "HTTP error: {msg}"),
            BackupEncryptionError::SerializeError(msg) => write!(f, "serialize error: {msg}"),
        }
    }
}

impl std::error::Error for BackupEncryptionError {}

impl From<std::io::Error> for BackupEncryptionError {
    fn from(e: std::io::Error) -> Self {
        BackupEncryptionError::IoError(e)
    }
}

/// Whether `data` is an encrypted backup container. Only the magic is inspected, so a
/// prefix of an artifact is enough.
pub fn is_encrypted_artifact(data: &[u8]) -> bool {
    data.starts_with(BACKUP_ENCRYPTION_MAGIC)
}

/// Parse the header of an encrypted backup container without decrypting it. Returns the
/// header and the offset at which the ciphertext starts.
pub fn read_encryption_header(
    data: &[u8],
) -> Result<(BackupEncryptionHeader, usize), BackupEncryptionError> {
    let header_len_start = BACKUP_ENCRYPTION_MAGIC.len();
    let header_start = header_len_start + 4;

    if data.len() < header_start {
        return Err(if is_encrypted_artifact(data) {
            BackupEncryptionError::InvalidHeader
        } else {
            BackupEncryptionError::InvalidMagic
        });
    }

    if !is_encrypted_artifact(data) {
        return Err(BackupEncryptionError::InvalidMagic);
    }

    let header_len_bytes = data
        .get(header_len_start..header_start)
        .ok_or(BackupEncryptionError::InvalidHeader)?;
    let header_len = u32::from_le_bytes(
        header_len_bytes
            .try_into()
            .map_err(|_| BackupEncryptionError::InvalidHeader)?,
    );
    let header_end = header_start
        .checked_add(header_len as usize)
        .ok_or(BackupEncryptionError::InvalidHeader)?;

    let header_json = data
        .get(header_start..header_end)
        .ok_or(BackupEncryptionError::InvalidHeader)?;
    let header: BackupEncryptionHeader = serde_json::from_slice(header_json)
        .map_err(|e| BackupEncryptionError::SerializeError(e.to_string()))?;

    if !header.validate_magic() {
        return Err(BackupEncryptionError::InvalidMagic);
    }

    Ok((header, header_end))
}

/// Check that Argon2id parameters are within the bounds this server accepts, both for the
/// configuration and for the header of an artifact about to be decrypted (so that a crafted
/// header can not make a restore allocate gigabytes).
pub fn validate_key_derivation_params(params: &KeyDerivationParams) -> Result<(), String> {
    if params.m_cost < MIN_KDF_M_COST || params.m_cost > MAX_KDF_M_COST {
        return Err(format!(
            "key_derivation.m_cost must be between {MIN_KDF_M_COST} and {MAX_KDF_M_COST} KiB, got {}",
            params.m_cost
        ));
    }
    if params.t_cost == 0 || params.t_cost > MAX_KDF_T_COST {
        return Err(format!(
            "key_derivation.t_cost must be between 1 and {MAX_KDF_T_COST}, got {}",
            params.t_cost
        ));
    }
    if params.p_cost == 0 || params.p_cost > MAX_KDF_P_COST {
        return Err(format!(
            "key_derivation.p_cost must be between 1 and {MAX_KDF_P_COST}, got {}",
            params.p_cost
        ));
    }
    Params::new(params.m_cost, params.t_cost, params.p_cost, None)
        .map(|_| ())
        .map_err(|err| format!("key_derivation parameters are rejected by Argon2: {err}"))
}

/// Check an encryption configuration without any network access: the key derivation
/// parameters are within bounds, the options fit the key source, and when encryption is
/// enabled the key source is resolvable right now (the passphrase or key file exists and
/// is readable, the endpoint URL parses). Disabled encryption is always accepted.
pub fn validate_encryption_config(config: &BackupEncryptionConfig) -> Result<(), String> {
    if !config.enabled {
        return Ok(());
    }

    validate_key_derivation_params(&config.key_derivation)?;

    if let Some(id) = &config.key_identifier {
        if id.trim().is_empty() || id.chars().any(char::is_control) {
            return Err(
                "key_identifier must not be empty or contain control characters".to_string(),
            );
        }
    }

    if config.passphrase_file.is_some()
        && !matches!(config.key_source, EncryptionKeySource::Passphrase)
    {
        return Err(format!(
            "passphrase_file is only used with key_source = \"Passphrase\", the configured key_source is {}",
            config.key_source
        ));
    }

    match &config.key_source {
        EncryptionKeySource::Passphrase => {
            resolve_passphrase(config.passphrase_file.as_deref()).map(|_| ())
        }
        EncryptionKeySource::File { path } => read_key_file(Path::new(path)).map(|_| ()),
        EncryptionKeySource::HttpEndpoint { url } => {
            let parsed = Url::parse(url)
                .map_err(|err| format!("key_source endpoint '{url}' is not a valid URL: {err}"))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(format!(
                    "key_source endpoint '{url}' must use the http or https scheme"
                ));
            }
            Ok(())
        }
    }
}

/// The passphrase: the content of `passphrase_file` with trailing whitespace removed when
/// a file is configured, otherwise the [`PASSPHRASE_ENV`] environment variable.
fn resolve_passphrase(passphrase_file: Option<&Path>) -> Result<Vec<u8>, String> {
    let passphrase = match passphrase_file {
        Some(path) => {
            let raw = fs::read(path).map_err(|err| {
                format!("unable to read passphrase_file {}: {err}", path.display())
            })?;
            let trimmed_len = raw
                .iter()
                .rposition(|byte| !byte.is_ascii_whitespace())
                .map(|pos| pos + 1)
                .unwrap_or(0);
            let mut passphrase = raw;
            passphrase.truncate(trimmed_len);
            if passphrase.is_empty() {
                return Err(format!("passphrase_file {} is empty", path.display()));
            }
            passphrase
        }
        None => match std::env::var_os(PASSPHRASE_ENV) {
            Some(value) if !value.is_empty() => value.into_encoded_bytes(),
            _ => {
                return Err(format!(
                    "key_source is \"Passphrase\" but neither passphrase_file is configured nor \
                     the {PASSPHRASE_ENV} environment variable is set"
                ))
            }
        },
    };
    Ok(passphrase)
}

/// The bytes of a key file, used exactly as stored.
fn read_key_file(path: &Path) -> Result<Vec<u8>, String> {
    let key = fs::read(path)
        .map_err(|err| format!("unable to read key file {}: {err}", path.display()))?;
    if key.is_empty() {
        return Err(format!("key file {} is empty", path.display()));
    }
    Ok(key)
}

/// Obtain the key material from the configured source. This is the only place that reads
/// secrets: the passphrase file or environment variable, the key file, or the HTTP key
/// endpoint.
pub async fn resolve_key_material(
    config: &BackupEncryptionConfig,
) -> Result<Vec<u8>, BackupEncryptionError> {
    match &config.key_source {
        EncryptionKeySource::Passphrase => resolve_passphrase(config.passphrase_file.as_deref())
            .map_err(BackupEncryptionError::KeySourceError),
        EncryptionKeySource::File { path } => {
            read_key_file(Path::new(path)).map_err(BackupEncryptionError::KeySourceError)
        }
        EncryptionKeySource::HttpEndpoint { url } => {
            let response = Client::new()
                .get(url)
                .send()
                .await
                .and_then(|response| response.error_for_status())
                .map_err(|e| BackupEncryptionError::HttpError(e.to_string()))?;
            let key = response
                .bytes()
                .await
                .map_err(|e| BackupEncryptionError::HttpError(e.to_string()))?;
            if key.is_empty() {
                return Err(BackupEncryptionError::KeySourceError(format!(
                    "key endpoint {url} returned an empty body"
                )));
            }
            Ok(key.to_vec())
        }
    }
}

/// Key material resolved from a configuration, ready to encrypt and decrypt artifacts.
pub struct BackupEncryptor {
    config: BackupEncryptionConfig,
    key_material: Vec<u8>,
    key_identifier: String,
}

impl fmt::Debug for BackupEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupEncryptor")
            .field("key_source", &self.config.key_source.to_string())
            .field("key_identifier", &self.key_identifier)
            .finish_non_exhaustive()
    }
}

impl BackupEncryptor {
    /// Resolve the key of an enabled configuration. Returns `None` when encryption is not
    /// enabled, so callers can carry an `Option<BackupEncryptor>` through the backup paths.
    pub async fn from_config(
        config: &BackupEncryptionConfig,
    ) -> Result<Option<Self>, BackupEncryptionError> {
        if !config.enabled {
            return Ok(None);
        }
        let key_material = resolve_key_material(config).await?;
        Self::with_key_material(config.clone(), key_material).map(Some)
    }

    /// Build an encryptor from already obtained key material. The identifier of the key is
    /// the configured `key_identifier`, or a fingerprint of the material.
    pub fn with_key_material(
        config: BackupEncryptionConfig,
        key_material: Vec<u8>,
    ) -> Result<Self, BackupEncryptionError> {
        if key_material.is_empty() {
            return Err(BackupEncryptionError::KeySourceError(
                "key material is empty".to_string(),
            ));
        }
        validate_key_derivation_params(&config.key_derivation)
            .map_err(BackupEncryptionError::KeyDerivationFailed)?;
        let key_identifier = match &config.key_identifier {
            Some(id) => id.clone(),
            None => key_fingerprint(&key_material)?,
        };
        Ok(Self {
            config,
            key_material,
            key_identifier,
        })
    }

    /// The identifier written into the header of every artifact this encryptor produces.
    pub fn key_identifier(&self) -> &str {
        &self.key_identifier
    }

    /// Seal a serialised (and possibly compressed) backup into an encrypted container.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        compression: BackupCompression,
    ) -> Result<Vec<u8>, BackupEncryptionError> {
        let mut rng = rand::rng();
        let mut salt = vec![0u8; BACKUP_ENCRYPTION_SALT_LEN];
        rng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; BACKUP_ENCRYPTION_NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);

        let key = derive_key(&self.key_material, &salt, &self.config.key_derivation)?;

        let header = BackupEncryptionHeader::new(
            self.key_identifier.clone(),
            salt,
            nonce_bytes.to_vec(),
            self.config.key_derivation.clone(),
            compression == BackupCompression::Gzip,
        );

        let key = key_from_slice(&key).ok_or(BackupEncryptionError::InvalidKeyLength)?;
        let cipher = Aes256Gcm::new(&*key);
        let nonce = <&Aes256GcmNonce>::try_from(nonce_bytes.as_slice())
            .map_err(|_| BackupEncryptionError::InvalidNonceLength)?;

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| BackupEncryptionError::EncryptionFailed(e.to_string()))?;

        let header_json = serde_json::to_vec(&header)
            .map_err(|e| BackupEncryptionError::SerializeError(e.to_string()))?;
        let header_len = u32::try_from(header_json.len())
            .map_err(|_| BackupEncryptionError::SerializeError("header too large".to_string()))?;

        let mut output = Vec::with_capacity(
            BACKUP_ENCRYPTION_MAGIC.len() + 4 + header_json.len() + ciphertext.len(),
        );
        output.extend_from_slice(BACKUP_ENCRYPTION_MAGIC);
        output.extend_from_slice(&header_len.to_le_bytes());
        output.extend_from_slice(&header_json);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Open an encrypted container with this key. When a `key_identifier` is configured it
    /// must match the one in the header; otherwise the key is simply tried and a failure
    /// names both identifiers.
    pub fn decrypt(
        &self,
        data: &[u8],
    ) -> Result<(Vec<u8>, BackupEncryptionHeader), BackupEncryptionError> {
        let (header, ciphertext_start) = read_encryption_header(data)?;

        if let Some(configured) = &self.config.key_identifier {
            if &header.key_identifier != configured {
                return Err(BackupEncryptionError::KeyIdentifierMismatch {
                    artifact_key: header.key_identifier,
                    configured_key: configured.clone(),
                });
            }
        }

        validate_key_derivation_params(&header.key_derivation)
            .map_err(BackupEncryptionError::KeyDerivationFailed)?;
        if header.salt.len() != BACKUP_ENCRYPTION_SALT_LEN {
            return Err(BackupEncryptionError::InvalidSaltLength);
        }
        if header.nonce.len() != BACKUP_ENCRYPTION_NONCE_LEN {
            return Err(BackupEncryptionError::InvalidNonceLength);
        }

        let key = derive_key(&self.key_material, &header.salt, &header.key_derivation)?;
        let ciphertext = data
            .get(ciphertext_start..)
            .ok_or(BackupEncryptionError::InvalidHeader)?;

        let key = key_from_slice(&key).ok_or(BackupEncryptionError::InvalidKeyLength)?;
        let cipher = Aes256Gcm::new(&*key);
        let nonce = <&Aes256GcmNonce>::try_from(header.nonce.as_slice())
            .map_err(|_| BackupEncryptionError::InvalidNonceLength)?;

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            BackupEncryptionError::DecryptionFailed {
                artifact_key: header.key_identifier.clone(),
                configured_key: self.key_identifier.clone(),
            }
        })?;

        Ok((plaintext, header))
    }
}

/// Derive the AES-256 key from key material and a salt with Argon2id.
fn derive_key(
    key_material: &[u8],
    salt: &[u8],
    params: &KeyDerivationParams,
) -> Result<Vec<u8>, BackupEncryptionError> {
    if salt.len() != BACKUP_ENCRYPTION_SALT_LEN {
        return Err(BackupEncryptionError::InvalidSaltLength);
    }

    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, None)
        .map_err(|e| BackupEncryptionError::KeyDerivationFailed(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key = vec![0u8; BACKUP_ENCRYPTION_KEY_LEN];
    argon
        .hash_password_into(key_material, salt, &mut key)
        .map_err(|e| BackupEncryptionError::KeyDerivationFailed(e.to_string()))?;
    Ok(key)
}

/// A stable, public identifier of key material: Argon2id of the material with a fixed salt
/// and the default parameters, truncated to [`KEY_FINGERPRINT_LEN`] hex characters.
fn key_fingerprint(key_material: &[u8]) -> Result<String, BackupEncryptionError> {
    let derived = derive_key(
        key_material,
        KEY_FINGERPRINT_SALT,
        &KeyDerivationParams::default(),
    )?;
    let mut fingerprint = hex::encode(derived);
    fingerprint.truncate(KEY_FINGERPRINT_LEN);
    Ok(fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Fast parameters for the tests: the smallest memory cost the server accepts.
    fn fast_kdf() -> KeyDerivationParams {
        KeyDerivationParams {
            m_cost: MIN_KDF_M_COST,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn config(key_identifier: Option<&str>) -> BackupEncryptionConfig {
        BackupEncryptionConfig {
            enabled: true,
            key_source: EncryptionKeySource::Passphrase,
            key_derivation: fast_kdf(),
            key_identifier: key_identifier.map(str::to_string),
            passphrase_file: None,
        }
    }

    fn encryptor(passphrase: &[u8], key_identifier: Option<&str>) -> BackupEncryptor {
        BackupEncryptor::with_key_material(config(key_identifier), passphrase.to_vec())
            .expect("encryptor")
    }

    #[test]
    fn test_is_encrypted_artifact() {
        assert!(is_encrypted_artifact(BACKUP_ENCRYPTION_MAGIC));
        let mut data = BACKUP_ENCRYPTION_MAGIC.to_vec();
        data.extend_from_slice(b"anything");
        assert!(is_encrypted_artifact(&data));

        assert!(!is_encrypted_artifact(b""));
        assert!(!is_encrypted_artifact(b"{\"version\": \"1\"}"));
        assert!(!is_encrypted_artifact(&[0x1f, 0x8b, 0x08]));
        assert!(!is_encrypted_artifact(&BACKUP_ENCRYPTION_MAGIC[..5]));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_both_compressions() {
        let enc = encryptor(b"correct horse battery staple", None);
        for compression in [BackupCompression::NoCompression, BackupCompression::Gzip] {
            let plaintext = b"{\"entries\": []}";
            let sealed = enc.encrypt(plaintext, compression).expect("encrypt");

            assert!(is_encrypted_artifact(&sealed));
            assert!(
                !sealed.windows(plaintext.len()).any(|w| w == plaintext),
                "plaintext must not appear in the container"
            );

            let (opened, header) = enc.decrypt(&sealed).expect("decrypt");
            assert_eq!(opened, plaintext);
            assert_eq!(header.compressed, compression == BackupCompression::Gzip);
            assert_eq!(header.key_identifier, enc.key_identifier());
            assert_eq!(header.key_derivation, fast_kdf());
            assert_eq!(header.salt.len(), BACKUP_ENCRYPTION_SALT_LEN);
            assert_eq!(header.nonce.len(), BACKUP_ENCRYPTION_NONCE_LEN);
        }
    }

    #[test]
    fn test_encrypt_empty_and_large_plaintext() {
        let enc = encryptor(b"pw", None);
        let (opened, _) = enc
            .decrypt(&enc.encrypt(b"", BackupCompression::NoCompression).unwrap())
            .unwrap();
        assert!(opened.is_empty());

        let large = vec![0xabu8; 2 * 1024 * 1024];
        let sealed = enc.encrypt(&large, BackupCompression::Gzip).unwrap();
        assert_eq!(enc.decrypt(&sealed).unwrap().0, large);
    }

    #[test]
    fn test_encrypt_uses_fresh_salt_and_nonce() {
        let enc = encryptor(b"pw", None);
        let a = enc.encrypt(b"same", BackupCompression::Gzip).unwrap();
        let b = enc.encrypt(b"same", BackupCompression::Gzip).unwrap();
        assert_ne!(a, b);
        let (ha, _) = read_encryption_header(&a).unwrap();
        let (hb, _) = read_encryption_header(&b).unwrap();
        assert_ne!(ha.salt, hb.salt);
        assert_ne!(ha.nonce, hb.nonce);
        assert_eq!(ha.key_identifier, hb.key_identifier);
    }

    #[test]
    fn test_decrypt_with_wrong_key_names_both_identifiers() {
        let writer = encryptor(b"right", None);
        let reader = encryptor(b"wrong", None);
        let sealed = writer.encrypt(b"secret", BackupCompression::Gzip).unwrap();

        match reader.decrypt(&sealed) {
            Err(BackupEncryptionError::DecryptionFailed {
                artifact_key,
                configured_key,
            }) => {
                assert_eq!(artifact_key, writer.key_identifier());
                assert_eq!(configured_key, reader.key_identifier());
                assert_ne!(artifact_key, configured_key);
            }
            other => panic!("expected DecryptionFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_decrypt_rejects_configured_key_identifier_mismatch() {
        let writer = encryptor(b"pw", Some("backup-key-2024"));
        let sealed = writer.encrypt(b"secret", BackupCompression::Gzip).unwrap();

        // Same material, different configured identifier: rejected before any decryption.
        let reader = encryptor(b"pw", Some("backup-key-2025"));
        match reader.decrypt(&sealed) {
            Err(BackupEncryptionError::KeyIdentifierMismatch {
                artifact_key,
                configured_key,
            }) => {
                assert_eq!(artifact_key, "backup-key-2024");
                assert_eq!(configured_key, "backup-key-2025");
            }
            other => panic!("expected KeyIdentifierMismatch, got {other:?}"),
        }

        // Without a configured identifier the key is tried and works.
        let reader = encryptor(b"pw", None);
        assert_eq!(reader.decrypt(&sealed).unwrap().0, b"secret");
        // And the artifact keeps the identifier it was written with.
        assert_eq!(
            reader.decrypt(&sealed).unwrap().1.key_identifier,
            "backup-key-2024"
        );
    }

    #[test]
    fn test_decrypt_detects_tampering() {
        let enc = encryptor(b"pw", None);
        let sealed = enc.encrypt(b"secret", BackupCompression::Gzip).unwrap();
        let (_, ciphertext_start) = read_encryption_header(&sealed).unwrap();

        // Flip a ciphertext byte.
        let mut tampered = sealed.clone();
        tampered[ciphertext_start + 1] ^= 0x01;
        assert!(matches!(
            enc.decrypt(&tampered),
            Err(BackupEncryptionError::DecryptionFailed { .. })
        ));

        // Flip a tag byte.
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x80;
        assert!(matches!(
            enc.decrypt(&tampered),
            Err(BackupEncryptionError::DecryptionFailed { .. })
        ));

        // Truncate the ciphertext.
        let truncated = &sealed[..sealed.len() - 4];
        assert!(matches!(
            enc.decrypt(truncated),
            Err(BackupEncryptionError::DecryptionFailed { .. })
        ));
    }

    #[test]
    fn test_decrypt_rejects_modified_header_salt() {
        let enc = encryptor(b"pw", None);
        let sealed = enc.encrypt(b"secret", BackupCompression::Gzip).unwrap();
        let (mut header, ciphertext_start) = read_encryption_header(&sealed).unwrap();
        header.salt = vec![0u8; BACKUP_ENCRYPTION_SALT_LEN];

        let header_json = serde_json::to_vec(&header).unwrap();
        let mut rebuilt = BACKUP_ENCRYPTION_MAGIC.to_vec();
        rebuilt.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
        rebuilt.extend_from_slice(&header_json);
        rebuilt.extend_from_slice(&sealed[ciphertext_start..]);

        assert!(matches!(
            enc.decrypt(&rebuilt),
            Err(BackupEncryptionError::DecryptionFailed { .. })
        ));
    }

    #[test]
    fn test_decrypt_rejects_header_with_excessive_kdf_cost() {
        let enc = encryptor(b"pw", None);
        let sealed = enc.encrypt(b"secret", BackupCompression::Gzip).unwrap();
        let (mut header, ciphertext_start) = read_encryption_header(&sealed).unwrap();
        header.key_derivation.m_cost = u32::MAX;

        let header_json = serde_json::to_vec(&header).unwrap();
        let mut rebuilt = BACKUP_ENCRYPTION_MAGIC.to_vec();
        rebuilt.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
        rebuilt.extend_from_slice(&header_json);
        rebuilt.extend_from_slice(&sealed[ciphertext_start..]);

        assert!(matches!(
            enc.decrypt(&rebuilt),
            Err(BackupEncryptionError::KeyDerivationFailed(_))
        ));
    }

    #[test]
    fn test_read_encryption_header_errors() {
        assert!(matches!(
            read_encryption_header(b"not encrypted at all, long enough"),
            Err(BackupEncryptionError::InvalidMagic)
        ));
        assert!(matches!(
            read_encryption_header(b"short"),
            Err(BackupEncryptionError::InvalidMagic)
        ));
        assert!(matches!(
            read_encryption_header(BACKUP_ENCRYPTION_MAGIC),
            Err(BackupEncryptionError::InvalidHeader)
        ));

        // Header length claims more bytes than present.
        let mut data = BACKUP_ENCRYPTION_MAGIC.to_vec();
        data.extend_from_slice(&1000u32.to_le_bytes());
        data.extend_from_slice(b"{}");
        assert!(matches!(
            read_encryption_header(&data),
            Err(BackupEncryptionError::InvalidHeader)
        ));

        // Header is not JSON.
        let mut data = BACKUP_ENCRYPTION_MAGIC.to_vec();
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(b"xxxx");
        assert!(matches!(
            read_encryption_header(&data),
            Err(BackupEncryptionError::SerializeError(_))
        ));

        // Header JSON with a wrong magic field.
        let header = BackupEncryptionHeader {
            magic: "OTHER".to_string(),
            key_identifier: "k".to_string(),
            salt: vec![0; 16],
            nonce: vec![0; 12],
            key_derivation: KeyDerivationParams::default(),
            compressed: false,
        };
        let json = serde_json::to_vec(&header).unwrap();
        let mut data = BACKUP_ENCRYPTION_MAGIC.to_vec();
        data.extend_from_slice(&(json.len() as u32).to_le_bytes());
        data.extend_from_slice(&json);
        assert!(matches!(
            read_encryption_header(&data),
            Err(BackupEncryptionError::InvalidMagic)
        ));
    }

    #[test]
    fn test_derive_key_is_deterministic_and_salt_sensitive() {
        let salt_a = [1u8; BACKUP_ENCRYPTION_SALT_LEN];
        let salt_b = [2u8; BACKUP_ENCRYPTION_SALT_LEN];
        let k1 = derive_key(b"pw", &salt_a, &fast_kdf()).unwrap();
        let k2 = derive_key(b"pw", &salt_a, &fast_kdf()).unwrap();
        let k3 = derive_key(b"pw", &salt_b, &fast_kdf()).unwrap();
        let k4 = derive_key(b"other", &salt_a, &fast_kdf()).unwrap();
        assert_eq!(k1.len(), BACKUP_ENCRYPTION_KEY_LEN);
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, k4);

        assert!(matches!(
            derive_key(b"pw", &[0u8; 8], &fast_kdf()),
            Err(BackupEncryptionError::InvalidSaltLength)
        ));
    }

    #[test]
    fn test_key_fingerprint_is_stable_and_distinct() {
        let a1 = key_fingerprint(b"passphrase-a").unwrap();
        let a2 = key_fingerprint(b"passphrase-a").unwrap();
        let b = key_fingerprint(b"passphrase-b").unwrap();
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert_eq!(a1.len(), KEY_FINGERPRINT_LEN);
        assert!(a1.chars().all(|c| c.is_ascii_hexdigit()));

        // The fingerprint does not depend on the configured KDF parameters, so changing
        // them does not change which key an artifact is attributed to.
        let default_params = BackupEncryptor::with_key_material(
            BackupEncryptionConfig {
                key_derivation: KeyDerivationParams::default(),
                ..config(None)
            },
            b"passphrase-a".to_vec(),
        )
        .unwrap();
        assert_eq!(default_params.key_identifier(), a1);
        assert_eq!(encryptor(b"passphrase-a", None).key_identifier(), a1);
        assert_eq!(
            encryptor(b"passphrase-a", Some("named")).key_identifier(),
            "named"
        );
    }

    #[test]
    fn test_with_key_material_rejects_empty_material_and_bad_params() {
        assert!(matches!(
            BackupEncryptor::with_key_material(config(None), Vec::new()),
            Err(BackupEncryptionError::KeySourceError(_))
        ));
        let bad = BackupEncryptionConfig {
            key_derivation: KeyDerivationParams {
                m_cost: 1,
                t_cost: 1,
                p_cost: 1,
            },
            ..config(None)
        };
        assert!(matches!(
            BackupEncryptor::with_key_material(bad, b"pw".to_vec()),
            Err(BackupEncryptionError::KeyDerivationFailed(_))
        ));
    }

    #[test]
    fn test_validate_key_derivation_params_bounds() {
        assert!(validate_key_derivation_params(&KeyDerivationParams::default()).is_ok());
        assert!(validate_key_derivation_params(&fast_kdf()).is_ok());
        assert!(validate_key_derivation_params(&KeyDerivationParams {
            m_cost: MAX_KDF_M_COST,
            t_cost: MAX_KDF_T_COST,
            p_cost: MAX_KDF_P_COST,
        })
        .is_ok());

        let err = validate_key_derivation_params(&KeyDerivationParams {
            m_cost: MIN_KDF_M_COST - 1,
            ..fast_kdf()
        })
        .unwrap_err();
        assert!(err.contains("m_cost"), "{err}");
        let err = validate_key_derivation_params(&KeyDerivationParams {
            m_cost: MAX_KDF_M_COST + 1,
            ..fast_kdf()
        })
        .unwrap_err();
        assert!(err.contains("m_cost"), "{err}");
        let err = validate_key_derivation_params(&KeyDerivationParams {
            t_cost: 0,
            ..fast_kdf()
        })
        .unwrap_err();
        assert!(err.contains("t_cost"), "{err}");
        let err = validate_key_derivation_params(&KeyDerivationParams {
            t_cost: MAX_KDF_T_COST + 1,
            ..fast_kdf()
        })
        .unwrap_err();
        assert!(err.contains("t_cost"), "{err}");
        let err = validate_key_derivation_params(&KeyDerivationParams {
            p_cost: 0,
            ..fast_kdf()
        })
        .unwrap_err();
        assert!(err.contains("p_cost"), "{err}");
        let err = validate_key_derivation_params(&KeyDerivationParams {
            p_cost: MAX_KDF_P_COST + 1,
            ..fast_kdf()
        })
        .unwrap_err();
        assert!(err.contains("p_cost"), "{err}");
    }

    #[test]
    fn test_resolve_passphrase_from_file_trims_trailing_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passphrase");
        std::fs::write(&path, "  my secret passphrase \n\n").unwrap();
        assert_eq!(
            resolve_passphrase(Some(&path)).unwrap(),
            b"  my secret passphrase".to_vec()
        );

        std::fs::write(&path, "\n").unwrap();
        let err = resolve_passphrase(Some(&path)).unwrap_err();
        assert!(err.contains("is empty"), "{err}");

        let err = resolve_passphrase(Some(&dir.path().join("missing"))).unwrap_err();
        assert!(err.contains("unable to read passphrase_file"), "{err}");
    }

    #[test]
    fn test_read_key_file_uses_bytes_as_stored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.bin");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&[0u8, 10, 13, 32, 255, 10]).unwrap();
        drop(file);
        assert_eq!(
            read_key_file(&path).unwrap(),
            vec![0u8, 10, 13, 32, 255, 10]
        );

        std::fs::write(&path, b"").unwrap();
        assert!(read_key_file(&path).unwrap_err().contains("is empty"));
        assert!(read_key_file(&dir.path().join("missing"))
            .unwrap_err()
            .contains("unable to read key file"));
    }

    #[tokio::test]
    async fn test_resolve_key_material_and_from_config_for_files() {
        let dir = tempfile::tempdir().unwrap();
        let passphrase_path = dir.path().join("passphrase");
        std::fs::write(&passphrase_path, "hunter2\n").unwrap();
        let key_path = dir.path().join("key.bin");
        std::fs::write(&key_path, [7u8; 32]).unwrap();

        let passphrase_config = BackupEncryptionConfig {
            passphrase_file: Some(passphrase_path.clone()),
            ..config(None)
        };
        assert_eq!(
            resolve_key_material(&passphrase_config).await.unwrap(),
            b"hunter2".to_vec()
        );

        let file_config = BackupEncryptionConfig {
            key_source: EncryptionKeySource::File {
                path: key_path.to_string_lossy().into_owned(),
            },
            ..config(None)
        };
        assert_eq!(
            resolve_key_material(&file_config).await.unwrap(),
            vec![7u8; 32]
        );

        // from_config resolves the key and derives the fingerprint of the material.
        let enc = BackupEncryptor::from_config(&passphrase_config)
            .await
            .unwrap()
            .expect("enabled configuration yields an encryptor");
        assert_eq!(enc.key_identifier(), key_fingerprint(b"hunter2").unwrap());

        // A disabled configuration yields no encryptor and reads no secret.
        let disabled = BackupEncryptionConfig {
            enabled: false,
            passphrase_file: Some(dir.path().join("does-not-exist")),
            ..config(None)
        };
        assert!(BackupEncryptor::from_config(&disabled)
            .await
            .unwrap()
            .is_none());

        // An enabled configuration whose source is missing fails clearly.
        let missing = BackupEncryptionConfig {
            key_source: EncryptionKeySource::File {
                path: dir.path().join("missing").to_string_lossy().into_owned(),
            },
            ..config(None)
        };
        assert!(matches!(
            BackupEncryptor::from_config(&missing).await,
            Err(BackupEncryptionError::KeySourceError(_))
        ));
    }

    #[test]
    fn test_validate_encryption_config() {
        let dir = tempfile::tempdir().unwrap();
        let passphrase_path = dir.path().join("passphrase");
        std::fs::write(&passphrase_path, "hunter2\n").unwrap();
        let key_path = dir.path().join("key.bin");
        std::fs::write(&key_path, [7u8; 32]).unwrap();

        // Disabled: anything goes.
        assert!(validate_encryption_config(&BackupEncryptionConfig::default()).is_ok());
        assert!(validate_encryption_config(&BackupEncryptionConfig {
            enabled: false,
            key_derivation: KeyDerivationParams {
                m_cost: 1,
                t_cost: 0,
                p_cost: 0
            },
            ..config(None)
        })
        .is_ok());

        // Passphrase from a file.
        assert!(validate_encryption_config(&BackupEncryptionConfig {
            passphrase_file: Some(passphrase_path.clone()),
            ..config(None)
        })
        .is_ok());
        let err = validate_encryption_config(&BackupEncryptionConfig {
            passphrase_file: Some(dir.path().join("missing")),
            ..config(None)
        })
        .unwrap_err();
        assert!(err.contains("unable to read passphrase_file"), "{err}");

        // Key file.
        assert!(validate_encryption_config(&BackupEncryptionConfig {
            key_source: EncryptionKeySource::File {
                path: key_path.to_string_lossy().into_owned(),
            },
            ..config(None)
        })
        .is_ok());
        let err = validate_encryption_config(&BackupEncryptionConfig {
            key_source: EncryptionKeySource::File {
                path: dir.path().join("missing").to_string_lossy().into_owned(),
            },
            ..config(None)
        })
        .unwrap_err();
        assert!(err.contains("unable to read key file"), "{err}");

        // passphrase_file only makes sense with the Passphrase source.
        let err = validate_encryption_config(&BackupEncryptionConfig {
            key_source: EncryptionKeySource::File {
                path: key_path.to_string_lossy().into_owned(),
            },
            passphrase_file: Some(passphrase_path.clone()),
            ..config(None)
        })
        .unwrap_err();
        assert!(err.contains("passphrase_file is only used"), "{err}");

        // HTTP endpoint: the URL must parse and be http(s); it is not fetched here.
        assert!(validate_encryption_config(&BackupEncryptionConfig {
            key_source: EncryptionKeySource::HttpEndpoint {
                url: "https://vault.example.com/v1/backup-key".to_string(),
            },
            ..config(None)
        })
        .is_ok());
        let err = validate_encryption_config(&BackupEncryptionConfig {
            key_source: EncryptionKeySource::HttpEndpoint {
                url: "not a url".to_string(),
            },
            ..config(None)
        })
        .unwrap_err();
        assert!(err.contains("not a valid URL"), "{err}");
        let err = validate_encryption_config(&BackupEncryptionConfig {
            key_source: EncryptionKeySource::HttpEndpoint {
                url: "ftp://vault.example.com/key".to_string(),
            },
            ..config(None)
        })
        .unwrap_err();
        assert!(err.contains("http or https"), "{err}");

        // KDF bounds and key identifier.
        let err = validate_encryption_config(&BackupEncryptionConfig {
            key_derivation: KeyDerivationParams {
                t_cost: 0,
                ..fast_kdf()
            },
            passphrase_file: Some(passphrase_path.clone()),
            ..config(None)
        })
        .unwrap_err();
        assert!(err.contains("t_cost"), "{err}");
        let err = validate_encryption_config(&BackupEncryptionConfig {
            passphrase_file: Some(passphrase_path.clone()),
            ..config(Some("  "))
        })
        .unwrap_err();
        assert!(err.contains("key_identifier"), "{err}");
        assert!(validate_encryption_config(&BackupEncryptionConfig {
            passphrase_file: Some(passphrase_path),
            ..config(Some("prod-2026"))
        })
        .is_ok());
    }

    #[test]
    fn test_error_display_is_actionable() {
        let err = BackupEncryptionError::DecryptionFailed {
            artifact_key: "aaaa".to_string(),
            configured_key: "bbbb".to_string(),
        }
        .to_string();
        assert!(err.contains("'aaaa'") && err.contains("'bbbb'"), "{err}");

        let err = BackupEncryptionError::KeyIdentifierMismatch {
            artifact_key: "aaaa".to_string(),
            configured_key: "bbbb".to_string(),
        }
        .to_string();
        assert!(err.contains("key_identifier is 'bbbb'"), "{err}");

        let err = BackupEncryptionError::KeySourceError("no key".to_string()).to_string();
        assert!(
            err.contains("unable to obtain the backup encryption key"),
            "{err}"
        );

        let io: BackupEncryptionError =
            std::io::Error::new(std::io::ErrorKind::NotFound, "gone").into();
        assert!(matches!(io, BackupEncryptionError::IoError(_)));
        assert!(io.to_string().contains("gone"));

        let debug = format!("{:?}", encryptor(b"top secret", Some("k")));
        assert!(!debug.contains("top secret"), "{debug}");
        assert!(debug.contains("\"k\""), "{debug}");
    }
}
