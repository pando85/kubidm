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
//! Everything before the ciphertext (magic, header length and header) is the associated
//! data of the AEAD, so a header that was modified in any way, such as a flipped
//! compression flag or a substituted key identifier, fails authentication exactly like a
//! modified ciphertext. The whole artifact is one AEAD message, so truncation and
//! reordering are detected by the tag as well.
//!
//! The header also records what the artifact is ([`BackupArtifactIdentity`]): a backup
//! and the timestamp of its name, or a WAL segment and its id. Every reader states what it
//! expects to open, so a valid artifact copied over another one (an old backup under the
//! name of a newer one, a segment under the id of another) is refused rather than
//! silently restoring the wrong content.
//!
//! Every key source yields *key material* (a passphrase, the bytes of a key file or the body
//! of an HTTP response). The material is never used as the cipher key directly: the cipher
//! key is derived from it with Argon2id and the salt stored in the header. Every backup gets
//! a fresh salt, so two backups made with the same material never share a key. Key material
//! and derived keys are held in [`Zeroizing`] buffers and wiped when dropped.
//!
//! WAL segments are small and many, and one Argon2id derivation per segment made reading a
//! large archive slow. An encryptor therefore seals segments in a *session*
//! ([`BackupEncryptor::encrypt_in_session`]): one random salt, and so one derived key, for
//! up to [`SESSION_MAX_ARTIFACTS`] artifacts, each with its own random nonce and its own
//! identity in the authenticated header. The container format is the same, the salt is
//! simply shared, so every reader opens session and per-artifact containers alike, and an
//! encryptor keeps the keys it derived for decryption by salt and parameters, so that the
//! segments of one session cost one derivation to open. The binding of a segment to its id
//! does not depend on the key: a segment of the same session stored under another id is
//! still refused.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use argon2::{Algorithm, Argon2, Params, Version};
use crypto_glue::aes256::key_from_slice;
use crypto_glue::aes256gcm::{Aead, AeadInOut, Aes256Gcm, Aes256GcmNonce, KeyInit, Payload};
use crypto_glue::traits::Zeroizing;
use kubidm_proto::backup::{
    BackupArtifactIdentity, BackupCompression, BackupEncryptionConfig, BackupEncryptionHeader,
    EncryptionKeySource, KeyDerivationParams, BACKUP_ENCRYPTION_KEY_LEN, BACKUP_ENCRYPTION_MAGIC,
    BACKUP_ENCRYPTION_NONCE_LEN, BACKUP_ENCRYPTION_SALT_LEN,
};
use rand::Rng;
use reqwest::Client;
use url::Url;

/// Environment variable holding the passphrase for `key_source = "Passphrase"` when no
/// `passphrase_file` is configured.
pub const PASSPHRASE_ENV: &str = "KUBIDM_BACKUP_PASSPHRASE";

// Bounds of the Argon2id parameters. They apply to the configuration and, more
// importantly, to the header of every artifact before it is decrypted: the header is only
// authenticated once the key has been derived with the parameters it names, so whoever can
// write to the backup store chooses them. The maxima keep the worst case of one artifact
// to about a gigabyte of memory and a few seconds of CPU on the host that restores, and
// still leave ample room above the defaults (19 MiB, 2 passes, 1 lane).

/// Lowest accepted Argon2id memory cost, in KiB (8 MiB).
pub const MIN_KDF_M_COST: u32 = 8 * 1024;
/// Highest accepted Argon2id memory cost, in KiB (1 GiB).
pub const MAX_KDF_M_COST: u32 = 1024 * 1024;
/// Highest accepted Argon2id iteration count.
pub const MAX_KDF_T_COST: u32 = 16;
/// Highest accepted Argon2id parallelism.
pub const MAX_KDF_P_COST: u32 = 16;
/// Highest accepted product of the memory cost (KiB) and the iteration count, the memory
/// Argon2id fills in total (4 GiB): 1 GiB with 4 passes, or 256 MiB with 16.
pub const MAX_KDF_WORK: u64 = 4 * 1024 * 1024;

/// How many artifacts one encryption session seals under one salt, and so one key, before
/// it draws a new salt. Every artifact has a random 96-bit nonce; with this many messages per
/// AES-256-GCM key the chance that two nonces collide stays below 2^-57.
pub const SESSION_MAX_ARTIFACTS: u64 = 1 << 20;
/// How many derived keys an encryptor keeps for decryption. Opening the segments of a few
/// sessions needs a few keys; artifacts that each carry their own salt (backups, segments
/// sealed before sessions existed) gain nothing from the cache, which is bounded so that
/// reading many of them does not grow it.
const MAX_CACHED_KEYS: usize = 64;

/// Fixed salt of the key fingerprint that identifies the material of a key file or key
/// endpoint when no `key_identifier` is configured. A fixed salt would let an attacker
/// precompute a dictionary of passphrase fingerprints once and look up every backup, so
/// passphrases are never fingerprinted, see [`PASSPHRASE_KEY_IDENTIFIER`].
const KEY_FINGERPRINT_SALT: &[u8; BACKUP_ENCRYPTION_SALT_LEN] = b"kubidm-bk-keyid1";
/// Argon2id parameters of the key fingerprint. They are pinned rather than taken from
/// [`KeyDerivationParams::default`], which may be raised for new artifacts: the fingerprint
/// is the public identifier of a key, and must stay the same for the same key forever.
const KEY_FINGERPRINT_PARAMS: KeyDerivationParams = KeyDerivationParams {
    m_cost: 19 * 1024,
    t_cost: 2,
    p_cost: 1,
};
/// Number of hex characters of a key fingerprint.
const KEY_FINGERPRINT_LEN: usize = 16;
/// Key identifier recorded for a passphrase when no `key_identifier` is configured.
pub const PASSPHRASE_KEY_IDENTIFIER: &str = "passphrase";

/// Time limit for obtaining the key from an HTTP key endpoint.
const KEY_ENDPOINT_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest key endpoint response accepted, in bytes.
const MAX_KEY_ENDPOINT_BODY: usize = 64 * 1024;
/// Largest encryption header accepted, in bytes. A real header is a few hundred bytes.
pub(crate) const MAX_HEADER_LEN: usize = 64 * 1024;

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
    /// The artifact was sealed as something else than what it is opened as, for example an
    /// older backup copied under the name of a newer one.
    ArtifactMismatch {
        /// What the artifact was opened as.
        expected: BackupArtifactIdentity,
        /// What the artifact records it is.
        recorded: BackupArtifactIdentity,
    },
    KeyDerivationFailed(String),
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidSaltLength,
    /// The key material could not be obtained from the configured source.
    KeySourceError(String),
    /// The encryption configuration can not produce valid artifacts.
    InvalidConfiguration(String),
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
            BackupEncryptionError::ArtifactMismatch { expected, recorded } => write!(
                f,
                "the artifact holds {recorded} but was opened as {expected}; it was copied or \
                 renamed over another artifact, so it is refused"
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
            BackupEncryptionError::InvalidConfiguration(msg) => {
                write!(f, "invalid backup encryption configuration: {msg}")
            }
            BackupEncryptionError::HttpError(msg) => write!(f, "HTTP error: {msg}"),
            BackupEncryptionError::SerializeError(msg) => write!(f, "serialize error: {msg}"),
        }
    }
}

impl std::error::Error for BackupEncryptionError {}

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
    if header_len as usize > MAX_HEADER_LEN {
        return Err(BackupEncryptionError::InvalidHeader);
    }
    let header_end = header_start
        .checked_add(header_len as usize)
        .ok_or(BackupEncryptionError::InvalidHeader)?;

    let header_json = data
        .get(header_start..header_end)
        .ok_or(BackupEncryptionError::InvalidHeader)?;
    let header: BackupEncryptionHeader =
        serde_json::from_slice(header_json).map_err(|_| BackupEncryptionError::InvalidHeader)?;

    if !header.validate_magic() {
        return Err(BackupEncryptionError::InvalidMagic);
    }

    // The identifiers end up in log lines and terminal output before the header is
    // authenticated, so they must not be able to carry escape sequences.
    if header.key_identifier.chars().any(char::is_control)
        || header.artifact.has_control_characters()
    {
        return Err(BackupEncryptionError::InvalidHeader);
    }

    Ok((header, header_end))
}

/// Check that Argon2id parameters are within the bounds this server accepts, both for the
/// configuration and for the header of an artifact about to be decrypted, before anything
/// is allocated: a crafted header can not make a restore allocate more than
/// [`MAX_KDF_M_COST`] or fill more than [`MAX_KDF_WORK`] KiB in total.
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
    let work = u64::from(params.m_cost) * u64::from(params.t_cost);
    if work > MAX_KDF_WORK {
        return Err(format!(
            "key_derivation.m_cost * key_derivation.t_cost must be at most {MAX_KDF_WORK} \
             (KiB times passes), got {} * {} = {work}",
            params.m_cost, params.t_cost
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
        validate_key_identifier(id)?;
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
            if let Some(path) = &config.passphrase_file {
                warn_on_insecure_permissions(path, "passphrase_file");
            }
            resolve_passphrase(config.passphrase_file.as_deref()).map(|_| ())
        }
        EncryptionKeySource::File { path } => {
            warn_on_insecure_permissions(Path::new(path), "key file");
            read_key_file(Path::new(path)).map(|_| ())
        }
        EncryptionKeySource::HttpEndpoint { url } => validate_key_endpoint(url).map(|_| ()),
    }
}

/// A configured key identifier is written into every artifact, and a reader refuses a
/// header whose identifier carries control characters, see [`read_encryption_header`].
fn validate_key_identifier(id: &str) -> Result<(), String> {
    if id.trim().is_empty() || id.chars().any(char::is_control) {
        return Err("key_identifier must not be empty or contain control characters".to_string());
    }
    Ok(())
}

/// The key endpoint must be an `https` URL. Plain `http` would send the key material in
/// the clear, so it is only accepted for a loopback address such as a local secrets agent.
/// Returns the parsed URL.
fn validate_key_endpoint(url: &str) -> Result<Url, String> {
    let parsed = Url::parse(url)
        .map_err(|err| format!("key_source endpoint '{url}' is not a valid URL: {err}"))?;
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" => {
            let loopback = match parsed.host() {
                Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
                Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
                Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
                None => false,
            };
            if loopback {
                Ok(parsed)
            } else {
                Err(format!(
                    "key_source endpoint '{url}' must use https; plain http is only accepted \
                     for a loopback address"
                ))
            }
        }
        _ => Err(format!(
            "key_source endpoint '{url}' must use the https scheme"
        )),
    }
}

/// Warn, like for the TLS key, when a file holding backup key material can be read by
/// everyone on the host. A missing file is reported by the read that follows.
fn warn_on_insecure_permissions(path: &Path, what: &str) {
    #[cfg(not(target_os = "windows"))]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = fs::metadata(path) {
            if meta.mode() & 0o007 != 0 {
                warn!(
                    "WARNING: the backup encryption {what} {} has 'everyone' permission bits in \
                     the mode. Anyone on this host can read the key of every backup ...",
                    path.display()
                );
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        let _ = (path, what);
    }
}

/// Remove trailing ASCII whitespace from a passphrase, whatever its source: a file
/// usually ends in a newline, and an environment variable may keep one depending on how it
/// was set (systemd `Environment=`, `.env` loaders). Moving a passphrase from one source to
/// the other must not change the key. Truncating keeps the allocation, so the trailing
/// bytes are wiped on drop too.
fn normalise_passphrase(mut passphrase: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
    let trimmed_len = passphrase
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|pos| pos + 1)
        .unwrap_or(0);
    passphrase.truncate(trimmed_len);
    passphrase
}

/// The passphrase: the content of `passphrase_file` when a file is configured, otherwise
/// the [`PASSPHRASE_ENV`] environment variable, with trailing whitespace removed either way.
fn resolve_passphrase(passphrase_file: Option<&Path>) -> Result<Zeroizing<Vec<u8>>, String> {
    // The variable is only read when no file is configured.
    resolve_passphrase_from(passphrase_file, || std::env::var_os(PASSPHRASE_ENV))
}

/// [`resolve_passphrase`] with the value of the [`PASSPHRASE_ENV`] environment variable
/// supplied by `env_value`, so that the tests need not change the process environment.
fn resolve_passphrase_from(
    passphrase_file: Option<&Path>,
    env_value: impl FnOnce() -> Option<OsString>,
) -> Result<Zeroizing<Vec<u8>>, String> {
    match passphrase_file {
        Some(path) => {
            let passphrase =
                normalise_passphrase(Zeroizing::new(fs::read(path).map_err(|err| {
                    format!("unable to read passphrase_file {}: {err}", path.display())
                })?));
            if passphrase.is_empty() {
                return Err(format!("passphrase_file {} is empty", path.display()));
            }
            Ok(passphrase)
        }
        None => {
            let passphrase = env_value()
                .map(|value| normalise_passphrase(Zeroizing::new(value.into_encoded_bytes())))
                .filter(|passphrase| !passphrase.is_empty());
            passphrase.ok_or_else(|| {
                format!(
                    "key_source is \"Passphrase\" but neither passphrase_file is configured nor \
                     the {PASSPHRASE_ENV} environment variable is set"
                )
            })
        }
    }
}

/// The bytes of a key file, used exactly as stored.
fn read_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let key = Zeroizing::new(
        fs::read(path)
            .map_err(|err| format!("unable to read key file {}: {err}", path.display()))?,
    );
    if key.is_empty() {
        return Err(format!("key file {} is empty", path.display()));
    }
    Ok(key)
}

/// Run a read of a passphrase or key file on the blocking thread pool: the file may live on
/// a slow or hung network or FUSE file system, which must not stall the async runtime.
async fn read_secret_off_runtime<F>(read: F) -> Result<Zeroizing<Vec<u8>>, BackupEncryptionError>
where
    F: FnOnce() -> Result<Zeroizing<Vec<u8>>, String> + Send + 'static,
{
    tokio::task::spawn_blocking(read)
        .await
        .map_err(|err| {
            BackupEncryptionError::KeySourceError(format!("the key source task failed: {err}"))
        })?
        .map_err(BackupEncryptionError::KeySourceError)
}

/// The HTTP client of a key endpoint. The check of [`validate_key_endpoint`] only holds for
/// the URL that is actually contacted, so the key must never travel anywhere else:
///
/// - no proxy: an environment proxy (`HTTP_PROXY`, `ALL_PROXY`) would otherwise receive the
///   request to a loopback `http` endpoint, and with it the key, in the clear;
/// - no redirects: a redirect from an `https` endpoint to a plain `http` URL would send the
///   key in the clear, and one to any other host would hand it to that host;
/// - `https` only when the endpoint is `https`, as a second line of defence.
fn key_endpoint_client(url: &Url) -> reqwest::Result<Client> {
    Client::builder()
        .timeout(KEY_ENDPOINT_TIMEOUT)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(url.scheme() == "https")
        .build()
}

/// Obtain the key material from the configured source. This is the only place that reads
/// secrets: the passphrase file or environment variable, the key file, or the HTTP key
/// endpoint.
pub async fn resolve_key_material(
    config: &BackupEncryptionConfig,
) -> Result<Zeroizing<Vec<u8>>, BackupEncryptionError> {
    match &config.key_source {
        EncryptionKeySource::Passphrase => {
            let passphrase_file = config.passphrase_file.clone();
            read_secret_off_runtime(move || resolve_passphrase(passphrase_file.as_deref())).await
        }
        EncryptionKeySource::File { path } => {
            let path = PathBuf::from(path);
            read_secret_off_runtime(move || read_key_file(&path)).await
        }
        EncryptionKeySource::HttpEndpoint { url } => {
            let parsed =
                validate_key_endpoint(url).map_err(BackupEncryptionError::KeySourceError)?;
            let client = key_endpoint_client(&parsed)
                .map_err(|e| BackupEncryptionError::HttpError(e.to_string()))?;
            let mut response = client
                .get(parsed)
                .send()
                .await
                .map_err(|e| BackupEncryptionError::HttpError(e.to_string()))?;
            // Redirects are not followed, so a 3xx is refused here like any other status
            // that does not deliver the key.
            if !response.status().is_success() {
                return Err(BackupEncryptionError::HttpError(format!(
                    "key endpoint {url} answered {}; only a 2xx response carries the key, \
                     redirects are not followed",
                    response.status()
                )));
            }
            let mut key = Zeroizing::new(Vec::new());
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| BackupEncryptionError::HttpError(e.to_string()))?
            {
                if key.len() + chunk.len() > MAX_KEY_ENDPOINT_BODY {
                    return Err(BackupEncryptionError::KeySourceError(format!(
                        "key endpoint {url} returned more than {MAX_KEY_ENDPOINT_BODY} bytes"
                    )));
                }
                key.extend_from_slice(&chunk);
            }
            if key.is_empty() {
                return Err(BackupEncryptionError::KeySourceError(format!(
                    "key endpoint {url} returned an empty body"
                )));
            }
            Ok(key)
        }
    }
}

/// Key material resolved from a configuration, ready to encrypt and decrypt artifacts.
///
/// [`Self::encrypt`] and [`Self::decrypt`] run Argon2id and process a whole backup, so they
/// are CPU bound: async callers run them on the blocking thread pool, which is what the
/// encryptor is cloneable for. A clone zeroizes its copy of the key material when dropped.
#[derive(Clone)]
pub struct BackupEncryptor {
    config: BackupEncryptionConfig,
    key_material: Zeroizing<Vec<u8>>,
    key_identifier: String,
    /// The keys derived from `key_material`, shared by every clone.
    derived: Arc<Mutex<DerivedKeys>>,
}

/// The salt and parameters a key was derived with.
type DerivationInput = (Vec<u8>, u32, u32, u32);

fn derivation_input(salt: &[u8], params: &KeyDerivationParams) -> DerivationInput {
    (salt.to_vec(), params.m_cost, params.t_cost, params.p_cost)
}

/// The keys an encryptor derived. The keys are wiped when they are dropped, with the last
/// clone of the encryptor.
#[derive(Default)]
struct DerivedKeys {
    /// Keys that opened an artifact, or seal the session, by salt and parameters.
    keys: BTreeMap<DerivationInput, Zeroizing<Vec<u8>>>,
    /// The session [`BackupEncryptor::encrypt_in_session`] seals with.
    session: Option<EncryptionSession>,
}

struct EncryptionSession {
    salt: Vec<u8>,
    key: Zeroizing<Vec<u8>>,
    /// Artifacts sealed with it so far.
    sealed: u64,
}

impl DerivedKeys {
    fn remember(&mut self, input: DerivationInput, key: &Zeroizing<Vec<u8>>) {
        if self.keys.len() >= MAX_CACHED_KEYS && !self.keys.contains_key(&input) {
            self.keys.clear();
        }
        self.keys.insert(input, key.clone());
    }
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
        // Without a configured identifier, a key file or key endpoint is fingerprinted with
        // Argon2id, which must not stall the async runtime.
        let config = config.clone();
        tokio::task::spawn_blocking(move || Self::with_key_material(config, key_material))
            .await
            .map_err(|err| {
                BackupEncryptionError::KeyDerivationFailed(format!(
                    "the key derivation task failed: {err}"
                ))
            })?
            .map(Some)
    }

    /// Build an encryptor from already obtained key material. The identifier of the key is
    /// the configured `key_identifier`. Without one it is [`PASSPHRASE_KEY_IDENTIFIER`] for
    /// a passphrase and a fingerprint of the material for a key file or key endpoint.
    pub fn with_key_material(
        config: BackupEncryptionConfig,
        key_material: impl Into<Zeroizing<Vec<u8>>>,
    ) -> Result<Self, BackupEncryptionError> {
        let key_material = key_material.into();
        if key_material.is_empty() {
            return Err(BackupEncryptionError::KeySourceError(
                "key material is empty".to_string(),
            ));
        }
        validate_key_derivation_params(&config.key_derivation)
            .map_err(BackupEncryptionError::KeyDerivationFailed)?;
        let key_identifier = match (&config.key_identifier, &config.key_source) {
            (Some(id), _) => {
                // However the encryptor was built: an artifact this would write can never
                // be opened again.
                validate_key_identifier(id).map_err(BackupEncryptionError::InvalidConfiguration)?;
                id.clone()
            }
            (None, EncryptionKeySource::Passphrase) => PASSPHRASE_KEY_IDENTIFIER.to_string(),
            (None, _) => key_fingerprint(&key_material)?,
        };
        Ok(Self {
            config,
            key_material,
            key_identifier,
            derived: Arc::default(),
        })
    }

    /// The identifier written into the header of every artifact this encryptor produces.
    pub fn key_identifier(&self) -> &str {
        &self.key_identifier
    }

    /// Whether `other` encrypts with the same key: the same material, identifier and key
    /// derivation parameters. A caller that resolves the key again for every run keeps its
    /// earlier encryptor, and with it the session and the derived keys, while this holds.
    pub fn same_key(&self, other: &BackupEncryptor) -> bool {
        *self.key_material == *other.key_material
            && self.key_identifier == other.key_identifier
            && self.config.key_derivation == other.config.key_derivation
    }

    fn derived(&self) -> MutexGuard<'_, DerivedKeys> {
        // The keys are only ever replaced whole, so a panic while the lock was held leaves
        // them consistent.
        self.derived
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The number of keys kept for decryption.
    #[cfg(test)]
    pub(crate) fn cached_keys(&self) -> usize {
        self.derived().keys.len()
    }

    /// Seal a serialised (and possibly compressed) backup or WAL segment into an encrypted
    /// container that records, authenticated, that it is `artifact`, under a fresh salt
    /// and so a key of its own.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        compression: BackupCompression,
        artifact: &BackupArtifactIdentity,
    ) -> Result<Vec<u8>, BackupEncryptionError> {
        let mut salt = vec![0u8; BACKUP_ENCRYPTION_SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        let key = derive_key(&self.key_material, &salt, &self.config.key_derivation)?;
        self.seal(plaintext, compression, artifact, salt, &key)
    }

    /// [`Self::encrypt`] in the session of this encryptor and its clones: the salt, and so
    /// the key, is shared with the other artifacts of the session, which costs a single
    /// Argon2id derivation to seal and to open them all. A new session starts after
    /// [`SESSION_MAX_ARTIFACTS`] artifacts. Each artifact still has its own random nonce,
    /// and records its own identity in the authenticated header.
    pub fn encrypt_in_session(
        &self,
        plaintext: &[u8],
        compression: BackupCompression,
        artifact: &BackupArtifactIdentity,
    ) -> Result<Vec<u8>, BackupEncryptionError> {
        let current = {
            let mut derived = self.derived();
            match derived.session.as_mut() {
                Some(session) if session.sealed < SESSION_MAX_ARTIFACTS => {
                    session.sealed += 1;
                    Some((session.salt.clone(), session.key.clone()))
                }
                _ => None,
            }
        };
        let (salt, key) = match current {
            Some(current) => current,
            None => {
                // Derived without the lock held: it takes as long as Argon2id takes.
                let mut salt = vec![0u8; BACKUP_ENCRYPTION_SALT_LEN];
                rand::rng().fill_bytes(&mut salt);
                let key = derive_key(&self.key_material, &salt, &self.config.key_derivation)?;
                let mut derived = self.derived();
                derived.remember(derivation_input(&salt, &self.config.key_derivation), &key);
                derived.session = Some(EncryptionSession {
                    salt: salt.clone(),
                    key: key.clone(),
                    sealed: 1,
                });
                (salt, key)
            }
        };
        self.seal(plaintext, compression, artifact, salt, &key)
    }

    /// Seal `plaintext` as `artifact` with `key`, derived from `salt`, and a fresh nonce.
    fn seal(
        &self,
        plaintext: &[u8],
        compression: BackupCompression,
        artifact: &BackupArtifactIdentity,
        salt: Vec<u8>,
        key: &[u8],
    ) -> Result<Vec<u8>, BackupEncryptionError> {
        let mut nonce_bytes = [0u8; BACKUP_ENCRYPTION_NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce_bytes);

        let header = BackupEncryptionHeader::new(
            self.key_identifier.clone(),
            salt,
            nonce_bytes.to_vec(),
            self.config.key_derivation.clone(),
            compression == BackupCompression::Gzip,
            artifact.clone(),
        );

        let header_json = serde_json::to_vec(&header)
            .map_err(|e| BackupEncryptionError::SerializeError(e.to_string()))?;
        let header_len = u32::try_from(header_json.len())
            .ok()
            .filter(|len| *len as usize <= MAX_HEADER_LEN)
            .ok_or_else(|| BackupEncryptionError::SerializeError("header too large".to_string()))?;

        // The prefix (magic, length, header) is written first and is the associated data.
        // The plaintext is then copied behind it and encrypted in place, so that a whole
        // backup is held once more, not twice more (ciphertext and output).
        let mut output = Vec::with_capacity(
            BACKUP_ENCRYPTION_MAGIC.len() + 4 + header_json.len() + plaintext.len() + 16,
        );
        output.extend_from_slice(BACKUP_ENCRYPTION_MAGIC);
        output.extend_from_slice(&header_len.to_le_bytes());
        output.extend_from_slice(&header_json);
        let prefix_len = output.len();
        output.extend_from_slice(plaintext);

        let key = key_from_slice(key).ok_or(BackupEncryptionError::InvalidKeyLength)?;
        let cipher = Aes256Gcm::new(&*key);
        let nonce = <&Aes256GcmNonce>::try_from(nonce_bytes.as_slice())
            .map_err(|_| BackupEncryptionError::InvalidNonceLength)?;

        let (associated_data, buffer) = output.split_at_mut(prefix_len);
        let tag = cipher
            .encrypt_inout_detached(nonce, associated_data, buffer.into())
            .map_err(|e| BackupEncryptionError::EncryptionFailed(e.to_string()))?;

        output.extend_from_slice(&tag);
        Ok(output)
    }

    /// Open an encrypted container with this key, as the artifact `expected` (see
    /// [`BackupArtifactIdentity::accepts`]). When a `key_identifier` is configured it must
    /// match the one in the header; otherwise the key is simply tried and a failure names
    /// both identifiers.
    ///
    /// Both checks of the header happen before the key derivation. A header forged to pass
    /// them still fails the authentication that follows.
    pub fn decrypt(
        &self,
        data: &[u8],
        expected: &BackupArtifactIdentity,
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

        if !expected.accepts(&header.artifact) {
            return Err(BackupEncryptionError::ArtifactMismatch {
                expected: expected.clone(),
                recorded: header.artifact,
            });
        }

        validate_key_derivation_params(&header.key_derivation)
            .map_err(BackupEncryptionError::KeyDerivationFailed)?;
        if header.salt.len() != BACKUP_ENCRYPTION_SALT_LEN {
            return Err(BackupEncryptionError::InvalidSaltLength);
        }
        if header.nonce.len() != BACKUP_ENCRYPTION_NONCE_LEN {
            return Err(BackupEncryptionError::InvalidNonceLength);
        }

        // A key derived for an earlier artifact with the same salt and parameters (one of
        // the same session) is used again rather than derived anew.
        let input = derivation_input(&header.salt, &header.key_derivation);
        let cached = self.derived().keys.get(&input).cloned();
        let derived = match cached {
            Some(key) => key,
            None => derive_key(&self.key_material, &header.salt, &header.key_derivation)?,
        };
        let (associated_data, ciphertext) = data
            .split_at_checked(ciphertext_start)
            .ok_or(BackupEncryptionError::InvalidHeader)?;

        let key = key_from_slice(&derived).ok_or(BackupEncryptionError::InvalidKeyLength)?;
        let cipher = Aes256Gcm::new(&*key);
        let nonce = <&Aes256GcmNonce>::try_from(header.nonce.as_slice())
            .map_err(|_| BackupEncryptionError::InvalidNonceLength)?;

        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };
        let plaintext = cipher.decrypt(nonce, payload).map_err(|_| {
            BackupEncryptionError::DecryptionFailed {
                artifact_key: header.key_identifier.clone(),
                configured_key: self.key_identifier.clone(),
            }
        })?;
        // Only a key that opened an artifact is kept.
        self.derived().remember(input, &derived);

        Ok((plaintext, header))
    }
}

/// Derive the AES-256 key from key material and a salt with Argon2id.
fn derive_key(
    key_material: &[u8],
    salt: &[u8],
    params: &KeyDerivationParams,
) -> Result<Zeroizing<Vec<u8>>, BackupEncryptionError> {
    if salt.len() != BACKUP_ENCRYPTION_SALT_LEN {
        return Err(BackupEncryptionError::InvalidSaltLength);
    }

    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, None)
        .map_err(|e| BackupEncryptionError::KeyDerivationFailed(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key = Zeroizing::new(vec![0u8; BACKUP_ENCRYPTION_KEY_LEN]);
    argon
        .hash_password_into(key_material, salt, &mut key)
        .map_err(|e| BackupEncryptionError::KeyDerivationFailed(e.to_string()))?;
    Ok(key)
}

/// A stable, public identifier of key material: Argon2id of the material with a fixed salt
/// and [`KEY_FINGERPRINT_PARAMS`], truncated to [`KEY_FINGERPRINT_LEN`] hex characters. Only
/// for high entropy material (key files, key endpoints): with a fixed salt it would be a
/// precomputable verifier of a passphrase.
fn key_fingerprint(key_material: &[u8]) -> Result<String, BackupEncryptionError> {
    let derived = derive_key(key_material, KEY_FINGERPRINT_SALT, &KEY_FINGERPRINT_PARAMS)?;
    let mut fingerprint = hex::encode(&*derived);
    fingerprint.truncate(KEY_FINGERPRINT_LEN);
    Ok(fingerprint)
}

/// Fast Argon2id parameters for tests: the smallest memory cost the server accepts.
#[cfg(test)]
pub(crate) fn test_kdf() -> KeyDerivationParams {
    KeyDerivationParams {
        m_cost: MIN_KDF_M_COST,
        t_cost: 1,
        p_cost: 1,
    }
}

/// A passphrase encryptor with [`test_kdf`] and no configured key identifier, for tests.
#[cfg(test)]
pub(crate) fn test_encryptor(passphrase: &[u8]) -> BackupEncryptor {
    #[allow(clippy::expect_used)]
    BackupEncryptor::with_key_material(
        BackupEncryptionConfig {
            enabled: true,
            key_derivation: test_kdf(),
            ..BackupEncryptionConfig::default()
        },
        passphrase.to_vec(),
    )
    .expect("test encryptor")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// The identity most tests seal and open their artifacts as.
    fn backup_id() -> BackupArtifactIdentity {
        BackupArtifactIdentity::Backup {
            taken_at: Some("2026-10-01T00:00:00Z".to_string()),
        }
    }

    fn config(key_identifier: Option<&str>) -> BackupEncryptionConfig {
        BackupEncryptionConfig {
            enabled: true,
            key_source: EncryptionKeySource::Passphrase,
            key_derivation: test_kdf(),
            key_identifier: key_identifier.map(str::to_string),
            passphrase_file: None,
        }
    }

    fn encryptor(passphrase: &[u8], key_identifier: Option<&str>) -> BackupEncryptor {
        BackupEncryptor::with_key_material(config(key_identifier), passphrase.to_vec())
            .expect("encryptor")
    }

    /// An encryptor whose material comes from a key file, so that it is identified by a
    /// fingerprint when no identifier is configured.
    fn key_file_encryptor(material: &[u8]) -> BackupEncryptor {
        BackupEncryptor::with_key_material(
            BackupEncryptionConfig {
                key_source: EncryptionKeySource::File {
                    path: "/unused/backup.key".to_string(),
                },
                ..config(None)
            },
            material.to_vec(),
        )
        .expect("encryptor")
    }

    /// Rebuild a container from a (modified) header and the original ciphertext.
    fn rebuild(header: &BackupEncryptionHeader, ciphertext: &[u8]) -> Vec<u8> {
        let header_json = serde_json::to_vec(header).unwrap();
        let mut rebuilt = BACKUP_ENCRYPTION_MAGIC.to_vec();
        rebuilt.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
        rebuilt.extend_from_slice(&header_json);
        rebuilt.extend_from_slice(ciphertext);
        rebuilt
    }

    /// The segments of one session share one salt, and so one derived key: opening them
    /// all derives it once, where a container with a salt of its own needs a derivation
    /// each. Every segment keeps its own nonce and stays bound to its own id.
    #[test]
    fn test_session_segments_share_one_key_and_stay_bound_to_their_id() {
        let writer = encryptor(b"pw", None);
        let segment_ids: Vec<String> = (0..8).map(|n| format!("wal-segment-{n}")).collect();
        let sealed: Vec<Vec<u8>> = segment_ids
            .iter()
            .map(|id| {
                writer
                    .encrypt_in_session(
                        id.as_bytes(),
                        BackupCompression::Gzip,
                        &BackupArtifactIdentity::wal_segment(id),
                    )
                    .expect("encrypt")
            })
            .collect();
        let headers: Vec<BackupEncryptionHeader> = sealed
            .iter()
            .map(|data| read_encryption_header(data).expect("header").0)
            .collect();
        assert!(headers.iter().all(|header| header.salt == headers[0].salt));
        let nonces: std::collections::BTreeSet<&Vec<u8>> =
            headers.iter().map(|header| &header.nonce).collect();
        assert_eq!(
            nonces.len(),
            sealed.len(),
            "every segment has its own nonce"
        );

        // A reader that never saw the session derives its key once, for the first segment.
        let reader = encryptor(b"pw", None);
        assert_eq!(reader.cached_keys(), 0);
        for (id, data) in segment_ids.iter().zip(&sealed) {
            let (plaintext, _) = reader
                .decrypt(data, &BackupArtifactIdentity::wal_segment(id))
                .expect("decrypt");
            assert_eq!(plaintext, id.as_bytes());
            assert_eq!(reader.cached_keys(), 1);
        }
        // Its clones share the derived key.
        assert_eq!(reader.clone().cached_keys(), 1);

        // The shared key does not make segments interchangeable.
        assert!(matches!(
            reader.decrypt(
                &sealed[0],
                &BackupArtifactIdentity::wal_segment(&segment_ids[1])
            ),
            Err(BackupEncryptionError::ArtifactMismatch { .. })
        ));

        // Containers with a salt of their own (backups, segments sealed one by one) still
        // open, each with its own key.
        let single = writer
            .encrypt(b"one", BackupCompression::Gzip, &backup_id())
            .expect("encrypt");
        assert_ne!(
            read_encryption_header(&single).expect("header").0.salt,
            headers[0].salt
        );
        assert_eq!(
            reader.decrypt(&single, &backup_id()).expect("decrypt").0,
            b"one"
        );
        assert_eq!(reader.cached_keys(), 2);

        // A key that opens nothing is not kept.
        let stranger = encryptor(b"other", None);
        assert!(stranger
            .decrypt(
                &sealed[0],
                &BackupArtifactIdentity::wal_segment(&segment_ids[0])
            )
            .is_err());
        assert_eq!(stranger.cached_keys(), 0);
    }

    #[test]
    fn test_same_key_compares_material_identifier_and_parameters() {
        let a = encryptor(b"pw", Some("k1"));
        assert!(a.same_key(&encryptor(b"pw", Some("k1"))));
        assert!(!a.same_key(&encryptor(b"other", Some("k1"))));
        assert!(!a.same_key(&encryptor(b"pw", Some("k2"))));
        let stronger = BackupEncryptor::with_key_material(
            BackupEncryptionConfig {
                key_derivation: KeyDerivationParams {
                    t_cost: 2,
                    ..test_kdf()
                },
                ..config(Some("k1"))
            },
            b"pw".to_vec(),
        )
        .expect("encryptor");
        assert!(!a.same_key(&stronger));
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
            let sealed = enc
                .encrypt(plaintext, compression, &backup_id())
                .expect("encrypt");

            assert!(is_encrypted_artifact(&sealed));
            assert!(
                !sealed.windows(plaintext.len()).any(|w| w == plaintext),
                "plaintext must not appear in the container"
            );

            let (opened, header) = enc.decrypt(&sealed, &backup_id()).expect("decrypt");
            assert_eq!(opened, plaintext);
            assert_eq!(header.compressed, compression == BackupCompression::Gzip);
            assert_eq!(header.key_identifier, enc.key_identifier());
            assert_eq!(header.key_derivation, test_kdf());
            assert_eq!(header.salt.len(), BACKUP_ENCRYPTION_SALT_LEN);
            assert_eq!(header.nonce.len(), BACKUP_ENCRYPTION_NONCE_LEN);
        }
    }

    #[test]
    fn test_encrypt_empty_and_large_plaintext() {
        let enc = encryptor(b"pw", None);
        let (opened, _) = enc
            .decrypt(
                &enc.encrypt(b"", BackupCompression::NoCompression, &backup_id())
                    .unwrap(),
                &backup_id(),
            )
            .unwrap();
        assert!(opened.is_empty());

        let large = vec![0xabu8; 2 * 1024 * 1024];
        let sealed = enc
            .encrypt(&large, BackupCompression::Gzip, &backup_id())
            .unwrap();
        assert_eq!(enc.decrypt(&sealed, &backup_id()).unwrap().0, large);
    }

    #[test]
    fn test_encrypt_uses_fresh_salt_and_nonce() {
        let enc = encryptor(b"pw", None);
        let a = enc
            .encrypt(b"same", BackupCompression::Gzip, &backup_id())
            .unwrap();
        let b = enc
            .encrypt(b"same", BackupCompression::Gzip, &backup_id())
            .unwrap();
        assert_ne!(a, b);
        let (ha, _) = read_encryption_header(&a).unwrap();
        let (hb, _) = read_encryption_header(&b).unwrap();
        assert_ne!(ha.salt, hb.salt);
        assert_ne!(ha.nonce, hb.nonce);
        assert_eq!(ha.key_identifier, hb.key_identifier);
    }

    #[test]
    fn test_decrypt_with_wrong_key_names_both_identifiers() {
        let writer = key_file_encryptor(b"right");
        let reader = key_file_encryptor(b"wrong");
        let sealed = writer
            .encrypt(b"secret", BackupCompression::Gzip, &backup_id())
            .unwrap();

        match reader.decrypt(&sealed, &backup_id()) {
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
        let sealed = writer
            .encrypt(b"secret", BackupCompression::Gzip, &backup_id())
            .unwrap();

        // Same material, different configured identifier: rejected before any decryption.
        let reader = encryptor(b"pw", Some("backup-key-2025"));
        match reader.decrypt(&sealed, &backup_id()) {
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
        assert_eq!(reader.decrypt(&sealed, &backup_id()).unwrap().0, b"secret");
        // And the artifact keeps the identifier it was written with.
        assert_eq!(
            reader
                .decrypt(&sealed, &backup_id())
                .unwrap()
                .1
                .key_identifier,
            "backup-key-2024"
        );
    }

    #[test]
    fn test_decrypt_detects_tampering() {
        let enc = encryptor(b"pw", None);
        let sealed = enc
            .encrypt(b"secret", BackupCompression::Gzip, &backup_id())
            .unwrap();
        let (_, ciphertext_start) = read_encryption_header(&sealed).unwrap();

        // Flip a ciphertext byte.
        let mut tampered = sealed.clone();
        tampered[ciphertext_start + 1] ^= 0x01;
        assert!(matches!(
            enc.decrypt(&tampered, &backup_id()),
            Err(BackupEncryptionError::DecryptionFailed { .. })
        ));

        // Flip a tag byte.
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x80;
        assert!(matches!(
            enc.decrypt(&tampered, &backup_id()),
            Err(BackupEncryptionError::DecryptionFailed { .. })
        ));

        // Truncate the ciphertext.
        let truncated = &sealed[..sealed.len() - 4];
        assert!(matches!(
            enc.decrypt(truncated, &backup_id()),
            Err(BackupEncryptionError::DecryptionFailed { .. })
        ));
    }

    #[test]
    fn test_decrypt_rejects_modified_header_salt() {
        let enc = encryptor(b"pw", None);
        let sealed = enc
            .encrypt(b"secret", BackupCompression::Gzip, &backup_id())
            .unwrap();
        let (mut header, ciphertext_start) = read_encryption_header(&sealed).unwrap();
        header.salt = vec![0u8; BACKUP_ENCRYPTION_SALT_LEN];
        let rebuilt = rebuild(&header, &sealed[ciphertext_start..]);

        assert!(matches!(
            enc.decrypt(&rebuilt, &backup_id()),
            Err(BackupEncryptionError::DecryptionFailed { .. })
        ));
    }

    #[test]
    fn test_header_is_authenticated() {
        // Without a configured identifier, so that no field is checked before the AEAD.
        let enc = encryptor(b"pw", None);
        for compression in [BackupCompression::NoCompression, BackupCompression::Gzip] {
            let sealed = enc.encrypt(b"secret", compression, &backup_id()).unwrap();
            let (header, ciphertext_start) = read_encryption_header(&sealed).unwrap();
            let ciphertext = &sealed[ciphertext_start..];

            // Re-serialising the unmodified header reproduces the container and opens.
            assert_eq!(rebuild(&header, ciphertext), sealed);
            assert!(enc
                .decrypt(&rebuild(&header, ciphertext), &backup_id())
                .is_ok());

            // A flipped compression flag would make a restore misread the plaintext.
            let mut flipped = header.clone();
            flipped.compressed = !flipped.compressed;
            assert!(matches!(
                enc.decrypt(&rebuild(&flipped, ciphertext), &backup_id()),
                Err(BackupEncryptionError::DecryptionFailed { .. })
            ));

            // A substituted key identifier would misattribute the artifact.
            let mut renamed = header.clone();
            renamed.key_identifier = "someone-else".to_string();
            assert!(matches!(
                enc.decrypt(&rebuild(&renamed, ciphertext), &backup_id()),
                Err(BackupEncryptionError::DecryptionFailed { .. })
            ));

            // Equivalent JSON with different bytes (extra whitespace) is a different header.
            let json = serde_json::to_vec_pretty(&header).unwrap();
            let mut respaced = BACKUP_ENCRYPTION_MAGIC.to_vec();
            respaced.extend_from_slice(&(json.len() as u32).to_le_bytes());
            respaced.extend_from_slice(&json);
            respaced.extend_from_slice(ciphertext);
            assert_eq!(read_encryption_header(&respaced).unwrap().0, header);
            assert!(matches!(
                enc.decrypt(&respaced, &backup_id()),
                Err(BackupEncryptionError::DecryptionFailed { .. })
            ));
        }
    }

    #[test]
    fn test_decrypt_refuses_an_artifact_opened_as_another_one() {
        let enc = encryptor(b"pw", None);
        let january = BackupArtifactIdentity::Backup {
            taken_at: Some("2026-01-01T00:00:00Z".to_string()),
        };
        let unnamed = BackupArtifactIdentity::Backup { taken_at: None };
        let segment = BackupArtifactIdentity::wal_segment("seg-1");

        // An old backup copied over the name of a newer one: valid, but not what the name
        // claims, so it would silently roll the restore back.
        let old = enc
            .encrypt(b"january", BackupCompression::Gzip, &january)
            .unwrap();
        match enc.decrypt(&old, &backup_id()) {
            Err(BackupEncryptionError::ArtifactMismatch { expected, recorded }) => {
                assert_eq!(expected, backup_id());
                assert_eq!(recorded, january);
            }
            other => panic!("expected ArtifactMismatch, got {other:?}"),
        }
        // Opened under its own name, or under a name that claims no time, it opens.
        assert_eq!(enc.decrypt(&old, &january).unwrap().0, b"january");
        let (_, header) = enc.decrypt(&old, &unnamed).unwrap();
        assert_eq!(header.artifact, january);

        // A manual backup without a timestamped name can not take the place of one.
        let manual = enc
            .encrypt(b"manual", BackupCompression::Gzip, &unnamed)
            .unwrap();
        assert!(matches!(
            enc.decrypt(&manual, &backup_id()),
            Err(BackupEncryptionError::ArtifactMismatch { .. })
        ));
        assert!(enc.decrypt(&manual, &unnamed).is_ok());

        // A WAL segment is neither a backup nor another segment, and the other way round.
        let wal = enc
            .encrypt(b"wal", BackupCompression::Gzip, &segment)
            .unwrap();
        assert!(enc.decrypt(&wal, &segment).is_ok());
        for expected in [
            unnamed.clone(),
            backup_id(),
            BackupArtifactIdentity::wal_segment("seg-2"),
        ] {
            assert!(matches!(
                enc.decrypt(&wal, &expected),
                Err(BackupEncryptionError::ArtifactMismatch { .. })
            ));
        }
        assert!(matches!(
            enc.decrypt(&old, &segment),
            Err(BackupEncryptionError::ArtifactMismatch { .. })
        ));

        // The identity is authenticated: rewriting it in the header to pass the check
        // breaks the tag.
        let (mut header, ciphertext_start) = read_encryption_header(&old).unwrap();
        header.artifact = backup_id();
        assert!(matches!(
            enc.decrypt(&rebuild(&header, &old[ciphertext_start..]), &backup_id()),
            Err(BackupEncryptionError::DecryptionFailed { .. })
        ));

        let err = BackupEncryptionError::ArtifactMismatch {
            expected: backup_id(),
            recorded: january,
        }
        .to_string();
        assert!(
            err.contains("2026-01-01T00:00:00Z") && err.contains("2026-10-01T00:00:00Z"),
            "{err}"
        );
    }

    #[test]
    fn test_decrypt_detects_swapped_ciphertexts() {
        // Two artifacts of the same key: the ciphertext of one under the header of the
        // other must not open.
        let enc = encryptor(b"pw", None);
        let a = enc
            .encrypt(b"first", BackupCompression::Gzip, &backup_id())
            .unwrap();
        let b = enc
            .encrypt(b"second", BackupCompression::Gzip, &backup_id())
            .unwrap();
        let (header_a, start_a) = read_encryption_header(&a).unwrap();
        let (_, start_b) = read_encryption_header(&b).unwrap();
        let mut spliced = a[..start_a].to_vec();
        spliced.extend_from_slice(&b[start_b..]);
        assert_eq!(read_encryption_header(&spliced).unwrap().0, header_a);
        assert!(matches!(
            enc.decrypt(&spliced, &backup_id()),
            Err(BackupEncryptionError::DecryptionFailed { .. })
        ));
    }

    #[test]
    fn test_read_encryption_header_rejects_control_characters_and_oversize() {
        let header = BackupEncryptionHeader::new(
            "evil\u{1b}[2J".to_string(),
            vec![0; BACKUP_ENCRYPTION_SALT_LEN],
            vec![0; BACKUP_ENCRYPTION_NONCE_LEN],
            KeyDerivationParams::default(),
            false,
            backup_id(),
        );
        assert!(matches!(
            read_encryption_header(&rebuild(&header, b"")),
            Err(BackupEncryptionError::InvalidHeader)
        ));
        let header = BackupEncryptionHeader {
            key_identifier: "k".to_string(),
            artifact: BackupArtifactIdentity::wal_segment("seg\u{1b}[2J"),
            ..header
        };
        assert!(matches!(
            read_encryption_header(&rebuild(&header, b"")),
            Err(BackupEncryptionError::InvalidHeader)
        ));

        let mut data = BACKUP_ENCRYPTION_MAGIC.to_vec();
        data.extend_from_slice(&((MAX_HEADER_LEN + 1) as u32).to_le_bytes());
        data.resize(data.len() + MAX_HEADER_LEN + 1, b' ');
        assert!(matches!(
            read_encryption_header(&data),
            Err(BackupEncryptionError::InvalidHeader)
        ));
    }

    #[test]
    fn test_decrypt_rejects_header_with_excessive_kdf_cost() {
        let enc = encryptor(b"pw", None);
        let sealed = enc
            .encrypt(b"secret", BackupCompression::Gzip, &backup_id())
            .unwrap();
        let (header, ciphertext_start) = read_encryption_header(&sealed).unwrap();
        let ciphertext = &sealed[ciphertext_start..];

        // Every one of these used to pass the bounds: the last one asks for 4 GiB filled 64
        // times, minutes of work and an allocation that can take down the restore host.
        // They are refused from the header alone, before any key derivation.
        for params in [
            KeyDerivationParams {
                m_cost: u32::MAX,
                ..test_kdf()
            },
            KeyDerivationParams {
                m_cost: 4 * 1024 * 1024,
                ..test_kdf()
            },
            KeyDerivationParams {
                t_cost: 64,
                ..test_kdf()
            },
            KeyDerivationParams {
                p_cost: 64,
                ..test_kdf()
            },
            KeyDerivationParams {
                m_cost: MAX_KDF_M_COST,
                t_cost: MAX_KDF_T_COST,
                p_cost: 1,
            },
            KeyDerivationParams {
                m_cost: 4 * 1024 * 1024,
                t_cost: 64,
                p_cost: 64,
            },
        ] {
            let mut crafted = header.clone();
            crafted.key_derivation = params.clone();
            let started = std::time::Instant::now();
            assert!(
                matches!(
                    enc.decrypt(&rebuild(&crafted, ciphertext), &backup_id()),
                    Err(BackupEncryptionError::KeyDerivationFailed(_))
                ),
                "{params}"
            );
            assert!(started.elapsed() < Duration::from_secs(1), "{params}");
        }
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

        // Header is not JSON, or JSON that is not a header: malformed like any other
        // broken container.
        for json in [&b"xxxx"[..], b"{}"] {
            let mut data = BACKUP_ENCRYPTION_MAGIC.to_vec();
            data.extend_from_slice(&(json.len() as u32).to_le_bytes());
            data.extend_from_slice(json);
            assert!(matches!(
                read_encryption_header(&data),
                Err(BackupEncryptionError::InvalidHeader)
            ));
        }

        // Header JSON with a wrong magic field.
        let header = BackupEncryptionHeader {
            magic: "OTHER".to_string(),
            key_identifier: "k".to_string(),
            salt: vec![0; 16],
            nonce: vec![0; 12],
            key_derivation: KeyDerivationParams::default(),
            compressed: false,
            artifact: backup_id(),
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
        let k1 = derive_key(b"pw", &salt_a, &test_kdf()).unwrap();
        let k2 = derive_key(b"pw", &salt_a, &test_kdf()).unwrap();
        let k3 = derive_key(b"pw", &salt_b, &test_kdf()).unwrap();
        let k4 = derive_key(b"other", &salt_a, &test_kdf()).unwrap();
        assert_eq!(k1.len(), BACKUP_ENCRYPTION_KEY_LEN);
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, k4);

        assert!(matches!(
            derive_key(b"pw", &[0u8; 8], &test_kdf()),
            Err(BackupEncryptionError::InvalidSaltLength)
        ));
    }

    /// The fingerprint of `passphrase-a`, see `test_key_fingerprint_is_stable_and_distinct`.
    const PINNED_FINGERPRINT_A: &str = "4462d5aa655b8cf6";

    #[test]
    fn test_key_fingerprint_is_stable_and_distinct() {
        let a1 = key_fingerprint(b"passphrase-a").unwrap();
        let a2 = key_fingerprint(b"passphrase-a").unwrap();
        let b = key_fingerprint(b"passphrase-b").unwrap();
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert_eq!(a1.len(), KEY_FINGERPRINT_LEN);
        assert!(a1.chars().all(|c| c.is_ascii_hexdigit()));
        // Pinned: a change here changes the identifier of every existing key file and key
        // endpoint, so old artifacts would seem to need a different key than new ones.
        assert_eq!(a1, PINNED_FINGERPRINT_A);

        // The fingerprint of key file material does not depend on the configured KDF
        // parameters, so changing them does not change which key an artifact is
        // attributed to.
        let default_params = BackupEncryptor::with_key_material(
            BackupEncryptionConfig {
                key_source: EncryptionKeySource::File {
                    path: "/unused/backup.key".to_string(),
                },
                key_derivation: KeyDerivationParams::default(),
                ..config(None)
            },
            b"passphrase-a".to_vec(),
        )
        .unwrap();
        assert_eq!(default_params.key_identifier(), a1);
        assert_eq!(key_file_encryptor(b"passphrase-a").key_identifier(), a1);
        let endpoint = BackupEncryptor::with_key_material(
            BackupEncryptionConfig {
                key_source: EncryptionKeySource::HttpEndpoint {
                    url: "https://vault.example.com/key".to_string(),
                },
                ..config(None)
            },
            b"passphrase-a".to_vec(),
        )
        .unwrap();
        assert_eq!(endpoint.key_identifier(), a1);

        // A passphrase is never fingerprinted: with a fixed salt the fingerprint would be
        // a precomputable verifier of the passphrase.
        let passphrase = encryptor(b"passphrase-a", None);
        assert_eq!(passphrase.key_identifier(), PASSPHRASE_KEY_IDENTIFIER);
        let sealed = passphrase
            .encrypt(b"x", BackupCompression::Gzip, &backup_id())
            .unwrap();
        let (header, _) = read_encryption_header(&sealed).unwrap();
        assert_eq!(header.key_identifier, PASSPHRASE_KEY_IDENTIFIER);
        assert!(!sealed.windows(a1.len()).any(|w| w == a1.as_bytes()));

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
        // An identifier the reader would refuse is refused by the writer too.
        for id in ["", "  ", "evil\u{1b}[2J", "line\nbreak"] {
            assert!(
                matches!(
                    BackupEncryptor::with_key_material(config(Some(id)), b"pw".to_vec()),
                    Err(BackupEncryptionError::InvalidConfiguration(_))
                ),
                "{id:?}"
            );
        }
    }

    #[test]
    fn test_validate_key_derivation_params_bounds() {
        assert!(validate_key_derivation_params(&KeyDerivationParams::default()).is_ok());
        assert!(validate_key_derivation_params(&test_kdf()).is_ok());
        assert!(validate_key_derivation_params(&KeyDerivationParams {
            m_cost: MAX_KDF_M_COST,
            t_cost: 4,
            p_cost: MAX_KDF_P_COST,
        })
        .is_ok());
        assert!(validate_key_derivation_params(&KeyDerivationParams {
            m_cost: 256 * 1024,
            t_cost: MAX_KDF_T_COST,
            p_cost: 1,
        })
        .is_ok());
        // Each bound holds alone, but together they exceed the total work.
        let err = validate_key_derivation_params(&KeyDerivationParams {
            m_cost: MAX_KDF_M_COST,
            t_cost: MAX_KDF_T_COST,
            p_cost: 1,
        })
        .unwrap_err();
        assert!(err.contains("m_cost * key_derivation.t_cost"), "{err}");

        let err = validate_key_derivation_params(&KeyDerivationParams {
            m_cost: MIN_KDF_M_COST - 1,
            ..test_kdf()
        })
        .unwrap_err();
        assert!(err.contains("m_cost"), "{err}");
        let err = validate_key_derivation_params(&KeyDerivationParams {
            m_cost: MAX_KDF_M_COST + 1,
            ..test_kdf()
        })
        .unwrap_err();
        assert!(err.contains("m_cost"), "{err}");
        let err = validate_key_derivation_params(&KeyDerivationParams {
            t_cost: 0,
            ..test_kdf()
        })
        .unwrap_err();
        assert!(err.contains("t_cost"), "{err}");
        let err = validate_key_derivation_params(&KeyDerivationParams {
            t_cost: MAX_KDF_T_COST + 1,
            ..test_kdf()
        })
        .unwrap_err();
        assert!(err.contains("t_cost"), "{err}");
        let err = validate_key_derivation_params(&KeyDerivationParams {
            p_cost: 0,
            ..test_kdf()
        })
        .unwrap_err();
        assert!(err.contains("p_cost"), "{err}");
        let err = validate_key_derivation_params(&KeyDerivationParams {
            p_cost: MAX_KDF_P_COST + 1,
            ..test_kdf()
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
            *resolve_passphrase(Some(&path)).unwrap(),
            b"  my secret passphrase".to_vec()
        );

        std::fs::write(&path, "\n").unwrap();
        let err = resolve_passphrase(Some(&path)).unwrap_err();
        assert!(err.contains("is empty"), "{err}");

        let err = resolve_passphrase(Some(&dir.path().join("missing"))).unwrap_err();
        assert!(err.contains("unable to read passphrase_file"), "{err}");
    }

    #[test]
    fn test_resolve_passphrase_from_the_environment() {
        let from_env = |value: Option<&str>| {
            resolve_passphrase_from(None, || value.map(OsString::from)).map(|p| p.to_vec())
        };
        assert_eq!(
            from_env(Some("env passphrase \n")).unwrap(),
            b"env passphrase".to_vec()
        );
        for missing in [None, Some(""), Some(" \n")] {
            let err = from_env(missing).unwrap_err();
            assert!(err.contains(PASSPHRASE_ENV), "{err}");
        }

        // A configured file takes precedence; the variable is then not even read.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passphrase");
        std::fs::write(&path, "file passphrase\n").unwrap();
        let passphrase = resolve_passphrase_from(Some(&path), || {
            panic!("The environment must not be read when a passphrase_file is configured")
        })
        .unwrap();
        assert_eq!(*passphrase, b"file passphrase".to_vec());
    }

    #[test]
    fn test_passphrase_is_normalised_the_same_for_every_source() {
        for (raw, normalised) in [
            (&b"pw"[..], &b"pw"[..]),
            (b"pw\n", b"pw"),
            (b"pw \r\n\t", b"pw"),
            (b"  p w", b"  p w"),
            (b" \n", b""),
        ] {
            assert_eq!(
                *normalise_passphrase(Zeroizing::new(raw.to_vec())),
                normalised.to_vec(),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn test_read_key_file_uses_bytes_as_stored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.bin");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&[0u8, 10, 13, 32, 255, 10]).unwrap();
        drop(file);
        assert_eq!(
            *read_key_file(&path).unwrap(),
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
            *resolve_key_material(&passphrase_config).await.unwrap(),
            b"hunter2".to_vec()
        );

        let file_config = BackupEncryptionConfig {
            key_source: EncryptionKeySource::File {
                path: key_path.to_string_lossy().into_owned(),
            },
            ..config(None)
        };
        assert_eq!(
            *resolve_key_material(&file_config).await.unwrap(),
            vec![7u8; 32]
        );

        // from_config resolves the key; a passphrase gets the generic identifier and a key
        // file the fingerprint of its material.
        let enc = BackupEncryptor::from_config(&passphrase_config)
            .await
            .unwrap()
            .expect("enabled configuration yields an encryptor");
        assert_eq!(enc.key_identifier(), PASSPHRASE_KEY_IDENTIFIER);
        let enc = BackupEncryptor::from_config(&file_config)
            .await
            .unwrap()
            .expect("enabled configuration yields an encryptor");
        assert_eq!(enc.key_identifier(), key_fingerprint(&[7u8; 32]).unwrap());

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

    /// The key file is read off the async runtime: on a current thread runtime, a key file
    /// that only becomes readable once another task of the same runtime has run (a FIFO
    /// whose writer is started by that task) must still resolve. Read on the runtime thread,
    /// it would block that task forever; a watchdog then feeds other bytes to end the test.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn test_resolve_key_material_reads_files_off_the_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("key.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(status.success());

        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let watchdog_fifo = fifo.clone();
        std::thread::spawn(move || {
            if done_rx.recv_timeout(Duration::from_secs(10)).is_err() {
                // The runtime is blocked in the read: unblock it with the wrong bytes, then
                // drain the writer that the freed runtime starts next.
                let _ = std::fs::write(&watchdog_fifo, b"watchdog");
                let _ = std::fs::read(&watchdog_fifo);
            }
        });

        let writer_fifo = fifo.clone();
        let writer = tokio::spawn(async move {
            tokio::task::yield_now().await;
            tokio::task::spawn_blocking(move || std::fs::write(writer_fifo, b"from-runtime"))
                .await
                .unwrap()
                .unwrap();
        });

        let key_file = BackupEncryptionConfig {
            key_source: EncryptionKeySource::File {
                path: fifo.to_string_lossy().into_owned(),
            },
            ..config(None)
        };
        let material = resolve_key_material(&key_file).await.unwrap();
        let _ = done_tx.send(());
        writer.await.unwrap();
        assert_eq!(*material, b"from-runtime".to_vec());
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
        assert!(err.contains("https"), "{err}");
        // Plain http would send the key in the clear: only accepted on loopback.
        let err = validate_encryption_config(&BackupEncryptionConfig {
            key_source: EncryptionKeySource::HttpEndpoint {
                url: "http://vault.example.com/key".to_string(),
            },
            ..config(None)
        })
        .unwrap_err();
        assert!(err.contains("loopback"), "{err}");
        for url in [
            "http://127.0.0.1:8200/key",
            "http://[::1]:8200/key",
            "http://localhost/key",
        ] {
            assert!(
                validate_encryption_config(&BackupEncryptionConfig {
                    key_source: EncryptionKeySource::HttpEndpoint {
                        url: url.to_string(),
                    },
                    ..config(None)
                })
                .is_ok(),
                "{url}"
            );
        }

        // KDF bounds and key identifier.
        let err = validate_encryption_config(&BackupEncryptionConfig {
            key_derivation: KeyDerivationParams {
                t_cost: 0,
                ..test_kdf()
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

    /// Serve `responses` one connection each on a loopback port, as a key endpoint would.
    async fn serve_key_endpoint(responses: Vec<Vec<u8>>) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                // Read the request head before answering.
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                assert!(request.starts_with(b"GET /backup-key "));
                stream.write_all(&response).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        addr
    }

    fn http_response(status: &str, body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    #[tokio::test]
    async fn test_http_key_endpoint_against_a_live_server() {
        let key = [0x5au8; 32];
        let addr = serve_key_endpoint(vec![
            http_response("200 OK", &key),
            http_response("200 OK", &key),
            http_response("404 Not Found", b"no such key"),
            http_response("200 OK", b""),
            http_response("200 OK", &vec![1u8; MAX_KEY_ENDPOINT_BODY + 1]),
        ])
        .await;
        let endpoint = BackupEncryptionConfig {
            key_source: EncryptionKeySource::HttpEndpoint {
                url: format!("http://{addr}/backup-key"),
            },
            ..config(None)
        };
        assert!(validate_encryption_config(&endpoint).is_ok());

        // The body is the key material, and an artifact sealed with it opens with a
        // second fetch of the same key.
        assert_eq!(
            *resolve_key_material(&endpoint).await.unwrap(),
            key.to_vec()
        );
        let writer = BackupEncryptor::from_config(&endpoint)
            .await
            .unwrap()
            .expect("enabled");
        assert_eq!(writer.key_identifier(), key_fingerprint(&key).unwrap());
        let sealed = writer
            .encrypt(b"secret", BackupCompression::Gzip, &backup_id())
            .unwrap();
        let reader = key_file_encryptor(&key);
        assert_eq!(reader.decrypt(&sealed, &backup_id()).unwrap().0, b"secret");

        // An error status, an empty body and an oversized body are refused.
        assert!(matches!(
            resolve_key_material(&endpoint).await,
            Err(BackupEncryptionError::HttpError(_))
        ));
        let err = resolve_key_material(&endpoint).await.unwrap_err();
        assert!(err.to_string().contains("empty body"), "{err}");
        let err = resolve_key_material(&endpoint).await.unwrap_err();
        assert!(err.to_string().contains("more than"), "{err}");

        // Nothing listens any more: the error is reported, not a hang.
        assert!(matches!(
            resolve_key_material(&endpoint).await,
            Err(BackupEncryptionError::HttpError(_))
        ));

        // A plain http endpoint off loopback is refused before any request is made.
        let remote = BackupEncryptionConfig {
            key_source: EncryptionKeySource::HttpEndpoint {
                url: "http://192.0.2.1/backup-key".to_string(),
            },
            ..config(None)
        };
        assert!(matches!(
            resolve_key_material(&remote).await,
            Err(BackupEncryptionError::KeySourceError(_))
        ));
    }

    #[tokio::test]
    async fn test_http_key_endpoint_does_not_follow_redirects() {
        // The redirect target would hand out a key: following it would send the request,
        // and with plain http the key, somewhere the configuration never named.
        let target = serve_key_endpoint(vec![http_response("200 OK", &[0x5au8; 32])]).await;
        let redirect = format!(
            "HTTP/1.1 302 Found\r\nlocation: http://{target}/backup-key\r\n\
             content-length: 0\r\nconnection: close\r\n\r\n"
        )
        .into_bytes();
        let addr = serve_key_endpoint(vec![redirect]).await;
        let endpoint = BackupEncryptionConfig {
            key_source: EncryptionKeySource::HttpEndpoint {
                url: format!("http://{addr}/backup-key"),
            },
            ..config(None)
        };
        match resolve_key_material(&endpoint).await {
            Err(BackupEncryptionError::HttpError(msg)) => {
                assert!(msg.contains("302") && msg.contains("redirects"), "{msg}")
            }
            other => panic!("expected HttpError, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn test_key_endpoint_client_builds_for_both_schemes() {
        for url in ["https://vault.example.com/key", "http://127.0.0.1:8200/key"] {
            assert!(
                key_endpoint_client(&Url::parse(url).unwrap()).is_ok(),
                "{url}"
            );
        }
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

        let debug = format!("{:?}", encryptor(b"top secret", Some("k")));
        assert!(!debug.contains("top secret"), "{debug}");
        assert!(debug.contains("\"k\""), "{debug}");
    }
}
