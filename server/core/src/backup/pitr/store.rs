//! Reading and writing the archive and the base backups.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kubidm_proto::backup::{
    BackupArtifactIdentity, BackupEncryptionConfig, PitrBaseBackup, PitrManifest, WalSegment,
    PITR_MANIFEST_KEY,
};
use kubidmd_lib::repl::wal::{
    format_ts_rfc3339, is_wal_segment_name, remove_segment, write_file_durably,
};
use sha2::{Digest, Sha256};

use super::{blocking, BaseLocation, PitrError, PitrLocation};
use crate::backup::{
    is_backup_artifact_name, is_encrypted_artifact, read_encryption_header, seal_backup_async,
    BackupEncryptor, S3ClientWrapper,
};

/// A base backup fetched for recovery. The S3 variant is removed when dropped.
pub(super) enum FetchedBase {
    Local(PathBuf),
    S3(crate::backup::cli::FetchedS3Backup),
}

impl FetchedBase {
    pub(super) fn path(&self) -> &Path {
        match self {
            FetchedBase::Local(path) => path,
            FetchedBase::S3(fetched) => &fetched.path,
        }
    }
}

impl BaseLocation {
    /// The keys of the base backups that currently exist at this location. In S3 only a
    /// complete backup counts: one whose object and metadata sidecar both exist, since
    /// recovery can not fetch any other.
    pub(super) async fn list_keys(&self) -> Result<Vec<String>, PitrError> {
        let mut keys = match self {
            BaseLocation::Local(dir) => {
                let dir = dir.clone();
                blocking(move || {
                    let mut keys = Vec::new();
                    if !dir.exists() {
                        return Ok(keys);
                    }
                    for entry in fs::read_dir(&dir)? {
                        let entry = entry?;
                        if let Some(name) = entry.file_name().to_str() {
                            if is_backup_artifact_name(name) {
                                keys.push(name.to_string());
                            }
                        }
                    }
                    Ok(keys)
                })
                .await?
            }
            BaseLocation::S3(config) => {
                S3ClientWrapper::new(config.clone())
                    .await?
                    .list_backup_artifacts()
                    .await?
            }
        };
        keys.sort();
        Ok(keys)
    }

    pub(super) async fn fetch(&self, base: &PitrBaseBackup) -> Result<FetchedBase, PitrError> {
        match self {
            BaseLocation::Local(dir) => {
                let path = dir.join(&base.key);
                if !path.is_file() {
                    return Err(PitrError::NotRecoverable(format!(
                        "base backup {} is missing",
                        path.display()
                    )));
                }
                Ok(FetchedBase::Local(path))
            }
            BaseLocation::S3(config) => {
                let fetched =
                    crate::backup::cli::fetch_s3_backup(config.clone(), &base.key).await?;
                Ok(FetchedBase::S3(fetched))
            }
        }
    }
}

/// Reads and writes the archive at a [`PitrLocation`].
#[derive(Clone)]
pub(super) enum PitrStore {
    Local { dir: PathBuf },
    S3 { client: Box<S3ClientWrapper> },
}

impl PitrStore {
    pub(super) async fn open(location: &PitrLocation) -> Result<Self, PitrError> {
        match location {
            PitrLocation::Local(dir) => Ok(PitrStore::Local { dir: dir.clone() }),
            PitrLocation::S3(config) => Ok(PitrStore::S3 {
                client: Box::new(S3ClientWrapper::new(config.clone()).await?),
            }),
        }
    }

    pub(super) fn is_s3(&self) -> bool {
        matches!(self, PitrStore::S3 { .. })
    }

    pub(super) async fn load_manifest(&self) -> Result<Option<PitrManifest>, PitrError> {
        let data = match self {
            PitrStore::Local { dir } => {
                let path = dir.join(PITR_MANIFEST_KEY);
                let read = blocking(move || {
                    if !path.exists() {
                        return Ok(None);
                    }
                    Ok(Some(fs::read(&path)?))
                })
                .await?;
                match read {
                    Some(data) => data,
                    None => return Ok(None),
                }
            }
            PitrStore::S3 { client } => {
                match client
                    .download_document_if_exists(PITR_MANIFEST_KEY)
                    .await?
                {
                    Some(data) => data,
                    None => return Ok(None),
                }
            }
        };
        let manifest: PitrManifest = serde_json::from_slice(&data).map_err(|err| {
            PitrError::Manifest(format!("{PITR_MANIFEST_KEY} is not readable: {err}"))
        })?;
        check_manifest_names(&manifest)?;
        Ok(Some(manifest))
    }

    /// Save `manifest`, updated at `now`.
    pub(super) async fn save_manifest(
        &self,
        manifest: &mut PitrManifest,
        now: Duration,
    ) -> Result<(), PitrError> {
        let now = format_ts_rfc3339(now);
        manifest.updated_at = now.clone();
        let data = serde_json::to_vec_pretty(manifest)
            .map_err(|err| PitrError::Manifest(format!("unable to serialise: {err}")))?;
        match self {
            PitrStore::Local { dir } => {
                let dir = dir.clone();
                blocking(move || {
                    fs::create_dir_all(&dir)?;
                    Ok(write_file_durably(&dir, PITR_MANIFEST_KEY, &data)?)
                })
                .await?;
            }
            PitrStore::S3 { client } => {
                // One object, so that the manifest is never torn from a sidecar.
                client
                    .upload_document(data.into(), PITR_MANIFEST_KEY, &now)
                    .await?;
            }
        }
        Ok(())
    }

    /// Archive the closed segment whose checked content is `data` at `now`, and return it
    /// as the manifest records it.
    ///
    /// With an `encryptor` the segment is sealed with the backup encryption scheme first
    /// and stored as `<segment>.enc`: uploaded to S3, or written next to the plaintext in
    /// the local directory, whose plaintext copy the caller removes once the manifest
    /// records the encrypted one. Without one, the segment is uploaded as it is to S3, and
    /// the local location has nothing to do: the segment already is where it belongs.
    pub(super) async fn put_segment(
        &self,
        segment: &WalSegment,
        data: Vec<u8>,
        encryptor: Option<&BackupEncryptor>,
        now: Duration,
    ) -> Result<WalSegment, PitrError> {
        if !self.is_s3() && encryptor.is_none() {
            return Ok(segment.clone());
        }

        let mut archived = WalSegment {
            encryption_key: None,
            ..segment.clone()
        };
        let stored = match encryptor {
            Some(encryptor) => {
                archived.encryption_key = Some(encryptor.key_identifier().to_string());
                seal_backup_async(
                    data,
                    segment.compression,
                    Some(encryptor),
                    BackupArtifactIdentity::wal_segment(&segment.segment_id),
                )
                .await
                .map_err(|err| {
                    PitrError::Encryption(format!(
                        "unable to encrypt segment {}: {err}",
                        segment.segment_id
                    ))
                })?
            }
            None => data,
        };

        match self {
            PitrStore::Local { dir } => {
                let dir = dir.clone();
                let name = archived.stored_name();
                blocking(move || Ok(write_file_durably(&dir, &name, &stored)?)).await?;
            }
            PitrStore::S3 { client } => {
                client
                    .upload_backup(
                        &stored,
                        &archived.object_key(),
                        &format_ts_rfc3339(now),
                        segment.compression,
                        archived.encryption_key.as_deref(),
                    )
                    .await?;
            }
        }
        Ok(archived)
    }

    pub(super) async fn delete_segment(
        &self,
        local_dir: &Path,
        segment: &WalSegment,
    ) -> Result<(), PitrError> {
        match self {
            PitrStore::Local { dir } => {
                let local_dir = local_dir.to_path_buf();
                let segment_id = segment.segment_id.clone();
                let stored = (segment.stored_name() != segment.segment_id)
                    .then(|| dir.join(segment.stored_name()));
                blocking(move || {
                    remove_segment(&local_dir, &segment_id)?;
                    if let Some(stored) = stored.filter(|path| path.exists()) {
                        fs::remove_file(stored)?;
                    }
                    Ok(())
                })
                .await?
            }
            PitrStore::S3 { client } => client.delete_backup(&segment.object_key()).await?,
        }
        Ok(())
    }

    /// Read a segment from the archive, or from `local_dir` when `local` says it has not
    /// been archived yet, decrypt it when it is encrypted, and check it against the
    /// checksum the manifest recorded.
    pub(super) async fn fetch_segment(
        &self,
        local_dir: &Path,
        segment: &WalSegment,
        local: bool,
        keys: &mut SegmentKeys<'_>,
    ) -> Result<Vec<u8>, PitrError> {
        let data = match self {
            PitrStore::S3 { client } if !local => {
                client.download_backup(&segment.object_key()).await?.0
            }
            PitrStore::Local { dir } if !local => {
                let path = dir.join(segment.stored_name());
                blocking(move || Ok(fs::read(path)?)).await?
            }
            _ => {
                let path = local_dir.join(&segment.segment_id);
                blocking(move || Ok(fs::read(path)?)).await?
            }
        };
        let plaintext = open_segment(segment, data, keys).await?;
        verify_segment_checksum(segment, &plaintext)?;
        Ok(plaintext)
    }
}

/// The backup encryption key recovery decrypts segments with, obtained from the configured
/// key source the first time an encrypted segment needs it, so that recovering a plain
/// archive never touches the key source.
pub(super) struct SegmentKeys<'a> {
    config: &'a BackupEncryptionConfig,
    encryptor: Option<BackupEncryptor>,
}

impl<'a> SegmentKeys<'a> {
    pub(super) fn new(config: &'a BackupEncryptionConfig) -> Self {
        Self {
            config,
            encryptor: None,
        }
    }

    pub(super) async fn get(
        &mut self,
        segment: &WalSegment,
        key_identifier: &str,
    ) -> Result<BackupEncryptor, PitrError> {
        if let Some(encryptor) = &self.encryptor {
            return Ok(encryptor.clone());
        }
        if !self.config.enabled {
            return Err(PitrError::Encryption(format!(
                "segment {} is encrypted with key '{key_identifier}' but backup encryption is \
                 not enabled in the configuration; enable [online_backup.encryption] with the \
                 key that wrote it",
                segment.segment_id
            )));
        }
        let encryptor = BackupEncryptor::from_config(self.config)
            .await
            .map_err(|err| {
                PitrError::Encryption(format!(
                    "segment {} is encrypted with key '{key_identifier}' and the configured key \
                     could not be obtained: {err}",
                    segment.segment_id
                ))
            })?
            .ok_or_else(|| PitrError::Encryption("backup encryption is not enabled".to_string()))?;
        self.encryptor = Some(encryptor.clone());
        Ok(encryptor)
    }
}

/// The plaintext of the archived copy `data` of `segment`. An encrypted container is
/// decrypted, whatever the manifest says. A segment the manifest records as encrypted must
/// be an encrypted container, so that whoever can write to the archive can not swap an
/// encrypted segment for an unauthenticated plain one, as for backups.
async fn open_segment(
    segment: &WalSegment,
    data: Vec<u8>,
    keys: &mut SegmentKeys<'_>,
) -> Result<Vec<u8>, PitrError> {
    if !is_encrypted_artifact(&data) {
        if let Some(key) = &segment.encryption_key {
            return Err(PitrError::NotRecoverable(format!(
                "segment {} is recorded as encrypted with key '{key}' but its archived copy is \
                 not an encrypted container; it may have been replaced, so it is refused",
                segment.segment_id
            )));
        }
        return Ok(data);
    }
    let (header, _) = read_encryption_header(&data).map_err(|err| {
        PitrError::Encryption(format!(
            "segment {} has an unreadable encryption header: {err}",
            segment.segment_id
        ))
    })?;
    let encryptor = keys.get(segment, &header.key_identifier).await?;
    let segment_id = segment.segment_id.clone();
    blocking(move || {
        encryptor
            .decrypt(&data, &BackupArtifactIdentity::wal_segment(&segment_id))
            .map(|(plaintext, _)| plaintext)
            .map_err(|err| {
                PitrError::Encryption(format!("unable to decrypt segment {segment_id}: {err}"))
            })
    })
    .await
}

/// Refuse a manifest that names a segment or a base backup by something else than the
/// names the server produces: those names are joined to local paths, and must never reach
/// outside the archive directory.
fn check_manifest_names(manifest: &PitrManifest) -> Result<(), PitrError> {
    if let Some(segment) = manifest
        .segments
        .iter()
        .find(|segment| !is_wal_segment_name(&segment.segment_id))
    {
        return Err(PitrError::Manifest(format!(
            "{PITR_MANIFEST_KEY} names an invalid segment '{}'",
            segment.segment_id
        )));
    }
    if let Some(base) = manifest
        .base_backups
        .iter()
        .find(|base| !is_backup_artifact_name(&base.key))
    {
        return Err(PitrError::Manifest(format!(
            "{PITR_MANIFEST_KEY} names an invalid base backup '{}'",
            base.key
        )));
    }
    Ok(())
}

/// Read the local segment `segment` from `local_dir` and check it against its sidecar.
/// None when the file is gone; [`PitrError::CorruptSegment`] when it does not match.
pub(super) async fn read_local_segment(
    local_dir: &Path,
    segment: &WalSegment,
) -> Result<Option<Vec<u8>>, PitrError> {
    let path = local_dir.join(&segment.segment_id);
    let data = match blocking(move || Ok(fs::read(path)?)).await {
        Ok(data) => data,
        Err(PitrError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    match verify_segment_checksum(segment, &data) {
        Ok(()) => Ok(Some(data)),
        Err(PitrError::NotRecoverable(msg)) => Err(PitrError::CorruptSegment(msg)),
        Err(err) => Err(err),
    }
}

pub(super) fn verify_segment_checksum(segment: &WalSegment, data: &[u8]) -> Result<(), PitrError> {
    let actual = hex::encode(Sha256::digest(data));
    if actual != segment.checksum_sha256 {
        return Err(PitrError::NotRecoverable(format!(
            "segment {} is corrupted: expected sha256 {}, got {actual}",
            segment.segment_id, segment.checksum_sha256
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use uuid::Uuid;

    use super::super::test_util::segment;
    use super::*;
    use crate::backup::s3::fake_s3;

    #[tokio::test]
    async fn test_s3_manifest_is_one_object_that_a_stale_sidecar_never_breaks() {
        let objects = Arc::new(Mutex::new(BTreeMap::new()));
        let fake = fake_s3::FakeS3::start(fake_s3::store(Arc::clone(&objects))).await;
        let store = PitrStore::open(&PitrLocation::S3(fake.config("bucket")))
            .await
            .expect("store");
        assert_eq!(store.load_manifest().await.expect("load"), None);

        let mut manifest = PitrManifest::new(Uuid::new_v4());
        store
            .save_manifest(&mut manifest, Duration::from_secs(10))
            .await
            .expect("save");
        let manifest_path = format!("/bucket/{PITR_MANIFEST_KEY}");
        assert_eq!(
            objects.lock().expect("objects").keys().collect::<Vec<_>>(),
            vec![&manifest_path]
        );

        // The sidecar an earlier version wrote next to it, out of step with the manifest
        // after an interrupted save.
        objects.lock().expect("objects").insert(
            format!("{manifest_path}.metadata.json"),
            br#"{"checksum_sha256":"0","timestamp":"t","compression":"NoCompression","size_bytes":1}"#
                .to_vec(),
        );
        manifest.add_base_backup(PitrBaseBackup {
            key: "backup-2024-01-01T00:00:00.000000000Z.json.gz".to_string(),
            timestamp: "t".to_string(),
            watermark_ts: Duration::from_secs(5),
            server_version: "v".to_string(),
            server_uuid: None,
        });
        store
            .save_manifest(&mut manifest, Duration::from_secs(20))
            .await
            .expect("save");
        assert_eq!(store.load_manifest().await.expect("load"), Some(manifest));
    }

    #[tokio::test]
    async fn test_s3_bases_without_a_sidecar_or_an_object_are_not_listed() {
        let objects = Arc::new(Mutex::new(BTreeMap::new()));
        let fake = fake_s3::FakeS3::start(fake_s3::store(Arc::clone(&objects))).await;
        let complete = "backup-2024-01-01T00:00:00.000000000Z.json.gz";
        let no_sidecar = "backup-2024-01-02T00:00:00.000000000Z.json.gz";
        let no_object = "backup-2024-01-03T00:00:00.000000000Z.json.gz";
        for path in [
            complete.to_string(),
            format!("{complete}.metadata.json"),
            no_sidecar.to_string(),
            format!("{no_object}.metadata.json"),
        ] {
            objects
                .lock()
                .expect("objects")
                .insert(format!("/bucket/{path}"), b"x".to_vec());
        }
        let bases = BaseLocation::S3(fake.config("bucket"));
        assert_eq!(bases.list_keys().await.expect("list"), vec![complete]);
    }

    #[test]
    fn test_verify_segment_checksum() {
        let mut s = segment("s", 1, 2);
        s.checksum_sha256 = hex::encode(Sha256::digest(b"data"));
        assert!(verify_segment_checksum(&s, b"data").is_ok());
        assert!(matches!(
            verify_segment_checksum(&s, b"other"),
            Err(PitrError::NotRecoverable(_))
        ));
    }
}
