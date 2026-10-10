//! Reading and writing the archive and the base backups.

use std::fs;
use std::path::{Path, PathBuf};

use kubidm_proto::backup::{
    BackupEncryptionConfig, PitrBaseBackup, PitrManifest, WalSegment, PITR_MANIFEST_KEY,
};
use kubidmd_lib::prelude::duration_from_epoch_now;
use kubidmd_lib::repl::wal::{format_ts_rfc3339, remove_segment};
use sha2::{Digest, Sha256};

use super::{blocking, BaseLocation, PitrError, PitrLocation};
use crate::backup::{
    is_backup_artifact_name, is_encrypted_artifact, read_encryption_header, seal_backup_async,
    BackupEncryptor, S3ClientWrapper,
};

/// A base backup fetched for recovery. The S3 variant is removed when dropped.
pub(super) enum FetchedBase {
    Local(PathBuf),
    S3(crate::FetchedS3Backup),
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
    /// The keys of the base backups that currently exist at this location.
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
            BaseLocation::S3(config) => S3ClientWrapper::new(config.clone())
                .await?
                .list_backups()
                .await?
                .into_iter()
                .filter(|key| is_backup_artifact_name(key))
                .collect(),
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
                let fetched = crate::fetch_s3_backup(config.clone(), &base.key).await?;
                Ok(FetchedBase::S3(fetched))
            }
        }
    }
}

/// Reads and writes the archive at a [`PitrLocation`].
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
                match client.download_backup_if_exists(PITR_MANIFEST_KEY).await? {
                    Some((data, _)) => data,
                    None => return Ok(None),
                }
            }
        };
        let manifest: PitrManifest = serde_json::from_slice(&data).map_err(|err| {
            PitrError::Manifest(format!("{PITR_MANIFEST_KEY} is not readable: {err}"))
        })?;
        Ok(Some(manifest))
    }

    pub(super) async fn save_manifest(&self, manifest: &mut PitrManifest) -> Result<(), PitrError> {
        let now = format_ts_rfc3339(duration_from_epoch_now());
        manifest.updated_at = now.clone();
        let data = serde_json::to_vec_pretty(manifest)
            .map_err(|err| PitrError::Manifest(format!("unable to serialise: {err}")))?;
        match self {
            PitrStore::Local { dir } => {
                let dir = dir.clone();
                blocking(move || {
                    fs::create_dir_all(&dir)?;
                    let path = dir.join(PITR_MANIFEST_KEY);
                    let tmp = dir.join(format!("{PITR_MANIFEST_KEY}.tmp"));
                    fs::write(&tmp, &data)?;
                    fs::rename(&tmp, &path)?;
                    Ok(())
                })
                .await?;
            }
            PitrStore::S3 { client } => {
                client
                    .upload_backup(
                        &data,
                        PITR_MANIFEST_KEY,
                        &now,
                        kubidm_proto::backup::BackupCompression::NoCompression,
                        None,
                    )
                    .await?;
            }
        }
        Ok(())
    }

    /// Archive the closed segment in `local_dir` and return it as the manifest records it.
    ///
    /// With an `encryptor` the segment is sealed with the backup encryption scheme first
    /// and stored as `<segment>.enc`: uploaded to S3, or written next to the plaintext in
    /// the local directory, whose plaintext copy the caller removes once the manifest
    /// records the encrypted one. Without one, the segment is uploaded as it is to S3, and
    /// the local location has nothing to do: the segment already is where it belongs.
    pub(super) async fn put_segment(
        &self,
        local_dir: &Path,
        segment: &WalSegment,
        encryptor: Option<&BackupEncryptor>,
    ) -> Result<WalSegment, PitrError> {
        if !self.is_s3() && encryptor.is_none() {
            return Ok(segment.clone());
        }
        let path = local_dir.join(&segment.segment_id);
        let data = blocking(move || Ok(fs::read(path)?)).await?;
        verify_segment_checksum(segment, &data)?;

        let mut archived = WalSegment {
            encryption_key: None,
            ..segment.clone()
        };
        let stored = match encryptor {
            Some(encryptor) => {
                archived.encryption_key = Some(encryptor.key_identifier().to_string());
                seal_backup_async(data, segment.compression, Some(encryptor))
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
                let path = dir.join(archived.stored_name());
                let tmp = dir.join(format!("{}.tmp", archived.stored_name()));
                blocking(move || {
                    fs::write(&tmp, &stored)?;
                    fs::rename(&tmp, &path)?;
                    Ok(())
                })
                .await?;
            }
            PitrStore::S3 { client } => {
                client
                    .upload_backup(
                        &stored,
                        &archived.object_key(),
                        &segment.created_at,
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
            .decrypt(&data)
            .map(|(plaintext, _)| plaintext)
            .map_err(|err| {
                PitrError::Encryption(format!("unable to decrypt segment {segment_id}: {err}"))
            })
    })
    .await
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
    use super::super::test_util::segment;
    use super::*;

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
