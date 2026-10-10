use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;
use std::time::Duration;

use aws_config::{timeout::TimeoutConfig, BehaviorVersion, Region, SdkConfig};
use aws_credential_types::Credentials;
use aws_sdk_s3::error::DisplayErrorContext;
use aws_sdk_s3::operation::create_multipart_upload::CreateMultipartUploadOutput;
use aws_sdk_s3::operation::get_object::GetObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    CompletedMultipartUpload, CompletedPart, ServerSideEncryption, StorageClass,
};
use aws_sdk_s3::Client as S3Client;
use bytes::Bytes;
use chrono::DateTime;
use hex::encode as hex_encode;
use kubidm_proto::backup::{
    BackupCompression, ReplicationConfig, ReplicationHealthCheck, ReplicationLagMetrics,
    ReplicationRegionConfig, ReplicationRegionStatus, ReplicationStatus, S3BackupMetadata,
    S3Config, S3EncryptionAlgorithm,
};
use regex::Regex;
use sha2::{Digest, Sha256};

use super::retention::{is_backup_artifact_name, sort_backup_names};
use super::run_blocking;

/// Limit on establishing a connection to the service. An unreachable endpoint fails
/// after this instead of the operating system's TCP timeout.
const S3_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Limit on one attempt of one request, which for an upload includes sending its body: up
/// to [`MULTIPART_THRESHOLD`] for a single upload, [`MULTIPART_CHUNK_SIZE`] for a part. A
/// stalled connection fails after this rather than hanging the backup run, the replication
/// monitor or the WAL archive.
const S3_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Limit on one request including the SDK's own retries.
const S3_OPERATION_TIMEOUT: Duration = Duration::from_secs(30 * 60);

const MULTIPART_THRESHOLD: u64 = 100 * 1024 * 1024;
const MULTIPART_CHUNK_SIZE: usize = 10 * 1024 * 1024;

/// How many per-backup problems a degraded region status message spells out before it
/// is cut short.
const REGION_PROBLEMS_IN_MESSAGE: usize = 3;

/// The `s3://bucket[/prefix]` location a configuration points at, for log lines and
/// command output.
pub fn s3_location(config: &S3Config) -> String {
    let prefix = S3ClientWrapper::listing_prefix(config.path_prefix.as_deref());
    match prefix.strip_suffix('/') {
        Some(prefix) if !prefix.is_empty() => format!("s3://{}/{}", config.bucket, prefix),
        _ => format!("s3://{}", config.bucket),
    }
}

#[derive(Debug)]
pub enum S3BackupError {
    ConfigError(String),
    UploadError(String),
    DownloadError(String),
    InvalidChecksum { expected: String, actual: String },
    IoError(std::io::Error),
    SdkError(String),
}

impl std::fmt::Display for S3BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            S3BackupError::ConfigError(msg) => write!(f, "S3 configuration error: {}", msg),
            S3BackupError::UploadError(msg) => write!(f, "S3 upload error: {}", msg),
            S3BackupError::DownloadError(msg) => write!(f, "S3 download error: {}", msg),
            S3BackupError::InvalidChecksum { expected, actual } => {
                write!(
                    f,
                    "Checksum mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            S3BackupError::IoError(e) => write!(f, "IO error: {}", e),
            S3BackupError::SdkError(msg) => write!(f, "AWS SDK error: {}", msg),
        }
    }
}

impl std::error::Error for S3BackupError {}

impl From<std::io::Error> for S3BackupError {
    fn from(e: std::io::Error) -> Self {
        S3BackupError::IoError(e)
    }
}

#[derive(Clone)]
pub struct S3ClientWrapper {
    client: S3Client,
    config: S3Config,
}

impl S3ClientWrapper {
    pub async fn new(config: S3Config) -> Result<Self, S3BackupError> {
        let sdk_config = Self::build_sdk_config(&config).await?;
        let client = Self::build_client(&sdk_config, config.endpoint.is_some());
        Ok(Self { client, config })
    }

    /// Build the SDK client. Custom endpoints (MinIO, Silo, Ceph RGW, ...) are
    /// addressed as `<endpoint>/<bucket>/<key>`. The SDK default of virtual-hosted-style
    /// addressing (`<bucket>.<endpoint>`) requires wildcard DNS that such deployments
    /// usually lack, so path-style addressing is forced whenever an endpoint is
    /// configured (`custom_endpoint`). AWS itself keeps the default.
    fn build_client(sdk_config: &SdkConfig, custom_endpoint: bool) -> S3Client {
        let s3_config = aws_sdk_s3::config::Builder::from(sdk_config)
            .force_path_style(custom_endpoint)
            .build();
        S3Client::from_conf(s3_config)
    }

    async fn build_sdk_config(config: &S3Config) -> Result<SdkConfig, S3BackupError> {
        let mut config_builder = aws_config::defaults(BehaviorVersion::latest()).timeout_config(
            TimeoutConfig::builder()
                .connect_timeout(S3_CONNECT_TIMEOUT)
                .operation_attempt_timeout(S3_ATTEMPT_TIMEOUT)
                .operation_timeout(S3_OPERATION_TIMEOUT)
                .build(),
        );

        if let Some(endpoint) = &config.endpoint {
            config_builder = config_builder.endpoint_url(endpoint);
        }

        if let Some(region) = &config.region {
            config_builder = config_builder.region(Region::new(region.clone()));
        }

        if let Some(credentials) = &config.credentials {
            let creds = Credentials::new(
                credentials.access_key_id.clone(),
                credentials.secret_access_key.clone(),
                credentials.session_token.clone(),
                None,
                "kubidm-backup",
            );
            config_builder = config_builder.credentials_provider(creds);
        }

        Ok(config_builder.load().await)
    }

    /// The configured `path_prefix` normalised for use as an object key prefix: empty when
    /// no prefix (or an empty or `/`-only one) is configured, otherwise ending in exactly
    /// one `/`.
    ///
    /// Every key the server writes is `<listing_prefix><name>` and the listing asks S3 for
    /// exactly this prefix. Passing the bare `path_prefix` to ListObjectsV2 would also match
    /// sibling prefixes (`prod` matches `production/...`), whose keys the display strip would
    /// then mangle to `uction/backup-...`.
    fn listing_prefix(path_prefix: Option<&str>) -> String {
        match path_prefix.map(|prefix| prefix.trim_end_matches('/')) {
            Some(prefix) if !prefix.is_empty() => format!("{prefix}/"),
            _ => String::new(),
        }
    }

    /// The display key of a listed object: `key` with the listing prefix removed, or None
    /// when the object does not live under the prefix.
    fn strip_listing_prefix<'a>(listing_prefix: &str, key: &'a str) -> Option<&'a str> {
        key.strip_prefix(listing_prefix)
    }

    fn build_object_key_with_prefix(path_prefix: Option<&str>, key: &str) -> String {
        format!("{}{}", Self::listing_prefix(path_prefix), key)
    }

    fn build_object_key(&self, key: &str) -> String {
        Self::build_object_key_with_prefix(self.config.path_prefix.as_deref(), key)
    }

    /// The configuration this client was built from.
    pub fn config(&self) -> &S3Config {
        &self.config
    }

    /// The `s3://bucket[/prefix]` location this client writes to.
    pub fn location(&self) -> String {
        s3_location(&self.config)
    }

    /// The replication configuration of this client, when replication is enabled.
    pub fn replication_config(&self) -> Option<&ReplicationConfig> {
        self.config
            .replication
            .as_ref()
            .filter(|replication| replication.enabled)
    }

    /// A client for a replication region. The region's bucket, endpoint, prefix,
    /// credentials, encryption and storage class are used exactly as the primary's are,
    /// so keys, listings and retention behave identically in both locations.
    pub async fn for_region(
        region_config: &ReplicationRegionConfig,
    ) -> Result<Self, S3BackupError> {
        Self::new(region_config.to_s3_config()).await
    }

    /// Upload `data`, a complete backup artifact, as the backup `key` (relative to the
    /// configured prefix) together with its `<key>.metadata.json` sidecar, and return the
    /// metadata written to it. `compression` is the compression of the backup and
    /// `encryption_key_identifier` the identifier of the key the artifact was encrypted
    /// with, if it is encrypted; both are recorded in the sidecar, which replication
    /// copies verbatim to every region.
    pub async fn upload_backup(
        &self,
        data: &[u8],
        key: &str,
        timestamp: &str,
        compression: BackupCompression,
        encryption_key_identifier: Option<&str>,
    ) -> Result<S3BackupMetadata, S3BackupError> {
        self.upload_backup_bytes(
            Bytes::copy_from_slice(data),
            key,
            timestamp,
            compression,
            encryption_key_identifier,
        )
        .await
    }

    /// [`Self::upload_backup`] for an artifact that is already shared as [`Bytes`]: it is
    /// uploaded without being copied, and its checksum is computed on the blocking thread
    /// pool.
    pub async fn upload_backup_bytes(
        &self,
        data: Bytes,
        key: &str,
        timestamp: &str,
        compression: BackupCompression,
        encryption_key_identifier: Option<&str>,
    ) -> Result<S3BackupMetadata, S3BackupError> {
        let size = data.len() as u64;
        let checksum = sha256_hex(data.clone()).await?;
        let metadata = match encryption_key_identifier {
            Some(key_identifier) => S3BackupMetadata::new_encrypted(
                checksum,
                timestamp.to_string(),
                compression,
                size,
                key_identifier.to_string(),
            ),
            None => S3BackupMetadata::new(checksum, timestamp.to_string(), compression, size),
        };

        self.upload_with_metadata(data, key, &metadata).await?;

        Ok(metadata)
    }

    /// Upload `data` under `key` (relative to the configured prefix) with the given,
    /// already computed, metadata sidecar. Shared by the primary upload and by
    /// replication, so a replica carries the very same sidecar as the primary.
    pub(crate) async fn upload_with_metadata(
        &self,
        data: Bytes,
        key: &str,
        metadata: &S3BackupMetadata,
    ) -> Result<(), S3BackupError> {
        let object_key = self.build_object_key(key);

        if data.len() as u64 > MULTIPART_THRESHOLD {
            self.upload_multipart(data, &object_key, metadata).await?;
        } else {
            self.upload_single(data, &object_key, metadata).await?;
        }

        // A backup is only complete with its sidecar, and listings ignore an object without
        // one. Removing the object right away keeps the prefix clean; should that fail too,
        // the retention removes it once a newer backup is complete. A key that already
        // had a sidecar (a replica copied again) is left alone: removing the object would
        // leave its old sidecar without it, and the next comparison sees the mismatch.
        if let Err(err) = self.upload_metadata(&object_key, metadata).await {
            match self.sidecar_exists(&object_key).await {
                Ok(false) => {
                    if let Err(delete_err) = self.delete_object(&object_key).await {
                        warn!(
                            "Unable to remove {} after its metadata could not be written: {}",
                            object_key, delete_err
                        );
                    }
                }
                Ok(true) => warn!(
                    "{} was overwritten, but its metadata could not be updated; it no longer \
                     matches its sidecar",
                    object_key
                ),
                Err(head_err) => warn!(
                    "{} is left in place: its metadata could not be written, and whether it \
                     existed before could not be checked: {}",
                    object_key, head_err
                ),
            }
            return Err(err);
        }
        Ok(())
    }

    /// Whether the metadata sidecar of `object_key` (a full key, prefix included) exists.
    async fn sidecar_exists(&self, object_key: &str) -> Result<bool, S3BackupError> {
        let metadata_key = format!("{object_key}{METADATA_SUFFIX}");
        match self
            .client
            .head_object()
            .bucket(&self.config.bucket)
            .key(&metadata_key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(|service_err| service_err.is_not_found()) =>
            {
                Ok(false)
            }
            Err(err) => Err(S3BackupError::SdkError(format!(
                "Failed to look up {metadata_key}: {}",
                DisplayErrorContext(&err)
            ))),
        }
    }

    async fn upload_single(
        &self,
        data: Bytes,
        key: &str,
        metadata: &S3BackupMetadata,
    ) -> Result<(), S3BackupError> {
        let mut builder = self
            .client
            .put_object()
            .bucket(&self.config.bucket)
            .key(key)
            .body(ByteStream::from(data))
            .metadata("checksum-sha256", &metadata.checksum_sha256)
            .metadata("backup-timestamp", &metadata.timestamp)
            .metadata("backup-size", metadata.size_bytes.to_string())
            .storage_class(self.storage_class()?);

        let (sse, kms_key_id) = self.server_side_encryption();
        builder = builder
            .set_server_side_encryption(sse)
            .set_ssekms_key_id(kms_key_id);

        builder.send().await.map_err(|e| {
            S3BackupError::UploadError(format!(
                "Failed to upload backup: {}",
                DisplayErrorContext(&e)
            ))
        })?;

        info!("Uploaded backup to S3: {}", key);
        Ok(())
    }

    async fn upload_multipart(
        &self,
        data: Bytes,
        key: &str,
        metadata: &S3BackupMetadata,
    ) -> Result<(), S3BackupError> {
        let create_output = self.create_multipart_upload(key, metadata).await?;
        let upload_id = create_output
            .upload_id()
            .filter(|upload_id| !upload_id.is_empty())
            .ok_or_else(|| {
                S3BackupError::UploadError(format!(
                    "The multipart upload of {key} was created without an upload id"
                ))
            })?
            .to_string();

        // An upload that fails is aborted, so that its parts do not linger (and get billed)
        // in the bucket. One whose future is dropped half way, such as a backup run or a
        // replication sync abandoned on shutdown, is aborted by the guard.
        let mut abort_guard = MultipartAbortGuard::new(
            self.client.clone(),
            self.config.bucket.clone(),
            key.to_string(),
            upload_id.clone(),
        );
        let uploaded = self.upload_parts_and_complete(key, &upload_id, data).await;

        // The guard stays armed until the explicit abort returned: should this future be
        // dropped while the abort is in flight, the guard still aborts the upload.
        if let Err(err) = uploaded {
            if let Err(abort_err) =
                abort_multipart_upload(&self.client, &self.config.bucket, key, &upload_id).await
            {
                warn!(
                    "Failed to abort the multipart upload of {}: {}",
                    key, abort_err
                );
            }
            abort_guard.disarm();
            return Err(err);
        }
        abort_guard.disarm();

        info!("Completed multipart upload to S3: {}", key);
        Ok(())
    }

    async fn upload_parts_and_complete(
        &self,
        key: &str,
        upload_id: &str,
        data: Bytes,
    ) -> Result<(), S3BackupError> {
        let mut parts = Vec::new();

        let starts = (0..data.len()).step_by(MULTIPART_CHUNK_SIZE);
        for (part_number, start) in (1_i32..).zip(starts) {
            // A part shares the artifact's buffer rather than copying it.
            let chunk = data.slice(start..data.len().min(start + MULTIPART_CHUNK_SIZE));
            let part = self.upload_part(key, upload_id, part_number, chunk).await?;
            parts.push(
                CompletedPart::builder()
                    .part_number(part_number)
                    .e_tag(part.e_tag().unwrap_or_default())
                    .build(),
            );
        }

        self.complete_multipart_upload(key, upload_id, parts).await
    }

    async fn create_multipart_upload(
        &self,
        key: &str,
        metadata: &S3BackupMetadata,
    ) -> Result<CreateMultipartUploadOutput, S3BackupError> {
        let mut builder = self
            .client
            .create_multipart_upload()
            .bucket(&self.config.bucket)
            .key(key)
            .metadata("checksum-sha256", &metadata.checksum_sha256)
            .metadata("backup-timestamp", &metadata.timestamp)
            .metadata("backup-size", metadata.size_bytes.to_string())
            .storage_class(self.storage_class()?);

        let (sse, kms_key_id) = self.server_side_encryption();
        builder = builder
            .set_server_side_encryption(sse)
            .set_ssekms_key_id(kms_key_id);

        builder.send().await.map_err(|e| {
            S3BackupError::UploadError(format!(
                "Failed to create multipart upload: {}",
                DisplayErrorContext(&e)
            ))
        })
    }

    async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        data: Bytes,
    ) -> Result<aws_sdk_s3::operation::upload_part::UploadPartOutput, S3BackupError> {
        self.client
            .upload_part()
            .bucket(&self.config.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(ByteStream::from(data))
            .send()
            .await
            .map_err(|e| {
                S3BackupError::UploadError(format!(
                    "Failed to upload part {}: {}",
                    part_number,
                    DisplayErrorContext(&e)
                ))
            })
    }

    async fn complete_multipart_upload(
        &self,
        key: &str,
        upload_id: &str,
        parts: Vec<CompletedPart>,
    ) -> Result<(), S3BackupError> {
        let completed_upload = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();

        self.client
            .complete_multipart_upload()
            .bucket(&self.config.bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(completed_upload)
            .send()
            .await
            .map_err(|e| {
                S3BackupError::UploadError(format!(
                    "Failed to complete multipart upload: {}",
                    DisplayErrorContext(&e)
                ))
            })?;

        Ok(())
    }

    async fn upload_metadata(
        &self,
        backup_key: &str,
        metadata: &S3BackupMetadata,
    ) -> Result<(), S3BackupError> {
        let metadata_key = format!("{}.metadata.json", backup_key);
        let metadata_json = serde_json::to_string(metadata).map_err(|e| {
            S3BackupError::UploadError(format!(
                "Failed to serialize metadata: {}",
                DisplayErrorContext(&e)
            ))
        })?;

        let (sse, kms_key_id) = self.server_side_encryption();
        self.client
            .put_object()
            .bucket(&self.config.bucket)
            .key(&metadata_key)
            .body(ByteStream::from(metadata_json.into_bytes()))
            .content_type("application/json")
            .set_server_side_encryption(sse)
            .set_ssekms_key_id(kms_key_id)
            .send()
            .await
            .map_err(|e| {
                S3BackupError::UploadError(format!(
                    "Failed to upload metadata: {}",
                    DisplayErrorContext(&e)
                ))
            })?;

        Ok(())
    }

    /// The storage class of the backup objects this client writes. The configuration
    /// rejects an unknown or archive class at load time.
    fn storage_class(&self) -> Result<StorageClass, S3BackupError> {
        parse_storage_class(&self.config.storage_class).map_err(S3BackupError::ConfigError)
    }

    /// The server-side encryption every object this client writes is stored with: the
    /// algorithm and, for `aws:kms`, the key. Applied to the backup objects, multipart
    /// uploads and metadata sidecars alike, so that a bucket policy requiring encryption,
    /// or a specific KMS key, accepts every one of them.
    fn server_side_encryption(&self) -> (Option<ServerSideEncryption>, Option<String>) {
        match &self.config.server_side_encryption {
            Some(sse) => (
                Some(match sse.algorithm {
                    Some(S3EncryptionAlgorithm::Aes256) => ServerSideEncryption::Aes256,
                    Some(S3EncryptionAlgorithm::AwsKms) | None => ServerSideEncryption::AwsKms,
                }),
                sse.kms_key_id.clone(),
            ),
            None => (None, None),
        }
    }

    pub async fn download_backup(
        &self,
        key: &str,
    ) -> Result<(Vec<u8>, S3BackupMetadata), S3BackupError> {
        let (data, metadata) = self.download_backup_bytes(key).await?;
        Ok((Vec::from(data), metadata))
    }

    /// [`Self::download_backup`] as [`Bytes`], which a copy to another location uploads
    /// as they are. The checksum is computed on the blocking thread pool.
    pub async fn download_backup_bytes(
        &self,
        key: &str,
    ) -> Result<(Bytes, S3BackupMetadata), S3BackupError> {
        let object_key = self.build_object_key(key);
        let metadata = self.download_metadata(&object_key).await?;
        let data = self.download_object(&object_key).await?;

        let actual_checksum = sha256_hex(data.clone()).await?;
        if actual_checksum != metadata.checksum_sha256 {
            return Err(S3BackupError::InvalidChecksum {
                expected: metadata.checksum_sha256.clone(),
                actual: actual_checksum,
            });
        }

        info!("Downloaded and verified backup from S3: {}", object_key);
        Ok((data, metadata))
    }

    /// Write `data` under `key` (relative to the configured prefix) as a single object
    /// whose SHA-256 is stored in its own metadata, with no sidecar. One PUT replaces the
    /// object atomically, so a write that fails or is abandoned half way leaves the
    /// previous version whole. This is how an index overwritten in place, the PITR
    /// manifest, is stored: a backup and its sidecar are two objects that can disagree.
    pub async fn upload_document(
        &self,
        data: Bytes,
        key: &str,
        timestamp: &str,
    ) -> Result<(), S3BackupError> {
        let size = data.len() as u64;
        let checksum = sha256_hex(data.clone()).await?;
        let metadata = S3BackupMetadata::new(
            checksum,
            timestamp.to_string(),
            BackupCompression::NoCompression,
            size,
        );
        self.upload_single(data, &self.build_object_key(key), &metadata)
            .await
    }

    /// Read the object `key` written by [`Self::upload_document`], checked against the
    /// checksum stored with it, or None when the bucket holds no such object. Only a
    /// missing key counts as absent: a missing bucket, or any other failure, is an error.
    ///
    /// An object written as a backup, with a sidecar, carries the same checksum in its own
    /// metadata, so a manifest written by an earlier version is read the same way, and
    /// its sidecar is ignored.
    pub async fn download_document_if_exists(
        &self,
        key: &str,
    ) -> Result<Option<Vec<u8>>, S3BackupError> {
        let object_key = self.build_object_key(key);
        let output = match self
            .client
            .get_object()
            .bucket(&self.config.bucket)
            .key(&object_key)
            .send()
            .await
        {
            Ok(output) => output,
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(|service_err| service_err.is_no_such_key()) =>
            {
                return Ok(None)
            }
            Err(err) => {
                return Err(S3BackupError::DownloadError(format!(
                    "Failed to download {object_key}: {}",
                    DisplayErrorContext(&err)
                )))
            }
        };
        let expected = output
            .metadata()
            .and_then(|metadata| metadata.get("checksum-sha256"))
            .cloned();
        let data = self.collect_stream(output).await?;
        if let Some(expected) = expected {
            let actual = sha256_hex(data.clone()).await?;
            if actual != expected {
                return Err(S3BackupError::InvalidChecksum { expected, actual });
            }
        }
        Ok(Some(Vec::from(data)))
    }

    /// Download the whole object at `object_key` (a full key, prefix included).
    async fn download_object(&self, object_key: &str) -> Result<Bytes, S3BackupError> {
        let output = self
            .client
            .get_object()
            .bucket(&self.config.bucket)
            .key(object_key)
            .send()
            .await
            .map_err(|e| {
                S3BackupError::DownloadError(format!(
                    "Failed to download backup: {}",
                    DisplayErrorContext(&e)
                ))
            })?;

        self.collect_stream(output).await
    }

    /// Fetch the metadata sidecar (`<key>.metadata.json`) of a backup without downloading
    /// the backup itself. `key` is relative to the configured `path_prefix`.
    pub async fn get_backup_metadata(&self, key: &str) -> Result<S3BackupMetadata, S3BackupError> {
        let object_key = self.build_object_key(key);
        self.download_metadata(&object_key).await
    }

    async fn download_metadata(&self, backup_key: &str) -> Result<S3BackupMetadata, S3BackupError> {
        let metadata_key = format!("{}.metadata.json", backup_key);

        let output = self
            .client
            .get_object()
            .bucket(&self.config.bucket)
            .key(&metadata_key)
            .send()
            .await
            .map_err(|e| {
                S3BackupError::DownloadError(format!(
                    "Failed to download metadata: {}",
                    DisplayErrorContext(&e)
                ))
            })?;

        let data = self.collect_stream(output).await?;
        let metadata: S3BackupMetadata = serde_json::from_slice(&data).map_err(|e| {
            S3BackupError::DownloadError(format!(
                "Failed to parse metadata: {}",
                DisplayErrorContext(&e)
            ))
        })?;

        Ok(metadata)
    }

    async fn collect_stream(&self, output: GetObjectOutput) -> Result<Bytes, S3BackupError> {
        let body = output.body.collect().await.map_err(|e| {
            S3BackupError::DownloadError(format!("Stream error: {}", DisplayErrorContext(&e)))
        })?;
        Ok(body.into_bytes())
    }

    /// List every object under the configured prefix, metadata sidecars included, with the
    /// prefix stripped. All pages of the listing are collected.
    ///
    /// The listing uses the `/`-terminated prefix of `Self::listing_prefix`, so objects
    /// under a sibling prefix that merely starts with the same characters are never
    /// returned.
    async fn list_keys(&self) -> Result<Vec<String>, S3BackupError> {
        let prefix = Self::listing_prefix(self.config.path_prefix.as_deref());

        let mut pages = self
            .client
            .list_objects_v2()
            .bucket(&self.config.bucket)
            .prefix(&prefix)
            .into_paginator()
            .send();

        let mut keys = Vec::new();
        while let Some(page) = pages.next().await {
            let page = page.map_err(|e| {
                S3BackupError::SdkError(format!(
                    "Failed to list objects: {}",
                    DisplayErrorContext(&e)
                ))
            })?;
            for obj in page.contents() {
                let Some(key) = obj.key() else {
                    continue;
                };
                // S3 only returns keys starting with the requested prefix; anything else
                // is not ours and is skipped rather than mangled.
                if let Some(display_key) = Self::strip_listing_prefix(&prefix, key) {
                    keys.push(display_key.to_string());
                }
            }
        }

        Ok(keys)
    }

    /// List every object under the configured prefix except metadata sidecars, with the
    /// prefix stripped. All pages of the listing are collected.
    pub async fn list_backups(&self) -> Result<Vec<String>, S3BackupError> {
        Ok(self
            .list_keys()
            .await?
            .into_iter()
            .filter(|key| !key.ends_with(METADATA_SUFFIX))
            .collect())
    }

    /// The automatically generated backups under the configured prefix, split by whether
    /// their metadata sidecar exists, each sorted oldest first.
    pub async fn list_backup_listing(&self) -> Result<BackupListing, S3BackupError> {
        Ok(BackupListing::from_keys(&self.list_keys().await?))
    }

    /// Delete one object, `object_key` being a full key, prefix included.
    async fn delete_object(&self, object_key: &str) -> Result<(), S3BackupError> {
        self.client
            .delete_object()
            .bucket(&self.config.bucket)
            .key(object_key)
            .send()
            .await
            .map_err(|e| {
                S3BackupError::SdkError(format!(
                    "Failed to delete {}: {}",
                    object_key,
                    DisplayErrorContext(&e)
                ))
            })?;
        Ok(())
    }

    pub async fn delete_backup(&self, key: &str) -> Result<(), S3BackupError> {
        let object_key = self.build_object_key(key);
        let metadata_key = format!("{}.metadata.json", object_key);

        self.delete_object(&object_key).await?;

        self.client
            .delete_object()
            .bucket(&self.config.bucket)
            .key(&metadata_key)
            .send()
            .await
            .map_err(|e| {
                S3BackupError::SdkError(format!(
                    "Failed to delete metadata: {}",
                    DisplayErrorContext(&e)
                ))
            })?;

        info!("Deleted backup from S3: {}", object_key);
        Ok(())
    }

    /// Verify that the stored backup object still matches its metadata sidecar.
    ///
    /// The object size reported by S3 is compared with `size_bytes` first as a cheap
    /// pre-check (skipped when the service reports no content length), then the object
    /// is downloaded and its SHA-256 is compared with `checksum_sha256`. Returns
    /// `Ok(false)` when either does not match, and `Err` when the object or its metadata
    /// could not be retrieved at all.
    pub async fn verify_backup(&self, key: &str) -> Result<bool, S3BackupError> {
        let object_key = self.build_object_key(key);
        let metadata = self.download_metadata(&object_key).await?;

        match self.head_object_size(&object_key).await? {
            Some(actual_size) if actual_size != metadata.size_bytes => {
                warn!(
                    "Backup size mismatch for {}: expected {}, got {}",
                    object_key, metadata.size_bytes, actual_size
                );
                return Ok(false);
            }
            Some(_) => {}
            None => debug!(
                "No content length reported for {}, skipping the size pre-check",
                object_key
            ),
        }

        let data = self.download_object(&object_key).await?;
        let actual_checksum = sha256_hex(data).await?;
        if actual_checksum != metadata.checksum_sha256 {
            warn!(
                "Backup checksum mismatch for {}: expected {}, got {}",
                object_key, metadata.checksum_sha256, actual_checksum
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// The size S3 reports for `object_key` (a full key, prefix included), or None when
    /// the service reports no content length.
    async fn head_object_size(&self, object_key: &str) -> Result<Option<u64>, S3BackupError> {
        let head = self
            .client
            .head_object()
            .bucket(&self.config.bucket)
            .key(object_key)
            .send()
            .await
            .map_err(|e| {
                S3BackupError::SdkError(format!(
                    "Failed to head object: {}",
                    DisplayErrorContext(&e)
                ))
            })?;

        Ok(head.content_length().map(|size| size as u64))
    }

    /// The prefix-relative keys of the complete automatically generated backups under the
    /// configured prefix, sorted oldest first: those with a metadata sidecar. Sidecars, the
    /// PITR manifest, manual objects and backup objects whose sidecar is missing (an upload
    /// that failed half way) are left out, so this is exactly the set replication has to
    /// mirror and retention counts.
    pub async fn list_backup_artifacts(&self) -> Result<Vec<String>, S3BackupError> {
        Ok(self.list_backup_listing().await?.complete)
    }

    /// Why the copy of `backup_key` in `region` differs from the primary copy described by
    /// `primary`, or None when sidecar and reported size agree with it. Nothing is
    /// downloaded: the sidecars must agree on checksum and size, and the size S3 reports
    /// for the replica must match.
    ///
    /// This catches a missing, truncated, replaced or re-uploaded replica cheaply enough
    /// to run on every health check; a replica whose bytes were corrupted without changing
    /// its size is only caught by `verify-s3 --region`, which downloads it.
    async fn replica_differs(
        region: &S3ClientWrapper,
        backup_key: &str,
        primary: &S3BackupMetadata,
    ) -> Result<Option<String>, S3BackupError> {
        let replica = region.get_backup_metadata(backup_key).await?;
        let replica_size = region
            .head_object_size(&region.build_object_key(backup_key))
            .await?;
        Ok(replica_mismatch(primary, &replica, replica_size))
    }

    /// The backups of the primary and their sidecars, read once per run however many
    /// regions are compared with them.
    async fn primary_backups(&self) -> Result<PrimaryBackups, S3BackupError> {
        let keys = self.list_backup_artifacts().await?;
        let mut metadata = BTreeMap::new();
        for key in &keys {
            metadata.insert(key.clone(), self.get_backup_metadata(key).await);
        }
        Ok(PrimaryBackups { keys, metadata })
    }

    /// Compare `region_config` with the primary's backups, and with `repair`, copy every
    /// backup the region misses or holds a differing copy of (another checksum or size, a
    /// missing sidecar) from the primary, checked against the primary's checksum and with
    /// the primary's sidecar. Returns what was copied, and the region's status after the
    /// copies, both from the same comparison.
    ///
    /// The region client is built once for the whole comparison. A primary copy that fails
    /// its checksum is never propagated. A backup whose primary sidecar can not be read
    /// (retention just removed it) is not copied and is reported as a problem. The sync
    /// result is an error only when the region itself can not be reached or listed; the
    /// status never fails on its own: problems are carried in it.
    async fn reconcile_region(
        &self,
        region_config: &ReplicationRegionConfig,
        primary: &PrimaryBackups,
        repair: bool,
    ) -> (
        Result<RegionSyncOutcome, S3BackupError>,
        ReplicationRegionStatus,
    ) {
        let mut status = RegionStatusBuilder::new(region_config, primary.keys.len());

        let region = match Self::for_region(region_config).await {
            Ok(region) => region,
            Err(err) => {
                let status = status.unreachable(&err);
                return (Err(err), status);
            }
        };
        let replicated: BTreeSet<String> = match region.list_backup_artifacts().await {
            Ok(replicated) => replicated.into_iter().collect(),
            Err(err) => {
                let status = status.unreachable(&err);
                return (Err(err), status);
            }
        };

        let mut outcome = RegionSyncOutcome::default();
        for backup_key in &primary.keys {
            let primary_metadata = match primary.metadata.get(backup_key) {
                Some(Ok(primary_metadata)) => primary_metadata,
                Some(Err(err)) => {
                    debug!(
                        "Replication skips {} for now: its primary metadata can not be read: {}",
                        backup_key, err
                    );
                    status.problem(format!("{backup_key} could not be checked: {err}"));
                    continue;
                }
                None => continue,
            };

            let reason = if replicated.contains(backup_key) {
                match Self::replica_differs(&region, backup_key, primary_metadata).await {
                    Ok(None) => {
                        status.intact(backup_key, primary_metadata);
                        continue;
                    }
                    Ok(Some(reason)) => reason,
                    Err(err) => format!("could not be checked: {err}"),
                }
            } else {
                "is missing".to_string()
            };

            if !repair {
                status.problem(format!("{backup_key} {reason}"));
                continue;
            }

            info!(
                "Replication sync copies {} to region {}: the region copy {}",
                backup_key,
                region_config.name(),
                reason
            );
            match self.copy_backup_to(&region, backup_key).await {
                Ok(()) => {
                    outcome.copied.push(backup_key.clone());
                    status.intact(backup_key, primary_metadata);
                }
                Err(err) => {
                    status.problem(format!("{backup_key} {reason}, and the copy failed: {err}"));
                    outcome.failed.push((backup_key.clone(), err.to_string()));
                }
            }
        }

        (
            Ok(outcome),
            status.finish(primary.newest_timestamp().as_deref()),
        )
    }

    /// One pass over every region of `replication_config`: copy to each region what it
    /// misses or holds a differing copy of, and report the health that results, in the
    /// same comparison. This is what the replication monitor runs every
    /// `sync_interval_seconds`. Fails only when the primary bucket can not be listed; a
    /// region that can not be synced is reported in its result and its status instead.
    pub async fn sync_and_check_replication(
        &self,
        replication_config: &ReplicationConfig,
        current_timestamp: Option<&str>,
    ) -> Result<ReplicationSyncReport, S3BackupError> {
        let primary = self.primary_backups().await?;

        let mut synced = Vec::with_capacity(replication_config.regions.len());
        let mut regions = Vec::with_capacity(replication_config.regions.len());
        for region_config in &replication_config.regions {
            let (sync, status) = self.reconcile_region(region_config, &primary, true).await;
            synced.push((region_config.name().to_string(), sync));
            regions.push(status);
        }

        Ok(ReplicationSyncReport {
            synced,
            health: summarise_health(regions, current_timestamp),
        })
    }

    /// Bring every region of `replication_config` up to date with the backups currently
    /// in the primary bucket, see [`Self::sync_and_check_replication`]. This is how a
    /// backup that could not be replicated when it was taken (the region was unreachable,
    /// the region was added later) reaches the region eventually. Fails only when the
    /// primary bucket can not be listed; a region that can not be synced is reported in
    /// its result instead.
    pub async fn sync_replication(
        &self,
        replication_config: &ReplicationConfig,
    ) -> Result<Vec<(String, Result<RegionSyncOutcome, S3BackupError>)>, S3BackupError> {
        Ok(self
            .sync_and_check_replication(replication_config, None)
            .await?
            .synced)
    }

    /// Copy the primary backup `backup_key` and its sidecar to `region`, after checking
    /// the downloaded bytes against the primary's checksum. The WAL archive replicates its
    /// segments with it as well.
    pub(crate) async fn copy_backup_to(
        &self,
        region: &S3ClientWrapper,
        backup_key: &str,
    ) -> Result<(), S3BackupError> {
        let (data, metadata) = self.download_backup_bytes(backup_key).await?;
        region
            .upload_with_metadata(data, backup_key, &metadata)
            .await
    }

    /// The replication health of every region of `replication_config` against the backups
    /// currently in the primary bucket: which of the primary's backups each region holds
    /// intact, and how far it lags behind the primary. Nothing is copied. A region that
    /// can not be reached is reported as `Failed`, one that misses or disagrees on any
    /// backup as `Degraded`, and one that holds every backup as `Completed`. Fails only
    /// when the primary bucket itself can not be listed.
    pub async fn check_replication_health(
        &self,
        replication_config: &ReplicationConfig,
        current_timestamp: Option<&str>,
    ) -> Result<ReplicationHealthCheck, S3BackupError> {
        let primary = self.primary_backups().await?;

        let mut regions = Vec::with_capacity(replication_config.regions.len());
        for region_config in &replication_config.regions {
            let (_, status) = self.reconcile_region(region_config, &primary, false).await;
            regions.push(status);
        }

        Ok(summarise_health(regions, current_timestamp))
    }
}

/// The hex encoded SHA-256 of `data`, computed on the blocking thread pool: hashing a whole
/// backup takes long enough to stall the async runtime.
async fn sha256_hex(data: Bytes) -> Result<String, S3BackupError> {
    Ok(run_blocking(move || Ok(hex_encode(Sha256::digest(&data)))).await?)
}

/// Abort the multipart upload `upload_id` of `key` (a full key, prefix included).
async fn abort_multipart_upload(
    client: &S3Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Result<(), String> {
    client
        .abort_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(upload_id)
        .send()
        .await
        .map(|_| ())
        .map_err(|err| DisplayErrorContext(&err).to_string())
}

/// Aborts a multipart upload when dropped while armed: the upload future was dropped
/// before it completed or failed, so its parts would otherwise stay in the bucket, billed,
/// until a lifecycle rule removes them. The abort is spawned on the current runtime, so it
/// is best effort; a runtime that is shutting down may not run it.
struct MultipartAbortGuard {
    upload: Option<(S3Client, String, String, String)>,
}

impl MultipartAbortGuard {
    fn new(client: S3Client, bucket: String, key: String, upload_id: String) -> Self {
        Self {
            upload: Some((client, bucket, key, upload_id)),
        }
    }

    /// The upload completed or failed, and the caller handles it.
    fn disarm(&mut self) {
        self.upload = None;
    }
}

impl Drop for MultipartAbortGuard {
    fn drop(&mut self) {
        let Some((client, bucket, key, upload_id)) = self.upload.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            warn!(
                "The multipart upload of {} was interrupted and can not be aborted",
                key
            );
            return;
        };
        runtime.spawn(async move {
            match abort_multipart_upload(&client, &bucket, &key, &upload_id).await {
                Ok(()) => info!("Aborted the interrupted multipart upload of {}", key),
                Err(err) => warn!(
                    "Failed to abort the interrupted multipart upload of {}: {}",
                    key, err
                ),
            }
        });
    }
}

/// Suffix of the metadata sidecar of a backup object.
const METADATA_SUFFIX: &str = ".metadata.json";

/// The automatically generated backups found under a prefix.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BackupListing {
    /// Backups with a metadata sidecar, oldest first.
    pub complete: Vec<String>,
    /// Backup objects without a sidecar, oldest first: an upload whose sidecar could not
    /// be written, or one still in progress.
    pub incomplete: Vec<String>,
}

impl BackupListing {
    /// Split the prefix-relative `keys` of one listing.
    fn from_keys(keys: &[String]) -> Self {
        let sidecars: BTreeSet<&str> = keys
            .iter()
            .filter_map(|key| key.strip_suffix(METADATA_SUFFIX))
            .collect();
        let (mut complete, mut incomplete): (Vec<String>, Vec<String>) = keys
            .iter()
            .filter(|key| is_backup_artifact_name(key))
            .cloned()
            .partition(|key| sidecars.contains(key.as_str()));
        sort_backup_names(&mut complete);
        sort_backup_names(&mut incomplete);
        Self {
            complete,
            incomplete,
        }
    }
}

/// What one `sync_region` run did in a region.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RegionSyncOutcome {
    /// Backups copied to the region because it missed them or held a differing copy.
    pub copied: Vec<String>,
    /// Backups that needed a copy which failed, with the reason.
    pub failed: Vec<(String, String)>,
}

/// The result of [`S3ClientWrapper::sync_and_check_replication`].
#[derive(Debug)]
pub struct ReplicationSyncReport {
    /// What the sync did in every region, by region name; an error when the region could
    /// not be reached or listed.
    pub synced: Vec<(String, Result<RegionSyncOutcome, S3BackupError>)>,
    /// The health of every region after the sync.
    pub health: ReplicationHealthCheck,
}

/// The primary's backups, oldest first, and the sidecar of each, or why it can not be
/// read.
struct PrimaryBackups {
    keys: Vec<String>,
    metadata: BTreeMap<String, Result<S3BackupMetadata, S3BackupError>>,
}

impl PrimaryBackups {
    /// The timestamp of the newest primary backup, which the lag of every region is
    /// measured against whether or not the region holds it.
    fn newest_timestamp(&self) -> Option<String> {
        let newest = self.keys.last()?;
        match self.metadata.get(newest)? {
            Ok(metadata) => Some(metadata.timestamp.clone()),
            Err(err) => {
                warn!(
                    "Unable to read the metadata of the newest primary backup {}: {}",
                    newest, err
                );
                None
            }
        }
    }
}

/// The status of one region, built up backup by backup.
struct RegionStatusBuilder {
    status: ReplicationRegionStatus,
    total: u64,
    problems: Vec<String>,
}

impl RegionStatusBuilder {
    fn new(region_config: &ReplicationRegionConfig, total: usize) -> Self {
        Self {
            status: ReplicationRegionStatus {
                region: region_config.name().to_string(),
                bucket: region_config.bucket.clone(),
                status: ReplicationStatus::Completed,
                last_sync_timestamp: None,
                last_sync_backup_id: None,
                lag_seconds: None,
                bytes_replicated: 0,
                backups_replicated: 0,
                pending_backups: 0,
                last_error: None,
            },
            total: total as u64,
            problems: Vec::new(),
        }
    }

    /// The region holds `backup_key` intact. Backups are recorded oldest first, so the
    /// last one recorded is the newest the region holds.
    fn intact(&mut self, backup_key: &str, primary: &S3BackupMetadata) {
        self.status.backups_replicated += 1;
        self.status.bytes_replicated += primary.size_bytes;
        self.status.last_sync_backup_id = Some(backup_key.to_string());
        self.status.last_sync_timestamp = Some(primary.timestamp.clone());
    }

    fn problem(&mut self, problem: String) {
        self.problems.push(problem);
    }

    fn unreachable(self, err: &S3BackupError) -> ReplicationRegionStatus {
        region_unreachable(self.status, self.total, err)
    }

    fn finish(mut self, newest_primary_timestamp: Option<&str>) -> ReplicationRegionStatus {
        self.status.pending_backups = self.problems.len() as u64;
        self.status.lag_seconds = match (newest_primary_timestamp, &self.status.last_sync_timestamp)
        {
            (Some(primary), Some(replica)) => lag_seconds(primary, replica),
            _ => None,
        };
        if !self.problems.is_empty() {
            self.status.status = ReplicationStatus::Degraded {
                message: degraded_message(&self.problems, self.total),
            };
        }
        self.status
    }
}

/// Whether two S3 configurations address the same objects: same endpoint, same bucket and
/// same normalised path prefix. A replication region at the primary's own location would
/// copy every backup onto itself and report perfect health without any redundancy.
///
/// Endpoints are compared without their scheme and trailing `/`, and every AWS S3 endpoint
/// (`s3.amazonaws.com`, `s3.<region>.amazonaws.com`, ...) counts as no endpoint at all: a
/// bucket name is unique across AWS, so the same bucket reached through another AWS
/// endpoint is the same location.
pub fn same_s3_location(a: &S3Config, b: &S3Config) -> bool {
    a.bucket == b.bucket
        && normalized_endpoint(a.endpoint.as_deref()) == normalized_endpoint(b.endpoint.as_deref())
        && S3ClientWrapper::listing_prefix(a.path_prefix.as_deref())
            == S3ClientWrapper::listing_prefix(b.path_prefix.as_deref())
}

/// Pattern of the host of an AWS S3 endpoint, regional, dual-stack or accelerated, in the
/// global and the China partitions.
static AWS_S3_ENDPOINT_HOST: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"^s3([.-][a-z0-9-]+)*\.amazonaws\.com(\.cn)?$")
        .expect("AWS endpoint regex is a constant and must compile")
});

/// The endpoint `endpoint` addresses, for comparing locations: lower case, without scheme
/// and trailing `/`, and None for AWS S3, see [`same_s3_location`].
fn normalized_endpoint(endpoint: Option<&str>) -> Option<String> {
    let endpoint = endpoint?.trim().trim_end_matches('/').to_ascii_lowercase();
    let host = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .unwrap_or(&endpoint)
        .to_string();
    if host.is_empty() || AWS_S3_ENDPOINT_HOST.is_match(&host) {
        None
    } else {
        Some(host)
    }
}

/// Whether a region is healthy for the purpose of monitoring and the exit code of
/// `replicate-status`: it holds every primary backup intact.
pub fn region_is_healthy(status: &ReplicationRegionStatus) -> bool {
    status.status == ReplicationStatus::Completed
}

/// Why a replica differs from the primary, or None when sidecars and reported size agree.
fn replica_mismatch(
    primary: &S3BackupMetadata,
    replica: &S3BackupMetadata,
    replica_size: Option<u64>,
) -> Option<String> {
    if replica.checksum_sha256 != primary.checksum_sha256 {
        return Some(format!(
            "has checksum {} but the primary has {}",
            replica.checksum_sha256, primary.checksum_sha256
        ));
    }
    if replica.size_bytes != primary.size_bytes {
        return Some(format!(
            "records {} bytes but the primary records {}",
            replica.size_bytes, primary.size_bytes
        ));
    }
    match replica_size {
        Some(size) if size != primary.size_bytes => Some(format!(
            "is {} bytes in the region but {} bytes are expected",
            size, primary.size_bytes
        )),
        _ => None,
    }
}

/// The seconds the newest replicated backup (`replica`) lags behind the newest primary
/// backup (`primary`), both RFC3339 timestamps. Zero when the replica is as new as, or
/// newer than, the primary; None when a timestamp can not be parsed.
fn lag_seconds(primary: &str, replica: &str) -> Option<u64> {
    let primary = DateTime::parse_from_rfc3339(primary).ok()?;
    let replica = DateTime::parse_from_rfc3339(replica).ok()?;
    Some((primary - replica).num_seconds().max(0) as u64)
}

fn degraded_message(problems: &[String], total: u64) -> String {
    let shown = problems
        .iter()
        .take(REGION_PROBLEMS_IN_MESSAGE)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    let more = problems.len().saturating_sub(REGION_PROBLEMS_IN_MESSAGE);
    if more > 0 {
        format!(
            "{} of {} backups not replicated: {}; and {} more",
            problems.len(),
            total,
            shown,
            more
        )
    } else {
        format!(
            "{} of {} backups not replicated: {}",
            problems.len(),
            total,
            shown
        )
    }
}

fn region_unreachable(
    mut status: ReplicationRegionStatus,
    total: u64,
    err: &S3BackupError,
) -> ReplicationRegionStatus {
    let error = err.to_string();
    status.pending_backups = total;
    status.last_error = Some(error.clone());
    status.status = ReplicationStatus::Failed { error };
    status
}

/// Aggregate per-region statuses into the overall health report.
fn summarise_health(
    regions: Vec<ReplicationRegionStatus>,
    current_timestamp: Option<&str>,
) -> ReplicationHealthCheck {
    let healthy = regions.iter().filter(|r| region_is_healthy(r)).count();
    let unhealthy = regions.len() - healthy;
    let lags = regions.iter().filter_map(|r| r.lag_seconds);
    let total_lag_seconds = lags.clone().sum();
    let max_lag_seconds = lags.max().unwrap_or(0);

    let overall_status = if unhealthy > 0 {
        if healthy == 0 {
            ReplicationStatus::Failed {
                error: format!("all {} regions unhealthy", unhealthy),
            }
        } else {
            ReplicationStatus::Degraded {
                message: format!("{} of {} regions unhealthy", unhealthy, regions.len()),
            }
        }
    } else if healthy > 0 {
        ReplicationStatus::Completed
    } else {
        ReplicationStatus::NotConfigured
    };

    ReplicationHealthCheck {
        overall_status,
        regions,
        total_lag_seconds,
        max_lag_seconds,
        healthy_regions: healthy,
        unhealthy_regions: unhealthy,
        last_check_timestamp: current_timestamp.map(str::to_string).unwrap_or_default(),
    }
}

/// The lag metrics of every region of an existing health check.
pub fn lag_metrics_from_health(
    health: &ReplicationHealthCheck,
    replication_config: &ReplicationConfig,
) -> Vec<ReplicationLagMetrics> {
    health
        .regions
        .iter()
        .map(|region| ReplicationLagMetrics {
            region: region.region.clone(),
            lag_seconds: region.lag_seconds.unwrap_or(0),
            pending_backups: region.pending_backups as usize,
            last_backup_timestamp: region.last_sync_timestamp.clone(),
            replication_delay_seconds: replication_config.sync_interval_seconds,
        })
        .collect()
}

/// A writer that hashes what it writes, for tests.
#[cfg(test)]
pub struct ChecksumWriter<W> {
    writer: W,
    hasher: Sha256,
}

#[cfg(test)]
impl<W> ChecksumWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            hasher: Sha256::new(),
        }
    }

    pub fn finalize(self) -> (W, String) {
        let checksum = hex_encode(self.hasher.finalize());
        (self.writer, checksum)
    }
}

#[cfg(test)]
impl<W: std::io::Write> std::io::Write for ChecksumWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

/// A reader that hashes what it reads, for tests.
#[cfg(test)]
pub struct ChecksumReader<R> {
    reader: R,
    hasher: Sha256,
}

#[cfg(test)]
impl<R> ChecksumReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            hasher: Sha256::new(),
        }
    }

    pub fn finalize(self) -> (R, String) {
        let checksum = hex_encode(self.hasher.finalize());
        (self.reader, checksum)
    }
}

#[cfg(test)]
impl<R: std::io::Read> std::io::Read for ChecksumReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.reader.read(buf)?;
        if let Some(slice) = buf.get(..n) {
            self.hasher.update(slice);
        }
        Ok(n)
    }
}

/// The storage class `name` selects. Archive classes are refused: their objects can only
/// be read after a restore request, so restore, verification, the replication sync and
/// point-in-time recovery could not read the backups, while the replication status, which
/// only reads metadata, would report them as healthy.
fn parse_storage_class(name: &str) -> Result<StorageClass, String> {
    match name.to_uppercase().as_str() {
        "STANDARD" => Ok(StorageClass::Standard),
        "REDUCED_REDUNDANCY" => Ok(StorageClass::ReducedRedundancy),
        "STANDARD_IA" => Ok(StorageClass::StandardIa),
        "ONEZONE_IA" => Ok(StorageClass::OnezoneIa),
        "INTELLIGENT_TIERING" => Ok(StorageClass::IntelligentTiering),
        "GLACIER_IR" => Ok(StorageClass::GlacierIr),
        "GLACIER" | "DEEP_ARCHIVE" => Err(format!(
            "storage_class {name:?} is an archive class whose objects can only be read after \
             a restore request, so the backups could neither be restored nor verified nor \
             replicated; use GLACIER_IR for an archive class that is readable at once"
        )),
        _ => Err(format!(
            "storage_class {name:?} is not a known S3 storage class; use one of STANDARD, \
             REDUCED_REDUNDANCY, STANDARD_IA, ONEZONE_IA, INTELLIGENT_TIERING or GLACIER_IR"
        )),
    }
}

/// Check the settings of an S3 location that S3 would otherwise only reject at the first
/// upload, or that would silently not do what they say: the storage class must be known
/// and readable without a restore request, and a KMS key needs `aws:kms` server-side
/// encryption. Returns the reason, without the location's configuration key.
pub fn validate_s3_location(config: &S3Config) -> Result<(), String> {
    parse_storage_class(&config.storage_class)?;
    if let Some(sse) = &config.server_side_encryption {
        if sse.algorithm == Some(S3EncryptionAlgorithm::Aes256) && sse.kms_key_id.is_some() {
            return Err(
                "server_side_encryption: kms_key_id requires algorithm = \"aws:kms\"; S3 \
                 rejects a KMS key together with AES256"
                    .to_string(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod fake_s3 {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use kubidm_proto::backup::{S3Config, S3Credentials};

    /// One request the fake endpoint received. `path` is `/<bucket>/<key>`, with the `:`
    /// of the timestamps decoded.
    #[derive(Debug, Clone)]
    pub struct Recorded {
        pub method: String,
        pub path: String,
        pub query: String,
        pub headers: BTreeMap<String, String>,
        pub body: Vec<u8>,
    }

    impl Recorded {
        pub fn header(&self, name: &str) -> Option<&str> {
            self.headers.get(name).map(String::as_str)
        }
    }

    /// The header of the `checksum-sha256` user metadata.
    pub const CHECKSUM_HEADER: &str = "x-amz-meta-checksum-sha256";

    /// The status, headers and body to answer a request with.
    pub type Reply = (u16, Vec<(&'static str, String)>, String);
    pub type Responder = Arc<dyn Fn(&Recorded) -> Reply + Send + Sync>;

    /// The answer of a store that accepts everything.
    pub fn ok(request: &Recorded) -> Reply {
        match request.method.as_str() {
            "DELETE" => (204, vec![], String::new()),
            _ => (200, vec![("etag", "\"etag\"".to_string())], String::new()),
        }
    }

    /// An S3 error answer.
    pub fn error(status: u16, code: &str) -> Reply {
        (
            status,
            vec![("content-type", "application/xml".to_string())],
            format!("<Error><Code>{code}</Code><Message>{code}</Message></Error>"),
        )
    }

    /// The value of the query parameter `name` of `query`, with the `/` and `:` of keys
    /// decoded.
    fn query_param(query: &str, name: &str) -> Option<String> {
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| value.replace("%2F", "/").replace("%3A", ":"))
        })
    }

    /// A responder that behaves like a small object store holding every bucket in
    /// `objects` (keyed by `/<bucket>/<key>`): PUT, GET, HEAD, DELETE and ListObjectsV2.
    ///
    /// The `checksum-sha256` user metadata of an object is kept and returned with it.
    pub fn store(objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>) -> Responder {
        let checksums: Arc<Mutex<BTreeMap<String, String>>> = Arc::default();
        Arc::new(move |request: &Recorded| {
            let mut objects = objects.lock().expect("objects");
            let mut checksums = checksums.lock().expect("checksums");
            let not_found = || error(404, "NoSuchKey");
            match request.method.as_str() {
                "PUT" => {
                    objects.insert(request.path.clone(), request.body.clone());
                    match request.header(CHECKSUM_HEADER) {
                        Some(checksum) => {
                            checksums.insert(request.path.clone(), checksum.to_string())
                        }
                        None => checksums.remove(&request.path),
                    };
                    ok(request)
                }
                "DELETE" => {
                    objects.remove(&request.path);
                    checksums.remove(&request.path);
                    ok(request)
                }
                "HEAD" => match objects.get(&request.path) {
                    Some(body) => (
                        200,
                        vec![("content-length", body.len().to_string())],
                        String::new(),
                    ),
                    None => (404, vec![], String::new()),
                },
                "GET" if request.query.contains("list-type=2") => {
                    let bucket = request.path.trim_matches('/');
                    let prefix = query_param(&request.query, "prefix").unwrap_or_default();
                    let full_prefix = format!("/{bucket}/{prefix}");
                    let contents: String = objects
                        .iter()
                        .filter(|(path, _)| path.starts_with(&full_prefix))
                        .map(|(path, body)| {
                            let key = path.trim_start_matches(&format!("/{bucket}/")).to_string();
                            format!(
                                "<Contents><Key>{key}</Key><Size>{}</Size></Contents>",
                                body.len()
                            )
                        })
                        .collect();
                    (
                        200,
                        vec![("content-type", "application/xml".to_string())],
                        format!(
                            "<ListBucketResult><Name>{bucket}</Name><Prefix>{prefix}</Prefix>\
                             <MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>\
                             {contents}</ListBucketResult>"
                        ),
                    )
                }
                "GET" => match objects.get(&request.path) {
                    Some(body) => (
                        200,
                        [("content-length", body.len().to_string())]
                            .into_iter()
                            .chain(
                                checksums
                                    .get(&request.path)
                                    .map(|checksum| (CHECKSUM_HEADER, checksum.clone())),
                            )
                            .collect(),
                        String::from_utf8_lossy(body).into_owned(),
                    ),
                    None => not_found(),
                },
                _ => error(405, "MethodNotAllowed"),
            }
        })
    }

    pub struct FakeS3 {
        pub endpoint: String,
        requests: Arc<Mutex<Vec<Recorded>>>,
    }

    impl FakeS3 {
        pub async fn start(responder: Responder) -> Self {
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorder = Arc::clone(&requests);
            let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
                let responder = Arc::clone(&responder);
                let recorder = Arc::clone(&recorder);
                async move {
                    let (parts, body) = request.into_parts();
                    let body = axum::body::to_bytes(body, usize::MAX)
                        .await
                        .map(|body| body.to_vec())
                        .unwrap_or_default();
                    let recorded = Recorded {
                        method: parts.method.to_string(),
                        // Backup names carry the `:` of their timestamp.
                        path: parts.uri.path().replace("%3A", ":"),
                        query: parts.uri.query().unwrap_or_default().to_string(),
                        headers: parts
                            .headers
                            .iter()
                            .map(|(name, value)| {
                                (
                                    name.as_str().to_string(),
                                    value.to_str().unwrap_or_default().to_string(),
                                )
                            })
                            .collect(),
                        body,
                    };
                    // On the blocking pool, so that a responder may hold a request back.
                    let ((status, headers, body), recorded) =
                        tokio::task::spawn_blocking(move || (responder(&recorded), recorded))
                            .await
                            .expect("responder");
                    recorder.lock().expect("recorder").push(recorded);
                    let mut response = axum::response::Response::builder().status(status);
                    for (name, value) in headers {
                        response = response.header(name, value);
                    }
                    response
                        .body(axum::body::Body::from(body))
                        .expect("response")
                }
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
            tokio::spawn(async move { axum::serve(listener, app).await });
            Self { endpoint, requests }
        }

        /// A configuration for `bucket` at this endpoint.
        pub fn config(&self, bucket: &str) -> S3Config {
            let mut config = S3Config::with_bucket(bucket.to_string());
            config.region = Some("us-east-1".to_string());
            config.endpoint = Some(self.endpoint.clone());
            config.credentials = Some(S3Credentials {
                access_key_id: "key".to_string(),
                secret_access_key: "secret".to_string(),
                session_token: None,
            });
            config
        }

        pub fn requests(&self) -> Vec<Recorded> {
            self.requests.lock().expect("recorder").clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_a_backup_whose_sidecar_fails_is_removed() {
        // A bucket policy, throttling or a network error rejects the sidecar after the
        // object went through.
        let fake = fake_s3::FakeS3::start(Arc::new(|request: &fake_s3::Recorded| {
            match request.method.as_str() {
                "PUT" if request.path.ends_with(".metadata.json") => {
                    fake_s3::error(403, "AccessDenied")
                }
                // A new backup: no sidecar existed before.
                "HEAD" => (404, vec![], String::new()),
                _ => fake_s3::ok(request),
            }
        }))
        .await;
        let client = S3ClientWrapper::new(fake.config("bucket"))
            .await
            .expect("client");

        let err = client
            .upload_backup(
                b"artifact",
                "backup-2024-01-01T22:00:00Z.json.gz",
                "2024-01-01T22:00:00Z",
                BackupCompression::Gzip,
                None,
            )
            .await
            .expect_err("a backup without its sidecar must fail");
        assert!(err.to_string().contains("metadata"), "{err}");

        let requests: Vec<(String, String)> = fake
            .requests()
            .into_iter()
            .map(|request| (request.method, request.path))
            .collect();
        assert_eq!(
            requests.last(),
            Some(&(
                "DELETE".to_string(),
                "/bucket/backup-2024-01-01T22:00:00Z.json.gz".to_string()
            )),
            "the object left without a sidecar must be removed: {requests:?}"
        );
    }

    #[tokio::test]
    async fn test_an_existing_object_whose_new_sidecar_fails_is_kept() {
        // A replica copied again over an existing pair: the object goes through, the new
        // sidecar does not, and the old one is still there.
        let fake = fake_s3::FakeS3::start(Arc::new(|request: &fake_s3::Recorded| {
            if request.method == "PUT" && request.path.ends_with(".metadata.json") {
                fake_s3::error(403, "AccessDenied")
            } else {
                fake_s3::ok(request)
            }
        }))
        .await;
        let client = S3ClientWrapper::new(fake.config("bucket"))
            .await
            .expect("client");

        client
            .upload_with_metadata(
                Bytes::from_static(b"artifact"),
                "backup-2024-01-01T22:00:00Z.json.gz",
                &metadata("checksum", "2024-01-01T22:00:00Z", 8),
            )
            .await
            .expect_err("an object without its sidecar must fail");
        let requests = fake.requests();
        assert!(
            requests.iter().all(|request| request.method != "DELETE"),
            "an object that existed before must not be removed: {requests:?}"
        );
    }

    #[tokio::test]
    async fn test_a_document_is_one_object_and_only_a_missing_key_is_absent() {
        let objects = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
        let fake = fake_s3::FakeS3::start(fake_s3::store(Arc::clone(&objects))).await;
        let client = S3ClientWrapper::new(fake.config("bucket"))
            .await
            .expect("client");

        assert_eq!(
            client
                .download_document_if_exists("doc.json")
                .await
                .expect("absent"),
            None
        );
        client
            .upload_document(
                Bytes::from_static(b"{}"),
                "doc.json",
                "2024-01-01T22:00:00Z",
            )
            .await
            .expect("upload");
        assert_eq!(
            objects.lock().expect("objects").keys().collect::<Vec<_>>(),
            vec!["/bucket/doc.json"],
            "a document has no sidecar"
        );
        // A sidecar left by an earlier version, whatever it says, is not read.
        objects.lock().expect("objects").insert(
            "/bucket/doc.json.metadata.json".to_string(),
            b"not a sidecar".to_vec(),
        );
        assert_eq!(
            client
                .download_document_if_exists("doc.json")
                .await
                .expect("present"),
            Some(b"{}".to_vec())
        );

        // Damaged behind the checksum stored with it.
        objects
            .lock()
            .expect("objects")
            .insert("/bucket/doc.json".to_string(), b"{\"x\":1}".to_vec());
        assert!(matches!(
            client.download_document_if_exists("doc.json").await,
            Err(S3BackupError::InvalidChecksum { .. })
        ));

        // A bucket that does not exist is not an absent document.
        let missing_bucket = fake_s3::FakeS3::start(Arc::new(|_: &fake_s3::Recorded| {
            fake_s3::error(404, "NoSuchBucket")
        }))
        .await;
        let client = S3ClientWrapper::new(missing_bucket.config("bucket"))
            .await
            .expect("client");
        let err = client
            .download_document_if_exists("doc.json")
            .await
            .expect_err("a missing bucket must fail");
        assert!(err.to_string().contains("NoSuchBucket"), "{err}");
    }

    #[tokio::test]
    async fn test_multipart_upload_without_an_upload_id_fails() {
        // A CreateMultipartUpload answer without an UploadId.
        let fake = fake_s3::FakeS3::start(Arc::new(|request: &fake_s3::Recorded| {
            if request.method == "POST" && request.query.starts_with("uploads") {
                (
                    200,
                    vec![("content-type", "application/xml".to_string())],
                    "<InitiateMultipartUploadResult><Bucket>bucket</Bucket>\
                     <Key>big</Key></InitiateMultipartUploadResult>"
                        .to_string(),
                )
            } else {
                fake_s3::ok(request)
            }
        }))
        .await;
        let client = S3ClientWrapper::new(fake.config("bucket"))
            .await
            .expect("client");

        let err = client
            .upload_multipart(
                Bytes::from_static(b"artifact"),
                "big",
                &metadata("checksum", "2024-01-01T22:00:00Z", 8),
            )
            .await
            .expect_err("an upload without an id must fail");
        assert!(err.to_string().contains("without an upload id"), "{err}");
        // Nothing was sent with an empty upload id.
        let requests = fake.requests();
        assert_eq!(requests.len(), 1, "{requests:?}");
    }

    #[tokio::test]
    async fn test_an_interrupted_multipart_upload_is_aborted() {
        let fake = fake_s3::FakeS3::start(Arc::new(fake_s3::ok)).await;
        let client = S3ClientWrapper::new(fake.config("bucket"))
            .await
            .expect("client");

        // Disarmed: the caller handled the outcome, nothing is sent.
        let mut guard = MultipartAbortGuard::new(
            client.client.clone(),
            "bucket".to_string(),
            "done".to_string(),
            "id-1".to_string(),
        );
        guard.disarm();
        drop(guard);

        // Dropped while armed, as when the upload future is dropped half way.
        drop(MultipartAbortGuard::new(
            client.client.clone(),
            "bucket".to_string(),
            "interrupted".to_string(),
            "id-2".to_string(),
        ));

        let aborted = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let requests = fake.requests();
                if !requests.is_empty() {
                    return requests;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the abort must be sent");
        assert_eq!(aborted.len(), 1, "{aborted:?}");
        assert_eq!(aborted[0].method, "DELETE");
        assert_eq!(aborted[0].path, "/bucket/interrupted");
        assert!(
            aborted[0].query.contains("uploadId=id-2"),
            "{:?}",
            aborted[0]
        );
    }

    #[tokio::test]
    async fn test_a_failed_multipart_upload_dropped_during_its_abort_is_still_aborted() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Condvar, Mutex};

        // A part fails, and the explicit abort hangs until the test releases it.
        let aborts = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let fake = {
            let aborts = Arc::clone(&aborts);
            let gate = Arc::clone(&gate);
            fake_s3::FakeS3::start(Arc::new(move |request: &fake_s3::Recorded| {
                match request.method.as_str() {
                    "POST" if request.query.starts_with("uploads") => (
                        200,
                        vec![("content-type", "application/xml".to_string())],
                        "<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>big</Key>\
                         <UploadId>id-1</UploadId></InitiateMultipartUploadResult>"
                            .to_string(),
                    ),
                    "PUT" => fake_s3::error(403, "AccessDenied"),
                    "DELETE" => {
                        if aborts.fetch_add(1, Ordering::SeqCst) == 0 {
                            let (released, wakeup) = &*gate;
                            let released = released.lock().expect("gate");
                            let _released = wakeup
                                .wait_timeout_while(released, Duration::from_secs(10), |r| !*r)
                                .expect("gate");
                        }
                        fake_s3::ok(request)
                    }
                    _ => fake_s3::ok(request),
                }
            }))
            .await
        };
        let client = S3ClientWrapper::new(fake.config("bucket"))
            .await
            .expect("client");

        // The upload is dropped, as on shutdown, while its explicit abort is in flight.
        let metadata = metadata("checksum", "2024-01-01T22:00:00Z", 8);
        let upload = client.upload_multipart(Bytes::from_static(b"artifact"), "big", &metadata);
        let abort_in_flight = async {
            while aborts.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::select! {
            _ = upload => panic!("the upload must still be aborting"),
            _ = tokio::time::timeout(Duration::from_secs(10), abort_in_flight) => {}
        }
        {
            let (released, wakeup) = &*gate;
            *released.lock().expect("gate") = true;
            wakeup.notify_all();
        }

        tokio::time::timeout(Duration::from_secs(10), async {
            while aborts.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the guard must abort the upload whose explicit abort was dropped");
        assert!(fake
            .requests()
            .iter()
            .filter(|request| request.method == "DELETE")
            .all(|request| request.query.contains("uploadId=id-1")));
    }

    #[tokio::test]
    async fn test_a_replication_run_compares_every_backup_once() {
        let objects = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
        let fake = fake_s3::FakeS3::start(fake_s3::store(Arc::clone(&objects))).await;
        let primary = S3ClientWrapper::new(fake.config("primary"))
            .await
            .expect("client");
        let region_s3 = fake.config("replica");
        let replication = ReplicationConfig {
            enabled: true,
            regions: vec![ReplicationRegionConfig {
                name: Some("dr".to_string()),
                region: "us-east-1".to_string(),
                endpoint: region_s3.endpoint.clone(),
                bucket: region_s3.bucket.clone(),
                path_prefix: None,
                credentials: region_s3.credentials.clone(),
                server_side_encryption: None,
                storage_class: "STANDARD".to_string(),
                kms_key_id: None,
            }],
            ..ReplicationConfig::default()
        };

        let keys = [
            "backup-2024-01-01T22:00:00Z.json.gz",
            "backup-2024-01-02T22:00:00Z.json.gz",
        ];
        for (day, key) in keys.iter().enumerate() {
            primary
                .upload_backup(
                    format!("artifact-{day}").as_bytes(),
                    key,
                    &format!("2024-01-0{}T22:00:00Z", day + 1),
                    BackupCompression::Gzip,
                    None,
                )
                .await
                .expect("upload");
        }

        let primary_sidecar_reads = |requests: &[fake_s3::Recorded]| {
            requests
                .iter()
                .filter(|request| {
                    request.method == "GET"
                        && request.path.starts_with("/primary/")
                        && request.path.ends_with(".metadata.json")
                })
                .count()
        };

        // The region misses both: the run copies them and reports the region as healthy,
        // from one comparison, reading each primary sidecar once.
        let before = fake.requests().len();
        let report = primary
            .sync_and_check_replication(&replication, None)
            .await
            .expect("sync");
        let run = fake.requests().split_off(before);
        let (name, outcome) = report.synced.first().expect("one region");
        assert_eq!(name, "dr");
        assert_eq!(outcome.as_ref().expect("synced").copied, keys);
        assert_eq!(report.health.overall_status, ReplicationStatus::Completed);
        assert_eq!(report.health.regions[0].region, "dr");
        assert_eq!(report.health.regions[0].backups_replicated, 2);
        // Once to compare and once by each copy, which checks the downloaded bytes.
        assert_eq!(primary_sidecar_reads(&run), 2 + 2, "{run:#?}");
        assert_eq!(
            run.iter()
                .filter(|request| request.query.contains("list-type=2"))
                .count(),
            2,
            "the primary and the region are listed once each"
        );

        // Nothing is missing any more: the next run copies nothing and reads every
        // primary sidecar once, where sync and health check used to read it twice.
        let before = fake.requests().len();
        let report = primary
            .sync_and_check_replication(&replication, None)
            .await
            .expect("sync");
        let run = fake.requests().split_off(before);
        assert!(report.synced[0]
            .1
            .as_ref()
            .expect("synced")
            .copied
            .is_empty());
        assert_eq!(report.health.overall_status, ReplicationStatus::Completed);
        assert_eq!(primary_sidecar_reads(&run), 2, "{run:#?}");
        assert!(objects
            .lock()
            .expect("objects")
            .contains_key("/replica/backup-2024-01-02T22:00:00Z.json.gz.metadata.json"));
    }

    #[test]
    fn test_backup_listing_counts_only_backups_with_a_sidecar() {
        let keys = [
            "backup-2024-01-03T22:00:00Z.json.gz",
            "backup-2024-01-03T22:00:00Z.json.gz.metadata.json",
            "backup-2024-01-02T22:00:00Z.json.gz",
            "backup-2024-01-01T22:00:00Z.json.gz",
            "backup-2024-01-01T22:00:00Z.json.gz.metadata.json",
            "pitr-manifest.json",
            "pitr-manifest.json.metadata.json",
            "wal/segment.bin",
        ]
        .map(str::to_string)
        .to_vec();

        let listing = BackupListing::from_keys(&keys);
        assert_eq!(
            listing.complete,
            [
                "backup-2024-01-01T22:00:00Z.json.gz",
                "backup-2024-01-03T22:00:00Z.json.gz"
            ]
        );
        assert_eq!(listing.incomplete, ["backup-2024-01-02T22:00:00Z.json.gz"]);
    }

    #[tokio::test]
    async fn test_every_object_is_written_with_the_configured_encryption() {
        let fake = fake_s3::FakeS3::start(Arc::new(fake_s3::ok)).await;
        let mut config = fake.config("bucket");
        config.server_side_encryption = Some(S3ServerSideEncryption {
            algorithm: Some(S3EncryptionAlgorithm::AwsKms),
            kms_key_id: Some("backup-key".to_string()),
        });
        let client = S3ClientWrapper::new(config).await.expect("client");

        client
            .upload_backup(
                b"artifact",
                "backup-2024-01-01T22:00:00Z.json.gz",
                "2024-01-01T22:00:00Z",
                BackupCompression::Gzip,
                None,
            )
            .await
            .expect("upload");

        let puts: Vec<_> = fake
            .requests()
            .into_iter()
            .filter(|request| request.method == "PUT")
            .collect();
        let paths: Vec<&str> = puts.iter().map(|put| put.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/bucket/backup-2024-01-01T22:00:00Z.json.gz",
                "/bucket/backup-2024-01-01T22:00:00Z.json.gz.metadata.json"
            ]
        );
        // The sidecar too: a bucket policy that denies unencrypted uploads, or requires
        // this key, must accept it.
        for put in &puts {
            assert_eq!(
                put.header("x-amz-server-side-encryption"),
                Some("aws:kms"),
                "{}",
                put.path
            );
            assert_eq!(
                put.header("x-amz-server-side-encryption-aws-kms-key-id"),
                Some("backup-key"),
                "{}",
                put.path
            );
        }
    }

    #[tokio::test]
    async fn test_sdk_config_bounds_every_request() {
        let mut config = S3Config::with_bucket("bucket".to_string());
        config.region = Some("us-east-1".to_string());
        config.endpoint = Some("http://127.0.0.1:1".to_string());
        config.credentials = Some(S3Credentials {
            access_key_id: "key".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: None,
        });

        let sdk_config = S3ClientWrapper::build_sdk_config(&config)
            .await
            .expect("sdk config");
        let timeouts = sdk_config
            .timeout_config()
            .expect("timeouts are configured");
        assert_eq!(timeouts.connect_timeout(), Some(S3_CONNECT_TIMEOUT));
        assert_eq!(
            timeouts.operation_attempt_timeout(),
            Some(S3_ATTEMPT_TIMEOUT)
        );
        assert_eq!(timeouts.operation_timeout(), Some(S3_OPERATION_TIMEOUT));
    }
    use kubidm_proto::backup::{S3Credentials, S3ServerSideEncryption};
    use std::io::Cursor;

    #[test]
    fn test_storage_class_conversion() {
        assert_eq!(parse_storage_class("STANDARD"), Ok(StorageClass::Standard));
        assert_eq!(parse_storage_class("standard"), Ok(StorageClass::Standard));
        assert_eq!(
            parse_storage_class("REDUCED_REDUNDANCY"),
            Ok(StorageClass::ReducedRedundancy)
        );
        assert_eq!(
            parse_storage_class("reduced_redundancy"),
            Ok(StorageClass::ReducedRedundancy)
        );
        assert_eq!(
            parse_storage_class("STANDARD_IA"),
            Ok(StorageClass::StandardIa)
        );
        assert_eq!(
            parse_storage_class("ONEZONE_IA"),
            Ok(StorageClass::OnezoneIa)
        );
        assert_eq!(
            parse_storage_class("INTELLIGENT_TIERING"),
            Ok(StorageClass::IntelligentTiering)
        );
        assert_eq!(
            parse_storage_class("GLACIER_IR"),
            Ok(StorageClass::GlacierIr)
        );

        // A typo no longer silently becomes STANDARD.
        let err = parse_storage_class("STANDARD-IA").expect_err("unknown class");
        assert!(err.contains("not a known"), "{err}");
        // Archive classes can not be read back without a restore request.
        for archive in ["GLACIER", "deep_archive"] {
            let err = parse_storage_class(archive).expect_err("archive class");
            assert!(err.contains("archive class"), "{err}");
        }
    }

    #[test]
    fn test_validate_s3_location() {
        let mut config = S3Config::with_bucket("backups".to_string());
        assert!(validate_s3_location(&config).is_ok());

        config.storage_class = "DEEP_ARCHIVE".to_string();
        assert!(validate_s3_location(&config).is_err());
        config.storage_class = "STANDARD".to_string();

        config.server_side_encryption = Some(S3ServerSideEncryption {
            algorithm: Some(S3EncryptionAlgorithm::AwsKms),
            kms_key_id: Some("key".to_string()),
        });
        assert!(validate_s3_location(&config).is_ok());

        // S3 rejects every upload that sends both.
        config.server_side_encryption = Some(S3ServerSideEncryption {
            algorithm: Some(S3EncryptionAlgorithm::Aes256),
            kms_key_id: Some("key".to_string()),
        });
        let err = validate_s3_location(&config).expect_err("AES256 with a KMS key");
        assert!(err.contains("aws:kms"), "{err}");
    }

    #[test]
    fn test_checksum_writer() {
        let mut writer = ChecksumWriter::new(Vec::new());
        writer.write_all(b"hello world").unwrap();
        let (data, checksum) = writer.finalize();

        assert_eq!(data, b"hello world");
        assert_eq!(checksum.len(), 64);
    }

    #[test]
    fn test_checksum_writer_empty() {
        let writer = ChecksumWriter::new(Vec::<u8>::new());
        let (data, checksum) = writer.finalize();

        assert_eq!(data, b"");
        assert_eq!(checksum.len(), 64);
        assert_eq!(
            checksum,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_checksum_writer_large_data() {
        let large_data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let mut writer = ChecksumWriter::new(Vec::<u8>::new());
        writer.write_all(&large_data).unwrap();
        let (data, checksum) = writer.finalize();

        assert_eq!(data.len(), 10000);
        assert_eq!(checksum.len(), 64);
    }

    #[test]
    fn test_checksum_writer_multiple_writes() {
        let mut writer = ChecksumWriter::new(Vec::<u8>::new());
        writer.write_all(b"hello").unwrap();
        writer.write_all(b" ").unwrap();
        writer.write_all(b"world").unwrap();
        let (data, checksum) = writer.finalize();

        assert_eq!(data, b"hello world");
        assert_eq!(checksum.len(), 64);

        let mut single_writer = ChecksumWriter::new(Vec::<u8>::new());
        single_writer.write_all(b"hello world").unwrap();
        let (_, single_checksum) = single_writer.finalize();

        assert_eq!(checksum, single_checksum);
    }

    #[test]
    fn test_checksum_reader() {
        let input = b"hello world".to_vec();
        let mut reader = ChecksumReader::new(&input[..]);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        let (_, checksum) = reader.finalize();

        assert_eq!(output, b"hello world");
        assert_eq!(checksum.len(), 64);
    }

    #[test]
    fn test_checksum_reader_empty() {
        let input: Vec<u8> = Vec::new();
        let mut reader = ChecksumReader::new(Cursor::new(input));
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        let (_, checksum) = reader.finalize();

        assert_eq!(output, b"");
        assert_eq!(checksum.len(), 64);
        assert_eq!(
            checksum,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_checksum_reader_writer_consistency() {
        let data = b"test data for consistency check";
        let mut writer = ChecksumWriter::new(Vec::<u8>::new());
        writer.write_all(data).unwrap();
        let (written_data, write_checksum) = writer.finalize();

        let mut reader = ChecksumReader::new(Cursor::new(written_data));
        let mut read_data = Vec::new();
        reader.read_to_end(&mut read_data).unwrap();
        let (_, read_checksum) = reader.finalize();

        assert_eq!(read_data, data);
        assert_eq!(write_checksum, read_checksum);
    }

    #[test]
    fn test_replication_region_config_display() {
        let config = ReplicationRegionConfig {
            name: None,
            region: "eu-west-1".to_string(),
            bucket: "backup-eu".to_string(),
            endpoint: Some("https://s3.eu-west-1.amazonaws.com".to_string()),
            path_prefix: None,
            credentials: None,
            server_side_encryption: None,
            storage_class: "STANDARD".to_string(),
            kms_key_id: None,
        };
        assert!(config.to_string().contains("eu-west-1"));
        assert!(config.to_string().contains("backup-eu"));
    }

    #[test]
    fn test_replication_config_display() {
        let config = ReplicationConfig {
            enabled: true,
            regions: vec![],
            sync_interval_seconds: 600,
        };
        assert!(config.to_string().contains("enabled: true"));
        assert!(config.to_string().contains("600s"));
    }

    #[test]
    fn test_s3_backup_error_display() {
        let err = S3BackupError::ConfigError("invalid bucket name".to_string());
        assert!(err.to_string().contains("S3 configuration error"));
        assert!(err.to_string().contains("invalid bucket name"));

        let err = S3BackupError::UploadError("connection timeout".to_string());
        assert!(err.to_string().contains("S3 upload error"));

        let err = S3BackupError::DownloadError("object not found".to_string());
        assert!(err.to_string().contains("S3 download error"));

        let err = S3BackupError::InvalidChecksum {
            expected: "abc123".to_string(),
            actual: "def456".to_string(),
        };
        assert!(err.to_string().contains("Checksum mismatch"));
        assert!(err.to_string().contains("abc123"));
        assert!(err.to_string().contains("def456"));

        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let err = S3BackupError::from(io_err);
        assert!(err.to_string().contains("IO error"));

        let err = S3BackupError::SdkError("service unavailable".to_string());
        assert!(err.to_string().contains("AWS SDK error"));
    }

    #[test]
    fn test_build_object_key_no_prefix() {
        assert_eq!(
            build_test_object_key(None, "backup.tar.gz"),
            "backup.tar.gz"
        );
        assert_eq!(
            build_test_object_key(None, "backups/2024/backup.tar.gz"),
            "backups/2024/backup.tar.gz"
        );
    }

    #[test]
    fn test_build_object_key_with_prefix() {
        assert_eq!(
            build_test_object_key(Some("kubidm/backups"), "backup.tar.gz"),
            "kubidm/backups/backup.tar.gz"
        );
    }

    #[test]
    fn test_build_object_key_with_trailing_slash_prefix() {
        assert_eq!(
            build_test_object_key(Some("kubidm/backups/"), "backup.tar.gz"),
            "kubidm/backups/backup.tar.gz"
        );
    }

    fn build_test_object_key(prefix: Option<&str>, key: &str) -> String {
        S3ClientWrapper::build_object_key_with_prefix(prefix, key)
    }

    #[test]
    fn test_build_object_key_with_empty_prefix() {
        assert_eq!(
            build_test_object_key(Some(""), "backup.tar.gz"),
            "backup.tar.gz"
        );
        assert_eq!(
            build_test_object_key(Some("/"), "backup.tar.gz"),
            "backup.tar.gz"
        );
    }

    #[test]
    fn test_listing_prefix_empty() {
        assert_eq!(S3ClientWrapper::listing_prefix(None), "");
        assert_eq!(S3ClientWrapper::listing_prefix(Some("")), "");
        assert_eq!(S3ClientWrapper::listing_prefix(Some("/")), "");
    }

    #[test]
    fn test_listing_prefix_without_trailing_slash() {
        assert_eq!(S3ClientWrapper::listing_prefix(Some("prod")), "prod/");
        assert_eq!(
            S3ClientWrapper::listing_prefix(Some("kubidm/backups")),
            "kubidm/backups/"
        );
    }

    #[test]
    fn test_listing_prefix_with_trailing_slash() {
        assert_eq!(S3ClientWrapper::listing_prefix(Some("prod/")), "prod/");
        assert_eq!(S3ClientWrapper::listing_prefix(Some("prod//")), "prod/");
    }

    /// The listing prefix and the object keys written by the server must agree, so that
    /// listing and retention find exactly what was uploaded.
    #[test]
    fn test_listing_prefix_matches_built_keys() {
        for prefix in [None, Some(""), Some("prod"), Some("prod/"), Some("a/b/c")] {
            let listing = S3ClientWrapper::listing_prefix(prefix);
            let key = build_test_object_key(prefix, "backup-2024-01-01T22:00:00Z.json.gz");
            assert_eq!(
                S3ClientWrapper::strip_listing_prefix(&listing, &key),
                Some("backup-2024-01-01T22:00:00Z.json.gz"),
                "prefix {prefix:?}"
            );
            assert_eq!(
                S3ClientWrapper::strip_listing_prefix(&listing, &format!("{key}.metadata.json")),
                Some("backup-2024-01-01T22:00:00Z.json.gz.metadata.json"),
                "prefix {prefix:?}"
            );
        }
    }

    #[test]
    fn test_strip_listing_prefix_empty_prefix() {
        assert_eq!(
            S3ClientWrapper::strip_listing_prefix("", "backup-2024-01-01T22:00:00Z.json.gz"),
            Some("backup-2024-01-01T22:00:00Z.json.gz")
        );
        assert_eq!(
            S3ClientWrapper::strip_listing_prefix("", "production/backup.json.gz"),
            Some("production/backup.json.gz")
        );
    }

    #[test]
    fn test_strip_listing_prefix_strips_only_own_prefix() {
        let listing = S3ClientWrapper::listing_prefix(Some("prod"));
        assert_eq!(
            S3ClientWrapper::strip_listing_prefix(
                &listing,
                "prod/backup-2024-01-01T22:00:00Z.json.gz"
            ),
            Some("backup-2024-01-01T22:00:00Z.json.gz")
        );
        assert_eq!(
            S3ClientWrapper::strip_listing_prefix(&listing, "prod/nested/backup.json.gz"),
            Some("nested/backup.json.gz")
        );
    }

    /// Issue #459: an object under the sibling prefix `production/` must neither be treated
    /// as ours nor be mangled into `uction/backup-...`.
    #[test]
    fn test_strip_listing_prefix_rejects_sibling_prefix() {
        let listing = S3ClientWrapper::listing_prefix(Some("prod"));
        assert_eq!(listing, "prod/");
        assert_eq!(
            S3ClientWrapper::strip_listing_prefix(
                &listing,
                "production/backup-2024-01-01T22:00:00Z.json.gz"
            ),
            None
        );
        assert_eq!(
            S3ClientWrapper::strip_listing_prefix(&listing, "prod"),
            None
        );
        assert_eq!(
            S3ClientWrapper::strip_listing_prefix(&listing, "other/backup.json.gz"),
            None
        );
    }

    #[test]
    fn test_same_s3_location() {
        let base = S3Config {
            bucket: "backups".to_string(),
            region: Some("us-east-1".to_string()),
            endpoint: Some("https://s3.example.com".to_string()),
            path_prefix: Some("prod".to_string()),
            credentials: None,
            server_side_encryption: None,
            storage_class: "STANDARD".to_string(),
            replication: None,
        };
        let with = |change: fn(&mut S3Config)| {
            let mut config = base.clone();
            change(&mut config);
            config
        };

        assert!(same_s3_location(&base, &base));
        // Signing region, storage class and the spelling of prefix and endpoint do not
        // make another location.
        assert!(same_s3_location(
            &base,
            &with(|c| {
                c.region = Some("eu-west-1".to_string());
                c.storage_class = "STANDARD_IA".to_string();
                c.path_prefix = Some("prod/".to_string());
                c.endpoint = Some("https://S3.example.com/".to_string());
            })
        ));
        assert!(!same_s3_location(
            &base,
            &with(|c| c.bucket = "backups-eu".to_string())
        ));
        assert!(!same_s3_location(
            &base,
            &with(|c| c.path_prefix = Some("dr".to_string()))
        ));
        assert!(!same_s3_location(&base, &with(|c| c.path_prefix = None)));
        assert!(!same_s3_location(
            &base,
            &with(|c| c.endpoint = Some("https://s3.eu.example.com".to_string()))
        ));
        assert!(!same_s3_location(&base, &with(|c| c.endpoint = None)));

        // On AWS, the default endpoint and any explicit AWS endpoint reach the same bucket.
        let aws = with(|c| c.endpoint = None);
        for endpoint in [
            "https://s3.amazonaws.com",
            "https://s3.eu-west-1.amazonaws.com/",
            "s3.dualstack.us-east-1.amazonaws.com",
            "https://s3-accelerate.amazonaws.com",
            "https://s3.cn-north-1.amazonaws.com.cn",
        ] {
            let mut explicit = aws.clone();
            explicit.endpoint = Some(endpoint.to_string());
            assert!(same_s3_location(&aws, &explicit), "{endpoint}");
        }
        // The scheme does not make another location either.
        assert!(same_s3_location(
            &base,
            &with(|c| c.endpoint = Some("http://s3.example.com".to_string()))
        ));
        // A look-alike host is not AWS.
        assert!(!same_s3_location(
            &aws,
            &with(|c| c.endpoint = Some("https://s3.amazonaws.com.example.com".to_string()))
        ));
    }

    #[test]
    fn test_s3_backup_metadata_creation() {
        let metadata = S3BackupMetadata::new(
            "abc123def456".to_string(),
            "2024-01-15T10:30:00Z".to_string(),
            BackupCompression::Gzip,
            1024,
        );

        assert_eq!(metadata.checksum_sha256, "abc123def456");
        assert_eq!(metadata.timestamp, "2024-01-15T10:30:00Z");
        assert_eq!(metadata.compression, BackupCompression::Gzip);
        assert_eq!(metadata.size_bytes, 1024);
        assert!(!metadata.encrypted);
        assert!(metadata.key_identifier.is_none());
    }

    #[test]
    fn test_s3_backup_metadata_encrypted() {
        let metadata = S3BackupMetadata::new_encrypted(
            "abc123def456".to_string(),
            "2024-01-15T10:30:00Z".to_string(),
            BackupCompression::Gzip,
            2048,
            "key-uuid-12345".to_string(),
        );

        assert!(metadata.encrypted);
        assert_eq!(metadata.key_identifier, Some("key-uuid-12345".to_string()));
        assert_eq!(metadata.size_bytes, 2048);
    }

    #[test]
    fn test_s3_backup_metadata_serialization() {
        let metadata = S3BackupMetadata::new(
            "checksum-value".to_string(),
            "2024-01-15T10:30:00Z".to_string(),
            BackupCompression::Gzip,
            4096,
        );

        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("checksum_sha256"));
        assert!(json.contains("checksum-value"));

        let deserialized: S3BackupMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.checksum_sha256, metadata.checksum_sha256);
        assert_eq!(deserialized.timestamp, metadata.timestamp);
        assert_eq!(deserialized.compression, metadata.compression);
        assert_eq!(deserialized.size_bytes, metadata.size_bytes);
    }

    #[test]
    fn test_s3_backup_metadata_no_compression() {
        let metadata = S3BackupMetadata::new(
            "checksum".to_string(),
            "2024-01-15T10:30:00Z".to_string(),
            BackupCompression::NoCompression,
            512,
        );

        assert_eq!(metadata.compression, BackupCompression::NoCompression);

        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: S3BackupMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.compression, BackupCompression::NoCompression);
    }

    #[test]
    fn test_s3_config_display() {
        let config = S3Config {
            bucket: "my-backup-bucket".to_string(),
            region: Some("us-west-2".to_string()),
            endpoint: Some("https://s3.us-west-2.amazonaws.com".to_string()),
            path_prefix: Some("kubidm".to_string()),
            credentials: None,
            server_side_encryption: None,
            storage_class: "STANDARD".to_string(),
            replication: None,
        };

        let display = config.to_string();
        assert!(display.contains("my-backup-bucket"));
        assert!(display.contains("us-west-2"));
        assert!(display.contains("https://s3.us-west-2.amazonaws.com"));
    }

    #[test]
    fn test_s3_config_with_replication_display() {
        let replication = ReplicationConfig {
            enabled: true,
            regions: vec![ReplicationRegionConfig {
                name: None,
                region: "eu-west-1".to_string(),
                bucket: "eu-backup".to_string(),
                endpoint: None,
                path_prefix: None,
                credentials: None,
                server_side_encryption: None,
                storage_class: "STANDARD".to_string(),
                kms_key_id: None,
            }],
            sync_interval_seconds: 300,
        };

        let config = S3Config {
            bucket: "primary-bucket".to_string(),
            region: Some("us-east-1".to_string()),
            endpoint: None,
            path_prefix: None,
            credentials: None,
            server_side_encryption: None,
            storage_class: "STANDARD".to_string(),
            replication: Some(replication),
        };

        let display = config.to_string();
        assert!(display.contains("replication_enabled: true"));
    }

    #[test]
    fn test_replication_config_default() {
        let config = ReplicationConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.regions.len(), 0);
        assert_eq!(config.sync_interval_seconds, 300);
    }

    #[test]
    fn test_replication_status_display() {
        assert_eq!(
            ReplicationStatus::NotConfigured.to_string(),
            "Not Configured"
        );
        assert_eq!(ReplicationStatus::Pending.to_string(), "Pending");
        assert_eq!(ReplicationStatus::InProgress.to_string(), "In Progress");
        assert_eq!(ReplicationStatus::Completed.to_string(), "Completed");
        assert_eq!(
            ReplicationStatus::Failed {
                error: "network error".to_string()
            }
            .to_string(),
            "Failed: network error"
        );
        assert_eq!(
            ReplicationStatus::Degraded {
                message: "missing backup".to_string()
            }
            .to_string(),
            "Degraded: missing backup"
        );
    }

    #[test]
    fn test_replication_health_check_display() {
        let check = ReplicationHealthCheck {
            overall_status: ReplicationStatus::Completed,
            regions: vec![],
            total_lag_seconds: 120,
            max_lag_seconds: 60,
            healthy_regions: 2,
            unhealthy_regions: 0,
            last_check_timestamp: "2024-01-15T10:30:00Z".to_string(),
        };

        let display = check.to_string();
        assert!(display.contains("Completed"));
        assert!(display.contains("healthy: 2"));
        assert!(display.contains("unhealthy: 0"));
        assert!(display.contains("max_lag: 60s"));
    }

    #[test]
    fn test_replication_lag_metrics_display() {
        let metrics = ReplicationLagMetrics {
            region: "ap-southeast-1".to_string(),
            lag_seconds: 450,
            pending_backups: 3,
            last_backup_timestamp: Some("2024-01-15T10:30:00Z".to_string()),
            replication_delay_seconds: 60,
        };

        let display = metrics.to_string();
        assert!(display.contains("ap-southeast-1"));
        assert!(display.contains("lag: 450s"));
        assert!(display.contains("pending: 3"));
    }

    #[test]
    fn test_replication_region_status_display() {
        let status = ReplicationRegionStatus {
            region: "us-west-2".to_string(),
            bucket: "backup-bucket".to_string(),
            status: ReplicationStatus::Completed,
            last_sync_timestamp: Some("2024-01-15T10:30:00Z".to_string()),
            last_sync_backup_id: Some("backup-123".to_string()),
            lag_seconds: Some(30),
            bytes_replicated: 1024000,
            backups_replicated: 10,
            pending_backups: 0,
            last_error: None,
        };

        let display = status.to_string();
        assert!(display.contains("us-west-2"));
        assert!(display.contains("backup-bucket"));
        assert!(display.contains("Completed"));
        assert!(display.contains("lag: 30s"));
        assert!(display.contains("backups: 10"));
        assert!(display.contains("bytes: 1024000"));
    }

    fn region_config(path_prefix: Option<&str>) -> ReplicationRegionConfig {
        ReplicationRegionConfig {
            name: None,
            region: "eu-west-1".to_string(),
            bucket: "eu-backup".to_string(),
            endpoint: Some("https://s3.eu.example.com".to_string()),
            path_prefix: path_prefix.map(str::to_string),
            credentials: None,
            server_side_encryption: None,
            storage_class: "STANDARD".to_string(),
            kms_key_id: None,
        }
    }

    /// Region keys are built through the same prefix handling as primary keys, so a
    /// region prefix with or without a trailing slash yields the same object key and the
    /// region listing strips exactly that prefix again.
    #[test]
    fn test_region_keys_behave_like_primary_keys() {
        for (prefix, expected) in [
            (None, "backup.tar.gz"),
            (Some(""), "backup.tar.gz"),
            (Some("replica/kubidm"), "replica/kubidm/backup.tar.gz"),
            (Some("replica/kubidm/"), "replica/kubidm/backup.tar.gz"),
        ] {
            let s3_config = region_config(prefix).to_s3_config();
            let key = S3ClientWrapper::build_object_key_with_prefix(
                s3_config.path_prefix.as_deref(),
                "backup.tar.gz",
            );
            assert_eq!(key, expected, "prefix {prefix:?}");

            let listing = S3ClientWrapper::listing_prefix(s3_config.path_prefix.as_deref());
            assert_eq!(
                S3ClientWrapper::strip_listing_prefix(&listing, &key),
                Some("backup.tar.gz"),
                "prefix {prefix:?}"
            );
        }
    }

    #[test]
    fn test_s3_location() {
        let mut config = S3Config::with_bucket("kubidm-backups".to_string());
        assert_eq!(s3_location(&config), "s3://kubidm-backups");
        config.path_prefix = Some("".to_string());
        assert_eq!(s3_location(&config), "s3://kubidm-backups");
        config.path_prefix = Some("prod".to_string());
        assert_eq!(s3_location(&config), "s3://kubidm-backups/prod");
        config.path_prefix = Some("prod/kubidm/".to_string());
        assert_eq!(s3_location(&config), "s3://kubidm-backups/prod/kubidm");

        let region = region_config(Some("dr/")).to_s3_config();
        assert_eq!(s3_location(&region), "s3://eu-backup/dr");
    }

    fn metadata(checksum: &str, timestamp: &str, size: u64) -> S3BackupMetadata {
        S3BackupMetadata::new(
            checksum.to_string(),
            timestamp.to_string(),
            BackupCompression::Gzip,
            size,
        )
    }

    #[test]
    fn test_replica_mismatch_agrees() {
        let primary = metadata("abc", "2024-01-01T22:00:00Z", 100);
        assert_eq!(replica_mismatch(&primary, &primary, Some(100)), None);
        // A service that reports no content length can not fail the size check.
        assert_eq!(replica_mismatch(&primary, &primary, None), None);
    }

    #[test]
    fn test_replica_mismatch_detects_divergence() {
        let primary = metadata("abc", "2024-01-01T22:00:00Z", 100);

        let other_checksum = metadata("def", "2024-01-01T22:00:00Z", 100);
        let reason = replica_mismatch(&primary, &other_checksum, Some(100)).expect("mismatch");
        assert!(reason.contains("checksum def"), "{reason}");

        let other_size = metadata("abc", "2024-01-01T22:00:00Z", 90);
        let reason = replica_mismatch(&primary, &other_size, Some(90)).expect("mismatch");
        assert!(reason.contains("records 90 bytes"), "{reason}");

        // Same sidecar, but the object in the region was truncated or replaced.
        let reason = replica_mismatch(&primary, &primary, Some(42)).expect("mismatch");
        assert!(reason.contains("is 42 bytes in the region"), "{reason}");
    }

    #[test]
    fn test_lag_seconds() {
        assert_eq!(
            lag_seconds("2024-01-01T22:00:00Z", "2024-01-01T22:00:00Z"),
            Some(0)
        );
        assert_eq!(
            lag_seconds("2024-01-02T22:00:00Z", "2024-01-01T22:00:00Z"),
            Some(86400)
        );
        // Offsets are honoured.
        assert_eq!(
            lag_seconds("2024-01-01T23:00:00+01:00", "2024-01-01T22:00:00Z"),
            Some(0)
        );
        // A replica newer than the primary is not behind.
        assert_eq!(
            lag_seconds("2024-01-01T22:00:00Z", "2024-01-02T22:00:00Z"),
            Some(0)
        );
        assert_eq!(lag_seconds("yesterday", "2024-01-01T22:00:00Z"), None);
        assert_eq!(lag_seconds("2024-01-01T22:00:00Z", ""), None);
    }

    #[test]
    fn test_degraded_message() {
        let problems: Vec<String> = (1..=2).map(|i| format!("backup-{i} is missing")).collect();
        assert_eq!(
            degraded_message(&problems, 5),
            "2 of 5 backups not replicated: backup-1 is missing; backup-2 is missing"
        );

        let problems: Vec<String> = (1..=5).map(|i| format!("backup-{i} is missing")).collect();
        let message = degraded_message(&problems, 7);
        assert!(message.starts_with("5 of 7 backups not replicated: backup-1 is missing; "));
        assert!(message.ends_with("; and 2 more"), "{message}");
        assert!(!message.contains("backup-4"), "{message}");
    }

    fn region_status(
        region: &str,
        status: ReplicationStatus,
        lag: Option<u64>,
    ) -> ReplicationRegionStatus {
        ReplicationRegionStatus {
            region: region.to_string(),
            bucket: format!("{region}-bucket"),
            status,
            last_sync_timestamp: Some("2024-01-01T22:00:00Z".to_string()),
            last_sync_backup_id: Some("backup-2024-01-01T22:00:00Z.json.gz".to_string()),
            lag_seconds: lag,
            bytes_replicated: 10,
            backups_replicated: 1,
            pending_backups: 0,
            last_error: None,
        }
    }

    #[test]
    fn test_region_unreachable_is_failed_with_everything_pending() {
        let status = region_unreachable(
            region_status("eu", ReplicationStatus::Completed, None),
            4,
            &S3BackupError::SdkError("connection refused".to_string()),
        );
        assert!(!region_is_healthy(&status));
        assert_eq!(status.pending_backups, 4);
        assert_eq!(
            status.status,
            ReplicationStatus::Failed {
                error: "AWS SDK error: connection refused".to_string()
            }
        );
        assert_eq!(
            status.last_error.as_deref(),
            Some("AWS SDK error: connection refused")
        );
    }

    #[test]
    fn test_summarise_health_no_regions() {
        let health = summarise_health(vec![], Some("2024-01-01T22:00:00Z"));
        assert_eq!(health.overall_status, ReplicationStatus::NotConfigured);
        assert_eq!(health.healthy_regions, 0);
        assert_eq!(health.unhealthy_regions, 0);
        assert_eq!(health.max_lag_seconds, 0);
        assert_eq!(health.last_check_timestamp, "2024-01-01T22:00:00Z");
    }

    #[test]
    fn test_summarise_health_all_healthy() {
        let health = summarise_health(
            vec![
                region_status("eu", ReplicationStatus::Completed, Some(0)),
                region_status("ap", ReplicationStatus::Completed, Some(120)),
            ],
            None,
        );
        assert_eq!(health.overall_status, ReplicationStatus::Completed);
        assert_eq!(health.healthy_regions, 2);
        assert_eq!(health.unhealthy_regions, 0);
        assert_eq!(health.total_lag_seconds, 120);
        assert_eq!(health.max_lag_seconds, 120);
        assert_eq!(health.last_check_timestamp, "");
    }

    #[test]
    fn test_summarise_health_degraded_and_failed() {
        let degraded = ReplicationStatus::Degraded {
            message: "1 of 3 backups not replicated".to_string(),
        };
        let health = summarise_health(
            vec![
                region_status("eu", ReplicationStatus::Completed, Some(0)),
                region_status("ap", degraded.clone(), Some(3600)),
            ],
            None,
        );
        assert_eq!(
            health.overall_status,
            ReplicationStatus::Degraded {
                message: "1 of 2 regions unhealthy".to_string()
            }
        );
        assert_eq!(health.healthy_regions, 1);
        assert_eq!(health.unhealthy_regions, 1);
        assert_eq!(health.max_lag_seconds, 3600);

        let failed = ReplicationStatus::Failed {
            error: "unreachable".to_string(),
        };
        let health = summarise_health(
            vec![
                region_status("eu", degraded, None),
                region_status("ap", failed, None),
            ],
            None,
        );
        assert_eq!(
            health.overall_status,
            ReplicationStatus::Failed {
                error: "all 2 regions unhealthy".to_string()
            }
        );
        assert_eq!(health.healthy_regions, 0);
        assert_eq!(health.unhealthy_regions, 2);
    }

    #[test]
    fn test_lag_metrics_from_health() {
        let mut lagging = region_status(
            "ap",
            ReplicationStatus::Degraded {
                message: "2 of 3 backups not replicated".to_string(),
            },
            Some(900),
        );
        lagging.pending_backups = 2;
        let health = summarise_health(
            vec![
                region_status("eu", ReplicationStatus::Completed, Some(0)),
                lagging,
            ],
            None,
        );
        let replication = ReplicationConfig {
            sync_interval_seconds: 600,
            ..ReplicationConfig::default()
        };

        let metrics = lag_metrics_from_health(&health, &replication);
        assert_eq!(metrics.len(), 2);
        assert_eq!(metrics[0].region, "eu");
        assert_eq!(metrics[0].lag_seconds, 0);
        assert_eq!(metrics[0].pending_backups, 0);
        assert_eq!(metrics[0].replication_delay_seconds, 600);
        assert_eq!(metrics[1].region, "ap");
        assert_eq!(metrics[1].lag_seconds, 900);
        assert_eq!(metrics[1].pending_backups, 2);
        assert_eq!(
            metrics[1].last_backup_timestamp.as_deref(),
            Some("2024-01-01T22:00:00Z")
        );
    }

    #[test]
    fn test_s3_credentials() {
        let creds = S3Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: Some("session-token-123".to_string()),
        };

        assert_eq!(creds.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert!(creds.session_token.is_some());
    }

    #[test]
    fn test_s3_credentials_no_session_token() {
        let creds = S3Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        };

        assert!(creds.session_token.is_none());
    }

    #[test]
    fn test_s3_server_side_encryption_aes256() {
        let sse = S3ServerSideEncryption {
            algorithm: Some(S3EncryptionAlgorithm::Aes256),
            kms_key_id: None,
        };

        assert_eq!(sse.algorithm, Some(S3EncryptionAlgorithm::Aes256));
        assert!(sse.kms_key_id.is_none());
    }

    #[test]
    fn test_s3_server_side_encryption_kms() {
        let sse = S3ServerSideEncryption {
            algorithm: Some(S3EncryptionAlgorithm::AwsKms),
            kms_key_id: Some(
                "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
                    .to_string(),
            ),
        };

        assert_eq!(sse.algorithm, Some(S3EncryptionAlgorithm::AwsKms));
        assert!(sse.kms_key_id.is_some());
    }

    #[test]
    fn test_s3_encryption_algorithm_display() {
        assert_eq!(S3EncryptionAlgorithm::Aes256.to_string(), "AES256");
        assert_eq!(S3EncryptionAlgorithm::AwsKms.to_string(), "aws:kms");
    }

    #[test]
    fn test_s3_encryption_algorithm_default() {
        let default = S3EncryptionAlgorithm::default();
        assert_eq!(default, S3EncryptionAlgorithm::AwsKms);
    }

    #[test]
    fn test_multipart_threshold() {
        assert_eq!(MULTIPART_THRESHOLD, 100 * 1024 * 1024);
    }

    #[test]
    fn test_multipart_chunk_size() {
        assert_eq!(MULTIPART_CHUNK_SIZE, 10 * 1024 * 1024);
    }

    #[test]
    fn test_checksum_sha256_consistency() {
        let data1 = b"test data";
        let checksum1 = hex_encode(Sha256::digest(data1));

        let data2 = b"test data";
        let checksum2 = hex_encode(Sha256::digest(data2));

        assert_eq!(checksum1, checksum2);
        assert_eq!(checksum1.len(), 64);
    }

    #[test]
    fn test_checksum_different_data() {
        let data1 = b"test data 1";
        let checksum1 = hex_encode(Sha256::digest(data1));

        let data2 = b"test data 2";
        let checksum2 = hex_encode(Sha256::digest(data2));

        assert_ne!(checksum1, checksum2);
    }

    #[test]
    fn test_s3_backup_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let s3_err: S3BackupError = io_err.into();

        assert!(matches!(s3_err, S3BackupError::IoError(_)));
        assert!(s3_err.to_string().contains("file not found"));
    }

    #[test]
    fn test_s3_config_serialization() {
        let config = S3Config {
            bucket: "test-bucket".to_string(),
            region: Some("us-east-1".to_string()),
            endpoint: Some("https://s3.example.com".to_string()),
            path_prefix: Some("kubidm/backups".to_string()),
            credentials: Some(S3Credentials {
                access_key_id: "key-id".to_string(),
                secret_access_key: "secret".to_string(),
                session_token: None,
            }),
            server_side_encryption: None,
            storage_class: "STANDARD".to_string(),
            replication: None,
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("test-bucket"));
        assert!(json.contains("us-east-1"));

        let deserialized: S3Config = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.bucket, config.bucket);
        assert_eq!(deserialized.region, config.region);
    }

    #[test]
    fn test_replication_region_config_serialization() {
        let config = ReplicationRegionConfig {
            name: None,
            region: "eu-west-1".to_string(),
            bucket: "eu-backup".to_string(),
            endpoint: Some("https://s3.eu-west-1.amazonaws.com".to_string()),
            path_prefix: Some("replica".to_string()),
            credentials: None,
            server_side_encryption: Some(S3ServerSideEncryption {
                algorithm: Some(S3EncryptionAlgorithm::AwsKms),
                kms_key_id: Some("kms-key-id".to_string()),
            }),
            storage_class: "STANDARD_IA".to_string(),
            kms_key_id: None,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ReplicationRegionConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.region, "eu-west-1");
        assert_eq!(deserialized.bucket, "eu-backup");
        assert_eq!(deserialized.storage_class, "STANDARD_IA");
    }

    #[test]
    fn test_replication_config_serialization() {
        let config = ReplicationConfig {
            enabled: true,
            regions: vec![
                ReplicationRegionConfig {
                    name: None,
                    region: "us-west-2".to_string(),
                    bucket: "west-backup".to_string(),
                    endpoint: None,
                    path_prefix: None,
                    credentials: None,
                    server_side_encryption: None,
                    storage_class: "STANDARD".to_string(),
                    kms_key_id: None,
                },
                ReplicationRegionConfig {
                    name: None,
                    region: "eu-west-1".to_string(),
                    bucket: "eu-backup".to_string(),
                    endpoint: None,
                    path_prefix: None,
                    credentials: None,
                    server_side_encryption: None,
                    storage_class: "STANDARD".to_string(),
                    kms_key_id: None,
                },
            ],
            sync_interval_seconds: 600,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ReplicationConfig = serde_json::from_str(&json).unwrap();

        assert!(deserialized.enabled);
        assert_eq!(deserialized.regions.len(), 2);
        assert_eq!(deserialized.sync_interval_seconds, 600);
    }

    #[test]
    fn test_empty_backup_name_handling() {
        let key = build_test_object_key(None, "");
        assert_eq!(key, "");
    }

    #[test]
    fn test_unicode_in_backup_key() {
        let key = build_test_object_key(Some("kubidm"), "backup-日本語-2024.tar.gz");
        assert!(key.contains("backup-日本語-2024.tar.gz"));
    }

    #[test]
    fn test_special_chars_in_backup_key() {
        let key = build_test_object_key(None, "backup-with-dashes_and_underscores.tar.gz");
        assert_eq!(key, "backup-with-dashes_and_underscores.tar.gz");
    }
}
