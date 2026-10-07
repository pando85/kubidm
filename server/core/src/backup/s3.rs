use std::io::{Read, Write};

use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_credential_types::Credentials;
use aws_sdk_s3::operation::create_multipart_upload::CreateMultipartUploadOutput;
use aws_sdk_s3::operation::get_object::GetObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    CompletedMultipartUpload, CompletedPart, ServerSideEncryption, StorageClass,
};
use aws_sdk_s3::Client as S3Client;
use hex::encode as hex_encode;
use kubidm_proto::backup::{
    BackupCompression, ReplicationConfig, ReplicationHealthCheck, ReplicationLagMetrics,
    ReplicationRegionConfig, ReplicationRegionStatus, ReplicationStatus, S3BackupMetadata,
    S3Config, S3EncryptionAlgorithm,
};
use sha2::{Digest, Sha256};

const MULTIPART_THRESHOLD: u64 = 100 * 1024 * 1024;
const MULTIPART_CHUNK_SIZE: usize = 10 * 1024 * 1024;

#[derive(Debug)]
pub enum S3BackupError {
    ConfigError(String),
    UploadError(String),
    DownloadError(String),
    CredentialsError(String),
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
            S3BackupError::CredentialsError(msg) => write!(f, "S3 credentials error: {}", msg),
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
        let mut config_builder = aws_config::defaults(BehaviorVersion::latest());

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

    /// Upload `data`, a complete backup artifact, as `key` under the configured prefix,
    /// followed by its `<key>.metadata.json` sidecar. `compression` is the compression of
    /// the backup and `encryption_key_identifier` the identifier of the key the artifact
    /// was encrypted with, if it is encrypted; both are recorded in the sidecar.
    pub async fn upload_backup(
        &self,
        data: Vec<u8>,
        key: &str,
        timestamp: &str,
        compression: BackupCompression,
        encryption_key_identifier: Option<&str>,
    ) -> Result<S3BackupMetadata, S3BackupError> {
        let size = data.len() as u64;
        let checksum = hex_encode(Sha256::digest(&data));
        let object_key = self.build_object_key(key);

        let metadata = match encryption_key_identifier {
            Some(key_identifier) => S3BackupMetadata::new_encrypted(
                checksum.clone(),
                timestamp.to_string(),
                compression,
                size,
                key_identifier.to_string(),
            ),
            None => {
                S3BackupMetadata::new(checksum.clone(), timestamp.to_string(), compression, size)
            }
        };

        if size > MULTIPART_THRESHOLD {
            self.upload_multipart(&data, &object_key, &metadata).await?;
        } else {
            self.upload_single(&data, &object_key, &metadata).await?;
        }

        self.upload_metadata(&object_key, &metadata).await?;

        Ok(metadata)
    }

    async fn upload_single(
        &self,
        data: &[u8],
        key: &str,
        metadata: &S3BackupMetadata,
    ) -> Result<(), S3BackupError> {
        let mut builder = self
            .client
            .put_object()
            .bucket(&self.config.bucket)
            .key(key)
            .body(ByteStream::from(data.to_vec()))
            .metadata("checksum-sha256", &metadata.checksum_sha256)
            .metadata("backup-timestamp", &metadata.timestamp)
            .metadata("backup-size", metadata.size_bytes.to_string())
            .storage_class(parse_storage_class(self.config.storage_class.as_str()));

        builder = self.apply_encryption(builder);

        builder
            .send()
            .await
            .map_err(|e| S3BackupError::UploadError(format!("Failed to upload backup: {}", e)))?;

        info!("Uploaded backup to S3: {}", key);
        Ok(())
    }

    async fn upload_multipart(
        &self,
        data: &[u8],
        key: &str,
        metadata: &S3BackupMetadata,
    ) -> Result<(), S3BackupError> {
        let create_output = self.create_multipart_upload(key, metadata).await?;
        let upload_id = create_output.upload_id().unwrap_or_default();

        let mut parts = Vec::new();

        for (part_number, chunk) in (1_i32..).zip(data.chunks(MULTIPART_CHUNK_SIZE)) {
            let part = self.upload_part(key, upload_id, part_number, chunk).await?;
            parts.push(
                CompletedPart::builder()
                    .part_number(part_number)
                    .e_tag(part.e_tag().unwrap_or_default())
                    .build(),
            );
        }

        self.complete_multipart_upload(key, upload_id, parts)
            .await?;
        info!("Completed multipart upload to S3: {}", key);
        Ok(())
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
            .storage_class(parse_storage_class(self.config.storage_class.as_str()));

        builder = self.apply_encryption_multipart(builder);

        builder.send().await.map_err(|e| {
            S3BackupError::UploadError(format!("Failed to create multipart upload: {}", e))
        })
    }

    async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        data: &[u8],
    ) -> Result<aws_sdk_s3::operation::upload_part::UploadPartOutput, S3BackupError> {
        self.client
            .upload_part()
            .bucket(&self.config.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(ByteStream::from(data.to_vec()))
            .send()
            .await
            .map_err(|e| {
                S3BackupError::UploadError(format!("Failed to upload part {}: {}", part_number, e))
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
                S3BackupError::UploadError(format!("Failed to complete multipart upload: {}", e))
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
            S3BackupError::UploadError(format!("Failed to serialize metadata: {}", e))
        })?;

        self.client
            .put_object()
            .bucket(&self.config.bucket)
            .key(&metadata_key)
            .body(ByteStream::from(metadata_json.into_bytes()))
            .content_type("application/json")
            .send()
            .await
            .map_err(|e| S3BackupError::UploadError(format!("Failed to upload metadata: {}", e)))?;

        Ok(())
    }

    fn apply_encryption(
        &self,
        mut builder: aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder,
    ) -> aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder {
        if let Some(sse) = &self.config.server_side_encryption {
            let sse_type = match &sse.algorithm {
                Some(S3EncryptionAlgorithm::Aes256) => ServerSideEncryption::Aes256,
                _ => ServerSideEncryption::AwsKms,
            };
            builder = builder.server_side_encryption(sse_type);
            if let Some(kms_key) = &sse.kms_key_id {
                builder = builder.ssekms_key_id(kms_key);
            }
        }
        builder
    }

    fn apply_encryption_multipart(
        &self,
        mut builder: aws_sdk_s3::operation::create_multipart_upload::builders::CreateMultipartUploadFluentBuilder,
    ) -> aws_sdk_s3::operation::create_multipart_upload::builders::CreateMultipartUploadFluentBuilder
    {
        if let Some(sse) = &self.config.server_side_encryption {
            let sse_type = match &sse.algorithm {
                Some(S3EncryptionAlgorithm::Aes256) => ServerSideEncryption::Aes256,
                _ => ServerSideEncryption::AwsKms,
            };
            builder = builder.server_side_encryption(sse_type);
            if let Some(kms_key) = &sse.kms_key_id {
                builder = builder.ssekms_key_id(kms_key);
            }
        }
        builder
    }

    pub async fn download_backup(
        &self,
        key: &str,
    ) -> Result<(Vec<u8>, S3BackupMetadata), S3BackupError> {
        let object_key = self.build_object_key(key);
        let metadata = self.download_metadata(&object_key).await?;
        let data = self.download_object(&object_key).await?;

        let actual_checksum = hex_encode(Sha256::digest(&data));
        if actual_checksum != metadata.checksum_sha256 {
            return Err(S3BackupError::InvalidChecksum {
                expected: metadata.checksum_sha256.clone(),
                actual: actual_checksum,
            });
        }

        info!("Downloaded and verified backup from S3: {}", object_key);
        Ok((data, metadata))
    }

    /// Download the whole object at `object_key` (a full key, prefix included).
    async fn download_object(&self, object_key: &str) -> Result<Vec<u8>, S3BackupError> {
        let output = self
            .client
            .get_object()
            .bucket(&self.config.bucket)
            .key(object_key)
            .send()
            .await
            .map_err(|e| {
                S3BackupError::DownloadError(format!("Failed to download backup: {}", e))
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
                S3BackupError::DownloadError(format!("Failed to download metadata: {}", e))
            })?;

        let data = self.collect_stream(output).await?;
        let metadata: S3BackupMetadata = serde_json::from_slice(&data).map_err(|e| {
            S3BackupError::DownloadError(format!("Failed to parse metadata: {}", e))
        })?;

        Ok(metadata)
    }

    async fn collect_stream(&self, output: GetObjectOutput) -> Result<Vec<u8>, S3BackupError> {
        let body = output
            .body
            .collect()
            .await
            .map_err(|e| S3BackupError::DownloadError(format!("Stream error: {}", e)))?;
        Ok(body.into_bytes().to_vec())
    }

    /// List every object under the configured prefix except metadata sidecars, with the
    /// prefix stripped. All pages of the listing are collected.
    ///
    /// The listing uses the `/`-terminated prefix of [`Self::listing_prefix`], so objects
    /// under a sibling prefix that merely starts with the same characters are never
    /// returned.
    pub async fn list_backups(&self) -> Result<Vec<String>, S3BackupError> {
        let prefix = Self::listing_prefix(self.config.path_prefix.as_deref());

        let mut pages = self
            .client
            .list_objects_v2()
            .bucket(&self.config.bucket)
            .prefix(&prefix)
            .into_paginator()
            .send();

        let mut backups = Vec::new();
        while let Some(page) = pages.next().await {
            let page = page
                .map_err(|e| S3BackupError::SdkError(format!("Failed to list objects: {}", e)))?;
            for obj in page.contents() {
                let Some(key) = obj.key() else {
                    continue;
                };
                if key.ends_with(".metadata.json") {
                    continue;
                }
                // S3 only returns keys starting with the requested prefix; anything else
                // is not ours and is skipped rather than mangled.
                if let Some(display_key) = Self::strip_listing_prefix(&prefix, key) {
                    backups.push(display_key.to_string());
                }
            }
        }

        Ok(backups)
    }

    pub async fn delete_backup(&self, key: &str) -> Result<(), S3BackupError> {
        let object_key = self.build_object_key(key);
        let metadata_key = format!("{}.metadata.json", object_key);

        self.client
            .delete_object()
            .bucket(&self.config.bucket)
            .key(&object_key)
            .send()
            .await
            .map_err(|e| S3BackupError::SdkError(format!("Failed to delete backup: {}", e)))?;

        self.client
            .delete_object()
            .bucket(&self.config.bucket)
            .key(&metadata_key)
            .send()
            .await
            .map_err(|e| S3BackupError::SdkError(format!("Failed to delete metadata: {}", e)))?;

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

        let head = self
            .client
            .head_object()
            .bucket(&self.config.bucket)
            .key(&object_key)
            .send()
            .await
            .map_err(|e| S3BackupError::SdkError(format!("Failed to head object: {}", e)))?;

        match head.content_length() {
            Some(actual_size) if actual_size as u64 != metadata.size_bytes => {
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
        let actual_checksum = hex_encode(Sha256::digest(&data));
        if actual_checksum != metadata.checksum_sha256 {
            warn!(
                "Backup checksum mismatch for {}: expected {}, got {}",
                object_key, metadata.checksum_sha256, actual_checksum
            );
            return Ok(false);
        }

        Ok(true)
    }

    pub async fn replicate_backup(
        &self,
        backup_key: &str,
        backup_data: Vec<u8>,
        metadata: &S3BackupMetadata,
        region_config: &ReplicationRegionConfig,
    ) -> Result<(), S3BackupError> {
        let region_wrapper = Self::create_region_wrapper(region_config).await?;
        let object_key = Self::build_region_object_key(region_config, backup_key);

        if backup_data.len() as u64 > MULTIPART_THRESHOLD {
            region_wrapper
                .upload_multipart(&backup_data, &object_key, metadata)
                .await?;
        } else {
            region_wrapper
                .upload_single(&backup_data, &object_key, metadata)
                .await?;
        }

        region_wrapper
            .upload_metadata(&object_key, metadata)
            .await?;

        info!(
            "Replicated backup {} to region {} bucket {}",
            backup_key, region_config.region, region_config.bucket
        );
        Ok(())
    }

    async fn create_region_wrapper(
        region_config: &ReplicationRegionConfig,
    ) -> Result<S3ClientWrapper, S3BackupError> {
        let sdk_config = Self::build_region_sdk_config(region_config).await?;
        let client = Self::build_client(&sdk_config, region_config.endpoint.is_some());

        let s3_config = kubidm_proto::backup::S3Config {
            bucket: region_config.bucket.clone(),
            region: Some(region_config.region.clone()),
            endpoint: region_config.endpoint.clone(),
            path_prefix: region_config.path_prefix.clone(),
            credentials: region_config.credentials.clone(),
            server_side_encryption: region_config.server_side_encryption.clone(),
            storage_class: region_config.storage_class.clone(),
            replication: None,
        };

        Ok(S3ClientWrapper {
            client,
            config: s3_config,
        })
    }

    async fn build_region_sdk_config(
        region_config: &ReplicationRegionConfig,
    ) -> Result<SdkConfig, S3BackupError> {
        let mut config_builder = aws_config::defaults(BehaviorVersion::latest());

        if let Some(endpoint) = &region_config.endpoint {
            config_builder = config_builder.endpoint_url(endpoint);
        }

        config_builder = config_builder.region(Region::new(region_config.region.clone()));

        if let Some(credentials) = &region_config.credentials {
            let creds = Credentials::new(
                credentials.access_key_id.clone(),
                credentials.secret_access_key.clone(),
                credentials.session_token.clone(),
                None,
                "kubidm-backup-replication",
            );
            config_builder = config_builder.credentials_provider(creds);
        }

        Ok(config_builder.load().await)
    }

    fn build_region_object_key(region_config: &ReplicationRegionConfig, key: &str) -> String {
        Self::build_object_key_with_prefix(region_config.path_prefix.as_deref(), key)
    }

    pub async fn check_region_replication_status(
        &self,
        region_config: &ReplicationRegionConfig,
        source_backups: &[String],
    ) -> Result<ReplicationRegionStatus, S3BackupError> {
        let region_wrapper = Self::create_region_wrapper(region_config).await?;

        let replicated_backups = region_wrapper.list_backups().await?;

        let mut status = ReplicationRegionStatus {
            region: region_config.region.clone(),
            bucket: region_config.bucket.clone(),
            status: ReplicationStatus::Completed,
            last_sync_timestamp: None,
            last_sync_backup_id: None,
            lag_seconds: None,
            bytes_replicated: 0,
            backups_replicated: 0,
            last_error: None,
        };

        for backup_key in source_backups {
            if replicated_backups.contains(backup_key) {
                status.backups_replicated += 1;
                let object_key = Self::build_region_object_key(region_config, backup_key);
                let (_, metadata) = region_wrapper.download_backup(&object_key).await?;
                status.bytes_replicated += metadata.size_bytes;
                status.last_sync_backup_id = Some(backup_key.clone());
                status.last_sync_timestamp = Some(metadata.timestamp.clone());
            } else {
                if status.status == ReplicationStatus::Completed {
                    status.status = ReplicationStatus::Degraded {
                        message: format!("Missing backup: {}", backup_key),
                    };
                }
            }
        }

        if let Some(last_sync_ts) = &status.last_sync_timestamp {
            if chrono::DateTime::parse_from_rfc3339(last_sync_ts).is_ok() {
                status.lag_seconds = Some(0);
            }
        }

        Ok(status)
    }

    pub async fn check_replication_health(
        &self,
        replication_config: &ReplicationConfig,
        current_timestamp: Option<&str>,
    ) -> Result<ReplicationHealthCheck, S3BackupError> {
        let source_backups = self.list_backups().await?;

        let mut regions = Vec::new();
        let mut max_lag = 0u64;
        let mut total_lag = 0u64;
        let mut healthy = 0usize;
        let mut unhealthy = 0usize;

        for region_config in &replication_config.regions {
            let region_status = self
                .check_region_replication_status(region_config, &source_backups)
                .await?;

            if let Some(lag) = region_status.lag_seconds {
                total_lag += lag;
                if lag > max_lag {
                    max_lag = lag;
                }
            }

            match &region_status.status {
                ReplicationStatus::Completed => healthy += 1,
                ReplicationStatus::Degraded { .. } | ReplicationStatus::Failed { .. } => {
                    unhealthy += 1
                }
                _ => {}
            }

            regions.push(region_status);
        }

        let overall_status = if unhealthy > 0 {
            if healthy == 0 {
                ReplicationStatus::Failed {
                    error: "All regions unhealthy".to_string(),
                }
            } else {
                ReplicationStatus::Degraded {
                    message: format!("{} regions unhealthy", unhealthy),
                }
            }
        } else if healthy > 0 {
            ReplicationStatus::Completed
        } else {
            ReplicationStatus::NotConfigured
        };

        let last_check_timestamp = current_timestamp.map(|s| s.to_string()).unwrap_or_default();

        Ok(ReplicationHealthCheck {
            overall_status,
            regions,
            total_lag_seconds: total_lag,
            max_lag_seconds: max_lag,
            healthy_regions: healthy,
            unhealthy_regions: unhealthy,
            last_check_timestamp,
        })
    }

    pub async fn get_replication_lag_metrics(
        &self,
        replication_config: &ReplicationConfig,
    ) -> Result<Vec<ReplicationLagMetrics>, S3BackupError> {
        let source_backups = self.list_backups().await?;
        let mut metrics = Vec::new();

        for region_config in &replication_config.regions {
            let region_status = self
                .check_region_replication_status(region_config, &source_backups)
                .await?;

            let pending = source_backups
                .iter()
                .filter(|b| region_status.last_sync_backup_id.as_ref() != Some(b))
                .count();

            metrics.push(ReplicationLagMetrics {
                region: region_config.region.clone(),
                lag_seconds: region_status.lag_seconds.unwrap_or(0),
                pending_backups: pending,
                last_backup_timestamp: region_status.last_sync_timestamp.clone(),
                replication_delay_seconds: replication_config.sync_interval_seconds,
            });
        }

        Ok(metrics)
    }
}

pub struct ChecksumWriter<W> {
    writer: W,
    hasher: Sha256,
}

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

impl<W: Write> Write for ChecksumWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

pub struct ChecksumReader<R> {
    reader: R,
    hasher: Sha256,
}

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

impl<R: Read> Read for ChecksumReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.reader.read(buf)?;
        if let Some(slice) = buf.get(..n) {
            self.hasher.update(slice);
        }
        Ok(n)
    }
}

fn parse_storage_class(s: &str) -> StorageClass {
    match s.to_uppercase().as_str() {
        "STANDARD" => StorageClass::Standard,
        "REDUCED_REDUNDANCY" => StorageClass::ReducedRedundancy,
        "STANDARD_IA" => StorageClass::StandardIa,
        "ONEZONE_IA" => StorageClass::OnezoneIa,
        "INTELLIGENT_TIERING" => StorageClass::IntelligentTiering,
        "GLACIER" => StorageClass::Glacier,
        "DEEP_ARCHIVE" => StorageClass::DeepArchive,
        "GLACIER_IR" => StorageClass::GlacierIr,
        _ => StorageClass::Standard,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kubidm_proto::backup::{S3Credentials, S3ServerSideEncryption};
    use std::io::Cursor;

    #[test]
    fn test_storage_class_conversion() {
        assert_eq!(parse_storage_class("STANDARD"), StorageClass::Standard);
        assert_eq!(parse_storage_class("standard"), StorageClass::Standard);
        assert_eq!(parse_storage_class("GLACIER"), StorageClass::Glacier);
        assert_eq!(parse_storage_class("unknown"), StorageClass::Standard);
        assert_eq!(
            parse_storage_class("REDUCED_REDUNDANCY"),
            StorageClass::ReducedRedundancy
        );
        assert_eq!(
            parse_storage_class("reduced_redundancy"),
            StorageClass::ReducedRedundancy
        );
        assert_eq!(parse_storage_class("STANDARD_IA"), StorageClass::StandardIa);
        assert_eq!(parse_storage_class("ONEZONE_IA"), StorageClass::OnezoneIa);
        assert_eq!(
            parse_storage_class("INTELLIGENT_TIERING"),
            StorageClass::IntelligentTiering
        );
        assert_eq!(
            parse_storage_class("DEEP_ARCHIVE"),
            StorageClass::DeepArchive
        );
        assert_eq!(parse_storage_class("GLACIER_IR"), StorageClass::GlacierIr);
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
            max_retries: 5,
            retry_delay_seconds: 60,
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

        let err = S3BackupError::CredentialsError("invalid key".to_string());
        assert!(err.to_string().contains("S3 credentials error"));

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
            max_retries: 3,
            retry_delay_seconds: 30,
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
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_seconds, 30);
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

    #[test]
    fn test_build_region_object_key() {
        let region_config = ReplicationRegionConfig {
            region: "eu-west-1".to_string(),
            bucket: "eu-backup".to_string(),
            endpoint: None,
            path_prefix: Some("replica/kubidm".to_string()),
            credentials: None,
            server_side_encryption: None,
            storage_class: "STANDARD".to_string(),
            kms_key_id: None,
        };

        let key = S3ClientWrapper::build_region_object_key(&region_config, "backup.tar.gz");
        assert_eq!(key, "replica/kubidm/backup.tar.gz");
    }

    #[test]
    fn test_build_region_object_key_no_prefix() {
        let region_config = ReplicationRegionConfig {
            region: "eu-west-1".to_string(),
            bucket: "eu-backup".to_string(),
            endpoint: None,
            path_prefix: None,
            credentials: None,
            server_side_encryption: None,
            storage_class: "STANDARD".to_string(),
            kms_key_id: None,
        };

        let key = S3ClientWrapper::build_region_object_key(&region_config, "backup.tar.gz");
        assert_eq!(key, "backup.tar.gz");
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
            max_retries: 5,
            retry_delay_seconds: 60,
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
