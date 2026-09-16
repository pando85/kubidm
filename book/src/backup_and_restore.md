# Backup and Restore

With any Identity Management (IDM) software, it's important you have the capability to restore in case of a disaster -
be that physical damage or a mistake. Kubidm supports backup and restore of the database with multiple methods.

It is important that you only attempt to restore data with the same version of the server that the backup originated
from.

## Backup Integrity Guarantees

When Kubidm reports that an online or manual backup completed successfully, that backup is guaranteed to be
semantically valid. Before finalizing any backup, the server validates every database entry through the same
conversion path used during normal database loading (`Entry::from_dbentry`). If any entry is syntactically valid
(deserializes correctly) but semantically invalid (cannot be loaded by the server), the backup will fail with an
error identifying the problematic entry.

This means:

- A successful backup can be safely restored by the same supported Kubidm release series
- Storage integrity (checksums) and semantic integrity (loadable entries) are both verified
- Corruption or invalid state in the database is detected at backup time, not restore time

If a backup fails due to semantic validation, the database contains entries that cannot be loaded. This requires
investigation and potentially manual intervention to resolve the underlying data issue.

## Method 1 - Automatic Backup

Automatic backups can be generated online by a `kubidmd server` instance by including the `[online_backup]` section in
the `server.toml`. This allows you to run regular backups, defined by a cron schedule, and maintain the number of backup
versions to keep. An example is located in
[examples/server.toml](https://github.com/kubidm/kubidm/blob/master/examples/server.toml).

### S3-Compatible Storage Backup

Kubidm supports backing up to S3-compatible object storage services (AWS S3, MinIO, Ceph, GCS, Azure Blob via S3 API).
To enable S3 backup, add the `[online_backup.s3]` section to your `server.toml`:

```toml
[online_backup]
path = "/var/lib/kubidm/backups/"
schedule = "00 22 * * *"
versions = 7
compression = "gzip"

[online_backup.s3]
bucket = "kubidm-backups"
region = "us-east-1"
# Optional: Custom endpoint for MinIO or other S3-compatible services
# endpoint = "https://minio.example.com"
# Optional: Path prefix for organizing backups
# path_prefix = "production"
# Optional: Storage class (STANDARD, GLACIER, etc.)
# storage_class = "STANDARD"

# For static credentials (not recommended for production)
[online_backup.s3.credentials]
access_key_id = "your-access-key"
secret_access_key = "your-secret-key"

# For IAM role authentication (recommended for EC2/EKS), omit credentials section

# Optional: Server-side encryption
[online_backup.s3.server_side_encryption]
# algorithm = "aws:kms"  # or "AES256"
# kms_key_id = "arn:aws:kms:us-east-1:123456789:key/..."
```

#### Authentication Methods

1. **Static Credentials**: Configure `access_key_id` and `secret_access_key` directly (suitable for testing)
2. **IAM Role Authentication**: Omit the `credentials` section - the server will use IAM roles when running on EC2/EKS
3. **Environment Variables**: Set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally `AWS_SESSION_TOKEN`

### Cross-Region Backup Replication

For enterprise disaster recovery, Kubidm supports automatic cross-region backup replication to ensure backups are
available in multiple geographic regions. This provides:

- Geographic backup redundancy
- Cross-region recovery capability
- Protection against regional outages
- Compliance with data residency requirements

#### Configuration

Add a `replication` section to your S3 configuration:

```toml
[online_backup.s3.replication]
enabled = true
# How often to check replication status (seconds)
sync_interval_seconds = 300
# Maximum retry attempts for failed replication
max_retries = 3
# Delay between retry attempts (seconds)
retry_delay_seconds = 30

# Configure secondary regions (multiple regions supported)
[[online_backup.s3.replication.regions]]
region = "eu-west-1"
bucket = "kubidm-backups-eu"
# Optional: Custom endpoint for non-AWS S3
# endpoint = "https://s3.eu-west-1.amazonaws.com"
# Optional: Path prefix
# path_prefix = "dr-backups"
# Optional: Storage class
# storage_class = "STANDARD"

# Optional: Region-specific encryption key
# kms_key_id = "arn:aws:kms:eu-west-1:123456789:key/..."

# Optional: Region-specific credentials (if different from primary)
# [online_backup.s3.replication.regions.credentials]
# access_key_id = "eu-region-key"
# secret_access_key = "eu-region-secret"

# Add additional regions as needed
[[online_backup.s3.replication.regions]]
region = "ap-southeast-1"
bucket = "kubidm-backups-ap"
```

#### Region-Specific Encryption Keys

For compliance requirements, you can configure region-specific KMS keys:

```toml
[[online_backup.s3.replication.regions]]
region = "eu-west-1"
bucket = "kubidm-backups-eu"
kms_key_id = "arn:aws:kms:eu-west-1:123456789:key/eu-key-id"

[online_backup.s3.replication.regions.server_side_encryption]
algorithm = "aws:kms"
kms_key_id = "arn:aws:kms:eu-west-1:123456789:key/eu-key-id"
```

#### Checking Replication Status

Use the `replicate-status` command to check the health of cross-region replication:

```bash
kubidmd database replicate-status -c /data/server.toml
```

For detailed output including lag metrics per region:

```bash
kubidmd database replicate-status -c /data/server.toml --detailed
```

The output shows:
- Overall replication status
- Per-region status (Completed, In Progress, Degraded, Failed)
- Number of backups replicated
- Bytes replicated
- Replication lag in seconds
- Last successful sync timestamp

#### Recovery from Secondary Region

To recover from a backup stored in a secondary region:

1. **Identify the backup in the secondary region**:
   ```bash
   # Use AWS CLI or S3 tools to list backups in the secondary region bucket
   aws s3 ls s3://kubidm-backups-eu/
   ```

2. **Restore using the S3 backup key**:
   ```bash
   docker stop <container name>
   docker run --rm -i -t -v kubidmd:/data \
       kubidm/server:latest /sbin/kubidmd database restore-s3 -c /data/server.toml \
       --bucket kubidm-backups-eu --key backup-2024-01-01T22:00:00Z.json.gz
   docker start <container name>
   ```

#### Monitoring Replication Lag

Replication lag metrics can be integrated with monitoring systems:

- `total_lag_seconds`: Cumulative lag across all regions
- `max_lag_seconds`: Maximum lag in any region
- `healthy_regions`: Count of regions with healthy replication
- `unhealthy_regions`: Count of regions with issues

Set up alerts for:
- `max_lag_seconds > threshold` (e.g., 3600 for 1 hour lag)
- `unhealthy_regions > 0`
- Overall status changing to `Failed` or `Degraded`

#### Disaster Recovery Runbook

**Scenario: Primary Region Outage**

1. Verify secondary region backups are available:
   ```bash
   # Check backup availability in secondary region (using S3 tools)
   aws s3 ls s3://kubidm-backups-eu/ --region eu-west-1
   ```

2. Deploy Kubidm instance in secondary region:
   - Configure `server.toml` to use secondary region S3 bucket
   - Use region-specific encryption keys if configured

3. Restore from secondary region backup:
   ```bash
   kubidmd database restore-s3 -c /data/server.toml \
       --bucket kubidm-backups-eu --key backup-2024-01-01T22:00:00Z.json.gz
   ```

4. Verify restoration success and start server

5. Update DNS/network configuration to point to new instance

**Important Considerations**

- S3 Cross-Region Replication has eventual consistency - expect RPO based on replication lag
- Regularly test recovery from secondary regions to validate DR procedures
- Document region-specific encryption key locations for recovery scenarios
- Consider immutable storage (S3 Object Lock) for ransomware protection
- Review compliance requirements for data residency in secondary regions

#### Backup Verification

Each S3 backup includes a SHA-256 checksum that is verified automatically on restore. You can verify backups
without restoring using:

```bash
kubidmd database verify-s3 -c /data/server.toml backup-2024-01-01T22:00:00Z.json.gz
```

## Backup Verification

Kubidm provides two levels of backup verification to ensure your backups are restorable:

### Structural Verification

Validates the backup format, JSON structure, and version compatibility without performing a full restore. This is fast and suitable for routine checks after backup creation.

```bash
kubidmd database verify-backup -c /data/server.toml --level structural /backup/kubidm.backup.json
```

### Full Restore Verification

Performs a complete restore into a temporary backend and runs semantic consistency checks including schema validation, index verification, entry consistency, and RUV reconstruction. This exercises the same code paths as a production restore and is the strongest guarantee that a backup is restorable.

```bash
kubidmd database verify-backup -c /data/server.toml --level full /backup/kubidm.backup.json
```

Full verification is slower but detects issues that structural checks cannot, such as corrupted entries or schema incompatibilities that would prevent a successful restore.

> **Note:** Structural verification checks format and checksums. Full verification proves the backup can be restored into a bootable, consistent server. For critical backups, use full verification.

## Method 2 - Manual Backup

This method uses the same process as the automatic process, but is manually invoked. This can be useful for pre-upgrade
backups

To take the backup (assuming our docker environment) you first need to stop the instance:

```bash
docker stop <container name>
docker run --rm -i -t -v kubidmd:/data -v kubidmd_backups:/backup \
    kubidm/server:latest /sbin/kubidmd database backup -c /data/server.toml \
    /backup/kubidm.backup.json
docker start <container name>
```

You can then restart your instance. DO NOT modify the backup.json as it may introduce data errors into your instance.

To restore from the backup:

```bash
docker stop <container name>
docker run --rm -i -t -v kubidmd:/data -v kubidmd_backups:/backup \
    kubidm/server:latest /sbin/kubidmd database restore -c /data/server.toml \
    /backup/kubidm.backup.json
docker start <container name>
```

### Restoring from S3

To restore from an S3 backup:

```bash
docker stop <container name>
docker run --rm -i -t -v kubidmd:/data \
    kubidm/server:latest /sbin/kubidmd database restore-s3 -c /data/server.toml \
    --bucket kubidm-backups --key backup-2024-01-01T22:00:00Z.json.gz
docker start <container name>
```

## Method 3 - Manual Database Copy

This is a simple backup of the data volume containing the database files. Ensure you copy the whole folder, rather than
individual files in the volume!

```bash
docker stop <container name>
# Backup your docker's volume folder
# cp -a /path/to/my/volume /path/to/my/backup-volume
docker start <container name>
```

Restoration is the reverse process where you copy the entire folder back into place.
