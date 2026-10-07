# Backup and Restore

With any Identity Management (IDM) software, it's important you have the capability to restore in case of a disaster -
be that physical damage or a mistake. Kubidm supports backup and restore of the database with multiple methods.

It is important that you only attempt to restore data with the same version of the server that the backup originated
from.

## Backup Integrity Guarantees

When Kubidm reports that an online or manual backup completed successfully, that backup is guaranteed to be semantically
valid. Before finalizing any backup, the server validates every database entry through the same conversion path used
during normal database loading (`Entry::from_dbentry`). If any entry is syntactically valid (deserializes correctly) but
semantically invalid (cannot be loaded by the server), the backup will fail with an error identifying the problematic
entry.

This means:

- A successful backup can be safely restored by the same supported Kubidm release series
- Storage integrity (checksums) and semantic integrity (loadable entries) are both verified
- Corruption or invalid state in the database is detected at backup time, not restore time

If a backup fails due to semantic validation, the database contains entries that cannot be loaded. This requires
investigation and potentially manual intervention to resolve the underlying data issue.

In addition, every online and manual backup is structurally verified immediately after it is written, with the same
checks as `kubidmd database verify-backup --level structural`: the artifact is read back, parsed, and checked for
entries and for the server version that wrote it. A local artifact that fails this check is renamed with an `.invalid`
suffix so that it is kept for inspection but is neither counted nor deleted by retention, and the backup is reported as
an error without pruning any older backup. An S3 artifact that fails this check is never uploaded.

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

#### Retention

`versions` applies independently to each location: the local directory keeps the newest `versions` backups, and the S3
prefix keeps the newest `versions` backups. After every successful upload the server lists the objects under
`path_prefix` and deletes the oldest automatically generated backups (`backup-<timestamp>.json[.gz]` together with their
`.metadata.json` object) beyond that number. No other object under the prefix is ever deleted.

#### Custom Endpoints

When `endpoint` is set, objects are addressed in path style (`<endpoint>/<bucket>/<key>`), as MinIO, Ceph RGW and most
other S3-compatible services expect. A `region` is still required for request signing; any value such as `us-east-1`
works for services that do not use regions.

#### Listing Backups

`kubidmd database list-backups` prints the backups in the local directory and under the S3 prefix with their size, time
and the first characters of the recorded SHA-256. `--local-only` and `--s3-only` restrict the output to one location.
The command does not open the database, so it can run while the server is running.

```bash
kubidmd database list-backups -c /data/server.toml
```

### Cross-Region Backup Replication

The S3 backups can be mirrored into further buckets, typically in other regions or at another provider, so that a backup
remains available when the primary bucket or its region is unavailable. Replication is driven by the server that takes
the backups; no bucket-level replication feature of the storage service is required, which also makes it work across
providers and with S3-compatible services such as MinIO or Ceph.

#### Configuration

Add a `replication` section with one entry per region to `[online_backup.s3]`:

```toml
[online_backup.s3.replication]
enabled = true
# Seconds between two replication health checks (default 300)
sync_interval_seconds = 300
# Further attempts when copying a backup to a region fails (default 3) ...
max_retries = 3
# ... and the seconds to wait between attempts (default 30)
retry_delay_seconds = 30

[[online_backup.s3.replication.regions]]
region = "eu-west-1"
bucket = "kubidm-backups-eu"
# Optional: Custom endpoint for MinIO or other S3-compatible services
# endpoint = "https://s3.eu-west-1.example.com"
# Optional: Path prefix inside the region's bucket, independent from the primary's
# path_prefix = "dr"
# Optional: Storage class for the copies (default STANDARD)
# storage_class = "STANDARD_IA"
# Optional: Shorthand for aws:kms server-side encryption with this key
# kms_key_id = "arn:aws:kms:eu-west-1:123456789:key/..."

# Optional: Credentials for this region. Omit them to use the SDK default provider chain.
# [online_backup.s3.replication.regions.credentials]
# access_key_id = "eu-region-access-key-id"
# secret_access_key = "eu-region-secret-access-key"

# Optional: Explicit server-side encryption; takes precedence over kms_key_id
# [online_backup.s3.replication.regions.server_side_encryption]
# algorithm = "aws:kms"  # or "AES256"
# kms_key_id = "arn:aws:kms:eu-west-1:123456789:key/..."

[[online_backup.s3.replication.regions]]
region = "ap-southeast-1"
bucket = "kubidm-backups-ap"
```

`region` names the entry: it is shown by `replicate-status`, selected by `--region` on the recovery commands, and used
as the signing region of the requests to that bucket. Each region has its own `bucket`, and optionally its own
`endpoint`, `path_prefix`, `credentials`, `storage_class` and server-side encryption, so a replica can live at a
different provider than the primary. When `enabled = true`, the configuration must list at least one region, region
names must be unique, every region needs a bucket, and `sync_interval_seconds` must be greater than zero; the server and
`kubidmd configtest` reject anything else. With `enabled = false` the section is ignored, but its regions can still be
targeted with `--region`, so a replica remains a recovery source after replication has been switched off.

#### What Is Replicated, and When

After every scheduled S3 backup has been uploaded and its `<key>.metadata.json` sidecar written, the server copies both
objects, unchanged, to every configured region under that region's `path_prefix`. The copy keeps the primary's key,
checksum, size and timestamp, so a replica is indistinguishable from the primary object for `verify-s3` and
`restore-s3`. Only automatically generated backups are replicated; nothing else under the primary prefix is copied, and
nothing is copied retroactively: a region added to the configuration receives the backups taken from then on.

A region that can not be written to is retried `max_retries` times, `retry_delay_seconds` apart, then logged at error
level and skipped. A failing region never fails the primary backup, and the next backup tries the region again. Local
backups are never replicated.

#### Retention per Region

`versions` applies to every location independently. After each backup the server prunes the primary prefix and then the
prefix of every region it could write to, keeping the newest `versions` automatically generated backups in each and
deleting the older ones together with their `.metadata.json` object. As in the primary, no other object under a region's
prefix is ever deleted. A region that could not be written to is not pruned in that run.

#### Health Monitoring

Every `sync_interval_seconds` the server compares the backups in the primary prefix with every region: a region is
healthy when it holds all of them, and each copy's sidecar (checksum and size) and the size the service reports for the
copy agree with the primary. The server logs one warning per region that misses a backup, holds a copy that differs, or
can not be reached, with the number of pending backups and the lag, and an info line per healthy region. The check runs
in its own task and never delays the backup schedule. The first check runs one interval after start up.

The lag of a region is the time between the newest backup in the primary and the newest backup the region holds intact:
zero when the region is up to date, one backup interval when it misses the latest backup only. A copy whose bytes were
corrupted without changing its size is not detected by the health check; `verify-s3 --region` downloads the copy and
recomputes its checksum.

#### Checking Replication Status

`kubidmd database replicate-status` runs the same comparison on demand and prints it. It does not open the database, so
it can run while the server is running:

```bash
kubidmd database replicate-status -c /data/server.toml
kubidmd database replicate-status -c /data/server.toml --detailed
```

The output shows the overall status, the primary location, the time of the check and one line per region with its
bucket, status (`Completed`, `Degraded` or `Failed`), the number of backups replicated and pending, its newest backup
and its lag. The reason is printed under every region that is not `Completed`. `--detailed` adds the lag metrics of
every region: lag, pending backups, the timestamp of the newest replicated backup, the bytes replicated, the check
interval, and the last error of a region that could not be reached. The command exits non-zero when replication is not
configured or disabled, when the primary bucket can not be listed, or when any region is not `Completed`, which makes it
suitable for monitoring.

#### Recovering from a Region

`restore-s3`, `verify-s3` and `list-backups` take `--region <name>`, where `<name>` is the `region` of a configured
entry. The command then uses that region's bucket, endpoint, path prefix, credentials and encryption instead of the
primary's; `--bucket` and `--endpoint` still override the selected settings. Keys are the same in every location.

```bash
# What does the eu-west-1 replica hold?
kubidmd database list-backups -c /data/server.toml --region eu-west-1

# Is the replica of this backup intact and restorable?
kubidmd database verify-s3 -c /data/server.toml --region eu-west-1 --key backup-2024-01-01T22:00:00Z.json.gz

# Restore from the replica (server stopped)
kubidmd database restore-s3 -c /data/server.toml --region eu-west-1 --key backup-2024-01-01T22:00:00Z.json.gz
```

To restore on a host whose `server.toml` has no replication section, pass the region's bucket and endpoint directly:
`restore-s3 --bucket kubidm-backups-eu --endpoint https://... --key ...` (credentials then come from the AWS environment
variables or the instance role, and the key is relative to the region's `path_prefix`, which has to be reproduced in
`[online_backup.s3]` as `path_prefix` in that case).

### Features Not Yet Available

The following backup features are planned but are not implemented in this release:

- Point-in-time recovery and WAL archiving (`online_backup.wal_archive`)
- Client-side backup encryption (`online_backup.encryption`)

Their configuration keys are still parsed so that existing files load, but enabling either of them is rejected when the
server starts and by `kubidmd configtest`. Remove or disable these keys until the features ship.

## Verifying That a Backup Can Be Restored

A backup that was written successfully is not necessarily a backup that can be restored. Kubidm therefore offers two
different kinds of verification:

- **Storage integrity**: Each backup uploaded to S3 is stored next to a `<key>.metadata.json` object that records the
  `checksum_sha256`, `timestamp`, `compression` and `size_bytes` of the artifact. Every download Kubidm performs
  (`restore-s3`, `verify-s3`) recomputes the SHA-256 of the object and refuses it when it does not match the metadata.
  `kubidmd database verify-s3` checks this without restoring anything, see
  [Verifying S3 Backups](#verifying-s3-backups).
- **Restorability**: `kubidmd database verify-backup` inspects the content of a local backup artifact. It has two
  levels, described below.

### Structural Verification

Parses the artifact and checks that it is a Kubidm backup, that it contains entries and that it was written by a server
of the same version. It never opens a database, so it is fast enough to run after every backup, but it can not detect
corrupted entries.

```bash
kubidmd database verify-backup -c /data/server.toml --level structural /backup/backup-2024-01-01T22:00:00Z.json
```

### Full Verification

Runs the structural checks, then restores the artifact into a temporary database using the same restore and reindex code
as `kubidmd database restore`, boots that database as a server start would, and runs the same consistency checks as
`kubidmd database verify` (schema, indexes, entries, replication metadata and plugins). This is the strongest guarantee
that a backup is restorable. The temporary database is removed afterwards and the server's own database is not opened.

```bash
kubidmd database verify-backup -c /data/server.toml /backup/backup-2024-01-01T22:00:00Z.json
```

Full verification is the default level. It loads the whole backup into a temporary database, so it needs disk space and
time proportional to the size of the backup. The command exits non-zero and prints the reasons when verification fails,
which makes it suitable for backup automation.

### Verifying S3 Backups

`kubidmd database verify-s3` downloads a backup from the bucket configured in `[online_backup.s3]`, compares its SHA-256
with the `checksum_sha256` recorded in the metadata object and, when it matches, runs the same structural or full
verification as `verify-backup` on the downloaded artifact. The artifact is kept in a temporary directory that is
removed afterwards, and the server's own database is not opened.

```bash
kubidmd database verify-s3 -c /data/server.toml --key backup-2024-01-01T22:00:00Z.json.gz
kubidmd database verify-s3 -c /data/server.toml --level structural --key backup-2024-01-01T22:00:00Z.json.gz
```

`--key` is relative to the configured `path_prefix`. `--bucket` and `--endpoint` override the corresponding settings of
the configuration, and `--bucket` is required when the configuration has no `[online_backup.s3]` section.
`--region <name>` verifies the copy held by a replication region instead, see
[Recovering from a Region](#recovering-from-a-region). The command exits non-zero when the checksum does not match or
when verification at the requested level fails.

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

`kubidmd database restore-s3` downloads a backup from the bucket configured in `[online_backup.s3]`, verifies its
SHA-256 against the metadata object and restores it with the same code as `restore`. Like `restore`, it must run while
the server is stopped:

```bash
docker stop <container name>
docker run --rm -i -t -v kubidmd:/data \
    kubidm/server:latest /sbin/kubidmd database restore-s3 -c /data/server.toml \
    --key backup-2024-01-01T22:00:00Z.json.gz
docker start <container name>
```

The key is relative to the configured `path_prefix`; `kubidmd database list-backups` shows the available keys. The
database is left untouched when the download or the checksum check fails. `--bucket` and `--endpoint` override the
configuration, which allows restoring on a host whose `server.toml` has no `[online_backup.s3]` section (credentials
then come from the AWS environment variables or the instance role). `--region <name>` restores from the copy held by a
replication region, see [Recovering from a Region](#recovering-from-a-region).

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
