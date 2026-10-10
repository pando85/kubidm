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

### Point-in-Time Recovery

Online backups capture the database at the moment they run. Point-in-time recovery (PITR) closes the window between
them: with WAL archiving enabled, the server archives the full state of every entry each committed write transaction
changed, tagged with the transaction's change identifier (CID). `kubidmd database recover` then rebuilds the database as
it was at any moment covered by the archive, by restoring the newest base backup taken at or before that moment and
replaying the archived changes up to it.

```toml
[online_backup]
path = "/var/lib/kubidm/backups/"
schedule = "00 22 * * *"
versions = 7

[online_backup.wal_archive]
enabled = true
# Close the open segment at least this often (also the upload period). Default 300.
# segment_interval_seconds = 300
# Close a segment once its records reach this size. Default 16 MiB.
# segment_size_bytes = 16777216
# Keep archived segments at least this long. Default 7.
# retention_days = 7
# Where segments are written before they are uploaded. Default: "wal" next to db_path.
# local_path = "/var/lib/kubidm/wal"
# Archive in another S3 location than [online_backup.s3]:
# [online_backup.wal_archive.s3]
# bucket = "kubidm-wal"
# region = "us-east-1"
```

WAL archiving requires `online_backup.enabled = true`, since recovery always starts from an online backup.

#### Where the Archive Lives

- **Segments.** Committed changes are collected into segments. A segment is closed when its records reach
  `segment_size_bytes` or when it is `segment_interval_seconds` old, and written to the local WAL directory as a gzip
  JSON file with a `.meta.json` sidecar that records its CID range and SHA-256.
- **Archive location.** When `[online_backup.wal_archive.s3]` or `[online_backup.s3]` is configured, closed segments are
  uploaded under `<path_prefix>/wal/` (each with a `.metadata.json` object) and removed locally once the upload
  succeeded. Otherwise they stay in the local WAL directory.
- **Manifest.** `pitr-manifest.json`, in the archive location, indexes the base backups with their CID watermark (the
  last transaction they contain), the segments, and the gaps and abandoned history described below. It records the
  server it belongs to, and a server refuses to archive into another server's manifest: give every server its own
  location.
- **Base backups.** Every successful scheduled online backup is indexed as a base: the S3 backup when
  `[online_backup.s3]` is configured, otherwise the local one. Manual `kubidmd database backup` artifacts are not
  indexed. Recovery becomes possible with the first online backup taken after WAL archiving was enabled. When only
  `[online_backup.wal_archive.s3]` is set, segments go to S3 but base backups stay in the local directory, so recovery
  needs that directory too.

The archive task runs every `segment_interval_seconds`: it closes a segment older than that, uploads closed segments,
updates the manifest and applies retention. A clean shutdown closes and archives the open segment, so nothing committed
is left behind.

#### Retention

Backup retention (`versions`) is unchanged. Base backups that it deletes drop out of the manifest at the next archive
run. An archived segment is deleted once it is older than `retention_days` **and** no longer needed by the oldest base
backup still present, so the archive always reaches back to the oldest base backup, however small `retention_days` is.

#### What Can Be Lost

Records live in memory until their segment is closed. If the server stops without shutting down (a crash, a kill, a
power loss) the open segment is lost from the archive, although the transactions themselves are safely committed in the
database. The next start notices this, logs `WAL ARCHIVE HOLE`, and records a **gap** in the manifest. A committed
transaction whose changes could not be recorded is logged and recorded as a gap the same way, while a closed segment
that could not be written (for example on a full disk) is kept in memory and retried. Replaying across a gap would
silently skip changes, so `recover` refuses any target whose replay would cross one, and `--latest` stops right before
it. A base backup taken after the gap makes later points recoverable again; take one after any `WAL ARCHIVE HOLE`. With
S3, segments that were closed but not yet uploaded are lost with the host, which only shortens the recoverable window.

The offline `kubidmd domain rename` and `kubidmd database reindex` commands archive their writes like the running server
does; the next server start uploads them. The `kubidmd db-scan quarantine-id2entry` and `restore-quarantined` repair
commands bypass the archive: take an online backup after using them.

#### Listing Recovery Points

```bash
kubidmd database pitr-list -c /data/server.toml
```

prints the base backups with their watermarks, the segments with their CID ranges and record counts (marking the
segments still only in the local WAL directory), any gaps and abandoned history, and the recoverable window. It does not
open the database, so it can run while the server is running. It exits non-zero when nothing is recoverable yet.

#### Recovering

Like `restore`, `recover` must run while the server is stopped. Exactly one target is required:

```bash
docker stop <container name>
docker run --rm -i -t -v kubidmd:/data \
    kubidm/server:latest /sbin/kubidmd database recover -c /data/server.toml \
    --target-time 2024-01-15T10:30:00Z
docker start <container name>
```

- `--target-time <RFC3339>` recovers every transaction committed at or before that time, as the server's clock recorded
  it.
- `--target-cid <CID>` recovers up to and including the transaction with that change identifier
  (`<nanoseconds>-<server uuid>`, as the server logs it).
- `--latest` recovers everything the archive holds.
- `--dry-run` prints the plan (base backup, segments, number of records, resulting point) and changes nothing.

The command reads the `[online_backup]` section of the configuration to find the archive and the base backups, so the
same `server.toml` works on a replacement host. It uses the segments of the same server still in the local WAL directory
that were never archived. It then:

1. downloads (from S3) or opens the base backup and checks every segment against the SHA-256 the manifest recorded;
2. restores the base backup into the configured database and replays the records after its watermark, in CID order, in
   the same database transaction, so that a failure leaves the database untouched;
3. reindexes, boots and verifies the recovered database like `verify-backup --level full`;
4. records in the manifest that the history after the recovered point was **abandoned**.

Abandoned history is never replayed again: after recovering to 10:30, the server started on the recovered database
writes new history, and a later recovery to any point after it replays the recovered state plus the new history, never
the transactions that were discarded. `kubidmd database restore` and `restore-s3` record abandoned history the same way
when WAL archiving is configured.

Base backups and segments can only be used by the server version that wrote them, like backups. In a replicated
topology, treat a recovered node like a restored one: the other nodes must be refreshed from it.

### Features Not Yet Available

The following backup features are planned but are not implemented in this release:

- Cross-region backup replication (`online_backup.s3.replication`)
- Client-side backup encryption (`online_backup.encryption`)

Their configuration keys are still parsed so that existing files load, but enabling any of them is rejected when the
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

`--key` is relative to the configured `path_prefix`. `--bucket`, `--region` and `--endpoint` override the corresponding
settings of the configuration, and `--bucket` is required when the configuration has no `[online_backup.s3]` section.
The command exits non-zero when the checksum does not match or when verification at the requested level fails.

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
database is left untouched when the download or the checksum check fails. `--bucket`, `--region` and `--endpoint`
override the configuration, which allows restoring on a host whose `server.toml` has no `[online_backup.s3]` section
(credentials then come from the AWS environment variables or the instance role).

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
