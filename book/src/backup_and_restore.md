# Backup and Restore

With any Identity Management (IDM) software, it's important you have the capability to restore in case of a disaster -
be that physical damage or a mistake. Kubidm supports backup and restore of the database with multiple methods.

It is important that you only attempt to restore data with the same version of the server that the backup originated
from.

The automatic backup is built from parts that can be combined freely:

- **Online backups** to a local directory and/or an [S3-compatible bucket](#s3-compatible-storage-backup), each verified
  after it is written ([verification](#verifying-that-a-backup-can-be-restored) can also be run on demand).
- **[Cross-region replication](#cross-region-backup-replication)** of the S3 backups to further buckets.
- **[Client-side encryption](#client-side-backup-encryption)** of everything that leaves the server.
- **[Point-in-time recovery](#point-in-time-recovery)** (PITR), which archives every committed write so that the
  database can be rebuilt as of any moment between backups.
- **[Monitoring](#monitoring-backups)**: a scheduled full verification of the newest backup, and Prometheus metrics of
  when every backup location last received, failed and verified a backup.

[How the Features Combine](#how-the-features-combine) summarises what each combination does and how to recover from it.

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
entries and for the server version that wrote it. It is opened the way a restore opens it, so its name counts: a plain
backup must carry the compression suffix of the compression it was written with (`.json.gz` for gzip, `.json` without
compression), and only an encrypted backup may end in `.enc`. `kubidmd database backup` refuses a destination whose name
contradicts the configured compression or encryption before it writes anything. It exits non-zero on every failure,
including a destination that already exists and a database that can not be opened, so a scheduled job never mistakes a
backup that was not written for a success.

A local artifact is first written to a hidden `.<name>.partial` file next to its destination, synced to disk and
verified there, and only then renamed to its final name, so a backup name never holds a partially written backup, even
after a full disk or a crash, and an existing file is never overwritten. An artifact that fails the verification is
renamed with an `.invalid` suffix so that it is kept for inspection but is neither counted nor deleted by retention, and
the backup is reported as an error without pruning any older backup. A `.partial` file left behind by a crash is never
counted either; retention removes it once a newer backup is complete, and a manual backup to the same destination names
it in its error. An S3 artifact that fails this check is never uploaded.

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
# Optional: Storage class: STANDARD (default), REDUCED_REDUNDANCY, STANDARD_IA, ONEZONE_IA,
# INTELLIGENT_TIERING or GLACIER_IR. GLACIER and DEEP_ARCHIVE are refused: their objects
# can only be read after a restore request.
# storage_class = "STANDARD"

# For static credentials (not recommended for production)
[online_backup.s3.credentials]
access_key_id = "your-access-key"
secret_access_key = "your-secret-key"

# For IAM role authentication (recommended for EC2/EKS), omit credentials section

# Optional: Server-side encryption, applied to the backups and their metadata objects
[online_backup.s3.server_side_encryption]
# algorithm = "aws:kms"  # or "AES256"
# Only with aws:kms; S3 refuses a KMS key with AES256
# kms_key_id = "arn:aws:kms:us-east-1:123456789:key/..."
```

#### Authentication Methods

1. **Static Credentials**: Configure `access_key_id` and `secret_access_key` directly (suitable for testing)
2. **IAM Role Authentication**: Omit the `credentials` section - the server will use IAM roles when running on EC2/EKS
3. **Environment Variables**: Set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally `AWS_SESSION_TOKEN`

#### Retention

`versions` applies independently to each location: the local directory keeps the newest `versions` backups, and the S3
prefix keeps the newest `versions` backups. After every successful upload the server lists the objects under
`path_prefix` and deletes the oldest automatically generated backups (`backup-<timestamp>.json[.gz][.enc]` together with
their `.metadata.json` object) beyond that number. Plain and encrypted backups count alike, ordered by the time in their
name. No other object under the prefix is ever deleted, and neither is the backup the run has just written. `versions`
must be at least 1; the server and `kubidmd configtest` reject `versions = 0`, also when it is given as
`--online-backup-versions`.

#### Large Backups

Backups larger than 100 MiB are uploaded in 10 MiB parts. An upload that fails, or that is interrupted by a shutdown, is
aborted so that its parts are not kept, and billed, by the storage service. Only a crash can leave the parts of an
unfinished upload behind; a bucket lifecycle rule that aborts incomplete multipart uploads after a day or so removes
them.

#### Custom Endpoints

When `endpoint` is set, objects are addressed in path style (`<endpoint>/<bucket>/<key>`), as MinIO, Ceph RGW and most
other S3-compatible services expect. A `region` is still required for request signing; any value such as `us-east-1`
works for services that do not use regions.

#### Listing Backups

`kubidmd database list-backups` prints the backups in the local directory and under the S3 prefix with their size, time,
the first characters of the recorded SHA-256 and whether they are encrypted (with the identifier of the key they need).
`--local-only` and `--s3-only` restrict the output to one location. The command does not open the database, so it can
run while the server is running.

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
# Seconds between two replication sync and health check runs (default 300)
sync_interval_seconds = 300

[[online_backup.s3.replication.regions]]
region = "eu-west-1"
bucket = "kubidm-backups-eu"
# Optional: The name of the replica for replicate-status and --region (default: region)
# name = "eu-dr"
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

`region` is the signing region of the requests to that bucket and, unless `name` is set, also names the entry: the name
is shown by `replicate-status` and selected by `--region` on the recovery commands. Set `name` when two replicas share a
signing region, such as two buckets or accounts in one AWS region, or two S3-compatible stores that both sign with the
same region. Each region has its own `bucket`, and optionally its own `endpoint`, `path_prefix`, `credentials`,
`storage_class` and server-side encryption, so a replica can live at a different provider than the primary. When
`enabled = true`, the configuration must list at least one region, region names (`name`, or `region` without one) must
be unique, every region needs a bucket, no region may point at the primary location or at the location of another region
(same bucket and `path_prefix`, and the same endpoint, where every AWS S3 endpoint counts as the default one), every
region's storage class and server-side encryption must be valid as for the primary (the `kms_key_id` shorthand can not
be combined with `AES256`), and `sync_interval_seconds` must be greater than zero; the server and `kubidmd configtest`
reject anything else. With `enabled = false` the section is ignored, but its regions can still be targeted with
`--region`, so a replica remains a recovery source after replication has been switched off.

#### What Is Replicated, and When

After every scheduled S3 backup has been uploaded and its `<key>.metadata.json` sidecar written, the server copies both
objects, unchanged, to every configured region under that region's `path_prefix`. The copy keeps the primary's key,
checksum, size and timestamp, so a replica is indistinguishable from the primary object for `verify-s3` and
`restore-s3`. The backup replication copies only automatically generated backups; nothing else under the primary prefix
is copied by it. Local backups are never replicated. Client-side encrypted backups are replicated like any other backup,
see [Encrypted Backups and Replication](#encrypted-backups-and-replication). The WAL archive of point-in-time recovery,
when it is uploaded to the same S3 location, is mirrored to the same regions by the archive itself, see
[The WAL Archive and Replication](#the-wal-archive-and-replication).

Each backup run makes a single attempt per region and never retries or waits: a region that can not be written to is
logged as a warning and skipped, so a slow or unreachable region can neither fail the primary backup nor delay the
schedule or a shutdown. The replication sync described below is the only place that retries: backups a region missed
this way, and all the existing backups of a region added to the configuration, are copied by it.

#### Retention per Region

`versions` applies to every location independently. After each backup the server prunes the primary prefix and then the
prefix of every region it could write to, keeping the newest `versions` automatically generated backups in each and
deleting the older ones together with their `.metadata.json` object. As in the primary, no other object under a region's
prefix is ever deleted. A region that could not be written to is not pruned in that run.

#### Sync and Health Monitoring

Every `sync_interval_seconds` the server compares the backups in the primary prefix with every region. A copy is intact
when it exists, its sidecar (checksum and size) agrees with the primary's, and the size the service reports for it
matches. Every backup a region misses or holds a differing copy of is downloaded from the primary, checked against the
primary's checksum, and uploaded to the region again; a primary copy that fails its checksum is never propagated. A
region that can not be reached is skipped and retried on the next run.

After the sync the server checks every region once more: a region is healthy when it holds every primary backup intact.
It logs one warning per region that still misses a backup, holds a copy that differs, or can not be reached, with the
number of pending backups and the lag, and an info line per healthy region. The sync runs in its own task and never
delays the backup schedule. The first run happens one interval after start up.

The lag of a region is the time between the newest backup in the primary and the newest backup the region holds intact:
zero when the region is up to date, one backup interval when it misses the latest backup only. A copy whose bytes were
corrupted without changing its size is not detected by the health check; `verify-s3 --region` downloads the copy and
recomputes its checksum.

#### Checking Replication Status

`kubidmd database replicate-status` runs the same health check on demand and prints it, without copying anything. It
does not open the database, so it can run while the server is running:

```bash
kubidmd database replicate-status -c /data/server.toml
kubidmd database replicate-status -c /data/server.toml --detailed
kubidmd database replicate-status -c /data/server.toml --deep
```

The output shows the overall status, the primary location, the time of the check and one line per region with its
bucket, status (`Completed`, `Degraded` or `Failed`), the number of backups replicated and pending, its newest backup
and its lag. The reason is printed under every region that is not `Completed`. `--detailed` adds the lag metrics of
every region: lag, pending backups, the timestamp of the newest replicated backup, the bytes replicated, the check
interval, and the last error of a region that could not be reached.

When the [WAL archive](#the-wal-archive-and-replication) of point-in-time recovery is replicated, a second report
follows for it: the primary archive with the time its `pitr-manifest.json` was last updated and the number of segments
it names, and one line per region with the state of the region's manifest (`current` when it records every segment, gap
and abandoned history of the primary's, `behind`, `damaged` when it can not be read or does not match its checksum,
`missing`, or `unreachable`), the segments it holds intact, those it misses (object or `.metadata.json`) and those whose
copy differs from the primary's, and the lag of its manifest: how much older the newest segment it names is than the
primary's newest. By default the listings are compared, a few requests per region, which catches a copy whose object or
`.metadata.json` is missing or whose size differs; `--deep` also compares the sidecars of every segment (checksum and
size, as for backups), two reads per segment and region, which catches a copy replaced by one of the same size. A region
copy is still healthy when it only lacks what the primary archived within the replication's `sync_interval_seconds` plus
two `segment_interval_seconds`, since the next archive run is due to copy it: its manifest is then `pending`, and
`--detailed` lists such segments as not copied yet. A segment the primary itself lacks is reported on its own, as a
problem of the primary that no region can be given, never as a damaged region copy. Before the first archive run there
is no manifest yet, which is reported as not yet archived and is healthy. `--detailed` names every missing or differing
segment. The command exits non-zero when neither backups nor the WAL archive are replicated, when a primary location can
not be read or misses segments its manifest names, or when any region of either is not healthy, which makes it suitable
for monitoring.

#### Recovering from a Region

`restore-s3`, `verify-s3` and `list-backups` take `--region <name>`, where `<name>` is the `region` of a configured
entry. The command then uses that region's bucket, endpoint, path prefix, credentials and server-side encryption instead
of the primary's; `--bucket` and `--endpoint` still override the selected settings. Keys are the same in every location.

```bash
# What does the eu-west-1 replica hold?
kubidmd database list-backups -c /data/server.toml --region eu-west-1

# Is the replica of this backup intact and restorable?
kubidmd database verify-s3 -c /data/server.toml --region eu-west-1 --key backup-2024-01-01T22:00:00Z.json.gz

# Restore from the replica (server stopped)
kubidmd database restore-s3 -c /data/server.toml --region eu-west-1 --key backup-2024-01-01T22:00:00Z.json.gz
```

`pitr-list` and `recover` take `--region <name>` as well, to recover to a point in time from a region's copy of the WAL
archive and of the base backups, see [The WAL Archive and Replication](#the-wal-archive-and-replication).

To restore on a host whose `server.toml` has no replication section, add the replica to it as a region, with replication
disabled, and select it with `--region`. Only the region entry is used, so `[online_backup.s3]` can keep the primary's
settings, or name any bucket on a host that does not take backups:

```toml
[online_backup.s3]
bucket = "kubidm-backups"
region = "us-east-1"

[online_backup.s3.replication]
# Never replicate from this host; the region is only a recovery source.
enabled = false

[[online_backup.s3.replication.regions]]
region = "eu-west-1"
bucket = "kubidm-backups-eu"
# path_prefix, endpoint and credentials as on the server that replicates to it
```

`--bucket` and `--endpoint` are no substitute for this: they replace only the bucket and the endpoint of
`[online_backup.s3]`, whose `region`, `path_prefix` and credentials still apply, so against AWS the requests would be
signed for the primary's region and fail for a replica in another one.

### Client-Side Backup Encryption

A backup contains every entry of the directory, including credential hashes and session state, so wherever it is stored
it deserves the same protection as the database itself. Server-side encryption of the S3 bucket protects the objects at
rest in S3 but leaves them readable to anyone with access to the bucket. Client-side encryption encrypts every backup
inside the server before it is written or uploaded, so that a backup can only be restored by whoever holds the key.

Enable it in the `[online_backup.encryption]` section:

```toml
[online_backup.encryption]
enabled = true
key_source = "Passphrase"
passphrase_file = "/etc/kubidm/backup-passphrase"
key_identifier = "prod-2026"
```

When it is enabled, every backup made from this configuration is encrypted: the scheduled online backup, its upload to
S3, `kubidmd database backup` and `kubidmd scripting backup` (also when it writes to stdout). The backup is serialised
and compressed as usual and the result is then sealed with AES-256-GCM under a key derived from the configured secret
with Argon2id and a fresh random salt. The artifact is a self-describing container: a header with the salt, the key
derivation parameters, the nonce, the key identifier, the compression and what the artifact is (a backup and the
timestamp of its name, or a WAL segment and its id), followed by the ciphertext. The header is authenticated together
with the ciphertext, so any change to either, a truncation or a header taken from another artifact makes the artifact
fail to open. Nothing but the secret is needed to open it.

#### Key Sources

`key_source` names where the secret comes from. Whatever the source, the secret is only ever used as input to the key
derivation and never as the cipher key itself.

- `"Passphrase"` (default): the passphrase is read from the `KUBIDM_BACKUP_PASSPHRASE` environment variable of the
  `kubidmd` process. When `passphrase_file` is set, the passphrase is read from that file instead and the environment
  variable is not consulted. Trailing whitespace and newlines are ignored in both, so moving a passphrase from one to
  the other keeps the key. One of the two must be present, or the server refuses to start.
- `{ File = { path = "/etc/kubidm/backup.key" } }`: the content of the file is the secret, byte for byte. Generate it
  with for example `head -c 32 /dev/urandom > /etc/kubidm/backup.key` and keep it readable only by the server user.
- `{ HttpEndpoint = { url = "https://secrets.example.com/kubidm-backup-key" } }`: the raw response body of a GET request
  to the URL is the secret, byte for byte (at most 64 KiB, within 30 seconds). The request carries no credentials, and
  the body is not parsed, so the endpoint must return the bare key and exactly the same bytes every time: a JSON
  envelope with a per-request field, such as a Vault API response, would yield a different key on every call and the
  backups could never be decrypted again. A local agent or sidecar that renders the secret is the usual way to serve it.
  The endpoint is called every time a backup is made or restored, and with point-in-time recovery also at every WAL
  archive run that has segments to archive and at every `recover`, so it has to be reachable from the server and from
  the host that restores. The URL must use `https`; plain `http` is only accepted for a loopback address such as a local
  secrets agent, because it would send the secret in the clear. The request never goes through a proxy (`HTTP_PROXY`,
  `HTTPS_PROXY` and `ALL_PROXY` are ignored) and redirects are not followed: any answer but a `2xx` fails.

At startup, and in `kubidmd configtest`, the key source is checked to be usable: the passphrase file or environment
variable is present and not empty, the key file exists and is readable, the URL is a well formed `https` URL, or `http`
on loopback (it is not fetched at that point). A passphrase file or key file that everyone on the host can read is
reported with a warning, as for the TLS key. The key derivation parameters (`key_derivation.m_cost` in KiB, `t_cost`,
`p_cost`) must lie within sane bounds; the defaults are 19 MiB, 2 iterations and no parallelism. `m_cost` must be
between 8 MiB (8192) and 1 GiB (1048576), `t_cost` and `p_cost` between 1 and 16, and `m_cost` times `t_cost` at most 4
GiB (4194304). The same bounds are checked on the parameters recorded in an artifact before anything is derived from
them, so a modified artifact can not make a restore allocate more memory or spend more time than that.

#### Key Identifier

Every artifact records the `key_identifier` of the key it was encrypted with, and so does the `.metadata.json` object in
S3. When no identifier is configured, a key file or key endpoint is identified by a fingerprint of its content, so
artifacts made with the same key always carry the same identifier. A passphrase is never fingerprinted, because a public
fingerprint of a passphrase would let an attacker test guesses against a precomputed dictionary; without a configured
identifier its artifacts record the identifier `passphrase`. Configure a `key_identifier` to tell passphrases apart. The
identifier is public information: it tells an operator which key a backup needs, it is shown by `list-backups`,
`verify-backup` and `verify-s3`, and it is named in every error about a key that could not be obtained or does not fit.

When a `key_identifier` is configured, a restore refuses an artifact whose header names a different one before trying to
decrypt it. Without a configured identifier the key is simply tried.

#### Naming and Storage

Encrypted artifacts get the extra suffix `.enc` after the compression suffix: `backup-<timestamp>.json.enc` and
`backup-<timestamp>.json.gz.enc`. Retention, `list-backups` and the post-write verification treat them as first class
backups, and a rejected encrypted artifact is quarantined as `...json.gz.enc.invalid` like a plain one. The suffix is
mostly informational: an encrypted container is recognised by its content. The reverse is refused: an artifact named
`.enc`, or an S3 object whose name or metadata says it is encrypted, must be an encrypted container, so that whoever can
write to the backup location can not swap an encrypted backup for an unauthenticated plain one.

An encrypted backup also records the timestamp of the name it was written under, `backup-<timestamp>.json[.gz].enc`.
Under a name of that form it only opens when the name carries the same timestamp, so an older backup copied over the
name or the S3 key of a newer one is refused instead of silently restoring the older state. Under any other name, such
as a copy to removable media or a manual `database backup` to a path of your choice, it opens and restores normally;
such a name does not claim when the backup was taken. `kubidmd scripting backup` writing to stdout does not know the
name the backup ends up under, so an encrypted one records no timestamp and is refused under a
`backup-<timestamp>.json[.gz].enc` name: pass the name with `--name`
(`kubidmd scripting backup --name backup-2024-01-01T22:00:00.000000000Z.json.gz.enc > ...`), which also checks it
against the compression and encryption like a destination path. Copies under the same name, in another directory,
bucket, prefix or [replication region](#encrypted-backups-and-replication), are the same artifact and open everywhere. A
WAL segment is bound to its segment id the same way, and a segment is never accepted as a backup or the other way round.

What is and is not encrypted:

- The backup itself, meaning every entry, is encrypted.
- With point-in-time recovery, every archived WAL segment is encrypted the same way, see
  [The Encrypted WAL Archive](#the-encrypted-wal-archive).
- The `.metadata.json` sidecar in S3 stays in plaintext. It contains only the SHA-256 checksum and size of the encrypted
  object, the upload timestamp, the compression, `encrypted = true` and the key identifier. It never contains directory
  content or the key.
- The PITR manifest `pitr-manifest.json` stays in plaintext. It contains the server UUID, CID ranges, record counts,
  checksums, object keys and key identifiers, never directory content.
- The file names and object keys embed only the timestamp (and, for WAL segments, the server UUID and the CID timestamp
  of their first record).

#### Restoring an Encrypted Backup

`restore`, `verify-backup`, `restore-s3`, `verify-s3` and `recover` decrypt transparently: they read the
`[online_backup.encryption]` section of the configuration they are given, obtain the secret from its key source and open
the artifact with it. A cold restore on a fresh host therefore needs the server configuration file and the secret it
names: the passphrase (in `KUBIDM_BACKUP_PASSPHRASE` or in the `passphrase_file`), the key file, or access to the key
endpoint. Nothing from the old host's database or data directory is required.

```bash
docker stop <container name>
docker run --rm -i -t -v kubidmd:/data -v kubidmd_backups:/backup \
    -e KUBIDM_BACKUP_PASSPHRASE \
    kubidm/server:latest /sbin/kubidmd database restore -c /data/server.toml \
    /backup/backup-2024-01-01T22:00:00Z.json.gz.enc
docker start <container name>
```

The commands fail with a clear message, and leave the target database untouched, when the artifact is encrypted and
encryption is not enabled in the configuration, when the secret can not be obtained, when the configured
`key_identifier` differs from the one in the artifact, or when the secret does not decrypt it. Each message names the
key identifier recorded in the artifact. Plain backups made before encryption was enabled keep restoring with an
encrypting configuration, with a warning: the encryption key does not protect their integrity, so only restore a plain
backup whose origin you trust.

A deployment that has turned encryption on keeps its secret outside of the backups it protects. Store the passphrase or
key file in a password manager or secret store that survives the loss of the server, and test a restore from it.

#### Key Rotation

Changing the secret only affects the backups made from then on. Every existing artifact stays encrypted with the key it
was written with and needs that key to be restored; its key identifier says which. When rotating, keep the previous
secret for as long as backups made with it are retained, and give each key its own `key_identifier` so that
`list-backups` and the error messages tell the two apart. To restore an artifact made with a previous key, point the
configuration at that secret (and its identifier, if one was configured) for the duration of the restore.

#### Encrypted Backups and Replication

Client-side encryption and [cross-region replication](#cross-region-backup-replication) combine without further
configuration. Replication copies the artifact exactly as it was uploaded, so every region holds the same
`backup-<timestamp>.json[.gz].enc` objects and the same plaintext `.metadata.json` sidecars (`encrypted = true` and the
key identifier included) as the primary. The replicated objects are never decrypted or re-encrypted in transit: a
region's credentials and server-side encryption settings never give access to the backup content, and the server-side
encryption of a region is applied on top of the client-side encryption.

The sync and health checks compare the SHA-256 and size of the encrypted objects, which is all they need: a missing or
differing `.enc` copy is repaired from the primary like a plain one, without the encryption key. With `--region`,
`list-backups` shows which copies are encrypted and with which key identifier, and `verify-s3` and `restore-s3` decrypt
a region's copy with the `[online_backup.encryption]` section of the configuration they are given, exactly as for the
primary. Recovering from a replica therefore needs the same secret as recovering from the primary; keep it available
independently of the primary region. Key rotation applies to replicas as well: a replicated backup keeps needing the key
it was written with.

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
# How the open segment survives an unclean stop: "Commit" (default), "Interval" or "Off".
# open_segment_journal = "Commit"
# With "Interval": sync the journal at most this often. Default 1000.
# journal_sync_interval_ms = 1000
# Archive in another S3 location than [online_backup.s3]:
# [online_backup.wal_archive.s3]
# bucket = "kubidm-wal"
# region = "us-east-1"
# That location can replicate the archive to regions of its own:
# [online_backup.wal_archive.s3.replication]
# enabled = true
# [[online_backup.wal_archive.s3.replication.regions]]
# region = "eu-west-1"
# bucket = "kubidm-wal-eu"
```

WAL archiving requires `online_backup.enabled = true`, since recovery always starts from an online backup.

#### Where the Archive Lives

- **Segments.** Committed changes are collected into segments. A segment is closed when its records reach
  `segment_size_bytes` or when it is `segment_interval_seconds` old, and written to the local WAL directory as a gzip
  JSON file with a `.meta.json` sidecar that records its CID range and SHA-256.
- **Archive location.** When `[online_backup.wal_archive.s3]` or `[online_backup.s3]` is configured, closed segments are
  uploaded under `<path_prefix>/wal/` (each with a `.metadata.json` object) and removed locally once the upload
  succeeded. Otherwise they stay in the local WAL directory. With [client-side encryption](#the-encrypted-wal-archive)
  enabled, every archived segment is encrypted and named `<segment>.enc`, in S3 and in the local directory alike.
- **Manifest.** `pitr-manifest.json`, in the archive location, indexes the base backups with their CID watermark (the
  last transaction they contain), the segments, and the gaps and abandoned history described below. It records the
  server it belongs to, and a server refuses to archive into another server's manifest: give every server its own
  location. A server that changes its own identity keeps its archive, see
  [Server Identity Changes](#server-identity-changes). In S3 the manifest is a single object that carries its SHA-256 in
  its own metadata, without a `.metadata.json` object, so a save that fails or is interrupted leaves the previous
  version whole. A base backup whose object or metadata object is gone drops out of the index.
- **Base backups.** Every successful scheduled online backup is indexed as a base: the S3 backup when
  `[online_backup.s3]` is configured, otherwise the local one. When the bases are local, a manual
  `kubidmd database backup` written into `online_backup.path` under a backup name is a base as well, see
  [Manual Backups as Recovery Bases](#manual-backups-as-recovery-bases). Recovery becomes possible with the first base
  taken after WAL archiving was enabled. When only `[online_backup.wal_archive.s3]` is set, segments go to S3 but base
  backups stay in the local directory, so recovery needs that directory too.

The archive task runs every `segment_interval_seconds`: it closes a segment older than that, archives (encrypts,
uploads) closed segments, updates the manifest, applies retention and
[mirrors the archive to the replication regions](#the-wal-archive-and-replication). A clean shutdown closes and archives
the open segment, so nothing committed is left behind.

#### Retention

Backup retention (`versions`) is unchanged. Base backups that it deletes drop out of the manifest at the next archive
run. An archived segment is deleted once it is older than `retention_days` **and** no longer needed by the oldest base
backup still present, so the archive always reaches back to the oldest base backup, however small `retention_days` is.

#### What Can Be Lost

Records live in memory until their segment is closed, and every commit also appends them to the journal of the open
segment, `<segment>.journal` in the WAL directory. If the server stops without shutting down (a crash, a kill, a power
loss), the next start closes the open segment, and any closed segment that was not written yet, from its journal, so the
archive loses nothing. The journal is the record of what was committed and not archived yet: a journal is only removed
once a written segment holds its records. `open_segment_journal` sets how durable the journal is:

- `Commit` (the default) syncs the journal to disk in every write commit, before the commit returns, so the journal
  holds every commit the database holds, whatever stops the server. It costs one more disk sync per write transaction,
  on top of the sync of the database itself. Write transactions are serialised and every authentication writes its
  session, so on slow storage (a network volume at 5-20 ms per sync) this bounds the write throughput and adds to the
  latency of every login.
- `Interval` writes the journal in every commit and syncs it every `journal_sync_interval_ms` when it changed: a crash
  or kill of the server still loses nothing, since the operating system holds what was written, while a power loss or an
  operating system crash can lose the commits of that interval.
- `Off` keeps the open segment in memory only, as before the journal existed: an unclean stop loses it.

Whatever the journal misses is detected: the database records its last committed transaction, the archive marks a
transaction as in flight before the database commits it, and the journal of the open segment records every commit,
including those that archived no change. The next start compares them, logs `WAL ARCHIVE HOLE` and records a **gap** in
the manifest from the first transaction the journal misses (the first record of the open segment with `Off`) up to the
last transaction the database committed. A journal that can not be written stops journaling for the rest of the run,
with an error. A committed transaction whose changes could not be recorded is logged and recorded as a gap the same way,
while a closed segment that could not be written (for example on a full disk) is kept in memory and retried at least
every `segment_interval_seconds`; once more than four such segments wait, the write is tried at once, and when it fails
again the oldest are dropped and recorded as gaps. A local segment that is found damaged is moved aside as
`<segment>.corrupt` and its range recorded as a gap. Gaps are kept in the WAL directory until the manifest records them,
so repeated crashes never lose one. Replaying across a gap would silently skip changes, so `recover` refuses any target
whose replay would cross one, and `--latest` stops right before it. A base backup taken after the gap makes later points
recoverable again; take one after any `WAL ARCHIVE HOLE`. With S3, segments that were closed but not yet uploaded are
lost with the host, which only shortens the recoverable window.

`recover` does not need the stopped server to start first, which a damaged database may not allow: it closes the open
segment from its journal itself, as the next start would, and replays it. Without the database it can not tell whether
the server committed anything after the last commit the journal holds, so `--latest` stops there; the next start of a
server on that WAL directory settles this against its database. `recover --dry-run` and `pitr-list` read the journal
without changing anything, so they may run next to the server.

The offline `kubidmd domain rename` and `kubidmd database reindex` commands archive their writes like the running server
does; the next server start uploads them. The `kubidmd db-scan quarantine-id2entry` and `restore-quarantined` repair
commands move an entry in or out of the database without a transaction the archive could record, so each records a
**gap**: from just after the last transaction the database committed up to the time of the command, with a reason naming
`db-scan`. The command first makes the change in its write transaction, so that a wrong id or an entry that is not
quarantined fails before anything is recorded; then it hands the gap over through the WAL directory (a file in
`.handed-over-gaps/`) and commits. A commit that fails takes the gap back. A server owns the manifest, and the command
may run next to it, so the command never writes the manifest itself: the server records the gap at its next start or
archive run, and `recover` and `pitr-list` honour it from the WAL directory meanwhile. When the gap can not be handed
over, the command refuses to change the database and exits non-zero, as it does when the change fails. Recovery then
stops right before the repair, and an online backup taken after it makes later points recoverable again: take one after
using these commands. Start the server after a repair before recovering on another host, which only sees the gaps the
manifest records.

#### Manual Backups as Recovery Bases

A manual backup captures the database exactly like an online backup: one read transaction, whose last committed
transaction is the watermark the backup records. When WAL archiving is enabled, the base backups are local
(`online_backup.path` without `[online_backup.s3]`), and the backup is written into `online_backup.path` under the name
an online backup would have, `backup-<RFC3339 UTC time>.json`, then `.gz` when compressed and `.enc` when encrypted, it
is a base like any other:

```bash
kubidmd database backup -c /data/server.toml \
    "/var/lib/kubidm/backups/backup-$(date -u +%Y-%m-%dT%H:%M:%SZ).json.gz"
```

The command prints whether the backup became a base, and why not. Since it may run next to a running server, which owns
the manifest, it does not write the manifest itself: it hands the base over through the WAL directory (a file in
`.handed-over-bases/`), the server indexes it at its next archive run, and `recover` and `pitr-list` use it from there
meanwhile. A backup of another server's database is never indexed. Backup retention counts such a backup with the online
backups of the directory, so it is pruned with them. With S3 base backups a manual backup is never a base: the archive
pairs its segments with the online backups in S3, and a local file would not be there for a recovery on another host.

#### Server Identity Changes

A replication refresh (a server joining a topology, or catching up after it fell too far behind) replaces the whole
database together with its domain and server uuids, and restoring or recovering a backup can put a database with another
server uuid in place (a backup taken before a refresh, or one of another server). The archive follows the server under
its new identity: the open segment is closed under the old uuid, the change is recorded in the manifest
(`server_uuid_changes`), and segments, base backups and `--target-cid` CIDs of every earlier identity stay valid.

A change of identity is a boundary for recovery. The state after it does not follow from the history before it, so a
base backup taken under another identity never replays across it: `recover` refuses such a target, naming the change,
and `--latest` stops right before it. Take an online backup after a refresh to make later points recoverable. A change
that a later restore or recovery abandoned no longer counts, and a recovery to a point before a refresh continues the
archive under the identity it restored.

#### Listing Recovery Points

```bash
kubidmd database pitr-list -c /data/server.toml
```

prints the base backups with their watermarks, the segments with their CID ranges and record counts (marking the
segments still only in the local WAL directory, and the key identifier of encrypted segments), any gaps and abandoned
history, and the recoverable window. It does not open the database, so it can run while the server is running, and it
needs no encryption key, since the manifest is not encrypted. It exits non-zero when nothing is recoverable yet.
`--region <name>` lists a replication region's copy instead.

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
- `--dry-run` prints the plan (base backup, segments, number of records, resulting point) and changes nothing. It reads,
  decrypts and checks every segment the recovery would replay, so it also proves that the archive up to the target is
  intact and that the configured key opens it.
- `--region <name>` recovers from a replication region's copy, see
  [The WAL Archive and Replication](#the-wal-archive-and-replication).

The command reads the `[online_backup]` section of the configuration to find the archive and the base backups, so the
same `server.toml` works on a replacement host. It uses the segments of the same server still in the local WAL directory
that were never archived. It then:

1. reads every segment it replays, decrypts it when it is encrypted, and checks it against the SHA-256 the manifest
   recorded;
2. downloads (from S3) or opens the base backup, decrypts it when it is encrypted, restores it into the configured
   database and replays the records after its watermark, in CID order, in the same database transaction, so that a
   failure leaves the database untouched;
3. records in the manifest that the history after the recovered point was **abandoned**, right after the commit, since
   the database no longer holds that history whatever happens next;
4. reindexes, boots and verifies the recovered database like `verify-backup --level full`.

Abandoned history is never replayed again: after recovering to 10:30, the server started on the recovered database
writes new history, and a later recovery to any point after it replays the recovered state plus the new history, never
the transactions that were discarded. `kubidmd database restore` and `restore-s3` record abandoned history the same way
when WAL archiving is configured. They record it in the primary archive, the one the server archives into. When that
archive can not be updated (for example while restoring with `restore-s3 --region` during an outage of the primary, or
when its bucket does not exist), they restore the database, hand the abandoned history to the server through its WAL
directory, and exit with code 2 and a warning: the restore succeeded and must not be repeated or rolled back. The server
records the abandoned history, and the change of server uuid when the restored backup carries another one, at its first
archive synchronisation that reaches the archive, before it archives anything else. Should even the WAL directory not be
writable, the error says so and the command exits with code 3: a later point-in-time recovery past the restore could
then replay the abandoned history until a new online backup is taken, so take one right after starting the server.
`recover` behaves the same way, and also records the abandoned history in the region it recovered from. A restore or
recovery that failed exits with code 1, including one whose reindex or verification failed after the commit: its error
then says that the database WAS restored, and whether to run `kubidmd database reindex` before the server starts or to
recover to another point.

#### The Encrypted WAL Archive

A segment holds the full state of every entry the archived transactions changed, password hashes and other credentials
included, so it needs the same protection as a backup. When `[online_backup.encryption]` is enabled, the archive task
encrypts every closed segment with the backup encryption scheme (AES-256-GCM, a key derived with Argon2id, the
configured `key_identifier` in its header) before it leaves the server's WAL bookkeeping:

- With S3, the encrypted segment is uploaded as `wal/<segment>.enc`, with `encrypted = true` and the key identifier in
  its `.metadata.json`.
- With the local archive, it is written next to the plaintext as `<segment>.enc`, and the plaintext segment is removed
  as soon as the manifest records the encrypted copy.
- In the local archive, plaintext segments archived before encryption was enabled are encrypted by the next archive run.
  Segments already uploaded to S3 stay as they were uploaded; recovery reads plain and encrypted segments alike.
- When the key can not be obtained, nothing is archived: the closed segments stay in the WAL directory, the run is
  logged as failed, and the next run retries. A segment is never archived in plaintext while encryption is enabled.

The only plaintext copies of archived changes are the open segment, held in memory and in its journal, and closed
segments waiting for their archive run (at most `segment_interval_seconds`), all in the WAL directory next to the
database, which holds the same data. The manifest records for every segment the key identifier it was encrypted with,
and keeps the SHA-256 of the plaintext segment, which recovery checks after decrypting.

Argon2id is deliberately slow, and segments are small and many, so one derivation per segment would make reading a large
archive slow. The segments a server archives are therefore sealed in an encryption session: they share one random salt,
and so one derived key, from the server start (or the last change of the key) for up to 2^20 segments, while every
segment keeps a random nonce of its own and its id in the authenticated header. A recovery derives the key once per
session and keeps the derived keys in memory, wiped when the command ends. The server likewise keeps the key of its
session in memory while it runs, wiped when it stops or the configured key changes. Sharing the key does not make
segments interchangeable: a segment stored under the id of another one is still refused. Backups keep a fresh salt each.

`recover` decrypts with the `[online_backup.encryption]` section of the configuration it is given, exactly like
`restore`; the key is only obtained when an encrypted segment or base backup is actually read. It fails, and changes
nothing, when a segment is encrypted and encryption is not enabled, when the key can not be obtained, or when it does
not open the segment, naming the key identifier the segment needs. A segment the manifest records as encrypted must be
an encrypted container, so a plain object can not be swapped in for it, and an encrypted segment must have been sealed
under the segment id it is stored as, so another segment can not be swapped in either. Base backups are encrypted by the
same setting, so one secret recovers both. Key rotation works as for backups: keep every previous secret for as long as
segments or base backups written with it are retained, which is at least `retention_days` and the age of the oldest base
backup.

#### The WAL Archive and Replication

When the S3 location the archive is uploaded to has an enabled replication section (`[online_backup.s3.replication]`
when the archive shares `[online_backup.s3]`, or `[online_backup.wal_archive.s3.replication]` for a separate location),
every archive run mirrors the archive to every region of that section, after its own work is done:

1. the segments a region misses, or holds a differing copy of, are copied from the primary (checked against the
   primary's checksum; bytes and sidecar unchanged, so encrypted segments stay encrypted and a region never needs the
   key). Every run compares the listings: a copy whose object or `.metadata.json` is missing, or whose size differs from
   the primary's, is copied again. Once per `sync_interval_seconds` of the replication section the sidecars are compared
   as well, 16 at a time and after the run released the manifest, so that neither archiving nor the indexing of a base
   backup waits on it, which catches a copy replaced by one of the same size. A copy that fails is retried by the next
   run and does not keep the region's manifest from being written; a segment the primary lacks is never copied;
2. the region's `pitr-manifest.json` is written: the primary's manifest, plus whatever only the region still records (so
   that a region keeps the history a primary that lost its archive no longer has). A region manifest that can not be
   read, or does not match its checksum, is written again from the primary's;
3. the region applies the archive retention rules to its own copy: base backups it no longer holds drop out of its
   index, and segments older than `retention_days` that its oldest remaining base backup does not need, and that the
   primary no longer lists, are deleted.

A region that fails is logged and retried by the next run; it never fails the archiving. A new base backup is mirrored
right after it is indexed. The base backups themselves reach the regions through the
[backup replication](#cross-region-backup-replication), and only when they are in `[online_backup.s3]`; a region of a
separate WAL location only has base backups when `[online_backup.s3]` replicates to a region of the same name, which
`recover --region` requires. When the base backups are local, recovering from a region needs the local backup directory.
Without an S3 archive location there is nothing to replicate: a local archive is never replicated. `replicate-status`
reports the state of every region's copy of the archive, see
[Checking Replication Status](#checking-replication-status), and `pitr-list --region <name>` shows what a region's
archive holds.

`pitr-list --region <name>` and `recover --region <name>` read the copy of the archive held by the configured region of
that name (looked up whether or not replication is still enabled), and the base backups from the same region when they
are in S3. Only the base backups the region actually holds are used. A recovery from a region records the abandoned
history in the region's manifest and, if it can be reached, in the primary's. When it could not be, the recovered server
takes the abandoned history from the region into the primary archive at its first archive run that reaches both, so a
later recovery from either location never replays it.

```bash
# The primary bucket is unavailable: recover from the eu-west-1 copy (server stopped)
kubidmd database pitr-list -c /data/server.toml --region eu-west-1
kubidmd database recover -c /data/server.toml --region eu-west-1 --latest
```

Base backups and segments can only be used by the server version that wrote them, like backups. In a replicated
topology, treat a recovered node like a restored one: the other nodes must be refreshed from it.

### How the Features Combine

| Artifact                                  | Where                                               | Encrypted with `[online_backup.encryption]` | Replicated to regions                        | Recovered with                     |
| ----------------------------------------- | --------------------------------------------------- | ------------------------------------------- | -------------------------------------------- | ---------------------------------- |
| Online backup                             | `online_backup.path` and/or `[online_backup.s3]`    | yes (`.enc`)                                | S3 copy, by `[online_backup.s3.replication]` | `restore`, `restore-s3 [--region]` |
| Manual backup (`kubidmd database backup`) | the path given                                      | yes                                         | no                                           | `restore`; `recover` as a base     |
| WAL segment                               | `wal/` of the archive's S3 location, or the WAL dir | yes (`.enc`)                                | when the archive's S3 location replicates    | `recover [--region]`               |
| `pitr-manifest.json`                      | next to the segments                                | no (holds no directory content)             | with the segments                            | read by `pitr-list` and `recover`  |
| `.metadata.json` sidecars                 | next to every S3 object but the manifest            | no (checksum, size, key identifier)         | with their object                            | checked by every download          |

Every combination is supported. Things to keep in mind when combining them:

- **One secret for everything.** Backups, base backups and WAL segments are encrypted with the same configured key. A
  cold recovery on a new host needs the `server.toml` and that secret, nothing from the old host. Replicas need the same
  secret: keep it available independently of the primary region.
- **Verification.** `verify-backup` and `verify-s3 [--region]` prove that a (base) backup restores, decrypting it with
  the configured key; `recover --dry-run [--region]` proves that the WAL segments up to a target are intact and decrypt.
  Together they verify a point-in-time recovery without touching the database.
- **Disaster recovery from a region.** With S3 backups, replication and PITR, a region holds the encrypted base backups,
  the encrypted segments and the manifest. `recover --region <name> --target-time ...` alone rebuilds the database as of
  any recoverable point; `restore-s3 --region <name>` restores a single backup.
- **Retention.** `versions` applies to the backups in every location, `retention_days` to the WAL archive in every
  location, and in every location the archive keeps the segments its oldest base backup needs.

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

Both commands decrypt a client-side encrypted artifact with the key named in the configuration, see
[Client-Side Backup Encryption](#client-side-backup-encryption), and fail when they can not.

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
which makes it suitable for backup automation. The running server can also run it on a schedule, see
[Scheduled Full Verification](#scheduled-full-verification).

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

## Monitoring Backups

A backup that silently stopped being taken, or that can no longer be restored, is only noticed when it is needed. The
server can prove the restorability of its newest backup on a schedule, and expose when every backup location last
received, failed and verified a backup, so that both can be alerted on.

### Scheduled Full Verification

With `verify_schedule` set, the server runs the [full verification](#full-verification) of its newest backup on that
schedule, using the same cron syntax as `schedule`. It is off by default and requires `enabled = true`.

```toml
[online_backup]
path = "/var/lib/kubidm/backups"
schedule = "00 22 * * *"
# Every Sunday at 03:30 UTC
verify_schedule = "30 3 * * Sun"
# Where the scratch data goes; the directory of the database by default.
# verify_temp_path = "/var/lib/kubidm/verify"
```

A run verifies the newest backup of the local backup directory and, when `[online_backup.s3]` is configured, the newest
complete backup of the S3 prefix, each picked by the time in its name:

- A local backup is first copied into a scratch directory, so that retention removing it meanwhile can not fail the run;
  when it disappears before it is copied, the directory is listed once more. An S3 backup is downloaded and checked
  against the SHA-256 of its metadata sidecar; when the download fails for another reason, the prefix is listed once
  more.
- The artifact is opened as a restore opens it (an encrypted backup is decrypted with the configured key), checked
  structurally, restored into a scratch database through the production restore and reindex code, booted as a server
  start would boot it, and checked with the consistency checks of `kubidmd database verify`.
- When the newest S3 backup holds exactly the bytes of the local backup the same run just verified (the same name and
  SHA-256, as it does when one online backup stored both), that verification counts for both instead of restoring the
  same backup twice. The download is still checked.
- The result is logged and recorded in the [metrics](#backup-metrics), with three outcomes kept apart:
  - **passed**: an info line, and the last verification time moves;
  - **failed**: the artifact can not be restored (it can not be decrypted or parsed, fails the structural checks, the
    restore, the boot or the consistency checks, or does not match its S3 checksum). An error with the reasons, and the
    verification failure metrics move;
  - **could not run**: the backups could not be listed, copied or downloaded, the encryption key could not be obtained,
    or the scratch space could not be used. An error that says so, and only the verification error metrics move: it is
    no verdict on the backup.

The live database is never opened. Every scratch directory of a run (the copied or downloaded artifact, the scratch
database) is named `kubidm-verify-*` and created in `verify_temp_path`, by default the directory of the database. The
scratch database is not encrypted, like the one of `kubidmd database verify-backup`, so the default keeps it as private
as the database; a `verify_temp_path` must be too. The directories are removed when the run ends, and at the next start
when the process was killed during a run. Because of that clean-up, `verify_temp_path` must not be shared with another
server.

Things to plan for:

- **Resources.** The verification boots a second database inside the server process. It needs the disk space of the
  artifact and of a restored database in `verify_temp_path`, memory for the whole artifact while it is checked (and for
  an S3 download, which is held in memory before it is written), and the time of a restore, all proportional to the size
  of the database. The scratch database uses the smallest entry cache and a single connection, so it adds little to the
  memory of the running server beyond the artifact. Schedule it outside busy hours, and less often than the backups for
  a large directory.
- **Never at the same time as a backup.** A verification and an online backup each hold a whole artifact in memory, so
  they never run at the same time: a verification that falls due during a backup starts when the backup ends, and a
  backup that falls due during a verification starts when the verification ends. Schedule them apart so that a backup is
  not delayed. The blocking work runs on the blocking thread pool, and the restore, reindex and boot of the scratch
  database on a dedicated database thread, never on the threads that serve requests.
- **No overlap.** A run that outlasts the gap to its next scheduled time skips the times that are already past; two runs
  never overlap.
- **Nothing to verify yet** (no backup was taken) is logged as a warning, not counted as a failure: the last success
  metric already shows it.
- **Maintenance and shutdown.** A run is skipped while the node is in maintenance (drained or fenced), since the scratch
  server writes while it boots. On shutdown, a run in progress is abandoned: it stops before its next step (the restore,
  the reindex, the boot and the consistency checks) and removes its scratch directories. The process waits at most 5
  seconds for it before it exits; the next start removes what was left. Neither is counted as a failure.

### Backup Metrics

With `metrics_endpoint = true` the server serves its backup metrics in the Prometheus text exposition format on
`GET /metrics`, on its HTTPS listeners. It is off by default: the metrics reveal when backups run, where they are stored
(the names of the replication regions) and whether they fail, which tells an attacker whether a destructive attack could
be recovered from. Without it, `/metrics` answers 404 like any other unknown path.

Restrict who can read it, in one or both of these ways:

- Set `metrics_token_file` to a file holding a token: a request must then send `Authorization: Bearer <token>`, and is
  answered 401 otherwise. The server reads the file when it starts, and the start fails when it is missing or empty.
  The offline commands (`database backup`, `restore`, `recover`, `db-scan` and the others) never read it, so it can be
  mounted for the server alone.
- Block `/metrics` on the reverse proxy or load balancer that exposes the server, and scrape the server directly.

```toml
[online_backup]
path = "/var/lib/kubidm/backups"
metrics_endpoint = true
metrics_token_file = "/etc/kubidm/metrics-token"
```

| Metric                                                      | Type    | Labels                  | Meaning                                                              |
| ----------------------------------------------------------- | ------- | ----------------------- | -------------------------------------------------------------------- |
| `kubidm_backup_last_success_timestamp_seconds`              | gauge   | `destination`, `region` | Unix time of the newest backup stored in the destination             |
| `kubidm_backup_last_failure_timestamp_seconds`              | gauge   | `destination`, `region` | Unix time of the last backup that could not be stored there          |
| `kubidm_backup_failures_total`                              | counter | `destination`, `region` | Backups that could not be stored there                               |
| `kubidm_backup_verification_last_success_timestamp_seconds` | gauge   | `destination`           | Unix time the newest artifact last passed the full verification      |
| `kubidm_backup_verification_last_failure_timestamp_seconds` | gauge   | `destination`           | Unix time the newest artifact last failed it: it can not be restored |
| `kubidm_backup_verification_failures_total`                 | counter | `destination`           | Full verifications the newest artifact failed                        |
| `kubidm_backup_verification_last_error_timestamp_seconds`   | gauge   | `destination`           | Unix time the full verification last could not run                   |
| `kubidm_backup_verification_errors_total`                   | counter | `destination`           | Full verifications that could not run                                |
| `kubidm_backup_pitr_sync_last_success_timestamp_seconds`    | gauge   |                         | Unix time of the last successful WAL archive synchronisation         |
| `kubidm_backup_pitr_sync_last_failure_timestamp_seconds`    | gauge   |                         | Unix time of the last failed WAL archive synchronisation             |
| `kubidm_backup_pitr_sync_failures_total`                    | counter |                         | Failed WAL archive synchronisations                                  |

- `destination` is `local` (`online_backup.path`), `s3` (`[online_backup.s3]`) or `s3_region`, with `region` set to the
  name of the replication region. A region counts a backup as stored when the copy made by the backup run, or later by
  the replication monitor, succeeded. It counts a failure when such a copy failed, the region could not be listed, or
  the backup run never reached it (the artifact could not be produced, or the upload to S3 failed).
- The verification series exist for `local` and `s3` when `verify_schedule` is set. Regions are not verified on their
  own: they hold copies of the S3 artifact, which is.
- A WAL archive synchronisation fails when the archive could not be written or uploaded, its closed segments could not
  be written to the local directory, or it could not be mirrored to one of the replication regions of its S3 location,
  including when the region copies could not be checked or a damaged copy could not be repaired.
- Every destination the configuration names is reported from the start, with `0` for "never", so an alert on a stale
  timestamp also fires for a destination that never received a backup. The WAL archive series exist when
  `[online_backup.wal_archive]` is enabled.
- **Restarts.** The timestamps survive a restart. They are written to `kubidm-backup-metrics.json` in the directory of
  the database whenever they change, and read back when the server starts. The last success of every destination is also
  taken, at start, from the newest complete backup it holds (by the time in its name), which covers a server that has no
  state file yet; for S3 and the regions this is read in the background within seconds of the start. The counters
  restart at `0`, as Prometheus expects of a restarted process: alert on them with `increase()`.
- Backups taken by `kubidmd database backup` and verifications by `kubidmd database verify-backup` run in another
  process and are not counted.

A scrape configuration and alert rules for a daily backup and a weekly verification:

```yaml
scrape_configs:
  - job_name: kubidm
    scheme: https
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/kubidm-metrics-token
    static_configs:
      - targets: ["idm.example.com:8443"]

groups:
  - name: kubidm-backups
    rules:
      - alert: KubidmBackupStale
        expr: time() - kubidm_backup_last_success_timestamp_seconds > 26 * 3600
        for: 15m
      - alert: KubidmBackupFailing
        expr: increase(kubidm_backup_failures_total[1d]) > 0
      - alert: KubidmBackupNotVerified
        expr: time() - kubidm_backup_verification_last_success_timestamp_seconds > 8 * 86400
        for: 15m
      - alert: KubidmBackupVerificationFailing
        expr: increase(kubidm_backup_verification_failures_total[8d]) > 0
      - alert: KubidmBackupVerificationCanNotRun
        expr: increase(kubidm_backup_verification_errors_total[8d]) > 0
      - alert: KubidmWalArchiveStale
        expr: time() - kubidm_backup_pitr_sync_last_success_timestamp_seconds > 3 * 300
        for: 15m
```

The `for:` durations only absorb the seconds a start needs to read the S3 listings; the alerts do not depend on them to
survive a restart.

## Method 2 - Manual Backup

This method uses the same process as the automatic process, but is manually invoked. This can be useful for pre-upgrade
backups

To take the backup (assuming our docker environment) you first need to stop the instance:

```bash
docker stop <container name>
docker run --rm -i -t -v kubidmd:/data -v kubidmd_backups:/backup \
    kubidm/server:latest /sbin/kubidmd database backup -c /data/server.toml \
    /backup/kubidm.backup.json.gz
docker start <container name>
```

You can then restart your instance. DO NOT modify the backup file as it may introduce data errors into your instance.

With WAL archiving enabled, a manual backup written into the local base backup directory under a backup name is also a
point-in-time recovery base, see [Manual Backups as Recovery Bases](#manual-backups-as-recovery-bases).

The manual backup uses the `compression` and the `[online_backup.encryption]` settings of the configuration. Name the
file after the compression: `.json.gz` with the default gzip, `.json` with `compression = "NoCompression"`. Restore
takes the compression of a plain backup from its name, so a name with another suffix is refused before anything is
written. With encryption enabled, the file written is an encrypted container whatever its name; name it with the `.enc`
suffix (`/backup/kubidm.backup.json.gz.enc`) to keep it recognisable, and keep the key, see
[Client-Side Backup Encryption](#client-side-backup-encryption).

To restore from the backup:

```bash
docker stop <container name>
docker run --rm -i -t -v kubidmd:/data -v kubidmd_backups:/backup \
    kubidm/server:latest /sbin/kubidmd database restore -c /data/server.toml \
    /backup/kubidm.backup.json.gz
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
configuration, which allows restoring on a host whose `server.toml` has no `[online_backup.s3]` section. The key is then
the full object key, since there is no `path_prefix`, and the signing region and the credentials come from the AWS
environment (`AWS_REGION`, `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`) or the instance role. `--region <name>`
restores from the copy held by a replication region, see [Recovering from a Region](#recovering-from-a-region).

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
