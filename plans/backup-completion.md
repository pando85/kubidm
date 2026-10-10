# Backup and restore completion plan

Single source of truth for finishing backup and restore in Kubidm. Goal: replication, client-side encryption and
WAL/PITR are all functional, tested and documented, delivered in one PR.

Last updated: 2026-10-10. Status: all planned work is implemented and verified on `backup/final`, including the fixes of
the review rounds below. Only the limitations and follow-ups listed below remain.

## Decisions

- All three half-built features are implemented, none removed (issues #454, #455, #456).
- One consolidated PR against master from `backup/final`. Earlier PRs #460, #461 and #462 are superseded by it and
  closed when it opens. #450 is already merged.
- The new encryption design replaces the old, unwired `encryption.rs` module.
- S3 test backend is Silo (`pgsty/silo:RELEASE.2026-09-16T00-00-00Z`, pinned by digest in CI), a MinIO fork. MinIO
  images are no longer pullable. CI uses port 9000 and the credentials from `KUBIDM_TEST_S3_ACCESS_KEY` /
  `KUBIDM_TEST_S3_SECRET_KEY`.

## Branches

| Branch                    | Base              | Content                                                                           | Status                         |
| ------------------------- | ----------------- | --------------------------------------------------------------------------------- | ------------------------------ |
| `backup/complete`         | master            | Phase 1 S3 recovery, Phase 2a/2b verification, Silo CI, #459 fix                  | Merged into `backup/final`     |
| `backup/feat-replication` | `backup/complete` | Replicate to regions, health monitor, `replicate-status`, `--region`              | Merged into `backup/final`     |
| `backup/feat-encryption`  | `backup/complete` | Encrypt on write, decrypt on restore, `.enc` naming, config checks                | Merged into `backup/final`     |
| `backup/feat-pitr`        | `backup/complete` | WAL archiver, manifest, `pitr-list`, `recover`                                    | Merged into `backup/final`     |
| `backup/final`            | master            | Everything above, plus encrypted and replicated WAL archive and the combined docs | Verified, the single PR source |

## Work items

### Done

- [x] Phase 0: stop advertising unimplemented features (#450, merged)
- [x] Phase 1: `restore-s3`, `verify-s3`, `list-backups`, S3 retention, SHA-256 check, pagination
- [x] Phase 2a: cold `database verify` ordering fix and entry diagnostics
- [x] Phase 2b: verify every backup right after it is written, quarantine bad ones as `.invalid`
- [x] Silo replaces s3mock in CI and tests
- [x] #459 S3 listing matches sibling prefixes (lists under the exact prefix)

### Replication (#454)

- [x] Replicate object and sidecar after upload, errors never fail the primary backup
- [x] Per-region `versions` retention
- [x] Health monitor task driven by `sync_interval_seconds`, catching up backups a region missed
- [x] `replicate-status [--detailed]`, `--region` on `restore-s3`, `verify-s3`, `list-backups`
- [x] Config validation (rejects self-replication and shared locations), docs, example config
- [x] End to end test against Silo
- [x] Independent review, findings fixed

### Client-side encryption (#455)

- [x] Encrypt on write (online, offline, scripting), decrypt on restore and verify
- [x] `.enc` artifact naming through retention, listing and quarantine
- [x] Key sources: passphrase (env or file), key file, HTTP endpoint
- [x] Config validation, docs, example config
- [x] End to end tests including S3 and replication of an encrypted backup
- [x] Independent review, findings fixed (authenticated header, key handling)
- [x] Zeroize key material (`Zeroizing` buffers)
- [x] Test the HTTP key endpoint against a live local server
- [x] Key derivation, encryption and verification run off the Tokio runtime

### WAL archiving and PITR (#456)

Design: every committed write records the full serialised entry under the transaction CID, so replay is an overwrite.
Recovery restores the newest base backup at or before the target, then applies later records in CID order.

- [x] Backend hook archives committed writes, replay by uuid
- [x] Failed flushes keep records, archive gaps are reported and recorded
- [x] Segment roll by size and by time
- [x] Uploader task, remote retention guarded by the oldest retained base backup
- [x] Manifest with base backup CID watermarks, abandoned history and gaps
- [x] `pitr-list` and `recover` (with `--dry-run`)
- [x] Config validation, docs, example config
- [x] End to end test: recover to a point in time and to latest, local and S3, and refuse to cross a gap
- [x] Encrypted WAL archive, replicated to regions, `recover --region` and `pitr-list --region`

### Integration

- [x] Stack replication, encryption and PITR on `backup/final`
- [x] Resolve overlaps: `proto/src/backup.rs`, `server/core/src/lib.rs`, `s3.rs`, `v1_read.rs`, `config.rs`,
      `interval.rs`, daemon CLI, book and example config
- [x] Full verification: fmt, clippy `-D warnings`, `cargo metadata --locked`, `cargo test --workspace` (2321 passed),
      codespell, backup e2e tests against Silo (backup 48, `s3_` 43, pitr 5, `database_verify` 2, replication 9,
      encryption 5)
- [x] Open the single PR, close #460, #461, #462; it closes #454, #455, #456, #459 and #360

### Known limitations, follow-ups

- [ ] `replicate-status` reports backups only, not the WAL archive (`pitr-list --region` shows a region's archive)
- [x] Per-segment key derivation (Argon2id with a fresh salt per segment) made decrypting large WAL archives slow:
      segments are sealed in an encryption session (one salt and derived key per server run, up to 2^20 segments, a
      random nonce and the segment id per segment) and decryption keeps derived keys by salt and parameters, zeroized
      on drop. The container format is unchanged, so segments sealed one by one still open; no release tag contains
      the WAL format (checked with `git tag --contains`)
- [ ] An unclean stop loses the open segment (up to `segment_interval_seconds` of WAL) from the archive, and more than
      four closed segments that can not be written are dropped; both are recorded as gaps that recovery does not cross,
      and only a new base backup makes later points recoverable
- [ ] A restore whose abandoned history can be recorded neither in the archive nor handed over through the WAL directory
      exits 3; until a new online backup is taken after the start, a recovery past it could replay that history
- [x] `db-scan` quarantine commands bypassed the WAL archive: `quarantine-id2entry` and `restore-quarantined` record a
      gap from just after the last committed transaction up to now before they change anything (in the manifest, or
      handed to the server through the WAL directory, else they refuse), so recovery never replays across them
- [ ] Manual `database backup` files are not PITR bases
- [x] The offline `restore` and `recover` ran their write transaction and reindex on the CLI's runtime: the restore,
      replay, reindex and boot verification now run on a dedicated database thread (`on_database_thread`), checked by
      a test that the single thread of a current thread runtime keeps ticking through a restore and a recovery
- [ ] A region of a separate `[online_backup.wal_archive.s3]` location only has base backups when `[online_backup.s3]`
      replicates to a region of the same name, which `recover --region` requires

### Follow-up issues, not blocking

- [ ] #453 migration schema cleanup filter never matches
- [ ] #457 backup metrics
- [ ] #458 scheduled full verification

## Review rounds

After the PR opened, three independent reviews (core and S3, encryption, PITR) and a second fix round found and fixed:

- Core and S3:
  - the scheduler built its cron iterator once, so a run longer than the gap to the next time wrapped the wait to about
    1.8e19 seconds and stopped backups until a restart; the next time is now computed from now and the wait saturates
  - a shutdown waited for a whole backup run; the run now races the shutdown signal so the final WAL sync happens
  - `.metadata.json` sidecars ignored the configured server-side encryption; every object now takes it from one place
  - `versions = 0` deleted every backup in every location; `versions >= 1` is required and the backup just written is
    never pruned
  - an object whose sidecar failed stayed behind and took a retention slot; it is removed, and only objects with a
    sidecar count
  - a dropped multipart upload left billed parts; a guard aborts it, and a missing upload id fails the upload
  - local backups are written to `.<name>.partial`, fsynced, verified under their final name and renamed; a stale
    partial file is removed by retention unless its writer still holds its lock
  - retention and listings ordered names as strings; they now order by the time in the name, and new names carry a fixed
    nine digit fraction
  - the offline commands moved from `lib.rs` to `backup/cli.rs` and `backup/restore.rs`; the online run is one
    `OnlineBackupJob` in `backup/online.rs`, used by the schedule and the tests
  - a backup run makes one attempt per region and never waits; the replication monitor does all retries, so
    `max_retries` and `retry_delay_seconds` are removed; regions take an optional `name` independent of the signing
    `region`
  - backup and restore report their outcome in the exit code: 0 complete, 1 failed, 2 restored and handed to the server,
    3 restored but a new online backup is needed
  - also: S3 request timeouts, invalid storage classes and AES256 with a KMS key refused at load, the online snapshot
    and all checksums on the blocking pool, one comparison per region per monitor run, S3 secrets never printed
- Encryption:
  - the key endpoint client uses no proxy and follows no redirect, and refuses any non-2xx answer
  - passphrase and key files are read on the blocking pool
  - Argon2id parameters from a header or the configuration are capped (1 GiB, 16 passes, 16 lanes, memory times passes
    at most 4 GiB)
  - the header binds what the artifact is (a backup and the timestamp of its name, or a WAL segment and its id), magic
    `KUBIDM_ENC_BACKUP_V2`; an older backup copied over a newer name, or one segment over another, no longer opens.
    `scripting backup --name` records the name of a backup written to stdout
- PITR:
  - `pitr.rs` is split into `backup/pitr/{settings,store,archive,replicate,recover}`
  - a server uuid change (replication refresh, restore of another server) continues the archive under the new identity
    and is recorded in `server_uuid_changes`; recovery never replays across it
  - gaps and other pending events are kept durably in `.pending-events.json` until a saved manifest records them
  - a failed segment write no longer stops the sync from archiving what is on disk; closed segments are sealed, written
    outside the archiver lock, and the unwritten backlog is bounded (four segments, then recorded as gaps)
  - every WAL file is fsynced and renamed atomically; damaged segments are set aside as `.corrupt` with a gap; segment
    ids and base keys from sidecars and manifests are validated
  - a restore whose archive can not be updated is handed to the server through the WAL directory and recorded at its
    first sync; abandoned history is recorded right after the commit, before the reindex
  - the S3 manifest is one object with its SHA-256 in its metadata; only `NoSuchKey` reads as absent; base backups whose
    object or sidecar is gone drop out of the index
  - recovery reads one segment at a time and keeps only the latest state of each entry
- Tests and CI:
  - one S3 gate in `backup_common`: without an endpoint the tests skip unless `KUBIDM_TEST_S3_REQUIRED` (or `CI`) makes
    them fail; `rust_build` requires them
  - the Silo image is pinned by digest
  - new e2e tests: restore and `restore-s3` then `recover --latest`, and recovery from a separate `wal_archive.s3`
    location and its regions
  - rustdoc links to private items fixed for the docs build
- Verification after the rounds: `cargo test --workspace` 2394 passed; e2e against Silo: backup 49, `s3_` 46,
  replication 9, encryption 5, pitr 9, `database_verify` 2

## How to resume

Every shell: `unset CARGO_TARGET_DIR`. Run the S3 tests against Silo:

```sh
docker run -d --rm --name silo -p 9000:9000 \
  -e MINIO_ROOT_USER=kubidm-test -e MINIO_ROOT_PASSWORD=kubidm-test-secret \
  pgsty/silo:RELEASE.2026-09-16T00-00-00Z server /data
KUBIDM_TEST_S3_REQUIRED=1 KUBIDM_TEST_S3_ENDPOINT=http://127.0.0.1:9000 \
  cargo test -p kubidmd_testkit --test integration_test -- backup s3_ replication encryption pitr database_verify
```

## Known caveats

- The Phase 2a cold-verify test passes with and without its fix. The on-disk schema entries it guards against come from
  #453.
- `--region` on the S3 recovery commands selects a replication region instead of overriding the signing region.
- The replication health check compares metadata and sizes. Same-size corruption is only caught by `verify-s3 --region`.
- An encrypted backup under a name that is not `backup-<timestamp>...` (a manual backup path, a copy on removable media)
  is not bound to a time and opens under any such name.
- A crash during a multipart upload can leave parts behind; a bucket lifecycle rule removes them.
- An S3 manifest without its checksum metadata (a copy tool that drops user metadata) is loaded with a warning only.
