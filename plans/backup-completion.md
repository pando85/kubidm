# Backup and restore completion plan

Single source of truth for finishing backup and restore in Kubidm. Goal: replication, client-side encryption and
WAL/PITR are all functional, tested and documented, delivered in one PR.

Last updated: 2026-10-10. Status: all planned work is implemented and verified on `backup/final`. Only the follow-ups
listed at the end remain.

## Decisions

- All three half-built features are implemented, none removed (issues #454, #455, #456).
- One consolidated PR against master from `backup/final`. Earlier PRs #460, #461 and #462 are superseded by it and
  closed when it opens. #450 is already merged.
- The new encryption design replaces the old, unwired `encryption.rs` module.
- S3 test backend is Silo (`pgsty/silo:RELEASE.2026-09-16T00-00-00Z`), a MinIO fork. MinIO images are no longer
  pullable. CI uses port 9000 and the credentials from `KUBIDM_TEST_S3_ACCESS_KEY` / `KUBIDM_TEST_S3_SECRET_KEY`.

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

- [ ] `restore` and `restore-s3 --region` record abandoned history only in the primary archive; if the primary is
      unreachable they exit non-zero (use `recover --region`)
- [ ] `replicate-status` reports backups only, not the WAL archive
- [ ] Per-segment key derivation makes decrypting large WAL archives slower
- [ ] A crash can lose up to `segment_interval_seconds` of WAL from the archive; it is recorded as a gap and recovery
      does not cross it
- [ ] `db-scan` quarantine commands bypass the WAL archive (documented)
- [ ] Manual `database backup` files are not PITR bases
- [ ] The online backup still serialises inside the read transaction on the runtime, and restore writes on the runtime
- [ ] An older valid encrypted backup copied under a newer name still restores

### Follow-up issues, not blocking

- [ ] #453 migration schema cleanup filter never matches
- [ ] #457 backup metrics
- [ ] #458 scheduled full verification

## How to resume

Every shell: `unset CARGO_TARGET_DIR`. Run the S3 tests against Silo:

```sh
docker run -d --name silo -p 9000:9000 \
  -e MINIO_ROOT_USER=kubidm-test -e MINIO_ROOT_PASSWORD=kubidm-test-secret \
  pgsty/silo:RELEASE.2026-09-16T00-00-00Z server /data
KUBIDM_TEST_S3_ENDPOINT=http://127.0.0.1:9000 \
  cargo test -p kubidmd_testkit --test integration_test backup
```

## Known caveats

- The Phase 2a cold-verify test passes with and without its fix. The on-disk schema entries it guards against come from
  #453.
- `--region` on the S3 recovery commands selects a replication region instead of overriding the signing region.
- The replication health check compares metadata and sizes. Same-size corruption is only caught by `verify-s3 --region`.
