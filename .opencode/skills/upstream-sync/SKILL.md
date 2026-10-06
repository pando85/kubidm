---
name: upstream-sync
description: Use when syncing changes from the upstream kanidm/kanidm repository into this kubidm fork. Use ONLY when the user asks to sync, rebase, merge, or bring changes from upstream/kanidm. Covers fetching upstream, triaging conflicts with a rebranded 3-way merge, splitting resolution across agents, resolving rename conflicts (kanidm -> kubidm), verifying, and opening the PR.
---

# Upstream Sync: kanidm -> kubidm

This skill handles syncing changes from the upstream `kanidm/kanidm` repository into the
`pando85/kubidm` fork.

Last run: 2026-10-06, PR #445 (43 upstream commits, 345 files, 172 conflicts, ~3h wall clock with 5
parallel agents).

## Repository Context

- **origin**: `git@github.com:pando85/kubidm.git` (this fork; the remote may still be named
  `kanidm.git`, that is fine)
- **upstream**: `git@github.com:kanidm/kanidm.git`
- **Main branch**: `master`
- Sync branches: `sync/upstream-YYYY-MM-DD`. PR title:
  `sync: merge upstream kanidm/kanidm master (YYYY-MM-DD)`.
- Some past syncs were done by cherry-pick "parity" PRs (e.g. #389) rather than merges. The merge
  base can therefore be older than the last absorbed upstream commit, and several upstream commits
  will show up as "already present". That is expected; they merge trivially.

## Branding Map

Apply to the UPSTREAM side only. The fork side is already branded.

| upstream                                                                                                                                                                                                   | fork                                                                                                    |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `kanidmd`                                                                                                                                                                                                  | `kubidmd`                                                                                               |
| `kanidm` / `Kanidm` / `KANIDM`                                                                                                                                                                             | `kubidm` / `Kubidm` / `KUBIDM`                                                                          |
| `kanidm_client`, `kanidm_proto`, `kanidmd_core`, `kanidmd_lib`, `kanidmd_lib_macros`, `kanidmd_testkit`, `kanidm_build_profiles`, `kanidm_lib_crypto`, `kanidm_lib_file_permissions`, `kanidm_utils_users` | same with `kubidm` / `kubidmd` prefix (workspace key AND package name)                                  |
| `KanidmClient`, `KanidmClientBuilder`, `KanidmProvider`, `ProviderOrigin::Kanidm`, `KANIDM_PKG_VERSION`                                                                                                    | `KubidmClient`, `KubidmClientBuilder`, `KubidmProvider`, `ProviderOrigin::Kubidm`, `KUBIDM_PKG_VERSION` |
| `pykanidm`, PyPI package `kanidm`                                                                                                                                                                          | `pykubidm`, package `kubidm`                                                                            |
| orca module `kani` (`mod kani`, `kani::`)                                                                                                                                                                  | `kubidm` (`tools/orca/src/kubidm.rs`)                                                                   |
| container images `kanidm/server` etc.                                                                                                                                                                      | `kubidm/server` etc.                                                                                    |

### Names that must stay `kanidm` (restore them after any blanket sed)

- External crate `kanidm-hsm-crypto` / `kanidm_hsm_crypto`.
- Directory and crate names upstream created: `rlm_kanidm/`, `resolver_kanidm/`, `nss_kanidm/`,
  `pam_kanidm/`, `pam_kanidm_common`, `rlm_kanidm.so`, and the RADIUS module internals
  (`kanidm_shared`, `kanidm_rerror`, `kanidm_rinfo`, `kanidm_rdebug`, `kanidm_module`,
  `kanidm_authorise`, `kanidm_instantiate`, `kanidm_radiusd`, `MODULE_NAME = c"kanidm"`).
- NSS exported symbols `_nss_kanidm_*`, `kanidm_getpwnam_r` etc.; unixd service names
  `kanidm-unixd`, `kanidm-unixd.service`, `kanidm-unixd-tasks.service`.
- URLs and git deps: `github.com/kanidm/...`, `kanidm/webauthn-rs.git`, `kanidm/ldap3.git`,
  `kanidm_ppa_automation`.
- Things that genuinely refer to upstream: the FreeBSD port `security/kanidm`, "Kanidm ldap3 client"
  in examples.
- Debian packaging under `server/daemon/debian/` and `platform/` files.

When unsure, check what the fork's HEAD uses: `git grep -n '<name>' HEAD -- '*.rs' '*.toml'`.

## Fork-Specific Code (must survive the merge)

- **Approval workflows**: `UUID_SCHEMA_ATTR_APPROVAL_*`, `UUID_SCHEMA_CLASS_APPROVAL_*`,
  `UUID_IDM_APPROVAL_ADMINS`, approval API routes in `server/core/src/https/v1.rs`, `ApprovalOpt` in
  `tools/cli/src/opt/kubidm.rs`, `DelayedAction::ApprovalTimeoutCheck` / `ApprovalEscalationCheck`.
- **Time-bounded grants**: `UUID_SCHEMA_ATTR_MEMBER_VALID_FROM/UNTIL`,
  `UUID_SCHEMA_ATTR_MAX_GRANT_DURATION`, `SyntaxType::TimeBoundedMember`,
  `ValueSetTimeBoundedMember`, `check_time_restriction` in `access/*.rs`, `plugins/memberof.rs` time
  handling, dl14 migration data.
- **Access control**: `AccessResult::ReauthRequired`, `Delegated` receivers, `access/create.rs` fork
  rules; the fork restructured `modify_allow_operation` / `batch_modify_allow_operation` (both call
  `apply_modify_access`).
- **OAuth2 federation**: `server/core/src/https/v1_oauth2_federation.rs`,
  `UUID_SCHEMA_ATTR_OAUTH2_ISSUER`, `UUID_SCHEMA_ATTR_OAUTH2_JWKS_URI`, `OidcDiscoveryResponse` in
  `idm/oauth2_client.rs`.
- **S3 backup / PITR**: `server/core/src/backup/` (directory), `proto/src/backup.rs`, `config.rs` S3
  and WAL config, `interval.rs` scheduling, `DbCommands::Recover` / `PitrList` in
  `server/daemon/src/main.rs`, deps `aws-config`, `aws-credential-types`, `aws-sdk-s3`, and the
  `patches/aws-runtime-1.7.2` workspace exclude.
- **ServerRole**: `proto/src/config.rs` (`pub use kubidm_proto::config::ServerRole` in
  `server/core/src/config.rs`; upstream has its own local `ServerRole` enum, drop upstream's copy).
- **proto**: `proto/src/internal/{authorization,pip}.rs` re-exported from `internal/mod.rs`.
- **Tests**: the fork uses the `AuthenticatorBackend` / `perform_register` webauthn test API, not
  upstream's `WebauthnAuthenticator` / `do_registration`.

## Policy Decisions (already made, keep applying them)

- **UUID collisions**: upstream allocates new UUIDs in ranges the fork already uses. In
  `server/lib/src/constants/uuids.rs`, keep the fork value for anything the fork already shipped,
  and relocate upstream's NEW constant into the fork's custom range with a comment. Known:
  `UUID_ACCOUNT_SIGNUP_FEATURE` stays `...000000000063` (upstream `...0059` is the fork's
  `UUID_IDM_APPROVAL_ADMINS`); `UUID_SCHEMA_CLASS_KEY_OBJECT_JWE_A256GCM` lives at `ffff00000305`
  (upstream `ffff00000229` is the fork's `UUID_SCHEMA_ATTR_OAUTH2_ISSUER`). Upstream's next numbers
  (`ffff00000230+`) are already taken; expect this every sync. Always finish with a duplicate check
  (script below).
- **SECURITY.md**: the fork removed AI-content restrictions (commit f6b16569f). Do not adopt
  upstream's "AI Usage in Vulnerability Reports" section.
- **Dependencies**: accept upstream bumps, but keep the fork's version when it is newer (renovate
  keeps the fork ahead; e.g. jsonschema, md-5, rand, cc). Never downgrade to match upstream's
  lockfile.
- **Migration identity**: upstream `049d2fbee` makes `InternalRole::Migration` return
  `AccessBasicResult::Ignore` and constrains it to `migration_entry_attrs`. The fork follows that;
  `Delegated` profiles only resolve for user identities.

## Sync Workflow

### Step 1: Assess

```bash
git fetch upstream
MB=$(git merge-base HEAD upstream/master)
git log --oneline $MB..upstream/master | wc -l
git log --format='%h %ad %s' --date=short $MB..upstream/master
git diff --stat $MB upstream/master | tail -1
```

Classify commits: security fixes (grep "Security", "CVE"), schema/migration changes, Cargo.toml
changes, directory restructures, "Fmt"/clippy passes (pure noise, but they cause most conflicts),
deps, docs, UI. Present a summary.

### Step 2: Branch and merge

```bash
git checkout master && git pull origin master
git checkout -b sync/upstream-$(date +%F)
git merge upstream/master --no-commit --no-ff
git diff --name-only --diff-filter=U | sort > /tmp/conflicts.txt
```

### Step 3: Triage with a rebranded 3-way merge (the big time saver)

Most conflicts exist only because upstream's side says `kanidm` and the fork's side says `kubidm`,
plus upstream's import-reordering commits. Rebrand upstream's base and theirs blobs, then let
`git merge-file` redo the merge:

```bash
rebrand() { sed -e 's/kanidmd/kubidmd/g' -e 's/kanidm/kubidm/g' -e 's/Kanidm/Kubidm/g' -e 's/KANIDM/KUBIDM/g' \
  -e 's/kubidm-hsm-crypto/kanidm-hsm-crypto/g' -e 's/kubidm_hsm_crypto/kanidm_hsm_crypto/g' \
  -e 's#rlm_kubidm#rlm_kanidm#g' -e 's#resolver_kubidm#resolver_kanidm#g' -e 's#nss_kubidm#nss_kanidm#g' \
  -e 's#pam_kubidm#pam_kanidm#g' -e 's#github.com/kubidm/#github.com/kanidm/#g' -e 's/kubidm-unixd/kanidm-unixd/g'; }
threeway() { f="$1"; d=$(mktemp -d); git show ":1:$f" | rebrand > $d/base; git show ":2:$f" > $d/ours;
  git show ":3:$f" | rebrand > $d/theirs; git merge-file -p -L fork -L base -L upstream $d/ours $d/base $d/theirs; }

: > /tmp/clean.txt; : > /tmp/dirty.txt
while read f; do
  case "$f" in Cargo.lock|pykubidm/uv.lock) echo "$f" >> /tmp/dirty.txt; continue;; esac
  if threeway "$f" > /tmp/out 2>/dev/null; then echo "$f" >> /tmp/clean.txt
  else echo "$(grep -c '^<<<<<<<' /tmp/out) $f" >> /tmp/dirty.txt; fi
done < /tmp/conflicts.txt
wc -l /tmp/clean.txt /tmp/dirty.txt; sort -rn /tmp/dirty.txt
```

On 2026-10-06 this turned 172 conflicts into 124 mechanical files and 48 real ones (mostly 1-2 hunks
each). Note `rebrand()` must NOT map `KubidmProvider` or `ProviderOrigin::Kubidm` back to `Kanidm`;
those are fork names. After writing a mechanical file, diff it against `git show :2:$f` and eyeball
every changed line containing `kubidm` for names from the must-stay-kanidm list.

### Step 4: Resolve in parallel

Split the dirty list by area and hand each to an agent (server/core; server/lib
server+storage+access; server/lib idm + small crates; Cargo.toml + lock files; mechanical list).
Rules that made this work:

- Each agent only touches its own files and only WRITES to the working tree. No
  `git add/commit/checkout/stash/reset`, no `cargo build/check/test` (the tree has markers
  elsewhere; the orchestrator stages and builds).
- Agents start from `threeway "$f"` output, then resolve remaining hunks using
  `git log -p $MB..upstream/master -- "$f"` (upstream intent) and `git diff $MB HEAD -- "$f"` (fork
  net delta). Rule: take upstream's change AND keep fork additions. Integrate, never pick a side.
- Each agent reports "follow-up risks" (call sites outside its files); collect them for the build
  loop.
- The orchestrator must never put a mutating git command inside a diagnostic one-liner. A stray
  `git stash` once silently dropped `MERGE_HEAD` and reset the tree; later checks ran against plain
  master for 20 minutes. Recovery:
  `git stash pop --index && git rev-parse upstream/master > .git/MERGE_HEAD`.

#### Resolution patterns

- **Import-block conflicts** (from upstream "Fmt" commits): take upstream's nested `use a::{b, c}`
  layout and add the fork's extra items back into it.
- **Cargo.toml**: upstream's version as base; rename internal crate keys to kubidm; keep fork deps
  and the aws patch exclude; keep newer fork versions; check every `[workspace] members` path exists
  and no key is duplicated.
- **Cargo.lock**: take upstream's lock, then `cargo update --workspace` (offline usually fails on
  new crates); then `cargo update --precise` to restore fork pins that upstream's lock would
  downgrade. Verify with `cargo metadata --locked --no-deps`.
- **pykubidm/uv.lock**: take upstream's, rename package `kanidm` -> `kubidm`, run `uv lock` in
  `pykubidm/`.
- **Files with large fork additions** (uuids.rs, access/mod.rs, v1.rs, config.rs, daemon
  main.rs/opt.rs): keep the fork's structure and graft upstream's new pieces in. Only fall back to
  `git show HEAD:<file> > <file>` plus rebrand when the 3-way output is hopeless.
- **crypto-glue / cert code** (`server/core/src/crypto.rs`, `server/lib/src/repl/supplier.rs`): the
  fork's custom x509 profiles were replaced by upstream's crypto-glue 0.2.1 code; take upstream.
  `x509-cert` is now an unused dependency.
- **Templates**: keep the fork's `github.com/pando85/kubidm` link and `KUBIDM_PKG_VERSION`.
- **Directory restructures**: accept upstream's layout, delete the fork's orphaned directories,
  re-apply branding.

### Step 5: Stage, build, fix loop

```bash
grep -rlE '^(<<<<<<<|>>>>>>>) ' --include='*.rs' --include='*.toml' --include='*.html' --include='*.md' . | grep -v target
git add -A
cargo check --workspace --all-targets
```

Fix by category (missing constants, then types/enum variants, then imports, then signatures). Also
sweep auto-merged files for stray branding: new upstream files merge without conflict and still say
`kanidm` (`git diff --cached --name-only --diff-filter=AM | xargs grep -nE 'kanidm|Kanidm|KANIDM'`
minus the allow-list).

### Step 6: Verify

- `cargo fmt --all -- --check`, then `cargo clippy --workspace --all-targets` (default features; CI
  runs `cargo clippy --quiet --lib --bins --examples`). `--all-features` needs FreeRADIUS and
  SELinux headers and fails locally. Pre-existing clippy items on master as of 2026-10: dead-code
  field in `libs/profiles`, `assert_eq!(body, true)` in
  `server/testkit/tests/testkit/health_endpoints.rs`. Use `--keep-going` so one of them does not
  hide others.
- `cargo test --workspace --no-fail-fast`. See "Build environment" below before running it.
- `uvx codespell` with the Makefile's arguments if `codespell` is not installed.
- `make doc/format` flags ~136 pre-existing files; only check the markdown files the merge touched
  (`git diff --cached --name-only | grep '\.md$' | xargs deno fmt --check`).
- `make test/pykubidm`: a few tests need DNS or a running server and fail locally on master too; CI
  is authoritative.
- **Independent audit** (worth it): a read-only agent takes each substantive upstream commit,
  rebrands its added lines, and greps them in the merged tree; reports LANDED / PARTIAL / MISSING
  with file:line. It also runs the UUID duplicate check and the marker check. This caught nothing
  missing in 2026-10 but did catch the stash accident.

```bash
# duplicate UUID check
grep -oE 'uuid!\("[0-9a-f-]+"\)' server/lib/src/constants/uuids.rs | sort | uniq -d
```

### Step 7: Commit, PR, CI

```bash
git commit -m "sync: merge upstream kanidm/kanidm master (YYYY-MM-DD)"   # pre-commit hook runs cargo fmt --check
git push -u origin sync/upstream-YYYY-MM-DD
gh pr create --draft --base master --title "sync: merge upstream kanidm/kanidm master (YYYY-MM-DD)" --body-file pr.md
gh pr checks <n>      # ~1.5h on this repo's runners; rust_build_next (beta/nightly) is continue-on-error
gh pr ready <n>
gh pr merge <n> --merge   # when approved: MERGE COMMIT ONLY, never --squash or --rebase
```

**Merge strategy: always "Create a merge commit".** The sync commit has upstream master as its
second parent; that link is what makes upstream's commits ancestors of the fork's master and lets
the next sync's merge base advance. Squash or rebase rewrites it into a one-parent commit: the
content lands, but the next sync re-conflicts on every upstream commit again. The repo allows all
three methods, so the GitHub button default can bite. Put this reminder in the PR body, and END YOUR
FINAL REPORT TO THE USER WITH IT, for example: "Please remember to merge this PR with the merge
commit strategy, not squash or rebase, so upstream parentage is kept." If follow-up commits need
tidying, squash them into each other, never into the merge commit.

PR body sections that reviewers expect: Summary (base, tip, counts), Upstream changes absorbed
(security first), Fork decisions made during the merge (UUIDs, policy, deps), Known follow-ups,
Verification, a note for any behavior change in access control, and a closing line asking for a
merge commit.

## Build environment (this workstation)

- `CARGO_TARGET_DIR=/dev/shm` is a 32 GB tmpfs. A full workspace test build does not fit (deps alone
  reach 22 GB): lld dies with `Bus error` and rustc with `Disk quota exceeded`. These are not code
  errors. For workspace-wide test or clippy runs use
  `CARGO_TARGET_DIR=/home/agil/.cache/kubidm-sync-target CARGO_INCREMENTAL=0`.
- With the tmpfs full, RAM is tight; `cargo test --workspace -j 4 RUST_TEST_THREADS=8` avoids the
  OOM killer (it killed rustc on `kubidmd_lib (lib test)` at `-j 32`).
- `cargo check` passes without linking, so a green check does not prove the test binaries link.

## Post-Sync Checklist

- [ ] No conflict markers; `MERGE_HEAD` was present at commit time (`git log -1 --format=%p` shows
      two parents)
- [ ] `cargo check --workspace --all-targets`, `cargo test --workspace`, clippy, fmt, codespell pass
- [ ] Fork-specific code preserved (see list above); fork tests updated only where upstream
      intentionally changed semantics
- [ ] No duplicate UUIDs; new upstream UUIDs that collide were relocated
- [ ] External crate names, RADIUS/NSS internals, service names and upstream URLs still say `kanidm`
- [ ] Auto-merged new files rebranded; SECURITY.md AI section not adopted
- [ ] Workspace dependency keys consistent between root and member `Cargo.toml` files; both lock
      files regenerated
- [ ] PR opened as draft, body filled, CI green, then `gh pr ready`
- [ ] PR body and the final report both remind the user to merge with a merge commit (no squash, no
      rebase)
- [ ] Known follow-ups listed in the PR (currently: unused `x509-cert` dep; stale
      `server/daemon/insecure_server.toml` and `server/daemon/run_insecure_dev_server.sh` copies of
      the `scripts/` versions)
