---
name: upstream-sync
description: Use when syncing changes from the upstream kanidm/kanidm repository into this kubidm fork. Use ONLY when the user asks to sync, rebase, merge, or bring changes from upstream/kanidm. Covers fetching upstream, triaging conflicts with a rebranded 3-way merge, splitting resolution across agents, resolving rename conflicts (kanidm -> kubidm), verifying, and opening the PR.
---

# Upstream Sync: kanidm -> kubidm

This skill handles syncing changes from the upstream `kanidm/kanidm` repository into the
`pando85/kubidm` fork.

Last run: 2026-11-19, PR #587 (automated routine, 17 min, draft with 13 failing checks: no local
build, compile errors, fork schema lost at the new domain level, `AGENTS.md` emptied, rebrand
leftovers, a committed scratch file, a broad lock refresh, silently adopted workflow triggers, and a
PR body that ticked claims nobody had checked). The "Preflight", "Hard gates" and "Honest PR body"
rules below exist to prevent that. Before: 2026-10-27, PR #511 (13 upstream commits, 124 files, 20
conflicts; 5 mechanical). Before: 2026-10-06, PR #445 (43 commits, 172 conflicts, ~3h wall clock with
5 parallel agents).

**Rules for every run, human or automated:** never merge the PR (the owner does, with a merge
commit); never tick a check or claim you did not run; a PR that fails any gate below stays DRAFT.

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
- Directory and crate names upstream created: `rlm_kanidm/`, `resolver_kanidm/`, `rlm_kanidm.so`, and the RADIUS module
  internals (`kanidm_shared`, `kanidm_rerror`, `kanidm_rinfo`, `kanidm_rdebug`, `kanidm_module`,
  `kanidm_authorise`, `kanidm_instantiate`, `kanidm_radiusd`, `MODULE_NAME = c"kanidm"`).
- The NSS and PAM modules are renamed: `nss_kubidm/`, `pam_kubidm/`, `libnss_kubidm.so.2`,
  `pam_kubidm.so`, exported symbols `_nss_kubidm_*`, and `passwd: kubidm` in nsswitch.conf. glibc
  derives the library and symbol names from the nsswitch name, so they must always agree. Upstream's
  `nss_kanidm`/`pam_kanidm` map to these when merging.
- Unixd service names `kanidm-unixd`, `kanidm-unixd.service`, `kanidm-unixd-tasks.service`.
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
- **proto**: `proto/src/internal/authorization.rs` re-exported from `internal/mod.rs`.
- **WAL / PITR helpers**: `DbEntry::stored_uuid()` / `stored_name()` in `server/lib/src/be/dbentry.rs`
  match `DbValueSetV2` variants directly; when upstream changes DB value formats, extend them (keep
  the legacy arms so old WAL segments replay). Symptom when missed: all `pitr_test::*` fail with
  `CorruptedEntry`.
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
- **SyntaxType numbering**: same idea as UUIDs. The fork's `SyntaxType::TimeBoundedMember = 47`, so
  upstream's `UuidN`..`UrlN` (upstream 47..51) live at 48..52 in `server/lib/src/value.rs`. New
  upstream syntaxes go after the fork's highest number.
- **Fork schema extras**: fork-only attributes/classes that must exist at DL >= 1.11 (delegation,
  step-up re-auth, ACP time restriction, fork `AccessControlProfile`) live in
  `kubidm_schema_attributes()` / `kubidm_schema_classes()` in `schema.rs`, chained last in
  `generate_in_memory`, `migrate_schema_1_11` and `migrate_schema_1_12`. When upstream adds a
  `migrate_schema_1_N`, chain them there too (see "New domain level checklist"), and add fork single-value attrs to any upstream
  on-disk rewrite list in migrations. Audit this at every new target domain level: #511 raised the
  level without the fork schema and the server lost it. The tests
  `test_schema_kubidm_extras_registered_at_target_level` (attributes and classes) and
  `test_migrations_kubidm_builtin_entries_exist` (`kubidm_builtin_entries()`) fail when a level
  misses it; run them (`cargo test -p kubidmd_lib -- kubidm_`) after any change to the domain level
  or the migrations.
- **SECURITY.md**: the fork removed AI-content restrictions (commit f6b16569f). Do not adopt
  upstream's "AI Usage in Vulnerability Reports" section. See "Files the fork owns".
- **Dependencies**: accept upstream bumps, but keep the fork's version when it is newer (renovate
  keeps the fork ahead; e.g. jsonschema, md-5, rand, cc). Never downgrade to match upstream's
  lockfile. Never go the other way either: no crate newer than both master's lock and upstream's
  lock unless a manifest change requires it (see "Lockfiles").

## Files the Fork Owns

Never take upstream's version of these, not even for a "clean" auto-merge: resolve as "ours"
(`git checkout --ours -- <path>` or `git show origin/master:<path> > <path>`), then re-apply only the
upstream fixes the fork needs, by hand. Check each after the merge with
`git diff origin/master -- <path>` (empty, or only intended hunks) and that it is not empty or
truncated (`wc -l`).

- `AGENTS.md`: the fork's own contributor guidance. Upstream's `AGENTS.md` is a different,
  anti-LLM text; in #587 it was blanked out. Never empty, replace or delete it.
- `SECURITY.md`: keep the fork's version (no "AI Usage in Vulnerability Reports" section).
- `.opencode/**` (including this skill) and `.github/copilot-instructions.md`.
- The fork's CI workflows in `.github/workflows/`: their TRIGGERS (`on:` blocks, `branches`,
  `paths`, `concurrency`) belong to the owner. Upstream changed triggers (upstream PR #4674) and #587
  adopted them silently, which removed `push: master` CI. Take upstream's job-level changes (steps, action
  versions, commands) rebranded, keep the fork's `on:` block, and list every upstream trigger or
  path-filter change in the PR body under "Workflow trigger changes (owner opt-in)". Check with
  `git diff origin/master -- .github/workflows | grep -nE '^[+-] *("?on"?:|push:|pull_request|branches:|paths:|schedule:|tags:)'`.
- **Migration identity**: upstream `049d2fbee` makes `InternalRole::Migration` return
  `AccessBasicResult::Ignore` and constrains it to `migration_entry_attrs`. The fork follows that;
  `Delegated` profiles only resolve for user identities.

## Sync Workflow

### Step 0: Preflight (environment)

Do this before touching the merge. #587 started on a runner without `libudev`, skipped every local
check, and opened the PR anyway.

System build dependencies (`libpam0g-dev libudev-dev libssl-dev libsystemd-dev`, plus `pkg-config
clang lld cmake build-essential` for the `.cargo/config.toml` linker and bundled SQLite) are
installed by `.forkline/setup.rh`, which the Forkline runner executes after the clone and before you
start. The preflight only verifies them:

```bash
git fetch --unshallow origin 2>/dev/null || git fetch origin          # full history for merge-base
git remote get-url upstream >/dev/null 2>&1 || git remote add upstream https://github.com/kanidm/kanidm.git
git fetch upstream
rustc --version && cargo --version && cargo fmt --version && cargo clippy --version
pkg-config --exists libudev openssl libsystemd && echo ok             # the failing one in #587 was libudev
command -v clang ld.lld cmake
cargo check --locked -p kubidm_proto                                    # small; must pass on the unmerged branch
```

Record the result. Missing system deps are fixed in `.forkline/setup.rh` (in a separate PR), never
installed ad hoc in a sync.

If any check fails (or the setup did not run): read `/tmp/.forkline-setup.log` for the reason, do
the merge anyway, push, and open the PR as **DRAFT** with
`**Local verification not possible: <exact reason and failing command>**` as the first line of the
body. Tick no checklist item, list no check as "passed", and say in "Known follow-ups" that nothing
compiled locally. Never mark such a PR ready for review, even if CI later passes without you
having read its logs.

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
  -e 's#rlm_kubidm#rlm_kanidm#g' -e 's#resolver_kubidm#resolver_kanidm#g' \
  -e 's#github.com/kubidm/#github.com/kanidm/#g' -e 's/kubidm-unixd/kanidm-unixd/g'; }
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
- Worktree agents (`isolation: worktree`) branch from `master`, not from the current `HEAD`. They
  will not see the merge in progress or a sync branch. Create follow-up worktrees manually from the
  branch you want (`git worktree add <path> -b <name> <base>`) and point agents at them.
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
- **Cargo.lock / pykubidm/uv.lock** (see "Lockfiles" right below): start from MASTER's lock, never
  from upstream's, and never run a broad update.
- **Files with large fork additions** (uuids.rs, access/mod.rs, v1.rs, config.rs, daemon
  main.rs/opt.rs): keep the fork's structure and graft upstream's new pieces in. Only fall back to
  `git show HEAD:<file> > <file>` plus rebrand when the 3-way output is hopeless.
- **crypto-glue / cert code** (`server/core/src/crypto.rs`, `server/lib/src/repl/supplier.rs`): the
  fork's custom x509 profiles were replaced by upstream's crypto-glue 0.2.1 code; take upstream.
  (`x509-cert` was dropped as unused after the 2026-10-27 sync.)
- **Templates**: keep the fork's `github.com/pando85/kubidm` link and `KUBIDM_PKG_VERSION`.
- **Directory restructures**: accept upstream's layout, delete the fork's orphaned directories,
  re-apply branding.

#### Lockfiles

#587 refreshed about 26 crates beyond upstream's lock; one (`filetime`) broke `deny(warnings)`.
Locks change only where a manifest change forces it.

```bash
git checkout origin/master -- Cargo.lock pykubidm/uv.lock     # start from master's locks
# after Cargo.toml files are resolved (never `cargo update`, `cargo update --workspace` or
# `uv lock --upgrade`):
cargo metadata --format-version 1 >/dev/null                  # cargo adds only what the manifests need
cargo update -p <crate> --precise <ver>                       # pin a NEW crate to upstream's locked version
(cd pykubidm && uv lock)                                      # only if pykubidm/pyproject.toml changed
# every crate version that is in our lock but in neither master's nor upstream's (must print nothing):
lockpkgs() { awk '/^name = /{n=$3} /^version = /&&n{print n, $3}' | tr -d '"' | sort -u; }
comm -13 <( { git show origin/master:Cargo.lock; git show upstream/master:Cargo.lock | rebrand; } | lockpkgs ) \
         <( lockpkgs < Cargo.lock )
git diff --stat origin/master -- Cargo.lock pykubidm/uv.lock
```

- Every changed or added lock entry must be explained by an upstream manifest change or be the
  version upstream's lock has (rebranded). No crate may be newer than master's lock AND upstream's
  lock. List anything you could not explain in the PR body.
- If upstream's merge does not touch `pykubidm/pyproject.toml`, `pykubidm/uv.lock` must be
  byte-identical to master's. Package `kanidm` -> `kubidm` rename applies only if upstream's lock
  introduced it.
- Never downgrade a fork pin; if `cargo update -p ... --precise` cannot hold a version, say so in the
  PR body rather than refreshing around it.
- `cargo check --locked --workspace --all-targets` (a hard gate) fails if the lock is out of sync.

#### New domain level checklist

Applies whenever upstream adds a `migrate_schema_1_N`, a `migrate_domain_A_to_B`, a `DOMAIN_LEVEL_*`
constant, a `reload_schema` arm, or a new `server/lib/src/migration_data/dl*/` module (check with
`git diff --stat $MB upstream/master -- server/lib/src/server server/lib/src/migration_data server/lib/src/constants`).
Upstream's lists do not contain the fork's schema or entries, so each new level must chain them
exactly as the previous one does. #511 lost them at DL 1.11 and #587 lost them again at DL 1.13.
Reference implementation on master (`server/lib/src/server/migrations.rs` unless noted):

1. **Schema**: the new `migrate_schema_1_N` ends with `all_attrs.extend(crate::schema::kubidm_schema_attributes());`
   and `all_classes.extend(crate::schema::kubidm_schema_classes());` before `self.schema.extend_in_memory(...)`,
   as `migrate_schema_1_12` does. Add the level to the `reload_schema` match in
   `server/lib/src/server/mod.rs` (`DOMAIN_LEVEL_1_N => self.migrate_schema_1_N()?`). If upstream
   instead reuses another level's schema, chain the extras the same way there. Also keep
   `generate_in_memory` in `server/lib/src/schema.rs` chaining `kubidm_schema_attributes()` /
   `kubidm_bootstrap_schema_classes()`.
2. **Builtin entries**: the new `migrate_domain_A_to_B` calls
   `self.internal_migrate_or_create_batch("phase 6 - kubidm builtin entries", migration_data::dl14::kubidm_builtin_entries()?)`
   after upstream's phase 6 batches (see `migrate_domain_1_11_to_1_12`). If the new level has no
   phase lists of its own, the fork's batches still must run (master's `migrate_domain_1_12_to_1_13`
   is an empty stub that is NOT a model: it only works while `DOMAIN_TGT_LEVEL` is 1.12).
3. **ACP patch**: after upstream's phase 7, call
   `self.kubidm_migrate_builtin_acp_batch("phase 7 - kubidm builtin access control profiles", migration_data::dl14::kubidm_builtin_access_control_profiles())`,
   and use `kubidm_migrate_builtin_acp_batch` (not the plain batch) for upstream's phase 7 too.
4. **New `dl_*` module**: the fork's data lives in `migration_data/dl14/` (`kubidm_builtin_entries`,
   `kubidm_builtin_access_control_profiles`, `delegation.rs`); reference it, do not copy it. If the
   new module's phase lists contain entries that clash with the fork's (same UUID, changed ACP),
   resolve per the UUID policy and note it in the PR body.
5. If upstream raises `DOMAIN_TGT_LEVEL`, wire the new `migrate_domain_*` into
   `server/lib/src/server/mod.rs` (the `previous_version <= ... && domain_info_version >= ...`
   chain) and update the `latest` alias in `migration_data/mod.rs`.
6. Run the guard tests and confirm they actually ran (not "0 tests"):
   `cargo test -p kubidmd_lib -- kubidm_` must include
   `schema::tests::test_schema_kubidm_extras_registered_at_target_level` and
   `server::migrations::tests::test_migrations_kubidm_builtin_entries_exist`. Do not weaken or
   delete them to get green.

### Step 5: Stage, build, fix loop

```bash
grep -rlE '^(<<<<<<<|>>>>>>>) ' --include='*.rs' --include='*.toml' --include='*.html' --include='*.md' . | grep -v target
git add -A
git status -s | grep -v '^[MADR] ' || true       # anything unmerged or untracked is unexpected
cargo check --locked --workspace --all-targets
```

Compile errors from conflict resolution are the most common failure; fix every one, do not push over
them. Typical ones: a fork field kept next to upstream's replacement (`feature_config`), a
half-applied upstream change in one file (for example the return-style conversion in
`server/daemon/src/main.rs`: take it for the whole file or not at all), and a misplaced `mod x;`
(`mod signup;`). Re-read each resolved file's diff against upstream's version of the same commit.

Fix by category (missing constants, then types/enum variants, then imports, then signatures). Also
sweep auto-merged files for stray branding: new upstream files merge without conflict and still say
`kanidm`. The content rebrand applies to files ADDED upstream (workflows, YAML, Dockerfiles, docs,
crate manifests), not only to conflicted files: #511 shipped `docker_build_kanidm_tools.yml` and the
`ghcr.io/<owner>/kanidm-tools` image that way. List the added files explicitly and read each one:
`git diff --name-only --diff-filter=A origin/master | grep -v '^target/'`, and
`git grep -n -i 'kanidm' -- <those files>`. #587 left 23 leftovers, among them `kanidmd_lib`
imports and new upstream files such as `platform/opensuse/kanidm-*.service`: their contents are
rebranded (and `kanidm-unixd*` service names stay, see the must-stay list). Run the guard, which scans
every tracked file (and untracked, non-ignored ones) against `scripts/rebrand_allowlist.txt`, and fix
each hit or add a narrow allow-list entry:

```bash
scripts/check_rebrand.sh
scripts/check_forbidden_patterns.sh
```

**Deleted upstream paths**: when upstream removes or moves a directory or file, nothing breaks in
the Rust build but the fork's workflows, `Makefile`, dependabot config and Dockerfiles can still
reference it (#587 kept a workflow job on the `rlm_python` directory after upstream deleted it).
List what the merge deleted and grep the fork's own files for each path; update or remove every hit
(and say so in the PR body):

```bash
git diff --name-only --diff-filter=D origin/master | cut -d/ -f1-2 | sort -u | while read -r p; do
  [ -e "$p" ] || git grep -nF "$p" -- .github Makefile '*Dockerfile*' scripts book Cargo.toml || true
done
```

**No scratch files in the repo**: conflict notes, resolution reports, `pr.md`, three-way outputs and
audit logs live in `/tmp` (or the runner's scratch dir) and the PR body, never in the working tree
(#587 committed `CONFLICT_RESOLUTION_REPORT.md`). Before every commit run `git status -s` and
`git diff --cached --stat origin/master`; every file listed must be explained by an upstream change
or a documented fork decision. Unexpected files go: `git rm --cached` / delete them.

Upstream file and directory names are kept on purpose (`platform/linux/kanidmd.service`,
`examples/kanidm`); only their contents are rebranded.

### Step 6: Verify

#### Hard gates (run all of them before pushing)

Each command exists on master today (CI workflows, `Makefile`, `scripts/`). Run them in this order
and record the exact result of each for the PR body.

```bash
cargo fmt --check                                              # CI: clippy.yml "fmt" job
cargo clippy --quiet --lib --bins --examples                   # exactly what CI's clippy job runs
cargo clippy --workspace --all-targets --keep-going            # stricter pass: new findings fail the gate, pre-existing ones (notes below) do not
cargo check --locked --workspace --all-targets                 # --locked as CI: also proves the lock is in sync
cargo test -p kubidmd_lib -- kubidm_                           # fork guard tests (schema extras, builtin entries, ...)
grep -oE 'uuid!\("[0-9a-f-]+"\)' server/lib/src/constants/uuids.rs | sort | uniq -d   # UUID duplicates: must print nothing
scripts/check_rebrand.sh
scripts/check_forbidden_patterns.sh
```

Also required: no conflict markers (command in Step 5) and the lock check from "Lockfiles".

If a gate fails and you cannot fix it within the run: the PR stays DRAFT and the body's first section
lists the failing gate verbatim (command, exit code, the first error lines). If a gate could not be
run at all, say that instead; "not run" is never "passed". Do not weaken a test, add an
`#[allow]`, or extend `scripts/rebrand_allowlist.txt` just to turn a gate green, unless the allow
entry is a genuine upstream-name case from the must-stay list.

#### Further checks

- Clippy notes: default features (CI runs `--lib --bins --examples`, with no `--all-features`).
  `--all-features` needs FreeRADIUS and SELinux headers and fails locally. Pre-existing clippy items
  on master as of 2026-10: dead-code field in `libs/profiles`, `assert_eq!(body, true)` in
  `server/testkit/tests/testkit/health_endpoints.rs`. Use `--keep-going` so one of them does not hide
  others.
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

### Step 7: Commit, PR, CI

```bash
git status -s; git diff --cached --stat origin/master | tail -n 40     # no unexpected files (Step 5)
git commit -m "sync: merge upstream kanidm/kanidm master (YYYY-MM-DD)"   # pre-commit hook runs cargo fmt --check
git push -u origin sync/upstream-YYYY-MM-DD
gh pr create --draft --base master --title "sync: merge upstream kanidm/kanidm master (YYYY-MM-DD)" --body-file /tmp/pr.md   # body file outside the repo
gh pr checks <n> --watch    # ~1.5h on this repo's runners; rust_build_next (beta/nightly) is continue-on-error
```

Always open the PR as DRAFT. After pushing, WAIT for the PR's CI inside the run's time budget (the
routine has 240 min; CI takes ~1.5h): `gh pr checks <n> --watch`, and read the logs of every failure
(`gh run view <run-id> --log-failed | tail -n 80`). Fix failures with NEW commits on the sync branch
(no amend, no force-push), re-run the affected gates locally, push, and wait again. Mark the PR ready
(`gh pr ready <n>`) only when every required check is green AND every local hard gate passed AND the
preflight did not report "local verification not possible". Otherwise leave it draft and say in the
PR body (edit it with `gh pr edit <n> --body-file`) which checks fail or are still pending and why.
Never merge: merging is the owner's step, with the merge commit strategy below.

#### PR body: be honest

- **Counts** (files, insertions, deletions, commits, conflicts) come from commands, not memory:
  `git diff --stat origin/master...HEAD | tail -n 1`, `git rev-list --count upstream/master ^$MB`, and
  `wc -l /tmp/conflicts.txt`. #587 stated wrong file and line counts.
- **Checks run**: list only commands you actually ran, each with its real result (pass/fail and, on
  failure, the first error lines). Commands not run are listed as "not run: <reason>".
- **No checkbox is ticked for something unverified.** Do not write "all fork features preserved" or
  "no unrelated changes" unless you ran the checks that support it (guard tests, `git diff --stat`
  review, fork-owned files check). Use unticked boxes and plain statements of what was and was not
  checked.
- Put these at the top when they apply: "Local verification not possible: <reason>", any failing
  gate (verbatim), "Workflow trigger changes (owner opt-in)" from "Files the fork owns", lock entries
  you could not explain.
- Keep the merge-commit reminder (below).

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
- [ ] Preflight done (toolchain and system deps present, or PR is draft with "local verification not
      possible: <reason>" first in the body)
- [ ] All hard gates passed and are listed in the body with their real results: `cargo fmt --check`,
      both clippy runs, `cargo check --locked --workspace --all-targets`,
      `cargo test -p kubidmd_lib -- kubidm_`, UUID check, `check_rebrand.sh`,
      `check_forbidden_patterns.sh`; also `cargo test --workspace` and codespell where the
      environment allows
- [ ] Fork-owned files untouched or intentionally merged: `AGENTS.md` (not empty), `SECURITY.md`,
      `.opencode/**`, workflow triggers; upstream trigger changes listed as owner opt-in
- [ ] No scratch or report files in the diff (`git diff --stat origin/master...HEAD` reviewed)
- [ ] Lockfiles started from master's, no broad update, no crate newer than master's and upstream's
      lock; `pykubidm/uv.lock` unchanged unless `pyproject.toml` changed
- [ ] References to paths upstream deleted removed from workflows, Makefile, dependabot, Dockerfiles
- [ ] Fork-specific code preserved (see list above); fork tests updated only where upstream
      intentionally changed semantics
- [ ] No duplicate UUIDs; new upstream UUIDs that collide were relocated
- [ ] External crate names, RADIUS/NSS internals, service names and upstream URLs still say `kanidm`
- [ ] Auto-merged AND newly added upstream files rebranded (the added-files grep was read) (`scripts/check_rebrand.sh` and
      `scripts/check_forbidden_patterns.sh` pass); SECURITY.md AI section not adopted
- [ ] Fork schema and builtin entries registered at the new target domain level (guard tests pass)
- [ ] Workspace dependency keys consistent between root and member `Cargo.toml` files; locks
      changed only where manifests require it (see "Lockfiles")
- [ ] PR opened as draft, body filled honestly, PR CI waited for and failures fixed with new commits;
      `gh pr ready` only when CI and all local gates are green. Never merged by the routine.
- [ ] PR body and the final report both remind the user to merge with a merge commit (no squash, no
      rebase)
- [ ] Known follow-ups listed in the PR, and a follow-up PR opened to fix them (2026-10-27: #511's
      list was fixed in the `fix/post-sync-followups-2026-10-27` PR)
