# Merge Conflict Resolution Report

## Files Resolved: 4

### 1. server/core/src/interval.rs (3 conflicts)

**Conflict 1 (line 6): chrono imports**
- **Resolution**: Kept fork's `use chrono::{DateTime, Utc};`
- **Rationale**: Fork refactored scheduling into `spawn_scheduled()` which uses `DateTime<Utc>`. Upstream's `Local` was only used in old inline code that's been replaced.

**Conflict 2 (lines 110-126): Output path handling**
- **Resolution**: Kept fork's conditional path handling with `if let Some(ref path) = outpath`
- **Rationale**: Fork supports S3-only configurations (no local path required). Upstream assumes local path always exists.

**Conflict 3 (lines 175-192): Backup scheduling and replication monitor**
- **Resolution**: Kept fork's `Ok(handles)` return and `start_replication_monitor()` method
- **Rationale**: Fork refactored inline scheduling into shared `spawn_scheduled()` function and added S3 cross-region replication monitoring. Upstream code was old inline scheduling loop.

**All fork-specific S3 backup, PITR, and replication code preserved.**

---

### 2. server/core/src/actors/mod.rs (1 conflict)

**Conflict (lines 57-59): Module declarations**
- **Resolution**: Kept BOTH sides
  - Fork: `#[cfg(test)] mod pip_tests;`
  - Upstream: `pub mod read_action;`
- **Rationale**: Independent additions - fork adds PIP test module, upstream adds new public read_action module.

---

### 3. server/core/src/https/views/mod.rs (1 conflict)

**Conflict (lines 37-39): View module declarations**
- **Resolution**: Kept BOTH sides
  - Fork: `#[cfg(debug_assertions)] mod ui_lab;`
  - Upstream: `mod signup;`
- **Rationale**: Both modules are referenced in the router code (signup routes at lines 122-128, ui_lab at lines 149-154). Both must exist.

---

### 4. server/core/static/modules/cred_update.mjs (1 conflict)

**Conflict (line 70): Passkey creation data**
- **Resolution**: Kept fork's cleanup (no duplicate `clientDataJSON` assignment) but added upstream's new `transports` field
- **Final code**:
  ```javascript
  creationData.response.transports = assertion.response.getTransports();
  ```
- **Rationale**: Fork removed duplicate `clientDataJSON` line (already set at lines 66-69). Upstream added new `transports` field for WebAuthn compliance. Both changes are compatible.

---

## Follow-up Risks and Call Sites

### 1. **New upstream module: `read_action`**
- **Location**: `server/core/src/actors/read_action.rs`
- **Risk**: This is a new public module from upstream. Verify it exists and is properly implemented.
- **Action**: Check if the file exists and compiles.

### 2. **New upstream module: `signup`**
- **Location**: `server/core/src/https/views/signup.rs`
- **Risk**: New account signup feature from upstream. Referenced in router at lines 122-128.
- **Action**: Verify the file exists and templates are present.

### 3. **Branding consistency**
- **Risk**: Upstream code may contain "kanidm" references that should be "kubidm"
- **Action**: Search new upstream code (signup, read_action) for branding that needs updating.

### 4. **S3/Replication dependencies**
- **Files using fork's S3 code**:
  - `server/core/src/interval.rs` - uses `S3ClientWrapper`, `ReplicationConfig`, `S3Config`
  - `server/core/src/backup/` - S3 backup implementation
  - `kubidm_proto/src/backup.rs` - Protocol definitions
- **Risk**: Ensure all S3/replication types and functions are still available after merge.

### 5. **Chrono import change**
- **Change**: Removed `use chrono::Local;` (upstream), kept `use chrono::{DateTime, Utc};` (fork)
- **Risk**: If any other code in the file or its dependents uses `Local`, it will fail to compile.
- **Action**: Verify no other code in `interval.rs` uses `Local`.

### 6. **Passkey transports field**
- **File**: `server/core/static/modules/cred_update.mjs`
- **Change**: Added `creationData.response.transports = assertion.response.getTransports();`
- **Risk**: Backend must accept and handle the new `transports` field in passkey registration.
- **Action**: Check passkey registration handler in backend code.

---

## Verification Checklist

- [x] No conflict markers remain in any file
- [x] All fork S3/backup/replication code preserved
- [x] Upstream's new features (signup, read_action) integrated
- [x] Fork branding (kubidm) maintained
- [ ] Compile check: `cargo check --workspace`
- [ ] Test check: `cargo test --workspace`
- [ ] Verify `read_action.rs` exists
- [ ] Verify `signup.rs` and templates exist
- [ ] Search new upstream code for "kanidm" branding
- [ ] Verify backend handles passkey `transports` field

---

## Summary

**Total conflicts resolved**: 6 across 4 files
**Strategy**: Kept all fork-specific S3 backup, PITR, and replication code while integrating upstream's new features (account signup, read_action module). Fork's refactoring of backup scheduling into shared `spawn_scheduled()` function was preserved over upstream's inline implementation.
