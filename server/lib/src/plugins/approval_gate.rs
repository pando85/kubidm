//! Kubidm: the approval gate on high privilege group membership.
//!
//! While at least one enabled approval policy covers
//! `ApprovalOperationType::GroupMembershipHighPrivilege`, a create, modify or batch modify
//! that adds a `member` (or `dynmember`) value to a high privilege group is refused with
//! `AP0002ApprovalRequired`, even though the access controls allow it. A high privilege
//! group is `idm_high_privilege` itself or a group that is a (direct or nested) member of
//! it, as recorded by `memberof` before the change. The member is then added by filing an
//! approval request (target: the group, details: `{"member": "<uuid>"}`) and, once it is
//! approved, executing it (`QueryServerWriteTransaction::approval_request_execute`), which
//! consumes the approval and adds the member internally.
//!
//! Without such a policy nothing changes: the gate is opt-in. Disabling (or deleting) the
//! policy turns it off again. Managing approval policies is not gated, but approval admins
//! are members of high privilege groups, so the last of them can leave and no one can be
//! added back while the gate is on. The break-glass is therefore on the server:
//! `kubidmd approval-policy disable` disables policies through the admin socket as the
//! system (`approval_policy_disable_break_glass`).
//!
//! Not gated:
//!
//! - removing members;
//! - writes by internal identities (migrations, referential integrity, `memberof`, and
//!   `approval_request_execute` itself). Internal callers adding members on behalf of
//!   someone must therefore apply the gate themselves (see below); time-bounded grants are
//!   refused on high privilege groups for this reason (see `server::time_bounded`);
//! - replication, which does not run these hooks: the gate applies where the change is
//!   made.
//!
//! Paths that add members without these hooks apply the gate themselves:
//!
//! - reviving an entry from the recycle bin restores its direct memberships with internal
//!   writes; a non-internal reviver is refused if one of them is a high privilege group
//!   (`server::recycle`);
//! - a SCIM sync (`idm::scim`, phase 3) writes internally on behalf of the sync connector;
//!   it is refused if it adds a member to a high privilege group;
//! - an approval request can not add a dynamic group or a sync owned entry (or a group
//!   containing one), whose members are decided by a filter or by the connector.
//!
//! A dynamic group that already is a member of a high privilege group (from before the gate
//! was enabled) still gains members as entries come to match its filter: those changes are
//! internal. Remove such nesting before relying on the gate.
//!
//! `dynmember` is computed by `plugins::dyngroup` (internally), and dynamic groups can not
//! be modified by other identities, so in practice the gate concerns `member`. Checking
//! `dynmember` too keeps the gate closed should that ever change.
//!
//! The gate runs after the access controls, so a caller who may not add the member at all
//! still gets `AccessDenied`.

use std::collections::BTreeSet;
use std::sync::Arc;

use kubidm_proto::v1::ApprovalOperationType;

use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::server::approval::approval_enabled_policies;

pub struct ApprovalGate {}

/// The attributes whose values make an entry a member of a group.
const MEMBER_ATTRS: [Attribute; 2] = [Attribute::Member, Attribute::DynMember];

/// Is `group` a high privilege group: `idm_high_privilege` itself, or a (nested) member
/// of it according to its `memberof`.
pub(crate) fn is_high_privilege_group<VALID, STATE>(group: &Entry<VALID, STATE>) -> bool {
    group.attribute_equality(
        Attribute::Uuid,
        &PartialValue::Uuid(UUID_IDM_HIGH_PRIVILEGE),
    ) || group.attribute_equality(
        Attribute::MemberOf,
        &PartialValue::Refer(UUID_IDM_HIGH_PRIVILEGE),
    )
}

/// Is the gate on: does an enabled approval policy cover
/// `group_membership_high_privilege`?
pub(crate) fn approval_gate_enabled(
    qs: &mut QueryServerWriteTransaction,
) -> Result<bool, OperationError> {
    approval_enabled_policies(qs, &ApprovalOperationType::GroupMembershipHighPrivilege)
        .map(|policies| !policies.is_empty())
}

/// Refuse a write by `ident` that makes something a direct member of each of `groups`, if
/// one of them is a high privilege group and the gate is on. For write paths that add
/// members outside the plugin hooks, such as reviving an entry, which restores its direct
/// memberships with internal writes.
pub(crate) fn approval_gate_check_member_adds(
    qs: &mut QueryServerWriteTransaction,
    ident: &Identity,
    op: &str,
    groups: impl IntoIterator<Item = Uuid>,
) -> Result<(), OperationError> {
    if ident.is_internal() {
        return Ok(());
    }
    let mut high_privilege = BTreeSet::new();
    for group in groups {
        match qs.internal_search_uuid(group) {
            Ok(entry) if is_high_privilege_group(entry.as_ref()) => {
                high_privilege.insert(group);
            }
            Ok(_) | Err(OperationError::NoMatchingEntries) => {}
            Err(err) => return Err(err),
        }
    }
    ApprovalGate::check(qs, ident, op, &high_privilege)
}

/// Does `after` hold a member that `before` does not?
pub(crate) fn adds_member(before: Option<&BTreeSet<Uuid>>, after: Option<&BTreeSet<Uuid>>) -> bool {
    after.is_some_and(|after| {
        after
            .iter()
            .any(|member| before.is_none_or(|before| !before.contains(member)))
    })
}

impl ApprovalGate {
    /// Refuse the write if it adds a member to one of `groups` (the uuids of the high
    /// privilege groups it adds members to) while the gate is enabled.
    fn check(
        qs: &mut QueryServerWriteTransaction,
        ident: &Identity,
        op: &str,
        groups: &BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        if groups.is_empty() {
            return Ok(());
        }
        if !approval_gate_enabled(qs)? {
            return Ok(());
        }
        security_access!(
            ident = %ident,
            op,
            ?groups,
            "denied - adding a member to a high privilege group requires an approved approval request"
        );
        Err(OperationError::AP0002ApprovalRequired)
    }

    fn check_modify(
        qs: &mut QueryServerWriteTransaction,
        ident: &Identity,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &[EntryInvalidCommitted],
    ) -> Result<(), OperationError> {
        if ident.is_internal() {
            return Ok(());
        }
        let groups: BTreeSet<Uuid> = pre_cand
            .iter()
            .zip(cand.iter())
            .filter(|(pre, post)| {
                is_high_privilege_group(pre.as_ref())
                    && MEMBER_ATTRS
                        .iter()
                        .any(|attr| adds_member(pre.get_ava_refer(attr), post.get_ava_refer(attr)))
            })
            .map(|(pre, _)| pre.get_uuid())
            .collect();
        Self::check(qs, ident, "modify", &groups)
    }
}

impl Plugin for ApprovalGate {
    fn id() -> &'static str {
        "plugin_approval_gate"
    }

    #[instrument(level = "debug", name = "approval_gate_pre_create_transform", skip_all)]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<EntryInvalidNew>,
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        if ce.ident.is_internal() {
            return Ok(());
        }
        // A new entry has no `memberof` yet, unless the caller supplied one, so this
        // rarely matches. It is checked anyway so that no write path skips the gate.
        let groups: BTreeSet<Uuid> = cand
            .iter()
            .filter(|entry| {
                is_high_privilege_group(*entry)
                    && MEMBER_ATTRS
                        .iter()
                        .any(|attr| adds_member(None, entry.get_ava_refer(attr)))
            })
            .filter_map(|entry| entry.get_uuid())
            .collect();
        Self::check(qs, &ce.ident, "create", &groups)
    }

    #[instrument(level = "debug", name = "approval_gate_pre_modify", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::check_modify(qs, &me.ident, pre_cand, cand)
    }

    #[instrument(level = "debug", name = "approval_gate_pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::check_modify(qs, &me.ident, pre_cand, cand)
    }
}
