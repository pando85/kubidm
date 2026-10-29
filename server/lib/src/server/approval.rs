//! Kubidm approval workflows.
//!
//! # How a request is decided
//!
//! **Snapshot.** When a request is created, what it is decided against is fixed on the
//! request (`approval_quorum_snapshot`): the requester, the policy's approver slots and
//! backup approvers (each recorded as a person or a group), the pattern, the number of
//! approved slots required, and the escalation timeout. These are plain uuids rather than
//! references, so neither deleting a person or group (which referential integrity removes
//! from the policy) nor editing the policy changes the outcome of an existing request. A
//! request without a snapshot is invalid.
//!
//! **Slots.** Every approver of the snapshot is one approver slot, naming either a person
//! or a group. A person fills a slot that names them directly, or a group they are a
//! (transitive) member of. One decision fills at most one slot, and a person decides at
//! most once, so a person who matches several slots (listed directly and through a group,
//! or listed as approver and as backup approver) still counts once. Two members of the same
//! group fill that group's slot only once. The requester never fills a slot.
//!
//! **Quorum.** Over the `n` (distinct) approver slots: `any_one` needs 1 slot approved,
//! `majority` needs `n / 2 + 1`, and `all` needs all `n`. A group slot is filled by any one
//! of its members, so `all` over `[group]` needs one member; list people individually to
//! require each of them. A request is approved once the quorum is reached, and rejected
//! once the slots that are still open can no longer bring it there (so under `all` a
//! single rejection rejects it).
//!
//! **Escalation.** Once the escalation timeout has passed since the request was created,
//! the backup approvers may fill any *open* approver slot: they stand in for approvers who
//! have not responded. This depends only on the time, not on the approval sweep having
//! recorded the escalation (`escalation_level`, which is informational). The approvers stay
//! eligible, decisions made before the escalation keep counting, and the quorum does not
//! change. A backup approver can not take a slot that has already been decided, so an
//! escalation never turns a rejection into an approval and never lowers the number of
//! people needed.
//!
//! **Storage.** Every decision is its own `approval_decision_record` entry, linked to its
//! request by `approval_record_request`, created once and never modified, holding one JSON
//! object that also records the slots the approver could fill when they decided. Separate
//! entries never conflict in replication, so two decisions made on different replicas are
//! both kept (see `SCHEMA_CLASS_APPROVAL_DECISION_RECORD` for why values of one attribute
//! would not be). Policies, requests and records are only written by the operations below,
//! as the internal system identity: `plugins::approval` refuses every other write.
//!
//! **Outcome.** The outcome is recomputed from the snapshot and the decision records:
//!
//! - decisions by the requester are dropped;
//! - only the first decision of each approver counts. Decisions are ordered by time (with
//!   nanosecond precision), then approver, then record uuid, so every replica picks the
//!   same one;
//! - a decision only fills the slots its approver could hold under the snapshot: slots of
//!   the snapshot, and a slot naming a person only for that person, or for a backup
//!   approver deciding after the escalation time. (Group membership at the time of the
//!   decision can not be checked again later, so group slots are taken as recorded.);
//! - approvals by approvers who have since been deleted or disabled (account expired or
//!   not yet valid) are ignored. Rejections always count.
//!
//! A stored pending state is replaced by the recomputed one, since after a replication
//! merge the stored state may lag behind the merged decisions; the approval sweep writes it
//! back. A stored final state (approved, rejected, expired, cancelled, consumed) is never
//! changed by a recomputation, so in particular a rejection never becomes an approval.
//!
//! **Gate.** An operation that needs approval must call
//! `QueryServerWriteTransaction::approval_request_check_and_consume`, and nothing else:
//! it recomputes the outcome rather than trusting the stored state, checks that the
//! request is for exactly this operation, under the policy the operation requires (which
//! the caller chooses, never the requester), that it has not expired and that the policy
//! is still enabled and still covers the operation, and consumes the approval in the same
//! transaction, so that it authorises the operation once. An approval is only final once
//! replication has converged: a decision made concurrently on another replica (say, a
//! rejection made earlier) can still change the outcome, and two replicas can each consume
//! the same approval before they replicate.
//!
//! **Gated operations.** Adding a member to a high privilege group
//! (`group_membership_high_privilege`) is gated while an enabled policy covers it:
//! `plugins::approval_gate` refuses the direct write, and
//! `QueryServerWriteTransaction::approval_request_execute` carries it out for the requester
//! of an approved request. Disabling the policy turns the gate off; when no approval admin
//! is left to do it, `kubidmd approval-policy disable` does it from the server's admin socket
//! (`QueryServerWriteTransaction::approval_policy_disable_break_glass`).

use crate::idm::account::Account;
use crate::plugins::approval_gate::is_high_privilege_group;
use crate::prelude::*;
use crate::server::time_bounded::group_member_rights;
use kubidm_proto::v1::{
    ApprovalDecision, ApprovalDecisionAction, ApprovalDecisionRequest, ApprovalOperationMember,
    ApprovalOperationType, ApprovalPattern, ApprovalPolicy, ApprovalPolicyCreateRequest,
    ApprovalRequest, ApprovalRequestState,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

/// Only the internal system identity bypasses the approval authorisation checks. Other
/// internal roles (migration, account request, message queue) have no business here.
fn approval_ident_is_system(ident: &Identity) -> bool {
    ident.is_internal() && ident.get_uuid() == UUID_SYSTEM
}

/// Kubidm: the approval operations below use internal (ACP bypassing) searches and
/// writes, so the caller has to be authorised explicitly. Approval policies and requests
/// are administered by members of `idm_approval_admins`.
fn approval_check_admin(ident: &Identity, write: bool) -> Result<(), OperationError> {
    if approval_ident_is_system(ident) {
        return Ok(());
    }

    if ident.is_internal() {
        security_access!(ident = %ident, "denied - internal identity is not the system");
        return Err(OperationError::AccessDenied);
    }

    if write && ident.access_scope() != AccessScope::ReadWrite {
        security_access!("approval write requires a read-write (privileged) session");
        return Err(OperationError::AccessDenied);
    }

    if ident.is_memberof(UUID_IDM_APPROVAL_ADMINS) {
        Ok(())
    } else {
        security_access!(ident = %ident, "denied - not a member of idm_approval_admins");
        Err(OperationError::AccessDenied)
    }
}

/// Kubidm: only an interactive person may decide on a request: a person (not a service
/// account, and not anonymous), with a read-write session that is not an API token.
fn approval_check_decider(ident: &Identity) -> Result<Arc<EntrySealedCommitted>, OperationError> {
    if ident.is_internal() {
        security_access!(ident = %ident, "denied - internal identity is not the system");
        return Err(OperationError::AccessDenied);
    }
    if ident.access_scope() != AccessScope::ReadWrite {
        security_access!("approval decision requires a read-write (privileged) session");
        return Err(OperationError::AccessDenied);
    }
    let Some(entry) = ident.get_user_entry() else {
        security_access!(ident = %ident, "denied - approval decisions are made by persons");
        return Err(OperationError::AccessDenied);
    };
    // API tokens belong to service accounts, which are excluded below. This also holds
    // should a person ever carry one.
    let session_id = ident.get_session_id();
    if entry
        .get_ava_as_apitoken_map(Attribute::ApiTokenSession)
        .is_some_and(|tokens| tokens.contains_key(&session_id))
    {
        security_access!(ident = %ident, "denied - approval decisions can not be made with an API token");
        return Err(OperationError::AccessDenied);
    }
    if entry.get_uuid() == UUID_ANONYMOUS
        || !entry.attribute_equality(Attribute::Class, &EntryClass::Person.into())
        || entry.attribute_equality(Attribute::Class, &EntryClass::ServiceAccount.into())
    {
        security_access!(ident = %ident, "denied - approval decisions are made by persons");
        return Err(OperationError::AccessDenied);
    }
    Ok(entry)
}

/// Is the account `entry` usable at `now`: within its valid from and expiry times.
fn approval_account_active(entry: &EntrySealedCommitted, now: OffsetDateTime) -> bool {
    let valid_from = entry.get_ava_single_datetime(Attribute::AccountValidFrom);
    let expire = entry.get_ava_single_datetime(Attribute::AccountExpire);
    let ct = Duration::try_from(now - OffsetDateTime::UNIX_EPOCH).unwrap_or(Duration::ZERO);
    Account::check_within_valid_time(ct, valid_from.as_ref(), expire.as_ref())
}

/// Whether an approver slot or backup approver named a person or a group when the request
/// was created.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ApprovalMemberKind {
    /// A person (or any other non-group entry): only they can fill the slot.
    Account,
    /// A group: any of its members can fill the slot.
    Group,
}

/// What a request is decided against, fixed when it is created. Stored as JSON in
/// `Attribute::ApprovalQuorumSnapshot`, see `SCHEMA_ATTR_APPROVAL_QUORUM_SNAPSHOT`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct ApprovalSnapshot {
    requester: Uuid,
    pattern: ApprovalPattern,
    /// The number of approved slots needed, see `approval_required_decisions`.
    required: u32,
    slots: BTreeMap<Uuid, ApprovalMemberKind>,
    backups: BTreeMap<Uuid, ApprovalMemberKind>,
    escalation_timeout_seconds: Option<u32>,
}

impl ApprovalSnapshot {
    fn slot_set(&self) -> BTreeSet<Uuid> {
        self.slots.keys().copied().collect()
    }

    /// When the backup approvers may start deciding on a request created at `created_at`,
    /// if ever.
    fn escalation_at(&self, created_at: OffsetDateTime) -> Option<OffsetDateTime> {
        if self.backups.is_empty() {
            return None;
        }
        self.escalation_timeout_seconds
            .map(|timeout| created_at + Duration::from_secs(u64::from(timeout)))
    }

    /// Could `approver` be one of the backup approvers? A backup approver named directly is
    /// known; membership of a backup group at the time of the decision can not be checked
    /// again, so any approver could be one if a group is a backup approver.
    fn may_be_backup(&self, approver: Uuid) -> bool {
        self.backups.contains_key(&approver)
            || self
                .backups
                .values()
                .any(|kind| *kind == ApprovalMemberKind::Group)
    }
}

/// The number of approved slots `pattern` needs out of `slots`, see the module
/// documentation.
fn approval_required_decisions(pattern: ApprovalPattern, slots: usize) -> u32 {
    let total = u32::try_from(slots).unwrap_or(u32::MAX);
    let required = match pattern {
        ApprovalPattern::AnyOne => 1,
        ApprovalPattern::Majority => total / 2 + 1,
        ApprovalPattern::All => total,
    };
    required.max(1)
}

/// One decision, as stored in `Attribute::ApprovalDecision` of an approval decision record.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct StoredApprovalDecision {
    approver_uuid: Uuid,
    approver_spn: String,
    /// Whole seconds, see `decided_at`.
    #[serde(with = "time::serde::timestamp")]
    decision_time: OffsetDateTime,
    /// The sub-second part of the decision time. Records written before it existed only
    /// have whole seconds, and read as 0 here.
    #[serde(default)]
    decision_time_nanos: u32,
    action: ApprovalDecisionAction,
    comment: Option<String>,
    /// The approver slots this approver could fill when they decided.
    slots: BTreeSet<Uuid>,
    /// The uuid of the record entry, the last tie-break when ordering decisions.
    #[serde(skip)]
    record_uuid: Uuid,
}

impl StoredApprovalDecision {
    /// The decision time, with nanosecond precision.
    fn decided_at(&self) -> OffsetDateTime {
        self.decision_time
            .replace_nanosecond(self.decision_time_nanos)
            .unwrap_or(self.decision_time)
    }

    /// Decisions are ordered by time, then approver, then record: the same on every
    /// replica, whatever order the backend returns them in.
    fn order_key(&self) -> (OffsetDateTime, Uuid, Uuid) {
        (self.decided_at(), self.approver_uuid, self.record_uuid)
    }

    fn to_proto(&self) -> ApprovalDecision {
        ApprovalDecision {
            approver_uuid: self.approver_uuid,
            approver_spn: self.approver_spn.clone(),
            decision_time: self.decided_at(),
            action: self.action,
            comment: self.comment.clone(),
        }
    }
}

/// The approver slots `ident` may fill on a request decided against `snapshot`: the slots
/// naming them or one of their groups, or every slot once the request has escalated and
/// they are a backup approver. Empty if they are not an approver of the request at all.
fn approval_ident_slots(
    ident: &Identity,
    snapshot: &ApprovalSnapshot,
    escalated: bool,
) -> BTreeSet<Uuid> {
    let ident_uuid = ident.get_uuid();
    let matches = |slot: &Uuid| *slot == ident_uuid || ident.is_memberof(*slot);

    if escalated && snapshot.backups.keys().any(matches) {
        snapshot.slot_set()
    } else {
        snapshot.slots.keys().copied().filter(matches).collect()
    }
}

/// What the decisions on a request are counted against.
struct ApprovalTallyContext<'a> {
    snapshot: &'a ApprovalSnapshot,
    /// See `ApprovalSnapshot::escalation_at`.
    escalation_at: Option<OffsetDateTime>,
    /// Approvers whose approvals no longer count: deleted or disabled since.
    inactive: &'a BTreeSet<Uuid>,
}

impl ApprovalTallyContext<'_> {
    /// The slots of `decision` that its approver could hold under the snapshot.
    fn valid_slots(&self, decision: &StoredApprovalDecision) -> BTreeSet<Uuid> {
        let approver = decision.approver_uuid;
        let as_backup = || {
            self.snapshot.may_be_backup(approver)
                && self
                    .escalation_at
                    .is_some_and(|at| decision.decided_at() >= at)
        };
        decision
            .slots
            .iter()
            .copied()
            .filter(|slot| match self.snapshot.slots.get(slot) {
                None => false,
                // The system may fill any slot.
                Some(_) if approver == UUID_SYSTEM => true,
                Some(ApprovalMemberKind::Group) => true,
                Some(ApprovalMemberKind::Account) => *slot == approver || as_backup(),
            })
            .collect()
    }
}

/// The decisions of a request counted against the slots of its snapshot.
struct ApprovalTally {
    required: u32,
    approvals: u32,
    open: u32,
    /// The approvers whose decision fills a slot.
    counted: BTreeSet<Uuid>,
}

impl ApprovalTally {
    fn state(&self) -> ApprovalRequestState {
        if self.approvals >= self.required {
            ApprovalRequestState::Approved
        } else if self.approvals.saturating_add(self.open) < self.required {
            ApprovalRequestState::Rejected
        } else {
            ApprovalRequestState::Pending
        }
    }
}

/// Try to give decision `idx` one of its `valid` slots, moving earlier decisions to
/// another of their slots if needed (an augmenting path). Earlier decisions never lose
/// their slot.
fn approval_assign_slot(
    idx: usize,
    valid: &[BTreeSet<Uuid>],
    owner: &mut BTreeMap<Uuid, usize>,
    visited: &mut BTreeSet<Uuid>,
) -> bool {
    let Some(slots) = valid.get(idx) else {
        return false;
    };
    for slot in slots.iter() {
        if !visited.insert(*slot) {
            continue;
        }
        let free = match owner.get(slot).copied() {
            None => true,
            Some(other) => approval_assign_slot(other, valid, owner, visited),
        };
        if free {
            owner.insert(*slot, idx);
            return true;
        }
    }
    false
}

/// Count `decisions` against the slots of the snapshot, see the module documentation.
/// Decisions are taken in order; a decision counts if it can fill a slot without taking one
/// away from an earlier decision.
fn approval_tally(
    ctx: &ApprovalTallyContext<'_>,
    decisions: &[StoredApprovalDecision],
) -> ApprovalTally {
    let snapshot = ctx.snapshot;

    let mut ordered: Vec<&StoredApprovalDecision> = decisions
        .iter()
        .filter(|d| d.approver_uuid != snapshot.requester)
        .collect();
    ordered.sort_by_key(|d| d.order_key());
    let mut seen = BTreeSet::new();
    ordered.retain(|d| seen.insert(d.approver_uuid));
    ordered.retain(|d| {
        d.action != ApprovalDecisionAction::Approve || !ctx.inactive.contains(&d.approver_uuid)
    });

    let valid: Vec<BTreeSet<Uuid>> = ordered.iter().map(|d| ctx.valid_slots(d)).collect();
    let mut owner: BTreeMap<Uuid, usize> = BTreeMap::new();
    for idx in 0..ordered.len() {
        let mut visited = BTreeSet::new();
        approval_assign_slot(idx, &valid, &mut owner, &mut visited);
    }

    let assigned: Vec<&StoredApprovalDecision> = owner
        .values()
        .filter_map(|idx| ordered.get(*idx).copied())
        .collect();
    let approvals = assigned
        .iter()
        .filter(|d| d.action == ApprovalDecisionAction::Approve)
        .count() as u32;

    ApprovalTally {
        required: snapshot.required,
        approvals,
        open: (snapshot.slots.len() as u32).saturating_sub(assigned.len() as u32),
        counted: assigned.iter().map(|d| d.approver_uuid).collect(),
    }
}

/// An approval request as read from its entry, with its policy if that still exists.
struct ResolvedApprovalRequest {
    policy: Option<ApprovalPolicy>,
    /// `None` for a request created before snapshots existed: it is invalid.
    snapshot: Option<ApprovalSnapshot>,
    /// `request.state` is the effective state, see `approval_effective_state`.
    request: ApprovalRequest,
    stored_state: ApprovalRequestState,
    /// The state recomputed from the snapshot and the decisions, ignoring the stored state.
    /// `None` without a snapshot.
    derived_state: Option<ApprovalRequestState>,
    decisions: Vec<StoredApprovalDecision>,
    /// See `approval_inactive_approvers`.
    inactive: BTreeSet<Uuid>,
}

impl ResolvedApprovalRequest {
    /// The policy, target and requester all still exist, and the request has a snapshot.
    fn is_valid(&self) -> bool {
        self.policy.is_some()
            && self.snapshot.is_some()
            && self.request.target_uuid.is_some()
            && self.request.requestor_uuid.is_some()
    }

    /// The context to count the decisions on this request in, `None` without a snapshot.
    fn tally_context(&self) -> Option<ApprovalTallyContext<'_>> {
        self.snapshot.as_ref().map(|snapshot| ApprovalTallyContext {
            snapshot,
            escalation_at: snapshot.escalation_at(self.request.created_at),
            inactive: &self.inactive,
        })
    }

    /// Has the escalation time passed at `now`, so that backup approvers may decide?
    fn escalated_at(&self, now: OffsetDateTime) -> bool {
        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.escalation_at(self.request.created_at))
            .is_some_and(|at| at <= now)
    }
}

/// The state of a request, given its stored state and the state recomputed from its
/// snapshot and decisions (`None` without a snapshot).
///
/// - A stored final state (approved, rejected, expired, cancelled, consumed) is kept: a
///   recomputation never moves a request out of it. If the decisions no longer reach a
///   stored approval or rejection (after a replication merge of concurrent decisions),
///   this is logged; `approval_request_check_and_consume` refuses such an approval.
/// - A pending request takes the recomputed state, unless its policy, target or requester
///   is gone, or it has no snapshot: then it is invalid.
fn approval_effective_state(
    request_uuid: Uuid,
    stored: ApprovalRequestState,
    valid: bool,
    derived: Option<ApprovalRequestState>,
) -> ApprovalRequestState {
    match stored {
        ApprovalRequestState::Cancelled
        | ApprovalRequestState::Expired
        | ApprovalRequestState::Invalid
        | ApprovalRequestState::Consumed => stored,
        ApprovalRequestState::Approved | ApprovalRequestState::Rejected => {
            if derived.is_some_and(|derived| derived != stored) {
                warn!(%request_uuid, %stored, ?derived, "approval request decisions no longer reach its stored state, keeping it");
            }
            stored
        }
        ApprovalRequestState::Pending | ApprovalRequestState::Escalated => match derived {
            Some(derived) if valid => {
                if derived != ApprovalRequestState::Pending {
                    debug!(%request_uuid, %derived, "approval request state recomputed from its decisions");
                }
                derived
            }
            _ => ApprovalRequestState::Invalid,
        },
    }
}

/// The approvers among `decisions` whose approvals no longer count at `now`: their
/// account was deleted, or is expired or not yet valid.
fn approval_inactive_approvers<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    decisions: &[StoredApprovalDecision],
    now: OffsetDateTime,
) -> Result<BTreeSet<Uuid>, OperationError> {
    let approvers: BTreeSet<Uuid> = decisions
        .iter()
        .filter(|d| d.action == ApprovalDecisionAction::Approve && d.approver_uuid != UUID_SYSTEM)
        .map(|d| d.approver_uuid)
        .collect();
    if approvers.is_empty() {
        return Ok(approvers);
    }

    let active: BTreeSet<Uuid> = qs
        .internal_search(filter!(f_or(
            approvers
                .iter()
                .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(*u)))
                .collect()
        )))?
        .iter()
        .filter(|entry| approval_account_active(entry, now))
        .map(|entry| entry.get_uuid())
        .collect();

    Ok(approvers.difference(&active).copied().collect())
}

/// Load an approval request together with the policy it refers to, as of `now`. A missing
/// policy, target, requester or snapshot is not an error (the request is then invalid, see
/// `approval_effective_state`), a malformed request, snapshot or decision record is.
fn approval_request_resolve<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    entry: &Entry<EntrySealed, EntryCommitted>,
    now: OffsetDateTime,
) -> Result<ResolvedApprovalRequest, OperationError> {
    let request_uuid = entry.get_uuid();
    let decisions = approval_decision_records(qs, &[request_uuid])?
        .remove(&request_uuid)
        .unwrap_or_else(|| Ok(Vec::with_capacity(0)))?;
    approval_request_resolve_with(qs, entry, decisions, now)
}

/// `approval_request_resolve`, with the decisions on the request already loaded.
fn approval_request_resolve_with<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    entry: &Entry<EntrySealed, EntryCommitted>,
    decisions: Vec<StoredApprovalDecision>,
    now: OffsetDateTime,
) -> Result<ResolvedApprovalRequest, OperationError> {
    let request_uuid = entry.get_uuid();

    let policy = match entry.get_ava_single_refer(Attribute::ApprovalRequestPolicy) {
        Some(policy_uuid) => match qs.internal_search_uuid(policy_uuid) {
            Ok(policy_entry) => Some(approval_policy_from_entry(&policy_entry)?),
            Err(OperationError::NoMatchingEntries) => {
                warn!(%request_uuid, %policy_uuid, "approval request policy not found");
                None
            }
            Err(err) => return Err(err),
        },
        None => None,
    };

    let snapshot = approval_request_snapshot(entry)?;
    if snapshot.is_none() {
        warn!(%request_uuid, "approval request has no quorum snapshot, it is invalid");
    }

    let stored_state = approval_request_state(entry)?;
    let request =
        approval_request_from_entry(entry, policy.as_ref(), snapshot.as_ref(), &decisions)?;
    let inactive = approval_inactive_approvers(qs, &decisions, now)?;

    let mut resolved = ResolvedApprovalRequest {
        policy,
        snapshot,
        request,
        stored_state,
        derived_state: None,
        decisions,
        inactive,
    };
    resolved.derived_state = resolved
        .tally_context()
        .map(|ctx| approval_tally(&ctx, &resolved.decisions).state());

    resolved.request.state = approval_effective_state(
        request_uuid,
        stored_state,
        resolved.is_valid(),
        resolved.derived_state,
    );
    if resolved.request.state == ApprovalRequestState::Invalid {
        warn!(%request_uuid, "approval request policy, target, requester or snapshot is missing");
    }

    Ok(resolved)
}

/// Resolve every entry. Each result is the resolved request, or the uuid of a malformed
/// request with the error.
#[allow(clippy::type_complexity)]
fn approval_request_resolve_each<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    entries: &[Arc<EntrySealedCommitted>],
    now: OffsetDateTime,
) -> Result<Vec<Result<ResolvedApprovalRequest, (Uuid, OperationError)>>, OperationError> {
    let request_uuids: Vec<Uuid> = entries.iter().map(|e| e.get_uuid()).collect();
    let mut records = approval_decision_records(qs, &request_uuids)?;

    Ok(entries
        .iter()
        .map(|entry| {
            let request_uuid = entry.get_uuid();
            records
                .remove(&request_uuid)
                .unwrap_or_else(|| Ok(Vec::with_capacity(0)))
                .and_then(|decisions| approval_request_resolve_with(qs, entry, decisions, now))
                .map_err(|err| (request_uuid, err))
        })
        .collect())
}

/// Resolve every entry, logging and skipping the ones that are malformed.
fn approval_request_resolve_all<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    entries: &[Arc<EntrySealedCommitted>],
    now: OffsetDateTime,
) -> Result<Vec<ResolvedApprovalRequest>, OperationError> {
    Ok(approval_request_resolve_each(qs, entries, now)?
        .into_iter()
        .filter_map(|resolved| match resolved {
            Ok(resolved) => Some(resolved),
            Err((request, err)) => {
                warn!(?err, %request, "skipping malformed approval request");
                None
            }
        })
        .collect())
}

/// The decisions on each of `request_uuids`, in decision order. A request with a malformed
/// decision record maps to an error. Records whose request is gone are not found here.
#[allow(clippy::type_complexity)]
fn approval_decision_records<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    request_uuids: &[Uuid],
) -> Result<BTreeMap<Uuid, Result<Vec<StoredApprovalDecision>, OperationError>>, OperationError> {
    let mut by_request: BTreeMap<Uuid, Result<Vec<StoredApprovalDecision>, OperationError>> =
        BTreeMap::new();
    if request_uuids.is_empty() {
        return Ok(by_request);
    }

    let requests = request_uuids
        .iter()
        .map(|u| f_eq(Attribute::ApprovalRecordRequest, PartialValue::Refer(*u)))
        .collect();
    let records = qs.internal_search(filter!(f_and!([
        f_eq(Attribute::Class, EntryClass::ApprovalDecisionRecord.into()),
        f_or(requests)
    ])))?;

    for record in records.iter() {
        let Some(request_uuid) = record.get_ava_single_refer(Attribute::ApprovalRecordRequest)
        else {
            continue;
        };
        let record_uuid = record.get_uuid();
        let decision = record
            .get_ava_single_utf8(Attribute::ApprovalDecision)
            .ok_or(OperationError::MissingAttribute(Attribute::ApprovalDecision))
            .and_then(|s| {
                serde_json::from_str::<StoredApprovalDecision>(s)
                    .map_err(|_| OperationError::InvalidValueState)
            })
            .map(|mut decision| {
                decision.record_uuid = record_uuid;
                decision
            })
            .inspect_err(|err| {
                error!(?err, record = %record_uuid, request = %request_uuid, "invalid approval decision record");
            });
        let decisions = by_request
            .entry(request_uuid)
            .or_insert_with(|| Ok(Vec::new()));
        match (decisions, decision) {
            (Ok(decisions), Ok(decision)) => decisions.push(decision),
            (decisions, Err(err)) => *decisions = Err(err),
            (Err(_), Ok(_)) => {}
        }
    }

    for decisions in by_request.values_mut().flatten() {
        decisions.sort_by_key(|d| d.order_key());
    }
    Ok(by_request)
}

/// Has the escalation timeout of a pending request passed, without the escalation having
/// been recorded yet?
fn approval_escalation_due(resolved: &ResolvedApprovalRequest, now: OffsetDateTime) -> bool {
    // There is a single escalation level: the backup approvers.
    resolved.request.state == ApprovalRequestState::Pending
        && resolved.request.escalation_level == 0
        && resolved.escalated_at(now)
}

/// Has a pending request passed its expiry time?
fn approval_expiry_due(resolved: &ResolvedApprovalRequest, now: OffsetDateTime) -> bool {
    resolved.request.state == ApprovalRequestState::Pending
        && resolved
            .request
            .expires_at
            .is_some_and(|expires_at| expires_at <= now)
}

impl QueryServerReadTransaction<'_> {
    pub fn approval_policy_list(
        &mut self,
        ident: &Identity,
    ) -> Result<Vec<ApprovalPolicy>, OperationError> {
        approval_check_admin(ident, false)?;

        let filter = filter!(f_eq(Attribute::Class, EntryClass::ApprovalPolicy.into()));
        let entries = self.internal_search(filter)?;

        entries
            .into_iter()
            .map(|e| approval_policy_from_entry(&e))
            .collect()
    }

    pub fn approval_policy_get(
        &mut self,
        ident: &Identity,
        name: &str,
    ) -> Result<ApprovalPolicy, OperationError> {
        approval_check_admin(ident, false)?;

        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::ApprovalPolicy.into()),
            f_eq(Attribute::ApprovalPolicyName, PartialValue::new_iname(name))
        ]));
        let entries = self.internal_search(filter)?;

        entries
            .first()
            .map(|e| approval_policy_from_entry(e))
            .ok_or(OperationError::NoMatchingEntries)?
    }

    /// List the approval requests, optionally only those in `state`. The state is the
    /// effective state (see `approval_effective_state`), so this filters after resolving
    /// rather than on the stored state. Malformed requests are logged and skipped.
    pub fn approval_request_list(
        &mut self,
        ident: &Identity,
        state: Option<ApprovalRequestState>,
    ) -> Result<Vec<ApprovalRequest>, OperationError> {
        approval_check_admin(ident, false)?;

        let now = self.get_accesscontrols().get_curtime();
        let filter = filter!(f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()));
        let entries = self.internal_search(filter)?;

        let mut requests: Vec<ApprovalRequest> = approval_request_resolve_all(self, &entries, now)?
            .into_iter()
            .map(|resolved| resolved.request)
            .filter(|request| state.is_none_or(|s| request.state == s))
            .collect();
        for request in requests.iter_mut() {
            request.operation_member = approval_operation_member(self, request);
        }
        Ok(requests)
    }

    /// Read one approval request. Approval admins may read every request; Kubidm: the
    /// requester may read their own (to see whether it was approved), without the details
    /// of its member (`operation_member`), which only approval admins get. Anyone else gets
    /// `AccessDenied` whether or not the request exists.
    pub fn approval_request_get(
        &mut self,
        ident: &Identity,
        uuid: Uuid,
    ) -> Result<ApprovalRequest, OperationError> {
        let now = self.get_accesscontrols().get_curtime();
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
            f_eq(Attribute::Uuid, PartialValue::Uuid(uuid))
        ]));
        let entry = self.internal_search(filter)?.into_iter().next();

        // Authorise before revealing whether the request exists.
        let is_requester = !ident.is_internal()
            && entry
                .as_ref()
                .and_then(|e| e.get_ava_single_refer(Attribute::ApprovalRequestor))
                == Some(ident.get_uuid());
        let is_admin = if is_requester {
            approval_check_admin(ident, false).is_ok()
        } else {
            approval_check_admin(ident, false)?;
            true
        };
        let entry = entry.ok_or(OperationError::NoMatchingEntries)?;

        let mut request = approval_request_resolve(self, &entry, now)?.request;
        if is_admin {
            request.operation_member = approval_operation_member(self, &request);
        }
        Ok(request)
    }
}

impl QueryServerWriteTransaction<'_> {
    pub fn approval_policy_create(
        &mut self,
        ident: &Identity,
        request: &ApprovalPolicyCreateRequest,
    ) -> Result<(), OperationError> {
        approval_check_admin(ident, true)?;

        let uuid = Uuid::new_v4();

        let approvers: Vec<Value> = request
            .approvers
            .iter()
            .map(|u| Value::ReferN(*u))
            .collect();

        let backup_approvers: Vec<Value> = request
            .backup_approvers
            .iter()
            .map(|u| Value::ReferN(*u))
            .collect();

        let op_types: Vec<Value> = request
            .operation_types
            .iter()
            .map(|o| Value::new_iutf8n(o.as_str()))
            .collect();

        let mut entry: Entry<EntryInit, EntryNew> = Entry::new();
        entry.set_ava(
            Attribute::Class,
            vec![EntryClass::ApprovalPolicy.into(), EntryClass::Object.into()],
        );
        entry.set_ava(Attribute::Uuid, vec![Value::Uuid(uuid)]);
        entry.set_ava(
            Attribute::ApprovalPolicyName,
            vec![Value::new_iname(&request.name)],
        );
        entry.set_ava(
            Attribute::ApprovalPatternAttr,
            vec![Value::new_iutf8(request.pattern.as_str())],
        );
        entry.set_ava(
            Attribute::ApprovalTimeout,
            vec![Value::Uint32(request.timeout_seconds)],
        );
        entry.set_ava(Attribute::Approver, approvers);

        if let Some(desc) = &request.description {
            entry.set_ava(Attribute::Description, vec![Value::new_utf8(desc.clone())]);
        }

        if !backup_approvers.is_empty() {
            entry.set_ava(Attribute::BackupApprover, backup_approvers);
        }

        if let Some(esc_timeout) = request.escalation_timeout_seconds {
            entry.set_ava(
                Attribute::EscalationTimeout,
                vec![Value::Uint32(esc_timeout)],
            );
        }

        entry.set_ava(Attribute::ApprovalOperationType, op_types);
        entry.set_ava(Attribute::ApprovalPolicyEnabled, vec![Value::Bool(true)]);

        let create_event = CreateEvent::new_internal(vec![entry]);
        self.create(&create_event)?;
        // The write is internal, so record who made it.
        info!(ident = %ident, policy = %request.name, %uuid, "approval policy created");
        self.approval_warn_duplicate_coverage(&request.name)?;
        self.approval_warn_delegated_high_privilege(&request.name)
    }

    /// Kubidm: warn when the enabled policy `name` gates high privilege group membership
    /// while a dynamic group, or a group owned by a sync agreement, is already nested in a
    /// high privilege group. Their members are decided by a filter or by the sync connector,
    /// not by member writes, so the gate does not control who joins through them.
    fn approval_warn_delegated_high_privilege(&mut self, name: &str) -> Result<(), OperationError> {
        let gates = self
            .internal_search(filter!(f_and!([
                f_eq(Attribute::Class, EntryClass::ApprovalPolicy.into()),
                f_eq(Attribute::ApprovalPolicyName, PartialValue::new_iname(name)),
                f_eq(
                    Attribute::ApprovalOperationType,
                    PartialValue::new_iutf8(
                        ApprovalOperationType::GroupMembershipHighPrivilege.as_str()
                    )
                )
            ])))?
            .iter()
            .any(|policy| {
                policy
                    .get_ava_single_bool(Attribute::ApprovalPolicyEnabled)
                    .unwrap_or(true)
            });
        if !gates {
            return Ok(());
        }
        let delegated = self.internal_search(filter!(f_and!([
            f_eq(
                Attribute::MemberOf,
                PartialValue::Refer(UUID_IDM_HIGH_PRIVILEGE)
            ),
            f_eq(Attribute::Class, EntryClass::Group.into()),
            f_or!([
                f_eq(Attribute::Class, EntryClass::DynGroup.into()),
                f_eq(Attribute::Class, EntryClass::SyncObject.into()),
                f_pres(Attribute::SyncParentUuid)
            ])
        ])))?;
        for group in delegated {
            warn!(
                policy = %name,
                group = %group.get_display_id(),
                "a dynamic or sync owned group is nested in a high privilege group: the approval gate does not control its members"
            );
        }
        Ok(())
    }

    /// Kubidm: warn when the enabled policy `name` covers an operation type that another
    /// enabled policy covers too. For an executable operation either policy is then accepted
    /// (see [Self::approval_request_execute]), so the laxer one decides in practice.
    fn approval_warn_duplicate_coverage(&mut self, name: &str) -> Result<(), OperationError> {
        let policies = self.internal_search(filter!(f_eq(
            Attribute::Class,
            EntryClass::ApprovalPolicy.into()
        )))?;
        let mut coverage: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for policy in policies.iter().filter(|policy| {
            policy
                .get_ava_single_bool(Attribute::ApprovalPolicyEnabled)
                .unwrap_or(true)
        }) {
            let policy_name = policy
                .get_ava_single_iname(Attribute::ApprovalPolicyName)
                .unwrap_or_default()
                .to_string();
            for operation_type in policy
                .get_ava_iter_iutf8(Attribute::ApprovalOperationType)
                .into_iter()
                .flatten()
            {
                coverage
                    .entry(operation_type.to_string())
                    .or_default()
                    .insert(policy_name.clone());
            }
        }
        for (operation_type, names) in coverage {
            if names.len() > 1 && names.contains(name) {
                warn!(
                    policy = %name,
                    %operation_type,
                    ?names,
                    "several enabled approval policies cover this operation type: a request under any of them is accepted"
                );
            }
        }
        Ok(())
    }

    pub fn approval_policy_delete(
        &mut self,
        ident: &Identity,
        name: &str,
    ) -> Result<(), OperationError> {
        approval_check_admin(ident, true)?;

        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::ApprovalPolicy.into()),
            f_eq(Attribute::ApprovalPolicyName, PartialValue::new_iname(name))
        ]));
        self.internal_delete(&filter)?;
        info!(ident = %ident, policy = %name, "approval policy deleted");
        Ok(())
    }

    pub fn approval_policy_enable(
        &mut self,
        ident: &Identity,
        name: &str,
        enable: bool,
    ) -> Result<(), OperationError> {
        approval_check_admin(ident, true)?;

        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::ApprovalPolicy.into()),
            f_eq(Attribute::ApprovalPolicyName, PartialValue::new_iname(name))
        ]));
        let modlist = ModifyList::new_list(vec![
            Modify::Purged(Attribute::ApprovalPolicyEnabled),
            Modify::Present(Attribute::ApprovalPolicyEnabled, Value::Bool(enable)),
        ]);
        self.internal_modify(&filter, &modlist)?;
        info!(ident = %ident, policy = %name, enable, "approval policy enabled state changed");
        if enable {
            self.approval_warn_duplicate_coverage(name)?;
            self.approval_warn_delegated_high_privilege(name)?;
        } else {
            for policy in self.internal_search(filter)? {
                self.approval_cancel_open_requests(policy.get_uuid())?;
            }
        }
        Ok(())
    }

    /// Kubidm: cancel the open (pending, escalated or approved) requests filed under the
    /// policy `policy_uuid`, when it is disabled. Otherwise re-enabling the policy would make
    /// approvals given before it was disabled usable again, possibly much later (they never
    /// expire with a timeout of 0). Returns the number of requests cancelled.
    fn approval_cancel_open_requests(
        &mut self,
        policy_uuid: Uuid,
    ) -> Result<usize, OperationError> {
        let open = self.internal_search(filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
            f_eq(
                Attribute::ApprovalRequestPolicy,
                PartialValue::Refer(policy_uuid)
            ),
            f_or!([
                f_eq(
                    Attribute::ApprovalState,
                    PartialValue::new_iutf8(ApprovalRequestState::Pending.as_str())
                ),
                f_eq(
                    Attribute::ApprovalState,
                    PartialValue::new_iutf8(ApprovalRequestState::Escalated.as_str())
                ),
                f_eq(
                    Attribute::ApprovalState,
                    PartialValue::new_iutf8(ApprovalRequestState::Approved.as_str())
                )
            ])
        ])))?;
        for request in &open {
            self.approval_request_set_state(request.get_uuid(), ApprovalRequestState::Cancelled)?;
            info!(
                request = %request.get_uuid(),
                policy = %policy_uuid,
                "approval request cancelled, its policy was disabled"
            );
        }
        Ok(open.len())
    }

    /// Record whether each of `members` is a group, for the snapshot of a new request.
    fn approval_member_kinds(
        &mut self,
        members: &[Uuid],
    ) -> Result<BTreeMap<Uuid, ApprovalMemberKind>, OperationError> {
        let mut kinds = BTreeMap::new();
        for member in members {
            let kind = match self.internal_search_uuid(*member) {
                Ok(entry)
                    if entry.attribute_equality(Attribute::Class, &EntryClass::Group.into()) =>
                {
                    ApprovalMemberKind::Group
                }
                Ok(_) | Err(OperationError::NoMatchingEntries) => ApprovalMemberKind::Account,
                Err(err) => return Err(err),
            };
            kinds.insert(*member, kind);
        }
        Ok(kinds)
    }

    /// The number of persons other than `requester` that can decide in one of `slots`
    /// now: the slot names them, or a group they are a member of. Only enabled persons
    /// count, never anonymous, as no one else may decide.
    fn approval_slot_candidates(
        &mut self,
        slots: &[Uuid],
        requester: Uuid,
    ) -> Result<usize, OperationError> {
        if slots.is_empty() {
            return Ok(0);
        }
        let now = self.get_curtime_odt();
        let candidates = slots
            .iter()
            .flat_map(|slot| {
                [
                    f_eq(Attribute::Uuid, PartialValue::Uuid(*slot)),
                    f_eq(Attribute::MemberOf, PartialValue::Refer(*slot)),
                ]
            })
            .collect();
        self.internal_search(filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::Person.into()),
            f_or(candidates),
            f_andnot(f_eq(Attribute::Uuid, PartialValue::Uuid(requester))),
            f_andnot(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_ANONYMOUS)))
        ])))
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| approval_account_active(entry, now))
                .count()
        })
    }

    /// Kubidm: reject a request that its snapshot can never approve, because too few of its
    /// approver slots can be filled by someone other than the requester (for example, the
    /// requester is the only approver). Without this the request would sit pending until it
    /// expires. Backup approvers can fill open slots after escalation, so they count when
    /// the policy escalates.
    ///
    /// This is a best-effort sanity check that errs on the side of accepting: a person who
    /// can fill several slots is counted for each, and approvers can be disabled, deleted
    /// or removed from a group after the check. A request that passes may still never be
    /// approved; it then expires.
    fn approval_check_reachable(
        &mut self,
        policy_name: &str,
        snapshot: &ApprovalSnapshot,
    ) -> Result<(), OperationError> {
        let required = snapshot.required as usize;
        let requester = snapshot.requester;

        let mut fillable = 0;
        for slot in snapshot.slots.keys() {
            if self.approval_slot_candidates(&[*slot], requester)? > 0 {
                fillable += 1;
            }
        }

        if fillable < required
            && snapshot.escalation_timeout_seconds.is_some()
            && !snapshot.backups.is_empty()
        {
            let backups: Vec<Uuid> = snapshot.backups.keys().copied().collect();
            let backups = self.approval_slot_candidates(&backups, requester)?;
            fillable += backups.min(snapshot.slots.len() - fillable);
        }

        if fillable < required {
            error!(
                policy = %policy_name,
                %requester,
                required,
                fillable,
                "approval request can never be approved: too few approvers other than the requester"
            );
            return Err(OperationError::AP0001ApprovalQuorumUnreachable);
        }
        Ok(())
    }

    /// Resolve the `target` (a uuid, name or spn) of an approval request to the uuid of an
    /// entry that `ident` may see. An entry that does not exist and one that `ident` may not
    /// see are indistinguishable: both are [OperationError::NoMatchingEntries]. The internal
    /// system identity sees every entry.
    pub fn approval_request_target_resolve(
        &mut self,
        ident: &Identity,
        target: &str,
    ) -> Result<Uuid, OperationError> {
        if ident.is_internal() {
            return self.name_to_uuid(target);
        }

        let target = target.trim();
        let mut terms = vec![f_eq(Attribute::Name, PartialValue::new_iname(target))];
        if let Some(spn) = PartialValue::new_spn_s(target) {
            terms.push(f_eq(Attribute::Spn, spn));
        }
        if let Ok(uuid) = Uuid::parse_str(target) {
            terms.push(f_eq(Attribute::Uuid, PartialValue::Uuid(uuid)));
        }

        let filter = filter!(f_or(terms));
        let entries = self
            .impersonate_search(filter.clone(), filter, ident)
            .map_err(|err| {
                error!(?err, "unable to resolve the approval request target");
                OperationError::NoMatchingEntries
            })?;

        match entries.as_slice() {
            [entry] => Ok(entry.get_uuid()),
            _ => Err(OperationError::NoMatchingEntries),
        }
    }

    /// Create a pending approval request from `ident` for `operation_type` on `target_uuid`,
    /// under the enabled policy `policy_name` that must cover that operation type. The
    /// request expires after the policy timeout. Returns the uuid of the new request.
    ///
    /// The approvers, pattern and escalation of the policy are copied onto the request (see
    /// the module documentation), so later changes to the policy do not affect it.
    ///
    /// The requester picks `policy_name` here, but that grants nothing by itself: the gate,
    /// [Self::approval_request_check_and_consume], only accepts a request filed under the
    /// policy that the operation requires. Filing under a laxer policy that covers the same
    /// operation type does not help.
    ///
    /// Kubidm: any identity with a read-write session may create a request (`POST
    /// /v1/approval/request`); creating one grants nothing. A request for an operation that
    /// can be executed must name a valid target and details for it, see
    /// [Self::approval_request_execute]; for other operation types a request only records
    /// intent and collects decisions.
    ///
    /// `target_uuid` is not checked against what `ident` may see, and a uuid that does not
    /// exist fails referential integrity. A caller acting for a user must therefore get it
    /// from [Self::approval_request_target_resolve], which only returns entries the user
    /// may see, so that the outcome does not reveal whether an entry they can not see exists.
    pub fn approval_request_create(
        &mut self,
        ident: &Identity,
        policy_name: &str,
        operation_type: &ApprovalOperationType,
        target_uuid: Uuid,
        operation_details: &BTreeMap<String, String>,
        ct: Duration,
    ) -> Result<Uuid, OperationError> {
        if ident.is_internal() && !approval_ident_is_system(ident) {
            security_access!(ident = %ident, "denied - internal identity is not the system");
            return Err(OperationError::AccessDenied);
        }
        if ident.access_scope() != AccessScope::ReadWrite {
            security_access!("approval request creation requires a read-write session");
            return Err(OperationError::AccessDenied);
        }

        let policy_entry = self
            .internal_search(filter!(f_and!([
                f_eq(Attribute::Class, EntryClass::ApprovalPolicy.into()),
                f_eq(
                    Attribute::ApprovalPolicyName,
                    PartialValue::new_iname(policy_name)
                )
            ])))?
            .into_iter()
            .next()
            .ok_or(OperationError::NoMatchingEntries)?;
        let policy = approval_policy_from_entry(&policy_entry)?;

        if !policy.enabled {
            error!(policy = %policy.name, "approval policy is disabled");
            return Err(OperationError::AP0003ApprovalNotUsable);
        }
        if !policy.operation_types.contains(operation_type) {
            error!(policy = %policy.name, %operation_type, "approval policy does not cover this operation type");
            return Err(OperationError::AP0003ApprovalNotUsable);
        }

        // Kubidm: operations that can be executed (`approval_request_execute`) define the
        // target and details they need. Validate them now, rather than when the approval
        // is used, and store the details in their canonical form, since the gate compares
        // them exactly.
        let canonical_details;
        let operation_details = match operation_type {
            ApprovalOperationType::GroupMembershipHighPrivilege => {
                let member = approval_group_membership_member(operation_details, false)?;
                let group = self.internal_search_uuid(target_uuid)?;
                if !group.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
                    return Err(OperationError::InvalidAttribute(format!(
                        "the target of a {operation_type} request must be a group"
                    )));
                }
                if !is_high_privilege_group(group.as_ref()) {
                    return Err(OperationError::InvalidAttribute(format!(
                        "the target of a {operation_type} request must be a high privilege group: \
                         members of other groups are added directly"
                    )));
                }
                if member == target_uuid {
                    return Err(OperationError::InvalidAttribute(
                        "a group can not be made a member of itself".to_string(),
                    ));
                }
                self.approval_member_check(member)?;
                // Record what a group member contains now: that is what is approved, and
                // the request can not be executed once it changes.
                let member_entry = self.internal_search_uuid(member)?;
                let contents = approval_member_contents(self, &member_entry)?;
                canonical_details = approval_group_membership_details(member, contents.as_ref());
                &canonical_details
            }
            _ => operation_details,
        };

        let slots = self.approval_member_kinds(&policy.approvers)?;
        let backups = self.approval_member_kinds(&policy.backup_approvers)?;
        let snapshot = ApprovalSnapshot {
            requester: ident.get_uuid(),
            pattern: policy.pattern,
            required: approval_required_decisions(policy.pattern, slots.len()),
            slots,
            backups,
            escalation_timeout_seconds: policy.escalation_timeout_seconds,
        };

        self.approval_check_reachable(&policy.name, &snapshot)?;

        let snapshot_json = serde_json::to_string(&snapshot).map_err(|err| {
            error!(?err, "unable to serialise approval quorum snapshot");
            OperationError::SerdeJsonError
        })?;

        let uuid = Uuid::new_v4();
        let mut entry: EntryInitNew = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::ApprovalRequest.to_value()),
            (Attribute::Uuid, Value::Uuid(uuid)),
            (Attribute::ApprovalRequestPolicy, Value::Refer(policy.uuid)),
            // Exactly one operation type per request.
            (
                Attribute::ApprovalOperationType,
                Value::new_iutf8n(operation_type.as_str())
            ),
            (Attribute::ApprovalTarget, Value::Refer(target_uuid)),
            (Attribute::ApprovalRequestor, Value::Refer(ident.get_uuid())),
            (
                Attribute::ApprovalState,
                Value::new_iutf8(ApprovalRequestState::Pending.as_str())
            ),
            (Attribute::ApprovalEscalationLevel, Value::Uint32(0))
        );
        entry.add_ava(
            Attribute::ApprovalQuorumSnapshot,
            Value::new_utf8(snapshot_json),
        );

        if policy.timeout_seconds > 0 {
            let expires = OffsetDateTime::UNIX_EPOCH
                + ct
                + Duration::from_secs(u64::from(policy.timeout_seconds));
            entry.add_ava(Attribute::ApprovalExpires, Value::DateTime(expires));
        }

        if !operation_details.is_empty() {
            let details = serde_json::to_string(operation_details).map_err(|err| {
                error!(?err, "unable to serialise approval operation details");
                OperationError::SerdeJsonError
            })?;
            entry.add_ava(
                Attribute::ApprovalOperationDetails,
                Value::new_utf8(details),
            );
        }

        self.internal_create(vec![entry])?;
        info!(
            ident = %ident,
            request = %uuid,
            policy = %policy.name,
            %operation_type,
            target = %target_uuid,
            "approval request created"
        );
        Ok(uuid)
    }

    /// Kubidm: is the decider's account managed by the requester (directly, or through a
    /// group the requester is a member of)? Such an account is under the requester's
    /// control, so its decision would be the requester's own.
    fn approval_decider_managed_by_requester(
        &mut self,
        decider: &EntrySealedCommitted,
        requester: Uuid,
    ) -> Result<bool, OperationError> {
        // Single valued.
        let Some(manager) = decider.get_ava_single_refer(Attribute::EntryManagedBy) else {
            return Ok(false);
        };
        if manager == requester {
            return Ok(true);
        }
        match self.internal_search_uuid(requester) {
            Ok(requester_entry) => Ok(requester_entry
                .get_ava_refer(Attribute::MemberOf)
                .is_some_and(|groups| groups.contains(&manager))),
            Err(OperationError::NoMatchingEntries) => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub fn approval_request_decision(
        &mut self,
        ident: &Identity,
        request_uuid: Uuid,
        request: ApprovalDecisionRequest,
        ct: Duration,
    ) -> Result<(), OperationError> {
        let current_time = OffsetDateTime::UNIX_EPOCH + ct;
        let is_system = approval_ident_is_system(ident);

        let decider = if is_system {
            None
        } else {
            let decider = approval_check_decider(ident)?;
            if !approval_account_active(&decider, current_time) {
                security_access!(ident = %ident, "denied - the approver's account is expired or not yet valid");
                return Err(OperationError::AccessDenied);
            }
            Some(decider)
        };

        // Kubidm: a missing request (or policy) and a request the caller may not decide on
        // are indistinguishable to non-system callers, so existence is not revealed.
        let not_found = if is_system {
            OperationError::NoMatchingEntries
        } else {
            OperationError::AccessDenied
        };

        let Some(entry) = self
            .internal_search(filter!(f_and!([
                f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
                f_eq(Attribute::Uuid, PartialValue::Uuid(request_uuid))
            ])))?
            .into_iter()
            .next()
        else {
            security_access!(ident = %ident, %request_uuid, "denied - approval request not found");
            return Err(not_found);
        };

        let resolved = approval_request_resolve(self, &entry, current_time)?;

        let (Some(policy), Some(snapshot)) = (resolved.policy.as_ref(), resolved.snapshot.as_ref())
        else {
            error!(%request_uuid, "approval request policy or quorum snapshot not found");
            return Err(not_found);
        };

        // Kubidm: only an approver of the request may decide on it - or a backup approver
        // once the escalation time has passed - and never on their own request, nor through
        // an account the requester manages. The system may fill any slot.
        let escalated = resolved.escalated_at(current_time);
        let slots = match decider.as_ref() {
            None => snapshot.slot_set(),
            Some(decider) => {
                let slots = approval_ident_slots(ident, snapshot, escalated);
                if slots.is_empty() {
                    security_access!(ident = %ident, %request_uuid, "denied - not an approver of this request");
                    return Err(OperationError::AccessDenied);
                }

                if snapshot.requester == ident.get_uuid() {
                    security_access!(ident = %ident, %request_uuid, "denied - approvers can not decide on their own request");
                    return Err(OperationError::AccessDenied);
                }

                if self.approval_decider_managed_by_requester(decider, snapshot.requester)? {
                    security_access!(ident = %ident, %request_uuid, "denied - the requester manages this approver's account");
                    return Err(OperationError::AccessDenied);
                }
                slots
            }
        };

        if !policy.enabled {
            error!(policy = %policy.name, "approval policy is disabled");
            return Err(OperationError::AP0003ApprovalNotUsable);
        }

        if !resolved.is_valid() {
            error!(%request_uuid, "approval request target or requester was deleted, it can not be decided");
            return Err(OperationError::AP0003ApprovalNotUsable);
        }

        if resolved.request.state != ApprovalRequestState::Pending {
            error!(state = %resolved.request.state, "approval request is not pending");
            return Err(OperationError::AP0003ApprovalNotUsable);
        }

        if resolved
            .request
            .expires_at
            .is_some_and(|expires_at| expires_at <= current_time)
        {
            error!("approval request has expired");
            return Err(OperationError::AP0003ApprovalNotUsable);
        }

        let approver_uuid = ident.get_uuid();
        if resolved
            .decisions
            .iter()
            .any(|d| d.approver_uuid == approver_uuid)
        {
            error!("approver has already decided on this approval request");
            return Err(OperationError::AP0003ApprovalNotUsable);
        }

        let action = request.action;
        let record_uuid = Uuid::new_v4();
        let decision = StoredApprovalDecision {
            approver_uuid,
            approver_spn: ident
                .get_user_entry()
                .and_then(|e| e.get_ava_single_proto_string(Attribute::Spn))
                .unwrap_or_default(),
            decision_time: current_time,
            decision_time_nanos: current_time.nanosecond(),
            action,
            comment: request.comment,
            slots,
            record_uuid,
        };

        let ctx = ApprovalTallyContext {
            snapshot,
            escalation_at: snapshot.escalation_at(resolved.request.created_at),
            inactive: &resolved.inactive,
        };
        let counted_before = approval_tally(&ctx, &resolved.decisions).counted;
        let mut decisions = resolved.decisions.clone();
        decisions.push(decision.clone());
        let tally = approval_tally(&ctx, &decisions);
        // The new decision must fill a slot, without displacing an earlier decision (which
        // could otherwise happen when two decisions have the same time, as they are then
        // ordered by approver).
        if !tally.counted.contains(&approver_uuid) || !tally.counted.is_superset(&counted_before) {
            // For example a second member of a group whose slot is already decided.
            error!(%request_uuid, "every approver slot this approver can fill has already been decided");
            return Err(OperationError::AP0003ApprovalNotUsable);
        }
        let new_state = tally.state();

        // A new entry per decision, so a decision made concurrently on another replica is
        // never lost, see `SCHEMA_CLASS_APPROVAL_DECISION_RECORD`.
        let decision_json = serde_json::to_string(&decision).map_err(|err| {
            error!(?err, "unable to serialise approval decision");
            OperationError::SerdeJsonError
        })?;
        self.internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::ApprovalDecisionRecord.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(record_uuid)),
            (Attribute::ApprovalRecordRequest, Value::Refer(request_uuid)),
            (
                Attribute::ApprovalDecision,
                Value::new_utf8s(&decision_json)
            )
        )])?;

        if new_state != resolved.stored_state {
            self.approval_request_set_state(request_uuid, new_state)?;
        }
        info!(
            ident = %ident,
            request = %request_uuid,
            policy = %policy.name,
            %action,
            state = %new_state,
            "approval decision recorded"
        );
        Ok(())
    }

    /// Kubidm: the approval gate. An operation that needs approval calls this, as the
    /// identity carrying out the operation, before it makes its change and in the same
    /// transaction. It succeeds once per approved request:
    ///
    /// - the outcome is recomputed from the request's snapshot and decision records (see
    ///   the module documentation) and must be approved; a stored approval is not enough,
    ///   and an approval whose approvers have since been deleted or disabled no longer
    ///   counts. The stored state must not be a final state other than approved;
    /// - the request must still be valid (policy, target and requester exist);
    /// - only the requester (or the system) may use the approval;
    /// - the request must have been filed under `policy_name`, the policy the operation
    ///   requires. **Callers must choose `policy_name` on the server side** (from the
    ///   configuration of the operation), never from the requester's input: otherwise a
    ///   requester could file under any laxer policy that covers the same operation type;
    /// - the request must not have expired (`expires_at`), and the policy must still be
    ///   enabled and still cover `operation_type`. Disabling a policy, or no longer covering
    ///   an operation type, stops its approvals from being used;
    /// - the operation type, target and operation details must match the request exactly;
    /// - the request then moves to the final `consumed` state.
    ///
    /// A request that fails one of these checks is reported as `AP0003ApprovalNotUsable`;
    /// a caller other than the requester (or the system) gets `AccessDenied`.
    ///
    /// An approval is only final once replication has converged: a decision made
    /// concurrently on another replica can still change the outcome, and the same approval
    /// can be consumed once on each replica before they replicate. Callers must not decide
    /// on approvals any other way, in particular not from `approval_request_get`.
    ///
    /// Kubidm: [Self::approval_request_execute] calls this for
    /// `group_membership_high_privilege`.
    pub fn approval_request_check_and_consume(
        &mut self,
        ident: &Identity,
        request_uuid: Uuid,
        policy_name: &str,
        operation_type: &ApprovalOperationType,
        target_uuid: Uuid,
        operation_details: &BTreeMap<String, String>,
    ) -> Result<(), OperationError> {
        let is_system = approval_ident_is_system(ident);
        if ident.is_internal() && !is_system {
            security_access!(ident = %ident, "denied - internal identity is not the system");
            return Err(OperationError::AccessDenied);
        }

        let now = self.get_curtime_odt();
        let entry = self
            .internal_search(filter!(f_and!([
                f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
                f_eq(Attribute::Uuid, PartialValue::Uuid(request_uuid))
            ])))?
            .into_iter()
            .next()
            .ok_or(OperationError::NoMatchingEntries)?;
        let resolved = approval_request_resolve(self, &entry, now)?;

        let Some(snapshot) = resolved.snapshot.as_ref() else {
            error!(%request_uuid, "approval request has no quorum snapshot, it can not be used");
            return Err(OperationError::AP0003ApprovalNotUsable);
        };
        if !is_system && snapshot.requester != ident.get_uuid() {
            security_access!(ident = %ident, %request_uuid, "denied - only the requester may use an approval");
            return Err(OperationError::AccessDenied);
        }

        if !resolved.is_valid() {
            error!(%request_uuid, "approval request policy, target or requester was deleted");
            return Err(OperationError::AP0003ApprovalNotUsable);
        }
        if resolved.request.state != ApprovalRequestState::Approved
            || resolved.derived_state != Some(ApprovalRequestState::Approved)
        {
            error!(
                %request_uuid,
                state = %resolved.request.state,
                stored = %resolved.stored_state,
                derived = ?resolved.derived_state,
                "approval request is not approved"
            );
            return Err(OperationError::AP0003ApprovalNotUsable);
        }

        // Filed under the policy the operation requires, not just any policy covering the
        // same operation type.
        let required_policy = self
            .internal_search(filter!(f_and!([
                f_eq(Attribute::Class, EntryClass::ApprovalPolicy.into()),
                f_eq(
                    Attribute::ApprovalPolicyName,
                    PartialValue::new_iname(policy_name)
                )
            ])))?
            .first()
            .map(|entry| entry.get_uuid());
        if required_policy.is_none() || resolved.request.policy_uuid != required_policy {
            security_access!(
                ident = %ident,
                %request_uuid,
                required_policy = %policy_name,
                policy = ?resolved.request.policy_name,
                "denied - the approval request is not under the policy the operation requires"
            );
            return Err(OperationError::AP0003ApprovalNotUsable);
        }

        if resolved
            .request
            .expires_at
            .is_some_and(|expires_at| expires_at <= now)
        {
            error!(%request_uuid, expires_at = ?resolved.request.expires_at, "approval request has expired");
            return Err(OperationError::AP0003ApprovalNotUsable);
        }

        let Some(policy) = resolved.policy.as_ref() else {
            error!(%request_uuid, "approval request policy was deleted");
            return Err(OperationError::AP0003ApprovalNotUsable);
        };
        if !policy.enabled {
            error!(%request_uuid, policy = %policy.name, "approval policy is disabled");
            return Err(OperationError::AP0003ApprovalNotUsable);
        }
        if !policy.operation_types.contains(operation_type) {
            error!(
                %request_uuid,
                policy = %policy.name,
                %operation_type,
                "approval policy no longer covers this operation type"
            );
            return Err(OperationError::AP0003ApprovalNotUsable);
        }

        if resolved.request.operation_type != *operation_type
            || resolved.request.target_uuid != Some(target_uuid)
            || resolved.request.operation_details != *operation_details
        {
            security_access!(
                ident = %ident,
                %request_uuid,
                %operation_type,
                target = %target_uuid,
                "denied - the approval request is for a different operation"
            );
            return Err(OperationError::AP0003ApprovalNotUsable);
        }

        self.approval_request_set_state(request_uuid, ApprovalRequestState::Consumed)?;
        info!(
            ident = %ident,
            request = %request_uuid,
            policy = %policy_name,
            %operation_type,
            target = %target_uuid,
            "approval request consumed"
        );
        Ok(())
    }

    /// Kubidm: carry out the operation of an approved request, as its requester. Only
    /// `group_membership_high_privilege` can be executed: it adds the member named by the
    /// request details (`{"member": "<uuid>"}`) to the target group. While an enabled
    /// policy covers that operation, `plugins::approval_gate` refuses the same write made
    /// directly, and this is the way to make it.
    ///
    /// - Only the requester may execute their request, with a read-write session
    ///   (`AccessDenied` otherwise).
    /// - The policy is chosen here, not by the requester: the request must have been filed
    ///   under an enabled policy that covers the operation type. If several enabled
    ///   policies cover it, any one of them is accepted (each is sufficient on its own). If
    ///   none covers it, the gate is off and the request can not be executed: add the member
    ///   directly instead.
    /// - The target must still be a high privilege group, and the member must still exist
    ///   and must not be a dynamic group, an entry owned by a sync agreement, or a group
    ///   containing one (see `approval_member_check`). A group member must still contain
    ///   exactly the nested members recorded when the request was created.
    /// - The requester must still be allowed to add members to the group by the access
    ///   controls, evaluated now as for a modify of its `member` attribute: an approval
    ///   lifts the gate, it does not grant rights.
    /// - [Self::approval_request_check_and_consume] then checks the approval and consumes it,
    ///   and the member is added as the internal identity (so the gate does not apply), all
    ///   in this transaction. A second execute finds the request consumed and fails.
    ///
    /// A request that can not be used in its current state (not approved, consumed,
    /// expired, policy disabled, target no longer high privilege, member deleted, ...) is
    /// reported as `AP0003ApprovalNotUsable`.
    pub fn approval_request_execute(
        &mut self,
        ident: &Identity,
        request_uuid: Uuid,
    ) -> Result<(), OperationError> {
        let not_usable = OperationError::AP0003ApprovalNotUsable;
        if ident.is_internal() {
            security_access!(ident = %ident, "denied - approval requests are executed by their requester");
            return Err(OperationError::AccessDenied);
        }
        if ident.access_scope() != AccessScope::ReadWrite {
            security_access!("approval request execution requires a read-write session");
            return Err(OperationError::AccessDenied);
        }

        let entry = self
            .internal_search(filter!(f_and!([
                f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
                f_eq(Attribute::Uuid, PartialValue::Uuid(request_uuid))
            ])))?
            .into_iter()
            .next();

        // Authorise before revealing anything about the request.
        let is_requester = entry
            .as_ref()
            .and_then(|e| e.get_ava_single_refer(Attribute::ApprovalRequestor))
            == Some(ident.get_uuid());
        if !is_requester {
            security_access!(ident = %ident, %request_uuid, "denied - only the requester may execute an approval request");
            return Err(OperationError::AccessDenied);
        }
        let entry = entry.ok_or(OperationError::NoMatchingEntries)?;

        let operation_type = approval_request_operation_type(&entry)?;
        if operation_type != ApprovalOperationType::GroupMembershipHighPrivilege {
            error!(%request_uuid, %operation_type, "this approval request operation type can not be executed");
            return Err(not_usable);
        }
        let Some(group) = entry.get_ava_single_refer(Attribute::ApprovalTarget) else {
            error!(%request_uuid, "approval request target was deleted");
            return Err(not_usable);
        };
        let operation_details = approval_request_operation_details(&entry)?;
        let (member, approved_contents) = approval_group_membership_stored(&operation_details)?;
        let request_policy = entry.get_ava_single_refer(Attribute::ApprovalRequestPolicy);

        // The policy the operation requires, chosen on the server side.
        let policy_name = approval_enabled_policies(self, &operation_type)?
            .into_iter()
            .find(|policy| Some(policy.get_uuid()) == request_policy)
            .and_then(|policy| {
                policy
                    .get_ava_single_iname(Attribute::ApprovalPolicyName)
                    .map(str::to_string)
            });
        let Some(policy_name) = policy_name else {
            security_access!(
                ident = %ident,
                %request_uuid,
                %operation_type,
                "denied - the approval request is not under an enabled policy that covers its operation"
            );
            return Err(not_usable);
        };

        // The situation the approval was given for must still hold.
        match self.internal_search_uuid(group) {
            Ok(group_entry) if is_high_privilege_group(group_entry.as_ref()) => {}
            Ok(_) => {
                error!(%request_uuid, %group, "approval request target is no longer a high privilege group");
                return Err(not_usable);
            }
            Err(OperationError::NoMatchingEntries) => {
                error!(%request_uuid, %group, "approval request target was deleted");
                return Err(not_usable);
            }
            Err(err) => return Err(err),
        }
        match self.approval_member_check(member) {
            Ok(()) => {}
            Err(OperationError::NoMatchingEntries) => {
                error!(%request_uuid, %member, "approval request member was deleted");
                return Err(not_usable);
            }
            Err(OperationError::InvalidAttribute(reason)) => {
                error!(%request_uuid, %member, %reason, "approval request member can no longer be added");
                return Err(not_usable);
            }
            Err(err) => return Err(err),
        }
        // A group member must still contain exactly what it contained when the request was
        // created (and approved): otherwise entries added to it since would become high
        // privilege without an approval.
        let member_entry = self.internal_search_uuid(member)?;
        let current_contents = approval_member_contents(self, &member_entry)?;
        if current_contents.unwrap_or_default() != approved_contents.unwrap_or_default() {
            security_access!(
                ident = %ident,
                %request_uuid,
                %member,
                "denied - the member's nested members changed since the request was created"
            );
            return Err(not_usable);
        }

        // The approval lifts the gate, it does not grant the right to add the member.
        let (_, rights) = group_member_rights(self, ident, group)?;
        if !rights.add {
            security_access!(ident = %ident, %group, "denied - may not add members to this group");
            return Err(OperationError::AccessDenied);
        }

        self.approval_request_check_and_consume(
            ident,
            request_uuid,
            &policy_name,
            &operation_type,
            group,
            &operation_details,
        )?;

        self.internal_modify_uuid(
            group,
            &ModifyList::new_append(Attribute::Member, Value::ReferN(member)),
        )?;
        security_info!(
            ident = %ident,
            request = %request_uuid,
            policy = %policy_name,
            %group,
            %member,
            "approved high privilege group member added"
        );
        Ok(())
    }

    /// Kubidm: can `member` be made a member of a high privilege group through an approval
    /// request? It must exist ([OperationError::NoMatchingEntries] otherwise), and must not
    /// be, or (transitively) contain, a dynamic group or an entry owned by a sync agreement
    /// ([OperationError::InvalidAttribute]): their members are decided by a filter or by
    /// the sync connector, so approving one would hand control over high privilege
    /// membership to them.
    fn approval_member_check(&mut self, member: Uuid) -> Result<(), OperationError> {
        let entry = self.internal_search_uuid(member)?;
        let delegated = |entry: &EntrySealedCommitted| {
            entry.attribute_equality(Attribute::Class, &EntryClass::DynGroup.into())
                || entry.attribute_equality(Attribute::Class, &EntryClass::SyncObject.into())
                || entry
                    .get_ava_single_refer(Attribute::SyncParentUuid)
                    .is_some()
        };
        if delegated(&entry) {
            return Err(OperationError::InvalidAttribute(
                "the member is a dynamic group or is owned by a sync agreement, so its \
                 membership is not under approval control"
                    .to_string(),
            ));
        }
        let nested = self.internal_search(filter!(f_and!([
            f_eq(Attribute::MemberOf, PartialValue::Refer(member)),
            f_or!([
                f_eq(Attribute::Class, EntryClass::DynGroup.into()),
                f_eq(Attribute::Class, EntryClass::SyncObject.into()),
                f_pres(Attribute::SyncParentUuid)
            ])
        ])))?;
        if nested.iter().any(|entry| delegated(entry)) {
            return Err(OperationError::InvalidAttribute(
                "the member contains a dynamic group or an entry owned by a sync agreement, so \
                 its membership is not under approval control"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Kubidm: break-glass, for the server's admin socket (`kubidmd approval-policy
    /// disable`): disable the approval policy `name`, or every enabled policy with `None`,
    /// as the internal system identity, with no other authorisation. This turns off any
    /// approval gate those policies enable, even when no one can act as an approval admin
    /// any more. Returns the names of the policies disabled.
    pub fn approval_policy_disable_break_glass(
        &mut self,
        name: Option<&str>,
    ) -> Result<Vec<String>, OperationError> {
        let mut terms = vec![f_eq(Attribute::Class, EntryClass::ApprovalPolicy.into())];
        if let Some(name) = name {
            terms.push(f_eq(
                Attribute::ApprovalPolicyName,
                PartialValue::new_iname(name),
            ));
        }
        let policies = self.internal_search(filter!(f_and(terms)))?;
        if name.is_some() && policies.is_empty() {
            return Err(OperationError::NoMatchingEntries);
        }
        let mut disabled = Vec::new();
        for policy in policies {
            let enabled = policy
                .get_ava_single_bool(Attribute::ApprovalPolicyEnabled)
                .unwrap_or(true);
            if !enabled {
                continue;
            }
            // Internal writes run as the system identity, which `plugins::approval` allows.
            self.internal_modify_uuid(
                policy.get_uuid(),
                &ModifyList::new_purge_and_set(
                    Attribute::ApprovalPolicyEnabled,
                    Value::Bool(false),
                ),
            )?;
            self.approval_cancel_open_requests(policy.get_uuid())?;
            disabled.push(
                policy
                    .get_ava_single_iname(Attribute::ApprovalPolicyName)
                    .map(str::to_string)
                    .unwrap_or_else(|| policy.get_uuid().to_string()),
            );
        }
        if disabled.is_empty() {
            info!("break-glass: no enabled approval policy to disable");
        } else {
            warn!(
                ?disabled,
                "break-glass: approval policies disabled from the admin socket"
            );
        }
        Ok(disabled)
    }

    pub fn approval_request_cancel(
        &mut self,
        ident: &Identity,
        request_uuid: Uuid,
    ) -> Result<(), OperationError> {
        let entry = self
            .internal_search(filter!(f_and!([
                f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
                f_eq(Attribute::Uuid, PartialValue::Uuid(request_uuid))
            ])))?
            .into_iter()
            .next();

        // Kubidm: the requestor may cancel their own request, otherwise this needs
        // approval admin rights. Authorise before revealing whether the request exists.
        let is_requestor = !ident.is_internal()
            && entry
                .as_ref()
                .and_then(|e| e.get_ava_single_refer(Attribute::ApprovalRequestor))
                == Some(ident.get_uuid());
        if !(is_requestor && ident.access_scope() == AccessScope::ReadWrite) {
            approval_check_admin(ident, true)?;
        }
        let entry = entry.ok_or(OperationError::NoMatchingEntries)?;

        // Only pending (or invalid) requests can be cancelled, decided ones are final. A
        // malformed request can still be cancelled based on its stored state.
        let now = self.get_curtime_odt();
        let state = match approval_request_resolve(self, &entry, now) {
            Ok(resolved) => resolved.request.state,
            Err(err) => {
                warn!(?err, %request_uuid, "malformed approval request");
                approval_request_state(&entry)?
            }
        };
        if !matches!(
            state,
            ApprovalRequestState::Pending | ApprovalRequestState::Invalid
        ) {
            error!(%state, "approval request is not pending");
            return Err(OperationError::AP0003ApprovalNotUsable);
        }

        self.approval_request_set_state(request_uuid, ApprovalRequestState::Cancelled)?;
        info!(ident = %ident, request = %request_uuid, "approval request cancelled");
        Ok(())
    }

    /// Mark a pending approval request as expired once its expiry time has passed.
    /// Returns whether the request was expired.
    pub fn approval_request_expire(
        &mut self,
        request_uuid: Uuid,
        ct: Duration,
    ) -> Result<bool, OperationError> {
        let current_time = OffsetDateTime::UNIX_EPOCH + ct;
        let Some(resolved) = self.approval_request_pending(request_uuid, current_time)? else {
            return Ok(false);
        };

        if !approval_expiry_due(&resolved, current_time) {
            return Ok(false);
        }

        self.approval_request_set_state(request_uuid, ApprovalRequestState::Expired)?;
        info!(request = %request_uuid, "approval request expired");
        Ok(true)
    }

    /// Record that a pending approval request has escalated to the backup approvers of its
    /// snapshot, once the escalation timeout has passed since the request was created.
    /// Backup approvers may decide from that time on whether or not this was recorded.
    /// Returns whether the request was escalated.
    pub fn approval_request_escalate(
        &mut self,
        request_uuid: Uuid,
        ct: Duration,
    ) -> Result<bool, OperationError> {
        let current_time = OffsetDateTime::UNIX_EPOCH + ct;
        let Some(resolved) = self.approval_request_pending(request_uuid, current_time)? else {
            return Ok(false);
        };

        if !approval_escalation_due(&resolved, current_time) {
            return Ok(false);
        }

        self.approval_request_set_escalated(request_uuid)?;
        Ok(true)
    }

    /// Kubidm: the periodic approval maintenance, run from the server's interval loop.
    /// For every request stored as pending:
    ///
    /// - an invalid request (its policy, target, requester or snapshot is missing) is
    ///   expired,
    /// - a malformed request (or one with a malformed decision record) is expired, as it
    ///   can never be decided,
    /// - a request whose decisions decide it (after a replication merge) gets that state,
    /// - an overdue request is expired,
    /// - a request past its escalation timeout is marked escalated, once.
    ///
    /// Returns the number of requests changed, so that the caller only commits when
    /// something changed.
    #[instrument(level = "debug", skip_all)]
    pub fn approval_sweep(&mut self) -> Result<usize, OperationError> {
        let now = self.get_curtime_odt();

        let entries = self.internal_search(filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
            f_eq(
                Attribute::ApprovalState,
                PartialValue::new_iutf8(ApprovalRequestState::Pending.as_str())
            )
        ])))?;

        let mut changed = 0;
        for resolved in approval_request_resolve_each(self, &entries, now)? {
            let resolved = match resolved {
                Ok(resolved) => resolved,
                Err((request_uuid, err)) => {
                    warn!(?err, %request_uuid, "expiring malformed approval request");
                    self.approval_request_set_state(request_uuid, ApprovalRequestState::Expired)?;
                    changed += 1;
                    continue;
                }
            };
            let request_uuid = resolved.request.uuid;

            let new_state = match resolved.request.state {
                ApprovalRequestState::Invalid => {
                    warn!(%request_uuid, "expiring invalid approval request");
                    Some(ApprovalRequestState::Expired)
                }
                ApprovalRequestState::Pending => {
                    if approval_expiry_due(&resolved, now) {
                        info!(%request_uuid, "approval request expired");
                        Some(ApprovalRequestState::Expired)
                    } else {
                        None
                    }
                }
                state if state != resolved.stored_state => {
                    info!(%request_uuid, %state, "approval request state updated from its decisions");
                    Some(state)
                }
                _ => None,
            };

            if let Some(state) = new_state {
                self.approval_request_set_state(request_uuid, state)?;
                changed += 1;
            } else if approval_escalation_due(&resolved, now) {
                self.approval_request_set_escalated(request_uuid)?;
                changed += 1;
            }
        }

        Ok(changed)
    }

    fn approval_request_set_state(
        &mut self,
        request_uuid: Uuid,
        state: ApprovalRequestState,
    ) -> Result<(), OperationError> {
        self.internal_modify_uuid(
            request_uuid,
            &ModifyList::new_purge_and_set(
                Attribute::ApprovalState,
                Value::new_iutf8(state.as_str()),
            ),
        )
    }

    fn approval_request_set_escalated(&mut self, request_uuid: Uuid) -> Result<(), OperationError> {
        self.internal_modify_uuid(
            request_uuid,
            &ModifyList::new_purge_and_set(Attribute::ApprovalEscalationLevel, Value::Uint32(1)),
        )?;
        info!(request = %request_uuid, "approval request escalated to the backup approvers");
        Ok(())
    }

    /// The request, if it is stored as pending. Malformed requests are logged and skipped.
    fn approval_request_pending(
        &mut self,
        request_uuid: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<ResolvedApprovalRequest>, OperationError> {
        let entries = self.internal_search(filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
            f_eq(Attribute::Uuid, PartialValue::Uuid(request_uuid)),
            f_eq(
                Attribute::ApprovalState,
                PartialValue::new_iutf8(ApprovalRequestState::Pending.as_str())
            )
        ])))?;
        let resolved = approval_request_resolve_all(self, &entries, now)?
            .into_iter()
            .next();
        if resolved.is_none() {
            debug!(%request_uuid, "approval request not found or not pending");
        }
        Ok(resolved)
    }
}

/// Kubidm: the enabled approval policies that cover `operation_type`. An operation gated on
/// approval is gated while this is not empty, see `plugins::approval_gate`.
///
/// This reads the attributes directly rather than through `approval_policy_from_entry`, so
/// that a policy which is otherwise malformed still turns the gate on (failing closed). Such
/// a policy also blocks executing requests filed under it (the gate,
/// [QueryServerWriteTransaction::approval_request_check_and_consume], can not read it) until
/// it is disabled or deleted.
pub(crate) fn approval_enabled_policies<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    operation_type: &ApprovalOperationType,
) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
    let entries = qs.internal_search(filter!(f_eq(
        Attribute::Class,
        EntryClass::ApprovalPolicy.into()
    )))?;
    Ok(entries
        .into_iter()
        .filter(|entry| {
            entry
                .get_ava_single_bool(Attribute::ApprovalPolicyEnabled)
                .unwrap_or(true)
                && entry
                    .get_ava_iter_iutf8(Attribute::ApprovalOperationType)
                    .is_some_and(|mut types| {
                        types.any(|t| {
                            t.parse::<ApprovalOperationType>().ok().as_ref() == Some(operation_type)
                        })
                    })
        })
        .collect())
}

/// Kubidm: the operation details key of a `group_membership_high_privilege` request, see
/// [approval_group_membership_member].
const APPROVAL_DETAIL_MEMBER: &str = "member";

/// Kubidm: the member to add from the operation details of a
/// `group_membership_high_privilege` request. The target of such a request is the group,
/// and its details are exactly `{"member": "<uuid>"}`, with the uuid of the entry to add
/// in its canonical (hyphenated, lower case) form. `approval_request_create` stores the
/// details in that form, and `approval_request_execute` only accepts them in that form.
fn approval_group_membership_member(
    details: &BTreeMap<String, String>,
    canonical: bool,
) -> Result<Uuid, OperationError> {
    let invalid = || {
        OperationError::InvalidAttribute(format!(
            "the details of a {} request must be exactly {{\"{APPROVAL_DETAIL_MEMBER}\": \"<uuid>\"}}",
            ApprovalOperationType::GroupMembershipHighPrivilege
        ))
    };
    let (Some(value), 1) = (details.get(APPROVAL_DETAIL_MEMBER), details.len()) else {
        return Err(invalid());
    };
    let member = Uuid::parse_str(value.trim()).map_err(|_| invalid())?;
    if member.is_nil() || (canonical && *value != member.to_string()) {
        return Err(invalid());
    }
    Ok(member)
}

/// Kubidm: the operation details key, set by the server, that records what a group member
/// of a `group_membership_high_privilege` request contained when the request was created:
/// the uuids of its nested members (direct and indirect), sorted and comma separated. The
/// request can only be executed while the group still contains exactly these, see
/// [approval_group_membership_stored].
const APPROVAL_DETAIL_MEMBER_CONTENTS: &str = "member_contents";

/// Kubidm: the canonical operation details of a `group_membership_high_privilege` request
/// that adds `member`, with the nested members of `member` when it is a group.
fn approval_group_membership_details(
    member: Uuid,
    contents: Option<&BTreeSet<Uuid>>,
) -> BTreeMap<String, String> {
    let mut details = BTreeMap::from([(APPROVAL_DETAIL_MEMBER.to_string(), member.to_string())]);
    if let Some(contents) = contents {
        details.insert(
            APPROVAL_DETAIL_MEMBER_CONTENTS.to_string(),
            approval_member_contents_string(contents),
        );
    }
    details
}

fn approval_member_contents_string(contents: &BTreeSet<Uuid>) -> String {
    contents
        .iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Kubidm: the member and, for a group member, its recorded nested members, from the
/// stored (canonical) operation details of a `group_membership_high_privilege` request.
fn approval_group_membership_stored(
    details: &BTreeMap<String, String>,
) -> Result<(Uuid, Option<BTreeSet<Uuid>>), OperationError> {
    let mut rest = details.clone();
    let contents = match rest.remove(APPROVAL_DETAIL_MEMBER_CONTENTS) {
        None => None,
        Some(value) => {
            let invalid = || {
                OperationError::InvalidAttribute(format!(
                    "the {APPROVAL_DETAIL_MEMBER_CONTENTS} of a {} request is malformed",
                    ApprovalOperationType::GroupMembershipHighPrivilege
                ))
            };
            let contents = if value.is_empty() {
                BTreeSet::new()
            } else {
                value
                    .split(',')
                    .map(|uuid| Uuid::parse_str(uuid).map_err(|_| invalid()))
                    .collect::<Result<BTreeSet<_>, _>>()?
            };
            if approval_member_contents_string(&contents) != value {
                return Err(invalid());
            }
            Some(contents)
        }
    };
    let member = approval_group_membership_member(&rest, true)?;
    Ok((member, contents))
}

/// Kubidm: the nested members (direct and indirect) of `member` when it is a group, `None`
/// otherwise.
fn approval_member_contents<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    member: &EntrySealedCommitted,
) -> Result<Option<BTreeSet<Uuid>>, OperationError> {
    if !member.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
        return Ok(None);
    }
    let nested = qs.internal_search(filter!(f_eq(
        Attribute::MemberOf,
        PartialValue::Refer(member.get_uuid())
    )))?;
    Ok(Some(nested.iter().map(|entry| entry.get_uuid()).collect()))
}

/// Kubidm: describe the member of a `group_membership_high_privilege` request for the
/// approval admins reading it: its name, classes and, for a group, its number of direct
/// members. `None` for other operation types or when the member no longer exists.
fn approval_operation_member<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    request: &ApprovalRequest,
) -> Option<ApprovalOperationMember> {
    if request.operation_type != ApprovalOperationType::GroupMembershipHighPrivilege {
        return None;
    }
    let (member, approved_members) =
        approval_group_membership_stored(&request.operation_details).ok()?;
    let entry = qs.internal_search_uuid(member).ok()?;
    let current_members = approval_member_contents(qs, &entry).ok()?;
    let members_changed = (approved_members.is_some() || current_members.is_some()).then(|| {
        approved_members.clone().unwrap_or_default() != current_members.unwrap_or_default()
    });
    let classes: Vec<String> = entry
        .get_ava_iter_iutf8(Attribute::Class)
        .map(|classes| classes.map(str::to_string).collect())
        .unwrap_or_default();
    let member_count = entry
        .attribute_equality(Attribute::Class, &EntryClass::Group.into())
        .then(|| {
            entry
                .get_ava_refer(Attribute::Member)
                .map_or(0, BTreeSet::len)
        });
    Some(ApprovalOperationMember {
        uuid: member,
        name: entry
            .get_ava_single_iname(Attribute::Name)
            .map(str::to_string),
        classes,
        member_count,
        approved_members: approved_members.map(|members| members.into_iter().collect()),
        members_changed,
    })
}

fn approval_policy_from_entry(
    entry: &Entry<EntrySealed, EntryCommitted>,
) -> Result<ApprovalPolicy, OperationError> {
    let uuid = entry.get_uuid();

    let name = entry
        .get_ava_single_iname(Attribute::ApprovalPolicyName)
        .ok_or(OperationError::MissingAttribute(
            Attribute::ApprovalPolicyName,
        ))?;

    let description = entry.get_ava_single_utf8(Attribute::Description);

    let pattern = entry
        .get_ava_single_iutf8(Attribute::ApprovalPatternAttr)
        .and_then(|s| s.parse::<ApprovalPattern>().ok())
        .ok_or(OperationError::InvalidValueState)?;

    let timeout_seconds = entry
        .get_ava_single_uint32(Attribute::ApprovalTimeout)
        .ok_or(OperationError::MissingAttribute(Attribute::ApprovalTimeout))?;

    let escalation_timeout_seconds = entry.get_ava_single_uint32(Attribute::EscalationTimeout);

    let enabled = entry
        .get_ava_single_bool(Attribute::ApprovalPolicyEnabled)
        .unwrap_or(true);

    let operation_types: Vec<ApprovalOperationType> = entry
        .get_ava_iter_iutf8(Attribute::ApprovalOperationType)
        .ok_or(OperationError::MissingAttribute(
            Attribute::ApprovalOperationType,
        ))?
        .filter_map(|s| s.parse().ok())
        .collect();

    let approvers: Vec<Uuid> = entry
        .get_ava_refer(Attribute::Approver)
        .map(|s| s.iter().copied().collect())
        .unwrap_or_default();

    let backup_approvers: Vec<Uuid> = entry
        .get_ava_refer(Attribute::BackupApprover)
        .map(|s| s.iter().copied().collect())
        .unwrap_or_default();

    Ok(ApprovalPolicy {
        uuid,
        name: name.to_string(),
        description: description.map(String::from),
        operation_types,
        approvers,
        backup_approvers,
        pattern,
        timeout_seconds,
        escalation_timeout_seconds,
        enabled,
    })
}

fn approval_request_state(
    entry: &Entry<EntrySealed, EntryCommitted>,
) -> Result<ApprovalRequestState, OperationError> {
    entry
        .get_ava_single_iutf8(Attribute::ApprovalState)
        .and_then(|s| s.parse().ok())
        .ok_or(OperationError::InvalidValueState)
}

/// The quorum snapshot of a request, `None` if it has none (created before snapshots
/// existed), an error if it is malformed.
fn approval_request_snapshot(
    entry: &Entry<EntrySealed, EntryCommitted>,
) -> Result<Option<ApprovalSnapshot>, OperationError> {
    entry
        .get_ava_single_utf8(Attribute::ApprovalQuorumSnapshot)
        .map(|s| {
            serde_json::from_str::<ApprovalSnapshot>(s).map_err(|err| {
                error!(?err, uuid = %entry.get_uuid(), "invalid approval quorum snapshot");
                OperationError::InvalidValueState
            })
        })
        .transpose()
}

/// Protect the authority retained by an outstanding approval's frozen quorum snapshot.
/// Current policy approvers alone are insufficient: removing an approver from the policy
/// does not remove that approver from requests already created under it. Backup slots
/// also remain actionable after escalation. Exclude both until the request is final.
/// Invalid snapshot JSON is an error rather than silently dropping a protection.
pub(crate) fn delegation_snapshot_principals(
    qs: &mut QueryServerWriteTransaction<'_>,
) -> Result<BTreeSet<Uuid>, OperationError> {
    let requests = qs.internal_search(filter!(f_and(vec![
        f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
        f_or(vec![
            f_eq(Attribute::ApprovalState, PartialValue::new_iutf8(ApprovalRequestState::Pending.as_str())),
            f_eq(Attribute::ApprovalState, PartialValue::new_iutf8(ApprovalRequestState::Escalated.as_str())),
            f_eq(Attribute::ApprovalState, PartialValue::new_iutf8(ApprovalRequestState::Approved.as_str())),
        ]),
    ])))?;

    let mut excluded = BTreeSet::new();
    for request in requests {
        // A request without a snapshot cannot be decided or consumed.
        if let Some(snapshot) = approval_request_snapshot(&request)? {
            excluded.extend(snapshot.slots.keys().copied());
            excluded.extend(snapshot.backups.keys().copied());
        }
    }
    Ok(excluded)
}

/// `ApprovalOperationType` is shared with approval policies, which list every operation
/// type they cover, so it is multi-value in the schema. A request is about exactly one
/// operation, which is enforced here.
fn approval_request_operation_type(
    entry: &Entry<EntrySealed, EntryCommitted>,
) -> Result<ApprovalOperationType, OperationError> {
    let mut operation_types = entry
        .get_ava_iter_iutf8(Attribute::ApprovalOperationType)
        .ok_or(OperationError::MissingAttribute(
            Attribute::ApprovalOperationType,
        ))?;

    match (operation_types.next(), operation_types.next()) {
        (Some(operation_type), None) => operation_type
            .parse()
            .map_err(|_| OperationError::InvalidValueState),
        _ => {
            error!(uuid = %entry.get_uuid(), "approval request must have exactly one operation type");
            Err(OperationError::InvalidValueState)
        }
    }
}

/// The operation details are stored as a JSON object string, see
/// `SCHEMA_ATTR_APPROVAL_OPERATION_DETAILS`.
fn approval_request_operation_details(
    entry: &Entry<EntrySealed, EntryCommitted>,
) -> Result<BTreeMap<String, String>, OperationError> {
    entry
        .get_ava_single_utf8(Attribute::ApprovalOperationDetails)
        .map(|s| {
            serde_json::from_str(s).map_err(|err| {
                error!(?err, uuid = %entry.get_uuid(), "invalid approval operation details");
                OperationError::InvalidValueState
            })
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

/// The request as stored. Its `state` is the stored state, the caller replaces it with the
/// effective state.
fn approval_request_from_entry(
    entry: &Entry<EntrySealed, EntryCommitted>,
    policy: Option<&ApprovalPolicy>,
    snapshot: Option<&ApprovalSnapshot>,
    decisions: &[StoredApprovalDecision],
) -> Result<ApprovalRequest, OperationError> {
    let uuid = entry.get_uuid();

    let operation_type = approval_request_operation_type(entry)?;

    let target_uuid = entry.get_ava_single_refer(Attribute::ApprovalTarget);
    let requestor_uuid = entry.get_ava_single_refer(Attribute::ApprovalRequestor);

    let created_at = entry
        .get_ava_set(Attribute::CreatedAtCid)
        .and_then(|vs| vs.to_cid_single())
        .map(|cid| OffsetDateTime::UNIX_EPOCH + cid.ts)
        .ok_or(OperationError::MissingAttribute(Attribute::CreatedAtCid))?;

    let expires_at = entry.get_ava_single_datetime(Attribute::ApprovalExpires);

    let state = approval_request_state(entry)?;

    let escalation_level = entry
        .get_ava_single_uint32(Attribute::ApprovalEscalationLevel)
        .unwrap_or(0);

    let operation_details = approval_request_operation_details(entry)?;

    Ok(ApprovalRequest {
        uuid,
        policy_uuid: policy.map(|p| p.uuid),
        policy_name: policy.map(|p| p.name.clone()),
        operation_type,
        target_uuid,
        target_spn: target_uuid.map(|u| u.to_string()).unwrap_or_default(),
        requestor_uuid,
        requestor_spn: requestor_uuid.map(|u| u.to_string()).unwrap_or_default(),
        created_at,
        expires_at,
        state,
        decisions: decisions
            .iter()
            .map(StoredApprovalDecision::to_proto)
            .collect(),
        escalation_level,
        required_decisions: snapshot.map(|s| s.required).unwrap_or(0),
        operation_details,
        operation_member: None,
    })
}

#[cfg(test)]
mod tests {
    use super::StoredApprovalDecision;
    use crate::event::{CreateEvent, DeleteEvent};
    use crate::idm::server::IdmServerTransaction;
    use crate::idm::serviceaccount::GenerateApiTokenEvent;
    use crate::migration_data::dl14::schema::{
        SCHEMA_ATTR_APPROVAL_OPERATION_TYPE, SCHEMA_ATTR_APPROVAL_PATTERN,
        SCHEMA_ATTR_APPROVAL_POLICY_NAME, SCHEMA_ATTR_APPROVER, SCHEMA_ATTR_BACKUP_APPROVER,
    };
    use crate::prelude::*;
    use crate::schema::SchemaAttribute;
    use kubidm_proto::v1::{
        ApprovalDecisionAction, ApprovalDecisionRequest, ApprovalOperationType, ApprovalPattern,
        ApprovalPolicyCreateRequest, ApprovalRequest, ApprovalRequestState,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Duration;
    use time::OffsetDateTime;

    fn check(schema: &SchemaAttribute, attr: &Attribute, vals: Vec<Value>, expected_len: usize) {
        let mut entry: Entry<EntryInit, EntryNew> = Entry::new();
        entry.set_ava(attr.clone(), vals);
        let vs = entry.get_ava_set(attr).expect("attribute missing");
        assert_eq!(vs.len(), expected_len);
        schema
            .validate_ava(attr, vs)
            .expect("values do not satisfy the declared attribute syntax");
    }

    /// The values written by `approval_policy_create` must satisfy the syntax declared in the
    /// schema, and the multi-value attributes must retain every value that was written.
    #[test]
    fn test_approval_policy_multi_value_syntax() {
        check(
            &SCHEMA_ATTR_APPROVER,
            &Attribute::Approver,
            vec![Value::ReferN(UUID_ADMIN), Value::ReferN(UUID_IDM_ADMINS)],
            2,
        );
        check(
            &SCHEMA_ATTR_BACKUP_APPROVER,
            &Attribute::BackupApprover,
            vec![
                Value::ReferN(UUID_IDM_ADMINS),
                Value::ReferN(UUID_SYSTEM_ADMINS),
            ],
            2,
        );
        check(
            &SCHEMA_ATTR_APPROVAL_OPERATION_TYPE,
            &Attribute::ApprovalOperationType,
            vec![
                Value::new_iutf8n("create_high_privilege_entry"),
                Value::new_iutf8n("schema_modify"),
            ],
            2,
        );
        check(
            &SCHEMA_ATTR_APPROVAL_POLICY_NAME,
            &Attribute::ApprovalPolicyName,
            vec![Value::new_iname("multi_approver_policy")],
            1,
        );
        check(
            &SCHEMA_ATTR_APPROVAL_PATTERN,
            &Attribute::ApprovalPatternAttr,
            vec![Value::new_iutf8("majority")],
            1,
        );
    }

    /// Decision records written before the sub-second part of the decision time was stored
    /// still read, with whole seconds.
    #[test]
    fn test_approval_decision_time_backward_compatible() {
        let approver = Uuid::new_v4();
        let legacy = format!(
            r#"{{"approver_uuid":"{approver}","approver_spn":"","decision_time":1700000000,"action":"approve","comment":null,"slots":["{approver}"]}}"#
        );
        let decision: StoredApprovalDecision =
            serde_json::from_str(&legacy).expect("legacy decision record must parse");
        assert_eq!(decision.decision_time_nanos, 0);
        assert_eq!(
            decision.decided_at(),
            OffsetDateTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
        );

        let at = OffsetDateTime::UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
        let decision = StoredApprovalDecision {
            decision_time: at,
            decision_time_nanos: at.nanosecond(),
            ..decision
        };
        let round_trip: StoredApprovalDecision =
            serde_json::from_str(&serde_json::to_string(&decision).expect("serialise"))
                .expect("deserialise");
        assert_eq!(round_trip.decided_at(), at);
    }

    /// A recomputation never moves a request out of a final state.
    #[test]
    fn test_approval_effective_state_final_states() {
        use super::approval_effective_state;
        use ApprovalRequestState::*;
        let request = Uuid::new_v4();

        assert_eq!(
            approval_effective_state(request, Rejected, true, Some(Approved)),
            Rejected
        );
        assert_eq!(
            approval_effective_state(request, Approved, true, Some(Rejected)),
            Approved
        );
        for stored in [Cancelled, Expired, Consumed] {
            for derived in [Pending, Approved, Rejected] {
                assert_eq!(
                    approval_effective_state(request, stored, true, Some(derived)),
                    stored
                );
            }
        }
        assert_eq!(
            approval_effective_state(request, Pending, true, Some(Approved)),
            Approved
        );
        assert_eq!(
            approval_effective_state(request, Pending, true, Some(Rejected)),
            Rejected
        );
        // Without a snapshot, or with a reference gone, a pending request is invalid.
        assert_eq!(
            approval_effective_state(request, Pending, true, None),
            Invalid
        );
        assert_eq!(
            approval_effective_state(request, Pending, false, Some(Approved)),
            Invalid
        );
    }

    fn two_approver_policy(name: &str) -> ApprovalPolicyCreateRequest {
        ApprovalPolicyCreateRequest {
            name: name.to_string(),
            description: Some("Two approver policy".to_string()),
            operation_types: vec![
                ApprovalOperationType::CreateHighPrivilegeEntry,
                ApprovalOperationType::SchemaModify,
            ],
            approvers: vec![UUID_ADMIN, UUID_IDM_ADMIN],
            backup_approvers: vec![UUID_SYSTEM_ADMINS],
            pattern: ApprovalPattern::Majority,
            timeout_seconds: 3600,
            escalation_timeout_seconds: Some(600),
        }
    }

    /// End to end: the approval schema and the approval admins group exist at the target
    /// domain level, and a policy with two approvers is stored and read back intact.
    #[qs_test]
    async fn test_approval_policy_create_and_read_back(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // Created by the domain migrations.
        let approval_admins = write_txn
            .internal_search_uuid(UUID_IDM_APPROVAL_ADMINS)
            .expect("idm_approval_admins must exist");
        assert!(approval_admins
            .attribute_equality(Attribute::Member, &PartialValue::Refer(UUID_IDM_ADMINS)));

        // idm_admin is an approval admin through idm_admins.
        let idm_admin_entry = write_txn.internal_search_uuid(UUID_IDM_ADMIN).unwrap();
        let idm_admin = Identity::from_impersonate_entry_readwrite(idm_admin_entry);

        write_txn
            .approval_policy_create(&idm_admin, &two_approver_policy("two_approvers"))
            .expect("failed to create approval policy");

        // ApprovalPolicyName is unique.
        assert!(write_txn
            .approval_policy_create(&idm_admin, &two_approver_policy("two_approvers"))
            .is_err());

        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();

        let policy = read_txn
            .approval_policy_get(&idm_admin, "two_approvers")
            .expect("failed to read back approval policy");

        assert_eq!(policy.name, "two_approvers");
        assert_eq!(policy.description.as_deref(), Some("Two approver policy"));
        assert_eq!(policy.approvers.len(), 2);
        assert!(policy.approvers.contains(&UUID_ADMIN));
        assert!(policy.approvers.contains(&UUID_IDM_ADMIN));
        assert_eq!(policy.backup_approvers, vec![UUID_SYSTEM_ADMINS]);
        assert_eq!(policy.operation_types.len(), 2);
        assert!(policy
            .operation_types
            .contains(&ApprovalOperationType::CreateHighPrivilegeEntry));
        assert!(policy
            .operation_types
            .contains(&ApprovalOperationType::SchemaModify));
        assert_eq!(policy.pattern, ApprovalPattern::Majority);
        assert_eq!(policy.timeout_seconds, 3600);
        assert_eq!(policy.escalation_timeout_seconds, Some(600));
        assert!(policy.enabled);

        let policies = read_txn
            .approval_policy_list(&idm_admin)
            .expect("failed to list approval policies");
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].approvers.len(), 2);

        drop(read_txn);

        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();
        write_txn
            .approval_policy_enable(&idm_admin, "two_approvers", false)
            .expect("failed to disable approval policy");
        write_txn
            .approval_policy_delete(&idm_admin, "two_approvers")
            .expect("failed to delete approval policy");
        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        assert!(matches!(
            read_txn.approval_policy_get(&idm_admin, "two_approvers"),
            Err(OperationError::NoMatchingEntries)
        ));
    }

    /// The approval operations bypass access control profiles, so they must reject callers
    /// that are not approval admins, and writes from read-only sessions.
    #[qs_test]
    async fn test_approval_policy_access_denied(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let anon_entry = write_txn.internal_search_uuid(UUID_ANONYMOUS).unwrap();
        let anon = Identity::from_impersonate_entry_readwrite(anon_entry);

        assert_eq!(
            write_txn.approval_policy_create(&anon, &two_approver_policy("denied")),
            Err(OperationError::AccessDenied)
        );

        // An approval admin with a read-only session can not write.
        let idm_admin_entry = write_txn.internal_search_uuid(UUID_IDM_ADMIN).unwrap();
        let idm_admin_ro = Identity::from_impersonate_entry_readonly(idm_admin_entry);
        assert_eq!(
            write_txn.approval_policy_create(&idm_admin_ro, &two_approver_policy("denied")),
            Err(OperationError::AccessDenied)
        );
        assert_eq!(
            write_txn.approval_policy_delete(&anon, "denied"),
            Err(OperationError::AccessDenied)
        );

        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        assert!(matches!(
            read_txn.approval_policy_list(&anon),
            Err(OperationError::AccessDenied)
        ));
        // ... but can read.
        assert!(read_txn
            .approval_policy_list(&idm_admin_ro)
            .expect("approval admin list")
            .is_empty());
    }

    /// Only approvers (or backup approvers) of the request may decide on it, and the
    /// requestor may cancel their own request (but nobody else's).
    #[qs_test]
    async fn test_approval_request_decision_access(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();

        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        let admin = identity(&mut write_txn, UUID_ADMIN);
        let anon = identity(&mut write_txn, UUID_ANONYMOUS);
        let a = create_person(&mut write_txn, "approver_a");
        let other = create_person(&mut write_txn, "not_an_approver");

        // The approver is A (direct), the backup approver system_admins (by group).
        let mut request = two_approver_policy("decision_policy");
        request.approvers = vec![a];
        write_txn
            .approval_policy_create(&idm_admin, &request)
            .expect("failed to create approval policy");
        // An approval admin is not implicitly an approver.
        write_txn
            .approval_policy_create(
                &idm_admin,
                &policy_request("other_policy", ApprovalPattern::AnyOne, vec![other]),
            )
            .expect("failed to create approval policy");

        let request_a = create_request(&mut write_txn, UUID_ANONYMOUS, "decision_policy", ct)
            .expect("failed to create approval request");
        let request_b = create_request(&mut write_txn, UUID_ANONYMOUS, "other_policy", ct)
            .expect("failed to create approval request");

        // Neither a direct nor a backup approver of the policy.
        assert_eq!(
            write_txn.approval_request_decision(&anon, request_a, approve(), ct),
            Err(OperationError::AccessDenied)
        );
        assert_eq!(
            decide_as(&mut write_txn, other, request_a, approve(), ct),
            Err(OperationError::AccessDenied)
        );
        // Approval admins are service accounts here, and not approvers either.
        assert_eq!(
            write_txn.approval_request_decision(&idm_admin, request_b, approve(), ct),
            Err(OperationError::AccessDenied)
        );
        assert_eq!(
            decide_as(&mut write_txn, a, request_b, approve(), ct),
            Err(OperationError::AccessDenied)
        );

        assert_eq!(
            stored_state(&mut write_txn, request_a).as_deref(),
            Some("pending")
        );

        // The requestor may cancel their own request, others may not unless approval admin.
        let request_c = create_request(&mut write_txn, UUID_ANONYMOUS, "decision_policy", ct)
            .expect("failed to create approval request");
        assert_eq!(
            write_txn.approval_request_cancel(&admin, request_c),
            Err(OperationError::AccessDenied)
        );
        write_txn
            .approval_request_cancel(&anon, request_c)
            .expect("requestor must be able to cancel");
        assert_eq!(
            stored_state(&mut write_txn, request_c).as_deref(),
            Some("cancelled")
        );

        write_txn.commit().expect("failed to commit");
    }

    fn identity(txn: &mut QueryServerWriteTransaction<'_>, uuid: Uuid) -> Identity {
        let entry = txn
            .internal_search_uuid(uuid)
            .expect("identity entry missing");
        Identity::from_impersonate_entry_readwrite(entry)
    }

    fn find_policy_uuid(txn: &mut QueryServerWriteTransaction<'_>, name: &str) -> Uuid {
        txn.internal_search(filter!(f_eq(
            Attribute::ApprovalPolicyName,
            PartialValue::new_iname(name)
        )))
        .expect("policy search")
        .first()
        .expect("policy missing")
        .get_uuid()
    }

    fn stored_state(txn: &mut QueryServerWriteTransaction<'_>, uuid: Uuid) -> Option<String> {
        txn.internal_search_uuid(uuid)
            .expect("request missing")
            .get_ava_single_iutf8(Attribute::ApprovalState)
            .map(str::to_string)
    }

    fn create_person(txn: &mut QueryServerWriteTransaction<'_>, name: &str) -> Uuid {
        let uuid = Uuid::new_v4();
        txn.internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname(name)),
            (Attribute::DisplayName, Value::new_utf8s(name)),
            (Attribute::Uuid, Value::Uuid(uuid))
        )])
        .expect("failed to create person");
        uuid
    }

    fn create_service_account(txn: &mut QueryServerWriteTransaction<'_>, name: &str) -> Uuid {
        let uuid = Uuid::new_v4();
        txn.internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname(name)),
            (Attribute::DisplayName, Value::new_utf8s(name)),
            (Attribute::Uuid, Value::Uuid(uuid))
        )])
        .expect("failed to create service account");
        uuid
    }

    fn create_group(
        txn: &mut QueryServerWriteTransaction<'_>,
        name: &str,
        members: &[Uuid],
    ) -> Uuid {
        let uuid = Uuid::new_v4();
        let mut entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname(name)),
            (Attribute::Uuid, Value::Uuid(uuid))
        );
        for member in members {
            entry.add_ava(Attribute::Member, Value::ReferN(*member));
        }
        txn.internal_create(vec![entry])
            .expect("failed to create group");
        uuid
    }

    /// Set (or with `None` clear) the expiry time of an account.
    fn set_account_expire(
        txn: &mut QueryServerWriteTransaction<'_>,
        account: Uuid,
        expire: Option<OffsetDateTime>,
    ) {
        let modlist = match expire {
            Some(expire) => {
                ModifyList::new_purge_and_set(Attribute::AccountExpire, Value::DateTime(expire))
            }
            None => ModifyList::new_purge(Attribute::AccountExpire),
        };
        txn.internal_modify_uuid(account, &modlist)
            .expect("failed to set account expiry");
    }

    /// Store a decision record directly, as replication would deliver one.
    fn add_decision_record_uuid(
        txn: &mut QueryServerWriteTransaction<'_>,
        record: Uuid,
        request: Uuid,
        decision_json: &str,
    ) {
        txn.internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::ApprovalDecisionRecord.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(record)),
            (Attribute::ApprovalRecordRequest, Value::Refer(request)),
            (Attribute::ApprovalDecision, Value::new_utf8s(decision_json))
        )])
        .expect("failed to create decision record");
    }

    fn add_decision_record(
        txn: &mut QueryServerWriteTransaction<'_>,
        request: Uuid,
        decision_json: &str,
    ) {
        add_decision_record_uuid(txn, Uuid::new_v4(), request, decision_json)
    }

    /// A decision record of `approver` at `at`, claiming `slots`.
    fn decision_json(
        approver: Uuid,
        action: ApprovalDecisionAction,
        at: OffsetDateTime,
        slots: &[Uuid],
    ) -> String {
        let decision = StoredApprovalDecision {
            approver_uuid: approver,
            approver_spn: String::new(),
            decision_time: at,
            decision_time_nanos: at.nanosecond(),
            action,
            comment: None,
            slots: slots.iter().copied().collect(),
            record_uuid: Uuid::nil(),
        };
        serde_json::to_string(&decision).expect("failed to serialise decision")
    }

    fn policy_request(
        name: &str,
        pattern: ApprovalPattern,
        approvers: Vec<Uuid>,
    ) -> ApprovalPolicyCreateRequest {
        ApprovalPolicyCreateRequest {
            name: name.to_string(),
            description: None,
            operation_types: vec![ApprovalOperationType::SchemaModify],
            approvers,
            backup_approvers: vec![],
            pattern,
            timeout_seconds: 3600,
            escalation_timeout_seconds: None,
        }
    }

    fn create_policy(
        txn: &mut QueryServerWriteTransaction<'_>,
        name: &str,
        pattern: ApprovalPattern,
        approvers: Vec<Uuid>,
    ) {
        let idm_admin = identity(txn, UUID_IDM_ADMIN);
        txn.approval_policy_create(&idm_admin, &policy_request(name, pattern, approvers))
            .expect("failed to create approval policy");
    }

    fn decide(action: ApprovalDecisionAction, comment: Option<&str>) -> ApprovalDecisionRequest {
        ApprovalDecisionRequest {
            action,
            comment: comment.map(str::to_string),
        }
    }

    fn approve() -> ApprovalDecisionRequest {
        decide(ApprovalDecisionAction::Approve, None)
    }

    fn reject() -> ApprovalDecisionRequest {
        decide(ApprovalDecisionAction::Reject, None)
    }

    /// Create a schema_modify request on idm_admins from `requester` under `policy`.
    fn create_request(
        txn: &mut QueryServerWriteTransaction<'_>,
        requester: Uuid,
        policy: &str,
        ct: Duration,
    ) -> Result<Uuid, OperationError> {
        let requester = identity(txn, requester);
        txn.approval_request_create(
            &requester,
            policy,
            &ApprovalOperationType::SchemaModify,
            UUID_IDM_ADMINS,
            &BTreeMap::new(),
            ct,
        )
    }

    fn decide_as(
        txn: &mut QueryServerWriteTransaction<'_>,
        approver: Uuid,
        request: Uuid,
        decision: ApprovalDecisionRequest,
        ct: Duration,
    ) -> Result<(), OperationError> {
        let approver = identity(txn, approver);
        txn.approval_request_decision(&approver, request, decision, ct)
    }

    /// Consume `request` as `requester` for a schema_modify on idm_admins without details
    /// requiring `policy`, as `create_request` creates it.
    fn consume_as(
        txn: &mut QueryServerWriteTransaction<'_>,
        requester: Uuid,
        policy: &str,
        request: Uuid,
    ) -> Result<(), OperationError> {
        let requester = identity(txn, requester);
        txn.approval_request_check_and_consume(
            &requester,
            request,
            policy,
            &ApprovalOperationType::SchemaModify,
            UUID_IDM_ADMINS,
            &BTreeMap::new(),
        )
    }

    fn read_request(txn: &mut QueryServerWriteTransaction<'_>, request: Uuid) -> ApprovalRequest {
        let now = txn.get_curtime_odt();
        let entry = txn.internal_search_uuid(request).expect("request missing");
        super::approval_request_resolve(txn, &entry, now)
            .expect("failed to resolve request")
            .request
    }

    /// End to end: policy -> request -> approver decision -> approved, with the decision
    /// persisted (committed and read back).
    #[qs_test]
    async fn test_approval_request_flow_approve(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        let admin = identity(&mut write_txn, UUID_ADMIN);
        let a = create_person(&mut write_txn, "approver_a");
        let other = create_person(&mut write_txn, "not_an_approver");

        create_policy(
            &mut write_txn,
            "approve_policy",
            ApprovalPattern::AnyOne,
            vec![a],
        );

        let details = BTreeMap::from([(
            "reason".to_string(),
            "add \"schema\"\nattribute".to_string(),
        )]);

        // The policy does not cover this operation type.
        assert_eq!(
            write_txn.approval_request_create(
                &admin,
                "approve_policy",
                &ApprovalOperationType::PrivilegeGrant,
                UUID_IDM_ADMINS,
                &details,
                ct,
            ),
            Err(OperationError::AP0003ApprovalNotUsable)
        );

        let request_uuid = write_txn
            .approval_request_create(
                &admin,
                "approve_policy",
                &ApprovalOperationType::SchemaModify,
                UUID_IDM_ADMINS,
                &details,
                ct,
            )
            .expect("failed to create approval request");
        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        let request = read_txn
            .approval_request_get(&idm_admin, request_uuid)
            .expect("failed to read approval request");
        assert_eq!(request.state, ApprovalRequestState::Pending);
        assert_eq!(request.policy_name.as_deref(), Some("approve_policy"));
        assert_eq!(request.operation_type, ApprovalOperationType::SchemaModify);
        assert_eq!(request.target_uuid, Some(UUID_IDM_ADMINS));
        assert_eq!(request.requestor_uuid, Some(UUID_ADMIN));
        assert_eq!(request.operation_details, details);
        assert_eq!(request.required_decisions, 1);
        assert!(request.decisions.is_empty());
        assert_eq!(
            request.expires_at,
            Some(OffsetDateTime::UNIX_EPOCH + ct + Duration::from_secs(3600))
        );
        drop(read_txn);

        let mut write_txn = server.write(ct).await.unwrap();
        // A disabled policy accepts no decisions.
        write_txn
            .approval_policy_enable(&idm_admin, "approve_policy", false)
            .expect("failed to disable approval policy");
        assert_eq!(
            decide_as(&mut write_txn, a, request_uuid, approve(), ct),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        write_txn
            .approval_policy_enable(&idm_admin, "approve_policy", true)
            .expect("failed to enable approval policy");
        // Kubidm: disabling the policy cancelled the request, a new one is needed.
        assert_eq!(
            stored_state(&mut write_txn, request_uuid).as_deref(),
            Some("cancelled")
        );
        let request_uuid = write_txn
            .approval_request_create(
                &admin,
                "approve_policy",
                &ApprovalOperationType::SchemaModify,
                UUID_IDM_ADMINS,
                &details,
                ct,
            )
            .expect("failed to create approval request");
        // A missing request is indistinguishable from an unauthorised one, except to the
        // system identity.
        assert_eq!(
            decide_as(&mut write_txn, a, Uuid::new_v4(), approve(), ct),
            Err(OperationError::AccessDenied)
        );
        assert_eq!(
            write_txn.approval_request_decision(
                &Identity::from_internal(),
                Uuid::new_v4(),
                approve(),
                ct
            ),
            Err(OperationError::NoMatchingEntries)
        );
        assert_eq!(
            write_txn.approval_request_cancel(&admin, Uuid::new_v4()),
            Err(OperationError::AccessDenied)
        );
        // Internal roles other than the system are not trusted.
        assert_eq!(
            write_txn.approval_request_decision(
                &Identity::migration(),
                request_uuid,
                approve(),
                ct
            ),
            Err(OperationError::AccessDenied)
        );
        assert_eq!(
            write_txn.approval_policy_create(
                &Identity::message_queue(),
                &policy_request("internal", ApprovalPattern::AnyOne, vec![a]),
            ),
            Err(OperationError::AccessDenied)
        );
        // Not an approver of the policy.
        assert_eq!(
            decide_as(&mut write_txn, other, request_uuid, approve(), ct),
            Err(OperationError::AccessDenied)
        );
        decide_as(
            &mut write_txn,
            a,
            request_uuid,
            decide(ApprovalDecisionAction::Approve, Some("looks good")),
            ct,
        )
        .expect("approver must be able to approve");
        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        let request = read_txn
            .approval_request_get(&idm_admin, request_uuid)
            .expect("failed to read approval request");
        assert_eq!(request.state, ApprovalRequestState::Approved);
        assert_eq!(request.decisions.len(), 1);
        assert_eq!(request.decisions[0].approver_uuid, a);
        assert_eq!(request.decisions[0].action, ApprovalDecisionAction::Approve);
        assert_eq!(request.decisions[0].comment.as_deref(), Some("looks good"));
        // The decision time keeps its sub-second part.
        assert_eq!(
            request.decisions[0].decision_time,
            OffsetDateTime::UNIX_EPOCH + ct
        );

        let approved = read_txn
            .approval_request_list(&idm_admin, Some(ApprovalRequestState::Approved))
            .expect("failed to list approval requests");
        assert_eq!(approved.len(), 1);
        assert!(read_txn
            .approval_request_list(&idm_admin, Some(ApprovalRequestState::Pending))
            .expect("failed to list approval requests")
            .is_empty());
        drop(read_txn);

        // A decided request is final.
        let mut write_txn = server.write(ct).await.unwrap();
        assert_eq!(
            decide_as(&mut write_txn, a, request_uuid, reject(), ct),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        assert_eq!(
            write_txn.approval_request_cancel(&idm_admin, request_uuid),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
    }

    /// Rejections: a single rejection rejects under `all`, and under `majority` a request
    /// is rejected once a majority of approvals can no longer be reached. Approvers can not
    /// decide on their own request, nor decide twice.
    #[qs_test]
    async fn test_approval_request_flow_reject(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        let a = create_person(&mut write_txn, "approver_a");
        let b = create_person(&mut write_txn, "approver_b");

        for (name, pattern) in [
            ("majority_policy", ApprovalPattern::Majority),
            ("all_policy", ApprovalPattern::All),
            ("any_policy", ApprovalPattern::AnyOne),
        ] {
            create_policy(&mut write_txn, name, pattern, vec![a, b]);
        }

        let majority_request =
            create_request(&mut write_txn, UUID_ANONYMOUS, "majority_policy", ct)
                .expect("failed to create approval request");
        let all_request = create_request(&mut write_txn, UUID_ANONYMOUS, "all_policy", ct)
            .expect("failed to create approval request");
        // B is one of the two approvers that a majority needs, so a request from B could
        // never be approved.
        assert_eq!(
            create_request(&mut write_txn, b, "majority_policy", ct),
            Err(OperationError::AP0001ApprovalQuorumUnreachable)
        );
        let own_request = create_request(&mut write_txn, b, "any_policy", ct)
            .expect("failed to create approval request");
        write_txn.commit().expect("failed to commit");

        let mut write_txn = server.write(ct).await.unwrap();
        // Majority of two approvers needs both: one approval keeps it pending.
        decide_as(&mut write_txn, a, majority_request, approve(), ct).expect("failed to approve");
        assert_eq!(
            decide_as(&mut write_txn, a, majority_request, approve(), ct),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        decide_as(
            &mut write_txn,
            b,
            majority_request,
            decide(ApprovalDecisionAction::Reject, Some("no")),
            ct,
        )
        .expect("failed to reject");

        decide_as(&mut write_txn, b, all_request, reject(), ct).expect("failed to reject");

        assert_eq!(
            decide_as(&mut write_txn, b, own_request, approve(), ct),
            Err(OperationError::AccessDenied)
        );
        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        let request = read_txn
            .approval_request_get(&idm_admin, majority_request)
            .expect("failed to read approval request");
        assert_eq!(request.state, ApprovalRequestState::Rejected);
        assert_eq!(request.required_decisions, 2);
        assert_eq!(request.decisions.len(), 2);
        assert_eq!(
            request
                .decisions
                .iter()
                .filter(|d| d.action == ApprovalDecisionAction::Reject)
                .count(),
            1
        );

        let request = read_txn
            .approval_request_get(&idm_admin, all_request)
            .expect("failed to read approval request");
        assert_eq!(request.state, ApprovalRequestState::Rejected);

        let request = read_txn
            .approval_request_get(&idm_admin, own_request)
            .expect("failed to read approval request");
        assert_eq!(request.state, ApprovalRequestState::Pending);
    }

    /// A request carries exactly one operation type, although the attribute is multi-value
    /// in the schema (it is shared with policies). The operation details are a JSON object.
    /// Malformed requests fail to read on their own, and are skipped when listing. A request
    /// without a quorum snapshot (created before snapshots existed) is invalid. The sweep
    /// expires all of them, so that none stays pending for ever.
    #[qs_test]
    async fn test_approval_request_operation_type_and_details(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        let a = create_person(&mut write_txn, "approver_a");

        create_policy(
            &mut write_txn,
            "fields_policy",
            ApprovalPattern::AnyOne,
            vec![a],
        );
        let policy_uuid = find_policy_uuid(&mut write_txn, "fields_policy");
        let good = create_request(&mut write_txn, UUID_ANONYMOUS, "fields_policy", ct)
            .expect("failed to create approval request");
        let snapshot = write_txn
            .internal_search_uuid(good)
            .expect("request missing")
            .get_ava_single_utf8(Attribute::ApprovalQuorumSnapshot)
            .expect("snapshot missing")
            .to_string();

        let two_types = Uuid::new_v4();
        let bad_details = Uuid::new_v4();
        let bad_decision = Uuid::new_v4();
        let bad_snapshot = Uuid::new_v4();
        let legacy = Uuid::new_v4();
        let mk_request = |uuid: Uuid, snapshot: Option<&str>| {
            let mut entry = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::ApprovalRequest.to_value()),
                (Attribute::Uuid, Value::Uuid(uuid)),
                (Attribute::ApprovalRequestPolicy, Value::Refer(policy_uuid)),
                (
                    Attribute::ApprovalOperationType,
                    Value::new_iutf8n("schema_modify")
                ),
                (Attribute::ApprovalTarget, Value::Refer(UUID_IDM_ADMINS)),
                (Attribute::ApprovalRequestor, Value::Refer(UUID_ANONYMOUS)),
                (Attribute::ApprovalState, Value::new_iutf8("pending"))
            );
            if let Some(snapshot) = snapshot {
                entry.add_ava(
                    Attribute::ApprovalQuorumSnapshot,
                    Value::new_utf8s(snapshot),
                );
            }
            entry
        };
        let mut e_two_types = mk_request(two_types, Some(&snapshot));
        e_two_types.add_ava(
            Attribute::ApprovalOperationType,
            Value::new_iutf8n("privilege_grant"),
        );
        let mut e_bad_details = mk_request(bad_details, Some(&snapshot));
        e_bad_details.add_ava(
            Attribute::ApprovalOperationDetails,
            Value::new_utf8s("not json"),
        );
        write_txn
            .internal_create(vec![
                e_two_types,
                e_bad_details,
                mk_request(bad_decision, Some(&snapshot)),
                mk_request(bad_snapshot, Some("not json")),
                mk_request(legacy, None),
            ])
            .expect("failed to create approval requests");
        add_decision_record(&mut write_txn, bad_decision, "[]");
        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        for malformed in [two_types, bad_details, bad_decision, bad_snapshot] {
            assert!(matches!(
                read_txn.approval_request_get(&idm_admin, malformed),
                Err(OperationError::InvalidValueState)
            ));
        }
        let legacy_request = read_txn
            .approval_request_get(&idm_admin, legacy)
            .expect("a request without a snapshot reads");
        assert_eq!(legacy_request.state, ApprovalRequestState::Invalid);
        assert_eq!(legacy_request.required_decisions, 0);
        let listed: BTreeSet<Uuid> = read_txn
            .approval_request_list(&idm_admin, None)
            .expect("one malformed request must not fail the list")
            .iter()
            .map(|r| r.uuid)
            .collect();
        assert_eq!(listed, BTreeSet::from([good, legacy]));
        drop(read_txn);

        // A request without a snapshot can not be decided.
        let mut write_txn = server.write(ct).await.unwrap();
        assert_eq!(
            decide_as(&mut write_txn, a, legacy, approve(), ct),
            Err(OperationError::AccessDenied)
        );
        // The sweep expires the malformed and the invalid requests, once.
        assert_eq!(write_txn.approval_sweep(), Ok(5));
        assert_eq!(write_txn.approval_sweep(), Ok(0));
        for expired in [two_types, bad_details, bad_decision, bad_snapshot, legacy] {
            assert_eq!(
                stored_state(&mut write_txn, expired).as_deref(),
                Some("expired")
            );
        }
        assert_eq!(
            stored_state(&mut write_txn, good).as_deref(),
            Some("pending")
        );
        write_txn.commit().expect("failed to commit");
    }

    /// Escalation: All of [A, B] with backup [X]. The quorum stays at two slots after
    /// escalation, the primary approvers stay eligible and their earlier decisions keep
    /// counting, and the backup approver can only fill a slot that is still open.
    #[qs_test]
    async fn test_approval_escalation_keeps_primary_quorum(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        let a = create_person(&mut write_txn, "approver_a");
        let b = create_person(&mut write_txn, "approver_b");
        let x = create_person(&mut write_txn, "backup_x");
        let r = create_person(&mut write_txn, "requester_r");

        let mut policy = policy_request("escalating", ApprovalPattern::All, vec![a, b]);
        policy.backup_approvers = vec![x];
        policy.escalation_timeout_seconds = Some(30);
        write_txn
            .approval_policy_create(&idm_admin, &policy)
            .expect("failed to create approval policy");

        // 1: A approves, escalation, B rejects -> rejected (previously approved).
        let rejected = create_request(&mut write_txn, r, "escalating", ct).unwrap();
        // 2: A approves, escalation, B never answers, X approves in B's place -> approved.
        let substituted = create_request(&mut write_txn, r, "escalating", ct).unwrap();
        // 3: escalation before anyone decided: X alone is not enough.
        let backup_alone = create_request(&mut write_txn, r, "escalating", ct).unwrap();

        decide_as(&mut write_txn, a, rejected, approve(), ct).expect("A approves");
        decide_as(&mut write_txn, a, substituted, approve(), ct).expect("A approves");
        // Backups can not decide before escalation.
        assert_eq!(
            decide_as(&mut write_txn, x, substituted, approve(), ct),
            Err(OperationError::AccessDenied)
        );
        let request = read_request(&mut write_txn, rejected);
        assert_eq!(request.state, ApprovalRequestState::Pending);
        assert_eq!(request.required_decisions, 2);
        write_txn.commit().expect("failed to commit");

        // The sweep escalates each request once, after the escalation timeout.
        let ct_early = ct + Duration::from_secs(10);
        let mut write_txn = server.write(ct_early).await.unwrap();
        assert_eq!(write_txn.approval_sweep(), Ok(0));
        drop(write_txn);

        let ct_escalate = ct + Duration::from_secs(31);
        let mut write_txn = server.write(ct_escalate).await.unwrap();
        assert_eq!(write_txn.approval_sweep(), Ok(3));
        assert_eq!(write_txn.approval_sweep(), Ok(0));
        for request in [rejected, substituted, backup_alone] {
            let request = read_request(&mut write_txn, request);
            assert_eq!(request.escalation_level, 1);
            // The quorum does not change.
            assert_eq!(request.required_decisions, 2);
            assert_eq!(request.state, ApprovalRequestState::Pending);
        }

        decide_as(&mut write_txn, b, rejected, reject(), ct_escalate)
            .expect("primary approvers stay eligible");
        assert_eq!(
            read_request(&mut write_txn, rejected).state,
            ApprovalRequestState::Rejected
        );
        // X can not override the rejection.
        assert_eq!(
            decide_as(&mut write_txn, x, rejected, approve(), ct_escalate),
            Err(OperationError::AP0003ApprovalNotUsable)
        );

        decide_as(&mut write_txn, x, substituted, approve(), ct_escalate)
            .expect("backup approvers may decide after escalation");
        assert_eq!(
            read_request(&mut write_txn, substituted).state,
            ApprovalRequestState::Approved
        );

        decide_as(&mut write_txn, x, backup_alone, approve(), ct_escalate)
            .expect("backup approvers may decide after escalation");
        assert_eq!(
            read_request(&mut write_txn, backup_alone).state,
            ApprovalRequestState::Pending
        );
        decide_as(&mut write_txn, b, backup_alone, approve(), ct_escalate)
            .expect("primary approvers stay eligible");
        assert_eq!(
            read_request(&mut write_txn, backup_alone).state,
            ApprovalRequestState::Approved
        );
        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        let rejected = read_txn.approval_request_get(&idm_admin, rejected).unwrap();
        assert_eq!(rejected.state, ApprovalRequestState::Rejected);
        assert_eq!(rejected.decisions.len(), 2);
    }

    /// A person who is both an approver and a backup approver counts once.
    #[qs_test]
    async fn test_approval_approver_and_backup_counts_once(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        let a = create_person(&mut write_txn, "approver_a");
        let b = create_person(&mut write_txn, "approver_b");
        let r = create_person(&mut write_txn, "requester_r");

        let mut policy = policy_request("overlap", ApprovalPattern::All, vec![a, b]);
        policy.backup_approvers = vec![a];
        policy.escalation_timeout_seconds = Some(30);
        write_txn
            .approval_policy_create(&idm_admin, &policy)
            .expect("failed to create approval policy");
        let request = create_request(&mut write_txn, r, "overlap", ct).unwrap();

        let ct_escalate = ct + Duration::from_secs(31);
        assert_eq!(
            write_txn.approval_request_escalate(request, ct_escalate),
            Ok(true)
        );
        assert_eq!(
            write_txn.approval_request_escalate(request, ct_escalate),
            Ok(false)
        );

        decide_as(&mut write_txn, a, request, approve(), ct_escalate).expect("A approves");
        assert_eq!(
            decide_as(&mut write_txn, a, request, approve(), ct_escalate),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        let state = read_request(&mut write_txn, request);
        assert_eq!(state.state, ApprovalRequestState::Pending);
        assert_eq!(state.required_decisions, 2);
    }

    /// Approvers can be groups: a group is one slot, filled by any one of its members. Two
    /// members of the same group do not fill two slots, and a member of two groups fills one.
    #[qs_test]
    async fn test_approval_group_slots(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        let m1 = create_person(&mut write_txn, "member_one");
        let m2 = create_person(&mut write_txn, "member_two");
        let m3 = create_person(&mut write_txn, "member_three");
        let m4 = create_person(&mut write_txn, "member_both");
        let r = create_person(&mut write_txn, "requester_r");
        let g1 = create_group(&mut write_txn, "approver_group_one", &[m1, m2, m4]);
        let g2 = create_group(&mut write_txn, "approver_group_two", &[m3, m4]);

        write_txn
            .approval_policy_create(
                &idm_admin,
                &policy_request("two_groups", ApprovalPattern::All, vec![g1, g2]),
            )
            .expect("failed to create approval policy");
        write_txn
            .approval_policy_create(
                &idm_admin,
                &policy_request("one_group", ApprovalPattern::All, vec![g1]),
            )
            .expect("failed to create approval policy");

        // Two members of G1 can not complete All of [G1, G2].
        let request = create_request(&mut write_txn, r, "two_groups", ct).unwrap();
        decide_as(&mut write_txn, m1, request, approve(), ct).expect("m1 approves");
        assert_eq!(
            decide_as(&mut write_txn, m2, request, approve(), ct),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        assert_eq!(
            read_request(&mut write_txn, request).state,
            ApprovalRequestState::Pending
        );
        decide_as(&mut write_txn, m3, request, approve(), ct).expect("m3 approves");
        let decided = read_request(&mut write_txn, request);
        assert_eq!(decided.state, ApprovalRequestState::Approved);
        assert_eq!(decided.required_decisions, 2);
        assert_eq!(decided.decisions.len(), 2);

        // A member of both groups fills one slot. A later member of G1 still fills the
        // other one, the earlier decision moving to G2.
        let request = create_request(&mut write_txn, r, "two_groups", ct).unwrap();
        decide_as(&mut write_txn, m4, request, approve(), ct).expect("m4 approves");
        assert_eq!(
            read_request(&mut write_txn, request).state,
            ApprovalRequestState::Pending
        );
        decide_as(&mut write_txn, m1, request, approve(), ct).expect("m1 approves");
        assert_eq!(
            read_request(&mut write_txn, request).state,
            ApprovalRequestState::Approved
        );

        // All of [G] is one slot, filled by one member.
        let request = create_request(&mut write_txn, r, "one_group", ct).unwrap();
        assert_eq!(read_request(&mut write_txn, request).required_decisions, 1);
        decide_as(&mut write_txn, m2, request, approve(), ct).expect("m2 approves");
        assert_eq!(
            read_request(&mut write_txn, request).state,
            ApprovalRequestState::Approved
        );
    }

    /// The requester never fills a slot. A request that can therefore never be approved is,
    /// on a best-effort basis, refused when it is created rather than left pending until it
    /// expires.
    #[qs_test]
    async fn test_approval_request_unreachable_quorum(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        let r = create_person(&mut write_txn, "requester_r");
        let b = create_person(&mut write_txn, "approver_b");
        let x = create_person(&mut write_txn, "backup_x");
        let only_r = create_group(&mut write_txn, "only_requester", &[r]);

        let policies = [
            ("self_only", ApprovalPattern::AnyOne, vec![r], vec![]),
            (
                "group_of_self",
                ApprovalPattern::AnyOne,
                vec![only_r],
                vec![],
            ),
            ("all_with_self", ApprovalPattern::All, vec![r, b], vec![]),
            ("any_with_self", ApprovalPattern::AnyOne, vec![r, b], vec![]),
            (
                "all_with_self_backup",
                ApprovalPattern::All,
                vec![r, b],
                vec![x],
            ),
        ];
        for (name, pattern, approvers, backups) in policies {
            let mut policy = policy_request(name, pattern, approvers);
            policy.escalation_timeout_seconds = (!backups.is_empty()).then_some(30);
            policy.backup_approvers = backups;
            write_txn
                .approval_policy_create(&idm_admin, &policy)
                .expect("failed to create approval policy");
        }

        for unreachable in ["self_only", "group_of_self", "all_with_self"] {
            assert_eq!(
                create_request(&mut write_txn, r, unreachable, ct),
                Err(OperationError::AP0001ApprovalQuorumUnreachable),
                "{unreachable}"
            );
        }
        // B alone can approve.
        create_request(&mut write_txn, r, "any_with_self", ct).expect("reachable");
        // After escalation X can fill the requester's slot.
        let request = create_request(&mut write_txn, r, "all_with_self_backup", ct)
            .expect("reachable through the backup approver");
        // The requester can not decide, even though they are an approver.
        assert_eq!(
            decide_as(&mut write_txn, r, request, approve(), ct),
            Err(OperationError::AccessDenied)
        );
        let ct_escalate = ct + Duration::from_secs(31);
        assert_eq!(
            write_txn.approval_request_escalate(request, ct_escalate),
            Ok(true)
        );
        decide_as(&mut write_txn, b, request, approve(), ct_escalate).expect("B approves");
        decide_as(&mut write_txn, x, request, approve(), ct_escalate).expect("X approves");
        assert_eq!(
            read_request(&mut write_txn, request).state,
            ApprovalRequestState::Approved
        );
    }

    /// Each decision is a separate record, and the state is recomputed from all of them:
    /// decisions that arrive without the state being updated (as through replication from
    /// several replicas) still decide the request, and the sweep writes the recomputed state
    /// back.
    #[qs_test]
    async fn test_approval_state_recomputed_from_decisions(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        let a = create_person(&mut write_txn, "approver_a");
        let b = create_person(&mut write_txn, "approver_b");
        let r = create_person(&mut write_txn, "requester_r");
        write_txn
            .approval_policy_create(
                &idm_admin,
                &policy_request("majority", ApprovalPattern::Majority, vec![a, b]),
            )
            .expect("failed to create approval policy");
        let request = create_request(&mut write_txn, r, "majority", ct).unwrap();

        let decision = |approver: Uuid, action: ApprovalDecisionAction, offset: u64| {
            decision_json(
                approver,
                action,
                OffsetDateTime::UNIX_EPOCH + ct + Duration::from_secs(offset),
                &[approver],
            )
        };
        // A's first decision counts, a later conflicting one from A (made on another
        // replica) does not.
        for (approver, action, offset) in [
            (a, ApprovalDecisionAction::Approve, 1),
            (b, ApprovalDecisionAction::Approve, 2),
            (a, ApprovalDecisionAction::Reject, 3),
        ] {
            add_decision_record(&mut write_txn, request, &decision(approver, action, offset));
        }
        assert_eq!(
            stored_state(&mut write_txn, request).as_deref(),
            Some("pending")
        );
        let read = read_request(&mut write_txn, request);
        assert_eq!(read.state, ApprovalRequestState::Approved);
        assert_eq!(read.decisions.len(), 3);
        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        assert!(read_txn
            .approval_request_list(&idm_admin, Some(ApprovalRequestState::Pending))
            .unwrap()
            .is_empty());
        assert_eq!(
            read_txn
                .approval_request_list(&idm_admin, Some(ApprovalRequestState::Approved))
                .unwrap()
                .len(),
            1
        );
        drop(read_txn);

        let mut write_txn = server.write(ct).await.unwrap();
        assert_eq!(write_txn.approval_sweep(), Ok(1));
        assert_eq!(
            stored_state(&mut write_txn, request).as_deref(),
            Some("approved")
        );
        assert_eq!(write_txn.approval_sweep(), Ok(0));
        write_txn.commit().expect("failed to commit");
    }

    /// The sweep expires overdue requests (once), and the commit can be skipped when it
    /// changed nothing. Expired requests accept no decisions.
    #[qs_test]
    async fn test_approval_sweep_expires(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        let a = create_person(&mut write_txn, "approver_a");
        let mut policy = policy_request("short", ApprovalPattern::AnyOne, vec![a]);
        policy.timeout_seconds = 60;
        write_txn
            .approval_policy_create(&idm_admin, &policy)
            .expect("failed to create approval policy");
        let request = create_request(&mut write_txn, UUID_ANONYMOUS, "short", ct).unwrap();
        write_txn.commit().expect("failed to commit");

        let ct_early = ct + Duration::from_secs(10);
        let mut write_txn = server.write(ct_early).await.unwrap();
        assert_eq!(write_txn.approval_sweep(), Ok(0));
        drop(write_txn);

        let ct_expired = ct + Duration::from_secs(61);
        let mut write_txn = server.write(ct_expired).await.unwrap();
        assert_eq!(
            decide_as(&mut write_txn, a, request, approve(), ct_expired),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        assert_eq!(write_txn.approval_sweep(), Ok(1));
        assert_eq!(write_txn.approval_sweep(), Ok(0));
        assert_eq!(
            read_request(&mut write_txn, request).state,
            ApprovalRequestState::Expired
        );
        write_txn.commit().expect("failed to commit");
    }

    /// The delayed actions still expire and escalate single requests.
    #[idm_test]
    async fn test_approval_request_delayed_actions(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        use crate::idm::delayed::{ApprovalEscalationCheck, ApprovalTimeoutCheck, DelayedAction};

        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let idm_admin = identity(&mut idms_prox_write.qs_write, UUID_IDM_ADMIN);
        let a = create_person(&mut idms_prox_write.qs_write, "approver_a");

        let mut policy = policy_request("timeout_policy", ApprovalPattern::AnyOne, vec![a]);
        policy.timeout_seconds = 60;
        policy.escalation_timeout_seconds = Some(30);
        policy.backup_approvers = vec![UUID_SYSTEM_ADMINS];
        idms_prox_write
            .qs_write
            .approval_policy_create(&idm_admin, &policy)
            .expect("failed to create approval policy");
        let request_uuid = create_request(
            &mut idms_prox_write.qs_write,
            UUID_ANONYMOUS,
            "timeout_policy",
            ct,
        )
        .expect("failed to create approval request");
        idms_prox_write.commit().expect("failed to commit");

        let escalate =
            DelayedAction::ApprovalEscalationCheck(ApprovalEscalationCheck { request_uuid });
        let timeout = DelayedAction::ApprovalTimeoutCheck(ApprovalTimeoutCheck { request_uuid });

        let ct_early = ct + Duration::from_secs(10);
        let mut idms_prox_write = idms.proxy_write(ct_early).await.unwrap();
        idms_prox_write
            .process_delayedaction(&escalate, ct_early)
            .expect("escalation check failed");
        idms_prox_write
            .process_delayedaction(&timeout, ct_early)
            .expect("timeout check failed");
        let request = read_request(&mut idms_prox_write.qs_write, request_uuid);
        assert_eq!(request.escalation_level, 0);
        assert_eq!(request.state, ApprovalRequestState::Pending);
        idms_prox_write.commit().expect("failed to commit");

        let ct_escalate = ct + Duration::from_secs(31);
        let mut idms_prox_write = idms.proxy_write(ct_escalate).await.unwrap();
        idms_prox_write
            .process_delayedaction(&escalate, ct_escalate)
            .expect("escalation check failed");
        assert_eq!(
            read_request(&mut idms_prox_write.qs_write, request_uuid).escalation_level,
            1
        );
        idms_prox_write.commit().expect("failed to commit");

        let ct_expired = ct + Duration::from_secs(61);
        let mut idms_prox_write = idms.proxy_write(ct_expired).await.unwrap();
        idms_prox_write
            .process_delayedaction(&timeout, ct_expired)
            .expect("timeout check failed");
        assert_eq!(
            read_request(&mut idms_prox_write.qs_write, request_uuid).state,
            ApprovalRequestState::Expired
        );
        idms_prox_write.commit().expect("failed to commit");
    }

    /// Requests do not block deleting their policy, target or requester. A pending request
    /// that lost one of them is invalid: it lists as invalid, can not be decided, and the
    /// sweep expires it. A decided request keeps its state, but can no longer be consumed.
    #[qs_test]
    async fn test_approval_request_references_deleted(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        let a = create_person(&mut write_txn, "approver_a");
        let r = create_person(&mut write_txn, "requester_r");
        let r2 = create_person(&mut write_txn, "requester_two");
        let target = create_group(&mut write_txn, "approval_target", &[]);
        let target2 = create_group(&mut write_txn, "approval_target_two", &[]);

        for name in ["deleted_policy", "kept_policy"] {
            write_txn
                .approval_policy_create(
                    &idm_admin,
                    &policy_request(name, ApprovalPattern::AnyOne, vec![a]),
                )
                .expect("failed to create approval policy");
        }
        let requester = identity(&mut write_txn, r);
        let requester2 = identity(&mut write_txn, r2);
        let create = |txn: &mut QueryServerWriteTransaction<'_>,
                      ident: &Identity,
                      policy: &str,
                      target: Uuid| {
            txn.approval_request_create(
                ident,
                policy,
                &ApprovalOperationType::SchemaModify,
                target,
                &BTreeMap::new(),
                ct,
            )
            .expect("failed to create approval request")
        };
        let lost_target = create(&mut write_txn, &requester, "kept_policy", target);
        let lost_requester = create(&mut write_txn, &requester2, "kept_policy", UUID_IDM_ADMINS);
        let lost_policy = create(
            &mut write_txn,
            &requester,
            "deleted_policy",
            UUID_IDM_ADMINS,
        );
        let decided = create(&mut write_txn, &requester, "kept_policy", target2);
        decide_as(&mut write_txn, a, decided, approve(), ct).expect("A approves");
        write_txn.commit().expect("failed to commit");

        // None of these deletes is blocked by the requests.
        let mut write_txn = server.write(ct).await.unwrap();
        write_txn
            .internal_delete_uuid(target)
            .expect("deleting a request target must not be blocked");
        write_txn
            .internal_delete_uuid(target2)
            .expect("deleting a request target must not be blocked");
        write_txn
            .internal_delete_uuid(r2)
            .expect("deleting a requester must not be blocked");
        write_txn
            .approval_policy_delete(&idm_admin, "deleted_policy")
            .expect("deleting a request policy must not be blocked");
        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        let invalid = read_txn
            .approval_request_list(&idm_admin, Some(ApprovalRequestState::Invalid))
            .expect("failed to list approval requests");
        let invalid_uuids: BTreeSet<_> = invalid.iter().map(|r| r.uuid).collect();
        assert_eq!(
            invalid_uuids,
            BTreeSet::from([lost_target, lost_requester, lost_policy])
        );
        let request = read_txn
            .approval_request_get(&idm_admin, lost_policy)
            .unwrap();
        assert_eq!(request.policy_uuid, None);
        assert_eq!(request.policy_name, None);
        // The quorum comes from the snapshot, not the (deleted) policy.
        assert_eq!(request.required_decisions, 1);
        let request = read_txn
            .approval_request_get(&idm_admin, lost_target)
            .unwrap();
        assert_eq!(request.target_uuid, None);
        let request = read_txn
            .approval_request_get(&idm_admin, lost_requester)
            .unwrap();
        assert_eq!(request.requestor_uuid, None);
        // A decided request is a record, it keeps its state.
        let request = read_txn.approval_request_get(&idm_admin, decided).unwrap();
        assert_eq!(request.state, ApprovalRequestState::Approved);
        assert_eq!(request.target_uuid, None);
        drop(read_txn);

        let mut write_txn = server.write(ct).await.unwrap();
        assert_eq!(
            write_txn.approval_request_check_and_consume(
                &requester,
                decided,
                "kept_policy",
                &ApprovalOperationType::SchemaModify,
                target2,
                &BTreeMap::new(),
            ),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        for request in [lost_target, lost_requester] {
            assert_eq!(
                decide_as(&mut write_txn, a, request, approve(), ct),
                Err(OperationError::AP0003ApprovalNotUsable)
            );
        }
        // Without a policy there is nothing to be an approver of.
        assert_eq!(
            decide_as(&mut write_txn, a, lost_policy, approve(), ct),
            Err(OperationError::AccessDenied)
        );
        assert_eq!(
            write_txn.approval_request_decision(
                &Identity::from_internal(),
                lost_policy,
                approve(),
                ct
            ),
            Err(OperationError::NoMatchingEntries)
        );

        assert_eq!(write_txn.approval_sweep(), Ok(3));
        assert_eq!(write_txn.approval_sweep(), Ok(0));
        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        let expired = read_txn
            .approval_request_list(&idm_admin, Some(ApprovalRequestState::Expired))
            .expect("failed to list approval requests");
        assert_eq!(expired.len(), 3);
    }

    /// M1: deleting an approver removes them from the policy (referential integrity), but
    /// not from the snapshot of existing requests, so it never changes their outcome.
    #[qs_test]
    async fn test_approval_snapshot_survives_approver_deletion(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let now = OffsetDateTime::UNIX_EPOCH + ct;
        let mut write_txn = server.write(ct).await.unwrap();
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        let a = create_person(&mut write_txn, "approver_a");
        let b = create_person(&mut write_txn, "approver_b");
        let c = create_person(&mut write_txn, "approver_c");
        let d = create_person(&mut write_txn, "approver_d");
        let r = create_person(&mut write_txn, "requester_r");
        create_policy(
            &mut write_txn,
            "all_abc",
            ApprovalPattern::All,
            vec![a, b, c],
        );
        create_policy(
            &mut write_txn,
            "majority_abcd",
            ApprovalPattern::Majority,
            vec![a, b, c, d],
        );

        // All of [A, B, C]: A and B approve, C rejects.
        let rejected = create_request(&mut write_txn, r, "all_abc", ct).unwrap();
        decide_as(&mut write_txn, a, rejected, approve(), ct).expect("A approves");
        decide_as(&mut write_txn, b, rejected, approve(), ct).expect("B approves");
        decide_as(&mut write_txn, c, rejected, reject(), ct).expect("C rejects");
        assert_eq!(
            read_request(&mut write_txn, rejected).state,
            ApprovalRequestState::Rejected
        );
        // The same decisions, delivered by replication without the state being stored.
        let replicated = create_request(&mut write_txn, r, "all_abc", ct).unwrap();
        for (approver, action) in [
            (a, ApprovalDecisionAction::Approve),
            (b, ApprovalDecisionAction::Approve),
            (c, ApprovalDecisionAction::Reject),
        ] {
            add_decision_record(
                &mut write_txn,
                replicated,
                &decision_json(approver, action, now, &[approver]),
            );
        }

        // Majority of [A, B, C, D] needs three: two approvals keep it pending.
        let majority = create_request(&mut write_txn, r, "majority_abcd", ct).unwrap();
        decide_as(&mut write_txn, a, majority, approve(), ct).expect("A approves");
        decide_as(&mut write_txn, b, majority, approve(), ct).expect("B approves");
        assert_eq!(
            read_request(&mut write_txn, majority).state,
            ApprovalRequestState::Pending
        );
        write_txn.commit().expect("failed to commit");

        let mut write_txn = server.write(ct).await.unwrap();
        write_txn
            .internal_delete_uuid(c)
            .expect("failed to delete C");
        write_txn
            .internal_delete_uuid(d)
            .expect("failed to delete D");
        write_txn.commit().expect("failed to commit");

        let mut write_txn = server.write(ct).await.unwrap();
        // The policies lost C and D ...
        let policy_uuid = find_policy_uuid(&mut write_txn, "all_abc");
        let policy = write_txn.internal_search_uuid(policy_uuid).unwrap();
        assert_eq!(
            policy.get_ava_refer(Attribute::Approver),
            Some(&BTreeSet::from([a, b]))
        );
        // ... but the requests did not: the rejection stands, stored or recomputed.
        for request in [rejected, replicated] {
            let read = read_request(&mut write_txn, request);
            assert_eq!(read.state, ApprovalRequestState::Rejected);
            assert_eq!(read.required_decisions, 3);
            assert_eq!(
                consume_as(&mut write_txn, r, "all_abc", request),
                Err(OperationError::AP0003ApprovalNotUsable)
            );
        }
        // ... and the majority still needs three of the four.
        let read = read_request(&mut write_txn, majority);
        assert_eq!(read.state, ApprovalRequestState::Pending);
        assert_eq!(read.required_decisions, 3);
        assert_eq!(
            consume_as(&mut write_txn, r, "majority_abcd", majority),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        assert_eq!(write_txn.approval_sweep(), Ok(1));
        assert_eq!(
            stored_state(&mut write_txn, replicated).as_deref(),
            Some("rejected")
        );
        assert_eq!(
            stored_state(&mut write_txn, majority).as_deref(),
            Some("pending")
        );

        // A new request is decided against the policy as it is now.
        let new_request = create_request(&mut write_txn, r, "majority_abcd", ct).unwrap();
        assert_eq!(
            read_request(&mut write_txn, new_request).required_decisions,
            2
        );
        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        let read = read_txn.approval_request_get(&idm_admin, majority).unwrap();
        assert_eq!(read.state, ApprovalRequestState::Pending);
        let read = read_txn.approval_request_get(&idm_admin, rejected).unwrap();
        assert_eq!(read.state, ApprovalRequestState::Rejected);
    }

    /// A quorum snapshot retains its approvers even after refint removes them from the
    /// current policy; both primary and backup slots must remain delegation exclusions.
    #[qs_test]
    async fn test_delegation_snapshot_principals_survive_approver_removal(
        server: &QueryServer,
    ) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let primary = create_person(&mut txn, "snapshot_primary");
        let backup = create_person(&mut txn, "snapshot_backup");
        let requester = create_person(&mut txn, "snapshot_requester");
        let mut policy = policy_request(
            "delegation_snapshot_exclusion",
            ApprovalPattern::AnyOne,
            vec![primary],
        );
        policy.backup_approvers = vec![backup];
        policy.escalation_timeout_seconds = Some(60);
        let admin = identity(&mut txn, UUID_IDM_ADMIN);
        txn.approval_policy_create(&admin, &policy).expect("create policy");
        let _request = create_request(&mut txn, requester, &policy.name, ct)
            .expect("create request");
        let excluded = super::delegation_snapshot_principals(&mut txn)
            .expect("read snapshot exclusions");
        assert!(excluded.contains(&primary));
        assert!(excluded.contains(&backup));
        txn.commit().expect("commit");

        let mut txn = server.write(ct).await.unwrap();
        txn.internal_delete_uuid(primary).expect("delete primary");
        let policy_uuid = find_policy_uuid(&mut txn, &policy.name);
        let current_policy = txn.internal_search_uuid(policy_uuid).expect("policy");
        assert!(!current_policy.get_ava_refer(Attribute::Approver)
            .is_some_and(|approvers| approvers.contains(&primary)));
        assert!(super::delegation_snapshot_principals(&mut txn)
            .expect("snapshot still protects primary").contains(&primary));
        txn.commit().expect("commit");

        let mut txn = server.write(ct).await.unwrap();
        txn.internal_revive_uuid(primary).expect("revive primary");
        assert!(super::delegation_snapshot_principals(&mut txn)
            .expect("snapshot remains protected after revival").contains(&primary));
        txn.commit().expect("commit");
    }

    /// S1: the order of decisions, and so which decision of an approver counts, does not
    /// depend on the order the backend returns the records in: decision times have
    /// sub-second precision, and records are the last tie-break.
    #[qs_test]
    async fn test_approval_decision_order_is_deterministic(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let second = OffsetDateTime::UNIX_EPOCH + Duration::from_secs(ct.as_secs() + 5);
        let mut write_txn = server.write(ct).await.unwrap();
        let a = create_person(&mut write_txn, "approver_a");
        let b = create_person(&mut write_txn, "approver_b");
        let r = create_person(&mut write_txn, "requester_r");
        create_policy(&mut write_txn, "all_ab", ApprovalPattern::All, vec![a, b]);

        // Same second: A's reject 100ns in comes first, although written second.
        let request = create_request(&mut write_txn, r, "all_ab", ct).unwrap();
        let approve_at = second + time::Duration::nanoseconds(200);
        let reject_at = second + time::Duration::nanoseconds(100);
        add_decision_record(
            &mut write_txn,
            request,
            &decision_json(a, ApprovalDecisionAction::Approve, approve_at, &[a]),
        );
        add_decision_record(
            &mut write_txn,
            request,
            &decision_json(a, ApprovalDecisionAction::Reject, reject_at, &[a]),
        );
        let read = read_request(&mut write_txn, request);
        assert_eq!(read.state, ApprovalRequestState::Rejected);
        assert_eq!(read.decisions[0].decision_time, reject_at);

        // A record without the sub-second part (as written before it was stored) is at
        // the start of its second.
        let request = create_request(&mut write_txn, r, "all_ab", ct).unwrap();
        add_decision_record(
            &mut write_txn,
            request,
            &decision_json(a, ApprovalDecisionAction::Reject, reject_at, &[a]),
        );
        let legacy = format!(
            r#"{{"approver_uuid":"{a}","approver_spn":"","decision_time":{},"action":"approve","comment":null,"slots":["{a}"]}}"#,
            second.unix_timestamp()
        );
        add_decision_record(&mut write_txn, request, &legacy);
        decide_as(&mut write_txn, b, request, approve(), ct).expect("B approves");
        assert_eq!(
            read_request(&mut write_txn, request).state,
            ApprovalRequestState::Approved
        );

        // Exactly the same time: the record uuid decides, whichever is written first.
        for (first, second_action, expected) in [
            (
                ApprovalDecisionAction::Reject,
                ApprovalDecisionAction::Approve,
                ApprovalRequestState::Rejected,
            ),
            (
                ApprovalDecisionAction::Approve,
                ApprovalDecisionAction::Reject,
                ApprovalRequestState::Approved,
            ),
        ] {
            let request = create_request(&mut write_txn, r, "all_ab", ct).unwrap();
            let (low, high) = {
                let (one, two) = (Uuid::new_v4(), Uuid::new_v4());
                (one.min(two), one.max(two))
            };
            add_decision_record_uuid(
                &mut write_txn,
                high,
                request,
                &decision_json(a, second_action, second, &[a]),
            );
            add_decision_record_uuid(
                &mut write_txn,
                low,
                request,
                &decision_json(a, first, second, &[a]),
            );
            add_decision_record(
                &mut write_txn,
                request,
                &decision_json(b, ApprovalDecisionAction::Approve, second, &[b]),
            );
            assert_eq!(read_request(&mut write_txn, request).state, expected);
        }
    }

    /// S2: the gate. An approval authorises exactly the requested operation, once, and only
    /// for the requester. It is computed from the decisions rather than the stored state.
    #[qs_test]
    async fn test_approval_request_check_and_consume(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let a = create_person(&mut write_txn, "approver_a");
        let r = create_person(&mut write_txn, "requester_r");
        let o = create_person(&mut write_txn, "other_o");
        create_policy(&mut write_txn, "any_a", ApprovalPattern::AnyOne, vec![a]);
        let requester = identity(&mut write_txn, r);
        let details = BTreeMap::from([("attribute".to_string(), "mail".to_string())]);

        let request = write_txn
            .approval_request_create(
                &requester,
                "any_a",
                &ApprovalOperationType::SchemaModify,
                UUID_IDM_ADMINS,
                &details,
                ct,
            )
            .expect("failed to create approval request");
        let consume = |txn: &mut QueryServerWriteTransaction<'_>,
                       ident: &Identity,
                       operation_type: ApprovalOperationType,
                       target: Uuid,
                       details: &BTreeMap<String, String>| {
            txn.approval_request_check_and_consume(
                ident,
                request,
                "any_a",
                &operation_type,
                target,
                details,
            )
        };

        // Not approved yet.
        assert_eq!(
            consume(
                &mut write_txn,
                &requester,
                ApprovalOperationType::SchemaModify,
                UUID_IDM_ADMINS,
                &details
            ),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        decide_as(&mut write_txn, a, request, approve(), ct).expect("A approves");

        // Only the requester may use it.
        let other = identity(&mut write_txn, o);
        for ident in [other, Identity::migration()] {
            assert_eq!(
                consume(
                    &mut write_txn,
                    &ident,
                    ApprovalOperationType::SchemaModify,
                    UUID_IDM_ADMINS,
                    &details
                ),
                Err(OperationError::AccessDenied)
            );
        }
        // Only for exactly this operation.
        let other_details = BTreeMap::from([("attribute".to_string(), "uid".to_string())]);
        for (operation_type, target, details) in [
            (
                ApprovalOperationType::PrivilegeGrant,
                UUID_IDM_ADMINS,
                &details,
            ),
            (ApprovalOperationType::SchemaModify, UUID_ADMIN, &details),
            (
                ApprovalOperationType::SchemaModify,
                UUID_IDM_ADMINS,
                &other_details,
            ),
            (
                ApprovalOperationType::SchemaModify,
                UUID_IDM_ADMINS,
                &BTreeMap::new(),
            ),
        ] {
            assert_eq!(
                consume(&mut write_txn, &requester, operation_type, target, details),
                Err(OperationError::AP0003ApprovalNotUsable)
            );
        }
        assert_eq!(
            read_request(&mut write_txn, request).state,
            ApprovalRequestState::Approved
        );

        // Once.
        consume(
            &mut write_txn,
            &requester,
            ApprovalOperationType::SchemaModify,
            UUID_IDM_ADMINS,
            &details,
        )
        .expect("an approved request must be consumable");
        assert_eq!(
            stored_state(&mut write_txn, request).as_deref(),
            Some("consumed")
        );
        assert_eq!(
            consume(
                &mut write_txn,
                &requester,
                ApprovalOperationType::SchemaModify,
                UUID_IDM_ADMINS,
                &details
            ),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        // A consumed request is final.
        assert_eq!(
            write_txn.approval_request_cancel(&requester, request),
            Err(OperationError::AP0003ApprovalNotUsable)
        );

        // The approval is computed from the decisions: a stored pending state that lags
        // behind a replicated approval does not block it ...
        let replicated = create_request(&mut write_txn, r, "any_a", ct).unwrap();
        add_decision_record(
            &mut write_txn,
            replicated,
            &decision_json(
                a,
                ApprovalDecisionAction::Approve,
                OffsetDateTime::UNIX_EPOCH + ct,
                &[a],
            ),
        );
        assert_eq!(
            stored_state(&mut write_txn, replicated).as_deref(),
            Some("pending")
        );
        consume_as(&mut write_txn, r, "any_a", replicated).expect("approved by its decisions");
        // ... and a stored approval that the decisions do not support is refused.
        let forged = create_request(&mut write_txn, r, "any_a", ct).unwrap();
        write_txn
            .internal_modify_uuid(
                forged,
                &ModifyList::new_purge_and_set(
                    Attribute::ApprovalState,
                    Value::new_iutf8(ApprovalRequestState::Approved.as_str()),
                ),
            )
            .expect("failed to set the state");
        assert_eq!(
            consume_as(&mut write_txn, r, "any_a", forged),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        let idm_admin = Identity::from_impersonate_entry_readwrite(
            read_txn.internal_search_uuid(UUID_IDM_ADMIN).unwrap(),
        );
        assert_eq!(
            read_txn
                .approval_request_get(&idm_admin, request)
                .unwrap()
                .state,
            ApprovalRequestState::Consumed
        );
    }

    /// The gate binds the policy the operation requires: an approval under another policy
    /// covering the same operation type (say, a laxer one) is refused, and stays unused.
    #[qs_test]
    async fn test_approval_consume_requires_the_policy(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let a = create_person(&mut write_txn, "approver_a");
        let b = create_person(&mut write_txn, "approver_b");
        let r = create_person(&mut write_txn, "requester_r");
        create_policy(&mut write_txn, "strict", ApprovalPattern::All, vec![a, b]);
        create_policy(&mut write_txn, "lax", ApprovalPattern::AnyOne, vec![a]);

        let lax = create_request(&mut write_txn, r, "lax", ct).unwrap();
        decide_as(&mut write_txn, a, lax, approve(), ct).expect("A approves");
        assert_eq!(
            read_request(&mut write_txn, lax).state,
            ApprovalRequestState::Approved
        );

        // The operation requires the strict policy (or a policy that does not exist).
        for policy in ["strict", "no_such_policy"] {
            assert_eq!(
                consume_as(&mut write_txn, r, policy, lax),
                Err(OperationError::AP0003ApprovalNotUsable),
                "{policy}"
            );
        }
        assert_eq!(
            stored_state(&mut write_txn, lax).as_deref(),
            Some("approved")
        );
        // Under its own policy it is used, once.
        consume_as(&mut write_txn, r, "lax", lax).expect("approved under lax");
        assert_eq!(
            consume_as(&mut write_txn, r, "lax", lax),
            Err(OperationError::AP0003ApprovalNotUsable)
        );

        // A request under the strict policy is used for the strict policy.
        let strict = create_request(&mut write_txn, r, "strict", ct).unwrap();
        decide_as(&mut write_txn, a, strict, approve(), ct).expect("A approves");
        decide_as(&mut write_txn, b, strict, approve(), ct).expect("B approves");
        assert_eq!(
            consume_as(&mut write_txn, r, "lax", strict),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        consume_as(&mut write_txn, r, "strict", strict).expect("approved under strict");
        write_txn.commit().expect("failed to commit");
    }

    /// The gate checks again, at use, that the request has not expired and that its policy
    /// is still enabled and still covers the operation type.
    #[qs_test]
    async fn test_approval_consume_rechecks_expiry_and_policy(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        let a = create_person(&mut write_txn, "approver_a");
        let r = create_person(&mut write_txn, "requester_r");
        create_policy(&mut write_txn, "any_a", ApprovalPattern::AnyOne, vec![a]);
        let policy_uuid = find_policy_uuid(&mut write_txn, "any_a");

        let mut approved = || {
            let request = create_request(&mut write_txn, r, "any_a", ct).unwrap();
            decide_as(&mut write_txn, a, request, approve(), ct).expect("A approves");
            request
        };
        let before_expiry = approved();
        let at_expiry = approved();
        let after_expiry = approved();
        let disabled = approved();
        let not_covered = approved();
        write_txn.commit().expect("failed to commit");

        // The policy timeout is an hour: an approval is used before the request expires.
        let timeout = Duration::from_secs(3600);
        let mut write_txn = server.write(ct + timeout).await.unwrap();
        assert_eq!(
            consume_as(&mut write_txn, r, "any_a", at_expiry),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        drop(write_txn);
        let mut write_txn = server
            .write(ct + timeout + Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(
            consume_as(&mut write_txn, r, "any_a", after_expiry),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        drop(write_txn);

        let mut write_txn = server
            .write(ct + timeout - Duration::from_secs(1))
            .await
            .unwrap();
        consume_as(&mut write_txn, r, "any_a", before_expiry).expect("not expired yet");

        // A policy that no longer covers the operation type.
        write_txn
            .internal_modify_uuid(
                policy_uuid,
                &ModifyList::new_purge_and_set(
                    Attribute::ApprovalOperationType,
                    Value::new_iutf8n(ApprovalOperationType::PrivilegeGrant.as_str()),
                ),
            )
            .expect("failed to change the operation types");
        assert_eq!(
            consume_as(&mut write_txn, r, "any_a", not_covered),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        write_txn
            .internal_modify_uuid(
                policy_uuid,
                &ModifyList::new_purge_and_set(
                    Attribute::ApprovalOperationType,
                    Value::new_iutf8n(ApprovalOperationType::SchemaModify.as_str()),
                ),
            )
            .expect("failed to change the operation types");

        // Kubidm: disabling a policy cancels its open requests, so its approvals can not
        // be used, also once it is enabled again.
        for request in [at_expiry, after_expiry, not_covered] {
            assert_eq!(
                stored_state(&mut write_txn, request).as_deref(),
                Some("approved")
            );
        }
        write_txn
            .approval_policy_enable(&idm_admin, "any_a", false)
            .expect("disable");
        assert_eq!(
            consume_as(&mut write_txn, r, "any_a", disabled),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        write_txn
            .approval_policy_enable(&idm_admin, "any_a", true)
            .expect("enable");
        assert_eq!(
            consume_as(&mut write_txn, r, "any_a", disabled),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        let deleted = create_request(&mut write_txn, r, "any_a", ct).expect("create");
        decide_as(&mut write_txn, a, deleted, approve(), ct).expect("A approves");

        // A deleted policy.
        write_txn
            .approval_policy_delete(&idm_admin, "any_a")
            .expect("delete");
        assert_eq!(
            consume_as(&mut write_txn, r, "any_a", deleted),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        write_txn.commit().expect("failed to commit");

        // Every refused approval is left unused.
        let mut write_txn = server
            .write(ct + timeout - Duration::from_secs(1))
            .await
            .unwrap();
        for request in [at_expiry, after_expiry, disabled, not_covered] {
            assert_eq!(
                stored_state(&mut write_txn, request).as_deref(),
                Some("cancelled")
            );
        }
        assert_eq!(
            stored_state(&mut write_txn, deleted).as_deref(),
            Some("approved")
        );
        assert_eq!(
            stored_state(&mut write_txn, before_expiry).as_deref(),
            Some("consumed")
        );
    }

    /// S3: only interactive persons decide: not service accounts, API tokens, anonymous,
    /// read-only sessions, disabled accounts, or accounts managed by the requester.
    #[idm_test]
    async fn test_approval_decider_must_be_interactive_person(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let txn = &mut idms_prox_write.qs_write;
        let sa = create_service_account(txn, "approver_service_account");
        let p = create_person(txn, "approver_p");
        let r = create_person(txn, "requester_r");
        let managed = create_person(txn, "managed_by_requester");
        let group_managed = create_person(txn, "managed_by_requester_group");
        let expired = create_person(txn, "expired_approver");
        let requester_group = create_group(txn, "requester_group", &[r]);
        txn.internal_modify_uuid(
            managed,
            &ModifyList::new_purge_and_set(Attribute::EntryManagedBy, Value::Refer(r)),
        )
        .expect("failed to set entry managed by");
        txn.internal_modify_uuid(
            group_managed,
            &ModifyList::new_purge_and_set(
                Attribute::EntryManagedBy,
                Value::Refer(requester_group),
            ),
        )
        .expect("failed to set entry managed by");
        create_policy(
            txn,
            "any_of_many",
            ApprovalPattern::AnyOne,
            vec![sa, p, managed, group_managed, expired, UUID_ANONYMOUS],
        );
        let request = create_request(txn, r, "any_of_many", ct).unwrap();
        set_account_expire(
            txn,
            expired,
            Some(OffsetDateTime::UNIX_EPOCH + ct - Duration::from_secs(60)),
        );
        idms_prox_write.commit().expect("failed to commit");

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let mut gte = GenerateApiTokenEvent::new_internal(sa, "approval", None);
        gte.read_write = true;
        let api_token = idms_prox_write
            .service_account_generate_api_token(&gte, ct)
            .expect("failed to generate api token");
        let api_ident = idms_prox_write
            .validate_client_auth_info_to_ident(api_token.into(), ct)
            .expect("failed to validate api token");
        assert_eq!(api_ident.get_uuid(), sa);
        assert_eq!(api_ident.access_scope(), AccessScope::ReadWrite);

        let txn = &mut idms_prox_write.qs_write;
        assert_eq!(
            txn.approval_request_decision(&api_ident, request, approve(), ct),
            Err(OperationError::AccessDenied)
        );
        for (name, denied) in [
            ("service account", sa),
            ("anonymous", UUID_ANONYMOUS),
            ("managed by the requester", managed),
            ("managed by the requester's group", group_managed),
            ("expired", expired),
        ] {
            assert_eq!(
                decide_as(txn, denied, request, approve(), ct),
                Err(OperationError::AccessDenied),
                "{name}"
            );
        }
        let p_ro = Identity::from_impersonate_entry_readonly(txn.internal_search_uuid(p).unwrap());
        assert_eq!(
            txn.approval_request_decision(&p_ro, request, approve(), ct),
            Err(OperationError::AccessDenied)
        );
        assert!(read_request(txn, request).decisions.is_empty());

        decide_as(txn, p, request, approve(), ct).expect("a person may decide");
        assert_eq!(
            read_request(txn, request).state,
            ApprovalRequestState::Approved
        );
        idms_prox_write.commit().expect("failed to commit");
    }

    /// Service accounts and disabled persons are not counted as possible approvers when a
    /// request is created.
    #[qs_test]
    async fn test_approval_reachable_counts_enabled_persons(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let sa = create_service_account(&mut write_txn, "service_approver");
        let expired = create_person(&mut write_txn, "expired_approver");
        let r = create_person(&mut write_txn, "requester_r");
        set_account_expire(
            &mut write_txn,
            expired,
            Some(OffsetDateTime::UNIX_EPOCH + ct - Duration::from_secs(60)),
        );
        let group = create_group(&mut write_txn, "inactive_group", &[sa, expired]);
        for (name, approvers) in [
            ("service_only", vec![sa]),
            ("expired_only", vec![expired]),
            ("anonymous_only", vec![UUID_ANONYMOUS]),
            ("group_without_persons", vec![group]),
        ] {
            create_policy(&mut write_txn, name, ApprovalPattern::AnyOne, approvers);
            assert_eq!(
                create_request(&mut write_txn, r, name, ct),
                Err(OperationError::AP0001ApprovalQuorumUnreachable),
                "{name}"
            );
        }
    }

    /// S4: while a request is pending, approvals by approvers who have since been deleted
    /// or disabled do not count, rejections do.
    #[qs_test]
    async fn test_approval_inactive_approvers(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let past = OffsetDateTime::UNIX_EPOCH + ct - Duration::from_secs(60);
        let mut write_txn = server.write(ct).await.unwrap();
        let a = create_person(&mut write_txn, "approver_a");
        let b = create_person(&mut write_txn, "approver_b");
        let c = create_person(&mut write_txn, "approver_c");
        let d = create_person(&mut write_txn, "approver_d");
        let e = create_person(&mut write_txn, "approver_e");
        let f = create_person(&mut write_txn, "approver_f");
        let g = create_person(&mut write_txn, "approver_g");
        let r = create_person(&mut write_txn, "requester_r");
        create_policy(
            &mut write_txn,
            "majority_abc",
            ApprovalPattern::Majority,
            vec![a, b, c],
        );
        create_policy(
            &mut write_txn,
            "majority_def",
            ApprovalPattern::Majority,
            vec![d, e, f],
        );
        create_policy(&mut write_txn, "any_g", ApprovalPattern::AnyOne, vec![g]);

        let disabled_approval = create_request(&mut write_txn, r, "majority_abc", ct).unwrap();
        let disabled_rejection = create_request(&mut write_txn, r, "majority_abc", ct).unwrap();
        let deleted_approval = create_request(&mut write_txn, r, "majority_def", ct).unwrap();
        let approved = create_request(&mut write_txn, r, "any_g", ct).unwrap();
        decide_as(&mut write_txn, a, disabled_approval, approve(), ct).expect("A approves");
        decide_as(&mut write_txn, c, disabled_rejection, reject(), ct).expect("C rejects");
        decide_as(&mut write_txn, d, deleted_approval, approve(), ct).expect("D approves");
        decide_as(&mut write_txn, g, approved, approve(), ct).expect("G approves");
        write_txn.commit().expect("failed to commit");

        let mut write_txn = server.write(ct).await.unwrap();
        set_account_expire(&mut write_txn, a, Some(past));
        set_account_expire(&mut write_txn, c, Some(past));
        set_account_expire(&mut write_txn, g, Some(past));
        write_txn
            .internal_delete_uuid(d)
            .expect("failed to delete D");
        write_txn.commit().expect("failed to commit");

        let mut write_txn = server.write(ct).await.unwrap();
        // A's approval no longer counts, B's alone is not a majority.
        decide_as(&mut write_txn, b, disabled_approval, approve(), ct).expect("B approves");
        assert_eq!(
            read_request(&mut write_txn, disabled_approval).state,
            ApprovalRequestState::Pending
        );
        // C's rejection still counts: with B's, a majority can no longer be reached.
        decide_as(&mut write_txn, b, disabled_rejection, reject(), ct).expect("B rejects");
        assert_eq!(
            read_request(&mut write_txn, disabled_rejection).state,
            ApprovalRequestState::Rejected
        );
        // Deleted D's approval no longer counts either.
        decide_as(&mut write_txn, e, deleted_approval, approve(), ct).expect("E approves");
        assert_eq!(
            read_request(&mut write_txn, deleted_approval).state,
            ApprovalRequestState::Pending
        );
        decide_as(&mut write_txn, f, deleted_approval, approve(), ct).expect("F approves");
        assert_eq!(
            read_request(&mut write_txn, deleted_approval).state,
            ApprovalRequestState::Approved
        );
        // A disabled approver can not decide.
        assert_eq!(
            decide_as(&mut write_txn, c, disabled_approval, approve(), ct),
            Err(OperationError::AccessDenied)
        );
        // A stored approval stays approved, but can no longer be used.
        assert_eq!(
            read_request(&mut write_txn, approved).state,
            ApprovalRequestState::Approved
        );
        assert_eq!(
            consume_as(&mut write_txn, r, "any_g", approved),
            Err(OperationError::AP0003ApprovalNotUsable)
        );

        // Enabled again, A's approval counts again.
        set_account_expire(&mut write_txn, a, None);
        assert_eq!(
            read_request(&mut write_txn, disabled_approval).state,
            ApprovalRequestState::Approved
        );
        write_txn.commit().expect("failed to commit");
    }

    /// S5: decision records and requests are only written by the approval operations (as
    /// the system), not by administrators nor by other internal identities, and not even
    /// by someone an access control profile allows to.
    #[qs_test]
    async fn test_approval_entries_protected(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let a = create_person(&mut write_txn, "approver_a");
        let b = create_person(&mut write_txn, "approver_b");
        let r = create_person(&mut write_txn, "requester_r");
        let forger = create_person(&mut write_txn, "forger");
        let forgers = create_group(&mut write_txn, "approval_forgers", &[forger]);
        create_policy(&mut write_txn, "all_ab", ApprovalPattern::All, vec![a, b]);
        let request = create_request(&mut write_txn, r, "all_ab", ct).unwrap();
        decide_as(&mut write_txn, a, request, approve(), ct).expect("A approves");

        // An access control profile allowing the forgers everything on approval entries.
        let mut acp = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlProfile.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlTargetScope.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlReceiverGroup.to_value()
            ),
            (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
            (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
            (Attribute::Class, EntryClass::AccessControlModify.to_value()),
            (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
            (Attribute::Name, Value::new_iname("acp_approval_forgers")),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4())),
            (Attribute::AcpReceiverGroup, Value::ReferN(forgers)),
            (
                Attribute::AcpTargetScope,
                Value::new_json_filter_s(
                    r#"{"or":[{"eq":["class","approval_decision_record"]},{"eq":["class","approval_request"]}]}"#
                )
                .expect("filter")
            ),
            (Attribute::AcpCreateClass, EntryClass::Object.to_value()),
            (
                Attribute::AcpCreateClass,
                EntryClass::ApprovalDecisionRecord.to_value()
            )
        );
        for attr in [
            Attribute::Class,
            Attribute::Uuid,
            Attribute::ApprovalRecordRequest,
            Attribute::ApprovalDecision,
            Attribute::ApprovalState,
        ] {
            acp.add_ava(Attribute::AcpSearchAttr, Value::new_iutf8n(attr.as_str()));
            acp.add_ava(
                Attribute::AcpModifyPresentAttr,
                Value::new_iutf8n(attr.as_str()),
            );
            acp.add_ava(
                Attribute::AcpModifyRemovedAttr,
                Value::new_iutf8n(attr.as_str()),
            );
            acp.add_ava(Attribute::AcpCreateAttr, Value::new_iutf8n(attr.as_str()));
        }
        write_txn
            .internal_create(vec![acp])
            .expect("failed to create access control profile");
        write_txn.commit().expect("failed to commit");

        let mut write_txn = server.write(ct).await.unwrap();
        let record_filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::ApprovalDecisionRecord.into()),
            f_eq(
                Attribute::ApprovalRecordRequest,
                PartialValue::Refer(request)
            )
        ]));
        let request_filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(request)));
        let records = write_txn.internal_search(record_filter.clone()).unwrap();
        assert_eq!(records.len(), 1);
        let record_json = records[0]
            .get_ava_single_utf8(Attribute::ApprovalDecision)
            .unwrap()
            .to_string();
        let forged = decision_json(
            b,
            ApprovalDecisionAction::Approve,
            OffsetDateTime::UNIX_EPOCH + ct,
            &[b],
        );
        let new_record = || {
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::ApprovalDecisionRecord.to_value()
                ),
                (Attribute::Uuid, Value::Uuid(Uuid::new_v4())),
                (Attribute::ApprovalRecordRequest, Value::Refer(request)),
                (Attribute::ApprovalDecision, Value::new_utf8s(&forged))
            )
        };
        let attempts = |txn: &mut QueryServerWriteTransaction<'_>,
                        ident: &Identity|
         -> Vec<(&'static str, Result<(), OperationError>)> {
            let ce = CreateEvent::new_impersonate_identity(ident.clone(), vec![new_record()]);
            let create = txn.create(&ce).map(|_| ());
            let modify_record = txn.impersonate_modify(
                &record_filter,
                &record_filter,
                &ModifyList::new_purge_and_set(
                    Attribute::ApprovalDecision,
                    Value::new_utf8s(&forged),
                ),
                ident,
            );
            let modify_request = txn.impersonate_modify(
                &request_filter,
                &request_filter,
                &ModifyList::new_purge_and_set(
                    Attribute::ApprovalState,
                    Value::new_iutf8("approved"),
                ),
                ident,
            );
            let de = DeleteEvent::new_impersonate_identity(ident.clone(), record_filter.clone());
            let delete_record = txn.delete(&de);
            let de = DeleteEvent::new_impersonate_identity(ident.clone(), request_filter.clone());
            let delete_request = txn.delete(&de);
            vec![
                ("create record", create),
                ("modify record", modify_record),
                ("modify request", modify_request),
                ("delete record", delete_record),
                ("delete request", delete_request),
            ]
        };

        // Access controls refuse administrators and the migration role ...
        let admin = identity(&mut write_txn, UUID_ADMIN);
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        for ident in [admin, idm_admin, Identity::migration()] {
            for (what, result) in attempts(&mut write_txn, &ident) {
                // An internal identity that finds nothing it may change succeeds silently.
                if !(ident.is_internal() && what.starts_with("modify")) {
                    assert!(result.is_err(), "{what} as {ident}");
                }
            }
        }

        // ... and where they allow it, the plugin refuses.
        let forger = identity(&mut write_txn, forger);
        assert_eq!(
            write_txn
                .impersonate_search(record_filter.clone(), record_filter.clone(), &forger)
                .map(|entries| entries.len()),
            Ok(1)
        );
        for (what, result) in attempts(&mut write_txn, &forger) {
            assert_eq!(result, Err(OperationError::SystemProtectedObject), "{what}");
        }

        let records = write_txn.internal_search(record_filter).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].get_ava_single_utf8(Attribute::ApprovalDecision),
            Some(record_json.as_str())
        );
        assert_eq!(
            read_request(&mut write_txn, request).state,
            ApprovalRequestState::Pending
        );
        assert_eq!(
            stored_state(&mut write_txn, request).as_deref(),
            Some("pending")
        );
    }

    /// Approval policies are only written by the policy operations (as the system, after
    /// checking `idm_approval_admins`), never directly, even where an access control profile
    /// allows it.
    #[qs_test]
    async fn test_approval_policies_protected(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let a = create_person(&mut write_txn, "approver_a");
        let forger = create_person(&mut write_txn, "forger");
        let forgers = create_group(&mut write_txn, "approval_forgers", &[forger]);
        create_policy(&mut write_txn, "any_a", ApprovalPattern::AnyOne, vec![a]);
        let policy_uuid = find_policy_uuid(&mut write_txn, "any_a");

        let mut acp = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlProfile.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlTargetScope.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlReceiverGroup.to_value()
            ),
            (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
            (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
            (Attribute::Class, EntryClass::AccessControlModify.to_value()),
            (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
            (
                Attribute::Name,
                Value::new_iname("acp_approval_policy_forgers")
            ),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4())),
            (Attribute::AcpReceiverGroup, Value::ReferN(forgers)),
            (
                Attribute::AcpTargetScope,
                Value::new_json_filter_s(r#"{"eq":["class","approval_policy"]}"#).expect("filter")
            ),
            (Attribute::AcpCreateClass, EntryClass::Object.to_value()),
            (
                Attribute::AcpCreateClass,
                EntryClass::ApprovalPolicy.to_value()
            )
        );
        for attr in [
            Attribute::Class,
            Attribute::Uuid,
            Attribute::ApprovalPolicyName,
            Attribute::ApprovalPatternAttr,
            Attribute::ApprovalTimeout,
            Attribute::ApprovalOperationType,
            Attribute::ApprovalPolicyEnabled,
            Attribute::Approver,
        ] {
            acp.add_ava(Attribute::AcpSearchAttr, Value::new_iutf8n(attr.as_str()));
            acp.add_ava(
                Attribute::AcpModifyPresentAttr,
                Value::new_iutf8n(attr.as_str()),
            );
            acp.add_ava(
                Attribute::AcpModifyRemovedAttr,
                Value::new_iutf8n(attr.as_str()),
            );
            acp.add_ava(Attribute::AcpCreateAttr, Value::new_iutf8n(attr.as_str()));
        }
        write_txn
            .internal_create(vec![acp])
            .expect("failed to create access control profile");
        write_txn.commit().expect("failed to commit");

        let mut write_txn = server.write(ct).await.unwrap();
        let forger = identity(&mut write_txn, forger);
        let policy_filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(policy_uuid)));
        assert_eq!(
            write_txn
                .impersonate_search(policy_filter.clone(), policy_filter.clone(), &forger)
                .map(|entries| entries.len()),
            Ok(1)
        );

        let new_policy = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::ApprovalPolicy.to_value()),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4())),
            (Attribute::ApprovalPolicyName, Value::new_iname("forged")),
            (Attribute::ApprovalPatternAttr, Value::new_iutf8("any_one")),
            (Attribute::ApprovalTimeout, Value::Uint32(3600)),
            (
                Attribute::ApprovalOperationType,
                Value::new_iutf8n(ApprovalOperationType::SchemaModify.as_str())
            ),
            (Attribute::Approver, Value::ReferN(forger.get_uuid()))
        );
        let ce = CreateEvent::new_impersonate_identity(forger.clone(), vec![new_policy]);
        assert_eq!(
            write_txn.create(&ce),
            Err(OperationError::SystemProtectedObject)
        );
        assert_eq!(
            write_txn.impersonate_modify(
                &policy_filter,
                &policy_filter,
                &ModifyList::new_purge_and_set(
                    Attribute::Approver,
                    Value::ReferN(forger.get_uuid())
                ),
                &forger,
            ),
            Err(OperationError::SystemProtectedObject)
        );
        let de = DeleteEvent::new_impersonate_identity(forger.clone(), policy_filter.clone());
        assert_eq!(
            write_txn.delete(&de),
            Err(OperationError::SystemProtectedObject)
        );

        // The policy operations are unaffected.
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        write_txn
            .approval_policy_enable(&idm_admin, "any_a", false)
            .expect("disable");
        write_txn
            .approval_policy_enable(&idm_admin, "any_a", true)
            .expect("enable");
        create_policy(
            &mut write_txn,
            "any_a_two",
            ApprovalPattern::AnyOne,
            vec![a],
        );
        write_txn
            .approval_policy_delete(&idm_admin, "any_a_two")
            .expect("delete");
        let policy = write_txn.internal_search_uuid(policy_uuid).unwrap();
        assert_eq!(
            policy.get_ava_refer(Attribute::Approver),
            Some(&BTreeSet::from([a]))
        );
        write_txn.commit().expect("failed to commit");
    }

    /// S5: in the tally, decisions by the requester and slots the approver could not hold
    /// under the snapshot are dropped.
    #[qs_test]
    async fn test_approval_tally_drops_invalid_decisions(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let at = OffsetDateTime::UNIX_EPOCH + ct;
        let mut write_txn = server.write(ct).await.unwrap();
        let a = create_person(&mut write_txn, "approver_a");
        let b = create_person(&mut write_txn, "approver_b");
        let x = create_person(&mut write_txn, "outsider_x");
        let r = create_person(&mut write_txn, "requester_r");
        create_policy(&mut write_txn, "all_ab", ApprovalPattern::All, vec![a, b]);
        let request = create_request(&mut write_txn, r, "all_ab", ct).unwrap();

        // The requester, an outsider claiming A's slot, and a slot that is not in the
        // snapshot at all.
        add_decision_record(
            &mut write_txn,
            request,
            &decision_json(r, ApprovalDecisionAction::Approve, at, &[a, b]),
        );
        add_decision_record(
            &mut write_txn,
            request,
            &decision_json(x, ApprovalDecisionAction::Approve, at, &[a]),
        );
        add_decision_record(
            &mut write_txn,
            request,
            &decision_json(b, ApprovalDecisionAction::Approve, at, &[b, Uuid::new_v4()]),
        );
        assert_eq!(
            read_request(&mut write_txn, request).state,
            ApprovalRequestState::Pending
        );
        decide_as(&mut write_txn, a, request, approve(), ct).expect("A approves");
        assert_eq!(
            read_request(&mut write_txn, request).state,
            ApprovalRequestState::Approved
        );
    }

    /// Backup approvers may decide once the escalation time has passed, whether or not the
    /// sweep has recorded the escalation yet.
    #[qs_test]
    async fn test_approval_backup_decides_before_sweep(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);
        let a = create_person(&mut write_txn, "approver_a");
        let b = create_person(&mut write_txn, "approver_b");
        let x = create_person(&mut write_txn, "backup_x");
        let r = create_person(&mut write_txn, "requester_r");
        let mut policy = policy_request("escalating", ApprovalPattern::All, vec![a, b]);
        policy.backup_approvers = vec![x];
        policy.escalation_timeout_seconds = Some(30);
        write_txn
            .approval_policy_create(&idm_admin, &policy)
            .expect("failed to create approval policy");
        let request = create_request(&mut write_txn, r, "escalating", ct).unwrap();
        write_txn.commit().expect("failed to commit");

        let ct_early = ct + Duration::from_secs(29);
        let mut write_txn = server.write(ct_early).await.unwrap();
        assert_eq!(
            decide_as(&mut write_txn, x, request, approve(), ct_early),
            Err(OperationError::AccessDenied)
        );
        drop(write_txn);

        let ct_escalate = ct + Duration::from_secs(31);
        let mut write_txn = server.write(ct_escalate).await.unwrap();
        decide_as(&mut write_txn, x, request, approve(), ct_escalate)
            .expect("backup approvers may decide after the escalation time");
        decide_as(&mut write_txn, a, request, approve(), ct_escalate).expect("A approves");
        let read = read_request(&mut write_txn, request);
        assert_eq!(read.escalation_level, 0);
        assert_eq!(read.state, ApprovalRequestState::Approved);
        write_txn.commit().expect("failed to commit");
    }

    /// idm_approval_admins is high privilege, so it is protected from lower privileged
    /// group administrators who could otherwise add themselves to it.
    #[qs_test]
    async fn test_approval_admins_high_privilege(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();

        let approval_admins = write_txn
            .internal_search_uuid(UUID_IDM_APPROVAL_ADMINS)
            .expect("idm_approval_admins must exist");
        assert!(approval_admins.attribute_equality(
            Attribute::MemberOf,
            &PartialValue::Refer(UUID_IDM_HIGH_PRIVILEGE)
        ));

        let group_admin_uuid = create_person(&mut write_txn, "group_admin");
        let plain_group_uuid = create_group(&mut write_txn, "plain_group", &[]);
        write_txn
            .internal_modify_uuid(
                UUID_IDM_GROUP_ADMINS,
                &ModifyList::new_append(Attribute::Member, Value::ReferN(group_admin_uuid)),
            )
            .expect("failed to add group admin");
        let group_admin = identity(&mut write_txn, group_admin_uuid);

        let add_self = |txn: &mut QueryServerWriteTransaction<'_>, group: Uuid| {
            let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(group)));
            txn.impersonate_modify(
                &filter,
                &filter,
                &ModifyList::new_append(Attribute::Member, Value::ReferN(group_admin_uuid)),
                &group_admin,
            )
        };

        // A group admin can manage ordinary groups ...
        add_self(&mut write_txn, plain_group_uuid).expect("group admin must manage groups");
        // ... but not idm_approval_admins (the modify finds no entry it may change).
        assert!(add_self(&mut write_txn, UUID_IDM_APPROVAL_ADMINS).is_err());
        assert!(!write_txn
            .internal_search_uuid(UUID_IDM_APPROVAL_ADMINS)
            .unwrap()
            .attribute_equality(Attribute::Member, &PartialValue::Refer(group_admin_uuid)));
    }

    /// Kubidm: the fixture of the high privilege membership gate tests.
    struct GateFixture {
        /// Manages (as entry manager) every group below.
        manager: Uuid,
        approver: Uuid,
        /// A person to add as a member.
        target: Uuid,
        /// A person with no rights over the groups.
        outsider: Uuid,
        /// Nested in idm_high_privilege through `parent`.
        nested: Uuid,
        /// A direct member of idm_high_privilege.
        direct: Uuid,
        /// Not high privilege.
        plain: Uuid,
    }

    const GATE_POLICY: &str = "hp_members";

    fn create_managed_group(
        txn: &mut QueryServerWriteTransaction<'_>,
        name: &str,
        managers: Uuid,
    ) -> Uuid {
        let uuid = Uuid::new_v4();
        txn.internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname(name)),
            (Attribute::Uuid, Value::Uuid(uuid)),
            (Attribute::EntryManagedBy, Value::Refer(managers))
        )])
        .expect("failed to create managed group");
        uuid
    }

    fn internal_add_member(txn: &mut QueryServerWriteTransaction<'_>, group: Uuid, member: Uuid) {
        txn.internal_modify_uuid(
            group,
            &ModifyList::new_append(Attribute::Member, Value::ReferN(member)),
        )
        .expect("failed to add member internally");
    }

    fn gate_setup(txn: &mut QueryServerWriteTransaction<'_>) -> GateFixture {
        let manager = create_person(txn, "gate_manager");
        let approver = create_person(txn, "gate_approver");
        let target = create_person(txn, "gate_target");
        let outsider = create_person(txn, "gate_outsider");
        let managers = create_group(txn, "gate_managers", &[manager]);
        let nested = create_managed_group(txn, "gate_nested", managers);
        let direct = create_managed_group(txn, "gate_direct", managers);
        let plain = create_managed_group(txn, "gate_plain", managers);
        let parent = create_group(txn, "gate_parent", &[nested]);
        internal_add_member(txn, UUID_IDM_HIGH_PRIVILEGE, parent);
        internal_add_member(txn, UUID_IDM_HIGH_PRIVILEGE, direct);
        GateFixture {
            manager,
            approver,
            target,
            outsider,
            nested,
            direct,
            plain,
        }
    }

    /// An enabled policy covering `group_membership_high_privilege`: this turns the gate on.
    fn create_gate_policy(txn: &mut QueryServerWriteTransaction<'_>, name: &str, approver: Uuid) {
        let idm_admin = identity(txn, UUID_IDM_ADMIN);
        let mut request = policy_request(name, ApprovalPattern::AnyOne, vec![approver]);
        request.operation_types = vec![ApprovalOperationType::GroupMembershipHighPrivilege];
        txn.approval_policy_create(&idm_admin, &request)
            .expect("failed to create approval policy");
    }

    fn set_policy_enabled(txn: &mut QueryServerWriteTransaction<'_>, name: &str, enable: bool) {
        let idm_admin = identity(txn, UUID_IDM_ADMIN);
        txn.approval_policy_enable(&idm_admin, name, enable)
            .expect("failed to change the policy enabled state");
    }

    fn modify_member_as(
        txn: &mut QueryServerWriteTransaction<'_>,
        actor: Uuid,
        group: Uuid,
        modlist: &ModifyList<ModifyInvalid>,
    ) -> Result<(), OperationError> {
        let actor = identity(txn, actor);
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(group)));
        txn.impersonate_modify(&filter, &filter, modlist, &actor)
    }

    fn add_member_as(
        txn: &mut QueryServerWriteTransaction<'_>,
        actor: Uuid,
        group: Uuid,
        member: Uuid,
    ) -> Result<(), OperationError> {
        modify_member_as(
            txn,
            actor,
            group,
            &ModifyList::new_append(Attribute::Member, Value::ReferN(member)),
        )
    }

    /// The same addition through batch modify, the path SCIM writes take.
    fn batch_add_member_as(
        txn: &mut QueryServerWriteTransaction<'_>,
        actor: Uuid,
        group: Uuid,
        member: Uuid,
    ) -> Result<(), OperationError> {
        let ident = identity(txn, actor);
        let modlist = ModifyList::new_append(Attribute::Member, Value::ReferN(member))
            .validate(txn.get_schema())
            .expect("invalid modlist");
        txn.batch_modify(&BatchModifyEvent {
            ident,
            modset: BTreeMap::from([(group, modlist)]),
        })
    }

    fn is_member(txn: &mut QueryServerWriteTransaction<'_>, group: Uuid, member: Uuid) -> bool {
        txn.internal_search_uuid(group)
            .expect("group missing")
            .attribute_equality(Attribute::Member, &PartialValue::Refer(member))
    }

    fn member_details(member: &str) -> BTreeMap<String, String> {
        BTreeMap::from([("member".to_string(), member.to_string())])
    }

    fn create_gate_request(
        txn: &mut QueryServerWriteTransaction<'_>,
        requester: Uuid,
        policy: &str,
        group: Uuid,
        details: &BTreeMap<String, String>,
        ct: Duration,
    ) -> Result<Uuid, OperationError> {
        let requester = identity(txn, requester);
        txn.approval_request_create(
            &requester,
            policy,
            &ApprovalOperationType::GroupMembershipHighPrivilege,
            group,
            details,
            ct,
        )
    }

    fn execute_as(
        txn: &mut QueryServerWriteTransaction<'_>,
        actor: Uuid,
        request: Uuid,
    ) -> Result<(), OperationError> {
        let actor = identity(txn, actor);
        txn.approval_request_execute(&actor, request)
    }

    /// An approved request from the manager to add `member` to `group`.
    fn approved_gate_request(
        txn: &mut QueryServerWriteTransaction<'_>,
        fx: &GateFixture,
        policy: &str,
        group: Uuid,
        member: Uuid,
        ct: Duration,
    ) -> Uuid {
        let request = create_gate_request(
            txn,
            fx.manager,
            policy,
            group,
            &member_details(&member.to_string()),
            ct,
        )
        .expect("failed to create request");
        decide_as(txn, fx.approver, request, approve(), ct).expect("failed to approve");
        assert_eq!(
            read_request(txn, request).state,
            ApprovalRequestState::Approved
        );
        request
    }

    /// Kubidm: without an enabled policy covering the operation, high privilege members are
    /// added as before. A policy for another operation type, or a disabled one, does not
    /// turn the gate on.
    #[qs_test]
    async fn test_approval_gate_off_without_policy(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);

        add_member_as(&mut txn, fx.manager, fx.nested, fx.target)
            .expect("no policy: the add must work");

        create_policy(
            &mut txn,
            "other_type",
            ApprovalPattern::AnyOne,
            vec![fx.approver],
        );
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);
        set_policy_enabled(&mut txn, GATE_POLICY, false);
        add_member_as(&mut txn, fx.manager, fx.direct, fx.target)
            .expect("disabled policy: the add must work");
        batch_add_member_as(&mut txn, fx.manager, fx.nested, fx.outsider)
            .expect("disabled policy: the batch add must work");
        assert!(is_member(&mut txn, fx.nested, fx.target));
        assert!(is_member(&mut txn, fx.direct, fx.target));
        assert!(is_member(&mut txn, fx.nested, fx.outsider));
        txn.commit().expect("failed to commit");
    }

    /// Kubidm: with an enabled policy, adding a member to a high privilege group (directly
    /// or nested) is refused to non-internal identities on every modify path; internal
    /// writes, removals and other groups are not gated, and disabling the policy turns the
    /// gate off again.
    #[qs_test]
    async fn test_approval_gate_refuses_high_privilege_member_add(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        internal_add_member(&mut txn, fx.nested, fx.outsider);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);

        // Nested and direct members of idm_high_privilege are gated, on modify and on
        // batch modify (SCIM).
        for group in [fx.nested, fx.direct] {
            assert_eq!(
                add_member_as(&mut txn, fx.manager, group, fx.target),
                Err(OperationError::AP0002ApprovalRequired)
            );
            assert_eq!(
                batch_add_member_as(&mut txn, fx.manager, group, fx.target),
                Err(OperationError::AP0002ApprovalRequired)
            );
            assert!(!is_member(&mut txn, group, fx.target));
        }

        // Replacing the members (purge and add) adds one too.
        assert_eq!(
            modify_member_as(
                &mut txn,
                fx.manager,
                fx.nested,
                &ModifyList::new_purge_and_set(Attribute::Member, Value::ReferN(fx.target)),
            ),
            Err(OperationError::AP0002ApprovalRequired)
        );

        // Someone without rights is still refused by the access controls first (here the
        // group is not even visible to them).
        assert_eq!(
            add_member_as(&mut txn, fx.outsider, fx.direct, fx.target),
            Err(OperationError::NoMatchingEntries)
        );

        // A group that is not high privilege is not gated.
        add_member_as(&mut txn, fx.manager, fx.plain, fx.target)
            .expect("a plain group is not gated");

        // Removals are not gated.
        modify_member_as(
            &mut txn,
            fx.manager,
            fx.nested,
            &ModifyList::new_remove(Attribute::Member, PartialValue::Refer(fx.outsider)),
        )
        .expect("a removal is not gated");
        assert!(!is_member(&mut txn, fx.nested, fx.outsider));

        // Internal writes are not gated.
        internal_add_member(&mut txn, fx.nested, fx.target);
        assert!(is_member(&mut txn, fx.nested, fx.target));

        // Break-glass: an approval admin disables the policy (which is not itself gated),
        // and direct adds work again.
        set_policy_enabled(&mut txn, GATE_POLICY, false);
        add_member_as(&mut txn, fx.manager, fx.direct, fx.target)
            .expect("the gate is off once the policy is disabled");
        assert!(is_member(&mut txn, fx.direct, fx.target));
        txn.commit().expect("failed to commit");
    }

    /// Kubidm: the full flow: the add is refused, the requester files a request, it is
    /// approved, and executing it adds the member once.
    #[qs_test]
    async fn test_approval_gate_execute_flow(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);

        assert_eq!(
            add_member_as(&mut txn, fx.manager, fx.nested, fx.target),
            Err(OperationError::AP0002ApprovalRequired)
        );

        // A uuid in another form is stored canonically.
        let request = create_gate_request(
            &mut txn,
            fx.manager,
            GATE_POLICY,
            fx.nested,
            &member_details(&fx.target.to_string().to_uppercase()),
            ct,
        )
        .expect("failed to create request");
        assert_eq!(
            read_request(&mut txn, request).operation_details,
            member_details(&fx.target.to_string())
        );

        // Pending: nothing to execute yet.
        assert_eq!(
            execute_as(&mut txn, fx.manager, request),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        decide_as(&mut txn, fx.approver, request, approve(), ct).expect("failed to approve");

        // Only the requester may execute it.
        for other in [fx.approver, fx.outsider] {
            assert_eq!(
                execute_as(&mut txn, other, request),
                Err(OperationError::AccessDenied)
            );
        }
        assert!(!is_member(&mut txn, fx.nested, fx.target));

        execute_as(&mut txn, fx.manager, request).expect("failed to execute");
        assert!(is_member(&mut txn, fx.nested, fx.target));
        assert_eq!(
            read_request(&mut txn, request).state,
            ApprovalRequestState::Consumed
        );

        // An approval authorises its operation once.
        assert_eq!(
            execute_as(&mut txn, fx.manager, request),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        txn.commit().expect("failed to commit");

        // The member was committed.
        let mut txn = server.write(ct).await.unwrap();
        assert!(is_member(&mut txn, fx.nested, fx.target));
        assert!(txn
            .internal_search_uuid(fx.target)
            .expect("target missing")
            .attribute_equality(
                Attribute::MemberOf,
                &PartialValue::Refer(UUID_IDM_HIGH_PRIVILEGE)
            ));
    }

    /// Kubidm: the target and details of a `group_membership_high_privilege` request are
    /// validated when it is created and when it is executed.
    #[qs_test]
    async fn test_approval_gate_request_details(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);
        let target = fx.target.to_string();

        let invalid = |res: Result<Uuid, OperationError>| {
            matches!(res, Err(OperationError::InvalidAttribute(_)))
        };
        for details in [
            BTreeMap::new(),
            BTreeMap::from([("group".to_string(), target.clone())]),
            BTreeMap::from([
                ("member".to_string(), target.clone()),
                ("extra".to_string(), "x".to_string()),
            ]),
            member_details("gate_target"),
            member_details(&Uuid::nil().to_string()),
        ] {
            assert!(
                invalid(create_gate_request(
                    &mut txn,
                    fx.manager,
                    GATE_POLICY,
                    fx.nested,
                    &details,
                    ct
                )),
                "{details:?} must be refused"
            );
        }
        // The target must be a high privilege group, other than the member.
        for group in [fx.plain, fx.target] {
            assert!(invalid(create_gate_request(
                &mut txn,
                fx.manager,
                GATE_POLICY,
                group,
                &member_details(&target),
                ct
            )));
        }
        assert!(invalid(create_gate_request(
            &mut txn,
            fx.manager,
            GATE_POLICY,
            fx.nested,
            &member_details(&fx.nested.to_string()),
            ct
        )));

        // Details that no longer have the canonical form (only the system can write them)
        // are refused on execute, and the approval is not consumed.
        let request = approved_gate_request(&mut txn, &fx, GATE_POLICY, fx.nested, fx.target, ct);
        txn.internal_modify_uuid(
            request,
            &ModifyList::new_purge_and_set(
                Attribute::ApprovalOperationDetails,
                Value::new_utf8(
                    serde_json::to_string(&member_details(&target.to_uppercase()))
                        .expect("serialise details"),
                ),
            ),
        )
        .expect("failed to rewrite the details");
        assert!(matches!(
            execute_as(&mut txn, fx.manager, request),
            Err(OperationError::InvalidAttribute(_))
        ));
        assert!(!is_member(&mut txn, fx.nested, fx.target));
        assert_eq!(
            read_request(&mut txn, request).state,
            ApprovalRequestState::Approved
        );

        // A request for another operation type can not be executed.
        create_policy(
            &mut txn,
            "schema",
            ApprovalPattern::AnyOne,
            vec![fx.approver],
        );
        let other =
            create_request(&mut txn, fx.manager, "schema", ct).expect("failed to create request");
        decide_as(&mut txn, fx.approver, other, approve(), ct).expect("failed to approve");
        assert_eq!(
            execute_as(&mut txn, fx.manager, other),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        txn.commit().expect("failed to commit");
    }

    /// Kubidm: an approval lifts the gate, it does not grant the right to add the member.
    #[qs_test]
    async fn test_approval_gate_execute_requires_add_rights(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);

        // The outsider may file and get approval, and can see the group (access control
        // admins read every group), but may not add members to it.
        internal_add_member(&mut txn, UUID_IDM_ACCESS_CONTROL_ADMINS, fx.outsider);
        let request = create_gate_request(
            &mut txn,
            fx.outsider,
            GATE_POLICY,
            fx.direct,
            &member_details(&fx.outsider.to_string()),
            ct,
        )
        .expect("failed to create request");
        decide_as(&mut txn, fx.approver, request, approve(), ct).expect("failed to approve");

        assert_eq!(
            execute_as(&mut txn, fx.outsider, request),
            Err(OperationError::AccessDenied)
        );
        assert!(!is_member(&mut txn, fx.direct, fx.outsider));
        assert_eq!(
            read_request(&mut txn, request).state,
            ApprovalRequestState::Approved
        );
        txn.commit().expect("failed to commit");
    }

    /// Kubidm: the policy is chosen on the server side: the request must be under an
    /// enabled policy covering the operation. With several, any of them will do.
    #[qs_test]
    async fn test_approval_gate_execute_policy_selection(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);
        create_gate_policy(&mut txn, "hp_members_2", fx.approver);

        let first = approved_gate_request(&mut txn, &fx, GATE_POLICY, fx.nested, fx.target, ct);
        let second = approved_gate_request(&mut txn, &fx, "hp_members_2", fx.direct, fx.target, ct);

        // The policy of the first request is disabled; the gate stays on through the
        // second policy, which the first request was not filed under.
        set_policy_enabled(&mut txn, GATE_POLICY, false);
        assert_eq!(
            add_member_as(&mut txn, fx.manager, fx.nested, fx.target),
            Err(OperationError::AP0002ApprovalRequired)
        );
        assert_eq!(
            execute_as(&mut txn, fx.manager, first),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        assert!(!is_member(&mut txn, fx.nested, fx.target));

        execute_as(&mut txn, fx.manager, second).expect("failed to execute");
        assert!(is_member(&mut txn, fx.direct, fx.target));
        txn.commit().expect("failed to commit");
    }

    /// Kubidm: the gate holds for adding a group to idm_high_privilege itself, and for
    /// nesting a group that already has members (who would become high privilege).
    #[qs_test]
    async fn test_approval_gate_group_nesting(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        // idm_high_privilege is managed by the access control admins.
        internal_add_member(&mut txn, UUID_IDM_ACCESS_CONTROL_ADMINS, fx.manager);
        internal_add_member(&mut txn, fx.plain, fx.target);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);

        assert_eq!(
            add_member_as(&mut txn, fx.manager, UUID_IDM_HIGH_PRIVILEGE, fx.plain),
            Err(OperationError::AP0002ApprovalRequired)
        );
        assert_eq!(
            add_member_as(&mut txn, fx.manager, fx.nested, fx.plain),
            Err(OperationError::AP0002ApprovalRequired)
        );
        assert!(!is_member(&mut txn, UUID_IDM_HIGH_PRIVILEGE, fx.plain));
        assert!(!is_member(&mut txn, fx.nested, fx.plain));
        assert!(!txn
            .internal_search_uuid(fx.target)
            .expect("target missing")
            .attribute_equality(
                Attribute::MemberOf,
                &PartialValue::Refer(UUID_IDM_HIGH_PRIVILEGE)
            ));

        // Without the gate the same nesting works.
        set_policy_enabled(&mut txn, GATE_POLICY, false);
        add_member_as(&mut txn, fx.manager, UUID_IDM_HIGH_PRIVILEGE, fx.plain)
            .expect("the gate is off");
        txn.commit().expect("failed to commit");
    }

    /// Kubidm: an approved request can not be executed once its situation changed: after
    /// it expired, after its member was deleted, or once its target is no longer high
    /// privilege. A read-only session can not execute it at all.
    #[qs_test]
    async fn test_approval_gate_execute_not_usable(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);
        let doomed = create_person(&mut txn, "gate_doomed");

        let expiring = approved_gate_request(&mut txn, &fx, GATE_POLICY, fx.nested, fx.target, ct);
        let deleted_member =
            approved_gate_request(&mut txn, &fx, GATE_POLICY, fx.nested, doomed, ct);
        let unnested = approved_gate_request(&mut txn, &fx, GATE_POLICY, fx.direct, fx.target, ct);

        // A read-only session.
        let manager_entry = txn.internal_search_uuid(fx.manager).expect("manager");
        let read_only = Identity::from_impersonate_entry_readonly(manager_entry);
        assert_eq!(
            txn.approval_request_execute(&read_only, unnested),
            Err(OperationError::AccessDenied)
        );

        // The member was deleted.
        txn.internal_delete_uuid(doomed)
            .expect("failed to delete the member");
        assert_eq!(
            execute_as(&mut txn, fx.manager, deleted_member),
            Err(OperationError::AP0003ApprovalNotUsable)
        );

        // The target is no longer high privilege.
        txn.internal_modify_uuid(
            UUID_IDM_HIGH_PRIVILEGE,
            &ModifyList::new_remove(Attribute::Member, PartialValue::Refer(fx.direct)),
        )
        .expect("failed to un-nest");
        assert_eq!(
            execute_as(&mut txn, fx.manager, unnested),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        assert!(!is_member(&mut txn, fx.direct, fx.target));
        txn.commit().expect("failed to commit");

        // The request expired (the policy timeout is an hour).
        let later = ct + Duration::from_secs(2 * 3600);
        let mut txn = server.write(later).await.unwrap();
        assert_eq!(
            execute_as(&mut txn, fx.manager, expiring),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        assert!(!is_member(&mut txn, fx.nested, fx.target));
    }

    /// Kubidm: a request can not add a dynamic group, an entry owned by a sync agreement,
    /// or a group containing either: their members are not under approval control.
    #[qs_test]
    async fn test_approval_gate_member_not_delegated(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);

        let sync_account = Uuid::new_v4();
        let synced = Uuid::new_v4();
        txn.internal_create(vec![
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::SyncAccount.to_value()),
                (Attribute::Name, Value::new_iname("gate_sync")),
                (Attribute::Uuid, Value::Uuid(sync_account))
            ),
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Class, EntryClass::SyncObject.to_value()),
                (Attribute::Name, Value::new_iname("gate_synced")),
                (Attribute::Uuid, Value::Uuid(synced)),
                (Attribute::SyncParentUuid, Value::Refer(sync_account))
            ),
        ])
        .expect("failed to create the synced group");
        let holds_dyngroup = create_group(&mut txn, "gate_holds_dyn", &[UUID_IDM_ALL_PERSONS]);
        let holds_synced = create_group(&mut txn, "gate_holds_synced", &[synced]);

        for member in [UUID_IDM_ALL_PERSONS, synced, holds_dyngroup, holds_synced] {
            assert!(
                matches!(
                    create_gate_request(
                        &mut txn,
                        fx.manager,
                        GATE_POLICY,
                        fx.nested,
                        &member_details(&member.to_string()),
                        ct,
                    ),
                    Err(OperationError::InvalidAttribute(_))
                ),
                "{member} must be refused"
            );
        }
        // A member that does not exist is refused too.
        assert_eq!(
            create_gate_request(
                &mut txn,
                fx.manager,
                GATE_POLICY,
                fx.nested,
                &member_details(&Uuid::new_v4().to_string()),
                ct,
            ),
            Err(OperationError::NoMatchingEntries)
        );

        // A group that comes to contain a dynamic group after approval can not be executed.
        let plain_member = create_group(&mut txn, "gate_plain_member", &[]);
        let request =
            approved_gate_request(&mut txn, &fx, GATE_POLICY, fx.nested, plain_member, ct);
        internal_add_member(&mut txn, plain_member, UUID_IDM_ALL_PERSONS);
        assert_eq!(
            execute_as(&mut txn, fx.manager, request),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        txn.commit().expect("failed to commit");
    }

    /// Kubidm: the requester may read their own request (without the member details);
    /// approval admins see the member described; anyone else is refused whether or not the
    /// request exists.
    #[qs_test]
    async fn test_approval_request_get_by_requester(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);
        let request = approved_gate_request(&mut txn, &fx, GATE_POLICY, fx.nested, fx.target, ct);
        let manager = identity(&mut txn, fx.manager);
        let outsider = identity(&mut txn, fx.outsider);
        let idm_admin = identity(&mut txn, UUID_IDM_ADMIN);
        txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        let own = read_txn
            .approval_request_get(&manager, request)
            .expect("the requester may read their request");
        assert_eq!(own.state, ApprovalRequestState::Approved);
        assert_eq!(own.operation_member, None);

        for uuid in [request, Uuid::new_v4()] {
            assert_eq!(
                read_txn.approval_request_get(&outsider, uuid).err(),
                Some(OperationError::AccessDenied)
            );
        }
        // Not even the requester learns whether another uuid exists.
        assert_eq!(
            read_txn
                .approval_request_get(&manager, Uuid::new_v4())
                .err(),
            Some(OperationError::AccessDenied)
        );

        let admin_view = read_txn
            .approval_request_get(&idm_admin, request)
            .expect("an approval admin may read the request");
        let member = admin_view
            .operation_member
            .expect("the member is described to approval admins");
        assert_eq!(member.uuid, fx.target);
        assert_eq!(member.name.as_deref(), Some("gate_target"));
        assert!(member.classes.iter().any(|c| c == "person"));
        assert_eq!(member.member_count, None);
        let listed = read_txn
            .approval_request_list(&idm_admin, None)
            .expect("failed to list");
        assert!(listed
            .iter()
            .any(|r| r.uuid == request && r.operation_member.is_some()));
    }

    /// Kubidm: M1 lockout. With the gate on, the last idm_admin can remove themselves from
    /// idm_admins (removals are not gated), after which no one may manage approval policies
    /// and high privilege adds stay gated. The admin socket break-glass disables the policy
    /// as the system and lifts the gate.
    #[qs_test]
    async fn test_approval_gate_lockout_break_glass(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);

        modify_member_as(
            &mut txn,
            UUID_IDM_ADMIN,
            UUID_IDM_ADMINS,
            &ModifyList::new_remove(Attribute::Member, PartialValue::Refer(UUID_IDM_ADMIN)),
        )
        .expect("removing yourself is not gated");
        let idm_admin = identity(&mut txn, UUID_IDM_ADMIN);
        assert_eq!(
            txn.approval_policy_enable(&idm_admin, GATE_POLICY, false),
            Err(OperationError::AccessDenied)
        );
        assert_eq!(
            add_member_as(&mut txn, fx.manager, fx.nested, fx.target),
            Err(OperationError::AP0002ApprovalRequired)
        );

        assert_eq!(
            txn.approval_policy_disable_break_glass(Some("no_such_policy")),
            Err(OperationError::NoMatchingEntries)
        );
        assert_eq!(
            txn.approval_policy_disable_break_glass(None),
            Ok(vec![GATE_POLICY.to_string()])
        );
        // Nothing left to disable.
        assert_eq!(txn.approval_policy_disable_break_glass(None), Ok(vec![]));
        add_member_as(&mut txn, fx.manager, fx.nested, fx.target)
            .expect("the gate is off after break-glass");

        // By name, too (idm_admin is locked out, so re-enable as the system).
        txn.approval_policy_enable(&Identity::from_internal(), GATE_POLICY, true)
            .expect("failed to re-enable");
        assert_eq!(
            txn.approval_policy_disable_break_glass(Some(GATE_POLICY)),
            Ok(vec![GATE_POLICY.to_string()])
        );
        txn.commit().expect("failed to commit");
    }

    /// Kubidm: S1. Reviving an entry restores its direct memberships; restoring one of a
    /// high privilege group is gated like any other add for a non-internal reviver.
    #[qs_test]
    async fn test_approval_gate_revive(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        let person = create_person(&mut txn, "gate_revived");
        internal_add_member(&mut txn, UUID_IDM_ADMINS, person);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);
        txn.internal_delete_uuid(person)
            .expect("failed to delete the person");

        let admin = txn.internal_search_uuid(UUID_ADMIN).expect("admin missing");
        let revive = crate::event::ReviveRecycledEvent::new_impersonate_entry(
            admin,
            filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(person))),
        );
        assert_eq!(
            txn.revive_recycled(&revive),
            Err(OperationError::AP0002ApprovalRequired)
        );
        txn.commit().expect("failed to commit");

        let mut txn = server.write(ct).await.unwrap();
        assert!(txn.internal_search_uuid(person).is_err(), "still recycled");
        set_policy_enabled(&mut txn, GATE_POLICY, false);
        txn.revive_recycled(&revive)
            .expect("without the gate the revive restores the membership");
        assert!(is_member(&mut txn, UUID_IDM_ADMINS, person));
        txn.commit().expect("failed to commit");
    }

    /// Kubidm: M1. The nested members of a group member are recorded on the request and
    /// shown to approvers. Once they change, also indirectly, executing is refused (and
    /// the approval is kept); a group whose members did not change is added.
    #[qs_test]
    async fn test_approval_gate_member_group_contents(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);
        let team = create_group(&mut txn, "gate_team", &[fx.target]);
        let sub = create_group(&mut txn, "gate_team_sub", &[]);
        let steady = create_group(&mut txn, "gate_steady", &[fx.target]);

        let changed = approved_gate_request(&mut txn, &fx, GATE_POLICY, fx.direct, team, ct);
        let unchanged = approved_gate_request(&mut txn, &fx, GATE_POLICY, fx.direct, steady, ct);

        let read = read_request(&mut txn, changed);
        let member =
            super::approval_operation_member(&mut txn, &read).expect("the member is shown");
        assert_eq!(member.approved_members, Some(vec![fx.target]));
        assert_eq!(member.members_changed, Some(false));

        // Entries join the group after the approval, through a nested group.
        internal_add_member(&mut txn, team, sub);
        internal_add_member(&mut txn, sub, fx.outsider);
        let member =
            super::approval_operation_member(&mut txn, &read).expect("the member is shown");
        assert_eq!(member.approved_members, Some(vec![fx.target]));
        assert_eq!(member.members_changed, Some(true));
        assert_eq!(
            execute_as(&mut txn, fx.manager, changed),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        assert!(!is_member(&mut txn, fx.direct, team));
        assert_eq!(
            read_request(&mut txn, changed).state,
            ApprovalRequestState::Approved
        );

        execute_as(&mut txn, fx.manager, unchanged).expect("unchanged members: execute works");
        assert!(is_member(&mut txn, fx.direct, steady));

        // A person member has no nested members to record.
        let person = approved_gate_request(&mut txn, &fx, GATE_POLICY, fx.nested, fx.target, ct);
        let read = read_request(&mut txn, person);
        let member =
            super::approval_operation_member(&mut txn, &read).expect("the member is shown");
        assert_eq!(member.approved_members, None);
        assert_eq!(member.members_changed, None);
        execute_as(&mut txn, fx.manager, person).expect("person member: execute works");
        txn.commit().expect("failed to commit");
    }

    /// Kubidm: S1. Disabling a policy, also through break-glass, cancels its open requests,
    /// so re-enabling it does not make approvals given before usable again.
    #[qs_test]
    async fn test_approval_gate_disable_cancels_requests(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);

        let approved = approved_gate_request(&mut txn, &fx, GATE_POLICY, fx.nested, fx.target, ct);
        let pending = create_gate_request(
            &mut txn,
            fx.manager,
            GATE_POLICY,
            fx.direct,
            &member_details(&fx.target.to_string()),
            ct,
        )
        .expect("failed to create request");
        set_policy_enabled(&mut txn, GATE_POLICY, false);
        set_policy_enabled(&mut txn, GATE_POLICY, true);
        for request in [approved, pending] {
            assert_eq!(
                read_request(&mut txn, request).state,
                ApprovalRequestState::Cancelled
            );
        }
        assert_eq!(
            execute_as(&mut txn, fx.manager, approved),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        assert!(!is_member(&mut txn, fx.nested, fx.target));

        let again = approved_gate_request(&mut txn, &fx, GATE_POLICY, fx.nested, fx.target, ct);
        assert_eq!(
            txn.approval_policy_disable_break_glass(None),
            Ok(vec![GATE_POLICY.to_string()])
        );
        set_policy_enabled(&mut txn, GATE_POLICY, true);
        assert_eq!(
            read_request(&mut txn, again).state,
            ApprovalRequestState::Cancelled
        );
        assert_eq!(
            execute_as(&mut txn, fx.manager, again),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        assert!(!is_member(&mut txn, fx.nested, fx.target));

        // Nothing left to disable.
        set_policy_enabled(&mut txn, GATE_POLICY, false);
        assert_eq!(txn.approval_policy_disable_break_glass(None), Ok(vec![]));
        txn.commit().expect("failed to commit");
    }

    /// Kubidm: a policy disabled without going through `approval_policy_enable` (so its
    /// requests are not cancelled) still refuses decisions, executes and consumes.
    #[qs_test]
    async fn test_approval_gate_disabled_policy_refuses_uncancelled(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);
        let approved = approved_gate_request(&mut txn, &fx, GATE_POLICY, fx.nested, fx.target, ct);
        let pending = create_gate_request(
            &mut txn,
            fx.manager,
            GATE_POLICY,
            fx.direct,
            &member_details(&fx.target.to_string()),
            ct,
        )
        .expect("failed to create request");

        let policy_uuid = find_policy_uuid(&mut txn, GATE_POLICY);
        txn.internal_modify_uuid(
            policy_uuid,
            &ModifyList::new_purge_and_set(Attribute::ApprovalPolicyEnabled, Value::Bool(false)),
        )
        .expect("failed to disable the policy directly");
        assert_eq!(
            read_request(&mut txn, approved).state,
            ApprovalRequestState::Approved
        );
        assert_eq!(
            read_request(&mut txn, pending).state,
            ApprovalRequestState::Pending
        );

        assert_eq!(
            decide_as(&mut txn, fx.approver, pending, approve(), ct),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        assert_eq!(
            execute_as(&mut txn, fx.manager, approved),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        let details = read_request(&mut txn, approved).operation_details;
        let manager = identity(&mut txn, fx.manager);
        assert_eq!(
            txn.approval_request_check_and_consume(
                &manager,
                approved,
                GATE_POLICY,
                &ApprovalOperationType::GroupMembershipHighPrivilege,
                fx.nested,
                &details,
            ),
            Err(OperationError::AP0003ApprovalNotUsable)
        );
        assert!(!is_member(&mut txn, fx.nested, fx.target));
        assert_eq!(
            read_request(&mut txn, approved).state,
            ApprovalRequestState::Approved
        );
        assert_eq!(
            read_request(&mut txn, pending).state,
            ApprovalRequestState::Pending
        );
        txn.commit().expect("failed to commit");
    }

    /// Kubidm: `member_contents` is recorded by the server; a request that supplies it is
    /// refused, whatever its value.
    #[qs_test]
    async fn test_approval_gate_client_member_contents_refused(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut txn = server.write(ct).await.unwrap();
        let fx = gate_setup(&mut txn);
        create_gate_policy(&mut txn, GATE_POLICY, fx.approver);
        let team = create_group(&mut txn, "gate_team", &[fx.target]);

        for (member, contents) in [
            (fx.target, String::new()),
            (team, String::new()),
            (team, fx.target.to_string()),
        ] {
            let details = BTreeMap::from([
                ("member".to_string(), member.to_string()),
                ("member_contents".to_string(), contents),
            ]);
            assert!(
                matches!(
                    create_gate_request(&mut txn, fx.manager, GATE_POLICY, fx.direct, &details, ct),
                    Err(OperationError::InvalidAttribute(_))
                ),
                "{details:?} must be refused"
            );
        }
        txn.commit().expect("failed to commit");
    }
}
