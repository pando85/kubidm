//! Kubidm approval workflows.
//!
//! # How a request is decided
//!
//! **Slots.** Every entry of the policy's `approver` list is one approver slot, naming
//! either a person or a group. A person fills a slot that names them directly, or a group
//! they are a (transitive) member of. One decision fills at most one slot, and a person
//! decides at most once, so a person who matches several slots (listed directly and through
//! a group, or listed as approver and as backup approver) still counts once. Two members of
//! the same group fill that group's slot only once. The requester never fills a slot.
//!
//! **Quorum.** Over the `n` (distinct) approver slots: `any_one` needs 1 slot approved,
//! `majority` needs `n / 2 + 1`, and `all` needs all `n`. A group slot is filled by any one
//! of its members, so `all` over `[group]` needs one member; list people individually to
//! require each of them. A request is approved once the quorum is reached, and rejected
//! once the slots that are still open can no longer bring it there (so under `all` a
//! single rejection rejects it).
//!
//! **Escalation.** Once the escalation timeout has passed, the backup approvers may fill
//! any *open* approver slot: they stand in for approvers who have not responded. The
//! approvers stay eligible, decisions made before the escalation keep counting, and the
//! quorum does not change. A backup approver can not take a slot that has already been
//! decided, so an escalation never turns a rejection into an approval and never lowers the
//! number of people needed. (The alternative - handing the request over to a separate
//! backup quorum - would either discard the decisions already made or mix two quorums,
//! which is how a rejection could previously complete an approval.)
//!
//! **Storage.** Every decision is its own `approval_decision_record` entry, created once
//! and never modified, holding one JSON object that also records the slots the approver
//! could fill when they decided. Separate entries never conflict in replication, so two
//! decisions made on different replicas are both kept (see
//! `SCHEMA_CLASS_APPROVAL_DECISION_RECORD` for why values of one attribute would not be).
//! The outcome is recomputed from all the decisions whenever a request is read or decided,
//! so it does not depend on group memberships changing later, and a stored state that lags
//! behind replicated decisions is corrected on read. The approval sweep writes the
//! recomputed state back.

use crate::prelude::*;
use kubidm_proto::v1::{
    ApprovalDecision, ApprovalDecisionAction, ApprovalDecisionRequest, ApprovalOperationType,
    ApprovalPattern, ApprovalPolicy, ApprovalPolicyCreateRequest, ApprovalRequest,
    ApprovalRequestState,
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

/// One decision, as stored in `Attribute::ApprovalDecision` of an approval decision record.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct StoredApprovalDecision {
    approver_uuid: Uuid,
    approver_spn: String,
    #[serde(with = "time::serde::timestamp")]
    decision_time: OffsetDateTime,
    action: ApprovalDecisionAction,
    comment: Option<String>,
    /// The approver slots this approver could fill when they decided.
    slots: BTreeSet<Uuid>,
}

impl StoredApprovalDecision {
    fn to_proto(&self) -> ApprovalDecision {
        ApprovalDecision {
            approver_uuid: self.approver_uuid,
            approver_spn: self.approver_spn.clone(),
            decision_time: self.decision_time,
            action: self.action,
            comment: self.comment.clone(),
        }
    }
}

/// The distinct approver slots of `policy`.
fn approval_slots(policy: &ApprovalPolicy) -> BTreeSet<Uuid> {
    policy.approvers.iter().copied().collect()
}

/// The number of approved slots `policy` needs, see the module documentation.
fn approval_required_decisions(policy: &ApprovalPolicy) -> u32 {
    let total = approval_slots(policy).len() as u32;
    let required = match policy.pattern {
        ApprovalPattern::AnyOne => 1,
        ApprovalPattern::Majority => total / 2 + 1,
        ApprovalPattern::All => total,
    };
    required.max(1)
}

/// The approver slots `ident` may fill on a request under `policy`: the slots naming them
/// or one of their groups, or every slot if the request has been escalated and they are a
/// backup approver. Empty if they are not an approver of the request at all.
fn approval_ident_slots(
    ident: &Identity,
    policy: &ApprovalPolicy,
    escalated: bool,
) -> BTreeSet<Uuid> {
    let ident_uuid = ident.get_uuid();
    let matches = |slot: &Uuid| *slot == ident_uuid || ident.is_memberof(*slot);

    if escalated && policy.backup_approvers.iter().any(matches) {
        approval_slots(policy)
    } else {
        policy.approvers.iter().copied().filter(matches).collect()
    }
}

/// The decisions of a request counted against the slots of its policy.
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

/// Try to give decision `idx` a slot, moving earlier decisions to another of their slots
/// if needed (an augmenting path). Earlier decisions never lose their slot.
fn approval_assign_slot(
    idx: usize,
    decisions: &[&StoredApprovalDecision],
    slots: &BTreeSet<Uuid>,
    owner: &mut BTreeMap<Uuid, usize>,
    visited: &mut BTreeSet<Uuid>,
) -> bool {
    let Some(decision) = decisions.get(idx) else {
        return false;
    };
    for slot in decision.slots.iter() {
        if !slots.contains(slot) || !visited.insert(*slot) {
            continue;
        }
        let free = match owner.get(slot).copied() {
            None => true,
            Some(other) => approval_assign_slot(other, decisions, slots, owner, visited),
        };
        if free {
            owner.insert(*slot, idx);
            return true;
        }
    }
    false
}

/// Count `decisions` against the slots of `policy`. Decisions are taken in time order; a
/// decision counts if it can fill a slot without taking one away from an earlier decision,
/// and only the first decision of each approver counts. Slots recorded in a decision that
/// are no longer approvers of the policy are ignored.
fn approval_tally(policy: &ApprovalPolicy, decisions: &[StoredApprovalDecision]) -> ApprovalTally {
    let slots = approval_slots(policy);

    let mut ordered: Vec<&StoredApprovalDecision> = decisions.iter().collect();
    ordered.sort_by_key(|d| (d.decision_time, d.approver_uuid));
    let mut seen = BTreeSet::new();
    ordered.retain(|d| seen.insert(d.approver_uuid));

    let mut owner: BTreeMap<Uuid, usize> = BTreeMap::new();
    for idx in 0..ordered.len() {
        let mut visited = BTreeSet::new();
        approval_assign_slot(idx, &ordered, &slots, &mut owner, &mut visited);
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
        required: approval_required_decisions(policy),
        approvals,
        open: (slots.len() as u32).saturating_sub(assigned.len() as u32),
        counted: assigned.iter().map(|d| d.approver_uuid).collect(),
    }
}

/// An approval request as read from its entry, with its policy if that still exists.
struct ResolvedApprovalRequest {
    policy: Option<ApprovalPolicy>,
    /// `request.state` is the effective state, see `approval_effective_state`.
    request: ApprovalRequest,
    stored_state: ApprovalRequestState,
    decisions: Vec<StoredApprovalDecision>,
}

impl ResolvedApprovalRequest {
    /// The policy, target and requester all still exist.
    fn is_valid(&self) -> bool {
        self.policy.is_some()
            && self.request.target_uuid.is_some()
            && self.request.requestor_uuid.is_some()
    }
}

/// The state of a request, given its stored state and its decisions.
///
/// - Cancelled and expired are set outside of decisions and are final.
/// - Otherwise the state is recomputed from the decisions. If they decide the request, that
///   is the state, whatever was stored (after a replication merge the stored state may lag
///   behind the merged decisions).
/// - If they do not decide it, a pending request stays pending. A stored approval or
///   rejection is kept (the policy may have gained approvers since), with a warning.
/// - A pending request whose policy, target or requester is gone is invalid. Decided
///   requests keep their state as a record.
fn approval_effective_state(
    request_uuid: Uuid,
    stored: ApprovalRequestState,
    valid: bool,
    policy: Option<&ApprovalPolicy>,
    decisions: &[StoredApprovalDecision],
) -> ApprovalRequestState {
    let pending = match stored {
        ApprovalRequestState::Cancelled
        | ApprovalRequestState::Expired
        | ApprovalRequestState::Invalid => return stored,
        ApprovalRequestState::Pending | ApprovalRequestState::Escalated => true,
        ApprovalRequestState::Approved | ApprovalRequestState::Rejected => false,
    };

    match policy {
        Some(policy) if valid => {
            let derived = approval_tally(policy, decisions).state();
            if derived != ApprovalRequestState::Pending {
                if derived != stored {
                    debug!(%request_uuid, %stored, %derived, "approval request state recomputed from its decisions");
                }
                derived
            } else if pending {
                ApprovalRequestState::Pending
            } else {
                warn!(%request_uuid, %stored, "approval request decisions no longer reach its stored state, keeping it");
                stored
            }
        }
        _ if pending => ApprovalRequestState::Invalid,
        _ => stored,
    }
}

/// Load an approval request together with the policy it refers to. A missing policy,
/// target or requester is not an error (the request is then invalid, see
/// `approval_effective_state`), a malformed request or policy is.
fn approval_request_resolve<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    entry: &Entry<EntrySealed, EntryCommitted>,
) -> Result<ResolvedApprovalRequest, OperationError> {
    let request_uuid = entry.get_uuid();
    let decisions = approval_decision_records(qs, &[request_uuid])?
        .remove(&request_uuid)
        .unwrap_or_else(|| Ok(Vec::with_capacity(0)))?;
    approval_request_resolve_with(qs, entry, decisions)
}

/// `approval_request_resolve`, with the decisions on the request already loaded.
fn approval_request_resolve_with<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    entry: &Entry<EntrySealed, EntryCommitted>,
    decisions: Vec<StoredApprovalDecision>,
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

    let stored_state = approval_request_state(entry)?;

    let mut request = approval_request_from_entry(entry, policy.as_ref(), &decisions)?;
    let valid =
        policy.is_some() && request.target_uuid.is_some() && request.requestor_uuid.is_some();
    request.state = approval_effective_state(
        request_uuid,
        stored_state,
        valid,
        policy.as_ref(),
        &decisions,
    );
    if request.state == ApprovalRequestState::Invalid {
        warn!(%request_uuid, "approval request policy, target or requester was deleted");
    }

    Ok(ResolvedApprovalRequest {
        policy,
        request,
        stored_state,
        decisions,
    })
}

/// Resolve every entry, logging and skipping the ones that are malformed.
fn approval_request_resolve_all<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    entries: &[Arc<EntrySealedCommitted>],
) -> Result<Vec<ResolvedApprovalRequest>, OperationError> {
    let request_uuids: Vec<Uuid> = entries.iter().map(|e| e.get_uuid()).collect();
    let mut records = approval_decision_records(qs, &request_uuids)?;

    Ok(entries
        .iter()
        .filter_map(|entry| {
            let request_uuid = entry.get_uuid();
            let resolved = records
                .remove(&request_uuid)
                .unwrap_or_else(|| Ok(Vec::with_capacity(0)))
                .and_then(|decisions| approval_request_resolve_with(qs, entry, decisions));
            match resolved {
                Ok(resolved) => Some(resolved),
                Err(err) => {
                    warn!(?err, request = %request_uuid, "skipping malformed approval request");
                    None
                }
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

    let targets = request_uuids
        .iter()
        .map(|u| f_eq(Attribute::ApprovalTarget, PartialValue::Refer(*u)))
        .collect();
    let records = qs.internal_search(filter!(f_and!([
        f_eq(Attribute::Class, EntryClass::ApprovalDecisionRecord.into()),
        f_or(targets)
    ])))?;

    for record in records.iter() {
        let Some(request_uuid) = record.get_ava_single_refer(Attribute::ApprovalTarget) else {
            continue;
        };
        let decision = record
            .get_ava_single_utf8(Attribute::ApprovalDecision)
            .ok_or(OperationError::MissingAttribute(Attribute::ApprovalDecision))
            .and_then(|s| {
                serde_json::from_str::<StoredApprovalDecision>(s)
                    .map_err(|_| OperationError::InvalidValueState)
            })
            .inspect_err(|err| {
                error!(?err, record = %record.get_uuid(), request = %request_uuid, "invalid approval decision record");
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
        decisions.sort_by_key(|d| (d.decision_time, d.approver_uuid));
    }
    Ok(by_request)
}

/// Has the escalation timeout of a pending, not yet escalated request passed?
fn approval_escalation_due(resolved: &ResolvedApprovalRequest, now: OffsetDateTime) -> bool {
    let Some(policy) = resolved.policy.as_ref() else {
        return false;
    };
    // There is a single escalation level: the backup approvers.
    let Some(escalation_timeout) = policy.escalation_timeout_seconds else {
        return false;
    };
    resolved.request.state == ApprovalRequestState::Pending
        && resolved.request.escalation_level == 0
        && !policy.backup_approvers.is_empty()
        && resolved.request.created_at + Duration::from_secs(u64::from(escalation_timeout)) <= now
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

        let filter = filter!(f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()));
        let entries = self.internal_search(filter)?;

        Ok(approval_request_resolve_all(self, &entries)?
            .into_iter()
            .map(|resolved| resolved.request)
            .filter(|request| state.is_none_or(|s| request.state == s))
            .collect())
    }

    pub fn approval_request_get(
        &mut self,
        ident: &Identity,
        uuid: Uuid,
    ) -> Result<ApprovalRequest, OperationError> {
        approval_check_admin(ident, false)?;

        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
            f_eq(Attribute::Uuid, PartialValue::Uuid(uuid))
        ]));
        let entry = self
            .internal_search(filter)?
            .into_iter()
            .next()
            .ok_or(OperationError::NoMatchingEntries)?;

        approval_request_resolve(self, &entry).map(|resolved| resolved.request)
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
        Ok(())
    }

    /// The number of accounts other than `requester` that can fill one of `slots`: the
    /// slot names them, or a group they are a member of.
    fn approval_slot_candidates(
        &mut self,
        slots: &[Uuid],
        requester: Uuid,
    ) -> Result<usize, OperationError> {
        if slots.is_empty() {
            return Ok(0);
        }
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
            f_eq(Attribute::Class, EntryClass::Account.into()),
            f_or(candidates),
            f_andnot(f_eq(Attribute::Uuid, PartialValue::Uuid(requester)))
        ])))
        .map(|entries| entries.len())
    }

    /// Kubidm: reject a request that its policy can never approve, because too few of its
    /// approver slots can be filled by someone other than the requester (for example, the
    /// requester is the only approver). Without this the request would sit pending until it
    /// expires. Backup approvers can fill open slots after escalation, so they count when
    /// the policy escalates. This is a sanity check that errs on the side of accepting: a
    /// person who can fill several slots is counted for each.
    fn approval_check_reachable(
        &mut self,
        policy: &ApprovalPolicy,
        requester: Uuid,
    ) -> Result<(), OperationError> {
        let required = approval_required_decisions(policy) as usize;
        let slots = approval_slots(policy);

        let mut fillable = 0;
        for slot in slots.iter() {
            if self.approval_slot_candidates(&[*slot], requester)? > 0 {
                fillable += 1;
            }
        }

        if fillable < required
            && policy.escalation_timeout_seconds.is_some()
            && !policy.backup_approvers.is_empty()
        {
            let backups = self.approval_slot_candidates(&policy.backup_approvers, requester)?;
            fillable += backups.min(slots.len() - fillable);
        }

        if fillable < required {
            error!(
                policy = %policy.name,
                %requester,
                required,
                fillable,
                "approval request can never be approved: too few approvers other than the requester"
            );
            return Err(OperationError::AP0001ApprovalQuorumUnreachable);
        }
        Ok(())
    }

    /// Create a pending approval request from `ident` for `operation_type` on `target_uuid`,
    /// under the enabled policy `policy_name` that must cover that operation type. The
    /// request expires after the policy timeout. Returns the uuid of the new request.
    ///
    /// Kubidm: nothing in the server calls this yet - no operation is gated on approval and
    /// there is no API route to create requests. It is the entry point for those.
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
            return Err(OperationError::InvalidRequestState);
        }
        if !policy.operation_types.contains(operation_type) {
            error!(policy = %policy.name, %operation_type, "approval policy does not cover this operation type");
            return Err(OperationError::InvalidRequestState);
        }

        self.approval_check_reachable(&policy, ident.get_uuid())?;

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

    pub fn approval_request_decision(
        &mut self,
        ident: &Identity,
        request_uuid: Uuid,
        request: ApprovalDecisionRequest,
        ct: Duration,
    ) -> Result<(), OperationError> {
        let current_time = OffsetDateTime::UNIX_EPOCH + ct;
        let is_system = approval_ident_is_system(ident);

        if !is_system {
            if ident.is_internal() {
                security_access!(ident = %ident, "denied - internal identity is not the system");
                return Err(OperationError::AccessDenied);
            }
            if ident.access_scope() != AccessScope::ReadWrite {
                security_access!("approval decision requires a read-write (privileged) session");
                return Err(OperationError::AccessDenied);
            }
        }

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

        let resolved = approval_request_resolve(self, &entry)?;

        let Some(policy) = resolved.policy.as_ref() else {
            error!(%request_uuid, "approval request policy not found");
            return Err(not_found);
        };

        // Kubidm: only an approver of the request's policy may decide on it - or a backup
        // approver once the request has been escalated - and never on their own request.
        // The system may fill any slot.
        let escalated = resolved.request.escalation_level > 0;
        let slots = if is_system {
            approval_slots(policy)
        } else {
            let slots = approval_ident_slots(ident, policy, escalated);
            if slots.is_empty() {
                security_access!(ident = %ident, %request_uuid, "denied - not an approver of this request");
                return Err(OperationError::AccessDenied);
            }

            if resolved.request.requestor_uuid == Some(ident.get_uuid()) {
                security_access!(ident = %ident, %request_uuid, "denied - approvers can not decide on their own request");
                return Err(OperationError::AccessDenied);
            }
            slots
        };

        if !policy.enabled {
            error!(policy = %policy.name, "approval policy is disabled");
            return Err(OperationError::InvalidRequestState);
        }

        if !resolved.is_valid() {
            error!(%request_uuid, "approval request target or requester was deleted, it can not be decided");
            return Err(OperationError::InvalidRequestState);
        }

        if resolved.request.state != ApprovalRequestState::Pending {
            error!(state = %resolved.request.state, "approval request is not pending");
            return Err(OperationError::InvalidRequestState);
        }

        if resolved
            .request
            .expires_at
            .is_some_and(|expires_at| expires_at <= current_time)
        {
            error!("approval request has expired");
            return Err(OperationError::InvalidRequestState);
        }

        let approver_uuid = ident.get_uuid();
        if resolved
            .decisions
            .iter()
            .any(|d| d.approver_uuid == approver_uuid)
        {
            error!("approver has already decided on this approval request");
            return Err(OperationError::InvalidRequestState);
        }

        let action = request.action;
        let decision = StoredApprovalDecision {
            approver_uuid,
            approver_spn: ident
                .get_user_entry()
                .and_then(|e| e.get_ava_single_proto_string(Attribute::Spn))
                .unwrap_or_default(),
            decision_time: current_time,
            action,
            comment: request.comment,
            slots,
        };

        let counted_before = approval_tally(policy, &resolved.decisions).counted;
        let mut decisions = resolved.decisions;
        decisions.push(decision.clone());
        let tally = approval_tally(policy, &decisions);
        // The new decision must fill a slot, without displacing an earlier decision (which
        // could otherwise happen when two decisions have the same time, as they are then
        // ordered by approver).
        if !tally.counted.contains(&approver_uuid) || !tally.counted.is_superset(&counted_before) {
            // For example a second member of a group whose slot is already decided.
            error!(%request_uuid, "every approver slot this approver can fill has already been decided");
            return Err(OperationError::InvalidRequestState);
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
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4())),
            (Attribute::ApprovalTarget, Value::Refer(request_uuid)),
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
        let state = match approval_request_resolve(self, &entry) {
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
            return Err(OperationError::InvalidRequestState);
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
        let Some(resolved) = self.approval_request_pending(request_uuid)? else {
            return Ok(false);
        };

        if !approval_expiry_due(&resolved, current_time) {
            return Ok(false);
        }

        self.approval_request_set_state(request_uuid, ApprovalRequestState::Expired)?;
        info!(request = %request_uuid, "approval request expired");
        Ok(true)
    }

    /// Escalate a pending approval request to the backup approvers of its policy once the
    /// policy's escalation timeout has passed since the request was created. Returns
    /// whether the request was escalated.
    pub fn approval_request_escalate(
        &mut self,
        request_uuid: Uuid,
        ct: Duration,
    ) -> Result<bool, OperationError> {
        let current_time = OffsetDateTime::UNIX_EPOCH + ct;
        let Some(resolved) = self.approval_request_pending(request_uuid)? else {
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
    /// - an invalid request (its policy, target or requester was deleted) is expired,
    /// - a request whose decisions decide it (after a replication merge) gets that state,
    /// - an overdue request is expired,
    /// - a request past its escalation timeout is escalated, once.
    ///
    /// Malformed requests are logged and skipped. Returns the number of requests changed,
    /// so that the caller only commits when something changed.
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
        for resolved in approval_request_resolve_all(self, &entries)? {
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
    ) -> Result<Option<ResolvedApprovalRequest>, OperationError> {
        let entries = self.internal_search(filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
            f_eq(Attribute::Uuid, PartialValue::Uuid(request_uuid)),
            f_eq(
                Attribute::ApprovalState,
                PartialValue::new_iutf8(ApprovalRequestState::Pending.as_str())
            )
        ])))?;
        let resolved = approval_request_resolve_all(self, &entries)?
            .into_iter()
            .next();
        if resolved.is_none() {
            debug!(%request_uuid, "approval request not found or not pending");
        }
        Ok(resolved)
    }
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
        required_decisions: policy.map(approval_required_decisions).unwrap_or(0),
        operation_details,
    })
}

#[cfg(test)]
mod tests {
    use super::StoredApprovalDecision;
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

    /// Only approvers (or backup approvers) of the request's policy may decide on it, and the
    /// requestor may cancel their own request (but nobody else's).
    #[qs_test]
    async fn test_approval_request_decision_access(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();

        let idm_admin_entry = write_txn.internal_search_uuid(UUID_IDM_ADMIN).unwrap();
        let idm_admin = Identity::from_impersonate_entry_readwrite(idm_admin_entry);
        let admin_entry = write_txn.internal_search_uuid(UUID_ADMIN).unwrap();
        let admin = Identity::from_impersonate_entry_readwrite(admin_entry);
        let anon_entry = write_txn.internal_search_uuid(UUID_ANONYMOUS).unwrap();
        let anon = Identity::from_impersonate_entry_readwrite(anon_entry);

        // Approvers are idm_admin (direct) and system_admins (backup, by group).
        let mut request = two_approver_policy("decision_policy");
        request.approvers = vec![UUID_IDM_ADMIN];
        write_txn
            .approval_policy_create(&idm_admin, &request)
            .expect("failed to create approval policy");
        let policy_uuid = find_policy_uuid(&mut write_txn, "decision_policy");

        let mk_request = |uuid: Uuid| {
            entry_init!(
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
            )
        };
        let request_a = Uuid::new_v4();
        let request_b = Uuid::new_v4();
        write_txn
            .internal_create(vec![mk_request(request_a), mk_request(request_b)])
            .expect("failed to create approval requests");

        let approve = || ApprovalDecisionRequest {
            action: ApprovalDecisionAction::Approve,
            comment: None,
        };

        // Neither a direct nor a backup approver of the policy.
        assert_eq!(
            write_txn.approval_request_decision(&anon, request_a, approve(), ct),
            Err(OperationError::AccessDenied)
        );
        // An approval admin is not implicitly an approver.
        let mut other_policy = two_approver_policy("other_policy");
        other_policy.approvers = vec![UUID_ANONYMOUS];
        other_policy.backup_approvers = vec![];
        write_txn
            .approval_policy_create(&idm_admin, &other_policy)
            .expect("failed to create approval policy");
        let other_policy_uuid = find_policy_uuid(&mut write_txn, "other_policy");
        write_txn
            .internal_modify_uuid(
                request_b,
                &ModifyList::new_purge_and_set(
                    Attribute::ApprovalRequestPolicy,
                    Value::Refer(other_policy_uuid),
                ),
            )
            .expect("failed to repoint request");
        assert_eq!(
            write_txn.approval_request_decision(&idm_admin, request_b, approve(), ct),
            Err(OperationError::AccessDenied)
        );

        assert_eq!(
            stored_state(&mut write_txn, request_a).as_deref(),
            Some("pending")
        );

        // The requestor may cancel their own request, others may not unless approval admin.
        let request_c = Uuid::new_v4();
        write_txn
            .internal_create(vec![mk_request(request_c)])
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

    /// Store a decision record directly, as replication would deliver one.
    fn add_decision_record(
        txn: &mut QueryServerWriteTransaction<'_>,
        request: Uuid,
        decision_json: &str,
    ) {
        txn.internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::ApprovalDecisionRecord.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4())),
            (Attribute::ApprovalTarget, Value::Refer(request)),
            (Attribute::ApprovalDecision, Value::new_utf8s(decision_json))
        )])
        .expect("failed to create decision record");
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

    fn read_request(txn: &mut QueryServerWriteTransaction<'_>, request: Uuid) -> ApprovalRequest {
        let entry = txn.internal_search_uuid(request).expect("request missing");
        super::approval_request_resolve(txn, &entry)
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

        write_txn
            .approval_policy_create(
                &idm_admin,
                &policy_request(
                    "approve_policy",
                    ApprovalPattern::AnyOne,
                    vec![UUID_IDM_ADMIN],
                ),
            )
            .expect("failed to create approval policy");

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
            Err(OperationError::InvalidRequestState)
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
            write_txn.approval_request_decision(&idm_admin, request_uuid, approve(), ct),
            Err(OperationError::InvalidRequestState)
        );
        write_txn
            .approval_policy_enable(&idm_admin, "approve_policy", true)
            .expect("failed to enable approval policy");
        // A missing request is indistinguishable from an unauthorised one, except to the
        // system identity.
        assert_eq!(
            write_txn.approval_request_decision(&idm_admin, Uuid::new_v4(), approve(), ct),
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
                &policy_request("internal", ApprovalPattern::AnyOne, vec![UUID_IDM_ADMIN]),
            ),
            Err(OperationError::AccessDenied)
        );
        // Not an approver of the policy.
        assert_eq!(
            write_txn.approval_request_decision(&admin, request_uuid, approve(), ct),
            Err(OperationError::AccessDenied)
        );
        write_txn
            .approval_request_decision(
                &idm_admin,
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
        assert_eq!(request.decisions[0].approver_uuid, UUID_IDM_ADMIN);
        assert_eq!(request.decisions[0].action, ApprovalDecisionAction::Approve);
        assert_eq!(request.decisions[0].comment.as_deref(), Some("looks good"));

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
            write_txn.approval_request_decision(&idm_admin, request_uuid, reject(), ct),
            Err(OperationError::InvalidRequestState)
        );
        assert_eq!(
            write_txn.approval_request_cancel(&idm_admin, request_uuid),
            Err(OperationError::InvalidRequestState)
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
        let admin = identity(&mut write_txn, UUID_ADMIN);

        for (name, pattern) in [
            ("majority_policy", ApprovalPattern::Majority),
            ("all_policy", ApprovalPattern::All),
            ("any_policy", ApprovalPattern::AnyOne),
        ] {
            write_txn
                .approval_policy_create(
                    &idm_admin,
                    &policy_request(name, pattern, vec![UUID_IDM_ADMIN, UUID_ADMIN]),
                )
                .expect("failed to create approval policy");
        }

        let majority_request =
            create_request(&mut write_txn, UUID_ANONYMOUS, "majority_policy", ct)
                .expect("failed to create approval request");
        let all_request = create_request(&mut write_txn, UUID_ANONYMOUS, "all_policy", ct)
            .expect("failed to create approval request");
        // admin is one of the two approvers that a majority needs, so a request from admin
        // could never be approved.
        assert_eq!(
            create_request(&mut write_txn, UUID_ADMIN, "majority_policy", ct),
            Err(OperationError::AP0001ApprovalQuorumUnreachable)
        );
        let own_request = create_request(&mut write_txn, UUID_ADMIN, "any_policy", ct)
            .expect("failed to create approval request");
        write_txn.commit().expect("failed to commit");

        let mut write_txn = server.write(ct).await.unwrap();
        // Majority of two approvers needs both: one approval keeps it pending.
        write_txn
            .approval_request_decision(&idm_admin, majority_request, approve(), ct)
            .expect("failed to approve");
        assert_eq!(
            write_txn.approval_request_decision(&idm_admin, majority_request, approve(), ct),
            Err(OperationError::InvalidRequestState)
        );
        write_txn
            .approval_request_decision(
                &admin,
                majority_request,
                decide(ApprovalDecisionAction::Reject, Some("no")),
                ct,
            )
            .expect("failed to reject");

        write_txn
            .approval_request_decision(&admin, all_request, reject(), ct)
            .expect("failed to reject");

        assert_eq!(
            write_txn.approval_request_decision(&admin, own_request, approve(), ct),
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
    /// Malformed requests fail to read on their own, and are skipped when listing.
    #[qs_test]
    async fn test_approval_request_operation_type_and_details(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut write_txn = server.write(ct).await.unwrap();
        let idm_admin = identity(&mut write_txn, UUID_IDM_ADMIN);

        write_txn
            .approval_policy_create(
                &idm_admin,
                &policy_request(
                    "fields_policy",
                    ApprovalPattern::AnyOne,
                    vec![UUID_IDM_ADMIN],
                ),
            )
            .expect("failed to create approval policy");
        let policy_uuid = find_policy_uuid(&mut write_txn, "fields_policy");

        let two_types = Uuid::new_v4();
        let bad_details = Uuid::new_v4();
        let bad_decision = Uuid::new_v4();
        let mk_request = |uuid: Uuid| {
            entry_init!(
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
            )
        };
        let mut e_two_types = mk_request(two_types);
        e_two_types.add_ava(
            Attribute::ApprovalOperationType,
            Value::new_iutf8n("privilege_grant"),
        );
        let mut e_bad_details = mk_request(bad_details);
        e_bad_details.add_ava(
            Attribute::ApprovalOperationDetails,
            Value::new_utf8s("not json"),
        );
        write_txn
            .internal_create(vec![e_two_types, e_bad_details, mk_request(bad_decision)])
            .expect("failed to create approval requests");
        add_decision_record(&mut write_txn, bad_decision, "[]");
        let good = create_request(&mut write_txn, UUID_ANONYMOUS, "fields_policy", ct)
            .expect("failed to create approval request");
        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        for malformed in [two_types, bad_details, bad_decision] {
            assert!(matches!(
                read_txn.approval_request_get(&idm_admin, malformed),
                Err(OperationError::InvalidValueState)
            ));
        }
        let listed = read_txn
            .approval_request_list(&idm_admin, None)
            .expect("one malformed request must not fail the list");
        assert_eq!(
            listed.iter().map(|r| r.uuid).collect::<Vec<_>>(),
            vec![good]
        );
        drop(read_txn);

        // The sweep skips them too.
        let mut write_txn = server.write(ct).await.unwrap();
        assert_eq!(write_txn.approval_sweep(), Ok(0));
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
            Err(OperationError::InvalidRequestState)
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
            Err(OperationError::InvalidRequestState)
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
            Err(OperationError::InvalidRequestState)
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

    /// The requester never fills a slot. A request that can therefore never be approved is
    /// refused when it is created rather than left pending until it expires.
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
            let decision = StoredApprovalDecision {
                approver_uuid: approver,
                approver_spn: String::new(),
                decision_time: OffsetDateTime::UNIX_EPOCH + ct + Duration::from_secs(offset),
                action,
                comment: None,
                slots: BTreeSet::from([approver]),
            };
            serde_json::to_string(&decision).unwrap()
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
        let mut policy = policy_request("short", ApprovalPattern::AnyOne, vec![UUID_IDM_ADMIN]);
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
            write_txn.approval_request_decision(&idm_admin, request, approve(), ct_expired),
            Err(OperationError::InvalidRequestState)
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

        let mut policy = policy_request(
            "timeout_policy",
            ApprovalPattern::AnyOne,
            vec![UUID_IDM_ADMIN],
        );
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
    /// sweep expires it. A decided request keeps its state.
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
        assert_eq!(request.required_decisions, 0);
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
        for request in [lost_target, lost_requester] {
            assert_eq!(
                decide_as(&mut write_txn, a, request, approve(), ct),
                Err(OperationError::InvalidRequestState)
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
}
