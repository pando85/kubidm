use crate::prelude::*;
use kubidm_proto::v1::{
    ApprovalDecision, ApprovalDecisionAction, ApprovalDecisionRequest, ApprovalOperationType,
    ApprovalPattern, ApprovalPolicy, ApprovalPolicyCreateRequest, ApprovalRequest,
    ApprovalRequestState,
};
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

/// Is `ident` one of `approvers`, either directly or through group membership?
fn approval_ident_in(ident: &Identity, approvers: Option<&BTreeSet<Uuid>>) -> bool {
    let ident_uuid = ident.get_uuid();
    approvers
        .map(|set| {
            set.iter()
                .any(|approver| *approver == ident_uuid || ident.is_memberof(*approver))
        })
        .unwrap_or(false)
}

/// The approvers whose decisions are expected at `escalation_level`: the backup approvers
/// once the request has been escalated (if the policy has any), the approvers otherwise.
fn approval_current_approvers(policy: &ApprovalPolicy, escalation_level: u32) -> &[Uuid] {
    if escalation_level == 0 || policy.backup_approvers.is_empty() {
        &policy.approvers
    } else {
        &policy.backup_approvers
    }
}

/// The number of approvals a request needs under `policy` at `escalation_level`.
fn approval_required_decisions(policy: &ApprovalPolicy, escalation_level: u32) -> u32 {
    let total = approval_current_approvers(policy, escalation_level).len() as u32;
    let required = match policy.pattern {
        ApprovalPattern::AnyOne => 1,
        ApprovalPattern::Majority => total / 2 + 1,
        ApprovalPattern::All => total,
    };
    required.max(1)
}

/// The state of a pending request given its `decisions`: approved once it has the required
/// number of approvals, rejected once the approvers that have not decided yet can no longer
/// bring it to that number, and still pending otherwise.
fn approval_outcome(
    policy: &ApprovalPolicy,
    escalation_level: u32,
    decisions: &[ApprovalDecision],
) -> ApprovalRequestState {
    let total = approval_current_approvers(policy, escalation_level).len() as u32;
    let required = approval_required_decisions(policy, escalation_level);
    let approvals = decisions
        .iter()
        .filter(|d| d.action == ApprovalDecisionAction::Approve)
        .count() as u32;
    let rejections = decisions
        .iter()
        .filter(|d| d.action == ApprovalDecisionAction::Reject)
        .count() as u32;
    let outstanding = total.saturating_sub(approvals.saturating_add(rejections));

    if approvals >= required {
        ApprovalRequestState::Approved
    } else if approvals.saturating_add(outstanding) < required {
        ApprovalRequestState::Rejected
    } else {
        ApprovalRequestState::Pending
    }
}

/// Load an approval request together with the policy it refers to.
fn approval_request_resolve<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    entry: &Entry<EntrySealed, EntryCommitted>,
) -> Result<(ApprovalPolicy, ApprovalRequest), OperationError> {
    let policy_uuid = entry
        .get_ava_single_refer(Attribute::ApprovalRequestPolicy)
        .ok_or(OperationError::MissingAttribute(
            Attribute::ApprovalRequestPolicy,
        ))?;
    let policy = qs
        .internal_search_uuid(policy_uuid)
        .and_then(|e| approval_policy_from_entry(&e))?;
    let request = approval_request_from_entry(entry, &policy)?;
    Ok((policy, request))
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

    pub fn approval_request_list(
        &mut self,
        ident: &Identity,
        state: Option<ApprovalRequestState>,
    ) -> Result<Vec<ApprovalRequest>, OperationError> {
        approval_check_admin(ident, false)?;

        let filter = match state {
            Some(s) => filter!(f_and!([
                f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
                f_eq(
                    Attribute::ApprovalState,
                    PartialValue::new_iutf8(s.as_str())
                )
            ])),
            None => filter!(f_eq(Attribute::Class, EntryClass::ApprovalRequest.into())),
        };
        let entries = self.internal_search(filter)?;

        entries
            .iter()
            .map(|e| approval_request_resolve(self, e).map(|(_, request)| request))
            .collect()
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

        approval_request_resolve(self, &entry).map(|(_, request)| request)
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

        let Some(policy_entry) = entry
            .get_ava_single_refer(Attribute::ApprovalRequestPolicy)
            .and_then(|policy_uuid| self.internal_search_uuid(policy_uuid).ok())
        else {
            error!(%request_uuid, "approval request policy not found");
            return Err(not_found);
        };

        let escalation_level = entry
            .get_ava_single_uint32(Attribute::ApprovalEscalationLevel)
            .unwrap_or(0);

        // Kubidm: only an approver of the request's policy may decide on it - or a backup
        // approver once the request has been escalated - and never on their own request.
        if !is_system {
            let is_approver =
                approval_ident_in(ident, policy_entry.get_ava_refer(Attribute::Approver))
                    || (escalation_level > 0
                        && approval_ident_in(
                            ident,
                            policy_entry.get_ava_refer(Attribute::BackupApprover),
                        ));
            if !is_approver {
                security_access!(ident = %ident, %request_uuid, "denied - not an approver of this request");
                return Err(OperationError::AccessDenied);
            }

            if entry.get_ava_single_refer(Attribute::ApprovalRequestor) == Some(ident.get_uuid()) {
                security_access!(ident = %ident, %request_uuid, "denied - approvers can not decide on their own request");
                return Err(OperationError::AccessDenied);
            }
        }

        let policy = approval_policy_from_entry(&policy_entry)?;
        let current = approval_request_from_entry(&entry, &policy)?;

        if !policy.enabled {
            error!(policy = %policy.name, "approval policy is disabled");
            return Err(OperationError::InvalidRequestState);
        }

        if current.state != ApprovalRequestState::Pending {
            error!(state = %current.state, "approval request is not pending");
            return Err(OperationError::InvalidRequestState);
        }

        if current
            .expires_at
            .is_some_and(|expires_at| expires_at <= current_time)
        {
            error!("approval request has expired");
            return Err(OperationError::InvalidRequestState);
        }

        let approver_uuid = ident.get_uuid();
        if current
            .decisions
            .iter()
            .any(|d| d.approver_uuid == approver_uuid)
        {
            error!("approver has already decided on this approval request");
            return Err(OperationError::InvalidRequestState);
        }

        let action = request.action;
        let decision = ApprovalDecision {
            approver_uuid,
            approver_spn: ident
                .get_user_entry()
                .and_then(|e| e.get_ava_single_proto_string(Attribute::Spn))
                .unwrap_or_default(),
            decision_time: current_time,
            action,
            comment: request.comment,
        };

        let mut decisions = current.decisions;
        decisions.push(decision);
        let new_state = approval_outcome(&policy, current.escalation_level, &decisions);

        // All decisions are stored together as one JSON array, see
        // `SCHEMA_ATTR_APPROVAL_DECISION`. Write transactions are serialised, so this
        // read-modify-write can not lose a concurrent decision.
        let decisions_json = serde_json::to_string(&decisions).map_err(|err| {
            error!(?err, "unable to serialise approval decisions");
            OperationError::SerdeJsonError
        })?;

        let mut mods = vec![
            Modify::Purged(Attribute::ApprovalDecision),
            Modify::Present(Attribute::ApprovalDecision, Value::new_utf8(decisions_json)),
        ];
        if new_state != ApprovalRequestState::Pending {
            mods.push(Modify::Purged(Attribute::ApprovalState));
            mods.push(Modify::Present(
                Attribute::ApprovalState,
                Value::new_iutf8(new_state.as_str()),
            ));
        }

        self.internal_modify_uuid(request_uuid, &ModifyList::new_list(mods))?;
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

        // Only pending requests can be cancelled, decided ones are final.
        if approval_request_state(&entry)? != ApprovalRequestState::Pending {
            error!("approval request is not pending");
            return Err(OperationError::InvalidRequestState);
        }

        self.internal_modify_uuid(
            request_uuid,
            &ModifyList::new_purge_and_set(
                Attribute::ApprovalState,
                Value::new_iutf8(ApprovalRequestState::Cancelled.as_str()),
            ),
        )?;
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
        let Some(entry) = self.approval_request_pending(request_uuid)? else {
            return Ok(false);
        };

        if !entry
            .get_ava_single_datetime(Attribute::ApprovalExpires)
            .is_some_and(|expires_at| expires_at <= current_time)
        {
            return Ok(false);
        }

        self.internal_modify_uuid(
            request_uuid,
            &ModifyList::new_purge_and_set(
                Attribute::ApprovalState,
                Value::new_iutf8(ApprovalRequestState::Expired.as_str()),
            ),
        )?;
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
        let Some(entry) = self.approval_request_pending(request_uuid)? else {
            return Ok(false);
        };

        let (policy, request) = approval_request_resolve(self, &entry)?;

        // There is a single escalation level: the backup approvers.
        let Some(escalation_timeout) = policy.escalation_timeout_seconds else {
            return Ok(false);
        };
        if request.escalation_level > 0
            || policy.backup_approvers.is_empty()
            || request.created_at + Duration::from_secs(u64::from(escalation_timeout))
                > current_time
        {
            return Ok(false);
        }

        self.internal_modify_uuid(
            request_uuid,
            &ModifyList::new_purge_and_set(Attribute::ApprovalEscalationLevel, Value::Uint32(1)),
        )?;
        info!(request = %request_uuid, "approval request escalated to the backup approvers");
        Ok(true)
    }

    fn approval_request_pending(
        &mut self,
        request_uuid: Uuid,
    ) -> Result<Option<Arc<EntrySealedCommitted>>, OperationError> {
        let entry = self
            .internal_search(filter!(f_and!([
                f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
                f_eq(Attribute::Uuid, PartialValue::Uuid(request_uuid)),
                f_eq(
                    Attribute::ApprovalState,
                    PartialValue::new_iutf8(ApprovalRequestState::Pending.as_str())
                )
            ])))?
            .into_iter()
            .next();
        if entry.is_none() {
            debug!(%request_uuid, "approval request not found or not pending");
        }
        Ok(entry)
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

/// The decisions are stored as one JSON array string, see `SCHEMA_ATTR_APPROVAL_DECISION`.
fn approval_request_decisions(
    entry: &Entry<EntrySealed, EntryCommitted>,
) -> Result<Vec<ApprovalDecision>, OperationError> {
    let mut decisions: Vec<ApprovalDecision> = entry
        .get_ava_single_utf8(Attribute::ApprovalDecision)
        .map(|s| {
            serde_json::from_str(s).map_err(|err| {
                error!(?err, uuid = %entry.get_uuid(), "invalid approval decisions");
                OperationError::InvalidValueState
            })
        })
        .transpose()?
        .unwrap_or_default();

    decisions.sort_by_key(|d| d.decision_time);
    Ok(decisions)
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

fn approval_request_from_entry(
    entry: &Entry<EntrySealed, EntryCommitted>,
    policy: &ApprovalPolicy,
) -> Result<ApprovalRequest, OperationError> {
    let uuid = entry.get_uuid();

    let operation_type = approval_request_operation_type(entry)?;

    let target_uuid = entry
        .get_ava_single_refer(Attribute::ApprovalTarget)
        .ok_or(OperationError::MissingAttribute(Attribute::ApprovalTarget))?;

    let requestor_uuid = entry
        .get_ava_single_refer(Attribute::ApprovalRequestor)
        .ok_or(OperationError::MissingAttribute(
            Attribute::ApprovalRequestor,
        ))?;

    let created_at = entry
        .get_ava_set(Attribute::CreatedAtCid)
        .and_then(|vs| vs.to_cid_single())
        .map(|cid| OffsetDateTime::UNIX_EPOCH + cid.ts)
        .ok_or(OperationError::MissingAttribute(Attribute::CreatedAtCid))?;

    let expires_at = entry.get_ava_single_datetime(Attribute::ApprovalExpires);

    let state = approval_request_state(entry)?;

    let decisions = approval_request_decisions(entry)?;

    let escalation_level = entry
        .get_ava_single_uint32(Attribute::ApprovalEscalationLevel)
        .unwrap_or(0);

    let operation_details = approval_request_operation_details(entry)?;

    Ok(ApprovalRequest {
        uuid,
        policy_uuid: policy.uuid,
        policy_name: policy.name.clone(),
        operation_type,
        target_uuid,
        target_spn: target_uuid.to_string(),
        requestor_uuid,
        requestor_spn: requestor_uuid.to_string(),
        created_at,
        expires_at,
        state,
        decisions,
        escalation_level,
        required_decisions: approval_required_decisions(policy, escalation_level),
        operation_details,
    })
}

#[cfg(test)]
mod tests {
    use crate::migration_data::dl14::schema::{
        SCHEMA_ATTR_APPROVAL_OPERATION_TYPE, SCHEMA_ATTR_APPROVAL_PATTERN,
        SCHEMA_ATTR_APPROVAL_POLICY_NAME, SCHEMA_ATTR_APPROVER, SCHEMA_ATTR_BACKUP_APPROVER,
    };
    use crate::prelude::*;
    use crate::schema::SchemaAttribute;
    use kubidm_proto::v1::{
        ApprovalDecisionAction, ApprovalDecisionRequest, ApprovalOperationType, ApprovalPattern,
        ApprovalPolicyCreateRequest, ApprovalRequestState,
    };
    use std::collections::BTreeMap;
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
        let policy_uuid = write_txn
            .internal_search(filter!(f_eq(
                Attribute::ApprovalPolicyName,
                PartialValue::new_iname("decision_policy")
            )))
            .expect("policy search")
            .first()
            .expect("policy missing")
            .get_uuid();

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
        let other_policy_uuid = write_txn
            .internal_search(filter!(f_eq(
                Attribute::ApprovalPolicyName,
                PartialValue::new_iname("other_policy")
            )))
            .expect("policy search")
            .first()
            .expect("policy missing")
            .get_uuid();
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

        let state_of = |txn: &mut QueryServerWriteTransaction<'_>, uuid: Uuid| {
            txn.internal_search_uuid(uuid)
                .unwrap()
                .get_ava_single_iutf8(Attribute::ApprovalState)
                .map(str::to_string)
        };
        assert_eq!(
            state_of(&mut write_txn, request_a).as_deref(),
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
            state_of(&mut write_txn, request_c).as_deref(),
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
        assert_eq!(request.policy_name, "approve_policy");
        assert_eq!(request.operation_type, ApprovalOperationType::SchemaModify);
        assert_eq!(request.target_uuid, UUID_IDM_ADMINS);
        assert_eq!(request.requestor_uuid, UUID_ADMIN);
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
            write_txn.approval_request_decision(
                &idm_admin,
                request_uuid,
                decide(ApprovalDecisionAction::Approve, None),
                ct
            ),
            Err(OperationError::InvalidRequestState)
        );
        write_txn
            .approval_policy_enable(&idm_admin, "approve_policy", true)
            .expect("failed to enable approval policy");
        // A missing request is indistinguishable from an unauthorised one, except to the
        // system identity.
        assert_eq!(
            write_txn.approval_request_decision(
                &idm_admin,
                Uuid::new_v4(),
                decide(ApprovalDecisionAction::Approve, None),
                ct
            ),
            Err(OperationError::AccessDenied)
        );
        assert_eq!(
            write_txn.approval_request_decision(
                &Identity::from_internal(),
                Uuid::new_v4(),
                decide(ApprovalDecisionAction::Approve, None),
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
                decide(ApprovalDecisionAction::Approve, None),
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
            write_txn.approval_request_decision(
                &admin,
                request_uuid,
                decide(ApprovalDecisionAction::Approve, None),
                ct
            ),
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
            write_txn.approval_request_decision(
                &idm_admin,
                request_uuid,
                decide(ApprovalDecisionAction::Reject, None),
                ct
            ),
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
        let anon = identity(&mut write_txn, UUID_ANONYMOUS);

        let no_details = BTreeMap::new();
        write_txn
            .approval_policy_create(
                &idm_admin,
                &policy_request(
                    "majority_policy",
                    ApprovalPattern::Majority,
                    vec![UUID_IDM_ADMIN, UUID_ADMIN],
                ),
            )
            .expect("failed to create approval policy");
        write_txn
            .approval_policy_create(
                &idm_admin,
                &policy_request(
                    "all_policy",
                    ApprovalPattern::All,
                    vec![UUID_IDM_ADMIN, UUID_ADMIN],
                ),
            )
            .expect("failed to create approval policy");

        let majority_request = write_txn
            .approval_request_create(
                &anon,
                "majority_policy",
                &ApprovalOperationType::SchemaModify,
                UUID_IDM_ADMINS,
                &no_details,
                ct,
            )
            .expect("failed to create approval request");
        let all_request = write_txn
            .approval_request_create(
                &anon,
                "all_policy",
                &ApprovalOperationType::SchemaModify,
                UUID_IDM_ADMINS,
                &no_details,
                ct,
            )
            .expect("failed to create approval request");
        let own_request = write_txn
            .approval_request_create(
                &admin,
                "majority_policy",
                &ApprovalOperationType::SchemaModify,
                UUID_IDM_ADMINS,
                &no_details,
                ct,
            )
            .expect("failed to create approval request");
        write_txn.commit().expect("failed to commit");

        let mut write_txn = server.write(ct).await.unwrap();
        // Majority of two approvers needs both: one approval keeps it pending.
        write_txn
            .approval_request_decision(
                &idm_admin,
                majority_request,
                decide(ApprovalDecisionAction::Approve, None),
                ct,
            )
            .expect("failed to approve");
        assert_eq!(
            write_txn.approval_request_decision(
                &idm_admin,
                majority_request,
                decide(ApprovalDecisionAction::Approve, None),
                ct
            ),
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
            .approval_request_decision(
                &admin,
                all_request,
                decide(ApprovalDecisionAction::Reject, None),
                ct,
            )
            .expect("failed to reject");

        assert_eq!(
            write_txn.approval_request_decision(
                &admin,
                own_request,
                decide(ApprovalDecisionAction::Approve, None),
                ct
            ),
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
        let policy_uuid = write_txn
            .internal_search(filter!(f_eq(
                Attribute::ApprovalPolicyName,
                PartialValue::new_iname("fields_policy")
            )))
            .expect("policy search")
            .first()
            .expect("policy missing")
            .get_uuid();

        let two_types = Uuid::new_v4();
        let bad_details = Uuid::new_v4();
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
            .internal_create(vec![e_two_types, e_bad_details])
            .expect("failed to create approval requests");
        write_txn.commit().expect("failed to commit");

        let mut read_txn = server.read().await.unwrap();
        assert!(matches!(
            read_txn.approval_request_get(&idm_admin, two_types),
            Err(OperationError::InvalidValueState)
        ));
        assert!(matches!(
            read_txn.approval_request_get(&idm_admin, bad_details),
            Err(OperationError::InvalidValueState)
        ));
    }

    /// Expiry and escalation, driven by the delayed actions.
    #[idm_test]
    async fn test_approval_request_timeout_and_escalation(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        use crate::idm::delayed::{ApprovalEscalationCheck, ApprovalTimeoutCheck, DelayedAction};

        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let idm_admin = identity(&mut idms_prox_write.qs_write, UUID_IDM_ADMIN);
        let anon = identity(&mut idms_prox_write.qs_write, UUID_ANONYMOUS);

        let mut policy = policy_request(
            "timeout_policy",
            ApprovalPattern::AnyOne,
            vec![UUID_IDM_ADMIN],
        );
        policy.timeout_seconds = 60;
        policy.escalation_timeout_seconds = Some(30);
        policy.backup_approvers = vec![UUID_SYSTEM_ADMINS, UUID_IDM_ADMINS];
        policy.pattern = ApprovalPattern::All;
        idms_prox_write
            .qs_write
            .approval_policy_create(&idm_admin, &policy)
            .expect("failed to create approval policy");
        let request_uuid = idms_prox_write
            .qs_write
            .approval_request_create(
                &anon,
                "timeout_policy",
                &ApprovalOperationType::SchemaModify,
                UUID_IDM_ADMINS,
                &BTreeMap::new(),
                ct,
            )
            .expect("failed to create approval request");
        idms_prox_write.commit().expect("failed to commit");

        let escalate =
            DelayedAction::ApprovalEscalationCheck(ApprovalEscalationCheck { request_uuid });
        let timeout = DelayedAction::ApprovalTimeoutCheck(ApprovalTimeoutCheck { request_uuid });

        let read_request = |txn: &mut QueryServerWriteTransaction<'_>| {
            let entry = txn.internal_search_uuid(request_uuid).unwrap();
            let (_, request) = super::approval_request_resolve(txn, &entry).unwrap();
            request
        };

        // Before the escalation timeout / expiry nothing happens.
        let ct_early = ct + Duration::from_secs(10);
        let mut idms_prox_write = idms.proxy_write(ct_early).await.unwrap();
        idms_prox_write
            .process_delayedaction(&escalate, ct_early)
            .expect("escalation check failed");
        idms_prox_write
            .process_delayedaction(&timeout, ct_early)
            .expect("timeout check failed");
        let request = read_request(&mut idms_prox_write.qs_write);
        assert_eq!(request.escalation_level, 0);
        assert_eq!(request.required_decisions, 1);
        assert_eq!(request.state, ApprovalRequestState::Pending);
        // Backup approvers (admin through system_admins) can not decide before escalation.
        let admin = identity(&mut idms_prox_write.qs_write, UUID_ADMIN);
        assert_eq!(
            idms_prox_write.qs_write.approval_request_decision(
                &admin,
                request_uuid,
                decide(ApprovalDecisionAction::Approve, None),
                ct_early
            ),
            Err(OperationError::AccessDenied)
        );
        idms_prox_write.commit().expect("failed to commit");

        // After the escalation timeout the backup approvers are expected (all of them).
        let ct_escalate = ct + Duration::from_secs(31);
        let mut idms_prox_write = idms.proxy_write(ct_escalate).await.unwrap();
        idms_prox_write
            .process_delayedaction(&escalate, ct_escalate)
            .expect("escalation check failed");
        let request = read_request(&mut idms_prox_write.qs_write);
        assert_eq!(request.escalation_level, 1);
        assert_eq!(request.required_decisions, 2);
        assert_eq!(request.state, ApprovalRequestState::Pending);
        // ... but can once it has been escalated. All backup approvers are needed.
        idms_prox_write
            .qs_write
            .approval_request_decision(
                &admin,
                request_uuid,
                decide(ApprovalDecisionAction::Approve, None),
                ct_escalate,
            )
            .expect("backup approver must be able to decide after escalation");
        let request = read_request(&mut idms_prox_write.qs_write);
        assert_eq!(request.state, ApprovalRequestState::Pending);
        // Escalation happens once.
        idms_prox_write
            .process_delayedaction(&escalate, ct_escalate)
            .expect("escalation check failed");
        assert_eq!(
            read_request(&mut idms_prox_write.qs_write).escalation_level,
            1
        );
        idms_prox_write.commit().expect("failed to commit");

        // After expiry no decision is accepted, and the timeout check expires the request.
        let ct_expired = ct + Duration::from_secs(61);
        let mut idms_prox_write = idms.proxy_write(ct_expired).await.unwrap();
        assert_eq!(
            idms_prox_write.qs_write.approval_request_decision(
                &idm_admin,
                request_uuid,
                decide(ApprovalDecisionAction::Approve, None),
                ct_expired
            ),
            Err(OperationError::InvalidRequestState)
        );
        idms_prox_write
            .process_delayedaction(&timeout, ct_expired)
            .expect("timeout check failed");
        let request = read_request(&mut idms_prox_write.qs_write);
        assert_eq!(request.state, ApprovalRequestState::Expired);
        idms_prox_write.commit().expect("failed to commit");
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

        let group_admin_uuid = Uuid::new_v4();
        let plain_group_uuid = Uuid::new_v4();
        write_txn
            .internal_create(vec![
                entry_init!(
                    (Attribute::Class, EntryClass::Object.to_value()),
                    (Attribute::Class, EntryClass::Account.to_value()),
                    (Attribute::Class, EntryClass::Person.to_value()),
                    (Attribute::Name, Value::new_iname("group_admin")),
                    (Attribute::DisplayName, Value::new_utf8s("group_admin")),
                    (Attribute::Uuid, Value::Uuid(group_admin_uuid))
                ),
                entry_init!(
                    (Attribute::Class, EntryClass::Object.to_value()),
                    (Attribute::Class, EntryClass::Group.to_value()),
                    (Attribute::Name, Value::new_iname("plain_group")),
                    (Attribute::Uuid, Value::Uuid(plain_group_uuid))
                ),
            ])
            .expect("failed to create entries");
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
