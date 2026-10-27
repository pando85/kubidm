use crate::prelude::*;
use kubidm_proto::v1::{
    ApprovalDecision, ApprovalDecisionAction, ApprovalDecisionRequest, ApprovalOperationType,
    ApprovalPattern, ApprovalPolicy, ApprovalPolicyCreateRequest, ApprovalRequest,
    ApprovalRequestState,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use time::OffsetDateTime;

/// Kubidm: the approval operations below use internal (ACP bypassing) searches and
/// writes, so the caller has to be authorised explicitly. Approval policies and requests
/// are administered by members of `idm_approval_admins`.
fn approval_check_admin(ident: &Identity, write: bool) -> Result<(), OperationError> {
    if ident.is_internal() {
        return Ok(());
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
            .into_iter()
            .map(|e| approval_request_from_entry(&e))
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
        let entries = self.internal_search(filter)?;

        entries
            .first()
            .map(|e| approval_request_from_entry(e))
            .ok_or(OperationError::NoMatchingEntries)?
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
            .map(|o| Value::new_iutf8n(&o.to_string()))
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
            vec![Value::new_iutf8(&request.pattern.to_string())],
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
        self.create(&create_event).map(|_| ())
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
        self.internal_delete(&filter)
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
        self.internal_modify(&filter, &modlist)
    }

    pub fn approval_request_decision(
        &mut self,
        ident: &Identity,
        request_uuid: Uuid,
        request: ApprovalDecisionRequest,
        ct: Duration,
    ) -> Result<(), OperationError> {
        let current_time = OffsetDateTime::UNIX_EPOCH + ct;
        let entries = self.internal_search(filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
            f_eq(Attribute::Uuid, PartialValue::Uuid(request_uuid))
        ])))?;

        let entry = entries.first().ok_or(OperationError::NoMatchingEntries)?;

        // Kubidm: only an approver (or backup approver) of the request's policy may
        // decide on it, from a read-write session.
        if !ident.is_internal() {
            if ident.access_scope() != AccessScope::ReadWrite {
                security_access!("approval decision requires a read-write (privileged) session");
                return Err(OperationError::AccessDenied);
            }

            let policy_uuid = entry
                .get_ava_single_refer(Attribute::ApprovalRequestPolicy)
                .ok_or(OperationError::MissingAttribute(
                    Attribute::ApprovalRequestPolicy,
                ))?;
            let policy = self.internal_search_uuid(policy_uuid)?;

            if !(approval_ident_in(ident, policy.get_ava_refer(Attribute::Approver))
                || approval_ident_in(ident, policy.get_ava_refer(Attribute::BackupApprover)))
            {
                security_access!(ident = %ident, "denied - not an approver of this policy");
                return Err(OperationError::AccessDenied);
            }
        }

        let current_state: ApprovalRequestState = entry
            .get_ava_single_iutf8(Attribute::ApprovalState)
            .and_then(|s| match s {
                "pending" => Some(ApprovalRequestState::Pending),
                "approved" => Some(ApprovalRequestState::Approved),
                "rejected" => Some(ApprovalRequestState::Rejected),
                "expired" => Some(ApprovalRequestState::Expired),
                "cancelled" => Some(ApprovalRequestState::Cancelled),
                "escalated" => Some(ApprovalRequestState::Escalated),
                _ => None,
            })
            .ok_or(OperationError::InvalidRequestState)?;

        if current_state != ApprovalRequestState::Pending {
            return Err(OperationError::InvalidRequestState);
        }

        let decision = ApprovalDecision {
            approver_uuid: ident.get_uuid(),
            approver_spn: ident
                .get_user_entry()
                .and_then(|e| e.get_ava_single_proto_string(Attribute::Spn))
                .unwrap_or_default(),
            decision_time: current_time,
            action: match request.action {
                ApprovalDecisionAction::Approve => ApprovalDecisionAction::Approve,
                ApprovalDecisionAction::Reject => ApprovalDecisionAction::Reject,
            },
            comment: request.comment,
        };

        let decision_json =
            serde_json::to_string(&decision).map_err(|_| OperationError::InvalidState)?;

        let new_state = if decision.action == ApprovalDecisionAction::Reject {
            ApprovalRequestState::Rejected
        } else {
            ApprovalRequestState::Approved
        };

        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(request_uuid)));
        let modlist = ModifyList::new_list(vec![
            Modify::Present(
                Attribute::ApprovalDecision,
                Value::Json(
                    serde_json::from_str(&decision_json)
                        .map_err(|_| OperationError::InvalidState)?,
                ),
            ),
            Modify::Purged(Attribute::ApprovalState),
            Modify::Present(
                Attribute::ApprovalState,
                Value::new_iutf8(new_state.as_str()),
            ),
        ]);

        self.internal_modify(&filter, &modlist)
    }

    pub fn approval_request_cancel(
        &mut self,
        ident: &Identity,
        request_uuid: Uuid,
    ) -> Result<(), OperationError> {
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::ApprovalRequest.into()),
            f_eq(Attribute::Uuid, PartialValue::Uuid(request_uuid))
        ]));

        // Kubidm: the requestor may cancel their own request, otherwise this needs
        // approval admin rights.
        let is_requestor = self
            .internal_search(filter.clone())?
            .first()
            .and_then(|e| e.get_ava_single_refer(Attribute::ApprovalRequestor))
            .is_some_and(|requestor| requestor == ident.get_uuid());
        if !(is_requestor && ident.access_scope() == AccessScope::ReadWrite) {
            approval_check_admin(ident, true)?;
        }

        let modlist = ModifyList::new_list(vec![
            Modify::Purged(Attribute::ApprovalState),
            Modify::Present(Attribute::ApprovalState, Value::new_iutf8("cancelled")),
        ]);
        self.internal_modify(&filter, &modlist)
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
        .and_then(|s| match s {
            "any_one" => Some(ApprovalPattern::AnyOne),
            "majority" => Some(ApprovalPattern::Majority),
            "all" => Some(ApprovalPattern::All),
            _ => None,
        })
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
        .filter_map(|s| match s {
            "create_high_privilege_entry" => Some(ApprovalOperationType::CreateHighPrivilegeEntry),
            "delete_high_privilege_entry" => Some(ApprovalOperationType::DeleteHighPrivilegeEntry),
            "modify_high_privilege_entry" => Some(ApprovalOperationType::ModifyHighPrivilegeEntry),
            "credential_reset_high_privilege" => {
                Some(ApprovalOperationType::CredentialResetHighPrivilege)
            }
            "privilege_grant" => Some(ApprovalOperationType::PrivilegeGrant),
            "privilege_revoke" => Some(ApprovalOperationType::PrivilegeRevoke),
            "schema_modify" => Some(ApprovalOperationType::SchemaModify),
            "access_control_modify" => Some(ApprovalOperationType::AccessControlModify),
            "domain_config_modify" => Some(ApprovalOperationType::DomainConfigModify),
            "key_provider_modify" => Some(ApprovalOperationType::KeyProviderModify),
            "sync_account_modify" => Some(ApprovalOperationType::SyncAccountModify),
            "oauth2_client_modify" => Some(ApprovalOperationType::OAuth2ClientModify),
            "application_modify" => Some(ApprovalOperationType::ApplicationModify),
            "group_membership_high_privilege" => {
                Some(ApprovalOperationType::GroupMembershipHighPrivilege)
            }
            _ => None,
        })
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

fn approval_request_from_entry(
    entry: &Entry<EntrySealed, EntryCommitted>,
) -> Result<ApprovalRequest, OperationError> {
    let uuid = entry.get_uuid();

    let policy_uuid = entry
        .get_ava_single_refer(Attribute::ApprovalRequestPolicy)
        .ok_or(OperationError::MissingAttribute(
            Attribute::ApprovalRequestPolicy,
        ))?;

    let operation_type = entry
        .get_ava_single_iutf8(Attribute::ApprovalOperationType)
        .and_then(|s| match s {
            "create_high_privilege_entry" => Some(ApprovalOperationType::CreateHighPrivilegeEntry),
            "delete_high_privilege_entry" => Some(ApprovalOperationType::DeleteHighPrivilegeEntry),
            "modify_high_privilege_entry" => Some(ApprovalOperationType::ModifyHighPrivilegeEntry),
            "credential_reset_high_privilege" => {
                Some(ApprovalOperationType::CredentialResetHighPrivilege)
            }
            "privilege_grant" => Some(ApprovalOperationType::PrivilegeGrant),
            "privilege_revoke" => Some(ApprovalOperationType::PrivilegeRevoke),
            "schema_modify" => Some(ApprovalOperationType::SchemaModify),
            "access_control_modify" => Some(ApprovalOperationType::AccessControlModify),
            "domain_config_modify" => Some(ApprovalOperationType::DomainConfigModify),
            "key_provider_modify" => Some(ApprovalOperationType::KeyProviderModify),
            "sync_account_modify" => Some(ApprovalOperationType::SyncAccountModify),
            "oauth2_client_modify" => Some(ApprovalOperationType::OAuth2ClientModify),
            "application_modify" => Some(ApprovalOperationType::ApplicationModify),
            "group_membership_high_privilege" => {
                Some(ApprovalOperationType::GroupMembershipHighPrivilege)
            }
            _ => None,
        })
        .ok_or(OperationError::InvalidValueState)?;

    let target_uuid = entry
        .get_ava_single_refer(Attribute::ApprovalTarget)
        .ok_or(OperationError::MissingAttribute(Attribute::ApprovalTarget))?;

    let requestor_uuid = entry
        .get_ava_single_refer(Attribute::ApprovalRequestor)
        .ok_or(OperationError::MissingAttribute(
            Attribute::ApprovalRequestor,
        ))?;

    let created_at = entry
        .get_ava_single_datetime(Attribute::CreatedAtCid)
        .ok_or(OperationError::MissingAttribute(Attribute::CreatedAtCid))?;

    let expires_at = entry.get_ava_single_datetime(Attribute::ApprovalExpires);

    let state = entry
        .get_ava_single_iutf8(Attribute::ApprovalState)
        .and_then(|s| match s {
            "pending" => Some(ApprovalRequestState::Pending),
            "approved" => Some(ApprovalRequestState::Approved),
            "rejected" => Some(ApprovalRequestState::Rejected),
            "expired" => Some(ApprovalRequestState::Expired),
            "cancelled" => Some(ApprovalRequestState::Cancelled),
            "escalated" => Some(ApprovalRequestState::Escalated),
            _ => None,
        })
        .ok_or(OperationError::InvalidValueState)?;

    let decisions: Vec<ApprovalDecision> = entry
        .get_ava_set(Attribute::ApprovalDecision)
        .and_then(|vs| vs.as_json_object())
        .and_then(|json| {
            if json.is_array() {
                json.as_array().map(|arr| {
                    arr.iter()
                        .filter_map(|v| serde_json::from_value(v.clone()).ok())
                        .collect()
                })
            } else {
                serde_json::from_value(json.clone()).ok().map(|d| vec![d])
            }
        })
        .unwrap_or_default();

    let escalation_level = entry
        .get_ava_single_uint32(Attribute::ApprovalEscalationLevel)
        .unwrap_or(0);

    let required_decisions = 1;

    let operation_details: BTreeMap<String, String> = entry
        .get_ava_set(Attribute::ApprovalOperationDetails)
        .and_then(|vs| vs.as_json_object())
        .and_then(|json| {
            if json.is_object() {
                json.as_object().map(|obj| {
                    obj.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                        .collect()
                })
            } else {
                None
            }
        })
        .unwrap_or_default();

    Ok(ApprovalRequest {
        uuid,
        policy_uuid,
        policy_name: String::new(),
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
        required_decisions,
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
        ApprovalPolicyCreateRequest,
    };

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
        // NOTE: the approver success path is not exercised here: recording a decision
        // writes a `Value::Json` to `ApprovalDecision`, and there is no valueset for the
        // Json syntax yet, so the decision write itself is not implemented.

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
}
