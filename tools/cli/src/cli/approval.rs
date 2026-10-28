use crate::{ApprovalOpt, ApprovalPolicyOpt, ApprovalRequestOpt, KubidmClientParser};
use kubidm_client::KubidmClient;
use kubidm_proto::v1::{
    ApprovalOperationType, ApprovalPattern, ApprovalPolicyCreateRequest,
    ApprovalRequestCreateRequest, ApprovalRequestState,
};
use std::collections::BTreeMap;

impl ApprovalOpt {
    pub async fn exec(&self, opt: KubidmClientParser) {
        let client = opt.to_client(crate::common::OpType::Write).await;
        match self {
            ApprovalOpt::Policy { commands } => commands.exec(&opt, &client).await,
            ApprovalOpt::Request { commands } => commands.exec(&opt, &client).await,
        }
    }
}

impl ApprovalPolicyOpt {
    pub async fn exec(&self, _opt: &KubidmClientParser, client: &KubidmClient) {
        match self {
            ApprovalPolicyOpt::List => {
                let policies = match client.approval_policy_list().await {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Failed to list approval policies: {:?}", e);
                        return;
                    }
                };

                if policies.is_empty() {
                    println!("No approval policies configured");
                    return;
                }

                for policy in policies {
                    println!("Policy: {} ({})", policy.name, policy.uuid);
                    if let Some(desc) = &policy.description {
                        println!("  Description: {}", desc);
                    }
                    println!("  Enabled: {}", policy.enabled);
                    println!("  Pattern: {}", policy.pattern);
                    println!("  Timeout: {}s", policy.timeout_seconds);
                    println!("  Operations: {:?}", policy.operation_types);
                    println!("  Approvers: {:?}", policy.approvers);
                    if !policy.backup_approvers.is_empty() {
                        println!("  Backup Approvers: {:?}", policy.backup_approvers);
                    }
                    println!();
                }
            }
            ApprovalPolicyOpt::Get(named) => {
                let policy = match client.approval_policy_get(&named.name).await {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Failed to get approval policy '{}': {:?}", named.name, e);
                        return;
                    }
                };

                println!("Policy: {} ({})", policy.name, policy.uuid);
                if let Some(desc) = &policy.description {
                    println!("Description: {}", desc);
                }
                println!("Enabled: {}", policy.enabled);
                println!("Pattern: {}", policy.pattern);
                println!("Timeout: {}s", policy.timeout_seconds);
                if let Some(esc_timeout) = policy.escalation_timeout_seconds {
                    println!("Escalation Timeout: {}s", esc_timeout);
                }
                println!("Operations: {:?}", policy.operation_types);
                println!("Approvers: {:?}", policy.approvers);
                println!("Backup Approvers: {:?}", policy.backup_approvers);
            }
            ApprovalPolicyOpt::Create(opts) => {
                let op_types: Vec<ApprovalOperationType> = opts
                    .operation_types
                    .iter()
                    .filter_map(|s| s.parse::<ApprovalOperationType>().ok())
                    .collect();

                if op_types.is_empty() {
                    error!("No valid operation types provided");
                    return;
                }

                let approver_uuids: Vec<uuid::Uuid> = opts
                    .approvers
                    .iter()
                    .filter_map(|s| uuid::Uuid::parse_str(s).ok())
                    .collect();

                if approver_uuids.is_empty() {
                    error!("No valid approver UUIDs provided");
                    return;
                }

                let backup_approver_uuids: Vec<uuid::Uuid> = opts
                    .backup_approvers
                    .iter()
                    .filter_map(|s| uuid::Uuid::parse_str(s).ok())
                    .collect();

                let approval_pattern = match opts.pattern.parse::<ApprovalPattern>() {
                    Ok(p) => p,
                    Err(_) => {
                        error!(
                            "Invalid pattern: {}. Must be 'any_one', 'majority', or 'all'",
                            opts.pattern
                        );
                        return;
                    }
                };

                let request = ApprovalPolicyCreateRequest {
                    name: opts.name.to_string(),
                    description: opts.description.as_deref().map(String::from),
                    operation_types: op_types,
                    approvers: approver_uuids,
                    backup_approvers: backup_approver_uuids,
                    pattern: approval_pattern,
                    timeout_seconds: opts.timeout_seconds,
                    escalation_timeout_seconds: opts.escalation_timeout_seconds,
                };

                match client.approval_policy_create(&request).await {
                    Ok(_) => println!("Approval policy '{}' created successfully", opts.name),
                    Err(e) => error!("Failed to create approval policy '{}': {:?}", opts.name, e),
                }
            }
            ApprovalPolicyOpt::Delete(named) => {
                match client.approval_policy_delete(&named.name).await {
                    Ok(_) => println!("Approval policy '{}' deleted successfully", named.name),
                    Err(e) => error!("Failed to delete approval policy '{}': {:?}", named.name, e),
                }
            }
            ApprovalPolicyOpt::Enable(named) => {
                match client.approval_policy_enable(&named.name).await {
                    Ok(_) => println!("Approval policy '{}' enabled successfully", named.name),
                    Err(e) => error!("Failed to enable approval policy '{}': {:?}", named.name, e),
                }
            }
            ApprovalPolicyOpt::Disable(named) => {
                match client.approval_policy_disable(&named.name).await {
                    Ok(_) => println!("Approval policy '{}' disabled successfully", named.name),
                    Err(e) => error!(
                        "Failed to disable approval policy '{}': {:?}",
                        named.name, e
                    ),
                }
            }
        }
    }
}

/// Shown in place of the policy, target or requester of a request once it is deleted.
const DELETED: &str = "<deleted>";

fn display_uuid(uuid: Option<uuid::Uuid>) -> String {
    uuid.map(|u| u.to_string())
        .unwrap_or_else(|| DELETED.to_string())
}

impl ApprovalRequestOpt {
    pub async fn exec(&self, _opt: &KubidmClientParser, client: &KubidmClient) {
        match self {
            ApprovalRequestOpt::List { state } => {
                let filter_state = match state {
                    Some(s) => s.parse::<ApprovalRequestState>().ok(),
                    None => None,
                };

                if let Some(s) = state {
                    if filter_state.is_none() {
                        warn!("Unknown state filter: {}. Showing all requests.", s);
                    }
                }

                let requests = match client.approval_request_list(filter_state).await {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Failed to list approval requests: {:?}", e);
                        return;
                    }
                };

                if requests.is_empty() {
                    println!("No approval requests found");
                    return;
                }

                for req in requests {
                    println!("Request: {} ({})", req.uuid, req.state);
                    println!(
                        "  Policy: {} ({})",
                        req.policy_name.as_deref().unwrap_or(DELETED),
                        display_uuid(req.policy_uuid)
                    );
                    println!("  Operation: {}", req.operation_type);
                    println!(
                        "  Target: {} ({})",
                        req.target_spn,
                        display_uuid(req.target_uuid)
                    );
                    println!(
                        "  Requestor: {} ({})",
                        req.requestor_spn,
                        display_uuid(req.requestor_uuid)
                    );
                    println!("  Created: {:?}", req.created_at);
                    if let Some(exp) = req.expires_at {
                        println!("  Expires: {:?}", exp);
                    }
                    println!("  Escalation Level: {}", req.escalation_level);
                    let approve_count = req
                        .decisions
                        .iter()
                        .filter(|d| d.action == kubidm_proto::v1::ApprovalDecisionAction::Approve)
                        .count();
                    let reject_count = req
                        .decisions
                        .iter()
                        .filter(|d| d.action == kubidm_proto::v1::ApprovalDecisionAction::Reject)
                        .count();
                    println!(
                        "  Decisions: {} approve, {} reject",
                        approve_count, reject_count
                    );
                    println!();
                }
            }
            ApprovalRequestOpt::Get(named) => {
                let req = match client.approval_request_get(&named.uuid).await {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Failed to get approval request '{}': {:?}", named.uuid, e);
                        return;
                    }
                };

                println!("Request: {} ({})", req.uuid, req.state);
                println!(
                    "Policy: {} ({})",
                    req.policy_name.as_deref().unwrap_or(DELETED),
                    display_uuid(req.policy_uuid)
                );
                println!("Operation: {}", req.operation_type);
                println!(
                    "Target: {} ({})",
                    req.target_spn,
                    display_uuid(req.target_uuid)
                );
                println!(
                    "Requestor: {} ({})",
                    req.requestor_spn,
                    display_uuid(req.requestor_uuid)
                );
                println!("Created: {:?}", req.created_at);
                if let Some(exp) = req.expires_at {
                    println!("Expires: {:?}", exp);
                }
                println!("Escalation Level: {}", req.escalation_level);
                println!("Required Decisions: {}", req.required_decisions);
                println!("Operation Details: {:?}", req.operation_details);
                println!("Decisions:");
                for dec in &req.decisions {
                    println!(
                        "  - {} ({}): {:?} at {:?}",
                        dec.approver_spn, dec.approver_uuid, dec.action, dec.decision_time
                    );
                    if let Some(c) = &dec.comment {
                        println!("    Comment: {}", c);
                    }
                }
            }
            ApprovalRequestOpt::Create(opts) => {
                let operation_type = match opts.operation.parse::<ApprovalOperationType>() {
                    Ok(o) => o,
                    Err(_) => {
                        error!("Invalid operation type: {}", opts.operation);
                        return;
                    }
                };

                let operation_details = match opts.details.as_deref() {
                    Some(details) => {
                        match serde_json::from_str::<BTreeMap<String, String>>(details) {
                            Ok(d) => d,
                            Err(e) => {
                                error!(
                                    "Invalid --details, expected a JSON object of string values: {}",
                                    e
                                );
                                return;
                            }
                        }
                    }
                    None => BTreeMap::new(),
                };

                let request = ApprovalRequestCreateRequest {
                    policy_name: opts.policy.to_string(),
                    operation_type,
                    target: opts.target.to_string(),
                    operation_details,
                };

                match client.approval_request_create(&request).await {
                    Ok(uuid) => println!("Approval request {} created successfully", uuid),
                    Err(e) => error!("Failed to create approval request: {:?}", e),
                }
            }
            ApprovalRequestOpt::Approve(opts) => {
                match client
                    .approval_request_approve(&opts.uuid, opts.comment.as_deref())
                    .await
                {
                    Ok(_) => println!("Approval request '{}' approved successfully", opts.uuid),
                    Err(e) => error!("Failed to approve request '{}': {:?}", opts.uuid, e),
                }
            }
            ApprovalRequestOpt::Reject(opts) => {
                match client
                    .approval_request_reject(&opts.uuid, opts.comment.as_deref())
                    .await
                {
                    Ok(_) => println!("Approval request '{}' rejected successfully", opts.uuid),
                    Err(e) => error!("Failed to reject request '{}': {:?}", opts.uuid, e),
                }
            }
            ApprovalRequestOpt::Cancel(named) => {
                match client.approval_request_cancel(&named.uuid).await {
                    Ok(_) => println!("Approval request '{}' cancelled successfully", named.uuid),
                    Err(e) => error!("Failed to cancel request '{}': {:?}", named.uuid, e),
                }
            }
        }
    }
}
