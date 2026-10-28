//! Kubidm: template driven delegated administration.

use crate::{handle_client_error, DelegationOpt, KubidmClientParser, OpType, OutputMode};
use kubidm_proto::internal::Filter as ProtoFilter;
use kubidm_proto::v1::{DelegationGrant, DelegationGroup};

fn print_grant(output_mode: OutputMode, grant: &DelegationGrant) {
    match output_mode {
        OutputMode::Json => println!(
            "{}",
            serde_json::to_string(grant).unwrap_or_else(|_| format!("{grant:?}"))
        ),
        OutputMode::Text => {
            let group = |group: &DelegationGroup| {
                group.spn.clone().unwrap_or_else(|| group.uuid.to_string())
            };
            println!("name: {}", grant.name);
            println!("uuid: {}", grant.uuid);
            println!(
                "template: {}",
                grant.template.as_deref().unwrap_or("(unknown)")
            );
            for receiver in grant.receivers.iter() {
                println!("receiver: {}", group(receiver));
            }
            println!(
                "scope: {}",
                grant
                    .scope
                    .as_ref()
                    .map(group)
                    .unwrap_or_else(|| "(deleted)".to_string())
            );
            if let Some(filter) = &grant.filter {
                println!(
                    "filter: {}",
                    serde_json::to_string(filter).unwrap_or_else(|_| format!("{filter:?}"))
                );
            }
            println!(
                "delegated by: {}",
                grant
                    .delegated_by
                    .as_ref()
                    .map(group)
                    .unwrap_or_else(|| "(deleted)".to_string())
            );
            for drift in grant.drift.iter() {
                println!("drift: {drift}");
            }
            println!("enabled: {}", grant.enabled);
        }
    }
}

impl DelegationOpt {
    pub async fn exec(&self, opt: KubidmClientParser) {
        match self {
            DelegationOpt::List => {
                let client = opt.to_client(OpType::Read).await;
                match client.delegation_list().await {
                    Ok(grants) => match opt.output_mode {
                        OutputMode::Json => println!(
                            "{}",
                            serde_json::to_string(&grants)
                                .unwrap_or_else(|_| format!("{grants:?}"))
                        ),
                        OutputMode::Text => {
                            if grants.is_empty() {
                                println!("No delegations");
                            }
                            for grant in grants.iter() {
                                print_grant(opt.output_mode, grant);
                                println!();
                            }
                        }
                    },
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            DelegationOpt::Get(named) => {
                let client = opt.to_client(OpType::Read).await;
                match client.delegation_get(&named.name).await {
                    Ok(grant) => print_grant(opt.output_mode, &grant),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            DelegationOpt::Grant(grant_opt) => {
                let filter = match grant_opt
                    .filter
                    .as_deref()
                    .map(serde_json::from_str::<ProtoFilter>)
                    .transpose()
                {
                    Ok(filter) => filter,
                    Err(e) => {
                        error!("Invalid --filter, expected a JSON filter: {:?}", e);
                        std::process::exit(1);
                    }
                };
                let client = opt.to_client(OpType::Write).await;
                match client
                    .delegation_grant(
                        &grant_opt.template,
                        &grant_opt.receiver,
                        &grant_opt.scope,
                        filter,
                    )
                    .await
                {
                    Ok(grant) => print_grant(opt.output_mode, &grant),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            DelegationOpt::Revoke(named) => {
                let client = opt.to_client(OpType::Write).await;
                match client.delegation_revoke(&named.name).await {
                    Ok(()) => opt
                        .output_mode
                        .print_message(format!("Revoked delegation {}", named.name)),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
        }
    }
}
