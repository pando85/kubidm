use crate::{
    handle_client_error, GroupGrantTemporaryOpt, GroupOpt, GroupPosix, KubidmClientParser, OpType,
    OutputMode,
};
use kubidm_proto::constants::ATTR_GIDNUMBER;
use kubidm_proto::v1::TimeBoundedMemberGrant;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

mod account_policy;

impl GroupOpt {
    pub async fn exec(&self, opt: KubidmClientParser) {
        match self {
            GroupOpt::List => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_group_list().await {
                    Ok(r) => match opt.output_mode {
                        OutputMode::Json => {
                            let r_attrs: Vec<_> = r.iter().map(|entry| &entry.attrs).collect();
                            println!(
                                "{}",
                                serde_json::to_string(&r_attrs).expect("Failed to serialise json")
                            );
                        }
                        OutputMode::Text => r.iter().for_each(|ent| println!("{ent}")),
                    },
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            GroupOpt::Search { name } => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_group_search(name).await {
                    Ok(r) => match opt.output_mode {
                        OutputMode::Json => {
                            let r_attrs: Vec<_> = r.iter().map(|entry| &entry.attrs).collect();
                            println!(
                                "{}",
                                serde_json::to_string(&r_attrs).expect("Failed to serialise json")
                            );
                        }
                        OutputMode::Text => r.iter().for_each(|ent| println!("{ent}")),
                    },
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            GroupOpt::Get(gcopt) => {
                let client = opt.to_client(OpType::Read).await;
                // idm_group_get
                match client.idm_group_get(gcopt.name.as_str()).await {
                    Ok(Some(e)) => opt.output_mode.print_message(e),
                    Ok(None) => opt
                        .output_mode
                        .print_message(format!("No matching group '{}'", gcopt.name.as_str())),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            GroupOpt::Create {
                name,
                entry_managed_by,
            } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_group_create(name.as_str(), entry_managed_by.as_deref())
                    .await
                {
                    Err(err) => {
                        error!("Error -> {:?}", err)
                    }
                    Ok(_) => opt
                        .output_mode
                        .print_message(format!("Successfully created group '{}'", name.as_str())),
                }
            }
            GroupOpt::Delete(gcopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_group_delete(gcopt.name.as_str()).await {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully deleted group {}",
                        gcopt.name.as_str()
                    )),
                }
            }
            GroupOpt::PurgeMembers(gcopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_group_purge_members(gcopt.name.as_str()).await {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully purged members of group {}",
                        gcopt.name.as_str()
                    )),
                }
            }
            GroupOpt::ListMembers(gcopt) => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_group_get_members(gcopt.name.as_str()).await {
                    Ok(Some(groups)) => match opt.output_mode {
                        OutputMode::Json => {
                            println!(
                                "{}",
                                serde_json::to_string(&groups)
                                    .expect("Failed to serialise groups to JSON")
                            );
                        }
                        OutputMode::Text => groups.iter().for_each(|m| println!("{m:?}")),
                    },
                    Ok(None) => warn!("No members in group {}", gcopt.name.as_str()),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            GroupOpt::AddMembers(gcopt) => {
                let client = opt.to_client(OpType::Write).await;
                let new_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client
                    .idm_group_add_members(gcopt.name.as_str(), &new_members)
                    .await
                {
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully added {:?} to group \"{}\"",
                        new_members,
                        gcopt.name.as_str()
                    )),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }

            GroupOpt::RemoveMembers(gcopt) => {
                let client = opt.to_client(OpType::Write).await;
                let remove_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client
                    .idm_group_remove_members(gcopt.name.as_str(), &remove_members)
                    .await
                {
                    Err(e) => {
                        error!("Failed to remove members!");
                        handle_client_error(e, opt.output_mode)
                    }
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully removed members from group {}",
                        gcopt.name
                    )),
                }
            }
            GroupOpt::SetMembers(gcopt) => {
                let client = opt.to_client(OpType::Write).await;
                let new_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client
                    .idm_group_set_members(gcopt.name.as_str(), &new_members)
                    .await
                {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully set members for group {}",
                        gcopt.name
                    )),
                }
            }
            GroupOpt::SetMail { name, mail } => {
                let client = opt.to_client(OpType::Write).await;

                let result = if mail.is_empty() {
                    client.idm_group_purge_mail(name.as_str()).await
                } else {
                    client
                        .idm_group_set_mail(name.as_str(), mail.as_slice())
                        .await
                };

                match result {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully set mail for group {}",
                        name.as_str()
                    )),
                }
            }
            GroupOpt::SetDescription { name, description } => {
                let client = opt.to_client(OpType::Write).await;

                let result = if let Some(description) = description {
                    client
                        .idm_group_set_description(name.as_str(), description.as_str())
                        .await
                } else {
                    client.idm_group_purge_description(name.as_str()).await
                };

                match result {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully set description for group {}",
                        name.as_str()
                    )),
                }
            }
            GroupOpt::Rename { name, new_name } => {
                let client = opt.to_client(OpType::Write).await;

                let result = client.group_rename(name.as_str(), new_name.as_str()).await;

                match result {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt
                        .output_mode
                        .print_message(format!("Successfully renamed group {name} to {new_name}")),
                }
            }
            GroupOpt::SetEntryManagedBy {
                name,
                entry_managed_by,
            } => {
                let client = opt.to_client(OpType::Write).await;

                match client
                    .idm_group_set_entry_managed_by(name, entry_managed_by)
                    .await
                {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully set entry manager to '{entry_managed_by}' for group '{name}'"
                    )),
                }
            }
            GroupOpt::Posix { commands } => match commands {
                GroupPosix::Show(gcopt) => {
                    let client = opt.to_client(OpType::Read).await;
                    match client.idm_group_unix_token_get(gcopt.name.as_str()).await {
                        Ok(token) => opt.output_mode.print_message(token),
                        Err(e) => handle_client_error(e, opt.output_mode),
                    }
                }
                GroupPosix::Set(gcopt) => {
                    let client = opt.to_client(OpType::Write).await;
                    match client
                        .idm_group_unix_extend(gcopt.name.as_str(), gcopt.gidnumber)
                        .await
                    {
                        Err(e) => handle_client_error(e, opt.output_mode),
                        Ok(_) => opt.output_mode.print_message(format!(
                            "Success adding POSIX configuration for group {}",
                            gcopt.name
                        )),
                    }
                }
                GroupPosix::ResetGidnumber { group_id } => {
                    let client = opt.to_client(OpType::Write).await;
                    if let Err(e) = client
                        .idm_group_purge_attr(group_id.as_str(), ATTR_GIDNUMBER)
                        .await
                    {
                        handle_client_error(e, opt.output_mode)
                    }
                }
            },
            GroupOpt::AccountPolicy { commands } => commands.exec(opt).await,
            GroupOpt::EnableTemporary { name, max } => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_group_time_bounded_enable(name, *max).await {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully enabled temporary memberships for group {name}"
                    )),
                }
            }
            GroupOpt::GrantTemporary(gopt) => {
                let Some(valid_until) = grant_valid_until(gopt) else {
                    error!("Unable to determine when the membership ends");
                    return;
                };
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_group_time_bounded_member_grant(
                        gopt.name.as_str(),
                        gopt.member.as_str(),
                        gopt.from,
                        valid_until,
                    )
                    .await
                {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully granted {} membership of group {} until {}",
                        gopt.member,
                        gopt.name,
                        format_datetime(&valid_until)
                    )),
                }
            }
            GroupOpt::RevokeTemporary { name, member } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_group_time_bounded_member_revoke(name, member)
                    .await
                {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully revoked the temporary membership of {member} in group {name}"
                    )),
                }
            }
            GroupOpt::ListTemporary(gcopt) => {
                let client = opt.to_client(OpType::Read).await;
                match client
                    .idm_group_time_bounded_member_list(gcopt.name.as_str())
                    .await
                {
                    Ok(grants) => match opt.output_mode {
                        OutputMode::Json => println!(
                            "{}",
                            serde_json::to_string(&grants)
                                .expect("Failed to serialise grants to JSON")
                        ),
                        OutputMode::Text => grants
                            .iter()
                            .for_each(|grant| println!("{}", format_grant(grant))),
                    },
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
        } // end match
    }
}

/// Kubidm: the end of a temporary membership, from `--until`, or `--for` after `--from` (or
/// now).
fn grant_valid_until(gopt: &GroupGrantTemporaryOpt) -> Option<OffsetDateTime> {
    if let Some(until) = gopt.until {
        return Some(until);
    }

    let secs = i64::try_from(gopt.duration?).ok()?;
    #[allow(clippy::disallowed_methods)]
    // Allowed as the grant is relative to the current time on the caller's machine.
    let start = gopt.from.unwrap_or_else(OffsetDateTime::now_utc);
    start.checked_add(time::Duration::seconds(secs))
}

fn format_datetime(odt: &OffsetDateTime) -> String {
    odt.format(&Rfc3339).unwrap_or_else(|_| odt.to_string())
}

fn format_grant(grant: &TimeBoundedMemberGrant) -> String {
    let member = grant
        .member_spn
        .clone()
        .unwrap_or_else(|| grant.member.to_string());
    let from = grant
        .valid_from
        .as_ref()
        .map(format_datetime)
        .unwrap_or_else(|| "-".to_string());
    // A server that predates the state does not send it: show nothing then.
    let state = grant
        .state
        .map(|state| format!(" ({state})"))
        .unwrap_or_default();
    format!(
        "{member}: from {from} until {}{state}",
        format_datetime(&grant.valid_until)
    )
}

#[cfg(test)]
mod tests {
    use super::format_grant;
    use kubidm_proto::v1::{TimeBoundedMemberGrant, TimeBoundedMemberGrantState};
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[test]
    fn format_grant_shows_the_state_when_known() {
        let mut grant = TimeBoundedMemberGrant {
            member: Uuid::nil(),
            member_spn: Some("alice@example.com".to_string()),
            valid_from: None,
            valid_until: OffsetDateTime::UNIX_EPOCH,
            state: Some(TimeBoundedMemberGrantState::Suppressed),
        };
        assert_eq!(
            format_grant(&grant),
            "alice@example.com: from - until 1970-01-01T00:00:00Z (suppressed)"
        );

        // A state from a newer server.
        grant.state = Some(TimeBoundedMemberGrantState::Unknown);
        assert_eq!(
            format_grant(&grant),
            "alice@example.com: from - until 1970-01-01T00:00:00Z (unknown)"
        );

        // A server that predates the state.
        grant.state = None;
        assert_eq!(
            format_grant(&grant),
            "alice@example.com: from - until 1970-01-01T00:00:00Z"
        );
    }
}
