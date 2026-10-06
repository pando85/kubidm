use super::utils::check_time_restriction;
use super::{
    migration::{MIGRATION_ENTRY_CLASSES, MIGRATION_IGNORE_CLASSES},
    profiles::{
        AccessControlReceiverCondition, AccessControlSearchResolved, AccessControlTargetCondition,
    },
    AccessSrchResult,
};
use crate::prelude::*;
use std::{collections::BTreeSet, ops::Sub, sync::Arc};

pub enum SearchResult {
    Deny,
    Grant,
    Allow(BTreeSet<Attribute>),
    #[allow(dead_code)]
    ReauthRequired {
        reason: String,
    },
}

pub fn apply_search_access(
    ident: &Identity,
    related_acp: &[AccessControlSearchResolved],
    entry: &Arc<EntrySealedCommitted>,
) -> SearchResult {
    // This could be considered "slow" due to allocs each iter with the entry. We
    // could move these out of the loop and reuse, but there are likely risks to
    // that.
    let mut denied = false;
    let mut grant = false;
    let constrain = BTreeSet::default();
    let mut allow = BTreeSet::new();
    let mut reauth_required: Option<String> = None;

    // The access control profile
    match search_filter_entry(ident, related_acp, entry) {
        AccessSrchResult::Deny => denied = true,
        AccessSrchResult::Grant => grant = true,
        AccessSrchResult::Ignore => {}
        // AccessSrchResult::Constrain { mut attr } => constrain.append(&mut attr),
        AccessSrchResult::Allow { mut attr } => allow.append(&mut attr),
        AccessSrchResult::ReauthRequired { reason } => {
            reauth_required = Some(reason);
        }
    };

    match search_oauth2_filter_entry(ident, entry) {
        AccessSrchResult::Deny => denied = true,
        AccessSrchResult::Grant => grant = true,
        AccessSrchResult::Ignore => {}
        // AccessSrchResult::Constrain { mut attr } => constrain.append(&mut attr),
        AccessSrchResult::Allow { mut attr } => allow.append(&mut attr),
        AccessSrchResult::ReauthRequired { reason } => {
            reauth_required = Some(reason);
        }
    };

    match search_applications_filter_entry(ident, entry) {
        AccessSrchResult::Deny => denied = true,
        AccessSrchResult::Grant => grant = true,
        AccessSrchResult::Ignore => {}
        // AccessSrchResult::Constrain { mut attr } => constrain.append(&mut attr),
        AccessSrchResult::Allow { mut attr } => allow.append(&mut attr),
        AccessSrchResult::ReauthRequired { reason } => {
            reauth_required = Some(reason);
        }
    };

    match search_sync_account_filter_entry(ident, entry) {
        AccessSrchResult::Deny => denied = true,
        AccessSrchResult::Grant => grant = true,
        AccessSrchResult::Ignore => {}
        // AccessSrchResult::Constrain{ mut attr } => constrain.append(&mut attr),
        AccessSrchResult::Allow { mut attr } => allow.append(&mut attr),
        AccessSrchResult::ReauthRequired { reason } => {
            reauth_required = Some(reason);
        }
    };

    // We'll add more modules later.

    // Now finalise the decision.

    if denied {
        SearchResult::Deny
    } else if grant {
        SearchResult::Grant
    } else if let Some(reason) = reauth_required {
        SearchResult::ReauthRequired { reason }
    } else {
        let allowed_attrs = if !constrain.is_empty() {
            // bit_and
            &constrain & &allow
        } else {
            allow
        };
        SearchResult::Allow(allowed_attrs)
    }
}

fn search_filter_entry(
    ident: &Identity,
    related_acp: &[AccessControlSearchResolved],
    entry: &Arc<EntrySealedCommitted>,
) -> AccessSrchResult {
    // If this is an internal search, return our working set.
    match &ident.origin {
        IdentType::Internal(InternalRole::System) => {
            trace!(uuid = ?entry.get_display_id(), "Internal operation, bypassing access check");
            // No need to check ACS
            return AccessSrchResult::Grant;
        }
        IdentType::Internal(InternalRole::AccountRequest) => {
            trace!(uuid = ?entry.get_display_id(), "Account Request");

            let valid_account_request_class = entry
                .get_ava_as_iutf8(Attribute::Class)
                .map(|classes| {
                    trace!(?classes);
                    classes.contains(&EntryClass::Account.to_string())
                })
                .unwrap_or(false);

            if valid_account_request_class {
                trace!("grant");
                return AccessSrchResult::Grant;
            } else {
                trace!("deny");
                return AccessSrchResult::Deny;
            }
        }
        IdentType::Internal(InternalRole::Migration) => {
            trace!(uuid = ?entry.get_display_id(), "Internal migration");

            let valid_migration_class = entry
                .get_ava_as_iutf8(Attribute::Class)
                .map(|classes| {
                    trace!(?classes);
                    let classes = classes.sub(&MIGRATION_IGNORE_CLASSES);
                    classes.is_subset(&MIGRATION_ENTRY_CLASSES)
                })
                .unwrap_or(false);

            if valid_migration_class {
                // Can proceed.
                trace!("grant");
                return AccessSrchResult::Grant;
            } else {
                trace!("deny");
                return AccessSrchResult::Deny;
            }
        }
        IdentType::Internal(InternalRole::MessageQueue) => {
            security_debug!(uuid = ?entry.get_display_id(), "Blocking message queue check");
            return AccessSrchResult::Deny;
        }
        IdentType::Synch(_) => {
            security_debug!(uuid = ?entry.get_display_id(), "Blocking sync check");
            return AccessSrchResult::Deny;
        }
        IdentType::User(_) => {}
    };
    debug!(event = %ident, "Access check for search (filter) event");

    match ident.access_scope() {
        AccessScope::Synchronise => {
            security_debug!(
                "denied ❌ - identity access scope 'Synchronise' is not permitted to search"
            );
            return AccessSrchResult::Deny;
        }
        AccessScope::ReadOnly | AccessScope::ReadWrite => {
            // As you were
        }
    };

    // needed for checking entry manager conditions.
    let ident_memberof = ident.get_memberof();
    let ident_uuid = ident.get_uuid();

    let acp_results: Vec<(BTreeSet<Attribute>, bool, Option<u32>)> = related_acp
        .iter()
        .filter_map(|acs| {
            // Assert that the receiver condition applies.
            match &acs.receiver_condition {
                AccessControlReceiverCondition::GroupChecked => {
                    // The groups were already checked during filter resolution. Trust
                    // that result, and continue.
                }
                AccessControlReceiverCondition::EntryManager => {
                    // This condition relies on the entry we are looking at to have a back-ref
                    // to our uuid or a group we are in as an entry manager.

                    // Note, while schema has this as single value, we currently
                    // fetch it as a multivalue btreeset for future in case we allow
                    // multiple entry manager by in future.
                    {
                        let entry_manager_uuids = entry.get_ava_refer(Attribute::EntryManagedBy)?;
                        let group_check = ident_memberof
                            // Have at least one group allowed.
                            .map(|imo| imo.intersection(entry_manager_uuids).next().is_some())
                            .unwrap_or_default();

                        let user_check =
                            entry_manager_uuids.contains(&ident_uuid);

                        if !(group_check || user_check) {
                            // Not the entry manager
                            return None
                        }
                    }
                }
                AccessControlReceiverCondition::Delegated { scope_filter_resolved } => {
                    // Check if the entry matches the delegated scope filter
                    if let Some(filter) = scope_filter_resolved {
                        if !entry.entry_match_no_index(filter) {
                            debug!(entry = ?entry.get_display_id(), acs = %acs.acp.acp.name, "entry DOES NOT match delegated scope filter");
                            return None
                        }
                    }
                }
            };

            match &acs.target_condition {
                AccessControlTargetCondition::Scope(f_res) => {
                    if !entry.entry_match_no_index(f_res) {
                        debug!(entry = ?entry.get_display_id(), acs = %acs.acp.acp.name, action="search_filter", "entry DOES NOT match acs");
                        return None
                    }
                }
                AccessControlTargetCondition::DelegatedScope { scope_filter_resolved } => {
                    // Check if the entry matches the delegated scope filter
                    if let Some(filter) = scope_filter_resolved {
                        if !entry.entry_match_no_index(filter) {
                            debug!(entry = ?entry.get_display_id(), acs = %acs.acp.acp.name, "entry DOES NOT match delegated scope filter");
                            return None
                        }
                    }
                }
            };

            // Check time restrictions
            if !check_time_restriction(
                acs.acp.acp.time_restriction_start,
                acs.acp.acp.time_restriction_end,
            ) {
                debug!(entry = ?entry.get_display_id(), acs = %acs.acp.acp.name, "time restriction not satisfied");
                return None;
            }

            // -- Conditions pass -- release the attributes.
            debug!(entry = ?entry.get_display_id(), acs = %acs.acp.acp.name, "acs applied to entry");
            // add search_attrs to allowed.
            Some((acs.acp.attrs.clone(), acs.acp.acp.require_reauth, acs.acp.acp.reauth_max_age))
        })
        .collect();

    // Check if any ACP requires reauth
    let any_requires_reauth = acp_results.iter().any(|(_, req_reauth, _)| *req_reauth);

    if any_requires_reauth && !matches!(ident.access_scope(), AccessScope::ReadWrite) {
        return AccessSrchResult::ReauthRequired {
            reason:
                "This operation requires elevated privileges. Please re-authenticate to continue."
                    .to_string(),
        };
    }

    let allowed_attrs: BTreeSet<Attribute> = acp_results
        .into_iter()
        .flat_map(|(a, _, _)| a.into_iter())
        .collect();

    AccessSrchResult::Allow {
        attr: allowed_attrs,
    }
}

fn search_oauth2_filter_entry(
    ident: &Identity,
    entry: &Arc<EntrySealedCommitted>,
) -> AccessSrchResult {
    match &ident.origin {
        IdentType::Internal(_) | IdentType::Synch(_) => AccessSrchResult::Ignore,
        IdentType::User(iuser) => {
            if iuser.entry.get_uuid() == UUID_ANONYMOUS {
                debug!("Anonymous can't access OAuth2 entries, ignoring");
                return AccessSrchResult::Ignore;
            }

            let contains_o2_rs = entry
                .get_ava_as_iutf8(Attribute::Class)
                .map(|set| {
                    trace!(?set);
                    set.contains(&EntryClass::OAuth2ResourceServer.to_string())
                })
                .unwrap_or(false);

            let contains_o2_scope_member = entry
                .get_ava_as_oauthscopemaps(Attribute::OAuth2RsScopeMap)
                .zip(ident.get_memberof())
                .map(|(maps, mo)| maps.keys().any(|k| mo.contains(k)))
                .unwrap_or(false);

            if contains_o2_rs && contains_o2_scope_member {
                security_debug!(entry = ?entry.get_uuid(), ident = ?iuser.entry.get_uuid2rdn(), "ident is a memberof a group granted an oauth2 scope by this entry");

                return AccessSrchResult::Allow {
                    attr: btreeset!(
                        Attribute::Class,
                        Attribute::DisplayName,
                        Attribute::Uuid,
                        Attribute::Name,
                        Attribute::OAuth2RsOriginLanding,
                        Attribute::Image
                    ),
                };
            }
            AccessSrchResult::Ignore
        }
    }
}

fn search_applications_filter_entry(
    ident: &Identity,
    entry: &Arc<EntrySealedCommitted>,
) -> AccessSrchResult {
    match &ident.origin {
        IdentType::Internal(_) | IdentType::Synch(_) => AccessSrchResult::Ignore,
        IdentType::User(iuser) => {
            if iuser.entry.get_uuid() == UUID_ANONYMOUS {
                debug!("Anonymous can't access application entries, ignoring");
                return AccessSrchResult::Ignore;
            }

            let contains_application = entry
                .get_ava_as_iutf8(Attribute::Class)
                .map(|set| {
                    trace!(?set);
                    set.contains(&EntryClass::Application.to_string())
                })
                .unwrap_or(false);

            let contains_application_linked_group = entry
                .get_ava_single_refer(Attribute::LinkedGroup)
                .and_then(|group_uuid| ident.get_memberof().map(|mo| mo.contains(&group_uuid)))
                .unwrap_or(false);

            trace!(?entry);

            if contains_application && contains_application_linked_group {
                security_debug!(entry = ?entry.get_uuid(), ident = ?iuser.entry.get_uuid2rdn(), "ident is a memberof a group granted application access for this entry");

                return AccessSrchResult::Allow {
                    attr: btreeset!(
                        Attribute::Class,
                        Attribute::DisplayName,
                        Attribute::Uuid,
                        Attribute::Name,
                        Attribute::LinkedGroup
                    ),
                };
            }
            AccessSrchResult::Ignore
        }
    }
}

fn search_sync_account_filter_entry(
    ident: &Identity,
    entry: &Arc<EntrySealedCommitted>,
) -> AccessSrchResult {
    match &ident.origin {
        IdentType::Internal(_) | IdentType::Synch(_) => AccessSrchResult::Ignore,
        IdentType::User(iuser) => {
            // Is the user a synced object?
            let is_user_sync_account = iuser
                .entry
                .get_ava_as_iutf8(Attribute::Class)
                .map(|set| {
                    trace!(?set);
                    set.contains(EntryClass::SyncObject.into())
                        && set.contains(EntryClass::Account.into())
                })
                .unwrap_or(false);

            if is_user_sync_account {
                let is_target_sync_account = entry
                    .get_ava_as_iutf8(Attribute::Class)
                    .map(|set| {
                        trace!(?set);
                        set.contains(&EntryClass::SyncAccount.to_string())
                    })
                    .unwrap_or(false);

                if is_target_sync_account {
                    // Okay, now we need to check if the uuids line up.
                    let sync_uuid = entry.get_uuid();
                    let sync_source_match = iuser
                        .entry
                        .get_ava_single_refer(Attribute::SyncParentUuid)
                        .map(|sync_parent_uuid| sync_parent_uuid == sync_uuid)
                        .unwrap_or(false);

                    if sync_source_match {
                        // We finally got here!
                        security_debug!(entry = ?entry.get_uuid(), ident = ?iuser.entry.get_uuid2rdn(), "ident is a synchronised account from this sync account");

                        return AccessSrchResult::Allow {
                            attr: btreeset!(
                                Attribute::Class,
                                Attribute::Uuid,
                                Attribute::SyncCredentialPortal
                            ),
                        };
                    }
                }
            }
            // Fall through
            AccessSrchResult::Ignore
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::identity::Identity;

    fn make_user_ident_rw() -> Identity {
        let entry = Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("testuser")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("00000000-0000-0000-0000-000000000001"))
                )
            )
            .into_sealed_committed(),
        );
        Identity::from_impersonate_entry_readwrite(entry)
    }

    fn make_user_ident_ro() -> Identity {
        let entry = Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("testuser")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("00000000-0000-0000-0000-000000000001"))
                )
            )
            .into_sealed_committed(),
        );
        Identity::from_impersonate_entry_readonly(entry)
    }

    fn make_sealed_entry(class: &str, uuid: Uuid) -> Arc<EntrySealedCommitted> {
        Arc::new(
            entry_init!(
                (Attribute::Class, Value::new_iutf8(class)),
                (Attribute::Uuid, Value::Uuid(uuid))
            )
            .into_sealed_committed(),
        )
    }

    #[test]
    fn test_search_filter_entry_internal_system_grants() {
        let ident = Identity::from_internal();
        let entry = make_sealed_entry(
            "account",
            uuid::uuid!("00000000-0000-0000-0000-000000000100"),
        );
        let acps: Vec<AccessControlSearchResolved> = vec![];
        let result = search_filter_entry(&ident, &acps, &entry);
        assert!(matches!(result, AccessSrchResult::Grant));
    }

    #[test]
    fn test_search_filter_entry_migration_with_valid_class_grants() {
        let ident = Identity::migration();
        let entry = make_sealed_entry(
            "account",
            uuid::uuid!("00000000-0000-0000-0000-000000000100"),
        );
        let acps: Vec<AccessControlSearchResolved> = vec![];
        let result = search_filter_entry(&ident, &acps, &entry);
        assert!(matches!(result, AccessSrchResult::Grant));
    }

    #[test]
    fn test_search_filter_entry_migration_with_invalid_class_denied() {
        let ident = Identity::migration();
        let entry = make_sealed_entry(
            "tombstone",
            uuid::uuid!("00000000-0000-0000-0000-000000000100"),
        );
        let acps: Vec<AccessControlSearchResolved> = vec![];
        let result = search_filter_entry(&ident, &acps, &entry);
        assert!(matches!(result, AccessSrchResult::Deny));
    }

    #[test]
    fn test_search_filter_entry_migration_no_class_denied() {
        let ident = Identity::migration();
        let entry = Arc::new(
            entry_init!((
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("00000000-0000-0000-0000-000000000100"))
            ))
            .into_sealed_committed(),
        );
        let acps: Vec<AccessControlSearchResolved> = vec![];
        let result = search_filter_entry(&ident, &acps, &entry);
        assert!(matches!(result, AccessSrchResult::Deny));
    }

    #[test]
    fn test_search_filter_entry_user_synchronise_denied() {
        let entry = Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("testuser")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("00000000-0000-0000-0000-000000000001"))
                )
            )
            .into_sealed_committed(),
        );
        let ident = Identity::from_impersonate_entry_readwrite(entry)
            .project_with_scope(AccessScope::Synchronise);
        let target = make_sealed_entry(
            "account",
            uuid::uuid!("00000000-0000-0000-0000-000000000100"),
        );
        let acps: Vec<AccessControlSearchResolved> = vec![];
        let result = search_filter_entry(&ident, &acps, &target);
        assert!(matches!(result, AccessSrchResult::Deny));
    }

    #[test]
    fn test_search_filter_entry_user_readonly_no_acps_empty_allow() {
        let ident = make_user_ident_ro();
        let entry = make_sealed_entry(
            "account",
            uuid::uuid!("00000000-0000-0000-0000-000000000100"),
        );
        let acps: Vec<AccessControlSearchResolved> = vec![];
        let result = search_filter_entry(&ident, &acps, &entry);
        match result {
            AccessSrchResult::Allow { attr } => assert!(attr.is_empty()),
            _ => panic!("Expected Allow with empty attrs"),
        }
    }

    #[test]
    fn test_search_filter_entry_user_rw_no_acps_empty_allow() {
        let ident = make_user_ident_rw();
        let entry = make_sealed_entry(
            "account",
            uuid::uuid!("00000000-0000-0000-0000-000000000100"),
        );
        let acps: Vec<AccessControlSearchResolved> = vec![];
        let result = search_filter_entry(&ident, &acps, &entry);
        match result {
            AccessSrchResult::Allow { attr } => assert!(attr.is_empty()),
            _ => panic!("Expected Allow with empty attrs"),
        }
    }

    #[test]
    fn test_search_oauth2_filter_entry_internal_ignores() {
        let ident = Identity::from_internal();
        let entry = make_sealed_entry(
            "oauth2_resource_server",
            uuid::uuid!("00000000-0000-0000-0000-000000000100"),
        );
        let result = search_oauth2_filter_entry(&ident, &entry);
        assert!(matches!(result, AccessSrchResult::Ignore));
    }

    #[test]
    fn test_search_applications_filter_entry_internal_ignores() {
        let ident = Identity::from_internal();
        let entry = make_sealed_entry(
            "application",
            uuid::uuid!("00000000-0000-0000-0000-000000000100"),
        );
        let result = search_applications_filter_entry(&ident, &entry);
        assert!(matches!(result, AccessSrchResult::Ignore));
    }

    #[test]
    fn test_search_sync_account_filter_entry_internal_ignores() {
        let ident = Identity::from_internal();
        let entry = make_sealed_entry(
            "sync_account",
            uuid::uuid!("00000000-0000-0000-0000-000000000100"),
        );
        let result = search_sync_account_filter_entry(&ident, &entry);
        assert!(matches!(result, AccessSrchResult::Ignore));
    }

    #[test]
    fn test_apply_search_access_internal_system_grants() {
        let ident = Identity::from_internal();
        let entry = make_sealed_entry(
            "account",
            uuid::uuid!("00000000-0000-0000-0000-000000000100"),
        );
        let acps: Vec<AccessControlSearchResolved> = vec![];
        let result = apply_search_access(&ident, &acps, &entry);
        assert!(matches!(result, SearchResult::Grant));
    }

    #[test]
    fn test_apply_search_access_user_no_acps_empty_allow() {
        let ident = make_user_ident_rw();
        let entry = make_sealed_entry(
            "account",
            uuid::uuid!("00000000-0000-0000-0000-000000000100"),
        );
        let acps: Vec<AccessControlSearchResolved> = vec![];
        let result = apply_search_access(&ident, &acps, &entry);
        match result {
            SearchResult::Allow(attrs) => assert!(attrs.is_empty()),
            _ => panic!("Expected Allow with empty attrs"),
        }
    }
}
