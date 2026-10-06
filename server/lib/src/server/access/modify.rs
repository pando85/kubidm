use super::utils::check_time_restriction;
use super::{
    migration::{migration_entry_attrs, MIGRATION_ENTRY_CLASSES, MIGRATION_IGNORE_CLASSES},
    profiles::{
        AccessControlModify, AccessControlModifyResolved, AccessControlReceiverCondition,
        AccessControlTargetCondition,
    },
    protected::{
        LOCKED_ENTRY_CLASSES, PROTECTED_MOD_ENTRY_CLASSES, PROTECTED_MOD_PRES_ENTRY_CLASSES,
        PROTECTED_MOD_REM_ENTRY_CLASSES,
    },
    AccessBasicResult, AccessModResult,
};
use crate::prelude::*;
use hashbrown::HashMap;
use std::{collections::BTreeSet, ops::Sub, sync::Arc};

pub enum ModifyResult<'a> {
    Deny,
    Grant,
    Allow {
        pres: BTreeSet<Attribute>,
        rem: BTreeSet<Attribute>,
        pres_cls: BTreeSet<&'a str>,
        rem_cls: BTreeSet<&'a str>,
    },
    #[allow(dead_code)]
    ReauthRequired {
        reason: String,
    },
}

pub fn apply_modify_access<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlModifyResolved],
    sync_agreements: &HashMap<Uuid, BTreeSet<Attribute>>,
    entry: &Arc<EntrySealedCommitted>,
) -> ModifyResult<'a> {
    let mut denied = false;
    let mut grant = false;

    let mut constrain_pres = BTreeSet::default();
    let mut allow_pres = BTreeSet::default();
    let mut constrain_rem = BTreeSet::default();
    let mut allow_rem = BTreeSet::default();

    let mut constrain_pres_cls = BTreeSet::default();
    let mut allow_pres_cls = BTreeSet::default();

    let mut constrain_rem_cls = BTreeSet::default();
    let mut allow_rem_cls = BTreeSet::default();

    // Some useful references.
    //  - needed for checking entry manager conditions.
    let ident_memberof = ident.get_memberof();
    let ident_uuid = ident.get_uuid();

    // run each module. These have to be broken down further due to modify
    // kind of being three operations all in one.

    match modify_ident_test(ident) {
        AccessBasicResult::Deny => denied = true,
        AccessBasicResult::Grant => grant = true,
        AccessBasicResult::Ignore => {}
    }

    // Check with protected if we should proceed.
    match modify_migration_attrs(ident, entry) {
        AccessModResult::Deny => denied = true,
        AccessModResult::Allow {
            mut pres_attr,
            mut rem_attr,
            mut pres_class,
            mut rem_class,
        } => {
            allow_pres.append(&mut pres_attr);
            allow_rem.append(&mut rem_attr);
            allow_pres_cls.append(&mut pres_class);
            allow_rem_cls.append(&mut rem_class);
        }
        AccessModResult::Constrain { .. }
        | AccessModResult::Ignore
        | AccessModResult::ReauthRequired { .. } => {}
    }

    // Check with protected if we should proceed.
    match modify_protected_attrs(ident, entry) {
        AccessModResult::Deny => denied = true,
        AccessModResult::Constrain {
            mut pres_attr,
            mut rem_attr,
            pres_cls,
            rem_cls,
        } => {
            constrain_rem.append(&mut rem_attr);
            constrain_pres.append(&mut pres_attr);

            if let Some(mut pres_cls) = pres_cls {
                constrain_pres_cls.append(&mut pres_cls);
            }

            if let Some(mut rem_cls) = rem_cls {
                constrain_rem_cls.append(&mut rem_cls);
            }
        }
        // Can't grant.
        // AccessModResult::Grant |
        // Can't allow
        AccessModResult::Allow { .. }
        | AccessModResult::Ignore
        | AccessModResult::ReauthRequired { .. } => {}
    }

    if !grant && !denied {
        // If it's a sync entry, constrain it.
        match modify_sync_constrain(ident, entry, sync_agreements) {
            AccessModResult::Deny => denied = true,
            AccessModResult::Constrain {
                mut pres_attr,
                mut rem_attr,
                ..
            } => {
                constrain_rem.append(&mut rem_attr);
                constrain_pres.append(&mut pres_attr);
            }
            // Can't grant.
            // AccessModResult::Grant |
            // Can't allow
            AccessModResult::Allow { .. }
            | AccessModResult::Ignore
            | AccessModResult::ReauthRequired { .. } => {}
        }

        // Setup the acp's here
        let scoped_acp: Vec<&AccessControlModify> = related_acp
            .iter()
            .filter_map(|acm| {
                match &acm.receiver_condition {
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
                                return None;
                            }
                        }
                    }
                    AccessControlReceiverCondition::Delegated { scope_filter_resolved } => {
                        // Check if the entry matches the delegated scope filter
                        if let Some(filter) = scope_filter_resolved {
                            if !entry.entry_match_no_index(filter) {
                                debug!(entry = ?entry.get_display_id(), acm = %acm.acp.acp.name, "entry DOES NOT match delegated scope filter");
                                return None;
                            }
                        }
                    }
                };

                match &acm.target_condition {
                    AccessControlTargetCondition::Scope(f_res) => {
                        if !entry.entry_match_no_index(f_res) {
                            debug!(entry = ?entry.get_display_id(), acm = %acm.acp.acp.name, "entry DOES NOT match acs");
                            return None;
                        }
                    }
                    AccessControlTargetCondition::DelegatedScope { scope_filter_resolved } => {
                        // Check if the entry matches the delegated scope filter
                        if let Some(filter) = scope_filter_resolved {
                            if !entry.entry_match_no_index(filter) {
                                debug!(entry = ?entry.get_display_id(), acm = %acm.acp.acp.name, "entry DOES NOT match delegated scope filter");
                                return None;
                            }
                        }
                    }
                };

                // Check time restrictions
                if !check_time_restriction(
                    acm.acp.acp.time_restriction_start,
                    acm.acp.acp.time_restriction_end,
                ) {
                    debug!(entry = ?entry.get_display_id(), acm = %acm.acp.acp.name, "time restriction not satisfied");
                    return None;
                }

                debug!(entry = ?entry.get_display_id(), acs = %acm.acp.acp.name, "acs applied to entry");

                Some(acm.acp)
            })
            .collect();

        match modify_pres_test(scoped_acp.as_slice()) {
            AccessModResult::Deny => denied = true,
            // Can never return a unilateral grant.
            // AccessModResult::Grant => {}
            AccessModResult::Ignore => {}
            AccessModResult::Constrain { .. } => {}
            AccessModResult::Allow {
                mut pres_attr,
                mut rem_attr,
                mut pres_class,
                mut rem_class,
            } => {
                allow_pres.append(&mut pres_attr);
                allow_rem.append(&mut rem_attr);
                allow_pres_cls.append(&mut pres_class);
                allow_rem_cls.append(&mut rem_class);
            }
            AccessModResult::ReauthRequired { .. } => {}
        }
    }

    if denied {
        ModifyResult::Deny
    } else if grant {
        ModifyResult::Grant
    } else {
        let allowed_pres = if !constrain_pres.is_empty() {
            // bit_and
            &constrain_pres & &allow_pres
        } else {
            allow_pres
        };

        let allowed_rem = if !constrain_rem.is_empty() {
            // bit_and
            &constrain_rem & &allow_rem
        } else {
            allow_rem
        };

        let mut allowed_pres_cls = if !constrain_pres_cls.is_empty() {
            // bit_and
            &constrain_pres_cls & &allow_pres_cls
        } else {
            allow_pres_cls
        };

        let mut allowed_rem_cls = if !constrain_rem_cls.is_empty() {
            // bit_and
            &constrain_rem_cls & &allow_rem_cls
        } else {
            allow_rem_cls
        };

        // Deny these classes from being part of any addition or removal to an entry
        for protected_cls in PROTECTED_MOD_PRES_ENTRY_CLASSES.iter() {
            allowed_pres_cls.remove(protected_cls.as_str());
        }

        for protected_cls in PROTECTED_MOD_REM_ENTRY_CLASSES.iter() {
            allowed_rem_cls.remove(protected_cls.as_str());
        }

        ModifyResult::Allow {
            pres: allowed_pres,
            rem: allowed_rem,
            pres_cls: allowed_pres_cls,
            rem_cls: allowed_rem_cls,
        }
    }
}

fn modify_ident_test(ident: &Identity) -> AccessBasicResult {
    match &ident.origin {
        IdentType::Internal(InternalRole::System) => {
            trace!("Internal operation, bypassing access check");
            // No need to check ACS
            return AccessBasicResult::Grant;
        }
        IdentType::Internal(InternalRole::Migration) => {
            return AccessBasicResult::Ignore;
        }
        IdentType::Internal(InternalRole::MessageQueue)
        | IdentType::Internal(InternalRole::AccountRequest) => {
            trace!("Deny internal role from modification");
            return AccessBasicResult::Deny;
        }
        IdentType::Synch(_) => {
            warn!("Blocking sync account from modifying entries.");
            return AccessBasicResult::Deny;
        }
        IdentType::User(_) => {}
    };
    debug!(event = %ident, "Access check for modify event");

    match ident.access_scope() {
        AccessScope::ReadOnly | AccessScope::Synchronise => {
            security_access!("denied ❌ - identity access scope is not permitted to modify");
            return AccessBasicResult::Deny;
        }
        AccessScope::ReadWrite => {
            // As you were
        }
    };

    AccessBasicResult::Ignore
}

fn modify_pres_test<'a>(scoped_acp: &[&'a AccessControlModify]) -> AccessModResult<'a> {
    let pres_attr: BTreeSet<Attribute> = scoped_acp
        .iter()
        .flat_map(|acp| acp.presattrs.iter().cloned())
        .collect();

    let rem_attr: BTreeSet<Attribute> = scoped_acp
        .iter()
        .flat_map(|acp| acp.remattrs.iter().cloned())
        .collect();

    let pres_class: BTreeSet<&'a str> = scoped_acp
        .iter()
        .flat_map(|acp| acp.pres_classes.iter().map(|s| s.as_str()))
        .collect();

    let rem_class: BTreeSet<&'a str> = scoped_acp
        .iter()
        .flat_map(|acp| acp.rem_classes.iter().map(|s| s.as_str()))
        .collect();

    AccessModResult::Allow {
        pres_attr,
        rem_attr,
        pres_class,
        rem_class,
    }
}

fn modify_sync_constrain<'a>(
    ident: &Identity,
    entry: &Arc<EntrySealedCommitted>,
    sync_agreements: &HashMap<Uuid, BTreeSet<Attribute>>,
) -> AccessModResult<'a> {
    match &ident.origin {
        IdentType::Internal(_) => AccessModResult::Ignore,
        IdentType::Synch(_) => {
            // Allowed to mod sync objects. Later we'll probably need to check the limits of what
            // it can do if we go that way.
            AccessModResult::Ignore
        }
        IdentType::User(_) => {
            // We need to meet these conditions.
            // * We are a sync object
            // * We have a sync_parent_uuid
            let is_sync = entry
                .get_ava_set(Attribute::Class)
                .map(|classes| classes.contains(&EntryClass::SyncObject.into()))
                .unwrap_or(false);

            if !is_sync {
                return AccessModResult::Ignore;
            }

            if let Some(sync_uuid) = entry.get_ava_single_refer(Attribute::SyncParentUuid) {
                let mut set = btreeset![
                    Attribute::UserAuthTokenSession,
                    Attribute::OAuth2Session,
                    Attribute::OAuth2ConsentScopeMap,
                    Attribute::CredentialUpdateIntentToken
                ];

                if let Some(sync_yield_authority) = sync_agreements.get(&sync_uuid) {
                    set.extend(sync_yield_authority.iter().cloned())
                }

                AccessModResult::Constrain {
                    pres_attr: set.clone(),
                    rem_attr: set,
                    pres_cls: None,
                    rem_cls: None,
                }
            } else {
                warn!(entry = ?entry.get_uuid(), "sync_parent_uuid not found on sync object, preventing all access");
                AccessModResult::Deny
            }
        }
    }
}

/// Verify if the modification runs into limits that are defined by our protection rules.
fn modify_protected_attrs<'a>(
    ident: &Identity,
    entry: &Arc<EntrySealedCommitted>,
) -> AccessModResult<'a> {
    match &ident.origin {
        IdentType::Internal(InternalRole::System) | IdentType::Synch(_) => {
            // We don't constraint or influence these.
            AccessModResult::Ignore
        }
        IdentType::Internal(InternalRole::AccountRequest)
        | IdentType::Internal(InternalRole::MessageQueue)
        | IdentType::Internal(InternalRole::Migration)
        | IdentType::User(_) => {
            if let Some(classes) = entry.get_ava_as_iutf8(Attribute::Class) {
                if entry.get_uuid() > UUID_ANONYMOUS
                    && classes.is_disjoint(&PROTECTED_MOD_ENTRY_CLASSES)
                {
                    // Not protected, go ahead
                    AccessModResult::Ignore
                } else {
                    // Okay, the entry is protected, apply the full ruleset.
                    modify_protected_entry_attrs(classes)
                }
            } else {
                // Nothing to check - this entry will fail to modify anyway because it has
                // no classes
                AccessModResult::Ignore
            }
        }
    }
}

fn modify_protected_entry_attrs<'a>(classes: &BTreeSet<String>) -> AccessModResult<'a> {
    // This is where the majority of the logic is - this contains the modification
    // rules as they apply.

    // First check for the hard-deny rules.
    if !classes.is_disjoint(&LOCKED_ENTRY_CLASSES) {
        // Hard deny attribute modifications to these types.
        info!("Denying attempt to modify a locked entry class");
        return AccessModResult::Deny;
    }

    let mut constrain_attrs = BTreeSet::default();

    // Allows removal of the recycled class specifically on recycled entries.
    if classes.contains(EntryClass::Recycled.into()) {
        constrain_attrs.extend([Attribute::Class]);
    }

    if classes.contains(EntryClass::ClassType.into()) {
        constrain_attrs.extend([Attribute::May, Attribute::Must]);
    }

    if classes.contains(EntryClass::SystemConfig.into()) {
        constrain_attrs.extend([Attribute::BadlistPassword]);
    }

    // Allow domain settings.
    if classes.contains(EntryClass::DomainInfo.into()) {
        constrain_attrs.extend([
            Attribute::DomainSsid,
            Attribute::DomainLdapBasedn,
            Attribute::LdapMaxQueryableAttrs,
            Attribute::LdapAllowUnixPwBind,
            Attribute::FernetPrivateKeyStr,
            Attribute::Es256PrivateKeyDer,
            Attribute::KeyActionRevoke,
            Attribute::KeyActionRotate,
            Attribute::IdVerificationEcKey,
            Attribute::DeniedName,
            Attribute::DomainDisplayName,
            Attribute::Image,
            Attribute::DomainAllowEasterEggs,
            Attribute::DomainAllowAccountRecovery,
        ]);
    }

    if classes.contains(EntryClass::Account.into()) {
        constrain_attrs.extend([Attribute::AccountExpire, Attribute::AccountValidFrom]);
    }

    if classes.contains(EntryClass::ServiceAccount.into()) {
        constrain_attrs.extend([
            Attribute::SshPublicKey,
            Attribute::UserAuthTokenSession,
            Attribute::OAuth2Session,
            Attribute::Mail,
            Attribute::PrimaryCredential,
            Attribute::ApiTokenSession,
        ]);
    }

    if classes.contains(EntryClass::Group.into()) {
        constrain_attrs.extend([Attribute::Member]);
    }

    // Allow account policy related attributes to be changed on dyngroup
    if classes.contains(EntryClass::DynGroup.into()) {
        constrain_attrs.extend([
            Attribute::AuthSessionExpiry,
            Attribute::AuthPasswordMinimumLength,
            Attribute::CredentialTypeMinimum,
            Attribute::PrivilegeExpiry,
            Attribute::WebauthnAttestationCaList,
            Attribute::LimitSearchMaxResults,
            Attribute::LimitSearchMaxFilterTest,
            Attribute::AllowPrimaryCredFallback,
        ]);
    }

    if classes.contains(EntryClass::Feature.into()) {
        constrain_attrs.extend([Attribute::Enabled]);
    }

    // If we don't constrain the attributes at all, we have to deny the change
    // from proceeding.
    if constrain_attrs.is_empty() {
        warn!("Unable to constrain attributes, denying request");
        AccessModResult::Deny
    } else {
        AccessModResult::Constrain {
            pres_attr: constrain_attrs.clone(),
            rem_attr: constrain_attrs,
            pres_cls: None,
            rem_cls: None,
        }
    }
}

fn modify_migration_attrs<'a>(
    ident: &Identity,
    entry: &Arc<EntrySealedCommitted>,
) -> AccessModResult<'a> {
    match &ident.origin {
        IdentType::Internal(InternalRole::Migration) => {
            if let Some(classes) = entry.get_ava_as_iutf8(Attribute::Class) {
                let classes = classes.sub(&MIGRATION_IGNORE_CLASSES);
                if !classes.is_empty() && classes.is_subset(&MIGRATION_ENTRY_CLASSES) {
                    // Check what may be allowed
                    let (allow_attrs, allow_cls) = migration_entry_attrs(&classes);

                    if allow_attrs.is_empty() {
                        return AccessModResult::Deny;
                    } else {
                        return AccessModResult::Allow {
                            pres_attr: allow_attrs.clone(),
                            rem_attr: allow_attrs,
                            pres_class: allow_cls.clone(),
                            rem_class: allow_cls,
                        };
                    }
                }
            }
            AccessModResult::Deny
        }
        _ => {
            // We don't constraint or influence these.
            AccessModResult::Ignore
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

    fn make_sealed_entry(class: &str) -> Arc<EntrySealedCommitted> {
        Arc::new(
            entry_init!(
                (Attribute::Class, Value::new_iutf8(class)),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("00000000-0000-0000-0000-000000000100"))
                )
            )
            .into_sealed_committed(),
        )
    }

    fn make_sealed_entry_two_classes(
        class1: &str,
        class2: &str,
        uuid: Uuid,
    ) -> Arc<EntrySealedCommitted> {
        Arc::new(
            entry_init!(
                (Attribute::Class, Value::new_iutf8(class1)),
                (Attribute::Class, Value::new_iutf8(class2)),
                (Attribute::Uuid, Value::Uuid(uuid))
            )
            .into_sealed_committed(),
        )
    }

    #[test]
    fn test_modify_protected_entry_attrs_tombstone_denied() {
        let classes = btreeset!["tombstone".to_string()];
        let result = modify_protected_entry_attrs(&classes);
        assert!(matches!(result, AccessModResult::Deny));
    }

    #[test]
    fn test_modify_protected_entry_attrs_recycled_constrains() {
        let classes = btreeset!["recycled".to_string()];
        let result = modify_protected_entry_attrs(&classes);
        match result {
            AccessModResult::Constrain {
                pres_attr,
                rem_attr,
                ..
            } => {
                assert!(pres_attr.contains(&Attribute::Class));
                assert!(rem_attr.contains(&Attribute::Class));
            }
            _ => panic!("Expected Constrain for recycled"),
        }
    }

    #[test]
    fn test_modify_protected_entry_attrs_domain_info_constrains() {
        let classes = btreeset!["domain_info".to_string()];
        let result = modify_protected_entry_attrs(&classes);
        match result {
            AccessModResult::Constrain { pres_attr, .. } => {
                assert!(pres_attr.contains(&Attribute::DomainSsid));
                assert!(pres_attr.contains(&Attribute::DomainDisplayName));
            }
            _ => panic!("Expected Constrain for domain_info"),
        }
    }

    #[test]
    fn test_modify_protected_entry_attrs_system_config_constrains() {
        let classes = btreeset!["system_config".to_string()];
        let result = modify_protected_entry_attrs(&classes);
        match result {
            AccessModResult::Constrain { pres_attr, .. } => {
                assert!(pres_attr.contains(&Attribute::BadlistPassword));
            }
            _ => panic!("Expected Constrain for system_config"),
        }
    }

    #[test]
    fn test_modify_protected_entry_attrs_classtype_constrains() {
        let classes = btreeset!["classtype".to_string()];
        let result = modify_protected_entry_attrs(&classes);
        match result {
            AccessModResult::Constrain { pres_attr, .. } => {
                assert!(pres_attr.contains(&Attribute::May));
                assert!(pres_attr.contains(&Attribute::Must));
            }
            _ => panic!("Expected Constrain for classtype"),
        }
    }

    #[test]
    fn test_modify_protected_entry_attrs_account_constrains() {
        let classes = btreeset!["account".to_string()];
        let result = modify_protected_entry_attrs(&classes);
        match result {
            AccessModResult::Constrain { pres_attr, .. } => {
                assert!(pres_attr.contains(&Attribute::AccountExpire));
                assert!(pres_attr.contains(&Attribute::AccountValidFrom));
            }
            _ => panic!("Expected Constrain for account"),
        }
    }

    #[test]
    fn test_modify_protected_entry_attrs_service_account_constrains() {
        let classes = btreeset!["service_account".to_string()];
        let result = modify_protected_entry_attrs(&classes);
        match result {
            AccessModResult::Constrain { pres_attr, .. } => {
                assert!(pres_attr.contains(&Attribute::SshPublicKey));
                assert!(pres_attr.contains(&Attribute::Mail));
            }
            _ => panic!("Expected Constrain for service_account"),
        }
    }

    #[test]
    fn test_modify_protected_entry_attrs_group_constrains() {
        let classes = btreeset!["group".to_string()];
        let result = modify_protected_entry_attrs(&classes);
        match result {
            AccessModResult::Constrain { pres_attr, .. } => {
                assert!(pres_attr.contains(&Attribute::Member));
            }
            _ => panic!("Expected Constrain for group"),
        }
    }

    #[test]
    fn test_modify_protected_entry_attrs_dyngroup_constrains() {
        let classes = btreeset!["dyngroup".to_string()];
        let result = modify_protected_entry_attrs(&classes);
        match result {
            AccessModResult::Constrain { pres_attr, .. } => {
                assert!(pres_attr.contains(&Attribute::AuthSessionExpiry));
                assert!(pres_attr.contains(&Attribute::PrivilegeExpiry));
            }
            _ => panic!("Expected Constrain for dyngroup"),
        }
    }

    #[test]
    fn test_modify_protected_entry_attrs_unknown_denied() {
        let classes = btreeset!["oauth2_resource_server".to_string()];
        let result = modify_protected_entry_attrs(&classes);
        assert!(matches!(result, AccessModResult::Deny));
    }

    #[test]
    fn test_modify_protected_entry_attrs_empty_denied() {
        let classes = BTreeSet::<String>::new();
        let result = modify_protected_entry_attrs(&classes);
        assert!(matches!(result, AccessModResult::Deny));
    }

    #[test]
    fn test_modify_ident_test_internal_system_grants() {
        let ident = Identity::from_internal();
        let result = modify_ident_test(&ident);
        assert!(matches!(result, AccessBasicResult::Grant));
    }

    #[test]
    fn test_modify_ident_test_migration_grants() {
        let ident = Identity::migration();
        let result = modify_ident_test(&ident);
        assert!(matches!(result, AccessBasicResult::Grant));
    }

    #[test]
    fn test_modify_ident_test_user_rw_ignores() {
        let ident = make_user_ident_rw();
        let result = modify_ident_test(&ident);
        assert!(matches!(result, AccessBasicResult::Ignore));
    }

    #[test]
    fn test_modify_ident_test_user_ro_denied() {
        let ident = make_user_ident_ro();
        let result = modify_ident_test(&ident);
        assert!(matches!(result, AccessBasicResult::Deny));
    }

    #[test]
    fn test_modify_pres_test_empty_acps() {
        let acps: Vec<&AccessControlModify> = vec![];
        let result = modify_pres_test(&acps);
        match result {
            AccessModResult::Allow {
                pres_attr,
                rem_attr,
                pres_class,
                rem_class,
            } => {
                assert!(pres_attr.is_empty());
                assert!(rem_attr.is_empty());
                assert!(pres_class.is_empty());
                assert!(rem_class.is_empty());
            }
            _ => panic!("Expected Allow with empty sets"),
        }
    }

    #[test]
    fn test_modify_protected_attrs_internal_system_ignores() {
        let ident = Identity::from_internal();
        let entry = make_sealed_entry("system");
        let result = modify_protected_attrs(&ident, &entry);
        assert!(matches!(result, AccessModResult::Ignore));
    }

    #[test]
    fn test_modify_protected_attrs_user_nonprotected_ignores() {
        let ident = make_user_ident_rw();
        let entry = make_sealed_entry_two_classes(
            "account",
            "person",
            uuid::uuid!("00000000-0000-0000-0001-000000000001"),
        );
        let result = modify_protected_attrs(&ident, &entry);
        assert!(matches!(result, AccessModResult::Ignore));
    }

    #[test]
    fn test_modify_protected_attrs_user_protected_constrains() {
        let ident = make_user_ident_rw();
        let entry = Arc::new(
            entry_init!(
                (Attribute::Class, Value::new_iutf8("domain_info")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("ffffffff-ffff-ffff-ffff-000000000100"))
                )
            )
            .into_sealed_committed(),
        );
        let result = modify_protected_attrs(&ident, &entry);
        match result {
            AccessModResult::Constrain { pres_attr, .. } => {
                assert!(pres_attr.contains(&Attribute::DomainSsid));
            }
            _ => panic!("Expected Constrain for protected domain_info entry"),
        }
    }

    #[test]
    fn test_modify_sync_constrain_internal_ignores() {
        let ident = Identity::from_internal();
        let entry = make_sealed_entry("account");
        let sync_agreements = HashMap::new();
        let result = modify_sync_constrain(&ident, &entry, &sync_agreements);
        assert!(matches!(result, AccessModResult::Ignore));
    }

    #[test]
    fn test_modify_sync_constrain_user_non_sync_ignores() {
        let ident = make_user_ident_rw();
        let entry = make_sealed_entry("account");
        let sync_agreements = HashMap::new();
        let result = modify_sync_constrain(&ident, &entry, &sync_agreements);
        assert!(matches!(result, AccessModResult::Ignore));
    }

    #[test]
    fn test_modify_sync_constrain_user_sync_no_parent_denied() {
        let ident = make_user_ident_rw();
        let entry = make_sealed_entry_two_classes(
            "sync_object",
            "account",
            uuid::uuid!("00000000-0000-0000-0000-000000000100"),
        );
        let sync_agreements = HashMap::new();
        let result = modify_sync_constrain(&ident, &entry, &sync_agreements);
        assert!(matches!(result, AccessModResult::Deny));
    }

    #[test]
    fn test_modify_migration_attrs_migration_valid_allows() {
        let ident = Identity::migration();
        let entry = make_sealed_entry("account");
        let result = modify_migration_attrs(&ident, &entry);
        match result {
            AccessModResult::Allow { pres_attr, .. } => {
                assert!(!pres_attr.is_empty());
            }
            _ => panic!("Expected Allow for migration with valid class"),
        }
    }

    #[test]
    fn test_modify_migration_attrs_migration_invalid_denied() {
        let ident = Identity::migration();
        let entry = make_sealed_entry("tombstone");
        let result = modify_migration_attrs(&ident, &entry);
        assert!(matches!(result, AccessModResult::Deny));
    }

    #[test]
    fn test_modify_migration_attrs_non_migration_ignores() {
        let ident = Identity::from_internal();
        let entry = make_sealed_entry("account");
        let result = modify_migration_attrs(&ident, &entry);
        assert!(matches!(result, AccessModResult::Ignore));
    }

    #[test]
    fn test_modify_migration_attrs_user_ignores() {
        let ident = make_user_ident_rw();
        let entry = make_sealed_entry("account");
        let result = modify_migration_attrs(&ident, &entry);
        assert!(matches!(result, AccessModResult::Ignore));
    }

    #[test]
    fn test_apply_modify_access_internal_system_grants() {
        let ident = Identity::from_internal();
        let entry = make_sealed_entry("account");
        let acps: Vec<AccessControlModifyResolved> = vec![];
        let sync_agreements = HashMap::new();
        let result = apply_modify_access(&ident, &acps, &sync_agreements, &entry);
        assert!(matches!(result, ModifyResult::Grant));
    }

    #[test]
    fn test_apply_modify_access_user_no_acps_empty_allow() {
        let ident = make_user_ident_rw();
        let entry = make_sealed_entry("account");
        let acps: Vec<AccessControlModifyResolved> = vec![];
        let sync_agreements = HashMap::new();
        let result = apply_modify_access(&ident, &acps, &sync_agreements, &entry);
        match result {
            ModifyResult::Allow {
                pres,
                rem,
                pres_cls,
                rem_cls,
            } => {
                assert!(pres.is_empty());
                assert!(rem.is_empty());
                assert!(pres_cls.is_empty());
                assert!(rem_cls.is_empty());
            }
            _ => panic!("Expected Allow with empty sets"),
        }
    }
}
