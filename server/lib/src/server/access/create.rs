use super::utils::check_time_restriction;
use super::{
    migration::{migration_entry_attrs, MIGRATION_ENTRY_CLASSES, MIGRATION_IGNORE_CLASSES},
    profiles::{
        AccessControlCreateResolved, AccessControlReceiverCondition, AccessControlTargetCondition,
    },
    protected::{PROTECTED_ENTRY_CLASSES, PROTECTED_MOD_PRES_ENTRY_CLASSES},
};
use crate::prelude::*;
use std::{collections::BTreeSet, ops::Sub};

pub enum CreateResult<'a> {
    Deny,
    Grant,
    Allow {
        pres: BTreeSet<Attribute>,
        pres_cls: BTreeSet<&'a str>,
    },
    #[allow(dead_code)]
    ReauthRequired {
        reason: String,
    },
}

enum IResult<'a> {
    Deny,
    Grant,
    Ignore,
    Allow {
        pres: BTreeSet<Attribute>,
        pres_cls: BTreeSet<&'a str>,
    },
}

pub(super) fn apply_create_access<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlCreateResolved],
    entry: &'a Entry<EntryInit, EntryNew>,
) -> CreateResult<'a> {
    let mut denied = false;
    let mut grant = false;

    let constrain_pres = BTreeSet::default();
    let mut allow_pres = BTreeSet::default();

    let constrain_pres_cls = BTreeSet::default();
    let mut allow_pres_cls = BTreeSet::default();

    // This module can never yield a grant.
    match protected_filter_entry(ident, entry) {
        IResult::Deny => denied = true,
        IResult::Grant | IResult::Ignore | IResult::Allow { .. } => {}
    }

    match message_queue(ident, entry) {
        IResult::Deny => denied = true,
        IResult::Grant => grant = true,
        IResult::Ignore => {}
        IResult::Allow {
            mut pres,
            mut pres_cls,
        } => {
            allow_pres.append(&mut pres);
            allow_pres_cls.append(&mut pres_cls);
        }
    }

    match migration_filter_entry(ident, entry) {
        IResult::Deny => denied = true,
        IResult::Grant => grant = true,
        IResult::Ignore => {}
        IResult::Allow {
            mut pres,
            mut pres_cls,
        } => {
            allow_pres.append(&mut pres);
            allow_pres_cls.append(&mut pres_cls);
        }
    }

    match create_filter_entry(ident, related_acp, entry) {
        IResult::Deny => denied = true,
        IResult::Grant => grant = true,
        IResult::Ignore => {}
        IResult::Allow {
            mut pres,
            mut pres_cls,
        } => {
            allow_pres.append(&mut pres);
            allow_pres_cls.append(&mut pres_cls);
        }
    }

    if denied {
        // Something explicitly said no.
        CreateResult::Deny
    } else if grant {
        // Something said yes
        CreateResult::Grant
    } else {
        let allowed_pres = if !constrain_pres.is_empty() {
            // bit_and
            &constrain_pres & &allow_pres
        } else {
            allow_pres
        };

        let mut allowed_pres_cls = if !constrain_pres_cls.is_empty() {
            // bit_and
            &constrain_pres_cls & &allow_pres_cls
        } else {
            allow_pres_cls
        };

        for protected_cls in PROTECTED_MOD_PRES_ENTRY_CLASSES.iter() {
            allowed_pres_cls.remove(protected_cls.as_str());
        }

        CreateResult::Allow {
            pres: allowed_pres,
            pres_cls: allowed_pres_cls,
        }
    }
}

fn create_filter_entry<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlCreateResolved],
    entry: &'a Entry<EntryInit, EntryNew>,
) -> IResult<'a> {
    match &ident.origin {
        IdentType::Internal(InternalRole::System) => {
            trace!("Internal operation, bypassing access check");
            // No need to check ACS
            return IResult::Grant;
        }
        IdentType::Internal(InternalRole::Migration) => {
            // Checked in a separate function.
            return IResult::Ignore;
        }
        IdentType::Internal(InternalRole::AccountRequest) => {
            trace!(uuid = ?entry.get_display_id(), "Account Request");

            let pres = BTreeSet::from([
                Attribute::Class,
                Attribute::DeleteAfter,
                Attribute::DisplayName,
                Attribute::Mail,
                Attribute::Name,
                Attribute::Uuid,
            ]);

            let pres_cls = BTreeSet::from([
                EntryClass::Object.into(),
                EntryClass::AccountSignupRequest.into(),
            ]);

            // We may create account signup requests.
            return IResult::Allow { pres, pres_cls };
        }
        IdentType::Internal(InternalRole::MessageQueue) => {
            // No current rules.
            return IResult::Ignore;
        }
        IdentType::Synch(_) => {
            security_critical!("Blocking sync check");
            return IResult::Deny;
        }
        IdentType::User(_) => {}
    };
    debug!(event = %ident, "Access check for create event");

    match ident.access_scope() {
        AccessScope::ReadOnly | AccessScope::Synchronise => {
            security_access!("denied ❌ - identity access scope is not permitted to create");
            return IResult::Deny;
        }
        AccessScope::ReadWrite => {
            // As you were
        }
    };

    // Build the set of requested classes and attrs here.
    let create_attrs: BTreeSet<&str> = entry.get_ava_names().collect();
    // If this is empty, we make an empty set, which is fine because
    // the empty class set despite matching is_subset, will have the
    // following effect:
    // * there is no class on entry, so schema will fail
    // * plugin-base will add object to give a class, but excess
    //   attrs will cause fail (could this be a weakness?)
    // * class is a "may", so this could be empty in the rules, so
    //   if the accr is empty this would not be a true subset,
    //   so this would "fail", but any content in the accr would
    //   have to be validated.
    //
    // I still think if this is None, we should just fail here ...
    // because it shouldn't be possible to match.

    let create_classes: BTreeSet<&str> = match entry.get_ava_iter_iutf8(Attribute::Class) {
        Some(s) => s.collect(),
        None => {
            admin_error!("Class set failed to build - corrupted entry?");
            return IResult::Deny;
        }
    };

    //      Find the set of related acps for this entry.
    //
    //      For each "created" entry.
    //          If the created entry is 100% allowed by this acp
    //          IE: all attrs to be created AND classes match classes
    //              allow
    //          if no acp allows, fail operation.
    let allow = related_acp.iter().any(|accr| {
        // Assert that the receiver condition applies.
        match &accr.receiver_condition {
            AccessControlReceiverCondition::GroupChecked => {
                // The groups were already checked during filter resolution. Trust
                // that result, and continue.
            }
            AccessControlReceiverCondition::EntryManager => {
                // Currently, this is unsatisfiable for creates.
                return false;
            }
            AccessControlReceiverCondition::Delegated { .. } => {
                // Delegated access is handled at filter resolution time
            }
        };

        match &accr.target_condition {
            AccessControlTargetCondition::Scope(f_res) => {
                if !entry.entry_match_no_index(f_res) {
                    trace!(?entry, acs = %accr.acp.acp.name, "entry DOES NOT match acs");
                    // Does not match, fail this rule.
                    return false;
                }
            }
            AccessControlTargetCondition::DelegatedScope { .. } => {
                // Delegated scope is handled at filter resolution time
            }
        };

        // Check time restrictions
        if !check_time_restriction(
            accr.acp.acp.time_restriction_start,
            accr.acp.acp.time_restriction_end,
        ) {
            debug!(entry = ?entry.get_display_id(), accr = %accr.acp.acp.name, "time restriction not satisfied");
            return false;
        }

        // -- Conditions pass -- now verify the attributes.

        let entry_name = entry.get_display_id();
        // It matches, so now we have to check attrs and classes.
        // Remember, we have to match ALL requested attrs
        // and classes to pass!
        let allowed_attrs: BTreeSet<&str> = accr.acp.attrs.iter().map(|s| s.as_str()).collect();
        let allowed_classes: BTreeSet<&str> = accr.acp.classes.iter().map(|s| s.as_str()).collect();

        if !create_attrs.is_subset(&allowed_attrs) {
            debug!(%entry_name, acs = ?accr.acp.acp.name, "entry create denied");
            debug!("create_attrs is not a subset of allowed");
            debug!("create: {:?} !⊆ allowed: {:?}", create_attrs, allowed_attrs);
            false
        } else if !create_classes.is_subset(&allowed_classes) {
            debug!(%entry_name, acs = ?accr.acp.acp.name, "entry create denied");
            debug!("create_classes is not a subset of allowed");
            debug!(
                "create: {:?} !⊆ allowed: {:?}",
                create_classes, allowed_classes
            );
            false
        } else {
            // All attribute conditions are now met.
            info!(%entry_name, acs = ?accr.acp.acp.name, "entry create allowed");
            debug!("create: {:?} ⊆ allowed: {:?}", create_attrs, allowed_attrs);
            debug!(
                "create: {:?} ⊆ allowed: {:?}",
                create_classes, allowed_classes
            );
            true
        }
    });

    if allow {
        IResult::Grant
    } else {
        IResult::Ignore
    }
}

fn protected_filter_entry<'a>(ident: &Identity, entry: &Entry<EntryInit, EntryNew>) -> IResult<'a> {
    match &ident.origin {
        IdentType::Internal(InternalRole::System)
        | IdentType::Internal(InternalRole::AccountRequest)
        | IdentType::Internal(InternalRole::MessageQueue) => {
            trace!("Internal operation, protected rules do not apply.");
            IResult::Ignore
        }
        IdentType::Synch(_) => {
            security_access!("sync agreements may not directly create entities");
            IResult::Deny
        }
        IdentType::Internal(InternalRole::Migration) | IdentType::User(_) => {
            if let Some(entry_uuid) = entry.get_uuid() {
                if entry_uuid <= UUID_ANONYMOUS {
                    security_access!("attempt to create a system builtin entry");
                    return IResult::Deny;
                }
            }

            // Now check things ...
            if let Some(classes) = entry.get_ava_as_iutf8(Attribute::Class) {
                if classes.is_disjoint(&PROTECTED_ENTRY_CLASSES) {
                    // It's different, go ahead
                    IResult::Ignore
                } else {
                    // Block the mod, something is present
                    security_access!("attempt to create with protected class type");
                    IResult::Deny
                }
            } else {
                // Nothing to check - this entry will fail to create anyway because it has
                // no classes
                IResult::Ignore
            }
        }
    }
}

fn migration_filter_entry<'a>(ident: &Identity, entry: &Entry<EntryInit, EntryNew>) -> IResult<'a> {
    match &ident.origin {
        IdentType::Internal(InternalRole::Migration) => {
            trace!(uuid = ?entry.get_display_id(), "Internal migration");

            if let Some(classes) = entry.get_ava_as_iutf8(Attribute::Class) {
                let classes = classes.sub(&MIGRATION_IGNORE_CLASSES);
                if classes.is_subset(&MIGRATION_ENTRY_CLASSES) {
                    // Check what may be allowed
                    let (allow_attrs, allow_cls) = migration_entry_attrs(&classes);

                    if allow_attrs.is_empty() {
                        return IResult::Deny;
                    } else {
                        return IResult::Allow {
                            pres: allow_attrs,
                            pres_cls: allow_cls,
                        };
                    }
                }
            }
            IResult::Deny
        }
        _ => IResult::Ignore,
    }
}

fn message_queue<'a>(ident: &Identity, entry: &Entry<EntryInit, EntryNew>) -> IResult<'a> {
    match &ident.origin {
        IdentType::Internal(InternalRole::MessageQueue) => {
            trace!(uuid = ?entry.get_display_id(), "Internal Message Queue");

            if let Some(classes) = entry.get_ava_as_iutf8(Attribute::Class) {
                if classes.contains(EntryClass::OutboundMessage.into()) {
                    let allow_attrs = BTreeSet::from([
                        Attribute::Class,
                        Attribute::DeleteAfter,
                        Attribute::MailDestination,
                        Attribute::MessageTemplate,
                        Attribute::SendAfter,
                    ]);

                    let allow_cls = BTreeSet::from([
                        EntryClass::Object.into(),
                        EntryClass::OutboundMessage.into(),
                    ]);

                    return IResult::Allow {
                        pres: allow_attrs,
                        pres_cls: allow_cls,
                    };
                }
            }
            IResult::Deny
        }
        _ => IResult::Ignore,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Entry, EntryInit, EntryNew};
    use crate::server::identity::Identity;
    use std::sync::Arc;

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

    fn make_entry_with_class(class: &str) -> Entry<EntryInit, EntryNew> {
        entry_init!((Attribute::Class, Value::new_iutf8(class)))
    }

    fn make_entry_with_class_and_uuid(class: &str, uuid: Uuid) -> Entry<EntryInit, EntryNew> {
        entry_init!(
            (Attribute::Class, Value::new_iutf8(class)),
            (Attribute::Uuid, Value::Uuid(uuid))
        )
    }

    #[test]
    fn test_protected_filter_entry_internal_system_ignores() {
        let ident = Identity::from_internal();
        let entry = make_entry_with_class("system");
        let result = protected_filter_entry(&ident, &entry);
        match result {
            IResult::Ignore => {}
            _ => panic!("Expected Ignore for internal system"),
        }
    }

    #[test]
    fn test_protected_filter_entry_user_with_protected_class_denied() {
        let ident = make_user_ident_rw();
        let entry = make_entry_with_class("system");
        let result = protected_filter_entry(&ident, &entry);
        match result {
            IResult::Deny => {}
            _ => panic!("Expected Deny for user with protected class"),
        }
    }

    #[test]
    fn test_protected_filter_entry_user_with_nonprotected_class_ignores() {
        let ident = make_user_ident_rw();
        let entry = make_entry_with_class("account");
        let result = protected_filter_entry(&ident, &entry);
        match result {
            IResult::Ignore => {}
            _ => panic!("Expected Ignore for user with non-protected class"),
        }
    }

    #[test]
    fn test_protected_filter_entry_user_with_system_uuid_denied() {
        let ident = make_user_ident_rw();
        let entry = make_entry_with_class_and_uuid("account", UUID_ANONYMOUS);
        let result = protected_filter_entry(&ident, &entry);
        match result {
            IResult::Deny => {}
            _ => panic!("Expected Deny for user with system UUID"),
        }
    }

    #[test]
    fn test_protected_filter_entry_user_no_classes_ignores() {
        let ident = make_user_ident_rw();
        let entry: Entry<EntryInit, EntryNew> = entry_init!();
        let result = protected_filter_entry(&ident, &entry);
        match result {
            IResult::Ignore => {}
            _ => panic!("Expected Ignore for entry with no classes"),
        }
    }

    #[test]
    fn test_migration_filter_entry_non_migration_ignores() {
        let ident = Identity::from_internal();
        let entry = make_entry_with_class("account");
        let result = migration_filter_entry(&ident, &entry);
        match result {
            IResult::Ignore => {}
            _ => panic!("Expected Ignore for non-migration identity"),
        }
    }

    #[test]
    fn test_migration_filter_entry_user_ignores() {
        let ident = make_user_ident_rw();
        let entry = make_entry_with_class("account");
        let result = migration_filter_entry(&ident, &entry);
        match result {
            IResult::Ignore => {}
            _ => panic!("Expected Ignore for user identity"),
        }
    }

    #[test]
    fn test_migration_filter_entry_migration_with_valid_class_allows() {
        let ident = Identity::migration();
        let entry = make_entry_with_class("account");
        let result = migration_filter_entry(&ident, &entry);
        match result {
            IResult::Allow { .. } => {}
            _ => panic!("Expected Allow for migration with valid class"),
        }
    }

    #[test]
    fn test_migration_filter_entry_migration_with_group_allows() {
        let ident = Identity::migration();
        let entry = make_entry_with_class("group");
        let result = migration_filter_entry(&ident, &entry);
        match result {
            IResult::Allow { .. } => {}
            _ => panic!("Expected Allow for migration with group class"),
        }
    }

    #[test]
    fn test_migration_filter_entry_migration_with_invalid_class_denied() {
        let ident = Identity::migration();
        let entry = make_entry_with_class("tombstone");
        let result = migration_filter_entry(&ident, &entry);
        match result {
            IResult::Deny => {}
            _ => panic!("Expected Deny for migration with invalid class"),
        }
    }

    #[test]
    fn test_migration_filter_entry_migration_no_class_denied() {
        let ident = Identity::migration();
        let entry: Entry<EntryInit, EntryNew> = entry_init!();
        let result = migration_filter_entry(&ident, &entry);
        match result {
            IResult::Deny => {}
            _ => panic!("Expected Deny for migration with no class"),
        }
    }

    #[test]
    fn test_create_filter_entry_internal_system_grants() {
        let ident = Identity::from_internal();
        let entry = make_entry_with_class("account");
        let acps: Vec<AccessControlCreateResolved> = vec![];
        let result = create_filter_entry(&ident, &acps, &entry);
        match result {
            IResult::Grant => {}
            _ => panic!("Expected Grant for internal system"),
        }
    }

    #[test]
    fn test_create_filter_entry_readonly_denied() {
        let ident = make_user_ident_ro();
        let entry = make_entry_with_class("account");
        let acps: Vec<AccessControlCreateResolved> = vec![];
        let result = create_filter_entry(&ident, &acps, &entry);
        match result {
            IResult::Deny => {}
            _ => panic!("Expected Deny for read-only identity"),
        }
    }

    #[test]
    fn test_create_filter_entry_user_no_acps_ignores() {
        let ident = make_user_ident_rw();
        let entry = make_entry_with_class("account");
        let acps: Vec<AccessControlCreateResolved> = vec![];
        let result = create_filter_entry(&ident, &acps, &entry);
        match result {
            IResult::Ignore => {}
            _ => panic!("Expected Ignore for user with no ACPs"),
        }
    }

    #[test]
    fn test_apply_create_access_internal_system_grants() {
        let ident = Identity::from_internal();
        let entry = make_entry_with_class("account");
        let acps: Vec<AccessControlCreateResolved> = vec![];
        let result = apply_create_access(&ident, &acps, &entry);
        match result {
            CreateResult::Grant => {}
            _ => panic!("Expected Grant for internal system"),
        }
    }

    #[test]
    fn test_apply_create_access_user_no_acps_empty_allow() {
        let ident = make_user_ident_rw();
        let entry = make_entry_with_class("account");
        let acps: Vec<AccessControlCreateResolved> = vec![];
        let result = apply_create_access(&ident, &acps, &entry);
        match result {
            CreateResult::Allow { pres, pres_cls } => {
                assert!(pres.is_empty());
                assert!(pres_cls.is_empty());
            }
            _ => panic!("Expected Allow with empty sets for user with no ACPs"),
        }
    }

    #[test]
    fn test_apply_create_access_protected_class_denied() {
        let ident = make_user_ident_rw();
        let entry = make_entry_with_class("system");
        let acps: Vec<AccessControlCreateResolved> = vec![];
        let result = apply_create_access(&ident, &acps, &entry);
        match result {
            CreateResult::Deny => {}
            _ => panic!("Expected Deny for protected class"),
        }
    }

    #[test]
    fn test_apply_create_access_system_uuid_denied() {
        let ident = make_user_ident_rw();
        let entry = make_entry_with_class_and_uuid("account", UUID_ANONYMOUS);
        let acps: Vec<AccessControlCreateResolved> = vec![];
        let result = apply_create_access(&ident, &acps, &entry);
        match result {
            CreateResult::Deny => {}
            _ => panic!("Expected Deny for system UUID"),
        }
    }

    #[test]
    fn test_apply_create_access_migration_allows() {
        let ident = Identity::migration();
        let entry = make_entry_with_class("account");
        let acps: Vec<AccessControlCreateResolved> = vec![];
        let result = apply_create_access(&ident, &acps, &entry);
        match result {
            CreateResult::Allow { pres, .. } => {
                assert!(!pres.is_empty());
            }
            _ => panic!("Expected Allow for migration with valid class"),
        }
    }
}
