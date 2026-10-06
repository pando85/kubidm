use super::utils::check_time_restriction;
use super::{
    migration::{MIGRATION_ENTRY_CLASSES, MIGRATION_IGNORE_CLASSES},
    profiles::{
        AccessControlDeleteResolved, AccessControlReceiverCondition, AccessControlTargetCondition,
    },
    protected::PROTECTED_ENTRY_CLASSES,
};
use crate::prelude::*;
use std::{ops::Sub, sync::Arc};

pub enum DeleteResult {
    Deny,
    Grant,
    #[allow(dead_code)]
    ReauthRequired {
        reason: String,
    },
}

enum IResult {
    Deny,
    Grant,
    Ignore,
}

pub fn apply_delete_access<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlDeleteResolved],
    entry: &'a Arc<EntrySealedCommitted>,
) -> DeleteResult {
    let mut denied = false;
    let mut grant = false;

    match protected_filter_entry(ident, entry) {
        IResult::Deny => denied = true,
        IResult::Grant | IResult::Ignore => {}
    }

    match delete_filter_entry(ident, related_acp, entry) {
        IResult::Deny => denied = true,
        IResult::Grant => grant = true,
        IResult::Ignore => {}
    }

    if denied {
        // Something explicitly said no.
        DeleteResult::Deny
    } else if grant {
        // Something said yes
        DeleteResult::Grant
    } else {
        // Nothing said yes.
        DeleteResult::Deny
    }
}

fn delete_filter_entry<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlDeleteResolved],
    entry: &'a Arc<EntrySealedCommitted>,
) -> IResult {
    match &ident.origin {
        IdentType::Internal(InternalRole::System) => {
            trace!("Internal operation, bypassing access check");
            // No need to check ACS
            return IResult::Grant;
        }
        IdentType::Internal(InternalRole::Migration) => {
            trace!(uuid = ?entry.get_display_id(), "Internal migration");

            let valid_migration_class = entry
                .get_ava_as_iutf8(Attribute::Class)
                .map(|classes| {
                    let classes = classes.sub(&MIGRATION_IGNORE_CLASSES);
                    classes.is_subset(&MIGRATION_ENTRY_CLASSES)
                })
                .unwrap_or(false);

            if valid_migration_class {
                // Can proceed.
                return IResult::Grant;
            } else {
                return IResult::Deny;
            }
        }
        IdentType::Internal(InternalRole::AccountRequest)
        | IdentType::Internal(InternalRole::MessageQueue) => {
            debug!("Blocking role from deletion");
            return IResult::Deny;
        }
        IdentType::Synch(_) => {
            security_critical!("Blocking sync check");
            return IResult::Deny;
        }
        IdentType::User(_) => {}
    };
    debug!(event = %ident, "Access check for delete event");

    match ident.access_scope() {
        AccessScope::ReadOnly | AccessScope::Synchronise => {
            security_access!("denied ❌ - identity access scope is not permitted to delete");
            return IResult::Deny;
        }
        AccessScope::ReadWrite => {
            // As you were
        }
    };

    let ident_memberof = ident.get_memberof();
    let ident_uuid = ident.get_uuid();

    let allow = related_acp.iter().any(|acd| {
        // Assert that the receiver condition applies.
        match &acd.receiver_condition {
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
                if let Some(entry_manager_uuids) = entry.get_ava_refer(Attribute::EntryManagedBy) {
                    let group_check = ident_memberof
                        // Have at least one group allowed.
                        .map(|imo| imo.intersection(entry_manager_uuids).next().is_some())
                        .unwrap_or_default();

                    let user_check = entry_manager_uuids.contains(&ident_uuid);

                    if !(group_check || user_check) {
                        // Not the entry manager
                        return false;
                    }
                } else {
                    // Can not satisfy.
                    return false;
                }
            }
            AccessControlReceiverCondition::Delegated {
                scope_filter_resolved,
            } => {
                // Check if the entry matches the delegated scope filter
                if let Some(filter) = scope_filter_resolved {
                    if !entry.entry_match_no_index(filter) {
                        trace!(
                            "entry {:?} DOES NOT match delegated scope filter for acs {}",
                            entry.get_uuid(),
                            acd.acp.acp.name
                        );
                        return false;
                    }
                }
            }
        };

        match &acd.target_condition {
            AccessControlTargetCondition::Scope(f_res) => {
                if !entry.entry_match_no_index(f_res) {
                    trace!(
                        "entry {:?} DOES NOT match acs {}",
                        entry.get_uuid(),
                        acd.acp.acp.name
                    );
                    // Does not match, fail.
                    return false;
                }
            }
            AccessControlTargetCondition::DelegatedScope {
                scope_filter_resolved,
            } => {
                // Check if the entry matches the delegated scope filter
                if let Some(filter) = scope_filter_resolved {
                    if !entry.entry_match_no_index(filter) {
                        trace!(
                            "entry {:?} DOES NOT match delegated scope filter for acs {}",
                            entry.get_uuid(),
                            acd.acp.acp.name
                        );
                        return false;
                    }
                }
            }
        };

        // Check time restrictions
        if !check_time_restriction(
            acd.acp.acp.time_restriction_start,
            acd.acp.acp.time_restriction_end,
        ) {
            debug!(entry = ?entry.get_display_id(), acd = %acd.acp.acp.name, "time restriction not satisfied");
            return false;
        }

        let entry_name = entry.get_display_id();
        security_access!(
            %entry_name,
            acs = %acd.acp.acp.name,
            "entry matches acs"
        );

        true
    }); // any related_acp

    if allow {
        IResult::Grant
    } else {
        IResult::Ignore
    }
}

fn protected_filter_entry(ident: &Identity, entry: &Arc<EntrySealedCommitted>) -> IResult {
    match &ident.origin {
        IdentType::Internal(InternalRole::System) => {
            trace!("Internal operation, protected rules do not apply.");
            IResult::Ignore
        }
        IdentType::Synch(_) => {
            security_access!("sync agreements may not directly delete entities");
            IResult::Deny
        }
        IdentType::Internal(InternalRole::AccountRequest)
        | IdentType::Internal(InternalRole::MessageQueue) => {
            debug!("Internal Role may not delete entries");
            IResult::Deny
        }
        IdentType::Internal(InternalRole::Migration) | IdentType::User(_) => {
            // Prevent deletion of entries that exist in the system controlled entry range.
            if entry.get_uuid() <= UUID_ANONYMOUS {
                security_access!("attempt to delete system builtin entry");
                return IResult::Deny;
            }

            // Prevent deleting some protected types.
            if let Some(classes) = entry.get_ava_as_iutf8(Attribute::Class) {
                if classes.is_disjoint(&PROTECTED_ENTRY_CLASSES) {
                    // It's different, go ahead
                    IResult::Ignore
                } else {
                    // Block the mod, something is present
                    security_access!("attempt to delete a protected class type");
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
    fn test_protected_filter_entry_internal_system_ignores() {
        let ident = Identity::from_internal();
        let entry = make_sealed_entry(
            "system",
            uuid::uuid!("ffffffff-ffff-ffff-ffff-000000000100"),
        );
        let result = protected_filter_entry(&ident, &entry);
        match result {
            IResult::Ignore => {}
            _ => panic!("Expected Ignore for internal system"),
        }
    }

    #[test]
    fn test_protected_filter_entry_user_with_protected_class_denied() {
        let ident = make_user_ident_rw();
        let entry = make_sealed_entry(
            "system",
            uuid::uuid!("ffffffff-ffff-ffff-ffff-000000000100"),
        );
        let result = protected_filter_entry(&ident, &entry);
        match result {
            IResult::Deny => {}
            _ => panic!("Expected Deny for user with protected class"),
        }
    }

    #[test]
    fn test_protected_filter_entry_user_with_nonprotected_class_ignores() {
        let ident = make_user_ident_rw();
        let entry = make_sealed_entry(
            "account",
            uuid::uuid!("ffffffff-ffff-ffff-ffff-000000000100"),
        );
        let result = protected_filter_entry(&ident, &entry);
        match result {
            IResult::Ignore => {}
            _ => panic!("Expected Ignore for user with non-protected class"),
        }
    }

    #[test]
    fn test_protected_filter_entry_user_with_system_uuid_denied() {
        let ident = make_user_ident_rw();
        let entry = make_sealed_entry("account", UUID_ANONYMOUS);
        let result = protected_filter_entry(&ident, &entry);
        match result {
            IResult::Deny => {}
            _ => panic!("Expected Deny for system UUID"),
        }
    }

    #[test]
    fn test_protected_filter_entry_user_no_classes_ignores() {
        let ident = make_user_ident_rw();
        let entry = Arc::new(
            entry_init!((
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("ffffffff-ffff-ffff-ffff-000000000100"))
            ))
            .into_sealed_committed(),
        );
        let result = protected_filter_entry(&ident, &entry);
        match result {
            IResult::Ignore => {}
            _ => panic!("Expected Ignore for entry with no classes"),
        }
    }

    #[test]
    fn test_delete_filter_entry_internal_system_grants() {
        let ident = Identity::from_internal();
        let entry = make_sealed_entry(
            "account",
            uuid::uuid!("ffffffff-ffff-ffff-ffff-000000000100"),
        );
        let acps: Vec<AccessControlDeleteResolved> = vec![];
        let result = delete_filter_entry(&ident, &acps, &entry);
        match result {
            IResult::Grant => {}
            _ => panic!("Expected Grant for internal system"),
        }
    }

    #[test]
    fn test_delete_filter_entry_migration_with_valid_class_grants() {
        let ident = Identity::migration();
        let entry = make_sealed_entry(
            "account",
            uuid::uuid!("ffffffff-ffff-ffff-ffff-000000000100"),
        );
        let acps: Vec<AccessControlDeleteResolved> = vec![];
        let result = delete_filter_entry(&ident, &acps, &entry);
        match result {
            IResult::Grant => {}
            _ => panic!("Expected Grant for migration with valid class"),
        }
    }

    #[test]
    fn test_delete_filter_entry_migration_with_invalid_class_denied() {
        let ident = Identity::migration();
        let entry = make_sealed_entry(
            "tombstone",
            uuid::uuid!("ffffffff-ffff-ffff-ffff-000000000100"),
        );
        let acps: Vec<AccessControlDeleteResolved> = vec![];
        let result = delete_filter_entry(&ident, &acps, &entry);
        match result {
            IResult::Deny => {}
            _ => panic!("Expected Deny for migration with invalid class"),
        }
    }

    #[test]
    fn test_delete_filter_entry_migration_no_class_denied() {
        let ident = Identity::migration();
        let entry = Arc::new(
            entry_init!((
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("ffffffff-ffff-ffff-ffff-000000000100"))
            ))
            .into_sealed_committed(),
        );
        let acps: Vec<AccessControlDeleteResolved> = vec![];
        let result = delete_filter_entry(&ident, &acps, &entry);
        match result {
            IResult::Deny => {}
            _ => panic!("Expected Deny for migration with no class"),
        }
    }

    #[test]
    fn test_delete_filter_entry_user_no_acps_ignores() {
        let ident = make_user_ident_rw();
        let entry = make_sealed_entry(
            "account",
            uuid::uuid!("ffffffff-ffff-ffff-ffff-000000000100"),
        );
        let acps: Vec<AccessControlDeleteResolved> = vec![];
        let result = delete_filter_entry(&ident, &acps, &entry);
        match result {
            IResult::Ignore => {}
            _ => panic!("Expected Ignore for user with no ACPs"),
        }
    }

    #[test]
    fn test_apply_delete_access_internal_system_grants() {
        let ident = Identity::from_internal();
        let entry = make_sealed_entry(
            "account",
            uuid::uuid!("ffffffff-ffff-ffff-ffff-000000000100"),
        );
        let acps: Vec<AccessControlDeleteResolved> = vec![];
        let result = apply_delete_access(&ident, &acps, &entry);
        match result {
            DeleteResult::Grant => {}
            _ => panic!("Expected Grant for internal system"),
        }
    }

    #[test]
    fn test_apply_delete_access_user_no_acps_denied() {
        let ident = make_user_ident_rw();
        let entry = make_sealed_entry(
            "account",
            uuid::uuid!("ffffffff-ffff-ffff-ffff-000000000100"),
        );
        let acps: Vec<AccessControlDeleteResolved> = vec![];
        let result = apply_delete_access(&ident, &acps, &entry);
        match result {
            DeleteResult::Deny => {}
            _ => panic!("Expected Deny for user with no ACPs"),
        }
    }

    #[test]
    fn test_apply_delete_access_protected_class_denied() {
        let ident = make_user_ident_rw();
        let entry = make_sealed_entry(
            "system",
            uuid::uuid!("ffffffff-ffff-ffff-ffff-000000000100"),
        );
        let acps: Vec<AccessControlDeleteResolved> = vec![];
        let result = apply_delete_access(&ident, &acps, &entry);
        match result {
            DeleteResult::Deny => {}
            _ => panic!("Expected Deny for protected class"),
        }
    }
}
