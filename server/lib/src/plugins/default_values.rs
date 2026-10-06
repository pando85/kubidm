/// Set and maintain default values on entries that require them. This is separate to
/// migrations that enforce entry existence and state on startup, this enforces
/// default values for specific entry uuids over every transaction.
use std::iter::once;
use std::sync::Arc;

// use crate::event::{CreateEvent, ModifyEvent};
use crate::{plugins::Plugin, prelude::*};

pub struct DefaultValues {}

impl Plugin for DefaultValues {
    fn id() -> &'static str {
        "plugin_default_values"
    }

    #[instrument(
        level = "debug",
        name = "default_values::pre_create_transform",
        skip_all
    )]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "default_values::pre_modify", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "default_values::pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(qs, cand)
    }
}

impl DefaultValues {
    fn modify_inner<T: Clone + std::fmt::Debug>(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut [Entry<EntryInvalid, T>],
    ) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(|e| {
            // We have to do this rather than get_uuid here because at this stage we haven't
            // scheme validated the entry so it's uuid could be missing in theory.

            let Some(e_uuid) = e.get_ava_single_uuid(Attribute::Uuid) else {
                trace!("entry does not contain a uuid");
                return Ok(());
            };

            if e_uuid == UUID_IDM_ALL_ACCOUNTS {
                // Set default account policy values if none exist.
                e.add_ava(Attribute::Class, EntryClass::AccountPolicy.to_value());

                if !e.attribute_pres(Attribute::AuthSessionExpiry) {
                    e.set_ava(&Attribute::AuthSessionExpiry, once(
                        Value::Uint32(DEFAULT_AUTH_SESSION_EXPIRY),
                    ));
                    debug!("default_values: idm_all_accounts - restore default auth_session_expiry");
                }

                // Setup the minimum functional level if one is not set already.
                if !e.attribute_pres(Attribute::PrivilegeExpiry) {
                    e.set_ava(&Attribute::PrivilegeExpiry, once(
                        Value::Uint32(DEFAULT_AUTH_PRIVILEGE_EXPIRY),
                    ));
                    debug!("default_values: idm_all_accounts - restore default privilege_session_expiry");
                }

                trace!(?e);
                Ok(())
            } else {
                Ok(())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    // test we can create and generate the id
    #[qs_test]
    async fn test_default_values_idm_all_accounts(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        let e_all_accounts = server_txn
            .internal_search_uuid(UUID_IDM_ALL_ACCOUNTS)
            .expect("must not fail");

        assert!(e_all_accounts.attribute_equality(
            Attribute::AuthSessionExpiry,
            &PartialValue::Uint32(DEFAULT_AUTH_SESSION_EXPIRY)
        ));
        assert!(e_all_accounts.attribute_equality(
            Attribute::PrivilegeExpiry,
            &PartialValue::Uint32(DEFAULT_AUTH_PRIVILEGE_EXPIRY)
        ));

        // delete the values.
        server_txn
            .internal_modify_uuid(
                UUID_IDM_ALL_ACCOUNTS,
                &ModifyList::new_list(vec![
                    Modify::Purged(Attribute::AuthSessionExpiry),
                    Modify::Purged(Attribute::PrivilegeExpiry),
                ]),
            )
            .expect("failed to modify account");

        // They are re-populated.
        let e_all_accounts = server_txn
            .internal_search_uuid(UUID_IDM_ALL_ACCOUNTS)
            .expect("must not fail");

        assert!(e_all_accounts.attribute_equality(
            Attribute::AuthSessionExpiry,
            &PartialValue::Uint32(DEFAULT_AUTH_SESSION_EXPIRY)
        ));
        assert!(e_all_accounts.attribute_equality(
            Attribute::PrivilegeExpiry,
            &PartialValue::Uint32(DEFAULT_AUTH_PRIVILEGE_EXPIRY)
        ));
    }

    #[qs_test]
    async fn test_default_values_account_policy_class_added(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        let e_all_accounts = server_txn
            .internal_search_uuid(UUID_IDM_ALL_ACCOUNTS)
            .expect("must not fail");

        assert!(e_all_accounts
            .attribute_equality(Attribute::Class, &PartialValue::new_iutf8("account_policy")));
    }

    #[qs_test]
    async fn test_default_values_non_matching_uuid_not_modified(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let test_uuid = Uuid::new_v4();
        server_txn
            .internal_create(vec![entry_init_fn([
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::ServiceAccount.to_value()),
                (Attribute::Uuid, Value::Uuid(test_uuid)),
                (Attribute::Name, Value::new_iname("test_svc_account")),
                (Attribute::DisplayName, Value::new_utf8s("test_svc_account")),
            ])])
            .expect("Unable to create test account");

        let e = server_txn
            .internal_search_uuid(test_uuid)
            .expect("must not fail");

        assert!(!e.attribute_pres(Attribute::AuthSessionExpiry));
        assert!(!e.attribute_pres(Attribute::PrivilegeExpiry));
    }

    #[test]
    fn test_default_values_constants() {
        assert_eq!(DEFAULT_AUTH_SESSION_EXPIRY, 86400);
        assert_eq!(DEFAULT_AUTH_PRIVILEGE_EXPIRY, 600);
    }

    #[test]
    fn test_default_values_plugin_id() {
        use crate::plugins::Plugin;
        assert_eq!(
            crate::plugins::default_values::DefaultValues::id(),
            "plugin_default_values"
        );
    }
}
