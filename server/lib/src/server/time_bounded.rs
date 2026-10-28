//! Kubidm: administration of time-bounded group memberships.
//!
//! A group with the `time_bounded_grant` class can hold `time_bounded_member` grants
//! `(member, valid_from?, valid_until)`. While a grant is valid its member is treated as
//! a member of the group by `memberof` (see `plugins::memberof`); a periodic refresh
//! applies grants that start or expire between writes.
//!
//! # Authorisation
//!
//! `time_bounded_member` values can not be written through the generic modify paths (see
//! `clone_value`), so the operations below write the grant internally. Before that, the
//! caller is authorised against the normal access controls as if it were changing the
//! `member` attribute of the group: a grant is a (temporary) membership, so whoever may
//! add or remove members of a group may grant or revoke time-bounded ones, and nobody
//! else. Concretely the group is fetched with the caller's search access (an invisible
//! group is indistinguishable from a missing one) and the caller's effective permissions
//! over it are evaluated by the access control engine, exactly as for a real modify:
//!
//! - granting needs `member` in the caller's allowed present attributes, and replacing an
//!   existing grant additionally needs it in the allowed removed attributes;
//! - revoking needs `member` in the allowed removed attributes;
//! - listing needs `member` in the caller's readable attributes.
//!
//! Read-only sessions get no modify rights from the access controls, so they can only
//! list. Enabling the class and setting `max_grant_duration` on a group are ordinary
//! attribute writes, allowed to group administrators by `idm_acp_group_time_bounded_manage`
//! (a group's entry managers can not raise its cap).
//!
//! # Cap
//!
//! The window of a new grant, from the later of now and `valid_from` to `valid_until`, may
//! not exceed the group's `max_grant_duration` (in seconds), or
//! [`DEFAULT_MAX_GRANT_DURATION_SECS`] when the group does not set one.

use crate::prelude::*;
use crate::server::access::{Access, AccessControlsTransaction};
use crate::value::TimeBoundedMember;
use kubidm_proto::v1::TimeBoundedMemberGrant;
use std::sync::Arc;
use time::OffsetDateTime;

/// Kubidm: the longest window (in seconds) that a time-bounded grant may cover on a group
/// that does not set `max_grant_duration`: 90 days. Conservative on purpose, since a grant
/// that was meant to be temporary should not silently become long lived.
pub const DEFAULT_MAX_GRANT_DURATION_SECS: u32 = 90 * 24 * 60 * 60;

/// What the caller may do with the members of a group.
struct MemberRights {
    read: bool,
    add: bool,
    remove: bool,
}

/// Fetch `group` as the caller and evaluate the caller's rights over its `member`
/// attribute through the access control engine.
fn group_member_rights<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    ident: &Identity,
    group: Uuid,
) -> Result<(Arc<EntrySealedCommitted>, MemberRights), OperationError> {
    if ident.is_internal() {
        let entry = qs.internal_search_uuid(group)?;
        let rights = MemberRights {
            read: true,
            add: true,
            remove: true,
        };
        return Ok((entry, rights));
    }

    // Search with the caller's access, so a group the caller can not see is reported as
    // missing.
    let entry = qs.impersonate_search_uuid(group, ident)?;

    if !entry.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
        return Err(OperationError::NoMatchingEntries);
    }

    let effective = qs
        .get_accesscontrols()
        .effective_permission_check(ident, None, std::slice::from_ref(&entry))?
        .into_iter()
        .next()
        .ok_or(OperationError::InvalidState)?;

    let allows_member = |access: &Access| match access {
        Access::Grant => true,
        Access::Deny => false,
        Access::Allow(attrs) => attrs.contains(&Attribute::Member),
    };

    let rights = MemberRights {
        read: allows_member(&effective.search),
        add: allows_member(&effective.modify_pres),
        remove: allows_member(&effective.modify_rem),
    };

    Ok((entry, rights))
}

fn grant_of(entry: &EntrySealedCommitted, member: Uuid) -> Option<&TimeBoundedMember> {
    entry
        .get_ava_as_time_bounded_member(Attribute::TimeBoundedMemberAttr)
        .and_then(|grants| grants.get(&member))
}

fn list_time_bounded_members<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    ident: &Identity,
    group: Uuid,
) -> Result<Vec<TimeBoundedMemberGrant>, OperationError> {
    let (entry, rights) = group_member_rights(qs, ident, group)?;

    if !rights.read {
        security_access!(%ident, %group, "denied - may not read the members of this group");
        return Err(OperationError::AccessDenied);
    }

    let grants: Vec<TimeBoundedMember> = entry
        .get_ava_as_time_bounded_member(Attribute::TimeBoundedMemberAttr)
        .map(|grants| grants.values().cloned().collect())
        .unwrap_or_default();

    grants
        .into_iter()
        .map(|grant| {
            let member_spn = qs
                .uuid_to_spn(grant.uuid)?
                .map(|spn| spn.to_proto_string_clone());
            Ok(TimeBoundedMemberGrant {
                member: grant.uuid,
                member_spn,
                valid_from: grant.valid_from,
                valid_until: grant.valid_until,
            })
        })
        .collect()
}

impl QueryServerReadTransaction<'_> {
    /// Kubidm: list the time-bounded grants of `group`. The caller must be able to read
    /// the members of the group.
    #[instrument(level = "debug", skip_all)]
    pub fn time_bounded_member_list(
        &mut self,
        ident: &Identity,
        group: Uuid,
    ) -> Result<Vec<TimeBoundedMemberGrant>, OperationError> {
        list_time_bounded_members(self, ident, group)
    }
}

impl QueryServerWriteTransaction<'_> {
    /// Kubidm: list the time-bounded grants of `group`, as
    /// [`QueryServerReadTransaction::time_bounded_member_list`].
    #[instrument(level = "debug", skip_all)]
    pub fn time_bounded_member_list(
        &mut self,
        ident: &Identity,
        group: Uuid,
    ) -> Result<Vec<TimeBoundedMemberGrant>, OperationError> {
        list_time_bounded_members(self, ident, group)
    }

    /// Kubidm: grant `member` a membership of `group` from `valid_from` (or now) until
    /// `valid_until`, replacing any existing grant of `member` on the group.
    ///
    /// The caller must be able to add members to the group (and to remove them, when an
    /// existing grant is replaced), the group must have the `time_bounded_grant` class,
    /// the member must be a person, group or service account, and the window must end in
    /// the future and fit within the group's cap (see the module documentation).
    #[instrument(level = "debug", skip_all)]
    pub fn grant_time_bounded_member(
        &mut self,
        ident: &Identity,
        group: Uuid,
        member: Uuid,
        valid_from: Option<OffsetDateTime>,
        valid_until: OffsetDateTime,
    ) -> Result<(), OperationError> {
        let (entry, rights) = group_member_rights(self, ident, group)?;

        if !rights.add {
            security_access!(%ident, %group, "denied - may not add members to this group");
            return Err(OperationError::AccessDenied);
        }

        let replaces = grant_of(&entry, member).is_some();
        if replaces && !rights.remove {
            security_access!(
                %ident,
                %group,
                "denied - replacing a grant requires the right to remove members"
            );
            return Err(OperationError::AccessDenied);
        }

        if !entry.attribute_equality(Attribute::Class, &EntryClass::TimeBoundedGrant.into()) {
            return Err(OperationError::InvalidAttribute(format!(
                "group does not have the {} class",
                EntryClass::TimeBoundedGrant
            )));
        }

        if member == group {
            return Err(OperationError::InvalidAttribute(
                "a group can not be granted membership of itself".to_string(),
            ));
        }

        let member_entry = self.internal_search_uuid(member)?;
        let member_is_allowed = [
            EntryClass::Person,
            EntryClass::Group,
            EntryClass::ServiceAccount,
        ]
        .into_iter()
        .any(|class| member_entry.attribute_equality(Attribute::Class, &class.into()));
        if !member_is_allowed {
            return Err(OperationError::InvalidAttribute(
                "member must be a person, group or service account".to_string(),
            ));
        }

        let now = self.get_curtime_odt();
        let start = valid_from.map_or(now, |vf| vf.max(now));
        if valid_until <= start {
            return Err(OperationError::InvalidAttribute(
                "valid_until must be after both the current time and valid_from".to_string(),
            ));
        }

        let max_secs = entry
            .get_ava_single_uint32(Attribute::MaxGrantDuration)
            .unwrap_or(DEFAULT_MAX_GRANT_DURATION_SECS);
        if valid_until - start > time::Duration::seconds(i64::from(max_secs)) {
            return Err(OperationError::InvalidAttribute(format!(
                "the grant exceeds the maximum grant duration of this group ({max_secs} seconds)"
            )));
        }

        let grant = TimeBoundedMember::new(member, valid_from, valid_until);
        if !grant.has_valid_window() {
            return Err(OperationError::InvalidAttribute(
                "the grant window can not be stored".to_string(),
            ));
        }

        security_info!(
            %ident,
            %group,
            %member,
            ?valid_from,
            %valid_until,
            replaces,
            "granting time bounded membership"
        );

        let mut mods = Vec::with_capacity(2);
        if replaces {
            mods.push(Modify::Removed(
                Attribute::TimeBoundedMemberAttr,
                PartialValue::TimeBoundedMember(member),
            ));
        }
        mods.push(Modify::Present(
            Attribute::TimeBoundedMemberAttr,
            Value::TimeBoundedMember(grant),
        ));

        self.internal_modify(
            &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(group))),
            &ModifyList::new_list(mods),
        )
    }

    /// Kubidm: revoke the time-bounded grant of `member` on `group`. The caller must be able
    /// to remove members from the group. Fails with `NoMatchingEntries` when there is no
    /// such grant.
    #[instrument(level = "debug", skip_all)]
    pub fn revoke_time_bounded_member(
        &mut self,
        ident: &Identity,
        group: Uuid,
        member: Uuid,
    ) -> Result<(), OperationError> {
        let (entry, rights) = group_member_rights(self, ident, group)?;

        if !rights.remove {
            security_access!(%ident, %group, "denied - may not remove members from this group");
            return Err(OperationError::AccessDenied);
        }

        if grant_of(&entry, member).is_none() {
            return Err(OperationError::NoMatchingEntries);
        }

        security_info!(%ident, %group, %member, "revoking time bounded membership");

        self.internal_modify(
            &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(group))),
            &ModifyList::new_remove(
                Attribute::TimeBoundedMemberAttr,
                PartialValue::TimeBoundedMember(member),
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_MAX_GRANT_DURATION_SECS;
    use crate::prelude::*;
    use time::OffsetDateTime;

    const UUID_TB_GROUP: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e001");
    const UUID_TB_CAPPED: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e002");
    const UUID_TB_PLAIN: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e003");
    const UUID_TB_MANAGERS: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e004");
    const UUID_TB_MANAGER: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e005");
    const UUID_TB_OUTSIDER: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e006");
    const UUID_TB_TARGET: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e007");
    const UUID_TB_READER: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e008");

    /// The cap of `UUID_TB_CAPPED`, in seconds.
    const CAPPED_MAX: u32 = 3600;

    fn person(name: &str, uuid: Uuid) -> EntryInitNew {
        entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname(name)),
            (Attribute::Uuid, Value::Uuid(uuid)),
            (Attribute::DisplayName, Value::new_utf8s(name))
        )
    }

    fn group(name: &str, uuid: Uuid, time_bounded: bool) -> EntryInitNew {
        let mut entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname(name)),
            (Attribute::Uuid, Value::Uuid(uuid)),
            (Attribute::EntryManagedBy, Value::Refer(UUID_TB_MANAGERS))
        );
        if time_bounded {
            entry.add_ava(Attribute::Class, EntryClass::TimeBoundedGrant.to_value());
        }
        entry
    }

    /// Create the fixture: three managed groups (time-bounded, time-bounded with a cap,
    /// and plain), a group of managers holding one manager, an outsider and a target.
    async fn setup(server: &QueryServer, ct: Duration) {
        let mut capped = group("tb_capped", UUID_TB_CAPPED, true);
        capped.add_ava(Attribute::MaxGrantDuration, Value::Uint32(CAPPED_MAX));

        let managers = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("tb_managers")),
            (Attribute::Uuid, Value::Uuid(UUID_TB_MANAGERS)),
            (Attribute::Member, Value::ReferN(UUID_TB_MANAGER))
        );

        let mut server_txn = server.write(ct).await.expect("txn");
        server_txn
            .internal_create(vec![
                person("tb_manager", UUID_TB_MANAGER),
                person("tb_outsider", UUID_TB_OUTSIDER),
                person("tb_target", UUID_TB_TARGET),
                managers,
                group("tb_group", UUID_TB_GROUP, true),
                capped,
                group("tb_plain", UUID_TB_PLAIN, false),
            ])
            .expect("create");
        server_txn.commit().expect("commit");
    }

    fn ident_of(server_txn: &mut QueryServerWriteTransaction, uuid: Uuid) -> Identity {
        let entry = server_txn.internal_search_uuid(uuid).expect("entry");
        Identity::from_impersonate_entry_readwrite(entry)
    }

    fn is_memberof(
        server_txn: &mut QueryServerWriteTransaction,
        member: Uuid,
        group: Uuid,
    ) -> bool {
        server_txn
            .internal_search_uuid(member)
            .expect("member")
            .attribute_equality(Attribute::MemberOf, &PartialValue::Refer(group))
    }

    fn odt(ct: Duration) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + ct
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    fn invalid_attribute(res: Result<(), OperationError>) -> bool {
        matches!(res.err(), Some(OperationError::InvalidAttribute(_)))
    }

    #[qs_test]
    async fn test_time_bounded_grant_and_revoke(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        setup(server, ct).await;

        let mut server_txn = server.write(ct).await.expect("txn");
        let manager = ident_of(&mut server_txn, UUID_TB_MANAGER);

        assert!(!is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));

        // A grant within the default cap is reflected in memberof immediately.
        let until = odt(ct + secs(86_400));
        server_txn
            .grant_time_bounded_member(&manager, UUID_TB_GROUP, UUID_TB_TARGET, None, until)
            .expect("grant");
        assert!(is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));

        let grants = server_txn
            .time_bounded_member_list(&manager, UUID_TB_GROUP)
            .expect("list");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].member, UUID_TB_TARGET);
        assert!(grants[0]
            .member_spn
            .as_deref()
            .is_some_and(|spn| spn.starts_with("tb_target@")));
        assert_eq!(grants[0].valid_from, None);
        assert_eq!(grants[0].valid_until, until);

        // A second grant replaces the first: a future start removes the membership.
        let from = odt(ct + secs(600));
        let until = odt(ct + secs(1200));
        server_txn
            .grant_time_bounded_member(&manager, UUID_TB_GROUP, UUID_TB_TARGET, Some(from), until)
            .expect("replace grant");
        assert!(!is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));
        let grants = server_txn
            .time_bounded_member_list(&manager, UUID_TB_GROUP)
            .expect("list");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].valid_from, Some(from));
        assert_eq!(grants[0].valid_until, until);

        // Back to an active grant, then revoke it.
        server_txn
            .grant_time_bounded_member(
                &manager,
                UUID_TB_GROUP,
                UUID_TB_TARGET,
                None,
                odt(ct + secs(3600)),
            )
            .expect("grant");
        assert!(is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));

        server_txn
            .revoke_time_bounded_member(&manager, UUID_TB_GROUP, UUID_TB_TARGET)
            .expect("revoke");
        assert!(!is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));
        assert!(server_txn
            .time_bounded_member_list(&manager, UUID_TB_GROUP)
            .expect("list")
            .is_empty());

        // Revoking a grant that does not exist is reported as missing.
        assert_eq!(
            server_txn.revoke_time_bounded_member(&manager, UUID_TB_GROUP, UUID_TB_TARGET),
            Err(OperationError::NoMatchingEntries)
        );

        server_txn.commit().expect("commit");
    }

    #[qs_test]
    async fn test_time_bounded_grant_cap(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        setup(server, ct).await;

        let mut server_txn = server.write(ct).await.expect("txn");
        let manager = ident_of(&mut server_txn, UUID_TB_MANAGER);
        let cap = u64::from(CAPPED_MAX);

        // Exceeding the cap of the group is rejected.
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &manager,
            UUID_TB_CAPPED,
            UUID_TB_TARGET,
            None,
            odt(ct + secs(cap + 1)),
        )));
        // The cap counts from the start of the grant ...
        server_txn
            .grant_time_bounded_member(
                &manager,
                UUID_TB_CAPPED,
                UUID_TB_TARGET,
                Some(odt(ct + secs(cap))),
                odt(ct + secs(2 * cap)),
            )
            .expect("grant within the cap from a future start");
        // ... but never from before now.
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &manager,
            UUID_TB_CAPPED,
            UUID_TB_TARGET,
            Some(odt(ct - secs(cap))),
            odt(ct + secs(cap + 1)),
        )));
        // Exactly the cap is allowed.
        server_txn
            .grant_time_bounded_member(
                &manager,
                UUID_TB_CAPPED,
                UUID_TB_TARGET,
                None,
                odt(ct + secs(cap)),
            )
            .expect("grant at the cap");
        assert!(is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_CAPPED));

        // Without max_grant_duration the default cap applies.
        let default_cap = u64::from(DEFAULT_MAX_GRANT_DURATION_SECS);
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &manager,
            UUID_TB_GROUP,
            UUID_TB_TARGET,
            None,
            odt(ct + secs(default_cap + 1)),
        )));
        server_txn
            .grant_time_bounded_member(
                &manager,
                UUID_TB_GROUP,
                UUID_TB_TARGET,
                None,
                odt(ct + secs(default_cap)),
            )
            .expect("grant at the default cap");

        server_txn.commit().expect("commit");
    }

    #[qs_test]
    async fn test_time_bounded_grant_rejects_invalid(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        setup(server, ct).await;

        let mut server_txn = server.write(ct).await.expect("txn");
        let manager = ident_of(&mut server_txn, UUID_TB_MANAGER);
        let until = odt(ct + secs(3600));

        // A valid_until in the past, or at now, is rejected.
        for valid_until in [odt(ct - secs(1)), odt(ct)] {
            assert!(invalid_attribute(server_txn.grant_time_bounded_member(
                &manager,
                UUID_TB_GROUP,
                UUID_TB_TARGET,
                None,
                valid_until,
            )));
        }
        // As is one that does not end after valid_from.
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &manager,
            UUID_TB_GROUP,
            UUID_TB_TARGET,
            Some(until),
            until,
        )));

        // A group without the time_bounded_grant class is rejected, even though the
        // manager may change its members.
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &manager,
            UUID_TB_PLAIN,
            UUID_TB_TARGET,
            None,
            until,
        )));

        // The member must exist, and be a person, group or service account.
        assert_eq!(
            server_txn.grant_time_bounded_member(
                &manager,
                UUID_TB_GROUP,
                Uuid::new_v4(),
                None,
                until
            ),
            Err(OperationError::NoMatchingEntries)
        );
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &manager,
            UUID_TB_GROUP,
            UUID_DOMAIN_INFO,
            None,
            until,
        )));
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &manager,
            UUID_TB_GROUP,
            UUID_TB_GROUP,
            None,
            until,
        )));

        // A group may be granted.
        server_txn
            .grant_time_bounded_member(&manager, UUID_TB_GROUP, UUID_TB_PLAIN, None, until)
            .expect("grant a group");
        assert!(is_memberof(&mut server_txn, UUID_TB_PLAIN, UUID_TB_GROUP));

        assert!(server_txn
            .internal_search_uuid(UUID_TB_GROUP)
            .expect("group")
            .get_ava_as_time_bounded_member(Attribute::TimeBoundedMemberAttr)
            .is_some_and(|grants| grants.len() == 1));

        server_txn.commit().expect("commit");
    }

    fn denied<T>(res: Result<T, OperationError>) -> bool {
        matches!(
            res.err(),
            Some(OperationError::AccessDenied | OperationError::NoMatchingEntries)
        )
    }

    #[qs_test]
    async fn test_time_bounded_grant_authorisation(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        setup(server, ct).await;

        let mut server_txn = server.write(ct).await.expect("txn");
        let until = odt(ct + secs(3600));

        // A reader can see the group and its members, but not change them.
        server_txn
            .internal_create(vec![person("tb_reader", UUID_TB_READER)])
            .expect("create reader");
        server_txn
            .internal_modify_uuid(
                UUID_IDM_ACCESS_CONTROL_ADMINS,
                &ModifyList::new_append(Attribute::Member, Value::ReferN(UUID_TB_READER)),
            )
            .expect("add reader");

        let manager = ident_of(&mut server_txn, UUID_TB_MANAGER);
        let outsider = ident_of(&mut server_txn, UUID_TB_OUTSIDER);
        let reader = ident_of(&mut server_txn, UUID_TB_READER);

        // Unauthorised callers are denied.
        assert!(denied(server_txn.grant_time_bounded_member(
            &outsider,
            UUID_TB_GROUP,
            UUID_TB_OUTSIDER,
            None,
            until,
        )));
        assert_eq!(
            server_txn.grant_time_bounded_member(
                &reader,
                UUID_TB_GROUP,
                UUID_TB_READER,
                None,
                until
            ),
            Err(OperationError::AccessDenied)
        );
        assert!(!is_memberof(
            &mut server_txn,
            UUID_TB_OUTSIDER,
            UUID_TB_GROUP
        ));
        assert!(!is_memberof(&mut server_txn, UUID_TB_READER, UUID_TB_GROUP));

        // The manager (an entry manager of the group, through the builtin access controls)
        // may grant.
        server_txn
            .grant_time_bounded_member(&manager, UUID_TB_GROUP, UUID_TB_TARGET, None, until)
            .expect("grant");
        assert!(is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));

        // Revoking and listing are authorised the same way.
        assert!(denied(server_txn.revoke_time_bounded_member(
            &outsider,
            UUID_TB_GROUP,
            UUID_TB_TARGET
        )));
        assert_eq!(
            server_txn.revoke_time_bounded_member(&reader, UUID_TB_GROUP, UUID_TB_TARGET),
            Err(OperationError::AccessDenied)
        );
        assert!(denied(
            server_txn.time_bounded_member_list(&outsider, UUID_TB_GROUP)
        ));
        assert_eq!(
            server_txn
                .time_bounded_member_list(&reader, UUID_TB_GROUP)
                .map(|grants| grants.len()),
            Ok(1)
        );
        assert!(is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));

        // A read-only session of the manager may list, but not grant or revoke.
        let manager_entry = server_txn
            .internal_search_uuid(UUID_TB_MANAGER)
            .expect("manager");
        let manager_ro = Identity::from_impersonate_entry_readonly(manager_entry);
        assert_eq!(
            server_txn
                .time_bounded_member_list(&manager_ro, UUID_TB_GROUP)
                .map(|grants| grants.len()),
            Ok(1)
        );
        assert_eq!(
            server_txn.grant_time_bounded_member(
                &manager_ro,
                UUID_TB_GROUP,
                UUID_TB_OUTSIDER,
                None,
                until
            ),
            Err(OperationError::AccessDenied)
        );
        assert_eq!(
            server_txn.revoke_time_bounded_member(&manager_ro, UUID_TB_GROUP, UUID_TB_TARGET),
            Err(OperationError::AccessDenied)
        );

        // The rights follow the access controls: once the outsider is the entry manager,
        // the outsider may grant and the former manager may not.
        server_txn
            .internal_modify_uuid(
                UUID_TB_GROUP,
                &ModifyList::new_purge_and_set(
                    Attribute::EntryManagedBy,
                    Value::Refer(UUID_TB_OUTSIDER),
                ),
            )
            .expect("change entry manager");
        let outsider = ident_of(&mut server_txn, UUID_TB_OUTSIDER);
        let manager = ident_of(&mut server_txn, UUID_TB_MANAGER);
        server_txn
            .grant_time_bounded_member(&outsider, UUID_TB_GROUP, UUID_TB_OUTSIDER, None, until)
            .expect("the new entry manager may grant");
        assert!(denied(server_txn.grant_time_bounded_member(
            &manager,
            UUID_TB_GROUP,
            UUID_TB_MANAGER,
            None,
            until,
        )));
        assert!(denied(server_txn.revoke_time_bounded_member(
            &manager,
            UUID_TB_GROUP,
            UUID_TB_TARGET
        )));
        assert!(is_memberof(
            &mut server_txn,
            UUID_TB_OUTSIDER,
            UUID_TB_GROUP
        ));
        assert!(!is_memberof(
            &mut server_txn,
            UUID_TB_MANAGER,
            UUID_TB_GROUP
        ));

        server_txn.commit().expect("commit");
    }
}
