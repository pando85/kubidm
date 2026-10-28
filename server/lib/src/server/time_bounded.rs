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
//!   existing grant that is active or yet to start additionally needs it in the allowed
//!   removed attributes (replacing an expired grant is only an addition);
//! - revoking needs `member` in the allowed removed attributes;
//! - listing needs `member` in the caller's readable attributes.
//!
//! Read-only sessions get no modify rights from the access controls, so they can only
//! list. Enabling the class and setting `max_grant_duration` on a group are ordinary
//! attribute writes, allowed to group administrators by `idm_acp_group_time_bounded_manage`
//! (a group's entry managers can not raise its cap).
//!
//! Grants on high privilege groups (`idm_high_privilege` itself and its direct or nested
//! members) are refused, since approvals for high privilege membership are not wired up
//! yet and an internal write would bypass them.
//!
//! # Cap
//!
//! The window of a new grant, from the later of now and `valid_from` to `valid_until`, may
//! not exceed the group's `max_grant_duration` (in seconds), or
//! [`DEFAULT_MAX_GRANT_DURATION_SECS`] when the group does not set one. The start of a
//! grant may also be at most that far in the future.
//!
//! Writing a `max_grant_duration` of 0 is rejected (`plugins::max_grant_duration`), but
//! released versions accepted it, so a group may still hold it (stored, or replicated from
//! such a version). A stored 0 is read as "no grants allowed": the safer reading, and what
//! such a cap always did, since no window fits in 0 seconds. Grants that already exist on
//! the group are left as they are, and can be revoked.

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
        // Normalise both times to UTC first. This is checked: a time that is out of range
        // in UTC (year 9999 with a negative offset) would make `to_offset` panic.
        let grant = TimeBoundedMember::try_new(member, valid_from, valid_until)
            .filter(TimeBoundedMember::has_valid_window)
            .ok_or_else(|| {
                OperationError::InvalidAttribute(
                    "valid_from and valid_until must be valid times that can be stored".to_string(),
                )
            })?;
        let now = self.get_curtime_odt();

        let (entry, rights) = group_member_rights(self, ident, group)?;

        if !rights.add {
            security_access!(%ident, %group, "denied - may not add members to this group");
            return Err(OperationError::AccessDenied);
        }

        // Replacing a grant that is active or yet to start takes it away, so it needs the
        // right to remove members. An expired grant no longer grants anything, so replacing
        // it is just an addition.
        let existing = grant_of(&entry, member);
        let replaces = existing.is_some();
        if existing.is_some_and(|g| g.valid_until > now) && !rights.remove {
            security_access!(
                %ident,
                %group,
                "denied - replacing a current grant requires the right to remove members"
            );
            return Err(OperationError::AccessDenied);
        }

        if !entry.attribute_equality(Attribute::Class, &EntryClass::TimeBoundedGrant.into()) {
            return Err(OperationError::InvalidAttribute(format!(
                "group does not have the {} class",
                EntryClass::TimeBoundedGrant
            )));
        }

        // Kubidm: membership of a high privilege group is meant to be gated by approvals
        // (`ApprovalOperationType::GroupMembershipHighPrivilege`), which is not wired up
        // yet. Grants are written internally, so they would bypass such a gate. Until it
        // exists, refuse grants on high privilege groups, including a group that became high
        // privilege (by nesting) after it was enabled for time-bounded grants.
        if group == UUID_IDM_HIGH_PRIVILEGE
            || entry.attribute_equality(
                Attribute::MemberOf,
                &PartialValue::Refer(UUID_IDM_HIGH_PRIVILEGE),
            )
        {
            security_access!(%ident, %group, "denied - time bounded grant on a high privilege group");
            return Err(OperationError::InvalidAttribute(
                "time-bounded grants are not allowed on high privilege groups".to_string(),
            ));
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

        let start = grant.valid_from.map_or(now, |vf| vf.max(now));
        if grant.valid_until <= start {
            return Err(OperationError::InvalidAttribute(
                "valid_until must be after both the current time and valid_from".to_string(),
            ));
        }

        let max_secs = entry
            .get_ava_single_uint32(Attribute::MaxGrantDuration)
            .unwrap_or(DEFAULT_MAX_GRANT_DURATION_SECS);
        // A stored cap of 0 (accepted by released versions) allows no grant, see the module
        // documentation.
        if max_secs == 0 {
            return Err(OperationError::InvalidAttribute(
                "the maximum grant duration of this group is 0, which allows no grant: set it \
                 to a positive number of seconds, or remove it to use the default"
                    .to_string(),
            ));
        }
        let max = time::Duration::seconds(i64::from(max_secs));
        if grant.valid_until - start > max {
            return Err(OperationError::InvalidAttribute(format!(
                "the grant exceeds the maximum grant duration of this group ({max_secs} seconds)"
            )));
        }
        // The start is bounded by the same cap, so that a grant can not be planted to start
        // long after the granter has lost the right to grant it.
        if start - now > max {
            return Err(OperationError::InvalidAttribute(format!(
                "the grant starts later than the maximum grant duration of this group \
                 ({max_secs} seconds) from now"
            )));
        }

        security_info!(
            %ident,
            %group,
            %member,
            valid_from = ?grant.valid_from,
            valid_until = %grant.valid_until,
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
    use crate::value::TimeBoundedMember;
    use time::OffsetDateTime;

    const UUID_TB_GROUP: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e001");
    const UUID_TB_CAPPED: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e002");
    const UUID_TB_PLAIN: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e003");
    const UUID_TB_MANAGERS: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e004");
    const UUID_TB_MANAGER: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e005");
    const UUID_TB_OUTSIDER: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e006");
    const UUID_TB_TARGET: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e007");
    const UUID_TB_READER: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e008");
    const UUID_TB_GROUP_ADMIN: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e009");
    const UUID_TB_HP_PARENT: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e00a");
    const UUID_TB_ADDER: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e00b");
    const UUID_TB_ADDERS: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e00c");
    const UUID_TB_SYNC_ACCOUNT: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e00d");
    const UUID_TB_SYNC_GROUP: Uuid = uuid::uuid!("7b2f8d2e-4b0e-4a43-a39b-3d27a5c1e00e");

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

    /// Add `member` to `group` internally.
    fn add_member(server_txn: &mut QueryServerWriteTransaction, group: Uuid, member: Uuid) {
        server_txn
            .internal_modify_uuid(
                group,
                &ModifyList::new_append(Attribute::Member, Value::ReferN(member)),
            )
            .expect("add member");
    }

    /// Store a grant directly, bypassing the checks of the grant operation.
    fn store_grant(
        server_txn: &mut QueryServerWriteTransaction,
        group: Uuid,
        grant: TimeBoundedMember,
    ) {
        server_txn
            .internal_modify_uuid(
                group,
                &ModifyList::new_list(vec![
                    Modify::Removed(
                        Attribute::TimeBoundedMemberAttr,
                        PartialValue::TimeBoundedMember(grant.uuid),
                    ),
                    Modify::Present(
                        Attribute::TimeBoundedMemberAttr,
                        Value::TimeBoundedMember(grant),
                    ),
                ]),
            )
            .expect("store grant");
    }

    /// Modify `target` as `ident` through the normal (access controlled) modify path.
    fn modify_as(
        server_txn: &mut QueryServerWriteTransaction,
        ident: &Identity,
        target: Uuid,
        mods: Vec<Modify>,
    ) -> Result<(), OperationError> {
        let me = ModifyEvent::new_impersonate_identity(
            ident.clone(),
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(target))),
            ModifyList::new_list(mods),
        );
        server_txn.modify(&me)
    }

    #[qs_test]
    async fn test_time_bounded_grant_out_of_range_times(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        setup(server, ct).await;

        let mut server_txn = server.write(ct).await.expect("txn");
        let manager = ident_of(&mut server_txn, UUID_TB_MANAGER);

        // The reported input: valid_until is in year 10000 once converted to UTC. This used
        // to panic in to_offset.
        let from = OffsetDateTime::parse("9999-12-31T00:00:00-23:59", &Rfc3339).expect("from");
        let until = OffsetDateTime::parse("9999-12-31T23:59:59-23:59", &Rfc3339).expect("until");
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &manager,
            UUID_TB_GROUP,
            UUID_TB_TARGET,
            Some(from),
            until,
        )));
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &manager,
            UUID_TB_GROUP,
            UUID_TB_TARGET,
            None,
            until,
        )));
        // A valid_from that is out of range in UTC.
        let late_from = OffsetDateTime::parse("9999-12-31T01:00:00-23:59", &Rfc3339).expect("from");
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &manager,
            UUID_TB_GROUP,
            UUID_TB_TARGET,
            Some(late_from),
            odt(ct + secs(60)),
        )));

        // The transaction is still usable.
        server_txn
            .grant_time_bounded_member(
                &manager,
                UUID_TB_GROUP,
                UUID_TB_TARGET,
                None,
                odt(ct + secs(60)),
            )
            .expect("grant");
        server_txn.commit().expect("commit");
    }

    #[qs_test]
    async fn test_time_bounded_grant_start_limited_by_cap(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        setup(server, ct).await;

        let mut server_txn = server.write(ct).await.expect("txn");
        let manager = ident_of(&mut server_txn, UUID_TB_MANAGER);
        let cap = u64::from(CAPPED_MAX);

        // A grant may not start more than the cap from now, however short it is.
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &manager,
            UUID_TB_CAPPED,
            UUID_TB_TARGET,
            Some(odt(ct + secs(cap + 1))),
            odt(ct + secs(cap + 2)),
        )));
        let default_cap = u64::from(DEFAULT_MAX_GRANT_DURATION_SECS);
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &manager,
            UUID_TB_GROUP,
            UUID_TB_TARGET,
            Some(odt(ct + secs(default_cap + 1))),
            odt(ct + secs(default_cap + 60)),
        )));
        // Exactly at the cap is allowed.
        server_txn
            .grant_time_bounded_member(
                &manager,
                UUID_TB_CAPPED,
                UUID_TB_TARGET,
                Some(odt(ct + secs(cap))),
                odt(ct + secs(cap + 1)),
            )
            .expect("grant starting at the cap");
        server_txn.commit().expect("commit");
    }

    #[qs_test]
    async fn test_time_bounded_max_grant_duration_zero_rejected(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        setup(server, ct).await;

        let mut server_txn = server.write(ct).await.expect("txn");
        assert!(matches!(
            server_txn.internal_modify_uuid(
                UUID_TB_GROUP,
                &ModifyList::new_purge_and_set(Attribute::MaxGrantDuration, Value::Uint32(0)),
            ),
            Err(OperationError::SchemaViolation(_))
        ));
        server_txn
            .internal_modify_uuid(
                UUID_TB_GROUP,
                &ModifyList::new_purge_and_set(Attribute::MaxGrantDuration, Value::Uint32(1)),
            )
            .expect("a positive cap");

        // Nor can a group be created with it.
        let mut zero = group("tb_zero", Uuid::new_v4(), true);
        zero.add_ava(Attribute::MaxGrantDuration, Value::Uint32(0));
        assert!(matches!(
            server_txn.internal_create(vec![zero]),
            Err(OperationError::SchemaViolation(_))
        ));
        server_txn.commit().expect("commit");
    }

    #[qs_test]
    async fn test_time_bounded_stored_zero_cap_allows_no_grant(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        setup(server, ct).await;

        // Plant a grant, then a cap of 0 as a released version could store it (or
        // replicate it), bypassing the write checks.
        let mut server_txn = server.write(ct).await.expect("txn");
        server_txn
            .grant_time_bounded_member(
                &Identity::from_internal(),
                UUID_TB_GROUP,
                UUID_TB_TARGET,
                None,
                odt(ct + secs(3600)),
            )
            .expect("grant");
        let filt = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_TB_GROUP)));
        let mut work_set = server_txn.internal_search_writeable(&filt).expect("search");
        for (_, entry) in work_set.iter_mut() {
            entry.set_ava(&Attribute::MaxGrantDuration, [Value::Uint32(0)]);
        }
        server_txn
            .internal_apply_writable(work_set)
            .expect("plant 0");
        server_txn.commit().expect("commit");

        let mut server_txn = server.write(ct).await.expect("txn");
        assert_eq!(
            server_txn
                .internal_search_uuid(UUID_TB_GROUP)
                .expect("group")
                .get_ava_single_uint32(Attribute::MaxGrantDuration),
            Some(0)
        );
        // The group can still be modified, as long as the cap is left as it is.
        server_txn
            .internal_modify_uuid(
                UUID_TB_GROUP,
                &ModifyList::new_append(Attribute::Member, Value::ReferN(UUID_TB_OUTSIDER)),
            )
            .expect("add a member to a group with a stored cap of 0");
        assert!(is_memberof(
            &mut server_txn,
            UUID_TB_OUTSIDER,
            UUID_TB_GROUP
        ));
        // The existing grant stays active.
        assert!(is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));

        // A stored 0 allows no new grant.
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &Identity::from_internal(),
            UUID_TB_GROUP,
            UUID_TB_MANAGER,
            None,
            odt(ct + secs(1)),
        )));
        // The existing grant can be revoked.
        server_txn
            .revoke_time_bounded_member(&Identity::from_internal(), UUID_TB_GROUP, UUID_TB_TARGET)
            .expect("revoke");
        assert!(!is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));

        // The cap can be fixed, but not set to 0 again.
        server_txn
            .internal_modify_uuid(
                UUID_TB_GROUP,
                &ModifyList::new_purge_and_set(Attribute::MaxGrantDuration, Value::Uint32(60)),
            )
            .expect("a positive cap");
        assert!(matches!(
            server_txn.internal_modify_uuid(
                UUID_TB_GROUP,
                &ModifyList::new_purge_and_set(Attribute::MaxGrantDuration, Value::Uint32(0)),
            ),
            Err(OperationError::SchemaViolation(_))
        ));
        server_txn.commit().expect("commit");
    }

    #[qs_test]
    async fn test_time_bounded_grant_refused_on_high_privilege(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        setup(server, ct).await;

        let mut server_txn = server.write(ct).await.expect("txn");
        let manager = ident_of(&mut server_txn, UUID_TB_MANAGER);
        let until = odt(ct + secs(3600));

        server_txn
            .grant_time_bounded_member(&manager, UUID_TB_GROUP, UUID_TB_TARGET, None, until)
            .expect("grant before the group is high privilege");

        // Nest the (already enabled) group into a high privilege group, transitively.
        server_txn
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Name, Value::new_iname("tb_hp_parent")),
                (Attribute::Uuid, Value::Uuid(UUID_TB_HP_PARENT)),
                (Attribute::Member, Value::ReferN(UUID_TB_GROUP))
            )])
            .expect("create parent");
        add_member(&mut server_txn, UUID_IDM_HIGH_PRIVILEGE, UUID_TB_HP_PARENT);
        assert!(server_txn
            .internal_search_uuid(UUID_TB_GROUP)
            .expect("group")
            .attribute_equality(
                Attribute::MemberOf,
                &PartialValue::Refer(UUID_IDM_HIGH_PRIVILEGE)
            ));

        // The entry manager may still change the members, but not grant.
        let manager = ident_of(&mut server_txn, UUID_TB_MANAGER);
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &manager,
            UUID_TB_GROUP,
            UUID_TB_OUTSIDER,
            None,
            until,
        )));
        // Not even as the internal identity.
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &Identity::from_internal(),
            UUID_TB_GROUP,
            UUID_TB_OUTSIDER,
            None,
            until,
        )));
        assert!(!is_memberof(
            &mut server_txn,
            UUID_TB_OUTSIDER,
            UUID_TB_GROUP
        ));

        // A direct member of idm_high_privilege is refused too.
        add_member(&mut server_txn, UUID_IDM_HIGH_PRIVILEGE, UUID_TB_CAPPED);
        assert!(invalid_attribute(server_txn.grant_time_bounded_member(
            &Identity::from_internal(),
            UUID_TB_CAPPED,
            UUID_TB_OUTSIDER,
            None,
            until,
        )));

        // Existing grants can still be revoked.
        server_txn
            .revoke_time_bounded_member(&manager, UUID_TB_GROUP, UUID_TB_TARGET)
            .expect("revoke");
        assert!(!is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));
        server_txn.commit().expect("commit");
    }

    #[qs_test]
    async fn test_time_bounded_grants_inactive_on_group_that_became_high_privilege(
        server: &QueryServer,
    ) {
        let ct = duration_from_epoch_now();
        setup(server, ct).await;

        // A grant that starts later, and one that is active now.
        let mut server_txn = server.write(ct).await.expect("txn");
        let manager = ident_of(&mut server_txn, UUID_TB_MANAGER);
        server_txn
            .grant_time_bounded_member(
                &manager,
                UUID_TB_GROUP,
                UUID_TB_TARGET,
                Some(odt(ct + secs(60))),
                odt(ct + secs(3600)),
            )
            .expect("future grant");
        server_txn
            .grant_time_bounded_member(
                &manager,
                UUID_TB_GROUP,
                UUID_TB_OUTSIDER,
                None,
                odt(ct + secs(3600)),
            )
            .expect("active grant");
        assert!(is_memberof(
            &mut server_txn,
            UUID_TB_OUTSIDER,
            UUID_TB_GROUP
        ));

        // The group becomes high privilege, by nesting.
        server_txn
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Name, Value::new_iname("tb_hp_parent")),
                (Attribute::Uuid, Value::Uuid(UUID_TB_HP_PARENT)),
                (Attribute::Member, Value::ReferN(UUID_TB_GROUP))
            )])
            .expect("create parent");
        add_member(&mut server_txn, UUID_IDM_HIGH_PRIVILEGE, UUID_TB_HP_PARENT);
        // The active grant no longer grants anything.
        assert!(!is_memberof(
            &mut server_txn,
            UUID_TB_OUTSIDER,
            UUID_TB_GROUP
        ));
        assert!(!is_memberof(
            &mut server_txn,
            UUID_TB_OUTSIDER,
            UUID_IDM_HIGH_PRIVILEGE
        ));
        server_txn.commit().expect("commit");

        // Once the future grant starts, the refresh does not activate it.
        let later = ct + secs(120);
        let mut server_txn = server.write(later).await.expect("txn");
        assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(0));
        assert!(!is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));
        assert!(!is_memberof(
            &mut server_txn,
            UUID_TB_TARGET,
            UUID_IDM_HIGH_PRIVILEGE
        ));
        // Nor does a write that recomputes the member's memberof.
        server_txn
            .internal_modify_uuid(
                UUID_TB_TARGET,
                &ModifyList::new_purge_and_set(Attribute::DisplayName, Value::new_utf8s("t")),
            )
            .expect("modify target");
        assert!(!is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));

        // The grants can still be revoked.
        server_txn
            .revoke_time_bounded_member(&Identity::from_internal(), UUID_TB_GROUP, UUID_TB_TARGET)
            .expect("revoke");

        // Once the group is no longer high privilege, the remaining grant applies again.
        server_txn
            .internal_modify_uuid(
                UUID_IDM_HIGH_PRIVILEGE,
                &ModifyList::new_remove(Attribute::Member, PartialValue::Refer(UUID_TB_HP_PARENT)),
            )
            .expect("remove parent from high privilege");
        assert!(is_memberof(
            &mut server_txn,
            UUID_TB_OUTSIDER,
            UUID_TB_GROUP
        ));
        assert!(!is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));
        server_txn.commit().expect("commit");
    }

    #[qs_test]
    async fn test_time_bounded_replace_expired_needs_only_add(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        setup(server, ct).await;

        // An access control that lets tb_adders add, but not remove, members of tb_group.
        let mut acp = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlProfile.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlReceiverGroup.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlTargetScope.to_value()
            ),
            (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
            (Attribute::Class, EntryClass::AccessControlModify.to_value()),
            (Attribute::Name, Value::new_iname("tb_add_only")),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4())),
            (Attribute::AcpReceiverGroup, Value::ReferN(UUID_TB_ADDERS)),
            (
                Attribute::AcpTargetScope,
                Value::new_json_filter_s("{\"eq\":[\"name\",\"tb_group\"]}").expect("filter")
            ),
            (
                Attribute::AcpModifyPresentAttr,
                Value::new_iutf8n(Attribute::Member.as_str())
            )
        );
        for attr in [
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Member,
        ] {
            acp.add_ava(Attribute::AcpSearchAttr, Value::new_iutf8n(attr.as_str()));
        }

        let mut server_txn = server.write(ct).await.expect("txn");
        server_txn
            .internal_create(vec![
                person("tb_adder", UUID_TB_ADDER),
                entry_init!(
                    (Attribute::Class, EntryClass::Object.to_value()),
                    (Attribute::Class, EntryClass::Group.to_value()),
                    (Attribute::Name, Value::new_iname("tb_adders")),
                    (Attribute::Uuid, Value::Uuid(UUID_TB_ADDERS)),
                    (Attribute::Member, Value::ReferN(UUID_TB_ADDER))
                ),
                acp,
            ])
            .expect("create");
        server_txn.commit().expect("commit");

        let mut server_txn = server.write(ct).await.expect("txn");
        let adder = ident_of(&mut server_txn, UUID_TB_ADDER);
        let until = odt(ct + secs(3600));

        // A new grant needs only add rights.
        server_txn
            .grant_time_bounded_member(&adder, UUID_TB_GROUP, UUID_TB_TARGET, None, until)
            .expect("new grant");

        // Replacing a current grant would remove it, so it is denied.
        assert_eq!(
            server_txn.grant_time_bounded_member(
                &adder,
                UUID_TB_GROUP,
                UUID_TB_TARGET,
                None,
                odt(ct + secs(60))
            ),
            Err(OperationError::AccessDenied)
        );

        // As is replacing one that has not started yet.
        store_grant(
            &mut server_txn,
            UUID_TB_GROUP,
            TimeBoundedMember::new(
                UUID_TB_TARGET,
                Some(odt(ct + secs(600))),
                odt(ct + secs(1200)),
            ),
        );
        assert_eq!(
            server_txn.grant_time_bounded_member(
                &adder,
                UUID_TB_GROUP,
                UUID_TB_TARGET,
                None,
                until
            ),
            Err(OperationError::AccessDenied)
        );

        // An expired grant grants nothing, so replacing it is only an addition.
        store_grant(
            &mut server_txn,
            UUID_TB_GROUP,
            TimeBoundedMember::new(UUID_TB_TARGET, None, odt(ct - secs(10))),
        );
        assert!(!is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));
        server_txn
            .grant_time_bounded_member(&adder, UUID_TB_GROUP, UUID_TB_TARGET, None, until)
            .expect("replace an expired grant");
        assert!(is_memberof(&mut server_txn, UUID_TB_TARGET, UUID_TB_GROUP));

        // Revoking always needs remove rights.
        assert_eq!(
            server_txn.revoke_time_bounded_member(&adder, UUID_TB_GROUP, UUID_TB_TARGET),
            Err(OperationError::AccessDenied)
        );
        server_txn.commit().expect("commit");
    }

    #[qs_test]
    async fn test_time_bounded_enable_and_cap_rights(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        setup(server, ct).await;

        let mut server_txn = server.write(ct).await.expect("txn");
        server_txn
            .internal_create(vec![person("tb_group_admin", UUID_TB_GROUP_ADMIN)])
            .expect("create");
        add_member(&mut server_txn, UUID_IDM_GROUP_ADMINS, UUID_TB_GROUP_ADMIN);
        // tb_capped becomes high privilege.
        add_member(&mut server_txn, UUID_IDM_HIGH_PRIVILEGE, UUID_TB_CAPPED);

        let group_admin = ident_of(&mut server_txn, UUID_TB_GROUP_ADMIN);
        let manager = ident_of(&mut server_txn, UUID_TB_MANAGER);
        let enable = || {
            vec![
                Modify::Present(Attribute::Class, EntryClass::TimeBoundedGrant.to_value()),
                Modify::Purged(Attribute::MaxGrantDuration),
                Modify::Present(Attribute::MaxGrantDuration, Value::Uint32(600)),
            ]
        };

        // A group admin may enable time-bounded grants and set the cap in one modify ...
        modify_as(&mut server_txn, &group_admin, UUID_TB_PLAIN, enable())
            .expect("group admin enables");
        let plain = server_txn
            .internal_search_uuid(UUID_TB_PLAIN)
            .expect("group");
        assert!(plain.attribute_equality(Attribute::Class, &EntryClass::TimeBoundedGrant.into()));
        assert_eq!(
            plain.get_ava_single_uint32(Attribute::MaxGrantDuration),
            Some(600)
        );

        // ... but not on a high privilege group,
        assert!(denied(modify_as(
            &mut server_txn,
            &group_admin,
            UUID_TB_CAPPED,
            vec![Modify::Present(
                Attribute::MaxGrantDuration,
                Value::Uint32(600)
            )],
        )));
        assert!(denied(modify_as(
            &mut server_txn,
            &group_admin,
            UUID_TB_CAPPED,
            vec![Modify::Removed(
                Attribute::Class,
                EntryClass::TimeBoundedGrant.into()
            )],
        )));
        // and it may not grant there either: it has no member rights on it.
        assert!(denied(server_txn.grant_time_bounded_member(
            &group_admin,
            UUID_TB_CAPPED,
            UUID_TB_TARGET,
            None,
            odt(ct + secs(60)),
        )));

        // An entry manager can neither set the cap nor enable the class.
        assert_eq!(
            modify_as(
                &mut server_txn,
                &manager,
                UUID_TB_GROUP,
                vec![Modify::Present(
                    Attribute::MaxGrantDuration,
                    Value::Uint32(u32::MAX)
                )],
            ),
            Err(OperationError::AccessDenied)
        );
        assert_eq!(
            modify_as(
                &mut server_txn,
                &manager,
                UUID_TB_PLAIN,
                vec![Modify::Purged(Attribute::MaxGrantDuration)],
            ),
            Err(OperationError::AccessDenied)
        );
        server_txn.commit().expect("commit");
    }

    #[qs_test]
    async fn test_time_bounded_grant_refused_on_sync_object(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        setup(server, ct).await;

        let mut server_txn = server.write(ct).await.expect("txn");
        server_txn
            .internal_create(vec![
                person("tb_group_admin", UUID_TB_GROUP_ADMIN),
                entry_init!(
                    (Attribute::Class, EntryClass::Object.to_value()),
                    (Attribute::Class, EntryClass::SyncAccount.to_value()),
                    (Attribute::Name, Value::new_iname("tb_sync")),
                    (Attribute::Uuid, Value::Uuid(UUID_TB_SYNC_ACCOUNT))
                ),
            ])
            .expect("create");
        let mut sync_group = group("tb_sync_group", UUID_TB_SYNC_GROUP, true);
        sync_group.add_ava(Attribute::Class, EntryClass::SyncObject.to_value());
        sync_group.add_ava(
            Attribute::SyncParentUuid,
            Value::Refer(UUID_TB_SYNC_ACCOUNT),
        );
        server_txn
            .internal_create(vec![sync_group])
            .expect("create sync group");
        add_member(&mut server_txn, UUID_IDM_GROUP_ADMINS, UUID_TB_GROUP_ADMIN);

        // The members of a synchronised group belong to the sync agreement: neither a
        // group admin nor an entry manager may add members, so neither may grant.
        for caller in [UUID_TB_GROUP_ADMIN, UUID_TB_MANAGER] {
            let ident = ident_of(&mut server_txn, caller);
            assert!(denied(modify_as(
                &mut server_txn,
                &ident,
                UUID_TB_SYNC_GROUP,
                vec![Modify::Present(
                    Attribute::Member,
                    Value::ReferN(UUID_TB_TARGET)
                )],
            )));
            assert_eq!(
                server_txn.grant_time_bounded_member(
                    &ident,
                    UUID_TB_SYNC_GROUP,
                    UUID_TB_TARGET,
                    None,
                    odt(ct + secs(60))
                ),
                Err(OperationError::AccessDenied)
            );
        }
        server_txn.commit().expect("commit");
    }

    /// "May grant" must equal "may add a permanent member", for each kind of caller.
    #[qs_test]
    async fn test_time_bounded_grant_matches_member_add(server: &QueryServer) {
        let ct = duration_from_epoch_now();
        setup(server, ct).await;

        let mut server_txn = server.write(ct).await.expect("txn");
        server_txn
            .internal_create(vec![person("tb_group_admin", UUID_TB_GROUP_ADMIN)])
            .expect("create");
        add_member(&mut server_txn, UUID_IDM_GROUP_ADMINS, UUID_TB_GROUP_ADMIN);
        server_txn.commit().expect("commit");

        let mut server_txn = server.write(ct).await.expect("txn");
        let manager_entry = server_txn
            .internal_search_uuid(UUID_TB_MANAGER)
            .expect("manager");
        let callers = [
            (
                "entry manager",
                ident_of(&mut server_txn, UUID_TB_MANAGER),
                true,
            ),
            (
                "group admin",
                ident_of(&mut server_txn, UUID_TB_GROUP_ADMIN),
                true,
            ),
            (
                "unrelated person",
                ident_of(&mut server_txn, UUID_TB_OUTSIDER),
                false,
            ),
            (
                "read-only session",
                Identity::from_impersonate_entry_readonly(manager_entry),
                false,
            ),
        ];
        drop(server_txn);

        for (name, ident, expected) in callers {
            // Each attempt runs in its own transaction, which is dropped (rolled back).
            let mut server_txn = server.write(ct).await.expect("txn");
            let can_add = modify_as(
                &mut server_txn,
                &ident,
                UUID_TB_GROUP,
                vec![Modify::Present(
                    Attribute::Member,
                    Value::ReferN(UUID_TB_TARGET),
                )],
            )
            .is_ok();
            drop(server_txn);

            let mut server_txn = server.write(ct).await.expect("txn");
            let can_grant = server_txn
                .grant_time_bounded_member(
                    &ident,
                    UUID_TB_GROUP,
                    UUID_TB_TARGET,
                    None,
                    odt(ct + secs(60)),
                )
                .is_ok();
            drop(server_txn);

            assert_eq!(can_add, expected, "{name}: may add a member");
            assert_eq!(can_grant, can_add, "{name}: may grant iff may add a member");
        }
    }
}
