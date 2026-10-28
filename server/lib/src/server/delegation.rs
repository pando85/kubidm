//! Kubidm: template driven delegated administration.
//!
//! A delegation lets the members of a *receiver* group administer the members of a
//! *scope* group, with a fixed set of rights defined here, in code, by a
//! [`DelegationTemplate`]. Administrators never write the access control profile
//! themselves: [`QueryServerWriteTransaction::delegation_grant`] builds it from the
//! template, validates it with the access control parser and creates it internally, and
//! [`QueryServerWriteTransaction::delegation_revoke`] deletes it.
//!
//! # The profile
//!
//! A delegation is one access control profile, named
//! `delegation_<template>_<scope>_<receiver>` from the low 64 bits (16 hex digits) of the
//! uuids of the groups, so that names never depend on (or are confused by) group names.
//! A template is granted once per receiver and scope group, whatever the name. It has:
//!
//! - an `access_control_receiver_group` receiver: the receiver group;
//! - an `access_control_target_delegated_scope` target: the scope group
//!   (`delegated_scope_group`), and a `delegated_scope_filter` of the template's class
//!   terms ANDed with the optional filter given when granting. That filter is stored with
//!   every reference to an entry resolved to its uuid, so that renaming a group never
//!   changes the scope; `self` is refused;
//! - `delegated_role_template`, the template's built-in `delegated_role` entry, and
//!   `delegated_by`, the person who granted it.
//!
//! The access control parser (`access::profiles`) turns the delegated target into the
//! upstream scope target `memberof=<scope> AND <filter> AND NOT (memberof=
//! idm_high_privilege OR uuid=<R> OR memberof=<R> OR recycled OR tombstone)`, for every
//! receiver group R of *any* delegated profile, and every privileged built-in group R of
//! `access::profiles::DELEGATION_EXCLUDED_BUILTINS`. So a delegation only ever reaches the
//! (direct or nested) members of the scope group, never a high privilege entry, never its
//! own receivers (even if they are nested into the scope later) and never the receivers of
//! any delegation, whatever the filter says: the filter can only narrow the scope.
//!
//! # Receivers
//!
//! The receivers excluded from every delegated target are derived from the delegated
//! profiles each time the access controls are reloaded, which they are whenever a profile
//! is created, changed, deleted or revived. Nothing else maintains them, so they can not
//! drift from the profiles (say, under concurrent grants on different replicas).
//!
//! # Entry managers and dynamic groups
//!
//! The entry manager of a group changes its members (`idm_acp_group_entry_manager`), so
//! it could add anyone to the scope, or to the receivers. A grant is refused when the
//! receiver group, the scope group or a group nested in either has an entry manager that
//! is not high privilege, and such an entry manager added later is reported as drift. The
//! members of a dynamic group follow its filter, so a dynamic receiver, scope or group
//! nested in them is refused too.
//!
//! # Creating entries
//!
//! A new entry has no `memberof`, so it is never in a delegated scope, and a create
//! right could never be used. No template grants create: persons are created by
//! `idm_people_admins` or `idm_people_on_boarding`, and enter the scope once they are
//! added to the scope group.
//!
//! # Authorisation
//!
//! Granting, revoking and listing delegations is reserved to `idm_access_control_admins`,
//! the group that administers access control profiles. `idm_acp_acp_manage` does not
//! target delegations (see `migration_data::dl14::kubidm_patch_builtin_acp`), so they are
//! only changed through the operations here. It is high privilege, so a
//! delegation can only be granted by someone who can not be its target. The operations
//! write internally, so the caller is authorised here, explicitly. Granting and revoking
//! need a read-write (privileged) session.
//!
//! The receiver and the scope must be groups that are neither built-in (system range
//! uuids, such as `idm_all_persons`, which would make everybody a receiver or a target)
//! nor high privilege (`idm_high_privilege`, or nested in it). The receiver can not be the
//! scope, nor nested in it, and the scope can not be the receiver of a delegation, nor
//! nested in one (its members would all be excluded). See above for entry managers and
//! dynamic groups.
//!
//! # Drift
//!
//! [`DelegationGrant::drift`] lists how a stored profile differs from what its template
//! grants (say, a profile granted by an older version of a template, or changed by the
//! internal system identity), and all of its receivers are listed.
//!
//! # Lifecycle
//!
//! Deleting the scope group or the receiver group of a delegation is refused while the
//! delegation exists, since the profile would be left invalid (see
//! `QueryServerWriteTransaction::acp_reload_rejects_invalid`): revoke the delegation
//! first.

use crate::prelude::*;
use crate::schema::SchemaTransaction;
use crate::server::access::profiles::{
    delegated_receivers, AccessControlDelete, AccessControlModify, AccessControlSearch,
};
use kubidm_proto::v1::{DelegationGrant, DelegationGroup};
use std::collections::BTreeSet;
use std::sync::Arc;

/// A built-in delegation template: what a delegation grants to its receivers over the
/// entries in its scope. Every template applies to (non high privilege) members of the
/// scope group only, see the module documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DelegationTemplate {
    /// Help desk: find the persons in scope and reset their credentials. The same rights
    /// as upstream's `idm_service_desk` over persons (`idm_acp_people_read` and
    /// `idm_acp_people_credential_reset`).
    Helpdesk,
    /// User administration: read the profile of the persons in scope, modify their display
    /// and legal name and account validity, and delete them. A subset of upstream's
    /// `idm_people_admins` (`idm_acp_people_read`, `idm_acp_people_pii_manage` without the
    /// name and mail, `idm_acp_people_manage` and `idm_acp_people_delete`). No create, see
    /// the module documentation, and no credentials: grant `helpdesk` as well for those.
    ///
    /// The mail address is read only: it is a credential. Kubidm sends account recovery
    /// links to it (`credential_update_account_recovery`), and OAuth2 releases it as a
    /// verified address, so whoever can write it can take over the account. Likewise the
    /// name, which changes how the person logs in.
    UserAdmin,
    /// Group administration, read only: find the groups in scope and read their members.
    /// Managing members is not delegated: a member added to a group in scope becomes a
    /// (nested) member of the scope group, so it would pull any entry (the receivers of
    /// other delegations, OAuth2 scope map groups, POSIX and sudo groups, the receiver
    /// group itself) into the scope. That needs a constraint on the values added, which
    /// access controls can not express yet.
    GroupAdmin,
}

/// What a [`DelegationTemplate`] grants, on the targets of its scope.
#[derive(Clone, Debug)]
pub struct DelegationTemplateGrant {
    /// The targets must have all of these classes.
    pub target_classes: Vec<EntryClass>,
    /// The attributes the receivers may read.
    pub search_attrs: Vec<Attribute>,
    /// The attributes the receivers may set and remove values of. Empty for no modify.
    pub modify_attrs: Vec<Attribute>,
    /// May the receivers delete the targets?
    pub delete: bool,
}

impl DelegationTemplate {
    pub const ALL: [DelegationTemplate; 3] = [
        DelegationTemplate::Helpdesk,
        DelegationTemplate::UserAdmin,
        DelegationTemplate::GroupAdmin,
    ];

    /// The short name of the template, as used in requests and profile names.
    pub fn name(self) -> &'static str {
        match self {
            DelegationTemplate::Helpdesk => "helpdesk",
            DelegationTemplate::UserAdmin => "user_admin",
            DelegationTemplate::GroupAdmin => "group_admin",
        }
    }

    /// The uuid of the template's built-in `delegated_role` entry.
    pub fn role_uuid(self) -> Uuid {
        match self {
            DelegationTemplate::Helpdesk => UUID_IDM_DELEGATED_HELPDESK,
            DelegationTemplate::UserAdmin => UUID_IDM_DELEGATED_USER_ADMIN,
            DelegationTemplate::GroupAdmin => UUID_IDM_DELEGATED_GROUP_ADMIN,
        }
    }

    /// The template named `name`: its short name, or the name of its `delegated_role`
    /// entry (`idm_delegated_<short name>`).
    pub fn from_name(name: &str) -> Option<Self> {
        let name = name.trim().to_lowercase();
        let short = name.strip_prefix("idm_delegated_").unwrap_or(&name);
        Self::ALL.into_iter().find(|t| t.name() == short)
    }

    pub fn from_role_uuid(uuid: Uuid) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.role_uuid() == uuid)
    }

    pub fn grant(self) -> DelegationTemplateGrant {
        match self {
            DelegationTemplate::Helpdesk => DelegationTemplateGrant {
                target_classes: vec![EntryClass::Person, EntryClass::Account],
                // idm_acp_people_read and idm_acp_people_credential_reset.
                search_attrs: vec![
                    Attribute::Class,
                    Attribute::Name,
                    Attribute::Spn,
                    Attribute::Uuid,
                    Attribute::DisplayName,
                    Attribute::MemberOf,
                    Attribute::AccountExpire,
                    Attribute::AccountValidFrom,
                    Attribute::PrimaryCredential,
                    Attribute::PassKeys,
                    Attribute::AttestedPasskeys,
                    Attribute::AccountSoftlockExpire,
                ],
                // idm_acp_people_credential_reset.
                modify_attrs: vec![
                    Attribute::PrimaryCredential,
                    Attribute::PassKeys,
                    Attribute::AttestedPasskeys,
                    Attribute::AccountValidFrom,
                    Attribute::AccountExpire,
                    Attribute::AccountSoftlockExpire,
                ],
                delete: false,
            },
            DelegationTemplate::UserAdmin => DelegationTemplateGrant {
                target_classes: vec![EntryClass::Person, EntryClass::Account],
                // idm_acp_people_read and the attributes managed below.
                search_attrs: vec![
                    Attribute::Class,
                    Attribute::Name,
                    Attribute::Spn,
                    Attribute::Uuid,
                    Attribute::DisplayName,
                    Attribute::LegalName,
                    Attribute::Mail,
                    Attribute::MemberOf,
                    Attribute::AccountExpire,
                    Attribute::AccountValidFrom,
                ],
                // idm_acp_people_pii_manage, without the name (renaming changes how the
                // person logs in) or the mail (account recovery and verified OAuth2 mail
                // make it a credential), and idm_acp_people_manage.
                modify_attrs: vec![
                    Attribute::DisplayName,
                    Attribute::LegalName,
                    Attribute::AccountExpire,
                    Attribute::AccountValidFrom,
                ],
                // idm_acp_people_delete.
                delete: true,
            },
            DelegationTemplate::GroupAdmin => DelegationTemplateGrant {
                target_classes: vec![EntryClass::Group],
                // idm_acp_group_manage.
                search_attrs: vec![
                    Attribute::Class,
                    Attribute::Name,
                    Attribute::Uuid,
                    Attribute::Spn,
                    Attribute::Description,
                    Attribute::Mail,
                    Attribute::Member,
                    Attribute::MemberOf,
                    Attribute::DynMember,
                    Attribute::EntryManagedBy,
                ],
                // Read only, see DelegationTemplate::GroupAdmin.
                modify_attrs: vec![],
                delete: false,
            },
        }
    }

    /// The template's class terms, the start of every `delegated_scope_filter` it writes.
    fn target_terms(self) -> Vec<ProtoFilter> {
        self.grant()
            .target_classes
            .into_iter()
            .map(|class| ProtoFilter::Eq(Attribute::Class.to_string(), class.to_string()))
            .collect()
    }

    /// The `delegated_scope_filter` of a delegation: the class terms, and the filter given
    /// when granting, if any.
    fn scope_filter(self, filter: Option<&ProtoFilter>) -> ProtoFilter {
        let mut terms = self.target_terms();
        terms.extend(filter.cloned());
        ProtoFilter::And(terms)
    }

    /// The filter given when granting, recovered from a `delegated_scope_filter`. A filter
    /// that was not written by this template (say, changed since) is returned whole.
    fn granted_filter(self, stored: &ProtoFilter) -> Option<ProtoFilter> {
        let terms = self.target_terms();
        if let ProtoFilter::And(stored_terms) = stored {
            if let Some(rest) = stored_terms.strip_prefix(terms.as_slice()) {
                return match rest {
                    [] => None,
                    [filter] => Some(filter.clone()),
                    _ => Some(stored.clone()),
                };
            }
        }
        Some(stored.clone())
    }
}

/// Only the internal system identity bypasses the authorisation, and only members of
/// `idm_access_control_admins` administer delegations. Writes need a read-write session.
fn delegation_check_admin(ident: &Identity, write: bool) -> Result<(), OperationError> {
    if ident.is_internal() {
        if ident.get_uuid() == UUID_SYSTEM {
            return Ok(());
        }
        security_access!(ident = %ident, "denied - internal identity is not the system");
        return Err(OperationError::AccessDenied);
    }

    if write && ident.access_scope() != AccessScope::ReadWrite {
        security_access!("delegation write requires a read-write (privileged) session");
        return Err(OperationError::AccessDenied);
    }

    if ident.is_memberof(UUID_IDM_ACCESS_CONTROL_ADMINS) {
        Ok(())
    } else {
        security_access!(ident = %ident, "denied - not a member of idm_access_control_admins");
        Err(OperationError::AccessDenied)
    }
}

/// Is `entry` high privilege: `idm_high_privilege` itself, or a (nested) member of it?
/// `memberof` is transitive, so a nested member has it in its `memberof` too.
fn delegation_is_high_privilege(entry: &EntrySealedCommitted) -> bool {
    entry.get_uuid() == UUID_IDM_HIGH_PRIVILEGE
        || entry.attribute_equality(
            Attribute::MemberOf,
            &PartialValue::Refer(UUID_IDM_HIGH_PRIVILEGE),
        )
}

/// Is `entry` a dynamic group?
fn delegation_is_dyngroup(entry: &EntrySealedCommitted) -> bool {
    entry.attribute_equality(Attribute::Class, &EntryClass::DynGroup.into())
}

/// The group `group` and the groups nested (directly or not) in it.
fn delegation_group_and_nested<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    group: &Arc<EntrySealedCommitted>,
) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
    let mut groups = qs.internal_search(filter!(f_and(vec![
        f_eq(Attribute::Class, EntryClass::Group.into()),
        f_eq(Attribute::MemberOf, PartialValue::Refer(group.get_uuid())),
    ])))?;
    groups.push(group.clone());
    Ok(groups)
}

/// The `(group, manager)` pairs of `groups` whose `entry_managed_by` is not high
/// privilege (or no longer exists). Such a manager changes the members of the group (see
/// `idm_acp_group_entry_manager`), so it could pull anyone into a delegation's scope or
/// receivers.
fn delegation_unsafe_entry_managers<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    groups: &[Arc<EntrySealedCommitted>],
) -> Result<Vec<(Uuid, Uuid)>, OperationError> {
    let mut unsafe_managers = Vec::new();
    for group in groups {
        // entry_managed_by is single valued, read it as either kind of reference.
        let mut managers: BTreeSet<Uuid> = group
            .get_ava_refer(Attribute::EntryManagedBy)
            .cloned()
            .unwrap_or_default();
        managers.extend(group.get_ava_single_refer(Attribute::EntryManagedBy));
        for manager in managers {
            let high_privilege = match qs.internal_search_uuid(manager) {
                Ok(entry) => delegation_is_high_privilege(&entry),
                Err(OperationError::NoMatchingEntries) => false,
                Err(err) => return Err(err),
            };
            if !high_privilege {
                unsafe_managers.push((group.get_uuid(), manager));
            }
        }
    }
    Ok(unsafe_managers)
}

/// The drift of the groups of the delegation `entry`: entry managers and dynamic groups
/// that granting it now would refuse.
fn delegation_group_drift<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    entry: &EntrySealedCommitted,
) -> Result<Vec<String>, OperationError> {
    let mut uuids: Vec<Uuid> = entry
        .get_ava_refer(Attribute::AcpReceiverGroup)
        .map(|receivers| receivers.iter().copied().collect())
        .unwrap_or_default();
    uuids.extend(entry.get_ava_single_refer(Attribute::DelegatedScopeGroup));

    let mut groups = Vec::new();
    for uuid in uuids {
        match qs.internal_search_uuid(uuid) {
            Ok(group) => groups.extend(delegation_group_and_nested(qs, &group)?),
            Err(OperationError::NoMatchingEntries) => {}
            Err(err) => return Err(err),
        }
    }

    let mut drift = Vec::new();
    let mut dyngroups: BTreeSet<String> = BTreeSet::new();
    for group in groups.iter().filter(|group| delegation_is_dyngroup(group)) {
        dyngroups.insert(group.get_display_id());
    }
    if !dyngroups.is_empty() {
        drift.push(format!(
            "the receiver or scope is, or holds, the dynamic groups {dyngroups:?}"
        ));
    }
    let managed: BTreeSet<(Uuid, Uuid)> = delegation_unsafe_entry_managers(qs, &groups)?
        .into_iter()
        .collect();
    for (group, manager) in managed {
        drift.push(format!(
            "group {group} has the entry manager {manager}, which is not high privilege and bypasses the scope"
        ));
    }
    Ok(drift)
}

/// Resolve `id` (a name, spn or uuid) to a group that may be the receiver or the scope of
/// a delegation.
fn delegation_resolve_group(
    qs: &mut QueryServerWriteTransaction<'_>,
    id: &str,
) -> Result<Arc<EntrySealedCommitted>, OperationError> {
    let uuid = qs.name_to_uuid(id)?;
    let entry = qs.internal_search_uuid(uuid)?;

    if !entry.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
        security_access!(%id, "denied - a delegation receiver or scope must be a group");
        return Err(OperationError::DG0004DelegationNotAGroup);
    }
    if delegation_is_high_privilege(&entry) {
        security_access!(%id, "denied - a delegation receiver or scope can not be high privilege");
        return Err(OperationError::DG0002DelegationHighPrivilegeGroup);
    }
    if uuid < DYNAMIC_RANGE_MINIMUM_UUID {
        security_access!(%id, "denied - a delegation receiver or scope can not be built-in");
        return Err(OperationError::DG0003DelegationBuiltinGroup);
    }

    Ok(entry)
}

/// The name of the profile of a delegation, see the module documentation.
fn delegation_name(template: DelegationTemplate, scope: Uuid, receiver: Uuid) -> String {
    let short = |uuid: Uuid| format!("{:016x}", uuid.as_u128() & u128::from(u64::MAX));
    format!(
        "delegation_{}_{}_{}",
        template.name(),
        short(scope),
        short(receiver)
    )
}

/// The filter matching the delegations (profiles granted from a template), narrowed by
/// `extra`.
fn delegation_filter(extra: Vec<FC>) -> Filter<FilterInvalid> {
    let mut terms = vec![
        f_eq(Attribute::Class, EntryClass::AccessControlProfile.into()),
        f_eq(
            Attribute::Class,
            EntryClass::AccessControlTargetDelegatedScope.into(),
        ),
        f_pres(Attribute::DelegatedRoleTemplate),
    ];
    terms.extend(extra);
    filter!(f_and(terms))
}

/// The filter term matching the delegation named, or with the uuid, `id`.
fn delegation_id_term(id: &str) -> FC {
    match Uuid::parse_str(id) {
        Ok(uuid) => f_eq(Attribute::Uuid, PartialValue::Uuid(uuid)),
        Err(_) => f_eq(Attribute::Name, PartialValue::new_iname(id)),
    }
}

/// The syntaxes whose filter values `Filter::from_rw` resolves from a name to a uuid.
fn delegation_resolves_names(syntax: SyntaxType) -> bool {
    matches!(
        syntax,
        SyntaxType::Uuid
            | SyntaxType::UuidN
            | SyntaxType::ReferenceUuid
            | SyntaxType::ReferenceUuidN
            | SyntaxType::OauthScopeMap
            | SyntaxType::Session
            | SyntaxType::ApiToken
            | SyntaxType::Oauth2Session
            | SyntaxType::ApplicationPassword
    )
}

/// The scope filter `filter` as it is stored: every value that refers to an entry by name
/// is resolved to the entry's uuid now, so that renaming (or replacing) a group later
/// never changes which entries the filter matches. The parser resolves the filter again on
/// every reload, which by uuid is stable. A name that resolves to nothing, and `self`
/// (which means nothing for a profile), are refused.
fn delegation_normalise_filter(
    qs: &mut QueryServerWriteTransaction<'_>,
    filter: &ProtoFilter,
) -> Result<ProtoFilter, OperationError> {
    let mut normalise_all = |filters: &[ProtoFilter]| {
        filters
            .iter()
            .map(|f| delegation_normalise_filter(qs, f))
            .collect::<Result<Vec<_>, _>>()
    };
    Ok(match filter {
        ProtoFilter::Eq(attr, value) | ProtoFilter::Cnt(attr, value) => {
            let resolves = qs
                .get_schema()
                .get_attributes()
                .get(&Attribute::from(attr.as_str()))
                .is_some_and(|schema_attr| delegation_resolves_names(schema_attr.syntax));
            let value = if resolves {
                qs.name_to_uuid(value)
                    .map_err(|err| {
                        security_access!(
                            ?err,
                            %attr,
                            %value,
                            "denied - a delegation scope filter refers to an entry that does not exist"
                        );
                        OperationError::DG0008DelegationInvalidFilter
                    })?
                    .to_string()
            } else {
                value.clone()
            };
            match filter {
                ProtoFilter::Cnt(..) => ProtoFilter::Cnt(attr.clone(), value),
                _ => ProtoFilter::Eq(attr.clone(), value),
            }
        }
        ProtoFilter::Pres(attr) => ProtoFilter::Pres(attr.clone()),
        ProtoFilter::Or(filters) => ProtoFilter::Or(normalise_all(filters)?),
        ProtoFilter::And(filters) => ProtoFilter::And(normalise_all(filters)?),
        ProtoFilter::AndNot(filter) => {
            ProtoFilter::AndNot(Box::new(delegation_normalise_filter(qs, filter)?))
        }
        ProtoFilter::SelfUuid => {
            security_access!("denied - a delegation scope filter can not use self");
            return Err(OperationError::DG0008DelegationInvalidFilter);
        }
    })
}

fn delegation_group<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    uuid: Uuid,
) -> Result<DelegationGroup, OperationError> {
    Ok(DelegationGroup {
        uuid,
        spn: qs.uuid_to_spn(uuid)?.map(|spn| spn.to_proto_string_clone()),
    })
}

/// The values of the iutf8 attribute `attr` of `entry`.
fn delegation_iutf8_set(entry: &EntrySealedCommitted, attr: Attribute) -> BTreeSet<String> {
    entry
        .get_ava_iter_iutf8(attr)
        .map(|values| values.map(str::to_string).collect())
        .unwrap_or_default()
}

/// How the profile `entry` differs from what `template` grants, see the module
/// documentation. Empty when it matches.
fn delegation_drift(
    entry: &EntrySealedCommitted,
    template: Option<DelegationTemplate>,
) -> Vec<String> {
    let mut drift = Vec::new();
    let Some(template) = template else {
        drift.push(format!(
            "{} is not a known template",
            Attribute::DelegatedRoleTemplate
        ));
        return drift;
    };
    let grant = template.grant();
    let has = |class: EntryClass| entry.attribute_equality(Attribute::Class, &class.into());

    let receivers = entry
        .get_ava_refer(Attribute::AcpReceiverGroup)
        .map(BTreeSet::len)
        .unwrap_or(0);
    if receivers != 1 {
        drift.push(format!("{receivers} receiver groups, the template has one"));
    }
    if entry
        .get_ava_single_refer(Attribute::DelegatedScopeGroup)
        .is_none()
    {
        drift.push(format!("no {}", Attribute::DelegatedScopeGroup));
    }

    for (class, expected) in [
        (EntryClass::AccessControlReceiverGroup, true),
        (EntryClass::AccessControlTargetDelegatedScope, true),
        (EntryClass::AccessControlReceiverEntryManager, false),
        (EntryClass::AccessControlReceiverDelegated, false),
        (EntryClass::AccessControlTargetScope, false),
        (EntryClass::AccessControlSearch, true),
        (
            EntryClass::AccessControlModify,
            !grant.modify_attrs.is_empty(),
        ),
        (EntryClass::AccessControlDelete, grant.delete),
        (EntryClass::AccessControlCreate, false),
    ] {
        match (has(class), expected) {
            (true, false) => drift.push(format!("class {class} is not granted by the template")),
            (false, true) => drift.push(format!("class {class} is missing")),
            _ => {}
        }
    }

    let names = |attrs: &[Attribute]| -> BTreeSet<String> {
        attrs.iter().map(|attr| attr.as_str().to_string()).collect()
    };
    for (attr, expected) in [
        (Attribute::AcpSearchAttr, names(&grant.search_attrs)),
        (Attribute::AcpModifyPresentAttr, names(&grant.modify_attrs)),
        (Attribute::AcpModifyRemovedAttr, names(&grant.modify_attrs)),
        (Attribute::AcpModifyClass, BTreeSet::new()),
        (Attribute::AcpModifyPresentClass, BTreeSet::new()),
        (Attribute::AcpModifyRemoveClass, BTreeSet::new()),
        (Attribute::AcpCreateClass, BTreeSet::new()),
        (Attribute::AcpCreateAttr, BTreeSet::new()),
    ] {
        let stored = delegation_iutf8_set(entry, attr.clone());
        let extra: Vec<&String> = stored.difference(&expected).collect();
        let missing: Vec<&String> = expected.difference(&stored).collect();
        if !extra.is_empty() {
            drift.push(format!("{attr} has {extra:?}, not granted by the template"));
        }
        if !missing.is_empty() {
            drift.push(format!("{attr} lacks {missing:?}"));
        }
    }

    let terms = template.target_terms();
    let restricted = matches!(
        entry.get_ava_single_protofilter(Attribute::DelegatedScopeFilter),
        Some(ProtoFilter::And(stored)) if stored.starts_with(terms.as_slice())
    );
    if !restricted {
        drift.push(format!(
            "{} does not restrict the targets to the template's classes",
            Attribute::DelegatedScopeFilter
        ));
    }

    drift
}

fn delegation_from_entry<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    entry: &EntrySealedCommitted,
) -> Result<DelegationGrant, OperationError> {
    let template = entry
        .get_ava_single_refer(Attribute::DelegatedRoleTemplate)
        .and_then(DelegationTemplate::from_role_uuid);
    let receivers = entry
        .get_ava_refer(Attribute::AcpReceiverGroup)
        .map(|receivers| receivers.iter().copied().collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .map(|uuid| delegation_group(qs, uuid))
        .collect::<Result<Vec<_>, _>>()?;
    let scope = entry
        .get_ava_single_refer(Attribute::DelegatedScopeGroup)
        .map(|uuid| delegation_group(qs, uuid))
        .transpose()?;
    let delegated_by = entry
        .get_ava_single_refer(Attribute::DelegatedBy)
        .map(|uuid| delegation_group(qs, uuid))
        .transpose()?;
    let filter = entry
        .get_ava_single_protofilter(Attribute::DelegatedScopeFilter)
        .and_then(|stored| match template {
            Some(template) => template.granted_filter(stored),
            None => Some(stored.clone()),
        });

    let mut drift = delegation_drift(entry, template);
    drift.extend(delegation_group_drift(qs, entry)?);

    Ok(DelegationGrant {
        uuid: entry.get_uuid(),
        name: entry
            .get_ava_single_iname(Attribute::Name)
            .map(str::to_string)
            .unwrap_or_else(|| entry.get_display_id()),
        template: template.map(|t| t.name().to_string()),
        receivers,
        scope,
        filter,
        delegated_by,
        enabled: entry
            .get_ava_single_bool(Attribute::AcpEnable)
            .unwrap_or(true),
        drift,
    })
}

fn delegation_list<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    ident: &Identity,
) -> Result<Vec<DelegationGrant>, OperationError> {
    delegation_check_admin(ident, false)?;

    let entries = qs.internal_search(delegation_filter(Vec::new()))?;
    let mut grants = entries
        .iter()
        .map(|entry| delegation_from_entry(qs, entry))
        .collect::<Result<Vec<_>, _>>()?;
    grants.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(grants)
}

fn delegation_get<'a, T: QueryServerTransaction<'a>>(
    qs: &mut T,
    ident: &Identity,
    id: &str,
) -> Result<DelegationGrant, OperationError> {
    delegation_check_admin(ident, false)?;

    let entry = qs
        .internal_search(delegation_filter(vec![delegation_id_term(id)]))?
        .into_iter()
        .next()
        .ok_or(OperationError::NoMatchingEntries)?;
    delegation_from_entry(qs, &entry)
}

impl QueryServerReadTransaction<'_> {
    /// Kubidm: list the delegations, by name.
    #[instrument(level = "debug", skip_all)]
    pub fn delegation_list(
        &mut self,
        ident: &Identity,
    ) -> Result<Vec<DelegationGrant>, OperationError> {
        delegation_list(self, ident)
    }

    /// Kubidm: the delegation named, or with the uuid, `id`.
    #[instrument(level = "debug", skip_all)]
    pub fn delegation_get(
        &mut self,
        ident: &Identity,
        id: &str,
    ) -> Result<DelegationGrant, OperationError> {
        delegation_get(self, ident, id)
    }
}

impl QueryServerWriteTransaction<'_> {
    /// Kubidm: list the delegations, as [`QueryServerReadTransaction::delegation_list`].
    #[instrument(level = "debug", skip_all)]
    pub fn delegation_list(
        &mut self,
        ident: &Identity,
    ) -> Result<Vec<DelegationGrant>, OperationError> {
        delegation_list(self, ident)
    }

    /// Kubidm: the delegation named, or with the uuid, `id`, as
    /// [`QueryServerReadTransaction::delegation_get`].
    #[instrument(level = "debug", skip_all)]
    pub fn delegation_get(
        &mut self,
        ident: &Identity,
        id: &str,
    ) -> Result<DelegationGrant, OperationError> {
        delegation_get(self, ident, id)
    }

    /// Kubidm: grant the members of `receiver_group` the rights of `template_name` over
    /// the members of `scope_group` that match `scope_filter` (if any). The groups are
    /// names, spns or uuids. See the module documentation for what is refused.
    #[instrument(level = "debug", skip_all)]
    pub fn delegation_grant(
        &mut self,
        ident: &Identity,
        template_name: &str,
        receiver_group: &str,
        scope_group: &str,
        scope_filter: Option<&ProtoFilter>,
    ) -> Result<DelegationGrant, OperationError> {
        delegation_check_admin(ident, true)?;

        let template = DelegationTemplate::from_name(template_name).ok_or_else(|| {
            security_access!(template = %template_name, "denied - unknown delegation template");
            OperationError::DG0001DelegationUnknownTemplate
        })?;
        let receiver = delegation_resolve_group(self, receiver_group)?;
        let scope = delegation_resolve_group(self, scope_group)?;
        if receiver.get_uuid() == scope.get_uuid()
            || receiver
                .attribute_equality(Attribute::MemberOf, &PartialValue::Refer(scope.get_uuid()))
        {
            security_access!("denied - the receiver of a delegation can not be in its scope");
            return Err(OperationError::DG0005DelegationReceiverIsScope);
        }
        // Every member of a receiver group is excluded from every delegated target, so a
        // scope that is (or is in) a receiver group would never match anything.
        let mut receivers = delegated_receivers(self)?;
        receivers.insert(receiver.get_uuid());
        if receivers.iter().any(|receiver| {
            scope.get_uuid() == *receiver
                || scope.attribute_equality(Attribute::MemberOf, &PartialValue::Refer(*receiver))
        }) {
            security_access!("denied - the scope of a delegation can not be a receiver group");
            return Err(OperationError::DG0007DelegationScopeIsReceiver);
        }
        // The receiver and the scope, and the groups nested in them, are checked for what
        // would let someone change their members outside of the delegation.
        let mut groups = delegation_group_and_nested(self, &receiver)?;
        groups.extend(delegation_group_and_nested(self, &scope)?);
        // A dynamic group's members follow its filter, on attributes that a delegation
        // (or anyone matching it) may be able to write.
        if groups.iter().any(|group| delegation_is_dyngroup(group)) {
            security_access!(
                "denied - a delegation receiver or scope can not be, or hold, a dynamic group"
            );
            return Err(OperationError::DG0010DelegationDynamicGroup);
        }
        // The entry manager of a group changes its members: one that is not high privilege
        // could add anyone to the scope, or to the receivers.
        let managed = delegation_unsafe_entry_managers(self, &groups)?;
        if !managed.is_empty() {
            security_access!(
                ?managed,
                "denied - a delegation receiver or scope group has an entry manager that is not high privilege"
            );
            return Err(OperationError::DG0009DelegationEntryManaged);
        }
        // The template's built-in entry is referenced, it must exist.
        let role = self.internal_search_uuid(template.role_uuid())?;

        // A template is granted once per receiver and scope.
        if self.internal_exists(&delegation_filter(vec![
            f_eq(
                Attribute::DelegatedRoleTemplate,
                PartialValue::Refer(role.get_uuid()),
            ),
            f_eq(
                Attribute::DelegatedScopeGroup,
                PartialValue::Refer(scope.get_uuid()),
            ),
            f_eq(
                Attribute::AcpReceiverGroup,
                PartialValue::Refer(receiver.get_uuid()),
            ),
        ]))? {
            security_access!("denied - the delegation already exists");
            return Err(OperationError::DG0006DelegationAlreadyExists);
        }

        // The filter given is stored with its references resolved, and must be valid on
        // its own, so a bad one is reported as such rather than as an invalid profile. It
        // is resolved as the parser does.
        let scope_filter = scope_filter
            .map(|scope_filter| delegation_normalise_filter(self, scope_filter))
            .transpose()?;
        if let Some(scope_filter) = scope_filter.as_ref() {
            Filter::from_rw(&Identity::from_internal(), scope_filter, self)?
                .validate(self.get_schema())
                .map_err(|err| {
                    security_access!(?err, "denied - invalid delegation scope filter");
                    OperationError::SchemaViolation(err)
                })?;
        }

        let name = delegation_name(template, scope.get_uuid(), receiver.get_uuid());
        let grant = template.grant();
        let uuid = Uuid::new_v4();
        let mut entry = EntryInitNew::new();

        let mut classes = vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlReceiverGroup,
            EntryClass::AccessControlTargetDelegatedScope,
            EntryClass::AccessControlSearch,
        ];
        if !grant.modify_attrs.is_empty() {
            classes.push(EntryClass::AccessControlModify);
        }
        if grant.delete {
            classes.push(EntryClass::AccessControlDelete);
        }
        entry.set_ava(
            Attribute::Class,
            classes.into_iter().map(|class| class.to_value()),
        );
        entry.set_ava(Attribute::Uuid, [Value::Uuid(uuid)]);
        entry.set_ava(Attribute::Name, [Value::new_iname(&name)]);
        entry.set_ava(
            Attribute::Description,
            [Value::new_utf8(format!(
                "Delegated {} rights for the members of {} over the members of {}",
                template.name(),
                receiver.get_display_id(),
                scope.get_display_id()
            ))],
        );
        entry.set_ava(
            Attribute::AcpReceiverGroup,
            [Value::ReferN(receiver.get_uuid())],
        );
        entry.set_ava(
            Attribute::DelegatedScopeGroup,
            [Value::Refer(scope.get_uuid())],
        );
        entry.set_ava(
            Attribute::DelegatedScopeFilter,
            [Value::JsonFilt(
                template.scope_filter(scope_filter.as_ref()),
            )],
        );
        entry.set_ava(
            Attribute::DelegatedRoleTemplate,
            [Value::Refer(role.get_uuid())],
        );
        // The system identity has no entry to refer to.
        if !ident.is_internal() {
            entry.set_ava(Attribute::DelegatedBy, [Value::Refer(ident.get_uuid())]);
        }
        entry.set_ava(
            Attribute::AcpSearchAttr,
            grant
                .search_attrs
                .iter()
                .map(|attr| Value::new_iutf8n(attr.as_str())),
        );
        if !grant.modify_attrs.is_empty() {
            for attr in [
                Attribute::AcpModifyPresentAttr,
                Attribute::AcpModifyRemovedAttr,
            ] {
                entry.set_ava(
                    attr,
                    grant
                        .modify_attrs
                        .iter()
                        .map(|attr| Value::new_iutf8n(attr.as_str())),
                );
            }
        }

        self.internal_create(vec![entry])?;

        // The profile is parsed again when the access controls are reloaded on commit,
        // which rejects an invalid one. Parse it here too, to fail before anything else
        // happens in this transaction, with the parser's reason.
        let created = self.internal_search_uuid(uuid)?;
        delegation_validate_profile(self, &created)?;

        info!(
            ident = %ident,
            delegation = %name,
            %uuid,
            template = template.name(),
            receiver = %receiver.get_display_id(),
            scope = %scope.get_display_id(),
            "delegation granted"
        );
        delegation_from_entry(self, &created)
    }

    /// Kubidm: revoke the delegation named, or with the uuid, `id`: delete its profile.
    #[instrument(level = "debug", skip_all)]
    pub fn delegation_revoke(&mut self, ident: &Identity, id: &str) -> Result<(), OperationError> {
        delegation_check_admin(ident, true)?;

        let filter = delegation_filter(vec![delegation_id_term(id)]);
        let entries = self.internal_search(filter.clone())?;
        if entries.is_empty() {
            return Err(OperationError::NoMatchingEntries);
        }
        self.internal_delete(&filter)?;

        for entry in entries {
            info!(
                ident = %ident,
                delegation = %entry.get_display_id(),
                uuid = %entry.get_uuid(),
                "delegation revoked"
            );
        }
        Ok(())
    }
}

/// Parse `entry` as every kind of profile it is, as the access control reload does.
fn delegation_validate_profile(
    qs: &mut QueryServerWriteTransaction<'_>,
    entry: &EntrySealedCommitted,
) -> Result<(), OperationError> {
    let is = |class: EntryClass| entry.attribute_equality(Attribute::Class, &class.into());
    let report = |err: OperationError| {
        admin_error!(?err, "a delegation profile failed to parse");
        err
    };
    if is(EntryClass::AccessControlSearch) {
        AccessControlSearch::try_from(qs, entry).map_err(report)?;
    }
    if is(EntryClass::AccessControlModify) {
        AccessControlModify::try_from(qs, entry).map_err(report)?;
    }
    if is(EntryClass::AccessControlDelete) {
        AccessControlDelete::try_from(qs, entry).map_err(report)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::DelegationTemplate;
    use crate::idm::credupdatesession::InitCredentialUpdateIntentEvent;
    use crate::prelude::*;
    use std::collections::BTreeSet;

    /// The attributes of `attr` on the built-in profile `uuid` of the latest migrations.
    fn upstream_attrs(uuid: Uuid, attr: Attribute) -> BTreeSet<String> {
        let entry = crate::migration_data::latest::phase_7_builtin_access_control_profiles()
            .into_iter()
            .find(|entry| entry.get_uuid() == Some(uuid))
            .expect("builtin profile");
        entry
            .get_ava_iter_iutf8(attr)
            .map(|values| values.map(str::to_string).collect())
            .unwrap_or_default()
    }

    fn names(attrs: &[Attribute]) -> BTreeSet<String> {
        attrs.iter().map(|attr| attr.as_str().to_string()).collect()
    }

    /// The templates reuse the attribute sets of the upstream profiles they are modelled
    /// on, and stay within them.
    #[test]
    fn test_delegation_templates_match_upstream() {
        let union = |sets: &[BTreeSet<String>]| -> BTreeSet<String> {
            sets.iter().flatten().cloned().collect()
        };

        let helpdesk = DelegationTemplate::Helpdesk.grant();
        assert_eq!(
            names(&helpdesk.search_attrs),
            union(&[
                upstream_attrs(UUID_IDM_ACP_PEOPLE_READ_V1, Attribute::AcpSearchAttr),
                upstream_attrs(
                    UUID_IDM_ACP_PEOPLE_CREDENTIAL_RESET_V1,
                    Attribute::AcpSearchAttr
                ),
            ])
        );
        for attr in [
            Attribute::AcpModifyPresentAttr,
            Attribute::AcpModifyRemovedAttr,
        ] {
            assert_eq!(
                names(&helpdesk.modify_attrs),
                upstream_attrs(UUID_IDM_ACP_PEOPLE_CREDENTIAL_RESET_V1, attr)
            );
        }
        assert!(!helpdesk.delete);

        let user_admin = DelegationTemplate::UserAdmin.grant();
        let people_modify = union(&[
            upstream_attrs(
                UUID_IDM_ACP_PEOPLE_PII_MANAGE_V1,
                Attribute::AcpModifyPresentAttr,
            ),
            upstream_attrs(
                UUID_IDM_ACP_PEOPLE_MANAGE_V1,
                Attribute::AcpModifyPresentAttr,
            ),
        ]);
        assert!(names(&user_admin.modify_attrs).is_subset(&people_modify));
        // Never the credentials, the name, or the mail (account recovery).
        assert!(!user_admin.modify_attrs.contains(&Attribute::Mail));
        assert!(user_admin.search_attrs.contains(&Attribute::Mail));
        assert!(!user_admin
            .modify_attrs
            .contains(&Attribute::PrimaryCredential));
        assert!(!user_admin.modify_attrs.contains(&Attribute::Name));
        assert!(user_admin.delete);

        let group_admin = DelegationTemplate::GroupAdmin.grant();
        let group_search = upstream_attrs(UUID_IDM_ACP_GROUP_MANAGE_V1, Attribute::AcpSearchAttr);
        assert_eq!(names(&group_admin.search_attrs), group_search);
        // Read only: member management needs a constraint on the values added.
        assert!(group_admin.modify_attrs.is_empty());
        assert!(!group_admin.delete);

        // Every template applies to members of its scope only, and its class terms are
        // recovered from the stored filter.
        for template in DelegationTemplate::ALL {
            assert_eq!(
                DelegationTemplate::from_name(template.name()),
                Some(template)
            );
            assert_eq!(
                DelegationTemplate::from_name(&format!("idm_delegated_{}", template.name())),
                Some(template)
            );
            assert_eq!(
                DelegationTemplate::from_role_uuid(template.role_uuid()),
                Some(template)
            );
            assert_eq!(template.granted_filter(&template.scope_filter(None)), None);
            let filter = ProtoFilter::Pres(Attribute::Mail.to_string());
            assert_eq!(
                template.granted_filter(&template.scope_filter(Some(&filter))),
                Some(filter)
            );
        }
        assert_eq!(DelegationTemplate::from_name("domain_admin"), None);
    }

    fn person(name: &str, uuid: Uuid) -> EntryInitNew {
        entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname(name)),
            (Attribute::DisplayName, Value::new_utf8s(name)),
            (Attribute::Uuid, Value::Uuid(uuid))
        )
    }

    fn group(name: &str, uuid: Uuid, members: &[Uuid]) -> EntryInitNew {
        let mut entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname(name)),
            (Attribute::Uuid, Value::Uuid(uuid))
        );
        for member in members {
            entry.add_ava(Attribute::Member, Value::ReferN(*member));
        }
        entry
    }

    fn add_member(qs_write: &mut QueryServerWriteTransaction<'_>, group: Uuid, member: Uuid) {
        qs_write
            .internal_modify_uuid(
                group,
                &ModifyList::new_append(Attribute::Member, Value::ReferN(member)),
            )
            .expect("add member");
    }

    fn ident(qs_write: &mut QueryServerWriteTransaction<'_>, uuid: Uuid) -> Identity {
        let entry = qs_write.internal_search_uuid(uuid).expect("entry");
        Identity::from_impersonate_entry_readwrite(entry)
    }

    fn can_modify(
        qs_write: &mut QueryServerWriteTransaction<'_>,
        ident: &Identity,
        target: Uuid,
        modlist: &ModifyList<ModifyInvalid>,
    ) -> bool {
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(target)));
        qs_write
            .impersonate_modify(&filter, &filter, modlist, ident)
            .is_ok()
    }

    fn can_delete(
        qs_write: &mut QueryServerWriteTransaction<'_>,
        ident: &Identity,
        target: Uuid,
    ) -> bool {
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(target)));
        let de = DeleteEvent::new_impersonate_identity(ident.clone(), filter);
        qs_write.delete(&de).is_ok()
    }

    fn set_displayname() -> ModifyList<ModifyInvalid> {
        ModifyList::new_purge_and_set(Attribute::DisplayName, Value::new_utf8s("delegated"))
    }

    const ACP_ADMIN: Uuid = uuid!("d1e9a7e0-0000-4000-8000-000000000001");
    const HELPER: Uuid = uuid!("d1e9a7e0-0000-4000-8000-000000000002");
    const TARGET: Uuid = uuid!("d1e9a7e0-0000-4000-8000-000000000003");
    const OUTSIDER: Uuid = uuid!("d1e9a7e0-0000-4000-8000-000000000004");
    const HP_TARGET: Uuid = uuid!("d1e9a7e0-0000-4000-8000-000000000005");
    const RECEIVERS: Uuid = uuid!("d1e9a7e0-0000-4000-8000-000000000006");
    const SCOPE: Uuid = uuid!("d1e9a7e0-0000-4000-8000-000000000007");
    const GROUP_IN_SCOPE: Uuid = uuid!("d1e9a7e0-0000-4000-8000-000000000008");
    const GROUP_OUTSIDE: Uuid = uuid!("d1e9a7e0-0000-4000-8000-000000000009");
    const HP_PARENT: Uuid = uuid!("d1e9a7e0-0000-4000-8000-00000000000a");
    const HP_NESTED: Uuid = uuid!("d1e9a7e0-0000-4000-8000-00000000000b");
    const HELPER2: Uuid = uuid!("d1e9a7e0-0000-4000-8000-00000000000c");
    const HELPER_B: Uuid = uuid!("d1e9a7e0-0000-4000-8000-00000000000d");
    const RECEIVERS_B: Uuid = uuid!("d1e9a7e0-0000-4000-8000-00000000000e");
    const SCOPE_B: Uuid = uuid!("d1e9a7e0-0000-4000-8000-00000000000f");
    const EXCLUDED: Uuid = uuid!("d1e9a7e0-0000-4000-8000-000000000010");

    /// An access control admin, a receiver group with one helper, and a scope group with a
    /// person, a high privilege person and a group. A person and a group outside of the
    /// scope, and a group nested in idm_high_privilege.
    fn setup(qs_write: &mut QueryServerWriteTransaction<'_>) {
        qs_write
            .internal_create(vec![
                person("dlg_acp_admin", ACP_ADMIN),
                person("dlg_helper", HELPER),
                person("dlg_target", TARGET),
                person("dlg_outsider", OUTSIDER),
                person("dlg_hp_target", HP_TARGET),
                group("dlg_group_in_scope", GROUP_IN_SCOPE, &[]),
                group("dlg_group_outside", GROUP_OUTSIDE, &[]),
                group("dlg_receivers", RECEIVERS, &[HELPER]),
                group("dlg_scope", SCOPE, &[TARGET, HP_TARGET, GROUP_IN_SCOPE]),
                group("dlg_hp_nested", HP_NESTED, &[]),
                group("dlg_hp_parent", HP_PARENT, &[HP_NESTED]),
            ])
            .expect("create entries");
        add_member(qs_write, UUID_IDM_ACCESS_CONTROL_ADMINS, ACP_ADMIN);
        add_member(qs_write, UUID_IDM_HIGH_PRIVILEGE, HP_TARGET);
        add_member(qs_write, UUID_IDM_HIGH_PRIVILEGE, HP_PARENT);
    }

    /// Can `helper` start a credential reset of `target`, as the help desk does?
    fn can_reset(
        idms_prox_write: &mut crate::idm::server::IdmServerProxyWriteTransaction<'_>,
        helper: Uuid,
        target: Uuid,
        ct: Duration,
    ) -> bool {
        let helper = idms_prox_write
            .qs_write
            .internal_search_uuid(helper)
            .expect("helper");
        let event = InitCredentialUpdateIntentEvent::new_impersonate_entry(
            helper,
            target,
            Duration::from_secs(600),
        );
        idms_prox_write
            .init_credential_update_intent(&event, ct)
            .is_ok()
    }

    /// The help desk template, end to end: grant, use, the refused delete of the scope
    /// group, listing, revoke.
    #[idm_test]
    async fn test_delegation_helpdesk_grant_use_revoke(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        setup(&mut idms_prox_write.qs_write);
        idms_prox_write.commit().expect("commit");

        // Before any delegation, the helper can not reset anyone.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        assert!(!can_reset(&mut idms_prox_write, HELPER, TARGET, ct));
        drop(idms_prox_write);

        // An access control admin grants the help desk template.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let admin = ident(&mut idms_prox_write.qs_write, ACP_ADMIN);
        let grant = idms_prox_write
            .qs_write
            .delegation_grant(&admin, "helpdesk", "dlg_receivers", "dlg_scope", None)
            .expect("grant");
        assert_eq!(
            grant.name,
            "delegation_helpdesk_8000000000000007_8000000000000006"
        );
        assert_eq!(grant.template.as_deref(), Some("helpdesk"));
        assert_eq!(
            grant
                .receivers
                .iter()
                .map(|group| group.uuid)
                .collect::<Vec<_>>(),
            vec![RECEIVERS]
        );
        assert_eq!(grant.scope.as_ref().map(|group| group.uuid), Some(SCOPE));
        assert_eq!(grant.filter, None);
        assert_eq!(
            grant.delegated_by.as_ref().map(|person| person.uuid),
            Some(ACP_ADMIN)
        );
        assert!(grant.enabled);
        assert!(grant.drift.is_empty(), "{:?}", grant.drift);
        idms_prox_write.commit().expect("commit");

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        // The helper resets the credentials of a person in the scope ...
        assert!(can_reset(&mut idms_prox_write, HELPER, TARGET, ct));
        // ... but not of a person outside of it, nor of a high privilege member of it.
        assert!(!can_reset(&mut idms_prox_write, HELPER, OUTSIDER, ct));
        assert!(!can_reset(&mut idms_prox_write, HELPER, HP_TARGET, ct));
        // The template grants no other modification, and no delete.
        let helper = ident(&mut idms_prox_write.qs_write, HELPER);
        assert!(!can_modify(
            &mut idms_prox_write.qs_write,
            &helper,
            TARGET,
            &set_displayname()
        ));
        assert!(!can_delete(&mut idms_prox_write.qs_write, &helper, TARGET));
        // Nor does it make the members of the scope administrators.
        assert!(!can_reset(&mut idms_prox_write, TARGET, HELPER, ct));
        drop(idms_prox_write);

        // The scope group can not be deleted while the delegation exists.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        idms_prox_write
            .qs_write
            .internal_delete_uuid(SCOPE)
            .expect("delete scope group");
        assert!(matches!(
            idms_prox_write.commit(),
            Err(OperationError::InvalidAcpState(_))
        ));

        // The delegation is listed, and found by name and uuid.
        let mut idms_prox_read = idms.proxy_read().await.unwrap();
        let listed = idms_prox_read
            .qs_read
            .delegation_list(&admin)
            .expect("list");
        assert_eq!(listed, vec![grant.clone()]);
        assert_eq!(
            idms_prox_read.qs_read.delegation_get(&admin, &grant.name),
            Ok(grant.clone())
        );
        assert_eq!(
            idms_prox_read
                .qs_read
                .delegation_get(&admin, &grant.uuid.to_string()),
            Ok(grant.clone())
        );
        drop(idms_prox_read);

        // Revoking removes the access.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        idms_prox_write
            .qs_write
            .delegation_revoke(&admin, &grant.name)
            .expect("revoke");
        idms_prox_write.commit().expect("commit");

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        assert!(!can_reset(&mut idms_prox_write, HELPER, TARGET, ct));
        assert_eq!(
            idms_prox_write.qs_write.delegation_list(&admin),
            Ok(Vec::new())
        );
        assert_eq!(
            idms_prox_write
                .qs_write
                .delegation_revoke(&admin, &grant.name),
            Err(OperationError::NoMatchingEntries)
        );
        // The same delegation can be granted again, and revoked by uuid. The scope group
        // can be deleted once it is not used anymore.
        let again = idms_prox_write
            .qs_write
            .delegation_grant(&admin, "helpdesk", "dlg_receivers", "dlg_scope", None)
            .expect("grant again");
        idms_prox_write
            .qs_write
            .delegation_revoke(&admin, &again.uuid.to_string())
            .expect("revoke by uuid");
        idms_prox_write
            .qs_write
            .internal_delete_uuid(SCOPE)
            .expect("delete scope group");
        idms_prox_write.commit().expect("commit");
    }

    /// The user and group administration templates grant what they define, on their
    /// scope only.
    #[qs_test]
    async fn test_delegation_user_and_group_admin(qs: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut qs_write = qs.write(ct).await.unwrap();
        setup(&mut qs_write);
        let admin = ident(&mut qs_write, ACP_ADMIN);
        for template in ["user_admin", "group_admin"] {
            qs_write
                .delegation_grant(&admin, template, "dlg_receivers", "dlg_scope", None)
                .expect("grant");
        }
        qs_write.commit().expect("commit");

        let mut qs_write = qs.write(ct).await.unwrap();
        let helper = ident(&mut qs_write, HELPER);

        // user_admin: the profile of the persons in scope, not their name.
        assert!(can_modify(
            &mut qs_write,
            &helper,
            TARGET,
            &set_displayname()
        ));
        assert!(!can_modify(
            &mut qs_write,
            &helper,
            TARGET,
            &ModifyList::new_purge_and_set(Attribute::Name, Value::new_iname("dlg_renamed"))
        ));
        for denied in [OUTSIDER, HP_TARGET] {
            assert!(!can_modify(
                &mut qs_write,
                &helper,
                denied,
                &set_displayname()
            ));
            assert!(!can_delete(&mut qs_write, &helper, denied));
        }
        // A new person has no memberof, so it is never in the scope: no create.
        assert!(qs_write
            .impersonate_create(&helper, vec![person("dlg_created", Uuid::new_v4())])
            .is_err());

        // user_admin: never the mail, which account recovery trusts.
        assert!(!can_modify(
            &mut qs_write,
            &helper,
            TARGET,
            &ModifyList::new_purge_and_set(
                Attribute::Mail,
                Value::new_email_address_s("dlg@example.com").expect("mail")
            )
        ));

        // group_admin is read only: adding a member to a group in scope would pull that
        // member (say, the receivers of another delegation) into the scope.
        let add_outsider = || ModifyList::new_append(Attribute::Member, Value::ReferN(OUTSIDER));
        assert!(!can_modify(
            &mut qs_write,
            &helper,
            GROUP_IN_SCOPE,
            &add_outsider()
        ));
        let add_receivers = ModifyList::new_append(Attribute::Member, Value::ReferN(RECEIVERS));
        assert!(!can_modify(
            &mut qs_write,
            &helper,
            GROUP_IN_SCOPE,
            &add_receivers
        ));
        // But it reads the members of the groups in scope.
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(GROUP_IN_SCOPE)));
        let se = SearchEvent::new_impersonate_identity(helper.clone(), filter);
        let found = qs_write.search(&se).expect("search");
        assert_eq!(found.len(), 1);
        // Negative control: a group outside of the scope is not even found.
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(GROUP_OUTSIDE)));
        let se = SearchEvent::new_impersonate_identity(helper.clone(), filter);
        assert!(qs_write.search(&se).expect("search").is_empty());
        assert!(!can_modify(
            &mut qs_write,
            &helper,
            GROUP_OUTSIDE,
            &add_outsider()
        ));
        assert!(!can_modify(
            &mut qs_write,
            &helper,
            GROUP_IN_SCOPE,
            &ModifyList::new_purge_and_set(Attribute::Description, Value::new_utf8s("x"))
        ));
        assert!(!can_delete(&mut qs_write, &helper, GROUP_IN_SCOPE));

        // user_admin deletes a person in scope.
        assert!(can_delete(&mut qs_write, &helper, TARGET));

        // The members of the privileged built-in groups are never targets, while another
        // person added to the scope the same way is.
        let control = Uuid::new_v4();
        qs_write
            .internal_create(vec![person("dlg_control", control)])
            .expect("create");
        add_member(&mut qs_write, SCOPE, control);
        assert!(can_modify(
            &mut qs_write,
            &helper,
            control,
            &set_displayname()
        ));
        for (i, builtin) in crate::server::access::profiles::DELEGATION_EXCLUDED_BUILTINS
            .into_iter()
            .enumerate()
        {
            let privileged = Uuid::new_v4();
            qs_write
                .internal_create(vec![person(&format!("dlg_privileged_{i}"), privileged)])
                .expect("create");
            add_member(&mut qs_write, SCOPE, privileged);
            add_member(&mut qs_write, builtin, privileged);
            assert!(
                !can_modify(&mut qs_write, &helper, privileged, &set_displayname()),
                "{builtin}"
            );
        }

        // Positive control for the member write denials: the same changes are accepted
        // from a group administrator, so they were denied for the access, not as invalid.
        add_member(&mut qs_write, UUID_IDM_GROUP_ADMINS, ACP_ADMIN);
        let group_admin = ident(&mut qs_write, ACP_ADMIN);
        assert!(can_modify(
            &mut qs_write,
            &group_admin,
            GROUP_IN_SCOPE,
            &add_outsider()
        ));
        assert!(can_modify(
            &mut qs_write,
            &group_admin,
            GROUP_OUTSIDE,
            &add_outsider()
        ));
    }

    /// Who may grant, and what is refused.
    #[qs_test]
    async fn test_delegation_grant_refused(qs: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut qs_write = qs.write(ct).await.unwrap();
        setup(&mut qs_write);
        qs_write.commit().expect("commit");

        let mut qs_write = qs.write(ct).await.unwrap();
        let admin = ident(&mut qs_write, ACP_ADMIN);
        let helper = ident(&mut qs_write, HELPER);
        let admin_entry = qs_write.internal_search_uuid(ACP_ADMIN).expect("admin");
        let admin_read_only = Identity::from_impersonate_entry_readonly(admin_entry);

        let mut grant = |ident: &Identity, template: &str, receiver: &str, scope: &str| {
            qs_write
                .delegation_grant(ident, template, receiver, scope, None)
                .map(|_| ())
        };

        // Only access control admins, with a read-write session.
        assert_eq!(
            grant(&helper, "helpdesk", "dlg_receivers", "dlg_scope"),
            Err(OperationError::AccessDenied)
        );
        assert_eq!(
            grant(&admin_read_only, "helpdesk", "dlg_receivers", "dlg_scope"),
            Err(OperationError::AccessDenied)
        );
        // Only the built-in templates.
        assert_eq!(
            grant(&admin, "domain_admin", "dlg_receivers", "dlg_scope"),
            Err(OperationError::DG0001DelegationUnknownTemplate)
        );
        // Never high privilege groups, directly or nested.
        for (receiver, scope) in [
            ("dlg_hp_nested", "dlg_scope"),
            ("dlg_receivers", "dlg_hp_nested"),
            ("dlg_receivers", "dlg_hp_parent"),
            ("dlg_receivers", "idm_high_privilege"),
            ("idm_admins", "dlg_scope"),
        ] {
            assert_eq!(
                grant(&admin, "helpdesk", receiver, scope),
                Err(OperationError::DG0002DelegationHighPrivilegeGroup),
                "{receiver} {scope}"
            );
        }
        // Never built-in groups, such as every person.
        for (receiver, scope) in [
            ("dlg_receivers", "idm_all_persons"),
            ("idm_all_accounts", "dlg_scope"),
        ] {
            assert_eq!(
                grant(&admin, "helpdesk", receiver, scope),
                Err(OperationError::DG0003DelegationBuiltinGroup),
                "{receiver} {scope}"
            );
        }
        // Only groups.
        assert_eq!(
            grant(&admin, "helpdesk", "dlg_receivers", "dlg_target"),
            Err(OperationError::DG0004DelegationNotAGroup)
        );
        assert_eq!(
            grant(&admin, "helpdesk", "dlg_receivers", "dlg_does_not_exist"),
            Err(OperationError::NoMatchingEntries)
        );
        // The receivers are not the scope, nor in it.
        assert_eq!(
            grant(&admin, "helpdesk", "dlg_scope", "dlg_scope"),
            Err(OperationError::DG0005DelegationReceiverIsScope)
        );
        assert_eq!(
            grant(&admin, "group_admin", "dlg_group_in_scope", "dlg_scope"),
            Err(OperationError::DG0005DelegationReceiverIsScope)
        );
        // A delegation exists once.
        assert_eq!(
            grant(&admin, "helpdesk", "dlg_receivers", "dlg_scope"),
            Ok(())
        );
        assert_eq!(
            grant(
                &admin,
                "idm_delegated_helpdesk",
                "dlg_receivers",
                "dlg_scope"
            ),
            Err(OperationError::DG0006DelegationAlreadyExists)
        );

        // A scope that is a receiver group (of the delegation just granted) is refused:
        // its members are never targets.
        assert_eq!(
            grant(&admin, "helpdesk", "dlg_group_outside", "dlg_receivers"),
            Err(OperationError::DG0007DelegationScopeIsReceiver)
        );

        // Neither self nor a reference to an entry that does not exist.
        for bad_filter in [
            ProtoFilter::AndNot(Box::new(ProtoFilter::SelfUuid)),
            ProtoFilter::Eq(
                Attribute::MemberOf.to_string(),
                "dlg_does_not_exist".to_string(),
            ),
        ] {
            assert_eq!(
                qs_write
                    .delegation_grant(
                        &admin,
                        "user_admin",
                        "dlg_receivers",
                        "dlg_scope",
                        Some(&bad_filter),
                    )
                    .map(|_| ()),
                Err(OperationError::DG0008DelegationInvalidFilter),
                "{bad_filter:?}"
            );
        }

        // The filter is validated against the schema.
        let bad_filter = ProtoFilter::Eq("dlg_not_an_attribute".to_string(), "x".to_string());
        let err = qs_write
            .delegation_grant(
                &admin,
                "user_admin",
                "dlg_receivers",
                "dlg_scope",
                Some(&bad_filter),
            )
            .expect_err("invalid filter");
        assert!(
            matches!(err, OperationError::InvalidAttributeName(_)),
            "{err:?}"
        );

        // A valid filter is kept, and reported as given.
        let filter = ProtoFilter::Pres(Attribute::Mail.to_string());
        let narrowed = qs_write
            .delegation_grant(
                &admin,
                "user_admin",
                "dlg_receivers",
                "dlg_scope",
                Some(&filter),
            )
            .expect("grant with a filter");
        assert_eq!(narrowed.filter, Some(filter));

        // Only access control admins list and revoke.
        assert_eq!(
            qs_write.delegation_list(&helper),
            Err(OperationError::AccessDenied)
        );
        assert_eq!(
            qs_write.delegation_revoke(&helper, &narrowed.name),
            Err(OperationError::AccessDenied)
        );
        let listed: Vec<String> = qs_write
            .delegation_list(&admin)
            .expect("list")
            .into_iter()
            .map(|grant| grant.name)
            .collect();
        assert_eq!(
            listed,
            vec![
                "delegation_helpdesk_8000000000000007_8000000000000006".to_string(),
                "delegation_user_admin_8000000000000007_8000000000000006".to_string(),
            ]
        );
        // Revoke only deletes delegations, not other profiles.
        assert_eq!(
            qs_write.delegation_revoke(&admin, "idm_acp_people_read"),
            Err(OperationError::NoMatchingEntries)
        );
        qs_write.commit().expect("commit");
    }

    /// The administrators of delegations can read the built-in templates.
    #[qs_test]
    async fn test_delegation_templates_readable(qs: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut qs_write = qs.write(ct).await.unwrap();
        setup(&mut qs_write);
        qs_write.commit().expect("commit");

        let mut qs_write = qs.write(ct).await.unwrap();
        let filter = filter!(f_eq(Attribute::Class, EntryClass::DelegatedRole.into()));
        let search = |qs_write: &mut QueryServerWriteTransaction<'_>, uuid: Uuid| {
            let ident = ident(qs_write, uuid);
            let se = SearchEvent::new_impersonate_identity(ident, filter.clone());
            qs_write
                .search(&se)
                .expect("search")
                .iter()
                .map(|entry| entry.get_uuid())
                .collect::<BTreeSet<_>>()
        };
        let templates: BTreeSet<Uuid> = DelegationTemplate::ALL
            .into_iter()
            .map(DelegationTemplate::role_uuid)
            .collect();
        assert_eq!(search(&mut qs_write, ACP_ADMIN), templates);
        assert!(search(&mut qs_write, HELPER).is_empty());
    }

    /// The receivers of a delegation are never its targets, even when their group is
    /// nested into the scope after the grant, and the receivers of one delegation are
    /// never the targets of another, in either direction. The exclusion follows the
    /// profiles as they are granted, revoked and revived.
    #[idm_test]
    async fn test_delegation_receivers_never_targets(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        setup(&mut idms_prox_write.qs_write);
        idms_prox_write
            .qs_write
            .internal_create(vec![
                person("dlg_helper2", HELPER2),
                person("dlg_helper_b", HELPER_B),
                group("dlg_receivers_b", RECEIVERS_B, &[HELPER_B]),
                // The scope of delegation B holds a receiver of delegation A.
                group("dlg_scope_b", SCOPE_B, &[HELPER, OUTSIDER]),
            ])
            .expect("create entries");
        add_member(&mut idms_prox_write.qs_write, RECEIVERS, HELPER2);
        // The scope of delegation A holds a receiver of delegation B.
        add_member(&mut idms_prox_write.qs_write, SCOPE, HELPER_B);
        idms_prox_write.commit().expect("commit");

        // Two separate grants, in separate transactions.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let admin = ident(&mut idms_prox_write.qs_write, ACP_ADMIN);
        idms_prox_write
            .qs_write
            .delegation_grant(&admin, "helpdesk", "dlg_receivers", "dlg_scope", None)
            .expect("grant a");
        idms_prox_write.commit().expect("commit");
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let grant_b = idms_prox_write
            .qs_write
            .delegation_grant(&admin, "helpdesk", "dlg_receivers_b", "dlg_scope_b", None)
            .expect("grant b");
        idms_prox_write.commit().expect("commit");

        // Each administers its scope, but not the receivers of the other in it.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        assert!(can_reset(&mut idms_prox_write, HELPER_B, OUTSIDER, ct));
        assert!(!can_reset(&mut idms_prox_write, HELPER_B, HELPER, ct));
        assert!(can_reset(&mut idms_prox_write, HELPER, TARGET, ct));
        assert!(!can_reset(&mut idms_prox_write, HELPER, HELPER_B, ct));
        drop(idms_prox_write);

        // The receiver group of A is nested into the scope of A after the grant: its
        // members are still not targets of A.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        add_member(&mut idms_prox_write.qs_write, SCOPE, RECEIVERS);
        idms_prox_write.commit().expect("commit");

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        assert!(can_reset(&mut idms_prox_write, HELPER, TARGET, ct));
        assert!(!can_reset(&mut idms_prox_write, HELPER, HELPER2, ct));
        assert!(!can_reset(&mut idms_prox_write, HELPER2, HELPER, ct));
        assert!(!can_reset(&mut idms_prox_write, HELPER, HELPER_B, ct));
        drop(idms_prox_write);

        // Once B is revoked, its former receiver is an ordinary member of the scope of A.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        idms_prox_write
            .qs_write
            .delegation_revoke(&admin, &grant_b.name)
            .expect("revoke b");
        idms_prox_write.commit().expect("commit");
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        assert!(can_reset(&mut idms_prox_write, HELPER, HELPER_B, ct));
        assert!(!can_reset(&mut idms_prox_write, HELPER_B, OUTSIDER, ct));
        drop(idms_prox_write);

        // Reviving the profile of B excludes its receivers again.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        idms_prox_write
            .qs_write
            .internal_revive_uuid(grant_b.uuid)
            .expect("revive b");
        idms_prox_write.commit().expect("commit");
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        assert!(!can_reset(&mut idms_prox_write, HELPER, HELPER_B, ct));
        assert!(can_reset(&mut idms_prox_write, HELPER_B, OUTSIDER, ct));
        assert!(!can_reset(&mut idms_prox_write, HELPER_B, HELPER, ct));
        drop(idms_prox_write);
    }

    /// A grant is refused while a group it depends on has an entry manager that is not
    /// high privilege, or is (or holds) a dynamic group. An entry manager set after the
    /// grant is reported as drift.
    #[qs_test]
    async fn test_delegation_entry_managers_and_dyngroups(qs: &QueryServer) {
        let ct = duration_from_epoch_now();
        let dyngroup = Uuid::new_v4();
        let mut qs_write = qs.write(ct).await.unwrap();
        setup(&mut qs_write);
        qs_write
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Class, EntryClass::DynGroup.to_value()),
                (Attribute::Name, Value::new_iname("dlg_dyngroup")),
                (Attribute::Uuid, Value::Uuid(dyngroup)),
                (
                    Attribute::DynGroupFilter,
                    Value::new_json_filter_s("{\"eq\":[\"displayname\",\"dyn\"]}").expect("filter")
                )
            )])
            .expect("create");
        qs_write.commit().expect("commit");

        let set_manager =
            |qs_write: &mut QueryServerWriteTransaction<'_>, group: Uuid, manager: Uuid| {
                qs_write
                    .internal_modify_uuid(
                        group,
                        &ModifyList::new_purge_and_set(
                            Attribute::EntryManagedBy,
                            Value::Refer(manager),
                        ),
                    )
                    .expect("set entry manager");
            };
        let clear_manager = |qs_write: &mut QueryServerWriteTransaction<'_>, group: Uuid| {
            qs_write
                .internal_modify_uuid(group, &ModifyList::new_purge(Attribute::EntryManagedBy))
                .expect("clear entry manager");
        };

        // A non high privilege entry manager of the scope, of a group nested in it, or of
        // the receiver group refuses the grant.
        // That includes a scope managed by the receiver group itself.
        for (group, manager) in [
            (SCOPE, HELPER),
            (GROUP_IN_SCOPE, HELPER),
            (RECEIVERS, HELPER),
            (SCOPE, RECEIVERS),
        ] {
            let mut qs_write = qs.write(ct).await.unwrap();
            let admin = ident(&mut qs_write, ACP_ADMIN);
            set_manager(&mut qs_write, group, manager);
            assert_eq!(
                qs_write
                    .delegation_grant(&admin, "helpdesk", "dlg_receivers", "dlg_scope", None)
                    .map(|_| ()),
                Err(OperationError::DG0009DelegationEntryManaged),
                "{group}"
            );
        }
        // A high privilege entry manager is accepted.
        let mut qs_write = qs.write(ct).await.unwrap();
        let admin = ident(&mut qs_write, ACP_ADMIN);
        set_manager(&mut qs_write, GROUP_IN_SCOPE, HP_TARGET);
        qs_write
            .delegation_grant(&admin, "helpdesk", "dlg_receivers", "dlg_scope", None)
            .expect("grant");
        qs_write.commit().expect("commit");

        // A dynamic group can not be the receiver or the scope, nor be nested in them.
        let mut qs_write = qs.write(ct).await.unwrap();
        let admin = ident(&mut qs_write, ACP_ADMIN);
        for (receiver, scope) in [
            ("dlg_dyngroup", "dlg_group_outside"),
            ("dlg_receivers", "dlg_dyngroup"),
        ] {
            assert_eq!(
                qs_write
                    .delegation_grant(&admin, "user_admin", receiver, scope, None)
                    .map(|_| ()),
                Err(OperationError::DG0010DelegationDynamicGroup),
                "{receiver} {scope}"
            );
        }
        add_member(&mut qs_write, GROUP_IN_SCOPE, dyngroup);
        assert_eq!(
            qs_write
                .delegation_grant(&admin, "user_admin", "dlg_receivers", "dlg_scope", None)
                .map(|_| ()),
            Err(OperationError::DG0010DelegationDynamicGroup)
        );
        drop(qs_write);

        // An entry manager set after the grant is reported as drift, until it is removed.
        let mut qs_write = qs.write(ct).await.unwrap();
        let admin = ident(&mut qs_write, ACP_ADMIN);
        let name = "delegation_helpdesk_8000000000000007_8000000000000006";
        assert!(qs_write
            .delegation_get(&admin, name)
            .expect("get")
            .drift
            .is_empty());
        set_manager(&mut qs_write, GROUP_IN_SCOPE, HELPER);
        let drifted = qs_write.delegation_get(&admin, name).expect("get");
        assert_eq!(drifted.drift.len(), 1, "{:?}", drifted.drift);
        assert!(
            drifted.drift[0].contains("entry manager"),
            "{:?}",
            drifted.drift
        );
        assert_eq!(
            qs_write
                .delegation_list(&admin)
                .expect("list")
                .into_iter()
                .map(|grant| grant.drift.len())
                .collect::<Vec<_>>(),
            vec![1]
        );
        clear_manager(&mut qs_write, GROUP_IN_SCOPE);
        assert!(qs_write
            .delegation_get(&admin, name)
            .expect("get")
            .drift
            .is_empty());
        qs_write.commit().expect("commit");
    }

    /// The scope filter is stored by uuid: renaming a group it refers to (and giving its
    /// name to another group) does not change the scope.
    #[qs_test]
    async fn test_delegation_filter_stored_by_uuid(qs: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut qs_write = qs.write(ct).await.unwrap();
        setup(&mut qs_write);
        qs_write
            .internal_create(vec![group("dlg_excluded", EXCLUDED, &[TARGET])])
            .expect("create");
        let admin = ident(&mut qs_write, ACP_ADMIN);
        let filter = ProtoFilter::AndNot(Box::new(ProtoFilter::Eq(
            Attribute::MemberOf.to_string(),
            "dlg_excluded".to_string(),
        )));
        let grant = qs_write
            .delegation_grant(
                &admin,
                "user_admin",
                "dlg_receivers",
                "dlg_scope",
                Some(&filter),
            )
            .expect("grant");
        assert_eq!(
            grant.filter,
            Some(ProtoFilter::AndNot(Box::new(ProtoFilter::Eq(
                Attribute::MemberOf.to_string(),
                EXCLUDED.to_string(),
            ))))
        );
        qs_write.commit().expect("commit");

        let mut qs_write = qs.write(ct).await.unwrap();
        let helper = ident(&mut qs_write, HELPER);
        assert!(!can_modify(
            &mut qs_write,
            &helper,
            TARGET,
            &set_displayname()
        ));
        // The excluded group is renamed, and an empty group takes its name.
        qs_write
            .internal_modify_uuid(
                EXCLUDED,
                &ModifyList::new_purge_and_set(Attribute::Name, Value::new_iname("dlg_renamed")),
            )
            .expect("rename");
        qs_write
            .internal_create(vec![group("dlg_excluded", Uuid::new_v4(), &[])])
            .expect("create");
        // Any change of a profile reloads (and re-resolves) all of them.
        qs_write
            .delegation_grant(&admin, "helpdesk", "dlg_receivers", "dlg_scope", None)
            .expect("grant");
        qs_write.commit().expect("commit");

        let mut qs_write = qs.write(ct).await.unwrap();
        let helper = ident(&mut qs_write, HELPER);
        assert!(!can_modify(
            &mut qs_write,
            &helper,
            TARGET,
            &set_displayname()
        ));
        assert_eq!(
            qs_write
                .delegation_get(&admin, &grant.name)
                .expect("get")
                .filter,
            grant.filter
        );
    }

    /// A delegated profile grants what its template grants, even when the stored profile
    /// was changed (internally) to grant more.
    #[qs_test]
    async fn test_delegation_template_enforced_at_parse(qs: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut qs_write = qs.write(ct).await.unwrap();
        setup(&mut qs_write);
        let admin = ident(&mut qs_write, ACP_ADMIN);
        let grant = qs_write
            .delegation_grant(&admin, "user_admin", "dlg_receivers", "dlg_scope", None)
            .expect("grant");
        qs_write.commit().expect("commit");

        let set_mail = || {
            ModifyList::new_purge_and_set(
                Attribute::Mail,
                Value::EmailAddress("dlg_target@example.com".to_string(), true),
            )
        };
        let set_name =
            || ModifyList::new_purge_and_set(Attribute::Name, Value::new_iname("dlg_renamed"));

        // The profile is changed to grant writing the mail and the name, creating
        // entries and the targets of other classes.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_modify_uuid(
                grant.uuid,
                &ModifyList::new_list(vec![
                    Modify::Present(
                        Attribute::AcpModifyPresentAttr,
                        Value::new_iutf8n(Attribute::Mail.as_str()),
                    ),
                    Modify::Present(
                        Attribute::AcpModifyRemovedAttr,
                        Value::new_iutf8n(Attribute::Mail.as_str()),
                    ),
                    Modify::Present(
                        Attribute::AcpModifyPresentAttr,
                        Value::new_iutf8n(Attribute::Name.as_str()),
                    ),
                    Modify::Purged(Attribute::DelegatedScopeFilter),
                ]),
            )
            .expect("modify");
        qs_write.commit().expect("commit");

        let mut qs_write = qs.write(ct).await.unwrap();
        let helper = ident(&mut qs_write, HELPER);
        // The template's rights are kept ...
        assert!(can_modify(
            &mut qs_write,
            &helper,
            TARGET,
            &set_displayname()
        ));
        // ... and nothing more: not the mail, nor the name, nor a group in scope.
        assert!(!can_modify(&mut qs_write, &helper, TARGET, &set_mail()));
        assert!(!can_modify(&mut qs_write, &helper, TARGET, &set_name()));
        assert!(!can_delete(&mut qs_write, &helper, GROUP_IN_SCOPE));
        let drift = qs_write.delegation_get(&admin, &grant.name).expect("get");
        assert!(!drift.drift.is_empty());
    }

    /// A delegation's profile can not be changed through the generic access control
    /// operations, and a profile that differs from its template is reported.
    #[qs_test]
    async fn test_delegation_acp_manage_and_drift(qs: &QueryServer) {
        let ct = duration_from_epoch_now();
        let plain_acp = Uuid::new_v4();
        let mut qs_write = qs.write(ct).await.unwrap();
        setup(&mut qs_write);
        qs_write
            .internal_create(vec![entry_init!(
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
                (Attribute::Name, Value::new_iname("dlg_plain_acp")),
                (Attribute::Uuid, Value::Uuid(plain_acp)),
                (Attribute::AcpReceiverGroup, Value::ReferN(RECEIVERS)),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"pres\":\"name\"}").expect("filter")
                ),
                (
                    Attribute::AcpSearchAttr,
                    Value::new_iutf8n(Attribute::Name.as_str())
                )
            )])
            .expect("create");
        let admin = ident(&mut qs_write, ACP_ADMIN);
        let grant = qs_write
            .delegation_grant(&admin, "helpdesk", "dlg_receivers", "dlg_scope", None)
            .expect("grant");
        qs_write.commit().expect("commit");

        let mut qs_write = qs.write(ct).await.unwrap();
        let admin = ident(&mut qs_write, ACP_ADMIN);
        // idm_acp_acp_manage still lets access control admins change other profiles ...
        assert!(can_modify(
            &mut qs_write,
            &admin,
            plain_acp,
            &ModifyList::new_purge_and_set(Attribute::Description, Value::new_utf8s("x"))
        ));
        // ... but not a delegation's.
        assert!(!can_modify(
            &mut qs_write,
            &admin,
            grant.uuid,
            &ModifyList::new_append(Attribute::AcpReceiverGroup, Value::ReferN(GROUP_OUTSIDE))
        ));
        assert!(!can_modify(
            &mut qs_write,
            &admin,
            grant.uuid,
            &ModifyList::new_append(
                Attribute::AcpSearchAttr,
                Value::new_iutf8n(Attribute::LegalName.as_str())
            )
        ));
        assert!(!can_delete(&mut qs_write, &admin, grant.uuid));
        drop(qs_write);

        // Changed behind the template's back (internally): the drift is reported, with
        // every receiver.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_modify_uuid(
                grant.uuid,
                &ModifyList::new_list(vec![
                    Modify::Present(Attribute::AcpReceiverGroup, Value::ReferN(GROUP_OUTSIDE)),
                    Modify::Present(
                        Attribute::AcpSearchAttr,
                        Value::new_iutf8n(Attribute::LegalName.as_str()),
                    ),
                    Modify::Present(Attribute::Class, EntryClass::AccessControlDelete.to_value()),
                ]),
            )
            .expect("modify");
        let drifted = qs_write.delegation_get(&admin, &grant.name).expect("get");
        assert_eq!(
            drifted
                .receivers
                .iter()
                .map(|group| group.uuid)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([RECEIVERS, GROUP_OUTSIDE])
        );
        assert_eq!(drifted.drift.len(), 3, "{:?}", drifted.drift);
        assert!(drifted
            .drift
            .iter()
            .any(|d| d.contains("2 receiver groups")));
        assert!(drifted.drift.iter().any(|d| d.contains("legalname")));
        assert!(drifted
            .drift
            .iter()
            .any(|d| d.contains(EntryClass::AccessControlDelete.as_ref())));
        qs_write.commit().expect("commit");
    }
}
