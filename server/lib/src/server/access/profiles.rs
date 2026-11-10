use crate::idm::pip::PipAttributeName;
use crate::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

use crate::filter::{Filter, FilterValid, FilterValidResolved};
use crate::server::delegation::{DelegationTemplate, DelegationTemplateGrant};

use kubidm_proto::internal::Filter as ProtoFilter;

// =========================================================================
// PARSE ENTRY TO ACP, AND ACP MANAGEMENT
// =========================================================================

#[derive(Debug, Clone)]
pub struct AccessControlSearchResolved<'a> {
    pub acp: &'a AccessControlSearch,
    pub receiver_condition: AccessControlReceiverCondition,
    pub target_condition: AccessControlTargetCondition,
}

#[derive(Debug, Clone)]
pub struct AccessControlSearch {
    pub acp: AccessControlProfile,
    pub attrs: BTreeSet<Attribute>,
}

impl AccessControlSearch {
    pub fn try_from(
        qs: &mut QueryServerWriteTransaction,
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality(Attribute::Class, &EntryClass::AccessControlSearch.into()) {
            admin_error!("class {} not present.", EntryClass::AccessControlSearch);
            return Err(OperationError::InvalidAcpState(format!(
                "Missing {}",
                EntryClass::AccessControlSearch
            )));
        }

        let mut attrs: BTreeSet<_> = value
            .get_ava_iter_iutf8(Attribute::AcpSearchAttr)
            .ok_or_else(|| {
                admin_error!("Missing {}", Attribute::AcpSearchAttr);
                OperationError::InvalidAcpState(format!("Missing {}", Attribute::AcpSearchAttr))
            })?
            .map(Attribute::from)
            .collect();

        // Kubidm: a delegated profile grants what its template grants, whatever is stored.
        if let Some(grant) = delegated_template_grant(value)? {
            attrs = grant.search_attrs.into_iter().collect();
        }

        // Ability to search memberof, implies the ability to read directmemberof
        if attrs.contains(&Attribute::MemberOf) {
            attrs.insert(Attribute::DirectMemberOf);
        }

        let acp = AccessControlProfile::try_from(qs, value)?;

        Ok(AccessControlSearch { acp, attrs })
    }

    /// ⚠️  - Manually create a search access profile from values.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(super) fn from_raw(
        name: &str,
        uuid: Uuid,
        receiver: Uuid,
        targetscope: Filter<FilterValid>,
        attrs: &str,
    ) -> Self {
        let mut attrs: BTreeSet<_> = attrs.split_whitespace().map(Attribute::from).collect();

        // Ability to search memberof, implies the ability to read directmemberof
        if attrs.contains(&Attribute::MemberOf) {
            attrs.insert(Attribute::DirectMemberOf);
        }

        AccessControlSearch {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid,
                receiver: AccessControlReceiver::Group(btreeset!(receiver)),
                target: AccessControlTarget::Scope(targetscope),
                require_reauth: false,
                time_restriction_start: None,
                time_restriction_end: None,
                pip_condition: None,
            },
            attrs,
        }
    }

    /// ⚠️  - Manually create a search access profile with time restrictions.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(super) fn from_raw_with_time(
        name: &str,
        uuid: Uuid,
        receiver: Uuid,
        targetscope: Filter<FilterValid>,
        attrs: &str,
        time_restriction_start: Option<time::OffsetDateTime>,
        time_restriction_end: Option<time::OffsetDateTime>,
    ) -> Self {
        let mut attrs: BTreeSet<_> = attrs.split_whitespace().map(Attribute::from).collect();

        // Ability to search memberof, implies the ability to read directmemberof
        if attrs.contains(&Attribute::MemberOf) {
            attrs.insert(Attribute::DirectMemberOf);
        }

        AccessControlSearch {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid,
                receiver: AccessControlReceiver::Group(btreeset!(receiver)),
                target: AccessControlTarget::Scope(targetscope),
                require_reauth: false,
                time_restriction_start,
                time_restriction_end,
                pip_condition: None,
            },
            attrs,
        }
    }

    /// ⚠️  - Manually create a search access profile that requires a privileged
    /// (read-write) session.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(super) fn from_raw_require_reauth(
        name: &str,
        uuid: Uuid,
        receiver: Uuid,
        targetscope: Filter<FilterValid>,
        attrs: &str,
    ) -> Self {
        let mut acs = Self::from_raw(name, uuid, receiver, targetscope, attrs);
        acs.acp.require_reauth = true;
        acs
    }

    /// ⚠️  - Manually create a search access profile from values.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(super) fn from_managed_by(
        name: &str,
        uuid: Uuid,
        target: AccessControlTarget,
        attrs: &str,
    ) -> Self {
        AccessControlSearch {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid,
                receiver: AccessControlReceiver::EntryManager,
                target,
                require_reauth: false,
                time_restriction_start: None,
                time_restriction_end: None,
                pip_condition: None,
            },
            attrs: attrs.split_whitespace().map(Attribute::from).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessControlDeleteResolved<'a> {
    pub acp: &'a AccessControlDelete,
    pub receiver_condition: AccessControlReceiverCondition,
    pub target_condition: AccessControlTargetCondition,
}

#[derive(Debug, Clone)]
pub struct AccessControlDelete {
    pub acp: AccessControlProfile,
}

impl AccessControlDelete {
    pub fn try_from(
        qs: &mut QueryServerWriteTransaction,
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality(Attribute::Class, &EntryClass::AccessControlDelete.into()) {
            admin_error!("class access_control_delete not present.");
            return Err(OperationError::InvalidAcpState(
                "Missing access_control_delete".to_string(),
            ));
        }

        let mut acp = AccessControlProfile::try_from(qs, value)?;
        // Kubidm: a delegated profile grants delete only when its template does.
        if delegated_template_grant(value)?.is_some_and(|grant| !grant.delete) {
            acp.receiver = AccessControlReceiver::None;
        }

        Ok(AccessControlDelete { acp })
    }

    /// ⚠️  - Manually create a delete access profile from values.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(super) fn from_raw(
        name: &str,
        uuid: Uuid,
        receiver: Uuid,
        targetscope: Filter<FilterValid>,
    ) -> Self {
        AccessControlDelete {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid,
                receiver: AccessControlReceiver::Group(btreeset!(receiver)),
                target: AccessControlTarget::Scope(targetscope),
                require_reauth: false,
                time_restriction_start: None,
                time_restriction_end: None,
                pip_condition: None,
            },
        }
    }

    /// ⚠️  - Manually create a delete access profile from values.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(super) fn from_managed_by(name: &str, uuid: Uuid, target: AccessControlTarget) -> Self {
        AccessControlDelete {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid,
                receiver: AccessControlReceiver::EntryManager,
                target,
                require_reauth: false,
                time_restriction_start: None,
                time_restriction_end: None,
                pip_condition: None,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessControlCreateResolved<'a> {
    pub acp: &'a AccessControlCreate,
    pub receiver_condition: AccessControlReceiverCondition,
    pub target_condition: AccessControlTargetCondition,
}

#[derive(Debug, Clone)]
pub struct AccessControlCreate {
    pub acp: AccessControlProfile,
    pub classes: Vec<AttrString>,
    pub attrs: Vec<Attribute>,
}

impl AccessControlCreate {
    pub fn try_from(
        qs: &mut QueryServerWriteTransaction,
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality(Attribute::Class, &EntryClass::AccessControlCreate.into()) {
            admin_error!("class {} not present.", EntryClass::AccessControlCreate);
            return Err(OperationError::InvalidAcpState(format!(
                "Missing {}",
                EntryClass::AccessControlCreate
            )));
        }

        let attrs: Vec<Attribute> = value
            .get_ava_iter_iutf8(Attribute::AcpCreateAttr)
            .map(|i| i.map(Attribute::from).collect())
            .unwrap_or_default();

        // Kubidm: create access is evaluated before the memberof plugin purges client
        // supplied values, so granting memberof on create would let a client claim
        // memberships for the access check. memberof is always server maintained.
        for attr in [Attribute::MemberOf, Attribute::DirectMemberOf] {
            if attrs.contains(&attr) {
                admin_error!(
                    "{} may not grant the server maintained {}",
                    Attribute::AcpCreateAttr,
                    attr
                );
                return Err(OperationError::InvalidAcpState(format!(
                    "{} may not contain {}",
                    Attribute::AcpCreateAttr,
                    attr
                )));
            }
        }

        let classes = value
            .get_ava_iter_iutf8(Attribute::AcpCreateClass)
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_default();

        let mut acp = AccessControlProfile::try_from(qs, value)?;
        // Kubidm: no delegation template grants create.
        if delegated_template_grant(value)?.is_some() {
            acp.receiver = AccessControlReceiver::None;
        }

        Ok(AccessControlCreate {
            acp,
            classes,
            attrs,
        })
    }

    /// ⚠️  - Manually create a create access profile from values.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(super) fn from_raw(
        name: &str,
        uuid: Uuid,
        receiver: Uuid,
        targetscope: Filter<FilterValid>,
        classes: &str,
        attrs: &str,
    ) -> Self {
        AccessControlCreate {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid,
                receiver: AccessControlReceiver::Group(btreeset!(receiver)),
                target: AccessControlTarget::Scope(targetscope),
                require_reauth: false,
                time_restriction_start: None,
                time_restriction_end: None,
                pip_condition: None,
            },
            classes: classes.split_whitespace().map(AttrString::from).collect(),
            attrs: attrs.split_whitespace().map(Attribute::from).collect(),
        }
    }

    /// ⚠️  - Manually create a create access profile from values.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(super) fn from_managed_by(
        name: &str,
        uuid: Uuid,
        target: AccessControlTarget,
        classes: &str,
        attrs: &str,
    ) -> Self {
        AccessControlCreate {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid,
                receiver: AccessControlReceiver::EntryManager,
                target,
                require_reauth: false,
                time_restriction_start: None,
                time_restriction_end: None,
                pip_condition: None,
            },
            classes: classes.split_whitespace().map(AttrString::from).collect(),
            attrs: attrs.split_whitespace().map(Attribute::from).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessControlModifyResolved<'a> {
    pub acp: &'a AccessControlModify,
    pub receiver_condition: AccessControlReceiverCondition,
    pub target_condition: AccessControlTargetCondition,
}

#[derive(Debug, Clone)]
pub struct AccessControlModify {
    pub acp: AccessControlProfile,
    pub presattrs: Vec<Attribute>,
    pub remattrs: Vec<Attribute>,
    pub pres_classes: Vec<AttrString>,
    pub rem_classes: Vec<AttrString>,
}

impl AccessControlModify {
    pub fn try_from(
        qs: &mut QueryServerWriteTransaction,
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality(Attribute::Class, &EntryClass::AccessControlModify.into()) {
            admin_error!("class access_control_modify not present.");
            return Err(OperationError::InvalidAcpState(
                "Missing access_control_modify".to_string(),
            ));
        }

        // Kubidm: a delegated profile grants what its template grants, whatever is stored:
        // its attributes, and no classes.
        if let Some(grant) = delegated_template_grant(value)? {
            return Ok(AccessControlModify {
                acp: AccessControlProfile::try_from(qs, value)?,
                pres_classes: Vec::new(),
                rem_classes: Vec::new(),
                presattrs: grant.modify_attrs.clone(),
                remattrs: grant.modify_attrs,
            });
        }

        let presattrs = value
            .get_ava_iter_iutf8(Attribute::AcpModifyPresentAttr)
            .map(|i| i.map(Attribute::from).collect())
            .unwrap_or_default();

        let remattrs = value
            .get_ava_iter_iutf8(Attribute::AcpModifyRemovedAttr)
            .map(|i| i.map(Attribute::from).collect())
            .unwrap_or_default();

        let classes: Vec<AttrString> = value
            .get_ava_iter_iutf8(Attribute::AcpModifyClass)
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_default();

        let pres_classes = value
            .get_ava_iter_iutf8(Attribute::AcpModifyPresentClass)
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(|| classes.clone());

        let rem_classes = value
            .get_ava_iter_iutf8(Attribute::AcpModifyRemoveClass)
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(|| classes);

        Ok(AccessControlModify {
            acp: AccessControlProfile::try_from(qs, value)?,
            pres_classes,
            rem_classes,
            presattrs,
            remattrs,
        })
    }

    /// ⚠️  - Manually create a modify access profile from values.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(super) fn from_raw(
        name: &str,
        uuid: Uuid,
        receiver: Uuid,
        targetscope: Filter<FilterValid>,
        presattrs: &str,
        remattrs: &str,
        pres_classes: &str,
        rem_classes: &str,
    ) -> Self {
        AccessControlModify {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid,
                receiver: AccessControlReceiver::Group(btreeset!(receiver)),
                target: AccessControlTarget::Scope(targetscope),
                require_reauth: false,
                time_restriction_start: None,
                time_restriction_end: None,
                pip_condition: None,
            },
            pres_classes: pres_classes
                .split_whitespace()
                .map(AttrString::from)
                .collect(),
            rem_classes: rem_classes
                .split_whitespace()
                .map(AttrString::from)
                .collect(),
            presattrs: presattrs.split_whitespace().map(Attribute::from).collect(),
            remattrs: remattrs.split_whitespace().map(Attribute::from).collect(),
        }
    }

    /// ⚠️  - Manually create a modify access profile from values.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(super) fn from_managed_by(
        name: &str,
        uuid: Uuid,
        target: AccessControlTarget,
        presattrs: &str,
        remattrs: &str,
        pres_classes: &str,
        rem_classes: &str,
    ) -> Self {
        AccessControlModify {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid,
                receiver: AccessControlReceiver::EntryManager,
                target,
                require_reauth: false,
                time_restriction_start: None,
                time_restriction_end: None,
                pip_condition: None,
            },
            pres_classes: pres_classes
                .split_whitespace()
                .map(AttrString::from)
                .collect(),
            rem_classes: rem_classes
                .split_whitespace()
                .map(AttrString::from)
                .collect(),
            presattrs: presattrs.split_whitespace().map(Attribute::from).collect(),
            remattrs: remattrs.split_whitespace().map(Attribute::from).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum AccessControlReceiver {
    None,
    Group(BTreeSet<Uuid>),
    EntryManager,
}

#[derive(Debug, Clone)]
pub enum AccessControlReceiverCondition {
    // None,
    GroupChecked,
    EntryManager,
}

/*
impl AccessControlReceiverCondition {
    pub(crate) fn is_none(&self) {
        matches!(self, AccessControlReceiverCondition::None)
    }
}
*/

#[derive(Debug, Clone)]
pub enum AccessControlTarget {
    None,
    Scope(Filter<FilterValid>),
}

#[derive(Debug, Clone)]
pub enum AccessControlTargetCondition {
    // None,
    Scope(Filter<FilterValidResolved>),
}

/*
impl AccessControlTargetCondition {
    pub(crate) fn is_none(&self) {
        matches!(&self, AccessControlTargetCondition::None)
    }
}
*/

#[derive(Debug, Clone)]
pub struct AccessControlProfile {
    pub name: String,
    uuid: Uuid,
    pub receiver: AccessControlReceiver,
    pub target: AccessControlTarget,
    pub require_reauth: bool,
    pub time_restriction_start: Option<time::OffsetDateTime>,
    pub time_restriction_end: Option<time::OffsetDateTime>,
    /// Kubidm: the receiver must also satisfy this PIP condition, see [AcpPipCondition].
    pub pip_condition: Option<AcpPipCondition>,
}

impl AccessControlProfile {
    /// The uuid of the profile entry.
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    pub(super) fn try_from(
        qs: &mut QueryServerWriteTransaction,
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        // Assert we have class access_control_profile
        if !value.attribute_equality(Attribute::Class, &EntryClass::AccessControlProfile.into()) {
            error!("class access_control_profile not present.");
            return Err(OperationError::InvalidAcpState(
                "Missing access_control_profile".to_string(),
            ));
        }

        // copy name
        let name = value
            .get_ava_single_iname(Attribute::Name)
            .ok_or_else(|| {
                error!("Missing {}", Attribute::Name);
                OperationError::InvalidAcpState(format!("Missing {}", Attribute::Name))
            })?
            .to_string();
        // copy uuid
        let uuid = value.get_uuid();

        // Kubidm delegated administration. A delegated target is rewritten at parse time
        // into an upstream `Scope` target, so that the enforcement paths only ever see
        // `Group`/`EntryManager` receivers and `Scope` targets, and inherit their
        // fail-closed behaviour.
        let has_class =
            |class: EntryClass| value.attribute_equality(Attribute::Class, &class.into());
        let receiver_group = has_class(EntryClass::AccessControlReceiverGroup);
        let receiver_entry_manager = has_class(EntryClass::AccessControlReceiverEntryManager);
        let receiver_delegated = has_class(EntryClass::AccessControlReceiverDelegated);
        let target_scope = has_class(EntryClass::AccessControlTargetScope);
        let target_delegated = has_class(EntryClass::AccessControlTargetDelegatedScope);

        // Receiving a profile through the delegated scope is unsupported: it would make
        // the scope group both the administrators and the administered. Only a `Group`
        // (or `EntryManager`) receiver with a delegated target is supported.
        if receiver_delegated {
            admin_error!(
                ?name,
                "{} is unsupported, use {} with {}",
                EntryClass::AccessControlReceiverDelegated,
                EntryClass::AccessControlReceiverGroup,
                EntryClass::AccessControlTargetDelegatedScope
            );
            return Err(OperationError::InvalidAcpState(format!(
                "{} is unsupported",
                EntryClass::AccessControlReceiverDelegated
            )));
        }

        // Conflicting receiver or target kinds are ambiguous, reject them rather than
        // silently picking one.
        if receiver_group && receiver_entry_manager {
            admin_error!(
                ?name,
                "{} and {} are mutually exclusive",
                EntryClass::AccessControlReceiverGroup,
                EntryClass::AccessControlReceiverEntryManager
            );
            return Err(OperationError::InvalidAcpState(format!(
                "{} and {} are mutually exclusive",
                EntryClass::AccessControlReceiverGroup,
                EntryClass::AccessControlReceiverEntryManager
            )));
        }
        // A delegated target is administered by the receiver group its delegation
        // names, never by entry managers, which a delegation does not control.
        if target_delegated && !receiver_group {
            admin_error!(
                ?name,
                "{} requires {}",
                EntryClass::AccessControlTargetDelegatedScope,
                EntryClass::AccessControlReceiverGroup
            );
            return Err(OperationError::InvalidAcpState(format!(
                "{} requires {}",
                EntryClass::AccessControlTargetDelegatedScope,
                EntryClass::AccessControlReceiverGroup
            )));
        }
        if target_scope && target_delegated {
            admin_error!(
                ?name,
                "{} and {} are mutually exclusive",
                EntryClass::AccessControlTargetScope,
                EntryClass::AccessControlTargetDelegatedScope
            );
            return Err(OperationError::InvalidAcpState(format!(
                "{} and {} are mutually exclusive",
                EntryClass::AccessControlTargetScope,
                EntryClass::AccessControlTargetDelegatedScope
            )));
        }

        let receiver = if receiver_group {
            value
                .get_ava_refer(Attribute::AcpReceiverGroup)
                .cloned()
                .map(AccessControlReceiver::Group)
                .ok_or_else(|| {
                    admin_error!("Missing {}", Attribute::AcpReceiverGroup);
                    OperationError::InvalidAcpState(format!(
                        "Missing {}",
                        Attribute::AcpReceiverGroup
                    ))
                })?
        } else if receiver_entry_manager {
            AccessControlReceiver::EntryManager
        } else {
            warn!(
                ?name,
                "access control has no defined receivers - this will do nothing!"
            );
            AccessControlReceiver::None
        };

        let targetscope_f: Option<ProtoFilter> =
            if target_scope {
                // targetscope, and turn to real filter
                let targetscope_f: ProtoFilter = value
                    .get_ava_single_protofilter(Attribute::AcpTargetScope)
                    .cloned()
                    .ok_or_else(|| {
                        admin_error!("Missing {}", Attribute::AcpTargetScope);
                        OperationError::InvalidAcpState(format!(
                            "Missing {}",
                            Attribute::AcpTargetScope
                        ))
                    })?;
                Some(targetscope_f)
            } else if target_delegated {
                // The scope group is required. It is a reference, so referential integrity
                // removes it when the group is deleted: the filter alone must then never
                // become the scope, or the receivers would administer everything matching it.
                let Some(group) = value.get_ava_single_refer(Attribute::DelegatedScopeGroup) else {
                    admin_error!(
                        ?name,
                        "A delegated target requires {}",
                        Attribute::DelegatedScopeGroup
                    );
                    return Err(OperationError::InvalidAcpState(format!(
                        "A delegated target requires {}",
                        Attribute::DelegatedScopeGroup
                    )));
                };

                // The targets are the members of the delegated scope group ...
                let mut target_terms = vec![ProtoFilter::Eq(
                    Attribute::MemberOf.to_string(),
                    group.to_string(),
                )];
                // ... that have the classes of the template, whatever the stored filter says
                // (an unknown template is refused) ...
                if let Some(grant) = delegated_template_grant(value)? {
                    target_terms.extend(grant.target_classes.into_iter().map(|class| {
                        ProtoFilter::Eq(Attribute::Class.to_string(), class.to_string())
                    }));
                }
                // ... that also match the delegated scope filter, if any ...
                if let Some(scope_filter) = value
                    .get_ava_single_protofilter(Attribute::DelegatedScopeFilter)
                    .cloned()
                {
                    target_terms.push(scope_filter);
                }
                // ... and are never high privilege, recycled or tombstoned, the same exclusion
                // the upstream user management profiles apply, nor members of the privileged
                // built-in groups listed in `DELEGATION_EXCLUDED_BUILTINS`. Nor are they the
                // receivers of any delegated profile, so that the administrators of one
                // delegation are never administered through another, and a profile's own
                // administrators are never administered through it, even when a receiver group
                // is nested into the scope group later.
                let mut excluded = vec![
                    ProtoFilter::Eq(
                        Attribute::MemberOf.to_string(),
                        UUID_IDM_HIGH_PRIVILEGE.to_string(),
                    ),
                    ProtoFilter::Eq(
                        Attribute::Class.to_string(),
                        EntryClass::Recycled.to_string(),
                    ),
                    ProtoFilter::Eq(
                        Attribute::Class.to_string(),
                        EntryClass::Tombstone.to_string(),
                    ),
                ];
                // The receivers are derived from the delegated profiles themselves, each time
                // the access controls are reloaded, which they are whenever a profile is
                // created, changed, deleted or revived. So the exclusion can never drift from
                // the profiles, as a separately maintained group could (say, under concurrent
                // replicated grants). This profile's own receivers are always included.
                // A change of an entry manager or approver anywhere also reloads them.
                // Nor are they (members of) an entry manager or an approver of any entry:
                // taking over such a person would reach what it manages or approves (say, a
                // high privilege service account it manages), outside of the scope. Both
                // sets are computed once per reload, see `delegation_excluded_principals`.
                let mut receivers = match &qs.delegation_excluded {
                    Some(excluded) => excluded.clone(),
                    None => delegation_excluded_principals(qs)?,
                };
                if let AccessControlReceiver::Group(own) = &receiver {
                    receivers.extend(own.iter().copied());
                }
                for excluded_uuid in receivers
                    .into_iter()
                    .chain(DELEGATION_EXCLUDED_BUILTINS.iter().copied())
                {
                    excluded.push(ProtoFilter::Eq(
                        Attribute::Uuid.to_string(),
                        excluded_uuid.to_string(),
                    ));
                    excluded.push(ProtoFilter::Eq(
                        Attribute::MemberOf.to_string(),
                        excluded_uuid.to_string(),
                    ));
                }
                target_terms.push(ProtoFilter::AndNot(Box::new(ProtoFilter::Or(excluded))));
                Some(ProtoFilter::And(target_terms))
            } else {
                None
            };

        let target = if let Some(targetscope_f) = targetscope_f {
            let ident = Identity::from_internal();

            let targetscope_i = Filter::from_rw(&ident, &targetscope_f, qs).map_err(|e| {
                admin_error!("{} validation failed {:?}", Attribute::AcpTargetScope, e);
                e
            })?;

            targetscope_i
                .validate(qs.get_schema())
                .map_err(|e| {
                    admin_error!("{} Schema Violation {:?}", Attribute::AcpTargetScope, e);
                    OperationError::SchemaViolation(e)
                })
                .map(AccessControlTarget::Scope)?
        } else {
            warn!(
                ?name,
                "access control has no defined targets - this will do nothing!"
            );
            AccessControlTarget::None
        };

        let require_reauth = value
            .get_ava_single_bool(Attribute::AcpRequireReauth)
            .unwrap_or(false);

        // A maximum session age for step-up is not implemented. Reject it rather than
        // silently ignoring a restriction the administrator asked for.
        if value.attribute_pres(Attribute::AcpReauthMaxAge) {
            admin_error!(?name, "{} is unsupported", Attribute::AcpReauthMaxAge);
            return Err(OperationError::InvalidAcpState(format!(
                "{} is unsupported",
                Attribute::AcpReauthMaxAge
            )));
        }

        // Kubidm: checked, as to_offset panics for a time that is out of range in UTC. Such
        // a restriction is an error rather than dropped, which would widen the access.
        let restriction_utc = |attr: Attribute| {
            value
                .get_ava_single_datetime(attr.clone())
                .map(|dt| {
                    dt.checked_to_offset(time::UtcOffset::UTC).ok_or_else(|| {
                        admin_error!(?name, "{} can not be expressed in UTC", attr);
                        OperationError::InvalidAcpState(format!(
                            "{attr} can not be expressed in UTC"
                        ))
                    })
                })
                .transpose()
        };
        let time_restriction_start = restriction_utc(Attribute::AcpTimeRestrictionStart)?;
        let time_restriction_end = restriction_utc(Attribute::AcpTimeRestrictionEnd)?;

        // Kubidm: a malformed condition is an error rather than ignored, which would
        // widen the access to every receiver.
        let pip_condition = match value.get_ava_set(Attribute::AcpReceiverPipCondition) {
            Some(vs) => {
                let terms = vs.as_iutf8_iter().ok_or_else(|| {
                    admin_error!(?name, "{} is not iutf8", Attribute::AcpReceiverPipCondition);
                    OperationError::InvalidAcpState(format!(
                        "{} is not iutf8",
                        Attribute::AcpReceiverPipCondition
                    ))
                })?;
                Some(AcpPipCondition::parse(terms).map_err(|err| {
                    admin_error!(?name, %err, "Invalid {}", Attribute::AcpReceiverPipCondition);
                    OperationError::InvalidAcpState(format!(
                        "Invalid {}: {err}",
                        Attribute::AcpReceiverPipCondition
                    ))
                })?)
            }
            None => None,
        };

        Ok(AccessControlProfile {
            name,
            uuid,
            receiver,
            target,
            require_reauth,
            time_restriction_start,
            time_restriction_end,
            pip_condition,
        })
    }
}

/// Kubidm: a Policy Information Point condition on the receiver of an access control
/// profile, from `acp_receiver_pip_condition`.
///
/// Each value is `pip:<source>:<attribute>=<value>`, and every value must hold: the
/// receiver's prefetched PIP attribute `pip:<source>:<attribute>` must contain `<value>`.
/// Values are compared as strings, and (like the source and attribute names)
/// case-insensitively: the attribute's syntax stores them lowercased, see
/// [crate::idm::pip::prefetch::PipPrefetchedAttributes].
///
/// It fails closed: an identity without prefetched attributes (PIP not configured,
/// prefetch failed or timed out, an internal or anonymous identity) or without the
/// attribute or value never satisfies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcpPipCondition {
    /// `pip:<source>:<attribute>` to the values it must all contain, all lowercase.
    required: BTreeMap<String, BTreeSet<String>>,
}

impl AcpPipCondition {
    /// Parse the condition terms. At least one term is required, and every term must
    /// be well formed. Terms are lowercased.
    pub fn parse<'a>(terms: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let mut required: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for term in terms {
            let (name, value) = Self::parse_term(term)?;
            required.entry(name).or_default().insert(value);
        }
        if required.is_empty() {
            return Err("at least one condition is required".to_string());
        }
        Ok(AcpPipCondition { required })
    }

    fn parse_term(term: &str) -> Result<(String, String), String> {
        let term = term.to_lowercase();
        let term = term.as_str();
        let malformed = || format!("'{term}' is not of the form pip:<source>:<attribute>=<value>");

        let (name, value) = term.split_once('=').ok_or_else(malformed)?;
        let (source, attribute) = PipAttributeName::parse(name).ok_or_else(malformed)?;

        let valid_name = |part: &str| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        };
        if !valid_name(source.as_str()) {
            return Err(format!(
                "'{term}': the source must be non-empty and only use ASCII letters, digits, '_', '-' and '.'"
            ));
        }
        if !valid_name(&attribute) {
            return Err(format!(
                "'{term}': the attribute must be non-empty and only use ASCII letters, digits, '_', '-' and '.'"
            ));
        }
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(format!(
                "'{term}': the value must be non-empty and must not contain control characters"
            ));
        }

        Ok((name.to_string(), value.to_string()))
    }

    /// The `pip:<source>:<attribute>` names this condition reads.
    pub fn attribute_names(&self) -> impl Iterator<Item = &String> {
        self.required.keys()
    }

    /// Does `ident` satisfy this condition, from its prefetched PIP attributes?
    pub fn is_satisfied_by(&self, ident: &Identity) -> bool {
        let Some(attributes) = ident.pip_attributes() else {
            return false;
        };
        // Defence in depth: attributes are only attached to their own subject.
        if attributes.subject() != ident.get_uuid() {
            return false;
        }
        self.required.iter().all(|(name, values)| {
            attributes
                .values(name)
                .is_some_and(|have| values.is_subset(have))
        })
    }
}

/// Kubidm: the privileged built-in groups whose members (and which themselves) are never
/// the targets of a delegated profile, whatever its scope: taking over one of their
/// members would grant what the group grants (reading every mail address or the unix
/// authentication data, sending mail, or changing one's own mail address).
pub(crate) const DELEGATION_EXCLUDED_BUILTINS: [Uuid; 4] = [
    UUID_IDM_ACCOUNT_MAIL_READ,
    UUID_IDM_UNIX_AUTHENTICATION_READ,
    UUID_IDM_MAIL_SERVERS,
    UUID_IDM_PEOPLE_SELF_MAIL_WRITE,
];

/// Kubidm: the receiver groups of every delegated profile (enabled or not, valid or not),
/// as stored now. Their members are excluded from every delegated target.
pub(crate) fn delegated_receivers(
    qs: &mut QueryServerWriteTransaction,
) -> Result<BTreeSet<Uuid>, OperationError> {
    let profiles = qs.internal_search(filter!(f_eq(
        Attribute::Class,
        EntryClass::AccessControlTargetDelegatedScope.into()
    )))?;
    Ok(profiles
        .iter()
        .filter_map(|profile| profile.get_ava_refer(Attribute::AcpReceiverGroup))
        .flatten()
        .copied()
        .collect())
}

/// Kubidm: what the template of the delegated profile `value` grants, rebuilt from the
/// template its `delegated_role_template` names, so that a profile changed behind the
/// template's back (or granted by an older version of it) grants only what the template
/// grants now. `None` for a profile that is not delegated, and an error for a delegated
/// profile without a known template.
fn delegated_template_grant(
    value: &Entry<EntrySealed, EntryCommitted>,
) -> Result<Option<DelegationTemplateGrant>, OperationError> {
    if !value.attribute_equality(
        Attribute::Class,
        &EntryClass::AccessControlTargetDelegatedScope.into(),
    ) {
        return Ok(None);
    }
    value
        .get_ava_single_refer(Attribute::DelegatedRoleTemplate)
        .and_then(DelegationTemplate::from_role_uuid)
        .map(|template| Some(template.grant()))
        .ok_or_else(|| {
            admin_error!(
                "A delegated target requires a known {}",
                Attribute::DelegatedRoleTemplate
            );
            OperationError::InvalidAcpState(format!(
                "A delegated target requires a known {}",
                Attribute::DelegatedRoleTemplate
            ))
        })
}

/// Kubidm: does `entry` name entry managers or approvers? A change of such an entry
/// reloads the access controls, so that [`delegation_lateral_principals`] (and so every
/// delegated target) follows it.
pub(crate) fn delegation_lateral_reach<VALID, STATE>(entry: &Entry<VALID, STATE>) -> bool {
    entry.attribute_pres(Attribute::EntryManagedBy)
        || entry.attribute_pres(Attribute::Approver)
        || entry.attribute_pres(Attribute::BackupApprover)
        // Outstanding quorum snapshots keep authority even when policy references
        // disappear; request lifecycle changes must refresh the ACP exclusions.
        || entry.attribute_equality(Attribute::Class, &EntryClass::ApprovalRequest.into())
}

/// Kubidm: every entry manager (`entry_managed_by`) and approval policy approver
/// (`approver`, `backup_approver`) of any entry, as stored now. They, and their members, are excluded from
/// every delegated target: a delegation that could take over one of them would reach
/// whatever it manages or approves.
pub(crate) fn delegation_lateral_principals(
    qs: &mut QueryServerWriteTransaction,
) -> Result<BTreeSet<Uuid>, OperationError> {
    let entries = qs.internal_search(filter!(f_or(vec![
        f_pres(Attribute::EntryManagedBy),
        f_pres(Attribute::Approver),
        f_pres(Attribute::BackupApprover),
    ])))?;
    let mut principals = BTreeSet::new();
    for entry in entries.iter() {
        for attr in [
            Attribute::EntryManagedBy,
            Attribute::Approver,
            Attribute::BackupApprover,
        ] {
            if let Some(refs) = entry.get_ava_refer(&attr) {
                principals.extend(refs.iter().copied());
            }
            principals.extend(entry.get_ava_single_refer(&attr));
        }
    }
    Ok(principals)
}

/// Kubidm: the receivers of every delegated profile, and every entry manager and
/// approver: the entries that, with their members, are excluded from every delegated
/// target.
pub(crate) fn delegation_excluded_principals(
    qs: &mut QueryServerWriteTransaction,
) -> Result<BTreeSet<Uuid>, OperationError> {
    let mut excluded = delegated_receivers(qs)?;
    // No delegated receiver means no delegated profile can grant anything.
    // Avoid scanning every manager and outstanding approval during unrelated
    // ACP reloads on installations that do not use delegated administration.
    if excluded.is_empty() {
        return Ok(excluded);
    }
    excluded.extend(delegation_lateral_principals(qs)?);
    excluded.extend(crate::server::approval::delegation_snapshot_principals(qs)?);
    Ok(excluded)
}
