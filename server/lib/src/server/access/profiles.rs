use crate::prelude::*;
use std::collections::BTreeSet;

use crate::filter::{Filter, FilterValid, FilterValidResolved};

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

        Ok(AccessControlDelete {
            acp: AccessControlProfile::try_from(qs, value)?,
        })
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

        Ok(AccessControlCreate {
            acp: AccessControlProfile::try_from(qs, value)?,
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

        let targetscope_f: Option<ProtoFilter> = if target_scope {
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
            // ... that also match the delegated scope filter, if any ...
            if let Some(scope_filter) = value
                .get_ava_single_protofilter(Attribute::DelegatedScopeFilter)
                .cloned()
            {
                target_terms.push(scope_filter);
            }
            // ... and are never high privilege, recycled or tombstoned, the same exclusion
            // the upstream user management profiles apply.
            target_terms.push(ProtoFilter::AndNot(Box::new(ProtoFilter::Or(vec![
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
            ]))));
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

        Ok(AccessControlProfile {
            name,
            uuid,
            receiver,
            target,
            require_reauth,
            time_restriction_start,
            time_restriction_end,
        })
    }
}
