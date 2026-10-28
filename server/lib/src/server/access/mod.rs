//! Access Control Profiles
//!
//! This is a pretty important and security sensitive part of the code - it's
//! responsible for making sure that who is allowed to do what is enforced, as
//! well as who is *not* allowed to do what.
//!
//! A detailed design can be found in access-profiles-and-security.
//!
//! This component of the server really has a few parts
//! - the ability to parse access profile structures into real ACP structs
//! - the ability to apply sets of ACP's to entries for coarse actions (IE
//!   search.
//! - the ability to turn an entry into a partial-entry for results send
//!   requirements (also search).

use hashbrown::HashMap;
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    ops::DerefMut,
    sync::Arc,
    time::Duration,
};
use time::OffsetDateTime;

use concread::{arcache::ARCacheBuilder, cowcell::*};
use uuid::Uuid;

use crate::{
    entry::{Entry, EntryInit, EntryNew},
    event::{CreateEvent, DeleteEvent, ModifyEvent, SearchEvent},
    filter::{Filter, FilterValid, ResolveFilterCache, ResolveFilterCacheReadTxn},
    modify::Modify,
    prelude::*,
};

use self::profiles::{
    AccessControlCreate, AccessControlCreateResolved, AccessControlDelete,
    AccessControlDeleteResolved, AccessControlModify, AccessControlModifyResolved,
    AccessControlReceiver, AccessControlReceiverCondition, AccessControlSearch,
    AccessControlSearchResolved, AccessControlTarget, AccessControlTargetCondition,
};

use kubidm_proto::scim_v1::server::ScimAttributeEffectiveAccess;

use self::create::apply_create_access;

const ACP_RESOLVE_FILTER_CACHE_MAX: usize = 256;
const ACP_RESOLVE_FILTER_CACHE_LOCAL: usize = 0;

mod create;
mod delete;
mod migration;
mod modify;
pub mod profiles;
mod protected;
mod search;
mod utils;

pub use self::create::CreateResult;

/// Kubidm: the access control profiles that a reload skipped because they are invalid,
/// keyed by the profile uuid and the kind it was skipped as (the access control class
/// name, such as `access_control_search`), to the profile name. A profile of several
/// kinds may be valid as one kind and invalid as another.
pub type SkippedAcps = BTreeMap<(Uuid, &'static str), String>;
pub use self::delete::{apply_delete_access, DeleteResult};
pub use self::modify::{apply_modify_access, ModifyResult};
pub use self::search::{apply_search_access, SearchResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    Grant,
    Deny,
    Allow(BTreeSet<Attribute>),
}

impl From<&Access> for ScimAttributeEffectiveAccess {
    fn from(value: &Access) -> Self {
        match value {
            Access::Grant => Self::Grant,
            Access::Deny => Self::Deny,
            Access::Allow(set) => Self::Allow(set.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessClass {
    Grant,
    Deny,
    Allow(BTreeSet<AttrString>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessEffectivePermission {
    /// Who the access applies to
    pub ident: Uuid,
    /// The target the access affects
    pub target: Uuid,
    pub delete: bool,
    pub search: Access,
    pub modify_pres: Access,
    pub modify_rem: Access,
    pub modify_pres_class: AccessClass,
    pub modify_rem_class: AccessClass,
}

pub enum AccessBasicResult {
    // Deny this operation unconditionally.
    Deny,
    // Unbounded allow, provided no deny state exists.
    Grant,
    // This module makes no decisions about this entry.
    Ignore,
}

pub enum AccessSrchResult {
    // Deny this operation unconditionally.
    Deny,
    // Unbounded allow, provided no deny state exists.
    Grant,
    // This module makes no decisions about this entry.
    Ignore,
    // Limit the allowed attr set to this - this doesn't
    // allow anything, it constrains what might be allowed
    // by a later module.
    /*
    Constrain {
        attr: BTreeSet<Attribute>,
    },
    */
    Allow { attr: BTreeSet<Attribute> },
}

pub enum AccessModResult<'a> {
    // Deny this operation unconditionally.
    Deny,
    // Unbounded allow, provided no deny state exists.
    // Grant,
    // This module makes no decisions about this entry.
    Ignore,
    // Limit the allowed attr set to this - this doesn't
    // allow anything, it constrains what might be allowed
    // by a later module.
    Constrain {
        pres_attr: BTreeSet<Attribute>,
        rem_attr: BTreeSet<Attribute>,
        pres_cls: Option<BTreeSet<&'a str>>,
        rem_cls: Option<BTreeSet<&'a str>>,
    },
    // Allow these modifications within constraints.
    Allow {
        pres_attr: BTreeSet<Attribute>,
        rem_attr: BTreeSet<Attribute>,
        pres_class: BTreeSet<&'a str>,
        rem_class: BTreeSet<&'a str>,
    },
}

// =========================================================================
// ACP transactions and management for server bits.
// =========================================================================

#[derive(Clone)]
struct AccessControlsInner {
    acps_search: Vec<AccessControlSearch>,
    acps_create: Vec<AccessControlCreate>,
    acps_modify: Vec<AccessControlModify>,
    acps_delete: Vec<AccessControlDelete>,
    sync_agreements: HashMap<Uuid, BTreeSet<Attribute>>,
    /// Kubidm: the enabled profiles that the last reload skipped because they are invalid,
    /// per kind. They grant nothing (as that kind) until they are fixed or disabled.
    skipped: SkippedAcps,
    // Oauth2
    // Sync prov
}

pub struct AccessControls {
    inner: CowCell<AccessControlsInner>,
    // acp_related_search_cache: ARCache<Uuid, Vec<Uuid>>,
    acp_resolve_filter_cache: ResolveFilterCache,
}

fn resolve_access_conditions(
    ident: &Identity,
    ident_memberof: Option<&BTreeSet<Uuid>>,
    receiver: &AccessControlReceiver,
    target: &AccessControlTarget,
    acp_resolve_filter_cache: &mut ResolveFilterCacheReadTxn<'_>,
) -> Option<(AccessControlReceiverCondition, AccessControlTargetCondition)> {
    let receiver_condition = match receiver {
        AccessControlReceiver::Group(groups) => {
            let group_check = ident_memberof
                // Have at least one group allowed.
                .map(|imo| {
                    trace!(?imo, ?groups);
                    imo.intersection(groups).next().is_some()
                })
                .unwrap_or_default();

            if group_check {
                AccessControlReceiverCondition::GroupChecked
            } else {
                // AccessControlReceiverCondition::None
                return None;
            }
        }
        AccessControlReceiver::EntryManager => AccessControlReceiverCondition::EntryManager,
        AccessControlReceiver::None => return None,
        // AccessControlReceiverCondition::None,
    };

    let target_condition = match &target {
        AccessControlTarget::Scope(filter) => filter
            .resolve(ident, None, Some(acp_resolve_filter_cache))
            .map_err(|e| {
                admin_error!(?e, "A internal filter/event was passed for resolution!?!?");
                e
            })
            .ok()
            .map(AccessControlTargetCondition::Scope)?,
        AccessControlTarget::None => return None,
    };

    Some((receiver_condition, target_condition))
}

pub trait AccessControlsTransaction<'a> {
    fn get_search(&self) -> &Vec<AccessControlSearch>;
    fn get_create(&self) -> &Vec<AccessControlCreate>;
    fn get_modify(&self) -> &Vec<AccessControlModify>;
    fn get_delete(&self) -> &Vec<AccessControlDelete>;
    fn get_sync_agreements(&self) -> &HashMap<Uuid, BTreeSet<Attribute>>;
    /// Kubidm: the enabled profiles that the last reload skipped because they are
    /// invalid, per kind, see `SkippedAcps`.
    fn get_skipped(&self) -> &SkippedAcps;

    /// Kubidm: the enabled profiles (uuid to name) that the last reload skipped as any
    /// kind.
    fn get_skipped_profiles(&self) -> BTreeMap<Uuid, &str> {
        self.get_skipped()
            .iter()
            .map(|((uuid, _), name)| (*uuid, name.as_str()))
            .collect()
    }

    #[allow(clippy::mut_from_ref)]
    fn get_acp_resolve_filter_cache(&self) -> &mut ResolveFilterCacheReadTxn<'a>;
    /// The time of the enclosing transaction, used to evaluate ACP time restrictions.
    fn get_curtime(&self) -> OffsetDateTime;

    #[instrument(level = "trace", name = "access::search_related_acp", skip_all)]
    fn search_related_acp<'b>(
        &'b self,
        ident: &Identity,
        attrs: Option<&BTreeSet<Attribute>>,
    ) -> Vec<AccessControlSearchResolved<'b>> {
        let search_state = self.get_search();
        let acp_resolve_filter_cache = self.get_acp_resolve_filter_cache();

        // ⚠️  WARNING ⚠️  -- Why is this cache commented out?
        //
        // The reason for this is that to determine what acps relate, we need to be
        // aware of session claims - since these can change session to session, we
        // would need the cache to be structured to handle this. It's much better
        // in a search to just lean on the filter resolve cache because of this
        // dynamic behaviour.
        //
        // It may be possible to do per-operation caching when we know that we will
        // perform the reduce step, but it may not be worth it. It's probably better
        // to make entry_match_no_index faster.

        /*
        if let Some(acs_uuids) = acp_related_search_cache.get(rec_entry.get_uuid()) {
            lperf_trace_segment!( "access::search_related_acp<cached>", || {
                // If we have a cache, we should look here first for all the uuids that match

                // could this be a better algo?
                search_state
                    .iter()
                    .filter(|acs| acs_uuids.binary_search(&acs.acp.uuid).is_ok())
                    .collect()
            })
        } else {
        */
        // else, we calculate this, and then stash/cache the uuids.

        let ident_memberof = ident.get_memberof();

        // let related_acp: Vec<(&AccessControlSearch, Filter<FilterValidResolved>)> =
        let related_acp: Vec<AccessControlSearchResolved<'b>> = search_state
            .iter()
            .filter_map(|acs| {
                // Now resolve the receiver filter
                // Okay, so in filter resolution, the primary error case
                // is that we have a non-user in the event. We have already
                // checked for this above BUT we should still check here
                // properly just in case.
                //
                // In this case, we assume that if the event is internal
                // that the receiver can NOT match because it has no selfuuid
                // and can as a result, never return true. This leads to this
                // acp not being considered in that case ... which should never
                // happen because we already bypassed internal ops above!
                //
                // A possible solution is to change the filter resolve function
                // such that it takes an entry, rather than an event, but that
                // would create issues in search.
                let (receiver_condition, target_condition) = resolve_access_conditions(
                    ident,
                    ident_memberof,
                    &acs.acp.receiver,
                    &acs.acp.target,
                    acp_resolve_filter_cache,
                )?;

                Some(AccessControlSearchResolved {
                    acp: acs,
                    receiver_condition,
                    target_condition,
                })
            })
            .collect();

        // Trim any search rule that doesn't provide attributes related to the request.
        let related_acp = if let Some(r_attrs) = attrs.as_ref() {
            related_acp
                .into_iter()
                .filter(|acs| !acs.acp.attrs.is_disjoint(r_attrs))
                .collect()
        } else {
            // None here means all attrs requested.
            related_acp
        };

        related_acp
    }

    #[instrument(level = "debug", name = "access::filter_entries", skip_all)]
    fn filter_entries(
        &self,
        ident: &Identity,
        filter_orig: &Filter<FilterValid>,
        entries: Vec<Arc<EntrySealedCommitted>>,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        // Prepare some shared resources.

        // Get the set of attributes requested by this se filter. This is what we are
        // going to access check.
        let requested_attrs: BTreeSet<Attribute> = filter_orig.get_attr_set();

        // First get the set of acps that apply to this receiver
        let related_acp = self.search_related_acp(ident, None);

        // For each entry.
        let entries_is_empty = entries.is_empty();
        let allowed_entries: Vec<_> = entries
            .into_iter()
            .filter(|e| {
                match apply_search_access(ident, related_acp.as_slice(), e, self.get_curtime()) {
                    SearchResult::Deny => false,
                    SearchResult::Grant => true,
                    SearchResult::Allow(allowed_attrs) => {
                        // The allow set constrained.
                        let decision = requested_attrs.is_subset(&allowed_attrs);
                        security_debug!(
                            ?decision,
                            allowed = ?allowed_attrs,
                            requested = ?requested_attrs,
                            "search attribute decision",
                        );
                        decision
                    }
                }
            })
            .collect();

        if allowed_entries.is_empty() {
            if !entries_is_empty {
                security_access!("denied ❌ - no entries were released");
            }
        } else {
            debug!("allowed search of {} entries ✅", allowed_entries.len());
        }

        Ok(allowed_entries)
    }

    // Contains all the way to eval acps to entries
    #[inline(always)]
    fn search_filter_entries(
        &self,
        se: &SearchEvent,
        entries: Vec<Arc<EntrySealedCommitted>>,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        self.filter_entries(&se.ident, &se.filter_orig, entries)
    }

    #[instrument(
        level = "debug",
        name = "access::search_filter_entry_attributes",
        skip_all
    )]
    fn search_filter_entry_attributes(
        &self,
        se: &SearchEvent,
        entries: Vec<Arc<EntrySealedCommitted>>,
    ) -> Result<Vec<EntryReducedCommitted>, OperationError> {
        struct DoEffectiveCheck<'b> {
            modify_related_acp: Vec<AccessControlModifyResolved<'b>>,
            delete_related_acp: Vec<AccessControlDeleteResolved<'b>>,
            sync_agmts: &'b HashMap<Uuid, BTreeSet<Attribute>>,
        }

        match &se.ident.origin {
            IdentType::Internal(_) => {
                // In production we can't risk leaking data here, so we return
                // empty sets.
                security_critical!("IMPOSSIBLE STATE: Internal search in external interface?! Returning empty for safety.");
                // No need to check ACS
                return Err(OperationError::InvalidState);
            }
            IdentType::Synch(_) => {
                security_critical!("Blocking sync check");
                return Err(OperationError::InvalidState);
            }
            IdentType::User(u) => u.entry.get_uuid(),
        };

        // Build a reference set from the req_attrs. This is what we test against
        // to see if the attribute is something we currently want.

        let do_effective_check = se.effective_access_check.then(|| {
            debug!("effective permission check requested during reduction phase");

            // == modify ==
            let modify_related_acp = self.modify_related_acp(&se.ident);
            // == delete ==
            let delete_related_acp = self.delete_related_acp(&se.ident);

            let sync_agmts = self.get_sync_agreements();

            DoEffectiveCheck {
                modify_related_acp,
                delete_related_acp,
                sync_agmts,
            }
        });

        // Get the relevant acps for this receiver.
        let search_related_acp = self.search_related_acp(&se.ident, se.attrs.as_ref());

        // For each entry.
        let entries_is_empty = entries.is_empty();
        let allowed_entries: Vec<_> = entries
            .into_iter()
            .filter_map(|entry| {
                match apply_search_access(&se.ident, &search_related_acp, &entry, self.get_curtime()) {
                    SearchResult::Deny => {
                        None
                    }
                    SearchResult::Grant => {
                        // No properly written access module should allow
                        // unbounded attribute read!
                        error!("An access module allowed full read, this is a BUG! Denying read to prevent data leaks.");
                        None
                    }
                    SearchResult::Allow(allowed_attrs) => {
                        // The allow set constrained.
                        debug!(
                            requested = ?se.attrs,
                            allowed = ?allowed_attrs,
                            "reduction",
                        );

                        // Reduce requested by allowed.
                        let reduced_attrs = if let Some(requested) = se.attrs.as_ref() {
                            requested & &allowed_attrs
                        } else {
                            allowed_attrs
                        };

                        let effective_permissions = do_effective_check.as_ref().map(|do_check| {
                            self.entry_effective_permission_check(
                                &se.ident,
                                &entry,
                                &search_related_acp,
                                &do_check.modify_related_acp,
                                &do_check.delete_related_acp,
                                do_check.sync_agmts,
                            )
                        })
                        .map(Box::new);

                        Some(entry.reduce_attributes(&reduced_attrs, effective_permissions))
                    }
                }

                // End filter
            })
            .collect();

        if allowed_entries.is_empty() {
            if !entries_is_empty {
                security_access!("reduced to empty set on all entries ❌");
            }
        } else {
            debug!(
                "attribute set reduced on {} entries ✅",
                allowed_entries.len()
            );
        }

        Ok(allowed_entries)
    }

    #[instrument(level = "trace", name = "access::modify_related_acp", skip_all)]
    fn modify_related_acp<'b>(&'b self, ident: &Identity) -> Vec<AccessControlModifyResolved<'b>> {
        // Some useful references we'll use for the remainder of the operation
        let modify_state = self.get_modify();
        let acp_resolve_filter_cache = self.get_acp_resolve_filter_cache();

        let ident_memberof = ident.get_memberof();

        // Find the acps that relate to the caller, and compile their related
        // target filters.
        let related_acp: Vec<_> = modify_state
            .iter()
            .filter_map(|acs| {
                trace!(acs_name = ?acs.acp.name);
                let (receiver_condition, target_condition) = resolve_access_conditions(
                    ident,
                    ident_memberof,
                    &acs.acp.receiver,
                    &acs.acp.target,
                    acp_resolve_filter_cache,
                )?;

                Some(AccessControlModifyResolved {
                    acp: acs,
                    receiver_condition,
                    target_condition,
                })
            })
            .collect();

        related_acp
    }

    #[instrument(level = "debug", name = "access::modify_allow_operation", skip_all)]
    fn modify_allow_operation(
        &self,
        me: &ModifyEvent,
        entries: &[Arc<EntrySealedCommitted>],
    ) -> Result<bool, OperationError> {
        // Pre-check if the no-no purge class is present
        let disallow = me
            .modlist
            .iter()
            .any(|m| matches!(m, Modify::Purged(a) if a == Attribute::Class.as_ref()));

        if disallow {
            security_access!("Disallowing purge {} in modification", Attribute::Class);
            return Ok(false);
        }

        // Find the acps that relate to the caller, and compile their related
        // target filters.
        let related_acp: Vec<_> = self.modify_related_acp(&me.ident);

        // build two sets of "requested pres" and "requested rem"
        let requested_pres: BTreeSet<Attribute> = me
            .modlist
            .iter()
            .filter_map(|m| match m {
                Modify::Present(a, _) | Modify::Set(a, _) => Some(a.clone()),
                Modify::Removed(..) | Modify::Assert(..) | Modify::Purged(_) => None,
            })
            .collect();

        let requested_rem: BTreeSet<Attribute> = me
            .modlist
            .iter()
            .filter_map(|m| match m {
                Modify::Set(a, _) | Modify::Removed(a, _) | Modify::Purged(a) => Some(a.clone()),
                Modify::Present(..) | Modify::Assert(..) => None,
            })
            .collect();

        // Build the set of classes that we to work on, only in terms of "addition". To remove
        // I think we have no limit, but ... william of the future may find a problem with this
        // policy.
        let mut requested_pres_classes: BTreeSet<&str> = Default::default();
        let mut requested_rem_classes: BTreeSet<&str> = Default::default();

        for modify in me.modlist.iter() {
            match modify {
                Modify::Present(a, v) if a == Attribute::Class.as_ref() => {
                    // Here we have an option<&str> which could mean there is a risk of
                    // a malicious entity attempting to trick us by masking class mods
                    // in non-iutf8 types. However, the server first won't respect their
                    // existence, and second, we would have failed the mod at schema checking
                    // earlier in the process as these were not correctly type. As a result
                    // we can trust these to be correct here and not to be "None". Even so,
                    // deny rather than silently ignore a class we can not determine.
                    if let Some(s) = v.to_str() {
                        requested_pres_classes.insert(s);
                    } else {
                        error!("invalid modify present state - class was unable to be determined");
                        return Ok(false);
                    }
                }
                Modify::Removed(a, v) if a == Attribute::Class.as_ref() => {
                    if let Some(s) = v.to_str() {
                        requested_rem_classes.insert(s);
                    } else {
                        error!("invalid modify removed state - class was unable to be determined");
                        return Ok(false);
                    }
                }
                Modify::Set(a, v) if a == Attribute::Class.as_ref() => {
                    // This is a reasonably complex case - we actually have to contemplate
                    // the difference between what exists and what doesn't, but that's per-entry.
                    //
                    // for now, we treat this as both pres and rem, but I think that ultimately
                    // to fix this we need to make all modifies apply in terms of "batch mod"
                    requested_pres_classes.extend(v.as_iutf8_iter().into_iter().flatten());
                    requested_rem_classes.extend(v.as_iutf8_iter().into_iter().flatten());
                }
                _ => {}
            }
        }

        debug!(?requested_pres, "Requested present attribute set");
        debug!(?requested_rem, "Requested remove attribute set");
        debug!(?requested_pres_classes, "Requested present class set");
        debug!(?requested_rem_classes, "Requested remove class set");

        let sync_agmts = self.get_sync_agreements();

        let r = entries.iter().all(|e| {
            debug!(entry_id = %e.get_display_id());

            match apply_modify_access(
                &me.ident,
                related_acp.as_slice(),
                sync_agmts,
                e,
                self.get_curtime(),
            ) {
                ModifyResult::Deny => {
                    security_error!("modify access denied.");
                    false
                }
                ModifyResult::Grant => true,
                ModifyResult::Allow {
                    pres,
                    rem,
                    pres_cls,
                    rem_cls,
                } => {
                    let mut decision = true;

                    if !requested_pres.is_subset(&pres) {
                        security_error!("requested_pres is not a subset of allowed");
                        security_error!(
                            "requested_pres: {:?} !⊆ allowed: {:?}",
                            requested_pres,
                            pres
                        );
                        decision = false
                    };

                    if !requested_rem.is_subset(&rem) {
                        security_error!("requested_rem is not a subset of allowed");
                        security_error!("requested_rem: {:?} !⊆ allowed: {:?}", requested_rem, rem);
                        decision = false;
                    };

                    if !requested_pres_classes.is_subset(&pres_cls) {
                        security_error!("requested_pres_classes is not a subset of allowed");
                        security_error!(
                            "requested_pres_classes: {:?} !⊆ allowed: {:?}",
                            requested_pres_classes,
                            pres_cls
                        );
                        decision = false;
                    };

                    if !requested_rem_classes.is_subset(&rem_cls) {
                        security_error!("requested_rem_classes is not a subset of allowed");
                        security_error!(
                            "requested_rem_classes: {:?} !⊆ allowed: {:?}",
                            requested_rem_classes,
                            rem_cls
                        );
                        decision = false;
                    }

                    if decision {
                        debug!("passed pres, rem, classes check.");
                    }

                    // Yield the result
                    decision
                }
            }
        });

        if r {
            debug!("allowed modify of {} entries ✅", entries.len());
        } else {
            security_access!("denied ❌ - modify may not proceed");
        }
        Ok(r)
    }

    #[instrument(
        level = "debug",
        name = "access::batch_modify_allow_operation",
        skip_all
    )]
    fn batch_modify_allow_operation(
        &self,
        me: &BatchModifyEvent,
        entries: &[Arc<EntrySealedCommitted>],
    ) -> Result<bool, OperationError> {
        // Find the acps that relate to the caller, and compile their related
        // target filters.
        let related_acp = self.modify_related_acp(&me.ident);

        let r = entries.iter().all(|e| {
            // Due to how batch mod works, we have to check the modlist *per entry* rather
            // than as a whole.

            let Some(modlist) = me.modset.get(&e.get_uuid()) else {
                security_access!(
                    "modlist not present for {}, failing operation.",
                    e.get_uuid()
                );
                return false;
            };

            let disallow = modlist
                .iter()
                .any(|m| matches!(m, Modify::Purged(a) if a == Attribute::Class.as_ref()));

            if disallow {
                security_access!("Disallowing purge in modification");
                return false;
            }

            // build two sets of "requested pres" and "requested rem"
            if modlist.is_empty() {
                return false;
            };

            let requested_pres: BTreeSet<Attribute> = modlist
                .iter()
                .filter_map(|m| match m {
                    Modify::Present(a, _) | Modify::Set(a, _) | Modify::Assert(a, _) => Some(a.clone()),
                    _ => None,
                })
                .collect();

            let requested_rem: BTreeSet<Attribute> = modlist
                .iter()
                .filter_map(|m| match m {
                    Modify::Set(a, _) | Modify::Removed(a, _) | Modify::Purged(a) => Some(a.clone()),
                    _ => None,
                })
                .collect();

            let mut requested_pres_classes: BTreeSet<&str> = Default::default();
            let mut requested_rem_classes: BTreeSet<&str> = Default::default();

            for modify in modlist.iter() {
                match modify {
                    Modify::Present(a, v) if a == Attribute::Class.as_ref() => {
                        if let Some(s) = v.to_str() {
                            requested_pres_classes.insert(s);
                        } else {
                            error!("invalid modify present state - class was unable to be determined");
                            return false;
                        }
                    }
                    Modify::Removed(a, v) if a == Attribute::Class.as_ref() => {
                        if let Some(s) = v.to_str() {
                            requested_rem_classes.insert(s);
                        } else {
                            error!("invalid modify removed state - class was unable to be determined");
                            return false;
                        }
                    }
                    Modify::Set(a, v) if a == Attribute::Class.as_ref() => {
                        // When we apply the set of classes, we base the access control decision
                        // only on what CHANGED, rather than the full set that is present.
                        if let Some(current_classes) = e.get_ava_as_iutf8(Attribute::Class) {
                            if let Some(requested_classes) = v.as_iutf8_set() {
                                // Diff the classes to determine what changed. We only perform access
                                // checks on what is different, rather than everything in the set. This
                                // is what allow's SCIM PUT to operate since you have to "set" every
                                // value in the set, even if it's not one you have access too.
                                requested_pres_classes.extend( requested_classes.difference(current_classes).map(|s| s.as_str()) );
                                requested_rem_classes.extend( current_classes.difference(requested_classes).map(|s| s.as_str()) );
                            } else {
                                // This should be an impossible case - to have made it to this
                                // point, then the modify should have passed schema validation
                                // an must be a valid iutf8 set, and return a Some(). However
                                // in the interest of completeness, we defend from this and
                                // and deny the operation.
                                error!("invalid valueset state - requested class set is not valid");
                                return false;
                            }
                        } else {
                            error!("invalid entry state - entry does not have attribute class and is not valid");
                            return false;
                        }
                    }
                    _ => {}
                }
            }

            debug!(?requested_pres, "Requested present set");
            debug!(?requested_rem, "Requested remove set");
            debug!(?requested_pres_classes, "Requested present class set");
            debug!(?requested_rem_classes, "Requested remove class set");
            debug!(entry_id = %e.get_display_id());

            let sync_agmts = self.get_sync_agreements();

            match apply_modify_access(
                &me.ident,
                related_acp.as_slice(),
                sync_agmts,
                e,
                self.get_curtime(),
            ) {
                ModifyResult::Deny => {
                    security_error!("modify access denied.");
                    false
                }
                ModifyResult::Grant => true,
                ModifyResult::Allow {
                    pres,
                    rem,
                    pres_cls,
                    rem_cls,
                } => {
                    let mut decision = true;

                    if !requested_pres.is_subset(&pres) {
                        security_error!("requested_pres is not a subset of allowed");
                        security_error!(
                            "requested_pres: {:?} !⊆ allowed: {:?}",
                            requested_pres,
                            pres
                        );
                        decision = false
                    };

                    if !requested_rem.is_subset(&rem) {
                        security_error!("requested_rem is not a subset of allowed");
                        security_error!("requested_rem: {:?} !⊆ allowed: {:?}", requested_rem, rem);
                        decision = false;
                    };

                    if !requested_pres_classes.is_subset(&pres_cls) {
                        security_error!("requested_pres_classes is not a subset of allowed");
                        security_error!(
                            "requested_classes: {:?} !⊆ allowed: {:?}",
                            requested_pres_classes,
                            pres_cls
                        );
                        decision = false;
                    };

                    if !requested_rem_classes.is_subset(&rem_cls) {
                        security_error!("requested_rem_classes is not a subset of allowed");
                        security_error!(
                            "requested_classes: {:?} !⊆ allowed: {:?}",
                            requested_rem_classes,
                            rem_cls
                        );
                        decision = false;
                    }

                    if decision {
                        debug!("passed pres, rem, classes check.");
                    }

                    // Yield the result
                    decision
                }
            }
        });

        if r {
            debug!("allowed modify of {} entries ✅", entries.len());
        } else {
            security_access!("denied ❌ - modifications may not proceed");
        }
        Ok(r)
    }

    #[instrument(level = "debug", name = "access::create_allow_operation", skip_all)]
    fn create_allow_operation(
        &self,
        ce: &CreateEvent,
        entries: &[Entry<EntryInit, EntryNew>],
    ) -> Result<bool, OperationError> {
        // Some useful references we'll use for the remainder of the operation
        let create_state = self.get_create();
        let acp_resolve_filter_cache = self.get_acp_resolve_filter_cache();

        let ident_memberof = ce.ident.get_memberof();

        // Find the acps that relate to the caller.
        let related_acp: Vec<_> = create_state
            .iter()
            .filter_map(|acs| {
                let (receiver_condition, target_condition) = resolve_access_conditions(
                    &ce.ident,
                    ident_memberof,
                    &acs.acp.receiver,
                    &acs.acp.target,
                    acp_resolve_filter_cache,
                )?;

                Some(AccessControlCreateResolved {
                    acp: acs,
                    receiver_condition,
                    target_condition,
                })
            })
            .collect();

        // For each entry
        let decision = entries.iter().all(|e| {
            let requested_pres: BTreeSet<_> = e.attr_keys().cloned().collect();
            let Some(requested_pres_classes) = e
                .get_ava_as_iutf8(Attribute::Class)
                .map(|set| set.iter().map(|s| s.as_str()).collect::<BTreeSet<_>>())
            else {
                error!("unable to perform access control checks on entry with no classes, denied.");
                return false;
            };

            debug!(?requested_pres, "Requested present set");
            debug!(?requested_pres_classes, "Requested present class set");
            debug!(entry_id = %e.get_display_id());

            match apply_create_access(&ce.ident, related_acp.as_slice(), e, self.get_curtime()) {
                CreateResult::Deny => false,
                CreateResult::Grant => true,
                CreateResult::Allow { pres, pres_cls } => {
                    let mut decision = true;

                    if !requested_pres.is_subset(&pres) {
                        security_error!("requested_pres is not a subset of allowed");
                        security_error!(
                            "requested_pres: {:?} !⊆ allowed: {:?}",
                            requested_pres,
                            pres
                        );
                        decision = false
                    };

                    if !requested_pres_classes.is_subset(&pres_cls) {
                        security_error!("requested_pres_classes is not a subset of allowed");
                        security_error!(
                            "requested_classes: {:?} !⊆ allowed: {:?}",
                            requested_pres_classes,
                            pres_cls
                        );
                        decision = false;
                    };

                    if decision {
                        debug!("passed pres, classes check.");
                    }

                    decision
                }
            }
        });

        if decision {
            debug!("allowed create of {} entries ✅", entries.len());
        } else {
            security_access!("denied ❌ - create may not proceed");
        }

        Ok(decision)
    }

    #[instrument(level = "trace", name = "access::delete_related_acp", skip_all)]
    fn delete_related_acp<'b>(&'b self, ident: &Identity) -> Vec<AccessControlDeleteResolved<'b>> {
        // Some useful references we'll use for the remainder of the operation
        let delete_state = self.get_delete();
        let acp_resolve_filter_cache = self.get_acp_resolve_filter_cache();

        let ident_memberof = ident.get_memberof();

        let related_acp: Vec<_> = delete_state
            .iter()
            .filter_map(|acs| {
                let (receiver_condition, target_condition) = resolve_access_conditions(
                    ident,
                    ident_memberof,
                    &acs.acp.receiver,
                    &acs.acp.target,
                    acp_resolve_filter_cache,
                )?;

                Some(AccessControlDeleteResolved {
                    acp: acs,
                    receiver_condition,
                    target_condition,
                })
            })
            .collect();

        related_acp
    }

    #[instrument(level = "debug", name = "access::delete_allow_operation", skip_all)]
    fn delete_allow_operation(
        &self,
        de: &DeleteEvent,
        entries: &[Arc<EntrySealedCommitted>],
    ) -> Result<bool, OperationError> {
        // Find the acps that relate to the caller.
        let related_acp = self.delete_related_acp(&de.ident);

        // For each entry
        let r = entries.iter().all(|e| {
            match apply_delete_access(&de.ident, related_acp.as_slice(), e, self.get_curtime()) {
                DeleteResult::Deny => false,
                DeleteResult::Grant => true,
            }
        });
        if r {
            debug!("allowed delete of {} entries ✅", entries.len());
        } else {
            security_access!("denied ❌ - delete may not proceed");
        }
        Ok(r)
    }

    #[instrument(level = "debug", name = "access::effective_permission_check", skip_all)]
    fn effective_permission_check(
        &self,
        ident: &Identity,
        attrs: Option<BTreeSet<Attribute>>,
        entries: &[Arc<EntrySealedCommitted>],
    ) -> Result<Vec<AccessEffectivePermission>, OperationError> {
        // I think we need a structure like CheckResult, which is in the order of the
        // entries, but also stashes the uuid. Then it has search, mod, create, delete,
        // as separate attrs to describe what is capable.

        // Does create make sense here? I don't think it does. Create requires you to
        // have an entry template. I think james was right about the create being
        // a template copy op ...

        trace!(ident = %ident, "Effective permission check");
        // I think we separate this to multiple checks ...?

        // == search ==
        // Get the relevant acps for this receiver.
        let search_related_acp = self.search_related_acp(ident, attrs.as_ref());
        // == modify ==
        let modify_related_acp = self.modify_related_acp(ident);
        // == delete ==
        let delete_related_acp = self.delete_related_acp(ident);

        let sync_agmts = self.get_sync_agreements();

        let effective_permissions: Vec<_> = entries
            .iter()
            .map(|entry| {
                self.entry_effective_permission_check(
                    ident,
                    entry,
                    &search_related_acp,
                    &modify_related_acp,
                    &delete_related_acp,
                    sync_agmts,
                )
            })
            .collect();

        effective_permissions.iter().for_each(|ep| {
            trace!(?ep);
        });

        Ok(effective_permissions)
    }

    fn entry_effective_permission_check<'b>(
        &'b self,
        ident: &Identity,
        entry: &Arc<EntrySealedCommitted>,
        search_related_acp: &[AccessControlSearchResolved<'b>],
        modify_related_acp: &[AccessControlModifyResolved<'b>],
        delete_related_acp: &[AccessControlDeleteResolved<'b>],
        sync_agmts: &HashMap<Uuid, BTreeSet<Attribute>>,
    ) -> AccessEffectivePermission {
        // == search ==
        let search_effective =
            match apply_search_access(ident, search_related_acp, entry, self.get_curtime()) {
                SearchResult::Deny => Access::Deny,
                SearchResult::Grant => Access::Grant,
                SearchResult::Allow(allowed_attrs) => {
                    // Bound by requested attrs?
                    Access::Allow(allowed_attrs.into_iter().collect())
                }
            };

        // == modify ==
        let (modify_pres, modify_rem, modify_pres_class, modify_rem_class) =
            match apply_modify_access(
                ident,
                modify_related_acp,
                sync_agmts,
                entry,
                self.get_curtime(),
            ) {
                ModifyResult::Deny => (
                    Access::Deny,
                    Access::Deny,
                    AccessClass::Deny,
                    AccessClass::Deny,
                ),
                ModifyResult::Grant => (
                    Access::Grant,
                    Access::Grant,
                    AccessClass::Grant,
                    AccessClass::Grant,
                ),
                ModifyResult::Allow {
                    pres,
                    rem,
                    pres_cls,
                    rem_cls,
                } => (
                    Access::Allow(pres.into_iter().collect()),
                    Access::Allow(rem.into_iter().collect()),
                    AccessClass::Allow(pres_cls.into_iter().map(|s| s.into()).collect()),
                    AccessClass::Allow(rem_cls.into_iter().map(|s| s.into()).collect()),
                ),
            };

        // == delete ==
        let delete_status =
            apply_delete_access(ident, delete_related_acp, entry, self.get_curtime());

        let delete = match delete_status {
            DeleteResult::Deny => false,
            DeleteResult::Grant => true,
        };

        AccessEffectivePermission {
            ident: ident.get_uuid(),
            target: entry.get_uuid(),
            delete,
            search: search_effective,
            modify_pres,
            modify_rem,
            modify_pres_class,
            modify_rem_class,
        }
    }
}

pub struct AccessControlsWriteTransaction<'a> {
    inner: CowCellWriteTxn<'a, AccessControlsInner>,
    acp_resolve_filter_cache: Cell<ResolveFilterCacheReadTxn<'a>>,
    curtime: OffsetDateTime,
}

impl AccessControlsWriteTransaction<'_> {
    // We have a method to update each set, so that if an error
    // occurs we KNOW it's an error, rather than using errors as
    // part of the logic (IE try-parse-fail method).
    pub fn update_search(
        &mut self,
        mut acps: Vec<AccessControlSearch>,
    ) -> Result<(), OperationError> {
        std::mem::swap(&mut acps, &mut self.inner.deref_mut().acps_search);
        Ok(())
    }

    pub fn update_create(
        &mut self,
        mut acps: Vec<AccessControlCreate>,
    ) -> Result<(), OperationError> {
        std::mem::swap(&mut acps, &mut self.inner.deref_mut().acps_create);
        Ok(())
    }

    pub fn update_modify(
        &mut self,
        mut acps: Vec<AccessControlModify>,
    ) -> Result<(), OperationError> {
        std::mem::swap(&mut acps, &mut self.inner.deref_mut().acps_modify);
        Ok(())
    }

    pub fn update_delete(
        &mut self,
        mut acps: Vec<AccessControlDelete>,
    ) -> Result<(), OperationError> {
        std::mem::swap(&mut acps, &mut self.inner.deref_mut().acps_delete);
        Ok(())
    }

    /// Kubidm: record the profiles the reload skipped, see [AccessControlsTransaction::get_skipped].
    pub fn update_skipped(&mut self, mut skipped: SkippedAcps) {
        std::mem::swap(&mut skipped, &mut self.inner.deref_mut().skipped);
    }

    pub fn update_sync_agreements(
        &mut self,
        mut sync_agreements: HashMap<Uuid, BTreeSet<Attribute>>,
    ) {
        std::mem::swap(
            &mut sync_agreements,
            &mut self.inner.deref_mut().sync_agreements,
        );
    }

    pub fn commit(self) -> Result<(), OperationError> {
        self.inner.commit();

        Ok(())
    }
}

impl<'a> AccessControlsTransaction<'a> for AccessControlsWriteTransaction<'a> {
    fn get_search(&self) -> &Vec<AccessControlSearch> {
        &self.inner.acps_search
    }

    fn get_create(&self) -> &Vec<AccessControlCreate> {
        &self.inner.acps_create
    }

    fn get_modify(&self) -> &Vec<AccessControlModify> {
        &self.inner.acps_modify
    }

    fn get_delete(&self) -> &Vec<AccessControlDelete> {
        &self.inner.acps_delete
    }

    fn get_sync_agreements(&self) -> &HashMap<Uuid, BTreeSet<Attribute>> {
        &self.inner.sync_agreements
    }

    fn get_skipped(&self) -> &SkippedAcps {
        &self.inner.skipped
    }

    fn get_acp_resolve_filter_cache(&self) -> &mut ResolveFilterCacheReadTxn<'a> {
        unsafe {
            let mptr = self.acp_resolve_filter_cache.as_ptr();
            &mut (*mptr) as &mut ResolveFilterCacheReadTxn<'a>
        }
    }

    fn get_curtime(&self) -> OffsetDateTime {
        self.curtime
    }
}

// =========================================================================
// ACP operations (Should this actually be on the ACP's themself?
// =========================================================================

pub struct AccessControlsReadTransaction<'a> {
    inner: CowCellReadTxn<AccessControlsInner>,
    // acp_related_search_cache: Cell<ARCacheReadTxn<'a, Uuid, Vec<Uuid>>>,
    acp_resolve_filter_cache: Cell<ResolveFilterCacheReadTxn<'a>>,
    curtime: OffsetDateTime,
}

unsafe impl Sync for AccessControlsReadTransaction<'_> {}

unsafe impl Send for AccessControlsReadTransaction<'_> {}

impl<'a> AccessControlsTransaction<'a> for AccessControlsReadTransaction<'a> {
    fn get_search(&self) -> &Vec<AccessControlSearch> {
        &self.inner.acps_search
    }

    fn get_create(&self) -> &Vec<AccessControlCreate> {
        &self.inner.acps_create
    }

    fn get_modify(&self) -> &Vec<AccessControlModify> {
        &self.inner.acps_modify
    }

    fn get_delete(&self) -> &Vec<AccessControlDelete> {
        &self.inner.acps_delete
    }

    fn get_sync_agreements(&self) -> &HashMap<Uuid, BTreeSet<Attribute>> {
        &self.inner.sync_agreements
    }

    fn get_skipped(&self) -> &SkippedAcps {
        &self.inner.skipped
    }

    fn get_acp_resolve_filter_cache(&self) -> &mut ResolveFilterCacheReadTxn<'a> {
        unsafe {
            let mptr = self.acp_resolve_filter_cache.as_ptr();
            &mut (*mptr) as &mut ResolveFilterCacheReadTxn<'a>
        }
    }

    fn get_curtime(&self) -> OffsetDateTime {
        self.curtime
    }
}

// =========================================================================
// ACP transaction operations
// =========================================================================

impl Default for AccessControls {
    #![allow(clippy::expect_used)]
    fn default() -> Self {
        AccessControls {
            inner: CowCell::new(AccessControlsInner {
                acps_search: Vec::with_capacity(0),
                acps_create: Vec::with_capacity(0),
                acps_modify: Vec::with_capacity(0),
                acps_delete: Vec::with_capacity(0),
                sync_agreements: HashMap::default(),
                skipped: BTreeMap::new(),
            }),
            // Allow the expect, if this fails it represents a programming/development
            // failure.
            acp_resolve_filter_cache: ARCacheBuilder::new()
                .set_size(ACP_RESOLVE_FILTER_CACHE_MAX, ACP_RESOLVE_FILTER_CACHE_LOCAL)
                .set_reader_quiesce(true)
                .build()
                .expect("Failed to construct acp_resolve_filter_cache"),
        }
    }
}

impl AccessControls {
    pub fn try_quiesce(&self) {
        self.acp_resolve_filter_cache.try_quiesce();
    }

    /// `curtime` is the time of the enclosing transaction, see `get_curtime`.
    pub fn read(&self, curtime: Duration) -> AccessControlsReadTransaction<'_> {
        AccessControlsReadTransaction {
            inner: self.inner.read(),
            // acp_related_search_cache: Cell::new(self.acp_related_search_cache.read()),
            acp_resolve_filter_cache: Cell::new(self.acp_resolve_filter_cache.read()),
            curtime: OffsetDateTime::UNIX_EPOCH + curtime,
        }
    }

    /// `curtime` is the time of the enclosing transaction, see `get_curtime`.
    pub fn write(&self, curtime: Duration) -> AccessControlsWriteTransaction<'_> {
        AccessControlsWriteTransaction {
            inner: self.inner.write(),
            // acp_related_search_cache_wr: self.acp_related_search_cache.write(),
            // acp_related_search_cache: Cell::new(self.acp_related_search_cache.read()),
            acp_resolve_filter_cache: Cell::new(self.acp_resolve_filter_cache.read()),
            curtime: OffsetDateTime::UNIX_EPOCH + curtime,
        }
    }
}

/// Kubidm: assert that no access control profile is skipped, and that every built-in
/// profile (of the latest migrations, and any other profile stored in the system uuid
/// range) is stored, enabled and loaded as every kind it has.
#[cfg(test)]
pub(crate) fn assert_builtin_acps_all_loaded(
    qs_write: &mut crate::server::QueryServerWriteTransaction<'_>,
) {
    // Nothing was skipped.
    assert_eq!(
        qs_write.get_accesscontrols().get_skipped(),
        &SkippedAcps::new()
    );

    // The built-in profiles of the migrations ...
    let mut builtin: BTreeSet<Uuid> =
        crate::migration_data::latest::phase_7_builtin_access_control_profiles()
            .into_iter()
            .chain(crate::migration_data::dl14::kubidm_builtin_access_control_profiles())
            .map(|entry| entry.get_uuid().expect("builtin acp uuid"))
            .collect();
    for uuid in builtin.iter() {
        assert!(*uuid < DYNAMIC_RANGE_MINIMUM_UUID, "{uuid}");
    }
    // ... and any other profile in the system range.
    let stored = qs_write
        .internal_search(filter!(f_eq(
            Attribute::Class,
            EntryClass::AccessControlProfile.into()
        )))
        .expect("search");
    let stored: BTreeMap<Uuid, _> = stored
        .into_iter()
        .map(|entry| (entry.get_uuid(), entry))
        .filter(|(uuid, _)| *uuid < DYNAMIC_RANGE_MINIMUM_UUID)
        .collect();
    builtin.extend(stored.keys().copied());
    assert!(builtin.len() > 40, "{}", builtin.len());

    let acps = qs_write.get_accesscontrols();
    let kinds: [(EntryClass, BTreeSet<Uuid>); 4] = [
        (
            EntryClass::AccessControlSearch,
            acps.get_search().iter().map(|a| a.acp.uuid()).collect(),
        ),
        (
            EntryClass::AccessControlCreate,
            acps.get_create().iter().map(|a| a.acp.uuid()).collect(),
        ),
        (
            EntryClass::AccessControlModify,
            acps.get_modify().iter().map(|a| a.acp.uuid()).collect(),
        ),
        (
            EntryClass::AccessControlDelete,
            acps.get_delete().iter().map(|a| a.acp.uuid()).collect(),
        ),
    ];
    let mut checked = 0;
    for uuid in builtin {
        let entry = stored.get(&uuid).expect("builtin acp is stored");
        assert_ne!(
            entry.get_ava_single_bool(Attribute::AcpEnable),
            Some(false),
            "{uuid}"
        );
        let mut has_kind = false;
        for (kind, loaded) in kinds.iter() {
            if entry.attribute_equality(Attribute::Class, &(*kind).into()) {
                has_kind = true;
                checked += 1;
                assert!(
                    loaded.contains(&uuid),
                    "{} ({uuid}) is not loaded as {kind}",
                    entry.get_display_id()
                );
            }
        }
        assert!(has_kind, "{uuid}");
    }
    assert!(checked > 40, "{checked}");
}

#[cfg(test)]
mod tests {
    use hashbrown::HashMap;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
    };

    use uuid::uuid;

    use super::{
        profiles::{
            AccessControlCreate, AccessControlDelete, AccessControlModify, AccessControlProfile,
            AccessControlReceiver, AccessControlSearch, AccessControlTarget,
        },
        Access, AccessClass, AccessControls, AccessControlsTransaction, AccessEffectivePermission,
    };
    use crate::{migration_data::BUILTIN_ACCOUNT_ANONYMOUS, prelude::*, valueset::ValueSetIname};

    const UUID_TEST_ACCOUNT_1: Uuid = uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");
    const UUID_TEST_ACCOUNT_2: Uuid = uuid::uuid!("cec0852a-abdf-4ea6-9dae-d3157cb33d3a");
    const UUID_TEST_GROUP_1: Uuid = uuid::uuid!("81ec1640-3637-4a2f-8a52-874fa3c3c92f");
    const UUID_TEST_GROUP_2: Uuid = uuid::uuid!("acae81d6-5ea7-4bd8-8f7f-fcec4c0dd647");

    pub static E_TEST_ACCOUNT_1: LazyLock<Arc<EntrySealedCommitted>> = LazyLock::new(|| {
        Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("test_account_1")),
                (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1)),
                (Attribute::MemberOf, Value::ReferN(UUID_TEST_GROUP_1))
            )
            .into_sealed_committed(),
        )
    });
    pub static E_TEST_ACCOUNT_2: LazyLock<Arc<EntrySealedCommitted>> = LazyLock::new(|| {
        Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("test_account_1")),
                (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_2)),
                (Attribute::MemberOf, Value::ReferN(UUID_TEST_GROUP_2))
            )
            .into_sealed_committed(),
        )
    });

    macro_rules! acp_from_entry_err {
        (
            $qs:expr,
            $e:expr,
            $type:ty
        ) => {{
            let ev1 = $e.into_sealed_committed();

            let r1 = <$type>::try_from($qs, &ev1);
            error!(?r1);
            assert!(r1.is_err());
        }};
    }

    macro_rules! acp_from_entry_ok {
        (
            $qs:expr,
            $e:expr,
            $type:ty
        ) => {{
            let ev1 = $e.into_sealed_committed();

            let r1 = <$type>::try_from($qs, &ev1);
            assert!(r1.is_ok());
            r1.unwrap()
        }};
    }

    #[qs_test]
    async fn test_access_acp_parser(qs: &QueryServer) {
        // Test parsing entries to acp. There so no point testing schema violations
        // because the schema system is well tested an robust. Instead we target
        // entry misconfigurations, such as missing classes required.

        // Generally, we are testing the *positive* cases here, because schema
        // really protects us *a lot* here, but it's nice to have defence and
        // layers of validation.

        let mut qs_write = qs.write(duration_from_epoch_now()).await.unwrap();

        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("acp_invalid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                )
            ),
            AccessControlProfile
        );

        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
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
                (Attribute::Name, Value::new_iname("acp_invalid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                )
            ),
            AccessControlProfile
        );

        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
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
                (Attribute::Name, Value::new_iname("acp_invalid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (Attribute::AcpReceiverGroup, Value::Bool(true)),
                (Attribute::AcpTargetScope, Value::Bool(true))
            ),
            AccessControlProfile
        );

        // "\"Self\""
        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
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
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::ReferN(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlProfile
        );
    }

    /// Kubidm: `AcpTimeRestrictionStart` / `AcpTimeRestrictionEnd` are allowed on access
    /// control profiles by schema, and are honoured once the profile is loaded from the
    /// database.
    #[qs_test]
    async fn test_access_acp_time_restriction_end_to_end(qs: &QueryServer) {
        let ct = duration_from_epoch_now();
        let now = time::OffsetDateTime::UNIX_EPOCH + ct;
        let day = time::Duration::days(1);

        let reader_uuid = Uuid::new_v4();
        let group_uuid = Uuid::new_v4();
        let target_uuid = Uuid::new_v4();
        let acp_uuid = Uuid::new_v4();

        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_create(vec![
                entry_init!(
                    (Attribute::Class, EntryClass::Object.to_value()),
                    (Attribute::Class, EntryClass::Account.to_value()),
                    (Attribute::Class, EntryClass::Person.to_value()),
                    (Attribute::Name, Value::new_iname("tr_reader")),
                    (Attribute::DisplayName, Value::new_utf8s("tr_reader")),
                    (Attribute::Uuid, Value::Uuid(reader_uuid))
                ),
                entry_init!(
                    (Attribute::Class, EntryClass::Object.to_value()),
                    (Attribute::Class, EntryClass::Account.to_value()),
                    (Attribute::Class, EntryClass::Person.to_value()),
                    (Attribute::Name, Value::new_iname("tr_target")),
                    (Attribute::DisplayName, Value::new_utf8s("tr_target")),
                    (Attribute::Uuid, Value::Uuid(target_uuid))
                ),
                entry_init!(
                    (Attribute::Class, EntryClass::Object.to_value()),
                    (Attribute::Class, EntryClass::Group.to_value()),
                    (Attribute::Name, Value::new_iname("tr_readers")),
                    (Attribute::Uuid, Value::Uuid(group_uuid)),
                    (Attribute::Member, Value::ReferN(reader_uuid))
                ),
                entry_init!(
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
                    (Attribute::Name, Value::new_iname("acp_time_restricted")),
                    (Attribute::Uuid, Value::Uuid(acp_uuid)),
                    (Attribute::AcpReceiverGroup, Value::ReferN(group_uuid)),
                    (
                        Attribute::AcpTargetScope,
                        Value::new_json_filter_s("{\"eq\":[\"name\",\"tr_target\"]}")
                            .expect("filter")
                    ),
                    (
                        Attribute::AcpSearchAttr,
                        Value::new_iutf8n(Attribute::Name.as_str())
                    ),
                    (
                        Attribute::AcpSearchAttr,
                        Value::new_iutf8n(Attribute::Class.as_str())
                    ),
                    // The window has not opened yet.
                    (
                        Attribute::AcpTimeRestrictionStart,
                        Value::DateTime(now + day)
                    ),
                    (
                        Attribute::AcpTimeRestrictionEnd,
                        Value::DateTime(now + day + day)
                    )
                ),
            ])
            .expect("failed to create entries");

        // The restriction was stored and is parsed onto the profile ...
        let acp_entry = qs_write.internal_search_uuid(acp_uuid).unwrap();
        let acp = AccessControlProfile::try_from(&mut qs_write, &acp_entry).expect("acp parse");
        assert_eq!(acp.time_restriction_start, Some(now + day));
        assert_eq!(acp.time_restriction_end, Some(now + day + day));

        qs_write.commit().expect("commit");

        let search_as_reader = |qs_read: &mut QueryServerReadTransaction<'_>| {
            let reader = qs_read.internal_search_uuid(reader_uuid).unwrap();
            let ident = Identity::from_impersonate_entry_readonly(reader);
            let filter = filter!(f_eq(Attribute::Name, PartialValue::new_iname("tr_target")));
            qs_read
                .impersonate_search(filter.clone(), filter, &ident)
                .expect("search failed")
                .len()
        };

        // ... and is enforced: outside of the window nothing is granted.
        let mut qs_read = qs.read().await.unwrap();
        assert_eq!(search_as_reader(&mut qs_read), 0);
        drop(qs_read);

        // Open the window.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_modify_uuid(
                acp_uuid,
                &ModifyList::new_list(vec![
                    Modify::Purged(Attribute::AcpTimeRestrictionStart),
                    Modify::Present(
                        Attribute::AcpTimeRestrictionStart,
                        Value::DateTime(now - day),
                    ),
                    Modify::Purged(Attribute::AcpTimeRestrictionEnd),
                    Modify::Present(Attribute::AcpTimeRestrictionEnd, Value::DateTime(now + day)),
                ]),
            )
            .expect("failed to modify acp");
        qs_write.commit().expect("commit");

        let mut qs_read = qs.read().await.unwrap();
        assert_eq!(search_as_reader(&mut qs_read), 1);
        drop(qs_read);

        // The restriction is evaluated at the transaction time, not the wall clock, and
        // the end of the window is exclusive.
        for (offset, expected) in [
            (std::time::Duration::from_secs(86_400 - 1), 1),
            (std::time::Duration::from_secs(86_400), 0),
        ] {
            let mut qs_write = qs.write(ct + offset).await.unwrap();
            let reader = qs_write.internal_search_uuid(reader_uuid).unwrap();
            let ident = Identity::from_impersonate_entry_readonly(reader);
            let filter = filter!(f_eq(Attribute::Name, PartialValue::new_iname("tr_target")));
            let found = qs_write
                .impersonate_search(filter.clone(), filter, &ident)
                .expect("search failed")
                .len();
            assert_eq!(found, expected, "offset {offset:?}");
        }
    }

    #[qs_test]
    async fn test_access_acp_delete_parser(qs: &QueryServer) {
        let mut qs_write = qs.write(duration_from_epoch_now()).await.unwrap();

        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::ReferN(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlDelete
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::ReferN(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlDelete
        );
    }

    #[qs_test]
    async fn test_access_acp_search_parser(qs: &QueryServer) {
        // Test that parsing search access controls works.
        let mut qs_write = qs.write(duration_from_epoch_now()).await.unwrap();

        // Missing class acp
        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::ReferN(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                (
                    Attribute::AcpSearchAttr,
                    Value::new_iutf8n(Attribute::Name.as_str())
                ),
                (
                    Attribute::AcpSearchAttr,
                    Value::new_iutf8n(Attribute::Class.as_str())
                )
            ),
            AccessControlSearch
        );

        // Missing class acs
        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::ReferN(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                (
                    Attribute::AcpSearchAttr,
                    Value::new_iutf8n(Attribute::Name.as_str())
                ),
                (
                    Attribute::AcpSearchAttr,
                    Value::new_iutf8n(Attribute::Class.as_str())
                )
            ),
            AccessControlSearch
        );

        // Missing attr acp_search_attr
        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::ReferN(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlSearch
        );

        // All good!
        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::ReferN(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                (
                    Attribute::AcpSearchAttr,
                    Value::new_iutf8n(Attribute::Name.as_str())
                ),
                (
                    Attribute::AcpSearchAttr,
                    Value::new_iutf8n(Attribute::Class.as_str())
                )
            ),
            AccessControlSearch
        );
    }

    #[qs_test]
    async fn test_access_acp_modify_parser(qs: &QueryServer) {
        // Test that parsing modify access controls works.
        let mut qs_write = qs.write(duration_from_epoch_now()).await.unwrap();

        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Name, Value::new_iname("acp_invalid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::ReferN(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlModify
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Class, EntryClass::AccessControlModify.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::ReferN(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlModify
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Class, EntryClass::AccessControlModify.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::ReferN(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                (
                    Attribute::AcpModifyRemovedAttr,
                    Value::new_iutf8n(Attribute::Name.as_str())
                ),
                (
                    Attribute::AcpModifyPresentAttr,
                    Value::new_iutf8n(Attribute::Name.as_str())
                ),
                (Attribute::AcpModifyClass, EntryClass::Object.to_value())
            ),
            AccessControlModify
        );
    }

    #[qs_test]
    async fn test_access_acp_create_parser(qs: &QueryServer) {
        // Test that parsing create access controls works.
        let mut qs_write = qs.write(duration_from_epoch_now()).await.unwrap();

        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Name, Value::new_iname("acp_invalid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::ReferN(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                (
                    Attribute::AcpCreateAttr,
                    Value::new_iutf8n(Attribute::Name.as_str())
                ),
                (Attribute::AcpCreateClass, EntryClass::Object.to_value())
            ),
            AccessControlCreate
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::ReferN(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlCreate
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::ReferN(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                (
                    Attribute::AcpCreateAttr,
                    Value::new_iutf8n(Attribute::Name.as_str())
                ),
                (
                    Attribute::AcpCreateClass,
                    Value::new_iutf8n(EntryClass::Object.as_str())
                )
            ),
            AccessControlCreate
        );
    }

    #[qs_test]
    async fn test_access_acp_compound_parser(qs: &QueryServer) {
        // Test that parsing compound access controls works. This means that
        // given a single &str, we can evaluate all types from a single record.
        // This is valid, and could exist, IE a rule to allow create, search and modify
        // over a single scope.
        let mut qs_write = qs.write(duration_from_epoch_now()).await.unwrap();

        let e = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlProfile.to_value()
            ),
            (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
            (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
            (Attribute::Class, EntryClass::AccessControlModify.to_value()),
            (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
            (Attribute::Name, Value::new_iname("acp_valid")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (
                Attribute::AcpReceiverGroup,
                Value::ReferN(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (
                Attribute::AcpTargetScope,
                Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
            ),
            (
                Attribute::AcpSearchAttr,
                Value::new_iutf8n(Attribute::Name.as_str())
            ),
            (
                Attribute::AcpCreateClass,
                Value::new_iutf8n(EntryClass::Class.as_str())
            ),
            (
                Attribute::AcpCreateAttr,
                Value::new_iutf8n(Attribute::Name.as_str())
            ),
            (
                Attribute::AcpModifyRemovedAttr,
                Value::new_iutf8n(Attribute::Name.as_str())
            ),
            (
                Attribute::AcpModifyPresentAttr,
                Value::new_iutf8n(Attribute::Name.as_str())
            ),
            (
                Attribute::AcpModifyClass,
                Value::new_iutf8n(EntryClass::Object.as_str())
            )
        );

        acp_from_entry_ok!(&mut qs_write, e.clone(), AccessControlCreate);
        acp_from_entry_ok!(&mut qs_write, e.clone(), AccessControlDelete);
        acp_from_entry_ok!(&mut qs_write, e.clone(), AccessControlModify);
        acp_from_entry_ok!(&mut qs_write, e, AccessControlSearch);
    }

    macro_rules! test_acp_search {
        (
            $se:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write(duration_from_epoch_now());
            acw.update_search($controls).expect("Failed to update");
            let acw = acw;

            let res = acw
                .search_filter_entries(&mut $se, $entries)
                .expect("op failed");
            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert_eq!(res, $expect);
        }};
    }

    fn test_acp_search_reduce(
        se: &SearchEvent,
        controls: Vec<AccessControlSearch>,
        entries: Vec<Arc<EntrySealedCommitted>>,
        expect: Vec<EntrySealedCommitted>,
    ) {
        let ac = AccessControls::default();
        let mut acw = ac.write(duration_from_epoch_now());
        acw.update_search(controls).expect("Failed to update");
        let acw = acw;

        // We still have to reduce the entries to be sure that we are good.
        let res = acw
            .search_filter_entries(se, entries)
            .expect("operation failed");
        // Now on the reduced entries, reduce the entries attrs.
        let reduced = acw
            .search_filter_entry_attributes(se, res)
            .expect("operation failed");

        // Help the type checker for the expect set.
        let expect_set: Vec<EntryReducedCommitted> =
            expect.into_iter().map(|e| e.into_reduced()).collect();

        debug!("expect --> {:?}", expect_set);
        debug!("result --> {:?}", reduced);
        // should be ok, and same as expect.
        assert_eq!(reduced, expect_set);
    }

    #[test]
    fn test_access_internal_search() {
        // Test that an internal search bypasses ACS
        let se = SearchEvent::new_internal_invalid(filter!(f_pres(Attribute::Class)));

        let expect = vec![E_TEST_ACCOUNT_1.clone()];
        let entries = vec![E_TEST_ACCOUNT_1.clone()];

        // This acp basically is "allow access to stuff, but not this".
        test_acp_search!(
            &se,
            vec![AccessControlSearch::from_raw(
                "test_acp",
                Uuid::new_v4(),
                UUID_TEST_GROUP_1,
                filter_valid!(f_pres(Attribute::NonExist)), // apply to none - ie no allowed results
                Attribute::Name.as_ref(), // allow to this attr, but we don't eval this.
            )],
            entries,
            expect
        );
    }

    #[test]
    fn test_access_enforce_search() {
        // Test that entries from a search are reduced by acps
        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let ev2 = E_TESTPERSON_2.clone().into_sealed_committed();

        let r_set = vec![Arc::new(ev1.clone()), Arc::new(ev2)];

        let se_a = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_pres(Attribute::Name)),
        );
        let ex_a = vec![Arc::new(ev1)];

        let se_b = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_2.clone(),
            filter_all!(f_pres(Attribute::Name)),
        );
        let ex_b = vec![];

        let acp = AccessControlSearch::from_raw(
            "test_acp",
            Uuid::new_v4(),
            // apply to admin only
            UUID_TEST_GROUP_1,
            // Allow admin to read only testperson1
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // In that read, admin may only view the "name" attribute, or query on
            // the name attribute. Any other query (should be) rejected.
            Attribute::Name.as_ref(),
        );

        // Check the admin search event
        test_acp_search!(&se_a, vec![acp.clone()], r_set.clone(), ex_a);

        // Check the anonymous
        test_acp_search!(&se_b, vec![acp], r_set, ex_b);
    }

    #[test]
    fn test_access_enforce_scope_search() {
        sketching::test_init();
        // Test that identities are bound by their access scope.
        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();

        let ex_some = vec![Arc::new(ev1.clone())];

        let r_set = vec![Arc::new(ev1)];

        let se_ro = SearchEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readonly(E_TEST_ACCOUNT_1.clone()),
            filter_all!(f_pres(Attribute::Name)),
        );

        let se_rw = SearchEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            filter_all!(f_pres(Attribute::Name)),
        );

        let acp = AccessControlSearch::from_raw(
            "test_acp",
            Uuid::new_v4(),
            // apply to admin only
            UUID_TEST_GROUP_1,
            // Allow admin to read only testperson1
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // In that read, admin may only view the "name" attribute, or query on
            // the name attribute. Any other query (should be) rejected.
            Attribute::Name.as_ref(),
        );

        // Check the admin search event
        test_acp_search!(&se_ro, vec![acp.clone()], r_set.clone(), ex_some);

        test_acp_search!(&se_rw, vec![acp], r_set, ex_some);
    }

    #[test]
    fn test_access_enforce_scope_search_attrs() {
        // Test that in ident only mode that all attrs are always denied. The op should already have
        // "nothing to do" based on search_filter_entries, but we do the "right thing" anyway.

        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        let exv1 = E_TESTPERSON_1_REDUCED.clone().into_sealed_committed();

        let ex_anon_some = vec![exv1];

        let se_anon_ro = SearchEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readonly(E_TEST_ACCOUNT_1.clone()),
            filter_all!(f_pres(Attribute::Name)),
        );

        let acp = AccessControlSearch::from_raw(
            "test_acp",
            Uuid::new_v4(),
            // apply to all accounts.
            UUID_TEST_GROUP_1,
            // Allow anonymous to read only testperson1
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // In that read, admin may only view the "name" attribute, or query on
            // the name attribute. Any other query (should be) rejected.
            Attribute::Name.as_ref(),
        );

        // Finally test it!
        test_acp_search_reduce(&se_anon_ro, vec![acp], r_set, ex_anon_some);
    }

    pub static E_TESTPERSON_1_REDUCED: LazyLock<EntryInitNew> =
        LazyLock::new(|| entry_init_fn([(Attribute::Name, Value::new_iname("testperson1"))]));

    #[test]
    fn test_access_enforce_search_attrs() {
        // Test that attributes are correctly limited.
        // In this case, we test that a user can only see "name" despite the
        // class and uuid being present.
        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        let exv1 = E_TESTPERSON_1_REDUCED.clone().into_sealed_committed();
        let ex_anon = vec![exv1];

        let se_anon = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let acp = AccessControlSearch::from_raw(
            "test_acp",
            Uuid::new_v4(),
            // apply to anonymous only
            UUID_TEST_GROUP_1,
            // Allow anonymous to read only testperson1
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // In that read, admin may only view the "name" attribute, or query on
            // the name attribute. Any other query (should be) rejected.
            Attribute::Name.as_ref(),
        );

        // Finally test it!
        test_acp_search_reduce(&se_anon, vec![acp], r_set, ex_anon);
    }

    #[test]
    fn test_access_enforce_search_attrs_req() {
        sketching::test_init();

        // Test that attributes are correctly limited by the request.
        // In this case, we test that a user can only see "name" despite the
        // class and uuid being present.
        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();

        let r_set = vec![Arc::new(ev1)];

        let exv1 = E_TESTPERSON_1_REDUCED.clone().into_sealed_committed();
        let ex_anon = vec![exv1];

        let mut se_anon = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );
        // the requested attrs here.
        se_anon.attrs = Some(btreeset![Attribute::Name]);

        let acp = AccessControlSearch::from_raw(
            "test_acp",
            Uuid::new_v4(),
            // apply to anonymous only
            UUID_TEST_GROUP_1,
            // Allow anonymous to read only testperson1
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // In that read, admin may only view the "name" attribute, or query on
            // the name attribute. Any other query (should be) rejected.
            "name uuid",
        );

        trace!(?acp);

        // Finally test it!
        test_acp_search_reduce(&se_anon, vec![acp], r_set, ex_anon);
    }

    macro_rules! test_acp_modify {
        (
            $me:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write(duration_from_epoch_now());
            acw.update_modify($controls).expect("Failed to update");
            let acw = acw;

            let res = acw
                .modify_allow_operation(&mut $me, $entries)
                .expect("op failed");

            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert_eq!($expect, res);
        }};
        (
            $me:expr,
            $controls:expr,
            $sync_uuid:expr,
            $sync_yield_attr:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write(duration_from_epoch_now());
            acw.update_modify($controls).expect("Failed to update");
            let mut sync_agmt = HashMap::new();
            let mut set = BTreeSet::new();
            set.insert($sync_yield_attr);
            sync_agmt.insert($sync_uuid, set);
            acw.update_sync_agreements(sync_agmt);
            let acw = acw;

            let res = acw
                .modify_allow_operation(&mut $me, $entries)
                .expect("op failed");

            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert_eq!($expect, res);
        }};
    }

    #[test]
    fn test_access_enforce_modify() {
        sketching::test_init();

        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        // Name present
        let me_pres = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::Name, &Value::new_iname("value"))]),
        );
        // Name rem
        let me_rem = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_remove(Attribute::Name, &PartialValue::new_iname("value"))]),
        );
        // Name purge
        let me_purge = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_purge(Attribute::Name)]),
        );

        // Name Set
        let me_set = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([Modify::Set(Attribute::Name, ValueSetIname::new("value"))]),
        );

        // Class account pres
        let me_pres_class = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::Class, &EntryClass::Account.to_value())]),
        );
        // Class account rem
        let me_rem_class = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_remove(
                Attribute::Class,
                &EntryClass::Account.to_partialvalue()
            )]),
        );
        // Class purge
        let me_purge_class = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_purge(Attribute::Class)]),
        );

        // Set Class
        let me_set_class = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([Modify::Set(
                Attribute::Class,
                EntryClass::Account.to_valueset()
            )]),
        );

        // Allow name and class, class is account
        let acp_allow = AccessControlModify::from_raw(
            "test_modify_allow",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To modify testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // Allow pres name and class
            "name class",
            // Allow rem name and class
            "name class",
            // And the class allowed is account
            EntryClass::Account.into(),
            // And the class allowed is account
            EntryClass::Account.into(),
        );
        // Allow member, class is group. IE not account
        let acp_deny = AccessControlModify::from_raw(
            "test_modify_deny",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To modify testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // Allow pres name and class
            "member class",
            // Allow rem name and class
            "member class",
            EntryClass::Group.into(),
            EntryClass::Group.into(),
        );
        // Does not have a pres or rem class in attrs
        let acp_no_class = AccessControlModify::from_raw(
            "test_modify_no_class",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To modify testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // Allow pres name and class
            "name class",
            // Allow rem name and class
            "name class",
            // And the class allowed is NOT an account ...
            EntryClass::Group.into(),
            EntryClass::Group.into(),
        );

        // Test allowed pres
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r_set, true);
        // test allowed rem
        test_acp_modify!(&me_rem, vec![acp_allow.clone()], &r_set, true);
        // test allowed purge
        test_acp_modify!(&me_purge, vec![acp_allow.clone()], &r_set, true);
        // test allowed set
        test_acp_modify!(&me_set, vec![acp_allow.clone()], &r_set, true);

        // Test rejected pres
        test_acp_modify!(&me_pres, vec![acp_deny.clone()], &r_set, false);
        // Test rejected rem
        test_acp_modify!(&me_rem, vec![acp_deny.clone()], &r_set, false);
        // Test rejected purge
        test_acp_modify!(&me_purge, vec![acp_deny.clone()], &r_set, false);
        // Test rejected set
        test_acp_modify!(&me_set, vec![acp_deny.clone()], &r_set, false);

        // test allowed pres class
        test_acp_modify!(&me_pres_class, vec![acp_allow.clone()], &r_set, true);
        // test allowed rem class
        test_acp_modify!(&me_rem_class, vec![acp_allow.clone()], &r_set, true);
        // test reject purge-class even if class present in allowed remattrs
        test_acp_modify!(&me_purge_class, vec![acp_allow.clone()], &r_set, false);
        // test allowed set class
        test_acp_modify!(&me_set_class, vec![acp_allow], &r_set, true);

        // Test reject pres class, but class not in classes
        test_acp_modify!(&me_pres_class, vec![acp_no_class.clone()], &r_set, false);
        // Test reject pres class, class in classes but not in pres attrs
        test_acp_modify!(&me_pres_class, vec![acp_deny.clone()], &r_set, false);
        // test reject rem class, but class not in classes
        test_acp_modify!(&me_rem_class, vec![acp_no_class.clone()], &r_set, false);
        // test reject rem class, class in classes but not in pres attrs
        test_acp_modify!(&me_rem_class, vec![acp_deny.clone()], &r_set, false);

        // Test reject set class, but class not in classes
        test_acp_modify!(&me_set_class, vec![acp_no_class], &r_set, false);
        // Test reject set class, class in classes but not in pres attrs
        test_acp_modify!(&me_set_class, vec![acp_deny], &r_set, false);
    }

    #[test]
    fn test_access_enforce_scope_modify() {
        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        // Name present
        let me_pres_ro = ModifyEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readonly(E_TEST_ACCOUNT_1.clone()),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::Name, &Value::new_iname("value"))]),
        );

        // Name present
        let me_pres_rw = ModifyEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::Name, &Value::new_iname("value"))]),
        );

        let acp_allow = AccessControlModify::from_raw(
            "test_modify_allow",
            Uuid::new_v4(),
            // apply to admin only
            UUID_TEST_GROUP_1,
            // To modify testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // Allow pres name and class
            "name class",
            // Allow rem name and class
            "name class",
            // And the class allowed is account
            EntryClass::Account.into(),
            EntryClass::Account.into(),
        );

        test_acp_modify!(&me_pres_ro, vec![acp_allow.clone()], &r_set, false);

        test_acp_modify!(&me_pres_rw, vec![acp_allow], &r_set, true);
    }

    macro_rules! test_acp_create {
        (
            $ce:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write(duration_from_epoch_now());
            acw.update_create($controls).expect("Failed to update");
            let acw = acw;

            let res = acw
                .create_allow_operation(&mut $ce, $entries)
                .expect("op failed");

            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert_eq!(res, $expect);
        }};
    }

    #[test]
    fn test_access_enforce_create() {
        sketching::test_init();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r1_set = vec![ev1];

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::TestNotAllowed, Value::new_iutf8n("notallowed")),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );

        let r2_set = vec![ev2];

        let ev3 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, Value::new_iutf8n("notallowed")),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r3_set = vec![ev3];

        let ev4 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r4_set = vec![ev4];

        // In this case, we can make the create event with an empty entry
        // set because we only reference the entries in r_set in the test.
        //
        // In the server code, the entry set is derived from and checked
        // against the create event, so we have some level of trust in it.

        let ce_admin = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            vec![],
        );

        let acp = AccessControlCreate::from_raw(
            "test_create",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To create matching filter testperson
            // Can this be empty?
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // classes
            EntryClass::Account.into(),
            // attrs
            "class name uuid",
        );

        let acp2 = AccessControlCreate::from_raw(
            "test_create_2",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To create matching filter testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // classes
            EntryClass::Group.into(),
            // attrs
            "class name uuid",
        );

        // Test allowed to create
        test_acp_create!(&ce_admin, vec![acp.clone()], &r1_set, true);
        // Test reject create (not allowed attr)
        test_acp_create!(&ce_admin, vec![acp.clone()], &r2_set, false);
        // Test reject create (not allowed class)
        test_acp_create!(&ce_admin, vec![acp.clone()], &r3_set, false);
        // Test reject create (hybrid u + g entry w_ u & g create allow)
        test_acp_create!(&ce_admin, vec![acp, acp2], &r4_set, false);
    }

    #[test]
    fn test_access_enforce_scope_create() {
        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r1_set = vec![ev1];

        let admin = E_TEST_ACCOUNT_1.clone();

        let ce_admin_ro = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readonly(admin.clone()),
            vec![],
        );

        let ce_admin_rw = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(admin),
            vec![],
        );

        let acp = AccessControlCreate::from_raw(
            "test_create",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To create matching filter testperson
            // Can this be empty?
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // classes
            EntryClass::Account.into(),
            // attrs
            "class name uuid",
        );

        test_acp_create!(&ce_admin_ro, vec![acp.clone()], &r1_set, false);

        test_acp_create!(&ce_admin_rw, vec![acp], &r1_set, true);
    }

    macro_rules! test_acp_delete {
        (
            $de:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write(duration_from_epoch_now());
            acw.update_delete($controls).expect("Failed to update");
            let acw = acw;

            let res = acw
                .delete_allow_operation($de, $entries)
                .expect("op failed");

            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert_eq!(res, $expect);
        }};
    }

    #[test]
    fn test_access_enforce_delete() {
        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        let de_admin = DeleteEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let de_anon = DeleteEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_2.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let acp = AccessControlDelete::from_raw(
            "test_delete",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To delete testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        // Test allowed to delete
        test_acp_delete!(&de_admin, vec![acp.clone()], &r_set, true);
        // Test reject delete
        test_acp_delete!(&de_anon, vec![acp], &r_set, false);
    }

    #[test]
    fn test_access_enforce_scope_delete() {
        sketching::test_init();

        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        let admin = E_TEST_ACCOUNT_1.clone();

        let de_admin_ro = DeleteEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readonly(admin.clone()),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let de_admin_rw = DeleteEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(admin),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let acp = AccessControlDelete::from_raw(
            "test_delete",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To delete testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        test_acp_delete!(&de_admin_ro, vec![acp.clone()], &r_set, false);

        test_acp_delete!(&de_admin_rw, vec![acp], &r_set, true);
    }

    macro_rules! test_acp_effective_permissions {
        (
            $ident:expr,
            $attrs:expr,
            $search_controls:expr,
            $modify_controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write(duration_from_epoch_now());
            acw.update_search($search_controls)
                .expect("Failed to update");
            acw.update_modify($modify_controls)
                .expect("Failed to update");
            let acw = acw;

            let res = acw
                .effective_permission_check($ident, $attrs, $entries)
                .expect("Failed to apply effective_permission_check");

            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert_eq!(res, $expect);
        }};
    }

    #[test]
    fn test_access_effective_permission_check_1() {
        sketching::test_init();

        let admin = Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone());

        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();

        let r_set = vec![Arc::new(ev1)];

        test_acp_effective_permissions!(
            &admin,
            None,
            vec![AccessControlSearch::from_raw(
                "test_acp",
                Uuid::new_v4(),
                // apply to admin only
                UUID_TEST_GROUP_1,
                // Allow admin to read only testperson1
                filter_valid!(f_eq(
                    Attribute::Name,
                    PartialValue::new_iname("testperson1")
                )),
                // They can read "name".
                Attribute::Name.as_ref(),
            )],
            vec![],
            &r_set,
            vec![AccessEffectivePermission {
                ident: UUID_TEST_ACCOUNT_1,
                delete: false,
                target: uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                search: Access::Allow(btreeset![Attribute::Name]),
                modify_pres: Access::Allow(BTreeSet::new()),
                modify_rem: Access::Allow(BTreeSet::new()),
                modify_pres_class: AccessClass::Allow(BTreeSet::new()),
                modify_rem_class: AccessClass::Allow(BTreeSet::new()),
            }]
        )
    }

    #[test]
    fn test_access_effective_permission_check_2() {
        sketching::test_init();

        let admin = Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone());

        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();

        let r_set = vec![Arc::new(ev1)];

        test_acp_effective_permissions!(
            &admin,
            None,
            vec![],
            vec![AccessControlModify::from_raw(
                "test_acp",
                Uuid::new_v4(),
                // apply to admin only
                UUID_TEST_GROUP_1,
                // Allow admin to read only testperson1
                filter_valid!(f_eq(
                    Attribute::Name,
                    PartialValue::new_iname("testperson1")
                )),
                // They can read "name".
                Attribute::Name.as_ref(),
                Attribute::Name.as_ref(),
                EntryClass::Object.into(),
                EntryClass::Object.into(),
            )],
            &r_set,
            vec![AccessEffectivePermission {
                ident: UUID_TEST_ACCOUNT_1,
                delete: false,
                target: uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                search: Access::Allow(BTreeSet::new()),
                modify_pres: Access::Allow(btreeset![Attribute::Name]),
                modify_rem: Access::Allow(btreeset![Attribute::Name]),
                modify_pres_class: AccessClass::Allow(btreeset![EntryClass::Object.into()]),
                modify_rem_class: AccessClass::Allow(btreeset![EntryClass::Object.into()]),
            }]
        )
    }

    #[test]
    fn test_access_sync_authority_create() {
        sketching::test_init();

        let ce_admin = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            vec![],
        );

        // We can create without a sync class.
        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r1_set = vec![ev1];

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::SyncObject.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r2_set = vec![ev2];

        let acp = AccessControlCreate::from_raw(
            "test_create",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To create matching filter testperson
            // Can this be empty?
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // classes
            "account sync_object",
            // attrs
            "class name uuid",
        );

        // Test allowed to create
        test_acp_create!(&ce_admin, vec![acp.clone()], &r1_set, true);
        // Test Fails due to protected from sync object
        test_acp_create!(&ce_admin, vec![acp], &r2_set, false);
    }

    #[test]
    fn test_access_sync_authority_delete() {
        sketching::test_init();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();
        let r1_set = vec![Arc::new(ev1)];

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::SyncObject.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();
        let r2_set = vec![Arc::new(ev2)];

        let de_admin = DeleteEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let acp = AccessControlDelete::from_raw(
            "test_delete",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To delete testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        // Test allowed to delete
        test_acp_delete!(&de_admin, vec![acp.clone()], &r1_set, true);
        // Test reject delete
        test_acp_delete!(&de_admin, vec![acp], &r2_set, false);
    }

    #[test]
    fn test_access_sync_authority_modify() {
        sketching::test_init();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();
        let r1_set = vec![Arc::new(ev1)];

        let sync_uuid = Uuid::new_v4();
        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::SyncObject.to_value()),
            (Attribute::SyncParentUuid, Value::Refer(sync_uuid)),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();
        let r2_set = vec![Arc::new(ev2)];

        // Allow name and class, class is account
        let acp_allow = AccessControlModify::from_raw(
            "test_modify_allow",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To modify testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // Allow pres user_auth_token_session
            &format!("{} {}", Attribute::UserAuthTokenSession, Attribute::Name),
            // Allow user_auth_token_session
            &format!("{} {}", Attribute::UserAuthTokenSession, Attribute::Name),
            // And the class allowed is account, we don't use it though.
            EntryClass::Account.into(),
            EntryClass::Account.into(),
        );

        // NOTE! Syntax doesn't matter here, we just need to assert if the attr exists
        // and is being modified.
        // Name present
        let me_pres = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(
                Attribute::UserAuthTokenSession,
                &Value::new_iname("value")
            )]),
        );
        // Name rem
        let me_rem = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_remove(
                Attribute::UserAuthTokenSession,
                &PartialValue::new_iname("value")
            )]),
        );
        // Name purge
        let me_purge = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_purge(Attribute::UserAuthTokenSession)]),
        );

        // Test allowed pres
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r1_set, true);
        // test allowed rem
        test_acp_modify!(&me_rem, vec![acp_allow.clone()], &r1_set, true);
        // test allowed purge
        test_acp_modify!(&me_purge, vec![acp_allow.clone()], &r1_set, true);

        // Test allow pres
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r2_set, true);
        // Test allow rem
        test_acp_modify!(&me_rem, vec![acp_allow.clone()], &r2_set, true);
        // Test allow purge
        test_acp_modify!(&me_purge, vec![acp_allow.clone()], &r2_set, true);

        // But other attrs are blocked.
        let me_pres = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::Name, &Value::new_iname("value"))]),
        );
        // Name rem
        let me_rem = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_remove(Attribute::Name, &PartialValue::new_iname("value"))]),
        );
        // Name purge
        let me_purge = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_purge(Attribute::Name)]),
        );

        // Test reject pres
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r2_set, false);
        // Test reject rem
        test_acp_modify!(&me_rem, vec![acp_allow.clone()], &r2_set, false);
        // Test reject purge
        test_acp_modify!(&me_purge, vec![acp_allow.clone()], &r2_set, false);

        // Test that when an attribute is in the sync_yield state that it can be
        // modified by a user.

        // Test allow pres
        test_acp_modify!(
            &me_pres,
            vec![acp_allow.clone()],
            sync_uuid,
            Attribute::Name,
            &r2_set,
            true
        );
        // Test allow rem
        test_acp_modify!(
            &me_rem,
            vec![acp_allow.clone()],
            sync_uuid,
            Attribute::Name,
            &r2_set,
            true
        );
        // Test allow purge
        test_acp_modify!(
            &me_purge,
            vec![acp_allow],
            sync_uuid,
            Attribute::Name,
            &r2_set,
            true
        );
    }

    #[test]
    fn test_access_oauth2_dyn_search() {
        sketching::test_init();
        // Test that an account that is granted a scope to an oauth2 rs is granted
        // the ability to search that rs.
        let rs_uuid = Uuid::new_v4();
        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(rs_uuid)),
            (Attribute::Name, Value::new_iname("test_resource_server")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            (
                Attribute::OAuth2RsOrigin,
                Value::new_url_s("app://hidden").unwrap()
            ),
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(UUID_TEST_GROUP_1, btreeset!["groups".to_string()])
                    .expect("invalid oauthscope")
            ),
            (
                Attribute::OAuth2RsSupScopeMap,
                Value::new_oauthscopemap(UUID_TEST_GROUP_1, btreeset!["supplement".to_string()])
                    .expect("invalid oauthscope")
            ),
            (
                Attribute::OAuth2AllowInsecureClientDisablePkce,
                Value::new_bool(true)
            ),
            (
                Attribute::OAuth2JwtLegacyCryptoEnable,
                Value::new_bool(false)
            ),
            (Attribute::OAuth2PreferShortUsername, Value::new_bool(false))
        )
        .into_sealed_committed();

        let ev1_reduced = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(rs_uuid)),
            (Attribute::Name, Value::new_iname("test_resource_server")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://demo.example.com").unwrap()
            )
        )
        .into_sealed_committed();

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4())),
            (Attribute::Name, Value::new_iname("second_resource_server")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("second_resource_server")
            ),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://noaccess.example.com").unwrap()
            ),
            (
                Attribute::OAuth2RsOrigin,
                Value::new_url_s("app://hidden").unwrap()
            ),
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(UUID_SYSTEM_ADMINS, btreeset!["groups".to_string()])
                    .expect("invalid oauthscope")
            ),
            (
                Attribute::OAuth2RsSupScopeMap,
                Value::new_oauthscopemap(
                    // This is NOT the scope map that is access checked!
                    UUID_TEST_GROUP_1,
                    btreeset!["supplement".to_string()]
                )
                .expect("invalid oauthscope")
            ),
            (
                Attribute::OAuth2AllowInsecureClientDisablePkce,
                Value::new_bool(true)
            ),
            (
                Attribute::OAuth2JwtLegacyCryptoEnable,
                Value::new_bool(false)
            ),
            (Attribute::OAuth2PreferShortUsername, Value::new_bool(false))
        )
        .into_sealed_committed();

        let r_set = vec![Arc::new(ev1.clone()), Arc::new(ev2)];

        // Check the authorisation search event, and that it reduces correctly.
        let se_a = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_pres(Attribute::Name)),
        );
        let ex_a = vec![Arc::new(ev1)];
        let ex_a_reduced = vec![ev1_reduced];

        test_acp_search!(&se_a, vec![], r_set.clone(), ex_a);
        test_acp_search_reduce(&se_a, vec![], r_set.clone(), ex_a_reduced);

        // Check that anonymous is denied even though it's a member of the group.
        let anon: EntryInitNew = BUILTIN_ACCOUNT_ANONYMOUS.clone().into();
        let mut anon = anon.into_invalid_new();
        anon.set_ava_set(&Attribute::MemberOf, ValueSetReferN::new(UUID_TEST_GROUP_1));

        let anon = Arc::new(anon.into_sealed_committed());

        let se_anon =
            SearchEvent::new_impersonate_entry(anon, filter_all!(f_pres(Attribute::Name)));
        let ex_anon = vec![];
        test_acp_search!(&se_anon, vec![], r_set.clone(), ex_anon);

        // Check the deny case.
        let se_b = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_2.clone(),
            filter_all!(f_pres(Attribute::Name)),
        );
        let ex_b = vec![];

        test_acp_search!(&se_b, vec![], r_set, ex_b);
    }

    #[test]
    fn test_access_sync_account_dyn_search() {
        sketching::test_init();
        // Test that an account that has been synchronised from external
        // sources is able to read the sync providers credential portal
        // url.

        let sync_uuid = Uuid::new_v4();
        let portal_url = Url::parse("https://localhost/portal").unwrap();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::SyncAccount.to_value()),
            (Attribute::Uuid, Value::Uuid(sync_uuid)),
            (Attribute::Name, Value::new_iname("test_sync_account")),
            (
                Attribute::SyncCredentialPortal,
                Value::Url(portal_url.clone())
            )
        )
        .into_sealed_committed();

        let ev1_reduced = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::SyncAccount.to_value()),
            (Attribute::Uuid, Value::Uuid(sync_uuid)),
            (
                Attribute::SyncCredentialPortal,
                Value::Url(portal_url.clone())
            )
        )
        .into_sealed_committed();

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::SyncAccount.to_value()),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4())),
            (Attribute::Name, Value::new_iname("test_sync_account")),
            (
                Attribute::SyncCredentialPortal,
                Value::Url(portal_url.clone())
            )
        )
        .into_sealed_committed();

        let sync_test_account: Arc<EntrySealedCommitted> = Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::SyncObject.to_value()),
                (Attribute::Name, Value::new_iname("test_account_1")),
                (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1)),
                (Attribute::MemberOf, Value::ReferN(UUID_TEST_GROUP_1)),
                (Attribute::SyncParentUuid, Value::Refer(sync_uuid))
            )
            .into_sealed_committed(),
        );

        // Check the authorised search event, and that it reduces correctly.
        let r_set = vec![Arc::new(ev1.clone()), Arc::new(ev2)];

        let se_a = SearchEvent::new_impersonate_entry(
            sync_test_account,
            filter_all!(f_pres(Attribute::SyncCredentialPortal)),
        );
        let ex_a = vec![Arc::new(ev1)];
        let ex_a_reduced = vec![ev1_reduced];

        test_acp_search!(&se_a, vec![], r_set.clone(), ex_a);
        test_acp_search_reduce(&se_a, vec![], r_set.clone(), ex_a_reduced);

        // Test a non-synced account aka the deny case
        let se_b = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_2.clone(),
            filter_all!(f_pres(Attribute::SyncCredentialPortal)),
        );
        let ex_b = vec![];

        test_acp_search!(&se_b, vec![], r_set, ex_b);
    }

    #[test]
    fn test_access_entry_managed_by_search() {
        sketching::test_init();

        let test_entry = Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1)),
                (Attribute::EntryManagedBy, Value::Refer(UUID_TEST_GROUP_1))
            )
            .into_sealed_committed(),
        );

        let data_set = vec![test_entry.clone()];

        let se_a = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_pres(Attribute::Name)),
        );
        let expect_a = vec![test_entry];

        let se_b = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_2.clone(),
            filter_all!(f_pres(Attribute::Name)),
        );
        let expect_b = vec![];

        let acp = AccessControlSearch::from_managed_by(
            "test_acp",
            Uuid::new_v4(),
            // Allow admin to read only testperson1
            AccessControlTarget::Scope(filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            ))),
            // In that read, admin may only view the "name" attribute, or query on
            // the name attribute. Any other query (should be) rejected.
            Attribute::Name.as_ref(),
        );

        // Check where allowed
        test_acp_search!(&se_a, vec![acp.clone()], data_set.clone(), expect_a);

        // And where not
        test_acp_search!(&se_b, vec![acp], data_set, expect_b);
    }

    #[test]
    fn test_access_entry_managed_by_create() {
        sketching::test_init();

        let test_entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1)),
            (Attribute::EntryManagedBy, Value::Refer(UUID_TEST_GROUP_1))
        );

        let data_set = vec![test_entry];

        let ce = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            vec![],
        );

        let acp = AccessControlCreate::from_managed_by(
            "test_create",
            Uuid::new_v4(),
            AccessControlTarget::Scope(filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            ))),
            // classes
            EntryClass::Account.into(),
            // attrs
            "class name uuid",
        );

        // Test reject create (not allowed attr). This is because entry
        // managed by is non-sensical with creates!
        test_acp_create!(&ce, vec![acp.clone()], &data_set, false);
    }

    #[test]
    fn test_access_entry_managed_by_modify() {
        let test_entry = Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1)),
                (Attribute::EntryManagedBy, Value::Refer(UUID_TEST_GROUP_1))
            )
            .into_sealed_committed(),
        );

        let data_set = vec![test_entry];

        // Name present
        let me_pres = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::Name, &Value::new_iname("value"))]),
        );
        // Name rem
        let me_rem = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_remove(Attribute::Name, &PartialValue::new_iname("value"))]),
        );
        // Name purge
        let me_purge = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_purge(Attribute::Name)]),
        );

        let acp_allow = AccessControlModify::from_managed_by(
            "test_modify_allow",
            Uuid::new_v4(),
            // To modify testperson
            AccessControlTarget::Scope(filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            ))),
            // Allow pres name and class
            "name class",
            // Allow rem name and class
            "name class",
            // And the class allowed is account
            EntryClass::Account.into(),
            EntryClass::Account.into(),
        );

        // Test allowed pres
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &data_set, true);
        // test allowed rem
        test_acp_modify!(&me_rem, vec![acp_allow.clone()], &data_set, true);
        // test allowed purge
        test_acp_modify!(&me_purge, vec![acp_allow.clone()], &data_set, true);
    }

    #[test]
    fn test_access_entry_managed_by_delete() {
        let test_entry = Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1)),
                (Attribute::EntryManagedBy, Value::Refer(UUID_TEST_GROUP_1))
            )
            .into_sealed_committed(),
        );

        let data_set = vec![test_entry];

        let de_a = DeleteEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let de_b = DeleteEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_2.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let acp = AccessControlDelete::from_managed_by(
            "test_delete",
            Uuid::new_v4(),
            // To delete testperson
            AccessControlTarget::Scope(filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            ))),
        );

        // Test allowed to delete
        test_acp_delete!(&de_a, vec![acp.clone()], &data_set, true);
        // Test reject delete
        test_acp_delete!(&de_b, vec![acp], &data_set, false);
    }

    #[test]
    fn test_access_delete_protect_system_ranges() {
        let ev1: EntryInitNew = BUILTIN_ACCOUNT_ANONYMOUS.clone().into();
        let ev1 = ev1.into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        let de_account = DeleteEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let acp = AccessControlDelete::from_raw(
            "test_delete",
            Uuid::new_v4(),
            UUID_TEST_GROUP_1,
            // To delete testperson
            filter_valid!(f_eq(Attribute::Name, PartialValue::new_iname("anonymous"))),
        );

        // Test reject delete, can not delete due to system protection
        test_acp_delete!(&de_account, vec![acp], &r_set, false);
    }

    #[test]
    fn test_access_sync_memberof_implies_directmemberof() {
        sketching::test_init();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Name, Value::new_iname("test_account_1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1)),
            (Attribute::MemberOf, Value::ReferN(UUID_TEST_GROUP_1)),
            (Attribute::DirectMemberOf, Value::ReferN(UUID_TEST_GROUP_1))
        )
        .into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        let exv1 = entry_init!(
            (Attribute::Name, Value::new_iname("test_account_1")),
            (Attribute::MemberOf, Value::ReferN(UUID_TEST_GROUP_1)),
            (Attribute::DirectMemberOf, Value::ReferN(UUID_TEST_GROUP_1))
        )
        .into_sealed_committed();

        let ex_anon_some = vec![exv1];

        let se_anon_ro = SearchEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readonly(E_TEST_ACCOUNT_1.clone()),
            filter_all!(f_pres(Attribute::Name)),
        );

        let acp = AccessControlSearch::from_raw(
            "test_acp",
            Uuid::new_v4(),
            // apply to all accounts.
            UUID_TEST_GROUP_1,
            // Allow anonymous to read only testperson1
            filter_valid!(f_eq(
                Attribute::Uuid,
                PartialValue::Uuid(UUID_TEST_ACCOUNT_1)
            )),
            // May query on name, and see memberof. MemberOf implies direct
            // memberof.
            format!("{} {}", Attribute::Name, Attribute::MemberOf).as_str(),
        );

        // Finally test it!
        test_acp_search_reduce(&se_anon_ro, vec![acp], r_set, ex_anon_some);
    }

    #[test]
    fn test_access_protected_deny_create() {
        sketching::test_init();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r1_set = vec![ev1];

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::System.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );

        let r2_set = vec![ev2];

        let ce_admin = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            vec![],
        );

        let acp = AccessControlCreate::from_raw(
            "test_create",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To create matching filter testperson
            // Can this be empty?
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // classes
            EntryClass::Account.into(),
            // attrs
            "class name uuid",
        );

        // Test allowed to create
        test_acp_create!(&ce_admin, vec![acp.clone()], &r1_set, true);
        // Test reject create (not allowed attr)
        test_acp_create!(&ce_admin, vec![acp.clone()], &r2_set, false);
    }

    #[test]
    fn test_access_protected_deny_delete() {
        sketching::test_init();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();
        let r1_set = vec![Arc::new(ev1)];

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::System.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();

        let r2_set = vec![Arc::new(ev2)];

        let de = DeleteEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let acp = AccessControlDelete::from_raw(
            "test_delete",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To delete testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        // Test allowed to delete
        test_acp_delete!(&de, vec![acp.clone()], &r1_set, true);
        // Test not allowed to delete
        test_acp_delete!(&de, vec![acp.clone()], &r2_set, false);
    }

    #[test]
    fn test_access_protected_deny_modify() {
        sketching::test_init();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();
        let r1_set = vec![Arc::new(ev1)];

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::System.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();

        let r2_set = vec![Arc::new(ev2)];

        // Allow name and class, class is account
        let acp_allow = AccessControlModify::from_raw(
            "test_modify_allow",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To modify testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // Allow pres disp name and class
            "displayname class",
            // Allow rem disp name and class
            "displayname class",
            // And the classes allowed to add/rem are as such
            "system recycled",
            "system recycled",
        );

        let me_pres = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::DisplayName, &Value::new_utf8s("value"))]),
        );

        // Test allowed pres
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r1_set, true);

        // Test not allowed pres (due to system class)
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r2_set, false);

        // Test that we can not remove class::system
        let me_rem_sys = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Class,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_remove(
                Attribute::Class,
                &EntryClass::System.to_partialvalue()
            )]),
        );

        test_acp_modify!(&me_rem_sys, vec![acp_allow.clone()], &r2_set, false);

        // Ensure that we can't add recycled.
        let me_pres = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::Class, &EntryClass::Recycled.to_value())]),
        );

        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r1_set, false);
    }

    #[allow(clippy::disallowed_methods)]
    #[test]
    fn test_access_time_restriction_valid() {
        sketching::test_init();

        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1.clone())];
        let ex_set = vec![Arc::new(ev1)];

        let se_admin = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let now = time::OffsetDateTime::now_utc();
        let start = now - time::Duration::hours(1);
        let end = now + time::Duration::hours(1);

        let acp = AccessControlSearch::from_raw_with_time(
            "test_acp_time_valid",
            Uuid::new_v4(),
            UUID_TEST_GROUP_1,
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            Attribute::Name.as_ref(),
            Some(start),
            Some(end),
        );

        test_acp_search!(&se_admin, vec![acp], r_set, ex_set);
    }

    #[allow(clippy::disallowed_methods)]
    #[test]
    fn test_access_time_restriction_expired() {
        sketching::test_init();

        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];
        let ex_set = vec![];

        let se_admin = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let now = time::OffsetDateTime::now_utc();
        let start = now - time::Duration::hours(2);
        let end = now - time::Duration::hours(1);

        let acp = AccessControlSearch::from_raw_with_time(
            "test_acp_time_expired",
            Uuid::new_v4(),
            UUID_TEST_GROUP_1,
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            Attribute::Name.as_ref(),
            Some(start),
            Some(end),
        );

        test_acp_search!(&se_admin, vec![acp], r_set, ex_set);
    }

    #[allow(clippy::disallowed_methods)]
    #[test]
    fn test_access_time_restriction_future() {
        sketching::test_init();

        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];
        let ex_set = vec![];

        let se_admin = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let now = time::OffsetDateTime::now_utc();
        let start = now + time::Duration::hours(1);
        let end = now + time::Duration::hours(2);

        let acp = AccessControlSearch::from_raw_with_time(
            "test_acp_time_future",
            Uuid::new_v4(),
            UUID_TEST_GROUP_1,
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            Attribute::Name.as_ref(),
            Some(start),
            Some(end),
        );

        test_acp_search!(&se_admin, vec![acp], r_set, ex_set);
    }

    #[allow(clippy::disallowed_methods)]
    #[test]
    fn test_access_time_restriction_start_only() {
        sketching::test_init();

        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1.clone())];
        let ex_set = vec![Arc::new(ev1)];

        let se_admin = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let now = time::OffsetDateTime::now_utc();
        let start = now - time::Duration::hours(1);

        let acp = AccessControlSearch::from_raw_with_time(
            "test_acp_time_start_only",
            Uuid::new_v4(),
            UUID_TEST_GROUP_1,
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            Attribute::Name.as_ref(),
            Some(start),
            None,
        );

        test_acp_search!(&se_admin, vec![acp], r_set, ex_set);
    }

    #[allow(clippy::disallowed_methods)]
    #[test]
    fn test_access_time_restriction_end_only() {
        sketching::test_init();

        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1.clone())];
        let ex_set = vec![Arc::new(ev1)];

        let se_admin = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let now = time::OffsetDateTime::now_utc();
        let end = now + time::Duration::hours(1);

        let acp = AccessControlSearch::from_raw_with_time(
            "test_acp_time_end_only",
            Uuid::new_v4(),
            UUID_TEST_GROUP_1,
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            Attribute::Name.as_ref(),
            None,
            Some(end),
        );

        test_acp_search!(&se_admin, vec![acp], r_set, ex_set);
    }

    // =========================================================================
    // Step-up (require reauth) Tests
    // =========================================================================

    /// Kubidm: a profile that requires a privileged session contributes nothing to a
    /// read-only session, while the other profiles that apply are unaffected.
    #[test]
    fn test_access_search_require_reauth_readonly_session() {
        sketching::test_init();

        let mut target = E_TESTPERSON_1.clone();
        target.add_ava(Attribute::LegalName, Value::new_utf8s("Test Person"));
        let r_set = vec![Arc::new(target.into_sealed_committed())];

        let filter = filter_all!(f_eq(
            Attribute::Name,
            PartialValue::new_iname("testperson1")
        ));
        let scope = filter_valid!(f_eq(
            Attribute::Name,
            PartialValue::new_iname("testperson1")
        ));

        let acps = vec![
            AccessControlSearch::from_raw(
                "test_acp_name",
                Uuid::new_v4(),
                UUID_TEST_GROUP_1,
                scope.clone(),
                Attribute::Name.as_ref(),
            ),
            AccessControlSearch::from_raw_require_reauth(
                "test_acp_legalname",
                Uuid::new_v4(),
                UUID_TEST_GROUP_1,
                scope,
                Attribute::LegalName.as_ref(),
            ),
        ];

        // A read-only session only gets the attributes of the normal profile.
        let se_ro = SearchEvent::new_impersonate_entry(E_TEST_ACCOUNT_1.clone(), filter.clone());
        let ex_ro = vec![E_TESTPERSON_1_REDUCED.clone().into_sealed_committed()];
        test_acp_search_reduce(&se_ro, acps.clone(), r_set.clone(), ex_ro);

        // A read-write session gets both.
        let se_rw = SearchEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            filter,
        );
        let ex_rw = vec![entry_init_fn([
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::LegalName, Value::new_utf8s("Test Person")),
        ])
        .into_sealed_committed()];
        test_acp_search_reduce(&se_rw, acps, r_set, ex_rw);
    }

    // =========================================================================
    // Delegated Administration Tests
    // =========================================================================

    /// Kubidm: build an access control profile entry with every operation class.
    fn delegated_acp_entry(
        name: &str,
        receiver_class: EntryClass,
        target_class: EntryClass,
        extra: Vec<(Attribute, Value)>,
    ) -> EntryInitNew {
        let mut entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlProfile.to_value()
            ),
            (Attribute::Class, receiver_class.to_value()),
            (Attribute::Class, target_class.to_value()),
            (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
            (Attribute::Class, EntryClass::AccessControlModify.to_value()),
            (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
            (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
            (Attribute::Name, Value::new_iname(name)),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4()))
        );
        for attr in [
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Class,
            Attribute::DisplayName,
            Attribute::LegalName,
        ] {
            entry.add_ava(Attribute::AcpSearchAttr, Value::new_iutf8n(attr.as_str()));
        }
        for attr in [
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Class,
            Attribute::DisplayName,
        ] {
            entry.add_ava(Attribute::AcpCreateAttr, Value::new_iutf8n(attr.as_str()));
        }
        for class in [EntryClass::Object, EntryClass::Account, EntryClass::Person] {
            entry.add_ava(Attribute::AcpCreateClass, Value::new_iutf8n(class.as_ref()));
        }
        entry.add_ava(
            Attribute::AcpModifyPresentAttr,
            Value::new_iutf8n(Attribute::DisplayName.as_str()),
        );
        entry.add_ava(
            Attribute::AcpModifyRemovedAttr,
            Value::new_iutf8n(Attribute::DisplayName.as_str()),
        );
        // A delegated profile grants what its template grants (here user_admin: no
        // create), see `access::profiles`.
        if matches!(target_class, EntryClass::AccessControlTargetDelegatedScope) {
            entry.add_ava(
                Attribute::DelegatedRoleTemplate,
                Value::Refer(UUID_IDM_DELEGATED_USER_ADMIN),
            );
        }
        for (attr, value) in extra {
            entry.add_ava(attr, value);
        }
        entry
    }

    /// Kubidm: a person entry for the delegated administration tests.
    fn dg_person(name: &str, uuid: Uuid) -> EntryInitNew {
        entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname(name)),
            (Attribute::DisplayName, Value::new_utf8s(name)),
            (Attribute::Uuid, Value::Uuid(uuid))
        )
    }

    /// Kubidm: a group entry for the delegated administration tests.
    fn dg_group(name: &str, uuid: Uuid, members: &[Uuid]) -> EntryInitNew {
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

    /// Kubidm: a read-write identity for the entry `uuid`.
    fn dg_ident(qs_write: &mut QueryServerWriteTransaction<'_>, uuid: Uuid) -> Identity {
        let entry = qs_write.internal_search_uuid(uuid).expect("entry");
        Identity::from_impersonate_entry_readwrite(entry)
    }

    /// Kubidm: can `ident` replace the displayname of `target`?
    fn dg_can_modify(
        qs_write: &mut QueryServerWriteTransaction<'_>,
        ident: &Identity,
        target: Uuid,
    ) -> bool {
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(target)));
        let modlist = ModifyList::new_list(vec![
            Modify::Purged(Attribute::DisplayName),
            Modify::Present(Attribute::DisplayName, Value::new_utf8s("delegated")),
        ]);
        qs_write
            .impersonate_modify(&filter, &filter, &modlist, ident)
            .is_ok()
    }

    /// Kubidm: can `ident` delete `target`?
    fn dg_can_delete(
        qs_write: &mut QueryServerWriteTransaction<'_>,
        ident: &Identity,
        target: Uuid,
    ) -> bool {
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(target)));
        let de = DeleteEvent::new_impersonate_identity(ident.clone(), filter);
        qs_write.delete(&de).is_ok()
    }

    /// Kubidm: the names of the loaded modify profiles.
    fn dg_loaded_modify(qs_write: &QueryServerWriteTransaction<'_>) -> BTreeSet<String> {
        qs_write
            .get_accesscontrols()
            .get_modify()
            .iter()
            .map(|acm| acm.acp.name.clone())
            .collect()
    }

    /// Kubidm: the scope filter used by most delegated tests.
    fn dg_person_filter() -> Value {
        Value::new_json_filter_s("{\"eq\":[\"class\",\"person\"]}").expect("filter")
    }

    /// Kubidm: delegated targets are rewritten into upstream scope targets at parse time,
    /// and every profile that can not be expressed safely is rejected.
    #[qs_test]
    async fn test_access_delegated_acp_parser(qs: &QueryServer) {
        let mut qs_write = qs.write(duration_from_epoch_now()).await.unwrap();
        let receivers = Uuid::new_v4();
        let group = Uuid::new_v4();
        let filter = || Value::new_json_filter_s("{\"pres\":\"name\"}").expect("filter");
        let receiver_group = || (Attribute::AcpReceiverGroup, Value::ReferN(receivers));
        let scope_group = || (Attribute::DelegatedScopeGroup, Value::Refer(group));

        // Receiving through the delegated scope is unsupported in every form, so the
        // scope group is never both the administrators and the administered.
        for extra in [
            vec![scope_group()],
            vec![scope_group(), (Attribute::DelegatedScopeFilter, filter())],
            vec![(Attribute::DelegatedScopeFilter, filter())],
            vec![
                scope_group(),
                (
                    Attribute::AcpReceiverDelegated,
                    Value::Refer(Uuid::new_v4()),
                ),
            ],
        ] {
            acp_from_entry_err!(
                &mut qs_write,
                delegated_acp_entry(
                    "acp_delegated_receiver",
                    EntryClass::AccessControlReceiverDelegated,
                    EntryClass::AccessControlTargetDelegatedScope,
                    extra
                ),
                AccessControlProfile
            );
        }

        // A delegated receiver class next to a group receiver is rejected, not ignored.
        let mut entry = delegated_acp_entry(
            "acp_delegated_receiver_and_group",
            EntryClass::AccessControlReceiverGroup,
            EntryClass::AccessControlTargetDelegatedScope,
            vec![receiver_group(), scope_group()],
        );
        entry.add_ava(
            Attribute::Class,
            EntryClass::AccessControlReceiverDelegated.to_value(),
        );
        acp_from_entry_err!(&mut qs_write, entry, AccessControlProfile);

        // Conflicting receiver kinds.
        let mut entry = delegated_acp_entry(
            "acp_group_and_entry_manager",
            EntryClass::AccessControlReceiverGroup,
            EntryClass::AccessControlTargetScope,
            vec![receiver_group(), (Attribute::AcpTargetScope, filter())],
        );
        entry.add_ava(
            Attribute::Class,
            EntryClass::AccessControlReceiverEntryManager.to_value(),
        );
        acp_from_entry_err!(&mut qs_write, entry, AccessControlProfile);

        // Conflicting target kinds.
        let mut entry = delegated_acp_entry(
            "acp_scope_and_delegated_scope",
            EntryClass::AccessControlReceiverGroup,
            EntryClass::AccessControlTargetDelegatedScope,
            vec![
                receiver_group(),
                scope_group(),
                (Attribute::AcpTargetScope, filter()),
            ],
        );
        entry.add_ava(
            Attribute::Class,
            EntryClass::AccessControlTargetScope.to_value(),
        );
        acp_from_entry_err!(&mut qs_write, entry, AccessControlProfile);

        // A delegated target requires the scope group: a filter alone (for example after
        // the scope group was deleted) or nothing at all is rejected.
        for extra in [
            vec![
                receiver_group(),
                (Attribute::DelegatedScopeFilter, filter()),
            ],
            vec![receiver_group()],
        ] {
            acp_from_entry_err!(
                &mut qs_write,
                delegated_acp_entry(
                    "acp_delegated_no_group",
                    EntryClass::AccessControlReceiverGroup,
                    EntryClass::AccessControlTargetDelegatedScope,
                    extra
                ),
                AccessControlProfile
            );
        }

        // A scope filter that is not valid for the schema is rejected.
        acp_from_entry_err!(
            &mut qs_write,
            delegated_acp_entry(
                "acp_delegated_bad_filter",
                EntryClass::AccessControlReceiverGroup,
                EntryClass::AccessControlTargetDelegatedScope,
                vec![
                    receiver_group(),
                    scope_group(),
                    (
                        Attribute::DelegatedScopeFilter,
                        Value::new_json_filter_s("{\"eq\":[\"not_an_attribute\",\"x\"]}")
                            .expect("filter")
                    ),
                ]
            ),
            AccessControlProfile
        );

        // A maximum reauth age is unsupported.
        acp_from_entry_err!(
            &mut qs_write,
            delegated_acp_entry(
                "acp_reauth_max_age",
                EntryClass::AccessControlReceiverGroup,
                EntryClass::AccessControlTargetScope,
                vec![
                    receiver_group(),
                    (Attribute::AcpTargetScope, filter()),
                    (Attribute::AcpReauthMaxAge, Value::Uint32(300)),
                ]
            ),
            AccessControlProfile
        );

        // memberof is server maintained and may never be granted on create.
        for attr in [Attribute::MemberOf, Attribute::DirectMemberOf] {
            acp_from_entry_err!(
                &mut qs_write,
                delegated_acp_entry(
                    "acp_create_memberof",
                    EntryClass::AccessControlReceiverGroup,
                    EntryClass::AccessControlTargetScope,
                    vec![
                        receiver_group(),
                        (Attribute::AcpTargetScope, filter()),
                        (Attribute::AcpCreateAttr, Value::new_iutf8n(attr.as_str())),
                    ]
                ),
                AccessControlCreate
            );
        }
        acp_from_entry_ok!(
            &mut qs_write,
            delegated_acp_entry(
                "acp_create_valid",
                EntryClass::AccessControlReceiverGroup,
                EntryClass::AccessControlTargetScope,
                vec![receiver_group(), (Attribute::AcpTargetScope, filter())]
            ),
            AccessControlCreate
        );

        // A group receiver with a delegated target, with or without the scope filter,
        // becomes a group receiver and a scope target.
        for extra in [
            vec![
                receiver_group(),
                scope_group(),
                (Attribute::DelegatedScopeFilter, filter()),
            ],
            vec![receiver_group(), scope_group()],
        ] {
            let acp = acp_from_entry_ok!(
                &mut qs_write,
                delegated_acp_entry(
                    "acp_delegated_valid",
                    EntryClass::AccessControlReceiverGroup,
                    EntryClass::AccessControlTargetDelegatedScope,
                    extra
                ),
                AccessControlProfile
            );
            assert!(matches!(
                &acp.receiver,
                AccessControlReceiver::Group(groups) if groups == &btreeset![receivers]
            ));
            assert!(matches!(acp.target, AccessControlTarget::Scope(_)));
        }

        // An entry manager receiver with a delegated target parses: the delegated scope
        // only narrows the entries the manager already manages.
        let acp = acp_from_entry_ok!(
            &mut qs_write,
            delegated_acp_entry(
                "acp_delegated_entry_manager",
                EntryClass::AccessControlReceiverEntryManager,
                EntryClass::AccessControlTargetDelegatedScope,
                vec![scope_group()]
            ),
            AccessControlProfile
        );
        assert!(matches!(&acp.receiver, AccessControlReceiver::EntryManager));
        assert!(matches!(acp.target, AccessControlTarget::Scope(_)));
    }

    /// Kubidm: a delegated profile is enforced as its upstream rewrite. The receivers
    /// administer exactly the members of the scope group that match the scope filter
    /// and are not high privilege, and the effective permission check agrees with the
    /// real operations.
    #[qs_test]
    async fn test_access_delegated_acp_enforced(qs: &QueryServer) {
        let ct = duration_from_epoch_now();

        let admin_uuid = Uuid::new_v4();
        let target_uuid = Uuid::new_v4();
        let outsider_uuid = Uuid::new_v4();
        let svc_uuid = Uuid::new_v4();
        let hp_uuid = Uuid::new_v4();
        let peer_uuid = Uuid::new_v4();
        let receivers_uuid = Uuid::new_v4();
        let scope_uuid = Uuid::new_v4();

        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_create(vec![
                dg_person("dg_admin", admin_uuid),
                dg_person("dg_target", target_uuid),
                dg_person("dg_peer", peer_uuid),
                dg_person("dg_outsider", outsider_uuid),
                dg_person("dg_hp", hp_uuid),
                entry_init!(
                    (Attribute::Class, EntryClass::Object.to_value()),
                    (Attribute::Class, EntryClass::Account.to_value()),
                    (Attribute::Class, EntryClass::ServiceAccount.to_value()),
                    (Attribute::Name, Value::new_iname("dg_svc")),
                    (Attribute::DisplayName, Value::new_utf8s("dg_svc")),
                    (Attribute::Uuid, Value::Uuid(svc_uuid))
                ),
                dg_group("dg_receivers", receivers_uuid, &[admin_uuid]),
                dg_group(
                    "dg_scope",
                    scope_uuid,
                    &[target_uuid, peer_uuid, svc_uuid, hp_uuid],
                ),
                // Members of dg_receivers administer the persons in dg_scope.
                delegated_acp_entry(
                    "acp_delegated_enforced",
                    EntryClass::AccessControlReceiverGroup,
                    EntryClass::AccessControlTargetDelegatedScope,
                    vec![
                        (Attribute::AcpReceiverGroup, Value::ReferN(receivers_uuid)),
                        (Attribute::DelegatedScopeGroup, Value::Refer(scope_uuid)),
                        (Attribute::DelegatedScopeFilter, dg_person_filter()),
                    ],
                ),
            ])
            .expect("failed to create entries");
        // dg_hp is in the scope, but also high privilege.
        qs_write
            .internal_modify_uuid(
                UUID_IDM_HIGH_PRIVILEGE,
                &ModifyList::new_append(Attribute::Member, Value::ReferN(hp_uuid)),
            )
            .expect("add to high privilege");
        // Access controls are reloaded on commit.
        qs_write.commit().expect("commit");
        let mut qs_write = qs.write(ct).await.unwrap();

        let admin = dg_ident(&mut qs_write, admin_uuid);
        let outsider = dg_ident(&mut qs_write, outsider_uuid);
        let target = dg_ident(&mut qs_write, target_uuid);
        let anonymous = dg_ident(&mut qs_write, UUID_ANONYMOUS);

        // The effective permissions agree with the operations below.
        let effective =
            |qs_write: &mut QueryServerWriteTransaction<'_>, ident: &Identity, uuid: Uuid| {
                let entry = qs_write.internal_search_uuid(uuid).expect("entry");
                qs_write
                    .get_accesscontrols()
                    .effective_permission_check(ident, None, std::slice::from_ref(&entry))
                    .expect("effective permission check")
                    .remove(0)
            };
        let can_modify = |ep: &AccessEffectivePermission| {
            matches!(&ep.modify_pres, Access::Allow(attrs) if attrs.contains(&Attribute::DisplayName))
                && matches!(&ep.modify_rem, Access::Allow(attrs) if attrs.contains(&Attribute::DisplayName))
        };
        let can_read_legalname = |ep: &AccessEffectivePermission| matches!(&ep.search, Access::Allow(attrs) if attrs.contains(&Attribute::LegalName));

        // Neither non receivers, nor the members of the scope group themselves, receive
        // the profile.
        for denied in [&anonymous, &outsider, &target] {
            let ep = effective(&mut qs_write, denied, peer_uuid);
            assert!(!can_modify(&ep));
            assert!(!can_read_legalname(&ep));
            assert!(!ep.delete);
            assert!(!dg_can_modify(&mut qs_write, denied, peer_uuid));
            assert!(!dg_can_delete(&mut qs_write, denied, peer_uuid));
        }

        // The receiver can not administer anything outside of the scope: a person that
        // is not in the scope group, a scope group member that does not match the scope
        // filter, or a high privilege scope group member.
        for out_of_scope in [outsider_uuid, svc_uuid, hp_uuid] {
            let ep = effective(&mut qs_write, &admin, out_of_scope);
            assert!(!can_modify(&ep), "{out_of_scope}");
            assert!(!ep.delete, "{out_of_scope}");
            assert!(!dg_can_modify(&mut qs_write, &admin, out_of_scope));
            assert!(!dg_can_delete(&mut qs_write, &admin, out_of_scope));
        }

        // A new entry has no memberof, so it is never in a delegated scope.
        assert!(qs_write
            .impersonate_create(&admin, vec![dg_person("dg_created", Uuid::new_v4())])
            .is_err());

        let ep = effective(&mut qs_write, &admin, target_uuid);
        assert!(can_modify(&ep));
        assert!(can_read_legalname(&ep));
        assert!(ep.delete);
        assert!(dg_can_modify(&mut qs_write, &admin, target_uuid));
        assert!(dg_can_delete(&mut qs_write, &admin, target_uuid));

        qs_write.commit().expect("commit");
    }

    /// Kubidm: an entry manager receiver with a delegated target only administers the
    /// managed entries that are in the delegated scope.
    #[qs_test]
    async fn test_access_delegated_acp_entry_manager(qs: &QueryServer) {
        let ct = duration_from_epoch_now();

        let manager_uuid = Uuid::new_v4();
        let managers_uuid = Uuid::new_v4();
        let in_scope_uuid = Uuid::new_v4();
        let out_of_scope_uuid = Uuid::new_v4();
        let scope_uuid = Uuid::new_v4();

        let managed = |name: &str, uuid: Uuid| {
            let mut entry = dg_person(name, uuid);
            entry.add_ava(Attribute::EntryManagedBy, Value::Refer(managers_uuid));
            entry
        };

        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_create(vec![
                dg_person("dgm_manager", manager_uuid),
                dg_group("dgm_managers", managers_uuid, &[manager_uuid]),
                managed("dgm_in_scope", in_scope_uuid),
                managed("dgm_out_of_scope", out_of_scope_uuid),
                dg_group("dgm_scope", scope_uuid, &[in_scope_uuid]),
                delegated_acp_entry(
                    "acp_delegated_entry_manager",
                    EntryClass::AccessControlReceiverEntryManager,
                    EntryClass::AccessControlTargetDelegatedScope,
                    vec![
                        (Attribute::DelegatedScopeGroup, Value::Refer(scope_uuid)),
                        (Attribute::DelegatedScopeFilter, dg_person_filter()),
                    ],
                ),
            ])
            .expect("failed to create entries");
        qs_write.commit().expect("commit");
        let mut qs_write = qs.write(ct).await.unwrap();

        let manager = dg_ident(&mut qs_write, manager_uuid);
        assert!(!dg_can_modify(&mut qs_write, &manager, out_of_scope_uuid));
        assert!(!dg_can_delete(&mut qs_write, &manager, out_of_scope_uuid));
        assert!(dg_can_modify(&mut qs_write, &manager, in_scope_uuid));
    }

    /// Kubidm: deleting the delegated scope group must never widen the target to the
    /// scope filter alone. A local delete is refused, since it leaves the profile
    /// invalid. When the delete arrives through replication, the profile is skipped and
    /// grants nothing until it is fixed.
    #[qs_test]
    async fn test_access_delegated_scope_group_deleted(qs: &QueryServer) {
        let ct = duration_from_epoch_now();

        let admin_uuid = Uuid::new_v4();
        let target_uuid = Uuid::new_v4();
        let outsider_uuid = Uuid::new_v4();
        let receivers_uuid = Uuid::new_v4();
        let scope_uuid = Uuid::new_v4();
        let new_scope_uuid = Uuid::new_v4();
        let acp_uuid = Uuid::new_v4();

        let mut acp = delegated_acp_entry(
            "acp_delegated_deleted_scope",
            EntryClass::AccessControlReceiverGroup,
            EntryClass::AccessControlTargetDelegatedScope,
            vec![
                (Attribute::AcpReceiverGroup, Value::ReferN(receivers_uuid)),
                (Attribute::DelegatedScopeGroup, Value::Refer(scope_uuid)),
                (Attribute::DelegatedScopeFilter, dg_person_filter()),
            ],
        );
        acp.remove_ava(Attribute::Uuid);
        acp.add_ava(Attribute::Uuid, Value::Uuid(acp_uuid));

        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_create(vec![
                dg_person("dgd_admin", admin_uuid),
                dg_person("dgd_target", target_uuid),
                dg_person("dgd_outsider", outsider_uuid),
                dg_group("dgd_receivers", receivers_uuid, &[admin_uuid]),
                dg_group("dgd_scope", scope_uuid, &[target_uuid]),
                dg_group("dgd_new_scope", new_scope_uuid, &[outsider_uuid]),
                acp,
            ])
            .expect("failed to create entries");
        qs_write.commit().expect("commit");

        // A local delete of the scope group is refused: referential integrity removes the
        // scope group from the profile in the same transaction, which leaves it invalid.
        // The caller is told why, the server log also names the profile that blocks the
        // delete.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_delete_uuid(scope_uuid)
            .expect("delete scope group");
        assert_eq!(
            qs_write.commit(),
            Err(OperationError::InvalidAcpState(format!(
                "A delegated target requires {}",
                Attribute::DelegatedScopeGroup
            )))
        );

        // Nothing changed: the receiver still only administers the scope.
        let mut qs_write = qs.write(ct).await.unwrap();
        assert!(qs_write.internal_search_uuid(scope_uuid).is_ok());
        let admin = dg_ident(&mut qs_write, admin_uuid);
        assert!(!dg_can_modify(&mut qs_write, &admin, outsider_uuid));
        assert!(!dg_can_delete(&mut qs_write, &admin, outsider_uuid));
        assert!(dg_can_modify(&mut qs_write, &admin, target_uuid));
        drop(qs_write);

        // The same delete applied by replication is accepted, and the profile is skipped
        // rather than widened to every person.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write.replication_apply = true;
        qs_write
            .internal_delete_uuid(scope_uuid)
            .expect("delete scope group");
        qs_write.commit().expect("commit");

        let mut qs_write = qs.write(ct).await.unwrap();
        let acp_entry = qs_write.internal_search_uuid(acp_uuid).expect("acp");
        assert!(!acp_entry.attribute_pres(Attribute::DelegatedScopeGroup));
        assert!(!dg_loaded_modify(&qs_write).contains("acp_delegated_deleted_scope"));
        assert_eq!(
            qs_write.get_accesscontrols().get_skipped_profiles(),
            BTreeMap::from([(acp_uuid, "acp_delegated_deleted_scope")])
        );
        let admin = dg_ident(&mut qs_write, admin_uuid);
        for uuid in [outsider_uuid, target_uuid] {
            assert!(!dg_can_modify(&mut qs_write, &admin, uuid));
            assert!(!dg_can_delete(&mut qs_write, &admin, uuid));
        }
        drop(qs_write);

        // Unrelated writes are not blocked by the skipped profile.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_create(vec![delegated_acp_entry(
                "acp_unrelated",
                EntryClass::AccessControlReceiverGroup,
                EntryClass::AccessControlTargetScope,
                vec![
                    (Attribute::AcpReceiverGroup, Value::ReferN(receivers_uuid)),
                    (
                        Attribute::AcpTargetScope,
                        Value::new_json_filter_s("{\"eq\":[\"name\",\"no_such_entry\"]}")
                            .expect("filter"),
                    ),
                ],
            )])
            .expect("create");
        qs_write.commit().expect("commit");

        // Setting a new scope group fixes the profile.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_modify_uuid(
                acp_uuid,
                &ModifyList::new_purge_and_set(
                    Attribute::DelegatedScopeGroup,
                    Value::Refer(new_scope_uuid),
                ),
            )
            .expect("modify");
        qs_write.commit().expect("commit");

        let mut qs_write = qs.write(ct).await.unwrap();
        assert!(dg_loaded_modify(&qs_write).contains("acp_delegated_deleted_scope"));
        let admin = dg_ident(&mut qs_write, admin_uuid);
        assert!(!dg_can_modify(&mut qs_write, &admin, target_uuid));
        assert!(dg_can_modify(&mut qs_write, &admin, outsider_uuid));
    }

    /// Kubidm: a stored profile that the current parser rejects (for example written by
    /// an older version or received through replication) is skipped at reload and on
    /// start up, while every other profile keeps working. Changing it locally requires
    /// making it valid, or disabling it.
    #[qs_test]
    async fn test_access_reload_skips_stored_invalid_acp(qs: &QueryServer) {
        let ct = duration_from_epoch_now();

        let admin_uuid = Uuid::new_v4();
        let valid_target_uuid = Uuid::new_v4();
        let other_target_uuid = Uuid::new_v4();
        let receivers_uuid = Uuid::new_v4();
        let scope_uuid = Uuid::new_v4();
        let reauth_max_age_uuid = Uuid::new_v4();

        let name_filter = |name: &str| {
            Value::new_json_filter_s(&format!("{{\"eq\":[\"name\",\"{name}\"]}}")).expect("filter")
        };
        let receiver_group = || (Attribute::AcpReceiverGroup, Value::ReferN(receivers_uuid));

        let mut reauth_max_age = delegated_acp_entry(
            "acp_stored_reauth_max_age",
            EntryClass::AccessControlReceiverGroup,
            EntryClass::AccessControlTargetScope,
            vec![
                receiver_group(),
                (Attribute::AcpTargetScope, name_filter("dgs_other")),
                (Attribute::AcpReauthMaxAge, Value::Uint32(300)),
            ],
        );
        reauth_max_age.remove_ava(Attribute::Uuid);
        reauth_max_age.add_ava(Attribute::Uuid, Value::Uuid(reauth_max_age_uuid));

        // Written as replicated content, so the current parser does not validate it.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write.replication_apply = true;
        qs_write
            .internal_create(vec![
                dg_person("dgs_admin", admin_uuid),
                dg_person("dgs_valid", valid_target_uuid),
                dg_person("dgs_other", other_target_uuid),
                dg_group("dgs_receivers", receivers_uuid, &[admin_uuid]),
                dg_group("dgs_scope", scope_uuid, &[admin_uuid, other_target_uuid]),
                delegated_acp_entry(
                    "acp_stored_valid",
                    EntryClass::AccessControlReceiverGroup,
                    EntryClass::AccessControlTargetScope,
                    vec![
                        receiver_group(),
                        (Attribute::AcpTargetScope, name_filter("dgs_valid")),
                    ],
                ),
                reauth_max_age,
                delegated_acp_entry(
                    "acp_stored_delegated_receiver",
                    EntryClass::AccessControlReceiverDelegated,
                    EntryClass::AccessControlTargetDelegatedScope,
                    vec![(Attribute::DelegatedScopeGroup, Value::Refer(scope_uuid))],
                ),
                delegated_acp_entry(
                    "acp_stored_filter_only",
                    EntryClass::AccessControlReceiverGroup,
                    EntryClass::AccessControlTargetDelegatedScope,
                    vec![
                        receiver_group(),
                        (Attribute::DelegatedScopeFilter, name_filter("dgs_other")),
                    ],
                ),
            ])
            .expect("failed to create entries");
        qs_write.commit().expect("commit");

        let check = |qs_write: &mut QueryServerWriteTransaction<'_>| {
            let loaded = dg_loaded_modify(qs_write);
            assert!(loaded.contains("acp_stored_valid"));
            let invalid = [
                "acp_stored_reauth_max_age",
                "acp_stored_delegated_receiver",
                "acp_stored_filter_only",
            ];
            for name in invalid {
                assert!(!loaded.contains(name), "{name}");
            }
            // The skipped profiles are recorded (and reported once at start up), unless
            // they are disabled.
            let reauth_max_age_enabled = qs_write
                .internal_search_uuid(reauth_max_age_uuid)
                .expect("acp")
                .get_ava_single_bool(Attribute::AcpEnable)
                != Some(false);
            let skipped: BTreeSet<&str> = qs_write
                .get_accesscontrols()
                .get_skipped()
                .values()
                .map(String::as_str)
                .collect();
            let expected: BTreeSet<&str> = invalid
                .into_iter()
                .filter(|name| reauth_max_age_enabled || *name != "acp_stored_reauth_max_age")
                .collect();
            assert_eq!(skipped, expected);
            assert_eq!(
                qs_write
                    .get_accesscontrols()
                    .get_skipped_profiles()
                    .contains_key(&reauth_max_age_uuid),
                reauth_max_age_enabled
            );
            let admin = dg_ident(qs_write, admin_uuid);
            assert!(!dg_can_modify(qs_write, &admin, other_target_uuid));
            assert!(dg_can_modify(qs_write, &admin, valid_target_uuid));
        };

        let mut qs_write = qs.write(ct).await.unwrap();
        check(&mut qs_write);
        drop(qs_write);

        // A local change to another profile reloads every profile, and is not blocked.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_create(vec![delegated_acp_entry(
                "acp_stored_unrelated",
                EntryClass::AccessControlReceiverGroup,
                EntryClass::AccessControlTargetScope,
                vec![
                    receiver_group(),
                    (Attribute::AcpTargetScope, name_filter("no_such_entry")),
                ],
            )])
            .expect("create");
        qs_write.commit().expect("commit");

        // Start up is not blocked either. Return to the bootstrap phase first, as a
        // freshly started server would be.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write.set_phase_bootstrap();
        qs_write.commit().expect("commit");
        qs.initialise_helper(duration_from_epoch_now(), DOMAIN_TGT_LEVEL)
            .await
            .expect("restart");

        let mut qs_write = qs.write(ct).await.unwrap();
        check(&mut qs_write);
        drop(qs_write);

        // Changing a stored invalid profile locally without fixing it is refused.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_modify_uuid(
                reauth_max_age_uuid,
                &ModifyList::new_purge_and_set(
                    Attribute::Description,
                    Value::new_utf8s("still invalid"),
                ),
            )
            .expect("modify");
        assert!(matches!(
            qs_write.commit(),
            Err(OperationError::InvalidAcpState(_))
        ));

        // Disabling it is accepted.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_modify_uuid(
                reauth_max_age_uuid,
                &ModifyList::new_purge_and_set(Attribute::AcpEnable, Value::new_bool(false)),
            )
            .expect("modify");
        qs_write.commit().expect("commit");

        let mut qs_write = qs.write(ct).await.unwrap();
        check(&mut qs_write);
    }

    /// Kubidm: every built-in access control profile is loaded after bootstrap and
    /// migration, as every kind it has. A built-in profile that the parser rejects fails
    /// start up, rather than being skipped silently.
    #[qs_test]
    async fn test_access_builtin_acps_all_loaded(qs: &QueryServer) {
        let ct = duration_from_epoch_now();
        let mut qs_write = qs.write(ct).await.unwrap();
        super::assert_builtin_acps_all_loaded(&mut qs_write);
    }

    /// Kubidm: a built-in profile is validated strictly when it is changed in the
    /// transaction or was loaded before, in every phase. A built-in made invalid by
    /// replication is skipped (replication is lenient), and must not stop the server from
    /// starting afterwards (in the same process, or in a fresh one that never loaded it):
    /// start up skips and reports it, or repairs it when it re-runs the migrations,
    /// while a local change that leaves a built-in invalid is still refused.
    #[qs_test]
    async fn test_access_reload_strict_for_builtin_acp(qs: &QueryServer) {
        let ct = duration_from_epoch_now();
        let invalid =
            || ModifyList::new_purge_and_set(Attribute::AcpReauthMaxAge, Value::Uint32(300));
        let refused = || {
            Err(OperationError::InvalidAcpState(format!(
                "{} is unsupported",
                Attribute::AcpReauthMaxAge
            )))
        };
        // Skipped as the only kind it has.
        let builtin_skipped = || {
            super::SkippedAcps::from([(
                (
                    UUID_IDM_ACP_PEOPLE_READ_V1,
                    EntryClass::AccessControlSearch.into(),
                ),
                "idm_acp_people_read".to_string(),
            )])
        };
        let builtin_loaded = |qs_write: &QueryServerWriteTransaction<'_>| {
            qs_write
                .get_accesscontrols()
                .get_search()
                .iter()
                .any(|a| a.acp.uuid() == UUID_IDM_ACP_PEOPLE_READ_V1)
        };
        let invalid_by_replication = |qs_write: &mut QueryServerWriteTransaction<'_>| {
            qs_write.replication_apply = true;
            qs_write
                .internal_modify_uuid(UUID_IDM_ACP_PEOPLE_READ_V1, &invalid())
                .expect("modify");
        };
        // A pre-release build re-runs the migrations of the current level on every start
        // up, and the built-in profile migrations repair the built-in (see
        // `test_migrations_builtin_acp_unsupported_values_repaired`). Otherwise start up
        // skips it, and reports it.
        let remigrates = option_env!("KUBIDM_PRE_RELEASE").is_some();
        let check_started = |qs_write: &QueryServerWriteTransaction<'_>| {
            if remigrates {
                assert!(qs_write.get_accesscontrols().get_skipped().is_empty());
                assert!(builtin_loaded(qs_write));
            } else {
                assert_eq!(
                    qs_write.get_accesscontrols().get_skipped(),
                    &builtin_skipped()
                );
                assert!(!builtin_loaded(qs_write));
            }
        };

        // A local change that leaves it invalid is refused, with the reason but without
        // naming it to the caller.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_modify_uuid(UUID_IDM_ACP_PEOPLE_READ_V1, &invalid())
            .expect("modify");
        assert_eq!(qs_write.commit(), refused());

        // Through replication it is skipped, and the skip is recorded.
        let mut qs_write = qs.write(ct).await.unwrap();
        invalid_by_replication(&mut qs_write);
        qs_write.commit().expect("commit");
        let mut qs_write = qs.write(ct).await.unwrap();
        assert_eq!(
            qs_write.get_accesscontrols().get_skipped(),
            &builtin_skipped()
        );
        assert!(!builtin_loaded(&qs_write));

        // An unrelated write that reloads the access controls is not blocked by it.
        qs_write
            .internal_create(vec![dg_group("strict_builtin_group", Uuid::new_v4(), &[])])
            .expect("create");
        qs_write
            .changed_flags
            .insert(crate::server::ChangeFlag::ACP);
        qs_write.commit().expect("commit");

        // A restart succeeds.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write.set_phase_bootstrap();
        qs_write.commit().expect("commit");
        qs.initialise_helper(duration_from_epoch_now(), DOMAIN_TGT_LEVEL)
            .await
            .expect("restart");
        let qs_write = qs.write(ct).await.unwrap();
        check_started(&qs_write);
        drop(qs_write);

        // So does the start up of a fresh process, which has neither loaded nor skipped
        // any profile before: the built-in is not strict since it was not loaded, and the
        // migration rewrite of it is lenient since the first start up reload skipped it.
        let mut qs_write = qs.write(ct).await.unwrap();
        invalid_by_replication(&mut qs_write);
        qs_write.commit().expect("commit");
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write.set_phase_bootstrap();
        qs_write
            .accesscontrols
            .update_search(Vec::new())
            .expect("clear");
        qs_write
            .accesscontrols
            .update_create(Vec::new())
            .expect("clear");
        qs_write
            .accesscontrols
            .update_modify(Vec::new())
            .expect("clear");
        qs_write
            .accesscontrols
            .update_delete(Vec::new())
            .expect("clear");
        qs_write
            .accesscontrols
            .update_skipped(super::SkippedAcps::new());
        qs_write.commit().expect("commit");
        let qs_write = qs.write(ct).await.unwrap();
        let acps = qs_write.get_accesscontrols();
        assert!(acps.get_search().is_empty() && acps.get_create().is_empty());
        assert!(acps.get_modify().is_empty() && acps.get_delete().is_empty());
        assert!(acps.get_skipped().is_empty());
        drop(qs_write);
        qs.initialise_helper(duration_from_epoch_now(), DOMAIN_TGT_LEVEL)
            .await
            .expect("fresh start up");
        let qs_write = qs.write(ct).await.unwrap();
        check_started(&qs_write);
        assert!(qs_write.get_accesscontrols().get_search().len() > 10);
        drop(qs_write);

        // While it is skipped, a local change to it that leaves it invalid is refused.
        let mut qs_write = qs.write(ct).await.unwrap();
        invalid_by_replication(&mut qs_write);
        qs_write.commit().expect("commit");
        let qs_write = qs.write(ct).await.unwrap();
        assert_eq!(
            qs_write.get_accesscontrols().get_skipped(),
            &builtin_skipped()
        );
        drop(qs_write);
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_modify_uuid(
                UUID_IDM_ACP_PEOPLE_READ_V1,
                &ModifyList::new_purge_and_set(
                    Attribute::Description,
                    Value::new_utf8s("still invalid"),
                ),
            )
            .expect("modify");
        assert_eq!(qs_write.commit(), refused());

        // Fixing it loads it again, and a local change that makes a loaded built-in
        // invalid is refused.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_modify_uuid(
                UUID_IDM_ACP_PEOPLE_READ_V1,
                &ModifyList::new_purge(Attribute::AcpReauthMaxAge),
            )
            .expect("modify");
        qs_write.commit().expect("commit");
        let mut qs_write = qs.write(ct).await.unwrap();
        assert!(qs_write.get_accesscontrols().get_skipped().is_empty());
        assert!(builtin_loaded(&qs_write));
        qs_write
            .internal_modify_uuid(UUID_IDM_ACP_PEOPLE_READ_V1, &invalid())
            .expect("modify");
        assert_eq!(qs_write.commit(), refused());
    }

    /// Kubidm: the profiles a running reload newly skips (as any kind) are the ones it
    /// reports, so a profile made invalid by replication is summarised once. A skipped
    /// built-in is reported as such.
    #[test]
    fn test_access_acp_newly_skipped() {
        use crate::server::{acp_newly_skipped, acp_skipped_report};

        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let search: &'static str = EntryClass::AccessControlSearch.into();
        let modify: &'static str = EntryClass::AccessControlModify.into();
        let previous = super::SkippedAcps::from([((a, search), "acp_a".to_string())]);
        let current = super::SkippedAcps::from([
            ((a, search), "acp_a".to_string()),
            ((a, modify), "acp_a".to_string()),
            ((b, search), "acp_b".to_string()),
        ]);
        // `a` is newly skipped as another kind.
        assert_eq!(
            acp_newly_skipped(&previous, &current),
            BTreeMap::from([(a, "acp_a"), (b, "acp_b")])
        );
        assert!(acp_newly_skipped(&current, &current).is_empty());
        assert!(acp_newly_skipped(&current, &previous).is_empty());

        assert_eq!(
            acp_skipped_report(&BTreeMap::from([(b, "acp_b")])),
            (false, vec![format!("acp_b ({b})")])
        );
        assert!(
            acp_skipped_report(&BTreeMap::from([
                (b, "acp_b"),
                (UUID_IDM_ACP_PEOPLE_READ_V1, "idm_acp_people_read")
            ]))
            .0
        );
    }

    /// Kubidm: a profile that was valid and loaded, and that a change in the transaction
    /// leaves invalid without changing the profile itself (here, a schema change removing
    /// an attribute its target scope uses), is refused like a change to the profile. The
    /// same change applied by replication skips the profile.
    #[qs_test]
    async fn test_access_reload_rejects_indirectly_broken_acp(qs: &QueryServer) {
        use crate::schema::{SchemaAttribute, SchemaTransaction};

        let ct = duration_from_epoch_now();
        let receivers_uuid = Uuid::new_v4();

        let acp = delegated_acp_entry(
            "acp_login_shell_scope",
            EntryClass::AccessControlReceiverGroup,
            EntryClass::AccessControlTargetScope,
            vec![
                (Attribute::AcpReceiverGroup, Value::ReferN(receivers_uuid)),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"loginshell\",\"/bin/false\"]}")
                        .expect("filter"),
                ),
            ],
        );
        let acp_uuid = acp.get_uuid().expect("uuid");

        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write
            .internal_create(vec![dg_group("dgi_receivers", receivers_uuid, &[]), acp])
            .expect("failed to create entries");
        qs_write.commit().expect("commit");

        let qs_write = qs.write(ct).await.unwrap();
        assert!(dg_loaded_modify(&qs_write).contains("acp_login_shell_scope"));
        drop(qs_write);

        let remove_login_shell = |qs_write: &mut QueryServerWriteTransaction<'_>| {
            let attrs: Vec<SchemaAttribute> = qs_write
                .schema
                .get_attributes()
                .values()
                .filter(|attr| attr.name != Attribute::LoginShell)
                .cloned()
                .collect();
            qs_write
                .schema
                .update_attributes(attrs.into_iter())
                .expect("schema");
            qs_write
                .changed_flags
                .insert(crate::server::ChangeFlag::ACP);
        };

        // A local change is refused, with the parser's error (the server log names the
        // profile).
        let mut qs_write = qs.write(ct).await.unwrap();
        remove_login_shell(&mut qs_write);
        assert!(!qs_write.is_changed_uuid(&acp_uuid));
        assert_eq!(
            qs_write.commit(),
            Err(OperationError::InvalidAttributeName(
                Attribute::LoginShell.to_string()
            ))
        );

        let qs_write = qs.write(ct).await.unwrap();
        assert!(dg_loaded_modify(&qs_write).contains("acp_login_shell_scope"));
        drop(qs_write);

        // Through replication the profile is skipped.
        let mut qs_write = qs.write(ct).await.unwrap();
        qs_write.replication_apply = true;
        remove_login_shell(&mut qs_write);
        qs_write.commit().expect("commit");

        let qs_write = qs.write(ct).await.unwrap();
        assert!(!dg_loaded_modify(&qs_write).contains("acp_login_shell_scope"));
        assert_eq!(
            qs_write.get_accesscontrols().get_skipped_profiles(),
            BTreeMap::from([(acp_uuid, "acp_login_shell_scope")])
        );
    }

    // =========================================================================
    // Migration Identity Modify Tests
    // =========================================================================

    #[test]
    fn test_access_migration_modify_constrained_to_migration_attrs() {
        sketching::test_init();

        let uuid_group = uuid!("3c1e4f5a-7f0a-4b0e-9a55-2f2a6b7f9c01");
        let group_entry = Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Name, Value::new_iname("migration_test_group")),
                (Attribute::Uuid, Value::Uuid(uuid_group))
            )
            .into_sealed_committed(),
        );
        let data_set = vec![group_entry];

        let filter = filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(uuid_group)));

        // An attribute that migrations are allowed to manage on groups.
        let allowed_mods = || {
            modlist!([
                m_pres(Attribute::Description, &Value::new_utf8s("migrated")),
                m_pres(Attribute::Member, &Value::Refer(UUID_TEST_ACCOUNT_1))
            ])
        };
        // An attribute outside of the migration attribute set.
        let denied_mods = || modlist!([m_pres(Attribute::Mail, &Value::new_utf8s("x"))]);

        // A broad profile must not extend what the migration identity may modify.
        let broad_acp = AccessControlModify::from_raw(
            "test_broad_modify",
            Uuid::new_v4(),
            UUID_TEST_GROUP_1,
            filter_valid!(f_pres(Attribute::Uuid)),
            "mail",
            "mail",
            "",
            "",
        );

        let me_allowed = ModifyEvent::new_impersonate_identity(
            Identity::migration(),
            filter.clone(),
            allowed_mods(),
        );
        test_acp_modify!(&me_allowed, vec![], &data_set, true);

        let me_denied =
            ModifyEvent::new_impersonate_identity(Identity::migration(), filter, denied_mods());
        test_acp_modify!(&me_denied, vec![], &data_set, false);
        test_acp_modify!(&me_denied, vec![broad_acp.clone()], &data_set, false);

        // Batch modify path must apply the same rules.
        let batch =
            |modlist: ModifyList<ModifyInvalid>| crate::server::batch_modify::BatchModifyEvent {
                ident: Identity::migration(),
                modset: [(uuid_group, modlist.into_valid())].into_iter().collect(),
            };

        let run_batch = |bme: &crate::server::batch_modify::BatchModifyEvent,
                         acps: Vec<AccessControlModify>| {
            let ac = AccessControls::default();
            let mut acw = ac.write(duration_from_epoch_now());
            acw.update_modify(acps).expect("Failed to update");
            acw.batch_modify_allow_operation(bme, &data_set)
                .expect("op failed")
        };

        assert!(run_batch(&batch(allowed_mods()), vec![]));
        assert!(!run_batch(&batch(denied_mods()), vec![]));
        assert!(!run_batch(&batch(denied_mods()), vec![broad_acp]));
    }
}
