// Member Of
//
// Generate reverse relationships for groups to their members.
//
// Note referential integrity MUST be run first - this is to avoid the situation
// demonstrated in test_delete_mo_multi_cycle - that is, when we delete B, we trigger
// an update to C. C then triggers to A, which re-reades C + D. Because D still has not
// been update, it's stale reference to B flows to A, causing refint to fail the mod.
//
// As a result, we first need to run refint to clean up all dangling references, then memberof
// fixes the graph of memberships

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crate::{
    entry::{Entry, EntryCommitted, EntrySealed},
    event::{CreateEvent, DeleteEvent, ModifyEvent},
    plugins::Plugin,
    prelude::*,
    schema::SchemaTransaction,
    value::{PartialValue, TimeBoundedMember},
};
use time::OffsetDateTime;

pub struct MemberOf;

/// Tolerance applied by verify to time bounded grant boundaries, to absorb clock
/// differences between when memberof was applied and when verify runs.
const TIME_BOUNDED_VERIFY_GRACE: u64 = PURGE_FREQUENCY;

fn has_time_bounded_member_attr(qs: &QueryServerWriteTransaction) -> bool {
    qs.get_schema()
        .get_attributes()
        .contains_key(&Attribute::TimeBoundedMemberAttr)
}

/// Kubidm: whether the time-bounded grants of `group` grant nothing because the group is
/// high privilege: `idm_high_privilege` itself, or a group nested in it. Grants on such
/// groups are refused when written (see `server::time_bounded`), but a group can become
/// high privilege after grants on it were written, including grants that start later.
/// Those are treated as inactive for as long as the group is high privilege, so that they
/// can not bypass the approvals that high privilege membership is meant to require. They
/// can still be revoked.
pub(crate) fn time_bounded_grants_suppressed(group: &EntrySealedCommitted) -> bool {
    group.get_uuid() == UUID_IDM_HIGH_PRIVILEGE
        || group.attribute_equality(
            Attribute::MemberOf,
            &PartialValue::Refer(UUID_IDM_HIGH_PRIVILEGE),
        )
}

fn get_valid_time_bounded_members(
    entry: &Arc<Entry<EntrySealed, EntryCommitted>>,
    now: OffsetDateTime,
) -> BTreeSet<Uuid> {
    if time_bounded_grants_suppressed(entry) {
        return BTreeSet::new();
    }
    entry
        .get_ava_set(Attribute::TimeBoundedMemberAttr)
        .and_then(|vs| vs.as_time_bounded_member_set())
        .map(|map| {
            map.values()
                .filter(|m: &&TimeBoundedMember| m.is_valid_at(now))
                .map(|m| m.uuid)
                .collect()
        })
        .unwrap_or_default()
}

type TimeBoundedGrantKey = (Uuid, Option<OffsetDateTime>, OffsetDateTime);

fn time_bounded_grants(entry: &EntrySealedCommitted) -> BTreeSet<TimeBoundedGrantKey> {
    entry
        .get_ava_set(Attribute::TimeBoundedMemberAttr)
        .and_then(|vs| vs.as_time_bounded_member_set())
        .map(|map| {
            map.values()
                .map(|m| (m.uuid, m.valid_from, m.valid_until))
                .collect()
        })
        .unwrap_or_default()
}

fn time_bounded_member_uuids<VALID, STATE>(
    entry: &Entry<VALID, STATE>,
) -> impl Iterator<Item = Uuid> + '_ {
    entry
        .get_ava_set(Attribute::TimeBoundedMemberAttr)
        .and_then(|vs| vs.as_time_bounded_member_set())
        .into_iter()
        .flat_map(|map| map.keys().copied())
}

fn do_group_memberof(
    qs: &mut QueryServerWriteTransaction,
    uuid: Uuid,
    tgte: &mut EntryInvalidCommitted,
) -> Result<(), OperationError> {
    let now = qs.get_curtime_odt();

    let has_tbm = has_time_bounded_member_attr(qs);

    let groups = qs
        .internal_search({
            let mut filter_parts = vec![
                f_eq(Attribute::Member, PartialValue::Refer(uuid)),
                f_eq(Attribute::DynMember, PartialValue::Refer(uuid)),
            ];
            if has_tbm {
                filter_parts.push(f_eq(
                    Attribute::TimeBoundedMemberAttr,
                    PartialValue::TimeBoundedMember(uuid),
                ));
            }
            filter!(f_and(vec![
                f_eq(Attribute::Class, EntryClass::Group.into()),
                f_or(filter_parts)
            ]))
        })
        .map_err(|e| {
            admin_error!("internal search failure -> {:?}", e);
            e
        })?;

    let groups_with_valid_time_bounded: BTreeSet<Uuid> = groups
        .iter()
        .filter(|g| !time_bounded_grants_suppressed(g))
        .filter_map(|g| {
            let time_bounded = g
                .get_ava_set(Attribute::TimeBoundedMemberAttr)
                .and_then(|vs| vs.as_time_bounded_member_set())?;
            let valid_member = time_bounded
                .values()
                .any(|m: &TimeBoundedMember| m.uuid == uuid && m.is_valid_at(now));
            if valid_member {
                Some(g.get_uuid())
            } else {
                None
            }
        })
        .collect();

    let groups_with_permanent_membership: BTreeSet<Uuid> = groups
        .iter()
        .filter(|g| {
            let is_member = g
                .get_ava_refer(Attribute::Member)
                .map(|set| set.contains(&uuid))
                .unwrap_or(false);
            let is_dynmember = g
                .get_ava_refer(Attribute::DynMember)
                .map(|set| set.contains(&uuid))
                .unwrap_or(false);
            is_member || is_dynmember
        })
        .map(|g| g.get_uuid())
        .collect();

    tgte.add_ava_if_not_exist(Attribute::Class, EntryClass::MemberOf.into());
    tgte.purge_ava(Attribute::MemberOf);
    tgte.purge_ava(Attribute::DirectMemberOf);

    // What are our direct and indirect mos? Direct memberships include both
    // permanent (member/dynmember) and currently valid time-bounded grants.
    let all_direct_members: BTreeSet<Uuid> = groups_with_permanent_membership
        .union(&groups_with_valid_time_bounded)
        .copied()
        .collect();

    let dmo = ValueSetReferN::from_iter(all_direct_members.iter().copied());

    let groups_for_mo: Vec<_> = groups
        .iter()
        .filter(|g| all_direct_members.contains(&g.get_uuid()))
        .collect();

    let mut mo = ValueSetReferN::from_iter(
        groups_for_mo
            .iter()
            .filter_map(|g| {
                g.get_ava_set(Attribute::MemberOf)
                    .and_then(|s| s.as_refer_set())
                    .map(|s| s.iter())
            })
            .flatten()
            .copied(),
    );

    if let Some(dmo) = dmo {
        tgte.set_ava_set(&Attribute::DirectMemberOf, dmo.clone());

        if let Some(mo) = &mut mo {
            let dmo = dmo as ValueSet;
            mo.merge(&dmo)?;
        } else {
            mo = Some(dmo);
        };
    };

    if let Some(mo) = mo {
        tgte.set_ava_set(&Attribute::MemberOf, mo);
    }

    trace!(
        "Updating {:?} to be dir mo {:?}",
        uuid,
        tgte.get_ava_set(Attribute::DirectMemberOf)
    );
    trace!(
        "Updating {:?} to be mo {:?}",
        uuid,
        tgte.get_ava_set(Attribute::MemberOf)
    );
    Ok(())
}

fn do_leaf_memberof(
    qs: &mut QueryServerWriteTransaction,
    all_affected_uuids: BTreeSet<Uuid>,
) -> Result<(), OperationError> {
    trace!("---");

    // We just put everything into the filter here, the query code will remove
    // anything that is a group.
    let all_affected_filter: Vec<_> = all_affected_uuids
        .into_iter()
        .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
        .collect();

    if all_affected_filter.is_empty() {
        trace!("all affected filter is empty, return");
        return Ok(());
    }

    // These are all the affected entries.
    let leaf_entries = qs.internal_search_writeable(&filter!(f_and!([
        f_andnot(f_eq(Attribute::Class, EntryClass::Group.into())),
        FC::Or(all_affected_filter)
    ])))?;

    if leaf_entries.is_empty() {
        trace!("leaf entries empty, return");
        return Ok(());
    }

    let mut leaf_entries: BTreeMap<_, _> = leaf_entries
        .into_iter()
        .map(|entry_tuple| (entry_tuple.0.get_uuid(), entry_tuple))
        .collect();

    let mut changes = Vec::with_capacity(leaf_entries.len());

    // Now that we know which *entries* changed, we actually have to load the groups *again*
    // because the affected entries could still be a DMO/MO of a group that *wasn't* in the
    // change set, and we still need to reflect that they exist.

    let mut groups_or = Vec::with_capacity(leaf_entries.len() * 3);

    let has_tbm = has_time_bounded_member_attr(qs);

    for uuid in leaf_entries.keys().copied() {
        groups_or.push(f_eq(Attribute::Member, PartialValue::Refer(uuid)));
        groups_or.push(f_eq(Attribute::DynMember, PartialValue::Refer(uuid)));
        if has_tbm {
            groups_or.push(f_eq(
                Attribute::TimeBoundedMemberAttr,
                PartialValue::TimeBoundedMember(uuid),
            ));
        }
    }

    let now = qs.get_curtime_odt();

    let all_groups = qs
        .internal_search(filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::Group.into()),
            FC::Or(groups_or)
        ])))
        .map_err(|err| {
            error!(?err, "internal search failure");
            err
        })?;

    /*
     * Previously we went through the remaining items and processed them one at a time, but
     * that has significant performance limits, since if we update a large dyn group, we then
     * have to perform N searches for each affected member, which may be repeatedly searching
     * for the same groups over and over again.
     *
     * Instead, at this point we know that in memberof application the entire group tree is
     * now stable, and all we need to do is reflect those values into our entries. We can do
     * this in two steps. First we load *all* the groups that relate to our leaf entries that
     * we need to reflect.
     *
     * Then we can go through that in a single pass updating our entries that need to be
     * updated. Since we know that the leaf entries aren't groups, we don't have a collision
     * as a result of using internal_search_writeable.
     */

    // Clear the existing Mo and Dmo on the write stripe.
    for (_pre, tgte) in leaf_entries.values_mut() {
        // Ensure we are MO capable. We only add this if it's not already present.
        tgte.add_ava_if_not_exist(Attribute::Class, EntryClass::MemberOf.into());
        // Clear the dmo + mos, we will recreate them now.
        // This is how we handle deletes/etc.
        tgte.purge_ava(Attribute::MemberOf);
        tgte.purge_ava(Attribute::DirectMemberOf);
    }

    // Now, we go through all the groups, and from each one we update the relevant
    // target entry as needed.
    for group in all_groups {
        trace!(group_id = %group.get_display_id());
        // Our group uuid that we add to direct members.
        let group_uuid = group.get_uuid();

        let memberof_ref = group.get_ava_refer(Attribute::MemberOf);

        let member_ref = group.get_ava_refer(Attribute::Member);
        let dynmember_ref = group.get_ava_refer(Attribute::DynMember);

        let time_bounded_valid_members = get_valid_time_bounded_members(&group, now);

        let dir_members = member_ref
            .iter()
            .flat_map(|set| set.iter())
            .chain(dynmember_ref.iter().flat_map(|set| set.iter()))
            .chain(time_bounded_valid_members.iter())
            .copied();

        for dir_member in dir_members {
            if let Some((_pre, tgte)) = leaf_entries.get_mut(&dir_member) {
                trace!(?dir_member, entry_id = ?tgte.get_display_id());
                // We were in the group, lets update.
                if let Some(dmo_set) = tgte.get_ava_refer_mut(Attribute::DirectMemberOf) {
                    dmo_set.insert(group_uuid);
                } else {
                    let dmo = ValueSetReferN::new(group_uuid);
                    tgte.set_ava_set(&Attribute::DirectMemberOf, dmo);
                }

                // We're also in member of this group.
                if let Some(mo_set) = tgte.get_ava_refer_mut(Attribute::MemberOf) {
                    mo_set.insert(group_uuid);
                } else {
                    let mo = ValueSetReferN::new(group_uuid);
                    tgte.set_ava_set(&Attribute::MemberOf, mo);
                }

                // If the group has memberOf attributes, we propagate these to
                // our entry now.
                if let Some(group_mo) = memberof_ref {
                    // IMPORTANT this can't be a NONE because we just create MO in
                    // the step above!
                    if let Some(mo_set) = tgte.get_ava_refer_mut(Attribute::MemberOf) {
                        mo_set.extend(group_mo.iter())
                    }
                }

                if cfg!(debug_assertions) {
                    if let Some(dmo) = group.get_ava_refer(Attribute::DirectMemberOf) {
                        if let Some(mo) = group.get_ava_refer(Attribute::MemberOf) {
                            debug_assert!(mo.is_superset(dmo))
                        }
                    }
                }
            }
            // Done updating that leaf entry.
            // Remember in the None case it could be that the group has a member which *isn't*
            // being altered as a leaf in this operation.
        }
        // Next group.
    }

    // Now only write back leaf entries that actually were changed as a result of the memberof
    // process.
    leaf_entries
        .into_iter()
        .try_for_each(|(auuid, (pre, tgte))| {
            // Only write if a change occurred.
            if pre.get_ava_set(Attribute::MemberOf) != tgte.get_ava_set(Attribute::MemberOf)
                || pre.get_ava_set(Attribute::DirectMemberOf)
                    != tgte.get_ava_set(Attribute::DirectMemberOf)
            {
                trace!("=> processing affected uuid {:?}", auuid);

                if cfg!(debug_assertions) {
                    if let Some(dmo_set) = tgte.get_ava_refer(Attribute::DirectMemberOf) {
                        trace!(?dmo_set);

                        if let Some(mo_set) = tgte.get_ava_refer(Attribute::MemberOf) {
                            trace!(?mo_set);
                            debug_assert!(mo_set.is_superset(dmo_set));
                        } else {
                            unreachable!();
                        }
                    } else {
                        trace!("NONE");
                    };

                    if let Some(pre_dmo_set) = pre.get_ava_refer(Attribute::DirectMemberOf) {
                        trace!(?pre_dmo_set);

                        if let Some(pre_mo_set) = pre.get_ava_refer(Attribute::MemberOf) {
                            trace!(?pre_mo_set);
                            debug_assert!(pre_mo_set.is_superset(pre_dmo_set));
                        } else {
                            unreachable!();
                        }
                    } else {
                        trace!("NONE");
                    };
                };

                changes.push((pre, tgte));
            } else {
                trace!("=> ignoring unmodified uuid {:?}", auuid);
            }
            Ok(())
        })?;

    // Write the batch out in a single stripe.
    qs.internal_apply_writable(changes)
    // Done! 🎉
}

// This is how you know the good code is here.
#[allow(clippy::cognitive_complexity)]
fn apply_memberof(
    qs: &mut QueryServerWriteTransaction,
    // TODO: Experiment with HashSet/BTreeSet here instead of vec.
    // May require https://github.com/rust-lang/rust/issues/62924 to allow popping
    mut affected_uuids: BTreeSet<Uuid>,
) -> Result<(), OperationError> {
    trace!(" => entering apply_memberof");

    // Because of how replication works, we don't send MO over a replication boundary.
    // As a result, we always need to trigger for any changed uuid, so we keep the
    // initial affected set for the leaf resolution.
    //
    // As we proceed, we'll also add the affected members of our groups that are
    // changing.
    let mut all_affected_uuids: BTreeSet<_> = affected_uuids.iter().copied().collect();

    // While there are still affected uuids.
    while !affected_uuids.is_empty() {
        trace!(?affected_uuids);

        // Ignore recycled/tombstones
        let filt = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::Group.into()),
            FC::Or(
                affected_uuids
                    .iter()
                    .copied()
                    .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
                    .collect()
            )
        ]));

        // Clear the set for the next iteration
        affected_uuids.clear();

        let work_set = qs.internal_search_writeable(&filt)?;
        let mut changes = Vec::with_capacity(work_set.len());

        for (pre, mut tgte) in work_set.into_iter() {
            let guuid = pre.get_uuid();

            trace!(
                "=> processing group update -> {:?} {}",
                guuid,
                tgte.get_display_id()
            );

            do_group_memberof(qs, guuid, &mut tgte)?;

            // Did we change? Note we don't check if the class changed, only if mo changed.
            if pre.get_ava_set(Attribute::MemberOf) != tgte.get_ava_set(Attribute::MemberOf)
                || pre.get_ava_set(Attribute::DirectMemberOf)
                    != tgte.get_ava_set(Attribute::DirectMemberOf)
            {
                // Yes we changed - we now must process all our members, as they need to
                // inherit changes. Some of these members COULD be non groups, but we
                // handle them in the subsequent steps.
                trace!(
                    "{:?} {} changed, flagging members as groups to change. ",
                    guuid,
                    tgte.get_display_id()
                );

                // Since our groups memberof (and related, direct member of) has changed, we
                // need to propagate these values forward into our members. At this point we
                // mark all our members as being part of the affected set.
                let pre_member = pre.get_ava_refer(Attribute::Member);
                let post_member = tgte.get_ava_refer(Attribute::Member);

                match (pre_member, post_member) {
                    (Some(pre_m), Some(post_m)) => {
                        affected_uuids.extend(pre_m);
                        affected_uuids.extend(post_m);
                    }
                    (Some(members), None) | (None, Some(members)) => {
                        // Doesn't matter what order, just that they are affected
                        affected_uuids.extend(members);
                    }
                    (None, None) => {}
                };

                let pre_dynmember = pre.get_ava_refer(Attribute::DynMember);
                let post_dynmember = tgte.get_ava_refer(Attribute::DynMember);

                match (pre_dynmember, post_dynmember) {
                    (Some(pre_m), Some(post_m)) => {
                        affected_uuids.extend(pre_m);
                        affected_uuids.extend(post_m);
                    }
                    (Some(members), None) | (None, Some(members)) => {
                        // Doesn't matter what order, just that they are affected
                        affected_uuids.extend(members);
                    }
                    (None, None) => {}
                };

                // Time bounded members inherit our memberof while their grant is
                // valid. Validity is re-evaluated when the leaf/group is processed,
                // so we include every grant here.
                affected_uuids.extend(time_bounded_member_uuids(&pre));
                affected_uuids.extend(time_bounded_member_uuids(&tgte));

                // push the entries to pre/cand
                changes.push((pre, tgte));
            } else {
                // If the group is stable, then we *only* need to update memberof
                // on members that may have been added or removed. This exists to
                // optimise when we add a member to a group, but without changing the
                // group's mo/dmo to save re-writing mo to all the other members.
                //
                // If the group's memberof has been through the unstable state,
                // all our members are already fully loaded into the affected sets.
                //
                // NOTE: This filtering of what members were actually impacted is
                // performed in the call to post_modify_inner.

                trace!("{:?} {} stable", guuid, tgte.get_display_id());
            }
        }

        // Write this stripe if populated.
        if !changes.is_empty() {
            trace!("wrote stripe {}", changes.len());
            qs.internal_apply_writable(changes).map_err(|err| {
                error!(?err, "Failed to commit memberof group set");
                err
            })?;
        }

        // Reflect the full set of affected uuids into our all affected set.
        all_affected_uuids.extend(affected_uuids.iter());

        // Next loop!
        trace!("-------------------------------------");
    }

    // ALL GROUP MOS + DMOS ARE NOW STABLE. We can update oul leaf entries as required.
    do_leaf_memberof(qs, all_affected_uuids)
}

/// For each candidate, the groups where it is a member *only* through a time bounded
/// grant - that is, the group has a grant for it but does not list it in member or
/// dynmember.
fn time_bounded_only_memberships(
    qs: &mut QueryServerWriteTransaction,
    cand: &[EntryInvalidCommitted],
) -> Result<BTreeMap<Uuid, BTreeSet<Uuid>>, OperationError> {
    let mut time_bounded_only: BTreeMap<Uuid, BTreeSet<Uuid>> = BTreeMap::new();

    if !has_time_bounded_member_attr(qs) {
        return Ok(time_bounded_only);
    }

    let cand_uuids: BTreeSet<Uuid> = cand.iter().filter_map(|e| e.get_uuid()).collect();

    if cand_uuids.is_empty() {
        return Ok(time_bounded_only);
    }

    let groups = qs
        .internal_search(filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::Group.into()),
            FC::Or(
                cand_uuids
                    .iter()
                    .map(|u| f_eq(
                        Attribute::TimeBoundedMemberAttr,
                        PartialValue::TimeBoundedMember(*u)
                    ))
                    .collect()
            )
        ])))
        .inspect_err(|err| {
            error!(?err, "internal search failure");
        })?;

    for group in groups.iter() {
        let member_ref = group.get_ava_refer(Attribute::Member);
        let dynmember_ref = group.get_ava_refer(Attribute::DynMember);

        for member_uuid in time_bounded_member_uuids(group) {
            let is_permanent = member_ref.is_some_and(|set| set.contains(&member_uuid))
                || dynmember_ref.is_some_and(|set| set.contains(&member_uuid));

            if !is_permanent && cand_uuids.contains(&member_uuid) {
                time_bounded_only
                    .entry(member_uuid)
                    .or_default()
                    .insert(group.get_uuid());
            }
        }
    }

    Ok(time_bounded_only)
}

/// Time bounded grants are only evaluated when memberof is applied, so a grant that
/// expires or becomes active needs memberof to be recomputed at that point in time.
/// This finds every time bounded member whose reflected direct membership disagrees
/// with the validity of its grant at the transaction's current time, and recomputes
/// memberof for those members. Returns the number of members that were recomputed.
pub(crate) fn refresh_time_bounded_memberships(
    qs: &mut QueryServerWriteTransaction,
) -> Result<usize, OperationError> {
    if !has_time_bounded_member_attr(qs) {
        // Schema does not yet provide time bounded members, nothing to do.
        return Ok(0);
    }

    let now = qs.get_curtime_odt();

    let groups = qs
        .internal_search(filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::Group.into()),
            f_pres(Attribute::TimeBoundedMemberAttr)
        ])))
        .inspect_err(|err| {
            error!(?err, "internal search failure");
        })?;

    // member uuid -> (group uuid -> should the member currently have this group as dmo)
    let mut expected: BTreeMap<Uuid, BTreeMap<Uuid, bool>> = BTreeMap::new();

    for group in groups.iter() {
        let group_uuid = group.get_uuid();
        let Some(grants) = group
            .get_ava_set(Attribute::TimeBoundedMemberAttr)
            .and_then(|vs| vs.as_time_bounded_member_set())
        else {
            continue;
        };

        let member_ref = group.get_ava_refer(Attribute::Member);
        let dynmember_ref = group.get_ava_refer(Attribute::DynMember);
        let suppressed = time_bounded_grants_suppressed(group);

        for grant in grants.values() {
            // A permanent membership in the same group always takes precedence.
            let is_member = (grant.is_valid_at(now) && !suppressed)
                || member_ref.is_some_and(|set| set.contains(&grant.uuid))
                || dynmember_ref.is_some_and(|set| set.contains(&grant.uuid));

            expected
                .entry(grant.uuid)
                .or_default()
                .insert(group_uuid, is_member);
        }
    }

    if expected.is_empty() {
        return Ok(0);
    }

    // Only load the members that could be stale. A member that should be in a group
    // must be checked for the group being absent, so it is always loaded. A member that
    // should not be in a group can only be stale if it still has that group as a direct
    // memberof, which the index can answer for us. This keeps grants that expired long
    // ago (or are far in the future) from loading their members on every refresh.
    let member_filter: Vec<_> = expected
        .iter()
        .flat_map(|(member_uuid, groups)| {
            let member_uuid = *member_uuid;
            if groups.values().any(|is_member| *is_member) {
                vec![f_eq(Attribute::Uuid, PartialValue::Uuid(member_uuid))]
            } else {
                groups
                    .keys()
                    .map(|group_uuid| {
                        f_and(vec![
                            f_eq(Attribute::Uuid, PartialValue::Uuid(member_uuid)),
                            f_eq(Attribute::DirectMemberOf, PartialValue::Refer(*group_uuid)),
                        ])
                    })
                    .collect()
            }
        })
        .collect();

    let members = qs
        .internal_search(filter!(f_or(member_filter)))
        .inspect_err(|err| {
            error!(?err, "internal search failure");
        })?;

    let affected_uuids: BTreeSet<Uuid> = members
        .iter()
        .filter_map(|member| {
            let member_uuid = member.get_uuid();
            let groups = expected.get(&member_uuid)?;
            let dmo = member.get_ava_refer(Attribute::DirectMemberOf);

            let stale = groups.iter().any(|(group_uuid, is_member)| {
                let reflected = dmo.is_some_and(|set| set.contains(group_uuid));
                reflected != *is_member
            });

            stale.then_some(member_uuid)
        })
        .collect();

    if affected_uuids.is_empty() {
        trace!("time bounded memberships are up to date");
        return Ok(0);
    }

    let changed = affected_uuids.len();
    debug!(?affected_uuids, "refreshing time bounded memberships");

    apply_memberof(qs, affected_uuids)?;

    Ok(changed)
}

impl Plugin for MemberOf {
    fn id() -> &'static str {
        Attribute::MemberOf.as_ref()
    }

    #[instrument(level = "debug", name = "memberof_post_create", skip_all)]
    fn post_create(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::post_create_inner(qs, cand, &ce.ident)
    }

    #[instrument(level = "debug", name = "memberof_post_repl_refresh", skip_all)]
    fn post_repl_refresh(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
    ) -> Result<(), OperationError> {
        let ident = Identity::from_internal();
        Self::post_create_inner(qs, cand, &ident)
    }

    #[instrument(level = "debug", name = "memberof_post_repl_incremental", skip_all)]
    fn post_repl_incremental(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &[EntrySealedCommitted],
        conflict_uuids: &BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        // If a uuid was in a conflict state, it will be present in the cand/pre_cand set,
        // but it *may not* trigger dyn groups as the conflict before and after may satisfy
        // the filter as it exists.
        //
        // In these cases we need to force dynmembers to be reloaded if any conflict occurs
        // to ensure that all our memberships are accurate.
        let force_dyngroup_cand_update = !conflict_uuids.is_empty();

        // IMPORTANT - we need this for now so that dyngroup doesn't error on us, since
        // repl is internal and dyngroup has a safety check to prevent external triggers.
        let ident_internal = Identity::from_internal();
        Self::post_modify_inner(
            qs,
            pre_cand,
            cand,
            &ident_internal,
            force_dyngroup_cand_update,
        )
    }

    #[instrument(level = "debug", name = "memberof_post_modify", skip_all)]
    fn post_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, pre_cand, cand, &me.ident, false)
    }

    #[instrument(level = "debug", name = "memberof_post_batch_modify", skip_all)]
    fn post_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, pre_cand, cand, &me.ident, false)
    }

    #[instrument(level = "debug", name = "memberof_pre_delete", skip_all)]
    fn pre_delete(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<EntryInvalidCommitted>,
        _de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        // Ensure that when an entry is deleted, that we remove its memberof values,
        // and convert direct memberof to recycled direct memberof.

        // Revive restores recycled direct memberships as permanent members, so any
        // membership that only exists due to a time bounded grant must not be recorded,
        // else a revive would turn a temporary grant into a permanent membership.
        let time_bounded_only = time_bounded_only_memberships(qs, cand)?;

        for entry in cand.iter_mut() {
            if let Some(mut direct_mo_vs) = entry.pop_ava(Attribute::DirectMemberOf) {
                let exclude = entry
                    .get_uuid()
                    .and_then(|uuid| time_bounded_only.get(&uuid));
                if let (Some(exclude), Some(dmo_set)) = (exclude, direct_mo_vs.as_refer_set_mut()) {
                    dmo_set.retain(|g| !exclude.contains(g));
                }

                if direct_mo_vs.is_empty() {
                    entry.purge_ava(Attribute::RecycledDirectMemberOf);
                } else {
                    entry.set_ava_set(&Attribute::RecycledDirectMemberOf, direct_mo_vs);
                }
            } else {
                // Ensure it's empty
                entry.purge_ava(Attribute::RecycledDirectMemberOf);
            }
            entry.purge_ava(Attribute::MemberOf);
        }

        Ok(())
    }

    #[instrument(level = "debug", name = "memberof_post_delete", skip_all)]
    fn post_delete(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        let affected_uuids = cand
            .iter()
            .filter_map(|e| {
                if e.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
                    e.get_ava_as_refuuid(Attribute::Member)
                } else {
                    None
                }
            })
            .flatten()
            .chain(
                cand.iter()
                    .filter_map(|post| {
                        if post.attribute_equality(Attribute::Class, &EntryClass::DynGroup.into()) {
                            post.get_ava_as_refuuid(Attribute::DynMember)
                        } else {
                            None
                        }
                    })
                    .flatten(),
            )
            .chain(
                cand.iter()
                    .filter_map(|e| {
                        if e.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
                            e.get_ava_as_refuuid(Attribute::TimeBoundedMemberAttr)
                        } else {
                            None
                        }
                    })
                    .flatten(),
            )
            .collect();

        apply_memberof(qs, affected_uuids)
    }

    #[instrument(level = "debug", name = "memberof::verify", skip_all)]
    fn verify(qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        let mut r = Vec::with_capacity(0);

        let filt_in = filter!(f_pres(Attribute::Class));

        let all_cand = match qs
            .internal_search(filt_in)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(all_cand) => all_cand,
            Err(e) => return vec![e],
        };

        // First we have to build a direct membership map. This saves us
        // needing to run queries since we already have every entry on hand
        // from the all_cand search.
        let mut direct_membership_map: BTreeMap<Uuid, BTreeSet<Uuid>> = Default::default();

        // Time bounded grants are reflected according to their validity at the time
        // memberof was last applied (a write, or the periodic refresh). That time is not
        // the time of verification: refresh lags by up to PURGE_FREQUENCY, the server may
        // have been stopped, and verify also runs on restored backups (backup verification
        // and offline database verify) where no refresh happens at all. Checking that an
        // expired grant is absent, or that a grant which became active is present, would
        // falsely fail on all of these.
        //
        // What *is* sound is that memberof is never applied at a time after now. So:
        // - a grant with no start that ends after now was valid at every point memberof
        //   could have been applied, and the membership must be present.
        // - a grant that starts after now can never have been valid when memberof was
        //   applied, and the membership must be absent.
        // Any other grant may legitimately be in either state. A grace period derived from
        // the refresh interval absorbs clock adjustments between the writer and verify.
        let now = OffsetDateTime::UNIX_EPOCH + duration_from_epoch_now();
        let grace = std::time::Duration::from_secs(TIME_BOUNDED_VERIFY_GRACE);
        let required_after = now + grace;

        // Memberships that may be present or absent.
        let mut time_bounded_membership_map: BTreeMap<Uuid, BTreeSet<Uuid>> = Default::default();

        let pv_class: PartialValue = EntryClass::Group.into();

        for entry in all_cand.iter() {
            if !entry.attribute_equality(Attribute::Class, &pv_class) {
                // Not a group, move on.
                continue;
            }

            let group_uuid = entry.get_uuid();

            let member_iter = entry
                .get_ava_refer(Attribute::Member)
                .into_iter()
                .flat_map(|set| set.iter())
                .chain(
                    entry
                        .get_ava_refer(Attribute::DynMember)
                        .into_iter()
                        .flat_map(|set| set.iter()),
                );

            for member_uuid in member_iter {
                let member_groups = direct_membership_map.entry(*member_uuid).or_default();
                member_groups.insert(group_uuid);
            }

            let grants = entry
                .get_ava_set(Attribute::TimeBoundedMemberAttr)
                .and_then(|vs| vs.as_time_bounded_member_set())
                .into_iter()
                .flat_map(|map| map.values());
            // Kubidm: the grants of a high privilege group are inactive. A database written
            // before they were may still reflect them, so they may be in either state.
            let suppressed = time_bounded_grants_suppressed(entry);

            for grant in grants {
                match grant.valid_from {
                    _ if suppressed => {
                        time_bounded_membership_map
                            .entry(grant.uuid)
                            .or_default()
                            .insert(group_uuid);
                    }
                    None if grant.valid_until > required_after => {
                        // Must be present.
                        direct_membership_map
                            .entry(grant.uuid)
                            .or_default()
                            .insert(group_uuid);
                    }
                    Some(valid_from) if valid_from > required_after => {
                        // Must be absent (unless a permanent membership requires it).
                    }
                    _ => {
                        time_bounded_membership_map
                            .entry(grant.uuid)
                            .or_default()
                            .insert(group_uuid);
                    }
                }
            }
        }

        // for each entry in the DB (live).
        for e in all_cand {
            let uuid = e.get_uuid();

            let d_groups_set: Option<&BTreeSet<Uuid>> = direct_membership_map.get(&uuid);
            let tb_groups_set: Option<&BTreeSet<Uuid>> = time_bounded_membership_map.get(&uuid);

            trace!(
                "DMO search groups {:?} -> {:?} (time bounded {:?})",
                e.get_display_id(),
                d_groups_set,
                tb_groups_set
            );

            // Remember, we only need to check direct memberships, because when memberof
            // it applies it clones dmo -> mo, so validation of all dmo sets implies mo is
            // valid (and a subset) of dmo.

            // Disregard optional time bounded memberships in the entry's dmo that are not
            // also required. What remains must exactly match the expected set.
            let edmos = e.get_ava_set(Attribute::DirectMemberOf).map(|edmos| {
                edmos.as_refer_set().map(|a| {
                    a.iter()
                        .filter(|g| {
                            d_groups_set.is_some_and(|b| b.contains(g))
                                || !tb_groups_set.is_some_and(|t| t.contains(g))
                        })
                        .copied()
                        .collect::<BTreeSet<Uuid>>()
                })
            });
            let edmos = match edmos {
                Some(Some(a)) if a.is_empty() => None,
                other => other,
            };

            match (edmos, d_groups_set) {
                (Some(edmos), Some(b)) => {
                    // Can they both be reference sets?
                    match edmos {
                        Some(a) => {
                            let diff: Vec<_> = a.symmetric_difference(b).collect();
                            if !diff.is_empty() {
                                error!(
                                    "MemberOfInvalid: Entry {}, DMO has inconsistencies",
                                    e.get_display_id(),
                                );
                                trace!(entry_direct_member_of = ?a);
                                trace!(expected_direct_groups = ?b);
                                trace!(?diff);

                                r.push(Err(ConsistencyError::MemberOfInvalid(e.get_id())));
                            }
                        }
                        _ => {
                            error!("MemberOfInvalid: Entry {}, DMO has incorrect syntax - should be reference uuid set", e.get_display_id());
                            r.push(Err(ConsistencyError::MemberOfInvalid(e.get_id())));
                        }
                    }
                }
                (None, None) => {
                    // Ok
                }
                (entry_direct_member_of, expected_direct_groups) => {
                    error!(
                        "MemberOfInvalid directmemberof set and DMO search set differ in presence: {}",
                        e.get_display_id()
                    );
                    // trace!(?e);
                    trace!(?entry_direct_member_of);
                    trace!(?expected_direct_groups);
                    r.push(Err(ConsistencyError::MemberOfInvalid(e.get_id())));
                }
            }
        }

        r
    }
}

impl MemberOf {
    fn post_create_inner(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        ident: &Identity,
    ) -> Result<(), OperationError> {
        let dyngroup_change = super::dyngroup::DynGroup::post_create(qs, cand, ident)?;

        let affected_uuids = cand
            .iter()
            .map(|e| e.get_uuid())
            .chain(dyngroup_change)
            .chain(
                cand.iter()
                    .filter_map(|e| {
                        if e.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
                            e.get_ava_as_refuuid(Attribute::Member)
                        } else {
                            None
                        }
                    })
                    .flatten(),
            )
            .chain(
                cand.iter()
                    .filter_map(|e| {
                        if e.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
                            e.get_ava_as_refuuid(Attribute::TimeBoundedMemberAttr)
                        } else {
                            None
                        }
                    })
                    .flatten(),
            )
            .collect();

        apply_memberof(qs, affected_uuids)
    }

    fn post_modify_inner(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &[EntrySealedCommitted],
        ident: &Identity,
        force_dyngroup_cand_update: bool,
    ) -> Result<(), OperationError> {
        let dyngroup_change = super::dyngroup::DynGroup::post_modify(
            qs,
            pre_cand,
            cand,
            ident,
            force_dyngroup_cand_update,
        )?;

        let mut affected_uuids: BTreeSet<_> = cand
            .iter()
            .map(|post| post.get_uuid())
            .chain(dyngroup_change)
            .collect();

        for (pre, post) in pre_cand.iter().zip(cand.iter()).filter(|(pre, post)| {
            post.attribute_equality(Attribute::Class, &EntryClass::Group.into())
                || pre.attribute_equality(Attribute::Class, &EntryClass::Group.into())
        }) {
            let pre_member = pre.get_ava_refer(Attribute::Member);
            let post_member = post.get_ava_refer(Attribute::Member);

            match (pre_member, post_member) {
                (Some(pre_m), Some(post_m)) => {
                    affected_uuids.extend(pre_m.symmetric_difference(post_m));
                }
                (Some(members), None) | (None, Some(members)) => {
                    affected_uuids.extend(members);
                }
                (None, None) => {}
            };

            let pre_dynmember = pre.get_ava_refer(Attribute::DynMember);
            let post_dynmember = post.get_ava_refer(Attribute::DynMember);

            match (pre_dynmember, post_dynmember) {
                (Some(pre_m), Some(post_m)) => {
                    affected_uuids.extend(pre_m.symmetric_difference(post_m));
                }
                (Some(members), None) | (None, Some(members)) => {
                    affected_uuids.extend(members);
                }
                (None, None) => {}
            };

            // Compare the full grant, not just the member uuid, so that a change to
            // the validity window of an existing grant also recomputes memberof.
            let pre_time_bounded = time_bounded_grants(pre);
            let post_time_bounded = time_bounded_grants(post);

            affected_uuids.extend(
                pre_time_bounded
                    .symmetric_difference(&post_time_bounded)
                    .map(|(uuid, _, _)| *uuid),
            );
        }

        apply_memberof(qs, affected_uuids)
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    const UUID_A: Uuid = uuid::uuid!("aaaaaaaa-f82e-4484-a407-181aa03bda5c");
    const UUID_B: Uuid = uuid::uuid!("bbbbbbbb-2438-4384-9891-48f4c8172e9b");
    const UUID_C: Uuid = uuid::uuid!("cccccccc-9b01-423f-9ba6-51aa4bbd5dd2");
    const UUID_D: Uuid = uuid::uuid!("dddddddd-2ab3-48e3-938d-1b4754cd2984");

    static EA: LazyLock<EntryInitNew> = LazyLock::new(|| {
        entry_init_fn([
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::MemberOf.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_a")),
            (Attribute::Uuid, Value::Uuid(UUID_A)),
        ])
    });
    static EB: LazyLock<EntryInitNew> = LazyLock::new(|| {
        entry_init_fn([
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::MemberOf.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_b")),
            (Attribute::Uuid, Value::Uuid(UUID_B)),
        ])
    });
    static EC: LazyLock<EntryInitNew> = LazyLock::new(|| {
        entry_init_fn([
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::MemberOf.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_c")),
            (Attribute::Uuid, Value::Uuid(UUID_C)),
        ])
    });
    static ED: LazyLock<EntryInitNew> = LazyLock::new(|| {
        entry_init_fn([
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::MemberOf.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_d")),
            (Attribute::Uuid, Value::Uuid(UUID_D)),
        ])
    });

    macro_rules! assert_memberof_int {
        (
            $qs:expr,
            $ea:expr,
            $eb:expr,
            $mo:expr,
            $cand:expr
        ) => {{
            let filt = filter!(f_and!([
                f_eq(Attribute::Uuid, PartialValue::Uuid($ea)),
                f_eq($mo, PartialValue::Refer($eb))
            ]));
            let cands = $qs.internal_search(filt).expect("Internal search failure");
            debug!("assert_mo_cands {:?}", cands);
            assert_eq!(cands.len(), $cand);
        }};
    }

    macro_rules! assert_memberof {
        (
            $qs:expr,
            $ea:expr,
            $eb:expr
        ) => {{
            assert_memberof_int!($qs, $ea, $eb, Attribute::MemberOf, 1);
        }};
    }

    macro_rules! assert_dirmemberof {
        (
            $qs:expr,
            $ea:expr,
            $eb:expr
        ) => {{
            assert_memberof_int!($qs, $ea, $eb, Attribute::DirectMemberOf, 1);
        }};
    }

    macro_rules! assert_not_memberof {
        (
            $qs:expr,
            $ea:expr,
            $eb:expr
        ) => {{
            assert_memberof_int!($qs, $ea, $eb, Attribute::MemberOf, 0);
        }};
    }

    macro_rules! assert_not_dirmemberof {
        (
            $qs:expr,
            $ea:expr,
            $eb:expr
        ) => {{
            assert_memberof_int!($qs, $ea, $eb, Attribute::DirectMemberOf, 0);
        }};
    }

    #[test]
    fn test_create_mo_single() {
        // A -> B
        let mut ea = EA.clone();
        let eb = EB.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));

        let preload = Vec::with_capacity(0);
        let create = vec![ea, eb];
        run_create_test!(
            Ok(None),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
            }
        );
    }

    #[test]
    fn test_create_mo_nested() {
        // A -> B -> C
        let mut ea = EA.clone();

        let mut eb = EB.clone();

        let ec = EC.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::Member, Value::ReferN(UUID_C));

        let preload = Vec::with_capacity(0);
        let create = vec![ea, eb, ec];
        run_create_test!(
            Ok(None),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                // This is due to nestig, C should be MO both!
                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_create_mo_cycle() {
        // A -> B -> C -
        // ^-----------/
        let mut ea = EA.clone();

        let mut eb = EB.clone();

        let mut ec = EC.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::Member, Value::ReferN(UUID_C));
        ec.add_ava(Attribute::Member, Value::ReferN(UUID_A));

        let preload = Vec::with_capacity(0);
        let create = vec![ea, eb, ec];
        run_create_test!(
            Ok(None),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(qs, UUID_A, UUID_A);
                assert_memberof!(qs, UUID_A, UUID_B);
                assert_memberof!(qs, UUID_A, UUID_C);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_memberof!(qs, UUID_B, UUID_B);
                assert_memberof!(qs, UUID_B, UUID_C);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_dirmemberof!(qs, UUID_A, UUID_C);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_create_mo_multi_cycle() {
        // A -> B -> C --> D -
        // ^-----------/    /
        // |---------------/
        let mut ea = EA.clone();

        let mut eb = EB.clone();

        let mut ec = EC.clone();

        let mut ed = ED.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::Member, Value::ReferN(UUID_C));

        ec.add_ava(Attribute::Member, Value::ReferN(UUID_A));
        ec.add_ava(Attribute::Member, Value::ReferN(UUID_D));

        ed.add_ava(Attribute::Member, Value::ReferN(UUID_A));

        let preload = Vec::with_capacity(0);
        let create = vec![ea, eb, ec, ed];
        run_create_test!(
            Ok(None),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(qs, UUID_A, UUID_A);
                assert_memberof!(qs, UUID_A, UUID_B);
                assert_memberof!(qs, UUID_A, UUID_C);
                assert_memberof!(qs, UUID_A, UUID_D);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_memberof!(qs, UUID_B, UUID_B);
                assert_memberof!(qs, UUID_B, UUID_C);
                assert_memberof!(qs, UUID_B, UUID_D);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_memberof!(qs, UUID_C, UUID_C);
                assert_memberof!(qs, UUID_C, UUID_D);

                assert_memberof!(qs, UUID_D, UUID_A);
                assert_memberof!(qs, UUID_D, UUID_B);
                assert_memberof!(qs, UUID_D, UUID_C);
                assert_memberof!(qs, UUID_D, UUID_D);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_dirmemberof!(qs, UUID_A, UUID_C);
                assert_dirmemberof!(qs, UUID_A, UUID_D);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);
                assert_not_dirmemberof!(qs, UUID_B, UUID_D);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
                assert_not_dirmemberof!(qs, UUID_C, UUID_D);

                assert_not_dirmemberof!(qs, UUID_D, UUID_A);
                assert_not_dirmemberof!(qs, UUID_D, UUID_B);
                assert_dirmemberof!(qs, UUID_D, UUID_C);
                assert_not_dirmemberof!(qs, UUID_D, UUID_D);
            }
        );
    }

    #[test]
    fn test_modify_mo_add_simple() {
        // A    B
        // Add member
        // A -> B
        let ea = EA.clone();
        let eb = EB.clone();

        let preload = vec![ea, eb];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_A))),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member,
                Value::ReferN(UUID_B)
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
            }
        );
    }

    #[test]
    fn test_modify_mo_add_nested_1() {
        // A    B -> C
        // Add member A -> B
        // A -> B -> C
        let ea = EA.clone();
        let mut eb = EB.clone();
        let ec = EC.clone();

        eb.add_ava(Attribute::Member, Value::ReferN(UUID_C));

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_A))),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member,
                Value::ReferN(UUID_B)
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_modify_mo_add_nested_2() {
        // A -> B    C
        // Add member B -> C
        // A -> B -> C
        let mut ea = EA.clone();
        let eb = EB.clone();
        let ec = EC.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_B))),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member,
                Value::ReferN(UUID_C)
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_modify_mo_add_cycle() {
        // A -> B -> C
        //
        // Add member C -> A
        // A -> B -> C -
        // ^-----------/
        let mut ea = EA.clone();
        let mut eb = EB.clone();
        let ec = EC.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::Member, Value::ReferN(UUID_C));

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_C))),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member,
                Value::ReferN(UUID_A)
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(qs, UUID_A, UUID_A);
                assert_memberof!(qs, UUID_A, UUID_B);
                assert_memberof!(qs, UUID_A, UUID_C);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_memberof!(qs, UUID_B, UUID_B);
                assert_memberof!(qs, UUID_B, UUID_C);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_dirmemberof!(qs, UUID_A, UUID_C);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_modify_mo_add_multi_cycle() {
        // A -> B -> C --> D
        //
        // Add member C -> A
        // Add member C -> D
        // Add member D -> A
        //
        // A -> B -> C --> D -
        // ^-----------/    /
        // |---------------/
        let mut ea = EA.clone();
        let mut eb = EB.clone();
        let mut ec = EC.clone();
        let ed = ED.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::Member, Value::ReferN(UUID_C));
        ec.add_ava(Attribute::Member, Value::ReferN(UUID_D));

        let preload = vec![ea, eb, ec, ed];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_or!([
                f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_C)),
                f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_D)),
            ])),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member,
                Value::ReferN(UUID_A)
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(qs, UUID_A, UUID_A);
                assert_memberof!(qs, UUID_A, UUID_B);
                assert_memberof!(qs, UUID_A, UUID_C);
                assert_memberof!(qs, UUID_A, UUID_D);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_memberof!(qs, UUID_B, UUID_B);
                assert_memberof!(qs, UUID_B, UUID_C);
                assert_memberof!(qs, UUID_B, UUID_D);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_memberof!(qs, UUID_C, UUID_C);
                assert_memberof!(qs, UUID_C, UUID_D);

                assert_memberof!(qs, UUID_D, UUID_A);
                assert_memberof!(qs, UUID_D, UUID_B);
                assert_memberof!(qs, UUID_D, UUID_C);
                assert_memberof!(qs, UUID_D, UUID_D);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_dirmemberof!(qs, UUID_A, UUID_C);
                assert_dirmemberof!(qs, UUID_A, UUID_D);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);
                assert_not_dirmemberof!(qs, UUID_B, UUID_D);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
                assert_not_dirmemberof!(qs, UUID_C, UUID_D);

                assert_not_dirmemberof!(qs, UUID_D, UUID_A);
                assert_not_dirmemberof!(qs, UUID_D, UUID_B);
                assert_dirmemberof!(qs, UUID_D, UUID_C);
                assert_not_dirmemberof!(qs, UUID_D, UUID_D);
            }
        );
    }

    #[test]
    fn test_modify_mo_del_simple() {
        // A -> B
        // remove member A -> B
        // A    B
        let mut ea = EA.clone();
        let mut eb = EB.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));

        let preload = vec![ea, eb];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_A))),
            ModifyList::new_list(vec![Modify::Removed(
                Attribute::Member,
                PartialValue::Refer(UUID_B)
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);

                assert_not_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
            }
        );
    }

    #[test]
    fn test_modify_mo_del_nested_1() {
        // A -> B -> C
        // Remove A -> B
        // A    B -> C
        let mut ea = EA.clone();
        let mut eb = EB.clone();
        let mut ec = EC.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));
        eb.add_ava(Attribute::Member, Value::ReferN(UUID_C));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_A))),
            ModifyList::new_list(vec![Modify::Removed(
                Attribute::Member,
                PartialValue::Refer(UUID_B)
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);

                assert_not_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                assert_not_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);

                assert_not_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_modify_mo_del_nested_2() {
        // A -> B -> C
        // Remove B -> C
        // A -> B    C
        let mut ea = EA.clone();
        let mut eb = EB.clone();
        let mut ec = EC.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));
        eb.add_ava(Attribute::Member, Value::ReferN(UUID_C));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_B))),
            ModifyList::new_list(vec![Modify::Removed(
                Attribute::Member,
                PartialValue::Refer(UUID_C)
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                assert_not_memberof!(qs, UUID_C, UUID_A);
                assert_not_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_not_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_modify_mo_del_cycle() {
        // A -> B -> C -
        // ^-----------/
        // Remove C -> A
        // A -> B -> C
        let mut ea = EA.clone();
        let mut eb = EB.clone();
        let mut ec = EC.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        ea.add_ava(Attribute::MemberOf, Value::ReferN(UUID_C));
        ea.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        ea.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));

        eb.add_ava(Attribute::Member, Value::ReferN(UUID_C));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_C));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));

        ec.add_ava(Attribute::Member, Value::ReferN(UUID_A));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_C));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_C))),
            ModifyList::new_list(vec![Modify::Removed(
                Attribute::Member,
                PartialValue::Refer(UUID_A)
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_modify_mo_del_multi_cycle() {
        // A -> B -> C --> D -
        // ^-----------/    /
        // |---------------/
        //
        // Remove C -> D
        // Remove C -> A
        //
        // A -> B -> C    D -
        // ^                /
        // |---------------/
        let mut ea = EA.clone();
        let mut eb = EB.clone();
        let mut ec = EC.clone();
        let mut ed = ED.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        ea.add_ava(Attribute::MemberOf, Value::ReferN(UUID_D));
        ea.add_ava(Attribute::MemberOf, Value::ReferN(UUID_C));
        ea.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        ea.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));

        eb.add_ava(Attribute::Member, Value::ReferN(UUID_C));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_D));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_C));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));

        ec.add_ava(Attribute::Member, Value::ReferN(UUID_A));
        ec.add_ava(Attribute::Member, Value::ReferN(UUID_D));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_D));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_C));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));

        ed.add_ava(Attribute::Member, Value::ReferN(UUID_A));
        ed.add_ava(Attribute::MemberOf, Value::ReferN(UUID_D));
        ed.add_ava(Attribute::MemberOf, Value::ReferN(UUID_C));
        ed.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        ed.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));

        let preload = vec![ea, eb, ec, ed];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_C))),
            ModifyList::new_list(vec![
                Modify::Removed(Attribute::Member, PartialValue::Refer(UUID_A)),
                Modify::Removed(Attribute::Member, PartialValue::Refer(UUID_D)),
            ]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);
                assert_memberof!(qs, UUID_A, UUID_D);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);
                assert_memberof!(qs, UUID_B, UUID_D);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);
                assert_memberof!(qs, UUID_C, UUID_D);

                assert_not_memberof!(qs, UUID_D, UUID_A);
                assert_not_memberof!(qs, UUID_D, UUID_B);
                assert_not_memberof!(qs, UUID_D, UUID_C);
                assert_not_memberof!(qs, UUID_D, UUID_D);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);
                assert_dirmemberof!(qs, UUID_A, UUID_D);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);
                assert_not_dirmemberof!(qs, UUID_B, UUID_D);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
                assert_not_dirmemberof!(qs, UUID_C, UUID_D);

                assert_not_dirmemberof!(qs, UUID_D, UUID_A);
                assert_not_dirmemberof!(qs, UUID_D, UUID_B);
                assert_not_dirmemberof!(qs, UUID_D, UUID_C);
                assert_not_dirmemberof!(qs, UUID_D, UUID_D);
            }
        );
    }

    #[test]
    fn test_delete_mo_simple() {
        // X -> B
        let mut ea = EA.clone();
        let mut eb = EB.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));

        let preload = vec![ea, eb];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_A))),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);

                assert_not_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
            }
        );
    }

    #[test]
    fn test_delete_mo_nested_head() {
        // X -> B -> C
        let mut ea = EA.clone();
        let mut eb = EB.clone();
        let mut ec = EC.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));

        eb.add_ava(Attribute::Member, Value::ReferN(UUID_C));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));

        let preload = vec![ea, eb, ec];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_A))),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                assert_not_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_delete_mo_nested_branch() {
        // A -> X -> C
        let mut ea = EA.clone();
        let mut eb = EB.clone();
        let mut ec = EC.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));

        eb.add_ava(Attribute::Member, Value::ReferN(UUID_C));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));

        let preload = vec![ea, eb, ec];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_B))),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);

                assert_not_memberof!(qs, UUID_C, UUID_A);
                assert_not_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_not_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_delete_mo_cycle() {
        // X -> B -> C -
        // ^-----------/
        let mut ea = EA.clone();
        let mut eb = EB.clone();
        let mut ec = EC.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        ea.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));
        ea.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        ea.add_ava(Attribute::MemberOf, Value::ReferN(UUID_C));

        eb.add_ava(Attribute::Member, Value::ReferN(UUID_C));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_C));

        ec.add_ava(Attribute::Member, Value::ReferN(UUID_A));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_C));

        let preload = vec![ea, eb, ec];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_A))),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                assert_not_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_delete_mo_multi_cycle() {
        // A -> X -> C --> D -
        // ^-----------/    /
        // |---------------/
        let mut ea = EA.clone();
        let mut eb = EB.clone();
        let mut ec = EC.clone();
        let mut ed = ED.clone();

        ea.add_ava(Attribute::Member, Value::ReferN(UUID_B));
        ea.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));
        ea.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        ea.add_ava(Attribute::MemberOf, Value::ReferN(UUID_C));
        ea.add_ava(Attribute::MemberOf, Value::ReferN(UUID_D));

        eb.add_ava(Attribute::Member, Value::ReferN(UUID_C));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_C));
        eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_D));

        ec.add_ava(Attribute::Member, Value::ReferN(UUID_A));
        ec.add_ava(Attribute::Member, Value::ReferN(UUID_D));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_C));
        ec.add_ava(Attribute::MemberOf, Value::ReferN(UUID_D));

        ed.add_ava(Attribute::Member, Value::ReferN(UUID_A));
        ed.add_ava(Attribute::MemberOf, Value::ReferN(UUID_A));
        ed.add_ava(Attribute::MemberOf, Value::ReferN(UUID_B));
        ed.add_ava(Attribute::MemberOf, Value::ReferN(UUID_C));
        ed.add_ava(Attribute::MemberOf, Value::ReferN(UUID_D));

        let preload = vec![ea, eb, ec, ed];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_B))),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_memberof!(qs, UUID_A, UUID_C);
                assert_memberof!(qs, UUID_A, UUID_D);

                assert_not_memberof!(qs, UUID_C, UUID_A);
                assert_not_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);
                assert_not_memberof!(qs, UUID_C, UUID_D);

                assert_not_memberof!(qs, UUID_D, UUID_A);
                assert_not_memberof!(qs, UUID_D, UUID_B);
                assert_memberof!(qs, UUID_D, UUID_C);
                assert_not_memberof!(qs, UUID_D, UUID_D);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_dirmemberof!(qs, UUID_A, UUID_C);
                assert_dirmemberof!(qs, UUID_A, UUID_D);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_not_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
                assert_not_dirmemberof!(qs, UUID_C, UUID_D);

                assert_not_dirmemberof!(qs, UUID_D, UUID_A);
                assert_not_dirmemberof!(qs, UUID_C, UUID_B);
                assert_dirmemberof!(qs, UUID_D, UUID_C);
                assert_not_dirmemberof!(qs, UUID_D, UUID_D);
            }
        );
    }

    mod time_bounded_member_tests {
        use crate::prelude::*;
        use crate::value::TimeBoundedMember;
        use std::time::Duration;
        use time::OffsetDateTime;

        const UUID_TB_A: Uuid = uuid::uuid!("aaaaaaaa-f82e-4484-a407-181aa03bda5c");
        const UUID_TB_B: Uuid = uuid::uuid!("bbbbbbbb-2438-4384-9891-48f4c8172e9b");
        const UUID_TB_C: Uuid = uuid::uuid!("cccccccc-9b01-423f-9ba6-51aa4bbd5dd2");

        static EA_TB: LazyLock<EntryInitNew> = LazyLock::new(|| {
            entry_init_fn([
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Class, EntryClass::TimeBoundedGrant.to_value()),
                (Attribute::Class, EntryClass::MemberOf.to_value()),
                (Attribute::Name, Value::new_iname("testgroup_tb_a")),
                (Attribute::Uuid, Value::Uuid(UUID_TB_A)),
            ])
        });

        static EB_TB: LazyLock<EntryInitNew> = LazyLock::new(|| {
            entry_init_fn([
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Class, EntryClass::MemberOf.to_value()),
                (Attribute::Name, Value::new_iname("testgroup_tb_b")),
                (Attribute::Uuid, Value::Uuid(UUID_TB_B)),
            ])
        });

        static EC_TB: LazyLock<EntryInitNew> = LazyLock::new(|| {
            entry_init_fn([
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Class, EntryClass::MemberOf.to_value()),
                (Attribute::Name, Value::new_iname("testgroup_tb_c")),
                (Attribute::Uuid, Value::Uuid(UUID_TB_C)),
            ])
        });

        #[test]
        fn test_create_time_bounded_member_valid() {
            let mut ea = EA_TB.clone();
            let eb = EB_TB.clone();

            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                Value::TimeBoundedMember(TimeBoundedMember::new(
                    UUID_TB_B,
                    None,
                    OffsetDateTime::UNIX_EPOCH + Duration::from_secs(100_000_000_000),
                )),
            );

            let preload = Vec::new();
            let create = vec![ea, eb];

            run_create_test!(
                Ok(None),
                preload,
                create,
                None,
                |qs: &mut QueryServerWriteTransaction| {
                    assert_memberof!(qs, UUID_TB_B, UUID_TB_A);
                    assert_dirmemberof!(qs, UUID_TB_B, UUID_TB_A);
                }
            );
        }

        #[test]
        fn test_create_time_bounded_member_with_immediate_start() {
            let mut ea = EA_TB.clone();
            let eb = EB_TB.clone();

            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                Value::TimeBoundedMember(TimeBoundedMember::new(
                    UUID_TB_B,
                    None,
                    OffsetDateTime::UNIX_EPOCH + Duration::from_secs(100_000_000_000),
                )),
            );

            let preload = Vec::new();
            let create = vec![ea, eb];

            run_create_test!(
                Ok(None),
                preload,
                create,
                None,
                |qs: &mut QueryServerWriteTransaction| {
                    assert_memberof!(qs, UUID_TB_B, UUID_TB_A);
                    assert_dirmemberof!(qs, UUID_TB_B, UUID_TB_A);
                }
            );
        }

        #[test]
        fn test_create_time_bounded_member_nested_valid() {
            let mut ea = EA_TB.clone();
            let mut eb = entry_init_fn([
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Class, EntryClass::TimeBoundedGrant.to_value()),
                (Attribute::Class, EntryClass::MemberOf.to_value()),
                (Attribute::Name, Value::new_iname("testgroup_tb_b")),
                (Attribute::Uuid, Value::Uuid(UUID_TB_B)),
            ]);
            let ec = EC_TB.clone();

            ea.add_ava(Attribute::Member, Value::ReferN(UUID_TB_B));
            eb.add_ava(
                Attribute::TimeBoundedMemberAttr,
                Value::TimeBoundedMember(TimeBoundedMember::new(
                    UUID_TB_C,
                    None,
                    OffsetDateTime::UNIX_EPOCH + Duration::from_secs(100_000_000_000),
                )),
            );

            let preload = Vec::new();
            let create = vec![ea, eb, ec];

            run_create_test!(
                Ok(None),
                preload,
                create,
                None,
                |qs: &mut QueryServerWriteTransaction| {
                    assert_memberof!(qs, UUID_TB_B, UUID_TB_A);
                    assert_memberof!(qs, UUID_TB_C, UUID_TB_B);
                    assert_dirmemberof!(qs, UUID_TB_B, UUID_TB_A);
                    assert_dirmemberof!(qs, UUID_TB_C, UUID_TB_B);
                }
            );
        }

        #[test]
        fn test_create_time_bounded_member_multiple_members() {
            let mut ea = EA_TB.clone();
            let eb = EB_TB.clone();
            let ec = EC_TB.clone();

            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                Value::TimeBoundedMember(TimeBoundedMember::new(
                    UUID_TB_B,
                    None,
                    OffsetDateTime::UNIX_EPOCH + Duration::from_secs(100_000_000_000),
                )),
            );
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                Value::TimeBoundedMember(TimeBoundedMember::new(
                    UUID_TB_C,
                    None,
                    OffsetDateTime::UNIX_EPOCH + Duration::from_secs(100_000_000_000),
                )),
            );

            let preload = Vec::new();
            let create = vec![ea, eb, ec];

            run_create_test!(
                Ok(None),
                preload,
                create,
                None,
                |qs: &mut QueryServerWriteTransaction| {
                    assert_memberof!(qs, UUID_TB_B, UUID_TB_A);
                    assert_memberof!(qs, UUID_TB_C, UUID_TB_A);
                    assert_dirmemberof!(qs, UUID_TB_B, UUID_TB_A);
                    assert_dirmemberof!(qs, UUID_TB_C, UUID_TB_A);
                }
            );
        }

        #[test]
        fn test_create_time_bounded_member_with_regular_member() {
            let mut ea = EA_TB.clone();
            let mut eb = entry_init_fn([
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Class, EntryClass::TimeBoundedGrant.to_value()),
                (Attribute::Class, EntryClass::MemberOf.to_value()),
                (Attribute::Name, Value::new_iname("testgroup_tb_b")),
                (Attribute::Uuid, Value::Uuid(UUID_TB_B)),
            ]);
            let ec = EC_TB.clone();

            ea.add_ava(Attribute::Member, Value::ReferN(UUID_TB_B));
            eb.add_ava(
                Attribute::TimeBoundedMemberAttr,
                Value::TimeBoundedMember(TimeBoundedMember::new(
                    UUID_TB_C,
                    None,
                    OffsetDateTime::UNIX_EPOCH + Duration::from_secs(100_000_000_000),
                )),
            );

            let preload = Vec::new();
            let create = vec![ea, eb, ec];

            run_create_test!(
                Ok(None),
                preload,
                create,
                None,
                |qs: &mut QueryServerWriteTransaction| {
                    assert_memberof!(qs, UUID_TB_B, UUID_TB_A);
                    assert_memberof!(qs, UUID_TB_C, UUID_TB_B);
                    assert_dirmemberof!(qs, UUID_TB_B, UUID_TB_A);
                    assert_dirmemberof!(qs, UUID_TB_C, UUID_TB_B);
                }
            );
        }

        #[test]
        fn test_create_time_bounded_member_default_expiration() {
            let mut ea = EA_TB.clone();
            let eb = EB_TB.clone();

            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                Value::TimeBoundedMember(TimeBoundedMember::new(
                    UUID_TB_B,
                    None,
                    OffsetDateTime::UNIX_EPOCH + Duration::from_secs(100_000_000_000),
                )),
            );

            let preload = Vec::new();
            let create = vec![ea, eb];

            run_create_test!(
                Ok(None),
                preload,
                create,
                None,
                |qs: &mut QueryServerWriteTransaction| {
                    assert_memberof!(qs, UUID_TB_B, UUID_TB_A);
                }
            );
        }

        #[test]
        fn test_create_time_bounded_member_with_specific_start() {
            let mut ea = EA_TB.clone();
            let eb = EB_TB.clone();

            let start_time = OffsetDateTime::UNIX_EPOCH + Duration::from_secs(60);

            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                Value::TimeBoundedMember(TimeBoundedMember::new(
                    UUID_TB_B,
                    Some(start_time),
                    OffsetDateTime::UNIX_EPOCH + Duration::from_secs(100_000_000_000),
                )),
            );

            let preload = Vec::new();
            let create = vec![ea, eb];

            run_create_test!(
                Ok(None),
                preload,
                create,
                None,
                |qs: &mut QueryServerWriteTransaction| {
                    assert_memberof!(qs, UUID_TB_B, UUID_TB_A);
                }
            );
        }

        #[test]
        fn test_modify_add_time_bounded_member() {
            let ea = EA_TB.clone();
            let eb = EB_TB.clone();

            let preload = vec![ea, eb];

            run_modify_test!(
                Ok(()),
                preload,
                filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_TB_A))),
                ModifyList::new_list(vec![Modify::Present(
                    Attribute::TimeBoundedMemberAttr,
                    Value::TimeBoundedMember(TimeBoundedMember::new(
                        UUID_TB_B,
                        None,
                        OffsetDateTime::UNIX_EPOCH + Duration::from_secs(100_000_000_000)
                    )),
                )]),
                None,
                |_| {},
                |qs: &mut QueryServerWriteTransaction| {
                    assert_memberof!(qs, UUID_TB_B, UUID_TB_A);
                    assert_dirmemberof!(qs, UUID_TB_B, UUID_TB_A);
                }
            );
        }

        #[test]
        fn test_modify_remove_time_bounded_member() {
            let mut ea = EA_TB.clone();
            let mut eb = EB_TB.clone();

            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                Value::TimeBoundedMember(TimeBoundedMember::new(
                    UUID_TB_B,
                    None,
                    OffsetDateTime::UNIX_EPOCH + Duration::from_secs(100_000_000_000),
                )),
            );
            eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_TB_A));
            eb.add_ava(Attribute::DirectMemberOf, Value::ReferN(UUID_TB_A));

            let preload = vec![ea, eb];

            run_modify_test!(
                Ok(()),
                preload,
                filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_TB_A))),
                ModifyList::new_list(vec![Modify::Removed(
                    Attribute::TimeBoundedMemberAttr,
                    PartialValue::TimeBoundedMember(UUID_TB_B),
                )]),
                None,
                |_| {},
                |qs: &mut QueryServerWriteTransaction| {
                    assert_not_memberof!(qs, UUID_TB_B, UUID_TB_A);
                    assert_not_dirmemberof!(qs, UUID_TB_B, UUID_TB_A);
                }
            );
        }

        #[test]
        fn test_delete_group_with_time_bounded_member() {
            let mut ea = EA_TB.clone();
            let mut eb = EB_TB.clone();

            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                Value::TimeBoundedMember(TimeBoundedMember::new(
                    UUID_TB_B,
                    None,
                    OffsetDateTime::UNIX_EPOCH + Duration::from_secs(100_000_000_000),
                )),
            );
            eb.add_ava(Attribute::MemberOf, Value::ReferN(UUID_TB_A));

            let preload = vec![ea, eb];

            run_delete_test!(
                Ok(()),
                preload,
                filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_TB_A))),
                None,
                |qs: &mut QueryServerWriteTransaction| {
                    assert_not_memberof!(qs, UUID_TB_B, UUID_TB_A);
                    assert_not_dirmemberof!(qs, UUID_TB_B, UUID_TB_A);
                }
            );
        }

        #[test]
        fn test_time_bounded_member_overlapping_windows() {
            let mut ea = EA_TB.clone();
            let eb = EB_TB.clone();

            let window1_start = None;
            let window1_end = OffsetDateTime::UNIX_EPOCH + Duration::from_secs(100_000_000_000);

            let window2_start = None;
            let window2_end = OffsetDateTime::UNIX_EPOCH + Duration::from_secs(150_000_000_000);

            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                Value::TimeBoundedMember(TimeBoundedMember::new(
                    UUID_TB_B,
                    window1_start,
                    window1_end,
                )),
            );
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                Value::TimeBoundedMember(TimeBoundedMember::new(
                    UUID_TB_B,
                    window2_start,
                    window2_end,
                )),
            );

            let preload = Vec::new();
            let create = vec![ea, eb];

            run_create_test!(
                Ok(None),
                preload,
                create,
                None,
                |qs: &mut QueryServerWriteTransaction| {
                    assert_memberof!(qs, UUID_TB_B, UUID_TB_A);
                    assert_dirmemberof!(qs, UUID_TB_B, UUID_TB_A);

                    let entry = qs.internal_search_uuid(UUID_TB_A).unwrap();
                    let tb_members =
                        entry.get_ava_as_time_bounded_member(Attribute::TimeBoundedMemberAttr);
                    assert!(tb_members.is_some());
                    let members = tb_members.unwrap();
                    assert_eq!(members.len(), 1);
                }
            );
        }

        const UUID_TB_USER: Uuid = uuid::uuid!("eeeeeeee-5b6e-4c4b-9b8e-6f6a3ad2c4a1");
        const UUID_TB_D: Uuid = uuid::uuid!("dddddddd-2ab3-48e3-938d-1b4754cd2984");

        fn tb_user() -> EntryInitNew {
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("testperson_tb")),
                (Attribute::Uuid, Value::Uuid(UUID_TB_USER)),
                (Attribute::Description, Value::new_utf8s("testperson_tb")),
                (Attribute::DisplayName, Value::new_utf8s("testperson_tb"))
            )
        }

        fn tb_grant(uuid: Uuid, valid_from: Option<Duration>, valid_until: Duration) -> Value {
            Value::TimeBoundedMember(TimeBoundedMember::new(
                uuid,
                valid_from.map(|vf| OffsetDateTime::UNIX_EPOCH + vf),
                OffsetDateTime::UNIX_EPOCH + valid_until,
            ))
        }

        /// These tests move the transaction clock forward. The verify run at the end
        /// of every qs_test uses the wall clock, and memberof is never applied after
        /// "now", so the simulated clock must stay in the past of the wall clock.
        fn past_base_time() -> Duration {
            duration_from_epoch_now() - Duration::from_secs(86_400)
        }

        fn set_grant(
            server_txn: &mut QueryServerWriteTransaction,
            valid_from: Option<Duration>,
            valid_until: Duration,
        ) {
            server_txn
                .internal_modify(
                    &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_TB_A))),
                    &ModifyList::new_list(vec![
                        Modify::Purged(Attribute::TimeBoundedMemberAttr),
                        Modify::Present(
                            Attribute::TimeBoundedMemberAttr,
                            tb_grant(UUID_TB_USER, valid_from, valid_until),
                        ),
                    ]),
                )
                .unwrap();
        }

        /// Overwrite the user's direct memberof without running plugins, to simulate
        /// a stale or corrupt memberof state.
        fn force_user_dmo(server_txn: &mut QueryServerWriteTransaction, dmo: Option<Uuid>) {
            let mut work_set = server_txn
                .internal_search_writeable(&filter!(f_eq(
                    Attribute::Uuid,
                    PartialValue::Uuid(UUID_TB_USER)
                )))
                .unwrap();
            for (_, entry) in work_set.iter_mut() {
                entry.purge_ava(Attribute::MemberOf);
                entry.purge_ava(Attribute::DirectMemberOf);
                if let Some(g) = dmo {
                    entry.add_ava(Attribute::MemberOf, Value::ReferN(g));
                    entry.add_ava(Attribute::DirectMemberOf, Value::ReferN(g));
                }
            }
            server_txn.internal_apply_writable(work_set).unwrap();
        }

        #[qs_test]
        async fn test_refresh_time_bounded_grant_expires(server: &QueryServer) {
            let ct = past_base_time();

            let mut ea = EA_TB.clone();
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                tb_grant(UUID_TB_USER, None, ct + Duration::from_secs(100)),
            );

            let mut server_txn = server.write(ct).await.unwrap();
            server_txn.internal_create(vec![ea, tb_user()]).unwrap();
            assert_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            // Still valid, nothing to refresh.
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(0));
            server_txn.commit().unwrap();

            // The grant has expired, but until the refresh runs the membership is
            // still reflected. Verify must tolerate this.
            assert!(server.verify().await.is_empty());

            let mut server_txn = server.write(ct + Duration::from_secs(200)).await.unwrap();
            assert_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(1));
            assert_not_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_not_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            // Idempotent - a second refresh has nothing to do.
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(0));
            server_txn.commit().unwrap();
        }

        #[qs_test]
        async fn test_refresh_time_bounded_grant_becomes_active(server: &QueryServer) {
            let ct = past_base_time();

            let mut ea = EA_TB.clone();
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                tb_grant(
                    UUID_TB_USER,
                    Some(ct + Duration::from_secs(100)),
                    ct + Duration::from_secs(1000),
                ),
            );

            let mut server_txn = server.write(ct).await.unwrap();
            server_txn.internal_create(vec![ea, tb_user()]).unwrap();
            assert_not_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            server_txn.commit().unwrap();

            // Not yet active.
            let mut server_txn = server.write(ct + Duration::from_secs(50)).await.unwrap();
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(0));
            assert_not_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            server_txn.commit().unwrap();

            let mut server_txn = server.write(ct + Duration::from_secs(200)).await.unwrap();
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(1));
            assert_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(0));
            server_txn.commit().unwrap();
        }

        #[qs_test]
        async fn test_refresh_time_bounded_permanent_member_kept(server: &QueryServer) {
            let ct = past_base_time();

            // A permanent membership in the same group must survive grant expiry.
            let mut ea = EA_TB.clone();
            ea.add_ava(Attribute::Member, Value::ReferN(UUID_TB_USER));
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                tb_grant(UUID_TB_USER, None, ct + Duration::from_secs(100)),
            );

            let mut server_txn = server.write(ct).await.unwrap();
            server_txn.internal_create(vec![ea, tb_user()]).unwrap();
            server_txn.commit().unwrap();

            let mut server_txn = server.write(ct + Duration::from_secs(200)).await.unwrap();
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(0));
            assert_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            server_txn.commit().unwrap();
        }

        #[qs_test]
        async fn test_modify_time_bounded_grant_window_recomputes(server: &QueryServer) {
            let ct = past_base_time();

            let mut ea = EA_TB.clone();
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                tb_grant(UUID_TB_USER, None, ct + Duration::from_secs(1000)),
            );

            let mut server_txn = server.write(ct).await.unwrap();
            server_txn.internal_create(vec![ea, tb_user()]).unwrap();
            assert_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            server_txn.commit().unwrap();

            let mut server_txn = server.write(ct + Duration::from_secs(20)).await.unwrap();

            // Change only the end of the existing grant so it is already expired.
            set_grant(&mut server_txn, None, ct + Duration::from_secs(10));
            assert_not_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_not_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);

            // Extending the end restores the membership.
            set_grant(&mut server_txn, None, ct + Duration::from_secs(5000));
            assert_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);

            // Moving the start into the future removes it again.
            set_grant(
                &mut server_txn,
                Some(ct + Duration::from_secs(100)),
                ct + Duration::from_secs(5000),
            );
            assert_not_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_not_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);

            // And moving the start back into the past restores it.
            set_grant(
                &mut server_txn,
                Some(ct + Duration::from_secs(10)),
                ct + Duration::from_secs(5000),
            );
            assert_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            server_txn.commit().unwrap();
        }

        #[qs_test]
        async fn test_time_bounded_grant_remove_and_readd(server: &QueryServer) {
            let ct = past_base_time();

            let mut ea = EA_TB.clone();
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                tb_grant(UUID_TB_USER, None, ct + Duration::from_secs(1000)),
            );

            let mut server_txn = server.write(ct).await.unwrap();
            server_txn.internal_create(vec![ea, tb_user()]).unwrap();
            assert_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            server_txn.commit().unwrap();

            let mut server_txn = server.write(ct + Duration::from_secs(10)).await.unwrap();
            server_txn
                .internal_modify(
                    &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_TB_A))),
                    &ModifyList::new_list(vec![Modify::Removed(
                        Attribute::TimeBoundedMemberAttr,
                        PartialValue::TimeBoundedMember(UUID_TB_USER),
                    )]),
                )
                .unwrap();
            assert_not_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_not_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            server_txn.commit().unwrap();

            let mut server_txn = server.write(ct + Duration::from_secs(20)).await.unwrap();
            server_txn
                .internal_modify(
                    &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_TB_A))),
                    &ModifyList::new_list(vec![Modify::Present(
                        Attribute::TimeBoundedMemberAttr,
                        tb_grant(UUID_TB_USER, None, ct + Duration::from_secs(1000)),
                    )]),
                )
                .unwrap();
            assert_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(0));
            server_txn.commit().unwrap();
        }

        #[qs_test]
        async fn test_revive_does_not_make_time_bounded_grant_permanent(server: &QueryServer) {
            let ct = past_base_time();

            // The user is a time bounded member of A and a permanent member of B.
            let mut ea = EA_TB.clone();
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                tb_grant(UUID_TB_USER, None, ct + Duration::from_secs(1000)),
            );
            let mut eb = EB_TB.clone();
            eb.add_ava(Attribute::Member, Value::ReferN(UUID_TB_USER));

            let mut server_txn = server.write(ct).await.unwrap();
            server_txn.internal_create(vec![ea, eb, tb_user()]).unwrap();
            assert_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_B);

            server_txn
                .internal_delete(&filter!(f_eq(
                    Attribute::Uuid,
                    PartialValue::Uuid(UUID_TB_USER)
                )))
                .unwrap();

            let recycled = server_txn.internal_search_all_uuid(UUID_TB_USER).unwrap();
            let rdmo = recycled
                .get_ava_refer(Attribute::RecycledDirectMemberOf)
                .expect("permanent membership was not recorded");
            assert!(rdmo.contains(&UUID_TB_B));
            assert!(!rdmo.contains(&UUID_TB_A));

            server_txn.internal_revive_uuid(UUID_TB_USER).unwrap();

            // The permanent membership is restored ...
            assert_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_B);
            // ... but the grant is neither restored nor converted to a membership.
            assert_not_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_not_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            let group = server_txn.internal_search_uuid(UUID_TB_A).unwrap();
            assert!(!group
                .get_ava_refer(Attribute::Member)
                .is_some_and(|set| set.contains(&UUID_TB_USER)));
            assert!(group
                .get_ava_set(Attribute::TimeBoundedMemberAttr)
                .is_none());
            server_txn.commit().unwrap();
        }

        #[qs_test]
        async fn test_verify_time_bounded_required_membership(server: &QueryServer) {
            let ct = past_base_time();
            // A grant with no start that ends well after now must be reflected.
            let far_future = duration_from_epoch_now() + Duration::from_secs(86_400 * 30);

            let mut ea = EA_TB.clone();
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                tb_grant(UUID_TB_USER, None, far_future),
            );

            let mut server_txn = server.write(ct).await.unwrap();
            server_txn.internal_create(vec![ea, tb_user()]).unwrap();
            assert_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            force_user_dmo(&mut server_txn, None);
            server_txn.commit().unwrap();

            let errs = server.verify().await;
            assert!(errs
                .iter()
                .any(|e| matches!(e, Err(ConsistencyError::MemberOfInvalid(_)))));

            // The refresh repairs the missing membership.
            let mut server_txn = server.write(ct + Duration::from_secs(1)).await.unwrap();
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(1));
            assert_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            server_txn.commit().unwrap();

            assert!(server.verify().await.is_empty());
        }

        #[qs_test]
        async fn test_verify_time_bounded_forbidden_membership(server: &QueryServer) {
            let ct = past_base_time();
            // A grant that starts well after now can not be reflected.
            let start = duration_from_epoch_now() + Duration::from_secs(86_400 * 30);

            let mut ea = EA_TB.clone();
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                tb_grant(
                    UUID_TB_USER,
                    Some(start),
                    start + Duration::from_secs(86_400),
                ),
            );

            let mut server_txn = server.write(ct).await.unwrap();
            server_txn.internal_create(vec![ea, tb_user()]).unwrap();
            assert_not_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            force_user_dmo(&mut server_txn, Some(UUID_TB_A));
            server_txn.commit().unwrap();

            let errs = server.verify().await;
            assert!(errs
                .iter()
                .any(|e| matches!(e, Err(ConsistencyError::MemberOfInvalid(_)))));

            // The refresh removes the premature membership.
            let mut server_txn = server.write(ct + Duration::from_secs(1)).await.unwrap();
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(1));
            assert_not_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            server_txn.commit().unwrap();

            assert!(server.verify().await.is_empty());
        }

        #[qs_test]
        async fn test_refresh_skips_long_expired_grants(server: &QueryServer) {
            let ct = past_base_time();

            let mut ea = EA_TB.clone();
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                tb_grant(UUID_TB_USER, None, ct + Duration::from_secs(100)),
            );

            let mut server_txn = server.write(ct).await.unwrap();
            server_txn.internal_create(vec![ea, tb_user()]).unwrap();
            server_txn.commit().unwrap();

            // Expire, refresh, then refresh again much later - the expired grant has
            // nothing left to do.
            let mut server_txn = server.write(ct + Duration::from_secs(200)).await.unwrap();
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(1));
            server_txn.commit().unwrap();

            let mut server_txn = server.write(ct + Duration::from_secs(5000)).await.unwrap();
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(0));
            assert_not_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);

            // But a stale membership for a long expired grant is still repaired.
            force_user_dmo(&mut server_txn, Some(UUID_TB_A));
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(1));
            assert_not_dirmemberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            server_txn.commit().unwrap();
        }

        #[qs_test]
        async fn test_delete_member_removes_time_bounded_grant(server: &QueryServer) {
            let ct = past_base_time();

            let mut ea = EA_TB.clone();
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                tb_grant(UUID_TB_USER, None, ct + Duration::from_secs(1000)),
            );
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                tb_grant(UUID_TB_B, None, ct + Duration::from_secs(1000)),
            );

            let mut server_txn = server.write(ct).await.unwrap();
            server_txn
                .internal_create(vec![ea, EB_TB.clone(), tb_user()])
                .unwrap();
            assert_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);

            server_txn
                .internal_delete(&filter!(f_eq(
                    Attribute::Uuid,
                    PartialValue::Uuid(UUID_TB_USER)
                )))
                .unwrap();

            let group = server_txn.internal_search_uuid(UUID_TB_A).unwrap();
            let grants = group
                .get_ava_as_time_bounded_member(Attribute::TimeBoundedMemberAttr)
                .expect("remaining grant was removed");
            assert!(!grants.contains_key(&UUID_TB_USER));
            assert!(grants.contains_key(&UUID_TB_B));

            server_txn
                .internal_delete(&filter!(f_eq(
                    Attribute::Uuid,
                    PartialValue::Uuid(UUID_TB_B)
                )))
                .unwrap();

            let group = server_txn.internal_search_uuid(UUID_TB_A).unwrap();
            assert!(group
                .get_ava_set(Attribute::TimeBoundedMemberAttr)
                .is_none());
            server_txn.commit().unwrap();
        }

        #[qs_test]
        async fn test_create_time_bounded_grant_missing_member(server: &QueryServer) {
            let ct = past_base_time();

            let mut ea = EA_TB.clone();
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                tb_grant(UUID_TB_USER, None, ct + Duration::from_secs(1000)),
            );

            let mut server_txn = server.write(ct).await.unwrap();
            assert_eq!(
                server_txn.internal_create(vec![ea]),
                Err(OperationError::Plugin(PluginError::ReferentialIntegrity(
                    "Uuid referenced not found in database".to_string()
                )))
            );
        }

        #[qs_test]
        async fn test_time_bounded_child_inherits_parent_memberof(server: &QueryServer) {
            let ct = past_base_time();

            // D -member-> A -time bounded-> C -member-> user
            let mut ea = EA_TB.clone();
            ea.add_ava(
                Attribute::TimeBoundedMemberAttr,
                tb_grant(UUID_TB_C, None, ct + Duration::from_secs(100)),
            );
            let mut ec = EC_TB.clone();
            ec.add_ava(Attribute::Member, Value::ReferN(UUID_TB_USER));
            let ed = entry_init_fn([
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Class, EntryClass::MemberOf.to_value()),
                (Attribute::Name, Value::new_iname("testgroup_tb_d")),
                (Attribute::Uuid, Value::Uuid(UUID_TB_D)),
            ]);

            let mut server_txn = server.write(ct).await.unwrap();
            server_txn
                .internal_create(vec![ea, ec, ed, tb_user()])
                .unwrap();
            assert_memberof!(server_txn, UUID_TB_C, UUID_TB_A);
            assert_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_not_memberof!(server_txn, UUID_TB_C, UUID_TB_D);

            // A's memberof changes, which must propagate to its time bounded members.
            server_txn
                .internal_modify(
                    &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_TB_D))),
                    &ModifyList::new_list(vec![Modify::Present(
                        Attribute::Member,
                        Value::ReferN(UUID_TB_A),
                    )]),
                )
                .unwrap();
            assert_memberof!(server_txn, UUID_TB_A, UUID_TB_D);
            assert_memberof!(server_txn, UUID_TB_C, UUID_TB_D);
            assert_not_dirmemberof!(server_txn, UUID_TB_C, UUID_TB_D);
            assert_memberof!(server_txn, UUID_TB_USER, UUID_TB_D);
            server_txn.commit().unwrap();

            // Once the grant expires, the child group and its members lose the
            // parent's memberships.
            let mut server_txn = server.write(ct + Duration::from_secs(200)).await.unwrap();
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(1));
            assert_not_memberof!(server_txn, UUID_TB_C, UUID_TB_A);
            assert_not_memberof!(server_txn, UUID_TB_C, UUID_TB_D);
            assert_not_memberof!(server_txn, UUID_TB_USER, UUID_TB_A);
            assert_not_memberof!(server_txn, UUID_TB_USER, UUID_TB_D);
            assert_memberof!(server_txn, UUID_TB_USER, UUID_TB_C);
            assert_eq!(server_txn.refresh_time_bounded_memberships(), Ok(0));
            server_txn.commit().unwrap();
        }
    }
}
