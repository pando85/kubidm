use super::cid::Cid;
use crate::{
    be::{dbrepl::DbEntryChangeState, dbvalue::DbCidV1},
    entry::Eattrs,
    prelude::*,
    schema::SchemaTransaction,
};

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub enum State {
    Live {
        at: Cid,
        changes: BTreeMap<Attribute, Cid>,
    },
    Tombstone {
        at: Cid,
    },
}

#[derive(Debug, Clone)]
pub struct EntryChangeState {
    pub(super) st: State,
}

impl EntryChangeState {
    pub fn new(cid: &Cid, attrs: &Eattrs, _schema: &dyn SchemaTransaction) -> Self {
        let changes = attrs
            .keys()
            .cloned()
            .map(|attr| (attr, cid.clone()))
            .collect();

        let st = State::Live {
            at: cid.clone(),
            changes,
        };

        EntryChangeState { st }
    }

    pub fn new_without_schema(cid: &Cid, attrs: &Eattrs) -> Self {
        let class = attrs.get(&Attribute::Class);
        let st = if class
            .as_ref()
            .map(|c| c.contains(&EntryClass::Tombstone.to_partialvalue()))
            .unwrap_or(false)
        {
            State::Tombstone { at: cid.clone() }
        } else {
            let changes = attrs
                .keys()
                .cloned()
                .map(|attr| (attr, cid.clone()))
                .collect();

            State::Live {
                at: cid.clone(),
                changes,
            }
        };

        EntryChangeState { st }
    }

    pub(crate) fn to_db_changestate(&self) -> DbEntryChangeState {
        match &self.st {
            State::Live { at, changes } => {
                let at = DbCidV1 {
                    server_id: at.s_uuid,
                    timestamp: at.ts,
                };

                let changes = changes
                    .iter()
                    .map(|(attr, cid)| {
                        (
                            attr.clone(),
                            DbCidV1 {
                                server_id: cid.s_uuid,
                                timestamp: cid.ts,
                            },
                        )
                    })
                    .collect();

                DbEntryChangeState::V1Live { at, changes }
            }
            State::Tombstone { at } => {
                let at = DbCidV1 {
                    server_id: at.s_uuid,
                    timestamp: at.ts,
                };

                DbEntryChangeState::V1Tombstone { at }
            }
        }
    }

    pub(crate) fn from_db_changestate(db_ecstate: DbEntryChangeState) -> Self {
        match db_ecstate {
            DbEntryChangeState::V1Live { at, changes } => {
                let at = Cid {
                    s_uuid: at.server_id,
                    ts: at.timestamp,
                };

                let changes = changes
                    .iter()
                    .map(|(attr, cid)| {
                        (
                            attr.clone(),
                            Cid {
                                s_uuid: cid.server_id,
                                ts: cid.timestamp,
                            },
                        )
                    })
                    .collect();

                EntryChangeState {
                    st: State::Live { at, changes },
                }
            }
            DbEntryChangeState::V1Tombstone { at } => EntryChangeState {
                st: State::Tombstone {
                    at: Cid {
                        s_uuid: at.server_id,
                        ts: at.timestamp,
                    },
                },
            },
        }
    }

    pub(crate) fn build(st: State) -> Self {
        EntryChangeState { st }
    }

    pub fn current(&self) -> &State {
        &self.st
    }

    pub fn at(&self) -> &Cid {
        match &self.st {
            State::Live { at, .. } => at,
            State::Tombstone { at } => at,
        }
    }

    pub(crate) fn stub(&self) -> Self {
        let st = match &self.st {
            State::Live { at, changes: _ } => State::Live {
                at: at.clone(),
                changes: Default::default(),
            },
            State::Tombstone { at } => State::Tombstone { at: at.clone() },
        };
        EntryChangeState { st }
    }

    pub fn change_ava(&mut self, cid: &Cid, attr: &Attribute) {
        match &mut self.st {
            State::Live {
                at: _,
                ref mut changes,
            } => {
                if let Some(change) = changes.get_mut(attr) {
                    // Update the cid.
                    if change != cid {
                        *change = cid.clone()
                    }
                } else {
                    changes.insert(attr.clone(), cid.clone());
                }
            }
            State::Tombstone { .. } => {
                unreachable!();
            }
        }
    }

    pub fn tombstone(&mut self, cid: &Cid) {
        match &mut self.st {
            State::Live { at: _, changes: _ } => self.st = State::Tombstone { at: cid.clone() },
            State::Tombstone { .. } => {} // no-op
        };
    }

    pub fn can_delete(&self, cid: &Cid) -> bool {
        match &self.st {
            State::Live { .. } => false,
            State::Tombstone { at } => at < cid,
        }
    }

    pub fn is_live(&self) -> bool {
        match &self.st {
            State::Live { .. } => true,
            State::Tombstone { .. } => false,
        }
    }

    pub fn contains_tail_cid(&self, cid: &Cid) -> bool {
        // This is slow? Is it needed?
        match &self.st {
            State::Live { at: _, changes } => changes.values().any(|change| change == cid),
            State::Tombstone { at } => at == cid,
        }
    }

    pub(crate) fn get_max_cid(&self) -> &Cid {
        match &self.st {
            State::Live { at, changes } => changes.values().max().unwrap_or(at),
            State::Tombstone { at } => at,
        }
    }

    #[cfg(test)]
    pub(crate) fn get_attr_cid(&self, attr: &Attribute) -> Option<&Cid> {
        match &self.st {
            State::Live { at: _, changes } => changes.get(attr),
            State::Tombstone { at: _ } => None,
        }
    }

    pub(crate) fn cid_iter(&self) -> Vec<&Cid> {
        match &self.st {
            State::Live { at: _, changes } => {
                let mut v: Vec<_> = changes.values().collect();
                v.sort_unstable();
                v.dedup();
                v
            }
            State::Tombstone { at } => vec![at],
        }
    }

    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&Attribute, &mut Cid) -> bool,
    {
        match &mut self.st {
            State::Live { at: _, changes } => changes.retain(f),
            State::Tombstone { .. } => {}
        }
    }

    #[instrument(level = "trace", name = "verify", skip_all)]
    pub fn verify(
        &self,
        schema: &dyn SchemaTransaction,
        expected_attrs: &Eattrs,
        entry_id: u64,
        results: &mut Vec<Result<(), ConsistencyError>>,
    ) {
        let class = expected_attrs.get(&Attribute::Class);
        let is_ts = class
            .as_ref()
            .map(|c| c.contains(&EntryClass::Tombstone.to_partialvalue()))
            .unwrap_or(false);

        match (&self.st, is_ts) {
            (State::Live { at, changes }, false) => {
                // Every change must be after at.

                // Check that all attrs from expected, have a value in our changes.
                let inconsistent: Vec<_> = expected_attrs
                    .keys()
                    .filter(|attr| {
                        /*
                         * If the attribute is a replicated attribute, and it is NOT present
                         * in the change state then we are in a desync state.
                         *
                         * However, we don't check the inverse - if an entry is in the change state
                         * but is NOT replicated by schema. This is because there is is a way to
                         * delete an attribute in schema which will then prevent future replications
                         * of that value. However the value, while not being updated, will retain
                         * a state entry in the change state.
                         *
                         * For the entry to then be replicated once more, it would require it's schema
                         * attributes to be re-added and then the replication will resume from whatever
                         * receives the changes first. Generally there are lots of desync and edge
                         * cases here, which is why we pretty much don't allow schema to be deleted
                         * but we have to handle it here due to a test case that simulates this.
                         */
                        let change_cid_present = if let Some(change_cid) = changes.get(*attr) {
                        if change_cid < at {
                            warn!("changestate has a change that occurs before entry was created! {attr:?} {change_cid:?} {at:?}");
                            results.push(Err(ConsistencyError::ChangeStateDesynchronised(entry_id)));
                        }
                           true
                        } else {
                           false
                        };

                        // Only assert this when we actually have replication requirements.
                        let desync = schema.is_replicated(attr) && !change_cid_present;
                        if desync {
                            debug!(%entry_id, %attr, %desync);
                        }
                        desync
                    })
                    .collect();

                if inconsistent.is_empty() {
                    trace!("changestate is synchronised");
                } else {
                    warn!("changestate has desynchronised! Missing state attrs {inconsistent:?}");
                    results.push(Err(ConsistencyError::ChangeStateDesynchronised(entry_id)));
                }
            }
            (State::Tombstone { .. }, true) => {
                trace!("changestate is synchronised");
            }
            (State::Live { .. }, true) => {
                warn!("changestate has desynchronised! State Live when tombstone is true");
                results.push(Err(ConsistencyError::ChangeStateDesynchronised(entry_id)));
            }
            (State::Tombstone { .. }, false) => {
                warn!("changestate has desynchronised! State Tombstone when tombstone is false");
                results.push(Err(ConsistencyError::ChangeStateDesynchronised(entry_id)));
            }
        }
    }
}

impl PartialEq for EntryChangeState {
    fn eq(&self, rhs: &Self) -> bool {
        match (&self.st, &rhs.st) {
            (
                State::Live {
                    at: at_left,
                    changes: changes_left,
                },
                State::Live {
                    at: at_right,
                    changes: changes_right,
                },
            ) => at_left.eq(at_right) && changes_left.eq(changes_right),
            (State::Tombstone { at: at_left }, State::Tombstone { at: at_right }) => {
                at_left.eq(at_right)
            }
            (_, _) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::be::dbrepl::DbEntryChangeState;
    use crate::be::dbvalue::DbCidV1;
    use std::time::Duration;

    fn make_cid(s_uuid: Uuid, secs: u64) -> Cid {
        Cid::new(s_uuid, Duration::from_secs(secs))
    }

    fn make_live_ecstate() -> EntryChangeState {
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 10);
        let mut attrs = Eattrs::default();
        attrs.insert(Attribute::Name, vs_iutf8!["testperson"]);
        attrs.insert(
            Attribute::Uuid,
            vs_uuid![uuid!("00000000-0000-0000-0000-000000000001")],
        );
        attrs.insert(Attribute::Class, vs_iutf8!["object", "account"]);
        EntryChangeState::new_without_schema(&cid, &attrs)
    }

    fn make_tombstone_ecstate() -> EntryChangeState {
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 20);
        let mut attrs = Eattrs::default();
        attrs.insert(
            Attribute::Uuid,
            vs_uuid![uuid!("00000000-0000-0000-0000-000000000001")],
        );
        attrs.insert(Attribute::Class, vs_iutf8!["object", "tombstone"]);
        attrs.insert(Attribute::LastModifiedCid, vs_cid![cid.clone()]);
        EntryChangeState::new_without_schema(&cid, &attrs)
    }

    #[test]
    fn test_entry_change_state_new_without_schema_live() {
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 5);
        let mut attrs = Eattrs::default();
        attrs.insert(Attribute::Name, vs_iutf8!["testentry"]);
        attrs.insert(
            Attribute::Uuid,
            vs_uuid![uuid!("00000000-0000-0000-0000-000000000001")],
        );

        let ecs = EntryChangeState::new_without_schema(&cid, &attrs);

        assert!(ecs.is_live());
        assert_eq!(ecs.at(), &cid);
        match ecs.current() {
            State::Live { at, changes } => {
                assert_eq!(at, &cid);
                assert_eq!(changes.len(), 2);
                assert!(changes.contains_key(&Attribute::Name));
                assert!(changes.contains_key(&Attribute::Uuid));
                for change_cid in changes.values() {
                    assert_eq!(change_cid, &cid);
                }
            }
            _ => panic!("Expected Live state"),
        }
    }

    #[test]
    fn test_entry_change_state_new_without_schema_tombstone() {
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 10);
        let mut attrs = Eattrs::default();
        attrs.insert(Attribute::Class, vs_iutf8!["object", "tombstone"]);
        attrs.insert(
            Attribute::Uuid,
            vs_uuid![uuid!("00000000-0000-0000-0000-000000000001")],
        );

        let ecs = EntryChangeState::new_without_schema(&cid, &attrs);

        assert!(!ecs.is_live());
        assert_eq!(ecs.at(), &cid);
        match ecs.current() {
            State::Tombstone { at } => assert_eq!(at, &cid),
            _ => panic!("Expected Tombstone state"),
        }
    }

    #[test]
    fn test_entry_change_state_new_without_schema_empty_attrs() {
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 1);
        let attrs = Eattrs::default();
        let ecs = EntryChangeState::new_without_schema(&cid, &attrs);
        assert!(ecs.is_live());
        match ecs.current() {
            State::Live { at, changes } => {
                assert_eq!(at, &cid);
                assert!(changes.is_empty());
            }
            _ => panic!("Expected Live state"),
        }
    }

    #[test]
    fn test_entry_change_state_build_live() {
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 5);
        let state = State::Live {
            at: cid,
            changes: BTreeMap::default(),
        };
        let ecs = EntryChangeState::build(state);
        assert!(ecs.is_live());
    }

    #[test]
    fn test_entry_change_state_build_tombstone() {
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 5);
        let state = State::Tombstone { at: cid };
        let ecs = EntryChangeState::build(state);
        assert!(!ecs.is_live());
    }

    #[test]
    fn test_entry_change_state_at_live() {
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 10);
        let attrs = Eattrs::default();
        let ecs = EntryChangeState::new_without_schema(&cid, &attrs);
        assert_eq!(ecs.at(), &cid);
    }

    #[test]
    fn test_entry_change_state_at_tombstone() {
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 10);
        let mut attrs = Eattrs::default();
        attrs.insert(Attribute::Class, vs_iutf8!["tombstone"]);
        let ecs = EntryChangeState::new_without_schema(&cid, &attrs);
        assert_eq!(ecs.at(), &cid);
    }

    #[test]
    fn test_entry_change_state_change_ava_update_existing() {
        let mut ecs = make_live_ecstate();
        let new_cid = make_cid(uuid!("00000000-0000-0000-0000-000000000002"), 15);
        ecs.change_ava(&new_cid, &Attribute::Name);
        let attr_cid = ecs.get_attr_cid(&Attribute::Name).unwrap();
        assert_eq!(attr_cid, &new_cid);
    }

    #[test]
    fn test_entry_change_state_change_ava_add_new() {
        let mut ecs = make_live_ecstate();
        let new_cid = make_cid(uuid!("00000000-0000-0000-0000-000000000002"), 15);
        assert!(ecs.get_attr_cid(&Attribute::Description).is_none());
        ecs.change_ava(&new_cid, &Attribute::Description);
        let attr_cid = ecs.get_attr_cid(&Attribute::Description).unwrap();
        assert_eq!(attr_cid, &new_cid);
    }

    #[test]
    fn test_entry_change_state_change_ava_same_cid_noop() {
        let mut ecs = make_live_ecstate();
        let original_cid = ecs.get_attr_cid(&Attribute::Name).unwrap().clone();
        ecs.change_ava(&original_cid, &Attribute::Name);
        let after_cid = ecs.get_attr_cid(&Attribute::Name).unwrap().clone();
        assert_eq!(original_cid, after_cid);
    }

    #[test]
    fn test_entry_change_state_tombstone_from_live() {
        let mut ecs = make_live_ecstate();
        let ts_cid = make_cid(uuid!("00000000-0000-0000-0000-000000000003"), 30);
        assert!(ecs.is_live());
        ecs.tombstone(&ts_cid);
        assert!(!ecs.is_live());
        assert_eq!(ecs.at(), &ts_cid);
    }

    #[test]
    fn test_entry_change_state_tombstone_idempotent() {
        let original_cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 20);
        let mut ecs = make_tombstone_ecstate();
        let ts_cid = make_cid(uuid!("00000000-0000-0000-0000-000000000003"), 30);
        ecs.tombstone(&ts_cid);
        assert!(!ecs.is_live());
        assert_eq!(ecs.at(), &original_cid);
    }

    #[test]
    fn test_entry_change_state_can_delete_live() {
        let ecs = make_live_ecstate();
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 100);
        assert!(!ecs.can_delete(&cid));
    }

    #[test]
    fn test_entry_change_state_can_delete_tombstone_with_later_cid() {
        let ecs = make_tombstone_ecstate();
        let later_cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 100);
        assert!(ecs.can_delete(&later_cid));
    }

    #[test]
    fn test_entry_change_state_can_delete_tombstone_with_earlier_cid() {
        let ecs = make_tombstone_ecstate();
        let earlier_cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 1);
        assert!(!ecs.can_delete(&earlier_cid));
    }

    #[test]
    fn test_entry_change_state_can_delete_tombstone_with_same_cid() {
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 20);
        let mut attrs = Eattrs::default();
        attrs.insert(Attribute::Class, vs_iutf8!["tombstone"]);
        let ecs = EntryChangeState::new_without_schema(&cid, &attrs);
        assert!(!ecs.can_delete(&cid));
    }

    #[test]
    fn test_entry_change_state_stub_live() {
        let ecs = make_live_ecstate();
        let stub = ecs.stub();
        assert!(stub.is_live());
        assert_eq!(stub.at(), ecs.at());
        match stub.current() {
            State::Live { changes, .. } => assert!(changes.is_empty()),
            _ => panic!("Expected Live state"),
        }
    }

    #[test]
    fn test_entry_change_state_stub_tombstone() {
        let ecs = make_tombstone_ecstate();
        let stub = ecs.stub();
        assert!(!stub.is_live());
        assert_eq!(stub.at(), ecs.at());
    }

    #[test]
    fn test_entry_change_state_contains_tail_cid_live() {
        let ecs = make_live_ecstate();
        match ecs.current() {
            State::Live { changes, .. } => {
                for cid in changes.values() {
                    assert!(ecs.contains_tail_cid(cid));
                }
            }
            _ => panic!("Expected Live state"),
        }
        let other_cid = make_cid(uuid!("00000000-0000-0000-0000-000000000099"), 999);
        assert!(!ecs.contains_tail_cid(&other_cid));
    }

    #[test]
    fn test_entry_change_state_contains_tail_cid_tombstone() {
        let ecs = make_tombstone_ecstate();
        assert!(ecs.contains_tail_cid(ecs.at()));
        let other_cid = make_cid(uuid!("00000000-0000-0000-0000-000000000099"), 999);
        assert!(!ecs.contains_tail_cid(&other_cid));
    }

    #[test]
    fn test_entry_change_state_get_max_cid_single_attr() {
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 10);
        let mut attrs = Eattrs::default();
        attrs.insert(Attribute::Name, vs_iutf8!["test"]);
        let ecs = EntryChangeState::new_without_schema(&cid, &attrs);
        assert_eq!(ecs.get_max_cid(), &cid);
    }

    #[test]
    fn test_entry_change_state_get_max_cid_multiple_attrs() {
        let cid_a = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 10);
        let mut ecs = EntryChangeState::build(State::Live {
            at: cid_a,
            changes: BTreeMap::default(),
        });
        let cid_early = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 5);
        let cid_late = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 15);
        ecs.change_ava(&cid_early, &Attribute::Name);
        ecs.change_ava(&cid_late, &Attribute::Description);
        assert_eq!(ecs.get_max_cid(), &cid_late);
    }

    #[test]
    fn test_entry_change_state_get_max_cid_tombstone() {
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 20);
        let mut attrs = Eattrs::default();
        attrs.insert(Attribute::Class, vs_iutf8!["tombstone"]);
        let ecs = EntryChangeState::new_without_schema(&cid, &attrs);
        assert_eq!(ecs.get_max_cid(), &cid);
    }

    #[test]
    fn test_entry_change_state_cid_iter_live_dedup() {
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 10);
        let mut attrs = Eattrs::default();
        attrs.insert(Attribute::Name, vs_iutf8!["test"]);
        attrs.insert(
            Attribute::Uuid,
            vs_uuid![uuid!("00000000-0000-0000-0000-000000000001")],
        );
        let ecs = EntryChangeState::new_without_schema(&cid, &attrs);
        let cids = ecs.cid_iter();
        assert_eq!(cids.len(), 1);
        assert_eq!(cids[0], &cid);
    }

    #[test]
    fn test_entry_change_state_cid_iter_live_multiple() {
        let cid_a = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 10);
        let mut ecs = EntryChangeState::build(State::Live {
            at: cid_a,
            changes: BTreeMap::default(),
        });
        let cid_5 = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 5);
        let cid_15 = make_cid(uuid!("00000000-0000-0000-0000-000000000002"), 15);
        ecs.change_ava(&cid_5, &Attribute::Name);
        ecs.change_ava(&cid_15, &Attribute::Description);
        let cids = ecs.cid_iter();
        assert_eq!(cids.len(), 2);
        assert!(cids.contains(&&cid_5));
        assert!(cids.contains(&&cid_15));
    }

    #[test]
    fn test_entry_change_state_cid_iter_tombstone() {
        let ecs = make_tombstone_ecstate();
        let cids = ecs.cid_iter();
        assert_eq!(cids.len(), 1);
        assert_eq!(cids[0], ecs.at());
    }

    #[test]
    fn test_entry_change_state_retain() {
        let mut ecs = make_live_ecstate();
        assert!(ecs.get_attr_cid(&Attribute::Name).is_some());
        assert!(ecs.get_attr_cid(&Attribute::Uuid).is_some());
        ecs.retain(|attr, _| attr != &Attribute::Name);
        assert!(ecs.get_attr_cid(&Attribute::Name).is_none());
        assert!(ecs.get_attr_cid(&Attribute::Uuid).is_some());
    }

    #[test]
    fn test_entry_change_state_retain_tombstone_noop() {
        let mut ecs = make_tombstone_ecstate();
        ecs.retain(|_, _| false);
        assert!(!ecs.is_live());
    }

    #[test]
    fn test_entry_change_state_get_attr_cid_live() {
        let ecs = make_live_ecstate();
        assert!(ecs.get_attr_cid(&Attribute::Name).is_some());
        assert!(ecs.get_attr_cid(&Attribute::Mail).is_none());
    }

    #[test]
    fn test_entry_change_state_get_attr_cid_tombstone() {
        let ecs = make_tombstone_ecstate();
        assert!(ecs.get_attr_cid(&Attribute::Name).is_none());
    }

    #[test]
    fn test_entry_change_state_partial_eq_live_equal() {
        let ecs1 = make_live_ecstate();
        let ecs2 = make_live_ecstate();
        assert_eq!(ecs1, ecs2);
    }

    #[test]
    fn test_entry_change_state_partial_eq_live_different_at() {
        let cid1 = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 10);
        let cid2 = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 20);
        let attrs = Eattrs::default();
        let ecs1 = EntryChangeState::new_without_schema(&cid1, &attrs);
        let ecs2 = EntryChangeState::new_without_schema(&cid2, &attrs);
        assert_ne!(ecs1, ecs2);
    }

    #[test]
    fn test_entry_change_state_partial_eq_tombstone_equal() {
        let ecs1 = make_tombstone_ecstate();
        let ecs2 = make_tombstone_ecstate();
        assert_eq!(ecs1, ecs2);
    }

    #[test]
    fn test_entry_change_state_partial_eq_live_vs_tombstone() {
        let ecs_live = make_live_ecstate();
        let ecs_ts = make_tombstone_ecstate();
        assert_ne!(ecs_live, ecs_ts);
    }

    #[test]
    fn test_entry_change_state_to_db_changestate_live() {
        let ecs = make_live_ecstate();
        let db = ecs.to_db_changestate();
        match db {
            DbEntryChangeState::V1Live { at, changes } => {
                assert_eq!(at.server_id, uuid!("00000000-0000-0000-0000-000000000001"));
                assert_eq!(at.timestamp, Duration::from_secs(10));
                assert!(!changes.is_empty());
            }
            DbEntryChangeState::V1Tombstone { .. } => panic!("Expected V1Live"),
        }
    }

    #[test]
    fn test_entry_change_state_to_db_changestate_tombstone() {
        let ecs = make_tombstone_ecstate();
        let db = ecs.to_db_changestate();
        match db {
            DbEntryChangeState::V1Tombstone { at } => {
                assert_eq!(at.server_id, uuid!("00000000-0000-0000-0000-000000000001"));
                assert_eq!(at.timestamp, Duration::from_secs(20));
            }
            DbEntryChangeState::V1Live { .. } => panic!("Expected V1Tombstone"),
        }
    }

    #[test]
    fn test_entry_change_state_from_db_changestate_live() {
        let db = DbEntryChangeState::V1Live {
            at: DbCidV1 {
                server_id: uuid!("00000000-0000-0000-0000-000000000001"),
                timestamp: Duration::from_secs(10),
            },
            changes: btreemap!((
                Attribute::Name,
                DbCidV1 {
                    server_id: uuid!("00000000-0000-0000-0000-000000000001"),
                    timestamp: Duration::from_secs(5),
                }
            )),
        };
        let ecs = EntryChangeState::from_db_changestate(db);
        assert!(ecs.is_live());
        match ecs.current() {
            State::Live { at, changes } => {
                assert_eq!(at.s_uuid, uuid!("00000000-0000-0000-0000-000000000001"));
                assert_eq!(at.ts, Duration::from_secs(10));
                assert_eq!(changes.len(), 1);
                let name_cid = changes.get(&Attribute::Name).unwrap();
                assert_eq!(name_cid.ts, Duration::from_secs(5));
            }
            _ => panic!("Expected Live state"),
        }
    }

    #[test]
    fn test_entry_change_state_from_db_changestate_tombstone() {
        let db = DbEntryChangeState::V1Tombstone {
            at: DbCidV1 {
                server_id: uuid!("00000000-0000-0000-0000-000000000002"),
                timestamp: Duration::from_secs(99),
            },
        };
        let ecs = EntryChangeState::from_db_changestate(db);
        assert!(!ecs.is_live());
        assert_eq!(
            ecs.at().s_uuid,
            uuid!("00000000-0000-0000-0000-000000000002")
        );
        assert_eq!(ecs.at().ts, Duration::from_secs(99));
    }

    #[test]
    fn test_entry_change_state_db_roundtrip_live() {
        let original = make_live_ecstate();
        let db = original.to_db_changestate();
        let restored = EntryChangeState::from_db_changestate(db);
        assert_eq!(original, restored);
    }

    #[test]
    fn test_entry_change_state_db_roundtrip_tombstone() {
        let original = make_tombstone_ecstate();
        let db = original.to_db_changestate();
        let restored = EntryChangeState::from_db_changestate(db);
        assert_eq!(original, restored);
    }

    #[test]
    fn test_entry_change_state_db_roundtrip_live_with_changes() {
        let cid = make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 10);
        let mut ecs = EntryChangeState::build(State::Live {
            at: cid,
            changes: BTreeMap::default(),
        });
        ecs.change_ava(
            &make_cid(uuid!("00000000-0000-0000-0000-000000000001"), 10),
            &Attribute::Name,
        );
        let cid2 = make_cid(uuid!("00000000-0000-0000-0000-000000000002"), 20);
        ecs.change_ava(&cid2, &Attribute::Description);
        let db = ecs.to_db_changestate();
        let restored = EntryChangeState::from_db_changestate(db);
        assert_eq!(ecs, restored);
    }

    #[test]
    fn test_entry_change_state_current_returns_ref() {
        let ecs = make_live_ecstate();
        let current = ecs.current();
        assert!(matches!(current, State::Live { .. }));
    }
}
