use std::{collections::BTreeMap, time::Duration};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    dbrepl::{DbEntryChangeState, DbReplMeta},
    dbvalue::DbValueSetV2,
    keystorage::{KeyHandle, KeyHandleId},
};
use crate::prelude::entries::Attribute;

// REMEMBER: If you add a new version here, you MUST
// update entry.rs to_dbentry to export to the latest
// type always!!
#[derive(Serialize, Deserialize, Debug)]
pub enum DbEntryVers {
    V3 {
        changestate: DbEntryChangeState,
        attrs: BTreeMap<Attribute, DbValueSetV2>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
// This doesn't need a version since uuid2spn is reindexed - remember if you change this
// though, to change the index version!
pub enum DbIdentSpn {
    #[serde(rename = "SP")]
    Spn(String, String),
    #[serde(rename = "N8")]
    Iname(String),
    #[serde(rename = "UU")]
    Uuid(Uuid),
}

// This is actually what we store into the DB.
#[derive(Serialize, Deserialize)]
pub struct DbEntry {
    pub ent: DbEntryVers,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum DbBackup {
    // Because of untagged, this has to be in order of newest
    // to oldest as untagged does a first-match when deserialising.
    V5 {
        version: String,
        db_s_uuid: Uuid,
        db_d_uuid: Uuid,
        db_ts_max: Duration,
        keyhandles: BTreeMap<KeyHandleId, KeyHandle>,
        repl_meta: DbReplMeta,
        entries: Vec<DbEntry>,
    },
    V4 {
        db_s_uuid: Uuid,
        db_d_uuid: Uuid,
        db_ts_max: Duration,
        keyhandles: BTreeMap<KeyHandleId, KeyHandle>,
        repl_meta: DbReplMeta,
        entries: Vec<DbEntry>,
    },
    V3 {
        db_s_uuid: Uuid,
        db_d_uuid: Uuid,
        db_ts_max: Duration,
        keyhandles: BTreeMap<KeyHandleId, KeyHandle>,
        entries: Vec<DbEntry>,
    },
    V2 {
        db_s_uuid: Uuid,
        db_d_uuid: Uuid,
        db_ts_max: Duration,
        entries: Vec<DbEntry>,
    },
    V1(Vec<DbEntry>),
}

impl std::fmt::Debug for DbEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.ent {
            DbEntryVers::V3 { changestate, attrs } => {
                write!(f, "v3 - {{ ")?;
                match changestate {
                    DbEntryChangeState::V1Live { at, changes } => {
                        writeln!(f, "\nlive {at:>32}")?;
                        for (attr, cid) in changes {
                            write!(f, "\n{attr:>32} - {cid} ")?;
                            if let Some(vs) = attrs.get(attr) {
                                write!(f, "{vs:?}")?;
                            } else {
                                write!(f, "-")?;
                            }
                        }
                    }
                    DbEntryChangeState::V1Tombstone { at } => {
                        writeln!(f, "\ntombstone {at:>32?}")?;
                    }
                }
                write!(f, "\n        }}")
            }
        }
    }
}

impl std::fmt::Display for DbEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.ent {
            DbEntryVers::V3 { changestate, attrs } => {
                write!(f, "v3 - {{ ")?;
                match attrs.get(&Attribute::Uuid) {
                    Some(uuids) => {
                        write!(f, "{uuids:?}, ")?;
                    }
                    None => write!(f, "Uuid(INVALID), ")?,
                };

                match changestate {
                    DbEntryChangeState::V1Live { at, changes: _ } => {
                        write!(f, "created: {at}, ")?;
                        if let Some(names) = attrs.get(&Attribute::Name) {
                            write!(f, "{names:?}, ")?;
                        }
                        if let Some(names) = attrs.get(&Attribute::AttributeName) {
                            write!(f, "{names:?}, ")?;
                        }
                        if let Some(names) = attrs.get(&Attribute::ClassName) {
                            write!(f, "{names:?}, ")?;
                        }
                    }
                    DbEntryChangeState::V1Tombstone { at } => {
                        write!(f, "tombstoned: {at}, ")?;
                    }
                }
                write!(f, "}}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::be::dbrepl::{DbEntryChangeState, DbReplMeta};
    use crate::be::dbvalue::{DbCidV1, DbValueSetV2};
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::time::Duration;

    fn make_cid(server_id: Uuid, secs: u64) -> DbCidV1 {
        DbCidV1 {
            timestamp: Duration::from_secs(secs),
            server_id,
        }
    }

    fn make_live_entry() -> DbEntry {
        let sid = Uuid::new_v4();
        let mut attrs = BTreeMap::new();
        attrs.insert(Attribute::Uuid, DbValueSetV2::Uuid(vec![Uuid::new_v4()]));
        attrs.insert(
            Attribute::Name,
            DbValueSetV2::Iname(vec!["testuser".to_string()]),
        );

        let mut changes = BTreeMap::new();
        changes.insert(Attribute::Uuid, make_cid(sid, 1));
        changes.insert(Attribute::Name, make_cid(sid, 2));

        DbEntry {
            ent: DbEntryVers::V3 {
                changestate: DbEntryChangeState::V1Live {
                    at: make_cid(sid, 0),
                    changes,
                },
                attrs,
            },
        }
    }

    fn make_tombstone_entry() -> DbEntry {
        let sid = Uuid::new_v4();
        DbEntry {
            ent: DbEntryVers::V3 {
                changestate: DbEntryChangeState::V1Tombstone {
                    at: make_cid(sid, 100),
                },
                attrs: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn test_dbentry_v3_live_serde_roundtrip() {
        let entry = make_live_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: DbEntry = serde_json::from_str(&json).unwrap();
        match &deserialized.ent {
            DbEntryVers::V3 { changestate, attrs } => {
                assert!(matches!(changestate, DbEntryChangeState::V1Live { .. }));
                assert!(attrs.contains_key(&Attribute::Uuid));
                assert!(attrs.contains_key(&Attribute::Name));
            }
        }
    }

    #[test]
    fn test_dbentry_v3_tombstone_serde_roundtrip() {
        let entry = make_tombstone_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: DbEntry = serde_json::from_str(&json).unwrap();
        match &deserialized.ent {
            DbEntryVers::V3 { changestate, attrs } => {
                assert!(matches!(
                    changestate,
                    DbEntryChangeState::V1Tombstone { .. }
                ));
                assert!(attrs.is_empty());
            }
        }
    }

    #[test]
    fn test_dbentry_v3_empty_attrs_serde_roundtrip() {
        let sid = Uuid::new_v4();
        let entry = DbEntry {
            ent: DbEntryVers::V3 {
                changestate: DbEntryChangeState::V1Live {
                    at: make_cid(sid, 0),
                    changes: BTreeMap::new(),
                },
                attrs: BTreeMap::new(),
            },
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: DbEntry = serde_json::from_str(&json).unwrap();
        match &deserialized.ent {
            DbEntryVers::V3 { changestate, attrs } => {
                assert!(matches!(changestate, DbEntryChangeState::V1Live { .. }));
                assert!(attrs.is_empty());
            }
        }
    }

    #[test]
    fn test_dbentry_v3_multiple_value_types() {
        let sid = Uuid::new_v4();
        let mut attrs = BTreeMap::new();
        attrs.insert(Attribute::Uuid, DbValueSetV2::Uuid(vec![Uuid::new_v4()]));
        attrs.insert(
            Attribute::Name,
            DbValueSetV2::Iname(vec!["alice".to_string()]),
        );
        attrs.insert(
            Attribute::UserId,
            DbValueSetV2::Utf8(vec!["alice".to_string()]),
        );
        attrs.insert(Attribute::Version, DbValueSetV2::Uint32(vec![1, 2, 3]));
        attrs.insert(
            Attribute::Description,
            DbValueSetV2::Utf8(vec!["a user".to_string()]),
        );

        let mut changes = BTreeMap::new();
        for attr in attrs.keys() {
            changes.insert(attr.clone(), make_cid(sid, 1));
        }

        let entry = DbEntry {
            ent: DbEntryVers::V3 {
                changestate: DbEntryChangeState::V1Live {
                    at: make_cid(sid, 0),
                    changes,
                },
                attrs,
            },
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: DbEntry = serde_json::from_str(&json).unwrap();
        match &deserialized.ent {
            DbEntryVers::V3 { attrs, .. } => {
                assert_eq!(attrs.len(), 5);
            }
        }
    }

    #[test]
    fn test_dbidentspn_spn_serde_roundtrip() {
        let spn = DbIdentSpn::Spn("admin".to_string(), "example.com".to_string());
        let json = serde_json::to_string(&spn).unwrap();
        let deserialized: DbIdentSpn = serde_json::from_str(&json).unwrap();
        if let DbIdentSpn::Spn(name, domain) = deserialized {
            assert_eq!(name, "admin");
            assert_eq!(domain, "example.com");
        } else {
            panic!("Expected Spn variant");
        }
    }

    #[test]
    fn test_dbidentspn_iname_serde_roundtrip() {
        let iname = DbIdentSpn::Iname("testuser".to_string());
        let json = serde_json::to_string(&iname).unwrap();
        let deserialized: DbIdentSpn = serde_json::from_str(&json).unwrap();
        if let DbIdentSpn::Iname(name) = deserialized {
            assert_eq!(name, "testuser");
        } else {
            panic!("Expected Iname variant");
        }
    }

    #[test]
    fn test_dbidentspn_uuid_serde_roundtrip() {
        let uuid = Uuid::new_v4();
        let spn = DbIdentSpn::Uuid(uuid);
        let json = serde_json::to_string(&spn).unwrap();
        let deserialized: DbIdentSpn = serde_json::from_str(&json).unwrap();
        if let DbIdentSpn::Uuid(u) = deserialized {
            assert_eq!(u, uuid);
        } else {
            panic!("Expected Uuid variant");
        }
    }

    #[test]
    fn test_dbidentspn_spn_json_format() {
        let spn = DbIdentSpn::Spn("user".to_string(), "domain.test".to_string());
        let json = serde_json::to_string(&spn).unwrap();
        assert!(json.contains("\"SP\""));
    }

    #[test]
    fn test_dbidentspn_iname_json_format() {
        let iname = DbIdentSpn::Iname("hostname".to_string());
        let json = serde_json::to_string(&iname).unwrap();
        assert!(json.contains("\"N8\""));
    }

    #[test]
    fn test_dbidentspn_uuid_json_format() {
        let uuid = Uuid::new_v4();
        let spn = DbIdentSpn::Uuid(uuid);
        let json = serde_json::to_string(&spn).unwrap();
        assert!(json.contains("\"UU\""));
    }

    #[test]
    fn test_dbentry_debug_live() {
        let entry = make_live_entry();
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("v3"));
        assert!(debug_str.contains("live"));
    }

    #[test]
    fn test_dbentry_debug_tombstone() {
        let entry = make_tombstone_entry();
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("v3"));
        assert!(debug_str.contains("tombstone"));
    }

    #[test]
    fn test_dbentry_display_live() {
        let entry = make_live_entry();
        let display_str = format!("{}", entry);
        assert!(display_str.contains("v3"));
    }

    #[test]
    fn test_dbentry_display_tombstone() {
        let entry = make_tombstone_entry();
        let display_str = format!("{}", entry);
        assert!(display_str.contains("tombstoned"));
    }

    #[test]
    fn test_dbbackup_v5_serde_roundtrip() {
        let sid = Uuid::new_v4();
        let mut ruv = BTreeSet::new();
        ruv.insert(make_cid(sid, 1));

        let backup = DbBackup::V5 {
            version: "5".to_string(),
            db_s_uuid: Uuid::new_v4(),
            db_d_uuid: Uuid::new_v4(),
            db_ts_max: Duration::from_secs(100),
            keyhandles: BTreeMap::new(),
            repl_meta: DbReplMeta::V1 { ruv },
            entries: vec![make_live_entry()],
        };

        let json = serde_json::to_string(&backup).unwrap();
        let deserialized: DbBackup = serde_json::from_str(&json).unwrap();
        match deserialized {
            DbBackup::V5 {
                version, entries, ..
            } => {
                assert_eq!(version, "5");
                assert_eq!(entries.len(), 1);
            }
            _ => panic!("Expected V5"),
        }
    }

    #[test]
    fn test_dbbackup_v4_serde_roundtrip() {
        let _sid = Uuid::new_v4();
        let ruv = BTreeSet::new();

        let backup = DbBackup::V4 {
            db_s_uuid: Uuid::new_v4(),
            db_d_uuid: Uuid::new_v4(),
            db_ts_max: Duration::from_secs(200),
            keyhandles: BTreeMap::new(),
            repl_meta: DbReplMeta::V1 { ruv },
            entries: vec![],
        };

        let json = serde_json::to_string(&backup).unwrap();
        let deserialized: DbBackup = serde_json::from_str(&json).unwrap();
        match deserialized {
            DbBackup::V4 {
                db_ts_max, entries, ..
            } => {
                assert_eq!(db_ts_max, Duration::from_secs(200));
                assert!(entries.is_empty());
            }
            _ => panic!("Expected V4"),
        }
    }

    #[test]
    fn test_dbbackup_v3_serde_roundtrip() {
        let backup = DbBackup::V3 {
            db_s_uuid: Uuid::new_v4(),
            db_d_uuid: Uuid::new_v4(),
            db_ts_max: Duration::from_secs(300),
            keyhandles: BTreeMap::new(),
            entries: vec![make_tombstone_entry()],
        };

        let json = serde_json::to_string(&backup).unwrap();
        let deserialized: DbBackup = serde_json::from_str(&json).unwrap();
        match deserialized {
            DbBackup::V3 {
                db_ts_max, entries, ..
            } => {
                assert_eq!(db_ts_max, Duration::from_secs(300));
                assert_eq!(entries.len(), 1);
            }
            _ => panic!("Expected V3"),
        }
    }

    #[test]
    fn test_dbbackup_v2_serde_roundtrip() {
        let backup = DbBackup::V2 {
            db_s_uuid: Uuid::new_v4(),
            db_d_uuid: Uuid::new_v4(),
            db_ts_max: Duration::from_secs(400),
            entries: vec![],
        };

        let json = serde_json::to_string(&backup).unwrap();
        let deserialized: DbBackup = serde_json::from_str(&json).unwrap();
        match deserialized {
            DbBackup::V2 { db_ts_max, .. } => {
                assert_eq!(db_ts_max, Duration::from_secs(400));
            }
            _ => panic!("Expected V2"),
        }
    }

    #[test]
    fn test_dbbackup_v1_serde_roundtrip() {
        let backup = DbBackup::V1(vec![make_live_entry(), make_tombstone_entry()]);

        let json = serde_json::to_string(&backup).unwrap();
        let deserialized: DbBackup = serde_json::from_str(&json).unwrap();
        match deserialized {
            DbBackup::V1(entries) => {
                assert_eq!(entries.len(), 2);
            }
            _ => panic!("Expected V1"),
        }
    }

    #[test]
    fn test_dbbackup_v5_empty_entries() {
        let backup = DbBackup::V5 {
            version: "5".to_string(),
            db_s_uuid: Uuid::new_v4(),
            db_d_uuid: Uuid::new_v4(),
            db_ts_max: Duration::ZERO,
            keyhandles: BTreeMap::new(),
            repl_meta: DbReplMeta::V1 {
                ruv: BTreeSet::new(),
            },
            entries: vec![],
        };

        let json = serde_json::to_string(&backup).unwrap();
        let deserialized: DbBackup = serde_json::from_str(&json).unwrap();
        match deserialized {
            DbBackup::V5 { entries, .. } => {
                assert!(entries.is_empty());
            }
            _ => panic!("Expected V5"),
        }
    }

    #[test]
    fn test_dbvaluesetv2_serde_variants() {
        let variants = vec![
            DbValueSetV2::Utf8(vec!["hello".to_string()]),
            DbValueSetV2::Iutf8(vec!["insensitive".to_string()]),
            DbValueSetV2::Iname(vec!["testname".to_string()]),
            DbValueSetV2::Uuid(vec![Uuid::new_v4()]),
            DbValueSetV2::Uint32(vec![42]),
            DbValueSetV2::Int64(vec![-1, 0, 1]),
            DbValueSetV2::Uint64(vec![100, 200]),
            DbValueSetV2::HexString(vec!["deadbeef".to_string()]),
            DbValueSetV2::OauthScope(vec!["read".to_string(), "write".to_string()]),
            DbValueSetV2::RestrictedString(vec!["restricted".to_string()]),
            DbValueSetV2::NsUniqueId(vec!["nsunique-1".to_string()]),
            DbValueSetV2::DateTime(vec!["2024-01-01T00:00:00Z".to_string()]),
        ];

        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let deserialized: DbValueSetV2 = serde_json::from_str(&json).unwrap();
            assert_eq!(variant.len(), deserialized.len());
        }
    }

    #[test]
    fn test_dbvaluesetv2_len_and_empty() {
        assert_eq!(DbValueSetV2::Utf8(vec![]).len(), 0);
        assert!(DbValueSetV2::Utf8(vec![]).is_empty());
        assert_eq!(DbValueSetV2::Uuid(vec![Uuid::new_v4()]).len(), 1);
        assert!(!DbValueSetV2::Uuid(vec![Uuid::new_v4()]).is_empty());
        assert_eq!(DbValueSetV2::Int64(vec![1, 2]).len(), 2);
    }
}
