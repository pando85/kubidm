use crate::be::dbvalue::DbValueTimeBoundedMemberV1;
use crate::prelude::*;
use crate::schema::SchemaAttribute;
use crate::value::TimeBoundedMember;
use crate::valueset::{DbValueSetV2, ScimResolveStatus, ValueSet};
use std::collections::{BTreeMap, BTreeSet};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Parse an RFC 3339 time and normalise it to UTC. `None` when the time does not parse, or
/// can not be expressed in UTC (`to_offset` would panic).
fn parse_utc(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339)
        .ok()
        .and_then(|odt| odt.checked_to_offset(time::UtcOffset::UTC))
}

#[derive(Debug, Clone)]
pub struct ValueSetTimeBoundedMember {
    map: BTreeMap<Uuid, TimeBoundedMember>,
}

impl ValueSetTimeBoundedMember {
    pub fn new(m: TimeBoundedMember) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(m.uuid, m);
        Box::new(ValueSetTimeBoundedMember { map })
    }

    pub fn push(&mut self, m: TimeBoundedMember) -> bool {
        self.map.insert(m.uuid, m).is_none()
    }

    pub fn from_dbvs2(data: Vec<DbValueTimeBoundedMemberV1>) -> Result<ValueSet, OperationError> {
        // Any value that fails to parse is an error rather than being dropped, as
        // silently discarding a grant would be data loss on the next write.
        let map = data
            .into_iter()
            .map(|dbv| {
                let valid_from = dbv
                    .valid_from
                    .map(|vf| {
                        parse_utc(&vf).ok_or_else(|| {
                            error!(uuid = %dbv.uuid, "invalid valid_from in time bounded member");
                            OperationError::InvalidValueState
                        })
                    })
                    .transpose()?;

                let valid_until = parse_utc(&dbv.valid_until).ok_or_else(|| {
                    error!(uuid = %dbv.uuid, "invalid valid_until in time bounded member");
                    OperationError::InvalidValueState
                })?;

                let member = TimeBoundedMember {
                    uuid: dbv.uuid,
                    valid_from,
                    valid_until,
                };

                Ok((dbv.uuid, member))
            })
            .collect::<Result<_, OperationError>>()?;
        Ok(Box::new(ValueSetTimeBoundedMember { map }))
    }

    pub fn new_from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = TimeBoundedMember>,
    {
        let map: BTreeMap<Uuid, TimeBoundedMember> =
            iter.into_iter().map(|m| (m.uuid, m)).collect();
        if map.is_empty() {
            None
        } else {
            Some(Box::new(ValueSetTimeBoundedMember { map }))
        }
    }

    pub fn get_valid_members_at(&self, when: OffsetDateTime) -> BTreeSet<Uuid> {
        self.map
            .values()
            .filter(|m| m.is_valid_at(when))
            .map(|m| m.uuid)
            .collect()
    }
}

impl ValueSetT for ValueSetTimeBoundedMember {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::TimeBoundedMember(m) => {
                let r = self.map.insert(m.uuid, m.clone()).is_none();
                Ok(r)
            }
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            // Refer is accepted so that referential integrity can remove the grants
            // of a member that has been deleted.
            PartialValue::TimeBoundedMember(uuid) | PartialValue::Refer(uuid) => {
                self.map.remove(uuid);
            }
            _ => {
                debug_assert!(false);
            }
        };
        self.map.is_empty()
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::TimeBoundedMember(uuid) | PartialValue::Refer(uuid) => {
                self.map.contains_key(uuid)
            }
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.map
            .keys()
            .map(|u| u.as_hyphenated().to_string())
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::TimeBoundedMember
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.map
            .iter()
            .all(|(uuid, m)| *uuid == m.uuid && m.has_valid_window())
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.values().map(|m| {
            let from_str = m
                .valid_from
                .map(|vf| {
                    vf.format(&Rfc3339)
                        .unwrap_or_else(|_| "invalid".to_string())
                })
                .unwrap_or_else(|| "now".to_string());
            let until_str = m
                .valid_until
                .format(&Rfc3339)
                .unwrap_or_else(|_| "invalid".to_string());
            format!("{}: {} - {}", m.uuid, from_str, until_str)
        }))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::TimeBoundedMember(
            self.map
                .values()
                .map(|m| DbValueTimeBoundedMemberV1 {
                    uuid: m.uuid,
                    // validate rejects times that can not be formatted, so these
                    // fallbacks are unreachable. If reached, they fail closed: the
                    // loader refuses "invalid" rather than treating a dropped start
                    // time as an immediately active grant.
                    valid_from: m.valid_from.map(|vf| {
                        vf.format(&Rfc3339)
                            .unwrap_or_else(|_| "invalid".to_string())
                    }),
                    valid_until: m
                        .valid_until
                        .format(&Rfc3339)
                        .unwrap_or_else(|_| "invalid".to_string()),
                })
                .collect(),
        )
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKubidm::ArrayString(
            self.to_proto_string_clone_iter().collect(),
        )))
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(
            self.map
                .keys()
                .copied()
                .map(PartialValue::TimeBoundedMember),
        )
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.map.values().cloned().map(Value::TimeBoundedMember))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_time_bounded_member_set() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(other) = other.as_time_bounded_member_set() {
            for (k, v) in other.iter() {
                self.map.insert(*k, v.clone());
            }
            Ok(())
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_time_bounded_member_set(&self) -> Option<&BTreeMap<Uuid, TimeBoundedMember>> {
        Some(&self.map)
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        Some(Box::new(self.map.keys().copied()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::be::dbvalue::DbValueTimeBoundedMemberV1;
    use crate::value::TimeBoundedMember;
    use std::time::Duration;
    use time::OffsetDateTime;

    fn create_test_uuid() -> Uuid {
        Uuid::new_v4()
    }

    fn baseline_time() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000)
    }

    fn create_member(
        uuid: Uuid,
        start: Option<OffsetDateTime>,
        end: OffsetDateTime,
    ) -> TimeBoundedMember {
        TimeBoundedMember::new(uuid, start, end)
    }

    #[test]
    fn test_valueset_new() {
        let uuid = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member = create_member(uuid, Some(start), end);
        let vs = ValueSetTimeBoundedMember::new(member);

        assert_eq!(vs.len(), 1);
        assert!(vs.as_time_bounded_member_set().unwrap().contains_key(&uuid));
    }

    #[test]
    fn test_valueset_push() {
        let uuid1 = create_test_uuid();
        let uuid2 = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member1 = create_member(uuid1, Some(start), end);
        let mut vs = ValueSetTimeBoundedMember::new(member1);

        let member2 = create_member(uuid2, Some(start), end);
        assert!(vs.push(member2));
        assert_eq!(vs.len(), 2);

        let member1_dup = create_member(uuid1, Some(start), end + Duration::from_secs(100));
        assert!(!vs.push(member1_dup));
        assert_eq!(vs.len(), 2);
    }

    #[test]
    fn test_valueset_from_dbvs2() {
        let uuid1 = create_test_uuid();
        let uuid2 = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let data = vec![
            DbValueTimeBoundedMemberV1 {
                uuid: uuid1,
                valid_from: Some(start.format(&Rfc3339).unwrap()),
                valid_until: end.format(&Rfc3339).unwrap(),
            },
            DbValueTimeBoundedMemberV1 {
                uuid: uuid2,
                valid_from: None,
                valid_until: end.format(&Rfc3339).unwrap(),
            },
        ];

        let vs = ValueSetTimeBoundedMember::from_dbvs2(data).expect("Failed to parse db values");

        assert_eq!(vs.len(), 2);
        let map = vs.as_time_bounded_member_set().unwrap();

        let member1 = map.get(&uuid1).expect("Member 1 not found");
        assert_eq!(member1.uuid, uuid1);
        assert_eq!(member1.valid_from, Some(start));

        let member2 = map.get(&uuid2).expect("Member 2 not found");
        assert_eq!(member2.uuid, uuid2);
        assert_eq!(member2.valid_from, None);
    }

    #[test]
    fn test_valueset_from_dbvs2_invalid_format() {
        let uuid = create_test_uuid();

        let data = vec![DbValueTimeBoundedMemberV1 {
            uuid,
            valid_from: Some("invalid-date-format".to_string()),
            valid_until: "invalid-date-format".to_string(),
        }];

        let vs = ValueSetTimeBoundedMember::from_dbvs2(data);
        assert!(matches!(vs, Err(OperationError::InvalidValueState)));
    }

    #[test]
    fn test_valueset_from_dbvs2_invalid_valid_from_only() {
        let uuid = create_test_uuid();
        let end = baseline_time() + Duration::from_secs(3600);

        // A valid until with a corrupt valid from must not be silently widened
        // to an immediately active grant.
        let data = vec![DbValueTimeBoundedMemberV1 {
            uuid,
            valid_from: Some("invalid-date-format".to_string()),
            valid_until: end.format(&Rfc3339).unwrap(),
        }];

        let vs = ValueSetTimeBoundedMember::from_dbvs2(data);
        assert!(matches!(vs, Err(OperationError::InvalidValueState)));
    }

    #[test]
    fn test_valueset_from_dbvs2_out_of_range_in_utc() {
        // Valid RFC 3339, but in year 10000 once converted to UTC. This must be an error,
        // not a panic in to_offset.
        let data = vec![DbValueTimeBoundedMemberV1 {
            uuid: create_test_uuid(),
            valid_from: None,
            valid_until: "9999-12-31T23:59:59-23:59".to_string(),
        }];
        let vs = ValueSetTimeBoundedMember::from_dbvs2(data);
        assert!(matches!(vs, Err(OperationError::InvalidValueState)));

        let data = vec![DbValueTimeBoundedMemberV1 {
            uuid: create_test_uuid(),
            valid_from: Some("9999-12-31T01:00:00-23:59".to_string()),
            valid_until: (baseline_time() + Duration::from_secs(3600))
                .format(&Rfc3339)
                .unwrap(),
        }];
        let vs = ValueSetTimeBoundedMember::from_dbvs2(data);
        assert!(matches!(vs, Err(OperationError::InvalidValueState)));
    }

    #[test]
    fn test_valueset_validate_window() {
        let schema_attr = SchemaAttribute::default();
        let start = baseline_time();

        let ok = ValueSetTimeBoundedMember::new(create_member(
            create_test_uuid(),
            Some(start),
            start + Duration::from_secs(1),
        ));
        assert!(ok.validate(&schema_attr));

        let no_start =
            ValueSetTimeBoundedMember::new(create_member(create_test_uuid(), None, start));
        assert!(no_start.validate(&schema_attr));

        let empty_window =
            ValueSetTimeBoundedMember::new(create_member(create_test_uuid(), Some(start), start));
        assert!(!empty_window.validate(&schema_attr));

        let inverted = ValueSetTimeBoundedMember::new(create_member(
            create_test_uuid(),
            Some(start + Duration::from_secs(10)),
            start,
        ));
        assert!(!inverted.validate(&schema_attr));

        // A time that can not be stored as RFC 3339 is rejected at write time.
        let negative_year = time::Date::from_calendar_date(-1, time::Month::January, 1)
            .unwrap()
            .midnight()
            .assume_utc();
        let unstorable = ValueSetTimeBoundedMember::new(create_member(
            create_test_uuid(),
            Some(negative_year),
            start,
        ));
        assert!(!unstorable.validate(&schema_attr));
    }

    #[test]
    fn test_valueset_refer_contains_and_remove() {
        let uuid1 = create_test_uuid();
        let uuid2 = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let mut vs = ValueSetTimeBoundedMember::new_from_iter(vec![
            create_member(uuid1, Some(start), end),
            create_member(uuid2, None, end),
        ])
        .expect("Failed to create valueset");

        assert!(vs.contains(&PartialValue::Refer(uuid1)));
        assert!(!vs.contains(&PartialValue::Refer(create_test_uuid())));

        assert!(!vs.remove(
            &PartialValue::Refer(uuid1),
            &crate::prelude::Cid::new_zero()
        ));
        assert!(!vs.contains(&PartialValue::Refer(uuid1)));
        assert_eq!(vs.len(), 1);

        assert!(vs.remove(
            &PartialValue::Refer(uuid2),
            &crate::prelude::Cid::new_zero()
        ));
        assert_eq!(vs.len(), 0);
    }

    #[test]
    fn test_valueset_new_from_iter_empty() {
        let iter: Vec<TimeBoundedMember> = vec![];
        let vs = ValueSetTimeBoundedMember::new_from_iter(iter);
        assert!(vs.is_none());
    }

    #[test]
    fn test_valueset_new_from_iter() {
        let uuid1 = create_test_uuid();
        let uuid2 = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let members = vec![
            create_member(uuid1, Some(start), end),
            create_member(uuid2, Some(start), end),
        ];

        let vs =
            ValueSetTimeBoundedMember::new_from_iter(members).expect("Failed to create valueset");
        assert_eq!(vs.len(), 2);
    }

    #[test]
    fn test_valueset_get_valid_members_at() {
        let uuid1 = create_test_uuid();
        let uuid2 = create_test_uuid();
        let uuid3 = create_test_uuid();
        let start = baseline_time();

        let member1 = create_member(uuid1, Some(start), start + Duration::from_secs(100));
        let member2 = create_member(uuid2, Some(start), start + Duration::from_secs(200));
        let member3 = create_member(uuid3, None, start + Duration::from_secs(300));

        let vs = ValueSetTimeBoundedMember::new_from_iter(vec![member1, member2, member3])
            .expect("Failed to create valueset");

        let valid_at_start = vs.get_valid_members_at(start);
        assert!(valid_at_start.contains(&uuid1));
        assert!(valid_at_start.contains(&uuid2));
        assert!(valid_at_start.contains(&uuid3));
        assert_eq!(valid_at_start.len(), 3);

        let valid_at_150 = vs.get_valid_members_at(start + Duration::from_secs(150));
        assert!(!valid_at_150.contains(&uuid1));
        assert!(valid_at_150.contains(&uuid2));
        assert!(valid_at_150.contains(&uuid3));
        assert_eq!(valid_at_150.len(), 2);

        let valid_at_250 = vs.get_valid_members_at(start + Duration::from_secs(250));
        assert!(!valid_at_250.contains(&uuid1));
        assert!(!valid_at_250.contains(&uuid2));
        assert!(valid_at_250.contains(&uuid3));
        assert_eq!(valid_at_250.len(), 1);

        let valid_at_400 = vs.get_valid_members_at(start + Duration::from_secs(400));
        assert!(valid_at_400.is_empty());
    }

    #[test]
    fn test_valueset_insert_checked() {
        let uuid = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member = create_member(uuid, Some(start), end);
        let mut vs = ValueSetTimeBoundedMember::new(member.clone());

        let new_uuid = create_test_uuid();
        let new_member = create_member(new_uuid, Some(start), end);

        let result = vs.insert_checked(crate::value::Value::TimeBoundedMember(new_member));
        assert!(result.is_ok());
        assert_eq!(vs.len(), 2);
    }

    #[test]
    fn test_valueset_clear() {
        let uuid = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member = create_member(uuid, Some(start), end);
        let mut vs = ValueSetTimeBoundedMember::new(member);

        vs.clear();
        assert_eq!(vs.len(), 0);
    }

    #[test]
    fn test_valueset_remove() {
        let uuid1 = create_test_uuid();
        let uuid2 = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member1 = create_member(uuid1, Some(start), end);
        let member2 = create_member(uuid2, Some(start), end);

        let mut vs = ValueSetTimeBoundedMember::new_from_iter(vec![member1, member2])
            .expect("Failed to create valueset");

        // remove returns true only when the set is now empty.
        assert!(!vs.remove(
            &PartialValue::TimeBoundedMember(uuid1),
            &crate::prelude::Cid::new_zero()
        ));
        assert_eq!(vs.len(), 1);

        assert!(!vs.remove(
            &PartialValue::TimeBoundedMember(uuid1),
            &crate::prelude::Cid::new_zero()
        ));
        assert_eq!(vs.len(), 1);

        assert!(vs.remove(
            &PartialValue::TimeBoundedMember(uuid2),
            &crate::prelude::Cid::new_zero()
        ));
        assert_eq!(vs.len(), 0);
    }

    #[test]
    fn test_valueset_contains() {
        let uuid = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member = create_member(uuid, Some(start), end);
        let vs = ValueSetTimeBoundedMember::new(member);

        assert!(vs.contains(&PartialValue::TimeBoundedMember(uuid)));
        assert!(!vs.contains(&PartialValue::TimeBoundedMember(create_test_uuid())));
    }

    #[test]
    fn test_valueset_syntax() {
        let uuid = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member = create_member(uuid, Some(start), end);
        let vs = ValueSetTimeBoundedMember::new(member);

        assert_eq!(vs.syntax(), SyntaxType::TimeBoundedMember);
    }

    #[test]
    fn test_valueset_generate_idx_eq_keys() {
        let uuid1 = create_test_uuid();
        let uuid2 = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member1 = create_member(uuid1, Some(start), end);
        let member2 = create_member(uuid2, Some(start), end);

        let vs = ValueSetTimeBoundedMember::new_from_iter(vec![member1, member2])
            .expect("Failed to create valueset");

        let keys = vs.generate_idx_eq_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&uuid1.as_hyphenated().to_string()));
        assert!(keys.contains(&uuid2.as_hyphenated().to_string()));
    }

    #[test]
    fn test_valueset_merge() {
        let uuid1 = create_test_uuid();
        let uuid2 = create_test_uuid();
        let uuid3 = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member1 = create_member(uuid1, Some(start), end);
        let member2 = create_member(uuid2, Some(start), end);

        let mut vs_a: ValueSet = ValueSetTimeBoundedMember::new_from_iter(vec![member1])
            .expect("Failed to create valueset A");

        let vs_b: ValueSet = ValueSetTimeBoundedMember::new_from_iter(vec![
            member2,
            create_member(uuid3, Some(start), end),
        ])
        .expect("Failed to create valueset B");

        vs_a.merge(&vs_b).expect("Failed to merge");

        assert_eq!(vs_a.len(), 3);
    }

    #[test]
    fn test_valueset_merge_overlapping() {
        let uuid = create_test_uuid();
        let start = baseline_time();
        let end1 = start + Duration::from_secs(3600);
        let end2 = start + Duration::from_secs(7200);

        let member1 = create_member(uuid, Some(start), end1);
        let member2 = create_member(uuid, Some(start), end2);

        let mut vs_a: ValueSet = ValueSetTimeBoundedMember::new(member1);
        let vs_b: ValueSet = ValueSetTimeBoundedMember::new(member2);

        vs_a.merge(&vs_b).expect("Failed to merge");

        assert_eq!(vs_a.len(), 1);
        let merged_member = vs_a
            .as_time_bounded_member_set()
            .unwrap()
            .get(&uuid)
            .unwrap();
        assert_eq!(merged_member.valid_until, end2);
    }

    #[test]
    fn test_valueset_to_proto_string_clone_iter() {
        let uuid = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member_with_start = create_member(uuid, Some(start), end);
        let vs = ValueSetTimeBoundedMember::new(member_with_start);

        let proto_strings: Vec<_> = vs.to_proto_string_clone_iter().collect();
        assert_eq!(proto_strings.len(), 1);

        let expected_start = start.format(&Rfc3339).unwrap();
        let expected_end = end.format(&Rfc3339).unwrap();
        let expected = format!("{}: {} - {}", uuid, expected_start, expected_end);
        assert_eq!(proto_strings[0], expected);
    }

    #[test]
    fn test_valueset_to_proto_string_no_valid_from() {
        let uuid = create_test_uuid();
        let end = baseline_time() + Duration::from_secs(3600);

        let member_no_start = create_member(uuid, None, end);
        let vs = ValueSetTimeBoundedMember::new(member_no_start);

        let proto_strings: Vec<_> = vs.to_proto_string_clone_iter().collect();
        assert_eq!(proto_strings.len(), 1);

        let expected_end = end.format(&Rfc3339).unwrap();
        let expected = format!("{}: now - {}", uuid, expected_end);
        assert_eq!(proto_strings[0], expected);
    }

    #[test]
    fn test_valueset_as_ref_uuid_iter() {
        let uuid1 = create_test_uuid();
        let uuid2 = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member1 = create_member(uuid1, Some(start), end);
        let member2 = create_member(uuid2, Some(start), end);

        let vs = ValueSetTimeBoundedMember::new_from_iter(vec![member1, member2])
            .expect("Failed to create valueset");

        let uuids: Vec<_> = vs.as_ref_uuid_iter().unwrap().collect();
        assert_eq!(uuids.len(), 2);
        assert!(uuids.contains(&uuid1));
        assert!(uuids.contains(&uuid2));
    }

    #[test]
    fn test_valueset_equal() {
        let uuid1 = create_test_uuid();
        let uuid2 = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member1 = create_member(uuid1, Some(start), end);
        let member2 = create_member(uuid2, Some(start), end);

        let vs_a: ValueSet =
            ValueSetTimeBoundedMember::new_from_iter(vec![member1.clone(), member2.clone()])
                .expect("Failed to create valueset A");
        let vs_b: ValueSet = ValueSetTimeBoundedMember::new_from_iter(vec![member1, member2])
            .expect("Failed to create valueset B");

        assert!(vs_a.equal(&vs_b));
    }

    #[test]
    fn test_valueset_not_equal() {
        let uuid1 = create_test_uuid();
        let uuid2 = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member1 = create_member(uuid1, Some(start), end);
        let member2 = create_member(uuid2, Some(start), end);

        let vs_a: ValueSet = ValueSetTimeBoundedMember::new(member1);
        let vs_b: ValueSet = ValueSetTimeBoundedMember::new(member2);

        assert!(!vs_a.equal(&vs_b));
    }

    #[test]
    fn test_valueset_to_db_valueset_v2() {
        let uuid = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member = create_member(uuid, Some(start), end);
        let vs = ValueSetTimeBoundedMember::new(member);

        let db_vs = vs.to_db_valueset_v2();

        match db_vs {
            DbValueSetV2::TimeBoundedMember(data) => {
                assert_eq!(data.len(), 1);
                assert_eq!(data[0].uuid, uuid);
                assert_eq!(data[0].valid_from, Some(start.format(&Rfc3339).unwrap()));
                assert_eq!(data[0].valid_until, end.format(&Rfc3339).unwrap());
            }
            _ => panic!("Expected TimeBoundedMember variant"),
        }
    }

    #[test]
    fn test_valueset_to_partialvalue_iter() {
        let uuid1 = create_test_uuid();
        let uuid2 = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member1 = create_member(uuid1, Some(start), end);
        let member2 = create_member(uuid2, Some(start), end);

        let vs = ValueSetTimeBoundedMember::new_from_iter(vec![member1, member2])
            .expect("Failed to create valueset");

        let partial_values: Vec<_> = vs.to_partialvalue_iter().collect();
        assert_eq!(partial_values.len(), 2);
        assert!(partial_values.contains(&PartialValue::TimeBoundedMember(uuid1)));
        assert!(partial_values.contains(&PartialValue::TimeBoundedMember(uuid2)));
    }

    #[test]
    fn test_valueset_to_value_iter() {
        let uuid = create_test_uuid();
        let start = baseline_time();
        let end = start + Duration::from_secs(3600);

        let member = create_member(uuid, Some(start), end);
        let vs = ValueSetTimeBoundedMember::new(member);

        let values: Vec<_> = vs.to_value_iter().collect();
        assert_eq!(values.len(), 1);

        match &values[0] {
            crate::value::Value::TimeBoundedMember(m) => {
                assert_eq!(m.uuid, uuid);
            }
            _ => panic!("Expected TimeBoundedMember value"),
        }
    }
}
