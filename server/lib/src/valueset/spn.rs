use crate::{
    prelude::*,
    schema::SchemaAttribute,
    valueset::{DbValueSetV2, ScimResolveStatus, ValueSet},
};

use smolset::SmolSet;

#[derive(Debug, Clone)]
pub struct ValueSetSpn {
    set: SmolSet<[(String, String); 1]>,
}

impl ValueSetSpn {
    pub fn new(u: (String, String)) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(u);
        Box::new(ValueSetSpn { set })
    }

    pub fn push(&mut self, u: (String, String)) -> bool {
        self.set.insert(u)
    }

    pub fn from_dbvs2(data: Vec<(String, String)>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetSpn { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (String, String)>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetSpn { set }))
    }
}

impl ValueSetT for ValueSetSpn {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Spn(n, d) => Ok(self.set.insert((n, d))),
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::Spn(n, d) => self.set.remove(&(n.clone(), d.clone())),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Spn(n, d) => self.set.contains(&(n.clone(), d.clone())),
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
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set.iter().map(|(n, d)| format!("{n}@{d}")).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::SecurityPrincipalName
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.set.iter().all(|(a, b)| {
            Value::validate_str_escapes(a)
                && Value::validate_str_escapes(b)
                && Value::validate_singleline(a)
                && Value::validate_singleline(b)
        })
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|(n, d)| format!("{n}@{d}")))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        let mut iter = self.set.iter().map(|(n, d)| format!("{n}@{d}"));
        if self.len() == 1 {
            let v = iter.next().unwrap_or_default();
            Some(v.into())
        } else {
            let arr = iter.collect::<Vec<_>>();
            Some(arr.into())
        }
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Spn(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(
            self.set
                .iter()
                .map(|(n, d)| PartialValue::Spn(n.clone(), d.clone())),
        )
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.set
                .iter()
                .map(|(n, d)| Value::Spn(n.clone(), d.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_spn_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_spn_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    /*
    fn to_spn_single(&self) -> Option<> {
        if self.set.len() == 1 {
            self.set.iter().copied().take(1).next()
        } else {
            None
        }
    }
    */

    fn as_spn_set(&self) -> Option<&SmolSet<[(String, String); 1]>> {
        Some(&self.set)
    }

    /*
    fn as_spn_iter(&self) -> Option<Box<dyn Iterator<Item = Spn> + '_>> {
        Some(Box::new(self.set.iter().copied()))
    }
    */
}

#[cfg(test)]
mod tests {
    use super::ValueSetSpn;
    use crate::prelude::ValueSet;

    #[test]
    fn test_scim_spn() {
        let vs: ValueSet = ValueSetSpn::new(("claire".to_string(), "example.com".to_string()));
        crate::valueset::scim_json_reflexive(&vs, r#""claire@example.com""#);
    }

    #[test]
    fn test_valueset_spn_new() {
        let vs: ValueSet = ValueSetSpn::new(("admin".to_string(), "test.com".to_string()));
        assert_eq!(vs.len(), 1);
    }

    #[test]
    fn test_valueset_spn_insert_checked() {
        let mut vs: ValueSet = ValueSetSpn::new(("user1".to_string(), "example.com".to_string()));
        assert!(vs
            .insert_checked(crate::prelude::Value::Spn(
                "user2".to_string(),
                "example.com".to_string()
            ))
            .unwrap());
        assert!(!vs
            .insert_checked(crate::prelude::Value::Spn(
                "user1".to_string(),
                "example.com".to_string()
            ))
            .unwrap());
        assert_eq!(vs.len(), 2);
    }

    #[test]
    fn test_valueset_spn_equal() {
        let vs1: ValueSet = ValueSetSpn::new(("alice".to_string(), "domain.com".to_string()));
        let vs2: ValueSet = ValueSetSpn::new(("alice".to_string(), "domain.com".to_string()));
        assert!(vs1.equal(&vs2));
    }

    #[test]
    fn test_valueset_spn_not_equal() {
        let vs1: ValueSet = ValueSetSpn::new(("alice".to_string(), "domain.com".to_string()));
        let vs2: ValueSet = ValueSetSpn::new(("bob".to_string(), "domain.com".to_string()));
        assert!(!vs1.equal(&vs2));
    }

    #[test]
    fn test_valueset_spn_merge() {
        let mut vs_a: ValueSet = ValueSetSpn::new(("user1".to_string(), "example.com".to_string()));
        let vs_b: ValueSet = ValueSetSpn::new(("user2".to_string(), "example.com".to_string()));
        vs_a.merge(&vs_b).expect("Failed to merge");
        assert_eq!(vs_a.len(), 2);
    }

    #[test]
    fn test_valueset_spn_clear() {
        let mut vs: ValueSet = ValueSetSpn::new(("admin".to_string(), "test.com".to_string()));
        vs.clear();
        assert_eq!(vs.len(), 0);
    }

    #[test]
    fn test_valueset_spn_len() {
        let mut vs: ValueSet = ValueSetSpn::new(("a".to_string(), "b".to_string()));
        assert_eq!(vs.len(), 1);
        vs.insert_checked(crate::prelude::Value::Spn("c".to_string(), "d".to_string()))
            .unwrap();
        assert_eq!(vs.len(), 2);
    }

    #[test]
    fn test_valueset_spn_dbv2_roundtrip() {
        let vs: ValueSet = ValueSetSpn::new(("claire".to_string(), "example.com".to_string()));
        let dbvs = vs.to_db_valueset_v2();
        let vs2 = crate::valueset::from_db_valueset_v2(dbvs).expect("Failed to restore");
        assert!(vs.equal(&vs2));
    }

    #[test]
    fn test_valueset_spn_contains() {
        let vs: ValueSet = ValueSetSpn::new(("admin".to_string(), "test.com".to_string()));
        assert!(vs.contains(&crate::prelude::PartialValue::Spn(
            "admin".to_string(),
            "test.com".to_string()
        )));
        assert!(!vs.contains(&crate::prelude::PartialValue::Spn(
            "nobody".to_string(),
            "test.com".to_string()
        )));
    }

    #[test]
    fn test_valueset_spn_proto_string_format() {
        let vs: ValueSet = ValueSetSpn::new(("alice".to_string(), "example.com".to_string()));
        let strings: Vec<String> = vs.to_proto_string_clone_iter().collect();
        assert_eq!(strings, vec!["alice@example.com"]);
    }
}
