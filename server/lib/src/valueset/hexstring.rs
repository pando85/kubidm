use crate::{
    prelude::*,
    schema::SchemaAttribute,
    valueset::{DbValueSetV2, ScimResolveStatus, ValueSet},
};

use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct ValueSetHexString {
    set: BTreeSet<String>,
}

impl ValueSetHexString {
    pub fn new(s: String) -> Box<Self> {
        let mut set = BTreeSet::new();
        set.insert(s);
        Box::new(ValueSetHexString { set })
    }

    pub fn push(&mut self, s: &str) -> bool {
        self.set.insert(s.to_lowercase())
    }

    pub fn from_dbvs2(data: Vec<String>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetHexString { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and str is foreign
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<'a, T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = &'a str>,
    {
        let set = iter.into_iter().map(str::to_string).collect();
        Some(Box::new(ValueSetHexString { set }))
    }
}

impl ValueSetT for ValueSetHexString {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::HexString(s) => Ok(self.set.insert(s)),
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
            PartialValue::HexString(s) => self.set.remove(s),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::HexString(s) => self.set.contains(s.as_str()),
            _ => false,
        }
    }

    fn substring(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::HexString(s2) => self.set.iter().any(|s1| s1.contains(s2)),
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn startswith(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::HexString(s2) => self.set.iter().any(|s1| s1.starts_with(s2)),
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn endswith(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::HexString(s2) => self.set.iter().any(|s1| s1.ends_with(s2)),
            _ => {
                debug_assert!(false);
                false
            }
        }
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set.iter().cloned().collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::HexString
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.set.iter().all(|s| {
            Value::validate_str_escapes(s.as_str())
                && Value::validate_singleline(s.as_str())
                && Value::validate_hexstr(s.as_str())
        })
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().cloned())
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        let mut iter = self.set.iter().cloned();
        if self.len() == 1 {
            let v = iter.next().unwrap_or_default();
            Some(v.into())
        } else {
            let arr = iter.collect::<Vec<_>>();
            Some(arr.into())
        }
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::HexString(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().cloned().map(PartialValue::HexString))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::HexString))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_hexstring_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_hexstring_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_hexstring_set(&self) -> Option<&BTreeSet<String>> {
        Some(&self.set)
    }
}

#[cfg(test)]
mod tests {
    use super::ValueSetHexString;
    use crate::prelude::ValueSet;

    #[test]
    fn test_scim_hexstring() {
        let vs: ValueSet =
            ValueSetHexString::new("D68475C760A7A0F6A924C28F095573A967F600D6".to_string());
        crate::valueset::scim_json_reflexive(&vs, r#""D68475C760A7A0F6A924C28F095573A967F600D6""#);
    }

    #[test]
    fn test_valueset_hexstring_new() {
        let vs: ValueSet = ValueSetHexString::new("0xABCD".to_string());
        assert_eq!(vs.len(), 1);
    }

    #[test]
    fn test_valueset_hexstring_insert_checked() {
        let mut vs: ValueSet = ValueSetHexString::new("0xABCD".to_string());
        assert!(vs
            .insert_checked(crate::prelude::Value::HexString("0xEF01".to_string()))
            .unwrap());
        assert!(!vs
            .insert_checked(crate::prelude::Value::HexString("0xABCD".to_string()))
            .unwrap());
        assert_eq!(vs.len(), 2);
    }

    #[test]
    fn test_valueset_hexstring_equal() {
        let vs1: ValueSet = ValueSetHexString::new("0xABCD".to_string());
        let vs2: ValueSet = ValueSetHexString::new("0xABCD".to_string());
        assert!(vs1.equal(&vs2));
    }

    #[test]
    fn test_valueset_hexstring_not_equal() {
        let vs1: ValueSet = ValueSetHexString::new("0xABCD".to_string());
        let vs2: ValueSet = ValueSetHexString::new("0xEF01".to_string());
        assert!(!vs1.equal(&vs2));
    }

    #[test]
    fn test_valueset_hexstring_merge() {
        let mut vs_a: ValueSet = ValueSetHexString::new("0xAAAA".to_string());
        let vs_b: ValueSet = ValueSetHexString::new("0xBBBB".to_string());
        vs_a.merge(&vs_b).expect("Failed to merge");
        assert_eq!(vs_a.len(), 2);
    }

    #[test]
    fn test_valueset_hexstring_clear() {
        let mut vs: ValueSet = ValueSetHexString::new("0xABCD".to_string());
        assert_eq!(vs.len(), 1);
        vs.clear();
        assert_eq!(vs.len(), 0);
    }

    #[test]
    fn test_valueset_hexstring_len() {
        let mut vs: ValueSet = ValueSetHexString::new("0x01".to_string());
        assert_eq!(vs.len(), 1);
        vs.insert_checked(crate::prelude::Value::HexString("0x02".to_string()))
            .unwrap();
        assert_eq!(vs.len(), 2);
    }

    #[test]
    fn test_valueset_hexstring_dbv2_roundtrip() {
        let mut vs: ValueSet = ValueSetHexString::new("0xCAFE".to_string());
        vs.insert_checked(crate::prelude::Value::HexString("0xBEEF".to_string()))
            .unwrap();
        let dbvs = vs.to_db_valueset_v2();
        let vs2 = crate::valueset::from_db_valueset_v2(dbvs).expect("Failed to restore");
        assert!(vs.equal(&vs2));
    }

    #[test]
    fn test_valueset_hexstring_push() {
        use crate::valueset::ValueSetT;
        let mut vs = ValueSetHexString::new("0xABCD".to_string());
        assert!(vs.push("0xEF01"));
        assert!(!vs.push("0xef01"));
        assert_eq!(vs.len(), 2);
    }

    #[test]
    fn test_valueset_hexstring_contains() {
        let vs: ValueSet = ValueSetHexString::new("0xABCD".to_string());
        assert!(vs.contains(&crate::prelude::PartialValue::HexString(
            "0xABCD".to_string()
        )));
        assert!(!vs.contains(&crate::prelude::PartialValue::HexString(
            "0xEF01".to_string()
        )));
    }

    #[test]
    fn test_valueset_hexstring_substring() {
        let vs: ValueSet = ValueSetHexString::new("0xABCDEF".to_string());
        assert!(vs.substring(&crate::prelude::PartialValue::HexString("ABCD".to_string())));
        assert!(vs.substring(&crate::prelude::PartialValue::HexString("CDEF".to_string())));
        assert!(!vs.substring(&crate::prelude::PartialValue::HexString("XYZ".to_string())));
    }
}
