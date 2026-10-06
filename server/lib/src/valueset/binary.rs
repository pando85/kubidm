use crate::{
    prelude::*,
    schema::SchemaAttribute,
    utils::trigraph_iter,
    valueset::{DbValueSetV2, ScimResolveStatus, ValueSet},
};
use base64urlsafedata::Base64UrlSafeData;
use kubidm_proto::scim_v1::server::ScimBinary;
use smolset::SmolSet;
use std::collections::{btree_map::Entry as BTreeEntry, BTreeMap};

#[derive(Debug, Clone)]
pub struct ValueSetPrivateBinary {
    set: SmolSet<[Vec<u8>; 1]>,
}

impl ValueSetPrivateBinary {
    pub fn new(b: Vec<u8>) -> Box<Self> {
        let mut set = SmolSet::new();
        set.insert(b);
        Box::new(ValueSetPrivateBinary { set })
    }

    pub fn push(&mut self, b: Vec<u8>) -> bool {
        self.set.insert(b)
    }

    pub fn from_dbvs2(data: Vec<Vec<u8>>) -> Result<ValueSet, OperationError> {
        let set = data.into_iter().collect();
        Ok(Box::new(ValueSetPrivateBinary { set }))
    }

    pub fn from_repl_v1(data: &[Base64UrlSafeData]) -> Result<ValueSet, OperationError> {
        let set = data.iter().map(|b| b.to_vec()).collect();
        Ok(Box::new(ValueSetPrivateBinary { set }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and vec is foreign
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<ValueSetPrivateBinary>>
    where
        T: IntoIterator<Item = Vec<u8>>,
    {
        let set = iter.into_iter().collect();
        Some(Box::new(ValueSetPrivateBinary { set }))
    }
}

impl ValueSetT for ValueSetPrivateBinary {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::PrivateBinary(u) => Ok(self.set.insert(u)),
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.set.clear();
    }

    fn remove(&mut self, _pv: &PartialValue, _cid: &Cid) -> bool {
        true
    }

    fn contains(&self, _pv: &PartialValue) -> bool {
        false
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
        Vec::with_capacity(0)
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::PrivateBinary
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(|_| "private_binary".to_string()))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        None
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::PrivateBinary(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().map(|_| PartialValue::PrivateBinary))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::PrivateBinary))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_private_binary_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_private_binary_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn to_private_binary_single(&self) -> Option<&[u8]> {
        if self.set.len() == 1 {
            self.set.iter().map(|b| b.as_slice()).take(1).next()
        } else {
            None
        }
    }

    fn as_private_binary_set(&self) -> Option<&SmolSet<[Vec<u8>; 1]>> {
        Some(&self.set)
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetPublicBinary {
    map: BTreeMap<String, Vec<u8>>,
}

impl ValueSetPublicBinary {
    pub fn new(t: String, b: Vec<u8>) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(t, b);
        Box::new(ValueSetPublicBinary { map })
    }

    pub fn push(&mut self, t: String, b: Vec<u8>) -> bool {
        self.map.insert(t, b).is_none()
    }

    pub fn from_dbvs2(data: Vec<(String, Vec<u8>)>) -> Result<ValueSet, OperationError> {
        let map = data.into_iter().collect();
        Ok(Box::new(ValueSetPublicBinary { map }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<ValueSetPublicBinary>>
    where
        T: IntoIterator<Item = (String, Vec<u8>)>,
    {
        let map = iter.into_iter().collect();
        Some(Box::new(ValueSetPublicBinary { map }))
    }
}

impl ValueSetT for ValueSetPublicBinary {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::PublicBinary(t, b) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(t) {
                    e.insert(b);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        match pv {
            PartialValue::PublicBinary(t) => self.map.remove(t.as_str()).is_some(),
            _ => false,
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::PublicBinary(t) => self.map.contains_key(t.as_str()),
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
        self.map.keys().cloned().collect()
    }

    fn generate_idx_sub_keys(&self) -> Vec<String> {
        let lower: Vec<_> = self.map.keys().map(|s| s.to_lowercase()).collect();
        let mut trigraphs: Vec<_> = lower.iter().flat_map(|v| trigraph_iter(v)).collect();

        trigraphs.sort_unstable();
        trigraphs.dedup();

        trigraphs.into_iter().map(String::from).collect()
    }

    fn syntax(&self) -> SyntaxType {
        // Apparently I never actually implemented this type in ... anything?
        // We should probably clean up syntax soon .....
        //
        // SyntaxType::PublicBinary
        unreachable!()
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.map
            .iter()
            .all(|(s, _)| Value::validate_str_escapes(s) && Value::validate_singleline(s))
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.keys().cloned())
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKubidm::from(
            self.map
                .iter()
                .map(|(tag, bin)| ScimBinary {
                    label: tag.clone(),
                    value: bin.clone(),
                })
                .collect::<Vec<_>>(),
        )))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::PublicBinary(
            self.map
                .iter()
                .map(|(tag, bin)| (tag.clone(), bin.clone()))
                .collect(),
        )
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::PublicBinary))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(t, b)| Value::PublicBinary(t.clone(), b.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_publicbinary_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_publicbinary_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_publicbinary_map(&self) -> Option<&BTreeMap<String, Vec<u8>>> {
        Some(&self.map)
    }
}

#[cfg(test)]
mod tests {
    use super::ValueSetPrivateBinary;
    use crate::prelude::ValueSet;

    #[test]
    fn test_scim_private_binary() {
        let vs: ValueSet = ValueSetPrivateBinary::new(vec![0x00]);

        assert!(vs.to_scim_value().is_none());
    }

    #[test]
    fn test_valueset_private_binary_new() {
        let vs: ValueSet = ValueSetPrivateBinary::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(vs.len(), 1);
    }

    #[test]
    fn test_valueset_private_binary_insert() {
        let mut vs: ValueSet = ValueSetPrivateBinary::new(vec![0x01]);
        assert!(vs
            .insert_checked(crate::prelude::Value::PrivateBinary(vec![0x02]))
            .unwrap());
        assert!(!vs
            .insert_checked(crate::prelude::Value::PrivateBinary(vec![0x01]))
            .unwrap());
        assert_eq!(vs.len(), 2);
    }

    #[test]
    fn test_valueset_private_binary_equal() {
        let vs1: ValueSet = ValueSetPrivateBinary::new(vec![0xAA, 0xBB]);
        let vs2: ValueSet = ValueSetPrivateBinary::new(vec![0xAA, 0xBB]);
        assert!(vs1.equal(&vs2));
    }

    #[test]
    fn test_valueset_private_binary_merge() {
        let mut vs_a: ValueSet = ValueSetPrivateBinary::new(vec![0x01]);
        let vs_b: ValueSet = ValueSetPrivateBinary::new(vec![0x02]);
        vs_a.merge(&vs_b).expect("Failed to merge");
        assert_eq!(vs_a.len(), 2);
    }

    #[test]
    fn test_valueset_private_binary_clear() {
        let mut vs: ValueSet = ValueSetPrivateBinary::new(vec![0x00]);
        vs.clear();
        assert_eq!(vs.len(), 0);
    }

    #[test]
    fn test_valueset_private_binary_to_single() {
        let vs: ValueSet = ValueSetPrivateBinary::new(vec![0xAB, 0xCD]);
        assert_eq!(vs.to_private_binary_single(), Some([0xAB, 0xCD].as_slice()));
    }

    #[test]
    fn test_valueset_private_binary_to_single_none_when_multiple() {
        let mut vs: ValueSet = ValueSetPrivateBinary::new(vec![0x01]);
        vs.insert_checked(crate::prelude::Value::PrivateBinary(vec![0x02]))
            .unwrap();
        assert_eq!(vs.to_private_binary_single(), None);
    }

    #[test]
    fn test_valueset_private_binary_dbv2_roundtrip() {
        let vs: ValueSet = ValueSetPrivateBinary::new(vec![0xCA, 0xFE]);
        let dbvs = vs.to_db_valueset_v2();
        let vs2 = crate::valueset::from_db_valueset_v2(dbvs).expect("Failed to restore");
        assert!(vs.equal(&vs2));
    }
}
