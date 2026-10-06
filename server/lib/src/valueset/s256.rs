use crate::{
    prelude::*,
    schema::SchemaAttribute,
    valueset::{DbValueSetV2, ScimResolveStatus, ValueSet, ValueSetResolveStatus, ValueSetScimPut},
};
use crypto_glue::s256::Sha256Output;
use serde::Deserialize;
use serde_with::serde_as;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct ValueSetSha256 {
    set: BTreeSet<Sha256Output>,
}

impl ValueSetSha256 {
    pub fn new(v: Sha256Output) -> Box<Self> {
        let mut set = BTreeSet::new();
        set.insert(v);
        Box::new(ValueSetSha256 { set })
    }

    pub fn from_dbvs2(set: BTreeSet<Sha256Output>) -> Result<ValueSet, OperationError> {
        Ok(Box::new(Self { set }))
    }
}

#[serde_as]
#[derive(Deserialize)]
struct Sha256OutputVec {
    #[serde(flatten)]
    #[serde_as(as = "Vec<serde_with::hex::Hex>")]
    set: Vec<Vec<u8>>,
}

impl ValueSetScimPut for ValueSetSha256 {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError> {
        let value = serde_json::from_value::<Sha256OutputVec>(value).map_err(|err| {
            error!(?err, "SCIM SHA256 Syntax Invalid");
            OperationError::SC0030Sha256SyntaxInvalid
        })?;

        let set: BTreeSet<Sha256Output> = value
            .set
            .into_iter()
            .map(|bytes| {
                Sha256Output::try_from_iter(bytes).map_err(|_| {
                    error!("SCIM SHA256 Syntax Invalid");
                    OperationError::SC0030Sha256SyntaxInvalid
                })
            })
            .collect::<Result<_, OperationError>>()?;

        Ok(ValueSetResolveStatus::Resolved(Box::new(Self { set })))
    }
}

impl ValueSetT for ValueSetSha256 {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Sha256(s) => Ok(self.set.insert(s)),
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
            PartialValue::Sha256(s) => self.set.remove(s),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Sha256(s) => self.set.contains(s),
            _ => false,
        }
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.set.iter().map(hex::encode).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Sha256
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.set.iter().map(hex::encode))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        let iter = self.set.iter().cloned();
        let arr = iter.collect::<Vec<_>>();
        Some(arr.into())
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Sha256(self.set.iter().cloned().collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.set.iter().cloned().map(PartialValue::Sha256))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.set.iter().cloned().map(Value::Sha256))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_s256_set() {
            &self.set == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_s256_set() {
            mergesets!(self.set, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_s256_set(&self) -> Option<&BTreeSet<Sha256Output>> {
        Some(&self.set)
    }

    fn as_s256_set_mut(&mut self) -> Option<&mut BTreeSet<Sha256Output>> {
        Some(&mut self.set)
    }
}

#[cfg(test)]
mod tests {
    use super::ValueSetSha256;
    use crate::prelude::ValueSet;
    use crate::value::{PartialValue, Value};
    use crypto_glue::s256::Sha256Output;

    fn make_hash(val: u8) -> Sha256Output {
        let bytes: [u8; 32] = [val; 32];
        Sha256Output::try_from(bytes.as_slice()).expect("exact 32 bytes")
    }

    #[test]
    fn test_valueset_sha256_new() {
        let hash = make_hash(0xAA);
        let vs: ValueSet = ValueSetSha256::new(hash);
        assert_eq!(vs.len(), 1);
    }

    #[test]
    fn test_valueset_sha256_insert_checked() {
        let hash1 = make_hash(0x01);
        let hash2 = make_hash(0x02);
        let hash1_dup = make_hash(0x01);
        let mut vs: ValueSet = ValueSetSha256::new(hash1);
        assert!(vs.insert_checked(Value::Sha256(hash2)).unwrap());
        assert!(!vs.insert_checked(Value::Sha256(hash1_dup)).unwrap());
        assert_eq!(vs.len(), 2);
    }

    #[test]
    fn test_valueset_sha256_equal() {
        let hash = make_hash(0xAB);
        let vs1: ValueSet = ValueSetSha256::new(hash);
        let vs2: ValueSet = ValueSetSha256::new(hash);
        assert!(vs1.equal(&vs2));
    }

    #[test]
    fn test_valueset_sha256_not_equal() {
        let vs1: ValueSet = ValueSetSha256::new(make_hash(0x10));
        let vs2: ValueSet = ValueSetSha256::new(make_hash(0x20));
        assert!(!vs1.equal(&vs2));
    }

    #[test]
    fn test_valueset_sha256_merge() {
        let mut vs_a: ValueSet = ValueSetSha256::new(make_hash(0x01));
        let vs_b: ValueSet = ValueSetSha256::new(make_hash(0x02));
        vs_a.merge(&vs_b).expect("Failed to merge");
        assert_eq!(vs_a.len(), 2);
    }

    #[test]
    fn test_valueset_sha256_clear() {
        let mut vs: ValueSet = ValueSetSha256::new(make_hash(0xFF));
        assert_eq!(vs.len(), 1);
        vs.clear();
        assert_eq!(vs.len(), 0);
    }

    #[test]
    fn test_valueset_sha256_len() {
        let mut vs: ValueSet = ValueSetSha256::new(make_hash(0x01));
        assert_eq!(vs.len(), 1);
        vs.insert_checked(Value::Sha256(make_hash(0x02))).unwrap();
        assert_eq!(vs.len(), 2);
    }

    #[test]
    fn test_valueset_sha256_dbv2_roundtrip() {
        let mut vs: ValueSet = ValueSetSha256::new(make_hash(0xAA));
        vs.insert_checked(Value::Sha256(make_hash(0xBB))).unwrap();
        let dbvs = vs.to_db_valueset_v2();
        let vs2 = crate::valueset::from_db_valueset_v2(dbvs).expect("Failed to restore");
        assert!(vs.equal(&vs2));
    }

    #[test]
    fn test_valueset_sha256_contains() {
        let hash = make_hash(0xCC);
        let vs: ValueSet = ValueSetSha256::new(hash);
        assert!(vs.contains(&PartialValue::Sha256(hash)));
        assert!(!vs.contains(&PartialValue::Sha256(make_hash(0xDD))));
    }
}
