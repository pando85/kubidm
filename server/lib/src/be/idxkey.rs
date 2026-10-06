use crate::{prelude::entries::Attribute, value::IndexType};
use std::{
    borrow::Borrow,
    cmp::Ordering,
    hash::{Hash, Hasher},
};

pub type IdxSlope = u8;

// Huge props to https://github.com/sunshowers/borrow-complex-key-example/blob/master/src/lib.rs

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdxKey {
    pub attr: Attribute,
    pub itype: IndexType,
}

impl IdxKey {
    pub fn new(attr: Attribute, itype: IndexType) -> Self {
        IdxKey { attr, itype }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdxKeyRef<'a> {
    pub attr: &'a Attribute,
    pub itype: &'a IndexType,
}

impl<'a> IdxKeyRef<'a> {
    pub fn new(attr: &'a Attribute, itype: &'a IndexType) -> Self {
        IdxKeyRef { attr, itype }
    }

    pub fn as_key(&self) -> IdxKey {
        IdxKey {
            attr: self.attr.clone(),
            itype: *self.itype,
        }
    }
}

pub trait IdxKeyToRef {
    fn keyref(&self) -> IdxKeyRef<'_>;
}

impl IdxKeyToRef for IdxKeyRef<'_> {
    fn keyref(&self) -> IdxKeyRef<'_> {
        // Copy the self.
        *self
    }
}

impl IdxKeyToRef for IdxKey {
    fn keyref(&self) -> IdxKeyRef<'_> {
        IdxKeyRef {
            attr: &self.attr,
            itype: &self.itype,
        }
    }
}

impl<'a> Borrow<dyn IdxKeyToRef + 'a> for IdxKey {
    fn borrow(&self) -> &(dyn IdxKeyToRef + 'a) {
        self
    }
}

impl PartialEq for dyn IdxKeyToRef + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.keyref().eq(&other.keyref())
    }
}

impl Eq for dyn IdxKeyToRef + '_ {}

impl Hash for dyn IdxKeyToRef + '_ {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.keyref().hash(state)
    }
}

// ===== idlcachekey ======

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct IdlCacheKey {
    pub a: Attribute,
    pub i: IndexType,
    pub k: String,
}

#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct IdlCacheKeyRef<'a> {
    pub a: &'a Attribute,
    pub i: IndexType,
    pub k: &'a str,
}

/*
impl<'a> IdlCacheKeyRef<'a> {
    pub fn new(a: &'a str, i: &'a IndexType, k: &'a str) -> Self {
        IdlCacheKeyRef { a, i, k }
    }
}
*/

pub trait IdlCacheKeyToRef {
    fn keyref(&self) -> IdlCacheKeyRef<'_>;
}

impl IdlCacheKeyToRef for IdlCacheKeyRef<'_> {
    fn keyref(&self) -> IdlCacheKeyRef<'_> {
        // Copy the self
        *self
    }
}

impl IdlCacheKeyToRef for IdlCacheKey {
    fn keyref(&self) -> IdlCacheKeyRef<'_> {
        IdlCacheKeyRef {
            a: &self.a,
            i: self.i,
            k: self.k.as_str(),
        }
    }
}

impl<'a> Borrow<dyn IdlCacheKeyToRef + 'a> for IdlCacheKey {
    fn borrow(&self) -> &(dyn IdlCacheKeyToRef + 'a) {
        self
    }
}

impl PartialEq for dyn IdlCacheKeyToRef + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.keyref().eq(&other.keyref())
    }
}

impl Eq for dyn IdlCacheKeyToRef + '_ {}

impl Hash for dyn IdlCacheKeyToRef + '_ {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.keyref().hash(state)
    }
}

impl PartialOrd for dyn IdlCacheKeyToRef + '_ {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other.keyref()))
    }
}

impl Ord for dyn IdlCacheKeyToRef + '_ {
    fn cmp(&self, other: &Self) -> Ordering {
        self.keyref().cmp(&other.keyref())
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct IdxNameKey {
    pub a: Attribute,
    pub i: IndexType,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashbrown::HashMap;
    use std::collections::BTreeSet;

    #[test]
    fn test_idxkey_new_and_accessors() {
        let key = IdxKey::new(Attribute::UserId, IndexType::Equality);
        assert_eq!(key.attr, Attribute::UserId);
        assert_eq!(key.itype, IndexType::Equality);
    }

    #[test]
    fn test_idxkey_equality_same() {
        let k1 = IdxKey::new(Attribute::UserId, IndexType::Equality);
        let k2 = IdxKey::new(Attribute::UserId, IndexType::Equality);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_idxkey_equality_different_attr() {
        let k1 = IdxKey::new(Attribute::UserId, IndexType::Equality);
        let k2 = IdxKey::new(Attribute::Name, IndexType::Equality);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_idxkey_equality_different_itype() {
        let k1 = IdxKey::new(Attribute::UserId, IndexType::Equality);
        let k2 = IdxKey::new(Attribute::UserId, IndexType::Presence);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_idxkey_hash_equal_keys() {
        let k1 = IdxKey::new(Attribute::UserId, IndexType::Equality);
        let k2 = IdxKey::new(Attribute::UserId, IndexType::Equality);
        let mut map = HashMap::new();
        map.insert(k1.clone(), 1u64);
        assert_eq!(map.get(&k2), Some(&1u64));
    }

    #[test]
    fn test_idxkey_hash_different_keys() {
        let k1 = IdxKey::new(Attribute::UserId, IndexType::Equality);
        let k2 = IdxKey::new(Attribute::Name, IndexType::Presence);
        let mut map = HashMap::new();
        map.insert(k1.clone(), 1u64);
        assert_eq!(map.get(&k2), None);
    }

    #[test]
    fn test_idxkey_clone() {
        let k1 = IdxKey::new(Attribute::UserId, IndexType::Equality);
        let k2 = k1.clone();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_idxkeyref_new() {
        let attr = Attribute::UserId;
        let itype = IndexType::Equality;
        let kr = IdxKeyRef::new(&attr, &itype);
        assert_eq!(*kr.attr, Attribute::UserId);
        assert_eq!(*kr.itype, IndexType::Equality);
    }

    #[test]
    fn test_idxkeyref_as_key() {
        let attr = Attribute::UserId;
        let itype = IndexType::SubString;
        let kr = IdxKeyRef::new(&attr, &itype);
        let owned = kr.as_key();
        assert_eq!(owned.attr, Attribute::UserId);
        assert_eq!(owned.itype, IndexType::SubString);
    }

    #[test]
    fn test_idxkey_toref_roundtrip() {
        let key = IdxKey::new(Attribute::Uuid, IndexType::Presence);
        let keyref = key.keyref();
        assert_eq!(*keyref.attr, Attribute::Uuid);
        assert_eq!(*keyref.itype, IndexType::Presence);
        let back = keyref.as_key();
        assert_eq!(key, back);
    }

    #[test]
    fn test_idxkeyref_toref_identity() {
        let attr = Attribute::Name;
        let itype = IndexType::Ordering;
        let kr = IdxKeyRef::new(&attr, &itype);
        let kr2 = kr.keyref();
        assert_eq!(*kr.attr, *kr2.attr);
        assert_eq!(*kr.itype, *kr2.itype);
    }

    #[test]
    fn test_idxkeytoref_dyn_eq() {
        let k1 = IdxKey::new(Attribute::UserId, IndexType::Equality);
        let k2 = IdxKey::new(Attribute::UserId, IndexType::Equality);
        let r1: &dyn IdxKeyToRef = &k1;
        let r2: &dyn IdxKeyToRef = &k2;
        assert!(r1 == r2);
    }

    #[test]
    fn test_idxkeytoref_dyn_ne() {
        let k1 = IdxKey::new(Attribute::UserId, IndexType::Equality);
        let k2 = IdxKey::new(Attribute::Name, IndexType::Equality);
        let r1: &dyn IdxKeyToRef = &k1;
        let r2: &dyn IdxKeyToRef = &k2;
        assert!(r1 != r2);
    }

    #[test]
    fn test_idxkeytoref_dyn_hash_in_hashmap() {
        let k1 = IdxKey::new(Attribute::Uuid, IndexType::Presence);
        let k2 = IdxKey::new(Attribute::Uuid, IndexType::Presence);
        let mut map: HashMap<IdxKey, u64> = HashMap::new();
        map.insert(k1, 42);
        assert_eq!(map.get(&k2), Some(&42));
    }

    #[test]
    fn test_idlcachekey_ordering() {
        let k1 = IdlCacheKey {
            a: Attribute::UserId,
            i: IndexType::Equality,
            k: "a".to_string(),
        };
        let k2 = IdlCacheKey {
            a: Attribute::UserId,
            i: IndexType::Equality,
            k: "b".to_string(),
        };
        assert!(k1 < k2);
    }

    #[test]
    fn test_idlcachekey_equality() {
        let k1 = IdlCacheKey {
            a: Attribute::Name,
            i: IndexType::SubString,
            k: "test".to_string(),
        };
        let k2 = IdlCacheKey {
            a: Attribute::Name,
            i: IndexType::SubString,
            k: "test".to_string(),
        };
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_idlcachekey_hash_in_btreeset() {
        let k1 = IdlCacheKey {
            a: Attribute::Uuid,
            i: IndexType::Equality,
            k: "key1".to_string(),
        };
        let k2 = IdlCacheKey {
            a: Attribute::Uuid,
            i: IndexType::Equality,
            k: "key1".to_string(),
        };
        let mut set = BTreeSet::new();
        set.insert(k1);
        assert!(set.contains(&k2));
    }

    #[test]
    fn test_idlcachekey_toref_roundtrip() {
        let key = IdlCacheKey {
            a: Attribute::UserId,
            i: IndexType::Equality,
            k: "value".to_string(),
        };
        let keyref = key.keyref();
        assert_eq!(*keyref.a, Attribute::UserId);
        assert_eq!(keyref.i, IndexType::Equality);
        assert_eq!(keyref.k, "value");
    }

    #[test]
    fn test_idlcachekeyref_toref_identity() {
        let attr = Attribute::Name;
        let k = "test";
        let kr = IdlCacheKeyRef {
            a: &attr,
            i: IndexType::Presence,
            k,
        };
        let kr2 = kr.keyref();
        assert_eq!(*kr.a, *kr2.a);
        assert_eq!(kr.i, kr2.i);
        assert_eq!(kr.k, kr2.k);
    }

    #[test]
    fn test_idlcachekeytoref_dyn_eq() {
        let k1 = IdlCacheKey {
            a: Attribute::UserId,
            i: IndexType::Equality,
            k: "x".to_string(),
        };
        let k2 = IdlCacheKey {
            a: Attribute::UserId,
            i: IndexType::Equality,
            k: "x".to_string(),
        };
        let r1: &dyn IdlCacheKeyToRef = &k1;
        let r2: &dyn IdlCacheKeyToRef = &k2;
        assert!(r1 == r2);
    }

    #[test]
    fn test_idlcachekeytoref_dyn_ordering() {
        let k1 = IdlCacheKey {
            a: Attribute::Name,
            i: IndexType::Equality,
            k: "a".to_string(),
        };
        let k2 = IdlCacheKey {
            a: Attribute::Name,
            i: IndexType::Equality,
            k: "b".to_string(),
        };
        let r1: &dyn IdlCacheKeyToRef = &k1;
        let r2: &dyn IdlCacheKeyToRef = &k2;
        assert!(r1 < r2);
    }

    #[test]
    fn test_idlcachekeytoref_dyn_hash() {
        let k1 = IdlCacheKey {
            a: Attribute::Uuid,
            i: IndexType::Presence,
            k: "hash_test".to_string(),
        };
        let k2 = IdlCacheKey {
            a: Attribute::Uuid,
            i: IndexType::Presence,
            k: "hash_test".to_string(),
        };
        let mut map: HashMap<IdlCacheKey, u64> = HashMap::new();
        map.insert(k1, 99);
        assert_eq!(map.get(&k2), Some(&99));
    }

    #[test]
    fn test_idxnamekey_ordering() {
        let k1 = IdxNameKey {
            a: Attribute::UserId,
            i: IndexType::Equality,
        };
        let k2 = IdxNameKey {
            a: Attribute::UserId,
            i: IndexType::Presence,
        };
        assert!(k1 < k2);
    }

    #[test]
    fn test_idxnamekey_equality() {
        let k1 = IdxNameKey {
            a: Attribute::Name,
            i: IndexType::SubString,
        };
        let k2 = IdxNameKey {
            a: Attribute::Name,
            i: IndexType::SubString,
        };
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_idxnamekey_hash_in_btreeset() {
        let k1 = IdxNameKey {
            a: Attribute::Uuid,
            i: IndexType::Equality,
        };
        let k2 = IdxNameKey {
            a: Attribute::Uuid,
            i: IndexType::Equality,
        };
        let mut set = BTreeSet::new();
        set.insert(k1);
        assert!(set.contains(&k2));
    }

    #[test]
    fn test_idxslope_comparison() {
        let s1: IdxSlope = 0;
        let s2: IdxSlope = 255;
        assert!(s1 < s2);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_idxslope_equality() {
        let s1: IdxSlope = 42;
        let s2: IdxSlope = 42;
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_all_index_types_with_idxkey() {
        let types = [
            IndexType::Equality,
            IndexType::Presence,
            IndexType::SubString,
            IndexType::Ordering,
        ];
        for itype in types {
            let key = IdxKey::new(Attribute::UserId, itype);
            let ref_key = key.keyref();
            let back = ref_key.as_key();
            assert_eq!(key, back);
        }
    }
}
