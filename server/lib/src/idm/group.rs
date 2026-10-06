use std::collections::BTreeSet;

use kubidm_proto::{
    internal::{Group as ProtoGroup, UiHint},
    v1::UnixGroupToken,
};
use uuid::Uuid;

use crate::{
    entry::{Committed, Entry, EntryCommitted, EntrySealed, GetUuid},
    prelude::*,
    value::PartialValue,
};

use super::accountpolicy::{AccountPolicy, ResolvedAccountPolicy};

// I hate that rust is forcing this to be public
pub trait GroupType {}

#[derive(Debug, Clone)]
pub(crate) struct Unix {
    name: String,
    gidnumber: u32,
}

impl GroupType for Unix {}

impl GroupType for () {}

#[derive(Debug, Clone)]
pub struct Group<T>
where
    T: GroupType,
{
    inner: T,
    spn: String,
    name: Option<String>,
    uuid: Uuid,
    // We'll probably add policy and claims later to this
    ui_hints: BTreeSet<UiHint>,
}

macro_rules! try_from_entry {
    ($value:expr, $inner:expr) => {{
        let spn = $value
            .get_ava_single_proto_string(Attribute::Spn)
            .ok_or_else(|| OperationError::MissingAttribute(Attribute::Spn))?;

        let name = $value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string());

        let uuid = $value.get_uuid();

        let ui_hints = $value
            .get_ava_uihint(Attribute::GrantUiHint)
            .cloned()
            .unwrap_or_default();

        Ok(Self {
            inner: $inner,
            name,
            spn,
            uuid,
            ui_hints,
        })
    }};
}

impl<T: GroupType> Group<T> {
    pub fn spn(&self) -> &String {
        &self.spn
    }

    pub fn uuid(&self) -> &Uuid {
        &self.uuid
    }

    pub fn name(&self) -> Option<&String> {
        self.name.as_ref()
    }

    pub fn ui_hints(&self) -> &BTreeSet<UiHint> {
        &self.ui_hints
    }

    pub fn to_proto(&self) -> ProtoGroup {
        ProtoGroup {
            spn: self.spn.clone(),
            uuid: self.uuid.as_hyphenated().to_string(),
        }
    }
}

macro_rules! try_from_account {
    ($value:expr, $qs:expr) => {{
        let Some(iter) = $value.get_ava_as_refuuid(Attribute::MemberOf) else {
            return Ok(vec![]);
        };

        // given a list of uuid, make a filter: even if this is empty, the be will
        // just give and empty result set.
        let f = filter!(f_or(
            iter.map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
                .collect()
        ));

        let entries = $qs.internal_search(f).map_err(|e| {
            admin_error!(?e, "internal search failed");
            e
        })?;

        Ok(entries
            .iter()
            .map(|entry| Self::try_from_entry(&entry))
            .filter_map(|v| v.ok())
            .collect())
    }};
}

impl Group<()> {
    pub fn try_from_account<'a, TXN>(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut TXN,
    ) -> Result<Vec<Group<()>>, OperationError>
    where
        TXN: QueryServerTransaction<'a>,
    {
        if !value.attribute_equality(Attribute::Class, &EntryClass::Account.into()) {
            return Err(OperationError::MissingClass(ENTRYCLASS_ACCOUNT.into()));
        }

        let user_group = try_from_entry!(value, ())?;
        Ok(std::iter::once(user_group)
            .chain(Self::try_from_account_reduced(value, qs)?)
            .collect())
    }

    pub fn try_from_account_reduced<'a, E, TXN>(
        value: &Entry<E, EntryCommitted>,
        qs: &mut TXN,
    ) -> Result<Vec<Group<()>>, OperationError>
    where
        E: Committed,
        TXN: QueryServerTransaction<'a>,
    {
        try_from_account!(value, qs)
    }

    pub fn try_from_entry<E>(value: &Entry<E, EntryCommitted>) -> Result<Self, OperationError>
    where
        E: Committed,
        Entry<E, EntryCommitted>: GetUuid,
    {
        if !value.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
            return Err(OperationError::MissingAttribute(Attribute::Group));
        }

        try_from_entry!(value, ())
    }
}

impl Group<Unix> {
    pub fn try_from_account<'a, TXN>(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut TXN,
    ) -> Result<Vec<Group<Unix>>, OperationError>
    where
        TXN: QueryServerTransaction<'a>,
    {
        if !value.attribute_equality(Attribute::Class, &EntryClass::Account.into()) {
            return Err(OperationError::MissingClass(ENTRYCLASS_ACCOUNT.into()));
        }

        if !value.attribute_equality(Attribute::Class, &EntryClass::PosixAccount.into()) {
            return Err(OperationError::MissingClass(
                ENTRYCLASS_POSIX_ACCOUNT.into(),
            ));
        }

        let name = value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string())
            .ok_or_else(|| OperationError::MissingAttribute(Attribute::Name))?;

        let gidnumber = value
            .get_ava_single_uint32(Attribute::GidNumber)
            .ok_or_else(|| OperationError::MissingAttribute(Attribute::GidNumber))?;

        let user_group = try_from_entry!(value, Unix { name, gidnumber })?;

        Ok(std::iter::once(user_group)
            .chain(Self::try_from_account_reduced(value, qs)?)
            .collect())
    }

    pub fn try_from_account_reduced<'a, E, TXN>(
        value: &Entry<E, EntryCommitted>,
        qs: &mut TXN,
    ) -> Result<Vec<Group<Unix>>, OperationError>
    where
        E: Committed,
        TXN: QueryServerTransaction<'a>,
    {
        try_from_account!(value, qs)
    }

    fn check_entry_classes<E>(value: &Entry<E, EntryCommitted>) -> Result<(), OperationError>
    where
        E: Committed,
        Entry<E, EntryCommitted>: GetUuid,
    {
        // If its an account, it must be a posix account
        if value.attribute_equality(Attribute::Class, &EntryClass::Account.into()) {
            if !value.attribute_equality(Attribute::Class, &EntryClass::PosixAccount.into()) {
                return Err(OperationError::MissingClass(
                    ENTRYCLASS_POSIX_ACCOUNT.into(),
                ));
            }
        } else {
            // Otherwise it must be both a group and a posix group
            if !value.attribute_equality(Attribute::Class, &EntryClass::PosixGroup.into()) {
                return Err(OperationError::MissingClass(ENTRYCLASS_POSIX_GROUP.into()));
            }

            if !value.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
                return Err(OperationError::MissingAttribute(Attribute::Group));
            }
        }
        Ok(())
    }

    pub fn try_from_entry<E>(value: &Entry<E, EntryCommitted>) -> Result<Self, OperationError>
    where
        E: Committed,
        Entry<E, EntryCommitted>: GetUuid,
    {
        Self::check_entry_classes(value)?;

        let name = value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string())
            .ok_or_else(|| OperationError::MissingAttribute(Attribute::Name))?;

        let gidnumber = value
            .get_ava_single_uint32(Attribute::GidNumber)
            .ok_or_else(|| OperationError::MissingAttribute(Attribute::GidNumber))?;

        try_from_entry!(value, Unix { name, gidnumber })
    }

    pub(crate) fn to_unixgrouptoken(&self) -> UnixGroupToken {
        UnixGroupToken {
            name: self.inner.name.clone(),
            spn: self.spn.clone(),
            uuid: self.uuid,
            gidnumber: self.inner.gidnumber,
        }
    }
}

pub(crate) fn load_account_policy<'a, T>(
    value: &Entry<EntrySealed, EntryCommitted>,
    qs: &mut T,
) -> Result<ResolvedAccountPolicy, OperationError>
where
    T: QueryServerTransaction<'a>,
{
    let iter = match value.get_ava_as_refuuid(Attribute::MemberOf) {
        Some(v) => v,
        None => Box::new(Vec::<Uuid>::new().into_iter()),
    };

    // given a list of uuid, make a filter: even if this is empty, the be will
    // just give and empty result set.
    let f = filter!(f_or(
        iter.map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
            .collect()
    ));

    let entries = qs.internal_search(f).map_err(|e| {
        admin_error!(?e, "internal search failed");
        e
    })?;

    Ok(ResolvedAccountPolicy::fold_from(entries.iter().filter_map(
        |entry| {
            let acc_pol: Option<AccountPolicy> = entry.as_ref().into();
            acc_pol
        },
    )))
}

pub(crate) fn load_all_groups_from_account<'a, E, TXN>(
    value: &Entry<E, EntryCommitted>,
    qs: &mut TXN,
) -> Result<(Vec<Group<()>>, Vec<Group<Unix>>), OperationError>
where
    E: Committed,
    Entry<E, EntryCommitted>: GetUuid,
    TXN: QueryServerTransaction<'a>,
{
    let Some(iter) = value.get_ava_as_refuuid(Attribute::MemberOf) else {
        return Ok((vec![], vec![]));
    };

    let conditions: Vec<_> = iter
        .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
        .collect();

    let f = filter!(f_or(conditions));

    let entries = qs.internal_search(f).map_err(|e| {
        admin_error!(?e, "internal search failed");
        e
    })?;

    let mut groups = vec![];
    let mut unix_groups = Group::<Unix>::try_from_entry(value)
        .ok()
        .into_iter()
        .collect::<Vec<_>>();

    for entry in entries.iter() {
        let entry = entry.as_ref();
        if entry.attribute_equality(Attribute::Class, &EntryClass::PosixGroup.into()) {
            unix_groups.push(Group::<Unix>::try_from_entry::<EntrySealed>(entry)?);
        }

        // No idea why we need to explicitly specify the type here
        groups.push(Group::<()>::try_from_entry::<EntrySealed>(entry)?);
    }

    Ok((groups, unix_groups))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kubidm_proto::internal::UiHint;
    use kubidm_proto::v1::UnixGroupToken;
    use std::collections::BTreeSet;

    fn make_group() -> Group<()> {
        Group {
            inner: (),
            spn: "testgroup@example.com".to_string(),
            name: Some("testgroup".to_string()),
            uuid: Uuid::new_v4(),
            ui_hints: BTreeSet::new(),
        }
    }

    fn make_unix_group() -> Group<Unix> {
        Group {
            inner: Unix {
                name: "posixgroup".to_string(),
                gidnumber: 10001,
            },
            spn: "posixgroup@example.com".to_string(),
            name: Some("posixgroup".to_string()),
            uuid: Uuid::new_v4(),
            ui_hints: BTreeSet::new(),
        }
    }

    #[test]
    fn test_group_spn() {
        let group = make_group();
        assert_eq!(group.spn(), "testgroup@example.com");
    }

    #[test]
    fn test_group_uuid() {
        let uuid = Uuid::new_v4();
        let group = Group {
            inner: (),
            spn: "g@example.com".to_string(),
            name: None,
            uuid,
            ui_hints: BTreeSet::new(),
        };
        assert_eq!(group.uuid(), &uuid);
    }

    #[test]
    fn test_group_name_some() {
        let group = make_group();
        assert_eq!(group.name(), Some(&"testgroup".to_string()));
    }

    #[test]
    fn test_group_name_none() {
        let group = Group {
            inner: (),
            spn: "g@example.com".to_string(),
            name: None,
            uuid: Uuid::new_v4(),
            ui_hints: BTreeSet::new(),
        };
        assert_eq!(group.name(), None);
    }

    #[test]
    fn test_group_ui_hints_empty() {
        let group = make_group();
        assert!(group.ui_hints().is_empty());
    }

    #[test]
    fn test_group_ui_hints_with_values() {
        let mut hints = BTreeSet::new();
        hints.insert(UiHint::PosixAccount);
        hints.insert(UiHint::CredentialUpdate);
        let group = Group {
            inner: (),
            spn: "g@example.com".to_string(),
            name: None,
            uuid: Uuid::new_v4(),
            ui_hints: hints,
        };
        assert_eq!(group.ui_hints().len(), 2);
        assert!(group.ui_hints().contains(&UiHint::PosixAccount));
        assert!(group.ui_hints().contains(&UiHint::CredentialUpdate));
    }

    #[test]
    fn test_group_to_proto() {
        let uuid = Uuid::new_v4();
        let group = Group {
            inner: (),
            spn: "testgroup@example.com".to_string(),
            name: Some("testgroup".to_string()),
            uuid,
            ui_hints: BTreeSet::new(),
        };
        let proto = group.to_proto();
        assert_eq!(proto.spn, "testgroup@example.com");
        assert_eq!(proto.uuid, uuid.as_hyphenated().to_string());
    }

    #[test]
    fn test_group_to_proto_uuid_format() {
        let uuid = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        let group = Group {
            inner: (),
            spn: "g@example.com".to_string(),
            name: None,
            uuid,
            ui_hints: BTreeSet::new(),
        };
        let proto = group.to_proto();
        assert_eq!(proto.uuid, "01234567-89ab-cdef-0123-456789abcdef");
    }

    #[test]
    fn test_unix_group_to_unixgrouptoken() {
        let uuid = Uuid::new_v4();
        let group = Group {
            inner: Unix {
                name: "posixgroup".to_string(),
                gidnumber: 10001,
            },
            spn: "posixgroup@example.com".to_string(),
            name: Some("posixgroup".to_string()),
            uuid,
            ui_hints: BTreeSet::new(),
        };
        let token = group.to_unixgrouptoken();
        assert_eq!(token.name, "posixgroup");
        assert_eq!(token.spn, "posixgroup@example.com");
        assert_eq!(token.uuid, uuid);
        assert_eq!(token.gidnumber, 10001);
    }

    #[test]
    fn test_unix_group_spn() {
        let group = make_unix_group();
        assert_eq!(group.spn(), "posixgroup@example.com");
    }

    #[test]
    fn test_unix_group_uuid() {
        let uuid = Uuid::new_v4();
        let group = Group {
            inner: Unix {
                name: "g".to_string(),
                gidnumber: 200,
            },
            spn: "g@example.com".to_string(),
            name: None,
            uuid,
            ui_hints: BTreeSet::new(),
        };
        assert_eq!(group.uuid(), &uuid);
    }

    #[test]
    fn test_unix_group_to_proto() {
        let uuid = Uuid::new_v4();
        let group = Group {
            inner: Unix {
                name: "g".to_string(),
                gidnumber: 300,
            },
            spn: "g@example.com".to_string(),
            name: Some("g".to_string()),
            uuid,
            ui_hints: BTreeSet::new(),
        };
        let proto = group.to_proto();
        assert_eq!(proto.spn, "g@example.com");
        assert_eq!(proto.uuid, uuid.as_hyphenated().to_string());
    }

    #[test]
    fn test_unix_group_name() {
        let group = make_unix_group();
        assert_eq!(group.name(), Some(&"posixgroup".to_string()));
    }

    #[test]
    fn test_unix_group_ui_hints() {
        let group = make_unix_group();
        assert!(group.ui_hints().is_empty());
    }

    #[test]
    fn test_unix_group_token_display() {
        let uuid = Uuid::new_v4();
        let token = UnixGroupToken {
            name: "testgroup".to_string(),
            spn: "testgroup@example.com".to_string(),
            uuid,
            gidnumber: 10001,
        };
        let display = token.to_string();
        assert!(display.contains("testgroup@example.com"));
        assert!(display.contains("10001"));
        assert!(display.contains("testgroup"));
    }

    #[test]
    fn test_proto_group_display() {
        let proto = kubidm_proto::internal::Group {
            spn: "group@example.com".to_string(),
            uuid: Uuid::new_v4().as_hyphenated().to_string(),
        };
        let display = proto.to_string();
        assert!(display.contains("group@example.com"));
    }

    #[test]
    fn test_group_clone() {
        let group = make_group();
        let cloned = group.clone();
        assert_eq!(group.spn(), cloned.spn());
        assert_eq!(group.uuid(), cloned.uuid());
        assert_eq!(group.name(), cloned.name());
    }

    #[test]
    fn test_unix_group_clone() {
        let group = make_unix_group();
        let cloned = group.clone();
        assert_eq!(group.spn(), cloned.spn());
        assert_eq!(group.uuid(), cloned.uuid());
    }

    #[test]
    fn test_group_debug_format() {
        let group = make_group();
        let debug = format!("{:?}", group);
        assert!(debug.contains("testgroup@example.com"));
    }

    #[test]
    fn test_unix_inner_debug() {
        let inner = Unix {
            name: "test".to_string(),
            gidnumber: 12345,
        };
        let debug = format!("{:?}", inner);
        assert!(debug.contains("test"));
        assert!(debug.contains("12345"));
    }

    #[test]
    fn test_unix_group_token_serde_roundtrip() {
        let uuid = Uuid::new_v4();
        let token = UnixGroupToken {
            name: "testgroup".to_string(),
            spn: "testgroup@example.com".to_string(),
            uuid,
            gidnumber: 10001,
        };
        let json = serde_json::to_string(&token).unwrap();
        let parsed: UnixGroupToken = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, token.name);
        assert_eq!(parsed.spn, token.spn);
        assert_eq!(parsed.uuid, token.uuid);
        assert_eq!(parsed.gidnumber, token.gidnumber);
    }

    #[test]
    fn test_proto_group_serde_roundtrip() {
        let proto = kubidm_proto::internal::Group {
            spn: "group@example.com".to_string(),
            uuid: Uuid::new_v4().as_hyphenated().to_string(),
        };
        let json = serde_json::to_string(&proto).unwrap();
        let parsed: kubidm_proto::internal::Group = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.spn, proto.spn);
        assert_eq!(parsed.uuid, proto.uuid);
    }

    #[test]
    fn test_unix_group_max_gidnumber() {
        let group = Group {
            inner: Unix {
                name: "maxgid".to_string(),
                gidnumber: u32::MAX,
            },
            spn: "maxgid@example.com".to_string(),
            name: Some("maxgid".to_string()),
            uuid: Uuid::new_v4(),
            ui_hints: BTreeSet::new(),
        };
        assert_eq!(group.to_unixgrouptoken().gidnumber, u32::MAX);
    }

    #[test]
    fn test_unix_group_min_gidnumber() {
        let group = Group {
            inner: Unix {
                name: "mingid".to_string(),
                gidnumber: 0,
            },
            spn: "mingid@example.com".to_string(),
            name: Some("mingid".to_string()),
            uuid: Uuid::new_v4(),
            ui_hints: BTreeSet::new(),
        };
        assert_eq!(group.to_unixgrouptoken().gidnumber, 0);
    }

    #[test]
    fn test_group_ui_hints_btree_ordering() {
        let mut hints = BTreeSet::new();
        hints.insert(UiHint::SynchronisedAccount);
        hints.insert(UiHint::ExperimentalFeatures);
        hints.insert(UiHint::PosixAccount);
        let group = Group {
            inner: (),
            spn: "g@example.com".to_string(),
            name: None,
            uuid: Uuid::new_v4(),
            ui_hints: hints.clone(),
        };
        let collected: Vec<_> = group.ui_hints().iter().collect();
        let mut expected: Vec<_> = hints.iter().collect();
        expected.sort();
        assert_eq!(collected, expected);
    }
}
