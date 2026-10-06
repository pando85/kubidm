use crate::prelude::{Attribute, EntryClass};
use std::{collections::BTreeSet, sync::LazyLock};

/// These entry classes can be modified by migrations. All protection rules still
/// apply.
pub static MIGRATION_ENTRY_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::Object,
        EntryClass::MemberOf,
        EntryClass::DomainInfo,
        EntryClass::OAuth2ResourceServer,
        EntryClass::OAuth2ResourceServerBasic,
        EntryClass::OAuth2ResourceServerPublic,
        EntryClass::Account,
        EntryClass::Person,
        EntryClass::PosixAccount,
        EntryClass::Group,
        EntryClass::DynGroup,
        EntryClass::AccountPolicy,
        EntryClass::PosixGroup,
        EntryClass::ServiceAccount,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

pub static MIGRATION_IGNORE_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::KeyObject,
        EntryClass::KeyObjectInternal,
        EntryClass::KeyObjectHkdfS256,
        EntryClass::KeyObjectJwtEs256,
        EntryClass::KeyObjectJwtHs256,
        EntryClass::KeyObjectJwtRs256,
        EntryClass::KeyObjectJweA128GCM,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

pub fn migration_entry_attrs(
    classes: &BTreeSet<String>,
) -> (BTreeSet<Attribute>, BTreeSet<&'static str>) {
    let mut allow_attrs = BTreeSet::default();
    let mut allow_cls: BTreeSet<&'static str> = BTreeSet::default();

    // Base attributes to always allow
    allow_attrs.extend([Attribute::Class, Attribute::Uuid]);

    if classes.contains(EntryClass::DomainInfo.into()) {
        allow_attrs.extend([
            Attribute::DomainLdapBasedn,
            Attribute::LdapMaxQueryableAttrs,
            Attribute::LdapAllowUnixPwBind,
            Attribute::DomainDisplayName,
        ]);
    }

    if classes.contains(EntryClass::Group.into()) {
        allow_cls.clear();
        allow_cls.extend([
            EntryClass::Group.as_ref(),
            EntryClass::AccountPolicy.as_ref(),
            EntryClass::PosixGroup.as_ref(),
        ]);
        allow_attrs.extend([
            Attribute::Member,
            Attribute::Name,
            Attribute::Description,
            Attribute::EntryManagedBy,
            Attribute::GidNumber,
        ])
    }

    if classes.contains(EntryClass::Person.into()) {
        allow_cls.clear();
        allow_cls.extend([
            EntryClass::Person.as_ref(),
            EntryClass::Account.as_ref(),
            EntryClass::PosixAccount.as_ref(),
        ]);
        allow_attrs.extend([
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::Mail,
            Attribute::SshPublicKey,
            Attribute::Description,
            Attribute::LoginShell,
            Attribute::GidNumber,
        ])
    }

    if classes.contains(EntryClass::ServiceAccount.into()) {
        allow_cls.clear();
        allow_cls.extend([
            EntryClass::Account.as_ref(),
            EntryClass::ServiceAccount.as_ref(),
        ]);
        allow_attrs.extend([
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::Mail,
            Attribute::SshPublicKey,
            Attribute::Description,
            Attribute::EntryManagedBy,
        ])
    }

    if classes.contains(EntryClass::AccountPolicy.into()) {
        allow_attrs.extend([
            Attribute::AuthSessionExpiry,
            Attribute::AuthPasswordMinimumLength,
            Attribute::CredentialTypeMinimum,
            Attribute::PrivilegeExpiry,
            Attribute::WebauthnAttestationCaList,
            Attribute::LimitSearchMaxResults,
            Attribute::LimitSearchMaxFilterTest,
            Attribute::AllowPrimaryCredFallback,
        ]);
    }

    if classes.contains(EntryClass::OAuth2ResourceServer.into()) {
        allow_cls.clear();
        allow_cls.extend([
            EntryClass::Account.as_ref(),
            EntryClass::OAuth2ResourceServer.as_ref(),
            EntryClass::OAuth2ResourceServerBasic.as_ref(),
            EntryClass::OAuth2ResourceServerPublic.as_ref(),
        ]);
        allow_attrs.extend([
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::Description,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2RsClaimMap,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2ConsentPromptEnable,
            Attribute::EntryManagedBy,
        ])
    }

    (allow_attrs, allow_cls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_entry_classes_not_empty() {
        assert!(!MIGRATION_ENTRY_CLASSES.is_empty());
        assert!(!MIGRATION_IGNORE_CLASSES.is_empty());
    }

    #[test]
    fn test_migration_entry_classes_contains_expected() {
        assert!(MIGRATION_ENTRY_CLASSES.contains("object"));
        assert!(MIGRATION_ENTRY_CLASSES.contains("account"));
        assert!(MIGRATION_ENTRY_CLASSES.contains("person"));
        assert!(MIGRATION_ENTRY_CLASSES.contains("group"));
        assert!(MIGRATION_ENTRY_CLASSES.contains("service_account"));
    }

    #[test]
    fn test_migration_ignore_classes_contains_key_objects() {
        assert!(MIGRATION_IGNORE_CLASSES.contains("key_object"));
        assert!(MIGRATION_IGNORE_CLASSES.contains("key_object_internal"));
        assert!(MIGRATION_IGNORE_CLASSES.contains("key_object_hkdf_s256"));
        assert!(MIGRATION_IGNORE_CLASSES.contains("key_object_jwt_es256"));
    }

    #[test]
    fn test_migration_entry_attrs_empty_classes() {
        let (attrs, cls) = migration_entry_attrs(&BTreeSet::new());
        // Should always have class and uuid
        assert!(attrs.contains(&Attribute::Class));
        assert!(attrs.contains(&Attribute::Uuid));
        // No class-specific attrs
        assert!(cls.is_empty());
    }

    #[test]
    fn test_migration_entry_attrs_domain_info() {
        let mut classes = BTreeSet::new();
        classes.insert("domain_info".to_string());

        let (attrs, _cls) = migration_entry_attrs(&classes);
        assert!(attrs.contains(&Attribute::DomainLdapBasedn));
        assert!(attrs.contains(&Attribute::DomainDisplayName));
        assert!(attrs.contains(&Attribute::Class));
        assert!(attrs.contains(&Attribute::Uuid));
    }

    #[test]
    fn test_migration_entry_attrs_group() {
        let mut classes = BTreeSet::new();
        classes.insert("group".to_string());

        let (attrs, cls) = migration_entry_attrs(&classes);
        assert!(attrs.contains(&Attribute::Member));
        assert!(attrs.contains(&Attribute::Name));
        assert!(attrs.contains(&Attribute::Description));
        assert!(cls.contains("group"));
        assert!(cls.contains("account_policy"));
    }

    #[test]
    fn test_migration_entry_attrs_person() {
        let mut classes = BTreeSet::new();
        classes.insert("person".to_string());

        let (attrs, cls) = migration_entry_attrs(&classes);
        assert!(attrs.contains(&Attribute::Name));
        assert!(attrs.contains(&Attribute::LegalName));
        assert!(attrs.contains(&Attribute::Mail));
        assert!(attrs.contains(&Attribute::SshPublicKey));
        assert!(cls.contains("person"));
        assert!(cls.contains("account"));
    }

    #[test]
    fn test_migration_entry_attrs_service_account() {
        let mut classes = BTreeSet::new();
        classes.insert("service_account".to_string());

        let (attrs, cls) = migration_entry_attrs(&classes);
        assert!(attrs.contains(&Attribute::Name));
        assert!(attrs.contains(&Attribute::Mail));
        assert!(attrs.contains(&Attribute::SshPublicKey));
        assert!(cls.contains("service_account"));
        assert!(cls.contains("account"));
    }

    #[test]
    fn test_migration_entry_attrs_account_policy() {
        let mut classes = BTreeSet::new();
        classes.insert("account_policy".to_string());

        let (attrs, cls) = migration_entry_attrs(&classes);
        assert!(attrs.contains(&Attribute::AuthSessionExpiry));
        assert!(attrs.contains(&Attribute::AuthPasswordMinimumLength));
        assert!(attrs.contains(&Attribute::CredentialTypeMinimum));
        assert!(attrs.contains(&Attribute::PrivilegeExpiry));
        assert!(cls.is_empty()); // account_policy adds attrs, not classes
    }

    #[test]
    fn test_migration_entry_attrs_oauth2_rs() {
        let mut classes = BTreeSet::new();
        classes.insert("oauth2_resource_server".to_string());

        let (attrs, cls) = migration_entry_attrs(&classes);
        assert!(attrs.contains(&Attribute::Name));
        assert!(attrs.contains(&Attribute::Description));
        assert!(attrs.contains(&Attribute::OAuth2RsOrigin));
        assert!(attrs.contains(&Attribute::OAuth2RsScopeMap));
        assert!(cls.contains("oauth2_resource_server"));
        assert!(cls.contains("oauth2_resource_server_basic"));
        assert!(cls.contains("oauth2_resource_server_public"));
    }

    #[test]
    fn test_migration_entry_attrs_multiple_classes() {
        // When multiple classes present, last one wins for cls
        let mut classes = BTreeSet::new();
        classes.insert("person".to_string());
        classes.insert("service_account".to_string());

        let (attrs, _cls) = migration_entry_attrs(&classes);
        // Both should contribute attrs
        assert!(attrs.contains(&Attribute::Name));
        assert!(attrs.contains(&Attribute::Mail));
    }
}
