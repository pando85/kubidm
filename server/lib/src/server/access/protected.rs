use crate::prelude::EntryClass;
use std::{collections::BTreeSet, sync::LazyLock};

/// These entry classes may not be created or deleted, and may invoke some protection rules
/// if on an entry.
pub static PROTECTED_ENTRY_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::System,
        EntryClass::DomainInfo,
        EntryClass::SystemInfo,
        EntryClass::SystemConfig,
        EntryClass::DynGroup,
        EntryClass::SyncObject,
        EntryClass::Tombstone,
        EntryClass::Recycled,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

/// Entries with these classes are protected from modifications - not that
/// sync object is not present here as there are separate rules for that in
/// the modification access module.
///
/// Recycled is also not protected here as it needs to be able to be removed
/// by a recycle bin admin.
pub static PROTECTED_MOD_ENTRY_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::System,
        EntryClass::DomainInfo,
        EntryClass::SystemInfo,
        EntryClass::SystemConfig,
        EntryClass::DynGroup,
        // EntryClass::SyncObject,
        EntryClass::Tombstone,
        EntryClass::Recycled,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

/// These classes may NOT be added to ANY ENTRY
pub static PROTECTED_MOD_PRES_ENTRY_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::System,
        EntryClass::DomainInfo,
        EntryClass::SystemInfo,
        EntryClass::SystemConfig,
        EntryClass::DynGroup,
        EntryClass::SyncObject,
        EntryClass::Tombstone,
        EntryClass::Recycled,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

/// These classes may NOT be removed from ANY ENTRY
pub static PROTECTED_MOD_REM_ENTRY_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::System,
        EntryClass::DomainInfo,
        EntryClass::SystemInfo,
        EntryClass::SystemConfig,
        EntryClass::DynGroup,
        EntryClass::SyncObject,
        EntryClass::Tombstone,
        // EntryClass::Recycled,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

/// Entries with these classes may not be modified under any circumstance.
pub static LOCKED_ENTRY_CLASSES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    let classes = vec![
        EntryClass::Tombstone,
        // EntryClass::Recycled,
    ];

    BTreeSet::from_iter(classes.into_iter().map(|ec| ec.into()))
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_entry_classes_contains_system() {
        assert!(PROTECTED_ENTRY_CLASSES.contains("system"));
        assert!(PROTECTED_ENTRY_CLASSES.contains("domain_info"));
        assert!(PROTECTED_ENTRY_CLASSES.contains("system_info"));
        assert!(PROTECTED_ENTRY_CLASSES.contains("system_config"));
        assert!(PROTECTED_ENTRY_CLASSES.contains("dyngroup"));
        assert!(PROTECTED_ENTRY_CLASSES.contains("sync_object"));
        assert!(PROTECTED_ENTRY_CLASSES.contains("tombstone"));
        assert!(PROTECTED_ENTRY_CLASSES.contains("recycled"));
    }

    #[test]
    fn test_protected_mod_entry_classes_contains_recycled() {
        // Recycled IS in PROTECTED_MOD_ENTRY_CLASSES (unlike create/delete)
        assert!(PROTECTED_MOD_ENTRY_CLASSES.contains("recycled"));
        assert!(PROTECTED_MOD_ENTRY_CLASSES.contains("system"));
        assert!(PROTECTED_MOD_ENTRY_CLASSES.contains("tombstone"));
    }

    #[test]
    fn test_protected_mod_pres_entry_classes_contains_all() {
        // All protected classes should be in the PRES set
        for class in PROTECTED_ENTRY_CLASSES.iter() {
            assert!(
                PROTECTED_MOD_PRES_ENTRY_CLASSES.contains(class),
                "Class {} should be in PROTECTED_MOD_PRES_ENTRY_CLASSES",
                class
            );
        }
    }

    #[test]
    fn test_protected_mod_rem_entry_classes_excludes_recycled() {
        // Recycled is NOT in PROTECTED_MOD_REM_ENTRY_CLASSES
        assert!(!PROTECTED_MOD_REM_ENTRY_CLASSES.contains("recycled"));
        // But system classes are
        assert!(PROTECTED_MOD_REM_ENTRY_CLASSES.contains("system"));
        assert!(PROTECTED_MOD_REM_ENTRY_CLASSES.contains("tombstone"));
    }

    #[test]
    fn test_locked_entry_classes() {
        assert!(LOCKED_ENTRY_CLASSES.contains("tombstone"));
        // Recycled is NOT locked (recycle bin admin can remove)
        assert!(!LOCKED_ENTRY_CLASSES.contains("recycled"));
    }

    #[test]
    fn test_protected_entry_classes_not_empty() {
        assert!(!PROTECTED_ENTRY_CLASSES.is_empty());
        assert!(!PROTECTED_MOD_ENTRY_CLASSES.is_empty());
        assert!(!PROTECTED_MOD_PRES_ENTRY_CLASSES.is_empty());
        assert!(!PROTECTED_MOD_REM_ENTRY_CLASSES.is_empty());
        assert!(!LOCKED_ENTRY_CLASSES.is_empty());
    }

    #[test]
    fn test_protected_mod_pres_vs_rem_diff() {
        // recycled is in PRES but NOT in REM
        assert!(PROTECTED_MOD_PRES_ENTRY_CLASSES.contains("recycled"));
        assert!(!PROTECTED_MOD_REM_ENTRY_CLASSES.contains("recycled"));
    }
}
