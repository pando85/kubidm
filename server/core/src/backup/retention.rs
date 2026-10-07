//! Backup retention shared by the local online backup directory and the S3 prefix.
//!
//! Both locations are pruned by the same rule: only artifacts named like an automatically
//! generated backup are ever considered, they are ordered by their RFC3339 timestamp, and
//! the oldest ones beyond the configured number of versions are removed. Anything else that
//! shares the location (metadata sidecars, the PITR manifest, manual backups with other
//! names) is left alone.

use std::sync::LazyLock;

use kubidm_proto::backup::{BackupCompression, BACKUP_ENCRYPTED_SUFFIX};
use regex::Regex;

/// Pattern of the file name / object key of an automatically generated backup, as written
/// by the online backup: `backup-<RFC3339 UTC timestamp>.json` with an optional compression
/// suffix and an optional encryption suffix (see [`backup_artifact_name`]).
static BACKUP_ARTIFACT_NAME: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"^backup-\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z\.json(\.gz)?(\.enc)?$")
        .expect("backup artifact regex is a constant and must compile")
});

/// Whether `name` (a file name or a prefix-stripped object key) is an automatically
/// generated backup artifact that retention may delete.
pub fn is_backup_artifact_name(name: &str) -> bool {
    BACKUP_ARTIFACT_NAME.is_match(name)
}

/// The file name / object key of an automatically generated backup taken at `timestamp`
/// (RFC3339 UTC): `backup-<timestamp>.json`, then `.gz` when compressed, then `.enc` when
/// client-side encrypted. This is the only place these names are built, and
/// [`is_backup_artifact_name`] recognises exactly the names it produces.
pub fn backup_artifact_name(
    timestamp: &str,
    compression: BackupCompression,
    encrypted: bool,
) -> String {
    let encryption_suffix = if encrypted {
        BACKUP_ENCRYPTED_SUFFIX
    } else {
        ""
    };
    format!(
        "backup-{timestamp}.json{}{encryption_suffix}",
        compression.suffix()
    )
}

/// Given the names found in a backup location, return the ones retention should delete so
/// that at most `versions` backup artifacts remain. Names that are not backup artifacts are
/// never returned. The result is ordered oldest first.
///
/// Backup names embed an RFC3339 UTC timestamp, so lexical order is chronological order.
pub fn select_backups_to_delete(names: &[String], versions: usize) -> Vec<String> {
    let mut backups: Vec<String> = names
        .iter()
        .filter(|name| is_backup_artifact_name(name))
        .cloned()
        .collect();
    backups.sort();

    let excess = backups.len().saturating_sub(versions);
    backups.truncate(excess);
    backups
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_is_backup_artifact_name() {
        assert!(is_backup_artifact_name("backup-2024-01-01T22:00:00Z.json"));
        assert!(is_backup_artifact_name(
            "backup-2024-01-01T22:00:00Z.json.gz"
        ));
        assert!(is_backup_artifact_name(
            "backup-2024-01-01T22:00:00.123456789Z.json.gz"
        ));
        assert!(is_backup_artifact_name(
            "backup-2024-01-01T22:00:00Z.json.enc"
        ));
        assert!(is_backup_artifact_name(
            "backup-2024-01-01T22:00:00Z.json.gz.enc"
        ));

        // The suffixes have a fixed order and appear at most once.
        assert!(!is_backup_artifact_name(
            "backup-2024-01-01T22:00:00Z.json.enc.gz"
        ));
        assert!(!is_backup_artifact_name(
            "backup-2024-01-01T22:00:00Z.json.gz.enc.enc"
        ));
        assert!(!is_backup_artifact_name(
            "backup-2024-01-01T22:00:00Z.json.gz.enc.invalid"
        ));
        assert!(!is_backup_artifact_name(
            "backup-2024-01-01T22:00:00Z.json.gz.enc.metadata.json"
        ));

        assert!(!is_backup_artifact_name("pitr-manifest.json"));
        assert!(!is_backup_artifact_name(
            "backup-2024-01-01T22:00:00Z.json.metadata.json"
        ));
        assert!(!is_backup_artifact_name(
            "backup-2024-01-01T22:00:00Z.json.gz.metadata.json"
        ));
        assert!(!is_backup_artifact_name("kubidm.backup.json"));
        assert!(!is_backup_artifact_name("backup-20240101220000.json"));
        assert!(!is_backup_artifact_name(
            "prefix/backup-2024-01-01T22:00:00Z.json"
        ));
    }

    #[test]
    fn test_backup_artifact_name_round_trips_through_the_matcher() {
        let ts = "2024-01-01T22:00:00Z";
        assert_eq!(
            backup_artifact_name(ts, BackupCompression::NoCompression, false),
            "backup-2024-01-01T22:00:00Z.json"
        );
        assert_eq!(
            backup_artifact_name(ts, BackupCompression::Gzip, false),
            "backup-2024-01-01T22:00:00Z.json.gz"
        );
        assert_eq!(
            backup_artifact_name(ts, BackupCompression::NoCompression, true),
            "backup-2024-01-01T22:00:00Z.json.enc"
        );
        assert_eq!(
            backup_artifact_name(ts, BackupCompression::Gzip, true),
            "backup-2024-01-01T22:00:00Z.json.gz.enc"
        );

        for compression in [BackupCompression::NoCompression, BackupCompression::Gzip] {
            for encrypted in [false, true] {
                let name = backup_artifact_name(ts, compression, encrypted);
                assert!(is_backup_artifact_name(&name), "{name}");
                assert_eq!(BackupCompression::identify_name(&name), compression);
                assert_eq!(
                    kubidm_proto::backup::is_encrypted_backup_name(&name),
                    encrypted
                );
            }
        }
    }

    #[test]
    fn test_select_backups_to_delete_mixes_plain_and_encrypted_artifacts() {
        // A deployment that turned encryption on keeps counting its older plain backups,
        // so the oldest ones are pruned first whatever their suffix.
        let listing = names(&[
            "backup-2024-01-03T22:00:00Z.json.gz.enc",
            "backup-2024-01-01T22:00:00Z.json.gz",
            "backup-2024-01-02T22:00:00Z.json.gz",
            "backup-2024-01-03T22:00:00Z.json.gz.enc.metadata.json",
            "backup-2024-01-04T22:00:00Z.json.gz.enc",
        ]);
        assert_eq!(
            select_backups_to_delete(&listing, 2),
            names(&[
                "backup-2024-01-01T22:00:00Z.json.gz",
                "backup-2024-01-02T22:00:00Z.json.gz",
            ])
        );
    }

    #[test]
    fn test_select_backups_to_delete_keeps_newest() {
        let listing = names(&[
            "backup-2024-01-03T22:00:00Z.json.gz",
            "backup-2024-01-01T22:00:00Z.json.gz",
            "backup-2024-01-02T22:00:00Z.json.gz",
            "backup-2024-01-04T22:00:00Z.json.gz",
        ]);

        assert_eq!(
            select_backups_to_delete(&listing, 2),
            names(&[
                "backup-2024-01-01T22:00:00Z.json.gz",
                "backup-2024-01-02T22:00:00Z.json.gz",
            ])
        );
        assert!(select_backups_to_delete(&listing, 4).is_empty());
        assert!(select_backups_to_delete(&listing, 10).is_empty());
        assert_eq!(select_backups_to_delete(&listing, 0), {
            let mut all = listing.clone();
            all.sort();
            all
        });
    }

    #[test]
    fn test_select_backups_to_delete_ignores_other_objects() {
        let listing = names(&[
            "pitr-manifest.json",
            "backup-2024-01-01T22:00:00Z.json.gz.metadata.json",
            "backup-2024-01-01T22:00:00Z.json.gz",
            "backup-2024-01-02T22:00:00Z.json.gz.metadata.json",
            "backup-2024-01-02T22:00:00Z.json.gz",
            "manual-copy.json",
            "wal/segment-0001.bin",
        ]);

        // Even with a retention of zero, only backup artifacts are selected.
        assert_eq!(
            select_backups_to_delete(&listing, 0),
            names(&[
                "backup-2024-01-01T22:00:00Z.json.gz",
                "backup-2024-01-02T22:00:00Z.json.gz",
            ])
        );
        assert_eq!(
            select_backups_to_delete(&listing, 1),
            names(&["backup-2024-01-01T22:00:00Z.json.gz"])
        );
    }

    #[test]
    fn test_select_backups_to_delete_empty() {
        assert!(select_backups_to_delete(&[], 3).is_empty());
        assert!(select_backups_to_delete(&names(&["pitr-manifest.json"]), 0).is_empty());
    }
}
