//! Backup retention shared by the local online backup directory and the S3 prefix.
//!
//! Both locations are pruned by the same rule: only artifacts named like an automatically
//! generated backup are ever considered, they are ordered by the RFC3339 timestamp in
//! their name, and the oldest ones beyond the configured number of versions are removed. Anything else that
//! shares the location (metadata sidecars, the PITR manifest, manual backups with other
//! names) is left alone.

use std::cmp::Ordering;
use std::path::Path;
use std::sync::LazyLock;

use chrono::{DateTime, FixedOffset};
use kubidm_proto::backup::{BackupCompression, BACKUP_ENCRYPTED_SUFFIX};
use regex::Regex;
use time::{OffsetDateTime, UtcOffset};

/// Pattern of the file name / object key of an automatically generated backup, as written
/// by the online backup: `backup-<RFC3339 UTC timestamp>.json` with an optional compression
/// suffix and an optional encryption suffix (see [`backup_artifact_name`]).
static BACKUP_ARTIFACT_NAME: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(
        r"^backup-(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z)\.json(\.gz)?(\.enc)?$",
    )
    .expect("backup artifact regex is a constant and must compile")
});

/// Whether `name` (a file name or a prefix-stripped object key) is an automatically
/// generated backup artifact that retention may delete.
pub fn is_backup_artifact_name(name: &str) -> bool {
    BACKUP_ARTIFACT_NAME.is_match(name)
}

/// The time an automatically generated backup was taken, read from its name. None when
/// `name` is not a backup artifact name.
pub fn backup_artifact_time(name: &str) -> Option<DateTime<FixedOffset>> {
    let timestamp = BACKUP_ARTIFACT_NAME.captures(name)?.get(1)?.as_str();
    DateTime::parse_from_rfc3339(timestamp).ok()
}

/// Order two backup names oldest first by the time in their name, then by name.
///
/// The names can not simply be compared as strings: RFC3339 drops trailing zeros of the
/// fraction and the whole fraction when it is zero, so within one second `...:00.1Z`
/// sorts after `...:00.12Z` and `...:00.5Z` before `...:00Z`. Names written by older
/// servers use that format.
pub fn compare_backup_names(a: &str, b: &str) -> Ordering {
    (backup_artifact_time(a), a).cmp(&(backup_artifact_time(b), b))
}

/// Sort backup names oldest first, see [`compare_backup_names`].
pub fn sort_backup_names<S: AsRef<str>>(names: &mut [S]) {
    names.sort_by(|a, b| compare_backup_names(a.as_ref(), b.as_ref()));
}

/// The timestamp of a backup taken at `now`, as it goes into the backup name and the S3
/// metadata: RFC3339 in UTC with a fixed nine digit fraction, so that names of new backups
/// also sort chronologically as plain strings, as directory listings show them.
pub fn backup_timestamp(now: OffsetDateTime) -> String {
    let now = now.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.nanosecond()
    )
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
/// never returned. The result is ordered oldest first, by the time in the names.
pub fn select_backups_to_delete(names: &[String], versions: usize) -> Vec<String> {
    let mut backups: Vec<String> = names
        .iter()
        .filter(|name| is_backup_artifact_name(name))
        .cloned()
        .collect();
    sort_backup_names(&mut backups);

    let excess = backups.len().saturating_sub(versions);
    backups.truncate(excess);
    backups
}

/// Apply the `versions` retention to the local online backup directory `dir` with
/// [`select_backups_to_delete`], the rule the S3 locations use. Only regular files named
/// like an automatically generated backup are considered; anything else in the directory,
/// including names that are not valid UTF-8, is left alone.
///
/// Never fails: the backup that triggered the cleanup has already succeeded, so an
/// unreadable directory or entry, or a file that can not be removed, is logged and the
/// cleanup carries on or stops, as an S3 cleanup does.
pub fn prune_local_backups(dir: &Path, versions: usize) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            error!(
                "Online backup cleanup failed to read {}: {}",
                dir.display(),
                err
            );
            return;
        }
    };

    let mut names = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                warn!(
                    "Online backup cleanup skips an unreadable entry of {}: {}",
                    dir.display(),
                    err
                );
                continue;
            }
        };
        let Ok(name) = entry.file_name().into_string() else {
            debug!(
                "Online backup cleanup ignores {:?}: its name is not valid UTF-8",
                entry.path()
            );
            continue;
        };
        if is_backup_artifact_name(&name) && entry.path().is_file() {
            names.push(name);
        }
    }

    let to_delete = select_backups_to_delete(&names, versions);
    if to_delete.is_empty() {
        debug!("Online backup cleanup had no files to remove");
        return;
    }
    info!(
        "Online backup cleanup found {} versions in {}, should keep {}, will remove {}",
        names.len(),
        dir.display(),
        versions,
        to_delete.len()
    );
    for name in to_delete {
        let path = dir.join(&name);
        match std::fs::remove_file(&path) {
            Ok(()) => debug!("Online backup cleanup removed {}", path.display()),
            Err(err) => error!(
                "Online backup cleanup failed to remove {}: {}",
                path.display(),
                err
            ),
        }
    }
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
    fn test_select_backups_to_delete_orders_by_time_within_a_second() {
        // RFC3339 as older servers wrote it: as strings, .1Z sorts after .12Z and .5Z
        // before the whole second, which would delete the newest backup.
        let listing = names(&[
            "backup-2024-01-01T22:00:00.1Z.json.gz",
            "backup-2024-01-01T22:00:00.12Z.json.gz",
            "backup-2024-01-01T22:00:00Z.json.gz",
            "backup-2024-01-01T22:00:00.5Z.json.gz",
        ]);
        assert_eq!(
            select_backups_to_delete(&listing, 1),
            names(&[
                "backup-2024-01-01T22:00:00Z.json.gz",
                "backup-2024-01-01T22:00:00.1Z.json.gz",
                "backup-2024-01-01T22:00:00.12Z.json.gz",
            ])
        );
    }

    #[test]
    fn test_backup_timestamp_has_a_fixed_width_fraction() {
        let at = |nanos: u32| {
            OffsetDateTime::from_unix_timestamp(1_704_146_400)
                .expect("time")
                .replace_nanosecond(nanos)
                .expect("nanos")
        };
        assert_eq!(backup_timestamp(at(0)), "2024-01-01T22:00:00.000000000Z");
        assert_eq!(
            backup_timestamp(at(100_000_000)),
            "2024-01-01T22:00:00.100000000Z"
        );
        assert_eq!(
            backup_timestamp(at(120_000_000)),
            "2024-01-01T22:00:00.120000000Z"
        );

        // New names sort chronologically as strings too, and are backup names.
        let mut stamps: Vec<String> = [120_000_000, 0, 100_000_000]
            .into_iter()
            .map(|nanos| {
                backup_artifact_name(&backup_timestamp(at(nanos)), BackupCompression::Gzip, false)
            })
            .collect();
        let mut by_time = stamps.clone();
        sort_backup_names(&mut by_time);
        stamps.sort();
        assert_eq!(stamps, by_time);
        assert!(stamps.iter().all(|name| is_backup_artifact_name(name)));
        assert_eq!(
            backup_artifact_time(&stamps[0]).map(|t| t.timestamp()),
            Some(1_704_146_400)
        );
    }

    #[test]
    fn test_select_backups_to_delete_empty() {
        assert!(select_backups_to_delete(&[], 3).is_empty());
        assert!(select_backups_to_delete(&names(&["pitr-manifest.json"]), 0).is_empty());
    }

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"backup").expect("write");
    }

    fn remaining(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn test_prune_local_backups_keeps_the_newest_and_everything_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        for day in 1..=4 {
            touch(
                dir.path(),
                &format!("backup-2024-01-0{day}T22:00:00Z.json.gz"),
            );
        }
        touch(dir.path(), "backup-2024-01-05T22:00:00Z.json.gz.invalid");
        touch(dir.path(), ".backup-2024-01-06T22:00:00Z.json.gz.partial");
        touch(dir.path(), "manual.json");
        // A directory named like a backup is not a backup.
        std::fs::create_dir(dir.path().join("backup-2024-01-00T22:00:00Z.json.gz")).expect("mkdir");

        prune_local_backups(dir.path(), 2);

        assert_eq!(
            remaining(dir.path()),
            names(&[
                ".backup-2024-01-06T22:00:00Z.json.gz.partial",
                "backup-2024-01-00T22:00:00Z.json.gz",
                "backup-2024-01-03T22:00:00Z.json.gz",
                "backup-2024-01-04T22:00:00Z.json.gz",
                "backup-2024-01-05T22:00:00Z.json.gz.invalid",
                "manual.json",
            ])
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_prune_local_backups_ignores_names_that_are_not_utf8() {
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().expect("tempdir");
        touch(dir.path(), "backup-2024-01-01T22:00:00Z.json.gz");
        touch(dir.path(), "backup-2024-01-02T22:00:00Z.json.gz");
        let stray = dir
            .path()
            .join(std::ffi::OsStr::from_bytes(b"stray-\xff.json"));
        std::fs::write(&stray, b"stray").expect("write");

        // Used to fail the whole cleanup, and with it the backup that had succeeded.
        prune_local_backups(dir.path(), 1);

        assert!(stray.exists());
        assert!(!dir
            .path()
            .join("backup-2024-01-01T22:00:00Z.json.gz")
            .exists());
        assert!(dir
            .path()
            .join("backup-2024-01-02T22:00:00Z.json.gz")
            .exists());
    }

    #[test]
    fn test_prune_local_backups_survives_a_missing_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        prune_local_backups(&dir.path().join("missing"), 1);
    }
}
