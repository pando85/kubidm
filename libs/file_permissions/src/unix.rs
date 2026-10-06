use std::fs::Metadata;

#[cfg(target_os = "freebsd")]
use std::os::freebsd::fs::MetadataExt;

#[cfg(target_os = "openbsd")]
use std::os::openbsd::fs::MetadataExt;

#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;

#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;

#[cfg(target_os = "illumos")]
use std::os::illumos::fs::MetadataExt;

#[cfg(target_os = "android")]
use std::os::android::fs::MetadataExt;

use kubidm_utils_users::{get_current_gid, get_current_uid};

use std::{
    fmt,
    path::{Path, PathBuf},
};

/// Check a given file's metadata is read-only for the current user (true = read-only)
pub fn readonly(meta: &Metadata) -> bool {
    // Who are we running as?
    let cuid = get_current_uid();
    let cgid = get_current_gid();

    // Who owns the file?
    // Who is the group owner of the file?
    let f_gid = meta.st_gid();
    let f_uid = meta.st_uid();

    let f_mode = meta.st_mode();

    !(
        // If we are the owner, we have write perms as we can alter the DAC rights
        cuid == f_uid ||
        // If we are the group owner, check the mode bits do not have write.
        (cgid == f_gid && (f_mode & 0o0020) != 0) ||
        // Finally, check that everyone bits don't have write.
        ((f_mode & 0o0002) != 0)
    )
}

#[derive(Debug)]
pub enum PathStatus {
    Dir {
        f_gid: u32,
        f_uid: u32,
        f_mode: u32,
        access: bool,
    },
    Link {
        f_gid: u32,
        f_uid: u32,
        f_mode: u32,
        access: bool,
    },
    File {
        f_gid: u32,
        f_uid: u32,
        f_mode: u32,
        access: bool,
    },
    Error(std::io::Error),
}

#[derive(Debug)]
pub struct Diagnosis {
    cuid: u32,
    cgid: u32,
    path: PathBuf,
    abs_path: Result<PathBuf, std::io::Error>,
    ancestors: Vec<(PathBuf, PathStatus)>,
}

impl fmt::Display for Diagnosis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "-- diagnosis for path: {}", self.path.to_string_lossy())?;
        let indent = match &self.abs_path {
            Ok(abs) => {
                let abs_str = abs.to_string_lossy();
                writeln!(f, "canonicalised to: {abs_str}")?;
                abs_str.len() + 1
            }
            Err(_) => {
                writeln!(f, "unable to canonicalise path")?;
                self.path.to_string_lossy().len() + 1
            }
        };

        writeln!(f, "running as: {}:{}", self.cuid, self.cgid)?;

        writeln!(f, "path permissions\n")?;
        for (anc, status) in &self.ancestors {
            match &status {
                PathStatus::Dir {
                    f_gid,
                    f_uid,
                    f_mode,
                    access,
                } => {
                    writeln!(
                        f,
                        "  {:indent$}: DIR access: {} owner: {} group: {} mode: {}",
                        anc.to_string_lossy(),
                        access,
                        f_uid,
                        f_gid,
                        mode_to_string(*f_mode)
                    )?;
                }
                PathStatus::Link {
                    f_gid,
                    f_uid,
                    f_mode,
                    access,
                } => {
                    writeln!(
                        f,
                        "  {:indent$}: LINK access: {} owner: {} group: {} mode: {}",
                        anc.to_string_lossy(),
                        access,
                        f_uid,
                        f_gid,
                        mode_to_string(*f_mode)
                    )?;
                }
                PathStatus::File {
                    f_gid,
                    f_uid,
                    f_mode,
                    access,
                } => {
                    writeln!(
                        f,
                        "  {:indent$}: FILE access: {} owner: {} group: {} mode: {}",
                        anc.to_string_lossy(),
                        access,
                        f_uid,
                        f_gid,
                        mode_to_string(*f_mode)
                    )?;
                }
                PathStatus::Error(err) => {
                    writeln!(f, "  {:indent$}: ERROR: {:?}", anc.to_string_lossy(), err)?;
                }
            }
        }

        writeln!(
            f,
            "\n  note that accessibility does not account for ACL's or MAC"
        )?;
        writeln!(f, "-- end diagnosis")
    }
}

pub fn diagnose_path(path: &Path) -> Diagnosis {
    // Who are we?
    let cuid = get_current_uid();
    let cgid = get_current_gid();

    // clone the path
    let path: PathBuf = path.into();

    // Display the abs/resolved path.
    let abs_path = path.canonicalize();

    // For each segment, from the root inc root
    // show the path -> owner/group mode
    //      or show that we have permission denied.
    let mut all_ancestors: Vec<_> = match &abs_path {
        Ok(ap) => ap.ancestors().collect(),
        Err(_) => path.ancestors().collect(),
    };

    let mut ancestors = Vec::with_capacity(all_ancestors.len());

    // Now pop from the right to start from the root.
    while let Some(anc) = all_ancestors.pop() {
        let status = match anc.metadata() {
            Ok(meta) => {
                let f_gid = meta.st_gid();
                let f_uid = meta.st_uid();
                let f_mode = meta.st_mode();
                if meta.is_dir() {
                    let access = x_accessible(cuid, cgid, f_uid, f_gid, f_mode);

                    PathStatus::Dir {
                        f_gid,
                        f_uid,
                        f_mode,
                        access,
                    }
                } else if meta.is_symlink() {
                    let access = x_accessible(cuid, cgid, f_uid, f_gid, f_mode);

                    PathStatus::Link {
                        f_gid,
                        f_uid,
                        f_mode,
                        access,
                    }
                } else {
                    let access = accessible(cuid, cgid, f_uid, f_gid, f_mode);

                    PathStatus::File {
                        f_gid,
                        f_uid,
                        f_mode,
                        access,
                    }
                }
            }
            Err(e) => PathStatus::Error(e),
        };

        ancestors.push((anc.into(), status))
    }

    Diagnosis {
        cuid,
        cgid,
        path,
        abs_path,
        ancestors,
    }
}

fn x_accessible(cuid: u32, cgid: u32, f_uid: u32, f_gid: u32, f_mode: u32) -> bool {
    (cuid == f_uid && f_mode & 0o500 == 0o500)
        || (cgid == f_gid && f_mode & 0o050 == 0o050)
        || f_mode & 0o005 == 0o005
}

fn accessible(cuid: u32, cgid: u32, f_uid: u32, f_gid: u32, f_mode: u32) -> bool {
    (cuid == f_uid && f_mode & 0o400 == 0o400)
        || (cgid == f_gid && f_mode & 0o040 == 0o040)
        || f_mode & 0o004 == 0o004
}

fn mode_to_string(mode: u32) -> String {
    let mut mode_str = String::with_capacity(9);
    if mode & 0o400 != 0 {
        mode_str.push('r')
    } else {
        mode_str.push('-')
    }

    if mode & 0o200 != 0 {
        mode_str.push('w')
    } else {
        mode_str.push('-')
    }

    if mode & 0o100 != 0 {
        mode_str.push('x')
    } else {
        mode_str.push('-')
    }

    if mode & 0o040 != 0 {
        mode_str.push('r')
    } else {
        mode_str.push('-')
    }

    if mode & 0o020 != 0 {
        mode_str.push('w')
    } else {
        mode_str.push('-')
    }

    if mode & 0o010 != 0 {
        mode_str.push('x')
    } else {
        mode_str.push('-')
    }

    if mode & 0o004 != 0 {
        mode_str.push('r')
    } else {
        mode_str.push('-')
    }

    if mode & 0o002 != 0 {
        mode_str.push('w')
    } else {
        mode_str.push('-')
    }

    if mode & 0o001 != 0 {
        mode_str.push('x')
    } else {
        mode_str.push('-')
    }

    mode_str
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::NamedTempFile;

    #[test]
    fn test_readonly() {
        let meta = std::fs::metadata("Cargo.toml").expect("Can't find Cargo.toml");
        println!("meta={:?} -> readonly={:?}", meta, readonly(&meta));
        assert!(!readonly(&meta));
    }

    #[test]
    fn test_x_accessible_owner() {
        // Owner with read+execute should have access
        assert!(x_accessible(1000, 1000, 1000, 2000, 0o500));
        // Owner with only read should NOT have execute access
        assert!(!x_accessible(1000, 1000, 1000, 2000, 0o400));
        // Owner with only execute should NOT have access
        assert!(!x_accessible(1000, 1000, 1000, 2000, 0o100));
    }

    #[test]
    fn test_x_accessible_group() {
        // Group member with read+execute should have access
        assert!(x_accessible(1000, 2000, 3000, 2000, 0o050));
        // Group member with only read should NOT have execute access
        assert!(!x_accessible(1000, 2000, 3000, 2000, 0o040));
    }

    #[test]
    fn test_x_accessible_other() {
        // Other with read+execute should have access
        assert!(x_accessible(1000, 1000, 3000, 4000, 0o005));
        // Other with only read should NOT have execute access
        assert!(!x_accessible(1000, 1000, 3000, 4000, 0o004));
    }

    #[test]
    fn test_x_accessible_no_match() {
        // No uid/gid match and no other bits
        assert!(!x_accessible(1000, 1000, 2000, 3000, 0o000));
    }

    #[test]
    fn test_accessible_owner() {
        // Owner with read should have access
        assert!(accessible(1000, 1000, 1000, 2000, 0o400));
        // Owner with read+write should have access
        assert!(accessible(1000, 1000, 1000, 2000, 0o600));
        // Owner with only write should NOT have read access
        assert!(!accessible(1000, 1000, 1000, 2000, 0o200));
    }

    #[test]
    fn test_accessible_group() {
        // Group member with read should have access
        assert!(accessible(1000, 2000, 3000, 2000, 0o040));
        // Group member with only write should NOT have read access
        assert!(!accessible(1000, 2000, 3000, 2000, 0o020));
    }

    #[test]
    fn test_accessible_other() {
        // Other with read should have access
        assert!(accessible(1000, 1000, 3000, 4000, 0o004));
        // Other with only write should NOT have read access
        assert!(!accessible(1000, 1000, 3000, 4000, 0o002));
    }

    #[test]
    fn test_accessible_no_match() {
        assert!(!accessible(1000, 1000, 2000, 3000, 0o000));
    }

    #[test]
    fn test_mode_to_string_all_perms() {
        assert_eq!(mode_to_string(0o000), "---------");
        assert_eq!(mode_to_string(0o777), "rwxrwxrwx");
        assert_eq!(mode_to_string(0o644), "rw-r--r--");
        assert_eq!(mode_to_string(0o755), "rwxr-xr-x");
        assert_eq!(mode_to_string(0o600), "rw-------");
        assert_eq!(mode_to_string(0o400), "r--------");
        assert_eq!(mode_to_string(0o100), "--x------");
    }

    #[test]
    fn test_mode_to_string_special_bits() {
        // SUID bit (0o4000) - should not affect the 9-char output
        assert_eq!(mode_to_string(0o4755), "rwxr-xr-x");
        // SGID bit (0o2000)
        assert_eq!(mode_to_string(0o2755), "rwxr-xr-x");
        // Sticky bit (0o1000)
        assert_eq!(mode_to_string(0o1755), "rwxr-xr-x");
    }

    #[test]
    fn test_readonly_owner_is_not_readonly() {
        // When we own the file (cuid == f_uid), readonly() always returns false
        // because the owner can always change DAC rights.
        // This is tested indirectly through test_readonly_with_temp_file
        // where we create and own a temp file.
        let cuid = get_current_uid();
        // Verify that owner with read permission has access
        assert!(accessible(cuid, 1000, cuid, 2000, 0o400));
    }

    #[test]
    fn test_readonly_with_temp_file() {
        // Create a temp file and check its readonly status
        let mut tmp = NamedTempFile::new().expect("Failed to create temp file");
        writeln!(tmp, "test content").expect("Failed to write");

        let meta = tmp.as_file().metadata().expect("Failed to get metadata");
        // We own the file, so it should not be readonly
        assert!(!readonly(&meta));
    }

    #[test]
    fn test_readonly_no_owner_write() {
        // Create a temp file, change permissions to remove owner write
        let mut tmp = NamedTempFile::new().expect("Failed to create temp file");
        writeln!(tmp, "test").expect("Failed to write");

        let path = tmp.path();
        // Change to read-only for owner (0o400)
        let mut perms = std::fs::metadata(path)
            .expect("Failed to get metadata")
            .permissions();
        perms.set_mode(0o400);
        std::fs::set_permissions(path, perms).expect("Failed to set permissions");

        let meta = std::fs::metadata(path).expect("Failed to get metadata after chmod");
        // Even though we own it, the readonly() function returns false when we're the owner
        // because the function considers owner as always having write capability (can change DAC)
        assert!(!readonly(&meta));
    }

    #[test]
    fn test_diagnose_path_existing_file() {
        let diagnosis = diagnose_path(Path::new("Cargo.toml"));
        assert_eq!(diagnosis.path, Path::new("Cargo.toml"));
        assert!(diagnosis.abs_path.is_ok());
        assert!(!diagnosis.ancestors.is_empty());
    }

    #[test]
    fn test_diagnose_path_nonexistent() {
        let diagnosis = diagnose_path(Path::new("/this/path/definitely/does/not/exist.txt"));
        assert!(diagnosis.abs_path.is_err());
    }

    #[test]
    fn test_diagnose_path_display() {
        let diagnosis = diagnose_path(Path::new("Cargo.toml"));
        let display = format!("{}", diagnosis);
        assert!(display.contains("diagnosis for path"));
        assert!(display.contains("running as"));
        assert!(display.contains("path permissions"));
        assert!(display.contains("end diagnosis"));
    }
}
