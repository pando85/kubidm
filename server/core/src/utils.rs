use filetime::FileTime;
use std::{fs::File, io, path::Path, time::SystemTime};

/// Touch the file at `file_path`: create it when it does not exist, set its access and
/// modification times to now otherwise. Fails, without ending the process, when it can do
/// neither, so that a caller inside a running server (the scheduled backup verification)
/// can report the error instead of stopping the server.
pub fn touch_file<P: AsRef<Path>>(file_path: P) -> io::Result<()> {
    let file_path: &Path = file_path.as_ref();

    if file_path.exists() {
        let t = FileTime::from_system_time(SystemTime::now());
        filetime::set_file_times(file_path, t, t).inspect_err(|err| {
            error!(?err, "Failed to write to {}", file_path.display());
        })?;
        debug!(
            "Successfully touched existing file {}, can continue",
            file_path.display()
        );
    } else {
        File::create(file_path).inspect_err(|err| {
            error!(?err, "Failed to write to {}", file_path.display());
        })?;
        debug!("Successfully touched new file {}", file_path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::touch_file;

    #[test]
    fn touch_file_creates_or_touches_and_reports_failures() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("db");
        touch_file(&path).expect("create");
        assert!(path.is_file());
        touch_file(&path).expect("touch");

        // A file in a directory that does not exist can not be created: an error, never
        // the end of the process.
        assert!(touch_file(dir.path().join("missing").join("db")).is_err());
    }
}
