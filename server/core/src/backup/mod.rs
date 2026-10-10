pub mod artifact;
pub mod encryption;
pub mod finalize;
pub mod mock_s3;
pub mod retention;
pub mod s3;

pub use artifact::*;
pub use encryption::*;
pub use finalize::*;
pub use mock_s3::*;
pub use retention::*;
pub use s3::*;

/// Run blocking backup work on Tokio's blocking thread pool so that it never stalls the
/// async runtime: the Argon2id key derivation, the encryption and decryption of a whole
/// backup, its decompression and parsing for verification, and the file I/O of an
/// artifact. A task that panicked or was cancelled is reported as an I/O error.
pub(crate) async fn run_blocking<T, F>(work: F) -> std::io::Result<T>
where
    F: FnOnce() -> std::io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(err) => Err(std::io::Error::other(err)),
    }
}
