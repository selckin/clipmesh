//! Small filesystem helpers shared across modules.

use std::path::Path;
use tracing::debug;

/// True if `path` is itself a symlink (does not follow it). A genuinely-absent
/// path is simply "not a symlink"; any *other* stat failure (EACCES, EIO, ...)
/// is also treated as non-symlink but logged at debug, so a transient fault
/// that hides a real symlink leaves a greppable trace rather than vanishing
/// silently.
pub fn is_symlink(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(m) => m.file_type().is_symlink(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            debug!(
                "can't lstat {} ({e}); treating it as a non-symlink",
                path.display()
            );
            false
        }
    }
}
