//! Small filesystem helpers shared across modules.

use std::fs;
use std::path::{Path, PathBuf};
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

/// Follow a symlink to the file it ultimately names, resolving each relative
/// hop against the directory of the link being followed (stow's default links
/// are relative). Stops at the first non-symlink or unreadable component and
/// returns the deepest path reached, which may or may not exist. A plain
/// (non-symlink) path is returned unchanged, so callers can use this
/// unconditionally.
pub fn resolve_link_target(path: &Path) -> PathBuf {
    const MAX_HOPS: usize = 8;
    let mut current = path.to_path_buf();
    for _ in 0..MAX_HOPS {
        match fs::read_link(&current) {
            Ok(target) if target.is_absolute() => current = target,
            Ok(target) => {
                let base = current.parent().unwrap_or_else(|| Path::new("."));
                current = base.join(target);
            }
            Err(_) => break,
        }
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_link_target_follows_a_relative_symlink_against_its_own_dir() {
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("dotfiles");
        std::fs::create_dir(&real_dir).unwrap();
        let real = real_dir.join("config.toml");
        std::fs::write(&real, "x").unwrap();
        // Relative link, like GNU Stow: config.toml -> dotfiles/config.toml,
        // resolved against the link's own dir.
        let link = dir.path().join("config.toml");
        std::os::unix::fs::symlink("dotfiles/config.toml", &link).unwrap();
        assert_eq!(resolve_link_target(&link), real);
    }

    #[test]
    fn resolve_link_target_is_a_noop_for_a_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain.toml");
        std::fs::write(&plain, "x").unwrap();
        assert_eq!(resolve_link_target(&plain), plain);
    }
}
