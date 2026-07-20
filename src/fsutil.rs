//! Small filesystem helpers shared across modules.

use anyhow::{bail, Context, Result};
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

/// The directory holding `path`, falling back to the current directory. A bare
/// file name has an *empty* parent rather than none, and an empty path is not
/// something a caller can open, watch, or join against meaningfully — so both
/// cases collapse to `.` here instead of at each call site.
pub fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
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

/// Write `contents` to `path` atomically: a temp file in the target's own
/// directory, then a rename. A crash, a full disk, or a kill mid-write can then
/// only leave the old file or the new one, never a truncated one.
///
/// Both files clipmesh owns are written through here — the config (`--sync-config`)
/// and the MIME rules, which are rewritten on every unseen type and shared
/// mesh-wide, so a half-written one would propagate rather than sit still.
///
/// If `path` is a symlink (stow-managed dotfiles are), follow it and rewrite the
/// real target in place rather than clobbering the link with a regular file;
/// `resolve_link_target` is a no-op for a plain file. The temp lives in the
/// target's own directory so the rename stays on one filesystem (and is
/// therefore atomic), and so `fswatch`, which watches that directory for
/// `CLOSE_WRITE | MOVED_TO`, still sees the replacement.
pub fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    let target = resolve_link_target(path);
    // resolve_link_target stops after a bounded number of hops; if the result
    // is still a symlink the chain was too deep (or a cycle) and we never
    // reached the real file. Refuse rather than rename over — and clobber —
    // that intermediate link. (Config::load already rejects broken/cyclic links
    // upstream; this guards the over-deep case its single open() can still pass.)
    if is_symlink(&target) {
        bail!(
            "{} resolves through too many symlink hops to write safely",
            path.display()
        );
    }
    let dir = parent_dir(&target);
    let name = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("clipmesh");
    let tmp = dir.join(format!(".{name}.tmp"));
    let written = fs::write(&tmp, contents)
        .with_context(|| format!("writing {}", tmp.display()))
        .and_then(|()| {
            fs::rename(&tmp, &target).with_context(|| format!("replacing {}", target.display()))
        });
    if written.is_err() {
        // Don't leave a partial temp behind — it would sit in the resolved
        // target's directory (e.g. a stow dotfiles repo). Best-effort; a
        // successful rename already consumed the temp.
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// Assert that a checked-in generated example matches what its template renders
/// now, or rewrite it when `CLIPMESH_REGEN_EXAMPLE` is set.
///
/// Both generated examples — `examples/config.toml` from `config_template` and
/// `examples/mimetypes` from `mime::TEMPLATE` — are pinned this way. Sharing the
/// check keeps the regen protocol and the staleness message identical for both,
/// so changing how regeneration works is one edit rather than two that can drift.
#[cfg(test)]
pub fn assert_matches_generated_example(path: &str, expected: &str, test_name: &str) {
    // cargo runs tests with CWD = crate root, so `path` is crate-relative.
    if std::env::var("CLIPMESH_REGEN_EXAMPLE").is_ok() {
        fs::write(path, expected).unwrap();
        return;
    }
    let actual = fs::read_to_string(path).unwrap();
    assert_eq!(
        actual, expected,
        "{path} is stale; regenerate with \
         CLIPMESH_REGEN_EXAMPLE=1 cargo test --lib {test_name}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_dir_uses_the_parent_or_falls_back_to_dot() {
        assert_eq!(parent_dir(Path::new("/a/b/c")), PathBuf::from("/a/b"));
        // A bare file name has an empty parent; use the current directory.
        assert_eq!(parent_dir(Path::new("config.toml")), PathBuf::from("."));
    }

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

    #[test]
    fn write_atomic_refuses_an_over_deep_symlink_chain() {
        // A chain longer than resolve_link_target's hop cap resolves to an
        // INTERMEDIATE symlink, not the real file. write_atomic must refuse
        // rather than rename over (and clobber) that intermediate link.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.toml");
        std::fs::write(&real, "old").unwrap();
        // real <- l0 <- l1 <- ... <- l9 (10 hops from l9 to real, > the cap)
        let mut prev = real.clone();
        let mut links = Vec::new();
        for i in 0..10 {
            let link = dir.path().join(format!("l{i}.toml"));
            std::os::unix::fs::symlink(&prev, &link).unwrap();
            prev = link.clone();
            links.push(link);
        }
        let head = prev; // l9

        assert!(
            write_atomic(&head, "new").is_err(),
            "should refuse a chain deeper than the hop cap"
        );
        // the real target is untouched and every intermediate link survives
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "old");
        for link in &links {
            assert!(
                is_symlink(link),
                "intermediate link was clobbered: {}",
                link.display()
            );
        }
    }

    #[test]
    fn write_atomic_does_not_leak_its_temp_on_a_failed_rename() {
        // Force the rename to fail by pointing at a path that is a directory
        // (you can't rename a file over a directory); the temp file must be
        // cleaned up rather than left behind (here, in a stow target dir).
        let dir = tempfile::tempdir().unwrap();
        let as_dir = dir.path().join("config.toml");
        std::fs::create_dir(&as_dir).unwrap();

        assert!(write_atomic(&as_dir, "x").is_err());
        let leftover_tmp = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!leftover_tmp, "temp file leaked after a failed write");
    }
}
