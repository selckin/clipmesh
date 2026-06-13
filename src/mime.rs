//! Per-MIME allow/deny rules, kept in a simple line-based file beside the
//! config. Each line is `<mime> <allow|deny> [max-size]`. A type with no rule
//! falls back to the `unknown_mime` policy and is appended to the end of the
//! file so it's easy to find and tune. Existing lines (comments, blanks, and
//! rules) are preserved verbatim and never reordered; a line that can't be
//! parsed is kept but commented out. The file is watched (see `fswatch`) and
//! reloaded as soon as it changes on disk, so edits take effect right away.

use crate::config::{parse_size, MimePolicy};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

const HEADER: &str = "\
# clipmesh MIME rules — one line per type: <mime> <allow|deny> [max-size]
# New types are appended at the end using the unknown_mime default. Flip
# allow/deny or add a per-type max-size (e.g. 4MiB) as you like; changes apply
# right away (the file is watched). Lines that don't parse are kept but commented out.";

/// Prefix used to comment out a line that doesn't parse. Kept as a constant so
/// the dedup check (`has_line_for`) can recover the original mime from it.
const UNPARSED_PREFIX: &str = "# (unparsed) ";

/// One rule: whether the type may sync, and an optional per-type size cap
/// (applied to that representation's bytes, on top of `max_payload_size`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MimeRule {
    pub allow: bool,
    pub max_size: Option<usize>,
}

/// A single line of the file, kept verbatim so comments, blanks, ordering, and
/// any inline notes survive rewrites. `rule` is set for lines that parsed as a
/// rule, and drives the allow/deny decision.
struct Line {
    text: String,
    rule: Option<(String, MimeRule)>,
}

/// The live ruleset. Two threads share it through an external
/// `Arc<Mutex<MimeRules>>` (the sync engine, and the inotify watcher in
/// `fswatch`), so the type holds no interior lock of its own — callers
/// serialize access via the Mutex.
pub struct MimeRules {
    lines: Vec<Line>,
    unknown: MimePolicy,
    path: Option<PathBuf>,
    /// The file contents as we last read or wrote them, or None if the file is
    /// absent. Used by `reload_if_changed` to detect real changes by content
    /// (not mtime) and to recognize our own writes.
    loaded: Option<String>,
    /// In-memory `lines` differ from disk and need a `persist`. Set when
    /// `ensure` adds a rule; cleared on a successful write. Lets a failed write
    /// be retried on the next `persist` instead of silently diverging.
    dirty: bool,
}

impl MimeRules {
    /// Load rules from the file. A missing file is created (seeded with a
    /// header) so the user can find it. With no path, the rules live only in
    /// memory.
    pub fn load(path: Option<PathBuf>, unknown: MimePolicy) -> MimeRules {
        let mut me = MimeRules {
            lines: Vec::new(),
            unknown,
            path,
            loaded: None,
            dirty: false,
        };
        let absent = me.read_file();
        // Materialize a header-only file when it's missing or empty so it's
        // discoverable — but never when we merely failed to read it (a transient
        // error must not clobber the user's existing rules).
        let empty = me.loaded.as_deref().is_some_and(|s| s.trim().is_empty());
        if me.path.is_some() && (absent || empty) {
            me.lines = HEADER
                .lines()
                .map(|l| Line {
                    text: l.to_string(),
                    rule: None,
                })
                .collect();
            me.dirty = true;
            me.write_file();
        }
        me
    }

    /// Read the file into the live ruleset. Returns whether the file was
    /// confirmed absent (NotFound) — distinct from a read error — so `load` only
    /// materializes the header for a genuinely-missing file.
    fn read_file(&mut self) -> bool {
        // Clone the path so we can call write_file (&mut self) below without
        // holding a borrow of self.path.
        let Some(path) = self.path.clone() else {
            return false;
        };
        match fs::read_to_string(&path) {
            Ok(text) => {
                self.ingest(text, &path);
                false
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.lines.clear();
                self.loaded = None;
                true
            }
            Err(e) => {
                warn!("couldn't read MIME rules from {}: {e}", path.display());
                false
            }
        }
    }

    /// Parse freshly-read file text into the live ruleset and remember it as
    /// our last-seen content. Rewrites the file if any line had to be
    /// commented out, so the on-disk copy matches.
    fn ingest(&mut self, text: String, path: &Path) {
        let (lines, had_bad) = parse(&text);
        self.lines = lines;
        self.loaded = Some(text);
        self.dirty = false; // in sync with what we just read
        info!(
            "loaded {} MIME rule(s) from {}",
            self.rule_count(),
            path.display()
        );
        if had_bad {
            self.write_file(); // persist the commented-out form
        }
    }

    fn write_file(&mut self) {
        let Some(path) = self.path.clone() else {
            return;
        };
        let mut text = String::new();
        for line in &self.lines {
            text.push_str(&line.text);
            text.push('\n');
        }
        match fs::write(&path, &text) {
            Ok(()) => {
                // Remember our own write so reload_if_changed treats it as
                // unchanged (no reload storm when the watcher sees this write).
                self.loaded = Some(text);
                self.dirty = false;
            }
            // Leave `dirty` set so the next persist() retries rather than
            // letting in-memory rules silently diverge from disk.
            Err(e) => warn!("couldn't write MIME rules to {}: {e}", path.display()),
        }
    }

    /// Reload from disk if the file's contents differ from what we last read
    /// or wrote. Comparing contents (not mtime) catches edits the filesystem's
    /// mtime granularity would hide, and recognizes our own writes so persist()
    /// can't trigger a reload via the watcher.
    pub fn reload_if_changed(&mut self) {
        let Some(path) = self.path.clone() else {
            return;
        };
        match fs::read_to_string(&path) {
            // Unchanged (includes our own writes): nothing to do, stay quiet.
            Ok(text) if self.loaded.as_deref() == Some(text.as_str()) => {}
            Ok(text) => {
                debug!("MIME rules file changed on disk; reloading");
                self.ingest(text, &path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // The file is momentarily absent (often an editor's
                // delete-then-write mid-save). Keep the last-known-good rules
                // rather than flipping every type to the unknown_mime policy; a
                // later write reloads the new content.
                debug!("MIME rules file is momentarily absent; keeping current rules");
            }
            Err(e) => warn!("couldn't read MIME rules from {}: {e}", path.display()),
        }
    }

    /// Append a default rule for every unseen type, marking the ruleset dirty if
    /// any were added (the caller then [`persist`](Self::persist)s). Returns
    /// whether anything was added.
    pub fn ensure<'a>(&mut self, mimes: impl IntoIterator<Item = &'a String>) -> bool {
        let allow = self.unknown == MimePolicy::Allow;
        let mut added = false;
        for m in mimes {
            if !self.has_line_for(m) {
                let action = if allow { "allow" } else { "deny" };
                self.lines.push(Line {
                    text: format!("{m} {action}"),
                    rule: Some((
                        m.clone(),
                        MimeRule {
                            allow,
                            max_size: None,
                        },
                    )),
                });
                debug!("new MIME type {m}: defaulting to {action} (unknown_mime)");
                added = true;
            }
        }
        self.dirty |= added;
        added
    }

    /// Whether any of `mimes` lacks a rule (and so would be recorded by
    /// `ensure`). Lets the caller skip touching disk when nothing is new.
    pub fn has_unseen<'a>(&self, mimes: impl IntoIterator<Item = &'a String>) -> bool {
        mimes.into_iter().any(|m| !self.has_line_for(m))
    }

    /// Whether there are in-memory rule changes not yet written to disk.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Write the rules to disk if there are unsaved changes (a no-op otherwise,
    /// so it's cheap to call unconditionally).
    pub fn persist(&mut self) {
        if self.dirty {
            self.write_file();
        }
    }

    /// Whether a `size`-byte representation of `mime` may sync.
    pub fn allows(&self, mime: &str, size: usize) -> bool {
        match self.find_rule(mime) {
            Some(r) => r.allow && r.max_size.map_or(true, |max| size <= max),
            None => self.unknown == MimePolicy::Allow,
        }
    }

    // Linear scan over the verbatim lines. Intentional: rule files hold a
    // handful of types and we'd otherwise need a parallel index kept in sync
    // with `lines` (which exists to preserve on-disk order and comments).
    fn find_rule(&self, mime: &str) -> Option<MimeRule> {
        self.lines.iter().find_map(|l| match &l.rule {
            Some((m, r)) if m == mime => Some(*r),
            _ => None,
        })
    }

    /// Whether the file already has a line for `mime` — a parsed rule, or a
    /// line commented out as unparseable whose first token is `mime`. Checking
    /// the latter stops `ensure` from appending a duplicate default for a type
    /// the user typo'd (e.g. `image/png allwo`).
    fn has_line_for(&self, mime: &str) -> bool {
        self.lines.iter().any(|l| match &l.rule {
            Some((m, _)) => m == mime,
            None => {
                l.text
                    .strip_prefix(UNPARSED_PREFIX)
                    .and_then(|rest| rest.split_whitespace().next())
                    == Some(mime)
            }
        })
    }

    fn rule_count(&self) -> usize {
        self.lines.iter().filter(|l| l.rule.is_some()).count()
    }
}

/// Parse the file into verbatim lines, attaching a rule to each line that is
/// one. Returns whether any line had to be commented out (so the caller can
/// rewrite the file). Comments and blank lines pass through untouched.
fn parse(text: &str) -> (Vec<Line>, bool) {
    let mut lines = Vec::new();
    let mut had_bad = false;
    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            lines.push(Line {
                text: raw.to_string(),
                rule: None,
            });
            continue;
        }
        match parse_rule(trimmed) {
            Some(rule) => lines.push(Line {
                text: raw.to_string(),
                rule: Some(rule),
            }),
            None => {
                warn!("MIME rules: keeping unparseable line as a comment: {raw:?}");
                lines.push(Line {
                    text: format!("{UNPARSED_PREFIX}{raw}"),
                    rule: None,
                });
                had_bad = true;
            }
        }
    }
    (lines, had_bad)
}

/// Parse a single non-comment line into `(mime, rule)`. A trailing `# comment`
/// is ignored for parsing (the raw line is preserved separately). A malformed
/// max-size is warned about and dropped, but the allow/deny still applies.
fn parse_rule(content: &str) -> Option<(String, MimeRule)> {
    let body = content.split('#').next().unwrap_or("").trim();
    let mut f = body.split_whitespace();
    let mime = f.next()?;
    let allow = match f.next()? {
        "allow" => true,
        "deny" => false,
        _ => return None,
    };
    let max_size = match f.next() {
        None => None,
        Some(s) => match parse_size(s) {
            // A 0-byte cap would make `allow` silently behave as `deny`
            // (nothing is `<= 0`). Drop it so the line means what it reads;
            // use `deny` to actually block a type.
            Ok(0) => {
                warn!("MIME rules: a 0-byte max-size on `{content}` would block the type; ignoring it (use `deny` to block it)");
                None
            }
            Ok(v) => Some(v),
            Err(e) => {
                warn!("MIME rules: bad max-size {s:?} ({e}) on `{content}`; ignoring it");
                None
            }
        },
    };
    Some((mime.to_string(), MimeRule { allow, max_size }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    #[test]
    fn allows_respects_rules_and_size_caps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png allow 100B\nimage/bmp deny\n").unwrap();
        let rules = MimeRules::load(Some(path), MimePolicy::Deny);
        assert!(rules.allows("image/png", 100)); // exactly at the cap
        assert!(!rules.allows("image/png", 101)); // over the cap
        assert!(!rules.allows("image/bmp", 1)); // denied outright
        assert!(!rules.allows("text/plain", 1)); // unknown -> deny policy
    }

    #[test]
    fn unknown_allow_policy_permits_unseen_types() {
        let rules = MimeRules::load(None, MimePolicy::Allow);
        assert!(rules.allows("anything/new", 999));
    }

    #[test]
    fn zero_size_cap_is_ignored_so_allow_still_allows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png allow 0B\n").unwrap();
        let rules = MimeRules::load(Some(path), MimePolicy::Deny);
        // A 0-byte cap is meaningless: `size <= 0` is false for any real
        // payload, so it would silently turn "allow" into "deny everything".
        // We drop the bogus cap instead, so the line behaves as plain allow.
        assert!(rules.allows("image/png", 1));
        assert!(rules.allows("image/png", 10_000));
    }

    #[test]
    fn deny_rule_with_a_cap_still_denies_regardless_of_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png deny 100B\n").unwrap();
        let rules = MimeRules::load(Some(path), MimePolicy::Deny);
        assert!(!rules.allows("image/png", 1)); // deny wins; the cap is moot
        assert!(!rules.allows("image/png", 50));
    }

    #[test]
    fn a_bad_max_size_keeps_the_allow_deny_and_drops_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png allow notasize\n").unwrap();
        let rules = MimeRules::load(Some(path), MimePolicy::Deny);
        // The garbage cap is dropped (warned), but the rule still applies as
        // a plain allow — distinct from a fully unparseable line.
        assert!(rules.allows("image/png", 999_999));
    }

    #[test]
    fn keeps_comments_and_blanks_and_appends_at_the_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(
            &path,
            "# my header\nimage/png allow\n\n# group\ntext/plain deny\n",
        )
        .unwrap();
        let mut rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert!(rules.allows("image/png", 1));
        assert!(!rules.allows("text/plain", 1));
        // a new type is appended at the end; comments, blank and order survive
        assert!(rules.ensure([&s("image/gif")]));
        rules.persist();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "# my header\nimage/png allow\n\n# group\ntext/plain deny\nimage/gif deny\n"
        );
    }

    #[test]
    fn ensure_appends_in_order_without_sorting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "text/plain allow\nimage/png allow\n").unwrap();
        let mut rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert!(rules.ensure([&s("zzz/type"), &s("aaa/type")]));
        rules.persist();
        let body: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            })
            .map(str::to_string)
            .collect();
        // original order kept; new types appended in the order ensure saw them
        assert_eq!(
            body,
            [
                "text/plain allow",
                "image/png allow",
                "zzz/type deny",
                "aaa/type deny"
            ]
        );
        assert!(!rules.ensure([&s("zzz/type")])); // already present
    }

    #[test]
    fn unparseable_lines_are_commented_out_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(
            &path,
            "image/png allow\nthis is not valid\ntext/plain deny\n",
        )
        .unwrap();
        let rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        // the good rules still apply
        assert!(rules.allows("image/png", 1));
        assert!(!rules.allows("text/plain", 1));
        // load rewrote the file with the bad line commented out, still present
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("this is not valid"),
            "bad line dropped:\n{text}"
        );
        assert!(
            text.lines()
                .any(|l| l.starts_with('#') && l.contains("this is not valid")),
            "bad line not commented:\n{text}"
        );
        // re-loading the now-commented file leaves it byte-for-byte unchanged
        let before = std::fs::read_to_string(&path).unwrap();
        let _again = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn inline_comments_on_rule_lines_are_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png allow   # keep this note\n").unwrap();
        let mut rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert!(rules.allows("image/png", 1)); // parsed despite the inline comment
        assert!(rules.ensure([&s("text/plain")]));
        rules.persist();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("image/png allow   # keep this note"),
            "inline comment lost:\n{text}"
        );
    }

    #[test]
    fn creates_the_file_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        assert!(!path.exists());
        let _rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert!(path.exists(), "load should create the rules file");
    }

    #[test]
    fn reload_if_changed_rereads_after_an_edit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png deny\n").unwrap();
        let mut rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert!(!rules.allows("image/png", 1));

        // An external edit is detected by content, so it's caught even when the
        // filesystem's mtime granularity wouldn't show the write as newer.
        std::fs::write(&path, "image/png allow\n").unwrap();
        rules.reload_if_changed();
        assert!(rules.allows("image/png", 1));
    }

    #[test]
    fn reload_keeps_rules_when_the_file_transiently_disappears() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png allow\n").unwrap();
        let mut rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert!(rules.allows("image/png", 1));
        // File vanishes momentarily (e.g. an editor's delete-then-write).
        std::fs::remove_file(&path).unwrap();
        rules.reload_if_changed();
        // Keep the last-known-good rules rather than flipping every type to the
        // unknown_mime policy.
        assert!(rules.allows("image/png", 1));
    }

    #[test]
    fn load_does_not_overwrite_the_file_on_a_non_notfound_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        // A directory at the path makes read_to_string fail with a non-NotFound
        // error; load must NOT clobber it with the header template.
        std::fs::create_dir(&path).unwrap();
        let _rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert!(
            path.is_dir(),
            "load overwrote a path it merely failed to read"
        );
    }

    #[test]
    fn ensure_does_not_duplicate_a_type_already_present_as_an_unparsed_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        // A typo'd action makes this unparseable; load comments it out.
        std::fs::write(&path, "image/png allwo\n").unwrap();
        let mut rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert!(
            !rules.ensure([&s("image/png")]),
            "ensure duplicated an unparsed type"
        );
        rules.persist();
        let body = std::fs::read_to_string(&path).unwrap();
        let count = body.lines().filter(|l| l.contains("image/png")).count();
        assert_eq!(count, 1, "duplicate image/png line:\n{body}");
    }

    #[test]
    fn empty_existing_file_gets_the_header_materialized() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "").unwrap();
        let _rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("clipmesh MIME rules"),
            "header not written:\n{body}"
        );
    }

    #[test]
    fn persist_only_writes_when_dirty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png allow\n").unwrap();
        let mut rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert!(!rules.is_dirty());
        assert!(rules.ensure([&s("text/plain")]));
        assert!(rules.is_dirty());
        rules.persist();
        assert!(!rules.is_dirty());
    }

    #[test]
    fn has_unseen_reports_types_without_a_rule() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png allow\n").unwrap();
        let rules = MimeRules::load(Some(path), MimePolicy::Deny);
        assert!(!rules.has_unseen([&s("image/png")]));
        assert!(rules.has_unseen([&s("text/plain")]));
    }

    #[test]
    fn reload_if_changed_is_a_noop_after_our_own_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png allow\n").unwrap();
        let mut rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        // We add and persist a new type; the watcher then fires on our own
        // write. reload_if_changed must treat it as unchanged (no reload storm)
        // and must not lose the just-added rule.
        assert!(rules.ensure([&s("text/plain")]));
        rules.persist();
        let on_disk = std::fs::read_to_string(&path).unwrap();
        rules.reload_if_changed();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), on_disk);
        // The rule is still in memory: ensure() doesn't re-add it.
        assert!(!rules.ensure([&s("text/plain")]));
    }
}
