//! Per-MIME allow/deny rules, kept in a TOML file beside the config. Each entry
//! under `[rules]` is `"<mime>" = "allow" | "deny"`, or a table with a per-type
//! size cap: `"<mime>" = { rule = "allow", max = "4MiB" }`. Quoting the MIME as
//! a TOML key means types with spaces or punctuation (e.g. Java dataflavors)
//! work fine. A key may be a glob (`*` matches any run, `?` one character), e.g.
//! `"JAVA_DATATRANSFER*" = "deny"`; matching is case-insensitive (ASCII), and `*`
//! and `?` are always wildcards (no escape). When more than one key matches a
//! type the most specific wins (see [`specificity`]). A type matched by no key
//! falls back to the `unknown_mime` policy and is appended automatically. The
//! whole-file last-writer-wins version lives in a
//! managed `[clipmesh]` table. On save the `[rules]` table is sorted by key and
//! comments interleaved among its entries are dropped (comments above `[rules]`
//! — the header and `[clipmesh]` — are kept). The file is watched (see
//! `fswatch`) and reloaded as soon as it changes.

use crate::config::{parse_size, MimePolicy};
use crate::protocol::Version;
use std::cmp::Reverse;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use toml_edit::{value, Decor, DocumentMut, Item, Key, Table, Value};

use tracing::{debug, info, warn};
use uuid::Uuid;

/// Lock the shared rules, tolerating a poisoned mutex.
///
/// `MimeRules` has no cross-field invariant that a panic mid-update could leave
/// half-applied — the worst case is an unsaved edit — so recovering the guard is
/// strictly better than propagating the panic into the engine or the fswatch
/// thread and taking clipboard sync down with it.
pub fn lock_rules(rules: &Mutex<MimeRules>) -> MutexGuard<'_, MimeRules> {
    rules
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Skeleton written for a brand-new (or reset) rules file, and the source
/// `examples/mimetypes` is generated from — see `render_example`.
///
/// The `[rules]` defaults matter: with the deny-by-default `unknown_mime`
/// policy, an empty table means clipmesh syncs *nothing* until the user curates
/// it, and the deny globs below are what keep per-transfer atom names from
/// accumulating in this file forever. Shipping them here rather than only in the
/// example means every install gets them, not just the ones that ran install.sh.
const TEMPLATE: &str = "\
# clipmesh MIME rules — managed, but safe to hand-edit.
#
# Each entry under [rules] decides whether a clipboard MIME type syncs:
#   \"<mime>\" = \"allow\"                          # sync this type
#   \"<mime>\" = \"deny\"                           # never sync it
#   \"<mime>\" = { rule = \"allow\", max = \"4MiB\" } # allow, with a per-type cap
#                                               # (on top of max_payload_size)
#
# Keys are quoted TOML strings, so MIME types with spaces, ';', '=' or other
# punctuation (e.g. Java dataflavors) are fine. A key may also be a glob: '*'
# matches any run of characters, '?' matches exactly one (always wildcards, no
# escape) — e.g. \"JAVA_DATATRANSFER*\" or \"*;charset=utf-16*\". Matching is
# case-insensitive (ASCII), and when several keys match a type the most specific
# wins (an exact key beats a glob; among globs, more literal characters win, ties
# break to deny).
#
# clipmesh manages this file: it creates it with the defaults below, appends any
# new type it sees (using the config's unknown_mime default, unless a glob
# already covers it), and reloads it when it changes (so edits apply right away).
# It keeps the [rules] entries sorted and drops notes placed among them; comments
# up here above [rules] are kept. The [clipmesh] table is added and managed
# automatically — leave it alone. You can also manage rules without opening the
# file:
#   clipmesh --allow \"*/svg+xml\"   clipmesh --deny \"JAVA_DATATRANSFER*\"
#   clipmesh --rules   # list the rules and flag overlapping globs
#
# The defaults allow the common text and image types, and deny a few that are
# useless or actively unhelpful to move between machines:
#   JAVA_DATATRANSFER*   Java/Swing mints one of these per transfer, so recording
#                        each would grow this file without bound.
#   *;charset=utf-16*    redundant with the UTF-8 representation of the same text.
#   text/uri-list        file copies put local filesystem paths on the clipboard;
#   x-special/*          those paths don't resolve on another machine.
#   image/bmp            uncompressed, so it burns the payload budget for nothing.
# Flip any of them to taste — this file is yours once created.

[clipmesh]

[rules]
\"text/plain\" = \"allow\"
\"text/plain;charset=utf-8\" = \"allow\"
\"text/html\" = \"allow\"
\"STRING\" = \"allow\"
\"UTF8_STRING\" = \"allow\"
\"TEXT\" = \"allow\"
\"image/png\" = \"allow\"
\"image/jpeg\" = \"allow\"
\"image/tiff\" = { rule = \"allow\", max = \"16MiB\" }
\"image/bmp\" = \"deny\"
\"JAVA_DATATRANSFER*\" = \"deny\"
\"*;charset=utf-16*\" = \"deny\"
\"text/uri-list\" = \"deny\"
\"x-special/*\" = \"deny\"
";

/// The built-in skeleton in its canonical on-disk form — byte-for-byte what
/// clipmesh writes when it creates a fresh rules file (`materialize_fresh` →
/// `persist_body` → `body`, which sorts and strips interleaved comments).
///
/// `examples/mimetypes` is generated from this and pinned by a golden test, so
/// the shipped example and the file clipmesh creates itself cannot drift — the
/// same arrangement `config_template` uses for `examples/config.toml`.
///
/// Test-scoped: both writing the example and pinning it happen in that test.
/// The daemon never renders the example — it renders the *file*, through
/// `materialize_fresh`, which is exactly what makes the pin meaningful.
#[cfg(test)]
fn render_example() -> String {
    let mut doc: DocumentMut = TEMPLATE.parse().expect("built-in TOML template must parse");
    normalize(&mut doc);
    doc.to_string()
}

/// One rule: whether the type may sync, and an optional per-type size cap
/// (applied to that representation's bytes, on top of `max_payload_size`).
/// Internal: callers outside this module ask [`CompiledRules::allows`], which
/// applies both halves, rather than interpreting a rule themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MimeRule {
    allow: bool,
    max_size: Option<usize>,
}

/// A rules-file version and body that are durably on disk together.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub version: Version,
    pub body: String,
}

/// Why a snapshot could not be taken. In every case the in-memory rules have
/// been rolled back, so nothing announces a version that isn't persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    /// The rendered body exceeds the caller's limit.
    TooLarge { len: usize },
    /// Writing the file failed.
    WriteFailed,
}

pub type SnapshotResult = Result<Snapshot, SnapshotError>;

/// One entry in the `--rules` overlap report.
/// What a rule (or an overlapping rule) decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
    /// The value isn't a usable rule (a typo); it falls back to `unknown_mime`.
    Invalid,
}

/// How an overlapping glob relates to the entry it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// Same verdict — the glob already covers this entry, which is redundant.
    Redundant,
    /// Different verdict; this entry is more specific and wins.
    Overrides,
    /// Different verdict; the glob is more specific and wins.
    OverriddenBy,
    /// This entry's value is invalid, so the glob decides its key instead.
    DecidesInstead,
}

/// Another glob whose pattern also matches an entry's key.
pub struct Overlap {
    /// The other glob's key, unquoted (e.g. `image/*`).
    pub key: String,
    pub verdict: Verdict,
    pub relation: Relation,
}

/// One entry in the `--rules` report.
pub struct RuleReport {
    /// The entry's key, unquoted (e.g. `image/png`).
    pub key: String,
    pub verdict: Verdict,
    /// The per-type size cap as written (e.g. `16MiB`), if any.
    pub max: Option<String>,
    /// Other globs that also match this entry's key (empty if none).
    pub overlaps: Vec<Overlap>,
}

/// The live ruleset. Two threads share it through an external
/// `Arc<Mutex<MimeRules>>` (the sync engine, and the inotify watcher in
/// `fswatch`), so the type holds no interior lock of its own — callers
/// serialize access via the Mutex.
pub struct MimeRules {
    /// The TOML document. Comments and ordering above `[rules]` are preserved;
    /// the `[rules]` table is sorted and its interleaved comments dropped on
    /// every write (see `normalize`).
    doc: DocumentMut,
    unknown: MimePolicy,
    path: Option<PathBuf>,
    /// The file contents as we last read or wrote them, or None if the file is
    /// absent. Used by `reload_if_changed` to detect real changes by content
    /// (not mtime) and to recognize our own writes.
    loaded: Option<String>,
    /// In-memory `doc` differs from disk and needs a `persist`. Set when a rule
    /// or the version changes; cleared on a successful write. Lets a failed
    /// write be retried on the next `persist` instead of silently diverging.
    dirty: bool,
}

/// Why [`MimeRules::open`] came back without a ruleset.
///
/// These are exactly the states [`MimeRules::load`] resolves by writing over the
/// file, which is why they have names: a caller that must not clobber it sees
/// what is wrong and decides for itself, instead of classifying the file a second
/// time — a duplicate that can disagree with this one, and that races the load it
/// is meant to guard.
#[derive(Debug)]
pub enum RulesFileState {
    /// Nothing at the configured path (including a symlink to a missing target).
    Missing,
    /// The file is there but holds only whitespace.
    Empty,
    /// The file is there but isn't valid TOML — a typo, or an old line-format
    /// rules file.
    Malformed(toml_edit::TomlError),
    /// The file couldn't be read at all (permissions, a mid-rename catch, ...).
    Unreadable(std::io::Error),
}

impl RulesFileState {
    /// Whether [`MimeRules::load`] should replace the file with a fresh
    /// skeleton, warning about what that costs the user.
    ///
    /// Every state but one is rewritten: there is nothing on disk to lose
    /// (missing, empty) or nothing clipmesh can use (malformed). A file we failed
    /// to *read* is the exception — the rules are most likely still in it and the
    /// failure transient — so it is left exactly as it is.
    fn warrants_a_rewrite(&self, path: &Path) -> bool {
        match self {
            RulesFileState::Empty => true,
            RulesFileState::Missing => {
                if crate::fsutil::is_symlink(path) {
                    warn!(
                        "MIME-rules file {} is a symlink whose target is missing; \
                         starting from an empty ruleset, then writing a fresh skeleton \
                         through the link (which recreates the target if its directory \
                         exists)",
                        path.display()
                    );
                }
                true
            }
            RulesFileState::Malformed(e) => {
                warn!(
                    "MIME rules file {} isn't valid TOML ({e}); replacing it with a fresh one",
                    path.display()
                );
                true
            }
            RulesFileState::Unreadable(e) => {
                warn!("couldn't read MIME rules from {}: {e}", path.display());
                false
            }
        }
    }
}

impl MimeRules {
    /// An empty in-memory ruleset for `path` — where both constructors below
    /// start, and what a caller is left with when there is no file to read.
    fn empty(path: Option<PathBuf>, unknown: MimePolicy) -> MimeRules {
        MimeRules {
            doc: DocumentMut::new(),
            unknown,
            path,
            loaded: None,
            dirty: false,
        }
    }

    /// Read the rules file, **never writing to it**: whatever is wrong with the
    /// file comes back as a [`RulesFileState`] for the caller to act on.
    ///
    /// This is the constructor for anything that must not surprise the user by
    /// rewriting their file — notably the one-shot CLI commands, since replacing
    /// a file we merely failed to parse also discards the `[clipmesh]` table the
    /// mesh's last-writer-wins version lives in. With no path the rules live only
    /// in memory, so there is no file to refuse: that is `Ok`, empty.
    pub fn open(path: Option<PathBuf>, unknown: MimePolicy) -> Result<MimeRules, RulesFileState> {
        let mut me = Self::empty(path, unknown);
        me.read_file()?;
        Ok(me)
    }

    /// Read the rules file, healing it in place: a missing, empty, or non-TOML
    /// file is **replaced** with a fresh skeleton (an old line-format file is
    /// discarded). With no path, the rules live only in memory.
    ///
    /// That write is the daemon's bootstrap — it is how a first run ends up with
    /// a rules file at all — but it destroys whatever was there, so the choice of
    /// this constructor over [`open`](Self::open) is the choice to allow it.
    pub fn load(path: Option<PathBuf>, unknown: MimePolicy) -> MimeRules {
        let state = match Self::open(path.clone(), unknown) {
            Ok(rules) => return rules,
            Err(state) => state,
        };
        let mut me = Self::empty(path, unknown);
        // `open` only ever refuses an actual file, so the path is necessarily
        // there; asking keeps the pathless case an ordinary in-memory ruleset
        // rather than an `expect` that would have to stay true forever.
        if let Some(path) = me.path.clone() {
            if state.warrants_a_rewrite(&path) {
                me.materialize_fresh();
            }
        }
        me
    }

    /// Read and parse the file into `self`, or report the state that stopped it.
    /// Never writes: what to do about a file that didn't load is the caller's
    /// decision, made from what comes back here.
    fn read_file(&mut self) -> Result<(), RulesFileState> {
        let Some(path) = self.path.clone() else {
            return Ok(()); // in-memory only; there is nothing to read
        };
        match fs::read_to_string(&path) {
            Ok(text) if text.trim().is_empty() => Err(RulesFileState::Empty),
            Ok(text) => match text.parse::<DocumentMut>() {
                Ok(doc) => {
                    self.ingest(doc, text, &path);
                    Ok(())
                }
                Err(e) => Err(RulesFileState::Malformed(e)),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(RulesFileState::Missing),
            Err(e) => Err(RulesFileState::Unreadable(e)),
        }
    }

    /// Write the built-in skeleton (comments + empty `[clipmesh]`/`[rules]`).
    fn materialize_fresh(&mut self) {
        self.doc = TEMPLATE.parse().expect("built-in TOML template must parse");
        self.loaded = None;
        self.dirty = true;
        self.persist_body(None);
    }

    /// Adopt a freshly-parsed document as the live ruleset and remember its text
    /// as our last-seen content. Warns about any unusable rule values.
    fn ingest(&mut self, doc: DocumentMut, text: String, path: &Path) {
        warn_invalid_rules(&doc, path);
        self.doc = doc;
        self.loaded = Some(text);
        self.dirty = false;
        info!(
            "loaded {} MIME rule(s) from {}",
            self.rule_count(),
            path.display()
        );
    }

    /// Render the current ruleset to its on-disk TOML text, so it can be sent to
    /// peers verbatim. Identical to what `persist_body` writes: the `[rules]` table
    /// is sorted and any comments interleaved among its entries are dropped, so
    /// the saved/shared form is deterministic. Comments above `[rules]` (the
    /// header and the `[clipmesh]` table) are kept.
    ///
    /// A body reaches a peer only as part of a [`Snapshot`], which is what makes
    /// "rendered" and "durably on disk at this version" one step rather than two
    /// a caller could take out of order.
    fn body(&self) -> String {
        let mut doc = self.doc.clone();
        normalize(&mut doc);
        doc.to_string()
    }

    /// Replace the entire ruleset with `text` (a file body received from a peer),
    /// marking it dirty so a subsequent `persist` writes it. A body that isn't
    /// valid TOML is ignored (we never adopt garbage). Does not touch `loaded` —
    /// `persist` updates that once the bytes are on disk.
    pub fn replace_from(&mut self, text: String) {
        match text.parse::<DocumentMut>() {
            Ok(doc) => {
                let label = self.path.clone().unwrap_or_else(|| PathBuf::from("<peer>"));
                warn_invalid_rules(&doc, &label);
                self.doc = doc;
                self.dirty = true;
            }
            Err(e) => warn!("ignoring a peer's MIME-rules update that isn't valid TOML: {e}"),
        }
    }

    /// Reload from disk if the file's contents differ from what we last read or
    /// wrote. Comparing contents (not mtime) recognizes our own writes so
    /// persist() can't trigger a reload via the watcher. Returns whether a new
    /// external file was applied.
    pub fn reload_if_changed(&mut self) -> bool {
        let Some(path) = self.path.clone() else {
            return false;
        };
        match fs::read_to_string(&path) {
            // Unchanged (includes our own writes): nothing to do, stay quiet.
            Ok(text) if self.loaded.as_deref() == Some(text.as_str()) => false,
            // An empty/whitespace read while we already hold content is almost
            // always a mid-save transient (a watcher event arriving before the
            // editor finished writing). Keep the current rules rather than wiping
            // them — same stance as the momentarily-absent case below.
            Ok(text) if text.trim().is_empty() && !self.doc.is_empty() => {
                debug!("MIME rules file read empty (likely a mid-save transient); keeping current rules");
                false
            }
            Ok(text) => {
                match text.parse::<DocumentMut>() {
                    Ok(doc) => {
                        debug!("MIME rules file changed on disk; reloading");
                        self.ingest(doc, text, &path);
                        true
                    }
                    Err(e) => {
                        warn!("MIME rules file changed but isn't valid TOML ({e}); keeping current rules");
                        false
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // The file is momentarily absent (often an editor's
                // delete-then-write mid-save). Keep the last-known-good rules.
                debug!("MIME rules file is momentarily absent; keeping current rules");
                false
            }
            Err(e) => {
                warn!("couldn't read MIME rules from {}: {e}", path.display());
                false
            }
        }
    }

    /// Append a default rule for every unseen type, marking the ruleset dirty if
    /// any were added (the caller then [`persist`](Self::persist)s). Returns
    /// whether anything was added.
    pub fn ensure<'a>(&mut self, mimes: impl IntoIterator<Item = &'a String>) -> bool {
        // Two phases: decide under one compiled view, then mutate. Deciding
        // per-type against the raw document instead would re-walk (and re-parse)
        // the whole table once per MIME type — the `reps × rules` cost
        // `CompiledRules` exists to remove. The view borrows the document, so
        // the compiler forces it to be dropped before the append.
        let unseen: Vec<String> = {
            let compiled = self.compile();
            mimes
                .into_iter()
                // Already covered by an exact key or a matching glob -> leave it.
                .filter(|m| !compiled.any_match(m))
                .cloned()
                .collect()
        };
        if unseen.is_empty() {
            return false;
        }
        let action = rule_word(self.unknown == MimePolicy::Allow);
        // A type repeated in `mimes` yields the same key twice; the second write
        // is identical to the first, so this stays idempotent.
        for m in &unseen {
            table_mut(&mut self.doc, "rules")[m.as_str()] = value(action);
            debug!("new MIME type {m}: defaulting to {action} (unknown_mime)");
        }
        self.dirty = true;
        true
    }

    /// Whether any of `mimes` is matched by no `[rules]` key.
    ///
    /// Walks the keys directly rather than going through [`compile`]: the answer
    /// depends only on key globs, while compiling *also* parses every rule's
    /// verdict, resolves its size cap and computes specificity weights — all of
    /// which this question discards. The capture path asks it on every copy, and
    /// the table is designed to grow (each unseen type is appended to it
    /// forever), so the saving grows with uptime.
    ///
    /// [`compile`]: MimeRules::compile
    pub fn has_unseen<'a>(&self, mimes: impl IntoIterator<Item = &'a String>) -> bool {
        let Some(table) = self.rules_table() else {
            // No rules at all: everything is unseen (unless there is nothing to
            // ask about).
            return mimes.into_iter().next().is_some();
        };
        mimes
            .into_iter()
            .any(|m| !table.iter().any(|(key, _)| glob_match(key, m)))
    }

    /// Remove every `[rules]` entry whose key the glob `pattern` matches
    /// (case-insensitive), except an entry equal to `pattern` itself. Returns the
    /// removed entries rendered as copy-pasteable `"key" = value` lines. Half of
    /// [`apply_glob`](Self::apply_glob), which is how the `--allow`/`--deny` CLI
    /// collapses entries under a new glob — removing without then setting the
    /// glob would drop rules and replace them with nothing.
    fn remove_matching(&mut self, pattern: &str) -> Vec<String> {
        let Some(rules) = self.doc.get_mut("rules").and_then(Item::as_table_mut) else {
            return Vec::new();
        };
        let mut keys: Vec<String> = rules
            .iter()
            .map(|(k, _)| k.to_string())
            .filter(|k| !k.eq_ignore_ascii_case(pattern) && glob_match(pattern, k))
            .collect();
        keys.sort(); // echo the removed entries in the same order as the sorted file
        let mut removed = Vec::new();
        for k in keys {
            if let Some(item) = rules.remove(&k) {
                removed.push(render_entry(&k, &item));
            }
        }
        if !removed.is_empty() {
            self.dirty = true;
        }
        removed
    }

    /// Add or replace a single `allow`/`deny` rule for `key` (which may be a
    /// glob). The other half of [`apply_glob`](Self::apply_glob).
    fn set_rule(&mut self, key: &str, allow: bool) {
        table_mut(&mut self.doc, "rules")[key] = value(rule_word(allow));
        self.dirty = true;
    }

    /// Apply an `--allow`/`--deny` glob: drop the entries it now covers, then set
    /// the rule itself (so an existing key equal to `pattern` is flipped in place,
    /// not removed-and-re-added). Returns the removed entries as copy-pasteable
    /// lines. Caller `persist`s. `pattern` is assumed non-empty (the CLI rejects
    /// empty input before calling).
    pub fn apply_glob(&mut self, allow: bool, pattern: &str) -> Vec<String> {
        let removed = self.remove_matching(pattern);
        self.set_rule(pattern, allow);
        removed
    }

    /// Build a read-only report of the rules (sorted by key) and, for each, any
    /// *other* glob whose pattern also matches that entry's key — flagging
    /// redundant duplicates (same verdict) and precedence conflicts (different
    /// verdict, resolved by [`specificity`]). Used by the `--rules` CLI.
    pub fn rules_report(&self) -> Vec<RuleReport> {
        let Some(rules) = self.rules_table() else {
            return Vec::new();
        };
        /// An entry, parsed exactly once. Every entry is also examined as a
        /// candidate overlap of every other, so parsing on demand re-derived the
        /// same values O(n²) times — and, worse, left three sites (the verdict,
        /// the rule, and the overlap's verdict) each having to agree about what
        /// a rule value means. They are one parse; keep them one value.
        struct Entry<'a> {
            key: &'a str,
            rule: Option<MimeRule>,
            verdict: Verdict,
            /// The cap as written, borrowed until the report needs it owned.
            max: Option<&'a str>,
            /// Only a glob can also match a *different* entry's key.
            is_glob: bool,
        }
        let mut entries: Vec<Entry<'_>> = rules
            .iter()
            .map(|(key, item)| {
                let (rule, verdict, max) = describe_value(item);
                Entry {
                    key,
                    rule,
                    verdict,
                    max,
                    is_glob: has_wildcard(key),
                }
            })
            .collect();
        entries.sort_by(|a, b| a.key.cmp(b.key));
        entries
            .iter()
            .map(|e| RuleReport {
                key: e.key.to_string(),
                verdict: e.verdict,
                max: e.max.map(str::to_string),
                overlaps: entries
                    .iter()
                    .filter(|o| o.is_glob && o.key != e.key && glob_match(o.key, e.key))
                    .filter_map(|o| {
                        let theirs = o.rule?; // an invalid glob decides nothing
                        let relation = match e.rule {
                            None => Relation::DecidesInstead,
                            Some(m) if m.allow == theirs.allow => Relation::Redundant,
                            Some(m)
                                if specificity(e.key, m.allow)
                                    > specificity(o.key, theirs.allow) =>
                            {
                                Relation::Overrides
                            }
                            Some(_) => Relation::OverriddenBy,
                        };
                        Some(Overlap {
                            key: o.key.to_string(),
                            verdict: o.verdict,
                            relation,
                        })
                    })
                    .collect(),
            })
            .collect()
    }

    /// Whether there are in-memory rule changes not yet written to disk.
    #[cfg(test)]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Write the rules to disk if there are unsaved changes (a no-op otherwise,
    /// so it's cheap to call unconditionally). Returns whether the on-disk file
    /// is now in sync — `true` if it wrote successfully or there was nothing to
    /// write, `false` if the write failed and changes are still pending.
    pub fn persist(&mut self) -> bool {
        self.persist_body(None)
    }

    /// The single write path: every route from memory to the rules file goes
    /// through here, so `loaded`/`dirty` — the record of what is actually on
    /// disk — cannot be reconciled in one place and forgotten in another.
    ///
    /// `body` is the rendered on-disk text when the caller already has one.
    /// Rendering clones the document, sorts `[rules]` and serialises it, so a
    /// snapshot — which needs the body anyway to measure and to send — hands its
    /// copy over rather than making this render an identical second one; `None`
    /// renders it here.
    fn persist_body(&mut self, body: Option<String>) -> bool {
        if !self.dirty {
            return true;
        }
        let Some(path) = self.path.clone() else {
            // Rules with no file (in-memory only): there is nothing to write, and
            // the change stays pending so no caller reads this as "it's on disk".
            return false;
        };
        let text = body.unwrap_or_else(|| self.body());
        // Atomic replace, not a truncate-and-write: this file is rewritten on
        // every unseen MIME type and shared mesh-wide, so a write interrupted by
        // a crash or a full disk would leave a half-file that peers then adopt.
        match crate::fsutil::write_atomic(&path, &text) {
            Ok(()) => {
                // Remember our own write so reload_if_changed treats it as
                // unchanged (no reload storm when the watcher sees this write).
                self.loaded = Some(text);
                self.dirty = false;
                true
            }
            // Leave `dirty` set so the next persist() retries rather than letting
            // in-memory rules silently diverge from disk.
            Err(e) => {
                warn!("couldn't write MIME rules to {}: {e:#}", path.display());
                false
            }
        }
    }

    /// Discard in-memory changes and restore the ruleset to the last content we
    /// read or wrote (`loaded`). Used to roll back a stamp bump or an adoption
    /// after a failed `persist`, so the in-memory rules never silently diverge
    /// from what's on disk (which would otherwise be lost on restart).
    /// A restore needs a baseline that parses, and there are two ways not to have
    /// one: nothing of ours has ever reached disk (`loaded` is None — the very
    /// first write failed, e.g. a read-only config dir), or the baseline somehow
    /// won't reparse (unreachable: `loaded` is only ever set from text that
    /// already parsed or that we rendered ourselves). Both keep the current
    /// document, so no path here can install an empty one: this is the *rollback*
    /// path, and an empty ruleset under the default `unknown_mime = deny` denies
    /// every type — the node goes on running and silently stops syncing anything
    /// until restart. What we hold is at worst the built-in template plus a stamp
    /// we failed to write, which beats nothing.
    fn revert_to_loaded(&mut self) {
        let restored = match self.loaded.as_deref().map(str::parse::<DocumentMut>) {
            Some(Ok(doc)) => Some(doc),
            Some(Err(e)) => {
                warn!("couldn't restore the last-good MIME rules ({e}); keeping the current ones");
                None
            }
            None => None,
        };
        // Only an actual restore makes memory match disk again. Without one the
        // change is still pending, so leave `dirty` set for the next persist to
        // retry rather than claiming a clean state that nothing on disk backs.
        if let Some(doc) = restored {
            self.doc = doc;
            self.dirty = false;
        }
    }

    /// The file's whole-file LWW version. Reads the managed `[clipmesh]` table if
    /// present; otherwise falls back to a baseline of (file mtime in ms, own_id)
    /// so enabling sharing converges on the most-recently-edited file. mtime is 0
    /// if unreadable or there is no path.
    pub fn version(&self, own_id: Uuid) -> Version {
        let cm = self.doc.get("clipmesh");
        // Reject a negative integer (e.g. a hand-edit typo): `as u64` would turn
        // it into a huge value that no peer could ever beat, isolating the node.
        let stamp = cm
            .and_then(|c| c.get("version"))
            .and_then(Item::as_integer)
            .filter(|s| *s >= 0);
        let origin = cm
            .and_then(|c| c.get("origin"))
            .and_then(Item::as_str)
            .and_then(|s| s.parse::<Uuid>().ok());
        match (stamp, origin) {
            (Some(s), Some(o)) => Version::new(s as u64, o),
            _ => Version::new(self.file_mtime_ms(), own_id),
        }
    }

    /// Whether the managed version is recorded in the file.
    fn has_version_header(&self) -> bool {
        self.doc
            .get("clipmesh")
            .and_then(|c| c.get("version"))
            .is_some()
    }

    /// Set (or replace) the managed version in the `[clipmesh]` table and mark
    /// dirty.
    fn set_version(&mut self, v: Version) {
        let cm = table_mut(&mut self.doc, "clipmesh");
        // TOML integers are i64; HLC stamps are wall-clock-ms bounded so they fit.
        cm["version"] = value(v.stamp as i64);
        cm["origin"] = value(v.origin.to_string());
        self.dirty = true;
    }

    /// Stamp `version`, persist, and return the durable result.
    ///
    /// The whole point is that a version is never announced before it is on
    /// disk: a stamp we kept but failed to write would outrank what peers
    /// actually have, then vanish on restart, leaving the mesh converged on a
    /// version nobody holds. Every failure path rolls the in-memory document
    /// back to what was last loaded.
    pub fn snapshot_at(&mut self, version: Version, max_len: usize) -> SnapshotResult {
        self.set_version(version);
        self.finish_snapshot(version, max_len)
    }

    /// The current version, materialised to disk if no `[clipmesh]` header had
    /// recorded one yet. Does NOT bump — this pins an existing baseline so it
    /// can be shared, rather than claiming a newer one.
    pub fn snapshot_baseline(&mut self, own_id: Uuid, max_len: usize) -> SnapshotResult {
        let version = self.version(own_id);
        if !self.has_version_header() {
            self.set_version(version);
        }
        self.finish_snapshot(version, max_len)
    }

    /// Shared tail: measure the real (post-stamp) body, reject it if oversized,
    /// persist it, and roll back on any failure.
    fn finish_snapshot(&mut self, version: Version, max_len: usize) -> SnapshotResult {
        let body = self.body();
        if body.len() > max_len {
            self.revert_to_loaded();
            return Err(SnapshotError::TooLarge { len: body.len() });
        }
        // The bytes need two owners: `loaded` (our record of what is on disk, so
        // the watcher doesn't read this write back as an external edit) and the
        // returned snapshot (moved onto the wire). One copy is therefore
        // irreducible while `Snapshot::body` is an owned `String` — but it is a
        // copy of an already-rendered body, not a second render of the document.
        if !self.persist_body(Some(body.clone())) {
            self.revert_to_loaded();
            return Err(SnapshotError::WriteFailed);
        }
        Ok(Snapshot { version, body })
    }

    /// The rules file's mtime in epoch-ms, or 0 if there is no path or it can't
    /// be read. Used as the version baseline before a version is recorded.
    fn file_mtime_ms(&self) -> u64 {
        let Some(path) = &self.path else {
            return 0;
        };
        fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Compile the `[rules]` table for repeated lookups: one pass over the TOML
    /// document instead of one per lookup. Use this whenever more than a couple
    /// of types are classified against the same ruleset (see
    /// [`CompiledRules`]).
    pub fn compile(&self) -> CompiledRules<'_> {
        let entries = self
            .rules_table()
            .map(|t| t.iter().map(CompiledEntry::new).collect())
            .unwrap_or_default();
        CompiledRules {
            entries,
            unknown: self.unknown,
        }
    }

    /// Whether a `size`-byte representation of `mime` may sync. Test-facing
    /// shim that compiles the table for one lookup; production classifies a
    /// whole offer against a single [`CompiledRules`].
    #[cfg(test)]
    pub fn allows(&self, mime: &str, size: usize) -> bool {
        self.compile().allows(mime, size)
    }

    fn rules_table(&self) -> Option<&Table> {
        self.doc.get("rules").and_then(Item::as_table)
    }

    fn rule_count(&self) -> usize {
        self.rules_table().map_or(0, Table::len)
    }
}

/// The `[rules]` table compiled once for repeated lookups.
///
/// `find_rule` otherwise re-walks the `toml_edit` document on *every* lookup,
/// re-deriving each entry's rule (including a string size-parse for capped
/// rules) and its specificity. The engine classifies every representation of
/// every copy against the same ruleset, and clipmesh auto-appends each unseen
/// type — so the table only ever grows, and the per-copy cost is
/// `reps × rules` document traversals.
///
/// This deliberately *borrows* the document rather than being a cache stored on
/// `MimeRules`. A stored cache would need manual invalidation at each of the
/// nine places that mutate the table, and missing one would silently apply
/// stale allow/deny decisions — a failure that is invisible in normal use and
/// fails open, letting denied content reach the wire. Borrowing makes that
/// unrepresentable: the compiler rejects any attempt to hold a compiled view
/// across a mutation, so recompiling after one is not a discipline but a
/// requirement.
pub struct CompiledRules<'a> {
    entries: Vec<CompiledEntry<'a>>,
    unknown: MimePolicy,
}

struct CompiledEntry<'a> {
    key: &'a str,
    /// `None` when the value isn't a usable `allow`/`deny` rule. The entry is
    /// still kept: `any_match` must treat even a typo'd key as covering its
    /// type, so `ensure` doesn't append a duplicate alongside it.
    rule: Option<MimeRule>,
    /// `specificity`'s components, precomputed (both are O(key length) scans).
    literals: usize,
    wildcards: usize,
}

impl<'a> CompiledEntry<'a> {
    fn new((key, item): (&'a str, &Item)) -> Self {
        let (literals, wildcards) = key_weights(key);
        CompiledEntry {
            key,
            rule: parse_rule_item(item),
            literals,
            wildcards,
        }
    }

    fn specificity(&self, allow: bool) -> Specificity<'a> {
        specificity_of(self.key, self.literals, self.wildcards, allow)
    }
}

impl CompiledRules<'_> {
    /// Whether a `size`-byte representation of `mime` may sync.
    pub fn allows(&self, mime: &str, size: usize) -> bool {
        match self.find_rule(mime) {
            Some(r) => r.allow && r.max_size.map_or(true, |max| size <= max),
            None => self.unknown == MimePolicy::Allow,
        }
    }

    /// The rule that decides `mime`: among all keys that match it (exact or
    /// glob, case-insensitive), the most specific one wins — see
    /// [`specificity`]. An exact key, having the most literal characters and no
    /// wildcards, always beats a glob.
    fn find_rule(&self, mime: &str) -> Option<MimeRule> {
        let mut best: Option<(Specificity<'_>, MimeRule)> = None;
        // Set once an exact key has decided this type. From there no glob can
        // win: a glob matching the same text can never carry *more* literals
        // than the text has characters, which is what an exact key carries, and
        // it carries at least one wildcard to lose the next component on — so
        // every remaining glob is skipped without running the backtracking
        // matcher against it. This file appends every unseen type, so the table
        // walked here per representation only ever grows.
        //
        // Not a bare early return, deliberately: an exact key can still be tied
        // by *another* exact key that differs only in case (`TEXT/PLAIN` beside
        // `text/plain` — both match, neither is more specific), and returning
        // the first one found would decide that by table order instead of by the
        // documented deny-then-lexicographic tie-break.
        let mut decided_exactly = false;
        for entry in &self.entries {
            let is_exact = entry.wildcards == 0;
            if decided_exactly && !is_exact {
                continue;
            }
            let Some(rule) = entry.rule else { continue };
            if !glob_match(entry.key, mime) {
                continue;
            }
            let spec = entry.specificity(rule.allow);
            if best.as_ref().map_or(true, |(b, _)| spec > *b) {
                best = Some((spec, rule));
            }
            decided_exactly |= is_exact;
        }
        best.map(|(_, r)| r)
    }

    /// Whether any key matches `mime`, valid rule or not (see
    /// [`CompiledEntry::rule`]).
    pub fn any_match(&self, mime: &str) -> bool {
        self.entries.iter().any(|e| glob_match(e.key, mime))
    }

    /// Whether any of `mimes` is matched by no key (and so would be recorded by
    /// `ensure`). Lets the caller skip touching disk when nothing is new.
    pub fn has_unseen<'m>(&self, mimes: impl IntoIterator<Item = &'m String>) -> bool {
        mimes.into_iter().any(|m| !self.any_match(m))
    }
}

/// Get a mutable handle to a top-level table, creating it (as an explicit table)
/// if absent or if the key currently holds something else.
fn table_mut<'a>(doc: &'a mut DocumentMut, name: &str) -> &'a mut Table {
    let item = &mut doc[name];
    if !item.is_table() {
        *item = Item::Table(Table::new());
    }
    item.as_table_mut().expect("just ensured it's a table")
}

/// Case-insensitive glob match of `pattern` against `text`: `*` matches any run
/// (including empty), `?` matches exactly one character, everything else is a
/// literal. A pattern with no wildcards is therefore an exact (case-insensitive)
/// match. `*` and `?` are always wildcards — there is no escape, so a key whose
/// literal text contains `*`/`?` can't be matched verbatim (MIME types never do).
/// Case folding is ASCII-only (MIME types are ASCII), so non-ASCII bytes compare
/// case-sensitively — which is also why matching runs over bytes rather than
/// chars: nothing above ASCII is folded, so decoding UTF-8 would buy nothing and
/// cost an allocation per call. (`?` therefore consumes one byte, which is one
/// character for the ASCII this file deals in.)
fn glob_match(pattern: &str, text: &str) -> bool {
    // Fast path: a wildcard-free pattern (every exact key) is just a
    // case-insensitive compare. This is the hot path, since `find_rule`/
    // `any_match` run it against every rule key per type.
    if !has_wildcard(pattern) {
        return pattern.eq_ignore_ascii_case(text);
    }
    // Byte slices, not `Vec<char>`: the wildcard path used to collect both sides
    // onto the heap on every call, re-collecting the same MIME text once per
    // wildcard rule in the table.
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0usize, 0usize);
    // Last '*' we passed and the text position to retry from, for backtracking.
    let (mut star, mut star_ti): (Option<usize>, usize) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi].eq_ignore_ascii_case(&t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(s) = star {
            // Mismatch after a '*': let the '*' swallow one more byte and retry.
            pi = s + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    // Trailing '*'s match the empty remainder.
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// A rule's precedence when several match a type. Compared as a tuple, *larger
/// wins*: more literal characters first (an exact key beats a glob), then fewer
/// wildcards, then `deny` over `allow`, then the lexicographically smaller key
/// (a stable, arbitrary final tie-break so the result is deterministic). The key
/// is borrowed (`&str`), so building a `Specificity` per lookup never allocates.
type Specificity<'a> = (usize, Reverse<usize>, bool, Reverse<&'a str>);

/// Whether `key` is a glob rather than an exact key. The one definition of what
/// makes a key a pattern, so "is this a glob?" cannot be answered one way where
/// matching short-circuits and another way where the report decides which keys
/// can overlap.
fn has_wildcard(key: &str) -> bool {
    key.bytes().any(|b| b == b'*' || b == b'?')
}

/// A key's `(literals, wildcards)` counts — the two O(key length) scans that
/// [`specificity_of`] orders by. Split out so a compiled ruleset can precompute
/// them once per key instead of per lookup.
fn key_weights(key: &str) -> (usize, usize) {
    let wildcards = key.bytes().filter(|&b| b == b'*' || b == b'?').count();
    (key.chars().count() - wildcards, wildcards)
}

/// Assemble the ordering key from a key's weights. THE single definition of
/// "most specific wins" — `rules_report` and the rule actually applied both come
/// through here, so the report can't disagree with enforcement.
fn specificity_of(key: &str, literals: usize, wildcards: usize, allow: bool) -> Specificity<'_> {
    (literals, Reverse(wildcards), !allow, Reverse(key))
}

fn specificity(key: &str, allow: bool) -> Specificity<'_> {
    let (literals, wildcards) = key_weights(key);
    specificity_of(key, literals, wildcards, allow)
}

/// A `Key` for `k` that always renders quoted, even when `k` is a valid bare key
/// (so `STRING`/`TEXT`/... are written as `"STRING"`/`"TEXT"`, consistent with
/// the punctuated keys). We render `k` as a TOML string value — always quoted and
/// correctly escaped — and parse that back as the key's representation, then drop
/// the parser's decor so the table still applies its own newline/indent between
/// entries. Falls back to a default (possibly bare) key if that ever fails, which
/// it won't for the strings `Value` produces.
fn quoted_key(k: &str) -> Key {
    let mut key = match Key::parse(&quoted_key_repr(k)) {
        Ok(mut keys) if keys.len() == 1 => keys.remove(0),
        _ => return Key::new(k),
    };
    *key.leaf_decor_mut() = Decor::default();
    *key.dotted_decor_mut() = Decor::default();
    key
}

/// `k` rendered as a quoted TOML key string (e.g. `"image/png"`). A TOML string
/// value uses the same quoting/escaping as a quoted key, so we borrow its
/// encoder.
fn quoted_key_repr(k: &str) -> String {
    Value::from(k).to_string().trim().to_string()
}

/// Classify a `[rules]` value for the report: the rule it parses to (`None` when
/// the value isn't a usable one), the verdict that follows, and the size cap as
/// written (only when the cap is a usable size).
///
/// The rule and the verdict come back together because they are one parse — the
/// report needs both, and deriving them separately is how a report starts
/// disagreeing with the rule actually enforced. A bad cap doesn't make the
/// verdict invalid: `parse_rule` decides validity from the rule word alone and
/// `usable_cap` drops the cap, so both fall out of the single parse below.
fn describe_value(item: &Item) -> (Option<MimeRule>, Verdict, Option<&str>) {
    let Some((rule, max)) = rule_fields(item) else {
        return (None, Verdict::Invalid, None);
    };
    // Defers to the definitions the enforced rule itself comes from.
    let parsed = parse_rule(rule, max);
    let verdict = match parsed {
        Some(r) if r.allow => Verdict::Allow,
        Some(_) => Verdict::Deny,
        None => Verdict::Invalid,
    };
    // Echo the cap as the user wrote it, but only when it's one that survives.
    (
        parsed,
        verdict,
        max.filter(|s| usable_cap(Some(s)).is_some()),
    )
}

/// Render one `[rules]` entry as a clean, copy-pasteable `"key" = value` line
/// (no surrounding comments or blank lines), for the `--allow`/`--deny` CLI to
/// echo the entries it removed.
fn render_entry(key: &str, item: &Item) -> String {
    let mut item = item.clone();
    // A rule hand-written as a `[rules."x"]` block is an `Item::Table`, which
    // renders to nothing when dropped into a single-key table — convert it to
    // the inline `{ rule = ..., max = ... }` form so the echoed line isn't blank.
    if let Item::Table(t) = item {
        item = Item::Value(Value::InlineTable(t.into_inline_table()));
    }
    let mut table = Table::new();
    insert_canonical(&mut table, key, item);
    table.to_string().trim().to_string()
}

/// Insert `item` under a quoted `key` with the canonical entry layout: one space
/// before the value, no trailing inline comment, and every key quoted (even
/// bare-valid ones like `STRING`) for a consistent file.
///
/// The single definition of how a `[rules]` entry is rendered. `normalize`
/// (what gets saved) and `render_entry` (what `--allow`/`--deny` echoes back)
/// both go through it, so the echoed line cannot drift from the written one.
fn insert_canonical(table: &mut Table, key: &str, mut item: Item) {
    if let Some(val) = item.as_value_mut() {
        val.decor_mut().set_prefix(" ");
        val.decor_mut().set_suffix("");
    }
    table.insert_formatted(&quoted_key(key), item);
}

/// Normalise the `[rules]` table for writing: sort entries by MIME key and drop
/// any comments interleaved among them. Everything above `[rules]` (the header
/// comments and the `[clipmesh]` table) is left untouched.
fn normalize(doc: &mut DocumentMut) {
    let Some(rules) = doc.get_mut("rules").and_then(Item::as_table_mut) else {
        return;
    };
    let mut entries: Vec<(String, Item)> = rules
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    rules.clear();
    for (k, v) in entries {
        insert_canonical(rules, &k, v);
    }
}

/// The rules-file word for an allow/deny decision. One definition, so the
/// literals that go into the file and the ones reported to the user can't drift.
pub fn rule_word(allow: bool) -> &'static str {
    if allow {
        "allow"
    } else {
        "deny"
    }
}

/// Extract the `(rule, max)` strings from a `[rules]` value: a `"allow"`/`"deny"`
/// string, or a `{ rule = "...", max = "..." }` (inline or regular) table.
/// Returns None if the value isn't a recognizable rule shape.
fn rule_fields(item: &Item) -> Option<(&str, Option<&str>)> {
    if let Some(s) = item.as_str() {
        return Some((s, None));
    }
    // `TableLike` covers both table flavours, so the two shapes share one
    // extraction and a new rule key is a single edit.
    let t = item.as_table_like()?;
    let rule = t.get("rule")?.as_str()?;
    Some((rule, t.get("max").and_then(Item::as_str)))
}

/// Interpret a `[rules]` value as a rule. Returns None for anything that isn't a
/// usable `allow`/`deny` rule.
fn parse_rule_item(item: &Item) -> Option<MimeRule> {
    let (rule, max) = rule_fields(item)?;
    parse_rule(rule, max)
}

fn parse_rule(rule: &str, max: Option<&str>) -> Option<MimeRule> {
    let allow = match rule {
        "allow" => true,
        "deny" => false,
        _ => return None,
    };
    Some(MimeRule {
        allow,
        max_size: usable_cap(max),
    })
}

/// A per-type size cap as a byte count, or `None` when there is none to honour.
/// A bad or zero-byte cap is dropped (the rule still applies); a 0-byte cap
/// would make `allow` behave as `deny` since nothing is `<= 0`.
fn usable_cap(max: Option<&str>) -> Option<usize> {
    match parse_size(max?) {
        Ok(0) | Err(_) => None,
        Ok(v) => Some(v),
    }
}

/// Warn (once, at load/reload) about `[rules]` entries that aren't usable, so a
/// typo doesn't silently do nothing.
fn warn_invalid_rules(doc: &DocumentMut, path: &Path) {
    let Some(rules) = doc.get("rules").and_then(Item::as_table) else {
        return;
    };
    for (mime, item) in rules.iter() {
        // Both guards ask the definitions that decide the rule actually applied,
        // rather than restating them — a warning that disagrees with enforcement
        // is worse than none, since it sends the user to fix a working entry (or
        // stays silent on a broken one).
        match rule_fields(item) {
            None => warn!(
                "MIME rules: ignoring {mime:?} in {} — value must be \"allow\"/\"deny\" or {{ rule = ..., max = ... }}",
                path.display()
            ),
            // Asked with no cap: a bad cap doesn't make the rule word invalid,
            // and is reported on its own below.
            Some((rule, _)) if parse_rule(rule, None).is_none() => warn!(
                "MIME rules: ignoring {mime:?} in {} — rule must be \"allow\" or \"deny\", got {rule:?}",
                path.display()
            ),
            Some((_, Some(max))) if usable_cap(Some(max)).is_none() => warn!(
                "MIME rules: ignoring the max-size {max:?} on {mime:?} in {} (the rule still applies)",
                path.display()
            ),
            Some(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    #[test]
    fn a_broken_rules_symlink_materializes_the_skeleton_at_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real-mimetypes"); // does not exist yet
        let link = dir.path().join("mimetypes");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let rules = MimeRules::load(Some(link.clone()), MimePolicy::Deny);
        // A type the skeleton says nothing about still falls to the
        // deny-by-default policy...
        assert!(!rules.allows("application/x-never-seen", 1));
        // ...and the fresh skeleton is written through the (previously broken)
        // symlink, creating the target.
        assert!(
            target.exists(),
            "a fresh skeleton should be materialized at the symlink target"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), render_example());
    }

    fn write(path: &Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
    }

    /// A `MimeRules` loaded from a temp file holding `body`, with the file's
    /// path. The returned `TempDir` must stay alive for the test's duration —
    /// bind it, don't drop it.
    fn loaded_at(body: &str, unknown: MimePolicy) -> (tempfile::TempDir, PathBuf, MimeRules) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        write(&path, body);
        let rules = MimeRules::load(Some(path.clone()), unknown);
        (dir, path, rules)
    }

    /// `loaded_at` for the tests that never touch the file again.
    fn loaded(body: &str, unknown: MimePolicy) -> (tempfile::TempDir, MimeRules) {
        let (dir, _path, rules) = loaded_at(body, unknown);
        (dir, rules)
    }

    /// One question put to a ruleset — a type and a size — with the answer it
    /// must give and the precedence rule that answer pins.
    type Decision<'a> = (&'a str, usize, bool, &'a str);

    /// A `[rules]` body, the unknown-type policy it loads under, and every
    /// decision that pair fixes.
    type AllowCase<'a> = (&'a str, MimePolicy, &'a [Decision<'a>]);

    /// Whether a representation may sync is a pure decision over (rules table,
    /// unknown-type policy, MIME type, size): no file state, no ordering, no
    /// engine. So the cases belong in one table, where a new precedence rule is
    /// a row instead of another copy of the same load-and-assert scaffolding.
    /// The per-row and per-case notes are the substance — each one is a
    /// precedence rule the module docs promise a user.
    #[test]
    fn allows_decides_by_rule_size_cap_and_specificity() {
        let cases: &[AllowCase<'_>] = &[
            // A cap bounds an allow, and only that entry.
            (
                "[rules]\n\"image/png\" = { rule = \"allow\", max = \"100B\" }\n\"image/bmp\" = \"deny\"\n",
                MimePolicy::Deny,
                &[
                    ("image/png", 100, true, "exactly at the cap"),
                    ("image/png", 101, false, "over the cap"),
                    ("image/bmp", 1, false, "denied outright"),
                    ("text/plain", 1, false, "no rule -> the deny policy"),
                ],
            ),
            // A 0-byte cap would turn `allow` into `deny` (nothing is <= 0), so
            // it is dropped rather than honoured.
            (
                "[rules]\n\"image/png\" = { rule = \"allow\", max = \"0B\" }\n",
                MimePolicy::Deny,
                &[
                    ("image/png", 1, true, "a zero cap is ignored, not enforced"),
                    ("image/png", 10_000, true, "at any size"),
                ],
            ),
            // A cap only narrows an allow; it can't soften a deny.
            (
                "[rules]\n\"image/png\" = { rule = \"deny\", max = \"100B\" }\n",
                MimePolicy::Deny,
                &[
                    ("image/png", 1, false, "under the cap, still denied"),
                    ("image/png", 50, false, "size is irrelevant to a deny"),
                ],
            ),
            // A typo in the cap drops the cap, not the rule — it must not
            // quietly stop a type from syncing.
            (
                "[rules]\n\"image/png\" = { rule = \"allow\", max = \"notasize\" }\n",
                MimePolicy::Deny,
                &[("image/png", 999_999, true, "the allow survives a bad cap")],
            ),
            // Globs fold case on both sides (MIME types are ASCII).
            (
                "[rules]\n\"JAVA_DATATRANSFER*\" = \"deny\"\n\"*;charset=utf-16BE\" = \"deny\"\n",
                MimePolicy::Allow,
                &[
                    (
                        "JAVA_DATATRANSFER_COOKIE_9147594d",
                        1,
                        false,
                        "a trailing * covers the whole family",
                    ),
                    (
                        "text/plain;charset=utf-16be",
                        1,
                        false,
                        "the pattern's case differs from the type's",
                    ),
                    ("text/plain", 1, true, "no glob matches -> the allow policy"),
                ],
            ),
            // An exact key carves an exception out of a glob's family: it has
            // the most literals and no wildcards, so it always wins.
            (
                "[rules]\n\"*;charset=utf-16*\" = \"deny\"\n\"text/uri-list;charset=utf-16\" = \"allow\"\n",
                MimePolicy::Deny,
                &[
                    (
                        "text/uri-list;charset=utf-16",
                        1,
                        true,
                        "the exact key beats the glob",
                    ),
                    ("text/plain;charset=utf-16le", 1, false, "only the glob matches"),
                ],
            ),
            // Between two globs, more literal characters wins.
            (
                "[rules]\n\"text/plain*\" = \"deny\"\n\"*plain*\" = \"allow\"\n",
                MimePolicy::Deny,
                &[
                    (
                        "text/plain;charset=utf-8",
                        1,
                        false,
                        "text/plain* (10 literals) beats *plain* (5)",
                    ),
                    ("application/plain-text", 1, true, "only *plain* matches"),
                ],
            ),
            // A genuine tie breaks to deny — the safe direction, since this
            // decision is what lets content leave the host.
            (
                "[rules]\n\"a/x*\" = \"allow\"\n\"a/*y\" = \"deny\"\n",
                MimePolicy::Allow,
                &[("a/xy", 1, false, "3 literals and 1 wildcard each -> deny wins")],
            ),
            // Two exact keys for one type, differing only in case, tie the same
            // way. This is the case that stops `find_rule` from returning the
            // first exact match it finds: doing so would answer by table order
            // rather than by the tie-break.
            (
                "[rules]\n\"TEXT/PLAIN\" = \"allow\"\n\"text/plain\" = \"deny\"\n",
                MimePolicy::Allow,
                &[(
                    "text/plain",
                    1,
                    false,
                    "neither case-variant is more specific -> deny wins",
                )],
            ),
        ];
        for &(body, unknown, expected) in cases {
            let (_dir, rules) = loaded(body, unknown);
            for &(mime, size, may_sync, why) in expected {
                assert_eq!(
                    rules.allows(mime, size),
                    may_sync,
                    "{why}: {mime} ({size} bytes) under\n{body}"
                );
            }
        }
    }

    #[test]
    fn mime_keys_with_spaces_and_punctuation_parse() {
        let java = "JAVA_DATAFLAVOR:application/x-java-serialized-object; \
                    class=com.intellij.openapi.editor.impl.EditorCopyPasteHelperImpl$CopyPasteOptionsTransferableData";
        let (_dir, rules) = loaded(
            &format!("[rules]\n\"{java}\" = \"deny\"\n\"text/plain;charset=utf-8\" = \"allow\"\n"),
            MimePolicy::Allow,
        );
        assert!(
            !rules.allows(java, 1),
            "spaced/punctuated MIME key must parse"
        );
        assert!(rules.allows("text/plain;charset=utf-8", 1));
        assert!(!rules.has_unseen([&s(java)]), "the key is recognised");
    }

    #[test]
    fn unknown_allow_policy_permits_unseen_types() {
        let rules = MimeRules::load(None, MimePolicy::Allow);
        assert!(rules.allows("anything/new", 999));
    }

    #[test]
    fn an_invalid_rule_value_is_ignored_and_kept() {
        let (_dir, path, rules) = loaded_at(
            "[rules]\n\"image/png\" = \"allwo\"\n\"text/plain\" = \"deny\"\n",
            MimePolicy::Allow,
        );
        // the typo'd entry falls back to the unknown policy (allow here)...
        assert!(rules.allows("image/png", 1));
        assert!(!rules.allows("text/plain", 1));
        // ...and the entry is kept in the file (not dropped).
        assert!(std::fs::read_to_string(&path).unwrap().contains("allwo"));
    }

    #[test]
    fn save_sorts_rules_strips_inner_comments_and_keeps_the_header() {
        let (_dir, path, mut rules) = loaded_at(
            "# my notes\n[rules]\n# inner note\n\"text/plain\" = \"deny\"\n\"image/png\" = \"allow\"  # keep this\n",
            MimePolicy::Deny,
        );
        assert!(rules.allows("image/png", 1));
        assert!(!rules.allows("text/plain", 1));
        assert!(rules.ensure([&s("image/gif")]));
        rules.persist();
        let body = std::fs::read_to_string(&path).unwrap();
        // Comments above [rules] are kept.
        assert!(body.contains("# my notes"), "header comment lost:\n{body}");
        // Comments interleaved among the rules are dropped.
        assert!(
            !body.contains("# inner note"),
            "inner comment kept:\n{body}"
        );
        assert!(
            !body.contains("# keep this"),
            "inline comment kept:\n{body}"
        );
        // The new type is present and entries are sorted by key.
        assert!(
            body.contains("\"image/gif\" = \"deny\""),
            "new type missing:\n{body}"
        );
        let (gif, png, txt) = (
            body.find("\"image/gif\"").unwrap(),
            body.find("\"image/png\"").unwrap(),
            body.find("\"text/plain\"").unwrap(),
        );
        assert!(gif < png && png < txt, "rules not sorted:\n{body}");
        assert!(!rules.ensure([&s("image/gif")])); // already present
    }

    #[test]
    fn creates_the_file_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        assert!(!path.exists());
        let _rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert!(path.exists(), "load should create the rules file");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("[rules]"), "skeleton not written:\n{body}");
    }

    #[test]
    fn an_old_line_format_file_is_replaced_with_a_fresh_skeleton() {
        // Old format isn't valid TOML.
        let (_dir, path, _rules) =
            loaded_at("image/png allow\ntext/plain deny\n", MimePolicy::Deny);
        // It's overwritten with a fresh TOML skeleton (no backup is kept).
        assert!(std::fs::read_to_string(&path).unwrap().contains("[rules]"));
        assert!(
            !path.with_extension("bak").exists(),
            "no backup should be made"
        );
    }

    #[test]
    fn load_does_not_overwrite_the_file_on_a_non_notfound_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        // A directory at the path makes read_to_string fail with a non-NotFound
        // error; load must NOT clobber it.
        std::fs::create_dir(&path).unwrap();
        let _rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert!(
            path.is_dir(),
            "load overwrote a path it merely failed to read"
        );
    }

    /// `open` is what the one-shot CLI commands use, and its whole job is to
    /// report instead of heal: the rewrite `load` would do here also drops the
    /// `[clipmesh]` table, i.e. this node's place in the mesh's rules version
    /// ordering, over what may be a single typo.
    #[test]
    fn open_reports_a_bad_file_and_leaves_every_byte_of_it_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        let body = "[clipmesh]\nversion = 42\nthis is = = not toml\n";
        write(&path, body);
        let err = MimeRules::open(Some(path.clone()), MimePolicy::Deny)
            .err()
            .expect("invalid TOML must be reported, not repaired");
        assert!(matches!(err, RulesFileState::Malformed(_)), "{err:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), body);

        // The same file through `load`, the healing constructor, IS rewritten —
        // the two constructors are the choice this test exists to keep visible.
        let _rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), render_example());
    }

    #[test]
    fn open_reports_an_absent_or_empty_file_without_creating_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        let missing = MimeRules::open(Some(path.clone()), MimePolicy::Deny)
            .err()
            .expect("a missing file must be reported");
        assert!(matches!(missing, RulesFileState::Missing), "{missing:?}");
        assert!(!path.exists(), "open must not create the rules file");

        write(&path, "  \n\t\n");
        let empty = MimeRules::open(Some(path.clone()), MimePolicy::Deny)
            .err()
            .expect("a whitespace-only file must be reported");
        assert!(matches!(empty, RulesFileState::Empty), "{empty:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "  \n\t\n");
    }

    #[test]
    fn empty_existing_file_gets_the_skeleton() {
        let (_dir, path, _rules) = loaded_at("", MimePolicy::Deny);
        assert!(std::fs::read_to_string(&path).unwrap().contains("[rules]"));
    }

    #[test]
    fn reload_if_changed_rereads_after_an_edit() {
        let (_dir, path, mut rules) =
            loaded_at("[rules]\n\"image/png\" = \"deny\"\n", MimePolicy::Deny);
        assert!(!rules.allows("image/png", 1));
        write(&path, "[rules]\n\"image/png\" = \"allow\"\n");
        assert!(rules.reload_if_changed());
        assert!(rules.allows("image/png", 1));
    }

    #[test]
    fn reload_keeps_rules_when_the_file_transiently_disappears() {
        let (_dir, path, mut rules) =
            loaded_at("[rules]\n\"image/png\" = \"allow\"\n", MimePolicy::Deny);
        assert!(rules.allows("image/png", 1));
        std::fs::remove_file(&path).unwrap();
        assert!(!rules.reload_if_changed());
        assert!(rules.allows("image/png", 1));
    }

    #[test]
    fn reload_ignores_an_empty_read_and_keeps_rules() {
        let (_dir, path, mut rules) =
            loaded_at("[rules]\n\"image/png\" = \"allow\"\n", MimePolicy::Deny);
        assert!(rules.allows("image/png", 1));
        write(&path, ""); // transient empty mid-save
        assert!(!rules.reload_if_changed(), "empty read must be no-change");
        assert!(
            rules.allows("image/png", 1),
            "rules must survive an empty read"
        );
        write(&path, "[rules]\n\"image/png\" = \"deny\"\n");
        assert!(rules.reload_if_changed());
        assert!(!rules.allows("image/png", 1));
    }

    #[test]
    fn reload_keeps_rules_when_the_new_content_is_not_toml() {
        let (_dir, path, mut rules) =
            loaded_at("[rules]\n\"image/png\" = \"allow\"\n", MimePolicy::Deny);
        write(&path, "this is = = not toml");
        assert!(
            !rules.reload_if_changed(),
            "invalid TOML must not be applied"
        );
        assert!(rules.allows("image/png", 1));
        // A subsequent valid edit must still be picked up (loaded not poisoned).
        write(&path, "[rules]\n\"image/png\" = \"deny\"\n");
        assert!(rules.reload_if_changed(), "valid fix must be applied");
        assert!(!rules.allows("image/png", 1));
    }

    #[test]
    fn example_mimetypes_matches_template() {
        crate::fsutil::assert_matches_generated_example(
            "examples/mimetypes",
            &render_example(),
            "example_mimetypes_matches_template",
        );
    }

    #[test]
    fn a_fresh_rules_file_is_written_exactly_as_the_example() {
        // The example is only meaningful as a default if it is what clipmesh
        // actually creates. Materialize a fresh file and compare the bytes.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        let _rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), render_example());
    }

    #[test]
    fn the_shipped_defaults_cover_the_unbounded_growth_cases() {
        // These globs are the reason the defaults live in the skeleton rather
        // than only in the example: without them a per-transfer atom name is
        // recorded on every copy and the file grows without bound.
        let (_dir, mut rules) = loaded(&render_example(), MimePolicy::Deny);
        for mime in [
            "JAVA_DATATRANSFER_COOKIE_f9e96042",
            "JAVA_DATATRANSFER_COOKIE_0000abcd",
            "text/plain;charset=utf-16le",
            "x-special/gnome-copied-files",
        ] {
            assert!(!rules.allows(mime, 1), "{mime} should be denied by default");
            assert!(
                !rules.ensure([&mime.to_string()]),
                "{mime} is covered by a glob, so it must not be appended"
            );
        }
        // and the everyday types do sync out of the box
        for mime in ["text/plain", "text/plain;charset=utf-8", "image/png"] {
            assert!(rules.allows(mime, 1), "{mime} should be allowed by default");
        }
    }

    #[test]
    fn ensure_does_not_duplicate_a_type_already_present_as_an_invalid_value() {
        let (_dir, mut rules) = loaded("[rules]\n\"image/png\" = \"allwo\"\n", MimePolicy::Deny);
        assert!(!rules.ensure([&s("image/png")]), "ensure duplicated a type");
    }

    #[test]
    fn a_rules_write_replaces_the_file_atomically_through_a_symlink() {
        // The rules file is rewritten on every unseen MIME type and shared
        // mesh-wide, so it goes through fsutil::write_atomic: the live file is
        // only ever replaced by a completed rename (no truncate-and-write window
        // a crash could leave behind), a stow-managed symlink keeps pointing at
        // its target instead of being replaced by a regular file, and the temp
        // does not survive the write.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("dotfiles-mimetypes");
        write(&target, "[rules]\n\"image/png\" = \"allow\"\n");
        let link = dir.path().join("mimetypes");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let mut rules = MimeRules::load(Some(link.clone()), MimePolicy::Deny);
        assert!(rules.ensure([&s("text/plain")]));
        assert!(rules.persist());

        assert!(
            crate::fsutil::is_symlink(&link),
            "the symlink was replaced by a regular file"
        );
        let body = std::fs::read_to_string(&target).unwrap();
        assert!(body.contains("\"text/plain\""), "write missed:\n{body}");
        assert!(body.contains("\"image/png\""), "write lost a rule:\n{body}");
        let temps = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!temps, "the write left its temp file behind");
        // Our own write is still recognised as ours, so it can't ping a reload.
        assert!(!rules.reload_if_changed());
    }

    #[test]
    fn a_failed_write_leaves_the_changes_pending() {
        // A directory at the rules path makes every write fail. persist() must
        // report not-in-sync and keep `dirty` set so the next attempt retries,
        // rather than letting the in-memory rules silently diverge from disk.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::create_dir(&path).unwrap();
        let mut rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert!(rules.ensure([&s("text/plain")]));
        assert!(!rules.persist(), "a failed write must report not-in-sync");
        assert!(rules.is_dirty(), "the change must stay pending");
        assert!(path.is_dir(), "the unwritable path must be untouched");
    }

    #[test]
    fn a_rollback_with_nothing_on_disk_keeps_the_ruleset() {
        // A path inside a directory that doesn't exist: the bootstrap write in
        // `materialize_fresh` fails, so the built-in template is live in memory
        // while `loaded` is still None. A later snapshot fails to persist too and
        // rolls back — which must not leave an EMPTY ruleset behind, because under
        // `unknown_mime = deny` that silently denies every type until restart.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent").join("mimetypes");
        let mut rules = MimeRules::load(Some(path), MimePolicy::Deny);
        assert!(
            rules.allows("text/plain", 10),
            "the built-in template's rules must be live"
        );

        let snapshot = rules.snapshot_baseline(Uuid::from_u128(1), 1 << 20);
        assert!(matches!(snapshot, Err(SnapshotError::WriteFailed)));

        assert!(
            rules.allows("text/plain", 10),
            "the rollback wiped the ruleset; every type is now denied until restart"
        );
        assert!(rules.is_dirty(), "the unwritten change must stay pending");
    }

    #[test]
    fn persist_only_writes_when_dirty() {
        let (_dir, mut rules) = loaded("[rules]\n\"image/png\" = \"allow\"\n", MimePolicy::Deny);
        assert!(!rules.is_dirty());
        assert!(rules.ensure([&s("text/plain")]));
        assert!(rules.is_dirty());
        assert!(rules.persist());
        assert!(!rules.is_dirty());
    }

    #[test]
    fn has_unseen_reports_types_without_a_rule() {
        let (_dir, rules) = loaded("[rules]\n\"image/png\" = \"allow\"\n", MimePolicy::Deny);
        assert!(!rules.has_unseen([&s("image/png")]));
        assert!(rules.has_unseen([&s("text/plain")]));
    }

    /// A compiled view must reflect the table it was built from, and a rule
    /// change must be visible once recompiled. The borrow checker already makes
    /// it impossible to hold a view across the mutation, so this pins the other
    /// half: that recompiling actually picks the change up rather than
    /// reproducing a stale decision.
    /// The invariant the whole transaction exists for: a version is never left
    /// in memory unless it reached disk. Announcing one that didn't would
    /// outrank what peers actually hold, then vanish on restart.
    #[test]
    fn a_snapshot_that_cannot_persist_rolls_the_version_back() {
        let (_dir, mut rules) = loaded("[rules]\n\"image/png\" = \"allow\"\n", MimePolicy::Deny);
        let own = Uuid::from_u128(9);
        let before = rules.version(own);

        // Way under any sane file, so the body is rejected before the write.
        let err = rules
            .snapshot_at(Version::new(9_999, own), 1)
            .expect_err("a 1-byte limit must reject the body");
        assert!(matches!(err, SnapshotError::TooLarge { .. }), "{err:?}");
        assert_eq!(
            rules.version(own),
            before,
            "a rejected snapshot must not leave its version behind"
        );

        // With room, the same call succeeds and the version sticks.
        let s = rules
            .snapshot_at(Version::new(9_999, own), usize::MAX)
            .expect("should persist");
        assert_eq!(s.version.stamp, 9_999);
        assert_eq!(rules.version(own), s.version);
        assert!(
            s.body.contains("9999"),
            "the returned body must carry the version it announces: {}",
            s.body
        );
    }

    /// `snapshot_baseline` pins an existing version rather than claiming a new
    /// one — it is used to share what we already have, not to win a race.
    #[test]
    fn snapshot_baseline_does_not_bump_the_version() {
        let origin = Uuid::from_u128(3);
        let (_dir, mut rules) = loaded(
            &format!("[clipmesh]\nversion = 42\norigin = \"{origin}\"\n\n[rules]\n"),
            MimePolicy::Deny,
        );
        let s = rules
            .snapshot_baseline(Uuid::from_u128(99), usize::MAX)
            .expect("should persist");
        assert_eq!(s.version, Version::new(42, origin), "kept, not bumped");
    }

    #[test]
    fn recompiling_after_a_rule_change_sees_the_new_verdict() {
        let (_dir, mut rules) = loaded("[rules]\n\"image/png\" = \"allow\"\n", MimePolicy::Deny);
        assert!(rules.compile().allows("image/png", 1));

        rules.set_rule("image/png", false);
        assert!(
            !rules.compile().allows("image/png", 1),
            "a recompiled view must see the flipped rule"
        );

        // A key whose value is not a usable rule still counts as covering its
        // type, so `ensure` won't append a duplicate beside it.
        rules.set_rule("image/gif", true);
        let compiled = rules.compile();
        assert!(compiled.any_match("image/gif"));
        assert!(!compiled.has_unseen([&s("image/gif")]));
        assert!(compiled.has_unseen([&s("image/tiff")]));
    }

    #[test]
    fn version_reads_the_clipmesh_table() {
        let origin = Uuid::from_u128(7);
        let (_dir, rules) = loaded(
            &format!("[clipmesh]\nversion = 1234\norigin = \"{origin}\"\n[rules]\n\"image/png\" = \"allow\"\n"),
            MimePolicy::Deny,
        );
        assert_eq!(rules.version(Uuid::nil()), Version::new(1234, origin));
        assert!(rules.has_version_header());
    }

    #[test]
    fn version_falls_back_to_mtime_baseline_without_a_clipmesh_table() {
        let (_dir, rules) = loaded("[rules]\n\"image/png\" = \"allow\"\n", MimePolicy::Deny);
        let own = Uuid::from_u128(9);
        let Version { stamp, origin } = rules.version(own);
        assert!(stamp > 0, "mtime baseline should be a real epoch-ms value");
        assert_eq!(origin, own);
        assert!(!rules.has_version_header());
    }

    #[test]
    fn set_version_writes_and_replaces_a_single_version() {
        let (_dir, path, mut rules) =
            loaded_at("[rules]\n\"image/png\" = \"allow\"\n", MimePolicy::Deny);
        let o = Uuid::from_u128(3);
        rules.set_version(Version::new(100, o));
        rules.persist();
        rules.set_version(Version::new(200, o)); // replace, not duplicate
        rules.persist();
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.matches("version =").count(), 1, "one version:\n{body}");
        assert_eq!(rules.version(Uuid::nil()), Version::new(200, o));
        assert!(rules.allows("image/png", 1), "rules survive version writes");
    }

    #[test]
    fn normalised_layout_is_clean_and_sorted() {
        let (_dir, rules) = loaded(
            "[rules]\n\"image/png\" = \"deny\"\n\"image/gif\" = \"allow\"\n",
            MimePolicy::Deny,
        );
        assert_eq!(
            rules.body(),
            "[rules]\n\"image/gif\" = \"allow\"\n\"image/png\" = \"deny\"\n"
        );
    }

    #[test]
    fn body_keeps_the_header_and_renders_valid_toml() {
        let (_dir, rules) = loaded(
            "# note\n[rules]\n\"image/png\" = \"allow\"\n",
            MimePolicy::Deny,
        );
        let body = rules.body();
        assert!(body.contains("# note"), "header lost:\n{body}");
        assert!(
            body.contains("\"image/png\" = \"allow\""),
            "rule lost:\n{body}"
        );
        // The rendered body is valid TOML that reloads to the same rule.
        let mut reparsed = MimeRules::load(None, MimePolicy::Deny);
        reparsed.replace_from(body);
        assert!(reparsed.allows("image/png", 1));
    }

    #[test]
    fn replace_from_swaps_the_whole_ruleset() {
        let (_dir, mut rules) = loaded("[rules]\n\"image/png\" = \"deny\"\n", MimePolicy::Deny);
        assert!(!rules.allows("image/png", 1));
        rules.replace_from(
            "[rules]\n\"image/png\" = \"allow\"\n\"text/plain\" = \"allow\"\n".to_string(),
        );
        rules.persist();
        assert!(rules.allows("image/png", 1));
        assert!(rules.allows("text/plain", 1));
    }

    #[test]
    fn replace_from_ignores_a_non_toml_body() {
        let (_dir, mut rules) = loaded("[rules]\n\"image/png\" = \"deny\"\n", MimePolicy::Deny);
        rules.replace_from("not toml = =".to_string());
        assert!(
            !rules.allows("image/png", 1),
            "garbage body must be ignored"
        );
    }

    #[test]
    fn reload_if_changed_reports_whether_it_changed() {
        let (_dir, path, mut rules) =
            loaded_at("[rules]\n\"image/png\" = \"deny\"\n", MimePolicy::Deny);
        assert!(
            !rules.reload_if_changed(),
            "no change immediately after load"
        );
        write(&path, "[rules]\n\"image/png\" = \"allow\"\n");
        assert!(
            rules.reload_if_changed(),
            "external edit must report changed"
        );
        assert!(!rules.reload_if_changed(), "no change on re-check");
    }

    #[test]
    fn reload_if_changed_is_a_noop_after_our_own_write() {
        let (_dir, path, mut rules) =
            loaded_at("[rules]\n\"image/png\" = \"allow\"\n", MimePolicy::Deny);
        assert!(rules.ensure([&s("text/plain")]));
        rules.persist();
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!rules.reload_if_changed());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), on_disk);
        assert!(!rules.ensure([&s("text/plain")])); // still present in memory
    }

    #[test]
    fn own_write_of_an_unsorted_file_does_not_trigger_a_spurious_reload() {
        // persist() writes the normalized (sorted) body and records it as
        // `loaded`, so when the watcher sees our own write the content matches
        // and no reload fires — even though the file started unsorted.
        let (_dir, mut rules) = loaded(
            "[rules]\n\"z/z\" = \"allow\"\n\"a/a\" = \"deny\"\n",
            MimePolicy::Deny,
        );
        assert!(rules.ensure([&s("m/m")]));
        rules.persist(); // disk is now sorted: a/a, m/m, z/z
        assert!(
            !rules.reload_if_changed(),
            "our own (sorting) write must not look like an external change"
        );
    }

    #[test]
    fn revert_to_loaded_discards_in_memory_changes() {
        let (_dir, mut rules) = loaded("[rules]\n\"image/png\" = \"deny\"\n", MimePolicy::Deny);
        rules.set_version(Version::new(999, Uuid::from_u128(1)));
        assert!(rules.has_version_header());
        rules.revert_to_loaded();
        assert!(
            !rules.has_version_header(),
            "version bump must be rolled back"
        );
        assert!(!rules.allows("image/png", 1));
    }

    #[test]
    fn glob_match_handles_star_question_and_case() {
        assert!(glob_match("text/plain", "text/plain")); // exact
        assert!(glob_match("TEXT/PLAIN", "text/plain")); // case-insensitive
        assert!(glob_match("JAVA*", "JAVA_DATATRANSFER_COOKIE_abc")); // trailing *
        assert!(glob_match(
            "*;charset=utf-16*",
            "text/plain;charset=utf-16le"
        )); // *...*
        assert!(glob_match("*/utf8*", "application/utf8-data")); // needs a literal /utf8
        assert!(!glob_match("*/utf8*", "image/x-utf8-thing")); // /x-utf8 is not /utf8
        assert!(glob_match("image/???", "image/png")); // ? = one char each
        assert!(!glob_match("image/???", "image/jpeg")); // wrong length
        assert!(glob_match("JAVA*", "java_lowercase_is_matched")); // literal case folds too
        assert!(!glob_match("text/*", "image/png")); // prefix mismatch
        assert!(glob_match("*", "anything at all")); // bare * matches all
    }

    #[test]
    fn glob_match_handles_empty_and_boundary_patterns() {
        assert!(glob_match("", "")); // empty pattern matches only empty text
        assert!(!glob_match("", "x"));
        assert!(!glob_match("a?", "a")); // trailing ? needs a character
        assert!(!glob_match("?", "")); // ? needs a character
        assert!(glob_match("**", "abc")); // adjacent stars
        assert!(glob_match("a**b", "aXYZb")); // double star mid-pattern
        assert!(!glob_match("a*a", "a")); // a trailing literal a star can't fill
        assert!(glob_match("a*a", "aba"));
        assert!(glob_match("*x", "x")); // leading star may match empty
    }

    #[test]
    fn a_glob_suppresses_appending_covered_types() {
        let (_dir, mut rules) = loaded(
            "[rules]\n\"JAVA_DATATRANSFER*\" = \"deny\"\n",
            MimePolicy::Deny,
        );
        let covered = s("JAVA_DATATRANSFER_COOKIE_f9e96042");
        assert!(!rules.has_unseen([&covered]), "the glob already covers it");
        assert!(!rules.ensure([&covered]), "so nothing is appended");
        let uncovered = s("text/plain");
        assert!(rules.has_unseen([&uncovered]));
        assert!(
            rules.ensure([&uncovered]),
            "an unmatched type is still appended"
        );
    }

    #[test]
    fn remove_matching_collapses_entries_and_echoes_them() {
        let (_dir, mut rules) = loaded(
            "[rules]\n\
             \"text/uri-list;charset=utf-16\" = \"deny\"\n\
             \"text/uri-list;charset=utf-16be\" = \"deny\"\n\
             \"text/uri-list;charset=utf-8\" = \"allow\"\n",
            MimePolicy::Deny,
        );
        let removed = rules.remove_matching("*;charset=utf-16*");
        assert_eq!(
            removed,
            vec![
                "\"text/uri-list;charset=utf-16\" = \"deny\"".to_string(),
                "\"text/uri-list;charset=utf-16be\" = \"deny\"".to_string(),
            ],
            "only the utf-16 entries are removed, rendered copy-pasteably"
        );
        rules.set_rule("*;charset=utf-16*", false);
        rules.persist();
        // utf-8 survived; utf-16 entries collapsed into the glob
        assert!(rules.allows("text/uri-list;charset=utf-8", 1));
        assert!(!rules.allows("text/uri-list;charset=utf-16", 1));
        let body = rules.body();
        assert!(body.contains("\"*;charset=utf-16*\" = \"deny\""));
        assert!(
            !body.contains("utf-16be"),
            "the specific utf-16 entries are gone"
        );
    }

    #[test]
    fn remove_matching_does_not_list_the_pattern_itself() {
        let (_dir, mut rules) = loaded(
            "[rules]\n\"JAVA*\" = \"deny\"\n\"JAVA_X\" = \"allow\"\n",
            MimePolicy::Deny,
        );
        let removed = rules.remove_matching("JAVA*");
        // Keys are always quoted on output (even bare-valid ones); the equal-key
        // "JAVA*" glob is excluded from removal.
        assert_eq!(
            removed,
            vec!["\"JAVA_X\" = \"allow\"".to_string()],
            "the equal-key glob is updated in place, not reported as removed"
        );
    }

    #[test]
    fn set_rule_adds_and_replaces() {
        let (_dir, mut rules) = loaded("[rules]\n\"image/png\" = \"deny\"\n", MimePolicy::Deny);
        rules.set_rule("image/png", true); // replace
        rules.set_rule("image/*", false); // add a glob
        assert!(rules.allows("image/png", 1), "exact replace took effect");
        assert!(!rules.allows("image/gif", 1), "the new glob denies others");
    }

    #[test]
    fn apply_glob_flips_an_existing_glob_in_place() {
        let (_dir, mut rules) = loaded(
            "[rules]\n\"JAVA*\" = \"allow\"\n\"JAVA_X\" = \"allow\"\n",
            MimePolicy::Deny,
        );
        let removed = rules.apply_glob(false, "JAVA*");
        // The equal "JAVA*" key is flipped in place (not removed); only the
        // now-covered "JAVA_X" is dropped and echoed.
        assert_eq!(removed, vec!["\"JAVA_X\" = \"allow\"".to_string()]);
        rules.persist();
        let body = rules.body();
        assert!(
            body.contains("\"JAVA*\" = \"deny\""),
            "glob flipped to deny"
        );
        assert!(!body.contains("JAVA_X"), "covered exact entry removed");
        assert!(!rules.allows("JAVA_DATATRANSFER_COOKIE_x", 1));
    }

    #[test]
    fn rules_report_flags_redundant_overrides_and_invalid() {
        let (_dir, rules) = loaded(
            "[rules]\n\
             \"*;charset=utf-16*\" = \"deny\"\n\
             \"text/plain;charset=utf-16\" = \"deny\"\n\
             \"text/uri-list;charset=utf-16\" = \"allow\"\n\
             \"image/*\" = \"deny\"\n\
             \"image/png\" = \"allow\"\n\
             \"text/html\" = \"nope\"\n",
            MimePolicy::Deny,
        );
        let report = rules.rules_report();
        let find = |k: &str| {
            report
                .iter()
                .find(|r| r.key == k)
                .unwrap_or_else(|| panic!("no report entry for {k}"))
        };

        // same verdict, covered by the broad glob -> redundant
        let r = find("text/plain;charset=utf-16");
        assert_eq!(r.verdict, Verdict::Deny);
        assert_eq!(r.overlaps.len(), 1);
        assert_eq!(r.overlaps[0].relation, Relation::Redundant);
        assert_eq!(r.overlaps[0].key, "*;charset=utf-16*");
        assert_eq!(r.overlaps[0].verdict, Verdict::Deny);

        // different verdict, this (more specific) rule wins -> overrides
        let r = find("text/uri-list;charset=utf-16");
        assert_eq!(r.verdict, Verdict::Allow);
        assert_eq!(r.overlaps[0].relation, Relation::Overrides);
        assert_eq!(find("image/png").overlaps[0].relation, Relation::Overrides);

        // a broad glob nothing else covers has no overlaps
        assert!(find("image/*").overlaps.is_empty());
        assert!(find("*;charset=utf-16*").overlaps.is_empty());

        // an unusable value is flagged
        assert_eq!(find("text/html").verdict, Verdict::Invalid);
    }

    #[test]
    fn bare_valid_keys_are_quoted_on_save() {
        // STRING/TEXT are valid bare TOML keys; toml_edit would leave them unquoted.
        let (_dir, rules) = loaded(
            "[rules]\nSTRING = \"allow\"\nTEXT = \"deny\"\n",
            MimePolicy::Deny,
        );
        let body = rules.body();
        assert!(
            body.contains("\"STRING\" = \"allow\""),
            "STRING must be quoted"
        );
        assert!(body.contains("\"TEXT\" = \"deny\""), "TEXT must be quoted");
        assert!(
            !body.contains("\nSTRING ") && !body.contains("\nTEXT "),
            "no bare keys remain"
        );
    }

    #[test]
    fn ensure_does_not_re_append_a_type_seen_in_a_different_case() {
        let (_dir, mut rules) = loaded("[rules]\n\"TEXT/PLAIN\" = \"deny\"\n", MimePolicy::Deny);
        let seen = s("text/plain"); // same type, different case
        assert!(
            !rules.has_unseen([&seen]),
            "a case-variant of an existing key is already covered"
        );
        assert!(!rules.ensure([&seen]), "so no duplicate entry is appended");
        assert_eq!(rules.rule_count(), 1, "still exactly one rule");
    }

    #[test]
    fn remove_matching_renders_a_subtable_rule_not_a_blank_line() {
        // A per-type cap hand-written as a [rules."x"] block rather than inline.
        let (_dir, mut rules) = loaded(
            "[rules]\n[rules.\"image/tiff\"]\nrule = \"allow\"\nmax = \"16MiB\"\n",
            MimePolicy::Deny,
        );
        let removed = rules.remove_matching("image/*");
        assert_eq!(
            removed,
            vec!["\"image/tiff\" = { rule = \"allow\", max = \"16MiB\" }".to_string()],
            "a sub-table rule echoes as a non-blank inline line"
        );
    }
}
