//! The canonical config-file template and the `--sync-config` normalizer.
//!
//! One ordered list of `Block`s describes every option, its comment, and its
//! default. `render` emits the file from that template, overlaying the user's
//! present values: options the user set are active with their values; the rest
//! are commented defaults. `examples/config.toml` is generated from the same
//! template (golden test), so the example and the normalizer can't drift.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::Path;
use toml_edit::{Decor, DocumentMut, Item, Value};

/// psk source keys in canonical order, with the sample shown when commented.
const PSK_SAMPLES: [(&str, &str); 3] = [
    ("psk_file", "\"~/.config/clipmesh/psk\""),
    ("psk", "\"supersecret\""),
    ("psk_env", "\"CLIPMESH_PSK\""),
];

/// What a commented-out line in the generated file is showing.
///
/// The rendered text is the same either way; the distinction is a *promise*.
/// `Default` claims "uncommenting this line changes nothing", which
/// `commented_defaults_are_the_parsers_defaults` then holds the template to —
/// so the TOML text here and `config.rs`'s `default_*` functions can no longer
/// drift apart unnoticed. `Sample` makes no such claim, and is the honest
/// answer for an option whose default isn't a literal this file could print.
#[derive(Clone, Copy)]
enum Shown {
    /// Exactly the value the parser applies when the key is absent.
    Default(&'static str),
    /// An illustrative value only: the option either has no default worth
    /// printing (`peers` is empty) or resolves one from the environment
    /// (`mime_rules_file` follows wherever the config lives). Uncommenting such
    /// a line *does* change behaviour, so its comment must say so.
    Sample(&'static str),
}

impl Shown {
    /// The TOML text rendered beside the key.
    fn text(self) -> &'static str {
        match self {
            Shown::Default(text) | Shown::Sample(text) => text,
        }
    }
}

/// One block of the canonical config file, in render order.
enum Block {
    /// Free prose not tied to a key (e.g. the file header).
    Prose(&'static str),
    /// A required scalar (no usable default): always active. `sample` is the
    /// illustrative value used to generate `examples/config.toml`. Deliberately
    /// not a `Shown`: a required key cannot have a default to promise.
    Required {
        key: &'static str,
        comment: &'static str,
        sample: &'static str,
    },
    /// An optional scalar: active with the user's value when present, else
    /// `# key = <shown>`.
    Optional {
        key: &'static str,
        comment: &'static str,
        shown: Shown,
    },
    /// The psk source group: exactly one of psk_file/psk/psk_env is active.
    PskGroup { comment: &'static str },
    /// The `[link_selections]` table; always rendered last.
    LinkSelections { comment: &'static str },
}

/// The user's present values, extracted from their config file.
#[derive(Default)]
struct Values {
    /// Present top-level key -> canonical (decor-stripped) value text.
    scalars: HashMap<String, String>,
    /// The `[link_selections]` table if present: (clipboard_to_selection,
    /// selection_to_clipboard).
    link: Option<(bool, bool)>,
}

/// Render each comment line as `# line` (a blank line becomes `#`).
fn push_comment(text: &str, out: &mut String) {
    for line in text.lines() {
        if line.is_empty() {
            out.push_str("#\n");
        } else {
            out.push_str("# ");
            out.push_str(line);
            out.push('\n');
        }
    }
}

/// Render the whole file: each block's comment, then its option line(s), then a
/// single blank line. Exactly one trailing newline at EOF.
fn render(template: &[Block], values: &Values) -> String {
    let mut out = String::new();
    for block in template {
        push_block(block, values, &mut out);
        out.push('\n');
    }
    let trimmed = out.trim_end().to_string();
    format!("{trimmed}\n")
}

/// Emit one optional option line: active at the user's value when they set it,
/// else the commented default. The single rule for "set stays set, unset shows
/// its default", shared by the plain options and the psk group.
fn push_option(key: &str, values: &Values, default: &str, out: &mut String) {
    match values.scalars.get(key) {
        Some(v) => out.push_str(&format!("{key} = {v}\n")),
        None => out.push_str(&format!("# {key} = {default}\n")),
    }
}

fn push_block(block: &Block, values: &Values, out: &mut String) {
    match block {
        Block::Prose(text) => push_comment(text, out),
        Block::Required {
            key,
            comment,
            sample,
        } => {
            push_comment(comment, out);
            let v = values
                .scalars
                .get(*key)
                .map(String::as_str)
                .unwrap_or(sample);
            out.push_str(&format!("{key} = {v}\n"));
        }
        Block::Optional {
            key,
            comment,
            shown,
        } => {
            push_comment(comment, out);
            push_option(key, values, shown.text(), out);
        }
        Block::PskGroup { comment } => {
            push_comment(comment, out);
            for (key, sample) in PSK_SAMPLES {
                push_option(key, values, sample, out);
            }
        }
        Block::LinkSelections { comment } => {
            push_comment(comment, out);
            match values.link {
                Some((c2s, s2c)) => {
                    out.push_str("[link_selections]\n");
                    out.push_str(&format!("clipboard_to_selection = {c2s}\n"));
                    out.push_str(&format!("selection_to_clipboard = {s2c}\n"));
                }
                None => {
                    out.push_str("# [link_selections]\n");
                    out.push_str("# clipboard_to_selection = false\n");
                    out.push_str("# selection_to_clipboard = false\n");
                }
            }
        }
    }
}

/// Parse config text and collect present top-level keys -> canonical
/// (decor-stripped, single-line) value text, plus the `[link_selections]`
/// booleans. Tables other than `[link_selections]` are ignored (config.toml has
/// no others). Errors only if the text isn't valid TOML.
fn extract_values(text: &str) -> Result<Values> {
    let doc: DocumentMut = text.parse().context("parsing the config as TOML")?;
    let mut scalars = HashMap::new();
    for (key, item) in doc.iter() {
        if key == "link_selections" {
            continue; // captured below
        }
        if let Some(value) = item.as_value() {
            scalars.insert(key.to_string(), canonical(value));
        }
    }
    // `as_table_like`, not `as_table`: `link_selections = { ... }` is stored as
    // an inline value, and serde accepts it — so `Config::load` honours a
    // setting that `as_table` cannot see. Reading it that way made
    // `--sync-config` re-emit the commented defaults and silently turn the
    // user's mirroring off in a file it had just claimed to normalize.
    let link = doc
        .get("link_selections")
        .and_then(Item::as_table_like)
        .map(|t| {
            let b = |k: &str| t.get(k).and_then(Item::as_bool).unwrap_or(false);
            (b("clipboard_to_selection"), b("selection_to_clipboard"))
        });
    Ok(Values { scalars, link })
}

/// A value as canonical TOML: decor (surrounding whitespace / inline comments)
/// stripped, arrays flattened to one line. Idempotent on its own output.
fn canonical(value: &Value) -> String {
    match value {
        Value::Array(arr) => {
            let elems: Vec<String> = arr.iter().map(canonical).collect();
            format!("[{}]", elems.join(", "))
        }
        other => {
            let mut v = other.clone();
            *v.decor_mut() = Decor::new("", "");
            v.to_string().trim().to_string()
        }
    }
}

/// What `sync_config` did, for the CLI summary.
pub enum SyncOutcome {
    /// The file already matched the canonical render; nothing written.
    Unchanged,
    /// The file was rewritten; `added` lists options that gained a commented
    /// default (i.e. keys in the template the user had not set).
    Rewrote { added: Vec<String> },
}

/// Normalize the config file at `path`: validate it loads, then rewrite it from
/// `TEMPLATE` overlaid with the user's present values. Never rewrites a config
/// that doesn't load (it is left untouched). Idempotent.
pub fn sync_config(path: &Path) -> Result<SyncOutcome> {
    use crate::config::Config;
    // 1. Validate. A config we can't load is left untouched.
    Config::load(path).context("the config must load before --sync-config can normalize it")?;
    // 2. Read raw values from the user's file.
    let current =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let values = extract_values(&current)?;
    // 3. Refuse to rewrite a file holding a key the template can't render.
    // `render` only emits keys that have a `Block`, so such a key would be
    // dropped from the rewritten file and the setting silently lost. Step 1
    // already rejected keys the parser doesn't know, so reaching this means
    // `TEMPLATE` has drifted from `RawConfig` — a bug, caught at build time by
    // `every_config_option_has_a_template_block`. This is the belt-and-braces
    // copy: losing a line of someone's config is not an acceptable failure mode
    // for a normalizer, so refuse rather than write a lossy file.
    let known = template_keys();
    let mut unknown: Vec<&str> = values
        .scalars
        .keys()
        .map(String::as_str)
        .filter(|k| !known.contains(k))
        .collect();
    if !unknown.is_empty() {
        unknown.sort_unstable();
        bail!(
            "{} has option(s) the canonical template doesn't know: {}. \
             Rewriting would drop them, so nothing was written — remove them, \
             or fix the typo, and re-run.",
            path.display(),
            unknown.join(", ")
        );
    }
    // 4. Render and compare.
    let rendered = render(TEMPLATE, &values);
    if rendered == current {
        return Ok(SyncOutcome::Unchanged);
    }
    // 5. Which optional keys are absent (added as commented defaults)?
    let added = optional_keys()
        .into_iter()
        .filter(|k| !values.scalars.contains_key(*k))
        .map(str::to_string)
        .collect();
    crate::fsutil::write_atomic(path, &rendered)?;
    Ok(SyncOutcome::Rewrote { added })
}

/// One scalar key the template renders, and what the template knows about it.
struct TemplateKey {
    key: &'static str,
    /// The value shown beside the key while the user hasn't set it.
    shown: Shown,
    /// True only for `Block::Optional` — a plain setting a config may leave
    /// out. `listen` and the psk sources are not optional (a bind address and
    /// exactly one psk source are always required), so `--sync-config` doesn't
    /// count them among the options it added a commented default for.
    optional: bool,
}

/// Every scalar key `TEMPLATE` can render. **The one place `TEMPLATE` is
/// scanned by shape**: the match below has no `_` arm, so a new `Block` variant
/// stops the build here instead of quietly falling out of the sets derived from
/// this function. Those gaps are invisible — a missing key makes `--sync-config`
/// refuse a perfectly valid config, or drop a line from it. (`link_selections`
/// is a table with its own block, not a scalar key.)
fn key_defaults() -> Vec<TemplateKey> {
    TEMPLATE
        .iter()
        .flat_map(|b| match b {
            Block::Prose(_) | Block::LinkSelections { .. } => Vec::new(),
            Block::Required { key, sample, .. } => vec![TemplateKey {
                key,
                shown: Shown::Sample(sample),
                optional: false,
            }],
            Block::Optional { key, shown, .. } => vec![TemplateKey {
                key,
                shown: *shown,
                optional: true,
            }],
            Block::PskGroup { .. } => PSK_SAMPLES
                .iter()
                .map(|(key, sample)| TemplateKey {
                    key,
                    shown: Shown::Sample(sample),
                    optional: false,
                })
                .collect(),
        })
        .collect()
}

/// Every top-level scalar key the template can render. The set `sync_config`
/// checks a user's file against, so a key with no `Block` is reported rather
/// than quietly dropped.
fn template_keys() -> Vec<&'static str> {
    key_defaults().into_iter().map(|k| k.key).collect()
}

/// The optional scalar keys in the template, for the "added" summary.
fn optional_keys() -> Vec<&'static str> {
    key_defaults()
        .into_iter()
        .filter(|k| k.optional)
        .map(|k| k.key)
        .collect()
}

const TEMPLATE: &[Block] = &[
    Block::Prose(
        "clipmesh configuration. Generate/refresh with `clipmesh --sync-config`:\n\
         it fills in every option and these comments, keeping the values you've\n\
         set. A commented-out line means the option is unset and its default\n\
         applies; the value shown is that default, except where the comment\n\
         calls it an example. clipmesh watches this file and restarts to apply\n\
         a change.",
    ),
    Block::Required {
        key: "listen",
        comment: "0.0.0.0 binds every interface; restrict to a specific LAN address (or\n\
                  firewall the port) on hosts reachable from untrusted networks. Traffic is\n\
                  Noise-encrypted, so peers without the psk can neither read nor inject.",
        sample: "\"0.0.0.0\"",
    },
    Block::Optional {
        key: "port",
        comment: "Port to listen on. Peers below that omit their own port reuse this one.\n\
                  Put the port here, not in `listen`.",
        shown: Shown::Default("48100"),
    },
    Block::Optional {
        key: "peers",
        comment: "List every other node directly. clipmesh connects peers point-to-point\n\
                  and never forwards between them, so a node left out here won't receive\n\
                  copies. Add \":port\" to override the shared port for one peer.\n\
                  The hosts below are an example: unset, this node dials nobody and only\n\
                  accepts connections others make to it.",
        shown: Shown::Sample("[\"host-b\", \"host-c\"]"),
    },
    Block::PskGroup {
        comment: "Exactly one of psk_file / psk / psk_env must be set: psk_file points to a\n\
                  file holding the shared secret, psk is the secret inline, psk_env names an\n\
                  environment variable holding it. The values below are examples — every\n\
                  node in the mesh must end up with the same secret.",
    },
    Block::Prose("Everything below is optional."),
    Block::Optional {
        key: "max_payload_size",
        comment: "Skip clipboard contents larger than this (whole offer).",
        shown: Shown::Default("\"32MiB\""),
    },
    Block::Optional {
        key: "debounce_ms",
        comment: "Quiet period (ms) before broadcasting, to coalesce rapid copies.",
        shown: Shown::Default("100"),
    },
    Block::Optional {
        key: "sync_selection",
        comment: "Also sync the middle-click selection across the mesh.",
        shown: Shown::Default("false"),
    },
    Block::Optional {
        key: "direction",
        comment: "\"both\" | \"send_only\" | \"receive_only\".",
        shown: Shown::Default("\"both\""),
    },
    Block::Optional {
        key: "exclude_sensitive",
        comment: "Skip password-manager-flagged contents.",
        shown: Shown::Default("true"),
    },
    Block::Optional {
        key: "resync_on_connect",
        comment: "Push current clipboard to peers when they (re)connect.",
        shown: Shown::Default("true"),
    },
    Block::Optional {
        key: "share_mime_rules",
        comment: "Share the MIME-rules file across the mesh (whole-file last-writer-wins:\n\
                  the most recently edited file wins outright and replaces the others, not\n\
                  a per-type merge). Turn off to keep each host's rules independent.",
        shown: Shown::Default("true"),
    },
    Block::Optional {
        key: "verbose",
        comment: "Log a one-line summary (at info level, so needs log_level >= info) per\n\
                  detected copy and received update.",
        shown: Shown::Default("false"),
    },
    Block::Optional {
        key: "log_level",
        comment: "Overridable with RUST_LOG.",
        shown: Shown::Default("\"info\""),
    },
    Block::Optional {
        key: "unknown_mime",
        comment: "What to do with a MIME type that has no rule yet: \"deny\" syncs nothing\n\
                  until you allow it; \"allow\" syncs everything not explicitly denied.",
        shown: Shown::Default("\"deny\""),
    },
    Block::Optional {
        key: "synthesize_text_plain",
        comment: "When a copied selection offers only a legacy X11 plain-text atom\n\
                  (UTF8_STRING/STRING/TEXT) and no text/plain* rep, synthesize\n\
                  text/plain;charset=utf-8 and text/plain from it so Wayland-native apps\n\
                  can paste it. The synthesized types go through the MIME rules below.",
        shown: Shown::Default("false"),
    },
    Block::Optional {
        key: "take_ownership",
        comment: "After a local copy, re-offer the selection so clipmesh owns it: the\n\
                  clipboard then survives the source app exiting, and (with\n\
                  synthesize_text_plain) X11-sourced content pastes on THIS host too. Never\n\
                  re-owns password-manager-flagged content while exclude_sensitive is on.",
        shown: Shown::Default("false"),
    },
    Block::Optional {
        key: "mime_rules_file",
        comment: "Per-type allow/deny rules file (TOML). Defaults to \"mimetypes\" beside\n\
                  this config, wherever this config lives — so the path below is an example\n\
                  of that, not a fixed default: setting it pins the rules file even if the\n\
                  config moves. clipmesh creates the file, appends any new type it sees (per\n\
                  unknown_mime), keeps it sorted, and reloads on change. Edit it or run\n\
                  `clipmesh --allow/--deny \"<glob>\"` (and `clipmesh --rules` to list).",
        shown: Shown::Sample("\"~/.config/clipmesh/mimetypes\""),
    },
    Block::LinkSelections {
        comment: "Locally mirror between the Ctrl+C clipboard and the mouse-highlight /\n\
                  middle-click selection on THIS host (separate from sync_selection, which\n\
                  is mesh-wide). Each direction is independent and off unless true.\n\
                  WARNING: selection_to_clipboard makes selecting any text overwrite your\n\
                  clipboard — and, because the clipboard is always synced when this node\n\
                  sends, your peers' clipboards too.",
    },
];

/// The value this file already shows for `key`, whatever kind of block it is in.
fn template_value(key: &str) -> Option<&'static str> {
    key_defaults()
        .into_iter()
        .find(|k| k.key == key)
        .map(|k| k.shown.text())
}

/// The illustrative values used to generate `examples/config.toml`: the example
/// shows `listen`/`port`/`peers`/`psk_file` active, everything else commented.
///
/// Only the *keys* are listed here — the values come from the template itself,
/// so an active line in the example can't disagree with the commented default
/// shown beside it. Spelling them out again would make a changed default fail
/// the golden test while regenerating silently shipped the stale value.
fn example_values() -> Values {
    const ACTIVE: [&str; 4] = ["listen", "port", "peers", "psk_file"];
    let scalars = ACTIVE
        .iter()
        .map(|key| {
            let value = template_value(key)
                .unwrap_or_else(|| panic!("example key {key:?} is not in the template"));
            (key.to_string(), value.to_string())
        })
        .collect();
    Values {
        scalars,
        link: None,
    }
}

/// The shipped `examples/config.toml` content, generated from `TEMPLATE`.
pub fn render_example() -> String {
    render(TEMPLATE, &example_values())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vals(pairs: &[(&str, &str)]) -> Values {
        Values {
            scalars: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            link: None,
        }
    }

    #[test]
    fn renders_prose_required_and_optional() {
        let template = &[
            Block::Prose("header line"),
            Block::Required {
                key: "listen",
                comment: "bind addr",
                sample: "\"0.0.0.0\"",
            },
            Block::Optional {
                key: "debounce_ms",
                comment: "quiet period",
                shown: Shown::Default("100"),
            },
        ];
        // `listen` set by the user, `debounce_ms` not.
        let out = render(template, &vals(&[("listen", "\"192.168.1.5\"")]));
        assert_eq!(
            out,
            "# header line\n\
             \n\
             # bind addr\n\
             listen = \"192.168.1.5\"\n\
             \n\
             # quiet period\n\
             # debounce_ms = 100\n"
        );
    }

    #[test]
    fn psk_group_actives_the_users_source_only() {
        let template = &[Block::PskGroup { comment: "one of:" }];
        // user uses psk_file
        let out = render(template, &vals(&[("psk_file", "\"/k\"")]));
        assert_eq!(
            out,
            "# one of:\n\
             psk_file = \"/k\"\n\
             # psk = \"supersecret\"\n\
             # psk_env = \"CLIPMESH_PSK\"\n"
        );
    }

    #[test]
    fn link_selections_absent_is_fully_commented() {
        let template = &[Block::LinkSelections { comment: "link" }];
        let out = render(template, &Values::default());
        assert_eq!(
            out,
            "# link\n\
             # [link_selections]\n\
             # clipboard_to_selection = false\n\
             # selection_to_clipboard = false\n"
        );
    }

    #[test]
    fn link_selections_present_actives_both_keys() {
        let template = &[Block::LinkSelections { comment: "link" }];
        let v = Values {
            link: Some((true, false)),
            ..Values::default()
        };
        let out = render(template, &v);
        assert_eq!(
            out,
            "# link\n\
             [link_selections]\n\
             clipboard_to_selection = true\n\
             selection_to_clipboard = false\n"
        );
    }

    #[test]
    fn rendered_example_is_a_valid_config() {
        let text = render_example();
        // every option key appears exactly once
        for key in [
            "listen",
            "port",
            "peers",
            "max_payload_size",
            "debounce_ms",
            "sync_selection",
            "direction",
            "exclude_sensitive",
            "resync_on_connect",
            "share_mime_rules",
            "verbose",
            "log_level",
            "unknown_mime",
            "synthesize_text_plain",
            "take_ownership",
            "mime_rules_file",
        ] {
            assert!(text.contains(&format!("{key} ")), "missing {key}");
        }
        // the [link_selections] table is present (commented) and last
        assert!(text.contains("# [link_selections]"));
        assert!(text
            .trim_end()
            .ends_with("# selection_to_clipboard = false"));
        // re-rendering the example through extract+render is a no-op (idempotent)
        let again = render(TEMPLATE, &extract_values(&text).unwrap());
        assert_eq!(again, text, "render is not idempotent on the example");
    }

    #[test]
    fn sync_config_adds_missing_keeps_set_and_is_idempotent() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // a minimal but valid config (psk inline so no psk_file read needed)
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "listen = \"x\"\npsk = \"s\"\ndebounce_ms = 250\n").unwrap();
        drop(f);

        let outcome = sync_config(&path).unwrap();
        assert!(matches!(outcome, SyncOutcome::Rewrote { .. }));
        let text = std::fs::read_to_string(&path).unwrap();
        // the user's set value is preserved, active
        assert!(text.contains("debounce_ms = 250"));
        // psk is the active source; psk_file/psk_env are commented
        assert!(text.contains("psk = \"s\""));
        assert!(text.contains("# psk_file ="));
        // a previously-absent option was added as a commented default
        assert!(text.contains("# exclude_sensitive = true"));
        // it still loads
        crate::config::Config::from_toml(&text).unwrap();

        // running again is a no-op
        let outcome2 = sync_config(&path).unwrap();
        assert!(matches!(outcome2, SyncOutcome::Unchanged));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }

    #[test]
    fn sync_config_refuses_an_unloadable_config() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = "listen = \"x\"\nsync_primary = true\n"; // unknown key
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{original}").unwrap();
        drop(f);
        assert!(sync_config(&path).is_err());
        // the broken file is left untouched
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }

    /// The template must be able to render every option the parser accepts, or
    /// `--sync-config` drops that line from a config file that sets it.
    /// `RAW_CONFIG_KEYS` is the schema: the compiler stops a new `RawConfig`
    /// field from reaching users without passing through it (see `from_toml`'s
    /// destructure), and this test carries that obligation on to `TEMPLATE`.
    #[test]
    fn every_config_option_has_a_template_block() {
        let renderable = template_keys();
        for key in crate::config::RAW_CONFIG_KEYS {
            // The only table; rendered by its own block, not as a scalar.
            if key == "link_selections" {
                continue;
            }
            assert!(
                renderable.contains(&key),
                "config option `{key}` has no TEMPLATE block: --sync-config would \
                 delete it from a config that sets it"
            );
        }
    }

    /// The generated file tells the reader that a commented line is the option's
    /// default. Prove it: render with nothing set, uncomment every line that
    /// isn't declared a `Shown::Sample`, and the result must parse to exactly
    /// what the parser produces from a config that sets none of them.
    ///
    /// Without this the template's TOML text and `config.rs`'s `default_*()`
    /// functions are two unlinked copies of the same ~15 values. The existing
    /// checks only compare key *presence*, so changing a default in `config.rs`
    /// left every generated config documenting the old one, golden test green.
    /// (Two had already drifted this way: `peers` and `mime_rules_file`, now
    /// declared samples because neither has a literal default to print.)
    #[test]
    fn commented_defaults_are_the_parsers_defaults() {
        use crate::config::Config;

        // Uncommenting `# key = value` lines can't supply a psk (one of three
        // mutually exclusive sources), so set one; both sides use the same
        // secret, since the config holds its derived key rather than the text.
        let listen = template_value("listen").expect("listen is in the template");
        let rendered = render(TEMPLATE, &vals(&[("psk", "\"s\"")]));

        // Deliberately opt *out* by name rather than in: anything that renders
        // commented is treated as a promised default unless declared a sample,
        // so a new option is covered the moment it is added.
        let samples: Vec<&str> = key_defaults()
            .into_iter()
            .filter(|k| matches!(k.shown, Shown::Sample(_)))
            .map(|k| k.key)
            .collect();
        let mut activated = Vec::new();
        let mut toml = String::new();
        for line in rendered.lines() {
            // A commented setting is `# key = value` or the `# [table]` header;
            // prose comments are neither. `[link_selections]` renders last, so
            // activating its header can't capture a key meant for the top level.
            let setting = line.strip_prefix("# ").filter(|bare| {
                bare.starts_with('[')
                    || bare
                        .split_once(" = ")
                        .is_some_and(|(key, _)| !key.contains(' ') && !samples.contains(&key))
            });
            match setting {
                Some(bare) => {
                    activated.push(bare.to_string());
                    toml.push_str(bare);
                }
                None => toml.push_str(line),
            }
            toml.push('\n');
        }
        // Guard against the line-shape sniffing above silently matching nothing.
        assert!(
            activated.len() > 10,
            "expected the template's defaults to be activated, got {activated:?}"
        );

        let from_template = Config::from_toml(&toml)
            .unwrap_or_else(|e| panic!("the activated template must parse: {e:#}\n{toml}"));
        let from_minimal = Config::from_toml(&format!("listen = {listen}\npsk = \"s\"\n")).unwrap();
        assert_eq!(
            from_template, from_minimal,
            "a value the template shows as a default is not the parser's default"
        );
    }

    #[test]
    fn sync_config_writes_through_a_symlink_without_replacing_it() {
        use std::io::Write;
        // A stow-managed config is a symlink into the dotfiles repo; --sync-config
        // must rewrite the real target in place, not clobber the link with a
        // regular file.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real-config.toml");
        let link = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&target).unwrap();
        write!(f, "listen = \"x\"\npsk = \"s\"\ndebounce_ms = 250\n").unwrap();
        drop(f);
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let outcome = sync_config(&link).unwrap();
        assert!(matches!(outcome, SyncOutcome::Rewrote { .. }));

        // the link is still a symlink to the same target, not a replaced file
        assert!(
            crate::fsutil::is_symlink(&link),
            "the symlink was replaced by a regular file"
        );
        assert_eq!(std::fs::read_link(&link).unwrap(), target);
        // the rewrite landed in the target, keeping the user's value
        let text = std::fs::read_to_string(&target).unwrap();
        assert!(text.contains("debounce_ms = 250"));
        assert!(text.contains("# exclude_sensitive = true"));
        crate::config::Config::from_toml(&text).unwrap();

        // idempotent through the link
        assert!(matches!(
            sync_config(&link).unwrap(),
            SyncOutcome::Unchanged
        ));
    }

    #[test]
    fn example_config_matches_template() {
        crate::fsutil::assert_matches_generated_example(
            "examples/config.toml",
            &render_example(),
            "example_config_matches_template",
        );
    }

    #[test]
    fn extract_collects_present_keys_decor_stripped() {
        let text = "\
listen = \"x\"
psk = \"s\"
debounce_ms = 250   # inline comment dropped
max_payload_size=\"8MiB\"
peers = [\n  \"a\",\n  \"b\",\n]

[link_selections]
clipboard_to_selection = true
";
        let v = extract_values(text).unwrap();
        assert_eq!(v.scalars.get("listen").unwrap(), "\"x\"");
        assert_eq!(v.scalars.get("debounce_ms").unwrap(), "250");
        // value is decor-stripped (no inline comment, canonical spacing)
        assert_eq!(v.scalars.get("max_payload_size").unwrap(), "\"8MiB\"");
        // multi-line array normalized to one line
        assert_eq!(v.scalars.get("peers").unwrap(), "[\"a\", \"b\"]");
        // the table is captured separately, not as a scalar
        assert!(!v.scalars.contains_key("link_selections"));
        // absent table key defaults to false
        assert_eq!(v.link, Some((true, false)));
    }

    /// `link_selections = { ... }` is valid TOML and serde accepts it, so
    /// `Config::load` honours it and mirroring works — but `toml_edit` stores it
    /// as an inline *value*, which `Item::as_table` does not see. Reading it
    /// that way made `--sync-config` collect no table at all and re-emit the
    /// commented defaults, silently turning the user's mirroring off in a file
    /// it had just claimed to normalize.
    #[test]
    fn sync_config_keeps_an_inline_link_selections_table() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            "listen = \"x\"\npsk = \"s\"\nlink_selections = {{ clipboard_to_selection = true }}\n"
        )
        .unwrap();
        drop(f);

        sync_config(&path).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let cfg = crate::config::Config::from_toml(&text).unwrap();
        assert!(
            cfg.link_selections.clipboard_to_selection,
            "--sync-config dropped an inline [link_selections]:\n{text}"
        );
    }
}
