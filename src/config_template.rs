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

/// One block of the canonical config file, in render order.
enum Block {
    /// Free prose not tied to a key (e.g. the file header).
    Prose(&'static str),
    /// A required scalar (no usable default): always active. `sample` is the
    /// illustrative value used to generate `examples/config.toml`.
    Required {
        key: &'static str,
        comment: &'static str,
        sample: &'static str,
    },
    /// An optional scalar: active with the user's value when present, else
    /// `# key = default`.
    Optional {
        key: &'static str,
        comment: &'static str,
        default: &'static str,
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
            default,
        } => {
            push_comment(comment, out);
            match values.scalars.get(*key) {
                Some(v) => out.push_str(&format!("{key} = {v}\n")),
                None => out.push_str(&format!("# {key} = {default}\n")),
            }
        }
        Block::PskGroup { comment } => {
            push_comment(comment, out);
            for (key, sample) in PSK_SAMPLES {
                match values.scalars.get(key) {
                    Some(v) => out.push_str(&format!("{key} = {v}\n")),
                    None => out.push_str(&format!("# {key} = {sample}\n")),
                }
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
    let link = doc
        .get("link_selections")
        .and_then(Item::as_table)
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
    // 3. Render and compare.
    let rendered = render(TEMPLATE, &values);
    if rendered == current {
        return Ok(SyncOutcome::Unchanged);
    }
    // 4. Which optional keys are absent (added as commented defaults)?
    let added = optional_keys()
        .into_iter()
        .filter(|k| !values.scalars.contains_key(*k))
        .map(str::to_string)
        .collect();
    write_atomic(path, &rendered)?;
    Ok(SyncOutcome::Rewrote { added })
}

/// The optional scalar keys in the template, for the "added" summary.
fn optional_keys() -> Vec<&'static str> {
    TEMPLATE
        .iter()
        .filter_map(|b| match b {
            Block::Optional { key, .. } => Some(*key),
            _ => None,
        })
        .collect()
}

/// Write `contents` to `path` atomically (temp file in the same dir + rename),
/// so a crash mid-write can't truncate the live config. If `path` is a symlink
/// (stow-managed configs are), follow it and rewrite the real target in place
/// rather than clobbering the link with a regular file; `resolve_link_target` is
/// a no-op for a plain file. The temp file lives in the target's own directory
/// so the rename stays on one filesystem (atomic).
fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    let target = crate::fsutil::resolve_link_target(path);
    // resolve_link_target stops after a bounded number of hops; if the result
    // is still a symlink the chain was too deep (or a cycle) and we never
    // reached the real file. Refuse rather than rename over — and clobber —
    // that intermediate link. (Config::load already rejects broken/cyclic links
    // upstream; this guards the over-deep case its single open() can still pass.)
    if crate::fsutil::is_symlink(&target) {
        bail!(
            "config {} resolves through too many symlink hops to write safely",
            path.display()
        );
    }
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let name = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("config.toml");
    let tmp = dir.join(format!(".{name}.sync-config.tmp"));
    let written = std::fs::write(&tmp, contents)
        .with_context(|| format!("writing {}", tmp.display()))
        .and_then(|()| {
            std::fs::rename(&tmp, &target)
                .with_context(|| format!("replacing {}", target.display()))
        });
    if written.is_err() {
        // Don't leave a partial temp behind — it would sit in the resolved
        // target's directory (e.g. a stow dotfiles repo). Best-effort; a
        // successful rename already consumed the temp.
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

const TEMPLATE: &[Block] = &[
    Block::Prose(
        "clipmesh configuration. Generate/refresh with `clipmesh --sync-config`:\n\
         it fills in every option (commented = default) and these comments,\n\
         keeping the values you've set. clipmesh watches this file and restarts\n\
         to apply a change.",
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
        comment: "Port to listen on (default 48100). Peers below that omit their own port\n\
                  reuse this one. Put the port here, not in `listen`.",
        default: "48100",
    },
    Block::Optional {
        key: "peers",
        comment: "List every other node directly. clipmesh connects peers point-to-point\n\
                  and never forwards between them, so a node left out here won't receive\n\
                  copies. Add \":port\" to override the shared port for one peer.",
        default: "[\"host-b\", \"host-c\"]",
    },
    Block::PskGroup {
        comment: "Exactly one of psk_file / psk / psk_env must be set: psk_file points to a\n\
                  file holding the shared secret, psk is the secret inline, psk_env names an\n\
                  environment variable holding it.",
    },
    Block::Prose("Everything below is optional; the commented value is the default."),
    Block::Optional {
        key: "max_payload_size",
        comment: "Skip clipboard contents larger than this (whole offer).",
        default: "\"32MiB\"",
    },
    Block::Optional {
        key: "debounce_ms",
        comment: "Quiet period (ms) before broadcasting, to coalesce rapid copies.",
        default: "100",
    },
    Block::Optional {
        key: "sync_selection",
        comment: "Also sync the middle-click selection across the mesh.",
        default: "false",
    },
    Block::Optional {
        key: "direction",
        comment: "\"both\" | \"send_only\" | \"receive_only\".",
        default: "\"both\"",
    },
    Block::Optional {
        key: "exclude_sensitive",
        comment: "Skip password-manager-flagged contents.",
        default: "true",
    },
    Block::Optional {
        key: "resync_on_connect",
        comment: "Push current clipboard to peers when they (re)connect.",
        default: "true",
    },
    Block::Optional {
        key: "share_mime_rules",
        comment: "Share the MIME-rules file across the mesh (whole-file last-writer-wins:\n\
                  the most recently edited file wins outright and replaces the others, not\n\
                  a per-type merge). Turn off to keep each host's rules independent.",
        default: "true",
    },
    Block::Optional {
        key: "verbose",
        comment: "Log a one-line summary (at info level, so needs log_level >= info) per\n\
                  detected copy and received update.",
        default: "false",
    },
    Block::Optional {
        key: "log_level",
        comment: "Overridable with RUST_LOG.",
        default: "\"info\"",
    },
    Block::Optional {
        key: "unknown_mime",
        comment: "What to do with a MIME type that has no rule yet: \"deny\" (default) syncs\n\
                  nothing until you allow it; \"allow\" syncs everything not explicitly denied.",
        default: "\"deny\"",
    },
    Block::Optional {
        key: "synthesize_text_plain",
        comment: "When a copied selection offers only a legacy X11 plain-text atom\n\
                  (UTF8_STRING/STRING/TEXT) and no text/plain* rep, synthesize\n\
                  text/plain;charset=utf-8 and text/plain from it so Wayland-native apps\n\
                  can paste it. The synthesized types go through the MIME rules below.",
        default: "false",
    },
    Block::Optional {
        key: "take_ownership",
        comment: "After a local copy, re-offer the selection so clipmesh owns it: the\n\
                  clipboard then survives the source app exiting, and (with\n\
                  synthesize_text_plain) X11-sourced content pastes on THIS host too. Never\n\
                  re-owns password-manager-flagged content while exclude_sensitive is on.",
        default: "false",
    },
    Block::Optional {
        key: "mime_rules_file",
        comment: "Per-type allow/deny rules file (TOML). Defaults to \"mimetypes\" beside\n\
                  this config. clipmesh creates it, appends any new type it sees (per\n\
                  unknown_mime), keeps it sorted, and reloads on change. Edit it or run\n\
                  `clipmesh --allow/--deny \"<glob>\"` (and `clipmesh --rules` to list).",
        default: "\"~/.config/clipmesh/mimetypes\"",
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

/// The illustrative values used to generate `examples/config.toml`: the example
/// shows `listen`/`port`/`peers`/`psk_file` active, everything else commented.
fn example_values() -> Values {
    let scalars = [
        ("listen", "\"0.0.0.0\""),
        ("port", "48100"),
        ("peers", "[\"host-b\", \"host-c\"]"),
        ("psk_file", "\"~/.config/clipmesh/psk\""),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
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
                default: "100",
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
                crate::fsutil::is_symlink(link),
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
            .any(|e| e.file_name().to_string_lossy().contains(".sync-config.tmp"));
        assert!(!leftover_tmp, "temp file leaked after a failed write");
    }

    #[test]
    fn example_config_matches_template() {
        let expected = render_example();
        let path = "examples/config.toml"; // cargo runs tests with CWD = crate root
        if std::env::var("CLIPMESH_REGEN_EXAMPLE").is_ok() {
            std::fs::write(path, &expected).unwrap();
            return;
        }
        let actual = std::fs::read_to_string(path).unwrap();
        assert_eq!(
            actual, expected,
            "examples/config.toml is stale; regenerate with \
             CLIPMESH_REGEN_EXAMPLE=1 cargo test --lib example_config_matches_template"
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
}
