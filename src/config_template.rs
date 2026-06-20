//! The canonical config-file template and the `--sync-config` normalizer.
//!
//! One ordered list of `Block`s describes every option, its comment, and its
//! default. `render` emits the file from that template, overlaying the user's
//! present values: options the user set are active with their values; the rest
//! are commented defaults. `examples/config.toml` is generated from the same
//! template (golden test), so the example and the normalizer can't drift.

use anyhow::{Context, Result};
use std::collections::HashMap;
use toml_edit::{Decor, DocumentMut, Item, Value};

/// psk source keys in canonical order, with the sample shown when commented.
const PSK_SAMPLES: [(&str, &str); 3] = [
    ("psk_file", "\"~/.config/clipmesh/psk\""),
    ("psk", "\"supersecret\""),
    ("psk_env", "\"CLIPMESH_PSK\""),
];

/// One block of the canonical config file, in render order.
#[allow(dead_code)] // used in tests
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
#[allow(dead_code)] // used in tests
struct Values {
    /// Present top-level key -> canonical (decor-stripped) value text.
    scalars: HashMap<String, String>,
    /// The `[link_selections]` table if present: (clipboard_to_selection,
    /// selection_to_clipboard).
    link: Option<(bool, bool)>,
}

/// Render each comment line as `# line` (a blank line becomes `#`).
#[allow(dead_code)] // used in tests
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
#[allow(dead_code)] // used in tests
fn render(template: &[Block], values: &Values) -> String {
    let mut out = String::new();
    for block in template {
        push_block(block, values, &mut out);
        out.push('\n');
    }
    let trimmed = out.trim_end().to_string();
    format!("{trimmed}\n")
}

#[allow(dead_code)] // used in tests
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
#[allow(dead_code)] // used in tests
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
#[allow(dead_code)] // used in tests
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
