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
