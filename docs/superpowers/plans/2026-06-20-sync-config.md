# `clipmesh --sync-config` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a one-shot `clipmesh --sync-config` CLI action that rewrites the config file so it contains every known option with its explanatory comments, preserving the user's active settings (set options stay active with their values; the rest are added as commented defaults).

**Architecture:** A new `src/config_template.rs` module holds an ordered, in-code canonical template (`Block` list) of every option plus its comment and default, a `render` function that emits the file from the template overlaid with the user's values, an `extract_values` helper that reads the user's present keys/values from a `toml_edit` parse, and `sync_config` which validates → extracts → renders → writes-if-changed. `examples/config.toml` is generated from the same template and locked by a golden test, so the example and the normalizer can't drift. `main.rs` gains a `CliAction::SyncConfig` arm.

**Tech Stack:** Rust, `toml_edit` 0.22 (already a dep), `anyhow`, the existing `crate::config::Config`.

## Global Constraints

- MSRV Rust 1.80 (`Cargo.toml` `rust-version`); no new dependencies (`toml_edit`, `anyhow` already present).
- CI gates must stay green: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.
- Commit as `Thomas Matthijs <selckin@selckin.be>` (repo-local git config; do not change it).
- Tests run headless (no live Wayland/network): use in-memory strings and `tempfile` for paths.
- The spec is `docs/superpowers/specs/2026-06-20-sync-config-design.md` — read it before starting.
- `--sync-config` only ever normalizes a config that already loads via `Config::load`; a config that doesn't parse (or has an unknown key) errors and the file is left untouched.

---

## File Structure

- **`src/config_template.rs` (new):** `Block`, `render`, `push_comment`/`push_block` helpers, `Values`, `extract_values`, `canonical_value`/`canonical`, `TEMPLATE`, `example_values`, `render_example`, `sync_config`, `SyncOutcome`, and all unit tests. One responsibility: the canonical config template and its rendering/normalization.
- **`src/lib.rs` (modify):** add `pub mod config_template;`.
- **`src/main.rs` (modify):** add `CliAction::SyncConfig`, parse `--sync-config`, dispatch to `config_template::sync_config`, update `USAGE`.
- **`examples/config.toml` (regenerate):** becomes the output of `render_example()`, locked by a golden test.
- **`README.md` (modify):** document `--sync-config` and the live-daemon-restart note.

---

## Task 1: Rendering engine — `Block`, `render`, Prose/Required/Optional

**Files:**
- Create: `src/config_template.rs`
- Modify: `src/lib.rs` (add `pub mod config_template;`)
- Test: in `src/config_template.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Produces: `enum Block { Prose(&'static str), Required { key, comment, sample }, Optional { key, comment, default }, PskGroup { comment }, LinkSelections { comment } }` (all `&'static str` fields); `struct Values { scalars: HashMap<String, String>, link: Option<(bool, bool)> }`; `fn render(template: &[Block], values: &Values) -> String`. Later tasks add `PskGroup`/`LinkSelections` rendering, `extract_values`, `TEMPLATE`, `sync_config`.

- [ ] **Step 1: Add the module to the library**

In `src/lib.rs`, add alongside the other `pub mod` lines:

```rust
pub mod config_template;
```

- [ ] **Step 2: Write the failing test**

Create `src/config_template.rs` with the types and a test (the `render` body is a stub so it compiles and the test fails on the assertion):

```rust
//! The canonical config-file template and the `--sync-config` normalizer.
//!
//! One ordered list of `Block`s describes every option, its comment, and its
//! default. `render` emits the file from that template, overlaying the user's
//! present values: options the user set are active with their values; the rest
//! are commented defaults. `examples/config.toml` is generated from the same
//! template (golden test), so the example and the normalizer can't drift.

use std::collections::HashMap;

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
        Block::Required { key, comment, sample } => {
            push_comment(comment, out);
            let v = values.scalars.get(*key).map(String::as_str).unwrap_or(sample);
            out.push_str(&format!("{key} = {v}\n"));
        }
        Block::Optional { key, comment, default } => {
            push_comment(comment, out);
            match values.scalars.get(*key) {
                Some(v) => out.push_str(&format!("{key} = {v}\n")),
                None => out.push_str(&format!("# {key} = {default}\n")),
            }
        }
        // PskGroup and LinkSelections rendering added in Task 2.
        Block::PskGroup { .. } | Block::LinkSelections { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vals(pairs: &[(&str, &str)]) -> Values {
        Values {
            scalars: pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
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
}
```

- [ ] **Step 3: Run the test to verify it passes** (the engine is already written; this confirms the layout)

Run: `cargo test --lib config_template::tests::renders_prose_required_and_optional`
Expected: PASS. If it fails, fix `render`/`push_block` until the exact string matches (watch the trailing-newline trim and the blank line between blocks).

- [ ] **Step 4: Confirm the crate builds clean**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: no warnings. (`PskGroup`/`LinkSelections` arms are intentionally empty until Task 2; the `_` match arm prevents non-exhaustive errors. If clippy flags the empty arms, allow it with a `// filled in Task 2` comment — do not delete the variants.)

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs src/config_template.rs
git commit -m "feat(config): rendering engine for the config template (prose/required/optional)"
```

---

## Task 2: Render the psk group and the `[link_selections]` table

**Files:**
- Modify: `src/config_template.rs`
- Test: same file

**Interfaces:**
- Consumes: `Block`, `Values`, `render` from Task 1.
- Produces: completed `push_block` (PskGroup + LinkSelections); `const PSK_SAMPLES: [(&str, &str); 3]`.

- [ ] **Step 1: Write the failing tests**

Add to `mod tests`:

```rust
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
        let v = Values { link: Some((true, false)), ..Values::default() };
        let out = render(template, &v);
        assert_eq!(
            out,
            "# link\n\
             [link_selections]\n\
             clipboard_to_selection = true\n\
             selection_to_clipboard = false\n"
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib config_template::tests::link_selections_present_actives_both_keys`
Expected: FAIL (the `PskGroup`/`LinkSelections` arms render nothing yet).

- [ ] **Step 3: Implement the two arms**

In `src/config_template.rs`, add the psk sample table near the top:

```rust
/// psk source keys in canonical order, with the sample shown when commented.
const PSK_SAMPLES: [(&str, &str); 3] = [
    ("psk_file", "\"~/.config/clipmesh/psk\""),
    ("psk", "\"supersecret\""),
    ("psk_env", "\"CLIPMESH_PSK\""),
];
```

Replace the empty `Block::PskGroup { .. } | Block::LinkSelections { .. } => {}` arm with:

```rust
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
```

Note for the psk test sample: the `psk_file` sample in `PSK_SAMPLES` is `"~/.config/clipmesh/psk"`, but the test `psk_group_actives_the_users_source_only` uses the user's value `"/k"`, so the active line shows `"/k"` and only the inactive `psk`/`psk_env` show samples — re-read the expected string in Step 1; it does not reference the psk_file sample.

- [ ] **Step 4: Run all module tests**

Run: `cargo test --lib config_template`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/config_template.rs
git commit -m "feat(config): render the psk group and [link_selections] table"
```

---

## Task 3: Extract the user's present values from their config text

**Files:**
- Modify: `src/config_template.rs`
- Test: same file

**Interfaces:**
- Consumes: `Values` from Task 1.
- Produces: `fn extract_values(text: &str) -> anyhow::Result<Values>`; `fn canonical(value: &toml_edit::Value) -> String`.

- [ ] **Step 1: Write the failing test**

Add to `mod tests`:

```rust
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
        assert!(v.scalars.get("link_selections").is_none());
        // absent table key defaults to false
        assert_eq!(v.link, Some((true, false)));
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib config_template::tests::extract_collects_present_keys_decor_stripped`
Expected: FAIL with "cannot find function `extract_values`".

- [ ] **Step 3: Implement `extract_values` and `canonical`**

Add to `src/config_template.rs` (top-level), with the imports:

```rust
use anyhow::{Context, Result};
use toml_edit::{Decor, DocumentMut, Item, Value};
```

```rust
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
    let link = doc.get("link_selections").and_then(Item::as_table).map(|t| {
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
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test --lib config_template::tests::extract_collects_present_keys_decor_stripped`
Expected: PASS. (If the `peers` assertion fails because inner array elements keep decor, confirm `canonical` recurses per element — it does via `arr.iter().map(canonical)`.)

- [ ] **Step 5: Commit**

```bash
git add src/config_template.rs
git commit -m "feat(config): extract present values from a config (decor-stripped)"
```

---

## Task 4: The real `TEMPLATE`, the generated example, and the golden + round-trip tests

**Files:**
- Modify: `src/config_template.rs` (add `TEMPLATE`, `example_values`, `render_example`)
- Regenerate: `examples/config.toml`
- Test: same module

**Interfaces:**
- Consumes: `Block`, `render`, `Values` from Tasks 1–2.
- Produces: `const TEMPLATE: &[Block]`; `fn example_values() -> Values`; `pub fn render_example() -> String`.

- [ ] **Step 1: Write the `TEMPLATE`, `example_values`, and `render_example`**

Add to `src/config_template.rs`. The `comment` text for each option is that option's comment block from the current `examples/config.toml` — transcribe each verbatim (single-line for short ones; for the long prose of `synthesize_text_plain`, `take_ownership`, `mime_rules_file`, `share_mime_rules`, and `link_selections`, copy the exact paragraph(s) from `examples/config.toml` into the raw string). Order and defaults are fixed as below:

```rust
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
        // Copy the share_mime_rules paragraph from the current examples/config.toml.
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
        // Copy the synthesize_text_plain paragraph from examples/config.toml verbatim.
        comment: "When a copied selection offers only a legacy X11 plain-text atom\n\
                  (UTF8_STRING/STRING/TEXT) and no text/plain* rep, synthesize\n\
                  text/plain;charset=utf-8 and text/plain from it so Wayland-native apps\n\
                  can paste it. The synthesized types go through the MIME rules below.",
        default: "false",
    },
    Block::Optional {
        key: "take_ownership",
        // Copy the take_ownership paragraph from examples/config.toml verbatim.
        comment: "After a local copy, re-offer the selection so clipmesh owns it: the\n\
                  clipboard then survives the source app exiting, and (with\n\
                  synthesize_text_plain) X11-sourced content pastes on THIS host too. Never\n\
                  re-owns password-manager-flagged content while exclude_sensitive is on.",
        default: "false",
    },
    Block::Optional {
        key: "mime_rules_file",
        // Copy the mime_rules_file / [rules] explanation from examples/config.toml.
        comment: "Per-type allow/deny rules file (TOML). Defaults to \"mimetypes\" beside\n\
                  this config. clipmesh creates it, appends any new type it sees (per\n\
                  unknown_mime), keeps it sorted, and reloads on change. Edit it or run\n\
                  `clipmesh --allow/--deny \"<glob>\"` (and `clipmesh --rules` to list).",
        default: "\"~/.config/clipmesh/mimetypes\"",
    },
    Block::LinkSelections {
        // Copy the link_selections block + WARNING from examples/config.toml.
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
    Values { scalars, link: None }
}

/// The shipped `examples/config.toml` content, generated from `TEMPLATE`.
pub fn render_example() -> String {
    render(TEMPLATE, &example_values())
}
```

- [ ] **Step 2: Write the round-trip test (template renders a loadable config)**

Add to `mod tests`:

```rust
    #[test]
    fn rendered_example_is_a_valid_config() {
        // The generated example must parse and load as a real config (the psk
        // path won't be read by from_toml only; use from_toml which derives psk
        // from the inline value path string — here we just check it parses).
        let text = render_example();
        // every option key appears exactly once
        for key in [
            "listen", "port", "peers", "max_payload_size", "debounce_ms",
            "sync_selection", "direction", "exclude_sensitive", "resync_on_connect",
            "share_mime_rules", "verbose", "log_level", "unknown_mime",
            "synthesize_text_plain", "take_ownership", "mime_rules_file",
        ] {
            assert_eq!(text.matches(&format!("{key} ")).count() >= 1, true, "missing {key}");
        }
        // the [link_selections] table is present (commented) and last
        assert!(text.contains("# [link_selections]"));
        assert!(text.trim_end().ends_with("# selection_to_clipboard = false"));
        // re-rendering the example through extract+render is a no-op (idempotent)
        let again = render(TEMPLATE, &extract_values(&text).unwrap());
        // NOTE: the example has psk_file/listen/etc active, which extract picks
        // up, so `again` must equal `text`.
        assert_eq!(again, text, "render is not idempotent on the example");
    }
```

- [ ] **Step 3: Run the round-trip test**

Run: `cargo test --lib config_template::tests::rendered_example_is_a_valid_config`
Expected: PASS. If the idempotence assertion fails, the most likely cause is a value-formatting mismatch between `example_values` literals and `canonical`'s output (e.g. array spacing) — make the `example_values` literals match `canonical`'s canonical form (`["host-b", "host-c"]` with `, ` separators).

- [ ] **Step 4: Write the golden test with a regenerate escape hatch**

Add to `mod tests`:

```rust
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
```

- [ ] **Step 5: Run it (expected to fail — the committed example differs)**

Run: `cargo test --lib config_template::tests::example_config_matches_template`
Expected: FAIL (the current hand-written `examples/config.toml` differs from the canonical render).

- [ ] **Step 6: Regenerate the example, then review it**

Run: `CLIPMESH_REGEN_EXAMPLE=1 cargo test --lib config_template::tests::example_config_matches_template`
Then inspect the diff:

Run: `git diff examples/config.toml`
Expected: the file is now the canonical render — every option present (commented defaults), all comments, `[link_selections]` last. Read it top-to-bottom: confirm it is valid, readable TOML and that the long prose blocks you transcribed read correctly. Tighten any `comment` string in `TEMPLATE` if the wording is off, then re-run Step 6 to regenerate.

- [ ] **Step 7: Verify the golden test now passes and the whole suite is green**

Run: `cargo test --lib config_template`
Expected: PASS (all module tests). Then `cargo test` — Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add src/config_template.rs examples/config.toml
git commit -m "feat(config): canonical config TEMPLATE; generate examples/config.toml from it"
```

---

## Task 5: `sync_config` + the `--sync-config` CLI action

**Files:**
- Modify: `src/config_template.rs` (add `sync_config`, `SyncOutcome`, `write_atomic`)
- Modify: `src/main.rs` (add `CliAction::SyncConfig`, parse flag, dispatch, update `USAGE`)
- Test: `src/config_template.rs` (unit tests over temp files)

**Interfaces:**
- Consumes: `TEMPLATE`, `render`, `extract_values`, `crate::config::Config`.
- Produces: `pub fn sync_config(path: &std::path::Path) -> anyhow::Result<SyncOutcome>`; `pub enum SyncOutcome { Unchanged, Rewrote { added: Vec<String> } }`.

- [ ] **Step 1: Write the failing tests**

Add a new test using `tempfile` (already a dev-dependency — confirm with `grep tempfile Cargo.toml`; it is used by `config.rs` tests):

```rust
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
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib config_template::tests::sync_config_adds_missing_keeps_set_and_is_idempotent`
Expected: FAIL with "cannot find function `sync_config`".

- [ ] **Step 3: Implement `sync_config`, `SyncOutcome`, `write_atomic`**

Add to `src/config_template.rs` (add `use std::path::Path;` and `use crate::config::Config;` to the imports):

```rust
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
    // 1. Validate. A config we can't load is left untouched.
    Config::load(path).context("the config must load before --sync-config can normalize it")?;
    // 2. Read raw values from the user's file.
    let current = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
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
/// so a crash mid-write can't truncate the live config.
fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("config.toml");
    let tmp = dir.join(format!(".{name}.sync-config.tmp"));
    std::fs::write(&tmp, contents).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}
```

- [ ] **Step 4: Run the module tests**

Run: `cargo test --lib config_template`
Expected: PASS (all tests, including the two new ones).

- [ ] **Step 5: Wire the CLI in `main.rs`**

In `src/main.rs`: add the import `use clipmesh::config_template;` near the other `clipmesh::` imports. Extend the `CliAction` enum:

```rust
enum CliAction {
    Edit { allow: bool, pattern: String },
    PrintRules,
    SyncConfig,
}
```

Update `USAGE`:

```rust
const USAGE: &str =
    "usage: clipmesh [--config <path>] [--allow <glob> | --deny <glob> | --rules | --sync-config]";
```

In the arg-parsing `match`, add `--sync-config` to the mutually-exclusive guard and a new arm (place the guard line alongside the existing one and the arm next to `--rules`):

```rust
            "--allow" | "--deny" | "--rules" | "--sync-config" if action.is_some() => bail!(USAGE),
            // ... existing --allow/--deny and --rules arms ...
            "--sync-config" => action = Some(CliAction::SyncConfig),
```

In the action dispatch `match` (where `PrintRules` returns `print_rules(...)`), add:

```rust
        Some(CliAction::SyncConfig) => return sync_config_action(&config_path),
```

Add the handler function near `print_rules` (it resolves the default config path the same way the daemon does):

```rust
/// Normalize the config file (fill in missing options + comments) and exit.
fn sync_config_action(config_path: &Path) -> Result<()> {
    let path = config_path.to_path_buf();
    match config_template::sync_config(&path)? {
        config_template::SyncOutcome::Unchanged => {
            println!("config {} is already up to date", path.display());
        }
        config_template::SyncOutcome::Rewrote { added } => {
            if added.is_empty() {
                println!("refreshed comments in {}", path.display());
            } else {
                println!(
                    "wrote {} ({} option(s) added as commented defaults: {})",
                    path.display(),
                    added.len(),
                    added.join(", ")
                );
            }
        }
    }
    Ok(())
}
```

Confirm how `config_path` is resolved for the existing actions (the default `~/.config/clipmesh/config.toml` is filled in before dispatch around `src/main.rs:40-45`); `sync_config_action` must receive the same resolved `&Path` the other actions get. If the existing actions take `&Path`, match that signature exactly.

- [ ] **Step 6: Build and lint**

Run: `cargo build && cargo clippy --all-targets -- -D warnings`
Expected: clean. Fix any signature mismatch on `config_path` (it should be the already-defaulted path used by `--rules`).

- [ ] **Step 7: Manual smoke test**

```bash
mkdir -p /tmp/cm && printf 'listen = "x"\npsk = "s"\n' > /tmp/cm/config.toml
cargo run -- --config /tmp/cm/config.toml --sync-config
cat /tmp/cm/config.toml   # every option present; listen/psk active; rest commented
cargo run -- --config /tmp/cm/config.toml --sync-config   # prints "already up to date"
```

Expected: first run rewrites and lists added options; second run reports no change; the file loads (`cargo run -- --config /tmp/cm/config.toml` would start the daemon — Ctrl-C it).

- [ ] **Step 8: Full gates + commit**

Run: `cargo fmt && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: all green.

```bash
git add src/config_template.rs src/main.rs
git commit -m "feat(config): add the clipmesh --sync-config CLI action"
```

---

## Task 6: Document `--sync-config` in the README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add the documentation**

In `README.md`, under the Configuration section (near where one-shot flags / the config file are described — around the `## Configuration` heading, `README.md:72`), add:

```markdown
### Keeping the config up to date

`clipmesh --sync-config` rewrites your `config.toml` so it lists every option
with its documentation: options you've set stay active with your values, and
any option you haven't set is added as a commented default. Run it after
upgrading to discover new options. It only normalizes a config that already
loads — a config that doesn't parse is left untouched.

Note: if the daemon is running while you do this, the config-file change makes
it restart (to re-read the config). The restart is harmless — only comments and
commented-out defaults changed, so the effective configuration is identical.
```

- [ ] **Step 2: Verify the flag is also listed in usage**

Confirm the `USAGE` string update from Task 5 is present (`grep -n 'sync-config' src/main.rs`). Expected: the usage line includes `--sync-config`.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document clipmesh --sync-config"
```

---

## Self-Review

**Spec coverage:**
- One-shot `--sync-config` flag, mutually exclusive, `--config` honored → Task 5. ✓
- Validate-then-write, never clobber an unloadable config → Task 5 (`sync_config` + `sync_config_refuses_an_unloadable_config`). ✓
- Values read verbatim/decor-stripped from `toml_edit`; arrays normalized → Task 3. ✓
- Canonical schema in code (`Block`/`TEMPLATE`) → Tasks 1, 4. ✓
- psk group (one active) and `[link_selections]` (absent→fully commented, present→both keys active, last) → Tasks 2, 4. ✓
- Idempotent; write-if-changed → Task 5. ✓
- `examples/config.toml` generated + golden drift test → Task 4. ✓
- Atomic write → Task 5 (`write_atomic`). ✓
- README incl. live-daemon-restart note → Task 6. ✓
- Non-goal (no migration): an unknown/old key errors at validate → Task 5 test. ✓

**Placeholder scan:** The `comment` strings for the five long-prose options in Task 4 say "copy the exact paragraph from `examples/config.toml`" — this is concrete (a committed file), and Step 6 (regenerate + read the diff) verifies the result; not a TBD. All code steps contain complete code.

**Type consistency:** `Values { scalars: HashMap<String, String>, link: Option<(bool, bool)> }`, `render(&[Block], &Values) -> String`, `extract_values(&str) -> Result<Values>`, `sync_config(&Path) -> Result<SyncOutcome>`, `SyncOutcome::{Unchanged, Rewrote{added: Vec<String>}}` are used consistently across tasks. `canonical` is `fn(&Value) -> String` throughout.
