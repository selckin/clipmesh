# clipmesh — `--sync-config`: self-documenting config normalization

**Date:** 2026-06-20
**Status:** Approved design

## Summary

Add a one-shot CLI action, `clipmesh --sync-config`, that rewrites the config
file so it contains **every** known option together with its explanatory
comments, while preserving the user's active settings. Options the user has set
stay active with their exact values; every option the user has *not* set is
added as a commented default. The canonical option list, ordering, comments, and
defaults live in one place in code (a config "template"), from which both
`--sync-config` and the shipped `examples/config.toml` are produced — so the two
can never drift.

This is for a user who, after upgrading clipmesh (new options added) or while
learning the config, wants their own `config.toml` to show all available options
and their documentation without hand-copying from the example.

## Motivation

The config surface grows over time (recent additions: `synthesize_text_plain`,
`take_ownership`, the `[link_selections]` table). A user's hand-written config
quickly lags the documented `examples/config.toml`, and there is no way to learn
"what options exist now" from one's own file. clipmesh already program-manages
the *MIME-rules* file (`mime.rs`: append unseen types, keep comments, atomic
persist); `--sync-config` brings the same "managed, self-documenting file"
treatment to the main config, on explicit demand.

## Non-goals (YAGNI)

- **Automatic rewriting.** `--sync-config` is one-shot and explicit. The daemon
  never rewrites the config on its own, so it never interacts with the
  `fswatch` config-change → restart path.
- **Key migration / aliasing.** A config containing an unknown or renamed key
  (e.g. the pre-rename `sync_primary`) fails the validation step and is left
  untouched, rather than being auto-migrated. Migration is a separate feature.
- **Preserving the user's ordering or custom comments.** Output is regenerated
  in canonical order with canonical comments. A user's bespoke comments or key
  order are not preserved (explicitly chosen in design).
- **Multi-file configs or a config-schema versioning scheme.** Out of scope.

## Architecture

One new module, `src/config_template.rs`, plus a new `CliAction` arm in
`src/main.rs`. `config.rs` is unchanged except possibly to expose what the
template needs. The transport/protocol/engine/mime layers are untouched.

### The canonical template (single source of truth)

An ordered list of blocks describing the whole config file, in file order:

```rust
/// One block of the canonical config file, in render order.
enum Block {
    /// Free prose not tied to a key (e.g. the file header). Rendered as
    /// `# `-prefixed comment lines only.
    Prose(&'static str),
    /// A required scalar (no usable default): always emitted active. `sample`
    /// is the illustrative value used when generating `examples/config.toml`;
    /// for a real config the user's own raw value is used instead.
    Required { key: &'static str, comment: &'static str, sample: &'static str },
    /// An optional scalar: emitted active with the user's raw value when the
    /// key is present in their file, otherwise as `# key = default`.
    Optional { key: &'static str, comment: &'static str, default: &'static str },
    /// The psk source group. Exactly one of `psk_file` / `psk` / `psk_env` is
    /// active (whichever the user has); the others are commented samples.
    PskGroup { comment: &'static str },
    /// The `[link_selections]` table. Always rendered LAST (a TOML table header
    /// captures every key below it). When present in the user's file: an active
    /// `[link_selections]` header with BOTH keys active (an omitted key filled
    /// with its `false` default). When absent: the whole block commented,
    /// header included (`# [link_selections]`).
    LinkSelections { comment: &'static str },
}

const TEMPLATE: &[Block] = &[ /* header Prose, listen, port, peers, PskGroup,
    max_payload_size, debounce_ms, sync_selection, direction, exclude_sensitive,
    resync_on_connect, share_mime_rules, verbose, log_level, unknown_mime,
    synthesize_text_plain, take_ownership, mime_rules_file, LinkSelections */ ];
```

`default`/`sample` strings are the literal TOML right-hand side (e.g. `"100"`,
`"\"32MiB\""`, `"false"`, `"[\"host-b\", \"host-c\"]"`). They are the value shown
in **commented form**; for an option whose real default is computed at load
(e.g. `mime_rules_file`, which defaults to `mimetypes` beside the config),
`default` is an illustrative value, not the literal runtime default. Comments
are multi-line string literals; the renderer prefixes each line with `# `.

### Rendering

`render(template, values) -> String` where `values` is the set of present
top-level keys and their raw TOML value text (and the `[link_selections]`
booleans). Layout is fixed: for each block, emit its comment lines, then the
option line(s), then one blank line. Concretely per block:

- **Prose** → the comment lines only.
- **Required `key`** → comment, then `key = <user raw value, or sample>`.
- **Optional `key`** → comment, then `key = <user raw value>` if the key is
  present, else `# key = <default>`.
- **PskGroup** → comment, then for `psk_file`, `psk`, `psk_env` in that order:
  `key = <user raw value>` if present, else `# key = <sample>`.
- **LinkSelections** → comment, then the table. If the user has a
  `[link_selections]` table, emit an active header with BOTH keys active
  (`clipboard_to_selection = <bool>`), filling any key the user omitted with
  `false` — never a commented key under an active header. If the table is absent
  entirely, comment the whole block including the header (`# [link_selections]`,
  `# clipboard_to_selection = false`, `# selection_to_clipboard = false`).

Rendering is deterministic, so `render` is idempotent: `render(render(x)) ==
render(x)`.

### `examples/config.toml` is generated

The shipped example is `render(TEMPLATE, SAMPLE)` for a small fixed `SAMPLE`
(`listen`, `port`, `peers`, `psk_file` set to the illustrative values currently
in the example; everything else absent). A unit test asserts the committed
`examples/config.toml` equals that rendering. Changing the template fails the
test until the example is regenerated. **The committed example will be
regenerated to the renderer's canonical formatting on first implementation;
minor cosmetic differences (blank-line spacing, comment wrapping) from today's
hand-formatted file are expected and accepted.**

### `--sync-config` flow (`main.rs`)

A new `CliAction::SyncConfig`, dispatched like the other one-shot actions
(`--allow`/`--deny`/`--rules`): mutually exclusive with them, honors `--config
<path>`, applies and returns (never starts the daemon). Steps:

1. **Validate.** `Config::load(path)` must succeed. If it errors (unparseable,
   unknown key, missing/oversized psk, etc.), print the error and write nothing
   — never clobber a config we can't load (same safety as `--allow`/`--deny`).
2. **Read raw values.** Parse the file text into a `toml_edit::DocumentMut` and
   collect present top-level keys → their value, plus the `[link_selections]`
   booleans. Using the raw doc (not the resolved `Config`) preserves the user's
   exact value forms (e.g. `"8MiB"` stays `"8MiB"`, not re-rendered as bytes).
   The value is taken **decor-stripped** — the canonical value only, dropping the
   user's surrounding whitespace and any inline trailing comment — so the output
   is canonical and idempotent. Consequently inline comments and bespoke value
   formatting (e.g. a multi-line `peers` array) are normalized away, consistent
   with not preserving custom comments.
3. **Render** the normalized text from `TEMPLATE` + those values.
4. **Write if changed.** If the rendered text equals the current file content,
   print "config already up to date" and exit without writing (idempotent; no
   mtime churn). Otherwise atomically write (temp file + rename, mirroring
   `mime.rs::persist`) and print a summary: the options added (commented
   defaults) and that comments were refreshed.

**Running while a daemon is live (accepted).** `fswatch` decides restarts by
comparing the config file's **raw text** (`config_change_action`,
`src/fswatch.rs:482-505`), so a *separately running* daemon watching the same
file **will restart** when `--sync-config` rewrites it — even though only
comments and commented defaults changed (no behavioral change). Accepted as
harmless: a clean exit → supervisor restart → re-handshake/re-prime, with an
identical effective config. Documented in the README so it isn't a surprise. (A
semantic parse-and-compare restart check in `fswatch` would avoid the bounce but
is out of scope for this feature.)

## Error handling

- Config fails to load → error to stderr, exit non-zero, file untouched.
- Write/rename failure → error, original file intact (atomic rename).
- `--config` path doesn't exist → `Config::load`'s existing error (it does not
  create a config from nothing; `--sync-config` normalizes an existing file).
- psk source: validation goes through `Config::load`, which resolves the psk
  (reads `psk_file`/`psk_env`). A missing psk file therefore errors. Accepted:
  `--sync-config` only normalizes a config that already loads.

## Testing

Unit tests in `config_template.rs` (mock paths / in-memory strings; no live
Wayland or network):

- **Adds missing, keeps set:** a partial config (a few options set) renders with
  those active and carrying the user's values, every other option present as a
  commented default, all comment blocks present, `[link_selections]` last.
- **Round-trip:** the rendered output re-parses via `Config::from_toml` to the
  same `Config` as the input.
- **Verbatim values:** `max_payload_size = "8MiB"` and a custom `peers` array
  survive unchanged; the active psk source is the one the user had.
- **Idempotence:** `render(render(x)) == render(x)`.
- **Example drift:** committed `examples/config.toml` == `render(TEMPLATE,
  SAMPLE)`.
- **`[link_selections]`:** absent table → whole block commented (header
  included); present table → active header with both keys active (user's
  booleans, an omitted key filled with `false`), placed last.
- **Validation gate (`main.rs`-level or a thin helper):** an unparseable or
  unknown-key config is rejected and the file is not rewritten.

CI gates (`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`) apply
as usual.

## File-by-file changes

- **`src/config_template.rs` (new):** `Block`, `TEMPLATE`, `SAMPLE`, the
  `render` function, the raw-value extraction helper, and the unit tests.
- **`src/main.rs`:** add `CliAction::SyncConfig`, parse `--sync-config`, dispatch
  to a `sync_config(&config_path)` function, update `USAGE`.
- **`src/lib.rs`:** expose the new module if `main.rs` needs it (`pub mod
  config_template;`).
- **`examples/config.toml`:** regenerated to canonical form (locked by the drift
  test).
- **`README.md`:** document `--sync-config` under the one-shot-flags /
  configuration section, including the note that running it while a daemon is
  live restarts that daemon (harmless, comment-only change).
