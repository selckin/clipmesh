# clipmesh — symlink-aware config/rules watching

**Date:** 2026-06-14
**Status:** Approved design

## Summary

Make `src/fswatch.rs` follow symlinks so that edits to a `config.toml`
or `mimetypes` file reached through a symlink (the common dotfiles-repo
setup: `~/.config/clipmesh/config.toml` → `~/dotfiles/.../config.toml`)
are actually detected. Today the watcher watches the **parent directory**
of each path and matches events by file name; when the path is a symlink,
real edits land in the *target's* directory, which isn't watched, so they
are silently missed.

The watcher gains a second watch per file — the symlink's **target site**
— and self-heals when a symlink is repointed, re-linked, or repaired.
Startup also gains a specific diagnostic when a config/rules path is a
broken symlink. Reads and writes already follow symlinks correctly
(`fs::read_to_string` / `fs::write`); only *watching* changes.

## Motivation

- `fswatch::run` watches `watch_dir(path)` (the parent) and dispatches on
  `event.name`. For an individual-file symlink, the file's directory entry
  never changes on an edit — the bytes change in the *target's* directory
  — so no event fires in the watched directory and the edit is lost. This
  defeats both the config auto-restart and the live MIME-rule reload for
  anyone who symlinks these files from a dotfiles repo.
- A broken config symlink fails startup with a generic "reading config"
  error; under `systemd Restart=always` that becomes an unexplained
  restart loop. The journal should say *why*.

## Non-goals (YAGNI)

- Symlinked **directories** (`~/.config/clipmesh` → dotfiles dir). inotify
  already follows the directory symlink when the watch is added, so
  in-place edits there are caught today. Not in scope.
- Changing how the files are **read or written**. `fs::read_to_string` and
  `fs::write` already follow symlinks (a write updates the target in place,
  preserving the link). Unchanged.
- Watching arbitrary deep symlink graphs. Resolution follows a small,
  bounded number of hops (covering a single stow/chezmoi indirection or a
  short chain) and otherwise treats the link as unresolved/broken.

## Architecture

All changes are in `src/fswatch.rs`, plus two small diagnostic additions
in `src/config.rs` and `src/mime.rs`. The watcher's reconnect loop
(`watch_forever`), the config-change decision (`config_change_action` /
`restart_on_config_change`), and the rules-reload/ping path are unchanged;
only how `run` sets up and dispatches watches changes.

### Governing rule

**Content is read only on `CLOSE_WRITE` / `MOVED_TO`, never on a regular
file's `CREATE`.** This preserves today's deliberate behavior — reacting to
`CREATE` would read a file an editor has created but not yet written, i.e.
empty/partial. `CREATE` is used for exactly one purpose: repairing the
watch topology when a **symlink** appears or is repointed. Acting on such a
`CREATE` reads *through* the symlink to its target — a pre-existing file —
never the just-created directory entry (a symlink is created atomically and
has no content of its own).

### Two watch sites per file

For each watched file (`config.toml`, and `mimetypes` when set) resolution
produces up to two watch entries:

- **Link site** — always present: `dir = watch_dir(path)`, `name =
  file_name(path)`. This is exactly today's watch. It catches the entry at
  the path being created, atomically renamed into place, or — for a symlink
  — (re)created / repointed.
- **Target site** — only when `path` is a symlink: follow the link to its
  intended target, then watch the target's **parent directory**, with `name
  = file_name(target)`. Two correctness points:
  - **Relative targets resolve against the symlink's own directory, not the
    CWD.** `read_link` commonly returns a relative path — GNU Stow's default
    is a relative link (`config.toml -> ../../dotfiles/clipmesh/config.toml`)
    — which must be joined onto the symlink's parent before use. Resolution
    follows a small, bounded number of hops, joining each relative hop
    against its link's directory (covering a single stow/chezmoi indirection
    or a short chain). `canonicalize` does this for a healthy link; the
    bounded manual walk is the fallback when a component is missing.
  - The target's **directory** only needs to *exist* — the target file
    itself may be currently absent. We still add the target entry and watch
    the directory, so a target deleted-then-recreated self-heals; this is
    logged softly ("target `<t>` missing; will pick it up when created").
- **No target entry** — when the resolved target's **directory** does not
  exist (or the link can't be resolved at all): no target entry is added; it
  is logged as a hard "broken symlink" and recovered later via the link-site
  watch when the link is re-pointed. ("Broken" in the startup diagnostics
  below is the narrower, file-level sense: the link resolves but the *file*
  can't be read.)

A non-symlink file yields only a link entry — byte-for-byte today's
behavior.

### Watch table and dispatch

The `config_name` / `rules_name` name compares are replaced by a small
table:

```rust
enum Target { Config, Rules }
enum Site   { Link, Target }
struct Entry { target: Target, site: Site, dir: PathBuf, name: OsString, wd: WatchDescriptor }
```

Each distinct directory is added once; its mask is the **union** of its
entries' needs (`inotify_add_watch` replaces rather than ORs a mask, so the
union is computed before adding). Equal directories dedup to the same `wd`
at the kernel, and entries are matched by `(event.wd, event.name)`, which
disambiguates two files sharing a directory.

Masks:

- **Link-site directories:** `CLOSE_WRITE | MOVED_TO | CREATE`. `CREATE` is
  required to notice a symlink created by `symlink(2)` (e.g. `stow`'s
  `ln -sf`), which emits neither `CLOSE_WRITE` (no fd write) nor `MOVED_TO`
  (no rename).
- **Target-site directories:** `CLOSE_WRITE | MOVED_TO` (today's mask, no
  `CREATE`). The real files you edit live here; never adding `CREATE` to
  their mask removes the empty-file race structurally. An edit always ends
  in `CLOSE_WRITE` (in-place) or `MOVED_TO` (atomic save).

Per-event handling (match `(event.wd, event.name)` against the table):

- **`CLOSE_WRITE` / `MOVED_TO`** → mark the entry's `Target` changed. If the
  matched entry is a **Link** site, also flag that `Target` for
  re-resolution (the symlink may have been replaced/repointed).
- **`CREATE`** → ignored **unless the named path is, at handle time, a
  symlink** (`symlink_metadata().is_symlink()`). For a symlink it flags the
  `Target` for re-resolution and marks it changed (the content check then
  reads through the link to the now-current target). For a regular file it
  is ignored — identical to today, so an editor's create-then-write is read
  only at the subsequent `CLOSE_WRITE`.
- **`Q_OVERFLOW`** → mark both targets changed and re-resolve both, as today
  (the reload is idempotent and the config check only restarts on a real,
  parseable content change).

After each event batch:

1. For each `Target` flagged for re-resolution, recompute its resolution.
   Only the **target-site** entry can change (the link-site entry's path is
   fixed): add a watch for the new target directory if not already watched,
   remove the now-unreferenced old `wd` (skipping any `wd` still referenced
   by another entry), and replace the entry. `remove` errors are ignored —
   the kernel auto-removes a watch on a deleted directory (`IN_IGNORED`), so
   a later `remove(wd)` for it returns `EINVAL` and is expected. A symlink
   that became broken drops its target entry with a warning.
2. If rules changed → `reload_if_changed()`; ping the engine only when it
   reports a real external change (the existing loop-prevention guard).
3. If config changed → `on_config_change()` (re-reads through the symlink;
   restarts only when content differs and still parses).

Because the apply path is content-diff based, a repoint to identical
content is a no-op, an unparseable config keeps the daemon running, and the
narrow case of a symlink created while its target is mid-write cannot cause
a spurious restart or a bad rule load.

The existing loop-prevention also still holds under the two-site model.
clipmesh's own rules writes land in the **target's** directory, so the
resulting event arrives on the target-site watch rather than the link-site
one — but the write records the bytes it wrote in `self.loaded`, so
`reload_if_changed()` sees no change and sends no ping. The write location
moved; the guard that prevents a write→reload→rebroadcast loop did not.

> **Updated since this spec:** rules writes now go through
> `fsutil::write_atomic` (temp file in the resolved target's directory, then
> `rename` onto it) rather than `fs::write` following the symlink in place, so
> a crash or full disk can no longer leave a truncated rules file. The event
> that arrives is therefore `MOVED_TO` rather than `CLOSE_WRITE`; both are in
> `target_mask()`, and the `self.loaded` content compare is unchanged, so the
> conclusion above still holds.

### Self-healing scenarios

- **Edit the real file in place** (the everyday case): `CLOSE_WRITE` at the
  target site → reload/restart. The fix.
- **Re-link via stow** (`ln -sf`, `symlink(2)`): `CREATE` at the link site;
  entry is a symlink → re-resolve (repoint the target watch) + content
  check.
- **Repoint to a new target**: as above; the old target `wd` is dropped if
  unreferenced, the new target directory is watched.
- **Target deleted then recreated**: if the target's directory still
  existed, its watch was retained, so the recreate's `CLOSE_WRITE` is
  caught; otherwise recovery comes via the link-site watch when the link is
  re-pointed.
- **Broken at startup**: if the target's directory exists (only the file is
  missing), the target watch is still placed, so creating the file there is
  caught directly; if the directory is missing or the link is unresolvable,
  there is no target entry and recovery comes when the link is repaired
  (link-site `CREATE`/`MOVED_TO`). Both are logged.

## Startup diagnostics

- `Config::load` (`src/config.rs`): when the read fails **and** the path is
  a symlink, return an error naming the broken target — e.g. *"config
  `<path>` is a symlink to `<target>`, which doesn't exist"* — instead of
  the generic "reading config `<path>`". Still fatal (clipmesh can't run
  without a config), but the journal now explains the restart loop.
- `MimeRules::load` (`src/mime.rs`): when the rules path is a broken
  symlink, warn specifically, distinguishing "symlink target missing" from
  "no rules file yet". Behavior is otherwise unchanged (empty ruleset;
  materialized on the next write, which — via `fs::write` following the
  link — recreates the target).

## Testing

Following the existing deadline-loop style in `fswatch.rs` tests (which
re-writes on each iteration so a not-yet-registered watch isn't a flake
source):

- **Resolution helper (unit):** a symlinked file yields link + target
  entries with the expected `(dir, name)`, including a **relative** link
  target resolved against the symlink's own directory; a symlink whose
  target file is absent but whose directory exists still yields a target
  entry (watching that directory); a symlink whose target directory is
  missing yields a link entry only and is flagged broken; a regular file
  yields a link entry only.
- **Target watched (integration):** real file in `target_dir/`, symlink in
  `link_dir/` pointing at it; run `run()`; edit the real file in place and
  assert the rules reload / the engine ping fires. This is the regression
  test for the core bug.
- **Self-heal (integration):** start with a symlink to a not-yet-existing
  target, create the target, and assert a later edit is picked up; and/or
  repoint the symlink A→B and assert edits to B are picked up.
- **No empty-file pickup (integration):** the regression guard for the
  `CREATE`-in-mask change. Creating-and-closing an empty file already fires
  `CLOSE_WRITE`, so the test must isolate the bare `CREATE`: open a new file
  at a watched path and **hold the handle open** (the `CREATE` has fired, no
  close yet), assert no reload/ping/restart is driven, then write + drop the
  handle and assert the reaction arrives only at the `CLOSE_WRITE`.
- **Startup diagnostic (unit):** `Config::load` on a broken symlink returns
  an error mentioning the symlink and its target.

## Risks

- The watch table and re-resolution add bookkeeping to `run()`. Mitigated by
  keeping the apply path (reload/restart decisions) untouched and
  content-diff guarded, and by matching entries on `(wd, name)` so shared
  directories and repoints stay correct.
- inotify cannot watch a directory that does not yet exist, so a symlink
  whose *target directory* is absent only recovers when the link itself is
  re-pointed (a link-site event). Acceptable: the dotfiles directory
  normally exists; only the file moves.
- A directory being deleted out from under a live watch is an existing
  limitation of the watcher (handled by the `watch_forever` reconnect loop),
  unchanged here.
