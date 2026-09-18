//! The `clipmesh history` subcommand: list a node's remembered clipboard
//! contents, print one, or put one back on its clipboard.
//!
//! It talks to a node over the same encrypted protocol `--paste` uses, as a
//! one-shot [`PeerRole::Paster`] — so it needs only the psk from the config, and
//! `--node` points it at a peer's history just as easily as at this host's.
//!
//! [`PeerRole::Paster`]: crate::protocol::PeerRole::Paster

use crate::client;
use crate::config::{self, Config};
use crate::paste;
use crate::protocol::{
    human_bytes, HistoryEntry, HistoryMiss, HistoryRequest, HistoryResult, Message, SelectionKind,
    Unavailable,
};
use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use std::time::Duration;

/// How long to wait for the node's answer. Matches paste mode: a listing is
/// tiny, but a `get` can carry a whole clipboard over a slow link.
const HISTORY_TIMEOUT: Duration = Duration::from_secs(10);

/// How many characters of an entry's hash the listing prints. Short enough to
/// retype, long enough that two entries colliding on it is not something anyone
/// will see.
const ID_CHARS: usize = 8;

const USAGE: &str =
    "usage: clipmesh history list                      (what this node remembers)\n\
     \x20      clipmesh history get <e> [-t <mime>] [-n]  (print one entry)\n\
     \x20      clipmesh history restore <e>               (put it back on the clipboard)\n\
     \x20      ... <e> is a row number or an ID, both from `history list`\n\
     \x20      ... each also taking [--node <host[:port]>] [--config <path>]";

/// What the invocation asks the node to do.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    List,
    /// Print entry `entry` — a row number or an id; the node decides which.
    Get {
        entry: String,
    },
    Restore {
        entry: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistoryArgs {
    command: Command,
    /// Print this exact MIME type (`-t`/`--type`); `None` auto-selects.
    type_: Option<String>,
    /// Suppress the trailing newline for text types (`-n`/`--no-newline`).
    no_newline: bool,
    /// Node to talk to (`--node`); `None` means this host's own daemon.
    node: Option<String>,
    config: Option<PathBuf>,
}

impl HistoryArgs {
    /// Parse `list|get|restore` plus its flags.
    ///
    /// Flag splitting matches paste mode exactly — both getopt spellings of an
    /// attached value, the short one split by *position* so
    /// `-ttext/plain;charset=utf-8` survives its own `=`. `history get` is
    /// `--paste` pointed at an older clipboard, so a flag that works on one and
    /// not the other would be a trap, not a simplification.
    fn parse(args: &[String]) -> Result<HistoryArgs> {
        let (verb, rest) = args.split_first().context(USAGE)?;
        let mut out = HistoryArgs {
            // Filled in from `verb` and the positional below, once both are
            // known. An id can follow its flags (`restore --node desktop 3f2a`)
            // the way it can in any getopt tool, so the verb cannot be turned
            // into a `Command` until the whole line has been read.
            command: Command::List,
            type_: None,
            no_newline: false,
            node: None,
            config: None,
        };
        let mut ids: Vec<&String> = Vec::new();
        let mut it = rest.iter();
        while let Some(arg) = it.next() {
            // Real wl-paste parses with getopt_long, which accepts a value
            // attached to its flag in two spellings: `--type=text/plain` and
            // `-ttext/plain`. The short split is by *position* — a short option
            // is exactly two characters — not by an `=`, which would mangle
            // `-ttext/plain;charset=utf-8`. `is_char_boundary` guards a
            // mistyped flag whose second character is multi-byte: `-é` must be
            // an unknown flag, not a panic.
            let (flag, mut inline) = match arg.as_str() {
                a if a.starts_with("--") => match a.split_once('=') {
                    Some((f, v)) => (f, Some(v.to_string())),
                    None => (a, None),
                },
                a if a.starts_with('-') && a.len() > 2 && a.is_char_boundary(2) => {
                    (&a[..2], Some(a[2..].to_string()))
                }
                a => (a, None),
            };
            let mut value = || {
                inline
                    .take()
                    .map(Ok)
                    .unwrap_or_else(|| it.next().cloned().context("needs a value"))
                    .with_context(|| format!("{flag} needs a value"))
            };
            match flag {
                "-t" | "--type" => out.type_ = Some(value()?),
                "-n" | "--no-newline" => out.no_newline = true,
                "--node" => out.node = Some(value()?),
                "--config" => out.config = Some(PathBuf::from(value()?)),
                other if !other.starts_with('-') => ids.push(arg),
                other => bail!("unknown history flag: {other}\n{USAGE}"),
            }
            // An inline value no arm consumed: the flag doesn't take one, and
            // silently dropping it would act on something other than what was
            // asked for.
            if inline.is_some() {
                bail!("{flag} does not take a value");
            }
        }
        // The id is taken from whatever was left over rather than from the
        // position right after the verb, because a flag may come first:
        // `restore --node desktop 3f2a` is the invocation the README leads with,
        // and taking the next argument positionally made it "restore the entry
        // called --node". Each verb then says what it does and does not take,
        // instead of a shared message telling `list` users about an id.
        // Passed through as typed: which of a node's two ways of naming a row
        // this is — its number or its id — is the *node's* decision, because
        // telling them apart needs the row count and the hashes. Guessing here
        // would put that rule in two places, and the client's copy would be the
        // one that is wrong.
        let one = |what: &str| match ids.as_slice() {
            [entry] => Ok((*entry).clone()),
            [] => bail!(
                "history {what} needs the number or id `clipmesh history list` printed\n{USAGE}"
            ),
            _ => bail!("history {what} takes one entry; got {}\n{USAGE}", ids.len()),
        };
        out.command = match verb.as_str() {
            "list" if !ids.is_empty() => {
                bail!("history list takes no arguments; got {:?}\n{USAGE}", ids[0])
            }
            "list" => Command::List,
            "get" => Command::Get { entry: one("get")? },
            "restore" => Command::Restore {
                entry: one("restore")?,
            },
            other => bail!("unknown history command {other:?}\n{USAGE}"),
        };
        // Silently ignoring an output flag on a command that has no output would
        // print a listing to someone who asked for one MIME type and think it
        // answered them.
        if !matches!(out.command, Command::Get { .. }) && (out.type_.is_some() || out.no_newline) {
            bail!("-t/--type and -n/--no-newline only apply to `history get`\n{USAGE}");
        }
        Ok(out)
    }
}

/// The node to talk to: `--node` when given (a bare host gets the configured
/// port, exactly as `--paste` does), else this host's own daemon.
///
/// Deliberately **not** "every configured peer, raced", the way `--paste`
/// defaults. A paste asks for a shared value — the mesh's current clipboard — so
/// whichever node answers first is as good as another. A history is per node:
/// racing peers would return whichever host happened to reply, which is nobody's
/// history in particular and would differ between two runs of the same command.
fn target(cfg: &Config, node: Option<&str>) -> String {
    match node {
        Some(n) => config::with_default_port(n, &cfg.port.to_string()),
        None => cfg.local_addr(),
    }
}

/// Entry point: parse args, load config, ask the node, print the answer.
pub async fn run(args: &[String]) -> Result<()> {
    let ha = HistoryArgs::parse(args)?;
    let config_path = ha
        .config
        .clone()
        .unwrap_or_else(config::default_config_path);
    let cfg = Config::load(&config_path)?;
    let addr = target(&cfg, ha.node.as_deref());

    let req = match &ha.command {
        Command::List => HistoryRequest::List,
        Command::Get { entry } => HistoryRequest::Get {
            entry: entry.clone(),
            type_: ha.type_.clone(),
        },
        Command::Restore { entry } => HistoryRequest::Restore {
            entry: entry.clone(),
        },
    };
    let what = match ha.command {
        Command::List => "history listing",
        _ => "clipboard",
    };
    let result = client::ask(
        &addr,
        cfg.psk,
        cfg.max_payload_size,
        Message::History { req },
        HISTORY_TIMEOUT,
        what,
        |msg| match msg {
            Message::HistoryReply { result } => Some(result),
            _ => None,
        },
    )
    .await?;

    match (result, &ha.command) {
        (HistoryResult::List(entries), Command::List) => {
            print!("{}", render_listing(&entries, &addr));
            Ok(())
        }
        (HistoryResult::Offer(offer), Command::Get { .. }) => {
            let mut offer = offer;
            let mime = paste::select_type(ha.type_.as_deref(), &offer)?.to_string();
            let data = offer.swap_remove(&mime).ok_or_else(|| {
                anyhow!("selected type {mime:?} is unexpectedly absent from the reply")
            })?;
            paste::write_stdout(&paste::render(data, &mime, ha.no_newline))
        }
        (HistoryResult::Restored { kind, broadcast }, Command::Restore { .. }) => {
            println!("{}", render_restored(&addr, kind, broadcast));
            Ok(())
        }
        (HistoryResult::Failed(miss), _) => bail!("{}", explain(miss, &addr)),
        // A node speaking this protocol version answers each request with its
        // own shape; anything else is a bug on one side, not a user error.
        (other, command) => bail!("{addr} answered a {command:?} with {other:?}"),
    }
}

/// Render a node's reason for having nothing to give, in the second person.
///
/// The point of [`HistoryMiss`] being a value rather than a log line on the
/// serving host: four of these are things the user can act on, and collapsing
/// them into "nothing found" would hide which.
fn explain(miss: HistoryMiss, addr: &str) -> String {
    match miss {
        HistoryMiss::Disabled => {
            format!("{addr} is not keeping a clipboard history (history_entries = 0 in its config)")
        }
        HistoryMiss::Empty => {
            format!("{addr} has not remembered any clipboard contents yet")
        }
        // A number that ran off the end usually means the listing it came from
        // is stale — a copy since then renumbered the rows — so say how far the
        // current one goes rather than just "no".
        HistoryMiss::NoSuchEntry { entries } => format!(
            "{addr} has no such entry: it remembers {entries}, numbered 1 to \
             {entries}, and no id there starts with that (`clipmesh history \
             list` shows what is left — an entry may have been dropped to stay \
             under that node's history limits, and a copy since your last \
             listing renumbers the rows but never the ids)"
        ),
        HistoryMiss::Ambiguous { matches } => {
            format!("that id matches {matches} remembered clipboards on {addr} — type more of it")
        }
        HistoryMiss::NotOffered { available } => format!(
            "that entry does not offer the requested type (available: {})",
            paste::list_available(available.iter().map(String::as_str))
        ),
        HistoryMiss::NotSynced => format!(
            "{addr} does not handle the selection that entry came from — for a \
             middle-click selection it needs sync_selection, and the GNOME \
             backend has none at all"
        ),
        // An entry outlives the configuration that recorded it: the MIME rules
        // are shared mesh-wide, so a peer can deny a type after the copy.
        HistoryMiss::Filtered(reason) => format!(
            "{addr} still has that entry, but {} — its content filters have \
             changed since it was remembered",
            match reason {
                Unavailable::Denied =>
                    "every type in it is now denied by that \
                     node's MIME rules (see `clipmesh --rules` on that host)",
                Unavailable::TooLarge => "it now exceeds that node's max_payload_size",
                Unavailable::Sensitive => "it is flagged as a password-manager secret",
                _ => "nothing in it passes that node's content filters",
            }
        ),
        HistoryMiss::WriteFailed => {
            format!("{addr} could not write the entry to its clipboard; its log says why")
        }
    }
}

/// The selection an entry came from, in `wl-paste`'s vocabulary.
fn where_of(kind: SelectionKind) -> &'static str {
    match kind {
        SelectionKind::Clipboard => "clipboard",
        SelectionKind::Selection => "primary",
    }
}

/// A short, fixed-width age token: "just now", "45s", "3m", "2h", "4d".
///
/// A new function rather than `sync::approx_duration_ms`, which exists to say
/// "about 6 days" inside a clock-skew log line; a column wants the short form.
fn age(ms: u64) -> String {
    const SECOND: u64 = 1000;
    const MINUTE: u64 = 60 * SECOND;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    match ms {
        ms if ms < 5 * SECOND => "just now".to_string(),
        ms if ms < MINUTE => format!("{}s", ms / SECOND),
        ms if ms < HOUR => format!("{}m", ms / MINUTE),
        ms if ms < DAY => format!("{}h", ms / HOUR),
        ms => format!("{}d", ms / DAY),
    }
}

/// What an entry's content column says: its preview, or its type names when
/// nothing in it is text.
fn content_of(entry: &HistoryEntry) -> String {
    match &entry.preview {
        Some(p) => p.clone(),
        None => entry
            .types
            .iter()
            .map(|(mime, _)| mime.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    }
}

/// The `history list` table.
fn render_listing(entries: &[HistoryEntry], addr: &str) -> String {
    let rows: Vec<[String; 6]> = entries
        .iter()
        .map(|e| {
            [
                e.index.to_string(),
                short_id(&e.hash),
                age(e.age_ms),
                where_of(e.kind).to_string(),
                human_bytes(e.bytes as usize),
                content_of(e),
            ]
        })
        .collect();
    let header = ["#", "ID", "AGE", "WHERE", "SIZE", "CONTENT"].map(str::to_string);
    // Width every column but the last to its widest cell; the content column
    // runs to the end of the line and is never padded, so a wide preview cannot
    // push trailing spaces into a copied line.
    let mut widths = [0usize; 5];
    for row in std::iter::once(&header).chain(&rows) {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let line = |row: &[String; 6]| {
        let mut out = String::new();
        for (w, cell) in widths.iter().zip(row) {
            out.push_str(cell);
            out.push_str(&" ".repeat(w - cell.chars().count() + 2));
        }
        out.push_str(&row[5]);
        format!("{}\n", out.trim_end())
    };
    let mut out = format!("{} remembered clipboard(s) on {addr}\n\n", entries.len());
    out.push_str(&line(&header));
    for row in &rows {
        out.push_str(&line(row));
    }
    out.push_str(
        "\nPut one back with: clipmesh history restore <#>, or its ID — \
         a later copy renumbers the rows but never the ids\n",
    );
    out
}

/// The `history restore` confirmation.
///
/// It names whether the mesh followed, because a node that does not send that
/// selection still restores its own clipboard — and a bare "done" there would
/// imply the other hosts had changed too.
fn render_restored(addr: &str, kind: SelectionKind, broadcast: bool) -> String {
    let what = where_of(kind);
    if broadcast {
        format!("Put it back on {addr}'s {what} and sent it to the mesh.")
    } else {
        format!(
            "Put it back on {addr}'s {what}. Not sent to the mesh — that node \
             does not send this selection."
        )
    }
}

/// The id a listing prints for an entry: the first [`ID_CHARS`] hex characters
/// of its content hash. A `get`/`restore` accepts this, or any longer prefix.
fn short_id(hash: &[u8; 32]) -> String {
    hash.iter()
        .flat_map(|b| [b >> 4, b & 0xf])
        .take(ID_CHARS)
        .map(|nibble| char::from_digit(nibble as u32, 16).expect("a nibble is a hex digit"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn parse(v: &[&str]) -> Result<HistoryArgs> {
        HistoryArgs::parse(&args(v))
    }

    fn entry(n: u8, age_ms: u64, kind: SelectionKind, preview: Option<&str>) -> HistoryEntry {
        HistoryEntry {
            index: n as u32,
            hash: [n; 32],
            kind,
            age_ms,
            bytes: 34,
            types: vec![("text/plain".into(), 34)],
            preview: preview.map(str::to_string),
        }
    }

    #[test]
    fn each_command_parses_with_its_id() {
        assert_eq!(parse(&["list"]).unwrap().command, Command::List);
        assert_eq!(
            parse(&["restore", "3f2a"]).unwrap().command,
            Command::Restore {
                entry: "3f2a".into()
            }
        );
        assert_eq!(
            parse(&["get", "3f2a"]).unwrap().command,
            Command::Get {
                entry: "3f2a".into()
            }
        );
        // A row number works just as well as an id, and which one this is is
        // the node's decision — the client passes it through as typed.
        assert_eq!(
            parse(&["restore", "2"]).unwrap().command,
            Command::Restore { entry: "2".into() }
        );
        // Naming nothing is not optional: a `restore` with nothing to restore
        // would otherwise have to guess, which is what naming exists to prevent.
        assert!(parse(&["restore"]).is_err());
        assert!(parse(&["get"]).is_err());
        assert!(parse(&[]).is_err());
        // A flag is not an id: taking one positionally would "restore" an entry
        // called --config and then report the path as an unknown flag.
        let err = format!(
            "{:#}",
            parse(&["restore", "--config", "/c.toml"]).unwrap_err()
        );
        assert!(err.contains("needs the number or id"), "got: {err}");
        // Nor is a second id silently dropped.
        assert!(parse(&["restore", "3f2a", "8b10"]).is_err());
        assert!(parse(&["forget", "3f2a"]).is_err());
        // ...and `list` is told what it actually takes, not about an id syntax
        // it has no form of.
        let err = format!("{:#}", parse(&["list", "3f2a"]).unwrap_err());
        assert!(err.contains("takes no arguments"), "got: {err}");
    }

    /// `history get` is `--paste` pointed at an older clipboard, so a spelling
    /// that works there must work here — both getopt attached-value forms, with
    /// the short one split by position so a value containing `=` survives.
    #[test]
    fn get_accepts_both_getopt_spellings_of_an_attached_value() {
        for spelling in [
            &["get", "3f", "--type=text/plain;charset=utf-8"][..],
            &["get", "3f", "-ttext/plain;charset=utf-8"][..],
            &["get", "3f", "-t", "text/plain;charset=utf-8"][..],
        ] {
            assert_eq!(
                parse(spelling).unwrap().type_.as_deref(),
                Some("text/plain;charset=utf-8"),
                "{spelling:?}"
            );
        }
    }

    /// The invocation the README leads with. An id may follow its flags, the way
    /// it may in any getopt tool — taking the argument right after the verb made
    /// `restore --node desktop 3f2a` try to restore an entry called `--node`.
    #[test]
    fn an_id_may_come_after_the_flags() {
        let a = parse(&["restore", "--node", "desktop", "3f2a"]).unwrap();
        assert_eq!(
            a.command,
            Command::Restore {
                entry: "3f2a".into()
            }
        );
        assert_eq!(a.node.as_deref(), Some("desktop"));
        let b = parse(&["get", "--type=image/png", "3f2a"]).unwrap();
        assert_eq!(
            b.command,
            Command::Get {
                entry: "3f2a".into()
            }
        );
        assert_eq!(b.type_.as_deref(), Some("image/png"));
    }

    /// A mistyped short flag whose second character is multi-byte must be an
    /// unknown flag, not a panic: `&a[..2]` on `-é` splits inside a character.
    #[test]
    fn a_multi_byte_short_flag_is_rejected_rather_than_panicking() {
        let err = format!("{:#}", parse(&["get", "3f", "-é"]).unwrap_err());
        assert!(err.contains("unknown history flag"), "got: {err}");
    }

    #[test]
    fn output_flags_are_refused_where_there_is_no_output() {
        // Accepting them silently would print a listing to someone who asked for
        // one MIME type, and look like it had answered.
        assert!(parse(&["list", "-t", "text/plain"]).is_err());
        assert!(parse(&["restore", "3f", "-n"]).is_err());
        assert!(parse(&["get", "3f", "-n"]).unwrap().no_newline);
    }

    #[test]
    fn node_and_config_apply_to_every_command() {
        let a = parse(&["list", "--node", "desktop", "--config", "/tmp/c.toml"]).unwrap();
        assert_eq!(a.node.as_deref(), Some("desktop"));
        assert_eq!(a.config, Some(PathBuf::from("/tmp/c.toml")));
        assert!(parse(&["list", "--node"]).is_err(), "--node needs a value");
    }

    #[test]
    fn the_default_target_is_this_hosts_own_daemon() {
        // Not "every configured peer, raced" the way --paste defaults: a history
        // is per node, so racing would answer with whichever host replied first.
        let cfg = Config::from_toml("listen = \"0.0.0.0\"\npsk = \"s\"\npeers = [\"a\", \"b\"]\n")
            .unwrap();
        assert_eq!(target(&cfg, None), "127.0.0.1:48100");
        // A bare host inherits the configured port, exactly as --paste does.
        assert_eq!(target(&cfg, Some("desktop")), "desktop:48100");
        assert_eq!(target(&cfg, Some("desktop:1234")), "desktop:1234");
    }

    #[test]
    fn age_renders_short_fixed_width_tokens() {
        assert_eq!(age(0), "just now");
        assert_eq!(age(4_999), "just now");
        assert_eq!(age(45_000), "45s");
        assert_eq!(age(3 * 60_000 + 30_000), "3m");
        assert_eq!(age(2 * 3_600_000), "2h");
        assert_eq!(age(4 * 86_400_000), "4d");
    }

    #[test]
    fn the_listing_shows_both_ways_of_naming_a_row() {
        // Both, because they fail differently: the number is what a human
        // retypes, the id is what survives a copy landing in between.
        let listing = render_listing(
            &[entry(0x3f, 12_000, SelectionKind::Clipboard, Some("x"))],
            "h:1",
        );
        assert!(listing.contains("3f3f3f3f"), "got:\n{listing}");
        assert!(
            listing.contains("63"),
            "the row number is missing:\n{listing}"
        );
        assert_eq!(short_id(&[0x3f; 32]).len(), ID_CHARS);
    }

    #[test]
    fn the_listing_names_the_selection_in_wl_pastes_vocabulary() {
        let listing = render_listing(
            &[
                entry(1, 0, SelectionKind::Clipboard, Some("copied")),
                entry(2, 0, SelectionKind::Selection, Some("highlighted")),
            ],
            "h:1",
        );
        assert!(listing.contains("clipboard"), "got:\n{listing}");
        assert!(listing.contains("primary"), "got:\n{listing}");
    }

    #[test]
    fn an_entry_with_no_preview_shows_its_types_instead() {
        let mut e = entry(1, 0, SelectionKind::Clipboard, None);
        e.types = vec![("image/png".into(), 1200), ("image/jpeg".into(), 900)];
        assert_eq!(content_of(&e), "image/png, image/jpeg");
    }

    #[test]
    fn listing_rows_carry_no_trailing_whitespace() {
        // The content column runs to the end of the line, so a wide preview must
        // not push padding into a line someone copies out of the terminal.
        let listing = render_listing(
            &[
                entry(1, 0, SelectionKind::Clipboard, Some("short")),
                entry(
                    2,
                    4 * 86_400_000,
                    SelectionKind::Selection,
                    Some("a much longer preview"),
                ),
            ],
            "h:1",
        );
        for line in listing.lines() {
            assert_eq!(line, line.trim_end(), "trailing whitespace in {line:?}");
        }
    }

    #[test]
    fn a_local_only_restore_says_the_mesh_did_not_follow() {
        // A bare "done" would imply every other host had changed too.
        let sent = render_restored("h:1", SelectionKind::Clipboard, true);
        assert!(sent.contains("sent it to the mesh"), "got: {sent}");
        let local = render_restored("h:1", SelectionKind::Clipboard, false);
        assert!(local.contains("Not sent to the mesh"), "got: {local}");
    }

    /// Every reason a node can have for handing back nothing renders as its own
    /// sentence. Collapsing them would put the user back where `HistoryMiss`
    /// exists to stop them: told "nothing found" when the answer is "type more
    /// of the id" or "that node isn't keeping a history at all".
    #[test]
    fn every_reason_explains_itself_distinctly() {
        let reasons = [
            HistoryMiss::Disabled,
            HistoryMiss::Empty,
            HistoryMiss::NoSuchEntry { entries: 4 },
            HistoryMiss::Filtered(Unavailable::Denied),
            HistoryMiss::Filtered(Unavailable::TooLarge),
            HistoryMiss::Ambiguous { matches: 3 },
            HistoryMiss::NotOffered {
                available: vec!["text/plain".into()],
            },
            HistoryMiss::NotSynced,
            HistoryMiss::WriteFailed,
        ];
        let rendered: Vec<String> = reasons.iter().cloned().map(|r| explain(r, "h:1")).collect();
        for (i, a) in rendered.iter().enumerate() {
            assert!(!a.is_empty());
            for b in &rendered[i + 1..] {
                assert_ne!(a, b, "two reasons render identically");
            }
        }
        let ambiguous = explain(HistoryMiss::Ambiguous { matches: 3 }, "h:1");
        assert!(ambiguous.contains('3'), "the match count is worth naming");
    }
}
