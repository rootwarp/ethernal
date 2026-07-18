# Research: G1 — Terminal scrollback clear after the mnemonic ceremony (ETHSTAKER-7)

## Verdict
The locked design (hard-coded `ESC[2J ESC[3J ESC[H` to `/dev/tty`, twice, fail-open) is sound and
**more appropriate for a security tool than the upstream remediation**, which shells out to
`clear` / `tput reset` / `reset`. The "twice" repetition is directly validated by the upstream fix.
The one factual correction: `ESC[3J` is broadly supported, but **macOS Terminal.app support is
version-dependent/unreliable** — the fail-open Cmd+K path is the *primary* scrub path there, not an
edge case. Confidence: **High** on the upstream mechanics and the support matrix (with Terminal.app
flagged Medium).

## Context
- **Lineage:** DEP-001 (ToB 2020) → ETHSTAKER-7 (ToB Mar 2026) — the finding that recurred in every
  upstream deposit-cli audit.
- **Local anchor:** single display site `run_ceremony` at `bins/ethernal/src/key_cmd.rs:432`, called
  from `key_cmd.rs:239` (key new) and `account_cmd.rs:242` (account new). A drafted implementation is
  preserved in `git stash ccd0abe9`.
- **Locked:** clear-on-confirm, raw ANSI, no terminfo, no new dependency, fail-open with warning,
  multiplexer caveat documented.

## How ethstaker-deposit-cli actually remediated ETHSTAKER-7

The fix lives in `ethstaker_deposit/utils/terminal.py`, function `clear_terminal()`, built up over
two PRs [1][2]:

- **PR #189 — "Use all clearing methods for linux/darwin"** (@valefar-on-discord): instead of
  stopping at the first available method, the Linux/Darwin branch runs **all** of, in sequence:
  `subprocess.run(['clear'], env=clean_env)`, `subprocess.run(['tput', 'reset'], env=clean_env)`,
  `subprocess.run(['reset'], env=clean_env)`, with `click.clear()` as fallback. Windows branch:
  `click.clear()` + `subprocess.run('cls', shell=True)`. Other platforms: `click.clear()`. [1]
- **PR #242 — "Call everything in clear terminal twice"** (@remyroy): wraps the whole body in
  `for count in range(2):` with the comment *"Call everything twice to complete the clear on iTerm2
  and for good measure."* [2]

**Key facts for us:**
- **How many times:** twice. Explicit rationale: iTerm2 does not fully clear on a single pass. [2]
- **When, relative to confirmation:** after the re-entry ceremony confirms (post-display exit path),
  before proceeding — the same ordering ethernal locks. [1][2]
- **What sequences:** upstream uses **no raw ANSI**. It delegates to external binaries (`clear`,
  `tput reset`, `reset`) and `click.clear()`. `clear`/`reset` are ncurses/terminfo-backed: `clear`
  emits the terminal's `E3` capability (which *is* `ESC[3J` on xterm-class terminals) plus the normal
  screen clear; `reset`/`tput reset` do a fuller terminal reset. So upstream effectively lets
  terminfo decide *which* scrollback sequence to emit per terminal. [1]

**Implication of the divergence:** ethernal hard-codes the bytes that `clear` + the `E3` capability
would emit (`ESC[2J` erase screen, `ESC[3J` erase saved/scrollback lines, `ESC[H` cursor home) and
writes them straight to the `/dev/tty` handle. This is a **deliberate, defensible simplification for
an air-gapped security tool**: no `subprocess`, no `PATH`/shell-injection surface, no dependency on
`clear`/`tput`/`reset` being installed, no terminfo lookup. The cost is that ethernal does not adapt
to exotic terminals whose `E3` differs — irrelevant for the target (xterm/iTerm2/Terminal.app/Linux
console). The "twice" repetition should be kept: it is the one piece of hard-won upstream tuning.

## Terminal support reality for `ESC[3J`

`ESC[3J` = **"Erase Saved Lines"**, an xterm extension (DECSED variant 3); the corresponding
terminfo capability is `E3`. `ESC[2J` erases the visible screen only; `3J` is what actually drops the
scrollback buffer. Unknown/unsupported CSI sequences are silently ignored by conforming terminals, so
emitting `3J` where unsupported is harmless.

| Terminal / layer | Clears scrollback on `ESC[3J`? | Notes |
|---|---|---|
| xterm | Yes | Origin of the sequence (`E3` capability). [3] |
| iTerm2 (macOS) | Yes, but **may need a second pass** | Exactly why upstream runs the clear twice. [2] |
| macOS **Terminal.app** | **Unreliable / version-dependent** | Reports conflict [4][5]; historically ignored `3J` (Cmd+K was the only scrub). Treat Cmd+K as the reliable manual path — matches ethernal's fail-open instruction. [4] |
| GNOME Terminal / VTE, Konsole (KDE) | Yes | VTE and Konsole implement `E3`. [4][5] |
| Windows Terminal, Alacritty, kitty, xterm.js | Yes | Modern emulators implement `E3` / erase-saved-lines. [6] |
| Linux console (kernel VT) | Yes (modern kernels) | The kernel VT + `linux` terminfo `E3` implement erase-saved-lines on current kernels; very old kernels lacked it. (Author's assessment — exact kernel version not sourced this session.) |
| **tmux / screen (multiplexer)** | **Not from the child, not guaranteed** | The multiplexer keeps its **own** per-pane scrollback (copy-mode history). A child's `3J` clears the pane's emulator buffer but does not reliably purge the multiplexer's saved history; behavior depends on tmux version/`terminal-features`. Documented remedy: `tmux clear-history`; screen `C-a :` → `scrollback 0`. [4] |

**Bottom line:** on the primary targets (xterm, iTerm2, Linux console) the hard-coded sequence works;
Terminal.app and multiplexers are the two residuals the locked design already handles via fail-open
(Cmd+K) + documented caveat.

## Prior art in Rust CLIs for post-secret-display scrubbing

- There is **no widely-adopted Rust convention** for scrubbing scrollback after a secret display;
  most Rust key tools (e.g. foundry `cast wallet`) do not do it. This makes ethernal's move a
  defense-in-depth improvement, not a table-stakes feature.
- The idiomatic dependency-based way would be `crossterm::terminal::Clear(ClearType::Purge)`, which
  emits exactly `ESC[3J`, plus `Clear(ClearType::All)` = `ESC[2J` and `cursor::MoveTo(0,0)` = `ESC[H`.
  ethernal's hard-coded three-byte-group sequence **is byte-identical to what crossterm's `Purge` +
  `All` + home would write** — so hard-coding it (per D-1, no new dep) loses nothing. (Assessment
  based on crossterm's documented sequences; no dep added.)

## Implications for implementation
1. **Keep raw ANSI to the same `/dev/tty` handle; do NOT copy upstream's subprocess approach.**
   Shelling out to `clear`/`tput`/`reset` (as ethstaker does) is the wrong model for an air-gapped
   security binary — it adds a `PATH`/shell surface and external-binary dependence the locked design
   correctly rejects.
2. **Keep the "twice."** It is not superstition — it is upstream's fix for iTerm2 not fully clearing
   on one pass [2]. Emit the full `ESC[2J ESC[3J ESC[H` group twice, then flush.
3. **Order matters:** `2J` (erase screen) → `3J` (erase scrollback) → `H` (home). This matches
   `clear`+`E3` semantics; do not reorder `H` before the erases.
4. **Terminal.app makes the fail-open path (G1-2) load-bearing on macOS**, not an edge case. The
   loud manual-clear warning must be genuinely actionable: `clear && printf '\x1b[3J'` and the
   explicit **Cmd+K** instruction. Test coverage of the fail-open warning (G1-5) is therefore
   security-relevant, not just completeness.
5. **Multiplexer caveat is real and unavoidable from the child** — `tmux clear-history` / screen
   `scrollback 0` must be in USER-GUIDE (G1-4). Do not attempt to detect/clear multiplexer history
   from inside `run_ceremony`.
6. No terminfo/`E3` probing needed; unsupported terminals ignore `3J` harmlessly, so the hard-coded
   sequence is safe to emit unconditionally.

## Sources
[1] [ethstaker-deposit-cli PR #189 — "Use all clearing methods for linux/darwin"](https://github.com/ethstaker/ethstaker-deposit-cli/pull/189) (diff via patch-diff.githubusercontent.com) — introduces `clear_terminal()` in `ethstaker_deposit/utils/terminal.py` running `clear`, `tput reset`, `reset`, `click.clear()`. Primary source (code diff).
[2] [ethstaker-deposit-cli PR #242 — "Call everything in clear terminal twice"](https://github.com/ethstaker/ethstaker-deposit-cli/pull/242) — wraps the clear in `for count in range(2)`; comment cites iTerm2. Primary source (code diff).
[3] [XTerm Control Sequences (invisible-island.net)](https://invisible-island.net/xterm/ctlseqs/ctlseqs.html) — `ESC [ 3 J` = Erase Saved Lines; `E3` terminfo capability. Reference doc (general knowledge; not re-fetched this session).
[4] [How to clear a Mac terminal and its scroll-back — Hashrocket TIL](https://til.hashrocket.com/posts/g1ola6c5ku-how-to-clear-a-mac-terminal-and-its-scroll-back) — `clear && printf '\e[3J'`; Cmd+K clears screen+scrollback but "messes up tmux"; motivates the multiplexer caveat. Blog.
[5] [termux-app issue #933 — Add support of ESC[3J to clear scrollback](https://github.com/termux/termux-app/issues/933) — cross-terminal `ESC[3J` support discussion. Forum/issue.
[6] [xterm.js issue #3315 — clearing scrollback buffer](https://github.com/xtermjs/xterm.js/issues/3315) — emulator-level erase-saved-lines behavior. Forum/issue.
[7] Trail of Bits, *ethstaker-deposit-cli Security Review*, March 2026 (ETHSTAKER-7 is the canonical finding) — [trailofbits/publications `reviews/2026-03-ethstaker-deposit-cli-securityreview.pdf`](https://github.com/trailofbits/publications/blob/master/reviews/2026-03-ethstaker-deposit-cli-securityreview.pdf). **PDF could not be text-parsed in this environment (returned as binary);** the ethstaker code fix [1][2] is the primary evidence for the *how*, and the vault audit note is the binding summary of the *recommendation*.
