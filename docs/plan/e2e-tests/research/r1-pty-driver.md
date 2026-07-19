# R1 — PTY driver for the interactive ceremonies

## Verdict (up front)

**Hand-roll the PTY harness over the existing `libc` dependency. The PRD's headline assumption (A-1) survives contact with the spike.** A ~140-SLOC dependency-free harness (`openpty` + `Command::pre_exec` with `setsid`+`TIOCSCTTY`) drove the **complete real `key new` ceremony** — passphrase-confirm, one-time mnemonic display, full re-entry quiz, scrollback clear, keystore written — to a valid v4 keystore on disk, exit 0, on this Darwin box driving the real `target/*/ethernal`. No dev-dependency is needed. OQ-1 resolves to **hand-roll**, not a crate.

Two hard constraints make this non-negotiable and eliminate the alternatives:

1. **A real controlling terminal is mandatory — piped stdin cannot reach the success path.** The ceremony reads echo-off secrets from `/dev/tty` directly (`rpassword ... input_file_path("/dev/tty")`, `key_cmd.rs:719,822`; keystore passphrase via `NewKeystorePassphrase`, `passphrase.rs:105`), displays the mnemonic on `/dev/tty` (`open_tty_writer`, `key_cmd.rs:183`), and gates entry on `isatty(0) && isatty(1)` (`require_tty_for_new`, `key_cli.rs:215`). Without a PTY as the child's controlling terminal, the `/dev/tty` opens fail (the binary then **fails closed**, exit 2: "cannot open controlling terminal for mnemonic display") and the isatty gate rejects. This is why the harness must `setsid`+`TIOCSCTTY`, not merely pipe fds.
2. **C-5 forbids external toolchain in the hermetic tier, where these tests live (T-14).** That eliminates `expect(1)` regardless of its local availability (`/usr/bin/expect` exists here) — a hermetic-tier test cannot shell out to a system binary. The choice is therefore strictly **hand-rolled-libc vs. one Rust dev-dep crate**, and C-1 + the spike settle it in favor of hand-rolling.

---

## The spike (D-1-style empirical proof)

Full source in the scratchpad: `scratchpad/pty-spike/` (`src/pty.rs` = the reusable harness, `src/main.rs` = the driver). It is a standalone crate depending only on `libc = "0.2"` — the same dep already in the workspace.

**What it proved, driving the real binary (no `--passphrase-env`, so the echo-off `/dev/tty` keystore-passphrase confirm fires twice — the mechanic most likely to break):**

```
== lock-step key new ceremony (no --passphrase-env) ==
[captured mnemonic: 24 words]
[exit status: exit status: 0]
[keystore file: /tmp/.../keystore-m_12381_3600_0_0_0-1784391042.json]
[file mode: 600]
[keystore structurally valid: version 4, pubkey, crypto, 0600]
RESULT: PASS — full key new ceremony driven over hand-rolled PTY; v4 keystore written.
```

The captured PTY stream shows every ceremony surface flowing through the single master, including the scrollback-clear escape run (matches `CLEAR_SCROLLBACK_TWICE`, `key_cmd.rs:436`):

```
...deposit line. It will not be shown again.\r\n\r\n<24 words>\r\n\r\n
Please re-enter your mnemonic to confirm: <echoed words>\r\n
\x1b[2J\x1b[3J\x1b[H\x1b[2J\x1b[3J\x1b[H The terminal was cleared to remove the displayed mnemonic.\r\n
  Note: a terminal multiplexer keeps its own scrollback — tmux: `tmux clear-history`; ...\r\n
Keystore passphrase: ...\r\n Confirm keystore passphrase: ...\r\n
```

### Harness mechanics that the spike settled empirically (not theorized)

- **`openpty` + `Command::pre_exec`, not raw `forkpty`.** `cargo test` runs on a multithreaded harness; `forkpty` would return control into Rust in the child where only async-signal-safe calls are legal before `exec`. `Command::pre_exec` confines that hazard to `setsid()` + one `ioctl(TIOCSCTTY)`, both async-signal-safe, and reuses std's spawn machinery.
- **`TIOCSCTTY` on a *captured dup* of the slave fd**, not on fd 0. This makes acquiring the controlling terminal independent of *when* std performs its stdio `dup2` — the spike clones the slave `File`, moves it into the `pre_exec` closure, and `ioctl`s that fd. Verified working on Darwin; macOS requires the **explicit `TIOCSCTTY`** (setsid alone does not grant the controlling terminal).
- **One byte stream, echo flips mid-ceremony → strict wait-for-prompt-then-send.** stdin (re-entry/retry) and `/dev/tty` (secrets) are the same slave; stderr prompts and the `/dev/tty` mnemonic display both surface on the same master read side. `rpassword` toggles the tty to raw/no-echo for its reads and restores after. The harness therefore **must** be an expect loop (wait for the prompt substring, then send) — never write-ahead. A `--probe-writeahead` run that queued all inputs up front aborts at re-entry (**exit 4**, `AppError::Aborted`), because the mnemonic is only knowable *after* display; a fixed script cannot drive this ceremony even before the raw-mode passphrase reads.
- **Reads via `libc::poll` with per-call timeouts**; a pty master read after the slave closes returns `EIO` on Linux (treated as EOF). The `wait()` reaps via `try_wait` and drains, so the harness never depends on master EOF.

### Harness size / complexity (the OQ-1 evidence)

`src/pty.rs` is **140 non-comment/non-blank SLOC** (178 lines with docs). It contains the whole reusable surface an architecture would lift into `tests/common/pty.rs`: `spawn`, `expect(needle, timeout) -> pre-text`, `send_line`, `wait`, `output`, plus `Drop` (kill+reap). A minimal version is ~100 SLOC. This is comparable in weight to the existing hand-rolled `Stub` (~200 lines in `tests/common/mod.rs`) and well within the house style (C-1). The flake surface is small and bounded: timeout handling and partial reads are the only moving parts, and both are exercised by the spike without flakiness across repeated runs.

### T-1 must offer a two-channel (split-stderr) mode for T-5 — verified

The single-master config above (stdin/stdout/stderr all on the slave) drives T-2/T-3/T-4/T-9..T-12, but it **cannot** express T-5 ("mnemonic/seed/secret appear only on the PTY, never on a redirected non-TTY channel"): with stderr on the PTY there is no non-TTY channel to assert absence on. The gate makes the fix possible — `require_tty_for_new` only checks `isatty(0) && isatty(1)` (`key_cli.rs:217-218`), so **fd 2 is free**. The harness therefore needs a second spawn mode: **stdin/stdout on the PTY slave, stderr on a plain pipe.** In that split, the mnemonic display + scrollback clear stay on `/dev/tty` (the PTY master) while the banner, prompts, and summary go to the stderr pipe — so the expect loop becomes genuinely **two-channel** (prompts matched on the stderr pipe via `expect_err`, the mnemonic captured from the master via `expect`).

Spiked and **passing**: the split-stderr driver completed the full ceremony and asserted the captured mnemonic is present on the PTY master and **absent from the stderr-pipe capture** (592 bytes, containing prompts + summary but not the mnemonic), landing a valid v4 keystore:

```
== T-5 split-stderr ceremony (stderr = non-TTY pipe) ==
[captured mnemonic from PTY: 24 words]
[stderr pipe bytes captured: 592]
RESULT: PASS — T-5 runnable: mnemonic on PTY only, absent from non-TTY stderr; v4 keystore written.
```

Implementation notes for the two-channel mode: use `Stdio::piped()` for stderr and a **drain thread** reading it to EOF into a shared buffer (so a full pipe never blocks the child), and pump the PTY master while blocking on the stderr channel (the mnemonic/clear land on the master even while you wait on a stderr prompt). This adds ~40 SLOC to the harness (`spawn_split_stderr` + `expect_err`).

---

## Critical finding not in the PRD: scrypt-in-debug makes ceremony tests slow unless optimized

The ceremony's `key new` write step runs scrypt at the production cost `n=262144` (fixed in the release binary; there is **no** CLI param-injection hook — confirmed by the entropy/flag-absence tests). `cargo test` drives the **debug** binary (`CARGO_BIN_EXE_ethernal`), and unoptimized scrypt dominates:

| Binary built | Full `key new` ceremony (1 keystore) wall time |
|---|---|
| debug, `opt-level = 0` (default) | **~18 s** (97% CPU, scrypt-bound) |
| debug, `[profile.dev.package.scrypt] opt-level = 3` (targeted) | **~1.0 s** |
| debug, `opt-level = 1` (whole workspace) | ~2.0 s |
| release | ~0.84 s |

At ~10 PTY ceremony tests (T-2..T-5, T-9..T-12) this is the difference between ~3 minutes and a few seconds of hermetic-tier time. The fix is a **per-package profile override** in the workspace `Cargo.toml`, which optimizes only the crypto without slowing the rest of the debug build (fast incremental builds of the workspace crates are preserved):

```toml
[profile.dev.package.scrypt]
opt-level = 3
```

**Empirically verified with the *exact* targeted override** (not just a whole-profile bump): injecting `--config 'profile.dev.package.scrypt.opt-level=3'` and rebuilding the debug binary cut the ceremony from ~18 s to **~1.0 s**. (This was worth checking because scrypt's inner mix can live in its `salsa20` dependency, which a `scrypt`-only pin would not reach — but the measurement confirms the targeted pin reproduces the speedup here.) If a future scrypt release moves the hot loop such that this regresses, the robust fallback is `[profile.dev.package."*"] opt-level = 2` (optimize all dependencies, leave workspace crates unoptimized). Architecture should add the override when landing the PTY tests.

---

## Full expected dialogue transcripts (the harness contract)

Channel legend: **[tty]** = `/dev/tty` (controlling terminal), **[err]** = stderr, **[in]** = read from stdin, **[sec]** = echo-off read from `/dev/tty`. Over a single PTY all of these interleave on the one master; the markers matter only because the harness keys `expect` on the prompt text and must send re-entry/retry vs. secrets to the same stream at the right moment.

### `key new` (default: no `--passphrase-env`, no `--mnemonic-passphrase`, `--count 1`)

```
[err] ethernal key new: count=1 output_dir=<DIR>          ← banner (+ WARNING line if DIR is a symlink, T-12)
[tty] This is your BIP-39 mnemonic. Write it down and store it offline.
[tty] It will not be shown again.
[tty]
[tty] <24-word mnemonic>            ← CAPTURE this line
[tty]
[err] Please re-enter your mnemonic to confirm:           → [in] send captured mnemonic
        (on mismatch: [err] "Mnemonic mismatch. Retry? [y/N]: " → [in] "y" to retry, else abort EXIT 4)
[tty] \x1b[2J\x1b[3J\x1b[H\x1b[2J\x1b[3J\x1b[H            ← scrollback clear (T-11)
[tty] The terminal was cleared to remove the displayed mnemonic.
[tty]   Note: a terminal multiplexer keeps its own scrollback — tmux: `tmux clear-history`; screen: C-a : then `scrollback 0`.
[err] Keystore passphrase:                                → [sec] send passphrase (≥8 chars)
[err] Confirm keystore passphrase:                        → [sec] send same passphrase
[err] keystore 1/1: <path> (pubkey=0x...)                 ← progress
[err] wrote 1 keystore
[err]   <path>  pubkey=0x...
EXIT 0
```

**Ordering note:** with bare `--mnemonic-passphrase` (Prompt form), the 25th-word prompts fire **before** the mnemonic display (step 2 of `run_key_new_with_deps`), with confirm on `new`:

```
[err] Mnemonic passphrase (empty is valid):   → [sec]
[err] Confirm mnemonic passphrase:            → [sec]   (key/account new only; recover is single-entry, no confirm)
```

### `account new`

**Byte-for-byte the same dialogue** — `account_cmd.rs` imports and calls the identical `run_ceremony`, `StdinMnemonicSource`, `RecoverMnemonicSource`, and `require_tty_for_new` (`account_cmd.rs:30-31`, `account_cli.rs:15,126`). The only difference is the file written: **Web3 v3** (`version:3`, `aes-128-ctr`, scrypt, keccak `mac`, top-level `address`, `UTC--…` filename) instead of EIP-2335 v4. One harness drives both `key new` and `account new`.

### `key recover` / `account recover` interactive prompt (T-9)

```
[err] ethernal key recover: count=N start_index=S output_dir=<DIR>   ← banner
[err] Enter your mnemonic:                    → [in] send mnemonic   (only when isatty(0); piped stdin skips the prompt)
      (optional 25th-word prompt if --mnemonic-passphrase bare: single entry, no confirm)
[err] Keystore passphrase:                     → [sec]
[err] Confirm keystore passphrase:             → [sec]
[err] wrote N keystores ...
EXIT 0
```

`RecoverMnemonicSource::read_line` branches on `stdin_is_tty()` (`key_cmd.rs:773`): TTY → prompt+`read_line`; non-TTY → read full stdin. Only the non-TTY (pipe) path is tested today; T-9 needs the PTY to exercise the prompt branch.

---

## Cross-platform (ubuntu CI vs. darwin local)

- **`openpty` linkage:** the spike compiled and ran on Darwin with `libc`'s `openpty` directly. On Linux, `openpty` historically lived in `libutil`; glibc ≥ 2.34 (ubuntu 22.04+/`ubuntu-latest`) merged it into the main C library, so no extra link flag is needed on current runners. If a future toolchain complains, add a one-line `build.rs` (`cargo:rustc-link-lib=util`) **or** use the pure-POSIX fallback `posix_openpt`+`grantpt`+`unlockpt`+`ptsname` (all in `libc` proper, no `libutil`). Note for architecture; not needed on `ubuntu-latest`.
- **`openpty` signature portability:** macOS's `libc::openpty` binds `termp`/`winp` as `*mut termios`/`*mut winsize`; Linux binds them `*const`. Passing `std::ptr::null_mut()` coerces to `*const` and compiles on **both** — the spike uses this. (Passing `null()` fails to compile on macOS.)
- **`TIOCSCTTY`:** present and same semantics on Linux; `setsid`+`TIOCSCTTY` is the portable acquire-controlling-terminal sequence. One `#[cfg(unix)]` gate covers the whole harness (C-4); Windows is out of scope.

---

## Comparison vs. the alternatives (honest)

| Option | LOC / dep cost | Works in hermetic tier? | Verdict |
|---|---|---|---|
| **Hand-rolled `openpty`+`pre_exec`** (spike) | ~140 SLOC, **0 new deps** (reuses `libc`) | Yes | **Chosen.** Honors C-1's empty `[dev-dependencies]`; proven end-to-end. |
| `rexpect` (dev-dep) | ~0 harness code, +1 dep (+ its own PTY layer) | Yes | Viable fallback if the hand-roll ever proves flaky; most-used Rust expect crate. Rejected only because the hand-roll is small and dep-free. |
| `expectrl` (dev-dep) | similar to rexpect | Yes | Same as rexpect; slightly less adoption. |
| `portable-pty` (dev-dep) | low-level PTY only, still write your own expect loop | Yes | No advantage over hand-rolling — you still write the expect logic. |
| `expect(1)` (system binary) | shell glue | **No (C-5)** | Eliminated: external toolchain banned in the hermetic tier. |

Fallback trigger: if the hand-rolled harness shows flakiness in CI that isn't fixable with timeout tuning, adopt **`rexpect`** as the single dev-dep (still workspace-compatible). The spike found no such flakiness.

---

## Verdict

Hand-roll the PTY harness over `libc` (`openpty` + `Command::pre_exec(setsid, TIOCSCTTY-on-dup'd-slave)`) with a `poll`-based expect loop. It is ~140 SLOC, needs zero new dependencies, and drove the real `key new` ceremony to a valid on-disk v4 keystore. `rexpect` is the named fallback if flakiness ever appears. **OQ-1 → hand-roll.**

## Consequences for architecture

- Add `tests/common/pty.rs` (the spike's `PtySession`: `spawn`/`expect`/`send_line`/`wait`, `#[cfg(unix)]`) next to `Stub`; reuse the `ethernal()` env-scrub builder and `TempDir` (C-3). No `[dev-dependencies]` entry.
- **T-1 needs two spawn modes:** the single-master mode (stdin/stdout/stderr all on the PTY) for T-2/T-3/T-4/T-9..T-12, and a **split-stderr mode** (stderr on a plain pipe + drain thread, prompts matched via `expect_err`) that T-5 requires to prove the mnemonic never reaches a non-TTY fd. Both are spiked and passing; the split adds ~40 SLOC.
- Every ceremony test is a **wait-for-prompt-then-send** script keyed on the exact prompt strings above; never write-ahead.
- Capture the mnemonic from the PTY (the 24-word line after "It will not be shown again.") and replay it — this is the no-fixed-golden model (C-2/A-5) and doubles as the source of truth for the recover-roundtrip cross-check (T-2/T-3).
- **Add `[profile.dev.package.scrypt] opt-level = 3` to the workspace `Cargo.toml`** or the ceremony tests will each spend ~18 s in debug scrypt. (Empirically: ~18 s → ~2 s.)
- The mismatch-abort path exits **4** (`AppError::Aborted`, verified), and nothing is written before re-entry succeeds — pin both in T-4.
- One harness covers `key new` and `account new` (shared ceremony code) and both recover prompt paths (T-9); only the written-keystore assertions differ (v4 vs v3).
