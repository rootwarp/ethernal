# Deferred issues — future PTY (interactive-`new`-ceremony) stage

**Deferred by the binding scope decision of 2026-07-19** — *"Building a new PTY driver is not in scope for
this stage. Assume the mnemonic is GIVEN by the user."* These six issues (**14 pts**) are removed from this
stage's execution and preserved here for a possible future stage. **Nothing here is built now.** The full
design is in [`../architecture.md`](../architecture.md) §"Deferred: PTY tier"; the settled harness verdict is
[`../research/r1-pty-driver.md`](../research/r1-pty-driver.md) (hand-roll `PtySession` over `libc`).

Each deferred requirement is, in the meantime, **guarded only by an in-crate unit test** in
`key_cmd`/`account_cmd` (see the PRD coverage matrix). The manual verify skill
(`.claude/skills/verify/SKILL.md`) is `gen → build → sign → send` over committed keystore fixtures and
**does not run the ceremony** — so the ceremony is a documented **carve-out** of the verify skill (T-18),
not something it covers. The "Meanwhile guarded by" column below names the unit test for each.

Kept this stage by rescoping to the non-interactive `recover` path: **T-3** ([`e3.md`](e3.md) — recover +
`decrypt_v3`) and **T-12·recover** ([`e4.md`](e4.md)). The scrypt override ([`e1.md`](e1.md)) is also **not**
deferred — the recover-path tests require it.

---

| Tag | Title | Pts | Discharges | Meanwhile guarded by |
|---|---|---|---|---|
| **[E1-2]** | PTY harness `PtySession` + ceremony driver scaffolding | 3 | T-1 (PTY half) | — (test infra) |
| **[E1-3]** | `key new` full ceremony test | 2 | T-2 | `key_cmd::happy_path_writes_n_keystores_loader_round_trip` |
| **[E3-2]** | Confirmation-mismatch abort — both commands | 2 | T-4 | `{key,account}_cmd::ceremony_mismatch_retry_then_abort_exit4_no_files` |
| **[E3-3]** | `new`-path secret hygiene (split-stderr) — both | 2 | T-5 | `{key,account}_cmd::happy_path_*` (tty_writer vs summary_out split) |
| **[E3-4]** | Mnemonic-passphrase + scrollback + new-path symlink | 2 | T-10, T-11, T-12·new | `key_cmd::clear_sequence_bytes_and_order`; `account_cmd::mnemonic_passphrase_raw_honored_on_new` |
| **[E4-1]** | Interactive `/dev/tty` recover prompt over PTY — both | 3 | T-9 | stdin recover path already ✓ (`key_e2e`, `account_e2e`) |

**Total deferred: 14 pts, 6 issues.**

---

## What each issue would build (preserved for the future stage)

- **[E1-2] — PTY harness (T-1 PTY half).** `tests/common/pty.rs` (`PtySession` over `libc::openpty` +
  `Command::pre_exec` setsid/TIOCSCTTY, `poll`-based expect loop, `Drop` kill+reap; `#[cfg(unix)]`, no
  `[dev-dependencies]` entry) + `tests/common/ceremony.rs` (prompt-string constants +
  `drive_new_ceremony`/`drive_recover_prompt` capture-and-replay). Was the critical-path root of the old
  Stream A. Named fallback if the hand-roll flakes in CI: the `rexpect` dev-dep behind the same API.

- **[E1-3] — `key new` full ceremony (T-2).** `tests/key_ceremony_pty.rs`: passphrase prompt+confirm →
  one-time mnemonic display → full re-entry quiz → `--count > 1` batch → v4 keystores; validate structurally
  (EIP-2335 v4, `0600`) + `keystore::Loader` round-trip + salt/IV/UUID pairwise-distinct on the *new* path +
  recover-roundtrip cross-check.

- **[E3-2] — Confirmation-mismatch abort (T-4), both commands.** Wrong mnemonic at the re-entry quiz →
  retry-or-abort (exit 4), nothing written until re-entry succeeds. `key_ceremony_pty.rs` +
  `account_ceremony_pty.rs`.

- **[E3-3] — `new`-path secret hygiene (T-5), both commands.** Via `spawn_split_stderr`: mnemonic/seed/derived
  secret present on the PTY master, **absent** from the drained stderr pipe (the display-once model on the
  success path). `require_tty_for_new` gates only on `isatty(0) && isatty(1)`, so fd 2 is free.

- **[E3-4] — Mnemonic-passphrase + scrollback + symlink·new (T-10/T-11/T-12·new), both commands.** Bare
  `--mnemonic-passphrase` prompt on the ceremony (25th-word prompts fire **before** the mnemonic display);
  scrollback clear (`transcript()` scan for `\x1b[2J\x1b[3J\x1b[H` ×2, `284d478`); symlink `--output-dir`
  warning on the ceremony path (`1736843`). Note the non-ceremony derivation-change property is already
  covered on `recover` (`account_cmd::mnemonic_passphrase_raw_honored_on_new`).

- **[E4-1] — Interactive `/dev/tty` recover prompt (T-9), both commands.** Drive the recover prompt path over
  a PTY (`RecoverMnemonicSource::read_line` branches on `stdin_is_tty()`, `key_cmd.rs:774`); only the
  non-TTY stdin path is testable without the harness, and it is already covered.

When this stage is picked up, restore these tags in `e1.md`/`e3.md`/`e4.md`, re-add the deferred rows to the
`index.md` table and coverage map, and reinstate D-1 and DD-1 in the architecture/plan.
