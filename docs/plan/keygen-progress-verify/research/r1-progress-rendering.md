# R1 — How to render progress: existing in-tree prior art vs. a dependency vs. a thread

**Question.** What renders the indicator, and what does it cost the codebase?

---

## 1. There is already a progress renderer in this tree

`bins/ethernal/src/gen_cmd.rs:362` — the deposit-signing loop:

```rust
fn emit_progress(progress: Progress, logger: &Logger, json_logs: bool, done: usize, total: usize) {
    if json_logs { logger.info("signing progress", …); return; }
    match progress {
        Progress::Tty => {
            let mut err = std::io::stderr();
            let _ = write!(err, "\rsigning: {done}/{total}");
            if done == total { let _ = writeln!(err); }
            let _ = err.flush();
        }
        Progress::NonTty => {
            let pct = done * 100 / total;
            let prev_pct = (done - 1) * 100 / total;
            if pct / 10 > prev_pct / 10 || done == total { logger.info("signing progress", …); }
        }
    }
}
```

That is the house style, and it establishes three conventions the new work should inherit
rather than reinvent:

1. **`\r`-overwrite on a TTY, structured log events off-TTY** — the `Progress` enum
   (`gen_cmd.rs:39`) is exactly this fork, chosen once at startup from `stderr_is_tty()`
   (`fs_util.rs:32`).
2. **Every write is `let _ = …`** — progress never affects control flow or exit status.
3. **Rate-limited off-TTY** (10% boundaries) so a CI log is not one line per unit.

`validator_cmd.rs:389` (`emit_key_progress`) and `account_cmd.rs:407`
(`emit_account_progress`) are the same shape minus the `\r` — they only fire *after* a
completed unit, which is precisely the gap this plan closes.

**Structural note.** `Progress` is defined in `gen_cmd.rs` and imported by *both*
`validator_cmd.rs:24` and `account_cmd.rs:30`. That is a leftover: the deposit-generation
module owns a type two unrelated namespaces depend on. The recent commit series is doing
exactly this kind of hoist —`refactor(bin): hoist keygen neutrals into shared keygen module`
(`27792a4`), `centralize TTY helpers in fs_util` (`2c9807b`). Extracting `progress.rs` fits
the direction of travel and lands as a clean no-behavior-change commit.

## 2. Dependency survey: `indicatif` and friends — rejected

`indicatif` is the ergonomic default for Rust progress bars, and it is the wrong choice here:

| Criterion | Verdict |
|---|---|
| Dependency footprint | pulls `console` → `unicode-width`, terminal-detection, and (feature-dependent) `portable-atomic` / `number_prefix`. This binary's entire dependency set today is crypto + `clap` + `rpassword` + `libc` + `serde`/`ureq`. |
| Threat model | the deliverable runs on air-gapped/bastion hosts and is heading for release signing + attestation (`0.README.md`, gap 5). Every added crate is supply-chain surface bought for cosmetics. |
| Capability actually needed | a `\r` line and an erase. That is `write!(w, "\r…")` and `\x1b[K` — about 20 lines including the non-TTY fork. |
| Fit with existing seams | `indicatif` wants to own a terminal handle; this codebase injects `&mut dyn Write` so tests capture a `Vec<u8>`. Adopting it means either bypassing the seam or wrapping it. |

**Rejected.** Hand-rolled, extending the existing `Progress` fork. This is not a
"not-invented-here" call: the in-tree renderer already exists and already matches the
injection discipline the tests rely on.

## 3. The one thing hand-rolling cannot do — and what it would cost

Nothing renders *during* a blocking `scrypt` call from the same thread
([`r2`](r2-scrypt-cost-and-hooks.md) §3). A live spinner needs a second thread ticking while
the main thread is inside the KDF. Cost of that:

- `ValidatorDeps.summary_out: &'a mut dyn Write` (`validator_cmd.rs:54`) must become something
  shareable and `Send` — `Arc<Mutex<dyn Write + Send>>` or a channel to a render thread.
- That seam is injected by **every** unit test in `validator_cmd.rs` (`run_with`,
  `run_recover_with`, the two `*_secret_hygiene_*` tests, the ceremony tests) and by the
  parallel `account_cmd.rs` seam — the same struct field shape at `account_cmd.rs:70`.
- Interaction with `CancelToken` (SIGINT) and with the `/dev/tty` ceremony writer must be
  re-reasoned: two writers to one terminal.

For a ~310 ms block (worst realistic ~1.2 s), buying "the dots move" with a threading change
across two namespaces and ~10 test call sites is a bad trade. **Phase-boundary granularity**
gives PR-2's bound with a strictly local change.

If this is ever revisited, the cheap version is a spinner thread that writes **only** to
`std::io::stderr()` directly (not through the seam) and is spawned only when
`Progress::Tty` *and* `stderr_is_tty()` — leaving every test path untouched. Recorded in
[`../issues/deferred.md`](../issues/deferred.md), not scheduled.

## 4. Rendering mechanics the implementation must get right

- **Erase, don't just overwrite.** `\r` alone leaves the tail of a longer previous line on
  screen (`\rwriting` after `\rencrypting` leaves `ing`). Use `\r\x1b[K` (erase to end of
  line), or pad to a fixed width. `\x1b[K` is the same CSI family the ceremony already emits
  (`CLEAR_SCROLLBACK_TWICE`, `keygen.rs:86`).
- **Erase before the persistent line.** PR-3/PR-4: the durable
  `keystore i/N: path (pubkey=…)` line must land on a clean line so scrollback is unchanged.
- **Terminal shared with the ceremony.** The mnemonic display writes to `/dev/tty`
  (`open_tty_writer`, `fs_util.rs:38`); progress writes to stderr — the same physical
  terminal. Today's ordering saves us: `run_ceremony` fully completes, including
  `clear_after_ceremony`, before `finish_from_mnemonic` runs
  (`validator_cmd.rs:226` then `:236`). This is an **invariant to state**, not a coincidence
  to rely on silently: progress must never start before the scrollback clear, or it would be
  wiped (or worse, keep a mnemonic-era line alive).
- **Tests inject `Progress::Tty` with a `Vec<u8>` sink**, so transient text *will* appear in
  captured buffers. Every existing assertion on those buffers is `contains`-based
  (`validator_cmd.rs:602`, `:603`, `:1247`, `:1575`) or a negative "secret must not appear"
  scan (`:599`, `:1504`, `:1631`), so added transient lines are compatible — **provided** they
  carry no secrets (PR-6) and no `WARNING` token (PR-9, `tests/validator_e2e.rs:444` counts
  `WARNING` lines and asserts exactly one).

**Connections:** [`r2-scrypt-cost-and-hooks.md`](r2-scrypt-cost-and-hooks.md) ·
[`../architecture.md`](../architecture.md) (D-1, D-2, D-3)
