# Architecture — Audit Gap Closure (G1–G4)

**Inputs:** [`prd.md`](prd.md) (binding *what/why*), [`research/g1..g4`](research/) (specs + traps),
[`issues/g1..g4.md`](issues/) (per-gap design), and the code as it exists on `develop` @ `0308f66`.
Style precedent: [`../keygen/architecture.md`](../keygen/architecture.md) — this doc owns the
*module boundaries, signatures, call paths, and test seams*, written against verified `file:line`, not
against the research prose.

**Scope shape.** This is not a greenfield system; it is four small, independent, defense-in-depth /
regression edits to an already-audited binary. So the deliverable is a **boundary + interface + test
map per gap**, plus the closed open-questions and PRD amendments the task demands — not a system
context diagram for a system that already exists.

## The crux: three of four gaps are additive edits to one binary; none adds an edge or a dep

Verified against the four `Cargo.toml`s and the call graph below: the change surface is confined to
`bins/ethernal` (G1, G3, G4-tests) and `.github/workflows/ci.yml` (G2). **No crate boundary moves, no
new dependency, no new inter-crate edge.** The keygen dependency law still holds and must not be
touched: `core` ⟂ `keystore` (siblings), bin → both; `keystore::encrypt` stays a pure function that
receives already-drawn `salt`/`iv`/`uuid_bytes` (this is *exactly* the invariant G4 regression-guards).

```
G1  bins/ethernal/src/key_cmd.rs  (run_ceremony: add clear + warn_out seam)   ← account_cmd.rs reuses
G3  bins/ethernal/src/fs_util.rs  (new pure detector + warner)                ← key_cli / account_cli / gen_cli call
G4  bins/ethernal/tests/*_e2e.rs  (test-only; zero src/ or crates/ change)
G2  .github/workflows/ci.yml      (config-only; no Rust change)
```

Guiding constraints carried verbatim from the PRD (D-1, S-1..S-3, C-1): **zero new third-party deps**;
no terminfo (G1 clear is hard-coded ANSI); reuse the existing **writer-injection** seam
(`KeyDeps`/`AccountDeps`/`load_config(banner_out)`) and the existing **`WARNING:`** error-string tone
(`sign_cmd.rs:48`, `send_cmd.rs:55`); **per-issue fast-forward commits**, each green under
`make lint && make test`; **G4 changes no product code**; **G2 is CI-only**.

---

## Decided open questions (the ones the task requires me to close)

| # | Question | Decision | One-line rationale |
|---|---|---|---|
| D-G3a | **G3 detection scope**: research option A (final-component `symlink_metadata` only) vs B (also intermediate via canonicalize-divergence) | **A — final-component `symlink_metadata` only**; `canonicalize` is used *only* to resolve the message target, never as a detection trigger | B false-positives on macOS `/tmp`,`/var`→`/private/…`, turning `make test` red on dev Macs while green on CI; A has zero false positives on any platform, is exactly the ToB threat ("operator points `--output-dir` at a symlink"), and satisfies SM-3's two test cases. |
| D-G3b | **G3 helper unification**: unify the duplicated `validate_output_dir` (`key_cli.rs:332` shared + `gen_cli.rs:362` private) vs patch both | **Do not unify.** Add an orthogonal pure helper in `fs_util.rs`; call it at each of the three `load_config` sites on the existing `banner_out` writer | Smallest change: `validate_output_dir`'s signature and body stay untouched (protects the "no behavior change beyond the warning" invariant S-2/S-3); the warning string lives once in `fs_util`; the pre-existing dup is out of scope for an audit-gap patch, and hoisting it (gen importing from key_cli) is refactor churn that buys nothing for G3. |
| D-G1 | **G1 module placement + interface**: where clear helpers live; how the warn writer threads through; assess the stashed `warn_out` draft | **Adopt the stash's seam** — add `warn_out: &mut dyn Write` to `run_ceremony`, fed by `deps.summary_out` at both call sites — **with a result-capture body** so the clear fires on *every* post-display exit path. Helpers live in `key_cmd.rs` next to `run_ceremony` (shared by key+account); `run_ceremony` stays `pub(crate)` | `summary_out` is already the stderr fallback in the injection struct, so `warn_out = deps.summary_out` is the correct, dependency-free fallback for the fail-open clear (G1-2); `tty_writer` and `summary_out` are disjoint `KeyDeps` fields → the two `&mut` reborrows compile; result-capture (not the stash's implicit early-returns) is what guarantees G1-1's "partial-display-write" and "abort" paths also clear. |
| D-G4 | **G4 test placement + fixtures + field paths** | New `#[test]` in `key_e2e.rs` (BLS) and `account_e2e.rs` (EOA), each reusing the existing `run_*_recover` harness at **`--count 3`**, real OS entropy, comparing raw-JSON fields (no decrypt) | Least churn, matches the harness the PRD names; field paths verified from `encrypt.rs`/`encrypt_v3.rs` source (below); `recover` is the only pipe-drivable batch path (`new` needs a TTY) and draws salt/IV/UUID from the identical encrypt-time loop. |
| D-G2 | **rust-cache pin target**: literal `@v2` tip (`e18b4977…`) vs the `v2.9.1` release commit (`c193711…`) | **Pin the literal `@v2` resolution `e18b497796c12c097a38f9edb9d0641fb99eee32 # v2 (≈ v2.9.1)`** | Honors G2-1/G2-3 as written ("the SHA the tag currently resolves to", "no upgrade") with **no PRD deviation**; the two commits differ only by a 17-second changelog commit so behavior is identical — the release-commit's marginal provenance edge is not worth a recorded amendment. |

### PRD amendments (explicit, per the task's grant of authority)

- **Amend G3-1.** The literal wording — detect a final-component symlink *AND* whether `canonicalize`
  diverges from the given path — is **internally inconsistent with SM-3 on macOS** (research g3 §"the
  `canonicalize`-divergence trap"): the divergence clause fires on every normal macOS temp dir
  (`/var/folders/…` under a `/var`→`/private` symlink), so the SM-3 "real dir → warning-free" case
  would fail under `make test` on a developer Mac. **Amended G3-1:** *detect whether the user-supplied
  path's final component is a symlink (`symlink_metadata`); if so, resolve the real target with
  `canonicalize` for the warning message only. Do not treat canonicalize-divergence as a detection
  trigger.* This is decision D-G3a; SM-3 is unaffected (it never tests intermediate-component
  symlinks). Intermediate/ancestor-symlink detection is explicitly **deferred** (warn-only,
  defense-in-depth, mostly-Linux targets — not worth the `cfg(macos)` gymnastics).
- **Amend G4-2 (spec correction, from research g4).** The EOA v3 keystore has **no `uuid` field — the
  top-level identifier is `id`** (`encrypt_v3.rs` emits `id: format_uuid_v4(...)`; `account_e2e.rs:343`
  already asserts `v["id"]`). The G4-2 EOA distinctness assertion reads **`v["id"]`**, not `v["uuid"]`.
- **No other PRD change.** All locked decisions (clear-on-confirm, warn-don't-fail, recover-`--count`
  real-entropy, per-issue ff) stand.

---

## G1 — Clear terminal scrollback after the mnemonic ceremony

**Lineage** DEP-001 → ETHSTAKER-7. **Locked** clear-on-confirm, raw ANSI, fail-open. **Single display
site** `run_ceremony` (`key_cmd.rs:432`), shared by `key new` (`key_cmd.rs:239`) and `account new`
(`account_cmd.rs:242`); `recover` never calls it.

### Boundary map — files touched

| File | Change |
|---|---|
| `bins/ethernal/src/key_cmd.rs` | Add `warn_out` param + result-capture body to `run_ceremony`; add `clear_after_ceremony` + the clear-byte const; new unit tests. |
| `bins/ethernal/src/account_cmd.rs` | **Call-site only** — pass `deps.summary_out` as the new `warn_out` arg (`:242`). |
| `docs/USER-GUIDE.md` | Document the automatic clear in `key new` (`:207`), `account new` (`:320`), and the ceremony intro (`:95`): why, fail-open warning, multiplexer caveat. |

### New items + signatures (in `key_cmd.rs`, next to `run_ceremony`)

```rust
/// ESC[2J (erase screen) · ESC[3J (erase scrollback) · ESC[H (home), the whole
/// group TWICE — iTerm2 needs a second pass (upstream ethstaker PR #242). Order
/// is load-bearing: erase-screen → erase-scrollback → home (research g1 §5).
const CLEAR_SCROLLBACK_TWICE: &[u8] = b"\x1b[2J\x1b[3J\x1b[H\x1b[2J\x1b[3J\x1b[H";

/// Post-ceremony scrub on the SAME display TTY (S-1: never stdout/stderr/logger).
/// Infallible & fail-open (G1-2): on a clear-write error, print manual-clear
/// instructions to `tty`, falling back to `warn_out` (stderr in prod); never
/// changes the ceremony's exit status. On success, print the notice + tmux/screen
/// caveat to the now-blank `tty` (G1-3).
fn clear_after_ceremony(tty: &mut dyn Write, warn_out: &mut dyn Write) {
    let cleared = tty.write_all(CLEAR_SCROLLBACK_TWICE).and_then(|_| tty.flush()).is_ok();
    if cleared {
        // G1-3 notice — best-effort; a failed notice does not re-trigger fail-open.
        let _ = writeln!(tty, "The terminal was cleared to remove the displayed mnemonic.");
        let _ = writeln!(tty, "  Note: a terminal multiplexer keeps its own scrollback — \
                               tmux: `tmux clear-history`; screen: C-a : then `scrollback 0`.");
        let _ = tty.flush();
    } else {
        // G1-2 fail-open — tty first, then stderr fallback. macOS Terminal.app makes
        // this the PRIMARY scrub path (research g1: ESC[3J unreliable there), so the
        // instructions must be genuinely actionable.
        let msg = "WARNING: could not clear the terminal automatically; the mnemonic may \
                   remain in scrollback.\n  Clear it manually: `clear && printf '\\x1b[3J'`  \
                   (macOS Terminal.app: press Cmd+K).\n";
        if tty.write_all(msg.as_bytes()).and_then(|_| tty.flush()).is_err() {
            let _ = warn_out.write_all(msg.as_bytes());
            let _ = warn_out.flush();
        }
    }
}
```

`run_ceremony` gains one parameter and a result-capture body (the current body becomes the private
`ceremony_body`, unchanged):

```rust
pub(crate) fn run_ceremony(
    mnemonic: &str,
    tty: &mut dyn Write,
    warn_out: &mut dyn Write,          // NEW — stderr fallback for the fail-open clear (G1-2)
    src: &dyn MnemonicSource,
    cancel: &CancelToken,
) -> Result<(), AppError> {
    let outcome = ceremony_body(mnemonic, tty, src, cancel); // display + re-entry loop (today's body)
    clear_after_ceremony(tty, warn_out);                     // EVERY post-display path (G1-1)
    outcome
}
```

### Call paths (the two production wirings — the only two edits outside `key_cmd.rs`)

```
run_key_new_with_deps   (key_cmd.rs:239)  ─▶ run_ceremony(m, deps.tty_writer, deps.summary_out, deps.mnemonic_src, cancel)
run_account_new_with_deps (account_cmd.rs:242) ─▶ run_ceremony(m, deps.tty_writer, deps.summary_out, deps.mnemonic_src, cancel)
                                                              └ tty (display + clear + notice)  └ warn_out (fail-open fallback)
```

`deps.tty_writer` (`&mut dyn Write`) and `deps.summary_out` (`&mut dyn Write`) are **disjoint fields**
of the deps struct → the two reborrows compile with no aliasing error. `finish_from_mnemonic` reuses
`deps.summary_out` afterward; the ceremony's borrow has ended by then. **Recover paths are untouched**
— they never call `run_ceremony`, so the existing empty-tty-buffer assertions
(`key_cmd.rs:1360`-style, `account_cmd.rs:1185`) stay green.

Why result-capture (not the stash's implicit returns): G1-1 requires the clear on **partial display
write** and **mismatch-abort** too. `ceremony_body`'s display `writeln!…map_err(exit2)` and its
`Err(Aborted)` both leave via `outcome`; capturing the `Result` and unconditionally calling
`clear_after_ceremony` before returning it is the single structure that covers all five paths (confirm
/ abort / read-error / cancel / partial-display-write) without a per-branch scrub. Clearing after the
**full `ceremony_body`** (not just after the display `writeln!`) is deliberate and auditable: the
re-entry reads via `src.read_line` with **echo ON** (`key_cmd.rs:456`), so the operator re-typing all
24 words also lands in scrollback — arguably a *larger* exposure than the one-time display. Scrubbing
after the whole body removes both. **No drop guard** (the repo has none): a *panic* between display
and clear skips the scrub — the stated, accepted residual for SM-1 (A-2), the same posture as the rest
of the binary.

### Test architecture (unit, in `key_cmd.rs #[cfg(test)]`; injection = tty/warn `Vec<u8>`)

Drive `run_ceremony` directly (now `pub(crate)`) with `ScriptedLines` for re-entry and two `Vec<u8>`
writers. Four tests map 1:1 to G1-5:

1. **`clear_sequence_bytes_and_order`** — correct re-entry → `Ok`; assert the tty buffer **ends with /
   contains** `CLEAR_SCROLLBACK_TWICE` (doubled) **and** the clear's byte offset > the mnemonic's
   offset (clear-after-display ordering); assert the G1-3 notice + `tmux`/`screen` text present.
2. **`abort_path_still_clears`** — mismatch → `n` → `Err(Aborted)` (exit 4) **and** the tty buffer
   contains `CLEAR_SCROLLBACK_TWICE` (the scrub fired despite the abort).
3. **`clear_failure_warns_on_fallback`** *(the security-relevant one — see the writer trap below)* —
   display succeeds, the clear write fails; assert `run_ceremony` still returns `Ok`, the tty received
   **no** clear bytes past the display, and **`warn_out` (the stderr Vec) contains the manual-clear
   instructions** (`Cmd+K` / `clear &&`).
4. **`success_prints_notice`** — covered by (1) or split out: on a clean clear, the notice + multiplexer
   caveat land on the tty.

**Writer-trap fix (must-do).** The obvious "fail on any write containing `0x1b`" writer is wrong: the
manual-clear string holds the *literal text* `printf '\x1b[3J'`, i.e. bytes `\`,`x`,`1`,`b` — **no real
ESC** — so an ESC-sniffing writer would let the warning-to-tty succeed and the stderr fallback would
never be exercised (the assertion would pass vacuously or fail). Use a writer that **fails all
writes/flushes after the display's first `flush()`** — the display body ends with
`.and_then(|_| tty.flush())`, and there are no tty writes between it and the clear, so that flush is a
clean seam. Then both the clear *and* the warning-to-tty fail, and `warn_out` genuinely receives the
message:

```rust
struct FailAfterDisplay { display_flushed: bool }
impl Write for FailAfterDisplay {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.display_flushed { Err(io::Error::new(io::ErrorKind::BrokenPipe, "tty gone")) }
        else { Ok(b.len()) }
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.display_flushed { return Err(io::Error::new(io::ErrorKind::BrokenPipe, "tty gone")); }
        self.display_flushed = true;   // the display's terminal flush; everything after fails
        Ok(())
    }
}
```

**No pty harness** (locked non-goal): the pipe-driven E2E suites exercise `recover`, which has no
ceremony. **Account coverage** is by construction (same `run_ceremony`); optionally one
`account_cmd.rs` smoke test asserts `run_account_new_with_deps` routes the clear to its `tty_writer`
after the mnemonic.

**Verified blast radius (whole-file grep of `key_cmd.rs`).** `run_ceremony` has exactly **one** caller
(`:239`) plus its definition (`:432`) — **no direct `run_ceremony(...)` test call** exists, so the
`warn_out` signature change compiles with only the two production call-site edits (key + account); the
new G1 tests are the first direct callers. Every existing `key new` tty assertion is `contains(...)` /
`!contains(...)`-based (`:1040`, `:1100`, `:1777`, and the S-2 secret-hygiene checks `:1845-1849`), so
the append-only clear bytes + notice cannot falsify them — the mnemonic still appears, and the notice
carries **no** seed/SK/passphrase/`TREZOR` bytes. Recover tty assertions (`:1524` `!contains`, `:1657`
/ `:1896` `is_empty`) are untouched because recover never calls `run_ceremony`.
`ceremony_tty_write_failure_exit2_no_files` (`:1145`) stays green unmodified — the clear runs fail-open
into the summary Vec, which it does not inspect. **No existing test needs editing.**

### Failure modes

- Clear write fails → fail-open warning (tty→stderr), exit code unchanged (G1-2). Primary path on
  macOS Terminal.app.
- `warn_out` also fails → silently continue (`let _ =`); nothing left to do, ceremony outcome preserved.
- Panic between display and clear → mnemonic remains in scrollback (accepted residual, no drop guard).
- Multiplexer running → `3J` cannot reach tmux/screen history; documented caveat (G1-4), not fixable
  from the child.

---

## G2 — Pin GitHub Actions to full commit SHAs (CI-only)

**Lineage** ETHSTAKER-1. **Boundary** `.github/workflows/ci.yml` only — three third-party `uses:`;
no Rust, no dep, CI semantics unchanged. This gap is *config*, so the architecture records the **pin
format + re-verification step**, not module boundaries.

### Resulting `ci.yml` (resolved 2026-07-18; re-verify verbatim before commit)

```yaml
- name: Checkout
  uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1

- name: Set up Rust
  uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4 # stable branch @ 2026-07-16
  with:
    toolchain: stable          # NEW (G2-2): @<sha> no longer names a toolchain; select explicitly
    components: clippy, rustfmt # unchanged

- name: Cache cargo
  uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32 # v2 (≈ v2.9.1, 2026-03-12)
```

Three traps (research g2), all handled above: (a) `dtolnay/rust-toolchain@stable` is a **branch, not a
tag** → version comment is `stable branch @ <date>`, not a semver, and the `with: toolchain: stable`
line is what preserves selection once `@<sha>` stops naming a toolchain; (b) `Swatinem/rust-cache@v2`
is an **annotated** tag → pin the **dereferenced commit** (`v2^{}` = `e18b4977…`), not the tag-object
SHA (`42dc69e1…`, which would fail to check out); (c) `actions/checkout@v4` is a lightweight tag
(SHA == commit, no deref).

### Re-verification step (put in the PR body; run before committing — G2-1 acceptance)

```sh
gh api repos/actions/checkout/commits/v4           --jq .sha   # expect 34e11487…
gh api repos/dtolnay/rust-toolchain/commits/stable --jq .sha   # MOVES OFTEN — re-resolve + update the date comment
gh api repos/Swatinem/rust-cache/commits/v2        --jq .sha   # expect e18b4977…  (git ls-remote … 'v2^{}' without gh)
```

`dtolnay/rust-toolchain@stable` is force-updated frequently; **re-resolve it fresh at implementation**
and update the `# stable branch @ <date>` comment. checkout/rust-cache are stable. **Acceptance
(G2-3):** no `actionlint` in the repo → a YAML parse + a green CI run whose log still shows the stable
toolchain installed with clippy/rustfmt present is the evidence.

---

## G3 — Warn when the output directory is a symlink

**Lineage** ToB Mar 2026. **Locked** warn, don't fail. **Decisions** D-G3a (final-component only) +
D-G3b (orthogonal `fs_util` helper, don't unify the validator) + the G3-1 amendment above.

### Boundary map — files touched

| File | Change |
|---|---|
| `bins/ethernal/src/fs_util.rs` | **New** pure detector + warner (below) + unit tests. Natural home: already holds `probe_dir_writable` and the symlink-in-tests idiom (`fs_util.rs:99`). |
| `bins/ethernal/src/key_cli.rs` | One line after `validate_output_dir(&output_dir)?` (`:265`) — covers `key new/recover`. |
| `bins/ethernal/src/account_cli.rs` | One line after `:177` — covers `account new/recover`. |
| `bins/ethernal/src/gen_cli.rs` | One line inside `if !dry_run` after `:222` — covers the `gen` deposit-data output dir. |

`validate_output_dir` (both the shared `key_cli.rs:332` and the private `gen_cli.rs:362` copy) is
**left byte-for-byte unchanged** (D-G3b).

### New items + signatures (in `fs_util.rs`)

```rust
use std::io::Write;                    // add
use std::path::{Path, PathBuf};        // add PathBuf

/// If `dir`'s FINAL component is a symlink, returns its fully-resolved real path.
/// `None` for a normal directory on ANY platform — including macOS temp dirs
/// (`/tmp`,`/var`→`/private/…`), whose final component is a real dir, not a link
/// (this is the false-positive that a canonicalize-divergence check would trip;
/// G3-1 amended, D-G3a). Advisory only (S-3): never consulted to decide where or
/// how a file is written.
pub(crate) fn symlinked_output_dir(dir: &Path) -> Option<PathBuf> {
    match std::fs::symlink_metadata(dir) {              // lstat — does NOT follow the final component
        Ok(m) if m.file_type().is_symlink() => std::fs::canonicalize(dir).ok(),
        _ => None,
    }
}

/// Emits exactly ONE `WARNING:` line to `warn_out` naming the given path and its
/// resolved target when `dir`'s final component is a symlink; returns whether it
/// warned. No behavior change beyond the text (S-2/S-3).
pub(crate) fn warn_if_symlinked_output_dir(dir: &Path, warn_out: &mut dyn Write) -> bool {
    match symlinked_output_dir(dir) {
        Some(real) => {
            let _ = writeln!(
                warn_out,
                "WARNING: output directory \"{}\" is a symlink; keystores will be written to \"{}\".",
                dir.display(), real.display()
            );
            true
        }
        None => false,
    }
}
```

`canonicalize` requires existence, which `validate_output_dir` has already proven on the happy path,
so it won't error there; a race that makes it fail yields `None` (no warning) — fail-safe for a
warn-only signal. **No TOCTOU hardening** (research g3 §TOCTOU): the file-level guarantee is the
`O_EXCL`/`create_new` publish in `write_new_0600` (proven by
`fs_util::symlink_probe_does_not_touch_canary_target`, `:99`); a dir swapped after the check only makes
the *warning* stale, never introduces a write vulnerability (S-3).

### Call path (identical shape at all three sites; `warn_out = banner_out` = stderr in prod)

```
load_config(m, [mode,] banner_out)
  … validate_output_dir(&output_dir)?               // unchanged: existence + is_dir + writability probe
  fs_util::warn_if_symlinked_output_dir(Path::new(&output_dir), banner_out);   // ← NEW, one line, one warning
  … print_banner(banner_out, &cfg)                  // unchanged
```

Placed **after** the `?` so a non-existent/unwritable dir errors out first (no warning on a dir that
won't be used); before the banner is fine (both go to stderr). `gen`'s site sits inside the existing
`if !dry_run` block, so `--dry-run` (which never touches disk) stays warning-free.

### Test architecture — cover BOTH call sites (the SM-3 subtlety)

Because the warn call is wired at the **call sites**, `key` and `account` are two distinct wirings;
SM-3 literally names "`key` **and** `account`." Testing only one leaves the other silently
unverified. Coverage, cheapest-faithful, no binary spawn / no scrypt:

- **Unit (detector), `fs_util.rs`:** `symlinked_output_dir` — real `mkdir`'d dir → `None`; a
  `std::os::unix::fs::symlink` → that dir, passed as the arg → `Some(resolved)`. And
  `warn_if_symlinked_output_dir` with a `Vec<u8>`: real dir → returns `false`, buffer empty; symlink →
  returns `true`, buffer holds **exactly one** line naming **both** paths. (Copy the `symlink`-in-tests
  idiom already at `fs_util.rs:99`.)
- **Unit (both call-site wirings), `key_cli.rs` + `account_cli.rs`:** model on the existing
  `validate_output_dir_negative` tests (`key_cli.rs:609`, `account_cli.rs:482`). Build
  `key recover --output-dir <symlink> --count 1 --start-index 0` matches, call
  `load_config(m, KeyMode::Recover, &mut banner_vec)`, assert `banner_vec` contains **one** symlink
  `WARNING` naming both paths; a `<real dir>` run → no `WARNING`. Same for `account recover`.
  `recover`-mode `load_config` only parses + validates + banners (no TTY gate, no pipeline, no scrypt),
  so this is deterministic and fast while exercising the *real* production wiring at `:265` / `:177`.
- **`gen`** shares the `fs_util` helper; its call site (`:222`, non-dry-run) is covered by the detector
  unit test. An analogous `gen_cli` `load_config` test is *optional* parity, not required by SM-3.

Existing E2E suites stay green (they write into real temp dirs → `warn_if_symlinked_output_dir` returns
`false`, no new stderr line to disturb their assertions).

### Failure modes

- Symlinked dir → one `WARNING`, then unchanged write (still `O_EXCL` + link-publish + `0600` +
  refuse-overwrite). Operator-visible signal only.
- `canonicalize` race → `None` → no warning; the write still succeeds or fails on its own merits.
- Non-symlink dir → zero warnings (no false positive on any platform, incl. dev Macs).

---

## G4 — Batch-distinctness E2E regression test (zero product-code change)

**Lineage** GHSA-c6rv-g6pj-r6qx / ETHSTAKER-6. **Locked** `recover --count` on real OS entropy.
**Boundary** `bins/ethernal/tests/` **only** — diff must be zero under `bins/ethernal/src` and
`crates/` (G4-4). The code is already correct (fresh CSPRNG salt/iv/uuid per keystore inside the loop,
`key_cmd.rs:344-351`, `account_cmd.rs:351-358`; `encrypt.rs` takes drawn bytes, draws no RNG); G4 is
the **behavioral** guard that a future refactor can't silently reintroduce reuse.

### Boundary map — files touched

| File | Change |
|---|---|
| `bins/ethernal/tests/key_e2e.rs` | New `#[test]` reusing `run_key_recover(dir, 3)` + `keystore_files(dir)`. |
| `bins/ethernal/tests/account_e2e.rs` | New `#[test]` reusing `run_account_recover(dir, 3)` + `v3_files(dir)`. |

Both harness helpers already take `count` and are exercised at `count = 2` today
(`key_e2e.rs:79`, `account_e2e.rs:80`); bumping to 3 is the whole driver. Do **not** touch the frozen
`COUNT = 2` golden constant — the new tests pass `3` literally.

### Exact JSON field paths (verified from `encrypt.rs` / `encrypt_v3.rs` source)

| Field | BLS v4 (`key_e2e`) — nested | EOA v3 (`account_e2e`) — flat |
|---|---|---|
| salt | `v["crypto"]["kdf"]["params"]["salt"]` | `v["crypto"]["kdfparams"]["salt"]` |
| IV | `v["crypto"]["cipher"]["params"]["iv"]` | `v["crypto"]["cipherparams"]["iv"]` |
| UUID | `v["uuid"]` (top-level) | **`v["id"]`** (top-level) — NOT `uuid` (G4-2 amended) |
| identity | `v["pubkey"]`, `v["path"]` | `v["address"]` |

BLS paths confirmed against the `Serialize` structs at `encrypt.rs:59-97` (`uuid` top-level;
`kdf.params.salt`; `cipher.params.iv`) and the existing `key_e2e.rs:217` (`crypto.kdf.function`). EOA
`id`/`address`/`kdfparams`/`cipherparams` confirmed against `account_e2e.rs:332-343`.

### Test shape (identical logic, per path)

```
run_*_recover(dir, 3)                     // fixed mnemonic over stdin; real OS entropy for salt/iv/uuid
files = *_files(dir); assert files.len() == 3        // G4-3: fail loudly if fewer than requested
for f: read raw JSON (serde_json::from_slice) — DO NOT decrypt (research g4 §1: byte compare only)
collect salt[], iv[], uuid_or_id[], identity[]
for each of salt / iv / uuid_or_id: assert HashSet::from(col).len() == 3   // pairwise-distinct, not adjacent (G4-3)
assert identity distinct too (pubkey+path for BLS, address for EOA) — proves 3 real validators, not 3 copies
```

Read raw JSON only — **no `Loader::load`** in these tests; distinctness is a byte comparison, and
decrypting three N=262144 scrypt keystores per path would be wasted cost. Runtime is bounded: the only
scrypt work is the CLI's own encrypt of 3 files per path (6 total across both tests), vs the 4 the
suite already pays at `count = 2`.

### "Prove it bites" (G4-4, comment only — never committed)

Each test carries a comment documenting the local verification: temporarily replace the CLI's
`OsEntropy` with fixed bytes (or wire the `#[cfg(test)]` `FixedEntropy`) and rebuild → the salt/iv sets
collapse to size 1 → the test goes **red**; revert. There is deliberately **no** entropy-injection flag
on the CLI (enforced by `key_recover_help_has_no_entropy_flag` / `..._no_entropy_or_time_flag`, S-4),
so the guard cannot be toggled at runtime — and must not gain a flag. If a real-entropy batch path were
somehow unreachable, **escalate** in the run summary rather than weakening to `FixedEntropy`.

---

## Cross-cutting

**Dependency direction / edges (unchanged).** No new crate, dep, or edge (D-1). G1/G3 add functions
inside `bins/ethernal`; G4 adds tests; G2 is YAML. `keystore::encrypt` stays a pure drawn-bytes-in
function — the exact invariant G4 guards.

**Security invariants preserved.** S-1: G1 writes clear/notice **only** to the display `tty` handle,
warning text carries no mnemonic bytes. S-2: only two user-visible changes, both additive (G1 clear +
notice, G3 stderr warning); entropy sourcing, TTY-only fail-closed display, atomic `0600`
refuse-overwrite, and the per-keystore CSPRNG loop are untouched. S-3: G3 reads metadata + emits text
only, never redirects the write.

**Merge model (C-1).** Four independent fast-forward commits on `develop`, each green under
`make lint && make test`. Default order **G1 → G2 → G3 → G4**; G2 (CI-only, stream B) may interleave
anywhere. No shared file between gaps except that G3 and G4 both live under `bins/ethernal` in
different files → no merge coupling.

## Traceability & checklist

| SM | Gap | Mechanical evidence |
|---|---|---|
| SM-1 | G1 | `run_ceremony` result-capture + `clear_after_ceremony`; 4 unit tests (bytes/order, abort-clears, fail-open→stderr via `FailAfterDisplay`, notice); USER-GUIDE ×2 flows. |
| SM-2 | G2 | 3 `uses:` = full SHA + comment; `dtolnay` carries `with: toolchain: stable`; YAML parse + green CI. |
| SM-3 | G3 | `fs_util` detector/warner unit tests + `load_config` symlink tests on **both** `key` and `account` call sites; real dir → warning-free. |
| SM-4 | G4 | `--count 3` pairwise-distinct salt/iv/(uuid\|id)+identity on BLS and EOA; test-only diff. |

- [x] No new dependency / crate edge (D-1).
- [x] Each gap independently landable, per-issue ff (C-1).
- [x] G1 clears on all five post-display paths; recover unchanged (empty-tty assertions green).
- [x] G1 fail-open exercised against **stderr** (writer-trap fix), not vacuously.
- [x] G3 zero false positives on macOS (final-component only); both call sites tested.
- [x] G4 zero product-code diff; field paths verified (incl. EOA `id`).
- [x] Failure modes defined per gap; security invariants S-1..S-3 preserved.

## Open items (for the implementer, not blockers)

- **G2:** re-resolve `dtolnay/rust-toolchain@stable` fresh (fast-moving branch); spot-check the other
  two via the commands above.
- **G3 warning wording:** the exact `WARNING:` string is illustrative — keep the `WARNING:` prefix
  (repo tone, `sign_cmd.rs:48`) and both paths on one line; the tests assert *count == 1* and *both
  paths present*, not the literal phrasing.
- **G1 USER-GUIDE:** lift the tmux/screen commands verbatim into `docs/USER-GUIDE.md` §207 / §320 / §95.
