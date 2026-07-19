# Research — e2e test suite for `ethernal`

> **Status (2026-07-19):** R1's PTY-driver verdict is **deferred by a binding user scope decision** — "building
> a new PTY driver is not in scope for this stage; assume the mnemonic is GIVEN." The research below remains
> **valid and on file for a possible future PTY stage**; it is not withdrawn. This stage assumes the mnemonic
> is given via a committed fixture and driven through the non-interactive `recover` path (see the revised
> [`../prd.md`](../prd.md), [`../architecture.md`](../architecture.md) §"Deferred: PTY tier", and
> [`../issues/deferred.md`](../issues/deferred.md)). R2–R5 (anvil, gating, v3 validation, prior art) are
> unaffected.

Resolves the open questions in [`../prd.md`](../prd.md) with evidence (empirical where possible; the R1 PTY driver and R2 anvil mechanics were spiked against the real binary on this Darwin box). One doc per topic; verdicts first, evidence below, each ends with "Consequences for architecture."

## Verdicts

| Doc | Topic | One-line verdict |
|---|---|---|
| [r1-pty-driver.md](r1-pty-driver.md) | PTY driver (headline, OQ-1) | **Hand-roll over `libc`** — a ~140-SLOC `openpty`+`pre_exec`(setsid+TIOCSCTTY) harness drove the full real `key new` ceremony to an on-disk v4 keystore; **A-1 survives**, no dev-dep needed, `rexpect` is the fallback. |
| [r2-anvil-ci.md](r2-anvil-ci.md) | Anvil live tier + CI (OQ-2/OQ-3) | **Two isolated tiers; live tier not PR-blocking.** anvil 1.7.1 local, ephemeral port + ~79 ms readiness + cheatcodes all verified; CI installs Foundry via `foundry-rs/foundry-toolchain@b00af27efadbc7b4ca8b82abbd903b17cc874d2a # v1.9.0` (pin `version:` too). |
| [r3-test-gating.md](r3-test-gating.md) | Gating mechanics | **`#[ignore]` + `--include-ignored`**, selected by the existing `e2e*` binary filter — the repo's own `make e2e-mock` convention and reth's pattern. No features, no env gate. |
| [r4-v3-keystore-validation.md](r4-v3-keystore-validation.md) | v3 validation depth (OQ-4) | **Add a test-only `decrypt_v3`** (crate `test-support` feature, reuses in-crate crypto, no new deps, compiled out of the release binary) — address-match alone does **not** prove the ciphertext decrypts; the Q3 veto forbids only an *in-binary* reader. |
| [r5-prior-art.md](r5-prior-art.md) | Prior art | Capture-and-replay the mnemonic keyed on prompts (ethstaker), drive the anvil *binary* via alloy's spawn+`Listening on`+`--port 0` pattern, `#[ignore]` the heavy tier out-of-band (reth). |

## What changes (or confirms) the PRD's assumptions

- **A-1 (hand-rolled PTY) — CONFIRMED by spike.** The headline assumption holds: the hand-roll is small, dep-free, and drove the entire ceremony end-to-end. `expect(1)` is independently **eliminated** by C-5 (no external toolchain in the hermetic tier), so the real choice was always hand-roll vs. one Rust crate; C-1 + the spike pick hand-roll. **OQ-1 resolved.**
- **NEW, not in the PRD — scrypt-in-debug is a hidden cost that the plan must budget for.** `cargo test` drives the *debug* binary; `key new`/`account new` run scrypt at production `n=262144` with **no** param-injection hook, so each ceremony test takes **~18 s** at default debug opt-level (measured). Fix (verified with the *exact* targeted override, not just a whole-profile bump): `[profile.dev.package.scrypt] opt-level = 3` in the workspace `Cargo.toml` → **~1.0 s**. Robust fallback if a future scrypt moves its hot loop into `salsa20`: `[profile.dev.package."*"] opt-level = 2`. Without this, ~10 ceremony tests add ~3 minutes to every PR run. **This is the single most important thing architecture must not miss.**
- **NEW — T-1 needs a two-channel (split-stderr) harness for T-5, verified.** Proving "the mnemonic never reaches a non-TTY fd" requires spawning with stderr on a plain pipe (fd 2 is free — the TTY gate checks only fds 0/1); prompts then arrive on the stderr pipe and the mnemonic on the PTY, so the expect loop reads both. Spiked and passing (mnemonic present on PTY, absent from the 592-byte stderr capture).
- **A-2 / OQ-2 — CONFIRMED not PR-blocking**, with the concrete pinned Foundry SHA supplied. Also flags a second pin the PRD didn't call out: the action's `version:` input **floats on `stable`** — pin an explicit Foundry version for determinism.
- **OQ-3 — CONFIRMED skip-with-message locally**, CI installs via the pinned action.
- **OQ-4 — RECOMMENDATION STRONGER THAN THE PRD's v1 floor.** The PRD leans toward structural + recover-address-cross-check only; research found that leaves the v3 **encrypt** path unverified through the binary (the `address` field is written independently of the ciphertext, so a v3-encrypt bug passes address-match). A cheap, veto-compliant test decrypt closes it and restores parity with the v4 `Loader` round-trip. The PRD's floor remains acceptable if annotated honestly.
- **OQ-5 (automate `run --rpc-url` live, T-17) — CONCUR with the PRD: defer / P2.** `run` is `build`+`sign` composed, and both stages are live-exercised by the T-6 pipe chain; the only thing unique to `run` (the in-process build→sign hand-off with no serialization) is low-risk and hermetically covered by `run::local_signer_happy_path`. Marginal value does not justify a second anvil-backed test. Revisit only if `run` grows logic beyond composing the two stages. No new evidence changes this.
- **A-3 (anvil params) — CONFIRMED**; recommend the `--port 0` + `Listening on` stdout-scrape over bind-and-close for a race-free ephemeral port.
- **C-4 portability notes for architecture:** `openpty` needs `std::ptr::null_mut()` (compiles on macOS *and* Linux); on glibc ≥ 2.34 (ubuntu-latest) `openpty` is in libc with no extra link flag; `posix_openpt`+`grantpt`+`unlockpt` is the pure-POSIX fallback if ever needed.

## Spike artifacts

The R1 PTY spike (standalone crate, `libc`-only) lives in the run scratchpad at `scratchpad/pty-spike/` (`src/pty.rs` = the reusable harness to lift into `tests/common/pty.rs`; `src/main.rs` = the ceremony driver). It is not committed to the repo tree; the harness reference implementation is embedded in [r1-pty-driver.md](r1-pty-driver.md)'s consequences.
