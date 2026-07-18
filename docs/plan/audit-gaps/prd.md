# PRD — Audit Gap Closure (deposit-cli / EOA-keystore lineage, audit 2026-07-18)

**Status:** draft (orchestrated — the final approval gate is owned by the team lead; this document is requirement-gathering only).
**Binding gap source:** `1.Projects/ethernal/202607181903 - Audit - ethernal Implementation vs Known deposit-cli and EOA Keystore Issues.md` (the issue-by-issue code audit of `develop` @ `0308f66`).
**Owner feature docs (own the *how*):** [`overview.md`](overview.md) (traceability + disposition D1) and [`issues/g1.md`](issues/g1.md)–[`issues/g4.md`](issues/g4.md) (locked per-gap design). This PRD states *what* and *why*.
**House style:** mirrors [`../keygen/prd.md`](../keygen/prd.md) and [`../eoa-keystore/prd.md`](../eoa-keystore/prd.md) (requirement-ID + P0/P1/P2 convention). This effort is the post-audit analogue of [`../keygen/hardening-plan.md`](../keygen/hardening-plan.md) (the H-series) — the audit is "well implemented, four gaps remain," and this closes them.
**Scope in one line:** close audit gaps 1–4 (terminal-scrollback clear after the mnemonic ceremony, SHA-pinned CI actions, symlinked-output-dir warning, batch-distinctness regression test) on `develop`, flipping four audit rows toward mitigated; gap 5 (release signing/attestation) is deferred to the future release pipeline.

---

## Problem statement

The 2026-07-18 code audit traced every known `staking-deposit-cli` / `ethstaker-deposit-cli` / EOA-keystore vulnerability class (Trail of Bits 2020 / 2024 / 2026 + GHSA-c6rv-g6pj-r6qx) directly into this codebase. **Verdict: well implemented** — all High-severity classes from the three ToB audits and the GHSA advisory are structurally mitigated, most with regression tests. Exactly four residual gaps remain; this effort closes them. Each is small (≤ 2 pts), independent, and either a defense-in-depth improvement or a regression guard — none is a live High-severity hole.

The four gaps and why they still matter:

1. **No terminal-scrollback clear after the mnemonic ceremony** (audit gap 1). The mnemonic is displayed on `/dev/tty` (fail-closed without a TTY) and then remains in terminal scrollback — the one finding that recurred in *every* upstream deposit-cli audit (DEP-001 2020 → ETHSTAKER-7 2026). No clear sequence exists anywhere in the binary today, and the risk is not documented in the USER-GUIDE.
2. **CI actions pinned to mutable tags** (audit gap 2). `.github/workflows/ci.yml` uses `@v4` / `@stable` / `@v2`; a compromised or retagged upstream action could execute arbitrary code in CI (ETHSTAKER-1). Low stakes while CI only lints and tests — but a hard prerequisite for the release/signing pipeline (gap 5), so it must be pinned before that pipeline lands.
3. **No symlinked-output-dir warning** (audit gap 3). File-level writes are already symlink-safe (`crates/ethernal-core/src/output.rs` `write_new_0600`: `O_EXCL` create, tmp+fsync+`hard_link` publish; the writability probe was made symlink-safe in hardening H5). Remaining gap: a symlinked *output directory* is silently followed, so keystores can land on an unexpected filesystem, a weaker-permission mount, or an attacker-chosen dir with no operator signal (Trail of Bits Mar 2026 recommendation).
4. **No batch-distinctness regression test** (audit gap 4). The code is correct today — fresh CSPRNG salt/IV/UUID per keystore inside the loop (`bins/ethernal/src/key_cmd.rs:344-351` BLS, `bins/ethernal/src/account_cmd.rs:351-358` EOA) — but the only tests exercising a batch use `FixedEntropy`, where all keystores *intentionally* share salt/IV. A regression reintroducing salt/IV reuse (the catastrophic GHSA-c6rv-g6pj-r6qx / ETHSTAKER-6 class) would pass the current suite undetected.

## Target users

Validator operators (BLS keys) and EOA operators (secp256k1 keys) who run `ethernal` on **air-gapped or bastion hosts** to generate and recover keys. They are security-sensitive: the mnemonic and derived secrets must never escape the process via stdout, stderr, logs, or a non-interactive stream, and keys are frequently generated on a machine whose terminal history, filesystem mounts, and CI supply chain are all part of the threat model. Gap 1 protects the mnemonic they just displayed on a shared or logged terminal; gap 3 protects the directory they write to; gaps 2 and 4 protect the toolchain and the code that produced their keys.

## Goals & success metrics

Success is **auditable**: each gap flips a specific row of the audit's issue-by-issue table and ships test (or CI) evidence. IDs are `SM-*` to avoid colliding with the per-gap requirement IDs (`G#-n`) below.

| # | Gap → audit row | Outcome (was → becomes) | Evidence |
|---|---|---|---|
| SM-1 | Gap 1 → **ETHSTAKER-7** — scrollback not cleared (DEP-001 recurrence) | ❌ Gap → ✅ **Mitigated (success path; fail-open warns, multiplexer caveat documented)** | G1 unit tests: exact clear byte-sequence, clear-after-mnemonic ordering on the tty buffer, abort path still clears, fail-open warning lands on the fallback writer; USER-GUIDE documents the automatic clear + fail-open + tmux/screen caveat in both flows |
| SM-2 | Gap 2 → **ETHSTAKER-1** — unpinned GitHub Actions | ❌ Gap → ✅ **Mitigated** | Every `uses:` in `ci.yml` is a full 40-char commit SHA + version comment; `dtolnay/rust-toolchain` carries `with: toolchain: stable`; `actionlint`/YAML parse passes; CI semantics unchanged |
| SM-3 | Gap 3 → **ToB Mar 2026 rec.** — warn on symlinked output dir | ❌ Gap → ✅ **Mitigated** | Integration test: symlinked output dir → exactly one warning naming given → resolved path; real dir → warning-free; existing suites green |
| SM-4 | Gap 4 → **GHSA-c6rv-g6pj-r6qx / ETHSTAKER-6** — salt/IV reuse across batch | ✅ Mitigated → ✅ **Mitigated + regression-guarded** (gap-list item 4 closed) | E2E test asserts pairwise-distinct `salt` / `iv` / `uuid` across a **real-entropy** `--count 3` batch on both BLS and EOA paths; fails if `FixedEntropy` is temporarily wired in |

**Non-goal reminder (measured by absence):** the audit row **DEP-007 / ETHSTAKER-2** (release signing/attestation) stays `⏳ Open`; see [Non-goals](#non-goals) / disposition D1.

## Locked decisions (carried verbatim)

These are settled inputs, not open for this PRD to reopen:

- **G1 uses clear-on-confirm** (automatic ANSI 2J/3J/H to `/dev/tty`, twice, on every post-display exit path; fail-open with warning; tmux/screen caveat documented).
- **G3 warns, does not fail** (the ToB recommendation is a warning).
- **G4 uses the `recover --count` path with real OS entropy** (`new` requires a TTY; salt/IV/UUID are drawn at encrypt time identically for `new`/`recover`).
- **Merge model:** per-issue fast-forward commits on `develop`; every merge green (`make test && make lint`).

---

## Functional requirements

Priority: **P0** = must ship to close the gap and earn the audit-row flip; **P1** = required for the gap to be *complete* (operator-facing clarity), non-blocking for the security flip itself; **P2** = polish. Requirement IDs are gap-scoped: `G1-1`, `G2-1`, … Each gap lists its requirements, then its acceptance criteria (checkbox = release bar).

### G1 — Clear terminal scrollback after the mnemonic ceremony

**Lineage:** DEP-001 (ToB 2020) → ETHSTAKER-7 (ToB 2026). **Locked:** clear-on-confirm. **Scope:** `run_ceremony` in `bins/ethernal/src/key_cmd.rs` (the single mnemonic-display site, shared by `key new` and `account new`), the `account_cmd.rs` call site, and `docs/USER-GUIDE.md`. Recover flows never display and must stay unchanged (existing tests assert an empty tty buffer).

| ID | Pri | Requirement |
|---|---|---|
| G1-1 | **P0** | Write `ESC[2J ESC[3J ESC[H` to the **same `/dev/tty` handle used for display** (never stdout), the whole sequence **twice**, then flush — on **every** post-display exit path: successful confirm, mismatch-abort (exit 4), SIGINT/cancel, read error, and partial display write. No terminfo, no new dependency. |
| G1-2 | **P0** | **Fail-open.** A failed clear write never turns a completed ceremony into an error: print a loud manual-clear warning (`clear && printf '\x1b[3J'`; Cmd+K in Terminal.app) to the TTY, falling back to stderr, and continue. The exit code of an otherwise-successful ceremony is unchanged. |
| G1-3 | **P1** | On a successful clear, print a short notice on the now-blank TTY — cleared to remove the mnemonic, plus the tmux/screen multiplexer caveat — in the existing ceremony message tone. |
| G1-4 | **P0** | `docs/USER-GUIDE.md` documents the automatic clear in both `key new` and `account new` flows: *why* (recurring audit finding), the fail-open warning behavior, and the **multiplexer caveat** (`3J` cannot reach a multiplexer's own scrollback: `tmux clear-history`, screen `C-a :scrollback 0`). P0 because the locked decision mandates that the tmux/screen caveat be documented, and SM-1 relies on it. |
| G1-5 | **P0** | Unit tests via the writer-injection pattern (`KeyDeps`/`AccountDeps`): exact clear byte-sequence; clear-after-mnemonic ordering on the tty buffer; abort path still clears; clear-failure warning lands on the fallback writer. No pty harness (the pipe-driven secret-hygiene E2E suites cover `recover` only, which has no ceremony) — do not over-engineer. |

**Acceptance criteria**
- [ ] Every path that displayed the mnemonic (or part of it) emits the clear sequence twice before the process advances or exits; recover flows unchanged (empty-tty-buffer assertions stay green). *(G1-1)*
- [ ] A clear-write failure warns loudly with manual-clear instructions and does **not** change the exit code of an otherwise-successful ceremony. *(G1-2)*
- [ ] A successful clear prints the notice + multiplexer caveat on the blank TTY. *(G1-3)*
- [ ] New unit tests cover sequence bytes, ordering, abort path, and the fail-open warning; USER-GUIDE updated in both flows; `make lint && make test` green. *(G1-4, G1-5)*

**Residual risk (accepted, stated so SM-1 is auditable):** on the fail-open path (G1-2) and in a panic between display and clear (the repo has **no** drop guard — a `run_ceremony` panic in that window skips the scrub), the mnemonic remains in scrollback; the operator is warned in the former, the latter is a stated residual. `3J` clears the emulator's scrollback but cannot reach a terminal multiplexer's own history — a documented limitation, not fixable from the child process. This is why SM-1 reads "Mitigated (success path)," not an unconditional scrub.

### G2 — Pin GitHub Actions to full commit SHAs

**Lineage:** ETHSTAKER-1 (ToB 2026). **Scope:** `.github/workflows/ci.yml` — the only workflow; three third-party actions (`actions/checkout@v4`, `dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`). Low stakes today, but a hard prerequisite for the future release/signing pipeline (disposition D1), which must start from pinned actions.

| ID | Pri | Requirement |
|---|---|---|
| G2-1 | **P0** | Replace each mutable tag with the full 40-char commit SHA it currently resolves to, with a trailing human-readable version comment, e.g. `uses: actions/checkout@<sha> # v4.x.y`. Resolve **annotated** tags to the *commit* they point at (deref tag → commit), not the tag-object SHA. |
| G2-2 | **P0** | `dtolnay/rust-toolchain`: `@stable` is **both** the action version and the toolchain selector. When pinning to a SHA, set the toolchain explicitly (`with: toolchain: stable`) so toolchain selection keeps working (per that action's documented SHA-pinning usage). |
| G2-3 | **P0** | No other workflow change: no version upgrade beyond what the tag already resolved to (unless a current tag is unresolvable); CI semantics unchanged. |

**Acceptance criteria**
- [ ] Every `uses:` in `ci.yml` references a full commit SHA + version comment; comment versions match the SHAs (spot-check via `git ls-remote` / GitHub API). *(G2-1)*
- [ ] `dtolnay/rust-toolchain` carries `with: toolchain: stable`; the stable toolchain is still selected in a CI run. *(G2-2)*
- [ ] `actionlint` (if available) or a YAML parse passes; CI runs and stays green with identical semantics. *(G2-3)*

### G3 — Warn when the output directory is (or resolves through) a symlink

**Lineage:** Trail of Bits Mar 2026 recommendation. **Locked:** warn, do not fail. **Scope:** output-directory validation for both CLIs — BLS (`key new` / `key recover`, and the separate deposit-data command's output dir if it validates through a distinct path) and EOA (`account new` / `account recover`) — starting from `bins/ethernal/src/fs_util.rs` and the H5 writability probe (read that code first). File-level writes are already symlink-safe; this closes the directory-level gap.

| ID | Pri | Requirement |
|---|---|---|
| G3-1 | **P0** | At output-dir validation time, detect whether the user-supplied path's **final component** is a symlink (`symlink_metadata`) **and** whether `canonicalize` diverges from the given path (catches symlinked *intermediate* components) — without following anything untrusted beyond `canonicalize`. |
| G3-2 | **P0** | On detection: **warn, do not fail.** Print the given path and the resolved real path to stderr in the repo's existing warning style, then proceed. Behavior is otherwise unchanged (still `O_EXCL` + link-publish + `0600` + refuse-overwrite). |
| G3-3 | **P0** | Unit/integration test with a tempdir: real dir → no warning; symlinked dir → exactly one warning naming both paths; existing E2E suites stay green. |

**Acceptance criteria**
- [ ] `key` and `account` generation into a symlinked output dir emits exactly one warning showing given → resolved path; non-symlinked runs are warning-free. *(G3-1, G3-2)*
- [ ] No behavior change beyond the warning (files still written atomically, `0600`, refuse-overwrite). *(G3-2)*
- [ ] `make lint && make test` green with the new test. *(G3-3)*

### G4 — Batch-distinctness E2E regression test (salt/IV/UUID across `--count > 1`)

**Lineage:** GHSA-c6rv-g6pj-r6qx / ETHSTAKER-6 — the catastrophic upstream class (salt/IV reused across a keystore batch). **Locked:** exercise the `recover --count` path with **real OS entropy** — `new` needs a TTY, and salt/IV/UUID are drawn at *encrypt* time identically for `new` and `recover`, so `recover --count N` exercises the exact loop the GHSA class regressed in. **Scope:** new integration/E2E test(s) under `bins/ethernal/tests/` (follow `key_e2e.rs` / `account_e2e.rs` harness patterns). **No product-code change.**

| ID | Pri | Requirement |
|---|---|---|
| G4-1 | **P0** | BLS path: drive `key recover` (harness equivalent) with `--count 3` on the **real OS entropy** path (not `FixedEntropy`), using a fixed test mnemonic via the harness's existing input mechanism; parse the three EIP-2335 JSONs; assert **pairwise-distinct** `crypto.kdf.params.salt`, `crypto.cipher.params.iv`, and top-level `uuid`; also assert distinct derivation paths / pubkeys (sanity that three different validators were produced). |
| G4-2 | **P0** | EOA path: `account recover --count 3` (confirmed supported — [`../eoa-keystore/prd.md`](../eoa-keystore/prd.md) F-8); the same pairwise-distinct assertions on the v3 keystores — `salt`, `iv`, `uuid`, and `address`. |
| G4-3 | **P0** | Distinctness is asserted across the **full** batch (pairwise, not adjacent-only); the test fails loudly if fewer files than requested appear. |
| G4-4 | **P0** | **No changes to product code.** If the harness genuinely cannot reach a real-entropy batch path, escalate in the run summary rather than weakening the test to `FixedEntropy`. |

**Acceptance criteria**
- [ ] New tests fail if `salt`, `iv`, or `uuid` collide anywhere in a `--count 3` batch (verifiable by temporarily wiring `FixedEntropy` locally — **not** committed). *(G4-1, G4-2, G4-3)*
- [ ] Both BLS and EOA batches covered; suites green under `make test`; runtime bounded (scrypt cost: 3 keystores per path, no more). *(G4-1, G4-2)*
- [ ] Diff is test-only — zero changes under `bins/ethernal/src` or `crates/`. *(G4-4)*

---

## Non-functional requirements

### Security invariants (preserved — this effort must not weaken them)

| ID | Invariant |
|---|---|
| S-1 | **No new secret exposure.** G1 writes the clear sequence only to the same `/dev/tty` handle used for display; the mnemonic never reaches stdout/stderr/logs, and the fail-open warning contains manual-clear instructions only — no mnemonic bytes. The audit's DEP-001 display-half mitigation (TTY-only, fail-closed) is unchanged. |
| S-2 | **No behavior change beyond G1's clear+notice and G3's warning.** Entropy sourcing (OS CSPRNG only, no hidden flag), fail-closed TTY-only mnemonic display, atomic `0600` refuse-overwrite output, and the per-keystore fresh CSPRNG salt/IV/UUID loop are all untouched. G2 is CI-only; G4 is test-only. |
| S-3 | **G3 stays within the trust boundary.** The symlink check never follows an untrusted path beyond `canonicalize` and never changes where or how the file is written; it only emits an operator signal. |

### Dependencies

| ID | Requirement |
|---|---|
| D-1 | **No new third-party dependency.** G1's clear is hard-coded ANSI bytes (no terminfo/ncurses). G2 introduces no new action — the same three, pinned. G3 uses `std` (`symlink_metadata` / `canonicalize`). G4 is a test on the existing harness. Consistent with the repo's auditable-minimal-dependency philosophy. |

### Compatibility & process

| ID | Requirement |
|---|---|
| C-1 | **Merge model (locked):** per-issue fast-forward commits on `develop`, one ordinary commit per issue; every merge green (`make test && make lint`). Behavior changes ship with tests. All four issues are independent; default order is G1 → G2 → G3 → G4, and G2 (CI-only, stream B) can interleave anywhere. |
| C-2 | **Only two user-visible changes**, both additive: G1 (clear + notice after the ceremony) and G3 (a stderr warning on a symlinked output dir). No flag, exit-code, keystore-format, or filename change. G2 and G4 are invisible to end users. |

---

## Non-goals

Explicitly **out of scope** for this effort:

- **Gap 5 — release signing / attestation (DEP-007 → ETHSTAKER-2), disposition D1.** Deferred by the audit itself: there is no release pipeline yet. **Trigger:** MUST land together with the first binary-release workflow (sigstore/SLSA-style attestation, or at minimum checksums + signature). G2 (SHA-pinned actions) is done now precisely so that future pipeline starts from pinned actions. The audit row DEP-007 / ETHSTAKER-2 stays `⏳ Open`.
- **Terminal-multiplexer scrollback history.** `3J` clears the emulator's scrollback but cannot reach tmux/screen history from the child process; documented as a caveat (G1-4), not solved here.
- **Prompt-to-clear / opt-in or disable-able clearing.** The locked decision is clear-on-confirm (automatic); no prompt, no flag.
- **A pty test harness for the `new`-ceremony clear.** G1-5 covers the clear via writer injection; the pipe-driven E2E suites exercise `recover`, which has no ceremony. A pty harness is deliberately not built.
- **Making G3 fail (non-zero exit) on a symlinked dir.** ToB's recommendation is a *warning*; failing would break legitimate symlinked-mount workflows.
- **Any product-code change for G4**, and no re-implementation of the already-correct per-keystore CSPRNG loop — G4 is a regression test only.
- **Re-litigating the audit's deliberate deviations** (passphrase minimum 8 bytes not 12; keystores `0600` not `0400`; runtime post-write decrypt-verify test-only). These are documented, intentional deviations — not gaps — and are unchanged here.
- **Windows support, clipboard handling, and custom-network JSON** — N/A by construction per the audit; unchanged.

## Assumptions

Genuine judgment calls I made where the sources left a decision open (locked facts are not repeated here):

- **A-1 — Priority split.** Within each gap I marked the security-load-bearing behavior and its test evidence **P0**, and only the on-screen success notice (**G1-3**) **P1**. Rationale: the ETHSTAKER-7 flip is earned by the clear itself plus its tests; a missing success notice does not leave the mnemonic in scrollback. **G1-4 (USER-GUIDE) is P0, not P1** — the locked decision mandates that the tmux/screen caveat be *documented*, and an operator who does not know `3J` cannot reach multiplexer history still has an unmitigated exposure, so SM-1's flip depends on it. G2, G3, and G4 are each a single small change with no meaningful sub-priority, so every requirement there is P0 — no manufactured P2 polish. **No requirement is P2.**
- **A-2 — SM-1 wording.** I record ETHSTAKER-7 as "✅ Mitigated (success path; fail-open warns, multiplexer caveat documented)" rather than an unconditional "✅ Mitigated," because the locked fail-open design and the no-drop-guard panic window are real residuals an auditor must see to close the row honestly. This is the auditable bar the G1 implementation must meet.
- **A-3 — Status/gate.** The header marks this "draft (orchestrated)" and I did **not** run a standalone review/approval loop, per the dev-plan pipeline convention where the team lead owns the gate. If this document is ever used standalone, the content applies pending a user gate.
- **A-4 — Execution context (not a requirement).** `overview.md` records that a drafted G1 implementation is preserved in `git stash` (`ccd0abe9`). This PRD specifies the *requirement*, not that draft; if the stash is applied, the G1 acceptance criteria above are the bar it must clear.

## Milestone gate

**M-AG (audit gaps closed):** G1–G4 each merged green on `develop` (`make test && make lint`), and the audit's issue-by-issue table + the project `0.README.md` open-gaps list updated to reflect:

- **ETHSTAKER-7** → ✅ Mitigated (success path; fail-open + multiplexer caveat documented) — *G1*
- **ETHSTAKER-1** → ✅ Mitigated (actions SHA-pinned) — *G2*
- **ToB Mar 2026 symlink rec.** → ✅ Mitigated (warn on symlinked output dir) — *G3*
- **GHSA-c6rv-g6pj-r6qx / ETHSTAKER-6** → ✅ Mitigated **+ regression-guarded**; gap-list item 4 closed — *G4*
- **DEP-007 / ETHSTAKER-2** → ⏳ Open, dispositioned **D1** (release-pipeline trigger) — unchanged, and its prerequisite (G2) is now satisfied.
