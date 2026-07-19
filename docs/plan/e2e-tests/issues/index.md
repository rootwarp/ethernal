# E2E test suite — issues index

Sprint-ready issues for the end-to-end test suite for `ethernal`. Detail folded in from
[`../project-plan.md`](../project-plan.md) (phases E1..E8, binding §"Sequencing choices the estimator
MUST respect"), [`../architecture.md`](../architecture.md) (binding — module APIs, file→requirement map,
decisions D-2..D-9, PRD amendments), and [`../prd.md`](../prd.md) (T-1..T-19 acceptance criteria).

> **Binding scope decision (2026-07-19):** the interactive `new`-ceremony **PTY tier is deferred to a
> future stage**; the mnemonic is *given* via the committed `ABANDON_12` fixture and driven through the
> non-interactive `recover` path. Six issues (E1-2, E1-3, E3-2, E3-3, E3-4, E4-1 — 14 pts) are moved to
> [`deferred.md`](deferred.md); **E3-1 is rescoped** to `account recover` + `decrypt_v3`. Surviving tags
> keep their numbers.

One file per phase: [`e1.md`](e1.md) · [`e2.md`](e2.md) · [`e3.md`](e3.md) · [`e4.md`](e4.md) ·
[`e5.md`](e5.md) · [`e6.md`](e6.md) · [`e7.md`](e7.md) · [`e8.md`](e8.md) · deferred: [`deferred.md`](deferred.md).

**12 required issues · 21 pts (E1–E7)** + **2 optional issues · 4 pts (E8)** = **14 issues / 25 pts**, plus
**6 deferred issues · 14 pts** (future PTY stage). 1 pt ≈ half a working day; every issue is ≤ 3 pts and
independently mergeable to `develop` via a fast-forward commit with `make lint && make test` green.
**Nature of the work: an additive extension of a mature ~130-test suite — no `bins/ethernal/src/**` behavior
change** (binding seq. #9).

---

## All issues (this stage)

| Tag | Title | Pts | Depends on | Discharges |
|---|---|---|---|---|
| **[E1-1]** | Scrypt debug-profile override (workspace `Cargo.toml`) | 1 | — | build-config prereq |
| **[E2-1]** | `decrypt_v3` test-support feature | 3 | — | enables T-3 |
| **[E3-1]** | v3 correctness via `account recover` + `decrypt_v3` (rescoped) | 2 | E2-1 | T-3 |
| **[E4-2]** | Symlink `--output-dir` warning on recover/stdin path | 1 | — | T-12·recover |
| **[E5-1]** | `gen` hoodi golden byte-diff + fixture accessor | 2 | — | T-7 |
| **[E5-2]** | Mainnet safety guard + golden + pipe gotcha | 2 | E5-1 | T-8 |
| **[E5-3]** | `gen --parallel` determinism | 1 | E5-1 | T-19 |
| **[E6-1]** | Anvil harness `tests/common/anvil.rs` | 3 | — | T-1 (anvil) |
| **[E6-2]** | Live pipe chain moves 32 ETH against anvil | 2 | E6-1 | T-6 |
| **[E6-3]** | Live hybrid RPC probes | 1 | E6-1 | T-13 |
| **[E6-4]** | `e2e-live.yml` — `workflow_dispatch`-only | 1 | E6-1, E6-2 | T-14·partial |
| **[E7-1]** | Makefile two-tier targets + `e2e-live.yml` triggers | 2 | E6-2, E6-3, E6-4 | T-14 |
| **[E8-1]** | `ws://` reject + SIGINT-during-estimation *(optional)* | 2 | — | T-15, T-16 |
| **[E8-2]** | Verify-skill parity checklist `verify-parity.md` *(optional)* | 2 | E3, E5, E6 | T-18 |

**Deferred to the future PTY stage** ([`deferred.md`](deferred.md)): E1-2 (PTY harness, 3), E1-3 (`key new`
ceremony T-2, 2), E3-2 (mismatch abort T-4, 2), E3-3 (new-path hygiene T-5, 2), E3-4 (mnemonic-passphrase +
scrollback + symlink·new T-10/11/12·new, 2), E4-1 (interactive recover prompt T-9, 3) — **14 pts.**

`T-1` this stage is only the **anvil harness** (E6-1); the PTY `PtySession` half is deferred (E1-2).

---

## Streams & ordering

The old two-stream A/B split **collapses** with the ceremony chain deferred: the **live tier (E6 → E7) is
the critical path**, and the hermetic issues (E1, E2 → E3, E4, E5) are a batch of small, mostly-independent
items that run alongside it. One developer can clear the hermetic batch while another owns the live tier, or
one person does the sum.

**Critical path (live tier):** `E6-1 → E6-2 → E6-3 → E6-4 → E7-1` (~9 pts). Nothing else chains beyond it.

**Hermetic batch (parallel to the live tier):**
- `E1-1` (scrypt override) — land **first**, speeds every scrypt-touching test (E3, E5, E6).
- `E2-1 → E3-1` (decrypt_v3 → rescoped recover T-3) — the only 2-issue chain here (~5 pts).
- `E4-2` (recover symlink) — one issue, independent.
- `E5-1 → E5-2 → E5-3` (gen goldens) — `E5-2`/`E5-3` extend `gen.rs` after `E5-1` adds the fixture accessors.

**Within-phase sequencing that is NOT parallelizable:**
- **E5-2, E5-3** both extend `gen.rs` after E5-1 adds the fixture accessors / hoodi golden.
- **E6-2, E6-3** both extend `e2e_live.rs` after E6-1 lands the anvil harness.

**Suggested merge order (respects all deps):**
`E1-1` · `E2-1` (parallel start) → `E3-1` (M3) · `E4-2` (M4) · `E5-1` → `E5-2` → `E5-3` (M5) · `E6-1` →
`E6-2` → `E6-3` → `E6-4` (M6) → **`E7-1` (M7a)** → `E8-1` · `E8-2` (M7b, optional).

---

## Production-tree touches (everything else is tests / CI / docs only)

Only **two** issues touch the production tree; the rest are additive test files, CI, or docs.

| Issue | Production-tree change | Note |
|---|---|---|
| **[E1-1]** | `[profile.dev.package.scrypt] opt-level = 3` in the workspace `Cargo.toml` | Build config only — no runtime or release-artifact behavior change. |
| **[E2-1]** | `crates/ethernal-keystore/src/decrypt_v3.rs` (feature-gated) + `lib.rs` re-export + `[features] test-support` | Compiled out of release (resolver-2 + `#[cfg]`). The `bins/ethernal/Cargo.toml [dev-dependencies]` line in the same issue is **test-only**, not production. |

**Everything else touches only `bins/ethernal/tests/**`, `.github/workflows/e2e-live.yml`, the `Makefile`,
or `docs/`.** A test that appears to need a `bins/ethernal/src/**` hook to pass is **stop-and-escalate in
the run summary, not a hook to add** (C-2 / binding seq. #9). Existing tests, crate boundaries, `ci.yml`,
and any third-party dependency stay unchanged (C-1 — anvil shells to the `anvil` binary, `decrypt_v3` reuses
in-crate crypto).

---

## Conventions (all issues)

- **Merge model (C-3):** per-issue **fast-forward ordinary commit on `develop`**, one issue per merge,
  subject prefixed with the tag (e.g. `[E1-3] …`); every commit green under `make lint && make test`.
- **Live tests** are `#[ignore]`d **and** skip-with-notice on a missing `anvil` binary — never in the
  PR-blocking hermetic tier (binding seq. #5). `e2e-live.yml` is a **separate** workflow; `ci.yml` is
  untouched (D-8).
- **Given-mnemonic rule (scope decision):** T-3 drives `account recover` with the committed `ABANDON_12`
  fixture over piped stdin + `--passphrase-env`; no ceremony, no PTY.
- **Foundry pin (DD-5):** `version: v1.7.1`, both the action SHA and the `version:` input pinned; re-resolve
  the action SHA fresh at implementation.
- **T-6 wording (D-9):** valid-tx-accepted + 32 ETH moved, **not** deposit-contract-logic validated.

---

## Requirement coverage (all 19 T-\* accounted for)

**This stage:** T-3 → E3-1 (+E2-1 enables) · T-6 → E6-2 · T-7 → E5-1 · T-8 → E5-2 · T-12·recover → E4-2 ·
T-13 → E6-3 · T-14 → E6-4 (partial) + E7-1 · T-15/T-16 → E8-1 · T-18 → E8-2 · T-19 → E5-3 · T-1 (anvil half)
→ E6-1.
**Deferred to the future PTY stage** ([`deferred.md`](deferred.md)): T-1 (PTY half), T-2, T-4, T-5, T-9,
T-10, T-11, T-12·new.
**T-17 deferred out of v1** (D-5 — `run` is `build`+`sign` composed, both live-exercised by T-6).

---

## Milestone map

| # | Milestone | Issue(s) |
|---|---|---|
| **M1** | Scrypt override landed (recover suite fast) | E1-1 |
| **M2** | `decrypt_v3` landed + proven out-of-release | E2-1 |
| **M3** | v3 correctness via recover + `decrypt_v3` green | E3-1 |
| **M4** | Recover-path symlink warning green | E4-2 |
| **M5** | Hermetic golden/guard tests green | E5-1..E5-3 |
| **M6** | Live pipe chain moves 32 ETH against anvil (headline anvil-in-CI proof) | E6-1..E6-4 |
| **M7a** | Two-tier CI wired | E7-1 |
| **M7b** | Verify-skill parity documented *(optional)* | E8-2 (+E8-1) |

**Definition of Done for v1 (the release gate) = M1–M7a (E1–E7).** M7b (E8) is polish that sharpens the G3
claim but does not gate the release.

---

## Sizing notes

- **Post-decision phase sums** — E1 1 · E2 3 · E3 2 · E4 1 · E5 5 · E6 7 · E7 2 · E8 4. Required total
  **21 pts across 12 issues** (+ 4 optional). The **14 deferred pts** (6 issues) reconcile with the
  pre-decision plan: 21 + 14 = the old 35 required; 25 + 14 = the old 39 total.
- **E6 reconciliation (flagged):** the plan places the `make e2e-live` **Makefile** target in E7 (D-6), but
  E6's `e2e-live.yml` must be dispatchable at M6. Resolved: **E6-4's workflow runs the inline `cargo test
  --workspace --test 'e2e*' -- --ignored`**, and **E7-1 switches that run step to `make e2e-live`** when it
  adds the target (and drops `--include-ignored` from `e2e-mock`). Both E7-1 edits are required.
- **Foundry version (flagged):** the binding pin is DD-5's `version: v1.7.1`; the architecture's
  `e2e-live.yml` example (`v1.3.6` / action `v1.9.0`) is stale and is **not** used.
