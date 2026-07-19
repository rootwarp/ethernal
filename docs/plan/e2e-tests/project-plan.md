# Project Plan — End-to-End Test Suite for `ethernal`

**Scope (one line):** close the e2e coverage gaps in the mature ~130-test integration suite by adding
one dependency-free test harness beside the existing `Stub` — an **anvil driver** for a real-EVM broadcast
— plus the hermetic golden/guard tests, a fixture-mnemonic `recover` → `decrypt_v3` round-trip for v3
correctness, one feature-gated test-only `decrypt_v3`, and the two-tier CI wiring, so the suite becomes a
checkable **pre-release gate** rather than a manual ritual. **The interactive `new`-ceremony PTY tier is
deferred to a future stage** (binding user decision 2026-07-19); the mnemonic is *given* via the committed
fixture and driven through the non-interactive `recover` path.
**Inputs (binding):** [`prd.md`](prd.md) (what/why: T-1..T-19, P0/P1/P2, C-1..C-6, coverage matrix) —
**as amended by the scope decision of 2026-07-19 (PTY tier deferred) and by [`architecture.md`](architecture.md)**,
which carries the binding decisions D-2..D-9 (esp. the PRD amendments to T-6/G4 per D-9 and to T-14/A-2 per
D-6; D-1 is deferred with the PTY tier) and the module/file→requirement map;
[`research/index.md`](research/index.md) + `r1..r5` (settled verdicts; r1's PTY verdict deferred, the
scrypt-in-debug cost re-justified by the recover path). Style precedent:
[`../eoa-keystore/project-plan.md`](../eoa-keystore/project-plan.md) and
[`../audit-gaps/project-plan.md`](../audit-gaps/project-plan.md), whose phase/stream/milestone shape this
mirrors.
**Sizing:** 1 story point ≈ half a working day (repo convention); every issue ≤ 3 pts, each ≈ 1–2 days.
Point totals here are a **sanity-check that each phase decomposes into 1–2-day issues**, not the committed
issue cut — Stage 6 (the estimator) cuts the actual `[E#-#]` issues from the architecture and may re-split
within a phase.
**Streams (post scope-decision):** the old two-stream A/B split **collapses** — Stream A (the
interactive/ceremony PTY chain) is almost entirely deferred, leaving a handful of small, mostly-independent
hermetic issues (E1-1 scrypt, E2-1 `decrypt_v3` → E3-1 rescoped recover, E4-2 symlink) that run **alongside**
the one remaining substantive chain, **Stream B** = crypto + golden + live tier (`decrypt_v3`, the hermetic
gen/send goldens, the anvil harness + live pipe, CI wiring) — the critical path is now inside Stream B
(E6→E7). See [Critical path & parallel streams](#critical-path--parallel-streams).
**Merge model (locked, C-3):** per-issue **fast-forward** commits on `develop`, one issue per merge,
every merge green under `make lint && make test`; phase tags `E1`..`E8`, issues later tagged `[E1-1]` etc.
Full `make test` is scrypt-heavy (the *recover*-path tests run production scrypt) — the scrypt debug-profile
override (E1-1, below) is what keeps it fast.
**Nature of the work:** an **additive extension** of an already-mature suite. No `bins/ethernal/src/**`
behavior change; no crate boundary moves; no new third-party dependency (anvil shells to the `anvil` binary,
`decrypt_v3` reuses in-crate crypto). The **only** production-tree change anywhere is the test-only,
feature-gated `decrypt_v3` in `ethernal-keystore`, compiled out of release by `resolver = "2"` + `#[cfg]`.

**Requirement-count note:** the PRD defines **T-1..T-19**; nothing defines T-20/T-21. This plan is built
against the **19** requirements that exist, of which the scope decision (2026-07-19) defers **T-1, T-2, T-4,
T-5, T-9, T-10, T-11, T-12·new** (PTY tier) and **rescopes T-3** to the recover path. **T-17** stays deferred
(D-5).

---

## Binding decisions & PRD amendments (architecture overrides raw PRD; planner resolves the open coin-flips)

The estimator and implementer follow these, not the literal PRD text where they differ.

| # | Decision | Effect on execution |
|---|---|---|
| **Scope decision (2026-07-19, binding)** | **PTY tier deferred; mnemonic is *given*.** T-1/T-2/T-4/T-5/T-9/T-10/T-11/T-12·new leave scope; **T-3 rescoped** to `account recover` + `decrypt_v3`; **T-12·recover** kept (non-PTY). | Deletes deferred issues **E1-2, E1-3, E3-2, E3-3, E3-4, E4-1** (→ [Deferred](#deferred-out-of-v1)); rescopes **E3-1**; keeps **E1-1, E2-1, E4-2, E5, E6, E7, E8**. |
| D-6 | `make e2e-mock` **drops** its (currently no-op) `--include-ignored`; a new `make e2e-live` runs `cargo test --workspace --test 'e2e*' -- --ignored`. Amends T-14/A-2. | Behavior-neutral today; it is what keeps the `#[ignore]`d live tests out of the hermetic PR gate once `e2e_live.rs` lands. Belongs to **E7**. |
| D-8 | The live tier is a **separate workflow file** `.github/workflows/e2e-live.yml`, not a job added to `ci.yml`. `ci.yml` (the PR gate) is untouched. | **E6** creates it as `workflow_dispatch`-only (risk burn-down); **E7** adds the `schedule` + release-tag triggers (T-14). |
| D-9 | T-6's on-chain assertion is **"a valid Ethereum tx was accepted by a real EVM AND 32 ETH moved to the deposit-contract address,"** NOT "the deposit contract validated the deposit" (bare anvil has no deposit-contract code). Amends T-6/G4. | **E6** asserts value-moved + successful receipt, and its test/doc wording must not over-claim contract-logic validation. |
| ~~DD-1~~ | **MOOT** (T-5 deferred with the PTY tier). | — |
| DD-2 (planner: **confirm**) | T-16 (SIGINT) extends **`send.rs`**, no dedicated `signals.rs`. | **E8** scope. |
| DD-3 (planner: **confirm**) | T-18 (verify-skill parity) is a **checklist doc** `verify-parity.md`, not a meta-test; the interactive ceremony is an explicit carve-out. | **E8** scope. |
| DD-5 (planner: **decide → v1.7.1**) | Pin Foundry to **`version: v1.7.1`** in `e2e-live.yml` (the version R2 verified locally), and pin **both** the `foundry-rs/foundry-toolchain` action SHA **and** its `version:` input (the input floats on `stable` otherwise). The exact release tag is re-confirmed at implementation. | **E6**/**E7** CI steps. |
| D-5 | T-17 (`run --rpc-url` live) **deferred / out of v1** — `run` is `build`+`sign` composed, both live-exercised by T-6; the in-process hand-off is hermetically covered by `run::local_signer_happy_path`. | See [Deferred](#deferred-out-of-v1). |

All the architecture's still-live settled verdicts (D-2 `#[ignore]` + skip-with-message, D-3
skip-on-missing-anvil, D-4 `decrypt_v3` test-support feature, D-7 hand-rolled JSON-RPC in `anvil.rs`) stand
unchanged and are assumed by the phases below. **D-1** (hand-rolled PTY) is deferred with the PTY tier.

**Hard boundary (every phase):** if any issue appears to need a hook in `bins/ethernal/src/**` (an entropy
injection, a time source, a test-only branch) to make a test pass, that is **stop-and-escalate in the run
summary, not a hook to add** — C-2 forbids injection in the release binary; determinism comes from the
*given* fixture mnemonic through `recover`, exactly as the existing `key_e2e`/`account_e2e` tests do it.
The sole production-tree change permitted by this plan is the feature-gated `decrypt_v3` (E2).

---

## Phase table

Phase tags are **kept stable** (surviving issues keep their tags; deferred ones are marked, not renumbered).
Points below are the **post-decision** phase sums; struck rows are deferred to a future PTY stage.

| Tag | Name | Pts (est) | Stream | Depends on | Discharges (T-\*) |
|---|---|---|---|---|---|
| **E1** | Scrypt override (recover-path justification) | **1** | — | — | build-config prereq |
| **E2** | `decrypt_v3` test-support feature | 3 | B | — | (enables T-3) |
| **E3** | v3 correctness via recover + `decrypt_v3` (rescoped T-3) | **2** | B | E2 | T-3 |
| **E4** | Recover-path symlink warning | **1** | — | — | T-12·recover |
| **E5** | Hermetic golden & guard tests | 5 | B | — (fixture accessors) | T-7, T-8, T-19 |
| **E6** | Anvil harness + live pipe chain (+ dispatch-only CI) | 7 | B | — (`anvil` binary) | T-6, T-13, T-14·partial |
| **E7** | CI two-tier wiring (required) | 2 | B | E6 | T-14 |
| **E8** | P2 polish + parity audit (**optional**) | 4 | B | E3, E5, E6 | T-15, T-16, T-18 |
| ~~E1-2/E1-3, E3-2/E3-3/E3-4, E4-1~~ | ~~PTY harness, key-new ceremony, mismatch/hygiene/passphrase/scrollback/symlink·new, recover-prompt PTY~~ | ~~14~~ | — | — | ~~T-1,2,4,5,9,10,11,12·new~~ **DEFERRED** |

**Total: 21 pts required (E1–E7) + 4 pts optional (E8) = 25 pts across 14 issues** (12 required + 2 optional).
Plus **14 pts / 6 issues deferred** to the future PTY stage. (Reconciles with the pre-decision plan: 21 + 14
= the old 35 required; 25 + 14 = the old 39 total.) Rough by design — the estimator refines per-issue.
**Deferred out of v1: T-17** (D-5) and the PTY tier (T-1/2/4/5/9/10/11/12·new).

**T-\* coverage check (all 19 accounted for):** T-3 → E3 · T-12·recover → E4 · T-7,8,19 → E5 · T-6,13 → E6 ·
T-14 → E6/E7 · T-15,16,18 → E8 · **deferred (PTY tier): T-1,2,4,5,9,10,11,12·new** · **T-17 deferred (D-5).**
Nothing dropped — the deferred requirements are preserved in [Deferred](#deferred-out-of-v1).

---

## Per-phase detail

### E1 — Scrypt debug-profile override (build-config prereq) · one issue, no predecessor

**Scope.** Land the targeted scrypt optimization so the debug binary `cargo test` drives never runs
production-cost scrypt (`n=262144`) unoptimized. **Re-justified by the *recover* path** (the PTY ceremony
tests that originally motivated it are deferred): the recover-path e2e tests (T-3 and the existing
`key_e2e`/`account_e2e` suite) encrypt each keystore at `ScryptParams::STANDARD`, with no cheap-param hook
(S-4 forbids injection). **Measured on develop @ `584c404`** (`account_e2e::account_recover_keystores_match_fixture`,
COUNT=2): **~39 s** debug-default → **~1.2 s** with the override (~19 s/keystore → ~0.6 s).
- `Cargo.toml` (workspace root): add `[profile.dev.package.scrypt]\nopt-level = 3`. Blast radius: only the
  `scrypt` crate is optimized; every workspace crate and other dep stays `opt-level = 0`. Fallback if a
  future scrypt moves its hot loop into `salsa20`: `[profile.dev.package."*"] opt-level = 2`.

**Entry.** None. Land **first**, ahead of anything scrypt-touching (E3, E5, E6 all decrypt/encrypt with
scrypt).

**Exit (→ M1).** `grep -A1 'profile.dev.package.scrypt' Cargo.toml` shows `opt-level = 3`; `make lint && make
test` green and materially faster on the recover suite. No runtime or release-artifact behavior change.

**Parallelism.** Independent one-issue phase; overlaps everything.

---

### E2 — `decrypt_v3` test-support feature (enables T-3) · Stream B, can start day 1

**Scope.** The one production-tree change, feature-gated and compiled out of release:
- `crates/ethernal-keystore/Cargo.toml`: `[features] test-support = []`.
- `crates/ethernal-keystore/src/decrypt_v3.rs` (new, ~35 lines, `#[cfg(feature = "test-support")]`):
  parse v3 JSON → `derive_scrypt(RAW password, …)` → verify `v3_mac` (MAC-before-decrypt, constant-time)
  → `Aes128Ctr` → `Zeroizing<[u8;32]>`, **reusing** the crate-internal `crypto::{derive_scrypt, Aes128Ctr,
  v3_mac}` verbatim so it cannot drift from the `encrypt_v3` writer.
- `crates/ethernal-keystore/src/lib.rs`: `#[cfg(feature = "test-support")] pub use decrypt_v3::decrypt_v3;`.
- `bins/ethernal/Cargo.toml`: one `[dev-dependencies]` line —
  `ethernal-keystore = { workspace = true, features = ["test-support"] }` — solely to flip the feature on
  for test builds.
- A crate unit test asserting `decrypt_v3` round-trips an `encrypt_v3` output (encrypt↔decrypt symmetry).

**Entry.** None. Independent of every other phase.

**Exit (→ M2).** `cargo test -p ethernal-keystore --features test-support` green; **the stays-out-of-release
invariant is validated and documented** — `cargo build --release --bin ethernal` does not enable
`test-support` (resolver-2 property, R-2), recorded as a module-header invariant with the `cargo tree -e
normal` inspection as a best-effort backstop in the live job. `make lint && make test` green.

**Parallelism.** Pure Stream B. **Must merge before E3's T-3** (T-3's v3 validation consumes `decrypt_v3`).

---

### E3 — v3 correctness via `account recover` + `decrypt_v3` (rescoped T-3) · Stream B, depends E2

**Scope (rescoped).** The scope decision replaces the deferred `account new` ceremony test with a
non-interactive proof of v3 correctness through the *given* fixture mnemonic — no PTY, no ceremony:
- `tests/account_e2e.rs` (edit): **T-3** — drive `account recover` with the committed `ABANDON_12` fixture
  (piped stdin, empty mnemonic-passphrase, `--passphrase-env`), producing **Web3 v3** keystores; validate
  structurally (`version: 3`, `aes-128-ctr`, scrypt kdf, keccak `mac`, top-level `address`, geth `UTC--…`
  filename, `0600`) **plus** `decrypt_v3(json, pass) → secret → derive address == keystore `address` ==
  fixture address` (from `testdata/eoa/cross-recovery.json`). The `decrypt_v3` round-trip is the piece the
  existing `account_recover_keystores_match_fixture` lacks — it checks structure + `address` but never
  decrypts the ciphertext, so the v3 **encrypt** path is unproven (address is written independent of
  ciphertext). This proves derivation **and** v3-encrypt self-consistency (D-4), and holds for the deferred
  ceremony write path too (byte-identical crypto).

**Entry.** E2 `decrypt_v3` merged (M2). No PTY, no E1 dependency beyond the scrypt speedup (E1-1 keeps it
fast but is not a compile dep).

**Exit (→ M3).** T-3 green on every PR inside `make test`; `make lint && make test` green. v3 correctness is
now proven through the binary, closing the encrypt-path gap that address-match alone left open.

**Parallelism.** Stream B, after E2. Independent of E4, E5, E6.

---

### E4 — Recover-path symlink warning (T-12·recover) · one issue, no predecessor

**Scope.** The `recover`/stdin half of T-12, reachable without a TTY (the ceremony/new half, T-12·new, is
deferred):
- `tests/key_e2e.rs` / `tests/account_e2e.rs` (edit): **T-12·recover** — a symlinked `--output-dir` on the
  *recover/stdin* path emits the documented warning (`1736843`). `load_config` calls
  `warn_if_symlinked_output_dir(…, banner_out)` for `recover` (`key_cli.rs:266` / `account_cli.rs:179`),
  already unit-verified by `recover_load_config_warns_on_symlinked_output_dir`; this adds the binary-level
  assertion via the existing `run_*_recover` stdin harness. Pin whatever the code does (warn + still writes).

**Entry.** None. Independent of every other phase (reuses the existing stdin recover harness).

**Exit (→ M4).** T-12·recover green for both commands; `make lint && make test` green.

**Parallelism.** Independent one-issue phase; slot anywhere (touches only `*_e2e.rs`, disjoint from the
live tier).

---

### E5 — Hermetic golden & guard tests (T-7, T-8, T-19) · Stream B, independent

**Scope.** No PTY, no anvil — pure additive hermetic tests using **existing** fixtures (verified present:
`testdata/hoodi/` and `testdata/mainnet/` both hold `deposit_data-expected.json` + keystores + passphrase +
pubkeys, so **no new committed fixture**, A-5):
- `tests/common/mod.rs` (edit): new `hoodi_expected_deposit_data()` and `mainnet_*()` fixture accessors.
- `tests/gen.rs` (edit): **T-7** (decrypt the hoodi keystore, run `gen`, **byte-diff** output vs
  `testdata/hoodi/deposit_data-expected.json`, replacing today's field-level asserts); **T-8** (the
  `--i-understand-this-is-mainnet` guard — `gen --network mainnet` without the flag → exit 2 naming the
  flag; with it → proceeds and byte-matches `testdata/mainnet/deposit_data-expected.json`; plus the pipe
  gotcha: `gen` without `--passphrase-env` in a pipe prompts on `/dev/tty` and dies non-TTY exit 2);
  **T-19** (`gen --parallel` output byte-identical to serial — reuse the T-7 hoodi golden with `--parallel`).

**Entry.** None (only the fixture accessors, added here). Independent of every other phase.

**Exit (→ M5).** T-7, T-8, T-19 green; `make lint && make test` green. The two safety-critical `gen` gaps
(the never-byte-diffed hoodi golden, the entirely-untested mainnet guard) are closed.

**Parallelism.** Pure Stream B; slot anywhere. Low-risk quick P0 wins — but T-7/T-8 are P0 (ship-blocking for
the gate), so they must not slip behind the P2 phase.

---

### E6 — Anvil harness + live pipe chain (T-6, T-13, partial T-14) · Stream B, gates the live tier

**Scope.**
- `tests/common/anvil.rs` (new, `#[cfg(unix)]`): the `Anvil` guard modeled on alloy `node-bindings` —
  `try_spawn(chain_id)` (skip-with-`eprintln!`-notice when the `anvil` binary is absent, D-3; `--port 0` +
  scrape `Listening on 127.0.0.1:<port>`; background stdout drain thread; `eth_chainId` readiness backstop),
  `url`, a **hand-rolled dependency-free JSON-RPC POST** (`rpc`, D-7 — requires only `anvil`, not `cast`),
  `set_balance`, `set_nonce`, and `Drop` (kill+reap).
- `tests/e2e_live.rs` (new, `#[ignore]`-gated, each test opens with the skip guard): **T-6** — start anvil
  (hoodi chain-id `560048`, ephemeral port), fund the phase-3 sender via `anvil_setBalance`, run
  `gen --dry-run | build --input-file - | sign --input - | send --yes --input - --rpc-url <anvil>
  --wait-for-receipt`, and assert **(a) a successful receipt AND (b) the deposit-contract address's balance
  grew 32 ETH per deposit** — worded per **D-9** (valid-tx-accepted + value-moved; **not**
  deposit-contract-logic validation). **T-13** — (a) `build --rpc-url <anvil> --from <addr>` resolves nonce
  from the real node (probe via `anvil_setNonce`); (b) interactive `send` (no `--yes`) with the wrong
  network name → exit 4.
- `.github/workflows/e2e-live.yml` (new): create it **`workflow_dispatch`-only** here (ci.yml untouched,
  nothing gated on any PR) — Foundry via `foundry-rs/foundry-toolchain` **SHA-pinned + `version: v1.7.1`
  pinned** (DD-5). This exists in E6 **specifically to burn down the second-biggest CI unknown early**:
  manually dispatch it to prove anvil runs on the ubuntu runner, before E7 hangs release/nightly triggers
  on it. (E7 completes T-14; this is the deliberate T-14 split.)

**Entry.** None (only the `anvil` binary; absent → green skip). Independent of E1–E5.

**Exit (→ M6).** T-6 + T-13 green **locally via `make e2e-live`** with anvil present **and via a manual
`workflow_dispatch` run of `e2e-live.yml` on the ubuntu runner** (the real anvil-in-CI proof); `make lint &&
make test` still green and the live tests are absent from it (`#[ignore]` + not `e2e*` in the hermetic tier).
This delivers G4's "the thing the Stub cannot prove": first real-EVM acceptance + on-chain state change.

**Parallelism.** Pure Stream B (the critical path); independent of the hermetic batch (E1–E5). The `Drop`
guards guarantee no anvil child outlives a panicking test.

---

### E7 — CI two-tier wiring, required (T-14) · Stream B, depends E6 · "CI last"

**Scope.** Complete the two-tier wiring now that `e2e_live.rs` exists and `e2e-live.yml` is proven-dispatchable:
- `Makefile` (edit, D-6): **drop** `--include-ignored` from `e2e-mock` (behavior-neutral today; keeps the
  live tests out of the hermetic gate going forward); add `e2e-live: cargo test --workspace --test 'e2e*'
  -- --ignored`.
- `.github/workflows/e2e-live.yml` (edit): add the `schedule` (nightly, placeholder `0 7 * * *`) and `push`
  on `v*.*.*` release-tag triggers alongside the existing `workflow_dispatch`; **not PR-blocking**, no job
  retries / no `continue-on-error` (a nightly failure is a real signal). All actions SHA-pinned to match the
  `9bec2c2` hardening.
- `ci.yml` stays **unchanged** — this stage's new hermetic tests (T-3, T-7/8/19, T-12·recover) already run
  transparently inside `make test` (no external toolchain), so the hermetic side of T-14 needs no CI edit.

**Entry.** E6 merged (`e2e_live.rs` + dispatch-only `e2e-live.yml` exist and a manual dispatch went green).

**Exit (→ M7a).** `make e2e-live` runs only the ignored live tests; `make e2e-mock` / `make test` run only
the hermetic tier; the live workflow is scheduled + release-gated + dispatchable and green on its first
scheduled/dispatched run. The suite is now a **two-tier gate** with the live tier isolated off the PR path
(C-5/G7).

**Parallelism.** Tail of Stream B; the required "CI last" phase.

---

### E8 — P2 polish + parity audit, **optional** (T-15, T-16, T-18) · depends E3, E5, E6

**Scope.** Non-blocking polish; each item is independently deferrable:
- `tests/send.rs` (edit): **T-15** (`send --rpc-url ws://…` → exit 5, a thin binary-level assertion over the
  existing crate unit test); **T-16** (SIGINT to the child mid gas/nonce estimation → exit 4, no broadcast;
  extends `send.rs`, DD-2).
- `docs/plan/e2e-tests/verify-parity.md` (new): **T-18** — a checklist mapping every `SKILL.md` step to the
  automated test now covering it, with the carve-outs (ledger signing, cross-tool import parity) explicitly
  marked non-automatable (DD-3). Makes G3's "verify skill automated" a **checkable** claim.

**Entry.** The surfaces they audit exist: E3 (recover v3) + E5 (goldens) + E6 (live) merged. T-15/T-16 need
only the existing `send` surface and can start earlier if capacity allows.

**Exit (→ M7b).** T-15, T-16 green; `verify-parity.md` committed with every automatable `SKILL.md` step
mapped to a named test, every carve-out marked (ledger, cross-tool parity, **and the deferred interactive
`new` ceremony** — the largest carve-out this stage). **Optional for v1** — if descoped, the suite still
gates releases via E1–E7; T-18's parity claim is the only thing that becomes "asserted by inspection" rather
than "documented," and that is an acceptable v1 floor.

**Parallelism.** Split across streams (T-15/16 = B on `send.rs`; T-18 = the cross-stream join that needs
everything landed).

---

## Milestones / checkpoints

The M-numbering is kept stable for the surviving phases; **M1 is repurposed** (the deferred PTY risk
burn-down is gone) and the **anvil-in-CI proof (M6) is now the headline risk**.

| # | Milestone | Gate (concrete exit) | Phase |
|---|---|---|---|
| **M1** | Scrypt override landed | `[profile.dev.package.scrypt] opt-level = 3` in-tree; recover suite fast (~39 s → ~1.2 s, measured). | E1 |
| **M2** | `decrypt_v3` landed + proven out-of-release | encrypt↔decrypt round-trip green; resolver-2 stays-out-of-release invariant documented + backstopped. | E2 |
| **M3** | v3 correctness via recover + `decrypt_v3` green | T-3 green on every PR — `account recover` (fixture mnemonic) → `decrypt_v3` round-trip + address; the v3-encrypt gap closed. | E3 |
| **M4** | Recover-path symlink warning green | T-12·recover green (both commands). | E4 |
| **M5** | Hermetic golden/guard tests green | T-7 hoodi byte-diff + T-8 mainnet guard/golden + T-19 parallel green. | E5 |
| **M6** | **Live pipe chain moves 32 ETH against anvil (headline risk burn-down)** | T-6 + T-13 green locally *and* via a manual `workflow_dispatch` CI run (real anvil-in-CI proof — now the biggest unknown). G4's Stub-can't-prove item met. | E6 |
| **M7a** | Two-tier CI wired | `make e2e-live` isolated from the PR gate; `e2e-live.yml` scheduled/release-gated/dispatchable and green. | E7 |
| **M7b** | Verify-skill parity documented (optional) | `verify-parity.md` maps every automatable `SKILL.md` step to a test; carve-outs marked (ledger, cross-tool, PTY ceremony). | E8 |

Definition of Done for **v1 (the release gate)** = **M1–M7a** (E1–E7). M7b (E8) is polish that sharpens the
G3 claim but does not gate the release.

---

## Critical path & parallel streams

The two-stream A/B split **collapses**: the interactive/ceremony chain (old Stream A) is deferred, leaving
one substantive chain (the live tier) plus a batch of small, mostly-independent hermetic issues.

```
Small independents (hermetic, parallel — no chain longer than 5 pts)
  E1 scrypt override (1) ── speeds ▶ E3/E5/E6
  E2 decrypt_v3 (3) ─────────────▶ E3 recover+decrypt_v3 / rescoped T-3 (2)     ┐
  E4 recover-path symlink (1)                                                    │
  E5 hermetic goldens T-7/8/19 (5)                                              ├─▶ E8 parity (T-18) OPTIONAL
                                                                                 │
Live tier (THE critical path)                                                    │
  E6 anvil + live pipe (T-6/13) + dispatch CI (7) ──▶ E7 CI two-tier wiring (2) ─┘
        (M6, headline anvil-in-CI risk)                     (M7a, CI last)
```

**Critical path (bounds calendar time):** the **live tier — E6 → E7** — is now the longest dependency chain:
`E6-1 → E6-2 → E6-3 → E6-4 → E7-1 ≈ 9 pts` (E6 ~7 → E7 ~2). Nothing else chains beyond it: the hermetic
crypto/golden work is E2 → E3 (5 pts), E5 (5 pts), and the one-issue E1 and E4 — all parallel to the live
tier. Including the optional parity audit, E8 joins after E3/E5/E6 and adds ~2 pts.

**Stream shape (honest):** with the ceremony chain gone this is effectively **~1 stream** (the live tier)
plus loose hermetic issues that a single developer clears alongside it (E1, E2→E3, E4, E5) or a second hand
picks up in parallel. There is no longer a genuine two-developer split — the required work is **21 pts ≈
~10.5 person-days ≈ ~2 weeks** solo, and a second developer mainly shortens the calendar by taking the
hermetic batch (E1/E2/E3/E4/E5, ~12 pts) off the live-tier owner's plate.

**Sequencing rationale (early risk burn-down):** **E1 scrypt override first** (its own issue) so no scrypt-
touching test — recover (E3), hoodi decrypt (E5), live gen (E6) — ever runs unoptimized. **E2 early** so it
never blocks E3's T-3. **E6 pulls a `workflow_dispatch`-only `e2e-live.yml` forward** so anvil-in-CI (now the
single biggest unknown, M6) is proven **before** E7 hangs release/nightly triggers on it. CI trigger wiring
(E7) is genuinely last.

---

## Deferred (out of v1)

- **The PTY / interactive-`new`-ceremony tier — deferred to a future stage (binding user decision, 2026-07-19).**
  Deleted from this plan's execution but preserved for the future stage (research `r1` stays valid):
  **E1-2** (PTY harness `PtySession`), **E1-3** (`key new` full ceremony, T-2), **E3-2** (mismatch abort,
  T-4), **E3-3** (new-path hygiene, T-5), **E3-4** (mnemonic-passphrase + scrollback + symlink·new,
  T-10/T-11/T-12·new), **E4-1** (interactive `/dev/tty` recover prompt, T-9). **~14 pts, 6 issues.** Each
  deferred requirement is still guarded by an in-crate unit test in `key_cmd`/`account_cmd` and by the manual
  verify procedure — see `issues/deferred.md`. Kept by rescoping to the non-interactive path: **T-3**
  (E3-1 → `account recover` + `decrypt_v3`) and **T-12·recover** (E4-2).
- **T-17 — `run --signer local --rpc-url` live against anvil** (P2). Per D-5/R5: `run` is `build`+`sign`
  composed, both stages live-exercised by the T-6 pipe chain; `run`'s only unique step (the in-process
  build→sign hand-off with no serialization) is low-risk and hermetically covered by
  `run::local_signer_happy_path`. Marginal value does not justify a second anvil-backed test. **Revisit only
  if `run` grows logic beyond composing the two stages.**
- **E8 (T-15, T-16, T-18)** is *optional* v1 polish, not deferred-forever — it lands after the gate is up if
  capacity allows; if it slips, the release gate (M1–M7a) is unaffected.
- **Out of scope entirely (PRD Non-goals, unchanged):** ledger hardware signing (stays on the negative tests
  + `--features ledger` compile check), real mainnet/testnet broadcast (anvil-only), cross-tool keystore
  import parity (the eoa-keystore manual per-release session), performance/fuzz, new commands/flags,
  Windows/non-Unix support.

---

## Sequencing choices the estimator MUST respect

Consolidated here so Stage 6 does not re-open them:

1. **Scrypt override in E1, first**, before any scrypt-touching test runs. Non-negotiable — measured ~19 s/
   keystore in debug on the *recover* path (~39 s → ~1.2 s for COUNT=2 with the override); it speeds T-3
   (E3), the hoodi decrypt (E5), and the existing recover suite.
2. **`decrypt_v3` (E2) before E3's T-3.** E2 has no predecessor and starts day 1.
3. **T-3 is the rescoped recover test** (`account recover` fixture mnemonic → `decrypt_v3` round-trip +
   address), landing in `account_e2e.rs` — **not** a ceremony/PTY test. It depends on E2-1 only.
4. **PTY tier is deferred** (binding scope decision 2026-07-19). No PTY harness, no ceremony tests
   (`key new`/`account new`), no `/dev/tty` recover-prompt test this stage — a test that needs a real TTY is
   out of scope, not to be added. See `issues/deferred.md`.
5. **Live tests `#[ignore]`d + skip-on-missing-anvil, never in the PR-blocking tier.** Drop
   `--include-ignored` from `make e2e-mock` (D-6); `e2e-live.yml` is a **separate** workflow, `ci.yml`
   untouched (D-8). Create `e2e-live.yml` as `workflow_dispatch`-only in **E6** (risk burn-down); add
   schedule + release-tag triggers in **E7**.
6. **T-6 assertion wording = valid-tx-accepted + 32 ETH moved, NOT deposit-contract-validated** (D-9). The
   test and any doc must not over-claim contract-logic validation on bare anvil.
7. **Foundry pinned to `version: v1.7.1`**, and **both** the action SHA **and** the `version:` input pinned
   (the input floats on `stable` otherwise). Re-confirm the exact release tag at implementation (DD-5).
8. **`decrypt_v3` stays-out-of-release is an acceptance criterion of E2**, not an afterthought — the invariant
   (resolver-2 + `#[cfg]`) is stated and the `cargo tree -e normal` backstop is included.
9. **No `bins/ethernal/src/**` behavior change in any phase.** A test that seems to need a src/ hook is
   stop-and-escalate, not a hook to add (C-2).
10. **T-17 and the PTY tier deferred** (D-5; scope decision 2026-07-19).

---

## Risks (phase-scoped; full analysis in [`architecture.md`](architecture.md) §Risks)

| # | Risk | Phase | Mitigation |
|---|---|---|---|
| **R-1** | **Scrypt override not landed first** → the *recover*-path tests (T-3 + the existing suite) run ~19 s/keystore in debug. | E1 | Land `[profile.dev.package.scrypt] opt-level = 3` first (E1); make it a review-checklist item. Measured ~39 s → ~1.2 s for COUNT=2. |
| R-2 | Resolver flipped to `"1"` would leak `test-support` into the release binary (Q3 violation). | E2 | Invariant documented in the `decrypt_v3` module header + here; `cargo tree` backstop in the live job. Low likelihood (resolver 2 is the confirmed workspace default). |
| R-4/R-6 | anvil `Listening on` / cheatcode version drift. | E6 | The **pinned anvil `version:`** freezes the readiness-line format, with `eth_chainId` polling as a format-independent backstop; local skip-on-missing means a drifted local anvil fails only in the live tier, never on a PR. |
| R-5 | T-6 over-claiming on-chain semantics. | E6 | Guarded by D-9: assertion scoped to valid-tx-accepted + value-moved on bare anvil; deposit-contract-logic validation stays on the manual/real-network path so G4 stays honest. |
| **R-A** | **anvil-in-CI (now the headline risk) proven only at the very end** if `e2e-live.yml` is left to E7. | E6 | Mitigated **by design**: E6 creates `e2e-live.yml` as `workflow_dispatch`-only and a manual dispatch is part of M6's exit — the anvil-in-CI unknown is burned down in E6, not E7. |

---

## Definition of Done — M-E2E (suite is a pre-release gate)

**v1 gate = E1–E7 merged green on `develop` (M1–M7a):**
- [x] **M1/E1** — scrypt override in-tree; recover suite fast. → G7.
- [x] **M2/E2** — `decrypt_v3` merged + out-of-release invariant documented. → enables G1 (recover v3).
- [x] **M3/E3** — T-3 green on every PR (recover → `decrypt_v3` round-trip + address). → G1 (recover),
  G5 (recover-path hardening reachable this stage).
- [x] **M4/E4** — T-12·recover green. → G5.
- [x] **M5/E5** — T-7/T-8/T-19 green. → G6.
- [x] **M6/E6** — T-6 + T-13 green locally + via a manual CI dispatch (anvil-in-CI proven). → G3, G4.
- [x] **M7a/E7** — two-tier CI wired; live workflow scheduled/release-gated and green; hermetic tier
  unchanged and PR-gating. → G3, G7.

**Optional (M7b/E8):** T-15/T-16 green; `verify-parity.md` maps every automatable `SKILL.md` step and marks
the ceremony carve-out. → sharpens G3.

**Known accepted hole (G1/G2/G5, this stage):** the interactive `new` **success** ceremony has no
binary-level e2e — deferred with the PTY tier, guarded **only** by in-crate `key_cmd`/`account_cmd` unit
tests (the manual verify skill is `gen → build → sign → send` and does not run the ceremony — it is a
documented T-18 carve-out, not a positive guard). G2 is not met this stage (deferred); G1 is met for every
subcommand *except* `key new`/`account new`.

**Success is auditable:** each success metric (G1–G7) is backed by a named green test or CI run, not a merged
diff — with the `new`-ceremony hole recorded honestly rather than claimed.
