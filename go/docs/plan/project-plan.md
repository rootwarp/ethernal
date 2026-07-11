# Project Plan — eth-deposit Findings-Resolution Release

**Status:** Ready for issue breakdown (task #23)
**Inputs:** `docs/plan/prd.md` (approved), `docs/plan/research/` (approved), `docs/plan/architecture.md` (implementation-ready)
**Scope:** `go/` — one Go module, the `eth-deposit` CLI
**Date:** 2026-07-12

This plan sequences the six findings (F1–F6) into four dependency-ordered phases for a
single developer or two parallel streams over a few days. It is deliberately at **phase
altitude**: exact signatures, sentinel names, and the file-by-file change list live in
`architecture.md` (§§1–9); line-granular task breakdown is task #23's job. Each work item
below is sized to be independently mergeable under the per-issue fast-forward merge cycle,
with one deliberate exception (the default-fill item in Phase 2), which is called out.

---

## Phase overview & critical path

| Phase | Theme | Findings | Depends on |
|---|---|---|---|
| **1 — Foundations** | sentinels, seams, exit-code plumbing, usage-error hook | F2, F5 (fully), foundations for F1 | — |
| **2 — Hybrid RPC wiring** | dial/inject, default-fill relocation, `--from`, `From` derivation | F1 (incl. F1.5) | Phase 1 |
| **3 — Independent fixes & doc pass** | dry-run, consolidated exit-code/`.raw` docs | F3, F4, F6, F1.6 | Phase 2 (F4/F1.6 content), none (F3/F6) |
| **4 — Integration verification** | full suite, e2e, golden diff, verify playbook | all | Phases 1–3 |

**Critical path:** Phase 1 (F1 foundations: `ErrRPCEstimation` + tagging, `exit.go`
mappings, `LocalSigner.Address()`) → Phase 2 (F1 wiring) → Phase 3 (F4/F1.6 doc pass, quick,
must reflect final behavior) → Phase 4 (verify playbook). F2 and F5 (Phase 1) and F3/F6
(Phase 3) are **off** the critical path and parallelizable.

**Two-stream shape:** Stream A drives the critical path (F1 foundations → F1 wiring → docs).
Stream B takes the parallel work: F2 hook and F5 no-TTY in Phase 1; then F3 dry-run and F6
`.raw` polish (no upstream dependency — pullable forward alongside Phase 2).

---

## Phase 1 — Foundations (P0/P1 primitives)

**Objective.** Land every sentinel, injection seam, address accessor, and exit-code mapping
that later phases depend on, and fully resolve the two findings that are self-contained at
this layer (F2 exit-code hook, F5 no-TTY). Package-isolated and parallel-friendly.

**Entry criteria.** Architecture approved (task #21 done). Clean `develop`.

**Work items** (each independently mergeable):

- **1a — `internal/tx` RPC-estimation sentinel** (F1 foundation; arch §2.2). Add
  `ErrRPCEstimation` to `errors.go`; tag the four `resolveRPC` call failures in `builder.go`
  with the two-`%w` form, **preserving the method-name substrings** the builder tests assert.
  Add builder-test assertions that the four call failures satisfy `errors.Is(…, ErrRPCEstimation)`
  and that `ErrChainIDMismatch` / `ErrMissingFromForNonce` do **not** (guard against over-tagging).
- **1b — `internal/signer` address accessor** (F1 foundation; arch §1.5). Add
  `Address() (common.Address, error)` on the concrete `*LocalSigner` only (never the `Signer`
  interface — Ledger stays offline-safe, N1), incl. the closed-signer → `ErrSignerClosed` path.
  Unit-tested in `internal/signer`.
- **1c — `internal/keystore` no-TTY (F5, complete)** (arch §6). Add `ErrNoTTY` sentinel
  (`keystore.go`) and wrap the `/dev/tty` open failure (`passphrase.go`) with the sentinel and
  the `--passphrase-env` hint. *Deviation from the team-lead's suggested shape: all of F5 lands
  here rather than splitting "message text" into Phase 3 — the sentinel and its wrap are one
  change and the exit mapping (1e) needs the sentinel.*
- **1d — F2 usage-error hook (complete)** (arch §3). Add `onUsageError` + `applyUsageErrorHook`
  in `cmd/eth-deposit` and call it in `main()` after the command list is built; add the
  `newFullTestApp` test constructor. Resolves F2 for all five subcommands.
- **1e — `cmd/eth-deposit/exit.go` sentinel mappings** (arch §2.3, §6). Map
  `internaltx.ErrRPCEstimation`→5 (load-bearing — the only mapper, since Phase 2 returns it
  unwrapped), `internaltx.ErrChainIDMismatch`→2, `internaltx.ErrMissingFromForNonce`→2,
  `keystore.ErrNoTTY`→2. Add `exit_test.go` sentinel cases (direct + wrapped). *Depends on 1a
  and 1c (imports their sentinels); the exit-code header-comment prose is deferred to the
  Phase 3 doc pass — see coordination note.*

**Parallelization.** 1a, 1b, 1c, 1d are fully independent (different packages / additive).
1e depends on 1a + 1c. A clean split: Stream A = 1a, 1b, 1e; Stream B = 1c, 1d.

**Exit criteria (measurable).**
- Module builds; `go test ./...` green.
- Missing a required flag exits **2** on all five subcommands (via `newFullTestApp`;
  build/gen/sign/run were the buggy bucket — sign's `--signer` included).
- `exit_test.go` maps `ErrRPCEstimation`→5, `ErrChainIDMismatch`→2,
  `ErrMissingFromForNonce`→2, `keystore.ErrNoTTY`→2 (direct and wrapped).
- The no-TTY passphrase error is `errors.Is(…, keystore.ErrNoTTY)`, its message names
  `--passphrase-env`, and it maps to exit **2**.
- `LocalSigner.Address()` returns the key's address; a closed signer returns `ErrSignerClosed`.
- Golden fixtures untouched and still byte-identical.

**➡ Milestone M1 — Foundations merged.** F2 and F5 closed; all F1 primitives in place.

---

## Phase 2 — Hybrid RPC wiring (F1, P0)

**Objective.** Make `--rpc-url` real: dial the node, inject the client, relocate default-fill
so unset gas/fee/nonce resolve from the node in RPC mode while offline stays byte-identical,
add `--from` with the tightened gate, derive `From` for `run --signer local`, and preserve
error classification through the wiring (F1.5).

**Entry criteria.** M1 (needs `ErrRPCEstimation` + tagging, `exit.go` mappings,
`LocalSigner.Address()`).

**Work items** (issue-sized, independently mergeable except 2b):

- **2a — dial + inject seam** (arch §1.1–§1.2). Add the `newEthRPC` package var (mirrors
  `newBroadcaster`), the `"errors"` import, and the RPC-mode branch in `buildUnsignedTx`:
  nil-interface guard, `defer client.Close()` only after the `err` check, set `buildCfg.RPC`.
  Check-before-wrap so `ErrRPCEstimation` returns **unwrapped** (bypasses the `ErrInvalidInput`
  branch, reaches exit 5) while everything else stays wrapped for the offline exit-2 contract.
- **2b — default-fill relocation** *(indivisible — one commit; see Risk R1)* (arch §1.2–§1.3).
  Move the `main.go:241-253` default-fill into the offline `else` branch **and** change
  `config.go:74` from eager `defaultGasLimit` to unset→`0`, **together**. Flip
  `config_test.go` `TestLoadBuildConfig_Defaults` GasLimit assertion to `0` (the single
  deliberate existing-test change). Splitting these across issues breaks a merge: config-only
  leaks `GasLimit=0` into offline builds → golden failure; main-only relocates the P0
  (`GasLimit=250000` → `EstimateGas` skipped).
- **2c — `--from` flag + `Config.From` + tightened gate** (arch §1.4). Add `Config.From [20]byte`
  and strict hex parse/validate in `LoadBuildConfig`; add the `--from` flag to `buildCommand()`
  only; add the build-Action config-time check requiring `--from` when `--rpc-url` is set and
  `--nonce` **or** `--gas-limit` is omitted (the strict tightening of PRD F1.3 — see Risk R5).
- **2d — remove dead `BuildConfig.RPCURL`** (arch §1.6). Delete the `interface.go` field + stale
  comment and the `RPCURL:` line in the `buildUnsignedTx` literal — **same commit** (compile
  coupling; rides with 2a).
- **2e — `run` local `From` derivation** (arch §1.5). Early derive-and-close in `runAction`:
  for `--signer local` in RPC mode, construct the signer, read `Address()`, close (zeroize),
  set `cfg.Build.From`. Ledger stays zero (requires `--nonce`; N1). *Depends on 1b + 2c.*
- **2f — cmd seam-fake tests** (arch §8.2). `withMockEthRPC` + a cmd-level fake `EthRPC`; the
  behavior-matrix cases (offline unchanged, RPC resolves unset fields, explicit flags win, dial
  unreachable→5, estimation-fail→5, chain-ID mismatch→2, missing-`--from`→2 for both the nonce
  and gas-omitted halves, bad-hex `--from`→2, run-local derives non-zero `From`, run-ledger→2).

**Parallelization.** `config.go` (`Config.From` + gasLimit) is the Phase-2 prerequisite. After
it, the build path (2a/2b/2c/2d in `main.go`+`interface.go`) and the run path (2e in `run.go`)
touch disjoint files and can run in parallel; 2f follows the seam existing. *Note for issue
breakdown (#23): 2a and 2b both edit `buildUnsignedTx` — the estimator may prefer to collapse
them into one issue to avoid two PRs rebasing on the same function; if kept separate, land 2a
first.*

**Exit criteria (measurable).**
- Hybrid build against anvil (or the seam-fake) with `--gas-limit`/`--nonce` omitted produces a
  tx whose maxFee = `2·baseFee + tip`, gas = `estimate·6/5`, and nonce = anvil's **pending
  nonce** — e.g. with the account's pending nonce at 7, the tx nonce is 7.
- Explicit flags in RPC mode win (fake `t.Fatal`s if a resolve call other than `ChainID` fires).
- Unreachable `--rpc-url` exits **5**; a reachable node whose estimation call fails exits **5**;
  RPC chain-ID mismatch exits **2**.
- `build --rpc-url` with `--nonce` **or** `--gas-limit` omitted and no `--from` exits **2** at
  config load; bad-hex `--from` exits **2**.
- `run --signer local --rpc-url` (nonce omitted) resolves using the key-derived non-zero `From`;
  `run --signer ledger --rpc-url` (nonce omitted) exits **2** with no device interaction.
- Offline builds (no `--rpc-url`) remain **250 000 / 20 gwei / 1 gwei / nonce 0**; golden
  fixtures byte-identical (diff empty).

**➡ Milestone M2 — Hybrid mode works end-to-end.**

---

## Phase 3 — Independent fixes & consolidated doc pass (F3, F4, F6, F1.6, P1/P2)

**Objective.** Close the remaining findings: make `gen --dry-run` not require `--output-dir`,
and write all exit-code / chain-ID / `.raw` / `--rpc-url` documentation **once** against final
behavior.

**Entry criteria.** F3 has none (pullable forward alongside Phase 2). The doc pass needs M2 so
its prose (build/run reach exit 5; build-side chain-ID→2) is accurate.

**Work items:**

- **3a — F3 dry-run conditional requiredness** (arch §4). Drop `Required: true` on
  `--output-dir` in `internal/cli`; validate in the Action gated on `!dry-run`, returning
  `ucli.Exit(…, 2)`. **No upstream dependency** — a second stream may land this during Phase 2.
- **3b — Consolidated exit-code / chain-ID doc pass (F4 + F1.6)** (arch §5, PRD F1.6, F4).
  Single coherent pass: `main.go` and `exit.go` header comments; all five per-subcommand
  `--help` exit-code lists (build/run now reach exit 5; three chain-ID paths read coherently —
  build-side config→2, signer-side→3, broadcast-side→5); and the `USER-GUIDE.md` `--rpc-url` /
  `--nonce` / `--from` narrative rows, removing "Phase 4 / accepted-but-stored" language.
  Doc-only, no behavior change. *See the coordination note — inline flag **Usage** strings are
  already done in Phase 2; this item owns the exit-code prose so no comment is edited twice.*
- **3c — F6 `.raw` companion polish** (arch §7). Verify/polish `run --help` and `USER-GUIDE.md`
  so the `0x` prefix, `0o600` mode, and "only when `--output` is a file" condition are explicit.
  Mostly already present — small edits. **No upstream dependency.**

**Parallelization.** 3a and 3c are independent of everything and of each other. 3b depends on
M2 for content accuracy.

**Exit criteria (measurable).**
- `gen --dry-run` with no (or invalid) `--output-dir` succeeds and writes JSON to stdout (exit 0);
  without `--dry-run`, missing/invalid `--output-dir` still exits **2**.
- `--help` and `USER-GUIDE.md` contain no "Phase 4 / accepted-but-stored" language, distinguish
  the exit-3 (signer-side) vs exit-5 (broadcast-side) vs exit-2 (build-side) chain-ID cases, and
  document the `.raw` companion (`0x` prefix, `0o600`, file-only).

**➡ Milestone M3 — All findings closed.** F1–F6 resolved; docs coherent.

---

## Phase 4 — Integration verification

**Objective.** Prove the release against the PRD success metrics (M1–M7) end to end.

**Entry criteria.** M3.

**Work items:**
- Full `go test ./...` and the e2e suite (`-tags=e2e`), including the hybrid `build`/`run
  --rpc-url` e2e case (apply `applyUsageErrorHook`; add `genCommand()` to the e2e app if a gen
  case is added).
- Golden byte-identity check: offline `gen`/`build`/`sign` outputs diff-empty vs the
  pre-release binary; fixtures **not** regenerated.
- Re-run the `verify` skill playbook (`go/.claude/skills/verify/SKILL.md`) gen→build→sign→send
  against a live anvil node, **with the RPC probes now resolving nonce and fees from the node**
  rather than emitting hardcoded defaults.
- Final `USER-GUIDE.md` consistency read.

**Parallelization.** The unit suite, the e2e run, the golden byte-identity diff, and the
verify-skill playbook are largely independent and can run concurrently; only the final
`USER-GUIDE.md` read waits on them.

**Exit criteria (measurable) — PRD success metrics.**
- **M1:** verify playbook passes; anvil `build`/`run` with gas/nonce omitted reflects anvil's
  live tip, base fee, and pending nonce.
- **M2:** unreachable `--rpc-url` on `build`/`run` exits **5**.
- **M3:** missing required flag exits **2** on all five subcommands.
- **M4:** `gen --dry-run` succeeds with no `--output-dir`; without it, missing still exits **2**.
- **M5:** piping into `gen` with no TTY and no `--passphrase-env` exits **2** naming the flag.
- **M6:** docs carry no stale RPC language, disambiguate the chain-ID cases, document `.raw`.
- **M7:** offline golden outputs byte-identical (diff empty).

**➡ Milestone M4 — Verification playbook passes.**

---

## Coordination note — the F1/F4 documentation overlap

F1 (Phase 2) and F4 (Phase 3) both touch the `main.go` / `exit.go` header comments and the
build/run `--help` exit-code lists. To avoid editing the same comment blocks twice:

- **Phase 2 owns only the inline flag `Usage` strings** — the new `--from` usage and dropping
  the "accepted-but-stored / Phase 4 wiring" phrasing from the `--rpc-url` usage (`main.go:96`,
  `main.go:149`) — because those live in the flag/command definitions being changed there.
- **Phase 3 (item 3b) owns all exit-code prose** — every header comment and per-subcommand
  exit-code list — written once against final behavior.

Between the Phase 2 merge and the 3b merge the exit-code prose is briefly stale (build help
won't yet list exit 5); acceptable within the release branch and resolved before M3.

---

## Milestones

| Milestone | Definition of done | Phase |
|---|---|---|
| **M1 — Foundations merged** | F2 + F5 closed; `ErrRPCEstimation`+tagging, `exit.go` mappings, `LocalSigner.Address()`, no-TTY hint all merged; sentinel/exit tests green | end of Phase 1 |
| **M2 — Hybrid mode works E2E** | `build`/`run --rpc-url` resolves nonce/fees from node; offline golden byte-identical; RPC error classification (dial/estimation→5, chain-ID/`--from`→2) correct | end of Phase 2 |
| **M3 — All findings closed** | F1–F6 resolved; F3 dry-run; docs coherent and stale language removed | end of Phase 3 |
| **M4 — Verification playbook passes** | verify skill green with live RPC resolution; PRD M1–M7 all met | end of Phase 4 |

---

## Risks

- **R1 — The two default-fill traps must land as one commit.** `config.go:74` (eager
  `defaultGasLimit`) and `main.go:241-253` (fee/nonce fill) are *both* default-fill sites.
  Fixing only `main.go` relocates the P0 (`GasLimit` still arrives `250000`, `resolveRPC` skips
  `EstimateGas`); fixing only `config.go` leaks `GasLimit=0` into offline builds and breaks the
  golden tests on that merge. Under the per-issue `--ff` cycle (every merge must be green) they
  **cannot** be split across issues. *Mitigation:* work item 2b is indivisible; verify with both
  an RPC-mode "EstimateGas fires when `--gas-limit` omitted" test and offline golden byte-identity.

- **R2 — `WrapInputErr` ordering hazard (F1.5).** `ExitCodeFor` checks `ErrInvalidInput`
  *before* the exit-5 block, and `buildUnsignedTx` blanket-wraps builder errors. If
  `ErrRPCEstimation` is wrapped (or the `ExitCodeFor`→5 line is omitted), a connectivity failure
  wrongly maps to 2 (or falls to the exit-1 fallback). *Mitigation:* check-before-wrap returns
  `ErrRPCEstimation` unwrapped; the `exit.go` →5 mapping is load-bearing (Phase 1, item 1e).
  Tested by dial-unreachable→5 and estimation-fail→5.

- **R3 — Golden-fixture byte-identity (C2/C3/M7).** The default-fill relocation must not perturb
  the offline path (250 000 / 20 gwei / 1 gwei / nonce 0). *Mitigation:* run all `*_golden_test.go`
  unchanged; never regenerate fixtures; diff must be empty. This is a Phase 2 exit criterion and
  an M4 metric.

- **R4 — Test-suite assumptions.** The **only** deliberate existing-test change is
  `config_test.go` `TestLoadBuildConfig_Defaults` (GasLimit `defaultGasLimit`→`0`); do not
  mistake it for a regression. No existing test asserts exit **1** for a missing required flag
  (verified in arch §8.1), so F2's test work is purely additive. The `gen_test.go` `want 1` cases
  are legitimate internal errors (disk-full / scanner) — leave them. All other new tests are
  additive.

- **R5 — PRD F1.3 tightening (RESOLVED).** The architecture strictly tightens F1.3: `--from` is
  required when `--rpc-url` is set and `--nonce` **or `--gas-limit`** is omitted (PRD text said
  only when `--nonce` is omitted), because `EstimateGas` carries the 32-ETH value from `From` and
  most nodes reject a zero sender. Approved at the architecture gate; PRD F1.3 has been synced to
  the tightened rule (plus a SHOULD extending the config-time check to ledger+RPC without
  `--gas-limit`). No open decision remains; Phase 2's config-time gate and exit criteria follow
  the tightened rule.
