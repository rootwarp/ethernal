# PRD — eth-deposit Findings-Resolution Release

**Status:** Draft for planning
**Owner:** eth-utils maintainers
**Scope:** `go/` (`eth-deposit` CLI)
**Date:** 2026-07-12

---

## 1. Problem statement

`eth-deposit` is a single Go CLI (urfave/cli v3) that takes BLS validator keystores
through to a broadcast Beacon Chain deposit transaction via five subcommands:
`gen`, `build`, `sign`, `run`, `send`. It was recently merged from two binaries
(`eth-deposit-gen` + `eth-deposit-tx`).

A full end-to-end verification — all five subcommands driven against golden
fixtures and a live anvil node — **passed**, but surfaced six findings. They
range from a P0 correctness gap (the `--rpc-url` flag is accepted and advertised
but never dialed, so "hybrid" gas/nonce estimation silently does nothing) to P2
documentation polish. Two of the findings are about **exit-code consistency**,
which matters because the tool's typed exit codes (0–5) are a documented,
scriptable contract that operators and automation depend on to distinguish
"operator rejected" from "signer problem" from "wrong network."

This release resolves all six findings without disturbing the security-critical
offline/air-gapped path or the byte-for-byte golden outputs.

---

## 2. Goals

- **G1 — Make `--rpc-url` real.** When an operator supplies `--rpc-url` to
  `build` or `run`, unset gas / fee / nonce fields are resolved from the node.
  Explicit flags always win. Offline mode (no `--rpc-url`) is unchanged.
- **G2 — Exit codes are consistent and correct across all five subcommands.**
  Every user/configuration error (including missing required flags) exits `2`;
  connectivity/broadcast errors exit `5`; the documented contract holds on every
  path.
- **G3 — Documentation matches behavior.** `--help` text and `USER-GUIDE.md`
  no longer over-promise (RPC estimation) or mislead (exit-code semantics), and
  document existing intentional behavior (the `.raw` companion file, the
  no-TTY passphrase hint).
- **G4 — No regressions.** All existing tests pass; golden fixtures remain
  byte-identical for offline builds with explicit flags; no new dependencies.

### Non-goals (summary; expanded in §7)

Ledger/signing changes, new networks, removing the `.raw` companion output, or
changing offline-mode defaults are explicitly out of scope.

---

## 3. User stories

- **U1 — Online hybrid build (new).** As an operator building a deposit tx on a
  connected machine, I pass `--rpc-url` and omit gas/nonce so the tool fetches
  the current tip, computes `maxFee = 2·baseFee + tip`, reads my pending nonce,
  and estimates gas with a safety margin — so my tx uses live network conditions
  instead of stale hardcoded defaults. If the RPC is unreachable, the command
  fails loudly (exit `5`) rather than silently producing a tx with default fees.
- **U2 — Air-gapped operator (unaffected).** As an operator on an offline
  machine, I supply all gas/nonce flags explicitly and never pass `--rpc-url`.
  My workflow, outputs, and exit codes are **identical** to before this release;
  the security-critical path does not change.
- **U3 — Script author relying on exit codes.** As an automation author, I branch
  on `eth-deposit`'s exit code. A missing required flag reliably exits `2`
  ("fix your invocation") on every subcommand — never `1` ("internal error,
  page a human") — so my error handling is correct and portable across
  subcommands.

---

## 4. Functional requirements

Priorities: **P0** = correctness/contract violation, ship first; **P1** =
user-visible defect; **P2** = documentation polish.

### F1 — Wire real RPC estimation into `build` and `run` (P0)

**Evidence.** `build`/`run` accept `--rpc-url` (main.go:147-151, run.go:196-200)
but the flag is never dialed. `buildUnsignedTx` (main.go:216-261) constructs
`internaltx.BuildConfig` with only the `RPCURL` string field set and never sets
`BuildConfig.RPC`; `interface.go:52` states "RPCURL is reserved for Issue 2.5 …
unused here." `builder.go:78` (`resolveFields`) branches solely on
`cfg.RPC == nil`, so a URL-only config always takes the static path. A fully
implemented `resolveRPC` (builder.go:91-165) — chain-ID check, `SuggestGasTipCap`,
`maxFee = 2·baseFee + tip`, `PendingNonceAt`, `EstimateGas` with a 20% margin —
and a working `internaltx.NewEthClient` (rpc_client.go:48-54) are dead code.
Separately, unset fields are **pre-filled with defaults in two places**, which
would defeat resolution even if `RPC` were wired: `config.go:74` sets
`gasLimit = defaultGasLimit` unconditionally, and `buildUnsignedTx`
(main.go:241-253) fills fees→20/1 gwei and nonce→0. The `--help` text falsely
promises "hybrid mode when `--rpc-url` is provided" (main.go:96) and
"gas/nonce estimation" (main.go:149); `USER-GUIDE.md:246` admits the flag is
"accepted-but-stored only (Phase 4 wiring)."

**Requirements.**

- **F1.1** When `--rpc-url` is non-empty, `build`/`run` MUST construct a live
  client via `internaltx.NewEthClient` and set `BuildConfig.RPC` so `resolveRPC`
  runs.
- **F1.2** In RPC mode, any gas / fee / nonce field **not explicitly set by a
  flag** MUST be left unset (gas `0`, fees `nil`, nonce `nil`) so it resolves
  from the node. The default-filling at `config.go:74` and `main.go:241-253` MUST
  become "resolve-only-when-unset-and-offline," not unconditional. Explicit flags
  MUST still take precedence (already honored inside `resolveRPC`, e.g.
  builder.go:105, 114, 125).
- **F1.3** `build` MUST gain a `--from` flag (the sender address). It is
  **required when `--rpc-url` is given and either `--nonce` or `--gas-limit` is
  omitted**: `PendingNonceAt` needs the sender for nonce resolution
  (builder.go:128-129, errors.go:20), and `EstimateGas` passes `From` in the
  32-ETH deposit call (builder.go:151), which most nodes reject for a zero
  sender ("insufficient funds") — a confusing runtime exit-5. Requiring
  `--from` at config-load time turns that into a clean exit-2. When both
  `--nonce` and `--gas-limit` are supplied, `--from` is not required.
  *(Tightened from "required only when `--nonce` is omitted" at the
  architecture gate — see architecture.md §1.4/§1.5; strict tightening, never
  relaxes the original rule.)*
  For `run`, sender derivation depends on the signer:
    - `--signer local`: `run` MUST derive `From` from the private key it already
      holds and pass it unconditionally in RPC mode, so nonce and gas
      auto-resolution work with no new flag.
    - `--signer ledger` (run.go:50): there is no private key, and querying the
      device for its address before signing would change Ledger behavior
      (violates N1). So `From` stays zero and, with `--nonce` omitted,
      `resolveRPC` returns `ErrMissingFromForNonce` (builder.go:128-129) →
      exit `2` (per F1.5). The requirement: `run --signer ledger` in RPC mode
      MUST require the operator to pass `--nonce` (nonce auto-resolution is
      unavailable for ledger); its absence surfaces as `ErrMissingFromForNonce`
      / exit `2` rather than a silent default. For the same zero-`From` reason
      as F1.3's `EstimateGas` case, ledger in RPC mode SHOULD also require
      `--gas-limit` at config-load time (else estimation fails at runtime with
      exit 5); implementation MAY extend the config-time check accordingly. (Whether to add a `--from` flag to
      `run` for the ledger case is an implementation choice for §architecture;
      it is not required by this PRD.)
- **F1.4** Offline mode (no `--rpc-url`) MUST be unchanged: defaults stay
  250 000 gas / 20 gwei maxFee / 1 gwei tip / nonce 0, and golden outputs remain
  byte-identical (see §5).
- **F1.5 — Error classification MUST survive wiring (intersects F2/F4).**
  Today `buildUnsignedTx` blanket-wraps every builder error with
  `WrapInputErr("build", …)` (main.go:258), tagging it `ErrInvalidInput`, and
  `ExitCodeFor` checks `ErrInvalidInput` (exit.go:44) **before** the RPC/broadcast
  sentinels (exit.go:85). Consequently, once RPC is wired, an estimation-time
  connectivity failure would resolve to exit `2` instead of the required `5`
  (and `resolveRPC` does not tag such errors with `ErrRPCDial` — they are plain
  `fmt.Errorf`, e.g. builder.go:109). The implementation MUST ensure:
    - RPC connectivity/dial failures (unreachable node, estimation call failure)
      map to exit **5** — a hard error, never silent success.
    - Build-time RPC chain-ID mismatch (`internaltx.ErrChainIDMismatch`,
      builder.go:97) maps to exit **2** (a configuration error: wrong endpoint).
      Note this is currently **not** in `ExitCodeFor` at all and must be added;
      it is the build-side sibling of the send-side mismatch F4 disambiguates —
      keep the two consistent.
    - `ErrMissingFromForNonce` (errors.go:20) maps to exit **2**. (F1.3's
      `--from` validation should catch this at config-load time; this is the
      backstop target.)
  In short, builder errors MUST NOT all be funneled through `WrapInputErr`.
- **F1.6** Update `--help` (build/run descriptions and the `--rpc-url` usage
  strings) and `USER-GUIDE.md:246` to describe the now-real behavior and the new
  `--from` flag; remove the "Phase 4 wiring / accepted-but-stored" language.

### F2 — Missing-required-flag errors must exit 2 everywhere (P0)

**Evidence.** Missing a required flag exits `1` ("internal error") on `build`
and `gen`, but `2` ("user/configuration error") on `sign`. `build` marks
`input-file` `Required: true` (main.go:124); `gen` marks four flags
`Required: true` (cli.go:112, 117, 122, 127). These trigger urfave/cli v3's
built-in required-flag validation, whose error is not recognized by
`ExitCodeFor` — the `ucli.ExitCoder` check only matches codes that already
equal `2` (exit.go:59-61) — so it falls through to the exit-`1` fallback
(exit.go:91). By contrast, `sign`, `run`, and `send` perform **manual** checks that
return `ucli.Exit(msg, 2)` (e.g. run.go:48; send.go:47, 52), which map correctly.
So the buggy bucket is `build` + `gen` (urfave `Required: true` → exit `1`); the
correct bucket is `sign` + `run` + `send` (manual `ucli.Exit(…, 2)`). The
documented contract is that user/config errors exit `2` (main.go:11, exit.go:4).

**Requirements.**

- **F2.1** A missing required flag MUST exit `2` on all five subcommands.
- **F2.2** The fix MUST be uniform (mapping urfave's required-flag error in
  `ExitCodeFor`, or equivalent), not per-flag manual checks that can drift again.
- **F2.3** All other exit-code paths that are currently correct MUST be
  preserved (see §5).

### F3 — `gen --dry-run` must not require a valid `--output-dir` (P1)

**Evidence.** `gen --dry-run` writes no file (it prints JSON to stdout via the
DryRunWriter — gen.go:81-86, cli.go:138-140), yet `--output-dir` is
`Required: true` (cli.go:124-128), so omitting it yields
`Required flag "output-dir" not set`; supplying an invalid directory fails
`validateOutputDir` (cli.go:200-204). This is a contradiction: the flag is
mandatory and validated for a mode that never touches disk.

**Requirements.**

- **F3.1** When `--dry-run` is set, `--output-dir` MUST NOT be required, and its
  directory validation MUST be skipped.
- **F3.2** When `--dry-run` is not set, `--output-dir` MUST remain required and
  validated exactly as today (missing/invalid → exit `2`).

### F4 — Disambiguate signer-side vs broadcast-side chain-ID mismatch in docs (P1)

**Evidence.** The `main.go:12` header comment lists "chain ID mismatch" under
exit `3`, but the codebase intentionally splits it: signer-side mismatch
(`signer.ErrInvalidChainID`, `signer.ErrChainIDMismatch`) → `3`
(exit.go:72-73), while the send-side signed-tx-vs-RPC mismatch
(`internaltx.ErrBroadcastChainIDMismatch`) → `5` (exit.go:87). The `exit.go:9-10`
comment already disambiguates; `main.go` and `--help` do not.

**Requirements.**

- **F4.1** The `main.go` doc comment (main.go:7-14) MUST distinguish signer-side
  chain-ID mismatch (exit `3`) from broadcast-side chain-ID mismatch (exit `5`).
- **F4.2** The `--help` exit-code text (e.g. the summary at main.go:70 and the
  per-subcommand exit-code lists) MUST reflect the same disambiguation.
- **F4.3** Documentation only — no behavior change. Keep consistent with F1.5's
  build-side `ErrChainIDMismatch` (exit `2`) so all three chain-ID paths
  (build-side config error `2`, signer-side `3`, broadcast-side `5`) are
  described coherently.

### F5 — No-TTY passphrase error must hint at `--passphrase-env` and exit 2 (P1)

**Evidence.** When `gen` needs a passphrase and no TTY exists (piped usage), the
termPromptSource fails opening `/dev/tty` (passphrase.go:46-48), producing
`passphrase source: open tty: open /dev/tty: device not configured`
(wrapped at keystore.go:127). This error matches no sentinel in `ExitCodeFor`,
so it hits the exit-`1` fallback (exit.go:91) — an "internal error" for what is
really a user/environment problem, and the message gives no remedy.

**Requirements.**

- **F5.1** The no-TTY passphrase error message MUST hint that the operator can
  supply `--passphrase-env VAR` for non-interactive/piped use.
- **F5.2** This error MUST exit `2` (user/environment error), which requires a
  recognizable sentinel (e.g. a new `keystore.ErrNoTTY`) mapped in `ExitCodeFor`
  alongside the other keystore exit-`2` sentinels (exit.go:48-56).

### F6 — Document the `.raw` companion output for `run` (P2)

**Evidence.** `run --output X.json` also writes `X.raw` (0x-prefixed RLP hex for
`cast publish`), unasked (run.go:287-296, `rawPathFor` at run.go:351-354). This
is intentional. Note it is **already documented** in `run`'s `--help`
(run.go:89-99, "Output artifacts … signed.raw") and in `USER-GUIDE.md:489-491`.

**Requirements.**

- **F6.1** Verify and, if needed, polish the existing documentation so the `.raw`
  companion, its `0o600` permission, its `0x` prefix, and the "only when
  `--output` is a file" condition are clearly stated in both `run --help` and
  `USER-GUIDE.md`. This is a **verify/polish** item, not net-new documentation —
  the estimate should reflect that most of the text already exists.

---

## 5. Constraints and invariants

- **C1 — Exit-code contract preserved.** The 0/1/2/3/4/5 contract
  (main.go:7-14, exit.go:1-11) MUST hold for every path that is already correct.
  Only the *incorrect* mappings (F2, F5) and *newly reachable* paths (F1.5)
  change.
- **C2 — Golden outputs byte-identical.** `gen`/`build`/`sign` golden fixtures
  MUST remain byte-for-byte identical for offline builds with explicit flags
  (see `*_golden_test.go` under `cmd/eth-deposit` and `internal/tx`).
- **C3 — Backward compatibility of the air-gapped path.** The offline workflow
  (no `--rpc-url`, explicit flags) is the security-critical path and MUST NOT
  change in behavior or defaults (250 000 gas / 20 gwei / 1 gwei / nonce 0).
- **C4 — Tests.** All existing tests MUST keep passing. New behavior (RPC-wired
  `build`/`run`, `--from`, dry-run without `--output-dir`, corrected exit codes,
  the no-TTY hint) MUST be covered by new tests, including the `-tags=e2e` tests
  under `cmd/eth-deposit`. Note: any existing test that asserts exit `1` for a
  missing required flag on `build`/`gen` is codifying the F2 bug; updating it to
  expect `2` is part of the fix, not a regression.
- **C5 — No new dependencies.** Reuse go-ethereum's `ethclient` already used by
  `send` (rpc_client.go). No other new modules.

---

## 6. Success metrics

- **M1** Re-running the end-to-end verification playbook (the `verify` skill /
  gen→build→sign→send against golden fixtures and a live anvil node) passes,
  **with the RPC probes now resolving nonce and fees from the node** rather than
  emitting hardcoded defaults. A `build`/`run` against anvil with gas/nonce
  omitted produces a tx whose fields reflect anvil's live tip, base fee, and
  pending nonce.
- **M2** An unreachable `--rpc-url` on `build`/`run` exits `5` (not `0`/`1`/`2`).
- **M3** Missing a required flag exits `2` on all five subcommands (verified per
  subcommand).
- **M4** `gen --dry-run` succeeds with no `--output-dir` supplied and writes JSON
  to stdout; without `--dry-run`, a missing `--output-dir` still exits `2`.
- **M5** Piping into `gen` with no TTY and no `--passphrase-env` exits `2` with a
  message naming `--passphrase-env`.
- **M6** `--help` and `USER-GUIDE.md` contain no "Phase 4 / accepted-but-stored"
  language, correctly disambiguate the exit-`3` vs exit-`5` chain-ID cases, and
  document the `.raw` companion.
- **M7** Offline golden-fixture outputs are byte-identical to the pre-release
  binary (diff is empty).

---

## 7. Non-goals

- **N1** No changes to Ledger / hardware signing behavior or the signer package
  beyond exit-code documentation.
- **N2** No new networks; the supported set (mainnet, hoodi, sepolia, holesky for
  tx; mainnet/hoodi for `gen`) is unchanged.
- **N3** Do **not** remove or alter the `.raw` companion output (F6 documents it;
  it stays).
- **N4** No change to offline-mode defaults or the air-gapped workflow (C3).
- **N5** No new RPC-dependent features beyond resolving gas / fee / nonce /
  chain-ID for `build` and `run`; `send`'s existing RPC behavior is untouched.
- **N6** No migration off urfave/cli v3 and no new third-party dependencies (C5).
