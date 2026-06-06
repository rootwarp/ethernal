# PRD: `eth-utils/go` Remediation — Path to Testnet-Trustworthy v0.2 and Mainnet-Ready v1.0

**Author:** prd-writer (team dev-plan)
**Date:** 2026-06-07
**Status:** Draft v1
**Input:** `go/plan/REVIEW.md` (adversarial review, 71 findings GO-001..GO-071 + unnumbered quality-theme catalogue)
**Scope module:** `/Users/nil-00/git/rootwarp/eth-utils/go` — the `eth-deposit-gen` and `eth-deposit-tx` CLIs and their `internal/` packages (`bls`, `ssz`, `deposit`, `keystore`, `signer`, `tx`, `cli`, `network`, `output`).

---

## 1. Overview

This PRD plans the remediation of every defect surfaced by the adversarial review of the Ethereum validator deposit toolchain. The toolchain is **security-critical**: a single defect can irreversibly burn 32+ ETH per validator. The review concluded that the codebase's architecture and cryptographic primitives are sound but that **two release-blocking trust-boundary bugs ship today**: deposits are generated with all-zero withdrawal credentials (`GO-001`) and the broadcaster never binds deposit-data network/fork-version to the transaction's target network (`GO-002`). A cluster of high/medium findings concentrate at the same boundaries.

We will deliver remediation in two milestones:

1. **M0 — v0.2 "Hoodi-Trustworthy"** (testnet-ready first): every defect that causes irreversible loss, silent data corruption, secret leakage, or test/release-hygiene failure is closed. The hoodi E2E flow becomes the trustworthy reference path; v0.2 must be a release on which we would not be embarrassed to base our mainnet release.
2. **M1 — v1.0 "Mainnet-Ready"**: the remaining safety, robustness, and documentation work that is mainnet-specific or whose impact is mitigated on testnet. Adds a non-bypassable mainnet acknowledgement gate, removes all dead/latent code paths, and converts every remaining latent bug into a tested invariant.

A small residue of pure code-quality and documentation hygiene work is grouped into **M2 — v1.1 Hardening**.

---

## 2. Problem Statement

The toolchain ships today with at least two paths that **permanently lock 32 ETH per validator on mainnet**, plus a series of corollary findings that make the failure invisible to a careful operator:

- **Cryptographically unwithdrawable deposits.** `eth-deposit-gen` hard-codes a `0x00`-prefix withdrawal credential with an all-zero 31-byte body. There is no `--withdrawal-address` flag, no downstream validator that rejects it, and the committed mainnet golden fixture proves this ships today. Only a `TODO(P1)` comment acknowledges the gap. `docs/USER-GUIDE.md` shows a `0x01` credential the tool can never produce, so an operator following the guide believes their deposit is recoverable. (GO-001, GO-052.)
- **Cross-network signing.** `eth-deposit-tx` reads the deposit-data JSON's `network_name`/`fork_version` but never binds them to the `--network` build target. A holesky deposit becomes a valid mainnet transaction whose BLS signature is over the wrong domain — accepted on-chain, rejected by the consensus layer. Default network is `hoodi`, so the inverse mistake is one forgotten flag away. (GO-002.)
- **Unverified signing and broadcast.** `sign` signs an unvalidated `to` address that `common.HexToAddress` silently mangles; `send` runs all of its safety prompts and chain-ID checks against JSON metadata while broadcasting an independent `rawRLP` blob. A tampered or mixed-up `signed.json` shows the operator one transaction and broadcasts another. (GO-003, GO-004.)
- **Silent failure modes on the read/write path.** Deposit data writes collide silently within a one-second window and `os.Rename` clobbers existing files; the read-path never recomputes SSZ roots or re-verifies the BLS signature; duplicate pubkeys and unexpected positional arguments are silently accepted; reverted on-chain deposits return exit code 0; the advertised `--rpc-url` hybrid mode is dead code. (GO-005, GO-009, GO-010, GO-011, GO-012, GO-040.)
- **Secret-material leakage in errors and artifacts.** A herumi error embeds the full 32-byte BLS secret in hex; an env-var validation error echoes the suspected private key value; the RPC dial error embeds the API-key URL; the e2e script `tee`s key-bearing URLs into git-tracked artifacts. (GO-006, GO-014, GO-049, GO-053.)
- **Toolchain and dependency staleness.** `go-ethereum v1.14.12` predates the `usbwallet` fix for current Ledger firmware (PID 0x5000, Flex, Gen5); release builds run on the unpatched `go1.26.0` stdlib (TLS/x509 reachable through the RPC path); no `govulncheck`/OSV scanning gates CI. (GO-055, GO-056, GO-057.)

The cumulative status quo is a toolchain that is "almost correct, with a default that burns funds." This PRD closes that gap.

---

## 3. Goals & Success Metrics

### 3.1 Primary Goal

Make `eth-utils/go` a toolchain that an operator can use to deposit 32 ETH against the hoodi testnet (M0), and against mainnet (M1), with no plausible operator error or input mishandling resulting in irreversible loss of funds.

### 3.2 Success Metrics

| # | Metric | Target | Milestone |
|---|---|---|---|
| 1 | Critical/High findings (GO-001..GO-004) closed and verified by automated test | 4 / 4 | M0 |
| 2 | All P0 findings closed | 100% | M0 |
| 3 | All P1 findings closed | 100% | M1 |
| 4 | Real-RPC hoodi E2E pipeline (`make e2e-testnet`) green, no secrets in artifacts, exit codes correct | passing | M0 |
| 5 | Real-device Ledger sign-and-broadcast E2E on hoodi against current firmware | passing | M0 |
| 6 | Independent cross-validation (`--verify-with-deposit-cli` against real `ethstaker-deposit-cli`) green for every network | passing | M0 |
| 7 | `govulncheck ./...` clean (or every hit triaged with documented suppression) in CI on every push | 0 reachable hits | M0 |
| 8 | `gofmt -l .` empty; `golangci-lint run` reports 0 errcheck/staticcheck/vet findings | 0 | M0 |
| 9 | Documented CLI contract (flags, exit codes, JSON shapes) matches behavior, audited by a `make doc-audit` target | 0 deltas | M0 |
| 10 | Mainnet acknowledgement gate present and not bypassable by `--yes` | implemented + tested | M1 |
| 11 | Test suite contains a differential SSZ oracle and an `accounts/abi` cross-check of `PackDeposit` | both passing | M1 |
| 12 | No process exit leaves secret material in **Go-managed** memory (audited via `runtime.KeepAlive`-corrected zeroizers + heap-dump test); herumi C-side scalar persistence documented as a known limitation | passing | M1 |
| 13 | Zero "tested only against ourselves" assertions in critical-path tests; every BLS/SSZ/ABI invariant has an external-authority cross-check | passing | M1 |

### 3.3 Non-Metric Goals

- Preserve the existing strong architecture: dependency injection, sentinel-error exit-code contracts, `internal/network` as the single constants source, verify-before-write in `internal/deposit`, atomic writes for signed artifacts.
- Do not regress idiomatic-Go conventions enumerated in `go/CONVENTIONS.md`.

---

## 4. Target Users & Stakeholders

### 4.1 Operators (primary)

Engineers running validator deposits, typically with one of these profiles:

- **Self-custody validator runner:** small number of keys (≤16), prefers Ledger for the sender key, runs from a workstation against a hosted RPC. Most sensitive to silent mistakes; the Ledger path is the documented mainnet-safe path.
- **Pro staker / pool operator:** dozens to hundreds of keys per batch, automation-driven (`--parallel`, `--yes`, `--wait-for-receipt`, `--receipt-output`), air-gapped signing ceremonies. Most sensitive to exit-code regressions, silent overwrites, and CLI surface stability inside a batch.
- **Test/CI:** runs e2e against hoodi as a smoke test before mainnet ceremonies. Most sensitive to deterministic golden fixtures and predictable exit codes.

### 4.2 Maintainers (secondary)

The repository maintainers who must keep the toolchain trustworthy across `go-ethereum`, Ledger firmware, and consensus-spec changes. Sensitive to test independence (no self-referential oracles), tooling/CI gates (govulncheck, gofmt), and the absence of dead/duplicated code that drifts.

### 4.3 Security reviewers (tertiary)

External audit teams and future adversarial reviewers. Sensitive to traceability: every finding closed by an identifiable PR, a regression test, and where applicable a CHANGELOG/migration note.

---

## 5. User Stories / Use Cases

- **As a self-custody validator runner**, I want to generate deposit data with a withdrawal address I control so that I can recover my 32 ETH if I exit the validator. *(GO-001, GO-052.)*
- **As an operator**, I want `--network hoodi` builds to refuse mainnet deposit data (and vice versa) so that I cannot accidentally cross-sign a deposit whose BLS signature is over the wrong domain. *(GO-002, GO-012.)*
- **As an operator using `sign` offline**, I want any malformed `to` address to fail loudly so that I cannot sign a transaction to the zero address or a typo-coerced contract. *(GO-003.)*
- **As an operator using `send`**, I want the confirmation prompt and chain-ID guard to display the values actually inside the `rawRLP` payload so that I cannot be tricked by tampered JSON metadata. *(GO-004.)*
- **As an automation operator**, I want a reverted on-chain deposit to exit non-zero so that my CI does not believe a stranded deposit succeeded. *(GO-010.)*
- **As an operator running `eth-deposit-gen --parallel 8`**, I want passphrase prompts to never echo to my terminal scrollback so that a recorded session does not leak my keystore passphrases. *(GO-007.)*
- **As an operator generating multiple deposits in a script**, I want each deposit-data file to be uniquely named and never silently overwritten so that I do not lose an already-funded deposit. *(GO-011.)*
- **As an operator using a current-firmware Ledger**, I want hardware signing to work so that I do not get steered to the development-only local-key path on a mainnet ceremony. *(GO-019, GO-023, GO-024, GO-055.)*
- **As an SRE running this in CI**, I want secrets (API keys, BLS secrets, private keys) to never appear in logs, error messages, or artifacts so that a build log share does not become an incident. *(GO-006, GO-014, GO-017, GO-049, GO-053.)*
- **As an operator using mainnet**, I want a confirmation step that `--yes` does not bypass so that a script written for testnet cannot silently broadcast a mainnet deposit. *(GO-013.)*
- **As a maintainer**, I want `govulncheck`, `gofmt`, and `errcheck` to gate CI so that staleness and silent-write bugs do not accumulate. *(GO-044, GO-057, GO-058.)*
- **As a maintainer**, I want every funds-critical invariant (SSZ roots, ABI layout, BLS validation, exit-code contract) to have an externally-authoritative cross-check so that a future refactor cannot regress it silently. *(GO-048, GO-059, GO-070.)*

---

## 6. Functional Requirements

All 71 numbered findings and the unnumbered quality catalogue are addressed below, prioritized **P0 (must ship in v0.2 / M0)**, **P1 (must ship in v1.0 / M1)**, **P2 (M2 hardening, no release blocker)**. Each entry lists the finding ID(s), the required behavior change, and (where applicable) the acceptance test.

### 6.1 P0 — Required for v0.2 (Testnet-Trustworthy, M0)

> The release bar for M0: a hoodi E2E walk-through that any of us would be willing to repeat against mainnet with only an additional acknowledgement gate. Any defect that can cause irreversible loss, silent data corruption, secret leakage, or an unsafe default ships fixed in M0.

#### 6.1.1 Trust-boundary critical bugs (FR-P0-A)

- **FR-P0-A1 (GO-001).** Remove `defaultWithdrawalCreds()`. Add a required `--withdrawal-address` flag that accepts a 20-byte EIP-55 address and emits a `0x01`-prefix credential (`0x01 || 11 zero bytes || address[20]`). Refuse to generate without it. **v0.2 supports `0x01` credentials only** — no `--withdrawal-bls-pubkey`/`0x00` support (user decision at plan gate, 2026-06-07: BLS-withdrawal is a niche/legacy path; candidates 0x00/0x02 tracked for vNext). *Breaking change accepted per product decision.* Acceptance: regen golden fixtures; assert no committed fixture contains 64 zero hex chars in `withdrawal_credentials`.
- **FR-P0-A2 (GO-001 defense-in-depth).** In `deposit.Entry.Validate` and `internal/tx.Validate`, reject `0x00`-prefix credentials whose 31-byte body is all-zero; reject `0x01`/`0x02`-prefix credentials whose first 11 bytes are non-zero; accept only the canonical layouts.
- **FR-P0-A3 (GO-002).** In `Entry.Validate`, capture the looked-up `network.Params` and require `entry.ForkVersion == params.GenesisForkVersion`. Add `Entry.ValidateForNetwork(target network.Params)` (or equivalent) called from `buildUnsignedTx`/`run`/`sign` that hard-fails with exit 2 if `entry.NetworkName != target.Name` or fork versions diverge.
- **FR-P0-A4 (GO-012, paired with GO-002).** On the read path, recompute `DepositMessage.HashTreeRoot` and `DepositData.HashTreeRoot` from entry fields and require equality with the stored roots; verify the BLS signature against the network's deposit domain; reject `bls.ValidatePubkeyBytes` for the point-at-infinity. Move the previously-skipped BLS pubkey on-curve check to the production path; all golden fixtures already carry real G1 points.
- **FR-P0-A5 (GO-003).** `parseUnsignedTx` must call `common.IsHexAddress(unsigned.To)` and additionally enforce exact 42-character `0x`-prefixed length. Cross-check `To` against `network.LookupByChainID(unsigned.ChainID).DepositContractAddress`; require an explicit `--allow-non-deposit-recipient` override for any other address. Print a signing summary (to/value/chainID) before the local-signer sign call. Acceptance: table-driven tests including empty `To`, 41-char truncation, trailing non-hex, and a non-deposit recipient.
- **FR-P0-A6 (GO-004).** Before the `send` confirmation prompt, decode `signed.RawRLP` via `types.Transaction.UnmarshalBinary`; derive chainID/to/value/nonce/hash/recovered-sender from the decoded tx; abort with exit 2 on any divergence from `signed.Unsigned`/`signed.From`/`signed.Hash`. Render the prompt and run the chain-ID guard from the decoded values. Compare decoded `To` against `netParams.DepositContractAddress`. Fix `hexToBigInt` to return an explicit error on `SetString` failure rather than the receiver. Acceptance: tampered-JSON regression test, malformed-value-hex test.

#### 6.1.2 Silent-loss and data-correctness bugs (FR-P0-B)

- **FR-P0-B1 (GO-009).** `parsePubkeys` must reject duplicate pubkeys with an exit-2 error naming the entry and indices. No silent dedup.
- **FR-P0-B2 (GO-010).** `--wait-for-receipt` must return a non-nil error mapped to a dedicated documented exit code (proposed: code **5** reused or **6** added — see Open Question §11.2) when `rec.Status == 0`, after writing the receipt file. Add a distinct documented code for "broadcast succeeded but receipt-poll timed out". Acceptance: receipt-revert + receipt-timeout integration test.
- **FR-P0-B3 (GO-011).** `FSWriter.Write` must allocate the temp file via `os.CreateTemp(dir, ".deposit_data-*.json.tmp")` (unique, `O_EXCL`). The final path must include a sufficiently high-resolution suffix (UTC `RFC3339Nano` or content hash); on collision, refuse to clobber an existing file. `fsync` the parent directory after rename. Acceptance: parallel-write stress test producing N>1000 files in the same second with no overwrite.
- **FR-P0-B4 (GO-027).** `ScanDir` must error (or warn at minimum and continue) when two `.json` files declare the same pubkey, naming both paths. Acceptance: fixture with a duplicate.
- **FR-P0-B5 (GO-026).** Introduce `internal/keystore.normalizePubkeyHex` (`TrimPrefix(ToLower(s), "0x")`); replace all three duplicated normalization sites; add a `0X`-prefix regression test.
- **FR-P0-B6 (GO-040).** `app.Action` must reject `c.NArg() > 0` with exit 2; document that `--pubkeys` is comma-separated only.
- **FR-P0-B7 (GO-031).** In both static and RPC fee-resolution paths, return an error when `tip.Cmp(maxFee) > 0`.
- **FR-P0-B8 (GO-005, per product decision).** Reject `--rpc-url` on `build` and `run` with an explicit exit-2 error ("--rpc-url is reserved for v1; provide --nonce and fees explicitly"). Delete `BuildConfig.RPCURL` and the dead `resolveRPC` path from the production call site (keep the implementation behind tests until M1, when the hybrid mode is wired). Never silently substitute `nonce=0` or the 20-gwei default — `--nonce` and fee flags become required for `build`/`run`. Update `scripts/e2e-testnet.sh` to pass them. Acceptance: GO-054 fixed transitively; documented `build` invocation reproducible from the manpage.
- **FR-P0-B9 (GO-016).** `build` and `sign` must use `atomicWriteFile` (or the same temp+rename helper as `run`/`send`), with explicit chmod re-application. Marshal vs write errors must map to consistent documented exit codes across `build`, `sign`, `run`, `send`.
- **FR-P0-B10 (GO-044).** Run `gofmt -w .`. Add `test -z "$(gofmt -l .)"` and `errcheck ./...` to `make lint` and to CI.

#### 6.1.3 Secret-material and credential leaks (FR-P0-C)

- **FR-P0-C1 (GO-006).** `bls.NewSigner` must not wrap herumi's `Deserialize` error verbatim. Return a fixed sentinel: `errors.New("bls: secret key rejected (scalar out of range for BLS12-381)")`.
- **FR-P0-C2 (GO-014).** `--private-key-env` validation must never echo the offending value. Print only a redacted summary ("rejected: first 4 chars + length=N") and an actionable warning that the rejected value should be treated as compromised. Apply to both `LoadRunConfig` and `LoadSignConfig` and to `NewLocalSignerFromEnv`'s missing-var error.
- **FR-P0-C3 (GO-049).** `ErrRPCDial`'s error must contain `scheme://host` only — never the path/query (where API keys typically live). Add a regression test against a URL with embedded credentials.
- **FR-P0-C4 (GO-053).** `scripts/e2e-testnet.sh` must not `echo`/`tee` the RPC URL; outputs must be written outside the repository tree (e.g., `${TMPDIR}/eth-deposit-tx-e2e/`). Add `.gitignore` entries for any in-tree e2e artifact directories. Acceptance: shell-grep CI check rejecting `tee $RPC_URL` style patterns.
- **FR-P0-C5 (GO-007).** `termPromptSource` must be concurrency-safe: a single prompt before the worker pool, caching the passphrase under a mutex (return a fresh copy per call to satisfy the loader's zeroize contract; zeroize the cache at end of run). Alternative acceptable per discretion: reject `--parallel > 1` whenever the TTY source is selected. Acceptance: `-race`-clean parallel run of 8 keystores with a single prompt observed.

#### 6.1.4 Ledger hardware path (FR-P0-D, per product decision)

- **FR-P0-D1 (GO-055).** Upgrade `github.com/ethereum/go-ethereum` to `>= v1.17.0`. Re-run all package tests. Pin the version in `go.mod`.
- **FR-P0-D2 (GO-019).** `NewLedgerSigner` must wrap (`%w`) the underlying Open/Status error alongside (or replacing) `ErrNoDevice`. Distinguish "no device enumerated" from "device present but unavailable" via a new sentinel (`ErrDeviceUnavailable`). Both Open and Status branches must call `w.Close()` on failure.
- **FR-P0-D3 (GO-023).** `LedgerSigner.Sign` must compare the recovered sender against `s.account.Address` and reject on mismatch; must field-compare the returned tx (nonce/to/value/data/chainID/fees/gasLimit) against the requested one.
- **FR-P0-D4.** Add a `make e2e-ledger-testnet` target gated by `LEDGER_E2E=1` that runs a real device against hoodi. Make this part of the M0 release checklist (manually triggered, signed off by a maintainer).

#### 6.1.5 Toolchain, dependencies, CI gates (FR-P0-E)

- **FR-P0-E1 (GO-056).** Add `toolchain go1.26.4` (or the latest 1.26.x at release time) to `go.mod`. Pin `setup-go` in CI to the same minor version. Confirm `govulncheck` reports zero reachable stdlib hits.
- **FR-P0-E2 (GO-057).** Add `govulncheck ./...` to `make lint` and to both CI workflows. Triage policy: module-only (unreachable) hits may be suppressed via documented `vuln-exclude.yaml` entries with rationale and re-review date; symbol-reachable hits are release blockers.
- **FR-P0-E3 (GO-058).** Resolve every `errcheck` hit (assign `_ =` with comment, propagate the error, or refactor). Add `errcheck` to `make lint` and CI.

#### 6.1.6 Documentation and release hygiene (FR-P0-F)

- **FR-P0-F1 (GO-052, paired with GO-001).** Update `docs/USER-GUIDE.md` to show the new `0x01` credential example produced by `--withdrawal-address` and remove any reference to the v0.1 all-zero placeholder behavior.
- **FR-P0-F2.** Add a CHANGELOG.md entry for v0.2 documenting every breaking change (CLI flag adds, JSON validation tightening, exit-code unifications). Provide a `MIGRATION.md` for v0.1 → v0.2.

#### 6.1.7 Quality-catalogue items required for release hygiene (FR-P0-G)

- **FR-P0-G1.** Delete the "Issue 2.5" / "until a signer is wired" / "scaffolding" comments and the now-dead `BuildConfig.RPCURL` and `UnsignedTx.From` fields (FR-P0-B8). Keep `network.Params.DefaultRPCURL` only if assigned and read; otherwise delete.
- **FR-P0-G2.** Centralize the deposit amount in `internal/network` as a **range pair** `MinDepositAmountGwei = 32_000_000_000` / `MaxDepositAmountGwei` (per-credential-type: 32 ETH for 0x00/0x01; 2048 ETH for 0x02 per EIP-7251), used by all three packages. v0.2 only emits/accepts exactly 32 ETH (0x00/0x01), but the constant surface is shaped as a range now so the M2 EIP-7251 work (§11.4) is not a breaking refactor. *(Amended per research: ethstaker-deposit-cli + EIP-7251 findings.)*

---

### 6.2 P1 — Required for v1.0 (Mainnet-Ready, M1)

> The release bar for M1: every latent bug becomes a tested invariant; mainnet-specific safeguards are present and non-bypassable; the test suite contains externally-authoritative cross-checks; and the documentation matches the binary byte for byte.

#### 6.2.1 Mainnet-specific safeguards (FR-P1-A)

- **FR-P1-A1 (GO-013).** Add a mainnet acknowledgement gate to `eth-deposit-tx`. Acceptable design: a `--confirm-network=mainnet` flag whose value must equal the RPC-derived (and decoded-RLP) network name. `--yes` does NOT imply or bypass this flag on mainnet. Emit a warning when `--signer local` is combined with `--network mainnet` in `run`/`sign`; require an additional `--i-accept-local-signer-on-mainnet` to proceed. Acceptance: integration test asserts `--yes --network mainnet` without the confirm flag exits non-zero.
- **FR-P1-A2.** Add a release-gate test matrix that exercises every `--network` × `--signer` × air-gap-mode combination against a mainnet-shaped (mock) chain ID.

#### 6.2.2 Cancellation, concurrency, and resource hygiene (FR-P1-B)

- **FR-P1-B1 (GO-008).** Add a `workerCtx.Err()` check at the top of every worker-loop iteration (emit `context.Canceled` results so the collector receives one per item). Make `loader.Load` honour `ctx`: check before file read, before `pw.Read()`, and before `Decrypt`. Register SIGTERM and wire the `signal.NotifyContext` `stop()` to run once ctx is cancelled (so a second Ctrl+C force-terminates). Acceptance: SIGINT during a queued prompt aborts within 1s without re-prompting remaining workers.
- **FR-P1-B2 (GO-021).** Guard `LocalSigner.key` with `sync.Mutex` held across `Sign`'s use and `Close`'s zeroize. Acceptance: `-race` clean under concurrent Sign+Close.
- **FR-P1-B3 (GO-024).** Document that `LedgerSigner.Close` blocks until the device responds after cancellation; emit a stderr message "reject on device to unblock" when `ctx.Err() != nil` and Close has been called. Consider a bounded timeout on the wait, after which Close returns and the goroutine is leaked with an explicit warning.
- **FR-P1-B4 (GO-017).** Call `os.Unsetenv` after constructing local signers from env; zeroize the decode buffer `b`, the validation `big.Int`, and every per-`Sign` `ToECDSA` reconstruction. Add a `Destroy`/`Zeroize` method to the BLS signer that wipes all **Go-side** copies of the secret and call it from CLI exit paths. **Known limitation (documented, not fixable here):** herumi's C-side `mcl` scalar has no destroy API, so the secret persists in C-allocated memory until process exit — the requirement is honest documentation of this boundary, not full erasure. The reachable leak path (secret embedded in herumi errors) is closed separately by FR-P0-C1. Set a sanitized `cmd.Env` for the external `ethstaker-deposit-cli` child process. *(Amended per research: herumi API findings.)*

#### 6.2.3 BLS / SSZ / ABI correctness defense-in-depth (FR-P1-C)

- **FR-P1-C1 (GO-036).** `bls.NewSigner` must reject `s.sk.IsZero()` after Deserialize; alternatively use `GetSafePublicKey()`.
- **FR-P1-C2 (GO-037).** `bls.ValidatePubkeyBytes` must reject the point-at-infinity (`if hPub.IsZero() { return … }`), matching IETF `KeyValidate`.
- **FR-P1-C3 (GO-038).** Convert `DomainDeposit` and `ZeroGenesisValidatorsRoot` from exported package vars to functions returning the array by value, backed by unexported values. Audit `internal/deposit.NewGenerator` to consume the function values.
- **FR-P1-C4 (GO-048).** Replace the dead `computeDepositMessageRoot`/`computeDepositDataRoot` oracle with a genuinely differential implementation (e.g., a port of the Python reference or an alternative Go SSZ library). Remove the tautological fuzz assertions; replace with seed-anchored equality fuzzers.
- **FR-P1-C5 (GO-070).** Add an `accounts/abi`-based equality test that independently encodes the same args as `PackDeposit` and asserts byte equality.

#### 6.2.4 RPC client robustness (FR-P1-D)

> Per the M0 decision, the RPC path is rejected on `build`/`run`. M1 wires the hybrid mode (or finalizes its removal).

- **FR-P1-D1 (GO-032).** `BlockBaseFee` (rename to `BlockBaseFee` / fix doc to say "latest") must use `HeaderByNumber`, not `BlockByNumber`. Return an explicit error on nil `BaseFee`. Update the interface doc.
- **FR-P1-D2 (GO-033).** Fix the RPC chain-ID guard to fail closed on RPC error or chain-ID 0; actually emit a warning if "warn and continue" remains the behavior. Inject a logger.
- **FR-P1-D3 (GO-034).** Fix the `estimate*6/5` overflow to `estimate + estimate/5` with a documented ceiling; use `cfg.NetworkParams.DepositContractAddress` directly instead of hex round-trip.
- **FR-P1-D4 (GO-035).** Replace the `strings.Contains("not found")` substring match with `errors.Is(err, ethereum.NotFound)`. Retry transient errors until the deadline. Map receipt-phase failures to a documented exit code.
- **FR-P1-D5 (Hybrid mode decision).** Either wire `NewEthClient` into `BuildConfig.RPC` and re-enable `resolveRPC` (validated by integration tests), or permanently delete the path. Update docs accordingly.

#### 6.2.5 Keystore correctness (FR-P1-E)

- **FR-P1-E1 (GO-025).** Pre-validate the keystorev4 JSON shape; only the checksum mismatch maps to `ErrWrongPassphrase`. Structural errors map to `ErrKeystoreMalformed` and exit 2.
- **FR-P1-E2 (GO-028).** Inject the CLI logger into `ScanDir`; treat read errors as warnings (visible at `--verbose`) or hard errors as appropriate.
- **FR-P1-E3 (GO-029).** Enforce `len(secret) == 32` after decrypt; zeroize and return `ErrKeystoreMalformed` otherwise.
- **FR-P1-E4 (GO-030).** `ScanDir` must `e.Type().IsRegular()` (rejecting FIFOs/devices/symlinks); both `ScanDir` and `Load` must wrap reads in `io.LimitReader` with a documented cap (proposed: 1 MiB).

#### 6.2.6 CLI contract and exit codes (FR-P1-F)

- **FR-P1-F1 (GO-015).** Detect urfave/cli's `errRequiredFlags` (or pre-validate flags) and map to exit 2.
- **FR-P1-F2 (GO-020).** `parseUnsignedTx` must reject `value.Sign() < 0`, `maxFee.Sign() < 0`, `tip.Sign() < 0` with field-specific errors. Reject `unsigned.Type != "0x2"`.
- **FR-P1-F3 (GO-022).** `NewLocalSignerFromEnv` must wrap (`%w`) the specific validation error rather than discarding it.
- **FR-P1-F4 (GO-041).** When `--input -` reads from stdin, the confirmation prompt must read from `/dev/tty`. If no `/dev/tty` is available and `--yes` is not set, reject with exit 2.
- **FR-P1-F5 (GO-051).** `signUnsignedTx` switch must include a `default` that returns `ErrInvalidInput` (no nil-interface panic).
- **FR-P1-F6 (GO-018).** `runDepositCLIVerify` must check `ctx.Err()` and wrap the exec error with `%w` so SIGINT routes to exit 4, not 3.
- **FR-P1-F7 (GO-042).** Wrap `BroadcasterChainID`'s error with `%w` (not `%v`) so `errors.Is(err, context.Canceled)` survives.
- **FR-P1-F8 (GO-046).** Wrap every bare error return with operation context + `%w`: at least `ScanDir`, `runWithDeps`, `Generate`. Audit the entire module for `return err` lines and fix.

#### 6.2.7 Test independence and fixture hygiene (FR-P1-G)

- **FR-P1-G1 (GO-059).** Add an env/tag-gated integration test that runs a real `ethstaker-deposit-cli` against generated output for at least mainnet and hoodi. Make this part of the M1 release checklist.
- **FR-P1-G2 (GO-066).** `TestEntriesFromJSON_GoldenFile` must read from the actual fixture file or round-trip via the output writer; remove the hand-copied literal.
- **FR-P1-G3 (GO-045).** Have `Key.Zeroize` delegate to `zeroizeBytes`; correct the `runtime.KeepAlive` comment.

#### 6.2.8 Documentation accuracy (FR-P1-H)

- **FR-P1-H1 (GO-068).** Fix `docs/USER-GUIDE.md` troubleshooting rows to attribute errors to the correct layer (`internal/tx.Validate` vs `Entry.Validate`) and replace the misquoted `ErrChainIDMismatch` with the actual `ErrBroadcastChainIDMismatch` emitted by `send`.

---

### 6.3 P2 — M2 (v1.1) Hardening

> No release-blocker impact; addressed as code-quality and developer-ergonomics work. Group into a single hardening release.

- **FR-P2-A1 (GO-039).** Correct `NewApp` doc comment and the `cli_test.go:550-551` comment to state exit code 2.
- **FR-P2-A2 (GO-043).** Either actually copy the sentinel in the secret-leak test or correct the misleading comment.
- **FR-P2-A3 (GO-047).** Derive every per-network metadata access from a single package-level `map[Network]Params` table; remove the four-site duplication; make address parsing happen at `init()` so a typo panics at process start, not at first `Lookup`.
- **FR-P2-A4 (GO-050).** Either delete `ledger_nocgo.go` and the unreachable `ErrLedgerNotSupported` path, or break the `signer→bls` dependency so a real `CGO_ENABLED=0` build succeeds; add a CI matrix for it.
- **FR-P2-A5 (GO-060).** Update `scripts/e2e-testnet.sh` "NEXT STEP" to point at `docs/USER-GUIDE.md`.
- **FR-P2-A6 (GO-061).** `merkleize` must guard `len(chunks) <= limit` (panic as a programmer error) or drop the parameter.
- **FR-P2-A7 (GO-062).** bls/ssz hygiene: fix the `Sign` doc-param name, normalize error casing, remove the `bls`-inside-`package bls` alias, prune the historical ssz package comment.
- **FR-P2-A8 (GO-063).** Extract `runtime.NumCPU() * parallelismMultiplier` into a single named constant.
- **FR-P2-A9 (GO-064).** Prefix the documented fixture-regen command with `GENERATE_FIXTURES=1`.
- **FR-P2-A10 (GO-065).** Regenerate keystore test fixtures with valid 96-char BLS pubkeys; remove the "realistic" mislabel.
- **FR-P2-A11 (GO-067).** Correct the stale APDU 6d00 comment; delete the tautological `TestFakeSignerName`/`TestFakeSignerSign` tests (keep the interface compile-time assertion).
- **FR-P2-A12 (GO-069).** Make `DEPOSIT_DATA_FILE` default and header comment consistent in `scripts/e2e-testnet.sh`.
- **FR-P2-A13 (GO-071).** `go get golang.org/x/crypto@latest && go mod tidy`. Re-run `govulncheck`.
- **FR-P2-A14 (Quality catalogue, dead/speculative code).** Delete `padRight` (test-only), the `tx.TxBuilder` consumer-less interface, the fake "compile-time assertions" in `run.go:355-356`, and the `EntryFromJSON` exported function if M0 work confirms it has no callers. Remove `deposit.Request.Pubkeys` if the batch path remains unused.
- **FR-P2-A15 (Quality catalogue, duplication).** Unify `jsonEntry` between `internal/deposit/json.go` and `internal/output/output.go`. Unify the build flag list between `buildCommand` and `buildFlags()`. De-duplicate signer/env-var validation between `LoadSignConfig` and `LoadRunConfig`.
- **FR-P2-A16 (Quality catalogue, conventions).** Resolve duplicate package doc comments (`cmd/eth-deposit-tx/exit.go` + `main.go`; `internal/deposit/json.go` + `deposit.go`). Add doc comments to all exported sentinels and a package comment to `internal/tx`. Replace `%v`-flattened error wrapping in `internal/tx/rpc_client.go` with `%w`. Move `runWithDeps`'s orchestration out of `package main` into `internal/cli` (or similar) to honor the thin-main convention.

---

## 7. Non-Functional Requirements

### 7.1 Security

- **No secret material in errors, logs, or artifacts.** Every error string emitted from any package, every artifact written to disk, and every shell-script output must be auditable for non-leakage. Enforce via regression tests (one per leakage class: BLS secret, secp256k1 secret, keystore passphrase, RPC API key).
- **No fund-loss path that lacks at least two independent validators.** GO-001 (one validator, missing) and GO-002 (zero validators, missing) are the archetypes. After M0, every operation that can lock funds must be gated by at least two checks at different layers (CLI flag validation + `internal/deposit` invariant + `internal/tx` invariant).
- **Verify-before-write extended to the tx pipeline.** `internal/tx.Build` (and `sign`) re-verify the deposit-data integrity (SSZ roots + BLS signature) just as `internal/deposit.Generate` does on the gen side.
- **No silent fallback on RPC-resolved values.** A nil/zero/error response from any RPC method must abort with a documented sentinel; no path silently substitutes `0` or a hardcoded default.

### 7.2 Reliability & Safety

- **CLI contract.** Documented exit codes 0–5 (and any new code added) are part of the public contract. Cross-validated by a `TestExitCodeContract` table that maps every sentinel error to its exit code.
- **Atomic writes everywhere.** Every artifact write (`build`, `sign`, `run`, `send`, deposit-data files, receipts) goes through the temp+`O_EXCL`+rename+`fsync` helper.
- **Cancellation honored within 1s.** Ctrl+C (SIGINT) and SIGTERM must propagate to all goroutines within 1 second; a second Ctrl+C must force-terminate.
- **Reproducible builds.** `go build -trimpath -buildvcs=true` and the pinned `toolchain` directive produce byte-identical binaries for a given commit.

### 7.3 Performance

- The 71 findings impose negligible perf cost; no metric regresses by more than 5% (measured by a baseline microbench of `deposit.Generate`, `ssz.HashTreeRoot`, and `PackDeposit`).
- The `--parallel` worker pool retains its scaling characteristics after the cancellation fixes (no per-iteration mutex contention measurable above noise).

### 7.4 Observability

- A `--verbose`/`--json-logs` operator must see every keystore-skip, every duplicate-pubkey rejection, every RPC chain-ID mismatch, and every cancellation event. No diagnostic goes to the never-configured global `slog` default.
- Sentinel errors are `errors.Is`-matchable and `errors.As`-typed; `%w` wrapping is mandatory for all returned errors.

### 7.5 Compatibility & Portability

- Linux x86_64 and macOS arm64/x86_64 are supported. Windows is not supported (no change from v0.1).
- CGO required (`CGO_ENABLED=1`). The `!cgo` build tag in `internal/signer/ledger_nocgo.go` is either fixed (FR-P2-A4) or removed; no false promise of CGO-free builds remains.
- Go toolchain: `>= 1.26.4`. Pinned via `toolchain` directive.

### 7.6 Maintainability

- `make lint` (vet + staticcheck + errcheck + gofmt + govulncheck) gates every PR and main-branch merge.
- No "tested only against ourselves" assertion on a funds-critical invariant. Differential SSZ oracle, `accounts/abi` cross-check for `PackDeposit`, and `ethstaker-deposit-cli` external authority must all exist and run in CI.

### 7.7 Accessibility / Internationalization

- N/A (developer CLI tool). Error messages remain in English.

---

## 8. Technical Considerations

### 8.1 Architecture preserved

The existing architecture — two CLIs sharing `internal/` packages, BLS validator key vs secp256k1 sender key never meeting, `internal/network` as constants source-of-truth, verify-before-write in `internal/deposit`, sentinel-error exit-code contracts — is sound and is the foundation for these fixes. We do not redesign; we tighten trust boundaries and remove silent fallbacks.

### 8.2 New invariants enforced at module boundaries

- `internal/deposit.Entry`: gains `ValidateForNetwork(target network.Params)` returning a wrapped sentinel; `Validate()` recomputes both SSZ roots and BLS-verifies the signature against the entry's stated network's deposit domain. (FR-P0-A3, FR-P0-A4.)
- `internal/tx.Validate`: gains the credential-shape checks (FR-P0-A2) and a `ValidateAgainstNetwork(target)` for the destination address (FR-P0-A5).
- `cmd/eth-deposit-tx/send.go`: gains a `validateSignedAgainstRLP(signed)` pre-prompt step that decodes the RLP and asserts equality. (FR-P0-A6.)

### 8.3 Breaking changes (CLI / JSON artifacts)

Per the product decision, v0.2 is a breaking release. The breaks are concentrated and documented:

- **New required flag:** `--withdrawal-address` on `eth-deposit-gen` (FR-P0-A1; v0.2 is `0x01`-only per the plan-gate decision).
- **New required flag for build/run without RPC:** `--nonce` and fee flags (FR-P0-B8).
- **Validation tightening on deposit_data JSON:** entries with all-zero `0x00` credentials or fork_version mismatching the target network are now rejected (FR-P0-A2/A3).
- **Exit-code unifications:** `build`/`sign` adopt `run`/`send` mappings; reverted on-chain deposits return non-zero (FR-P0-B2, FR-P0-B9, FR-P1-F1).
- **JSON schema (additive only at first):** the M1 mainnet ack gate may add a `--confirm-network` flag but does not change the artifact schema. We reserve the option to add `tx_metadata.decoded_*` fields to `signed.json` for future versions but do not in v0.2.
- **Mode removal:** `--rpc-url` is rejected on `build`/`run` in v0.2 (FR-P0-B8); v1.0 either wires it or permanently removes it (FR-P1-D5).

A `MIGRATION.md` and a CHANGELOG entry document every break (FR-P0-F2).

### 8.4 Dependencies

- `github.com/ethereum/go-ethereum`: bump to `>= v1.17.0` (FR-P0-D1, GO-055).
- Go toolchain: pin `toolchain go1.26.4` (FR-P0-E1, GO-056).
- `golang.org/x/crypto`: bump to latest (FR-P2-A13, GO-071).
- New build-time deps: `govulncheck` (FR-P0-E2), `errcheck` (FR-P0-E3). Both run as `go run` from `tools/tools.go`.
- New optional integration test dep: `ethstaker-deposit-cli` (FR-P1-G1) installed via tagged CI workflow.

### 8.5 Test plan

- Every P0 requirement comes with at least one regression test (table-driven where applicable). Acceptance lines are inlined in §6 above.
- Re-derive every golden fixture under `testdata/` (`make refresh-golden`) after FR-P0-A1 lands; commit the regeneration in a single PR.
- Add `make e2e-testnet` (real RPC) and `make e2e-ledger-testnet` (real device) targets to the M0 release checklist.
- Add `make test-cross-validate` (real `ethstaker-deposit-cli`) to the M1 release checklist.

### 8.6 Tooling and CI

- `make lint` becomes: `gofmt -l .`, `go vet`, `staticcheck`, `errcheck`, `govulncheck`.
- `golangci-lint` configured with the above + the existing settings; intentional suppressions (e.g., SA1012) remain with comments.
- CI workflow gains:
  - `lint` job (M0).
  - `test-race` job (M0; existing `-race` tests gain the GO-007 / GO-021 cases).
  - `e2e-testnet` job, gated on the presence of `RPC_URL`/`ETH_DEPOSIT_TX_PRIVATE_KEY` secrets (M0).
  - `e2e-ledger-testnet` job, manually triggered (M0).
  - `cross-validate-deposit-cli` job, tagged (M1).
  - `vuln-scan` job running `govulncheck` weekly on `develop` so staleness does not re-accumulate (M0).

---

## 9. UX / Design Notes

- **Mainnet acknowledgement gate (FR-P1-A1).** Two acceptable shapes. We prefer **(a)** an explicit `--confirm-network=<name>` whose value must equal the RPC-derived (and decoded-RLP) network name, both compared in `send`. The phrase the operator types is the network name they intend to broadcast on; `--yes` does not satisfy it. **(b)** Refuse `--yes` on mainnet entirely. We pick (a) for automation friendliness; document in the release notes.
- **Local-signer warning on mainnet.** When `--signer local` is paired with `--network mainnet`, print a multi-line warning describing the risk and require `--i-accept-local-signer-on-mainnet`. This mirrors the `--i-understand-this-is-mainnet` gate already present on `eth-deposit-gen`.
- **Signing summary on `sign` (FR-P0-A5).** Before the LocalSigner's actual `SignTx`, print a four-line summary (chainID, to, value, nonce) to stderr. This narrows the GO-003 gap for operators who use `sign` from a script.
- **`send` confirmation prompt (FR-P0-A6).** The prompt now shows the values decoded from `rawRLP`, not the JSON metadata. Label the values "(decoded from RLP)" so the operator can tell from the screen which source they are seeing.
- **Error redaction.** Standardize on a `redact(s, prefixLen)` helper in `internal/cli` so every redacted error (private-key value, API-key URL, BLS secret) uses the same format ("rejected: `<4-char-prefix>…` (len=N)").

---

## 10. Out of Scope (Non-Goals)

- **Multi-network expansion.** Adding new networks beyond the existing supported set is out of scope. (The `internal/network` consolidation in FR-P2-A3 makes future additions a one-line change.)
- **A wallet manager UI.** The toolchain remains CLI-only.
- **Validator key generation.** `eth-deposit-gen` only converts EIP-2335 keystores; we do not introduce mnemonic-to-key derivation here.
- **Custom withdrawal-credential prefixes (0x02 EIP-7251).** v0.2 supports `0x00` and `0x01`. `0x02` (compounding validators per EIP-7251) is a candidate for v1.1 (M2) and is tracked in §11.
- **A formal verification effort on SSZ/BLS.** We add a *differential* SSZ oracle and an `accounts/abi` cross-check, but we do not pursue Coq/Lean proofs.
- **Windows support.** Out of scope for v0.2 and v1.0.
- **A network-time / slot-timing safety gate.** Out of scope; deposits are slot-insensitive.
- **Refactor to a single `cobra` CLI.** We stay on `urfave/cli` v2.

---

## 11. Open Questions

The product-level decisions below are not blocking M0 planning but should be resolved before implementation.

1. **Withdrawal credential prefix coverage.** ~~Should v0.2 support `--withdrawal-bls-pubkey` (0x00 with a real BLS pubkey) at all, or restrict to `--withdrawal-address` (0x01)?~~ **RESOLVED (user decision at plan gate, 2026-06-07): `0x01` `--withdrawal-address` only in v0.2.** 0x00 BLS-withdrawal support is out of scope; 0x00/0x02 are vNext candidates.
2. **New exit code for receipt-poll-timeout (FR-P0-B2).** ~~Reuse code 5 ("broadcast error") with a sentinel discriminator, or introduce code 6 ("receipt unavailable")?~~ **RESOLVED (user decision at plan gate, 2026-06-07): reuse code 5 with a sentinel discriminator** (per project-plan D10); revisit code 6 in M1 only if automation demands it.
3. **Hybrid `--rpc-url` future (FR-P1-D5).** Wire fully on `run` only, or wire on both `build` and `run`, or permanently delete? The air-gap workflow benefits from `build` remaining strictly offline; recommend wiring on `run` only and removing from `build`.
4. **EIP-7251 (`0x02` compounding) timeline.** Track as v1.1 (M2) item or defer to a vNext PRD? This PRD assumes the latter.
5. **Compatibility of the new `Entry.Validate` with third-party readers.** External tooling that consumes our `deposit_data-*.json` does not enforce SSZ-root recomputation. We do not change the schema; this is a tightening of *our* reader. No action expected, but flagging for ecosystem awareness.

---

## 12. Milestones & Phases

### Milestone M0 — v0.2 "Hoodi-Trustworthy" (testnet-ready first)

Closes: all P0 requirements (§6.1). Concretely: GO-001, GO-002, GO-003, GO-004, GO-005, GO-006, GO-007, GO-009, GO-010, GO-011, GO-012, GO-014, GO-016, GO-019, GO-023, GO-026, GO-027, GO-031, GO-040, GO-044, GO-049, GO-052, GO-053, GO-054 (via GO-005 fix), GO-055, GO-056, GO-057, GO-058 + the FR-P0-G quality-catalogue items.

**Exit criteria:**
- All P0 acceptance tests green (CI).
- `make e2e-testnet` passing against a real hoodi RPC, with zero secrets in any artifact.
- `make e2e-ledger-testnet` signed off by a maintainer against a current-firmware Ledger.
- `govulncheck`, `gofmt`, `errcheck` clean.
- `CHANGELOG.md` v0.2 entry + `MIGRATION.md` published.
- Tagged release v0.2.0 with prebuilt binaries (linux-amd64, darwin-arm64, darwin-amd64).

### Milestone M1 — v1.0 "Mainnet-Ready"

Closes: all P1 requirements (§6.2). Adds the mainnet ack gate, mops up all latent bugs as tested invariants, adds external-authority test cross-checks, and fixes documentation accuracy.

**Exit criteria:**
- All P1 acceptance tests green.
- `make test-cross-validate` (real `ethstaker-deposit-cli`) passing in CI for every supported network.
- Mainnet ack gate integration test green (`--yes --network mainnet` without `--confirm-network=mainnet` exits non-zero).
- A maintainer-led dry-run of a real mainnet ceremony on a held-out test wallet (or a recorded `dryrun` mode if available) completes without warning.
- Tagged release v1.0.0.

### Milestone M2 — v1.1 Hardening (no release blocker)

Closes: all P2 requirements (§6.3) plus the quality catalogue.

**Exit criteria:**
- Module CR-clean: no dead code, no duplication of constants/structs across packages, no `%v`-wrapped errors, no missing doc comments on exported identifiers.
- `internal/network` reduced to a single source table.
- Optionally: EIP-7251 `0x02` withdrawal credential support if the upstream spec is settled by then.

---

## 13. Risks & Mitigations

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Breaking changes (FR-P0-A1, FR-P0-B8) surprise existing v0.1 users; broken scripts in production | Medium | Medium | `MIGRATION.md`; CHANGELOG; v0.2.0 release notes prominently flag breaks; v0.1.x branch kept available for back-compat for one cycle |
| R2 | `go-ethereum` v1.17.0 bump (FR-P0-D1) breaks `usbwallet`/`ethclient` API call sites | Medium | Medium | Stage the bump on a feature branch; run full test suite incl. `-race`; manual Ledger E2E gate; pin to the specific minor that compiles cleanly |
| R3 | Real-device Ledger E2E (FR-P0-D4) flaky in CI; gates M0 release | Medium | Low | Keep the gate manual (maintainer sign-off, not CI auto-merge); document the firmware versions tested |
| R4 | New `Entry.Validate` (FR-P0-A4) rejects pre-v0.2 valid deposit-data JSONs operators have on disk | Low | Medium | Provide a one-shot `eth-deposit-tx revalidate <file>` subcommand (or doc snippet) that re-derives the missing fields; ship in v0.2 |
| R5 | `govulncheck` adds reachable hits between PR and merge, blocking unrelated work | Medium | Low | Allow documented suppressions (FR-P0-E2 triage policy); rerun weekly on `develop` so flakes are caught between PRs |
| R6 | Differential SSZ oracle (FR-P1-C4) disagrees with our implementation on a corner case the consensus spec also handles ambiguously | Low | Medium | Re-derive both against the Python `ethstaker-deposit-cli` and the consensus-spec Python reference; treat any disagreement as a bug in *our* implementation by default |
| R7 | Withdrawal-credential UX (FR-P0-A1) confuses operators between 0x00 and 0x01 prefixes | Medium | High | Strong UI: print "Withdrawal target: 0x01 → address `<address>`" before any signing; require explicit `--withdrawal-prefix` if both flags are given; clear documentation with worked examples |
| R8 | Atomic write reverts (FR-P0-B3, FR-P0-B9) cause test flakes on macOS where `fsync` semantics differ | Low | Low | Run M0 CI on both Linux and macOS; accept best-effort `fsync` of the directory with documented platform note |
| R9 | Mainnet ack gate (FR-P1-A1) is socially-engineered around — operators type the literal `mainnet` into automation regardless | Medium | Medium | Pair the gate with a printed warning summarizing the destination, value, and a checksum of the signed.json; require human-readable summary in the prompt |
| R10 | Removing dead `--rpc-url` support (FR-P0-B8) surprises operators who believed the help text and were running unreliably | High | Low | The error message must point at the new `--nonce`/fees flow with a concrete example; document in MIGRATION.md |

---

## 14. Appendix — Finding → Requirement Map

| Finding | Severity | Priority | Requirement | Milestone |
|---|---|---|---|---|
| GO-001 | Critical | P0 | FR-P0-A1, FR-P0-A2 | M0 |
| GO-002 | Critical | P0 | FR-P0-A3 | M0 |
| GO-003 | High | P0 | FR-P0-A5 | M0 |
| GO-004 | High | P0 | FR-P0-A6 | M0 |
| GO-005 | Medium | P0 | FR-P0-B8 | M0 |
| GO-006 | Medium | P0 | FR-P0-C1 | M0 |
| GO-007 | Medium | P0 | FR-P0-C5 | M0 |
| GO-008 | Medium | P1 | FR-P1-B1 | M1 |
| GO-009 | Medium | P0 | FR-P0-B1 | M0 |
| GO-010 | Medium | P0 | FR-P0-B2 | M0 |
| GO-011 | Medium | P0 | FR-P0-B3 | M0 |
| GO-012 | Medium | P0 | FR-P0-A4 | M0 |
| GO-013 | Medium | P1 | FR-P1-A1 | M1 |
| GO-014 | Medium | P0 | FR-P0-C2 | M0 |
| GO-015 | Low | P1 | FR-P1-F1 | M1 |
| GO-016 | Low | P0 | FR-P0-B9 | M0 |
| GO-017 | Low | P1 | FR-P1-B4 | M1 |
| GO-018 | Low | P1 | FR-P1-F6 | M1 |
| GO-019 | Low | P0 | FR-P0-D2 | M0 |
| GO-020 | Low | P1 | FR-P1-F2 | M1 |
| GO-021 | Low | P1 | FR-P1-B2 | M1 |
| GO-022 | Low | P1 | FR-P1-F3 | M1 |
| GO-023 | Low | P0 | FR-P0-D3 | M0 |
| GO-024 | Low | P1 | FR-P1-B3 | M1 |
| GO-025 | Low | P1 | FR-P1-E1 | M1 |
| GO-026 | Low | P0 | FR-P0-B5 | M0 |
| GO-027 | Low | P0 | FR-P0-B4 | M0 |
| GO-028 | Low | P1 | FR-P1-E2 | M1 |
| GO-029 | Low | P1 | FR-P1-E3 | M1 |
| GO-030 | Low | P1 | FR-P1-E4 | M1 |
| GO-031 | Low | P0 | FR-P0-B7 | M0 |
| GO-032 | Low | P1 | FR-P1-D1 | M1 |
| GO-033 | Low | P1 | FR-P1-D2 | M1 |
| GO-034 | Low | P1 | FR-P1-D3 | M1 |
| GO-035 | Low | P1 | FR-P1-D4 | M1 |
| GO-036 | Low | P1 | FR-P1-C1 | M1 |
| GO-037 | Low | P1 | FR-P1-C2 | M1 |
| GO-038 | Low | P1 | FR-P1-C3 | M1 |
| GO-039 | Low | P2 | FR-P2-A1 | M2 |
| GO-040 | Low | P0 | FR-P0-B6 | M0 |
| GO-041 | Low | P1 | FR-P1-F4 | M1 |
| GO-042 | Low | P1 | FR-P1-F7 | M1 |
| GO-043 | Low | P2 | FR-P2-A2 | M2 |
| GO-044 | Low | P0 | FR-P0-B10 | M0 |
| GO-045 | Low | P1 | FR-P1-G3 | M1 |
| GO-046 | Low | P1 | FR-P1-F8 | M1 |
| GO-047 | Low | P2 | FR-P2-A3 | M2 |
| GO-048 | Low | P1 | FR-P1-C4 | M1 |
| GO-049 | Low | P0 | FR-P0-C3 | M0 |
| GO-050 | Low | P2 | FR-P2-A4 | M2 |
| GO-051 | Low | P1 | FR-P1-F5 | M1 |
| GO-052 | Low | P0 | FR-P0-F1 | M0 |
| GO-053 | Low | P0 | FR-P0-C4 | M0 |
| GO-054 | Low | P0 | (subsumed by FR-P0-B8) | M0 |
| GO-055 | Low | P0 | FR-P0-D1 | M0 |
| GO-056 | Low | P0 | FR-P0-E1 | M0 |
| GO-057 | Low | P0 | FR-P0-E2 | M0 |
| GO-058 | Low | P0 | FR-P0-E3 | M0 |
| GO-059 | Low | P1 | FR-P1-G1 | M1 |
| GO-060 | Low | P2 | FR-P2-A5 | M2 |
| GO-061 | Info | P2 | FR-P2-A6 | M2 |
| GO-062 | Info | P2 | FR-P2-A7 | M2 |
| GO-063 | Info | P2 | FR-P2-A8 | M2 |
| GO-064 | Info | P2 | FR-P2-A9 | M2 |
| GO-065 | Info | P2 | FR-P2-A10 | M2 |
| GO-066 | Info | P1 | FR-P1-G2 | M1 |
| GO-067 | Info | P2 | FR-P2-A11 | M2 |
| GO-068 | Info | P1 | FR-P1-H1 | M1 |
| GO-069 | Info | P2 | FR-P2-A12 | M2 |
| GO-070 | Info | P1 | FR-P1-C5 | M1 |
| GO-071 | Info | P2 | FR-P2-A13 | M2 |
| Quality catalogue (unnumbered) | Info | P0/P2 | FR-P0-G1/G2, FR-P2-A14/A15/A16 | M0/M2 |

**Coverage summary:** 71/71 numbered findings mapped; unnumbered quality catalogue split across FR-P0-G (release-hygiene items) and FR-P2-A14/A15/A16 (post-mainnet cleanup). Critical + High (GO-001..GO-004) are 4/4 in M0; Medium 10/10 are 9 in M0 + 1 in M1 (GO-013 is mainnet-specific); Low 46/46 distributed; Info 11/11 distributed.

---

## 15. Review & Sign-off

This PRD is a draft pending team-lead review. Open Questions §11 (1-5) and product decisions captured in §6.1.4 (Ledger M0 inclusion), §6.1 (breaking changes accepted), and §6.1.2 (FR-P0-B8 reject-rather-than-wire) reflect explicit prior decisions and should be confirmed at sign-off rather than re-litigated.
