# Project Plan: `eth-utils/go` Remediation — Path to v0.2 / v1.0 / v1.1

**Author:** project-planner (team dev-plan)
**Date:** 2026-06-07
**Status:** Draft v1 (pending team-lead review)
**Inputs:**
- `go/plan/prd.md` — approved amended PRD (FR-P0-A..G, FR-P1-A..H, FR-P2; finding→requirement map §14)
- `go/plan/architecture.md` — approved architecture (module change map §6, trust boundaries §7, phase alignment §14, interface contracts §15, ADRs §20)
- `go/plan/research/SUMMARY.md` — feasibility verdicts + sequencing recommendation
- `go/plan/REVIEW.md` — source findings GO-001..GO-071

---

## Summary

This plan sequences remediation of all 71 adversarial-review findings across the three locked
milestones (M0 v0.2 "Hoodi-Trustworthy", M1 v1.0 "Mainnet-Ready", M2 v1.1 Hardening). The
default execution model is a **single code-writer working sequentially**; phases are sized at
3–10 issues each so they are coherent units of work but small enough that future parallelization
along the documented dependency edges is straightforward.

The sequencing honors four invariants the team-lead locked in:

1. **CI/toolchain gates land first** so every subsequent fix is built/tested under the gates.
2. **The `go-ethereum` v1.17.x bump lands early** because every signer/tx fix depends on the new
   API surface.
3. **Golden-fixture regeneration happens exactly once** after all output-affecting M0 changes are
   in — GO-001's required `--withdrawal-address` flag changes every committed fixture.
4. **Breaking changes batch into the v0.2 release**, documented in CHANGELOG.md + MIGRATION.md.

M0 has 11 phases ending in the v0.2 tag. M1 has 9 phases ending in the v1.0 tag. M2 has 4 phases
ending in the v1.1 tag. The critical path through M0 is roughly linear; M1 has more parallelization
slack but the mainnet-acknowledgement gate is the release blocker.

---

## Prerequisites

Before any phase starts:

- **PRD + architecture signed off** by team-lead (this plan assumes the amended PRD and approved
  ADRs 001–007 are in force).
- **Repository access:** a clean working tree on `develop`; tag protections on `main` understood.
- **Tooling:** local `go1.26.4` (the toolchain directive landed in Phase M0.1 will auto-download
  if older); CGO toolchain (`gcc`/`clang`) available; `make` available.
- **CI secrets configured** for E2E paths: `RPC_URL` (hoodi testnet) and
  `ETH_DEPOSIT_TX_PRIVATE_KEY` (testnet sender key holding ≥0.1 ETH on hoodi).
- **Hardware available** for M0.11 manual Ledger E2E: at least one Ledger Nano S Plus, Nano X,
  or Flex with current firmware and the Ethereum app installed.
- **Open Questions §11 of the PRD resolved:** withdrawal credential prefix coverage (Q1),
  receipt-timeout exit code (Q2), and hybrid `--rpc-url` future (Q3). Architecture ADR-004
  already encodes the recommended Q3 answer (wire on `run` only in M1); Q1 and Q2 remain for
  team-lead sign-off and are flagged in Open Questions below.
- **External CI image:** Dockerfile baking `ethstaker-deposit-cli==<pinned>` (M1 prerequisite —
  research/01 §R2; can be prepared during M0 to reduce M1 startup time).

---

## Milestone M0 — v0.2 "Hoodi-Trustworthy"

**Objective:** Close every P0 finding (§6.1 of PRD). Produce a tagged v0.2.0 release whose hoodi
E2E walk-through any maintainer would be willing to repeat against mainnet given only an
additional acknowledgement gate.

**Closes findings:** GO-001, GO-002, GO-003, GO-004, GO-005, GO-006, GO-007, GO-009, GO-010,
GO-011, GO-012, GO-014, GO-016, GO-019, GO-023, GO-026, GO-027, GO-031, GO-040, GO-044, GO-049,
GO-052, GO-053, GO-054 (transitive via GO-005), GO-055, GO-056, GO-057, GO-058, plus the
FR-P0-G quality-catalogue items.

---

### Phase M0.1 — Toolchain, CI & Lint Gates Foundation

**Goal:** Land the gating infrastructure (toolchain pin, govulncheck, errcheck, gofmt, weekly
vuln scan, `-race` lane) before any code change so every subsequent PR is built/tested under
the new gates and regressions are caught at first occurrence.

**Scope:**
- FR-P0-B10 (GO-044): `gofmt -w .` once; `gofmt -l` gate added.
- FR-P0-E1 (GO-056): `toolchain go1.26.4` in `go.mod`; CI `setup-go` pinned to same version
  (research/07 §Pitfall 1 — `govulncheck` reads PATH `go`, not the directive).
- FR-P0-E2 (GO-057): `govulncheck ./...` in `make lint` + CI; weekly `vuln-scan` cron on
  `develop`; triage policy doc (architecture §12.5; `docs/SECURITY.md` new).
- FR-P0-E3 (GO-058): `errcheck ./...` in `make lint` + CI; resolve all current errcheck hits
  with `_ =` + comment, propagate, or refactor.
- Add `tools/tools.go` with build tag `tools` (architecture §12.2).
- Add CI `test-race` job (existing `-race` partial; this gives it a permanent home).
- ADR-001 prep: stub `internal/atomicio` package directory exists but empty (consumed in M0.3).

**Entry dependencies:** Prerequisites complete.

**Exit criteria (verifiable):**
- `make lint` runs gofmt + go vet + staticcheck + errcheck + govulncheck and passes locally.
- CI `lint` job green on a fresh PR.
- CI `vuln-scan` weekly job scheduled and visible in Actions UI.
- CI `test-race` job green.
- `go.mod` shows `toolchain go1.26.4`; `go env GOVERSION` matches.
- `gofmt -l .` produces no output.
- `docs/SECURITY.md` published with vuln suppression policy.

**Deliverable artifacts:**
- `Makefile` updated lint target.
- `tools/tools.go`.
- `.github/workflows/lint.yml`, `.github/workflows/test-race.yml`, `.github/workflows/vuln-scan.yml`.
- `docs/SECURITY.md`.
- One PR per concern minimum; final merge into `develop`.

**Critical path:** YES — blocks every subsequent phase (gates the merge).

---

### Phase M0.2 — `go-ethereum` v1.17.x Upgrade & Ledger Bring-up

**Goal:** Land the geth dependency bump so all M0.5–M0.7 work (signer, tx, RPC client) is
written against the v1.17.x API surface; close the two Ledger M0 findings while the package
is in active edit.

**Scope:**
- FR-P0-D1 (GO-055): bump `github.com/ethereum/go-ethereum` to `>= v1.17.0`; pin exact patch in
  `go.mod`; re-run full test suite; resolve any compile breakage in `internal/tx`,
  `internal/signer`, `cmd/eth-deposit-tx`.
- FR-P0-D2 (GO-019): `NewLedgerSigner` wraps Open/Status real cause; new sentinel
  `ErrDeviceUnavailable` distinguishes "no device" from "device present but unavailable"; both
  branches `w.Close()` on failure.
- FR-P0-D3 (GO-023): `LedgerSigner.Sign` cross-checks recovered sender against
  `s.account.Address`; new sentinel `ErrSenderMismatch`; field-compare returned tx vs requested.

**Entry dependencies:** M0.1 (lint gates must be in place before geth's larger surface area is
audited).

**Exit criteria:**
- `go.mod` shows pinned geth `v1.17.x`.
- `go build ./...` and `go test ./...` (including `-race`) pass.
- Unit tests added for new sentinels (`ErrDeviceUnavailable`, `ErrSenderMismatch`) using a fake
  HID wallet harness.
- `govulncheck` re-run: no new reachable hits introduced by the bump.
- Exit-code map (architecture §15) updated to include `ErrDeviceUnavailable` (exit 3) and
  `ErrSenderMismatch` (exit 3).

**Deliverable artifacts:**
- One PR with the geth bump + compile fixes (no behavior change beyond Ledger sentinels).
- One PR adding the Ledger sentinel work + unit tests.
- Updated `internal/signer/errors.go` with sentinel exports.

**Critical path:** YES — blocks every downstream signer/tx/RPC change.

---

### Phase M0.3 — `internal/atomicio` Foundation Package

**Goal:** Ship the new atomic-write helper (ADR-001) so the five M0 write call sites converge
on a single tested implementation. Closing GO-011 and the prereqs for GO-016 here means later
phases ("delete the local helper", "make `os.WriteFile` atomic") are mechanical refactors.

**Scope:**
- Create `internal/atomicio` package per architecture §6.5 and §15.
- Implement `WriteFile(path, data, perm)` and
  `WriteFileWithSuffix(dir, prefix, ext, data, perm, now)`.
- Implement sentinels `ErrClobber`, `ErrTempCreate`, `ErrSync`, `ErrRename`.
- Filename scheme: `<prefix>-<UTC RFC3339Nano>-<sha256[:4hex]>.<ext>` (research/06 §A).
- Stress test: parallel-write stress test producing N > 1000 files in the same second with no
  overwrite (FR-P0-B3 acceptance).
- Cross-platform `fsync(dir)` (best-effort on macOS, documented).

**Entry dependencies:** M0.1 (lint gates).

**Exit criteria:**
- `go test ./internal/atomicio/... -race -count=10` passes.
- Parallel-write stress test produces 1024 unique deposit-data filenames with no clobber.
- `ErrClobber` returned when target final path exists (no-clobber acceptance).
- Public API matches architecture §15.

**Deliverable artifacts:**
- `internal/atomicio/atomicio.go`, `internal/atomicio/atomicio_test.go`, stress test.

**Critical path:** YES — consumed by M0.4 (`internal/output`), M0.7 (build/sign/run/send),
and golden refresh (M0.10).

---

### Phase M0.4 — Trust Boundary 1: Withdrawal-Credential Input + `Redact` helper

**Goal:** Close GO-001 (the critical fund-loss bug) by removing `defaultWithdrawalCreds()` and
making the withdrawal-credential input boundary enforced at two layers (CLI flag + `Entry.Validate`
DiD). Ship the shared `Redact` helper as part of this phase because every downstream secret-leak
fix consumes it.

**Scope:**
- FR-P0-A1 (GO-001): add required `--withdrawal-address` (EIP-55, 20-byte) flag to
  `eth-deposit-gen` (v0.2 is 0x01-only per the plan-gate decision — no
  `--withdrawal-bls-pubkey`); derive 32-byte credential per FR-P0-A1.
- FR-P0-A2 (GO-001 DiD): `internal/deposit.Entry.Validate` rejects 0x00 WC with all-zero body
  (`ErrZeroWithdrawal00`); rejects 0x01/0x02 with non-zero bytes 1..11 (`ErrInvalidWCFormat`);
  rejects all other prefixes.
- FR-P0-G1 (subset): delete `defaultWithdrawalCreds()` (`main.go:66-70`).
- FR-P0-G2: add `MinDepositAmountGwei`/`MaxDepositAmountGwei` range constants in
  `internal/network` (ADR-005).
- FR-P0-A2 DiD in `internal/tx.Validate`: mirror WC-shape checks (`tx.ErrZeroWithdrawal00`,
  `tx.ErrInvalidWCFormat`).
- `internal/cli.Redact(s, prefixLen)` helper (architecture §8.1, §10) — consumed in M0.6, M0.8.
- `requireNoArgs` helper in `internal/cli` (used in M0.7 for FR-P0-B6).
- New lint guard `make assert-no-zero-wc` rejecting committed JSON containing 64 zero hex chars
  in any `withdrawal_credentials` field (active from M0.10 onward).

**Entry dependencies:** M0.1 (lint), M0.3 (range constants live in `internal/network`; not a
hard dep, but co-locating cleanly).

**Exit criteria:**
- Unit tests: `--withdrawal-address` flag accepts EIP-55, rejects bad checksum, rejects
  41-char/43-char inputs, rejects non-hex.
- Unit test: missing flag → exit 2.
- `Entry.Validate` table-driven tests for each rejection class.
- `internal/tx.Validate` table-driven tests mirror the same classes.
- `Redact("0xabcdef...", 4)` returns `"0xab... (len=N)"` format per PRD §9.
- `defaultWithdrawalCreds` symbol removed (grep -r returns nothing).
- Existing golden tests **skipped** with a tracking marker until M0.10 (they will all fail until
  fixtures are regenerated).

**Deliverable artifacts:**
- Updated `cmd/eth-deposit-gen/main.go`, `internal/cli/cli.go`, `internal/cli/redact.go`.
- Updated `internal/deposit/json.go`, `internal/tx/validation.go`, `internal/network/network.go`.
- New sentinels in `internal/deposit/errors.go` and `internal/tx/errors.go`.
- `make assert-no-zero-wc` Makefile target.

**Critical path:** YES — gates M0.10 (golden refresh) and M0.9 (USER-GUIDE update).

---

### Phase M0.5 — Trust Boundary 2: Network/Fork Binding + Read-Path Verification

**Goal:** Close GO-002 (the second critical/high finding) by binding deposit-data
network/fork-version to the build target at two layers, and close GO-012 by recomputing SSZ
roots and BLS-verifying the signature on the read path.

**Scope:**
- FR-P0-A3 (GO-002): `Entry.ValidateForNetwork(target, v)` method per architecture §15;
  enforces `entry.NetworkName == target.Name` and
  `entry.ForkVersion == target.GenesisForkVersion`; sentinels `ErrNetworkMismatch`,
  `ErrForkVersionMismatch`.
- FR-P0-A4 (GO-012): `Entry.Validate` recomputes `DepositMessage.HashTreeRoot` and
  `DepositData.HashTreeRoot`; sentinels `ErrDepositMessageRootMismatch`,
  `ErrDepositDataRootMismatch`.
- BLS signature verification against `compute_domain(DOMAIN_DEPOSIT, target.GenesisForkVersion,
  ZeroGenesisValidatorsRoot)` inside `ValidateForNetwork`; sentinel `ErrBLSSignatureInvalid`.
- Move `bls.ValidatePubkeyBytes` from "skipped" (`internal/tx/validation.go:17-19`) to the
  production path.
- DiD partner in `internal/tx.ValidateAgainstNetwork(entry, params)` per architecture §15.
- Call sites: `cmd/eth-deposit-tx/buildUnsignedTx` (`main.go:208-255`) and `run.runAction`
  (`run.go:223-298`) call `Entry.Validate → Entry.ValidateForNetwork → tx.Validate →
  tx.ValidateAgainstNetwork` in that order.

**Entry dependencies:** M0.2 (geth APIs), M0.4 (sentinel infrastructure + WC checks land in the
same `Entry.Validate`).

**Exit criteria:**
- Cross-network signing test: hoodi deposit data fed to `--network mainnet` build → exit 2
  with `ErrNetworkMismatch`.
- Fork-version mismatch test: hand-tampered `fork_version` → exit 2.
- SSZ-root tamper test: mutate `signature` field → recomputed root mismatch → exit 2.
- BLS-signature tamper test: flip a byte in `signature` → `ErrBLSSignatureInvalid` exit 3.
- Pubkey-at-infinity rejected (acceptance for FR-P0-A4 inf-check; FR-P1-C2 hardens further in M1).

**Deliverable artifacts:**
- New `Entry.ValidateForNetwork` in `internal/deposit/json.go`.
- New `tx.ValidateAgainstNetwork` in `internal/tx/validation.go`.
- Sentinels in `internal/deposit/errors.go` and `internal/tx/errors.go`.
- Cross-network regression test suite.

**Critical path:** YES — block of release-critical work + downstream M0.6.

---

### Phase M0.6 — Trust Boundary 3: Sign + Send RLP Verification

**Goal:** Close GO-003 (mangled `To` address signing) and GO-004 (broadcast disconnect between
JSON metadata and `rawRLP`). These are the third and fourth release-blockers; after this phase,
the three trust boundaries are all enforced.

**Scope:**
- FR-P0-A5 (GO-003): `parseUnsignedTx` strict `common.IsHexAddress` + exact 42-char length;
  reject empty/truncated/non-hex; cross-check against
  `network.LookupByChainID(unsigned.ChainID).DepositContractAddress`; require explicit
  `--allow-non-deposit-recipient` override; sentinel `ErrInvalidToAddress`.
- Print a four-line signing summary (chainID/to/value/nonce) to stderr in `signAction`
  (`sign.go:133-176`) before `s.Sign` (PRD §9).
- FR-P0-A6 (GO-004): new `validateSignedAgainstRLP(signed, netParams)` per architecture §15
  and §7.3:
  - Decode `signed.RawRLP` via `types.Transaction.UnmarshalBinary`.
  - `decoded.Type() == DynamicFeeTxType`.
  - Recover sender via `types.Sender(LatestSignerForChainID, decoded)`; equal `signed.From`.
  - `decoded.ChainId/To/Value/Nonce/Hash` equal JSON metadata.
  - `decoded.To` equals `netParams.DepositContractAddress`.
- `sendAction` (`send.go:150-270`) calls `validateSignedAgainstRLP` first; prompt and chain-ID
  guard render from decoded values labelled "(decoded from RLP)".
- Fix `hexToBigInt` (`send.go:303-308`) to return explicit `(*big.Int, error)`.
- Tampered-JSON regression suite (architecture §11.6): chain-ID divergence, To divergence,
  rawRLP bad-signature, malformed value-hex.

**Entry dependencies:** M0.2 (geth `types.Transaction.UnmarshalBinary` APIs), M0.5 (the
RLP-decoded view feeds the same network binding check), M0.4 (Redact for any redacted error in
the chain-ID guard).

**Exit criteria:**
- `parseUnsignedTx` rejects: empty `To`, 41-char trunc, trailing non-hex, non-deposit recipient
  (without override).
- Tampered-JSON test suite all green (4 tests, exit code 2).
- Signing summary printed to stderr in `sign` command (acceptance via captured stderr in test).
- `hexToBigInt` parse-failure test green.

**Deliverable artifacts:**
- `cmd/eth-deposit-tx/sign.go`, `send.go`, `parse.go`, `signer/parse.go` updated.
- `cmd/eth-deposit-tx/send_test.go` adds the tampered-JSON regression suite.
- New sentinel `signer.ErrInvalidToAddress`.

**Critical path:** YES — release-blocker class. After this phase, all four GO-001..GO-004 are
closed.

---

### Phase M0.7 — Silent-Loss & Data-Correctness Bulk

**Goal:** Close the FR-P0-B medium/low cluster — every silent failure path on read/write/CLI
input that turns operator mistakes into invisible losses.

**Scope:**
- FR-P0-B1 (GO-009): `parsePubkeys` rejects duplicate pubkeys naming the indices.
- FR-P0-B2 (GO-010): `--wait-for-receipt` returns `tx.ErrReceiptReverted` mapped to exit 5
  when `rec.Status == 0` AFTER writing receipt; add `tx.ErrReceiptTimeout` distinct sentinel.
  (Open Question §11.2 — code reuse vs new code; this plan adopts the architecture §15
  recommendation of exit 5 for both with sentinel discriminator; revisit in M1 if needed.)
- FR-P0-B3 (GO-011): `FSWriter.Write` rewrite via `atomicio.WriteFileWithSuffix`; high-res
  filename + sha256-suffix + no-clobber. The stress test from M0.3 now exercises the production
  path.
- FR-P0-B4 (GO-027): `ScanDir` errors when two `.json` files declare same pubkey, naming both
  paths.
- FR-P0-B5 (GO-026): `normalizePubkeyHex` shared helper replaces three duplicated sites;
  `0X`-prefix regression test.
- FR-P0-B6 (GO-040): both CLIs call `requireNoArgs(c)` from M0.4 in every Action; reject
  `c.NArg() > 0` with exit 2.
- FR-P0-B7 (GO-031): static + RPC fee paths return `tx.ErrTipExceedsMaxFee` when
  `tip.Cmp(maxFee) > 0`.
- FR-P0-B8 (GO-005, GO-054 transitive): `build`/`run` reject `--rpc-url` with
  `tx.ErrRPCURLRejected` (ADR-004); delete `BuildConfig.RPCURL`, `UnsignedTx.From` fields
  (FR-P0-G1); make `--nonce` and fee flags required; update `scripts/e2e-testnet.sh` to pass
  them.
- FR-P0-B9 (GO-016): `build` and `sign` use `internal/atomicio.WriteFile`; delete local
  `atomicWriteFile` helper from `run.go:303-330`; unify exit codes across build/sign/run/send
  for marshal-vs-write errors.

**Entry dependencies:** M0.2 (geth bump compile-clean), M0.3 (atomicio), M0.4 (`requireNoArgs`),
M0.5 (sentinel infrastructure pattern), M0.6 (validateSignedAgainstRLP — receipt-revert path
shares `sendAction`).

**Exit criteria:**
- Parallel-write stress test using production `FSWriter` produces 1024 files with no clobber.
- Duplicate-pubkey CLI test: exit 2, both indices named.
- Receipt-revert integration test (e2e build tag): mock broadcaster returns `Status: 0`; exit 5;
  receipt file present.
- Receipt-timeout integration test: mock broadcaster never returns; exit 5; receipt absent.
- `make e2e-testnet` script updated; running it locally against hoodi with the new required
  `--nonce`/fee flags succeeds.
- All `--rpc-url` references in `build`/`run` either deleted or behind explicit reject with
  test asserting exit 2 + operator guidance error message.
- `UnsignedTx.From` and `BuildConfig.RPCURL` symbols absent (grep clean).

**Deliverable artifacts:**
- Updated `internal/cli/cli.go`, `internal/keystore/scandir.go`, `internal/output/output.go`,
  `internal/tx/{interface,types,builder}.go`, `cmd/eth-deposit-tx/{main,sign,run,send}.go`,
  `scripts/e2e-testnet.sh`.
- New `tx.ErrTipExceedsMaxFee`, `tx.ErrRPCURLRejected`, `tx.ErrReceiptReverted`,
  `tx.ErrReceiptTimeout`.

**Critical path:** YES — fixes that touch the M0 release exit-code contract.

---

### Phase M0.8 — Secret-Material Leak Closure

**Goal:** Close every reachable secret-leak path identified in FR-P0-C. This phase consumes the
`Redact` helper shipped in M0.4 and the `CachingPromptSource` design from architecture §9.1.

**Scope:**
- FR-P0-C1 (GO-006): `bls.NewSigner` returns fixed `ErrSecretRejected` instead of wrapping
  herumi's `%x`-leaking error; regression test asserts no secret bytes in error string.
- FR-P0-C2 (GO-014): `--private-key-env` validation in `LoadRunConfig`, `LoadSignConfig`, and
  `NewLocalSignerFromEnv` uses `Redact()` for the offending value — never echoes it; prints an
  actionable "treat as compromised" warning.
- FR-P0-C3 (GO-049): `internal/tx.ErrRPCDial` redaction — only `scheme://host` survives into
  the error; never path/query (which carry API keys).
- FR-P0-C4 (GO-053): rewrite `scripts/e2e-testnet.sh` — no `echo`/`tee` of `$RPC_URL`; outputs
  go to `${TMPDIR}/eth-deposit-tx-e2e/`; `.gitignore` entries for any in-tree e2e artifact
  directories; CI shell-grep gate rejecting `tee $RPC_URL` style patterns.
- FR-P0-C5 (GO-007): `internal/keystore.CachingPromptSource` wrapping `termPromptSource`;
  mutex-guarded; single TTY prompt before worker pool; per-call copies for the loader's
  zeroize contract; end-of-run `Zeroize()`. Acceptance: `-race`-clean parallel run of 8
  keystores observed to issue exactly one TTY prompt.

**Entry dependencies:** M0.4 (`Redact` helper), M0.2 (no geth API changes affect this work but
all signer-side edits land cleanly), M0.7 (`internal/tx.ErrRPCDial` lives in updated tx layer).

**Exit criteria:**
- Secret-leak regression test matrix (architecture §11.7) all green:
  - `TestNewSigner_OutOfRangeNoSecretLeak` (`internal/bls`).
  - `TestLoadRunConfig_RejectKeyValueNoLeak` (`cmd/eth-deposit-tx`).
  - `TestNewEthClient_DialErrorRedactsAPIKey` (`internal/tx`).
- `TestCachingPromptSource_OncePromptAcrossWorkers` and
  `TestTermPromptSource_RaceParallelRead` `-race`-clean.
- CI shell-grep gate rejects a test PR that re-introduces `tee $RPC_URL`.
- `scripts/e2e-testnet.sh` runs locally against hoodi without writing secrets into the repo
  tree.

**Deliverable artifacts:**
- Updated `internal/bls/bls.go`, `internal/keystore/passphrase.go`, `internal/tx/rpc_client.go`,
  `cmd/eth-deposit-tx/{run,sign}.go`, `scripts/e2e-testnet.sh`.
- New `internal/keystore.CachingPromptSource`.
- `.gitignore` updates.
- CI gate script (e.g., `.github/workflows/lint.yml` extension).

**Critical path:** YES — release-critical (GO-006/14/49/53 are P0).

---

### Phase M0.9 — Documentation & Release Hygiene

**Goal:** Update operator-facing documentation to match the binary; produce the v0.2
CHANGELOG.md and MIGRATION.md required by FR-P0-F2. After this phase, the docs and the code are
in sync at the v0.2 boundary.

**Scope:**
- FR-P0-F1 (GO-052): `docs/USER-GUIDE.md` updated to show the new `--withdrawal-address`
  example producing a real `0x01` credential; remove every reference to the v0.1 placeholder
  behavior; update troubleshooting rows.
- FR-P0-F2: `CHANGELOG.md` v0.2 entry documenting every breaking change (new required flags,
  JSON validation tightening, exit-code unifications, `--rpc-url` rejection); `MIGRATION.md`
  v0.1 → v0.2 with worked examples.
- Update the `cmd/eth-deposit-tx/main.go:30-38` version comment block (per architecture §19
  conflict #7).
- Update `staking-deposit-cli` references to `ethstaker-deposit-cli` everywhere (architecture
  §19 conflict #1; subset of M1 work but the rename in docs lands now).

**Entry dependencies:** M0.4 (new flag is the headline breaking change), M0.5–M0.8 (every
M0 phase changes either CLI surface or behavior; all changes must be documented).

**Exit criteria:**
- `docs/USER-GUIDE.md` walked end-to-end by a maintainer with a fresh checkout produces a
  successful hoodi deposit run.
- `CHANGELOG.md` has a v0.2.0 entry covering every breaking change.
- `MIGRATION.md` v0.1 → v0.2 published with concrete `before`/`after` flag examples.
- `grep -r 'staking-deposit-cli' docs/` returns no hits (replaced by `ethstaker-deposit-cli`).

**Deliverable artifacts:**
- `docs/USER-GUIDE.md`, `CHANGELOG.md`, `MIGRATION.md`.
- Updated `cmd/eth-deposit-tx/main.go` header comment.

**Critical path:** YES — release-blocker (no v0.2 tag without CHANGELOG/MIGRATION).

---

### Phase M0.10 — Golden-Fixture Regeneration

**Goal:** Regenerate every committed `testdata/` golden fixture under the new
`--withdrawal-address` flag, exactly once. Per the team-lead constraint, this is batched late
in M0 so the regeneration captures every output-affecting change in one diff.

**Scope:**
- Update golden-test rigs to pass `--withdrawal-address` derived from a fixed test account
  committed in `testdata/keys.json` (architecture §11.4).
- Run `make refresh-golden` (`REFRESH_GOLDEN=1 go test -run TestRefreshHoodiGolden|TestRefreshMainnetGolden`).
- Single PR committing the regenerated fixtures with a CHANGELOG bullet.
- Activate `make assert-no-zero-wc` lint guard (set up in M0.4) on CI.
- Re-enable the skipped golden tests from M0.4.

**Entry dependencies:** M0.4–M0.8 (every output-affecting M0 change must be merged first); M0.3
(`atomicio.WriteFileWithSuffix` filename scheme is the new committed naming).

**Exit criteria:**
- `make test` green with regenerated fixtures.
- `make assert-no-zero-wc` lint guard green on CI; verified by an attempted
  intentionally-bad PR that reverts WC and gets blocked.
- No committed JSON contains 64 zero hex chars in any `withdrawal_credentials` field.
- New filename scheme `deposit_data-<RFC3339Nano>-<sha256[:4]>.json` is present in
  `testdata/`.

**Deliverable artifacts:**
- Regenerated `testdata/{hoodi,mainnet}/` fixtures.
- `testdata/keys.json` (test-only deterministic account).
- Activated `make assert-no-zero-wc` CI job.

**Critical path:** YES — required for v0.2 tag (release tests run against goldens).

---

### Phase M0.11 — v0.2 Release Checklist & Tag

**Goal:** Execute the M0 release checklist (PRD §12 exit criteria) and produce a tagged v0.2.0
release.

**Scope:**
- `make e2e-testnet` run against a real hoodi RPC: zero secrets in any artifact (verify by
  grepping artifact directory); receipt-success; receipt-revert (separate run); receipt-timeout
  (separate run, abbreviated deadline).
- `make e2e-ledger-testnet` (FR-P0-D4): manual maintainer-run with a current-firmware Ledger
  device against hoodi; document the firmware versions tested in the release notes.
- Final `make lint` clean (`gofmt`, `errcheck`, `govulncheck`, `staticcheck`).
- Tag `v0.2.0` on `main`; cut prebuilt binaries (linux-amd64, darwin-arm64, darwin-amd64) via
  `goreleaser` or manual `make build` per platform.
- Publish release notes referencing `CHANGELOG.md` and `MIGRATION.md`.
- Smoke test on a fresh download: hoodi deposit-gen + deposit-tx run from operator
  perspective.

**Entry dependencies:** M0.1–M0.10 all complete.

**Exit criteria (PRD §12 M0 exit):**
- All P0 acceptance tests green in CI.
- `make e2e-testnet` passing against real hoodi RPC; zero secrets in artifacts; correct exit
  codes (0 success, 5 revert, 5 timeout).
- `make e2e-ledger-testnet` signed off by a maintainer (recorded in release notes).
- `govulncheck`, `gofmt`, `errcheck` clean.
- `CHANGELOG.md` v0.2 entry + `MIGRATION.md` published.
- Tagged `v0.2.0` with prebuilt binaries (linux-amd64, darwin-arm64, darwin-amd64).

**Deliverable artifacts:**
- GitHub release `v0.2.0` with binaries attached.
- Release notes file (or GitHub release body).
- Manual Ledger E2E sign-off recorded in release notes or `docs/RELEASE-NOTES-v0.2.md`.

**Critical path:** YES — the release tag itself.

---

## Milestone M1 — v1.0 "Mainnet-Ready"

**Objective:** Close every P1 finding (§6.2 of PRD). Add mainnet-specific safeguards, convert
all remaining latent bugs into tested invariants, add external-authority cross-checks, fix
documentation accuracy.

**Closes findings:** GO-008, GO-013, GO-015, GO-017, GO-018, GO-020, GO-021, GO-022, GO-024,
GO-025, GO-028, GO-029, GO-030, GO-032, GO-033, GO-034, GO-035, GO-036, GO-037, GO-038, GO-041,
GO-042, GO-045, GO-046, GO-048, GO-051, GO-059, GO-066, GO-068, GO-070.

---

### Phase M1.1 — Cancellation, Concurrency & Resource Hygiene

**Goal:** Close FR-P1-B — every cancellation, race, and env-var lifecycle issue surfaced in
the review.

**Scope:**
- FR-P1-B1 (GO-008): worker `ctx.Err()` per-iteration check; loader.Load honours ctx
  (architecture §9.2); SIGTERM via `signal.NotifyContext`; second Ctrl+C force-terminate
  watchdog.
- FR-P1-B2 (GO-021): `LocalSigner.mu sync.Mutex` guards `key` + `closed`; `Sign` copies under
  lock; `Close` zeroes under lock (architecture §9.3).
- FR-P1-B3 (GO-024): `LedgerSigner.Close` doc + stderr "reject on device to unblock"; bounded
  30s timeout; documented goroutine-leak warning (architecture §9.5).
- FR-P1-B4 (GO-017): `os.Unsetenv(envVar)` inside `NewLocalSignerFromEnv` after construction
  (architecture §19 conflict #5 resolved by self-unset); per-`Sign` zeroize of `priv`/`b`/`d`;
  `bls.Signer.Zeroize` (Go-side only, ADR-006); sanitized `cmd.Env` for `ethstaker-deposit-cli`
  subprocess.

**Entry dependencies:** M0.11 (v0.2 baseline).

**Exit criteria:**
- `TestLocalSigner_RaceSignClose -race -count=100` clean (architecture §11.5).
- `TestWorkerPool_SIGINTPropagatesWithin1s` passes (cancellation propagates < 1s).
- SIGTERM test: kills `eth-deposit-gen` in flight; observed clean shutdown.
- After `NewLocalSignerFromEnv`, `os.Getenv(envVar) == ""` verified.
- `bls.Signer.Zeroize` exists; package doc comment explicit about C-side limitation
  (ADR-006).

**Deliverable artifacts:**
- Updated `internal/signer/local.go`, `internal/signer/ledger.go`,
  `internal/bls/bls.go`, `internal/keystore/loader.go`,
  `cmd/eth-deposit-gen/main.go` worker pool.
- New `-race` tests in `internal/signer`, `cmd/eth-deposit-gen`.

**Critical path:** Partial — race fixes are not strict release blockers but `os.Unsetenv` and
SIGTERM are mainnet-table-stakes.

---

### Phase M1.2 — BLS / SSZ / ABI Correctness Defense-in-Depth

**Goal:** Add the external-authority cross-checks (differential SSZ oracle, `accounts/abi`
cross-check) and the BLS scalar/identity rejections promised in FR-P1-C.

**Scope:**
- FR-P1-C1 (GO-036): `bls.NewSigner` rejects `s.sk.IsZero()` after Deserialize → `ErrSecretZero`.
- FR-P1-C2 (GO-037): `bls.ValidatePubkeyBytes` rejects point-at-infinity → `ErrPubkeyZero`.
- FR-P1-C3 (GO-038): `DomainDeposit` and `ZeroGenesisValidatorsRoot` converted from exported
  package vars to functions returning the array by value (architecture §6.1, ADR for value
  semantics).
- FR-P1-C4 (GO-048): differential SSZ oracle behind `//go:build differential_oracle` using
  `ferranbt/fastssz` (ADR-007); committed generated code; new CI lane `differential_oracle`.
- FR-P1-C5 (GO-070): `accounts/abi` cross-check for `PackDeposit` — fuzz-driven byte-equality
  test (architecture §11.2); no new dep (geth transitive).
- Delete dead `computeDepositMessageRoot`/`computeDepositDataRoot` oracle stubs and the
  tautological `FuzzMerkleize`/`FuzzUint64Chunk` assertions.

**Entry dependencies:** M0.11.

**Exit criteria:**
- `go test ./internal/ssz/...` (default tags) passes; new oracle tests skipped without tag.
- `go test -tags=differential_oracle ./internal/ssz/...` passes — fastssz and our impl agree on
  the fuzz corpus.
- `TestPackDeposit_AgainstGethABI` passes; fuzz lane stable for 60s.
- `bls.NewSigner` rejects 32-byte zero secret → exit 3.
- `bls.ValidatePubkeyBytes` rejects compressed-G1 infinity (`0xc0` then 47 zero bytes).
- `network.DomainDeposit()` and `ZeroGenesisValidatorsRoot()` are functions; package vars gone.

**Deliverable artifacts:**
- `internal/ssz/ssz_oracle_test.go`, `internal/ssz/testdata/oracle_types.go` + generated.
- `internal/tx/abi_diff_test.go`.
- `tools/tools.go` adds `fastssz/sszgen` under `tools` tag.
- `.github/workflows/differential-oracle.yml` CI lane.
- Updated `internal/bls/bls.go`, `internal/network/network.go`.

**Critical path:** Partial — oracle/ABI cross-checks are mainnet trust requirements (PRD
metric 11 + 13); the scalar/identity checks are P1.

---

### Phase M1.3 — RPC Client Robustness

**Goal:** Close FR-P1-D — the RPC client path becomes safe for receipt polling, fee resolution,
and the hybrid `--rpc-url` decision (ADR-004 lock-in).

**Scope:**
- FR-P1-D1 (GO-032): `BlockBaseFee` → `HeaderByNumber(ctx, nil)`; nil base fee →
  `tx.ErrNoBaseFee`; interface doc fix.
- FR-P1-D2 (GO-033): RPC chain-ID guard fail-closed on RPC error or chain-ID 0; inject
  `*slog.Logger` for "warn-and-continue" actually emitted.
- FR-P1-D3 (GO-034): gas estimate overflow → `estimate + estimate/5`; use
  `cfg.NetworkParams.DepositContractAddress` directly.
- FR-P1-D4 (GO-035): `errors.Is(err, ethereum.NotFound)` replaces substring match; retry
  transient errors until deadline; receipt-phase failures mapped to documented exit code.
- FR-P1-D5 (Hybrid `--rpc-url`): per ADR-004, wire `NewEthClient` into `BuildConfig.RPC` on
  `run` only; `build` stays strictly offline; document the final decision in MIGRATION notes
  for v1.0.

**Entry dependencies:** M0.11.

**Exit criteria:**
- Mock RPC test: `HeaderByNumber` returns header with `BaseFee == nil` → `tx.ErrNoBaseFee`.
- Mock RPC test: `chainID == 0` → fail closed (exit 5).
- Mock RPC test: `NotFound` after deadline → `tx.ErrReceiptTimeout`.
- Gas overflow regression test: `estimate = math.MaxUint64 - 1024` → no overflow.
- `eth-deposit-tx run --rpc-url URL` (no `--nonce`/fees) succeeds against hoodi end-to-end;
  `build --rpc-url URL` still rejected.

**Deliverable artifacts:**
- Updated `internal/tx/{builder,rpc_client}.go`.
- New `tx.ErrNoBaseFee`.
- Updated `cmd/eth-deposit-tx/run.go` for hybrid mode.
- Final FR-P1-D5 ADR document (architecture §19 conflict #4 closes).

**Critical path:** Partial — receipt-phase robustness is mainnet-relevant.

---

### Phase M1.4 — Keystore Correctness

**Goal:** Close FR-P1-E — every keystore loader path becomes tightly typed and bounded.

**Scope:**
- FR-P1-E1 (GO-025): pre-validate keystorev4 JSON shape; only checksum mismatch →
  `ErrWrongPassphrase`; structural → `ErrKeystoreMalformed` (or new `ErrKeystoreCipherText` per
  architecture §15).
- FR-P1-E2 (GO-028): `ScanDir` accepts `*slog.Logger`; read errors → warnings at `--verbose`;
  no global slog default leaks (signature break — documented in MIGRATION.md but internal-only).
- FR-P1-E3 (GO-029): `len(secret) == 32` after decrypt; otherwise zeroize + `ErrKeystoreMalformed`.
- FR-P1-E4 (GO-030): `e.Type().IsRegular()`; `io.LimitReader` 1 MiB cap (`MaxKeystoreSize`
  constant).

**Entry dependencies:** M0.11.

**Exit criteria:**
- Table-driven test: each rejection class returns its sentinel; exit codes per §15.
- FIFO/symlink/device-file in scan dir → skipped + warning logged.
- 2 MiB pseudo-keystore → `io.ErrUnexpectedEOF` or LimitReader bound exceeded → rejected.
- Short-secret (31 bytes after decrypt) → `ErrKeystoreMalformed`; secret bytes zeroed.

**Deliverable artifacts:**
- Updated `internal/keystore/keystore.go`, `scandir.go`, `passphrase.go`.
- New `internal/keystore.ErrKeystoreCipherText`.

**Critical path:** Partial — P1 hardening.

---

### Phase M1.5 — CLI Contract & Exit Codes

**Goal:** Close FR-P1-F — every error wrapping, exit-code, and CLI input path is tightened.
Lands the `TestExitCodeContract` table that gates every M1+ PR.

**Scope:**
- FR-P1-F1 (GO-015): pre-validate required flags; substring fallback in `ExitCodeFor` for
  "Required flag(s)" → 2.
- FR-P1-F2 (GO-020): `parseUnsignedTx` rejects negative `value`/`maxFee`/`tip` (field-specific
  errors); rejects `unsigned.Type != "0x2"` → `signer.ErrUnsupportedTxType`.
- FR-P1-F3 (GO-022): `NewLocalSignerFromEnv` wraps specific validation error with `%w`.
- FR-P1-F4 (GO-041): `internal/cli.ConfirmReader` — falls back to `/dev/tty` when stdin is
  consumed by `--input -`; new `ErrNoTTY` if neither + `--yes` not set; consumed in `sendAction`.
- FR-P1-F5 (GO-051): `signUnsignedTx` switch default → `ErrInvalidInput` (no nil-interface
  panic).
- FR-P1-F6 (GO-018): `runDepositCLIVerify` checks `ctx.Err()`; wraps exec error with `%w` so
  SIGINT routes to exit 4 not 3.
- FR-P1-F7 (GO-042): `BroadcasterChainID` error wrapped with `%w` (not `%v`).
- FR-P1-F8 (GO-046): module-wide `%w` audit at `ScanDir`, `runWithDeps`, `Generate`, and every
  `return err` site found in the audit.
- `TestExitCodeContract` table (one per binary) mapping every sentinel from architecture §15.

**Entry dependencies:** M0.11, M1.1 (cancellation interacts with F6 ctx propagation).

**Exit criteria:**
- `TestExitCodeContract` green for both binaries; covers every sentinel in architecture §15.
- `--input - --yes` test: prompt read from `/dev/tty` when available; reject with `ErrNoTTY` +
  guidance otherwise.
- `errors.Is(err, context.Canceled)` survives `BroadcasterChainID` failure (GO-042 regression
  test).
- `runDepositCLIVerify` test: SIGINT mid-exec → exit 4.

**Deliverable artifacts:**
- Updated `internal/cli/cli.go`, `internal/signer/parse.go`, `cmd/eth-deposit-tx/{exit,sign,send}.go`,
  `cmd/eth-deposit-gen/main.go`.
- New `internal/cli.ConfirmReader`, `ErrNoTTY`.
- `cmd/eth-deposit-{gen,tx}/exit_contract_test.go`.

**Critical path:** YES — exit-code contract is mainnet-table-stakes; release-blocker.

---

### Phase M1.6 — Mainnet Acknowledgement Gate

**Goal:** Close FR-P1-A — the headline v1.0 user-visible safeguard. After this phase, an
operator cannot accidentally broadcast a mainnet deposit.

**Scope:**
- FR-P1-A1 (GO-013): new `--confirm-network=<name>` flag on `eth-deposit-tx send`/`run`/`build`
  (architecture §6.12). Value must equal the decoded-RLP network name **and** the RPC-derived
  network name (where RPC available). `--yes` does NOT bypass.
- Local-signer-on-mainnet additional gate: `--i-accept-local-signer-on-mainnet` when
  `--signer local` + `--network mainnet`.
- FR-P1-A2: release-gate test matrix exercising every `--network` × `--signer` × air-gap-mode
  combination against a mainnet-shaped (mock) chain ID.
- Pre-validate in `Load{Build,Sign,Send,Run}Config`.

**Entry dependencies:** M0.11, M1.5 (`ConfirmReader` for the prompt).

**Exit criteria:**
- Integration test: `--yes --network mainnet` without `--confirm-network=mainnet` → exit 2.
- Integration test: `--confirm-network=hoodi` on a mainnet-shaped chain-ID RPC → exit 2.
- Integration test: `--signer local --network mainnet` without
  `--i-accept-local-signer-on-mainnet` → exit 2.
- Test matrix from FR-P1-A2 all green.

**Deliverable artifacts:**
- Updated `cmd/eth-deposit-tx/{run,sign,send,config}.go`.
- New flag definitions; pre-validation.
- `cmd/eth-deposit-tx/mainnet_gate_test.go` matrix.

**Critical path:** YES — v1.0 release-blocker.

---

### Phase M1.7 — Test Independence & Fixture Hygiene

**Goal:** Close FR-P1-G — the external-authority hermetic CI lane, the read-from-disk golden
fixture, and the `Key.Zeroize` documentation correction.

**Scope:**
- FR-P1-G1 (GO-059): hermetic `ethstaker-deposit-cli` cross-validation lane (architecture
  §11.3). Dockerized CI image with `ethstaker-deposit-cli==<pinned>` baked in; new tagged
  Go test `cmd/eth-deposit-gen/cross_validate_test.go` (`//go:build cross_validate`);
  sanitized `cmd.Env`; pinned image SHA-256 in workflow.
- FR-P1-G2 (GO-066): `TestEntriesFromJSON_GoldenFile` reads actual fixture file or
  round-trips via writer; remove hand-copied literal.
- FR-P1-G3 (GO-045): `Key.Zeroize` delegates to `zeroizeBytes`; `runtime.KeepAlive` comment
  correction.

**Entry dependencies:** M0.11, M1.2 (oracle pattern reused).

**Exit criteria:**
- `make test-cross-validate` green in CI for both `hoodi` and `mainnet` networks.
- `TestEntriesFromJSON_GoldenFile` passes reading the on-disk fixture.
- `Key.Zeroize` verified via `runtime.KeepAlive`-corrected heap-dump test.

**Deliverable artifacts:**
- `cmd/eth-deposit-gen/cross_validate_test.go`.
- `.github/workflows/cross-validate.yml` + `Dockerfile.cross-validate`.
- Updated `internal/deposit/json_test.go`, `internal/keystore/key.go`.

**Critical path:** YES — `make test-cross-validate` is PRD §12 M1 exit criterion.

---

### Phase M1.8 — Documentation Accuracy

**Goal:** Close FR-P1-H — the docs match the binary byte-for-byte. Lands every doc fix
deferred from M0.9.

**Scope:**
- FR-P1-H1 (GO-068): `docs/USER-GUIDE.md` troubleshooting rows correctly attribute errors to
  `internal/tx.Validate` vs `Entry.Validate`; replace misquoted `ErrChainIDMismatch` with
  `ErrBroadcastChainIDMismatch`.
- `CHANGELOG.md` v1.0 entry covering every M1 behavior change (mainnet gate, hybrid `--rpc-url`
  on `run`, exit-code additions, etc.).
- Update USER-GUIDE with worked mainnet-ceremony example using `--confirm-network`.
- Verify `make doc-audit` (PRD success metric #9) returns 0 deltas — add or wire up the target
  if not already present.

**Entry dependencies:** M1.1–M1.7 (every M1 phase changes either CLI surface or behavior).

**Exit criteria:**
- `make doc-audit` returns 0 deltas (audited CLI contract matches behavior).
- `CHANGELOG.md` v1.0.0 entry published.
- USER-GUIDE walked end-to-end produces a successful (testnet) mainnet-shaped flow.

**Deliverable artifacts:**
- `docs/USER-GUIDE.md`, `CHANGELOG.md`.
- `make doc-audit` Makefile target (if not present).

**Critical path:** YES — v1.0 release-blocker.

---

### Phase M1.9 — v1.0 Release Checklist & Tag

**Goal:** Execute the M1 release checklist (PRD §12 exit criteria); produce a tagged v1.0.0
release.

**Scope:**
- `make test-cross-validate` (real `ethstaker-deposit-cli`) passing in CI for every supported
  network.
- Mainnet-gate integration test green.
- Maintainer-led dry-run of a real mainnet ceremony on a held-out test wallet (or a recorded
  `dryrun` mode if available); document outcome in release notes.
- Final `make lint` clean (`govulncheck` with no new reachable hits).
- Tag `v1.0.0` on `main`; cut binaries for the three supported platforms.
- Publish release notes + updated CHANGELOG.

**Entry dependencies:** M1.1–M1.8 all complete.

**Exit criteria (PRD §12 M1 exit):**
- All P1 acceptance tests green.
- `make test-cross-validate` passing in CI for every supported network.
- Mainnet ack gate integration test green.
- Mainnet dry-run completed without warning; outcome recorded.
- Tagged `v1.0.0`.

**Deliverable artifacts:**
- GitHub release `v1.0.0` with binaries.
- Release notes including dry-run ceremony outcome.

**Critical path:** YES — the release tag itself.

---

## Milestone M2 — v1.1 Hardening

**Objective:** Close every P2 finding (§6.3 of PRD) plus the quality catalogue. No
release-blocker pressure; group into a single hardening release.

**Closes findings:** GO-039, GO-043, GO-047, GO-050, GO-060, GO-061, GO-062, GO-063, GO-064,
GO-065, GO-067, GO-069, GO-071, plus FR-P2-A14, A15, A16 quality-catalogue items.

---

### Phase M2.1 — Quality Catalogue Hygiene

**Goal:** Close the no-controversy P2 hygiene findings — doc-comment fixes, comment corrections,
small file moves, dependency bumps.

**Scope:**
- FR-P2-A1 (GO-039): `NewApp` doc comment + `cli_test.go:550-551` comment fixed to state exit 2.
- FR-P2-A2 (GO-043): sentinel-copy in secret-leak test fixed (or comment corrected).
- FR-P2-A5 (GO-060): `scripts/e2e-testnet.sh` "NEXT STEP" updated to point at
  `docs/USER-GUIDE.md`.
- FR-P2-A6 (GO-061): `merkleize` guard `len(chunks) <= limit` (panic-on-precondition).
- FR-P2-A7 (GO-062): bls/ssz hygiene — `Sign` doc-param name, error casing normalize,
  remove `bls`-inside-`package bls` alias, prune ssz package comment.
- FR-P2-A8 (GO-063): named constant for `runtime.NumCPU() * 4`.
- FR-P2-A9 (GO-064): prefix `GENERATE_FIXTURES=1` in fixture-regen docstring.
- FR-P2-A10 (GO-065): regenerate keystore test fixtures with valid 96-char BLS pubkeys.
- FR-P2-A11 (GO-067): correct stale APDU 6d00 comment; delete tautological
  `TestFakeSignerName`/`TestFakeSignerSign`; keep the interface compile-time assertion.
- FR-P2-A12 (GO-069): `DEPOSIT_DATA_FILE` script comment + default consistency.
- FR-P2-A13 (GO-071): `go get golang.org/x/crypto@latest && go mod tidy`; re-run `govulncheck`.

**Entry dependencies:** M1.9.

**Exit criteria:**
- All listed findings closed by regression-tested PRs.
- `golang.org/x/crypto` bumped; `govulncheck` re-run clean.

**Deliverable artifacts:** Touched files per finding.

**Critical path:** No.

---

### Phase M2.2 — Dead Code & Duplication Removal

**Goal:** Close FR-P2-A14, A15 — remove dead/speculative code and unify duplicated structs.

**Scope:**
- FR-P2-A14: delete `padRight`, `tx.TxBuilder` consumer-less interface, fake "compile-time
  assertions" in `run.go:355-356`, `EntryFromJSON` exported function if no callers,
  `deposit.Request.Pubkeys` batch field if unused.
- FR-P2-A15: unify `jsonEntry` between `internal/deposit/json.go` and
  `internal/output/output.go`; unify build-flag list between `buildCommand` and `buildFlags()`;
  de-duplicate signer/env-var validation between `LoadSignConfig` and `LoadRunConfig`.

**Entry dependencies:** M2.1 (mechanical refactors land cleanly after hygiene).

**Exit criteria:**
- `go test ./...` green after deletions; no broken callers.
- `grep` for removed symbols returns no hits.
- `jsonEntry` defined once.

**Deliverable artifacts:** Touched files; `git diff --stat` shows a net negative line count.

**Critical path:** No.

---

### Phase M2.3 — Convention & Architecture Hygiene

**Goal:** Close FR-P2-A3, A4, A16 — architectural-hygiene items requiring a small ADR or
decision.

**Scope:**
- FR-P2-A3 (GO-047): single registry table in `internal/network` (ADR per architecture §6.1);
  remove four-site duplication; address parsing at `init()` so a typo panics at process start.
- FR-P2-A4 (GO-050): `ledger_nocgo.go` decision per architecture §6.9 — either delete the
  unreachable path or break `signer → bls` cycle + CI matrix for `CGO_ENABLED=0`. Land a
  short ADR with the decision.
- FR-P2-A16: resolve duplicate package doc comments
  (`cmd/eth-deposit-tx/{exit,main}.go`; `internal/deposit/{json,deposit}.go`); add doc
  comments to all exported sentinels; package comment for `internal/tx`; replace
  `%v`-flattened wrapping in `internal/tx/rpc_client.go` with `%w`; move `runWithDeps`
  orchestration out of `package main` into `internal/cli` (thin-main convention).

**Entry dependencies:** M2.2.

**Exit criteria:**
- `golint -warn-out-of-set` (or equivalent) clean for missing exported-symbol doc comments.
- `internal/network.paramsByName` is the single registry; all `Lookup*` consume it.
- `cmd/eth-deposit-{gen,tx}/main.go` are thin entry points (orchestration lives in
  `internal/cli` or similar).

**Deliverable artifacts:** Touched files; short ADR-008 documenting the `ledger_nocgo` decision.

**Critical path:** No.

---

### Phase M2.4 — v1.1 Release (Optional 0x02 EIP-7251)

**Goal:** Tag v1.1; optionally include EIP-7251 0x02 compounding-validator support if the
upstream spec is settled by then (PRD §10 Out-of-Scope notes 0x02 is a candidate for v1.1).

**Scope:**
- Final `make lint` clean; `make test-cross-validate` clean.
- (Optional) implement `--withdrawal-address` with `0x02` prefix for compounding validators,
  per EIP-7251; extend `Entry.Validate` accepted prefixes; range constants already shipped in
  M0 (ADR-005) so this is additive.
- Tag `v1.1.0`; binaries; CHANGELOG; release notes.

**Entry dependencies:** M2.1–M2.3.

**Exit criteria (PRD §12 M2 exit):**
- Module CR-clean: no dead code, no duplication of constants/structs across packages, no
  `%v`-wrapped errors, no missing doc comments on exported identifiers.
- `internal/network` reduced to a single source table.
- Tagged `v1.1.0`.

**Deliverable artifacts:** GitHub release `v1.1.0`.

**Critical path:** No.

---

## Dependency Graph

### Within M0 (linear-ish, single-stream)

```
M0.1 (CI/toolchain) ──► M0.2 (geth bump) ──► M0.3 (atomicio)
                                                    │
                                                    ▼
                                        M0.4 (WC trust boundary + Redact)
                                                    │
                                                    ▼
                                        M0.5 (network/fork binding)
                                                    │
                                                    ▼
                                        M0.6 (RLP boundary in send)
                                                    │
                                                    ▼
                                        M0.7 (silent-loss bulk)
                                                    │
                                                    ▼
                                        M0.8 (secret-leak closure)
                                                    │
                                                    ▼
                                        M0.9 (docs + CHANGELOG/MIGRATION)
                                                    │
                                                    ▼
                                        M0.10 (golden refresh) ──► M0.11 (release/tag)
```

**Parallelization opportunities (future):** Given a second writer, M0.4 and M0.8 can largely
parallelize (Redact is the only shared dependency, ships first in M0.4). M0.7's sub-items
(B1..B9) can be split across writers. M0.9 (docs) can begin in parallel with M0.7/M0.8.

### Within M1 (more parallelization slack)

```
M0.11 (v0.2)
  │
  ├──► M1.1 (cancellation/concurrency)
  ├──► M1.2 (BLS/SSZ/ABI oracle)
  ├──► M1.3 (RPC robustness)
  ├──► M1.4 (keystore correctness)
  └──► M1.5 (CLI contract/exit codes)  ──► M1.6 (mainnet ack gate) ──► M1.8 (docs)
                                                                              │
                                                  M1.7 (cross-validate lane) ─┤
                                                                              ▼
                                                                          M1.9 (release/tag)
```

**Single-stream order recommended:** M1.5 → M1.1 → M1.6 → M1.2 → M1.3 → M1.4 → M1.7 → M1.8 →
M1.9. (M1.5 first because TestExitCodeContract gates every following PR; M1.6 second because
it's the visible release-blocker; M1.7 needs M1.6's mainnet-gate matrix anyway.)

### Within M2

```
M1.9 (v1.0) ──► M2.1 (hygiene) ──► M2.2 (dead code) ──► M2.3 (conventions) ──► M2.4 (v1.1 tag)
```

Largely linear; M2.1–M2.3 could be a single PR series if writers are limited.

---

## Critical-Path Analysis

### Phases that gate the **v0.2 tag**

Every M0 phase is critical-path for v0.2 by definition (all P0 must close). The narrow critical
path is:

**M0.1 → M0.2 → M0.4 → M0.5 → M0.6 → M0.7 → M0.10 → M0.11**

(M0.3 is a tight prerequisite for M0.7; M0.8 is required for v0.2 but can land in parallel
with M0.7 in a multi-writer setting; M0.9 docs must land before M0.11 tag.)

### Phases that gate the **v1.0 tag**

**M0.11 → M1.5 → M1.6 → M1.7 → M1.8 → M1.9**

These are the strict v1.0 blockers. M1.1, M1.2, M1.3, M1.4 are P1 by definition so they cannot
be skipped, but in a tight schedule M1.3 (RPC robustness sub-items) or M1.4 (keystore
sub-items) could in principle slip to a v1.0.x point release if reviewers agree no mainnet-
visible regression results — flagged here purely for emergency contingency planning, not
recommended.

### Phases that can slip from v0.2 to v1.0 without blocking testnet

**None of the M0 phases can slip** — every M0 phase is P0 by PRD §6 definition. The closest
candidates for "soft slip" would be:

- FR-P0-G2 (range constants) — purely additive, slipping it postpones M2 EIP-7251 work but
  doesn't affect v0.2 trust. Not recommended (FR-P0-G2 is small).
- The `make assert-no-zero-wc` lint guard (M0.10) — slipping it postpones the regression guard
  but does not regress v0.2 behavior.

Everything else in M0 directly enforces or documents a release-blocking invariant.

---

## Risk Register (planning-level; supersedes PRD §13 only where execution-specific)

| # | Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|---|
| P1 | geth v1.17.x bump (M0.2) breaks `usbwallet`/`ethclient` call sites with non-trivial deltas | High | Medium | Land M0.2 on a feature branch; full test + `-race` + manual Ledger E2E before merging to develop; pin to exact patch that compiles cleanly. |
| P2 | M0.7 (silent-loss bulk) is the largest single phase by issue count; estimation slip risk | Medium | Medium | Plan to split into 2 sub-PRs during issue estimation: (a) `--rpc-url` reject + dead-field delete + atomic write unification; (b) the GO-009/10/11/27/26/40/31 cluster. |
| P3 | Golden-fixture refresh (M0.10) lands a huge diff after many phases of skipped golden tests; reviewers struggle | Medium | Medium | Per-phase commits in M0.4–M0.8 mark goldens as "skipped pending refresh"; M0.10 PR is mechanically reviewable (the diff is regenerated, not edited). |
| P4 | Single-writer schedule for M0 stacks 11 phases; cumulative slip pressure on v0.2 | High | Medium | Phases M0.4/M0.5/M0.6 are the trust-boundary critical block — protect their schedule first; M0.7/M0.8 sequence is flexible. Allow M2 cleanup to absorb any defensible M1 slip. |
| P5 | `make e2e-testnet` (M0.11) flaky against public RPC providers (rate limits, transient errors) | Medium | High | Use a self-hosted hoodi RPC for the release-gating run; document specific RPC provider tested; allow up to 3 retries in the manual checklist. |
| P6 | Ledger E2E (M0.11, FR-P0-D4) requires physical device + firmware combinations | Medium | Medium | Per architecture R-D + PRD R3: gate manual (maintainer sign-off, not CI auto-merge); document tested firmware versions. |
| P7 | `--rpc-url` rejection in M0.7 surprises operators with broken scripts | Low (testnet only) | High | The error message points at the new `--nonce`/fees flow with a concrete example; MIGRATION.md prominently documents (FR-P0-B8 acceptance). |
| P8 | M1.7 hermetic CI image (ethstaker-deposit-cli) drifts between pin and upstream | Low | Low | Pin SHA-256; document upgrade cadence; track ethstaker releases in `docs/SECURITY.md`. |
| P9 | M1.2 differential SSZ oracle disagrees with our impl on a corner case the spec also handles ambiguously | Low | Medium | Per PRD R6: re-derive against ethstaker-deposit-cli Python and consensus-spec Python reference; treat any disagreement as our bug by default. |
| P10 | M0.9 docs PR lands after every M0 behavior change but before M0.10 fixture refresh — fixture filenames in USER-GUIDE need a second touch | Low | High | Document filename scheme in M0.9 as a pattern (`deposit_data-<RFC3339Nano>-<sha256[:4]>.json`); concrete example bytes get a follow-up edit in M0.10. |

---

## Technical Spikes / Open Questions

Spike work to resolve **before or during** the phases noted:

1. **Spike S1 — Open Question §11.1 (withdrawal credential prefix coverage).** **RESOLVED
   (user decision at plan gate, 2026-06-07): `--withdrawal-address` (0x01) ONLY in v0.2.**
   No `--withdrawal-bls-pubkey`; 0x00/0x02 are vNext candidates. M0.4 scope updated accordingly.

2. **Spike S2 — Open Question §11.2 (receipt-timeout exit code).** **RESOLVED (user decision
   at plan gate, 2026-06-07): reuse code 5 with sentinel discriminator** (D10 confirmed).

3. **Spike S3 — Hybrid `--rpc-url` final design (FR-P1-D5).** ADR-004 recommends wiring on
   `run` only. Final ADR + design lands during M1.3. **Needed by:** M1.3 start.

4. **Spike S4 — `ledger_nocgo` decision (FR-P2-A4, GO-050).** Delete vs break the
   `signer → bls` cycle. **Needed by:** M2.3 start.

5. **Spike S5 — `make doc-audit` mechanism (PRD success metric #9).** If no existing target,
   prototype during M0.9 docs phase; finalize during M1.8. **Needed by:** M1.8 exit.

6. **Spike S6 — Mainnet dry-run mechanism (M1.9 release checklist).** "Held-out test wallet"
   vs `dryrun` mode — PRD §12 leaves this open. Prototype during M1.6 design. **Needed by:**
   M1.9.

7. **EIP-7251 0x02 spec settled?** (PRD §11.4) — decide before M2.4 whether to ship 0x02
   support in v1.1.

---

## Decision Log

Decisions made during planning, with rationale:

| # | Decision | Rationale |
|---|---|---|
| D1 | M0 ordering: CI gates first, then geth bump, then atomicio, then three trust boundaries (M0.4 / M0.5 / M0.6), then silent-loss bulk, then secret leaks, then docs, then golden refresh, then release. | Honors team-lead constraints (CI first; geth early; goldens batched). Trust boundaries cluster early so secondary fixes (M0.7) can lean on their sentinel infrastructure. |
| D2 | `Redact` helper ships in M0.4 (with WC fix), not later. | Three M0 phases (M0.6 chain-ID guard, M0.8 secret leaks) consume it; landing it early avoids late churn. |
| D3 | Atomic write helper (`internal/atomicio`) is its own phase M0.3, not folded into M0.7. | Per ADR-001, the new package is consumed by 5 call sites; tested in isolation it's a 1-issue scope with high downstream leverage. |
| D4 | Golden fixture refresh is a single dedicated phase M0.10. | Per team-lead constraint: GO-001 changes every committed fixture; batching means one mechanical diff PR rather than threading regenerations through every behavior phase. |
| D5 | Doc updates (M0.9) land before golden refresh (M0.10). | Per architecture §19 conflict #6: USER-GUIDE shows a `0x01` credential the tool can now produce — order is "update flag docs", then "regenerate fixtures referenced by the worked example". |
| D6 | M1.5 (CLI contract / exit codes) lands first in M1 single-stream ordering. | `TestExitCodeContract` gates every following PR; landing the table early caches all future regressions. |
| D7 | M1.6 (mainnet ack gate) lands before M1.7 (cross-validate lane). | The cross-validate test matrix in M1.7 should exercise mainnet-gate scenarios; both depend on the same RPC-shape fixtures. |
| D8 | M2 is grouped into one release (v1.1) rather than three (v1.1, v1.2, v1.3). | Per PRD §6.3: no release-blocker work; better to ship as a coherent hardening release. |
| D9 | Optional EIP-7251 0x02 work scoped to M2.4 rather than its own milestone. | Per PRD §10 Out-of-Scope: candidate for v1.1; range constants already in M0 (ADR-005); marginal cost. |
| D10 | Receipt-revert (M0.7) and receipt-timeout (M0.7) both map to exit 5 with sentinel discriminator. | Per architecture §15 recommendation; allows v0.2 ship without introducing a new public exit code; revisit in M1 if automation needs require code 6. |
| D11 | Phases are sized at 3–10 issues each, not individual 1–2 day tasks. | Per team-lead constraint: issue estimation is the next planning stage. |

---

## Review Checklist for the Team-Lead

Before issue estimation begins, please confirm:

- [ ] Phasing makes sense (M0 11 phases / M1 9 phases / M2 4 phases).
- [ ] Priorities align with business needs (testnet-trust first, mainnet ack second, hardening
      last).
- [ ] Critical-path analysis matches your expectation of the release schedule.
- [ ] Open Questions §11.1, §11.2, §11.4 resolved (or carry into M0.4/M0.7/M2.4 explicitly).
- [ ] Risk P1 (geth v1.17.x bump) and Risk P3 (golden-fixture diff size) understood.
- [ ] M0.11 / M1.9 release-checklist work is correctly modeled as its own phase rather than
      bundled into the prior fix-phase.
- [ ] Optional EIP-7251 0x02 inclusion in M2.4 is acceptable to defer or include.
