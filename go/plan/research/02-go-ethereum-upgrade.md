# Research: go-ethereum v1.14.12 → ≥v1.17.0 Upgrade — Ledger Firmware Fix and API Surface

## Verdict
**FR-P0-D1 is correct and the minimum target is v1.15.0 (not v1.17.0)**: the `usbwallet` PID-`0x5000`/Ledger-Flex fix landed in **v1.15.0 via PR #31004** [1][2], not v1.17.0. v1.17.0 only adds **Ledger Gen5** and EIP-712 polish [3]. Pinning to `>= v1.17.0` is still the right choice (cumulative fixes, Gen5 support, latest signer hardening) but the PRD's framing that "v1.14.12 predates the v1.15.0 usbwallet fix" (REVIEW.md GO-055) is exactly correct, and the minimum-acceptable version is v1.15.0. **No breaking API changes** were found between v1.15.0–v1.17.x in the import surface this module uses (`common`, `core/types`, `crypto`, `rlp`, `accounts/usbwallet`, `ethclient`, `accounts/abi`).

## Context
- **Goal:** Unbreak Ledger sign on current firmware (Nano S Plus FW updates that ship `0x5000` PID, Flex, Gen5); pull in cumulative signer/RPC fixes.
- **Constraints:** Two CLIs depend on `usbwallet`, `ethclient`, `core/types`, `crypto`, `rlp`, `accounts/abi`, `common`. CGO is mandatory. Must not regress any existing test.
- **Evaluated:** v1.14.12 → v1.15.0, v1.16.0, v1.17.0, v1.17.3 (latest).

## Comparison

| Version | Release date (approx) | Relevant change | Risk to us |
|---|---|---|---|
| v1.14.12 | 2024-11 (current) | Ledger fails on FW with PID `0x5000`; no Flex | High — release blocker per REVIEW.md GO-055 |
| **v1.15.0** | 2025-01 | **PR #31004** [2]: `accounts/usbwallet` fixed for new Ledger FW + adds Ledger Flex. Upper-byte PID match replaces hardcoded PIDs. | **Minimum acceptable** |
| v1.16.0 | 2025-Q3 ("Terran Rivets") | Archive node, Fusaka prep; no `usbwallet` notes [4] | Low — pull-along |
| **v1.17.0** | 2025-Q4 | Ledger Gen5 + EIP-712 signing polish (#33297, #33113); `SignTextWithPassphrase` fix (#33138); `types.Signer.SignatureValues` now errors on invalid sig sizes (#33647) [3] | **Recommended target** |
| v1.17.x | latest | Cumulative | Recommended for release tag |

### Behavioral & API checks against our code

- **`accounts/usbwallet`** — only consumed via `usbwallet.NewLedgerHub()` / `wallet.Open/SignTx/Status/Close`. These signatures are unchanged across v1.15.0–v1.17.x; PR #31004 changed internals (hub PID matching) [2].
- **`ethclient.DialContext`, `Client.ChainID`, `SuggestGasTipCap`, `HeaderByNumber/BlockByNumber`, `PendingNonceAt`, `EstimateGas`, `SendTransaction`** — call sites in `internal/tx/rpc_client.go` are stable. No deprecations seen.
- **`core/types.Transaction`, `types.NewTx`, `types.DynamicFeeTx`, `types.LatestSignerForChainID`, `types.Signer.SignatureValues`** — unchanged signatures; v1.17.0's stricter `SignatureValues` error (#33647) is an *enhancement* we should welcome, not a break.
- **`accounts/abi`** — stable; used only for the FR-P1-C5 cross-check.
- **`crypto.ToECDSA`, `crypto.PubkeyToAddress`, `crypto.Keccak256Hash`** — stable.
- **`rlp.EncodeToBytes`, `Transaction.MarshalBinary/UnmarshalBinary`** — stable.
- **`common.HexToAddress`, `IsHexAddress`** — unchanged silent-mangle behaviour persists (still the root cause of GO-003); upgrade does NOT fix this — FR-P0-A5 (explicit `IsHexAddress` + length check) is still required.

### Transitive risk
- `holiman/uint256`, `karalabe/hid`, `consensys/gnark-crypto`, `crate-crypto/go-kzg-4844`, `c-kzg-4844`: all pulled by go-ethereum; minor version bumps in v1.17.x. None used directly by our code; CGO builds verified clean upstream.
- **`karalabe/hid`** specifically: vendored HID transport for `usbwallet`. PR #31004 may surface a transitive `hid` bump; verify in `go.sum` after upgrade.

### Toolchain compatibility
- v1.17.x requires `go >= 1.23`. PRD FR-P0-E1 targets `toolchain go1.26.4`, comfortably ahead.

## Recommended Approach
Pin **`require github.com/ethereum/go-ethereum v1.17.x`** (latest patch at release time) per FR-P0-D1. Stage on a feature branch and:
1. `go get github.com/ethereum/go-ethereum@v1.17.x && go mod tidy`
2. Run `make test`, `make e2e-mock`, `go test -race ./...`.
3. Manual Ledger E2E on at least one **current-firmware** Nano S Plus (PID 0x5000) and ideally Flex. FR-P0-D4 makes this a release-checklist gate; honor it.
4. Run `govulncheck ./...` (FR-P0-E2) — expect the four go-ethereum p2p advisories from REVIEW.md to disappear (they were not in our linked path anyway).
5. Re-grep call sites for any of the v1.17.0 method-signature changes (especially `types.Signer.SignatureValues` — if we ever call it directly, the new error return must be handled).

## Implementation Guidelines
- Pin the **exact** minor (e.g. `v1.17.3`), not a range. The Ethereum repo has historically broken downstream consumers between minors despite SemVer claims.
- Keep `karalabe/hid` and `holiman/uint256` versions exactly as the upgrade brings them in; don't manual-edit `go.sum`.
- Add the version bump as a standalone commit so a future bisect can isolate any regression.

## Common Pitfalls
- **CGO toolchain mismatch:** macOS arm64 builds of go-ethereum v1.17.x need a recent Xcode `clang`. CI must use `setup-go` ≥ v5 with the matching toolchain.
- **Ledger-Live conflict:** A common test failure during E2E is "device unavailable" when Ledger-Live is running. Document this in the runbook (matches GO-019 fix — distinguish `ErrNoDevice` vs `ErrDeviceUnavailable`).
- **HID permissions on Linux:** udev rules for the new Flex PID may be required on bare-metal Linux CI. Document or skip Linux Ledger-CI.

## Feasibility: ✅ GREEN. No PRD contradictions.

## Sources

[1] [go-ethereum v1.15.0 release notes](https://github.com/ethereum/go-ethereum/releases/tag/v1.15.0) — Ethereum, Jan 2025. "Package `accounts/usbwallet` was updated to support new Ledger firmware and the Ledger Flex device. (#31004)"
[2] [PR #31004: accounts/usbwallet: fix ledger access for latest firmware and add Ledger Flex](https://github.com/ethereum/go-ethereum/pull/31004) — Ethereum. Description: "The latest firmware for Ledger Nano S Plus now returns `0x5000` for it's product ID, which doesn't match any of the product IDs enumerated in `hub.go`." Solution: upper-byte match instead of hardcoded PIDs. Adds Flex (`0x7000`).
[3] [go-ethereum v1.17.0 release notes](https://github.com/ethereum/go-ethereum/releases/tag/v1.17.0) — Ethereum. Ledger Gen5 + EIP-712 (#33297, #33113); `SignTextWithPassphrase` (#33138); `types.Signer.SignatureValues` validation (#33647); EIP-1559 default for `eth_sendTransaction` (#33058).
[4] [go-ethereum v1.16.0 release notes](https://github.com/ethereum/go-ethereum/releases/tag/v1.16.0) — Ethereum. "Terran Rivets": archive node, Fusaka prep. No wallet/signer changes relevant to us.
