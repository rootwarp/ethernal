# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Code conventions

Follow [CONVENTIONS.md](CONVENTIONS.md) for all Go code in this module.

## Commands

All commands run from `go/` (this directory). CGO is required (`CGO_ENABLED=1`) for builds and tests — the BLS library (`herumi/bls-eth-go-binary`) and Ledger USB bindings need it. The Makefile sets it for you.

```sh
make build          # compile eth-deposit-gen to bin/
make build-tx       # compile eth-deposit-tx to bin/
make test           # all tests (unit + integration)
make lint           # go vet + staticcheck
make coverage       # per-package coverage summary
make fuzz           # 30s fuzz runs (ssz merkleize/chunk, cli pubkey parser)
make e2e-mock       # E2E via mock broadcaster, no real RPC (-tags=e2e)
make refresh-golden # regenerate testdata/{hoodi,mainnet}/ fixtures (REFRESH_GOLDEN=1)
```

Single test: `CGO_ENABLED=1 go test -run TestName ./internal/deposit/`

E2E tests in `cmd/eth-deposit-tx/` are behind the `e2e` build tag; `make e2e-testnet` runs against a real testnet and requires `RPC_URL` and `ETH_DEPOSIT_TX_PRIVATE_KEY`.

## Architecture

Two CLIs sharing a pipeline of `internal/` packages. Two distinct keys are involved and never meet: the **BLS validator key** (signs the deposit message, handled by eth-deposit-gen) and the **secp256k1 sender key** (signs the Ethereum transaction, handled by eth-deposit-tx).

### eth-deposit-gen (`cmd/eth-deposit-gen`)

EIP-2335 keystores → Launchpad-compatible deposit data JSON. Data flows:

```
cli (flags → typed Config, validation)
 → keystore (EIP-2335 v4 decrypt; sentinel errors; zeroize hook for key material)
 → bls (herumi wrapper; owns one-time process-global init; Signer/Verifier interfaces)
 → ssz (hand-rolled hash_tree_root for DepositMessage/DepositData/ForkData/SigningData)
 → deposit (orchestrator — see below)
 → output (Launchpad JSON schema serialization)
```

`internal/deposit` is the only package that knows the full domain story: it precomputes the deposit domain once at construction and enforces the driving correctness constraint — **verify-before-write**: every BLS signature is re-verified immediately after signing; a single failure aborts the run before anything is written.

`internal/network` is the source of truth for per-network compile-time constants (fork versions, deposit contract addresses). Add new networks there, nowhere else.

### eth-deposit-tx (`cmd/eth-deposit-tx`)

Subcommands `build`, `sign`, `send`, `run` (build+sign). The build/sign split is deliberate: it supports air-gapped operation (build unsigned tx online, sign offline, broadcast back online), so keep the unsigned/signed JSON artifacts stable.

- `internal/tx` — ABI encoding of `deposit(bytes,bytes,bytes,bytes32)`, EIP-1559 transaction builder, JSON-RPC client, validation.
- `internal/signer` — Ledger (hardware) and local-key signers. Ledger support is gated by `//go:build cgo` / `!cgo` file pairs; without CGO the Ledger path compiles to a stub that errors at runtime.

Exit codes (0–5) are part of the CLI contract, documented in `cmd/eth-deposit-tx/main.go`; map new error categories to the existing codes rather than inventing new ones.

### Testing layout

- Golden-file tests compare against `testdata/` fixtures generated from a fixed secret; after intentional output changes, regenerate with `make refresh-golden` (runs `test/e2e/` refresh tests under `REFRESH_GOLDEN=1`).
- `test/e2e/` holds per-network (hoodi, mainnet) pipeline tests; `cmd/eth-deposit-tx/*_e2e_test.go` (tag `e2e`) exercises build+sign+send with a mock broadcaster.
- Fuzz targets live in `internal/ssz` and `internal/cli`.
