# Changelog

All notable changes to tools in this repository are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## Unreleased

### Removed
- Tautological `FuzzMerkleize`/`FuzzUint64Chunk` assertions (internal/ssz/ssz_fuzz_test.go); differential oracle (M1.2-4) replaces assertion role (M1.2-7, closes FR-P1-C4 cleanup; M1.8-2).

## eth-deposit-tx

### [eth-deposit-tx 0.1.0] - 2026-05-18

First release. Builds, signs, and broadcasts Beacon Chain deposit transactions
from Launchpad-compatible deposit data JSON. Use v0.1.0 because Ledger heuristics
against real hardware are not yet refined — that refinement is tracked for v0.2.0.

#### Added

- **Subcommands:** `build`, `sign`, `run`, `send` wired via `urfave/cli/v2`. `run` is a convenience alias for `build + sign` on the same machine. `send` broadcasts a signed transaction via JSON-RPC.
- **Local signer:** `--signer local` reads the private key from `ETH_DEPOSIT_TX_PRIVATE_KEY` (env-var only; never a CLI flag), signs an EIP-1559 transaction, and zeroizes the key on close.
- **Ledger signer:** `--signer ledger` signs via a connected Ledger hardware wallet using the go-ethereum `usbwallet` transport. Key never leaves the device.
- **Networks:** Holesky, Sepolia, Hoodi, and Mainnet. Mainnet safety: `send` fetches the chain ID from the RPC node and refuses broadcast if it mismatches the signed tx's chain ID, preventing accidental cross-network broadcast. Users must type the network name interactively before `eth_sendRawTransaction` is called.
- **Static fee/gas/nonce:** all gas and nonce flags can be supplied manually for fully offline / air-gapped operation (`build` with no `--rpc-url`).
- **RPC fee/gas/nonce resolution:** when `--rpc-url` is provided, `build` fetches the current nonce, base fee, and suggests EIP-1559 tip cap from the node.
- **Double-confirmation broadcast:** `send` requires the user to type the network name to confirm before `eth_sendRawTransaction` is called, even in non-interactive mode.
- **Receipt polling:** after a successful broadcast `send` polls the RPC for the transaction receipt and prints the block number and tx hash.
- **Exit codes:** 0 success, 1 internal error, 2 user/config error, 3 signer/crypto error, 4 user abort (SIGINT or Ledger rejection), 5 broadcast/RPC error.
- **Stdin/stdout pipe support:** `--input-file -` and `--output -` for full Unix-pipe compatibility across all subcommands.
- **Multi-entry JSON:** warns on stderr when a JSON array has more than one entry and defaults to `--index 0`; `--index N` selects a specific entry.

#### Security

- Private key accepted only via environment variable (`ETH_DEPOSIT_TX_PRIVATE_KEY`); a POSIX-name validator rejects accidental raw-hex values passed as the flag name (exit code 2).
- Key bytes are zeroized immediately on `LocalSigner.Close()` (verified by `TestLocalSigner_Close_ZeroizesKey`).
- Signed output files written with permissions `0o600`.
- No key material appears in error messages, logs, or help text.
- Ledger is always promoted as the preferred path; local signer help text calls it "development and CI only".
- Sentinel-based error wrapping (`errors.Is`) maps signer failures to typed exit codes without leaking internals.
- **Synthetic test key callout:** the test private key in `testdata/` is used only for E2E mock tests and is clearly marked as non-production material.

#### Documentation

- `go/docs/USER-GUIDE.md` — single comprehensive user guide for both `eth-deposit-gen` and `eth-deposit-tx`: install, quickstart, full command reference, networks, exit codes, security, recipes, troubleshooting.
- Repo-level `README.md` updated to list both tools and the end-to-end flow.

#### Known Limitations

- Ledger heuristics (`isUserRejectedErr`, `isChainIDMismatchErr`) are pattern-based string matches on go-ethereum APDU error codes; not yet validated against all firmware versions on real hardware. Tracked for v0.2.0.
- CGO is required (go-ethereum `usbwallet` and `herumi/bls-eth-go-binary`). Pure-Go / `CGO_ENABLED=0` builds are not supported.
- Windows is not supported (no CI runner; operator use case is Linux/macOS only).
- Goroutine leak on context-cancelled Ledger sign: the APDU exchange goroutine runs until the device responds or times out (accepted trade-off; single-invocation, bounded).

---

## eth-deposit-gen

### [eth-deposit-gen 1.0.0] - 2026-05-17

#### Added

- **Networks:** Hoodi testnet support (fully enabled, golden-tested). Mainnet support enabled behind `--i-understand-this-is-mainnet` safety gate; the flag and an uppercase `MAINNET` banner are required before any mainnet signing occurs.
- **`--keystore-dir`:** Directory-based keystore loading; scans a directory of EIP-2335 v4 keystores and loads only the keystore matching each requested pubkey — no decryption of unneeded files.
- **`--parallel N`:** Bounded parallel signing worker pool (default 1); deterministic output order regardless of parallelism level; benchmarked at ≥ 200 entries/sec.
- **`--dry-run`:** Print deposit JSON to stdout without writing a file; sha256 on stderr matches stdout bytes.
- **`--verbose` / `--json-logs`:** Structured `log/slog` logging; text or JSON handler; signing-critical packages contain zero log statements.
- **`--verify-with-deposit-cli`:** Optional post-generation cross-check via `deposit verify --input-file` (requires `staking-deposit-cli >= 2.7.0`).
- **Progress indicator:** `signing: <i>/<n>` on TTY stderr for batches > 5; 10%-boundary `slog.Info` on non-TTY.
- **Exit codes:** 0 success, 2 configuration/user errors, 3 crypto/verification failures, 4 SIGINT.
- **Pre-built binaries:** darwin/amd64, darwin/arm64, linux/amd64, linux/arm64 with `checksums.txt` and per-artifact SBOM (SPDX 2.3).

#### Security

- Internal audit signed off 2026-05-17: SSZ chunk tables, BLS boundary sizes (pubkey 48 bytes, signature 96 bytes, secret 32 bytes), 10-step deposit pipeline, zeroization on every error path, atomic output write (temp + fsync + rename). (Audit document removed in subsequent docs cleanup; commit history preserves it.)
- `GOFLAGS=-mod=readonly` enforced in all CI jobs (both `eth-deposit-gen.yml` and `release.yml`).
- Atomic file write: `.tmp` file + `f.Sync()` + `os.Rename` — no partial file is ever visible to the OS.
- BLS secret key zeroized immediately after signing via `key.Zeroize()`; passphrase bytes zeroized via `defer zeroizeBytes` with `runtime.KeepAlive` guard.

---

[eth-deposit-tx 0.1.0]: https://github.com/rootwarp/eth-utils/releases/tag/eth-deposit-tx/v0.1.0
[eth-deposit-gen 1.0.0]: https://github.com/rootwarp/eth-utils/releases/tag/v1.0.0
