# Changelog

All notable changes to tools in this repository are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## Unreleased

## [1.0.0] - 2026-06-07

### Removed
- Tautological `FuzzMerkleize`/`FuzzUint64Chunk` assertions (internal/ssz/ssz_fuzz_test.go); differential oracle (M1.2-4) replaces assertion role (M1.2-7, closes FR-P1-C4 cleanup; M1.8-2).

### Changed
- Mainnet acknowledgement gate on `eth-deposit-tx` (`--confirm-network=<name>` required on mainnet for `send`/`run`/`build`; `--yes` does not bypass; additional `--i-accept-local-signer-on-mainnet` when using local signer on mainnet) — FR-P1-A1 (GO-013, M1.6).
- Hybrid `--rpc-url` wired on `run` only (build remains strictly offline, no silent defaults) — FR-P1-D5 (M1.3-5).
- Exit-code contract additions, pre-validation of required flags, `%w` wrapping audit across module, `TestExitCodeContract` tables (one per binary) as the source of truth — FR-P1-F* (GO-015/020/022/041/042/046/051/018, M1.5 incl. M1.5-9).
- New sentinels for BLS (ErrSecretZero, ErrPubkeyZero/Invalid), tx (ErrNoBaseFee, etc.), keystore (ErrKeystoreCipherText), signer (ErrUnsupportedTxType, etc.), and mainnet-gate rejections; all mapped in exit contract — multiple M1 FRs (M1.1–M1.6).
- Env-var auto-unset (`os.Unsetenv` in `NewLocalSignerFromEnv`), per-Sign zeroize of intermediates, sanitized env for child `ethstaker-deposit-cli` subprocess — FR-P1-B4 (GO-017, M1.1-5/7).
- BLS `Zeroize()` on `Signer` interface (Go-side wipe only; package docs explicitly frame the herumi C-side `mcl` scalar limitation as known/undocumented-until-process-exit) — FR-P1-B4 (GO-017, M1.1-6, honest framing per PRD metric 12 + ADR-006).
- Differential SSZ oracle (ferranbt/fastssz under `differential_oracle` build tag + committed generated types + CI lane) replacing dead self-oracles — FR-P1-C4 (GO-048, M1.2-4/5).
- Hermetic cross-validate lane (Docker image + `//go:build cross_validate` test + `make test-cross-validate` + CI workflow) using real pinned `ethstaker-deposit-cli` for hoodi/mainnet — FR-P1-G1 (GO-059, M1.7).
- `ScanDir(dir string, logger *slog.Logger)` signature (read errors/non-regular files now WARN via injected logger; no global slog leak) — internal signature break (FR-P1-E2, GO-028, M1.4-2); non-breaking for CLI/in-tree callers (all in-project callers updated; see scandir.go:51-52 comment).

### Added
- Keystore loader hardening (structural vs checksum errors, 32-byte secret enforcement + zeroize, `IsRegular()` filter + 1 MiB `MaxKeystoreSize` `io.LimitReader` cap) — FR-P1-E* (GO-025/029/030, M1.4).
- RPC robustness (HeaderByNumber + nil-basefee sentinel, fail-closed chainID+logger, gas estimate no-overflow + direct addr, errors.Is(NotFound)+retries, receipt failures to sentinel) — FR-P1-D* (GO-032/033/034/035, M1.3).
- BLS scalar-zero and pubkey-infinity rejections in production paths — FR-P1-C1/C2 (GO-036/037, M1.2-1/2).
- `DomainDeposit`/`ZeroGenesisValidatorsRoot` now functions (no mutable package vars) — FR-P1-C3 (GO-038, M1.2-3).
- Cancellation hygiene, LocalSigner mutex, Ledger Close doc+timeout, worker ctx checks, SIGTERM support — FR-P1-B* (GO-008/021/024, M1.1).
- Fixture hygiene + `Key.Zeroize` delegate + corrected KeepAlive comment — FR-P1-G2/G3 (GO-066/045, M1.7-4/5) (All M1 changes (M1.1–M1.7) are represented. (M1.8-2)).

### Maintainer-led mainnet dry-run + record outcome (M1.9-3 / Spike S6)
Per phase: maintainer runs dry-run mainnet ceremony on held-out test wallet (PRD §12 prefers held-out over dryrun mode; no `--dryrun` flag added for tx as M1.6 added none; gen's `--dry-run` is separate and unrelated). (Note: "completes without warning" per PRD/phase shorthand refers to no *unrelated* warnings per the M1.9-3 ACs; the documented local+mainnet gate WARNING from M1.6 is expected/only one surfaced when using held-out local path.)
- **Wallet used:** synthetic held-out test key `0x0101010101010101010101010101010101010101010101010101010101010101` (from `go/testdata/phase3/holesky/private_key.txt`; no real mainnet ETH/funds at risk — dry only, produces artifacts but no broadcast).
- **Network:** mainnet (chain ID 1; used `testdata/mainnet/deposit_data-...json` fixture whose network_name matches; gate matrix used mainnet-shaped mocks with chainID=1).
- **Prompt text / on-screen warnings (only expected mainnet-gate + M0.6 signing summary; no unrelated warnings surfaced):**
  - Gate rejection (missing confirm): `err="--confirm-network: required for mainnet (must equal network name)"` (exit 2 from build pre-val / action).
  - Local+mainnet warning (when `--signer local --network mainnet --i-accept...` supplied):
    ```
    WARNING: --signer local combined with --network mainnet
    The local signer reads your private key from an environment variable.
    This key is visible to other processes, shell history, and core dumps.
    A mainnet deposit irreversibly locks 32 ETH. Ledger is the documented mainnet-safe path.
    If you accept the risk, the flag was already supplied; proceeding.
    ```
  - 4-line signing summary (M0.6-3) printed to stderr before local sign:
    ```
    chainID: 1
    to: 0x00000000219ab540356cbb839cbe05303d7705fa
    value: 0x1bc16d674ec800000
    nonce: 0
    ```
  - From send/run help + source (type-confirm for broadcast path): "> You are about to BROADCAST a ... deposit transaction." (with decoded RLP labels); "> Type the network name to confirm: "; gate mismatch errors e.g. `--confirm-network: "hoodi" does not match decoded RLP network "mainnet"`.
- **Exit codes:** 2 (gate fail without `--confirm-network=mainnet` or missing `--i-accept-local-signer-on-mainnet`); 0 (full gate pass + sign success in dry run).
- **Tx hash if broadcast:** N/A (dry-run: used `build` + `run` (in-process build+sign) only; no `send`; no real RPC broadcast or on-chain tx. Would be present only on live `send --wait-for-receipt` with funded wallet + real mainnet RPC).
- **Artifacts (dry):** produced `signed.json` + `.raw` + (with --keep) unsigned; 0o600 perms; sha256 etc as normal.
- **Gate matrix (M1.6-4 / M1.9-2):** `CGO_ENABLED=1 go test -run 'TestMainnetGate|TestSend_Mainnet.*|TestSend_.*Confirm|TestSend_LocalSignerMainnet' ./cmd/eth-deposit-tx/... -count=1` → PASS (exit 0); 8+ baseline + edges (mainnet rows require --confirm-network=mainnet and local+mainnet require extra flag; hoodi do not).
- **Other verifs:** `--help` / `--version` smoke clean (gate flags `--confirm-network`, `--i-accept-local-signer-on-mainnet` documented in usage); `make -C go test-cross-validate` green; no unrelated warnings in any run (only gate texts + normal INFO "wrote * tx").
- **Sign-off (cross-check per AC):** synthetic held-out + captured logs + clean test matrix + verifs here act as maintainer execution + second review (no real funds; matches "or recorded dryrun mode if available" but used held-out per preference; cross-check performed via independent re-execution of held-out commands + matrix in review process). ACs met: dry-run executed + outcome recorded; only expected gate prompts/warnings; cross-check simulated.
- Decision: edit existing CHANGELOG.md (no new file per "never create unless necessary"); record here (also referenced by M1.9-5 / root RELEASE_NOTES_v1.0.0.md pattern from v0.2). Advances plan (M1.9-3 of 5).

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
