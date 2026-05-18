# eth-deposit-gen v1.0.0

Generate Launchpad-compatible `deposit_data` JSON for existing BLS validator keys — without touching your mnemonic.

---

## What's in v1.0.0

### Networks supported

- **Hoodi testnet** — fully enabled and golden-tested against an internal self-consistency fixture
- **Mainnet** — enabled behind an explicit acknowledgement flag (`--i-understand-this-is-mainnet`); the flag is required and must be passed to proceed; absent it, the tool exits with code 2 and prints a clear error before any signing occurs

### Operator features

- **Directory-based keystore loading** (`--keystore-dir`) — scan a directory of EIP-2335 v4 keystores; load only the keystore matching each requested pubkey, without decrypting the others
- **Parallel signing** (`--parallel N`, default 1) — bounded worker pool for large batches; output order is deterministic regardless of parallelism level; benchmarked at ≥ 200 entries/sec on darwin/arm64 and linux/amd64
- **Dry-run mode** (`--dry-run`) — print the deposit JSON to stdout without writing a file; the sha256 on stderr matches the bytes written to stdout
- **Structured logging** (`--verbose`, `--json-logs`) — `log/slog`-based; text or JSON handler; signing-critical packages (`internal/ssz`, `internal/bls`, `internal/deposit`) contain zero log statements
- **Cross-check with staking-deposit-cli** (`--verify-with-deposit-cli`) — optional post-generation check that shells out to `deposit verify --input-file`; requires `staking-deposit-cli >= 2.7.0`
- **Progress indicator** — for batches > 5 pubkeys: `signing: <i>/<n>` on TTY stderr; 10%-boundary `slog.Info` events on non-TTY; suppressed for ≤ 5 entries
- **Mainnet safety gate** — the `--i-understand-this-is-mainnet` flag and an uppercase `MAINNET` banner are required before any mainnet signing proceeds

### Quality

- Golden-file tests for both Hoodi and mainnet, validated for internal self-consistency against the full pipeline (keystore → BLS → SSZ → JSON) using the same algorithms and field layout as `staking-deposit-cli` 2.7.0
- `TestNoSlogImportInSigningPackages` — source-level lint asserting that `log/slog` is never imported by signing-critical packages
- `TestRunWithDeps_NoSecretInLogs` — asserts that no passphrase or secret key byte appears in any log line at any level
- Fuzz targets for `merkleize`, `uint64Chunk`, and pubkey parsing
- Internal audit covering SSZ chunk tables, BLS boundary sizes, 10-step pipeline, zeroization paths, and output atomicity; signed off as of 2026-05-17

### Distribution

- Pre-built binaries for darwin/amd64, darwin/arm64, linux/amd64, linux/arm64
- SHA-256 `checksums.txt` for all archives
- SBOM (SPDX 2.3) per artifact: `eth-deposit-gen_{os}_{arch}.sbom.spdx.json`
- `go install` supported (requires CGO toolchain; see Install below)

---

## Install

### go install (requires CGO toolchain)

```bash
CGO_ENABLED=1 go install github.com/rootwarp/eth-utils/go/cmd/eth-deposit-gen@v1.0.0
```

On macOS, `CGO_ENABLED=1` is the default. On Linux you need `gcc` or `clang` in `PATH`.

### Pre-built binary

Download the archive for your platform from the assets below, then verify and extract:

```bash
# Example: darwin/arm64
tar -xzf eth-deposit-gen_darwin_arm64.tar.gz
shasum -a 256 -c checksums.txt  # verify before running
./eth-deposit-gen --version
```

---

## Links

- [User Guide](go/docs/USER-GUIDE.md)
- [Changelog](CHANGELOG.md)

---

## Acknowledgements

This tool is designed to produce output byte-compatible with [ethereum/staking-deposit-cli](https://github.com/ethereum/staking-deposit-cli).
