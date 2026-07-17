# eth-deposit (Rust)

The Rust port of the `eth-deposit` CLI: generate, build, sign, and broadcast
Ethereum Beacon Chain deposit transactions. Ported from `go/` with behavioral
parity — same five subcommands (`gen`, `build`, `sign`, `run`, `send`), same
exit-code contract (0–5), byte-identical outputs on the shared golden fixtures.

See `docs/plan/issues/overview.md` for the migration plan and
`docs/plan/porting-conventions.md` for the parity rules. The Go tree remains
the reference implementation until retirement (see the decision record in the
overview); `make diff-go` cross-checks both binaries on identical inputs.

## Build & test

```sh
make build         # release binary at target/release/eth-deposit
make test          # workspace test suite
make lint          # clippy -D warnings + rustfmt check
make diff-go       # byte-identity harness vs go/bin/eth-deposit
```

Ledger hardware support is feature-gated (parity with the Go tree's CGO gate):

```sh
cargo build --release --features ledger
```

Without the feature, `--signer ledger` fails with exit code 3 and a message
pointing at the flag. The HID/APDU transport is compile-verified only —
validate on real hardware before any real-fund use.

## Usage

Identical to the Go binary — see `go/docs/USER-GUIDE.md`. Quick example:

```sh
ETH_DEPOSIT_PASSPHRASE=... eth-deposit gen \
  --network hoodi \
  --keystore-dir ./keystores \
  --pubkeys 0x8420...3fb9 \
  --passphrase-env ETH_DEPOSIT_PASSPHRASE \
  --output-dir ./out
```

## Documented divergences from the Go implementation

| Area | Go | Rust |
|---|---|---|
| `ws://` RPC endpoints | supported via geth ethclient | not supported (http/https only); dial fails with a clear exit-5 error |
| Wei quantities | `big.Int` (unbounded) | `u128` — values ≥ 2^128 wei rejected as invalid (≈ 3.4e20 ETH, unreachable in practice) |
| Log timestamps | slog, local time | UTC (`Z`); log *format* otherwise slog-like |
| RPC URL redaction | scrubbed at the log boundary (`RedactURLString`) | redacted **by construction** — no error type ever stores a raw URL |
| Ledger gating | CGO build tag | `ledger` cargo feature |
| `--receipt-timeout` | full Go `time.ParseDuration` | `ms`/`s`/`m`/`h` suffixes only |
| Broadcast tx hash | recomputed locally from the decoded tx | taken from the node's `eth_sendRawTransaction` response (same value) |

## Workspace layout

| Crate | Ports | Contents |
|---|---|---|
| `crates/core` | `internal/{ssz,network,bls,deposit,output}` | SSZ hash-tree-root, network params, blst BLS, deposit generator (verify-before-write), Launchpad JSON writers |
| `crates/keystore` | `internal/keystore` | EIP-2335 v4 decrypt (scrypt/pbkdf2 + AES-128-CTR), directory index, passphrase sources |
| `crates/tx` | `internal/tx` | deposit() ABI packing, EIP-1559 builder (offline + RPC), JSON-RPC client, URL redaction |
| `crates/signer` | `internal/signer` | local secp256k1 signer (hand-rolled RLP + keccak, EIP-55), Ledger signer |
| `bins/eth-deposit` | `cmd/eth-deposit` + `internal/cli` | the CLI: five subcommands, exit-code map, logging |
