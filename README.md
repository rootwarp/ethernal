# eth-utils

Ethereum utility CLIs for validator operations — building, signing, and broadcasting
Beacon Chain deposit transactions from Launchpad-compatible deposit data.

## Tools

| Tool | Description |
|------|-------------|
| `eth-deposit` | Generate deposit data, then build, sign, and broadcast Ethereum Beacon Chain deposit transactions (`gen`/`build`/`sign`/`run`/`send` subcommands) |

The repository is a Rust workspace. `eth-deposit` began as a Go tool and was
ported to Rust with behavioral parity — same five subcommands, same exit-code
contract (0–5), byte-identical outputs on the shared golden fixtures. The Go
and Python trees have been removed; see [CHANGELOG.md](CHANGELOG.md) for the
history and `docs/plan/` for the migration plan.

See the [User Guide](docs/USER-GUIDE.md) for installation, command reference,
security guidance, recipes, and troubleshooting.

## Quickstart

Typical end-to-end flow:

```bash
# Step 1: generate deposit data from your validator keystores
eth-deposit gen --network hoodi --keystore-dir ./keystores \
  --pubkeys 0x<your-pubkey> --output-dir ./out

# Step 2: build and sign the deposit transaction
eth-deposit run --network hoodi --input-file ./out/deposit_data-*.json \
  --signer local --output signed.json

# Step 3: broadcast
eth-deposit send --input signed.json --rpc-url https://hoodi.example/rpc
```

## Build & test

```sh
make build         # release binary at target/release/eth-deposit
make test          # workspace test suite
make lint          # clippy -D warnings + rustfmt check
make e2e-mock      # E2E tests (build+sign+send via mock broadcaster, no real RPC)
```

Ledger hardware support is feature-gated:

```sh
cargo build --release --features ledger
```

Without the feature, `--signer ledger` fails with exit code 3 and a message
pointing at the flag. The HID/APDU transport is compile-verified only —
validate on real hardware before any real-fund use.

## Documented divergences from the retired Go implementation

| Area | Go (retired) | Rust |
|---|---|---|
| `ws://` RPC endpoints | supported via geth ethclient | not supported (http/https only); dial fails with a clear exit-5 error |
| Wei quantities | `big.Int` (unbounded) | `u128` — values ≥ 2^128 wei rejected as invalid (≈ 3.4e20 ETH, unreachable in practice) |
| Log timestamps | slog, local time | UTC (`Z`); log *format* otherwise slog-like |
| RPC URL redaction | scrubbed at the log boundary (`RedactURLString`) | redacted **by construction** — no error type ever stores a raw URL |
| Ledger gating | CGO build tag | `ledger` cargo feature |
| `--receipt-timeout` | full Go `time.ParseDuration` | `ms`/`s`/`m`/`h` suffixes only |
| Broadcast tx hash | recomputed locally from the decoded tx | taken from the node's `eth_sendRawTransaction` response (same value) |

## Repository structure

| Path | Contents |
|---|---|
| `crates/core` | SSZ hash-tree-root, network params, blst BLS, deposit generator (verify-before-write), Launchpad JSON writers |
| `crates/keystore` | EIP-2335 v4 decrypt (scrypt/pbkdf2 + AES-128-CTR), directory index, passphrase sources |
| `crates/tx` | deposit() ABI packing, EIP-1559 builder (offline + RPC), JSON-RPC client, URL redaction |
| `crates/signer` | local secp256k1 signer (hand-rolled RLP + keccak, EIP-55), Ledger signer |
| `bins/eth-deposit` | the CLI: five subcommands, exit-code map, logging |
| `docs/` | [User Guide](docs/USER-GUIDE.md) and the Go→Rust migration plan (`docs/plan/`) |
| `testdata/` | golden fixtures (synthetic keys only, safe to commit) |
| `scripts/devnet/` | Dockerized local execution+consensus devnet for end-to-end testing |

## License

MIT — see [LICENSE](LICENSE).
