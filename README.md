# eth-utils

Ethereum utility CLIs for validator operations — generating BLS keystores,
building, signing, and broadcasting Beacon Chain deposit transactions from
Launchpad-compatible deposit data.

## Tools

| Tool | Description |
|------|-------------|
| `eth-deposit` | End-to-end deposit pipeline: `key` (new/recover keystores), `gen` (deposit data), `build`/`sign`/`run`/`send` (Ethereum tx) |

The repository is a Rust workspace. `eth-deposit` began as a Go tool and was
ported to Rust with behavioral parity on the deposit-tx path — same exit-code
contract (0–5), byte-identical outputs on the shared golden fixtures — then
extended with nested `key new` / `key recover` and a required
`--withdrawal-address` on `gen`. The Go and Python trees have been removed; see
[CHANGELOG.md](CHANGELOG.md) for the history and `docs/plan/` for the migration
and keygen plans.

See the [User Guide](docs/USER-GUIDE.md) for installation, command reference,
security guidance, recipes, and troubleshooting.

## Quickstart

Typical end-to-end flow:

```bash
# Step 0: create EIP-2335 validator keystores (TTY ceremony; write down the mnemonic)
mkdir -p ./keystores ./out
export KEYSTORE_PASS=...
eth-deposit key new --output-dir ./keystores --count 1 --passphrase-env KEYSTORE_PASS
# note the BLS pubkey from the summary

# Step 1: generate deposit data (withdrawal address must be EIP-55 checksummed)
eth-deposit gen --network hoodi --keystore-dir ./keystores \
  --pubkeys 0x<your-pubkey> \
  --withdrawal-address 0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1 \
  --output-dir ./out --passphrase-env KEYSTORE_PASS
unset KEYSTORE_PASS

# Step 2: build and sign the deposit transaction
eth-deposit run --network hoodi --input-file ./out/deposit_data-*.json \
  --signer local --output signed.json

# Step 3: broadcast
eth-deposit send --input signed.json --rpc-url https://hoodi.example/rpc
```

`key recover` rebuilds keystores from an existing mnemonic (TTY prompt or piped
stdin). Prefer `--mnemonic-passphrase-env` or a bare `--mnemonic-passphrase`
prompt over raw `--mnemonic-passphrase VALUE` (visible in `ps` / shell history).

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
| Validator keygen | out of band (e.g. staking-deposit-cli) | nested `eth-deposit key new` / `key recover` (BIP-39 → EIP-2333/2335) |
| `gen` withdrawal credentials | fixed placeholder path in the port era | **required** `--withdrawal-address` (EIP-55 checksummed) → real 0x01 creds; absent → exit 2 |
| EIP-55 on addresses | n/a for gen withdrawal | `--withdrawal-address` is **strict** EIP-55; `build`/`run` `--from` remains **lenient** (any-case 20-byte hex) |

## Repository structure

| Path | Contents |
|---|---|
| `crates/core` | SSZ hash-tree-root, network params, blst BLS, BIP-39/HD, deposit generator (verify-before-write), Launchpad JSON writers |
| `crates/keystore` | EIP-2335 v4 encrypt/decrypt (scrypt/pbkdf2 + AES-128-CTR), directory index, passphrase sources |
| `crates/tx` | deposit() ABI packing, EIP-1559 builder (offline + RPC), JSON-RPC client, URL redaction |
| `crates/signer` | local secp256k1 signer (hand-rolled RLP + keccak, EIP-55 encode + strict validate), Ledger signer |
| `bins/eth-deposit` | the CLI: `key` + five deposit subcommands, exit-code map, logging |
| `docs/` | [User Guide](docs/USER-GUIDE.md) and the Go→Rust / keygen plans (`docs/plan/`) |
| `testdata/` | golden fixtures (synthetic keys only, safe to commit) |
| `scripts/devnet/` | Dockerized local execution+consensus devnet for end-to-end testing |

## License

MIT — see [LICENSE](LICENSE).
