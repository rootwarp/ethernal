# ethernal

CLI for Ethereum validator deposits: BIP-39 keystores → Launchpad deposit data →
signed Beacon Chain deposit transaction → broadcast. Also generates Web3 v3 EOA
keystores (`account new|recover`) for geth / Foundry / MetaMask.

```text
mnemonic / keystores  →  deposit_data JSON  →  signed EIP-1559 tx  →  chain
     key new|recover           gen              build / sign / run      send

mnemonic  →  Web3 v3 EOA keystores (geth / cast / MetaMask)
  account new|recover
```

**Status:** unreleased (`0.1.0`). Formerly the `eth-deposit` binary in the
`eth-utils` repository — see [CHANGELOG.md](CHANGELOG.md) for the rename and
history.

Full command reference, security guidance, air-gapped recipes, and
troubleshooting: **[User Guide](docs/USER-GUIDE.md)**.

## Install

```bash
git clone https://github.com/rootwarp/ethernal.git
cd ethernal
make build                    # → target/release/ethernal
# optional Ledger HID support:
cargo build --release --features ledger
```

Requires a stable Rust toolchain and a C compiler (`blst`). Windows is not
supported. On Linux, enable the `ledger` feature only after installing
`libudev-dev` (or equivalent) and [Ledger udev rules](https://github.com/LedgerHQ/udev-rules).

## Subcommands

| Command | Purpose |
|---------|---------|
| `ethernal key new` | Fresh BIP-39 mnemonic (TTY ceremony) → EIP-2335 v4 scrypt BLS keystores |
| `ethernal key recover` | Existing mnemonic (TTY or stdin) → EIP-2335 BLS keystores |
| `ethernal account new` | Fresh BIP-39 mnemonic (TTY ceremony) → Web3 v3 EOA keystores |
| `ethernal account recover` | Existing mnemonic (TTY or stdin) → Web3 v3 EOA keystores |
| `ethernal gen` | EIP-2335 keystores → Launchpad `deposit_data` JSON (requires EIP-55 `--withdrawal-address`) |
| `ethernal build` | Deposit data → unsigned EIP-1559 deposit tx (offline or `--rpc-url`) |
| `ethernal sign` | Sign with Ledger (recommended) or local key (`ETHERNAL_TX_PRIVATE_KEY`) |
| `ethernal run` | `build` + `sign` in one shot |
| `ethernal send` | Broadcast signed tx (explicit network-name confirm) |

Exit codes: `0` ok · `1` internal · `2` bad input/config · `3` signer/crypto ·
`4` user abort · `5` broadcast/RPC.

## Quickstart (Hoodi)

```bash
mkdir -p ./keystores ./out
export KEYSTORE_PASS=...   # ≥ 8 bytes; prefer a dedicated shell session

# 0. Create EIP-2335 validator keystores (TTY-only; write down the mnemonic)
ethernal key new --output-dir ./keystores --count 1 --passphrase-env KEYSTORE_PASS
# note the BLS pubkey from the summary on stderr

# 1. Deposit data — withdrawal address must be EIP-55 checksummed
ethernal gen --network hoodi --keystore-dir ./keystores \
  --pubkeys 0x<your-pubkey> \
  --withdrawal-address 0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1 \
  --output-dir ./out --passphrase-env KEYSTORE_PASS
unset KEYSTORE_PASS

# 2. Build + sign (Ledger recommended for real funds)
ethernal run --network hoodi --input-file ./out/deposit_data-*.json \
  --signer ledger --output signed.json
# local signer (test only):
#   export ETHERNAL_TX_PRIVATE_KEY=0x...
#   ethernal run --network hoodi --input-file ./out/deposit_data-*.json \
#     --signer local --output signed.json
#   unset ETHERNAL_TX_PRIVATE_KEY

# 3. Broadcast
ethernal send --input signed.json --rpc-url https://hoodi.example/rpc
```

`key recover` / `account recover` rebuild keystores from an existing mnemonic
(TTY prompt or piped stdin). Prefer `--mnemonic-passphrase-env` or a bare
`--mnemonic-passphrase` prompt over raw `--mnemonic-passphrase VALUE` (visible
in `ps` / shell history).

`account` writes geth-style `UTC--…` **v3** files (BIP-44 `m/44'/60'/0'/0/i`);
`key` writes EIP-2335 **v4** BLS keystores. Do not pass v3 files to `gen`. v3
encryption uses the keystore passphrase as **raw UTF-8** (no NFKD), matching
geth/MetaMask — see [User Guide](docs/USER-GUIDE.md#create-eoa-keystores-ethernal-account).

## Build & test

```sh
make build         # release binary at target/release/ethernal
make test          # workspace unit + integration tests
make lint          # clippy -D warnings + rustfmt check
make e2e-mock      # build+sign+send via mock broadcaster (no real RPC)
```

Without `--features ledger`, `--signer ledger` exits `3` with a message pointing
at the flag. HID/APDU is compile-verified only — validate on real hardware
before any real-fund use.

## Repository layout

| Path | Contents |
|------|----------|
| `bins/ethernal` | CLI: subcommands, exit-code map, logging |
| `crates/ethernal-core` | SSZ HTR, network params, BLS, BIP-39/HD, deposit generator |
| `crates/ethernal-keystore` | EIP-2335 v4 + Web3 v3 encrypt/decrypt, directory index, passphrase sources |
| `crates/ethernal-tx` | `deposit()` ABI, EIP-1559 builder, JSON-RPC client, URL redaction |
| `crates/ethernal-signer` | Local secp256k1 + Ledger signers; strict EIP-55 validation |
| `docs/` | [User Guide](docs/USER-GUIDE.md), design/plan archive (`docs/plan/`) |
| `testdata/` | Golden fixtures (synthetic keys only) |
| `scripts/devnet/` | Docker EL+CL devnet for end-to-end testing |

## Notable details

| Topic | Behavior |
|-------|----------|
| Withdrawal credentials | `gen` **requires** `--withdrawal-address` (strict EIP-55) → real `0x01` creds; zero address rejected |
| `--from` (build only) | Lenient any-case 20-byte hex; `run` has no `--from` (sender from signing key) |
| `key` vs `account` | BLS EIP-2335 v4 (`key`) vs secp256k1 Web3 v3 (`account`); additive — `key`/`gen` surface unchanged |
| v3 keystore passphrase | Raw UTF-8 into scrypt (**no NFKD**); geth/MetaMask interop |
| Local private key | Env only (`ETHERNAL_TX_PRIVATE_KEY` by default) — never a CLI flag |
| RPC | `http`/`https` only (`ws://` rejected); API keys redacted from errors by construction |
| Wei quantities | `u128` (values ≥ 2^128 wei rejected) |

Documented divergences from the retired Go port (log timestamps UTC, receipt
timeout suffixes, broadcast hash from the node response, etc.) are listed in
[CHANGELOG.md](CHANGELOG.md) and the migration notes under `docs/plan/`.

## License

MIT — see [LICENSE](LICENSE).
