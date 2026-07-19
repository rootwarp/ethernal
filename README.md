# ethernal

**Deposit ETH to run an Ethereum validator — safely, from the command line.**

`ethernal` walks you through the whole deposit, one clear step at a time: create
your keys, produce the Launchpad deposit data, build and sign the deposit
transaction (hardware wallet recommended), and broadcast it. It can also create
ordinary wallet (EOA) keystores that geth, Foundry, and MetaMask can import.

```text
create keys  →  deposit data  →  unsigned tx  →  signed tx  →  broadcast
  key new           gen            build           sign          send
                                    └──────── run ────────┘
```

**New here? This page is the introduction — start below, then follow the
[User Guide](docs/USER-GUIDE.md) for the full walkthrough, every flag, and the
security details.**

## Is this for me?

Use `ethernal` if you want to run one or more Ethereum validators and would
rather stay on the command line — with your validator mnemonic written down
offline and your deposit signed on a Ledger — than paste keys into a website.

You'll want:

- A **testnet** to practice on first (Hoodi). Never rehearse on mainnet.
- **~32 ETH per validator plus gas**, held by the account that signs the deposit.
- A **Ledger** for any real deposit (a local key is available, but for testing only).
- Rust installed (the tool builds from source — see below).

Already have EIP-2335 validator keystores from another tool? Skip key creation
and hand them straight to `ethernal gen`.

## The pieces

A validator deposit moves through three artifacts:

1. **Keystores** — your encrypted BLS validator keys (`ethernal key new`).
2. **Deposit data** — the Launchpad JSON, signed by your validator key (`ethernal gen`).
3. **A signed transaction** — sends 32 ETH to the deposit contract, signed by
   *your wallet* (`ethernal build` + `sign`, or `run`), then broadcast (`send`).

Two different keys are involved, and they never mix: the **BLS validator key**
stays inside its keystore and only signs the deposit *message*; the
**secp256k1 wallet key** (on your Ledger) signs the *transaction* that pays the
32 ETH. The [User Guide](docs/USER-GUIDE.md#concepts-and-workflow-model)
explains this model in full.

## Commands at a glance

| Command | What it does |
|---------|--------------|
| `ethernal key new` / `key recover` | Create / recover **BLS validator** keystores (EIP-2335) from a mnemonic |
| `ethernal account new` / `account recover` | Create / recover **wallet (EOA)** keystores (Web3 v3) for geth / Foundry / MetaMask |
| `ethernal gen` | Keystores → Launchpad `deposit_data` JSON |
| `ethernal build` | Deposit data → unsigned deposit transaction |
| `ethernal sign` | Sign the transaction (Ledger, or a local key for testing) |
| `ethernal run` | `build` + `sign` in one step |
| `ethernal send` | Broadcast the signed transaction |

Full flags, examples, and exit codes are in the
[User Guide](docs/USER-GUIDE.md).

## Install

Builds from source; no prebuilt binaries yet.

```bash
git clone https://github.com/rootwarp/ethernal.git
cd ethernal
make build                    # → target/release/ethernal
```

For a real deposit, build with Ledger support:

```bash
cargo build --release --features ledger
```

You need a stable Rust toolchain and a C compiler (for the `blst` BLS library).
Windows is not supported. Linux needs `libudev-dev` (or equivalent) and
[Ledger udev rules](https://github.com/LedgerHQ/udev-rules) before the `ledger`
feature will build. Platform-by-platform notes are in the
[User Guide](docs/USER-GUIDE.md#install).

## Your first deposit (on a testnet)

The shortest path is the guide's **[Quick start
(Hoodi)](docs/USER-GUIDE.md#quick-start-hoodi-testnet)** — create a keystore,
generate deposit data, then `run` and `send`. Practice the whole flow on Hoodi
before you ever point it at mainnet.

A one-look preview of the core steps:

```bash
ethernal key new --output-dir ./keystores --count 1 --passphrase-env KEYSTORE_PASS
ethernal gen  --network hoodi --keystore-dir ./keystores --pubkeys 0x<pubkey> \
  --withdrawal-address 0x<your-eip55-address> --output-dir ./out --passphrase-env KEYSTORE_PASS
ethernal run  --network hoodi --signer ledger --input-file ./out/deposit_data-*.json --output signed.json
ethernal send --input signed.json --rpc-url https://your-hoodi-rpc
```

`--signer ledger` needs the `--features ledger` build; to rehearse on testnet
from the quick `make build`, use `--signer local` with a throwaway key (see the
guide's [local-signer note](docs/USER-GUIDE.md#option-a--local-private-key-testing-only)).

## Please read this before mainnet

`ethernal` has guardrails, but the irreversible parts are on you:

- **Mainnet deposits cannot be undone.** `gen --network mainnet` refuses to run
  without `--i-understand-this-is-mainnet`. Rehearse on Hoodi first.
- **Your mnemonic is the master key.** `key new` / `account new` show it once, on
  the terminal only, and clear the screen afterward. Write it down offline —
  never screenshot it, paste it into chat, or store it in the cloud.
- **Verify on the Ledger screen before you confirm.** Check the chain ID, the
  deposit-contract address, and that the value is exactly 32 ETH. If anything
  looks off, reject on the device.
- **The local signer is for testing only** — use a Ledger for real funds.

The [Security](docs/USER-GUIDE.md#security) section covers the threat model, key
handling, and air-gapped signing.

## Documentation

- **[User Guide](docs/USER-GUIDE.md)** — the comprehensive reference: full
  walkthrough, every command and flag, networks, exit codes, security, recipes,
  and troubleshooting.
- Key creation: [BLS validator keys](docs/USER-GUIDE.md#create-bls-validator-keys-ethernal-key)
  · [EOA keystores](docs/USER-GUIDE.md#create-eoa-keystores-ethernal-account)
  · [which to use](docs/USER-GUIDE.md#key-creation-overview)
- [CHANGELOG.md](CHANGELOG.md) — history, and divergences from the retired Go port.

## Build & test

```sh
make build         # release binary at target/release/ethernal
make test          # workspace unit + integration tests
make lint          # clippy -D warnings + rustfmt check
make e2e-mock      # build+sign+send via mock broadcaster (no real RPC)
```

Without `--features ledger`, `--signer ledger` exits `3` with a message pointing
at the flag. The HID/APDU path is compile-verified only — validate on real
hardware before any real-fund use.

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

## Status & license

Unreleased (`0.1.0`). Formerly the `eth-deposit` binary in the `eth-utils`
repository — see [CHANGELOG.md](CHANGELOG.md) for the rename and history.

MIT — see [LICENSE](LICENSE).
