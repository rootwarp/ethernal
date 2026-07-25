# ethernal User Guide

> **New here?** Start with the [README](../README.md) for the friendly
> introduction, then come back here. This is the comprehensive reference —
> every command, flag, exit code, and security detail.

Comprehensive guide for `ethernal`, the CLI in this repository that takes a
validator all the way from a BIP-39 mnemonic to a broadcast Ethereum deposit
transaction, and (separately) creates Web3 v3 EOA keystores:

- **`ethernal validator new|recover`** — generates or recovers EIP-2335 BLS validator keystores from a BIP-39 mnemonic (the front of the deposit pipeline).
- **`ethernal account new|recover`** — generates or recovers Web3 Secret Storage **v3** secp256k1 EOA keystores (geth / Foundry / MetaMask-importable); not part of the deposit steps.
- **`ethernal deposit gen|build`** — produces Launchpad-compatible deposit data JSON (BLS signatures over the deposit message) and constructs the unsigned deposit transaction.
- **`ethernal tx sign|run|send`** — signs (Ledger or local key), optionally builds+signs in one step, and broadcasts the Ethereum transaction that submits the deposit to the Beacon Chain deposit contract.

**Status:** unreleased (`0.1.0`), pending the first tag under the merged name.
`ethernal` is a Rust workspace that combines the formerly separate
`eth-deposit-gen` and `eth-deposit-tx` binaries; see [`CHANGELOG.md`](../CHANGELOG.md)
for the merge, the Go→Rust port, and the documented divergences.

---

## Table of contents

1. [Concepts and workflow model](#concepts-and-workflow-model)
2. [Command structure](#command-structure)
3. [Install](#install)
4. [Quick start (Hoodi testnet)](#quick-start-hoodi-testnet)
5. [Key creation overview](#key-creation-overview)
6. [Create BLS validator keys (`ethernal validator`)](#create-bls-validator-keys-ethernal-validator)
7. [Create EOA keystores (`ethernal account`)](#create-eoa-keystores-ethernal-account)
8. [Step 1 — Generate deposit data (`ethernal deposit gen`)](#step-1--generate-deposit-data-ethernal-deposit-gen)
9. [Step 2 — Build the unsigned transaction (`ethernal deposit build`)](#step-2--build-the-unsigned-transaction-ethernal-deposit-build)
10. [Step 3 — Sign the transaction (`ethernal tx sign`)](#step-3--sign-the-transaction-ethernal-tx-sign)
11. [Step 4 — Broadcast (optional) (`ethernal tx send`)](#step-4--broadcast-optional-ethernal-tx-send)
12. [Convenience: `ethernal tx run` (build + sign in one shot)](#convenience-ethernal-tx-run-build--sign-in-one-shot)
13. [Air-gapped workflow](#air-gapped-workflow)
14. [Networks](#networks)
15. [Exit codes](#exit-codes)
16. [Security](#security)
17. [Recipes](#recipes)
18. [Troubleshooting](#troubleshooting)

---

## Concepts and workflow model

A validator deposit takes three artifacts:

| Artifact | Produced by | Contains |
|---|---|---|
| **EIP-2335 keystores** | `ethernal validator new` / `validator recover` | Encrypted BLS signing keys (one JSON file per validator index) |
| **Deposit data JSON** | `ethernal deposit gen` | BLS-signed deposit message: validator pubkey, withdrawal credentials, signature, deposit_data_root, amount |
| **Signed Ethereum transaction** | `ethernal deposit build` / `tx sign` / `tx run` | EIP-1559 transaction calling the deposit contract's `deposit(bytes,bytes,bytes,bytes32)` with 32 ETH value, signed by the **sender's** secp256k1 key |

Separately, `ethernal account` produces **Web3 Secret Storage v3** keystores for ordinary Ethereum (EOA) accounts — the same format geth, Foundry (`cast`), and MetaMask import. These are **not** deposit-pipeline inputs; do not pass them to `deposit gen`.

Two distinct keys are involved in the deposit path:
- **BLS validator key** (per validator) — held in EIP-2335 keystores created by `ethernal validator` (or any compatible tool); used by `ethernal deposit gen` to sign the deposit message. Never leaves the keystore decryption boundary. See [Create BLS validator keys](#create-bls-validator-keys-ethernal-validator).
- **secp256k1 sender key** — held in your Ledger (recommended) or env var (testing only); used by `ethernal tx sign` / `tx run` to sign the Ethereum transaction that pays the 32 ETH. Whichever address holds this key needs ≥ 32 ETH + gas. (You can also create a local EOA keystore with `account new` / `account recover` for testing or wallet import; see [Create EOA keystores](#create-eoa-keystores-ethernal-account).)

The two-phase split (`deposit build` then `tx sign`) supports air-gapped operation: build the unsigned tx on an online machine, transfer the JSON to a signing machine (which may be offline), sign there, transfer the signed JSON back online, broadcast. Prefer generating BLS keys (`validator new`) on an air-gapped machine as well.

---

## Command structure

Commands are grouped into four namespaces:

| Namespace | What it groups |
|---|---|
| `validator` | EIP-2335 BLS keystores by role (`new` / `recover`) |
| `account` | Web3 v3 EOA keystores by role (`new` / `recover`) |
| `deposit` | Launchpad `deposit_data` (`gen`) and unsigned deposit-tx construction (`build`) |
| `tx` | Sign (`sign`), build+sign convenience (`run`), and broadcast (`send`) |

Typical pipeline:

```text
validator new  →  deposit gen  →  deposit build  →  tx sign  →  tx send
                                     └──────────── tx run ────────────┘
```

Environment variable names such as `ETHERNAL_TX_PRIVATE_KEY` (and other `ETHERNAL_TX_*` names) are retained unchanged.

---

## Install

### Requirements

- **Rust toolchain** (stable; install via https://rustup.rs). A C toolchain is needed for the `blst` BLS library (Xcode Command Line Tools on macOS, `build-essential` on Debian/Ubuntu).
- **Ledger support is opt-in.** The USB/HID transport is behind the `ledger` cargo feature; build with `--features ledger` to enable it. Without the feature, `--signer ledger` fails with exit code 3 and a message pointing at the flag; the rest of the binary still works.
- **Linux (with `ledger` feature)** — install `libudev-dev` (Debian/Ubuntu) or `systemd-devel` (Fedora/RHEL) so hidapi can build. For non-root device access, set up udev rules per https://github.com/LedgerHQ/udev-rules.
- **Windows** — not supported.

### Install from source

No prebuilt archives are published for the Rust binary yet — install from source:

```bash
git clone https://github.com/rootwarp/ethernal.git
cd ethernal
make build   # produces target/release/ethernal

# or, with Ledger hardware support:
cargo build --release --features ledger
```

Put `target/release` on your `PATH` (or copy the binary somewhere on it), then verify:

```bash
ethernal --version
```

---

## Quick start (Hoodi testnet)

End-to-end deposit on Hoodi using a Ledger:

```bash
# 0. Create validator keystores (interactive TTY ceremony — write down the mnemonic).
#    When the ceremony ends, ethernal clears the terminal screen + scrollback
#    automatically so the phrase does not linger; if that fails it warns and
#    continues. Inside tmux/screen also clear the multiplexer’s own history
#    (tmux: `tmux clear-history`; screen: C-a : then `scrollback 0`).
mkdir -p ./keystores ./out
export KEYSTORE_PASS=my-keystore-passphrase
ethernal validator new --output-dir ./keystores --count 1 --passphrase-env KEYSTORE_PASS
# note the pubkey printed in the summary, then:

# 1. Generate deposit data (withdrawal address must be EIP-55 checksummed)
ethernal deposit gen \
  --network hoodi \
  --keystore-dir ./keystores/ \
  --pubkeys 0x<pubkey-from-validator-new-summary> \
  --withdrawal-address 0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1 \
  --output-dir ./out \
  --passphrase-env KEYSTORE_PASS
unset KEYSTORE_PASS

# 2. Build unsigned tx (use --nonce explicitly if sender has prior txs)
ethernal deposit build \
  --network hoodi \
  --input-file ./out/deposit_data-*.json \
  --nonce 0 \
  --output ./out/unsigned_tx.json

# 3. Sign with Ledger (confirm on device)
ethernal tx sign \
  --signer ledger \
  --input ./out/unsigned_tx.json \
  --output ./out/signed_tx.json

# 4. Broadcast (will prompt to type "hoodi" to confirm)
ethernal tx send \
  --input ./out/signed_tx.json \
  --rpc-url https://your-hoodi-rpc-url \
  --wait-for-receipt
```

If you already have EIP-2335 keystores from another tool, skip BLS key creation and pass those paths to `deposit gen`. For a local-key dev flow, see the [recipes](#recipes) below.

---

## Key creation overview

`ethernal` can create two kinds of keys from a BIP-39 English mnemonic. They are **separate commands**, **separate keystores**, and **separate consumers** — do not mix directories.

| | **BLS validator keys** | **EOA account keys** |
|---|---|---|
| Commands | `ethernal validator new` / `validator recover` | `ethernal account new` / `account recover` |
| Curve / use | BLS12-381 validator signing | secp256k1 execution address (EOA) |
| HD path | EIP-2334 `m/12381/3600/i/0/0` | BIP-44 `m/44'/60'/0'/0/i` |
| Keystore format | EIP-2335 **v4** scrypt | Web3 Secret Storage **v3** scrypt |
| Filename | `keystore-m_12381_3600_<i>_0_0-<unix>.json` | `UTC--…--<40-hex-address>` |
| Passphrase KDF | EIP-2335 **NFKD**-normalized | **Raw UTF-8** (no NFKD) — geth/MetaMask |
| File mode | `0o600` | `0o600` |
| Summary prints | 96-hex BLS **pubkey** | EIP-55 **address** |
| Use with | Validator clients, `ethernal deposit gen` | geth, Foundry (`cast`), MetaMask, wallets |
| **Not** for | Wallet import / deposit-tx signing | `ethernal deposit gen` or validator clients |

**Same mnemonic, two trees.** One BIP-39 seed (plus optional 25th-word mnemonic passphrase) can derive **both** BLS and EOA keys. The secrets are unrelated; only the seed is shared. See [Recipe 6](#recipe-6--one-mnemonic--bls-and-eoa-keystores).

**Shared interaction model** (both namespaces):

| | `new` | `recover` |
|---|---|---|
| Mnemonic source | Fresh 24-word from OS CSPRNG | Existing 12–24-word phrase |
| Terminal | **TTY only** (stdin *and* stdout) | TTY prompt **or** piped stdin |
| Ceremony | Display once + full re-entry | None |
| On abort / mismatch | Exit 4; **nothing** written | N/A |

**Two different passphrases** (both commands):

1. **Keystore passphrase** — encrypts the JSON files (`--passphrase-env` or interactive prompt-with-confirm). Minimum **8 bytes**. There is no raw-argv form for this secret.
2. **Mnemonic passphrase** (optional BIP-39 “25th word”) — mixed into seed derivation only. Empty is valid; no minimum. Three forms: bare `--mnemonic-passphrase` (prompt), `--mnemonic-passphrase-env VAR`, or raw `--mnemonic-passphrase VALUE` (avoid for high-value keys — visible in `ps` / shell history).

They are never interchangeable. Prefer a dedicated shell session for keygen work; `unset` env vars when finished (`export VAR=secret` can also land in shell history).

---

## Create BLS validator keys (`ethernal validator`)

Use this when you need **EIP-2335** keystores for validators and the deposit pipeline (`ethernal deposit gen`). English BIP-39 only.

| Subcommand | Purpose | I/O |
|---|---|---|
| `validator new` | Fresh 24-word mnemonic + keystores | **TTY only** |
| `validator recover` | Keystores from an existing mnemonic | TTY prompt **or** piped stdin |

Each run writes one file per index into `--output-dir` (directory must already exist and be writable):

```text
keystore-m_12381_3600_<i>_0_0-<unix-seconds>.json
```

Derivation: signing path `m/12381/3600/i/0/0` (EIP-2333/2334).

### Flags

| Flag | Description | Default |
|---|---|---|
| `--output-dir DIR` *(required)* | Existing, writable directory for keystore JSON | — |
| `--count N` | Number of validator keys (≥ 1) | `1` |
| `--passphrase-env VAR` | Env var for **keystore** encryption passphrase (min 8 bytes after EIP-2335 normalization). Omit → TTY prompt-with-confirm | TTY prompt |
| `--mnemonic-passphrase [VALUE]` | Optional BIP-39 25th word. Bare → prompt; with `VALUE` → raw argv; omit → empty | empty |
| `--mnemonic-passphrase-env VAR` | Env var for the 25th word (empty string valid; unset → exit 2). Conflicts with `--mnemonic-passphrase` | — |
| `--start-index N` | **`validator recover` only.** First HD index; produces `[start, start+count)` | `0` |
| `--no-verify` | Skip the post-write keystore decrypt round-trip (C4) only. Derivation self-checks (C1–C3) always run and cannot be skipped. Halves wall-clock at the cost of the strongest correctness check. See [What is verified](#what-is-verified). | off (C4 on) |

`validator new` always starts at index `0` (no `--start-index`).

### Security notes (BLS)

- **Raw `--mnemonic-passphrase VALUE`** is visible in `ps` and shell history. Prefer `--mnemonic-passphrase-env` or bare `--mnemonic-passphrase` (on `validator new`, bare form is **double-entry** confirm). Scripting convenience only — not for high-value mnemonics.
- Keystore passphrase is **NFKD-normalized** for EIP-2335 (different from EOA v3 — see [EOA interop note](#interop-note--v3-keystore-passphrase-is-raw-no-nfkd)).

#### What is verified

Every key from `validator new` and `validator recover` is checked before it is treated as done. Three cheap derivation self-checks always run **before** the file is written; a fourth decrypt round-trip runs **after** writing by default.

| Check | When | Cost | Skippable |
|---|---|---|---|
| secret → public-key consistency (C1) | before writing | negligible | no |
| public-key point validity (C2) | before writing | negligible | no |
| sign/verify round trip (C3) | before writing | ~2 ms | no |
| decrypt the written file and compare secret **and** `pubkey` field (C4) | after writing | ~0.3 s (a second scrypt) | `--no-verify` |

**Wall-clock.** Encrypting one EIP-2335 keystore is one scrypt; C4 is a second scrypt at the same cost. Verification therefore roughly **doubles** the time per key — about **0.6 s instead of 0.3 s** on a modern laptop. Measured pure-scrypt cost is **≈ 310 ms** per call (`ScryptParams::STANDARD`, release build) on **Apple Silicon**; expect proportionally more on older servers or air-gapped boxes (realistically 2–4×). For `--count 100` that is roughly **one minute instead of thirty seconds**.

**What `--no-verify` does *not* skip.** C1–C3 always run. Skipping C4 only means a bad write (corrupt file, wrong ciphertext, mismatched `pubkey` field) is discovered only when the key is next loaded — possibly after the deposit is already on-chain. Prefer the default path for any mainnet or high-value ceremony; use `--no-verify` only when you accept that trade-off (e.g. bulk recovery on trusted hardware where wall-clock dominates).

### `validator new` — create a new BLS key set

```bash
ethernal validator new --output-dir DIR [--count N] [--passphrase-env VAR] \
  [--mnemonic-passphrase [VALUE] | --mnemonic-passphrase-env VAR] [--no-verify]
```

**Flow**

1. **Non-TTY guard** — if stdin or stdout is not a terminal, exit **2** before any entropy is drawn.
2. **Entropy → mnemonic** — 256-bit OS CSPRNG → 24-word English BIP-39 with checksum.
3. **Mnemonic passphrase** — flag / env / prompt-with-confirm / empty.
4. **Ceremony** — mnemonic displayed **once** on the controlling terminal (`/dev/tty` only — never stdout/stderr/logs). Write it down offline, then re-enter the full phrase. Mismatch → retry or abort (exit **4**); nothing on disk until re-entry succeeds.
5. **Automatic scrollback clear** — as soon as the ceremony ends (confirmed **or** aborted), the screen **and scrollback** of the controlling terminal are cleared (ANSI `2J`/`3J`/`H`, written twice) so the mnemonic does not stay readable to anyone scrolling back later — the one leak every deposit-cli audit found. If the clear fails, `ethernal` continues (fail-open) but warns loudly: clear manually (e.g. `clear && printf '\x1b[3J'`, or Cmd+K in Terminal.app) before leaving the machine. **tmux/screen caveat:** the multiplexer keeps its **own** scrollback buffer that ANSI sequences cannot reach — clear it there too (tmux: `tmux clear-history`; screen: C-a : then `scrollback 0`).
6. **Keystore passphrase** — env (min 8) or interactive confirm.
7. **Derive → self-check (C1–C3) → encrypt → write → verify (C4)** — path `m/12381/3600/i/0/0` for `i` in `0..count`; EIP-2335 scrypt keystores at `0o600`. C4 decrypts each written file and re-compares secret and `pubkey` unless `--no-verify` is set (see [What is verified](#what-is-verified)).

**Progress output.** On a terminal, stderr shows a live phase line per key (`deriving` / `checking` / `encrypting` / `writing` / `verifying`) that is erased before each durable `keystore i/N:` line, so scrollback shape is unchanged. When stderr is piped (non-TTY), the transient line is not drawn; structured log events fire per completed key (including `verified=full` or `verified=derived-only`). Scripts parsing stderr therefore see only the existing durable `keystore i/N:` lines — no `\r` or CSI escape sequences.

**Example**

```bash
mkdir -p ./keystores
export KEYSTORE_PASS=my-keystore-passphrase

# One validator
ethernal validator new \
  --output-dir ./keystores \
  --count 1 \
  --passphrase-env KEYSTORE_PASS

# Two validators + optional 25th word (env form preferred)
export MNEMONIC_PW=...
ethernal validator new \
  --output-dir ./keystores \
  --count 2 \
  --mnemonic-passphrase-env MNEMONIC_PW \
  --passphrase-env KEYSTORE_PASS
unset MNEMONIC_PW KEYSTORE_PASS
```

### `validator recover` — recreate BLS keys from a mnemonic

```bash
ethernal validator recover --output-dir DIR [--count N] [--start-index N] \
  [--passphrase-env VAR] \
  [--mnemonic-passphrase [VALUE] | --mnemonic-passphrase-env VAR] [--no-verify]
```

No display/re-entry ceremony — the mnemonic already exists. Accepts **12 / 15 / 18 / 21 / 24** English words (wordlist + checksum validated first; bad input → exit **2**). Interactive prompt when stdin is a TTY; otherwise one line from stdin.

```bash
# Interactive
ethernal validator recover \
  --output-dir ./keystores \
  --count 3 \
  --start-index 0 \
  --passphrase-env KEYSTORE_PASS

# Piped (automation)
echo "$MNEMONIC" | ethernal validator recover \
  --output-dir ./keystores \
  --count 1 \
  --passphrase-env KEYSTORE_PASS

# Extend an existing set (e.g. next index after 0..2)
ethernal validator recover --output-dir ./keystores --start-index 3 --count 1 \
  --passphrase-env KEYSTORE_PASS
```

### After BLS key creation

Stderr summary lists each path and its **96-hex-char BLS pubkey**. Next steps for a deposit:

1. Copy the pubkey(s) from the summary.
2. Run [`ethernal deposit gen`](#step-1--generate-deposit-data-ethernal-deposit-gen) with `--keystore-dir` and `--pubkeys`.

Keep the mnemonic offline only. Never paste it into chat, tickets, or cloud notes.

---

## Create EOA keystores (`ethernal account`)

Use this when you need a **software EOA** encrypted as a standard Web3 **v3** keystore (geth / Foundry / MetaMask). This is **not** the deposit-pipeline keystore format — never pass these files to `ethernal deposit gen`.

| Subcommand | Purpose | I/O |
|---|---|---|
| `account new` | Fresh 24-word mnemonic + v3 keystores | **TTY only** |
| `account recover` | v3 keystores from an existing mnemonic | TTY prompt **or** piped stdin |

Each run writes one geth-style file per BIP-44 address index into `--output-dir`:

```text
UTC--<YYYY-MM-DDTHH-MM-SS.nnnnnnnnnZ>--<40-hex-address-no-0x>
```

Derivation: `m/44'/60'/0'/0/i` (Ethereum BIP-44; `account'` fixed at `0'`).

### Flags

| Flag | Description | Default |
|---|---|---|
| `--output-dir DIR` *(required)* | Existing, writable directory for keystore JSON | — |
| `--count N` | Number of EOA keystores (≥ 1) | `1` |
| `--passphrase-env VAR` | Env var for **keystore** encryption passphrase (min 8 bytes). Omit → TTY prompt-with-confirm | TTY prompt |
| `--mnemonic-passphrase [VALUE]` | Optional BIP-39 25th word. Bare → prompt; with `VALUE` → raw argv; omit → empty | empty |
| `--mnemonic-passphrase-env VAR` | Env var for the 25th word (empty valid; unset → exit 2). Conflicts with `--mnemonic-passphrase` | — |
| `--start-index N` | **`account recover` only.** First address index; produces `[start, start+count)` | `0` |

`account new` always starts at index `0` (no `--start-index`).

### Security notes (EOA)

- **Raw `--mnemonic-passphrase VALUE`** — same `ps` / shell-history warning as `validator`. Prefer env or bare prompt. On `account new`, bare form is **double-entry** confirm; on `account recover`, bare form is **single-entry**.
- **Interop note — v3 keystore passphrase is raw (no NFKD):** scrypt consumes the keystore passphrase as **raw UTF-8 bytes** (no NFKD, no control-character strip). That matches geth and MetaMask. EIP-2335 (`validator`) *does* normalize — do not assume one passphrase form unlocks both formats for non-ASCII secrets. Prefer ASCII unless you have verified unlock in the target wallet.

### `account new` — create a new EOA key set

```bash
ethernal account new --output-dir DIR [--count N] [--passphrase-env VAR] \
  [--mnemonic-passphrase [VALUE] | --mnemonic-passphrase-env VAR]
```

**Flow** (same ceremony shape as `validator new`):

1. **Non-TTY guard** → exit **2** before entropy.
2. **Entropy →** 24-word BIP-39 mnemonic.
3. **Mnemonic passphrase** → flag / env / confirm / empty.
4. **Ceremony** → display once on `/dev/tty`, full re-entry; mismatch → exit **4**, nothing on disk.
5. **Automatic scrollback clear** → same clear-on-confirm as `validator new` (screen + scrollback, on confirm **and** abort; fail-open with a manual-clear warning if the ANSI write fails). **tmux/screen caveat:** multiplexers keep their own history that ANSI cannot reach — `tmux clear-history`; screen: C-a : then `scrollback 0`. Details under [`validator new` Flow](#validator-new--create-a-new-bls-key-set).
6. **Keystore passphrase** → env or interactive confirm (min 8, **raw** bytes to KDF).
7. **Derive → encrypt → write** → `m/44'/60'/0'/0/i`, Web3 v3 scrypt, `UTC--` names, mode `0o600`. Stderr summary lists path + **EIP-55 address**.

**Example**

```bash
mkdir -p ./eoa-keys
export KEYSTORE_PASS=my-keystore-passphrase

ethernal account new \
  --output-dir ./eoa-keys \
  --count 2 \
  --passphrase-env KEYSTORE_PASS

# optional 25th word via env
export MNEMONIC_PW=...
ethernal account new \
  --output-dir ./eoa-keys \
  --mnemonic-passphrase-env MNEMONIC_PW \
  --passphrase-env KEYSTORE_PASS
unset MNEMONIC_PW KEYSTORE_PASS
```

### `account recover` — recreate EOA keys from a mnemonic

```bash
ethernal account recover --output-dir DIR [--count N] [--start-index N] \
  [--passphrase-env VAR] \
  [--mnemonic-passphrase [VALUE] | --mnemonic-passphrase-env VAR]
```

No ceremony. Same 12–24-word validation as `validator recover` (bad word reported by **1-based position**, never the token). TTY or piped stdin.

```bash
# Interactive
ethernal account recover \
  --output-dir ./eoa-keys \
  --count 3 \
  --start-index 0 \
  --passphrase-env KEYSTORE_PASS

# Piped
echo "$MNEMONIC" | ethernal account recover \
  --output-dir ./eoa-keys \
  --count 1 \
  --passphrase-env KEYSTORE_PASS

# Next address index (e.g. after 0..2)
ethernal account recover --output-dir ./eoa-keys --start-index 3 --count 1 \
  --passphrase-env KEYSTORE_PASS
```

### After EOA key creation

Stderr summary lists each path and **EIP-55** address. Import with the same keystore passphrase:

| Tool | How |
|---|---|
| **Foundry** | `cast wallet import` / `cast wallet decrypt-keystore` / `cast wallet address --keystore …` |
| **geth** | Drop the `UTC--…` file into `<datadir>/keystore/` (standard scrypt `n=262144`) |
| **MetaMask** | *Import account → JSON File* |

Keep the mnemonic offline only.

---

## Step 1 — Generate deposit data (`ethernal deposit gen`)

### Synopsis

```
ethernal deposit gen --keystore-dir DIR --pubkeys HEX[,...] --network NET --output-dir DIR \
  --withdrawal-address ADDR [options]
```

### Flags

| Flag | Description | Default |
|---|---|---|
| `--keystore-dir DIR` *(required)* | Directory containing EIP-2335 JSON keystore files, one per validator | — |
| `--pubkeys HEX[,...]` *(required)* | Comma-separated 96-hex-char BLS pubkeys (0x-prefixed or bare) | — |
| `--network NET` *(required)* | `mainnet` or `hoodi` | — |
| `--output-dir DIR` *(required)* | Existing, writable directory for `deposit_data-<ts>.json` | — |
| `--withdrawal-address ADDR` *(required)* | EIP-55 **checksummed** execution address for 0x01 withdrawal credentials (`0x01 ‖ 11 zero bytes ‖ addr20`). Absent, lowercase, or checksum-mismatched → exit 2 | — |
| `--passphrase-env VAR` | Env var holding the keystore passphrase (omit for TTY prompt) | TTY prompt |
| `--i-understand-this-is-mainnet` | Required when `--network mainnet`; acknowledges irreversibility | `false` |
| `--dry-run` | Print JSON to stdout instead of writing a file; sha256 to stderr | `false` |
| `--parallel N` | Concurrent signing workers (1 to runtime.NumCPU()×4) | `1` |
| `--verbose` | Debug-level structured logging to stderr | `false` |
| `--json-logs` | Emit logs as JSON objects | `false` |
| `--verify-with-deposit-cli` | Cross-check output with `staking-deposit-cli >= 2.7.0` | `false` |
| `--deposit-cli-path PATH` | Path to `deposit` binary for verification | `deposit` (PATH) |

### EIP-55 asymmetry (`--withdrawal-address` vs `--from`)

`--withdrawal-address` is **strict**: the address must be a correctly mixed-case EIP-55 checksum. All-lowercase, all-uppercase, or a mixed-case checksum mismatch is rejected with exit 2. This matches ethstaker/staking-deposit-cli and catches typos before they become irreversible withdrawal credentials.

By contrast, `deposit build`'s `--from` is **lenient**: any 0x-prefixed (or bare) 20-byte hex is accepted regardless of case — no checksum check. (`tx run` has no `--from`; it derives the sender from its signing key.) Do not expect the two flags to behave the same way.

### Example — Hoodi single validator

```bash
export KEYSTORE_PASS=my-keystore-passphrase

ethernal deposit gen \
  --network hoodi \
  --keystore-dir ./keystores/ \
  --pubkeys 0x8420760d0de00ed65f290ab2122e65933e168539ad261b5e444a5094c649272527a1509dd105a801922c359e46e33fb9 \
  --withdrawal-address 0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1 \
  --output-dir ./out \
  --passphrase-env KEYSTORE_PASS
```

### Example — multiple validators, parallel signing

```bash
ethernal deposit gen \
  --network hoodi \
  --keystore-dir ./keystores/ \
  --pubkeys 0xpub1...,0xpub2...,0xpub3...,0xpub4... \
  --withdrawal-address 0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1 \
  --output-dir ./out \
  --passphrase-env KEYSTORE_PASS \
  --parallel 4
```

Output JSON is a single array with one entry per pubkey, in the order you supplied.

### Example — mainnet

Mainnet deposits are irreversible. The `--i-understand-this-is-mainnet` flag is required:

```bash
ethernal deposit gen \
  --network mainnet \
  --i-understand-this-is-mainnet \
  --keystore-dir ./keystores/ \
  --pubkeys 0xpub1... \
  --withdrawal-address 0xYourChecksummedExecutionAddress \
  --output-dir ./out \
  --passphrase-env KEYSTORE_PASS
```

Without the flag, `--network mainnet` exits with code 2. Without `--withdrawal-address`, `deposit gen` exits with code 2 (require-choice gate — there is no default BLS-to-execution credential).

### Example — dry-run preview

```bash
ethernal deposit gen ... --dry-run    # JSON to stdout, no file
```

### Output JSON shape

```json
[
  {
    "pubkey": "8420...",
    "withdrawal_credentials": "01000...",
    "amount": 32000000000,
    "signature": "...",
    "deposit_message_root": "...",
    "deposit_data_root": "...",
    "fork_version": "10000910",
    "network_name": "hoodi",
    "deposit_cli_version": "2.7.0"
  }
]
```

---

## Step 2 — Build the unsigned transaction (`ethernal deposit build`)

### Synopsis

```
ethernal deposit build --input-file FILE --network NET [options]
```

Produces an EIP-1559 unsigned transaction in JSON. No signing happens — runs fully offline.

### Flags

| Flag | Description | Default |
|---|---|---|
| `--input-file PATH` / `--input PATH` / `-i PATH` *(required)* | Path to `deposit_data-*.json`, or `-` for stdin | — |
| `--network NET` / `-n NET` | `mainnet`, `hoodi`, `sepolia`, `holesky` | `hoodi` |
| `--output PATH` | Output file for unsigned tx JSON; omit or `-` for stdout | stdout |
| `--index N` | Which deposit entry to use when the JSON has multiple validators | `0` |
| `--rpc-url URL` | JSON-RPC endpoint (`http`/`https` only; `ws://` is rejected). When set, any gas/fee/nonce not passed explicitly is fetched from the node (requires `--from`); when omitted, the build is fully offline | — |
| `--gas-limit N` | EIP-1559 gas limit | `250000` |
| `--max-fee-per-gas WEI` | EIP-1559 max fee per gas (decimal wei) | `20000000000` (20 gwei) |
| `--max-priority-fee-per-gas WEI` | EIP-1559 priority fee per gas (decimal wei) | `1000000000` (1 gwei) |
| `--nonce N` | Sender account nonce. With `--rpc-url` and omitted, the node's pending nonce is used; offline, omitting defaults to 0 (first-time sender only) | `0` (offline) |
| `--from ADDR` | Sender address (0x-prefixed, 20-byte hex). Required with `--rpc-url` when `--nonce`/`--gas-limit` is omitted, to fetch the pending nonce and estimate gas | — |

Wei quantities (fees, value) are held as `u128`; a value ≥ 2^128 wei is rejected.

### Examples

Air-gapped build (all values explicit):

```bash
ethernal deposit build \
  --network hoodi \
  --input-file ./out/deposit_data-1716000000.json \
  --gas-limit 300000 \
  --max-fee-per-gas 30000000000 \
  --max-priority-fee-per-gas 2000000000 \
  --nonce 17 \
  --output unsigned_tx.json
```

Multiple validators — produce a tx per validator by varying `--index`:

```bash
for i in 0 1 2 3; do
  ethernal deposit build \
    --network hoodi \
    --input-file deposit_data.json \
    --index $i \
    --nonce $((BASE_NONCE + i)) \
    --output unsigned_tx_${i}.json
done
```

### Output shape

```json
{
  "chainId": 560048,
  "to": "0x00000000219ab540356cBB839Cbe05303d7705Fa",
  "value": "0x1bc16d674ec800000",
  "data": "0x22895118...",
  "gas": 250000,
  "maxFeePerGas": "0x4a817c800",
  "maxPriorityFeePerGas": "0x3b9aca00",
  "nonce": 0,
  "type": "0x2"
}
```

The `data` field is exactly 420 bytes (`0x` + 840 hex chars): the 4-byte `deposit()` selector + 128-byte ABI head + 288-byte tail (pubkey, withdrawal_credentials, signature padded to 32-byte boundaries, deposit_data_root inline).

---

## Step 3 — Sign the transaction (`ethernal tx sign`)

### Synopsis

```
ethernal tx sign --signer local|ledger --input FILE [options]
```

### Flags

| Flag | Description | Default |
|---|---|---|
| `--signer TYPE` *(required)* | `local` or `ledger` | — |
| `--input PATH` / `-i PATH` *(required)* | Path to unsigned tx JSON, or `-` for stdin | — |
| `--output PATH` / `-o PATH` | Output file for signed tx JSON (0o600 perms); omit or `-` for stdout | stdout |
| `--private-key-env VAR` | Env var name holding the hex private key (local signer only) | `ETHERNAL_TX_PRIVATE_KEY` |

### Option A — Local private key (testing only)

`LocalSigner` is for development, testing, and CI — **not for real funds**. Use Ledger for any mainnet or non-trivial testnet deposit.

The private key MUST come from an environment variable. There is no CLI flag to accept a key value (deliberate: never appears in argv or shell history). The env-var-name flag value must match the POSIX pattern `^[A-Z_][A-Z0-9_]*$` — if you accidentally paste the hex key as the flag value, sign refuses with exit code 2.

```bash
export ETHERNAL_TX_PRIVATE_KEY=0x0101010101010101010101010101010101010101010101010101010101010101  # synthetic test key

ethernal tx sign \
  --signer local \
  --input ./out/unsigned_tx.json \
  --output ./out/signed_tx.json

unset ETHERNAL_TX_PRIVATE_KEY
```

The key bytes are zeroized in memory when sign exits (LocalSigner.Close).

To use a different env-var name (e.g., for a hosted CI secret):

```bash
export MY_DEPLOY_KEY=0x...
ethernal tx sign --signer local --private-key-env MY_DEPLOY_KEY --input unsigned_tx.json --output signed_tx.json
```

### Option B — Ledger Nano

Prerequisites:

- Ledger Nano S or Nano X with current firmware
- Ethereum app installed and open on the device
- Binary built with the `ledger` cargo feature (`cargo build --release --features ledger`)
- Linux: `libusb-1.0` installed and Ledger udev rules in place (see [Install](#install))

```bash
ethernal tx sign \
  --signer ledger \
  --input ./out/unsigned_tx.json \
  --output ./out/signed_tx.json
```

What you'll see:

1. The CLI prints to stderr: `Please confirm the transaction on your Ledger device...`
2. The Ledger displays the transaction details — **read every field carefully**:
   - **Network / Chain ID** (e.g., `Holesky` or chain ID `17000`)
   - **To address** (deposit contract, e.g., `0x4242424242424242424242424242424242424242` on Holesky)
   - **Value** (`32 ETH`)
   - **Max fee** (your gas × maxFeePerGas)
3. Press the right button to confirm. The Ledger returns the signature; sign writes the output file.

If you reject on the device, sign exits with code 4 (user abort). If no Ledger is found or the Ethereum app is not open, exit code 3 with a clear error.

**Note on heuristics:** the rejection / chain-ID-mismatch / app-not-open detection in `crates/ethernal-signer/src/ledger.rs` uses pattern matching on the device-side error strings and has NOT yet been validated against real hardware. If you observe unexpected error mappings on a real Ledger, file an issue describing what message you received so the heuristics can be tightened.

### Output shape

```json
{
  "unsigned": { ... },
  "from": "0xabc...",
  "hash": "0xdeadbeef...",
  "r": "0x...",
  "s": "0x...",
  "v": "0",
  "rawRLP": "0x02f8c483..."
}
```

`v` is the EIP-1559 y-parity (decimal `"0"` or `"1"`).
`rawRLP` is the EIP-2718 typed envelope (always starts with `0x02` for type-2 transactions) ready for `eth_sendRawTransaction`.

Output files are created with `0o600` permissions (owner read/write only).

---

## Step 4 — Broadcast (optional) (`ethernal tx send`)

### Synopsis

```
ethernal tx send --input FILE --rpc-url URL [options]
```

Broadcasts a signed transaction via JSON-RPC with a double-confirmation prompt and optional receipt polling.

### Flags

| Flag | Description | Default |
|---|---|---|
| `--input PATH` / `-i PATH` *(required)* | Path to signed tx JSON, or `-` for stdin | — |
| `--rpc-url URL` *(required)* | JSON-RPC endpoint for the target network | — |
| `--yes` | Skip the typed-confirmation prompt (use for automation only) | `false` |
| `--wait-for-receipt` | Poll for the receipt after broadcast | `false` |
| `--receipt-timeout DUR` | Receipt poll timeout (duration with `ms`/`s`/`m`/`h` suffix, e.g. `120s`) | `60s` |
| `--receipt-output PATH` | Write receipt JSON to file (0o600 perms) | — |

### Confirmation prompt

Unless `--yes` is set, send prints a summary and waits for you to type the network name:

```
> You are about to BROADCAST a 32 ETH deposit transaction.
>   Network:        holesky (chain ID 17000)
>   From:           0xabcd...
>   To (deposit):   0x4242...4242
>   Value:          32.000000 ETH
>   Nonce:          17
>   MaxFeePerGas:   20.000000 Gwei
>   Tx hash:        0xdeadbeef...
> Type the network name to confirm:
holesky
> Broadcasting...
> Tx hash: 0xdeadbeef...
> Explorer: https://holesky.etherscan.io/tx/0xdeadbeef...
```

Type anything other than the network name (or send EOF) → exit code 4.

send also fetches the chain ID from the RPC endpoint and refuses to broadcast if it doesn't match the signed tx's chain ID — preventing accidental cross-network broadcast (e.g., a Holesky-signed tx sent to a mainnet RPC).

### Example — with receipt

```bash
ethernal tx send \
  --input ./out/signed_tx.json \
  --rpc-url https://holesky.example/rpc \
  --wait-for-receipt \
  --receipt-timeout 180s \
  --receipt-output ./out/receipt.json
```

### Alternative — broadcast manually

If you prefer external tools:

```bash
RAW=$(jq -r .rawRLP ./out/signed_tx.json)

# Foundry
cast publish --rpc-url https://your-rpc-url "$RAW"

# Or raw curl
curl -X POST -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendRawTransaction\",\"params\":[\"$RAW\"],\"id\":1}" \
  https://your-rpc-url
```

Note: `cast send` is wrong here — that constructs a new transaction. Use `cast publish` for pre-signed raw RLP.

---

## Convenience: `ethernal tx run` (build + sign in one shot)

When you're signing on the same machine that has the deposit data, `tx run` collapses `deposit build` + `tx sign` into one command:

```bash
export ETHERNAL_TX_PRIVATE_KEY=0x...

ethernal tx run \
  --network hoodi \
  --signer local \
  --input-file ./out/deposit_data-1716000000.json \
  --nonce 17 \
  --output ./out/signed_tx.json

unset ETHERNAL_TX_PRIVATE_KEY
```

Outputs:
- `signed_tx.json` (0o600) — SignedTx JSON
- `signed_tx.raw` (0o600) — just the `rawRLP` hex (**0x-prefixed**), convenient for `cast publish` or curl. Written **only when `--output` is a file path**; with stdout output no `.raw` is produced.

Pass `--keep-unsigned` to also write the intermediate `unsigned_tx.json` (useful for auditing what was actually signed). Pass `--raw-output PATH` to override the auto-derived `.raw` filename.

The same flags work for `--signer ledger` — `tx run` calls the Ledger flow internally.

Use the two-step `deposit build` → `tx sign` flow when the signing machine is air-gapped; use `tx run` for the convenience case.

---

## Air-gapped workflow

The two-phase design supports air-gapping the signing machine entirely:

```
[ Online machine #1 ]                                 [ Air-gapped signing machine ]
  ethernal deposit gen ...           ─USB/QR transfer──>     ./signing-machine/in/
                                                          ethernal tx sign --signer ledger ...
  ethernal deposit build ...                                 ./signing-machine/out/
                                <─USB/QR transfer──     signed_tx.json
[ Online machine #2 ]
  ethernal tx send ...
```

1. **Air-gapped (recommended for mainnet)** — create BLS keystores with `ethernal validator new` (TTY ceremony; see [Create BLS validator keys](#create-bls-validator-keys-ethernal-validator)), transfer only the encrypted keystores (and later pubkeys) off the machine. Or generate keystores online if you accept the risk.
2. **Online machine** — generate deposit data and the unsigned transaction:
   ```bash
   ethernal deposit gen ... --withdrawal-address 0x... --output-dir ./out
   ethernal deposit build --network hoodi --input-file ./out/deposit_data-*.json --nonce N --output unsigned_tx.json
   ```
3. **Transfer** `unsigned_tx.json` to the air-gapped machine (USB, QR code, etc.). It contains no secrets.
4. **Air-gapped machine** — sign with the Ledger:
   ```bash
   ethernal tx sign --signer ledger --input unsigned_tx.json --output signed_tx.json
   ```
5. **Transfer** `signed_tx.json` back to an online machine.
6. **Online machine** — broadcast:
   ```bash
   ethernal tx send --input signed_tx.json --rpc-url https://...
   ```

Neither the unsigned nor the signed deposit-tx artifact contains the BLS private key. The Ledger never exports the secp256k1 key. Note that a merged `ethernal` binary on the air-gapped machine also carries the `deposit gen` / `deposit build` / `tx send` code paths it isn't using there — see `CHANGELOG.md` for that tradeoff.

---

## Networks

Supported by `ethernal` (see `crates/ethernal-core/src/network.rs`):

| Network | Chain ID | Deposit contract | Explorer |
|---|---|---|---|
| `mainnet` | 1 | `0x00000000219ab540356cBB839Cbe05303d7705Fa` | https://etherscan.io |
| `hoodi` | 560048 | `0x00000000219ab540356cBB839Cbe05303d7705Fa` | https://hoodi.etherscan.io |
| `sepolia` | 11155111 | `0x7f02C3E3c98b133055B8B348B2Ac625669Ed295D` | https://sepolia.etherscan.io |
| `holesky` | 17000 | `0x4242424242424242424242424242424242424242` | https://holesky.etherscan.io |

Notes:
- `deposit gen` only supports `mainnet` and `hoodi` (BLS fork-version material).
- `deposit build` / `tx sign` / `tx run` / `tx send` support all four (they just need chain ID + deposit contract address).
- For testnet ETH: use the testnet faucets — Hoodi `https://hoodi-faucet.pk910.de/`, Sepolia `https://sepoliafaucet.com/`, Holesky `https://holesky-faucet.pk910.de/`.

---

## Exit codes

All `ethernal` subcommands use a consistent set of exit codes you can script around:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Unexpected internal error |
| 2 | User / configuration error (bad input, missing/invalid flag, unknown network, missing `--withdrawal-address`, non-TTY `validator new` / `account new`, missing `--from`/`--nonce`/`--gas-limit` for RPC mode, build-side RPC chain-ID mismatch) |
| 3 | Signer / crypto error (Ledger not found, Ethereum app not open, invalid key, signer-side chain-ID mismatch, BLS/SSZ failure) |
| 4 | User abort (SIGINT, or rejected confirmation prompt) |
| 5 | Broadcast / RPC error (RPC dial failure, gas/nonce estimation failure, broadcast-side chain-ID mismatch, node rejection) — `deposit build` / `tx run` estimation and `tx send` broadcast |

Script around these:

```bash
if ethernal tx sign ...; then
  echo "signed"
else
  rc=$?
  case $rc in
    2) echo "bad input — check flags and files" ;;
    3) echo "signer error — Ledger not found or invalid key" ;;
    4) echo "user aborted (rejected on device or SIGINT)" ;;
    *) echo "unexpected error: $rc" ;;
  esac
fi
```

---

## Security

### Threat model

`ethernal` protects:

- **Private keys never appear in argv, environment dumps, or shell history when used correctly.** Local-signer keys come from env vars only; Ledger keys never leave the device. Mnemonics from `validator new` / `account new` are shown only on the controlling terminal and never on stdout/stderr/logs.
- **Signed artifacts and keystores are written with restricted perms** (0o600; receiver can verify a signed tx by recovering the sender and checking the tx hash).
- **Broadcast is gated by chain-ID match and operator confirmation.** A signed-for-Holesky transaction will not be broadcast to a mainnet RPC endpoint.
- **RPC credentials are redacted from error messages by construction.** API keys embedded in an `--rpc-url` are stripped before any error is logged or printed.

It does NOT protect:

- A compromised machine. If your build/sign machine is compromised, the unsigned tx data field (which encodes the deposit) could be silently altered. Verify on the Ledger screen before pressing confirm. A compromised keygen machine can capture the mnemonic at generation time — prefer air-gapped `validator new` / `account new` for high-value keys.
- Network-level interception of the broadcast (not a concern for signed transactions — they cannot be modified without invalidating the signature).
- Keystore confidentiality. The keystore passphrase is your responsibility; use a strong one and clear `KEYSTORE_PASS` from your shell after use.
- A raw `--mnemonic-passphrase VALUE` on the command line (visible in `ps` and shell history) — see [Create BLS validator keys](#create-bls-validator-keys-ethernal-validator) and [Create EOA keystores](#create-eoa-keystores-ethernal-account).

### Key handling rules

- **BLS mnemonic (`validator new` / `validator recover`)** — write it down offline during the ceremony; store it offline only. Never commit it, pipe `validator new` (refused), or paste it into tickets/chat. Prefer air-gapped generation for high-value validators. Full guide: [Create BLS validator keys](#create-bls-validator-keys-ethernal-validator).
- **EOA mnemonic (`account new` / `account recover`)** — same ceremony and offline rules as BLS; produces Web3 v3 keystores (not EIP-2335). Prefer air-gapped generation for high-value EOAs. Never pipe `account new` (refused). Full guide: [Create EOA keystores](#create-eoa-keystores-ethernal-account).
- **Mnemonic passphrase (BIP-39 "25th word")** — prefer `--mnemonic-passphrase-env` or bare `--mnemonic-passphrase` (prompt). **Do not** use raw `--mnemonic-passphrase VALUE` for high-value mnemonics: the value is visible in the process table (`ps`) and shell history. A mistyped 25th word yields keys you cannot recover from the mnemonic alone. Applies to both `validator` and `account`.
- **Keystore passphrase (`validator` / EIP-2335)** — env var (`--passphrase-env`) or TTY prompt-with-confirm; minimum 8 bytes after EIP-2335 **NFKD** normalization. There is no raw-argv form (unlike the mnemonic passphrase). Env vars persist for the shell lifetime (and `export VAR=secret` can land in shell history) — use a dedicated session and `unset` when done.
- **Keystore passphrase (`account` / Web3 v3)** — same CLI surface (env or TTY prompt-with-confirm; min 8 bytes; no raw-argv form), but encryption uses the passphrase as **raw UTF-8** (no NFKD) for geth/MetaMask interop.
- `ETHERNAL_TX_PRIVATE_KEY` — env var only. There is NO `--private-key` flag. The env-var-name flag (`--private-key-env`) is validated to match `^[A-Z_][A-Z0-9_]*$` to prevent users from accidentally passing the key value.
- `LocalSigner` zeroizes the key bytes in memory when `Close()` is called (end of every `tx sign` / `tx run` invocation).
- For mainnet: use Ledger for the deposit-tx signer. The local signer is explicitly tagged "for development only" in its docs and is not recommended for any real-fund deposit.
- The synthetic test key in `testdata/phase3/holesky/private_key.txt` is `0x0101010101010101010101010101010101010101010101010101010101010101` (obvious pattern). Never use it with real funds; it's for tests only.

### On-device verification (Ledger)

Before pressing confirm on your Ledger, **always verify on the screen**:

1. **Chain ID** matches your intended network (1 = mainnet, 17000 = Holesky, etc.).
2. **To address** is the deposit contract address for your network (see [Networks](#networks)). A different address means something is wrong — abort.
3. **Value** is exactly `32 ETH` (`32.000000`). Any other value is wrong.
4. **From address** (recovered by sign and printed in the output) matches the Ledger-derived address you expect to fund the deposit.

Reject on the device if anything is off. The CLI exits with code 4 and no broadcast happens.

### Exit codes as a security tool

The typed exit codes let your automation distinguish between "operator rejected" (code 4 — likely intentional), "signer/crypto problem" (code 3 — investigate), and "RPC / broadcast error" (code 5). Code 5 covers an endpoint dial or gas/nonce estimation failure (`deposit build` / `tx run`) and, on `tx send`, the broadcast safety guard tripping on a chain-ID mismatch — treat a send-side chain-ID mismatch as "wrong network, do not retry blindly".

---

## Recipes

### Recipe 1 — Local key, all on one machine (dev / CI)

```bash
export KEYSTORE_PASS=test-passphrase
export ETHERNAL_TX_PRIVATE_KEY=0x0101...   # synthetic; never real
mkdir -p ./keystores ./out

# Interactive validator new (or recover from a fixed test mnemonic via stdin)
ethernal validator new --output-dir ./keystores --passphrase-env KEYSTORE_PASS
# copy pubkey from the summary:

ethernal deposit gen \
  --network hoodi --keystore-dir ./keystores/ \
  --pubkeys 0x... \
  --withdrawal-address 0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1 \
  --output-dir ./out --passphrase-env KEYSTORE_PASS

ethernal tx run \
  --network hoodi --signer local \
  --input-file ./out/deposit_data-*.json \
  --nonce 0 --output ./out/signed_tx.json

unset KEYSTORE_PASS ETHERNAL_TX_PRIVATE_KEY
```

### Recipe 2 — Ledger, one machine, broadcast immediately

```bash
export KEYSTORE_PASS=...

ethernal deposit gen ... \
  --withdrawal-address 0x... \
  --output-dir ./out --passphrase-env KEYSTORE_PASS

ethernal tx run \
  --network hoodi --signer ledger \
  --input-file ./out/deposit_data-*.json \
  --nonce 17 --output ./out/signed_tx.json
# (confirm on Ledger)

ethernal tx send \
  --input ./out/signed_tx.json \
  --rpc-url https://your-hoodi-rpc \
  --wait-for-receipt --receipt-output ./out/receipt.json
# (type "hoodi" to confirm broadcast)

unset KEYSTORE_PASS
```

### Recipe 3 — Air-gapped Ledger (mainnet-ready)

```bash
# Air-gapped machine B — generate BLS keys (TTY only)
mkdir -p ./keystores
ethernal validator new --output-dir ./keystores --passphrase-env KEYSTORE_PASS
# transfer keystores (encrypted) + note the pubkeys to online machine A
# keep the mnemonic offline only

# Online machine A
ethernal deposit gen --network mainnet --i-understand-this-is-mainnet \
  --keystore-dir ./keystores/ --pubkeys 0x... \
  --withdrawal-address 0xYourChecksummedExecutionAddress \
  --output-dir ./out --passphrase-env KEYSTORE_PASS
ethernal deposit build --network mainnet \
  --input-file ./out/deposit_data-*.json \
  --nonce ${NONCE} --output unsigned_tx.json
# transfer unsigned_tx.json via USB/QR to air-gapped machine

# Air-gapped machine B (no network)
ethernal tx sign --signer ledger \
  --input unsigned_tx.json --output signed_tx.json
# (confirm on Ledger; verify on-device fields per Security section)
# transfer signed_tx.json back via USB/QR

# Online machine A
ethernal tx send --input signed_tx.json --rpc-url https://your-mainnet-rpc
# (type "mainnet" to confirm)
```

### Recipe 4 — Multiple validators in one shot

```bash
ethernal validator new --output-dir ./keystores --count 3 --passphrase-env KEYSTORE_PASS

ethernal deposit gen --network hoodi --keystore-dir ./keystores/ \
  --pubkeys 0xpub1...,0xpub2...,0xpub3... \
  --withdrawal-address 0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1 \
  --output-dir ./out --passphrase-env KEYSTORE_PASS --parallel 4

# One sign per validator, increment nonce
BASE_NONCE=17
for i in 0 1 2; do
  ethernal tx run --network hoodi --signer ledger \
    --input-file ./out/deposit_data-*.json --index $i \
    --nonce $((BASE_NONCE + i)) \
    --output ./out/signed_${i}.json
done
```

### Recipe 5 — Recover additional indices from an existing mnemonic

```bash
# BLS: you already have indices 0..2; derive the next three
echo "$MNEMONIC" | ethernal validator recover \
  --output-dir ./keystores \
  --start-index 3 \
  --count 3 \
  --passphrase-env KEYSTORE_PASS

# EOA: same idea for BIP-44 address indices
echo "$MNEMONIC" | ethernal account recover \
  --output-dir ./eoa-keys \
  --start-index 3 \
  --count 1 \
  --passphrase-env KEYSTORE_PASS
```

### Recipe 6 — One mnemonic → BLS and EOA keystores

The same BIP-39 seed feeds both HD trees. Create (or recover) once, reuse the mnemonic carefully:

```bash
export KEYSTORE_PASS=...   # or use different passphrases per format if you prefer
mkdir -p ./keystores ./eoa-keys

# Option A — fresh mnemonic via BLS ceremony; write the phrase down, then recover EOA
ethernal validator new --output-dir ./keystores --count 1 --passphrase-env KEYSTORE_PASS
# (after writing the mnemonic offline)
echo "$MNEMONIC" | ethernal account recover \
  --output-dir ./eoa-keys --count 1 --passphrase-env KEYSTORE_PASS

# Option B — recover both from an existing mnemonic (no ceremony)
echo "$MNEMONIC" | ethernal validator recover \
  --output-dir ./keystores --count 1 --passphrase-env KEYSTORE_PASS
echo "$MNEMONIC" | ethernal account recover \
  --output-dir ./eoa-keys --count 1 --passphrase-env KEYSTORE_PASS

unset KEYSTORE_PASS
```

If you used a BIP-39 mnemonic passphrase (25th word) for one tree, pass the **same** form to the other. BLS and EOA keystore files still differ (EIP-2335 vs Web3 v3) and must stay in separate directories.

### Recipe 7 — Pipe between commands

```bash
ethernal deposit gen --network hoodi ... --withdrawal-address 0x... --dry-run | \
  ethernal deposit build --network hoodi --input-file - --nonce 0 | \
  jq '.'   # pretty-print the unsigned tx
```

### Recipe 8 — Verify a signed tx independently

```bash
# Decode and inspect with cast
RAW=$(jq -r .rawRLP signed_tx.json)
cast tx --rpc-url https://your-rpc-url --from-rpc "$RAW"   # won't work for unbroadcast txs

# Or just decode locally
cast decode-typed-tx "$RAW"
```

---

## Troubleshooting

### `ethernal validator` errors

| Symptom | Cause / fix |
|---|---|
| `new requires an interactive terminal ...` (exit 2) | `validator new` is TTY-only. Run it in a real terminal; do not pipe or redirect stdin/stdout. Use `validator recover` for scripted mnemonic input. |
| `--output-dir: directory "..." does not exist` / `not writable` (exit 2) | Create the directory first (`mkdir -p`) and ensure write permission. |
| `--count: value 0 is invalid` (exit 2) | Pass `--count` ≥ 1. |
| Invalid mnemonic / checksum (exit 2, `validator recover`) | Check word count (12/15/18/21/24), spelling against the English wordlist, and that the full phrase matches what you wrote down (including any mnemonic passphrase). |
| Ceremony re-entry mismatch → abort (exit 4) | You declined retry after a wrong re-entry, or sent SIGINT. Run `validator new` again; the previous mnemonic was never written to disk. |
| Keystore passphrase too short (exit 2) | Keystore passphrase must be at least 8 bytes (after EIP-2335 normalization). |

### `ethernal account` errors

| Symptom | Cause / fix |
|---|---|
| interactive terminal / non-TTY refusal (exit 2) | `account new` is TTY-only (shares the same gate as `validator new`). Run it in a real terminal; do not pipe or redirect stdin/stdout. Use `account recover` for scripted mnemonic input. |
| `--output-dir: directory "..." does not exist` / `not writable` (exit 2) | Create the directory first (`mkdir -p`) and ensure write permission. |
| `--count: value 0 is invalid` (exit 2) | Pass `--count` ≥ 1. |
| Invalid mnemonic / checksum (exit 2, `account recover`) | Check word count (12/15/18/21/24), spelling against the English wordlist, and that the full phrase matches what you wrote down (including any mnemonic passphrase). |
| Ceremony re-entry mismatch → abort (exit 4) | You declined retry after a wrong re-entry, or sent SIGINT. Run `account new` again; the previous mnemonic was never written to disk. |
| Keystore passphrase too short (exit 2) | Keystore passphrase must be at least 8 bytes. For v3 encryption the bytes are used **raw** (no NFKD) — see [Create EOA keystores](#create-eoa-keystores-ethernal-account). |
| Imported keystore unlocks in neither geth nor MetaMask | Confirm you used the same passphrase string (raw UTF-8) and a v3 file from `account`, not an EIP-2335 file from `validator`. See [Create EOA keystores](#create-eoa-keystores-ethernal-account). |

### `ethernal deposit gen` errors

| Symptom | Cause / fix |
|---|---|
| `--withdrawal-address: required flag not set` (exit 2) | Pass `--withdrawal-address` with an EIP-55 checksummed execution address. There is no default. |
| `--withdrawal-address: ... EIP-55 checksum mismatch` (exit 2) | Address must be correctly mixed-case EIP-55 (not all-lowercase). Tools like `cast to-check-sum-address` can re-checksum. Note: `deposit build`'s `--from` is lenient and does **not** require EIP-55 — only `--withdrawal-address` is strict. |
| `mainnet selected; pass --i-understand-this-is-mainnet to acknowledge` (exit 2) | Add the flag. Mainnet is irreversible. |
| `pubkey ... not found in keystore directory` (exit 2) | The pubkey listed in `--pubkeys` has no matching keystore file. Check the keystore directory contents. |
| `decrypt: invalid passphrase` (exit 3) | Wrong `KEYSTORE_PASS`. The passphrase decrypts every keystore — all must share it. |
| `staking-deposit-cli not found in PATH` (exit 3, only with `--verify-with-deposit-cli`) | Either install `staking-deposit-cli >= 2.7.0`, set `--deposit-cli-path`, or drop the verify flag. |

### `ethernal deposit build` errors

| Symptom | Cause / fix |
|---|---|
| `--index N: out of bounds (file has M entries)` (exit 2) | Your deposit data JSON has fewer entries than the index you requested. |
| `deposit entry validation: ...` (exit 2) | The deposit data JSON is malformed (zero pubkey, bad withdrawal credentials prefix, etc.). Regenerate with `ethernal deposit gen`. |
| `value mismatch ...` (exit 2) | The entry's `amount` is not 32 ETH in Gwei. Only 32 ETH first deposits are currently supported. |

### `ethernal tx sign` errors

| Symptom | Cause / fix |
|---|---|
| `environment variable "ETHERNAL_TX_PRIVATE_KEY" is not set` (exit 3) | Set the env var (or use `--private-key-env` to point at a different one). |
| `--private-key-env: "0x..." is not a valid POSIX env var name` (exit 2) | You passed the hex key as the flag value. Pass the env var NAME instead, and put the key value into that env var. |
| `invalid private key: expected 32 bytes` (exit 3) | The env var contents are not a valid 32-byte hex secp256k1 key. The error never includes the key bytes. |
| `no Ledger device found` (exit 3) | Plug in the Ledger, unlock it, open the Ethereum app. On Linux, verify udev rules. |
| `ledger Ethereum app is not open` (exit 3) | Open the Ethereum app on the device, then retry. |
| `user rejected signing on Ledger` (exit 4) | You pressed the reject button on the device. Retry if intentional was confirm. |
| `ledger support requires the 'ledger' cargo feature; rebuild with --features ledger` (exit 3) | The binary was built without the Ledger transport. Rebuild with `cargo build --release --features ledger`. |

### `ethernal tx send` errors

| Symptom | Cause / fix |
|---|---|
| `signed tx chain ID does not match RPC chain ID; refusing to broadcast` (exit 5) | The RPC endpoint reports a different chain ID than the signed tx. You're pointing at the wrong network. Do NOT use `--yes` to bypass. |
| `dial RPC: ...` (exit 5) | Bad `--rpc-url` or network connectivity issue. |
| `eth_sendRawTransaction: nonce too low` (exit 5) | The sender's actual nonce is higher than what you signed. Rebuild with a correct `--nonce`, re-sign, retry. |
| `eth_sendRawTransaction: insufficient funds` (exit 5) | The sender address doesn't have 32 ETH + gas. Fund it. |
| `eth_sendRawTransaction: known transaction` (exit 5) | This exact tx was already broadcast. Check the explorer for the receipt. |

### General

- If `make e2e-mock` passes but real testnet broadcast fails, the gap is usually nonce or insufficient funds.
- For Ledger error-string mismatches (the heuristics aren't real-hardware-validated), file an issue with the exact error text.
- For everything else, run with `--verbose` and `--json-logs` (`ethernal deposit gen`) to get structured diagnostics.
