# eth-utils User Guide

Comprehensive guide for `ethernal`, the CLI in this repository that takes a
validator all the way from a BIP-39 mnemonic to a broadcast Ethereum deposit
transaction:

- **`ethernal key new|recover`** — generates or recovers EIP-2335 BLS validator keystores from a BIP-39 mnemonic (the front of the pipeline).
- **`ethernal gen`** — produces Launchpad-compatible deposit data JSON (BLS signatures over the deposit message) from EIP-2335 validator keystores.
- **`ethernal build|sign|run|send`** — builds, signs (Ledger or local key), and broadcasts the Ethereum transaction that submits the deposit to the Beacon Chain deposit contract.

**Status:** unreleased, pending the first tag under the merged name. `ethernal` combines the formerly separate `eth-deposit-gen` (released as v1.0.0) and `eth-deposit-tx` (never tagged) binaries into one tool — see `CHANGELOG.md` for the merge note.

**Implementation:** `ethernal` is a Rust workspace (the original Go implementation was ported with byte-identical outputs on the shared golden fixtures, then retired — see the repository `README.md` for the documented divergences and `docs/plan/` for the migration record).

---

## Table of contents

1. [Concepts and workflow model](#concepts-and-workflow-model)
2. [Install](#install)
3. [Quick start (Hoodi testnet)](#quick-start-hoodi-testnet)
4. [Step 0 — Create validator keys (`ethernal key`)](#step-0--create-validator-keys-ethernal-key)
5. [Step 1 — Generate deposit data (`ethernal gen`)](#step-1--generate-deposit-data-ethernal-gen)
6. [Step 2 — Build the unsigned transaction (`ethernal build`)](#step-2--build-the-unsigned-transaction-ethernal-build)
7. [Step 3 — Sign the transaction (`ethernal sign`)](#step-3--sign-the-transaction-ethernal-sign)
8. [Step 4 — Broadcast (optional) (`ethernal send`)](#step-4--broadcast-optional-ethernal-send)
9. [Convenience: `ethernal run` (build + sign in one shot)](#convenience-ethernal-run-build--sign-in-one-shot)
10. [Air-gapped workflow](#air-gapped-workflow)
11. [Networks](#networks)
12. [Exit codes](#exit-codes)
13. [Security](#security)
14. [Recipes](#recipes)
15. [Troubleshooting](#troubleshooting)

---

## Concepts and workflow model

A validator deposit takes three artifacts:

| Artifact | Produced by | Contains |
|---|---|---|
| **EIP-2335 keystores** | `ethernal key new` / `key recover` | Encrypted BLS signing keys (one JSON file per validator index) |
| **Deposit data JSON** | `ethernal gen` | BLS-signed deposit message: validator pubkey, withdrawal credentials, signature, deposit_data_root, amount |
| **Signed Ethereum transaction** | `ethernal build`/`sign`/`run` | EIP-1559 transaction calling the deposit contract's `deposit(bytes,bytes,bytes,bytes32)` with 32 ETH value, signed by the **sender's** secp256k1 key |

Two distinct keys are involved:
- **BLS validator key** (per validator) — held in EIP-2335 keystores created by `ethernal key` (or any compatible tool); used by `ethernal gen` to sign the deposit message. Never leaves the keystore decryption boundary.
- **secp256k1 sender key** — held in your Ledger (recommended) or env var (testing only); used by `ethernal sign`/`run` to sign the Ethereum transaction that pays the 32 ETH. Whichever address holds this key needs ≥ 32 ETH + gas.

The two-phase split (`build` then `sign`) supports air-gapped operation: build the unsigned tx on an online machine, transfer the JSON to a signing machine (which may be offline), sign there, transfer the signed JSON back online, broadcast. Prefer generating BLS keys (`key new`) on an air-gapped machine as well.

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
git clone https://github.com/rootwarp/eth-utils.git
cd eth-utils
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
# 0. Create validator keystores (interactive TTY ceremony — write down the mnemonic)
mkdir -p ./keystores ./out
export KEYSTORE_PASS=my-keystore-passphrase
ethernal key new --output-dir ./keystores --count 1 --passphrase-env KEYSTORE_PASS
# note the pubkey printed in the summary, then:

# 1. Generate deposit data (withdrawal address must be EIP-55 checksummed)
ethernal gen \
  --network hoodi \
  --keystore-dir ./keystores/ \
  --pubkeys 0x<pubkey-from-key-new-summary> \
  --withdrawal-address 0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1 \
  --output-dir ./out \
  --passphrase-env KEYSTORE_PASS
unset KEYSTORE_PASS

# 2. Build unsigned tx (use --nonce explicitly if sender has prior txs)
ethernal build \
  --network hoodi \
  --input-file ./out/deposit_data-*.json \
  --nonce 0 \
  --output ./out/unsigned_tx.json

# 3. Sign with Ledger (confirm on device)
ethernal sign \
  --signer ledger \
  --input ./out/unsigned_tx.json \
  --output ./out/signed_tx.json

# 4. Broadcast (will prompt to type "hoodi" to confirm)
ethernal send \
  --input ./out/signed_tx.json \
  --rpc-url https://your-hoodi-rpc-url \
  --wait-for-receipt
```

If you already have EIP-2335 keystores from another tool, skip step 0 and pass those paths to `gen`. For a local-key dev flow, see the [recipes](#recipes) below.

---

## Step 0 — Create validator keys (`ethernal key`)

`ethernal key` produces EIP-2335 v4 scrypt signing keystores from a BIP-39 English mnemonic. Two subcommands:

| Subcommand | Purpose | I/O |
|---|---|---|
| `key new` | Fresh 24-word mnemonic + keystores | **TTY only** (stdin and stdout must both be terminals) |
| `key recover` | Keystores from an existing mnemonic | Interactive TTY prompt **or** piped stdin |

Both write one `keystore-m_12381_3600_<i>_0_0-<unix>.json` (mode `0o600`) per index into `--output-dir`. The directory must already exist and be writable.

### Shared flags

| Flag | Description | Default |
|---|---|---|
| `--output-dir DIR` *(required)* | Existing, writable directory for keystore JSON files | — |
| `--count N` | Number of validator keys to produce (must be ≥ 1) | `1` |
| `--passphrase-env VAR` | Env var holding the **keystore** encryption passphrase (min 8 bytes after EIP-2335 normalization). Omit for a TTY prompt-with-confirm | TTY prompt |
| `--mnemonic-passphrase [VALUE]` | Optional BIP-39 mnemonic passphrase ("25th word"). Bare flag → interactive prompt; with `VALUE` → raw argv value; omit → empty (default) | empty |
| `--mnemonic-passphrase-env VAR` | Env var holding the BIP-39 mnemonic passphrase (empty string is valid; unset → exit 2). Conflicts with `--mnemonic-passphrase` | — |

`key recover` also accepts:

| Flag | Description | Default |
|---|---|---|
| `--start-index N` | First HD derivation index; produces indices `[start, start+count)` | `0` |

`key new` always starts at index `0` (no `--start-index`).

**Two different passphrases.** The keystore passphrase (`--passphrase-env` / TTY prompt) encrypts the JSON keystore files and has an 8-byte minimum (UTF-8 length after EIP-2335 normalization). The optional **mnemonic passphrase** is the BIP-39 "25th word" mixed into seed derivation; empty is valid and there is no minimum. They are never interchangeable.

**Env-var lifetime.** Values supplied via `--passphrase-env` or `--mnemonic-passphrase-env` remain in the process environment for the lifetime of that shell (and any child processes that inherit it). Prefer a dedicated shell/session for keygen work, and `unset` the variable when finished. Note that `export VAR=secret` can also land in shell history — the same exposure class as raw argv.

### Security note — raw `--mnemonic-passphrase VALUE`

A raw `--mnemonic-passphrase VALUE` is visible in the process table (`ps`) and in shell history. Prefer:

- `--mnemonic-passphrase-env VAR` (value lives only in the environment), or
- bare `--mnemonic-passphrase` (interactive prompt; on `key new` the prompt is double-entry confirmed).

Treat the raw form as a **scripting convenience, not for high-value mnemonics**.

### `key new` — TTY ceremony

```
ethernal key new --output-dir DIR [--count N] [--passphrase-env VAR] \
  [--mnemonic-passphrase [VALUE] | --mnemonic-passphrase-env VAR]
```

Flow:

1. **Non-TTY guard** — if stdin or stdout is not a terminal, exit 2 **before** any entropy is drawn (a mnemonic must never land on a pipe or log).
2. **Entropy → mnemonic** — 256-bit OS CSPRNG → 24-word English BIP-39 mnemonic with a valid checksum.
3. **Mnemonic passphrase** — resolved from flag / env / prompt-with-confirm / empty (see above).
4. **Ceremony** — the mnemonic is displayed **once** on the controlling terminal (`/dev/tty`, never stdout/stderr/logs). Write it down offline. You then re-enter the full mnemonic to confirm; mismatch → retry or abort (exit 4).
5. **Keystore passphrase** — env (min length 8) or interactive confirm-with-min-length.
6. **Derive → encrypt → write** — EIP-2333/2334 signing path `m/12381/3600/i/0/0` for `i` in `0..count`, EIP-2335 scrypt keystores at `0o600`.

Example:

```bash
mkdir -p ./keystores
export KEYSTORE_PASS=my-keystore-passphrase

ethernal key new \
  --output-dir ./keystores \
  --count 2 \
  --passphrase-env KEYSTORE_PASS

# optional 25th word via env (preferred over raw argv):
export MNEMONIC_PW=...
ethernal key new \
  --output-dir ./keystores \
  --mnemonic-passphrase-env MNEMONIC_PW \
  --passphrase-env KEYSTORE_PASS
unset MNEMONIC_PW KEYSTORE_PASS
```

### `key recover` — TTY or piped stdin

```
ethernal key recover --output-dir DIR [--count N] [--start-index N] \
  [--passphrase-env VAR] \
  [--mnemonic-passphrase [VALUE] | --mnemonic-passphrase-env VAR]
```

Unlike `key new`, there is **no** display/re-entry ceremony — the mnemonic already exists. Accepts 12/15/18/21/24-word English BIP-39 mnemonics (word-list membership + checksum validated first; bad input → exit 2). Interactive prompt when stdin is a TTY; otherwise the whole mnemonic is read from stdin (one line).

Examples:

```bash
# Interactive (prompts for mnemonic, then keystore passphrase if no env)
ethernal key recover \
  --output-dir ./keystores \
  --count 3 \
  --start-index 0 \
  --passphrase-env KEYSTORE_PASS

# Piped (scripting / recovery automation)
echo "$MNEMONIC" | ethernal key recover \
  --output-dir ./keystores \
  --count 1 \
  --passphrase-env KEYSTORE_PASS
```

Use `--start-index` to extend an existing set (e.g. you already deposited indices 0–2 and need index 3):

```bash
ethernal key recover --output-dir ./keystores --start-index 3 --count 1 \
  --passphrase-env KEYSTORE_PASS
```

### After key creation

The summary on stderr lists each written path and its 96-hex-char BLS pubkey. Feed those pubkeys (and the keystore directory) into [Step 1 — `gen`](#step-1--generate-deposit-data-ethernal-gen). Keep the mnemonic offline and offline-only; never paste it into chat, tickets, or cloud notes.

---

## Step 1 — Generate deposit data (`ethernal gen`)

### Synopsis

```
ethernal gen --keystore-dir DIR --pubkeys HEX[,...] --network NET --output-dir DIR \
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

By contrast, `build`'s `--from` is **lenient**: any 0x-prefixed (or bare) 20-byte hex is accepted regardless of case — no checksum check. (`run` has no `--from`; it derives the sender from its signing key.) Do not expect the two flags to behave the same way.

### Example — Hoodi single validator

```bash
export KEYSTORE_PASS=my-keystore-passphrase

ethernal gen \
  --network hoodi \
  --keystore-dir ./keystores/ \
  --pubkeys 0x8420760d0de00ed65f290ab2122e65933e168539ad261b5e444a5094c649272527a1509dd105a801922c359e46e33fb9 \
  --withdrawal-address 0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1 \
  --output-dir ./out \
  --passphrase-env KEYSTORE_PASS
```

### Example — multiple validators, parallel signing

```bash
ethernal gen \
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
ethernal gen \
  --network mainnet \
  --i-understand-this-is-mainnet \
  --keystore-dir ./keystores/ \
  --pubkeys 0xpub1... \
  --withdrawal-address 0xYourChecksummedExecutionAddress \
  --output-dir ./out \
  --passphrase-env KEYSTORE_PASS
```

Without the flag, `--network mainnet` exits with code 2. Without `--withdrawal-address`, `gen` exits with code 2 (require-choice gate — there is no default BLS-to-execution credential).

### Example — dry-run preview

```bash
ethernal gen ... --dry-run    # JSON to stdout, no file
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

## Step 2 — Build the unsigned transaction (`ethernal build`)

### Synopsis

```
ethernal build --input-file FILE --network NET [options]
```

Produces an EIP-1559 unsigned transaction in JSON. No signing happens — runs fully offline.

### Flags

| Flag | Description | Default |
|---|---|---|
| `--input-file PATH` / `--input PATH` / `-i PATH` *(required)* | Path to `deposit_data-*.json`, or `-` for stdin | — |
| `--network NET` / `-n NET` | `mainnet`, `hoodi`, `sepolia`, `holesky` | `hoodi` |
| `--output PATH` | Output file for unsigned tx JSON; omit or `-` for stdout | stdout |
| `--index N` | Which deposit entry to use when the JSON has multiple validators | `0` |
| `--rpc-url URL` | JSON-RPC endpoint. When set, any gas/fee/nonce not passed explicitly is fetched from the node (requires `--from`); when omitted, the build is fully offline | — |
| `--gas-limit N` | EIP-1559 gas limit | `250000` |
| `--max-fee-per-gas WEI` | EIP-1559 max fee per gas (decimal wei) | `20000000000` (20 gwei) |
| `--max-priority-fee-per-gas WEI` | EIP-1559 priority fee per gas (decimal wei) | `1000000000` (1 gwei) |
| `--nonce N` | Sender account nonce. With `--rpc-url` and omitted, the node's pending nonce is used; offline, omitting defaults to 0 (first-time sender only) | `0` (offline) |
| `--from ADDR` | Sender address (0x-prefixed, 20-byte hex). Required with `--rpc-url` when `--nonce`/`--gas-limit` is omitted, to fetch the pending nonce and estimate gas | — |

### Examples

Air-gapped build (all values explicit):

```bash
ethernal build \
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
  ethernal build \
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

## Step 3 — Sign the transaction (`ethernal sign`)

### Synopsis

```
ethernal sign --signer local|ledger --input FILE [options]
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

ethernal sign \
  --signer local \
  --input ./out/unsigned_tx.json \
  --output ./out/signed_tx.json

unset ETHERNAL_TX_PRIVATE_KEY
```

The key bytes are zeroized in memory when sign exits (LocalSigner.Close).

To use a different env-var name (e.g., for a hosted CI secret):

```bash
export MY_DEPLOY_KEY=0x...
ethernal sign --signer local --private-key-env MY_DEPLOY_KEY --input unsigned_tx.json --output signed_tx.json
```

### Option B — Ledger Nano

Prerequisites:

- Ledger Nano S or Nano X with current firmware
- Ethereum app installed and open on the device
- Binary built with the `ledger` cargo feature (`cargo build --release --features ledger`)
- Linux: `libusb-1.0` installed and Ledger udev rules in place (see [Install](#install))

```bash
ethernal sign \
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

## Step 4 — Broadcast (optional) (`ethernal send`)

### Synopsis

```
ethernal send --input FILE --rpc-url URL [options]
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
ethernal send \
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

## Convenience: `ethernal run` (build + sign in one shot)

When you're signing on the same machine that has the deposit data, `run` collapses build + sign into one command:

```bash
export ETHERNAL_TX_PRIVATE_KEY=0x...

ethernal run \
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

The same flags work for `--signer ledger` — `run` calls the Ledger flow internally.

Use the two-step `build` → `sign` flow when the signing machine is air-gapped; use `run` for the convenience case.

---

## Air-gapped workflow

The two-phase design supports air-gapping the signing machine entirely:

```
[ Online machine #1 ]                                 [ Air-gapped signing machine ]
  ethernal gen ...           ─USB/QR transfer──>     ./signing-machine/in/
                                                          ethernal sign --signer ledger ...
  ethernal build ...                                 ./signing-machine/out/
                                <─USB/QR transfer──     signed_tx.json
[ Online machine #2 ]
  ethernal send ...
```

1. **Air-gapped (recommended for mainnet)** — create BLS keystores with `ethernal key new` (TTY ceremony), transfer only the encrypted keystores (and later pubkeys) off the machine. Or generate keystores online if you accept the risk.
2. **Online machine** — generate deposit data and the unsigned transaction:
   ```bash
   ethernal gen ... --withdrawal-address 0x... --output-dir ./out
   ethernal build --network hoodi --input-file ./out/deposit_data-*.json --nonce N --output unsigned_tx.json
   ```
3. **Transfer** `unsigned_tx.json` to the air-gapped machine (USB, QR code, etc.). It contains no secrets.
4. **Air-gapped machine** — sign with the Ledger:
   ```bash
   ethernal sign --signer ledger --input unsigned_tx.json --output signed_tx.json
   ```
5. **Transfer** `signed_tx.json` back to an online machine.
6. **Online machine** — broadcast:
   ```bash
   ethernal send --input signed_tx.json --rpc-url https://...
   ```

Neither the unsigned nor the signed deposit-tx artifact contains the BLS private key. The Ledger never exports the secp256k1 key. Note that a merged `ethernal` binary on the air-gapped machine also carries the `gen`/`build`/`send` code paths it isn't using there — see `CHANGELOG.md` for that tradeoff.

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
- `gen` only supports `mainnet` and `hoodi` (BLS fork-version material).
- `build`/`sign`/`run`/`send` support all four (they just need chain ID + deposit contract address).
- For testnet ETH: use the testnet faucets — Hoodi `https://hoodi-faucet.pk910.de/`, Sepolia `https://sepoliafaucet.com/`, Holesky `https://holesky-faucet.pk910.de/`.

---

## Exit codes

All `ethernal` subcommands use a consistent set of exit codes you can script around:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Unexpected internal error |
| 2 | User / configuration error (bad input, missing/invalid flag, unknown network, missing `--withdrawal-address`, non-TTY `key new`, missing `--from`/`--nonce`/`--gas-limit` for RPC mode, build-side RPC chain-ID mismatch) |
| 3 | Signer / crypto error (Ledger not found, Ethereum app not open, invalid key, signer-side chain-ID mismatch, BLS/SSZ failure) |
| 4 | User abort (SIGINT, or rejected confirmation prompt) |
| 5 | Broadcast / RPC error (RPC dial failure, gas/nonce estimation failure, broadcast-side chain-ID mismatch, node rejection) — `build`/`run` estimation and `send` broadcast |

Script around these:

```bash
if ethernal sign ...; then
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

- **Private keys never appear in argv, environment dumps, or shell history when used correctly.** Local-signer keys come from env vars only; Ledger keys never leave the device. BLS mnemonics from `key new` are shown only on the controlling terminal and never on stdout/stderr/logs.
- **Signed artifacts and keystores are written with restricted perms** (0o600; receiver can verify a signed tx by recovering the sender and checking the tx hash).
- **Broadcast is gated by chain-ID match and operator confirmation.** A signed-for-Holesky transaction will not be broadcast to a mainnet RPC endpoint.

It does NOT protect:

- A compromised machine. If your build/sign machine is compromised, the unsigned tx data field (which encodes the deposit) could be silently altered. Verify on the Ledger screen before pressing confirm. A compromised keygen machine can capture the mnemonic at generation time — prefer air-gapped `key new` for mainnet.
- Network-level interception of the broadcast (not a concern for signed transactions — they cannot be modified without invalidating the signature).
- BLS keystore confidentiality. The keystore passphrase is your responsibility; use a strong one and clear `KEYSTORE_PASS` from your shell after use.
- A raw `--mnemonic-passphrase VALUE` on the command line (visible in `ps` and shell history) — see [Step 0](#step-0--create-validator-keys-ethernal-key).

### Key handling rules

- **BLS mnemonic (`key new` / `key recover`)** — write it down offline during the ceremony; store it offline only. Never commit it, pipe `key new` (refused), or paste it into tickets/chat. Prefer air-gapped generation for high-value validators.
- **Mnemonic passphrase (BIP-39 "25th word")** — prefer `--mnemonic-passphrase-env` or bare `--mnemonic-passphrase` (prompt). **Do not** use raw `--mnemonic-passphrase VALUE` for high-value mnemonics: the value is visible in the process table (`ps`) and shell history. A mistyped 25th word yields keys you cannot recover from the mnemonic alone.
- **Keystore passphrase** — env var (`--passphrase-env`) or TTY prompt-with-confirm; minimum 8 bytes after EIP-2335 normalization. There is no raw-argv form (unlike the mnemonic passphrase). Env vars persist for the shell lifetime (and `export VAR=secret` can land in shell history) — use a dedicated session and `unset` when done (see [Step 0](#step-0--create-validator-keys-ethernal-key)).
- `ETHERNAL_TX_PRIVATE_KEY` — env var only. There is NO `--private-key` flag. The env-var-name flag (`--private-key-env`) is validated to match `^[A-Z_][A-Z0-9_]*$` to prevent users from accidentally passing the key value.
- `LocalSigner` zeroizes the key bytes in memory when `Close()` is called (end of every `sign` / `run` invocation).
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

The typed exit codes let your automation distinguish between "operator rejected" (code 4 — likely intentional), "signer/crypto problem" (code 3 — investigate), and "RPC / broadcast error" (code 5). Code 5 covers an endpoint dial or gas/nonce estimation failure (`build`/`run`) and, on `send`, the broadcast safety guard tripping on a chain-ID mismatch — treat a send-side chain-ID mismatch as "wrong network, do not retry blindly".

---

## Recipes

### Recipe 1 — Local key, all on one machine (dev / CI)

```bash
export KEYSTORE_PASS=test-passphrase
export ETHERNAL_TX_PRIVATE_KEY=0x0101...   # synthetic; never real
mkdir -p ./keystores ./out

# Interactive key new (or recover from a fixed test mnemonic via stdin)
ethernal key new --output-dir ./keystores --passphrase-env KEYSTORE_PASS
# copy pubkey from the summary:

ethernal gen \
  --network hoodi --keystore-dir ./keystores/ \
  --pubkeys 0x... \
  --withdrawal-address 0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1 \
  --output-dir ./out --passphrase-env KEYSTORE_PASS

ethernal run \
  --network hoodi --signer local \
  --input-file ./out/deposit_data-*.json \
  --nonce 0 --output ./out/signed_tx.json

unset KEYSTORE_PASS ETHERNAL_TX_PRIVATE_KEY
```

### Recipe 2 — Ledger, one machine, broadcast immediately

```bash
export KEYSTORE_PASS=...

ethernal gen ... \
  --withdrawal-address 0x... \
  --output-dir ./out --passphrase-env KEYSTORE_PASS

ethernal run \
  --network hoodi --signer ledger \
  --input-file ./out/deposit_data-*.json \
  --nonce 17 --output ./out/signed_tx.json
# (confirm on Ledger)

ethernal send \
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
ethernal key new --output-dir ./keystores --passphrase-env KEYSTORE_PASS
# transfer keystores (encrypted) + note the pubkeys to online machine A
# keep the mnemonic offline only

# Online machine A
ethernal gen --network mainnet --i-understand-this-is-mainnet \
  --keystore-dir ./keystores/ --pubkeys 0x... \
  --withdrawal-address 0xYourChecksummedExecutionAddress \
  --output-dir ./out --passphrase-env KEYSTORE_PASS
ethernal build --network mainnet \
  --input-file ./out/deposit_data-*.json \
  --nonce ${NONCE} --output unsigned_tx.json
# transfer unsigned_tx.json via USB/QR to air-gapped machine

# Air-gapped machine B (no network)
ethernal sign --signer ledger \
  --input unsigned_tx.json --output signed_tx.json
# (confirm on Ledger; verify on-device fields per Security section)
# transfer signed_tx.json back via USB/QR

# Online machine A
ethernal send --input signed_tx.json --rpc-url https://your-mainnet-rpc
# (type "mainnet" to confirm)
```

### Recipe 4 — Multiple validators in one shot

```bash
ethernal key new --output-dir ./keystores --count 3 --passphrase-env KEYSTORE_PASS

ethernal gen --network hoodi --keystore-dir ./keystores/ \
  --pubkeys 0xpub1...,0xpub2...,0xpub3... \
  --withdrawal-address 0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1 \
  --output-dir ./out --passphrase-env KEYSTORE_PASS --parallel 4

# One sign per validator, increment nonce
BASE_NONCE=17
for i in 0 1 2; do
  ethernal run --network hoodi --signer ledger \
    --input-file ./out/deposit_data-*.json --index $i \
    --nonce $((BASE_NONCE + i)) \
    --output ./out/signed_${i}.json
done
```

### Recipe 5 — Recover additional indices from an existing mnemonic

```bash
# You already have indices 0..2; derive the next three
echo "$MNEMONIC" | ethernal key recover \
  --output-dir ./keystores \
  --start-index 3 \
  --count 3 \
  --passphrase-env KEYSTORE_PASS
```

### Recipe 6 — Pipe between commands

```bash
ethernal gen --network hoodi ... --withdrawal-address 0x... --dry-run | \
  ethernal build --network hoodi --input-file - --nonce 0 | \
  jq '.'   # pretty-print the unsigned tx
```

### Recipe 7 — Verify a signed tx independently

```bash
# Decode and inspect with cast
RAW=$(jq -r .rawRLP signed_tx.json)
cast tx --rpc-url https://your-rpc-url --from-rpc "$RAW"   # won't work for unbroadcast txs

# Or just decode locally
cast decode-typed-tx "$RAW"
```

---

## Troubleshooting

### `ethernal key` errors

| Symptom | Cause / fix |
|---|---|
| `key new requires an interactive terminal ...` (exit 2) | `key new` is TTY-only. Run it in a real terminal; do not pipe or redirect stdin/stdout. Use `key recover` for scripted mnemonic input. |
| `--output-dir: directory "..." does not exist` / `not writable` (exit 2) | Create the directory first (`mkdir -p`) and ensure write permission. |
| `--count: value 0 is invalid` (exit 2) | Pass `--count` ≥ 1. |
| Invalid mnemonic / checksum (exit 2, `key recover`) | Check word count (12/15/18/21/24), spelling against the English wordlist, and that the full phrase matches what you wrote down (including any mnemonic passphrase). |
| Ceremony re-entry mismatch → abort (exit 4) | You declined retry after a wrong re-entry, or sent SIGINT. Run `key new` again; the previous mnemonic was never written to disk. |
| Keystore passphrase too short (exit 2) | Keystore passphrase must be at least 8 bytes (after EIP-2335 normalization). |

### `ethernal gen` errors

| Symptom | Cause / fix |
|---|---|
| `--withdrawal-address: required flag not set` (exit 2) | Pass `--withdrawal-address` with an EIP-55 checksummed execution address. There is no default. |
| `--withdrawal-address: ... EIP-55 checksum mismatch` (exit 2) | Address must be correctly mixed-case EIP-55 (not all-lowercase). Tools like `cast to-check-sum-address` can re-checksum. Note: `build`'s `--from` is lenient and does **not** require EIP-55 — only `--withdrawal-address` is strict. |
| `mainnet selected; pass --i-understand-this-is-mainnet to acknowledge` (exit 2) | Add the flag. Mainnet is irreversible. |
| `pubkey ... not found in keystore directory` (exit 2) | The pubkey listed in `--pubkeys` has no matching keystore file. Check the keystore directory contents. |
| `decrypt: invalid passphrase` (exit 3) | Wrong `KEYSTORE_PASS`. The passphrase decrypts every keystore — all must share it. |
| `staking-deposit-cli not found in PATH` (exit 3, only with `--verify-with-deposit-cli`) | Either install `staking-deposit-cli >= 2.7.0`, set `--deposit-cli-path`, or drop the verify flag. |

### `ethernal build` errors

| Symptom | Cause / fix |
|---|---|
| `--index N: out of bounds (file has M entries)` (exit 2) | Your deposit data JSON has fewer entries than the index you requested. |
| `deposit entry validation: ...` (exit 2) | The deposit data JSON is malformed (zero pubkey, bad withdrawal credentials prefix, etc.). Regenerate with `ethernal gen`. |
| `value mismatch ...` (exit 2) | The entry's `amount` is not 32 ETH in Gwei. Only 32 ETH first deposits are currently supported. |

### `ethernal sign` errors

| Symptom | Cause / fix |
|---|---|
| `environment variable "ETHERNAL_TX_PRIVATE_KEY" is not set` (exit 3) | Set the env var (or use `--private-key-env` to point at a different one). |
| `--private-key-env: "0x..." is not a valid POSIX env var name` (exit 2) | You passed the hex key as the flag value. Pass the env var NAME instead, and put the key value into that env var. |
| `invalid private key: expected 32 bytes` (exit 3) | The env var contents are not a valid 32-byte hex secp256k1 key. The error never includes the key bytes. |
| `no Ledger device found` (exit 3) | Plug in the Ledger, unlock it, open the Ethereum app. On Linux, verify udev rules. |
| `ledger Ethereum app is not open` (exit 3) | Open the Ethereum app on the device, then retry. |
| `user rejected signing on Ledger` (exit 4) | You pressed the reject button on the device. Retry if intentional was confirm. |
| `ledger support requires the 'ledger' cargo feature; rebuild with --features ledger` (exit 3) | The binary was built without the Ledger transport. Rebuild with `cargo build --release --features ledger`. |

### `ethernal send` errors

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
- For everything else, run with `--verbose` and `--json-logs` (`ethernal gen`) to get structured diagnostics.
