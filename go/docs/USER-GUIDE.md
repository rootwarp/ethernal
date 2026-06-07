# eth-utils User Guide

Comprehensive guide for the two CLIs in this monorepo:

- **`eth-deposit-gen`** — produces Launchpad-compatible deposit data JSON (BLS signatures over the deposit message) from EIP-2335 validator keystores.
- **`eth-deposit-tx`** — builds, signs (Ledger or local key), and broadcasts the Ethereum transaction that submits the deposit to the Beacon Chain deposit contract.

**Status:** `eth-deposit-gen` released as v1.0.0; `eth-deposit-tx` v0.1.0 is release-ready.

---

## Table of contents

1. [Concepts and workflow model](#concepts-and-workflow-model)
2. [Install](#install)
3. [Quick start (Hoodi testnet)](#quick-start-hoodi-testnet)
4. [Step 1 — Generate deposit data (`eth-deposit-gen`)](#step-1--generate-deposit-data-eth-deposit-gen)
5. [Step 2 — Build the unsigned transaction (`eth-deposit-tx build`)](#step-2--build-the-unsigned-transaction-eth-deposit-tx-build)
6. [Step 3 — Sign the transaction (`eth-deposit-tx sign`)](#step-3--sign-the-transaction-eth-deposit-tx-sign)
7. [Step 4 — Broadcast (optional) (`eth-deposit-tx send`)](#step-4--broadcast-optional-eth-deposit-tx-send)
8. [Convenience: `eth-deposit-tx run` (build + sign in one shot)](#convenience-eth-deposit-tx-run-build--sign-in-one-shot)
9. [Air-gapped workflow](#air-gapped-workflow)
10. [Networks](#networks)
11. [Exit codes](#exit-codes)
12. [Security](#security)
13. [Recipes](#recipes)
14. [Troubleshooting](#troubleshooting)

---

## Concepts and workflow model

A validator deposit takes two artifacts:

| Artifact | Produced by | Contains |
|---|---|---|
| **Deposit data JSON** | `eth-deposit-gen` | BLS-signed deposit message: validator pubkey, withdrawal credentials, signature, deposit_data_root, amount |
| **Signed Ethereum transaction** | `eth-deposit-tx` | EIP-1559 transaction calling the deposit contract's `deposit(bytes,bytes,bytes,bytes32)` with 32 ETH value, signed by the **sender's** secp256k1 key |

Two distinct keys are involved:
- **BLS validator key** (per validator) — held in EIP-2335 keystores; used by `eth-deposit-gen` to sign the deposit message. Never leaves the keystore decryption boundary.
- **secp256k1 sender key** — held in your Ledger (recommended) or env var (testing only); used by `eth-deposit-tx` to sign the Ethereum transaction that pays the 32 ETH. Whichever address holds this key needs ≥ 32 ETH + gas.

The two-phase split (`build` then `sign`) supports air-gapped operation: build the unsigned tx on an online machine, transfer the JSON to a signing machine (which may be offline), sign there, transfer the signed JSON back online, broadcast.

---

## Install

### Requirements

- **Go 1.26.0 or later** (matches `go/go.mod`).
- **CGO enabled** (default).
  - `eth-deposit-gen` always requires CGO via `herumi/bls-eth-go-binary`.
  - `eth-deposit-tx` requires CGO via the BLS dependency it picks up transitively, AND for the Ledger USB/HID bindings (`github.com/ethereum/go-ethereum/accounts/usbwallet` → `karalabe/usb`). Without CGO, the Ledger code path is replaced by a stub that returns an error if you select `--signer ledger`; the rest of the binary still works.
- **macOS** — Xcode Command Line Tools provide the C toolchain. No extra packages needed.
- **Linux** — install `libusb-1.0-0-dev` (Debian/Ubuntu) or `libusb1-devel` (Fedora/RHEL) so the Ledger USB bindings can build and run. For non-root device access, set up udev rules per https://github.com/LedgerHQ/udev-rules.
- **Windows** — not supported in v1.0.0.

### Install from a release

When v0.1.0 is tagged, prebuilt archives for `darwin-amd64`, `darwin-arm64`, `linux-amd64`, `linux-arm64` (plus SBOMs and checksums) are produced by goreleaser CI:

```bash
# Replace ${VERSION} and ${OS_ARCH} as appropriate
curl -L -o eth-utils.tar.gz \
  "https://github.com/rootwarp/eth-utils/releases/download/v${VERSION}/eth-deposit-tx_${OS_ARCH}.tar.gz"
tar xzf eth-utils.tar.gz
sha256sum -c checksums.txt   # verify
./eth-deposit-tx --version
```

### Install from source

```bash
git clone https://github.com/rootwarp/eth-utils.git
cd eth-utils
make build      # produces bin/eth-deposit-gen
make build-tx   # produces bin/eth-deposit-tx
```

Or via `go install` (per-binary):

```bash
go install github.com/rootwarp/eth-utils/go/cmd/eth-deposit-gen@latest
go install github.com/rootwarp/eth-utils/go/cmd/eth-deposit-tx@latest
```

Verify:

```bash
./bin/eth-deposit-gen --version
./bin/eth-deposit-tx --version
```

---

## Quick start (Hoodi testnet)

End-to-end deposit on Hoodi using a Ledger:

```bash
# 1. Generate deposit data
export KEYSTORE_PASS=my-keystore-passphrase
./bin/eth-deposit-gen \
  --network hoodi \
  --keystore-dir ./keystores/ \
  --pubkeys 0x8420760d0de00ed65f290ab2122e65933e168539ad261b5e444a5094c649272527a1509dd105a801922c359e46e33fb9 \
  --output-dir ./out \
  --passphrase-env KEYSTORE_PASS
unset KEYSTORE_PASS

# 2. Build unsigned tx (use --nonce explicitly if sender has prior txs)
./bin/eth-deposit-tx build \
  --network hoodi \
  --input-file ./out/deposit_data-*.json \
  --nonce 0 \
  --output ./out/unsigned_tx.json

# 3. Sign with Ledger (confirm on device)
./bin/eth-deposit-tx sign \
  --signer ledger \
  --input ./out/unsigned_tx.json \
  --output ./out/signed_tx.json

# 4. Broadcast (will prompt to type "hoodi" to confirm)
./bin/eth-deposit-tx send \
  --input ./out/signed_tx.json \
  --rpc-url https://your-hoodi-rpc-url \
  --wait-for-receipt
```

For a local-key dev flow, see the [recipes](#recipes) below.

---

## Step 1 — Generate deposit data (`eth-deposit-gen`)

### Synopsis

```
eth-deposit-gen --keystore-dir DIR --pubkeys HEX[,...] --network NET --output-dir DIR [options]
```

### Flags

| Flag | Description | Default |
|---|---|---|
| `--keystore-dir DIR` *(required)* | Directory containing EIP-2335 JSON keystore files, one per validator | — |
| `--pubkeys HEX[,...]` *(required)* | Comma-separated 96-hex-char BLS pubkeys (0x-prefixed or bare) | — |
| `--network NET` *(required)* | `mainnet` or `hoodi` | — |
| `--output-dir DIR` *(required)* | Existing, writable directory for `deposit_data-<ts>.json` | — |
| `--passphrase-env VAR` | Env var holding the keystore passphrase (omit for TTY prompt) | TTY prompt |
| `--i-understand-this-is-mainnet` | Required when `--network mainnet`; acknowledges irreversibility | `false` |
| `--dry-run` | Print JSON to stdout instead of writing a file; sha256 to stderr | `false` |
| `--parallel N` | Concurrent signing workers (1 to runtime.NumCPU()×4) | `1` |
| `--verbose` | Debug-level structured logging to stderr | `false` |
| `--json-logs` | Emit logs as JSON objects | `false` |
| `--verify-with-deposit-cli` | Cross-check output with `staking-deposit-cli >= 2.7.0` | `false` |
| `--deposit-cli-path PATH` | Path to `deposit` binary for verification | `deposit` (PATH) |

### Example — Hoodi single validator

```bash
export KEYSTORE_PASS=my-keystore-passphrase

./bin/eth-deposit-gen \
  --network hoodi \
  --keystore-dir ./keystores/ \
  --pubkeys 0x8420760d0de00ed65f290ab2122e65933e168539ad261b5e444a5094c649272527a1509dd105a801922c359e46e33fb9 \
  --output-dir ./out \
  --passphrase-env KEYSTORE_PASS
```

### Example — multiple validators, parallel signing

```bash
./bin/eth-deposit-gen \
  --network hoodi \
  --keystore-dir ./keystores/ \
  --pubkeys 0xpub1...,0xpub2...,0xpub3...,0xpub4... \
  --output-dir ./out \
  --passphrase-env KEYSTORE_PASS \
  --parallel 4
```

Output JSON is a single array with one entry per pubkey, in the order you supplied.

### Example — mainnet

Mainnet deposits are irreversible. The `--i-understand-this-is-mainnet` flag is required:

```bash
./bin/eth-deposit-gen \
  --network mainnet \
  --i-understand-this-is-mainnet \
  --keystore-dir ./keystores/ \
  --pubkeys 0xpub1... \
  --output-dir ./out \
  --passphrase-env KEYSTORE_PASS
```

Without the flag, `--network mainnet` exits with code 2.

### Example — dry-run preview

```bash
./bin/eth-deposit-gen ... --dry-run    # JSON to stdout, no file
```

### Output JSON shape

```json
[
  {
    "pubkey": "8420760d0de00ed65f290ab2122e65933e168539ad261b5e444a5094c649272527a1509dd105a801922c359e46e33fb9",
    "withdrawal_credentials": "0100000000000000000000005aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
    "amount": 32000000000,
    "signature": "a9e7b4e88886658acb53d72eb454ee8f108a1380db95155b1d871145944669a10bd073ee38d71489775a7a78364918810f1e1cb8888c1d6dade3fa2670bdd558e325d1f4626da66127321d160c07ef5866a7828d9978d8a2723d01476d4e5717",
    "deposit_message_root": "3e320f9b0a2c6e33536764bc0f7c332e5241ad96d9b8c9a3ea3de15512a964c7",
    "deposit_data_root": "cd59791bcc14902cae86760c9e87842517d511b8a6a935887f2d319c976b46a8",
    "fork_version": "10000910",
    "network_name": "hoodi",
    "deposit_cli_version": "2.7.0"
  }
]
```
(The concrete bytes above are from the regenerated `testdata/hoodi/deposit_data-expected.json` post-M0.10 refresh; real runs produce `deposit_data-<RFC3339Nano>-<sha256[:4]>.json`.)

---

## Step 2 — Build the unsigned transaction (`eth-deposit-tx build`)

### Synopsis

```
eth-deposit-tx build --input-file FILE --network NET [options]
```

Produces an EIP-1559 unsigned transaction in JSON. No signing happens — runs fully offline.

### Flags

| Flag | Description | Default |
|---|---|---|
| `--input-file PATH` / `--input PATH` / `-i PATH` *(required)* | Path to `deposit_data-*.json`, or `-` for stdin | — |
| `--network NET` / `-n NET` | `mainnet`, `hoodi`, `sepolia`, `holesky` | `hoodi` |
| `--output PATH` | Output file for unsigned tx JSON; omit or `-` for stdout | stdout |
| `--index N` | Which deposit entry to use when the JSON has multiple validators | `0` |
| `--rpc-url URL` | RPC endpoint for dynamic gas/nonce fetch (Phase 4 wiring; currently accepted-but-stored only) | — |
| `--gas-limit N` | EIP-1559 gas limit | `250000` |
| `--max-fee-per-gas WEI` | EIP-1559 max fee per gas (decimal wei) | `20000000000` (20 gwei) |
| `--max-priority-fee-per-gas WEI` | EIP-1559 priority fee per gas (decimal wei) | `1000000000` (1 gwei) |
| `--nonce N` | Sender account nonce; omit defaults to 0 (correct only for first-time sender) | `0` |

### Examples

Air-gapped build (all values explicit):

```bash
./bin/eth-deposit-tx build \
  --network hoodi \
  --input-file ./out/deposit_data-2026-06-07T06:11:44.170453Z-4f7dc6a8.json \
  --gas-limit 300000 \
  --max-fee-per-gas 30000000000 \
  --max-priority-fee-per-gas 2000000000 \
  --nonce 17 \
  --output unsigned_tx.json
```

Multiple validators — produce a tx per validator by varying `--index`:

```bash
for i in 0 1 2 3; do
  ./bin/eth-deposit-tx build \
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

## Step 3 — Sign the transaction (`eth-deposit-tx sign`)

### Synopsis

```
eth-deposit-tx sign --signer local|ledger --input FILE [options]
```

### Flags

| Flag | Description | Default |
|---|---|---|
| `--signer TYPE` *(required)* | `local` or `ledger` | — |
| `--input PATH` / `-i PATH` *(required)* | Path to unsigned tx JSON, or `-` for stdin | — |
| `--output PATH` / `-o PATH` | Output file for signed tx JSON (0o600 perms); omit or `-` for stdout | stdout |
| `--private-key-env VAR` | Env var name holding the hex private key (local signer only) | `ETH_DEPOSIT_TX_PRIVATE_KEY` |

### Option A — Local private key (testing only)

`LocalSigner` is for development, testing, and CI — **not for real funds**. Use Ledger for any mainnet or non-trivial testnet deposit.

The private key MUST come from an environment variable. There is no CLI flag to accept a key value (deliberate: never appears in argv or shell history). The env-var-name flag value must match the POSIX pattern `^[A-Z_][A-Z0-9_]*$` — if you accidentally paste the hex key as the flag value, sign refuses with exit code 2.

```bash
export ETH_DEPOSIT_TX_PRIVATE_KEY=0x0101010101010101010101010101010101010101010101010101010101010101  # synthetic test key

./bin/eth-deposit-tx sign \
  --signer local \
  --input ./out/unsigned_tx.json \
  --output ./out/signed_tx.json

unset ETH_DEPOSIT_TX_PRIVATE_KEY
```

The key bytes are zeroized in memory when sign exits (LocalSigner.Close).

To use a different env-var name (e.g., for a hosted CI secret):

```bash
export MY_DEPLOY_KEY=0x...
./bin/eth-deposit-tx sign --signer local --private-key-env MY_DEPLOY_KEY --input unsigned_tx.json --output signed_tx.json
```

### Option B — Ledger Nano

Prerequisites:

- Ledger Nano S or Nano X with current firmware
- Ethereum app installed and open on the device
- Binary built with CGO enabled
- Linux: `libusb-1.0` installed and Ledger udev rules in place (see [Install](#install))

```bash
./bin/eth-deposit-tx sign \
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

**Note on heuristics (v0.1.0):** the rejection / chain-ID-mismatch / app-not-open detection in `internal/signer/ledger.go` uses pattern matching on the device-side error strings and has NOT yet been validated against real hardware. If you observe unexpected error mappings on a real Ledger, file an issue describing what message you received so the heuristics can be tightened.

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

## Step 4 — Broadcast (optional) (`eth-deposit-tx send`)

### Synopsis

```
eth-deposit-tx send --input FILE --rpc-url URL [options]
```

Broadcasts a signed transaction via JSON-RPC with a double-confirmation prompt and optional receipt polling.

### Flags

| Flag | Description | Default |
|---|---|---|
| `--input PATH` / `-i PATH` *(required)* | Path to signed tx JSON, or `-` for stdin | — |
| `--rpc-url URL` *(required)* | JSON-RPC endpoint for the target network | — |
| `--yes` | Skip the typed-confirmation prompt (use for automation only) | `false` |
| `--wait-for-receipt` | Poll for the receipt after broadcast | `false` |
| `--receipt-timeout DUR` | Receipt poll timeout (Go duration, e.g. `120s`) | `60s` |
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
./bin/eth-deposit-tx send \
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

## Convenience: `eth-deposit-tx run` (build + sign in one shot)

When you're signing on the same machine that has the deposit data, `run` collapses build + sign into one command:

```bash
export ETH_DEPOSIT_TX_PRIVATE_KEY=0x...

./bin/eth-deposit-tx run \
  --network hoodi \
  --signer local \
  --input-file ./out/deposit_data-1716000000.json \
  --nonce 17 \
  --output ./out/signed_tx.json

unset ETH_DEPOSIT_TX_PRIVATE_KEY
```

Outputs:
- `signed_tx.json` (0o600) — SignedTx JSON
- `signed_tx.raw` (0o600) — just the `rawRLP` hex, convenient for `cast publish` or curl

Pass `--keep-unsigned` to also write the intermediate `unsigned_tx.json` (useful for auditing what was actually signed). Pass `--raw-output PATH` to override the auto-derived `.raw` filename.

The same flags work for `--signer ledger` — `run` calls the Ledger flow internally.

Use the two-step `build` → `sign` flow when the signing machine is air-gapped; use `run` for the convenience case.

---

## Air-gapped workflow

The two-phase design supports air-gapping the signing machine entirely:

```
[ Online machine #1 ]                                 [ Air-gapped signing machine ]
  eth-deposit-gen ...           ─USB/QR transfer──>     ./signing-machine/in/
                                                          eth-deposit-tx sign --signer ledger ...
  eth-deposit-tx build ...                              ./signing-machine/out/
                                <─USB/QR transfer──     signed_tx.json
[ Online machine #2 ]
  eth-deposit-tx send ...
```

1. **Online machine** — generate deposit data and the unsigned transaction:
   ```bash
   ./bin/eth-deposit-gen ... --output-dir ./out
   ./bin/eth-deposit-tx build --network hoodi --input-file ./out/deposit_data-*.json --nonce N --output unsigned_tx.json
   ```
2. **Transfer** `unsigned_tx.json` to the air-gapped machine (USB, QR code, etc.). It contains no secrets.
3. **Air-gapped machine** — sign with the Ledger:
   ```bash
   ./bin/eth-deposit-tx sign --signer ledger --input unsigned_tx.json --output signed_tx.json
   ```
4. **Transfer** `signed_tx.json` back to an online machine.
5. **Online machine** — broadcast:
   ```bash
   ./bin/eth-deposit-tx send --input signed_tx.json --rpc-url https://...
   ```

Neither artifact contains the private key. The Ledger never exports the key.

---

## Networks

Supported by both tools (see `internal/network/network.go`):

| Network | Chain ID | Deposit contract | Explorer |
|---|---|---|---|
| `mainnet` | 1 | `0x00000000219ab540356cBB839Cbe05303d7705Fa` | https://etherscan.io |
| `hoodi` | 560048 | `0x00000000219ab540356cBB839Cbe05303d7705Fa` | https://hoodi.etherscan.io |
| `sepolia` | 11155111 | `0x7f02C3E3c98b133055B8B348B2Ac625669Ed295D` | https://sepolia.etherscan.io |
| `holesky` | 17000 | `0x4242424242424242424242424242424242424242` | https://holesky.etherscan.io |

Notes:
- `eth-deposit-gen` only supports `mainnet` and `hoodi` (BLS fork-version material).
- `eth-deposit-tx` supports all four (it just needs chain ID + deposit contract address).
- For testnet ETH: use the testnet faucets — Hoodi `https://hoodi-faucet.pk910.de/`, Sepolia `https://sepoliafaucet.com/`, Holesky `https://holesky-faucet.pk910.de/`.

---

## Exit codes

Both tools use a consistent set of exit codes you can script around:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Unexpected internal error |
| 2 | User / configuration error (bad input, missing flag, invalid JSON, unknown network) |
| 3 | Signer / crypto error (Ledger not found, Ethereum app not open, invalid key, BLS/SSZ failure) |
| 4 | User abort (SIGINT, or rejected confirmation prompt) |
| 5 | Broadcast / RPC error — `eth-deposit-tx send` only (chain-ID mismatch, RPC dial failure, broadcast failure) |

Script around these:

```bash
if ./bin/eth-deposit-tx sign ...; then
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

The tools protect:

- **Private keys never appear in argv, environment dumps, or shell history when used correctly.** Local-signer keys come from env vars only; Ledger keys never leave the device.
- **Signed artifacts are protected against tampering at rest** (0o600 perms; receiver can verify by recovering the sender and checking the tx hash).
- **Broadcast is gated by chain-ID match and operator confirmation.** A signed-for-Holesky transaction will not be broadcast to a mainnet RPC endpoint.

The tools do NOT protect:

- A compromised machine. If your build/sign machine is compromised, the unsigned tx data field (which encodes the deposit) could be silently altered. Verify on the Ledger screen before pressing confirm.
- Network-level interception of the broadcast (not a concern for signed transactions — they cannot be modified without invalidating the signature).
- BLS keystore confidentiality. The keystore passphrase is your responsibility; use a strong one and clear `KEYSTORE_PASS` from your shell after use.

### Key handling rules

- `ETH_DEPOSIT_TX_PRIVATE_KEY` — env var only. There is NO `--private-key` flag. The env-var-name flag (`--private-key-env`) is validated to match `^[A-Z_][A-Z0-9_]*$` to prevent users from accidentally passing the key value.
- `LocalSigner` zeroizes the key bytes in memory when `Close()` is called (end of every `sign` / `run` invocation).
- For mainnet: use Ledger. The local signer is explicitly tagged "for development only" in its godoc and is not recommended for any real-fund deposit.
- The synthetic test key in `go/testdata/phase3/holesky/private_key.txt` is `0x0101010101010101010101010101010101010101010101010101010101010101` (obvious pattern). Never use it with real funds; it's for tests only.

### On-device verification (Ledger)

Before pressing confirm on your Ledger, **always verify on the screen**:

1. **Chain ID** matches your intended network (1 = mainnet, 17000 = Holesky, etc.).
2. **To address** is the deposit contract address for your network (see [Networks](#networks)). A different address means something is wrong — abort.
3. **Value** is exactly `32 ETH` (`32.000000`). Any other value is wrong.
4. **From address** (recovered by sign and printed in the output) matches the Ledger-derived address you expect to fund the deposit.

Reject on the device if anything is off. The CLI exits with code 4 and no broadcast happens.

### Exit codes as a security tool

The typed exit codes let your automation distinguish between "operator rejected" (code 4 — likely intentional), "signer/crypto problem" (code 3 — investigate), and "broadcast safety guard tripped" (code 5 — wrong network, do not retry blindly). Treat code 5 with care: it usually means a chain-ID mismatch caught a real bug.

---

## Recipes

### Recipe 1 — Local key, all on one machine (dev / CI)

```bash
export KEYSTORE_PASS=test-passphrase
export ETH_DEPOSIT_TX_PRIVATE_KEY=0x0101...   # synthetic; never real

./bin/eth-deposit-gen \
  --network hoodi --keystore-dir ./keystores/ \
  --pubkeys 0x... --output-dir ./out --passphrase-env KEYSTORE_PASS

./bin/eth-deposit-tx run \
  --network hoodi --signer local \
  --input-file ./out/deposit_data-*.json \
  --nonce 0 --output ./out/signed_tx.json

unset KEYSTORE_PASS ETH_DEPOSIT_TX_PRIVATE_KEY
```

### Recipe 2 — Ledger, one machine, broadcast immediately

```bash
export KEYSTORE_PASS=...

./bin/eth-deposit-gen ... --output-dir ./out --passphrase-env KEYSTORE_PASS

./bin/eth-deposit-tx run \
  --network hoodi --signer ledger \
  --input-file ./out/deposit_data-*.json \
  --nonce 17 --output ./out/signed_tx.json
# (confirm on Ledger)

./bin/eth-deposit-tx send \
  --input ./out/signed_tx.json \
  --rpc-url https://your-hoodi-rpc \
  --wait-for-receipt --receipt-output ./out/receipt.json
# (type "hoodi" to confirm broadcast)

unset KEYSTORE_PASS
```

### Recipe 3 — Air-gapped Ledger (mainnet-ready)

```bash
# Online machine A
./bin/eth-deposit-gen --network mainnet --i-understand-this-is-mainnet \
  --keystore-dir ./keystores/ --pubkeys 0x... \
  --output-dir ./out --passphrase-env KEYSTORE_PASS
./bin/eth-deposit-tx build --network mainnet \
  --input-file ./out/deposit_data-*.json \
  --nonce ${NONCE} --output unsigned_tx.json
# transfer unsigned_tx.json via USB/QR to air-gapped machine

# Air-gapped machine B (no network)
./bin/eth-deposit-tx sign --signer ledger \
  --input unsigned_tx.json --output signed_tx.json
# (confirm on Ledger; verify on-device fields per Security section)
# transfer signed_tx.json back via USB/QR

# Online machine A
./bin/eth-deposit-tx send --input signed_tx.json --rpc-url https://your-mainnet-rpc
# (type "mainnet" to confirm)
```

### Recipe 4 — Multiple validators in one shot

```bash
./bin/eth-deposit-gen --network hoodi --keystore-dir ./keystores/ \
  --pubkeys 0xpub1...,0xpub2...,0xpub3... \
  --output-dir ./out --passphrase-env KEYSTORE_PASS --parallel 4

# One sign per validator, increment nonce
BASE_NONCE=17
for i in 0 1 2; do
  ./bin/eth-deposit-tx run --network hoodi --signer ledger \
    --input-file ./out/deposit_data-*.json --index $i \
    --nonce $((BASE_NONCE + i)) \
    --output ./out/signed_${i}.json
done
```

### Recipe 5 — Pipe between commands

```bash
./bin/eth-deposit-gen --network hoodi ... --dry-run | \
  ./bin/eth-deposit-tx build --network hoodi --input-file - --nonce 0 | \
  jq '.'   # pretty-print the unsigned tx
```

### Recipe 6 — Verify a signed tx independently

```bash
# Decode and inspect with cast
RAW=$(jq -r .rawRLP signed_tx.json)
cast tx --rpc-url https://your-rpc-url --from-rpc "$RAW"   # won't work for unbroadcast txs

# Or just decode locally
cast decode-typed-tx "$RAW"
```

---

## Troubleshooting

### `eth-deposit-gen` errors

| Symptom | Cause / fix |
|---|---|
| `mainnet selected; pass --i-understand-this-is-mainnet to acknowledge` (exit 2) | Add the flag. Mainnet is irreversible. |
| `pubkey ... not found in keystore directory` (exit 2) | The pubkey listed in `--pubkeys` has no matching keystore file. Check the keystore directory contents. |
| `decrypt: invalid passphrase` (exit 3) | Wrong `KEYSTORE_PASS`. The passphrase decrypts every keystore — all must share it. |
| `staking-deposit-cli not found in PATH` (exit 3, only with `--verify-with-deposit-cli`) | Either install `staking-deposit-cli >= 2.7.0`, set `--deposit-cli-path`, or drop the verify flag. |

### `eth-deposit-tx build` errors

| Symptom | Cause / fix |
|---|---|
| `--index N: out of bounds (file has M entries)` (exit 2) | Your deposit data JSON has fewer entries than the index you requested. |
| `deposit entry validation: ...` (exit 2) | The deposit data JSON is malformed (zero pubkey, bad withdrawal credentials prefix, etc.). Regenerate with `eth-deposit-gen`. |
| `value mismatch ...` (exit 2) | The entry's `amount` is not 32 ETH in Gwei. Only 32 ETH first deposits are supported in v0.1.0. |

### `eth-deposit-tx sign` errors

| Symptom | Cause / fix |
|---|---|
| `environment variable "ETH_DEPOSIT_TX_PRIVATE_KEY" is not set` (exit 3) | Set the env var (or use `--private-key-env` to point at a different one). |
| `--private-key-env: "0x..." is not a valid POSIX env var name` (exit 2) | You passed the hex key as the flag value. Pass the env var NAME instead, and put the key value into that env var. |
| `invalid private key: expected 32 bytes` (exit 3) | The env var contents are not a valid 32-byte hex secp256k1 key. The error never includes the key bytes. |
| `no Ledger device found` (exit 3) | Plug in the Ledger, unlock it, open the Ethereum app. On Linux, verify udev rules. |
| `ledger Ethereum app is not open` (exit 3) | Open the Ethereum app on the device, then retry. |
| `user rejected signing on Ledger` (exit 4) | You pressed the reject button on the device. Retry if intentional was confirm. |
| `ledger support requires CGO_ENABLED=1` (exit 3) | The binary was built without CGO. Rebuild with `make build-tx` (default sets `CGO_ENABLED=1`). |

### `eth-deposit-tx send` errors

| Symptom | Cause / fix |
|---|---|
| `RPC chain ID does not match configured network` (exit 5) | The RPC endpoint reports a different chain ID than the signed tx. You're pointing at the wrong network. Do NOT use `--yes` to bypass. |
| `dial RPC: ...` (exit 5) | Bad `--rpc-url` or network connectivity issue. |
| `eth_sendRawTransaction: nonce too low` (exit 5) | The sender's actual nonce is higher than what you signed. Rebuild with a correct `--nonce`, re-sign, retry. |
| `eth_sendRawTransaction: insufficient funds` (exit 5) | The sender address doesn't have 32 ETH + gas. Fund it. |
| `eth_sendRawTransaction: known transaction` (exit 5) | This exact tx was already broadcast. Check the explorer for the receipt. |

### General

- If `make e2e-mock` passes but real testnet broadcast fails, the gap is usually nonce or insufficient funds.
- For Ledger error-string mismatches (the heuristics aren't real-hardware-validated in v0.1.0), file an issue with the exact error text.
- For everything else, run with `--verbose` and `--json-logs` (eth-deposit-gen) to get structured diagnostics.
