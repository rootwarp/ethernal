---
name: verify
description: Verify the ethernal CLI end-to-end (gen → build → sign → send) using repo fixtures and a local anvil node.
---

# Verify ethernal

Build: `make build` (repo root) → `target/release/ethernal`. Ledger hardware support needs `cargo build --release --features ledger`; without the feature `--signer ledger` exits 3.

## Fixtures (all synthetic, committed)

- `testdata/hoodi/` — keystore + `passphrase.txt` + `pubkeys.txt` + `deposit_data-expected.json` (golden for `gen`)
- `testdata/phase2/holesky/` — `deposit_data_single.json` + `unsigned_tx_golden.json` (golden for `build`)
- `testdata/phase3/holesky/` — `private_key.txt` (key `0x0101…01`, address `0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1`) + `signed_tx_golden.json` (golden for `sign`)

## Golden checks

- gen: `KEYSTORE_PASSPHRASE=$(cat testdata/hoodi/passphrase.txt) target/release/ethernal gen --network hoodi --keystore-dir testdata/hoodi/keystores --pubkeys $(cat testdata/hoodi/pubkeys.txt) --output-dir <tmp> --passphrase-env KEYSTORE_PASSPHRASE` → diff vs `deposit_data-expected.json`
- build: `target/release/ethernal build --network holesky --input-file testdata/phase2/holesky/deposit_data_single.json` → diff vs `unsigned_tx_golden.json`
- sign: `ETHERNAL_TX_PRIVATE_KEY=$(cat testdata/phase3/holesky/private_key.txt) target/release/ethernal sign --signer local --input testdata/phase3/holesky/unsigned_tx.json` → diff vs `signed_tx_golden.json`

## Live broadcast (anvil)

```sh
anvil --chain-id 560048 --port 8599 --silent &   # hoodi chain ID
cast rpc --rpc-url http://127.0.0.1:8599 anvil_setBalance 0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1 0x21e19e0c9bab2400000
```

Full pipe chain (all four stages, stdin/stdout):

```sh
target/release/ethernal gen --network hoodi --keystore-dir testdata/hoodi/keystores \
  --pubkeys $(cat testdata/hoodi/pubkeys.txt) --output-dir <tmp> --dry-run --passphrase-env KEYSTORE_PASSPHRASE \
 | target/release/ethernal build --network hoodi --input-file - --nonce <N> \
 | target/release/ethernal sign --signer local --input - \
 | target/release/ethernal send --yes --input - --rpc-url http://127.0.0.1:8599 --wait-for-receipt
```

Verify on-chain: `cast tx --rpc-url http://127.0.0.1:8599 <hash>`; deposit contract balance grows 32 ETH per send.

Interactive send confirmation: pipe the network name (`echo hoodi | … send …` without `--yes`); wrong name → exit 4.

## Hybrid (RPC) mode probes

`--rpc-url` on build/run is real:

- `build --rpc-url <node> --from <addr>` with nonce/gas omitted resolves nonce (pending), maxFee (2·baseFee+tip), and gas (estimate·6/5) from the node — probe by `anvil_setNonce` to a nonzero value and asserting it appears in the output.
- `build --rpc-url` without `--from` when `--nonce` or `--gas-limit` is omitted → exit 2 at config time.
- `run --signer local --rpc-url` derives the sender from the key (no --from flag); `run --signer ledger --rpc-url` requires both `--nonce` and `--gas-limit` → exit 2 otherwise.
- Dead RPC endpoint → exit 5; RPC chain-ID mismatch vs `--network` → exit 2; API keys in the RPC URL are redacted from stderr (grep for the key — must be absent).

## Gotchas

- `gen` needs `--passphrase-env` in pipes — without it it prompts on /dev/tty and dies when no TTY (exit 2, message names the flag).
- `gen --dry-run` does NOT require `--output-dir` (writes JSON to stdout).
- Missing required flags exit 2 on all subcommands.
- Exit codes: 0 ok, 2 user/config error (incl. build-side chain-ID mismatch), 3 signer/crypto (signer-side chain-ID mismatch), 4 abort (incl. SIGINT during RPC estimation), 5 broadcast/RPC (incl. broadcast-side chain-ID mismatch).
- `ws://` RPC URLs are not supported (http/https only) — dial fails with exit 5.
- Ledger signer path needs hardware — not coverable here.
