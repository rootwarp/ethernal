---
name: verify
description: Verify the eth-deposit CLI end-to-end (gen → build → sign → send) using repo fixtures and a local anvil node.
---

# Verify eth-deposit

Build: `cd go && make build` → `bin/eth-deposit` (needs CGO).

## Fixtures (all synthetic, committed)

- `testdata/hoodi/` — keystore + `passphrase.txt` + `pubkeys.txt` + `deposit_data-expected.json` (golden for `gen`)
- `testdata/phase2/holesky/` — `deposit_data_single.json` + `unsigned_tx_golden.json` (golden for `build`)
- `testdata/phase3/holesky/` — `private_key.txt` (key `0x0101…01`, address `0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1`) + `signed_tx_golden.json` (golden for `sign`)

## Golden checks

- gen: `KEYSTORE_PASSPHRASE=$(cat testdata/hoodi/passphrase.txt) bin/eth-deposit gen --network hoodi --keystore-dir testdata/hoodi/keystores --pubkeys $(cat testdata/hoodi/pubkeys.txt) --output-dir <tmp> --passphrase-env KEYSTORE_PASSPHRASE` → diff vs `deposit_data-expected.json`
- build: `bin/eth-deposit build --network holesky --input-file testdata/phase2/holesky/deposit_data_single.json` → diff vs `unsigned_tx_golden.json`
- sign: `ETH_DEPOSIT_TX_PRIVATE_KEY=$(cat testdata/phase3/holesky/private_key.txt) bin/eth-deposit sign --signer local --input testdata/phase3/holesky/unsigned_tx.json` → diff vs `signed_tx_golden.json`

## Live broadcast (anvil)

```sh
anvil --chain-id 560048 --port 8599 --silent &   # hoodi chain ID
cast rpc --rpc-url http://127.0.0.1:8599 anvil_setBalance 0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1 0x21e19e0c9bab2400000
```

Full pipe chain (all four stages, stdin/stdout):

```sh
bin/eth-deposit gen --network hoodi --keystore-dir testdata/hoodi/keystores \
  --pubkeys $(cat testdata/hoodi/pubkeys.txt) --output-dir <tmp> --dry-run --passphrase-env KEYSTORE_PASSPHRASE \
 | bin/eth-deposit build --network hoodi --input-file - --nonce <N> \
 | bin/eth-deposit sign --signer local --input - \
 | bin/eth-deposit send --yes --input - --rpc-url http://127.0.0.1:8599 --wait-for-receipt
```

Verify on-chain: `cast tx --rpc-url http://127.0.0.1:8599 <hash>`; deposit contract balance grows 32 ETH per send.

Interactive send confirmation: pipe the network name (`echo hoodi | … send …` without `--yes`); wrong name → exit 4.

## Gotchas

- `gen` needs `--passphrase-env` in pipes — without it it prompts on /dev/tty and dies when no TTY.
- `gen --dry-run` still requires a valid existing `--output-dir` even though it writes nothing.
- `build --rpc-url` is inert (accepted-but-stored, USER-GUIDE §build); nonce defaults to 0 — pass `--nonce` explicitly for accounts with history.
- Exit codes: 0 ok, 2 user error, 3 signer/crypto, 4 abort, 5 broadcast/RPC (send-side chain-ID mismatch is 5, not 3).
- Ledger signer path needs hardware — not coverable here.
