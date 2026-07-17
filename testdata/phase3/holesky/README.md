# Phase 3 Holesky Test Fixtures

## Files

| File | Description |
|------|-------------|
| `private_key.txt` | Synthetic 32-byte secp256k1 private key (deterministic test key) |
| `unsigned_tx.json` | Unsigned Holesky deposit transaction (copied from `testdata/phase2/holesky/unsigned_tx_golden.json`) |
| `signed_tx_golden.json` | Signed transaction produced by the CLI using the synthetic key |

---

## Synthetic private key

The key in `private_key.txt` is:

```
0x0101010101010101010101010101010101010101010101010101010101010101
```

This is a deterministic 32-byte repeating pattern chosen for test identifiability. It corresponds to:

- **Address**: `0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1`

**WARNING: NEVER use this key with real funds.** It is a synthetic test key with a known private value and is committed to this repository. Any funds sent to the corresponding address are permanently at risk.

---

## Relationship to Phase 2 fixtures

`unsigned_tx.json` is a verbatim copy of `testdata/phase2/holesky/unsigned_tx_golden.json`. It represents a Holesky testnet (chainId=17000) Beacon Chain deposit transaction for the `0x42424242...` deposit contract.

---

## Regenerating the golden file

If the signing logic changes (e.g., go-ethereum version bump that changes the RLP encoding), regenerate with:

```sh
cd go
ETH_DEPOSIT_TX_PRIVATE_KEY=$(cat testdata/phase3/holesky/private_key.txt | tr -d '\n') \
  go run ./cmd/eth-deposit sign \
  --signer local \
  --input testdata/phase3/holesky/unsigned_tx.json \
  --output testdata/phase3/holesky/signed_tx_golden.json
```

Then update the SHA256 checksum below.

---

## SHA256 checksums

```
67c1f5a9b2f595892b0aad06104211405c2ad67d2da16cba815c03e26f80ccf2  signed_tx_golden.json
```

Verify with:
```sh
shasum -a 256 go/testdata/phase3/holesky/signed_tx_golden.json
```
