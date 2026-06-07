# testdata/

**WARNING — TEST-ONLY MATERIAL ONLY. DO NOT USE FOR REAL DEPOSITS.**

This directory holds:

- `keys.json`: deterministic BLS keystore secret + secp256k1 sender private key + withdrawal address used to drive golden fixture regeneration and certain e2e tests (see M0.10-1, architecture §11.4).
- `hoodi/` and `mainnet/`: committed golden fixtures (keystore, pubkeys, passphrase, deposit_data-expected.json) regenerated under the 0x01 withdrawal credential scheme.

All values here are public test vectors. Using `keys.json` (or any secret/passphrase under testdata/) on a real network will result in loss of funds or theft.

See source comments (e.g. `goldenSecret` in `test/e2e/hoodi_test.go`) for additional warnings. These fixtures exist solely to keep `make test` and `make refresh-golden` hermetic and reproducible.
