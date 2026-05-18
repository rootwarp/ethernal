# eth-utils

Ethereum utility CLIs for validator operations — building, signing, and broadcasting Beacon Chain deposit transactions from Launchpad-compatible deposit data.

## Tools

| Tool | Language | Description |
|------|----------|-------------|
| `eth-deposit-gen` | Go | Generate Launchpad-compatible `deposit_data` JSON for existing BLS validator keys |
| `eth-deposit-tx` | Go | Build, sign, and broadcast Ethereum Beacon Chain deposit transactions |

See the [User Guide](go/docs/USER-GUIDE.md) for installation, command reference, security guidance, recipes, and troubleshooting covering both binaries.

## Quickstart

Typical end-to-end flow:

```bash
# Step 1: generate deposit data from your validator keystores
eth-deposit-gen --network hoodi --keystore-dir ./keystores \
  --pubkeys 0x<your-pubkey> --output-dir ./out

# Step 2: build and sign the deposit transaction
eth-deposit-tx run --network hoodi --input-file ./out/deposit_data-*.json \
  --signer local --output signed.json

# Step 3: broadcast
eth-deposit-tx send --input signed.json --rpc-url https://hoodi.example/rpc
```

## Repository structure

```
eth-utils/
├── go/
│   ├── cmd/
│   │   ├── eth-deposit-gen/   # BLS deposit data generator
│   │   └── eth-deposit-tx/    # Deposit transaction builder + signer + broadcaster
│   ├── internal/              # Shared Go packages (tx, signer, network)
│   └── docs/USER-GUIDE.md     # Comprehensive user guide for both binaries
├── python/                    # Python utilities (in development)
├── rust/                      # Rust utilities (in development)
├── scripts/                   # Build and E2E scripts
└── tools/                     # Developer tooling
```

## License

MIT — see [LICENSE](LICENSE).