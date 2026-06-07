#!/usr/bin/env bash
#
# e2e-testnet.sh — Manual E2E testnet deposit procedure for eth-deposit-tx.
#
# This script orchestrates the full build → run → send flow against a live
# testnet RPC endpoint. It is intended for manual validation after a code change
# and requires a funded testnet account.
#
# Required env vars:
#   RPC_URL                   — JSON-RPC endpoint URL (e.g. https://holesky.infura.io/v3/<key>)
#   ETH_DEPOSIT_TX_PRIVATE_KEY — Hex-encoded secp256k1 private key (0x-prefixed) for signing
#
# Optional env vars:
#   DEPOSIT_DATA_FILE  — Path to deposit_data JSON (default: testdata/phase3/holesky/unsigned_tx.json
#                        is the signed fixture; use the actual deposit_data source here)
#   NETWORK            — Network name (default: holesky)
#   RECEIPT_TIMEOUT    — Max seconds to wait for receipt (default: 120)
#
# Usage:
#   cd go
#   export RPC_URL=https://holesky.infura.io/v3/<key>
#   export ETH_DEPOSIT_TX_PRIVATE_KEY=0x<your-test-key>
#   bash scripts/e2e-testnet.sh
#
# WARNING: This script BROADCASTS a real transaction that SPENDS REAL ETH
# (even on testnet, ensure you use a funded test account and that the
# deposit data points at a test validator pubkey that can be discarded).
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NETWORK="${NETWORK:-holesky}"
RECEIPT_TIMEOUT="${RECEIPT_TIMEOUT:-120}"

if [[ -z "${RPC_URL:-}" ]]; then
  echo "ERROR: RPC_URL env var is required." >&2
  echo "  Set it to your testnet JSON-RPC endpoint, e.g.:" >&2
  echo "  export RPC_URL=https://holesky.infura.io/v3/<key>" >&2
  exit 2
fi

if [[ -z "${ETH_DEPOSIT_TX_PRIVATE_KEY:-}" ]]; then
  echo "ERROR: ETH_DEPOSIT_TX_PRIVATE_KEY env var is required." >&2
  echo "  Set it to a 0x-prefixed secp256k1 hex private key for the funded test account." >&2
  echo "  WARNING: Never use a key that holds real mainnet ETH." >&2
  exit 2
fi

# Script must run from the go/ module root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_ROOT="${SCRIPT_DIR}/.."
cd "${GO_ROOT}"

# Resolve deposit data file.
if [[ -z "${DEPOSIT_DATA_FILE:-}" ]]; then
  # Default: use the phase3 fixture deposit data from the test suite.
  # This contains synthetic (test-only) validator data and is safe for testnet.
  DEPOSIT_DATA_FILE="cmd/eth-deposit-tx/testdata/deposit-fixture.json"
fi

if [[ ! -f "${DEPOSIT_DATA_FILE}" ]]; then
  echo "ERROR: DEPOSIT_DATA_FILE not found: ${DEPOSIT_DATA_FILE}" >&2
  exit 2
fi

# Output directory stamped with ISO-8601 timestamp.
TIMESTAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
ARTIFACTS_DIR="testdata/deposit-e2e/${TIMESTAMP}"

if [[ -d "${ARTIFACTS_DIR}" ]]; then
  echo "WARN: Output directory already exists: ${ARTIFACTS_DIR}" >&2
  echo "WARN: Existing artifacts will NOT be overwritten." >&2
fi
mkdir -p "${ARTIFACTS_DIR}"

echo "=== eth-deposit-tx E2E testnet validation ==="
echo "Network:         ${NETWORK}"
echo "RPC URL:         ${RPC_URL}"
echo "Deposit data:    ${DEPOSIT_DATA_FILE}"
echo "Artifacts dir:   ${ARTIFACTS_DIR}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Build the eth-deposit-tx binary.
# ---------------------------------------------------------------------------
echo "[1/5] Building eth-deposit-tx..."
CGO_ENABLED=1 go build -o "${ARTIFACTS_DIR}/eth-deposit-tx" ./cmd/eth-deposit-tx
echo "      Binary: ${ARTIFACTS_DIR}/eth-deposit-tx"

BIN="${ARTIFACTS_DIR}/eth-deposit-tx"

# ---------------------------------------------------------------------------
# Step 2: Run build+sign (the run subcommand) with the local signer.
# ---------------------------------------------------------------------------
echo "[2/5] Running build+sign (run subcommand)..."
SIGNED_JSON="${ARTIFACTS_DIR}/signed.json"
SIGNED_RAW="${ARTIFACTS_DIR}/signed.raw"

"${BIN}" run \
  --network "${NETWORK}" \
  --input-file "${DEPOSIT_DATA_FILE}" \
  --signer local \
  --output "${SIGNED_JSON}" \
  --raw-output "${SIGNED_RAW}" \
  --keep-unsigned

echo "      Signed tx: ${SIGNED_JSON}"
echo "      Raw RLP:   ${SIGNED_RAW}"

# ---------------------------------------------------------------------------
# Step 3: Display the signed tx summary for manual inspection.
# ---------------------------------------------------------------------------
echo "[3/5] Signed tx summary (inspect before broadcasting):"
if command -v python3 &>/dev/null; then
  python3 -m json.tool "${SIGNED_JSON}" | grep -E '"(hash|from|chainId|nonce|value)"' | head -10 || true
else
  grep -E '"(hash|from|chainId|nonce|value)"' "${SIGNED_JSON}" | head -10 || true
fi
echo ""

# ---------------------------------------------------------------------------
# Step 4: Broadcast via send --yes.
# ---------------------------------------------------------------------------
echo "[4/5] Broadcasting to ${NETWORK}..."
RECEIPT_JSON="${ARTIFACTS_DIR}/receipt.json"

"${BIN}" send \
  --input "${SIGNED_JSON}" \
  --rpc-url "${RPC_URL}" \
  --yes \
  --wait-for-receipt \
  --receipt-timeout "${RECEIPT_TIMEOUT}s" \
  --receipt-output "${RECEIPT_JSON}" 2>&1 | tee "${ARTIFACTS_DIR}/send-output.txt"

# ---------------------------------------------------------------------------
# Step 5: Extract and display result.
# ---------------------------------------------------------------------------
echo ""
echo "[5/5] Results:"
TX_HASH="$(grep "^Tx hash:" "${ARTIFACTS_DIR}/send-output.txt" | awk '{print $3}' || true)"

if [[ -n "${TX_HASH}" ]]; then
  echo "      Tx hash:  ${TX_HASH}"
  case "${NETWORK}" in
    holesky) echo "      Explorer: https://holesky.etherscan.io/tx/${TX_HASH}" ;;
    sepolia)  echo "      Explorer: https://sepolia.etherscan.io/tx/${TX_HASH}" ;;
    hoodi)    echo "      Explorer: https://hoodi.etherscan.io/tx/${TX_HASH}" ;;
    *)        echo "      (No explorer URL configured for network ${NETWORK})" ;;
  esac
else
  echo "WARN: Could not extract tx hash from send output." >&2
fi

echo ""
echo "Artifacts saved to: ${ARTIFACTS_DIR}/"
ls -la "${ARTIFACTS_DIR}/"
echo ""
echo "=== E2E testnet run complete ==="
echo ""
echo "NEXT STEP: Fill in the validation report template:"
echo "  docs/USER-GUIDE.md"
