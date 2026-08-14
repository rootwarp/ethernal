#!/bin/bash
# query-block.sh
# Show execution-layer data for a block.
#
# Not part of the numbered 00-08 setup sequence - run it any time the devnet
# is up.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

# GAS_PER_BLOB, 2**17 (EIP-4844)
GAS_PER_BLOB=131072

BLOCK_TAG="latest"
JSON_OUTPUT=false
SHOW_TXS=false

usage() {
    echo "Usage: $0 [BLOCK] [OPTIONS]"
    echo
    echo "Show data for a block on the devnet execution layer."
    echo
    echo "Arguments:"
    echo "  BLOCK           latest, earliest, pending, safe, finalized, a decimal"
    echo "                  block number, or a 0x quantity (default: latest)"
    echo
    echo "Options:"
    echo "  --txs           List the transaction hashes in the block"
    echo "  --json          Emit the raw RPC result instead of the summary"
    echo "  --help, -h      Show this message"
    echo
    echo "Examples:"
    echo "  $0"
    echo "  $0 finalized"
    echo "  $0 42 --txs"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --txs)
            SHOW_TXS=true
            shift
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        -*)
            log_error "Unknown option: $1"
            echo
            usage
            exit 1
            ;;
        *)
            BLOCK_TAG="$1"
            shift
            ;;
    esac
done

if ! BLOCK_PARAM=$(normalize_block_tag "$BLOCK_TAG"); then
    exit 1
fi

# false = return transaction hashes only, not full transaction objects
if ! BLOCK=$(el_rpc eth_getBlockByNumber "[\"${BLOCK_PARAM}\", false]"); then
    exit 1
fi

if [[ -z "$BLOCK" || "$BLOCK" == "null" ]]; then
    case "$BLOCK_PARAM" in
        finalized|safe)
            log_error "No ${BLOCK_PARAM} block yet"
            log_info "The chain finalises two epochs in, i.e. after 64 slots (~12.8 min)."
            log_info "Check progress with: ./query-block.sh latest"
            ;;
        *)
            log_error "Block not found: ${BLOCK_TAG}"
            ;;
    esac
    exit 1
fi

if [[ "$JSON_OUTPUT" == "true" ]]; then
    echo "$BLOCK" | jq .
    exit 0
fi

# Pull the fields out in one pass; missing keys come back as empty strings
read -r NUMBER_HEX HASH PARENT_HASH TIMESTAMP_HEX GAS_USED_HEX GAS_LIMIT_HEX \
        BASE_FEE_HEX MINER STATE_ROOT SIZE_HEX BLOB_GAS_HEX EXCESS_BLOB_HEX \
        EXTRA_DATA <<EOF
$(echo "$BLOCK" | jq -r '[.number, .hash, .parentHash, .timestamp, .gasUsed,
    .gasLimit, .baseFeePerGas, .miner, .stateRoot, .size, .blobGasUsed,
    .excessBlobGas, .extraData] | map(. // "") | @tsv')
EOF

TX_COUNT=$(echo "$BLOCK" | jq -r '.transactions | length')
WITHDRAWAL_COUNT=$(echo "$BLOCK" | jq -r 'if .withdrawals then (.withdrawals | length) else "n/a" end')

NUMBER=$(hex_to_dec "$NUMBER_HEX")
TIMESTAMP=$(hex_to_dec "$TIMESTAMP_HEX")
GAS_USED=$(hex_to_dec "$GAS_USED_HEX")
GAS_LIMIT=$(hex_to_dec "$GAS_LIMIT_HEX")
SIZE=$(hex_to_dec "$SIZE_HEX")

BLOCK_DATE=$(date -r "${TIMESTAMP}" 2>/dev/null || date -d "@${TIMESTAMP}" 2>/dev/null || echo "unknown")
AGE=$(( $(date +%s) - TIMESTAMP ))

if [[ "$GAS_LIMIT" != "0" ]]; then
    GAS_PCT=$(format_decimal "$(BC_LINE_LENGTH=0 bc <<< "scale=2; ${GAS_USED} * 100 / ${GAS_LIMIT}")")
else
    GAS_PCT="0"
fi

echo "=============================================="
echo "  Ethereum Devnet - Block Data"
echo "=============================================="
echo
echo "Number:       ${NUMBER}"
echo "Hash:         ${HASH}"
echo "Parent:       ${PARENT_HASH}"
echo "State root:   ${STATE_ROOT}"
echo
echo "Timestamp:    ${TIMESTAMP} (${BLOCK_DATE})"
echo "Age:          ${AGE}s ago"
echo
echo "Fee recipient: ${MINER}"
echo "Gas used:     ${GAS_USED} / ${GAS_LIMIT} (${GAS_PCT}%)"

if [[ -n "$BASE_FEE_HEX" ]]; then
    BASE_FEE_WEI=$(hex_to_dec "$BASE_FEE_HEX")
    echo "Base fee:     ${BASE_FEE_WEI} wei ($(wei_to_gwei "$BASE_FEE_WEI") gwei)"
fi

echo "Size:         ${SIZE} bytes"
echo "Transactions: ${TX_COUNT}"
echo "Withdrawals:  ${WITHDRAWAL_COUNT}"

# Blob fields exist from Deneb onwards; this devnet runs Fulu from genesis
if [[ -n "$BLOB_GAS_HEX" ]]; then
    BLOB_GAS=$(hex_to_dec "$BLOB_GAS_HEX")
    EXCESS_BLOB=$(hex_to_dec "${EXCESS_BLOB_HEX:-0x0}")
    echo "Blobs:        $(( BLOB_GAS / GAS_PER_BLOB )) (${BLOB_GAS} blob gas, excess ${EXCESS_BLOB})"
fi

if [[ -n "$EXTRA_DATA" && "$EXTRA_DATA" != "0x" ]]; then
    echo "Extra data:   ${EXTRA_DATA}"
fi

if [[ "$SHOW_TXS" == "true" ]]; then
    echo
    if [[ "$TX_COUNT" == "0" ]]; then
        echo "Transactions: (none)"
    else
        echo "Transaction hashes:"
        echo "$BLOCK" | jq -r '.transactions[] | "  " + .'
    fi
fi
echo
