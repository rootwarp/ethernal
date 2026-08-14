#!/bin/bash
# query-balance.sh
# Query the ETH balance and nonce of an account on the execution layer.
#
# Not part of the numbered 00-08 setup sequence - run it any time the devnet
# is up.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

ADDRESS=""
BLOCK_TAG="latest"
JSON_OUTPUT=false

usage() {
    echo "Usage: $0 [ADDRESS] [OPTIONS]"
    echo
    echo "Query the balance and nonce of an account on the devnet execution layer."
    echo
    echo "Arguments:"
    echo "  ADDRESS         0x-prefixed 20-byte address (default: the pre-funded"
    echo "                  DEV_ACCOUNT from config/network.env)"
    echo
    echo "Options:"
    echo "  --block TAG     latest, earliest, pending, safe, finalized, a decimal"
    echo "                  block number, or a 0x quantity (default: latest)"
    echo "  --json          Emit JSON instead of the formatted summary"
    echo "  --help, -h      Show this message"
    echo
    echo "Examples:"
    echo "  $0"
    echo "  $0 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    echo "  $0 --block 0 --json"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --block)
            if [[ -z "${2:-}" ]]; then
                log_error "--block requires a value"
                exit 1
            fi
            BLOCK_TAG="$2"
            shift 2
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
            if [[ -n "$ADDRESS" ]]; then
                log_error "Unexpected extra argument: $1"
                exit 1
            fi
            ADDRESS="$1"
            shift
            ;;
    esac
done

ADDRESS="${ADDRESS:-$DEV_ACCOUNT}"

if [[ ! "$ADDRESS" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    log_error "Not a valid 20-byte address: ${ADDRESS}"
    exit 1
fi

if ! BLOCK_PARAM=$(normalize_block_tag "$BLOCK_TAG"); then
    exit 1
fi

RPC_PARAMS="[\"${ADDRESS}\", \"${BLOCK_PARAM}\"]"

if ! BALANCE_HEX=$(el_rpc eth_getBalance "$RPC_PARAMS"); then exit 1; fi
if ! NONCE_HEX=$(el_rpc eth_getTransactionCount "$RPC_PARAMS"); then exit 1; fi
if ! CODE=$(el_rpc eth_getCode "$RPC_PARAMS"); then exit 1; fi

BALANCE_WEI=$(hex_to_dec "$BALANCE_HEX")
BALANCE_ETH=$(wei_to_eth "$BALANCE_WEI")
NONCE_DEC=$(hex_to_dec "$NONCE_HEX")

# An account with no deployed code is an EOA
if [[ "$CODE" == "0x" || -z "$CODE" || "$CODE" == "null" ]]; then
    IS_EOA=true
else
    IS_EOA=false
    CODE_BYTES=$(( (${#CODE} - 2) / 2 ))
fi

if [[ "$JSON_OUTPUT" == "true" ]]; then
    # balanceWei stays a string: it can exceed JSON's safe integer range
    jq -n \
        --arg address "$ADDRESS" \
        --arg block "$BLOCK_PARAM" \
        --arg balanceWei "$BALANCE_WEI" \
        --arg balanceEth "$BALANCE_ETH" \
        --argjson nonce "$NONCE_DEC" \
        --argjson isEoa "$IS_EOA" \
        '{address: $address, block: $block, balanceWei: $balanceWei,
          balanceEth: $balanceEth, nonce: $nonce, isEoa: $isEoa}'
    exit 0
fi

echo "=============================================="
echo "  Ethereum Devnet - Account Balance"
echo "=============================================="
echo
echo "Address:  ${ADDRESS}"
echo "Block:    ${BLOCK_PARAM}"
echo
echo "Balance:  ${BALANCE_ETH} ETH"
echo "          ${BALANCE_WEI} wei"
echo "Nonce:    ${NONCE_DEC}"

if [[ "$IS_EOA" == "true" ]]; then
    echo -e "Type:     ${GREEN}EOA${NC} (no code)"
else
    echo -e "Type:     ${YELLOW}Contract${NC} (${CODE_BYTES} bytes of code)"
fi
echo
