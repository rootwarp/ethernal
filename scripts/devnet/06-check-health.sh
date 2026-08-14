#!/bin/bash
# 06-check-health.sh
# Verify all services are running and display endpoints

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

echo "=============================================="
echo "  Ethereum Devnet - Health Check"
echo "=============================================="
echo

ALL_HEALTHY=true

# Check Docker containers
echo "Container Status:"
echo "-----------------"

for container in "$RETH_CONTAINER" "$BEACON_CONTAINER" "$VALIDATOR_CONTAINER"; do
    if is_container_running "$container"; then
        echo -e "  ${GREEN}[RUNNING]${NC} $container"
    else
        echo -e "  ${RED}[STOPPED]${NC} $container"
        ALL_HEALTHY=false
    fi
done
echo

# Check Reth JSON-RPC
echo "Execution Layer (Reth):"
echo "-----------------------"

RETH_RESPONSE=$(curl -s -X POST http://localhost:${EL_HTTP_PORT} \
    -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null || echo "")

if [[ -n "$RETH_RESPONSE" ]] && echo "$RETH_RESPONSE" | jq -e '.result' > /dev/null 2>&1; then
    BLOCK_HEX=$(echo "$RETH_RESPONSE" | jq -r '.result')
    BLOCK_NUM=$((BLOCK_HEX))
    echo -e "  ${GREEN}[OK]${NC} JSON-RPC responding"
    echo "       Block number: ${BLOCK_NUM}"

    # Get chain ID
    CHAIN_RESPONSE=$(curl -s -X POST http://localhost:${EL_HTTP_PORT} \
        -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' 2>/dev/null || echo "")
    if [[ -n "$CHAIN_RESPONSE" ]]; then
        CHAIN_ID_HEX=$(echo "$CHAIN_RESPONSE" | jq -r '.result')
        echo "       Chain ID: $((CHAIN_ID_HEX))"
    fi

    # Get sync status
    SYNC_RESPONSE=$(curl -s -X POST http://localhost:${EL_HTTP_PORT} \
        -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":1}' 2>/dev/null || echo "")
    if [[ -n "$SYNC_RESPONSE" ]]; then
        SYNC_STATUS=$(echo "$SYNC_RESPONSE" | jq -r '.result')
        if [[ "$SYNC_STATUS" == "false" ]]; then
            echo "       Sync status: Synced"
        else
            echo "       Sync status: Syncing"
        fi
    fi
else
    echo -e "  ${RED}[ERROR]${NC} JSON-RPC not responding"
    ALL_HEALTHY=false
fi
echo

# Check Lighthouse Beacon Node
echo "Consensus Layer (Lighthouse Beacon):"
echo "------------------------------------"

BEACON_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:${CL_HTTP_PORT}/eth/v1/node/health 2>/dev/null || echo "000")

if [[ "$BEACON_HEALTH" == "200" ]]; then
    echo -e "  ${GREEN}[OK]${NC} Beacon API responding (healthy)"
elif [[ "$BEACON_HEALTH" == "206" ]]; then
    echo -e "  ${YELLOW}[SYNCING]${NC} Beacon API responding (syncing)"
else
    echo -e "  ${RED}[ERROR]${NC} Beacon API not responding (HTTP: ${BEACON_HEALTH})"
    ALL_HEALTHY=false
fi

# Get beacon node version
BEACON_VERSION=$(curl -s http://localhost:${CL_HTTP_PORT}/eth/v1/node/version 2>/dev/null | jq -r '.data.version' 2>/dev/null || echo "unknown")
if [[ "$BEACON_VERSION" != "unknown" ]] && [[ "$BEACON_VERSION" != "null" ]]; then
    echo "       Version: ${BEACON_VERSION}"
fi

# Get sync committee info
SYNC_INFO=$(curl -s http://localhost:${CL_HTTP_PORT}/eth/v1/node/syncing 2>/dev/null || echo "")
if [[ -n "$SYNC_INFO" ]]; then
    HEAD_SLOT=$(echo "$SYNC_INFO" | jq -r '.data.head_slot' 2>/dev/null || echo "unknown")
    IS_SYNCING=$(echo "$SYNC_INFO" | jq -r '.data.is_syncing' 2>/dev/null || echo "unknown")
    echo "       Head slot: ${HEAD_SLOT}"
    echo "       Is syncing: ${IS_SYNCING}"
fi

# Get finality checkpoints
FINALITY=$(curl -s http://localhost:${CL_HTTP_PORT}/eth/v1/beacon/states/head/finality_checkpoints 2>/dev/null || echo "")
if [[ -n "$FINALITY" ]]; then
    FINALIZED_EPOCH=$(echo "$FINALITY" | jq -r '.data.finalized.epoch' 2>/dev/null || echo "unknown")
    if [[ "$FINALIZED_EPOCH" != "unknown" ]] && [[ "$FINALIZED_EPOCH" != "null" ]]; then
        echo "       Finalized epoch: ${FINALIZED_EPOCH}"
    fi
fi
echo

# Check Validators
echo "Validators:"
echo "-----------"

# Get validator count from beacon API
VALIDATORS=$(curl -s "http://localhost:${CL_HTTP_PORT}/eth/v1/beacon/states/head/validators?status=active_ongoing" 2>/dev/null || echo "")
if [[ -n "$VALIDATORS" ]]; then
    ACTIVE_COUNT=$(echo "$VALIDATORS" | jq '.data | length' 2>/dev/null || echo "0")
    echo "       Active validators: ${ACTIVE_COUNT}"
fi

# Check if validator container is running and producing attestations
if is_container_running "$VALIDATOR_CONTAINER"; then
    echo -e "  ${GREEN}[OK]${NC} Validator client running"
else
    echo -e "  ${RED}[ERROR]${NC} Validator client not running"
    ALL_HEALTHY=false
fi
echo

# Block Production Check
echo "Block Production:"
echo "-----------------"

INITIAL_BLOCK=$((BLOCK_HEX))
log_info "Checking if blocks are being produced..."
sleep 12  # Wait for at least one slot

BLOCK_RESPONSE=$(curl -s -X POST http://localhost:${EL_HTTP_PORT} \
    -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null || echo "")

if [[ -n "$BLOCK_RESPONSE" ]]; then
    NEW_BLOCK_HEX=$(echo "$BLOCK_RESPONSE" | jq -r '.result')
    NEW_BLOCK=$((NEW_BLOCK_HEX))

    if [[ $NEW_BLOCK -gt $INITIAL_BLOCK ]]; then
        echo -e "  ${GREEN}[OK]${NC} Blocks are being produced"
        echo "       Block increased: ${INITIAL_BLOCK} -> ${NEW_BLOCK}"
    else
        echo -e "  ${YELLOW}[WARN]${NC} No new blocks yet"
        echo "       Current block: ${NEW_BLOCK}"
        echo "       (May still be initializing, try again in a few slots)"
    fi
fi
echo

# Summary
echo "=============================================="
if [[ "$ALL_HEALTHY" == "true" ]]; then
    log_success "All services are healthy!"
else
    log_error "Some services are not healthy"
fi
echo "=============================================="
echo
echo "Endpoints:"
echo "  - JSON-RPC HTTP:  http://localhost:${EL_HTTP_PORT}"
echo "  - WebSocket:      ws://localhost:${EL_WS_PORT}"
echo "  - Beacon API:     http://localhost:${CL_HTTP_PORT}"
echo
echo "Quick Tests:"
echo "  curl http://localhost:${EL_HTTP_PORT} -X POST -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}'"
echo "  curl http://localhost:${CL_HTTP_PORT}/eth/v1/node/health"
echo
echo "View Logs:"
echo "  docker logs -f ${RETH_CONTAINER}"
echo "  docker logs -f ${BEACON_CONTAINER}"
echo "  docker logs -f ${VALIDATOR_CONTAINER}"
