#!/bin/bash
# 04-start-execution-layer.sh
# Initialize and start Reth container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

echo "=============================================="
echo "  Ethereum Devnet - Execution Layer Startup"
echo "=============================================="
echo

# Check prerequisites
validate_data_exists "JWT secret" "${JWT_DIR}/jwt.hex"
validate_data_exists "EL genesis" "${GENESIS_DIR}/genesis.json"

# Stop existing container if running
if is_container_running "$RETH_CONTAINER"; then
    log_warn "Reth container is already running"
    read -p "Do you want to restart it? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Keeping existing container"
        exit 0
    fi
    stop_container "$RETH_CONTAINER"
fi

# Remove existing container
remove_container "$RETH_CONTAINER"

# Create Docker network
ensure_docker_network

# Check if Reth needs initialization
# Reth writes its MDBX database to <datadir>/db/mdbx.dat
RETH_INITIALIZED=false
if [[ -f "${EL_DATA_DIR}/db/mdbx.dat" ]]; then
    RETH_INITIALIZED=true
    log_info "Reth data directory exists, skipping initialization"
else
    log_info "Initializing Reth with genesis..."

    docker run --rm \
        -v "${EL_DATA_DIR}:/data" \
        -v "${GENESIS_DIR}:/genesis:ro" \
        "${RETH_IMAGE}" \
        init \
        --datadir=/data \
        --chain=/genesis/genesis.json

    log_success "Reth initialized"
fi

# Start Reth container
log_info "Starting Reth container..."

# Notes on flag differences from Geth:
#   - --chain replaces --networkid as the genesis source; it must stay set on
#     every start, not just on init.
#   - Reth is archive by default, so --syncmode/--gcmode have no equivalent.
#   - Reth has no vhosts checks and no account management, so --http.vhosts,
#     --authrpc.vhosts and --allow-insecure-unlock are dropped.
#   - "engine" is not a valid --http.api namespace; the Engine API is served
#     only on the authenticated authrpc port.
docker run -d \
    --name "${RETH_CONTAINER}" \
    --network "${DOCKER_NETWORK}" \
    --restart unless-stopped \
    -p "${EL_HTTP_PORT}:8545" \
    -p "${EL_WS_PORT}:8546" \
    -p "${EL_AUTH_PORT}:8551" \
    -p "${EL_P2P_PORT}:30303/tcp" \
    -p "${EL_P2P_PORT}:30303/udp" \
    -v "${EL_DATA_DIR}:/data" \
    -v "${GENESIS_DIR}:/genesis:ro" \
    -v "${JWT_DIR}:/jwt:ro" \
    "${RETH_IMAGE}" \
    node \
    --datadir=/data \
    --chain=/genesis/genesis.json \
    --http \
    --http.addr=0.0.0.0 \
    --http.port=8545 \
    --http.api=eth,net,web3,admin,debug,txpool,trace \
    --http.corsdomain="*" \
    --ws \
    --ws.addr=0.0.0.0 \
    --ws.port=8546 \
    --ws.api=eth,net,web3,admin,debug,txpool,trace \
    --ws.origins="*" \
    --authrpc.addr=0.0.0.0 \
    --authrpc.port=8551 \
    --authrpc.jwtsecret=/jwt/jwt.hex \
    --port=30303 \
    --discovery.port=30303 \
    --network-id="${NETWORK_ID}" \
    --disable-discovery

log_success "Reth container started"

# Wait for RPC to be ready
log_info "Waiting for Reth RPC to be ready..."
sleep 3

MAX_ATTEMPTS=30
ATTEMPT=1
while [[ $ATTEMPT -le $MAX_ATTEMPTS ]]; do
    RESPONSE=$(curl -s -X POST http://localhost:${EL_HTTP_PORT} \
        -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' 2>/dev/null || echo "")

    if [[ -n "$RESPONSE" ]] && echo "$RESPONSE" | jq -e '.result' > /dev/null 2>&1; then
        CHAIN_ID_HEX=$(echo "$RESPONSE" | jq -r '.result')
        CHAIN_ID_DEC=$((CHAIN_ID_HEX))
        log_success "Reth RPC is ready (Chain ID: ${CHAIN_ID_DEC})"
        break
    fi

    echo -n "."
    sleep 2
    ((ATTEMPT++))
done

if [[ $ATTEMPT -gt $MAX_ATTEMPTS ]]; then
    log_error "Reth RPC did not become ready"
    log_info "Check container logs: docker logs ${RETH_CONTAINER}"
    exit 1
fi

echo
echo "=============================================="
log_success "Execution Layer startup complete!"
echo "=============================================="
echo
echo "Reth Endpoints:"
echo "  - JSON-RPC HTTP: http://localhost:${EL_HTTP_PORT}"
echo "  - WebSocket:     ws://localhost:${EL_WS_PORT}"
echo "  - Engine API:    http://localhost:${EL_AUTH_PORT} (authenticated)"
echo
echo "Container: ${RETH_CONTAINER}"
echo "View logs: docker logs -f ${RETH_CONTAINER}"
echo
echo "Next step: Run ./05-start-consensus-layer.sh"
