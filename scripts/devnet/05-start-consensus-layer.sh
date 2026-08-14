#!/bin/bash
# 05-start-consensus-layer.sh
# Start Lighthouse beacon node and validator client

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

echo "=============================================="
echo "  Ethereum Devnet - Consensus Layer Startup"
echo "=============================================="
echo

# Check prerequisites
validate_data_exists "JWT secret" "${JWT_DIR}/jwt.hex"
validate_data_exists "CL config" "${GENESIS_DIR}/config.yaml"
validate_data_exists "CL genesis" "${GENESIS_DIR}/genesis.ssz"

# Check if Reth is running
if ! is_container_running "$RETH_CONTAINER"; then
    log_error "Reth container is not running"
    log_error "Please run ./04-start-execution-layer.sh first"
    exit 1
fi

# Stop existing containers if running
for container in "$BEACON_CONTAINER" "$VALIDATOR_CONTAINER"; do
    if is_container_running "$container"; then
        log_warn "$container is already running"
        read -p "Do you want to restart it? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            continue
        fi
        stop_container "$container"
    fi
    remove_container "$container"
done

# Ensure Docker network exists
ensure_docker_network

# Create data directories
mkdir -p "${CL_DATA_DIR}/beacon"
mkdir -p "${CL_DATA_DIR}/validator"

# Start Lighthouse Beacon Node
log_info "Starting Lighthouse beacon node..."

docker run -d \
    --name "${BEACON_CONTAINER}" \
    --network "${DOCKER_NETWORK}" \
    --restart unless-stopped \
    -p "${CL_HTTP_PORT}:5052" \
    -p "${CL_P2P_PORT}:9000/tcp" \
    -p "${CL_P2P_PORT}:9000/udp" \
    -p "${CL_METRICS_PORT}:5054" \
    -v "${CL_DATA_DIR}/beacon:/data" \
    -v "${GENESIS_DIR}:/genesis:ro" \
    -v "${JWT_DIR}:/jwt:ro" \
    "${LIGHTHOUSE_IMAGE}" \
    lighthouse \
    beacon_node \
    --datadir=/data \
    --testnet-dir=/genesis \
    --execution-endpoint=http://${RETH_CONTAINER}:8551 \
    --execution-jwt=/jwt/jwt.hex \
    --http \
    --http-address=0.0.0.0 \
    --http-port=5052 \
    --http-allow-origin="*" \
    --metrics \
    --metrics-address=0.0.0.0 \
    --metrics-port=5054 \
    --disable-peer-scoring \
    --enable-private-discovery \
    --staking \
    --enr-address=127.0.0.1 \
    --enr-udp-port=9000 \
    --enr-tcp-port=9000 \
    --disable-packet-filter \
    --subscribe-all-subnets \
    --slots-per-restore-point=32

log_success "Beacon node started"

# Wait for beacon node to be ready
log_info "Waiting for beacon node API to be ready..."
sleep 5

MAX_ATTEMPTS=60
ATTEMPT=1
while [[ $ATTEMPT -le $MAX_ATTEMPTS ]]; do
    RESPONSE=$(curl -s http://localhost:${CL_HTTP_PORT}/eth/v1/node/health 2>/dev/null || echo "")
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:${CL_HTTP_PORT}/eth/v1/node/health 2>/dev/null || echo "000")

    # 200 = healthy, 206 = syncing (acceptable for devnet)
    if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "206" ]]; then
        log_success "Beacon node API is ready"
        break
    fi

    echo -n "."
    sleep 2
    ((ATTEMPT++))
done

if [[ $ATTEMPT -gt $MAX_ATTEMPTS ]]; then
    log_error "Beacon node API did not become ready"
    log_info "Check container logs: docker logs ${BEACON_CONTAINER}"
    exit 1
fi

# Import validator keys into Lighthouse
log_info "Setting up validator keystores..."

# Check if there are validator keys to import
if [[ -d "${KEYS_DIR}/validators" ]] && [[ -n "$(ls -A ${KEYS_DIR}/validators 2>/dev/null)" ]]; then
    # Copy keys to validator data directory
    mkdir -p "${CL_DATA_DIR}/validator/validators"

    for keydir in "${KEYS_DIR}/validators"/*; do
        if [[ -d "$keydir" ]]; then
            PUBKEY=$(basename "$keydir")
            DEST_DIR="${CL_DATA_DIR}/validator/validators/${PUBKEY}"
            mkdir -p "$DEST_DIR"

            # Copy keystore
            if [[ -f "${keydir}/voting-keystore.json" ]]; then
                cp "${keydir}/voting-keystore.json" "$DEST_DIR/"
            fi
        fi
    done

    # Copy secrets
    if [[ -d "${KEYS_DIR}/secrets" ]]; then
        cp -r "${KEYS_DIR}/secrets" "${CL_DATA_DIR}/validator/"
    fi

    log_success "Validator keystores configured"
else
    log_warn "No validator keys found - validator will start without keys"
fi

# Start Lighthouse Validator Client
log_info "Starting Lighthouse validator client..."

docker run -d \
    --name "${VALIDATOR_CONTAINER}" \
    --network "${DOCKER_NETWORK}" \
    --restart unless-stopped \
    -v "${CL_DATA_DIR}/validator:/data" \
    -v "${GENESIS_DIR}:/genesis:ro" \
    "${LIGHTHOUSE_IMAGE}" \
    lighthouse \
    validator_client \
    --datadir=/data \
    --testnet-dir=/genesis \
    --beacon-nodes=http://${BEACON_CONTAINER}:5052 \
    --init-slashing-protection \
    --suggested-fee-recipient="${DEV_ACCOUNT}" \
    --graffiti="eth-devnet" \
    --http \
    --http-address=0.0.0.0 \
    --http-port=5062 \
    --unencrypted-http-transport \
    --http-allow-origin="*"

log_success "Validator client started"

echo
echo "=============================================="
log_success "Consensus Layer startup complete!"
echo "=============================================="
echo
echo "Lighthouse Endpoints:"
echo "  - Beacon API:     http://localhost:${CL_HTTP_PORT}"
echo "  - Beacon Metrics: http://localhost:${CL_METRICS_PORT}/metrics"
echo
echo "Containers:"
echo "  - Beacon:    ${BEACON_CONTAINER}"
echo "  - Validator: ${VALIDATOR_CONTAINER}"
echo
echo "View logs:"
echo "  docker logs -f ${BEACON_CONTAINER}"
echo "  docker logs -f ${VALIDATOR_CONTAINER}"
echo
echo "Next step: Run ./06-check-health.sh"
