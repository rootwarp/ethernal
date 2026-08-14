#!/bin/bash
# 07-stop-devnet.sh
# Gracefully stop all devnet containers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

echo "=============================================="
echo "  Ethereum Devnet - Stopping Services"
echo "=============================================="
echo

# Stop containers in reverse order (validator -> beacon -> reth)
CONTAINERS=("$VALIDATOR_CONTAINER" "$BEACON_CONTAINER" "$RETH_CONTAINER")

for container in "${CONTAINERS[@]}"; do
    if is_container_running "$container"; then
        log_info "Stopping $container..."
        docker stop "$container" > /dev/null 2>&1
        log_success "Stopped $container"
    else
        log_info "$container is not running"
    fi
done

echo
echo "=============================================="
log_success "All services stopped"
echo "=============================================="
echo
echo "Containers are stopped but preserved."
echo "To restart: Run ./04-start-execution-layer.sh and ./05-start-consensus-layer.sh"
echo "To remove containers and data: Run ./08-cleanup.sh"
