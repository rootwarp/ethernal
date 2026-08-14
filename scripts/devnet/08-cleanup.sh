#!/bin/bash
# 08-cleanup.sh
# Remove all containers, networks, and optionally data

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

echo "=============================================="
echo "  Ethereum Devnet - Cleanup"
echo "=============================================="
echo

# Parse arguments
REMOVE_DATA=false
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --data)
            REMOVE_DATA=true
            shift
            ;;
        --force|-f)
            FORCE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --data    Also remove all data directories (genesis, keys, chain data)"
            echo "  --force   Skip confirmation prompts"
            echo "  --help    Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Confirmation
if [[ "$FORCE" != "true" ]]; then
    echo "This will remove:"
    echo "  - All devnet Docker containers"
    echo "  - Docker network: ${DOCKER_NETWORK}"
    if [[ "$REMOVE_DATA" == "true" ]]; then
        echo "  - All data in: ${DATA_DIR}"
    fi
    echo
    read -p "Are you sure? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Cleanup cancelled"
        exit 0
    fi
fi

# Stop and remove containers
log_info "Removing containers..."

CONTAINERS=("$VALIDATOR_CONTAINER" "$BEACON_CONTAINER" "$RETH_CONTAINER")

for container in "${CONTAINERS[@]}"; do
    if container_exists "$container"; then
        log_info "Removing $container..."
        docker rm -f "$container" > /dev/null 2>&1 || true
    fi
done

log_success "Containers removed"

# Remove Docker network
remove_docker_network

# Remove data if requested
if [[ "$REMOVE_DATA" == "true" ]]; then
    log_info "Removing data directories..."

    if [[ -d "${DATA_DIR}" ]]; then
        rm -rf "${DATA_DIR}"
        log_success "Data directories removed"
    else
        log_info "No data directory found"
    fi
fi

echo
echo "=============================================="
log_success "Cleanup complete!"
echo "=============================================="
echo
if [[ "$REMOVE_DATA" == "true" ]]; then
    echo "All containers and data have been removed."
    echo "To start fresh: Run ./00-setup-environment.sh"
else
    echo "Containers and network removed, data preserved."
    echo "To remove data as well: Run ./08-cleanup.sh --data"
fi
