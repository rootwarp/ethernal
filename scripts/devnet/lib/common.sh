#!/bin/bash
# Common functions and variables for devnet scripts

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the script directory (devnet root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source configuration
if [[ -f "${SCRIPT_DIR}/config/network.env" ]]; then
    source "${SCRIPT_DIR}/config/network.env"
fi

# Data directories
DATA_DIR="${SCRIPT_DIR}/data"
JWT_DIR="${DATA_DIR}/jwt"
EL_DATA_DIR="${DATA_DIR}/el"
CL_DATA_DIR="${DATA_DIR}/cl"
GENESIS_DIR="${DATA_DIR}/genesis"
KEYS_DIR="${DATA_DIR}/keys"

# Docker container names
CONTAINER_PREFIX="eth-devnet"
RETH_CONTAINER="${CONTAINER_PREFIX}-reth"
BEACON_CONTAINER="${CONTAINER_PREFIX}-beacon"
VALIDATOR_CONTAINER="${CONTAINER_PREFIX}-validator"

# Docker network name
DOCKER_NETWORK="${CONTAINER_PREFIX}-network"

# Print functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if a command exists
check_command() {
    local cmd=$1
    if ! command -v "$cmd" &> /dev/null; then
        return 1
    fi
    return 0
}

# Check if a Docker container is running
is_container_running() {
    local container=$1
    if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        return 0
    fi
    return 1
}

# Check if a Docker container exists (running or stopped)
container_exists() {
    local container=$1
    if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
        return 0
    fi
    return 1
}

# Stop a container if running
stop_container() {
    local container=$1
    if is_container_running "$container"; then
        log_info "Stopping container: $container"
        docker stop "$container" > /dev/null 2>&1 || true
    fi
}

# Remove a container if exists
remove_container() {
    local container=$1
    if container_exists "$container"; then
        log_info "Removing container: $container"
        docker rm -f "$container" > /dev/null 2>&1 || true
    fi
}

# Wait for a service to be ready
wait_for_service() {
    local url=$1
    local max_attempts=${2:-30}
    local attempt=1

    log_info "Waiting for service at $url..."
    while [[ $attempt -le $max_attempts ]]; do
        if curl -s "$url" > /dev/null 2>&1; then
            log_success "Service is ready"
            return 0
        fi
        echo -n "."
        sleep 2
        ((attempt++))
    done
    echo
    log_error "Service did not become ready after $max_attempts attempts"
    return 1
}

# Create Docker network if not exists
ensure_docker_network() {
    if ! docker network ls --format '{{.Name}}' | grep -q "^${DOCKER_NETWORK}$"; then
        log_info "Creating Docker network: $DOCKER_NETWORK"
        docker network create "$DOCKER_NETWORK" > /dev/null
    fi
}

# Remove Docker network
remove_docker_network() {
    if docker network ls --format '{{.Name}}' | grep -q "^${DOCKER_NETWORK}$"; then
        log_info "Removing Docker network: $DOCKER_NETWORK"
        docker network rm "$DOCKER_NETWORK" > /dev/null 2>&1 || true
    fi
}

# Get current timestamp for genesis
get_genesis_time() {
    # Use current time + 30 seconds to allow for setup
    echo $(($(date +%s) + 30))
}

# Validate that required data exists
validate_data_exists() {
    local name=$1
    local path=$2
    if [[ ! -e "$path" ]]; then
        log_error "$name not found at: $path"
        log_error "Please run the prerequisite scripts first"
        exit 1
    fi
}
