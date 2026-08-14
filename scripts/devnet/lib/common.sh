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

# ---------------------------------------------------------------------------
# Execution Layer JSON-RPC helpers
# ---------------------------------------------------------------------------

EL_RPC_URL="http://localhost:${EL_HTTP_PORT}"

# Call an EL JSON-RPC method and print its `result`.
# Usage: el_rpc <method> [params_json]   (params default: [])
# Returns non-zero (after logging why) if the node is unreachable, the response
# carries an `error`, or the payload is not the expected shape. Call it as
# `if ! out=$(el_rpc ...); then ...; fi` so `set -e` does not mask the reason.
el_rpc() {
    local method=$1
    local params=${2:-[]}
    local response

    response=$(curl -s --max-time 10 -X POST "${EL_RPC_URL}" \
        -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}" \
        2>/dev/null) || true

    if [[ -z "$response" ]]; then
        log_error "No response from the execution layer at ${EL_RPC_URL}"
        log_error "Is the devnet running? Try ./06-check-health.sh"
        return 1
    fi

    if echo "$response" | jq -e 'has("error")' > /dev/null 2>&1; then
        log_error "RPC error from ${method}: $(echo "$response" | jq -c '.error')"
        return 1
    fi

    if ! echo "$response" | jq -e 'has("result")' > /dev/null 2>&1; then
        log_error "Malformed RPC response from ${method}: ${response}"
        return 1
    fi

    echo "$response" | jq -r '.result'
}

# Convert a 0x-prefixed hex quantity to a decimal string.
# Uses bc: wei values routinely exceed the 64-bit range of bash arithmetic.
hex_to_dec() {
    local hex=${1#0x}
    hex=${hex#0X}
    if [[ -z "$hex" || ! "$hex" =~ ^[0-9a-fA-F]+$ ]]; then
        echo "0"
        return 0
    fi
    BC_LINE_LENGTH=0 bc <<< "ibase=16; $(echo "$hex" | tr '[:lower:]' '[:upper:]')"
}

# Tidy bc output: bc renders values below 1 as ".5", so restore the leading
# zero, then trim trailing fractional zeros.
format_decimal() {
    local out=$1
    [[ "$out" == .* ]] && out="0${out}"
    [[ "$out" == -.* ]] && out="-0${out#-.}"
    printf '%s' "$out" | sed -e 's/\.\([0-9]*[1-9]\)0*$/.\1/' -e 's/\.0*$//'
}

# Format a decimal wei string as ETH.
wei_to_eth() {
    format_decimal "$(BC_LINE_LENGTH=0 bc <<< "scale=18; ${1} / 1000000000000000000")"
}

# Format a decimal wei string as gwei.
wei_to_gwei() {
    format_decimal "$(BC_LINE_LENGTH=0 bc <<< "scale=9; ${1} / 1000000000")"
}

# Normalise a user-supplied block tag into a JSON-RPC block parameter.
# Accepts the named tags, a 0x quantity, or a plain decimal block number.
normalize_block_tag() {
    local tag=$1
    case "$tag" in
        latest|earliest|pending|safe|finalized)
            printf '%s' "$tag" ;;
        0x*|0X*)
            printf '%s' "$tag" ;;
        ''|*[!0-9]*)
            log_error "Invalid block tag: ${tag}"
            log_error "Expected latest/earliest/pending/safe/finalized, a decimal number, or 0x hex"
            return 1 ;;
        *)
            printf '0x%x' "$tag" ;;
    esac
}
