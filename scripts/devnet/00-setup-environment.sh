#!/bin/bash
# 00-setup-environment.sh
# Check prerequisites and create directory structure

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

echo "=============================================="
echo "  Ethereum Devnet - Environment Setup"
echo "=============================================="
echo

# Check required tools
log_info "Checking prerequisites..."

MISSING_TOOLS=()

if ! check_command docker; then
    MISSING_TOOLS+=("docker")
fi

if ! check_command jq; then
    MISSING_TOOLS+=("jq")
fi

if ! check_command curl; then
    MISSING_TOOLS+=("curl")
fi

if ! check_command openssl; then
    MISSING_TOOLS+=("openssl")
fi

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    log_error "Missing required tools: ${MISSING_TOOLS[*]}"
    echo
    echo "Please install the missing tools:"
    for tool in "${MISSING_TOOLS[@]}"; do
        case $tool in
            docker)
                echo "  - Docker: https://docs.docker.com/get-docker/"
                ;;
            jq)
                echo "  - jq: brew install jq (macOS) or apt-get install jq (Linux)"
                ;;
            curl)
                echo "  - curl: brew install curl (macOS) or apt-get install curl (Linux)"
                ;;
            openssl)
                echo "  - openssl: brew install openssl (macOS) or apt-get install openssl (Linux)"
                ;;
        esac
    done
    exit 1
fi

log_success "All required tools are installed"

# Check Docker is running
log_info "Checking Docker daemon..."
if ! docker info > /dev/null 2>&1; then
    log_error "Docker daemon is not running"
    echo "Please start Docker and try again"
    exit 1
fi
log_success "Docker daemon is running"

# Create directory structure
log_info "Creating directory structure..."

mkdir -p "${JWT_DIR}"
mkdir -p "${EL_DATA_DIR}"
mkdir -p "${CL_DATA_DIR}/beacon"
mkdir -p "${CL_DATA_DIR}/validator"
mkdir -p "${GENESIS_DIR}"
mkdir -p "${KEYS_DIR}"

log_success "Directory structure created"

# Pull required Docker images
log_info "Pulling required Docker images..."

echo "Pulling Reth image: ${RETH_IMAGE}"
docker pull "${RETH_IMAGE}" || log_warn "Failed to pull Reth image (may already exist)"

echo "Pulling Lighthouse image: ${LIGHTHOUSE_IMAGE}"
docker pull "${LIGHTHOUSE_IMAGE}" || log_warn "Failed to pull Lighthouse image (may already exist)"

echo "Pulling Genesis Generator image: ${GENESIS_GENERATOR_IMAGE}"
docker pull "${GENESIS_GENERATOR_IMAGE}" || log_warn "Failed to pull Genesis Generator image (may already exist)"

echo "Pulling eth2-val-tools image: ${ETH2_VAL_TOOLS_IMAGE}"
docker pull "${ETH2_VAL_TOOLS_IMAGE}" || log_warn "Failed to pull eth2-val-tools image (may already exist)"

log_success "Docker images ready"

echo
echo "=============================================="
log_success "Environment setup complete!"
echo "=============================================="
echo
echo "Directory structure created at: ${DATA_DIR}"
echo
echo "Next step: Run ./01-generate-jwt-secret.sh"
