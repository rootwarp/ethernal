#!/bin/bash
# 01-generate-jwt-secret.sh
# Generate JWT authentication secret for EL/CL communication

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

echo "=============================================="
echo "  Ethereum Devnet - JWT Secret Generation"
echo "=============================================="
echo

JWT_FILE="${JWT_DIR}/jwt.hex"

# Check if JWT already exists
if [[ -f "${JWT_FILE}" ]]; then
    log_warn "JWT secret already exists at: ${JWT_FILE}"
    read -p "Do you want to regenerate it? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Keeping existing JWT secret"
        exit 0
    fi
fi

# Create directory if not exists
mkdir -p "${JWT_DIR}"

# Generate 256-bit (32-byte) random hex secret
log_info "Generating JWT secret..."
openssl rand -hex 32 > "${JWT_FILE}"

# Verify the file was created and has correct format
if [[ ! -f "${JWT_FILE}" ]]; then
    log_error "Failed to create JWT secret file"
    exit 1
fi

JWT_CONTENT=$(cat "${JWT_FILE}")
if [[ ! ${JWT_CONTENT} =~ ^[a-f0-9]{64}$ ]]; then
    log_error "Generated JWT secret has invalid format"
    exit 1
fi

# Set appropriate permissions (read-only for owner)
chmod 600 "${JWT_FILE}"

log_success "JWT secret generated successfully"

echo
echo "=============================================="
log_success "JWT generation complete!"
echo "=============================================="
echo
echo "JWT secret file: ${JWT_FILE}"
echo "Secret (first 8 chars): ${JWT_CONTENT:0:8}..."
echo
echo "This secret will be used for authenticated communication"
echo "between the Execution Layer (Reth) and Consensus Layer (Lighthouse)"
echo
echo "Next step: Run ./02-generate-genesis.sh"
