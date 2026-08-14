#!/bin/bash
# 02-generate-genesis.sh
# Generate EL and CL genesis configurations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

echo "=============================================="
echo "  Ethereum Devnet - Genesis Generation"
echo "=============================================="
echo

# Check if genesis already exists
if [[ -f "${GENESIS_DIR}/genesis.json" ]] && [[ -f "${GENESIS_DIR}/genesis.ssz" ]]; then
    log_warn "Genesis files already exist"
    read -p "Do you want to regenerate them? This will require restarting from scratch. (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Keeping existing genesis files"
        exit 0
    fi
fi

# Create directories
mkdir -p "${GENESIS_DIR}"

# Calculate genesis time (current time + genesis delay)
GENESIS_TIME=$(get_genesis_time)
GENESIS_TIME_HEX=$(printf '%x' "$GENESIS_TIME")

log_info "Genesis time: ${GENESIS_TIME} ($(date -r ${GENESIS_TIME} 2>/dev/null || date -d @${GENESIS_TIME}))"

# SECONDS_PER_SLOT is derived; SLOT_DURATION_MS in network.env is the one knob.
SECONDS_PER_SLOT=$((SLOT_DURATION_MS / 1000))
GENESIS_GASLIMIT_HEX=$(printf '%x' "${GENESIS_GASLIMIT}")

# Generate EL genesis.json
# NOTE: this and the config.yaml below are scaffolding only - the genesis
# generator overwrites both further down. They are kept accurate so that the
# checked-in templates document the real chain rather than drifting from it.
log_info "Generating Execution Layer genesis.json..."

EL_TEMPLATE="${SCRIPT_DIR}/config/el/genesis-template.json"
EL_GENESIS="${GENESIS_DIR}/genesis.json"

# Substitute variables in template
sed -e "s/\${CHAIN_ID}/${CHAIN_ID}/g" \
    -e "s/\${GENESIS_TIME_HEX}/${GENESIS_TIME_HEX}/g" \
    -e "s/\${GENESIS_GASLIMIT_HEX}/${GENESIS_GASLIMIT_HEX}/g" \
    -e "s/\${DEPOSIT_CONTRACT_ADDRESS}/${DEPOSIT_CONTRACT_ADDRESS}/g" \
    -e "s/\${DEV_ACCOUNT}/${DEV_ACCOUNT}/g" \
    "${EL_TEMPLATE}" > "${EL_GENESIS}"

# Validate JSON
if ! jq empty "${EL_GENESIS}" 2>/dev/null; then
    log_error "Generated genesis.json is not valid JSON"
    exit 1
fi

log_success "EL genesis.json generated"

# Generate CL config.yaml
log_info "Generating Consensus Layer config.yaml..."

CL_TEMPLATE="${SCRIPT_DIR}/config/cl/config-template.yaml"
CL_CONFIG="${GENESIS_DIR}/config.yaml"

sed -e "s/\${CHAIN_ID}/${CHAIN_ID}/g" \
    -e "s/\${NETWORK_ID}/${NETWORK_ID}/g" \
    -e "s/\${NUM_VALIDATORS}/${NUM_VALIDATORS}/g" \
    -e "s/\${GENESIS_TIME}/${GENESIS_TIME}/g" \
    -e "s/\${GENESIS_DELAY}/${GENESIS_DELAY}/g" \
    -e "s/\${SECONDS_PER_SLOT}/${SECONDS_PER_SLOT}/g" \
    -e "s/\${SLOT_DURATION_MS}/${SLOT_DURATION_MS}/g" \
    -e "s/\${DEPOSIT_CONTRACT_ADDRESS}/${DEPOSIT_CONTRACT_ADDRESS}/g" \
    "${CL_TEMPLATE}" > "${CL_CONFIG}"

log_success "CL config.yaml generated"

# Generate genesis.ssz and deploy_block.txt using ethereum-genesis-generator
log_info "Generating CL genesis.ssz using ethereum-genesis-generator..."

# Create a temporary directory for the generator
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

# Create generator config
#
# Only keys present in the generator's defaults/defaults.env take effect;
# anything else is silently ignored. Unset keys fall back to that file's
# defaults, which are mainnet values - so forks/limits we do not name here
# (Fulu blob schedule, Electra churn limits, MAX_PAYLOAD_SIZE, ...) already
# match mainnet. Fork versions must differ from mainnet's 0x01-0x06.
cat > "${TEMP_DIR}/values.env" <<EOF
PRESET_BASE=mainnet
CHAIN_ID=${CHAIN_ID}
DEPOSIT_CONTRACT_ADDRESS=${DEPOSIT_CONTRACT_ADDRESS}
EL_AND_CL_MNEMONIC="${VALIDATOR_MNEMONIC}"
CL_EXEC_BLOCK=0
SLOT_DURATION_MS=${SLOT_DURATION_MS}
SECONDS_PER_ETH1_BLOCK=14
ETH1_FOLLOW_DISTANCE=2048
GENESIS_TIMESTAMP=${GENESIS_TIME}
GENESIS_DELAY=${GENESIS_DELAY}
GENESIS_GASLIMIT=${GENESIS_GASLIMIT}
NUMBER_OF_VALIDATORS=${NUM_VALIDATORS}
VALIDATOR_BALANCE=32000000000
GENESIS_FORK_VERSION=0x10000000
ALTAIR_FORK_VERSION=0x20000000
BELLATRIX_FORK_VERSION=0x30000000
CAPELLA_FORK_VERSION=0x40000000
DENEB_FORK_VERSION=0x50000000
ELECTRA_FORK_VERSION=0x60000000
FULU_FORK_VERSION=0x70000000
ALTAIR_FORK_EPOCH=0
BELLATRIX_FORK_EPOCH=0
CAPELLA_FORK_EPOCH=0
DENEB_FORK_EPOCH=0
ELECTRA_FORK_EPOCH=0
FULU_FORK_EPOCH=0
GLOAS_FORK_EPOCH=18446744073709551615
HEZE_FORK_EPOCH=18446744073709551615
BPO_1_EPOCH=0
BPO_1_MAX_BLOBS=15
BPO_1_TARGET_BLOBS=10
BPO_2_EPOCH=0
BPO_2_MAX_BLOBS=21
BPO_2_TARGET_BLOBS=14
WITHDRAWAL_TYPE=0x01
WITHDRAWAL_ADDRESS=${DEV_ACCOUNT}
EL_PREMINE_ADDRS='{"${DEV_ACCOUNT}": {"balance": "10000000000ETH"}}'
SHADOW_FORK_RPC=
SHADOW_FORK_FILE=
EOF

# Run the genesis generator
docker run --rm \
    -v "${GENESIS_DIR}:/data" \
    -v "${TEMP_DIR}/values.env:/config/values.env" \
    "${GENESIS_GENERATOR_IMAGE}" \
    all

# The generator outputs to /data/metadata/ and is the source of truth: its
# output replaces the templates rendered above. Fail loudly rather than falling
# through to the stale scaffolding, which would silently produce a chain whose
# fork schedule disagrees with the one this script just declared.
if [[ ! -f "${GENESIS_DIR}/metadata/genesis.ssz" ]]; then
    log_error "Genesis generator did not produce metadata/genesis.ssz"
    log_error "Inspect ${GENESIS_DIR}/metadata/ and the generator output above"
    exit 1
fi

cp "${GENESIS_DIR}/metadata/genesis.ssz" "${GENESIS_DIR}/genesis.ssz"
cp "${GENESIS_DIR}/metadata/config.yaml" "${GENESIS_DIR}/config.yaml"
cp "${GENESIS_DIR}/metadata/genesis.json" "${GENESIS_DIR}/genesis.json"

# Copy deposit contract files (required by Lighthouse). Guarded: an unmatched
# glob would otherwise abort the script via `set -e`.
shopt -s nullglob
DEPOSIT_CONTRACT_FILES=("${GENESIS_DIR}/metadata/deposit_contract"*.txt)
shopt -u nullglob
if [[ ${#DEPOSIT_CONTRACT_FILES[@]} -gt 0 ]]; then
    cp "${DEPOSIT_CONTRACT_FILES[@]}" "${GENESIS_DIR}/"
else
    log_warn "No deposit_contract*.txt emitted by the generator"
fi

# Create deploy_block.txt (genesis at block 0)
echo "0" > "${GENESIS_DIR}/deploy_block.txt"

log_success "CL genesis.ssz generated"

echo
echo "=============================================="
log_success "Genesis generation complete!"
echo "=============================================="
echo
echo "Generated files:"
echo "  - EL genesis: ${EL_GENESIS}"
echo "  - CL config:  ${CL_CONFIG}"
echo "  - CL genesis: ${GENESIS_DIR}/genesis.ssz"
echo
echo "Configuration:"
echo "  - Chain ID:        ${CHAIN_ID}"
echo "  - Genesis time:    ${GENESIS_TIME}"
echo "  - Validators:      ${NUM_VALIDATORS}"
echo "  - Slot duration:   ${SECONDS_PER_SLOT}s"
echo "  - Slots per epoch: 32 (mainnet preset; not configurable)"
echo "  - Epoch duration:  $((32 * SECONDS_PER_SLOT))s"
echo "  - Gas limit:       ${GENESIS_GASLIMIT}"
echo "  - Latest fork:     Fulu (Fusaka) at epoch 0"
echo
echo "The generated config.yaml above is authoritative - it came from the"
echo "genesis generator, not from config/cl/config-template.yaml."
echo
echo "Next step: Run ./03-generate-validator-keys.sh"
