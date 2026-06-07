package signer

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/rootwarp/eth-utils/go/internal/network"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// parsedTx holds the decoded fields of an UnsignedTx ready for EIP-1559 transaction construction.
type parsedTx struct {
	chainID *big.Int
	value   *big.Int
	maxFee  *big.Int
	tip     *big.Int
	to      common.Address
	data    []byte
}

// parseUnsignedTx decodes and validates the hex fields of an UnsignedTx.
// Returns ErrInvalidChainID for zero chain ID; ErrInvalidToAddress for bad To
// (non-hex / wrong length / not the deposit contract unless unsigned's
// AllowNonDepositRecipient is set); plain format errors for other fields.
func parseUnsignedTx(unsigned internaltx.UnsignedTx) (*parsedTx, error) {
	if unsigned.ChainID == 0 {
		return nil, fmt.Errorf("ChainID must be non-zero: %w", ErrInvalidChainID)
	}
	chainID := new(big.Int).SetUint64(unsigned.ChainID)

	value, ok := new(big.Int).SetString(strings.TrimPrefix(unsigned.Value, "0x"), 16)
	if !ok {
		return nil, fmt.Errorf("invalid Value hex %q", unsigned.Value)
	}

	maxFeeHex := strings.TrimPrefix(unsigned.MaxFeePerGas, "0x")
	if maxFeeHex == "" {
		return nil, fmt.Errorf("MaxFeePerGas is required for EIP-1559 transactions")
	}
	maxFee, ok := new(big.Int).SetString(maxFeeHex, 16)
	if !ok {
		return nil, fmt.Errorf("invalid MaxFeePerGas hex %q", unsigned.MaxFeePerGas)
	}

	maxPrioHex := strings.TrimPrefix(unsigned.MaxPriorityFeePerGas, "0x")
	if maxPrioHex == "" {
		return nil, fmt.Errorf("MaxPriorityFeePerGas is required for EIP-1559 transactions")
	}
	tip, ok := new(big.Int).SetString(maxPrioHex, 16)
	if !ok {
		return nil, fmt.Errorf("invalid MaxPriorityFeePerGas hex %q", unsigned.MaxPriorityFeePerGas)
	}

	dataHex := strings.TrimPrefix(unsigned.Data, "0x")
	var data []byte
	if dataHex != "" {
		var err error
		data, err = hex.DecodeString(dataHex)
		if err != nil {
			return nil, fmt.Errorf("invalid Data hex: %w", err)
		}
	}

	// Strict To validation per M0.6-1 / FR-P0-A5 (GO-003), following M0.4-1 withdrawal
	// flag style exactly: len==42 + common.IsHexAddress (EIP-55 optional) on the raw
	// string; HexToAddress only after; then cross-check decoded addr vs network's
	// deposit contract for the ChainID (LookupByChainID from post-M0.2 network pkg).
	toStr := unsigned.To
	if !common.IsHexAddress(toStr) || len(toStr) != 42 {
		return nil, ErrInvalidToAddress
	}
	to := common.HexToAddress(toStr)
	if !unsigned.AllowNonDepositRecipient {
		p, err := network.LookupByChainID(unsigned.ChainID)
		if err != nil || to != common.HexToAddress(p.DepositContractAddressHex()) {
			return nil, ErrInvalidToAddress
		}
	}

	return &parsedTx{
		chainID: chainID,
		value:   value,
		maxFee:  maxFee,
		tip:     tip,
		to:      to,
		data:    data,
	}, nil
}
