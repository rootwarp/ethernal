package tx

import (
	"context"
	"math/big"

	"github.com/rootwarp/eth-utils/go/internal/deposit"
	"github.com/rootwarp/eth-utils/go/internal/network"
)

// EthRPC is the minimal Ethereum RPC surface the builder needs to resolve gas,
// fees, nonce, and chain ID. A nil EthRPC means static-only mode.
type EthRPC interface {
	// SuggestGasTipCap returns the priority fee suggestion (eth_maxPriorityFeePerGas).
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
	// BlockBaseFee returns the baseFeePerGas of the latest block in wei.
	BlockBaseFee(ctx context.Context) (*big.Int, error)
	// PendingNonceAt returns the next nonce for the given address.
	PendingNonceAt(ctx context.Context, account [20]byte) (uint64, error)
	// EstimateGas estimates the gas required for a call.
	EstimateGas(ctx context.Context, msg CallMsg) (uint64, error)
	// ChainID returns the chain ID reported by the node.
	ChainID(ctx context.Context) (*big.Int, error)
	// Close closes the underlying RPC client.
	Close()
}

// CallMsg is the minimal call descriptor used by EstimateGas.
type CallMsg struct {
	From  [20]byte
	To    [20]byte
	Value *big.Int
	Data  []byte
}

// TxBuilder constructs unsigned EIP-1559 deposit transactions.
type TxBuilder interface {
	BuildUnsigned(ctx context.Context, entry deposit.Entry, cfg BuildConfig) (*UnsignedTx, error)
}

// BuildConfig carries the parameters needed to build an unsigned transaction.
//
// Static mode (RPC == nil): GasLimit, MaxFeePerGas, MaxPriorityFeePerGas, and
// Nonce must all be set; missing any returns an ErrMissing* sentinel.
//
// RPC mode (RPC != nil): any nil/zero field is resolved from the RPC. From is
// required when Nonce is nil so the pending nonce can be fetched.
type BuildConfig struct {
	// NetworkParams provides ChainID and the deposit contract address.
	NetworkParams network.Params

	// RPCURL is reserved for Issue 2.5 (wiring the real ethclient); unused here.
	RPCURL string

	// RPC is the live RPC client used to resolve missing gas/fee/nonce values.
	// nil means static-only mode.
	RPC EthRPC

	// From is the sender address. Required when RPC != nil and Nonce is nil.
	From [20]byte

	// GasLimit is the EIP-1559 gas limit. 0 with RPC != nil triggers EstimateGas.
	GasLimit uint64

	// MaxFeePerGas is the EIP-1559 maximum total fee per gas in wei.
	// nil with RPC != nil triggers computation from baseFee + tip.
	MaxFeePerGas *big.Int

	// MaxPriorityFeePerGas is the EIP-1559 miner tip per gas in wei.
	// nil with RPC != nil triggers SuggestGasTipCap.
	MaxPriorityFeePerGas *big.Int

	// Nonce is the sender nonce. nil with RPC != nil triggers PendingNonceAt.
	// A pointer distinguishes "explicit 0" from "not set".
	Nonce *uint64
}
