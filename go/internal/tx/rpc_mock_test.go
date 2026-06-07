package tx

import (
	"context"
	"math/big"
)

// mockRPC is a test double for EthRPC (and EthBroadcaster) using the
// function-field pattern. Set each Fn field to control per-call behavior.
type mockRPC struct {
	SuggestGasTipCapFn func(ctx context.Context) (*big.Int, error)
	BlockBaseFeeFn     func(ctx context.Context) (*big.Int, error)
	PendingNonceAtFn   func(ctx context.Context, account [20]byte) (uint64, error)
	EstimateGasFn      func(ctx context.Context, msg CallMsg) (uint64, error)
	ChainIDFn          func(ctx context.Context) (*big.Int, error)
	CloseFn            func()

	// broadcaster fns (extended for M1.3-4 receipt retry tests + interface parity with ethClient)
	SendRawTransactionFn func(ctx context.Context, rawRLP string) (string, error)
	TransactionReceiptFn func(ctx context.Context, txHash string) (*Receipt, error)
	BroadcasterChainIDFn func(ctx context.Context) (uint64, error)
}

func (m *mockRPC) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	if m.SuggestGasTipCapFn == nil {
		panic("mockRPC.SuggestGasTipCap not set")
	}
	return m.SuggestGasTipCapFn(ctx)
}

func (m *mockRPC) BlockBaseFee(ctx context.Context) (*big.Int, error) {
	if m.BlockBaseFeeFn == nil {
		panic("mockRPC.BlockBaseFee not set")
	}
	return m.BlockBaseFeeFn(ctx)
}

func (m *mockRPC) PendingNonceAt(ctx context.Context, account [20]byte) (uint64, error) {
	if m.PendingNonceAtFn == nil {
		panic("mockRPC.PendingNonceAt not set")
	}
	return m.PendingNonceAtFn(ctx, account)
}

func (m *mockRPC) EstimateGas(ctx context.Context, msg CallMsg) (uint64, error) {
	if m.EstimateGasFn == nil {
		panic("mockRPC.EstimateGas not set")
	}
	return m.EstimateGasFn(ctx, msg)
}

func (m *mockRPC) ChainID(ctx context.Context) (*big.Int, error) {
	if m.ChainIDFn == nil {
		panic("mockRPC.ChainID not set")
	}
	return m.ChainIDFn(ctx)
}

func (m *mockRPC) SendRawTransaction(ctx context.Context, rawRLP string) (string, error) {
	if m.SendRawTransactionFn == nil {
		panic("mockRPC.SendRawTransaction not set")
	}
	return m.SendRawTransactionFn(ctx, rawRLP)
}

func (m *mockRPC) TransactionReceipt(ctx context.Context, txHash string) (*Receipt, error) {
	if m.TransactionReceiptFn == nil {
		panic("mockRPC.TransactionReceipt not set")
	}
	return m.TransactionReceiptFn(ctx, txHash)
}

func (m *mockRPC) BroadcasterChainID(ctx context.Context) (uint64, error) {
	if m.BroadcasterChainIDFn == nil {
		panic("mockRPC.BroadcasterChainID not set")
	}
	return m.BroadcasterChainIDFn(ctx)
}

func (m *mockRPC) Close() {
	if m.CloseFn != nil {
		m.CloseFn()
	}
}

// compile-time assertion
var _ EthRPC = (*mockRPC)(nil)
var _ EthBroadcaster = (*mockRPC)(nil)
