package tx

import (
	"context"
	"math/big"
)

// mockRPC is a test double for EthRPC using the function-field pattern.
// Set each Fn field to control per-call behavior.
type mockRPC struct {
	SuggestGasTipCapFn func(ctx context.Context) (*big.Int, error)
	BlockBaseFeeFn     func(ctx context.Context) (*big.Int, error)
	PendingNonceAtFn   func(ctx context.Context, account [20]byte) (uint64, error)
	EstimateGasFn      func(ctx context.Context, msg CallMsg) (uint64, error)
	ChainIDFn          func(ctx context.Context) (*big.Int, error)
	CloseFn            func()
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

func (m *mockRPC) Close() {
	if m.CloseFn != nil {
		m.CloseFn()
	}
}

// compile-time assertion
var _ EthRPC = (*mockRPC)(nil)
