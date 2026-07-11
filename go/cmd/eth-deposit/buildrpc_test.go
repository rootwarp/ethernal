package main

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/rootwarp/eth-utils/go/internal/network"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// mockEthRPC is a cmd-level fake implementing the EXPORTED internaltx.EthRPC
// (package tx's mockRPC is unexported and unavailable here). Function-field
// pattern, mirroring mockBroadcaster (send_test.go). A nil Fn panics so an
// unexpected call is caught loudly.
type mockEthRPC struct {
	SuggestGasTipCapFn func(ctx context.Context) (*big.Int, error)
	BlockBaseFeeFn     func(ctx context.Context) (*big.Int, error)
	PendingNonceAtFn   func(ctx context.Context, account [20]byte) (uint64, error)
	EstimateGasFn      func(ctx context.Context, msg internaltx.CallMsg) (uint64, error)
	ChainIDFn          func(ctx context.Context) (*big.Int, error)
	CloseFn            func()
}

func (m *mockEthRPC) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	if m.SuggestGasTipCapFn == nil {
		panic("mockEthRPC.SuggestGasTipCap not set")
	}
	return m.SuggestGasTipCapFn(ctx)
}

func (m *mockEthRPC) BlockBaseFee(ctx context.Context) (*big.Int, error) {
	if m.BlockBaseFeeFn == nil {
		panic("mockEthRPC.BlockBaseFee not set")
	}
	return m.BlockBaseFeeFn(ctx)
}

func (m *mockEthRPC) PendingNonceAt(ctx context.Context, account [20]byte) (uint64, error) {
	if m.PendingNonceAtFn == nil {
		panic("mockEthRPC.PendingNonceAt not set")
	}
	return m.PendingNonceAtFn(ctx, account)
}

func (m *mockEthRPC) EstimateGas(ctx context.Context, msg internaltx.CallMsg) (uint64, error) {
	if m.EstimateGasFn == nil {
		panic("mockEthRPC.EstimateGas not set")
	}
	return m.EstimateGasFn(ctx, msg)
}

func (m *mockEthRPC) ChainID(ctx context.Context) (*big.Int, error) {
	if m.ChainIDFn == nil {
		panic("mockEthRPC.ChainID not set")
	}
	return m.ChainIDFn(ctx)
}

func (m *mockEthRPC) Close() {
	if m.CloseFn != nil {
		m.CloseFn()
	}
}

var _ internaltx.EthRPC = (*mockEthRPC)(nil)

// withMockEthRPC swaps the newEthRPC factory to return mock, restoring on cleanup.
func withMockEthRPC(t *testing.T, mock internaltx.EthRPC) {
	t.Helper()
	orig := newEthRPC
	newEthRPC = func(ctx context.Context, rpcURL string) (internaltx.EthRPC, error) {
		return mock, nil
	}
	t.Cleanup(func() { newEthRPC = orig })
}

// testFrom is a non-zero sender used so resolveRPC's PendingNonceAt / EstimateGas
// paths run (a zero From short-circuits to ErrMissingFromForNonce).
var testFrom = [20]byte{0x11, 0x22, 0x33}

// holeskyBuildInputs returns a build Config (holesky params) and the raw deposit
// fixture bytes for driving buildUnsignedTx directly.
func holeskyBuildInputs(t *testing.T) (*Config, []byte) {
	t.Helper()
	params, err := network.Lookup(network.Holesky)
	if err != nil {
		t.Fatalf("network.Lookup(holesky): %v", err)
	}
	raw, err := os.ReadFile(fixtureAbsPath(t))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return &Config{Network: network.Holesky, NetworkParams: params}, raw
}

func hexToBig(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
	if !ok {
		t.Fatalf("not a hex value: %q", s)
	}
	return v
}

// Case 1: offline, no --rpc-url, no gas flags → success with the static
// air-gapped defaults. Confirms the default-fill relocation into the offline
// branch is byte-equivalent and never dials.
func TestBuildUnsignedTx_OfflineDefaults(t *testing.T) {
	orig := newEthRPC
	newEthRPC = func(ctx context.Context, rpcURL string) (internaltx.EthRPC, error) {
		t.Fatal("newEthRPC must not be called in offline mode")
		return nil, nil
	}
	t.Cleanup(func() { newEthRPC = orig })

	cfg, raw := holeskyBuildInputs(t) // RPCURL == ""
	tx, err := buildUnsignedTx(context.Background(), cfg, raw)
	if err != nil {
		t.Fatalf("offline build: %v", err)
	}
	if tx.Gas != defaultGasLimit {
		t.Errorf("Gas: got %d, want %d", tx.Gas, defaultGasLimit)
	}
	if got := hexToBig(t, tx.MaxFeePerGas); got.Cmp(defaultMaxFeePerGas()) != 0 {
		t.Errorf("MaxFeePerGas: got %s, want %s", got, defaultMaxFeePerGas())
	}
	if got := hexToBig(t, tx.MaxPriorityFeePerGas); got.Cmp(defaultMaxPriorityFeePerGas()) != 0 {
		t.Errorf("MaxPriorityFeePerGas: got %s, want %s", got, defaultMaxPriorityFeePerGas())
	}
	if tx.Nonce != 0 {
		t.Errorf("Nonce: got %d, want 0", tx.Nonce)
	}
}

// Case 2: RPC mode with all fields unset → tx reflects the node's tip/baseFee/
// nonce/gas (maxFee = 2*baseFee + tip, gas = estimate*6/5); the 32-ETH
// EstimateGas call carries the non-zero From.
func TestBuildUnsignedTx_RPCResolvesUnsetFields(t *testing.T) {
	tip := big.NewInt(3_000_000_000)     // 3 gwei
	baseFee := big.NewInt(7_000_000_000) // 7 gwei
	wantMaxFee := new(big.Int).Add(new(big.Int).Mul(big.NewInt(2), baseFee), tip)
	const fakeNonce = uint64(99)
	const estimate = uint64(210_000)
	wantGas := estimate * 6 / 5

	var gotFrom [20]byte
	mock := &mockEthRPC{
		ChainIDFn:          func(context.Context) (*big.Int, error) { return big.NewInt(int64(holeskyChainID)), nil },
		SuggestGasTipCapFn: func(context.Context) (*big.Int, error) { return tip, nil },
		BlockBaseFeeFn:     func(context.Context) (*big.Int, error) { return baseFee, nil },
		PendingNonceAtFn:   func(context.Context, [20]byte) (uint64, error) { return fakeNonce, nil },
		EstimateGasFn: func(_ context.Context, msg internaltx.CallMsg) (uint64, error) {
			gotFrom = msg.From
			return estimate, nil
		},
	}

	dialed := false
	orig := newEthRPC
	newEthRPC = func(ctx context.Context, rpcURL string) (internaltx.EthRPC, error) {
		dialed = true
		return mock, nil
	}
	t.Cleanup(func() { newEthRPC = orig })

	cfg, raw := holeskyBuildInputs(t)
	cfg.RPCURL = "http://node.example"
	cfg.From = testFrom

	tx, err := buildUnsignedTx(context.Background(), cfg, raw)
	if err != nil {
		t.Fatalf("rpc build: %v", err)
	}
	if !dialed {
		t.Error("newEthRPC was not invoked in RPC mode")
	}
	if tx.Gas != wantGas {
		t.Errorf("Gas: got %d, want %d (estimate*6/5)", tx.Gas, wantGas)
	}
	if got := hexToBig(t, tx.MaxFeePerGas); got.Cmp(wantMaxFee) != 0 {
		t.Errorf("MaxFeePerGas: got %s, want %s (2*baseFee+tip)", got, wantMaxFee)
	}
	if got := hexToBig(t, tx.MaxPriorityFeePerGas); got.Cmp(tip) != 0 {
		t.Errorf("MaxPriorityFeePerGas: got %s, want %s", got, tip)
	}
	if tx.Nonce != fakeNonce {
		t.Errorf("Nonce: got %d, want %d", tx.Nonce, fakeNonce)
	}
	if gotFrom != testFrom {
		t.Errorf("EstimateGas From = %x, want %x (funded sender for the 32-ETH call)", gotFrom, testFrom)
	}
}

// Case 3: RPC mode with all gas/nonce flags explicit → the flags win and no
// resolve call other than ChainID fires.
func TestBuildUnsignedTx_RPCExplicitFlagsWin(t *testing.T) {
	mock := &mockEthRPC{
		ChainIDFn: func(context.Context) (*big.Int, error) { return big.NewInt(int64(holeskyChainID)), nil },
		SuggestGasTipCapFn: func(context.Context) (*big.Int, error) {
			t.Fatal("SuggestGasTipCap fired; explicit flags should win")
			return nil, nil
		},
		BlockBaseFeeFn: func(context.Context) (*big.Int, error) {
			t.Fatal("BlockBaseFee fired; explicit flags should win")
			return nil, nil
		},
		PendingNonceAtFn: func(context.Context, [20]byte) (uint64, error) {
			t.Fatal("PendingNonceAt fired; explicit flags should win")
			return 0, nil
		},
		EstimateGasFn: func(context.Context, internaltx.CallMsg) (uint64, error) {
			t.Fatal("EstimateGas fired; explicit flags should win")
			return 0, nil
		},
	}
	withMockEthRPC(t, mock)

	cfg, raw := holeskyBuildInputs(t)
	cfg.RPCURL = "http://node.example"
	cfg.From = testFrom
	cfg.GasLimit = 300_000
	cfg.MaxFeePerGas = big.NewInt(25_000_000_000)
	cfg.MaxPriorityFeePerGas = big.NewInt(2_000_000_000)
	n := uint64(7)
	cfg.Nonce = &n

	tx, err := buildUnsignedTx(context.Background(), cfg, raw)
	if err != nil {
		t.Fatalf("rpc build with explicit flags: %v", err)
	}
	if tx.Gas != 300_000 {
		t.Errorf("Gas: got %d, want 300000 (explicit flag)", tx.Gas)
	}
	if tx.Nonce != 7 {
		t.Errorf("Nonce: got %d, want 7 (explicit flag)", tx.Nonce)
	}
	if got := hexToBig(t, tx.MaxFeePerGas); got.Cmp(big.NewInt(25_000_000_000)) != 0 {
		t.Errorf("MaxFeePerGas: got %s, want 25000000000 (explicit flag)", got)
	}
}

// Case 4: RPC unreachable → newEthRPC returns ErrRPCDial → exit 5, and Close is
// NOT called (nil-interface guard: return before the deferred Close).
func TestBuildUnsignedTx_RPCUnreachable(t *testing.T) {
	mock := &mockEthRPC{CloseFn: func() { t.Fatal("Close called after dial failure (nil-interface guard violated)") }}
	orig := newEthRPC
	newEthRPC = func(ctx context.Context, rpcURL string) (internaltx.EthRPC, error) {
		return mock, fmt.Errorf("%w: dial tcp: connection refused", internaltx.ErrRPCDial)
	}
	t.Cleanup(func() { newEthRPC = orig })

	cfg, raw := holeskyBuildInputs(t)
	cfg.RPCURL = "http://127.0.0.1:0"
	cfg.From = testFrom

	_, err := buildUnsignedTx(context.Background(), cfg, raw)
	if err == nil {
		t.Fatal("expected dial error, got nil")
	}
	if got := ExitCodeFor(err); got != 5 {
		t.Errorf("exit code = %d, want 5; err = %v", got, err)
	}
}

// Case 5: RPC reachable but an estimation call fails → tagged ErrRPCEstimation,
// returned unwrapped → exit 5.
func TestBuildUnsignedTx_RPCEstimationFails(t *testing.T) {
	mock := &mockEthRPC{
		ChainIDFn:          func(context.Context) (*big.Int, error) { return big.NewInt(int64(holeskyChainID)), nil },
		SuggestGasTipCapFn: func(context.Context) (*big.Int, error) { return big.NewInt(1_000_000_000), nil },
		BlockBaseFeeFn:     func(context.Context) (*big.Int, error) { return big.NewInt(10_000_000_000), nil },
		PendingNonceAtFn:   func(context.Context, [20]byte) (uint64, error) { return 5, nil },
		EstimateGasFn: func(context.Context, internaltx.CallMsg) (uint64, error) {
			return 0, errors.New("insufficient funds for gas * price + value")
		},
	}
	withMockEthRPC(t, mock)

	cfg, raw := holeskyBuildInputs(t)
	cfg.RPCURL = "http://node.example"
	cfg.From = testFrom // GasLimit 0 → EstimateGas fires and fails.

	_, err := buildUnsignedTx(context.Background(), cfg, raw)
	if err == nil {
		t.Fatal("expected estimation error, got nil")
	}
	if !errors.Is(err, internaltx.ErrRPCEstimation) {
		t.Errorf("error not tagged ErrRPCEstimation: %v", err)
	}
	if got := ExitCodeFor(err); got != 5 {
		t.Errorf("exit code = %d, want 5; err = %v", got, err)
	}
}

// Case 6: RPC chain ID differs from the configured network → ErrChainIDMismatch
// (a config error) → exit 2.
func TestBuildUnsignedTx_RPCChainIDMismatch(t *testing.T) {
	mock := &mockEthRPC{
		ChainIDFn: func(context.Context) (*big.Int, error) { return big.NewInt(1), nil }, // mainnet != holesky 17000
	}
	withMockEthRPC(t, mock)

	cfg, raw := holeskyBuildInputs(t)
	cfg.RPCURL = "http://node.example"
	cfg.From = testFrom

	_, err := buildUnsignedTx(context.Background(), cfg, raw)
	if err == nil {
		t.Fatal("expected chain-ID mismatch error, got nil")
	}
	if !errors.Is(err, internaltx.ErrChainIDMismatch) {
		t.Errorf("error not ErrChainIDMismatch: %v", err)
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
}

// Matrix last row (carry-in c): a failed ChainID *call* (not a mismatch) is
// swallowed — the build proceeds and resolves the remaining fields. It must NOT
// promote to exit 5.
func TestBuildUnsignedTx_RPCChainIDCallError_WarnAndContinue(t *testing.T) {
	mock := &mockEthRPC{
		ChainIDFn: func(context.Context) (*big.Int, error) {
			return nil, errors.New("the method eth_chainId does not exist")
		},
		SuggestGasTipCapFn: func(context.Context) (*big.Int, error) { return big.NewInt(1_000_000_000), nil },
		BlockBaseFeeFn:     func(context.Context) (*big.Int, error) { return big.NewInt(10_000_000_000), nil },
		PendingNonceAtFn:   func(context.Context, [20]byte) (uint64, error) { return 5, nil },
		EstimateGasFn:      func(context.Context, internaltx.CallMsg) (uint64, error) { return 200_000, nil },
	}
	withMockEthRPC(t, mock)

	cfg, raw := holeskyBuildInputs(t)
	cfg.RPCURL = "http://node.example"
	cfg.From = testFrom

	tx, err := buildUnsignedTx(context.Background(), cfg, raw)
	if err != nil {
		t.Fatalf("ChainID call error should be swallowed (warn-and-continue), got: %v", err)
	}
	if tx.Nonce != 5 {
		t.Errorf("Nonce: got %d, want 5 (resolution proceeded after swallowed ChainID error)", tx.Nonce)
	}
}
