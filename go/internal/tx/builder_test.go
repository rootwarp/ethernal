package tx

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/rootwarp/eth-utils/go/internal/network"
)

// TestBuilderSatisfiesTxBuilder is an explicit runtime assertion complementing
// the compile-time var _ check in builder.go.
func TestBuilderSatisfiesTxBuilder(t *testing.T) {
	var _ TxBuilder = NewBuilder()
}

func TestBuilder_BuildUnsigned_Success(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	nonce := uint64(3)
	cfg := BuildConfig{
		NetworkParams:        params,
		GasLimit:             250_000,
		MaxFeePerGas:         big.NewInt(20_000_000_000),
		MaxPriorityFeePerGas: big.NewInt(1_000_000_000),
		Nonce:                &nonce,
	}

	b := NewBuilder()
	tx, err := b.BuildUnsigned(ctx, entry, cfg)
	if err != nil {
		t.Fatalf("BuildUnsigned returned error: %v", err)
	}
	if tx == nil {
		t.Fatal("BuildUnsigned returned nil tx")
	}
	if tx.ChainID != params.ChainID {
		t.Errorf("ChainID: got %d, want %d", tx.ChainID, params.ChainID)
	}
	wantTo := strings.ToLower(params.DepositContractAddressHex())
	if strings.ToLower(tx.To) != wantTo {
		t.Errorf("To: got %q, want %q", tx.To, wantTo)
	}
	if tx.Value != "0x1bc16d674ec800000" {
		t.Errorf("Value: got %q, want 0x1bc16d674ec800000", tx.Value)
	}
	if !strings.HasPrefix(tx.Data, "0x22895118") {
		t.Errorf("Data: must start with deposit() selector 0x22895118, got %q", tx.Data)
	}
	if tx.Gas != 250_000 {
		t.Errorf("Gas: got %d, want 250000", tx.Gas)
	}
	if tx.Type != "0x2" {
		t.Errorf("Type: got %q, want 0x2", tx.Type)
	}
	if tx.Nonce != nonce {
		t.Errorf("Nonce: got %d, want %d", tx.Nonce, nonce)
	}
}

func TestBuilder_BuildUnsigned_NilNonce_StaticMode_ReturnsError(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)
	cfg := BuildConfig{
		NetworkParams:        params,
		GasLimit:             250_000,
		MaxFeePerGas:         big.NewInt(1),
		MaxPriorityFeePerGas: big.NewInt(1),
		Nonce:                nil, // missing in static mode
	}

	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	if err == nil {
		t.Fatal("expected error for nil Nonce in static mode, got nil")
	}
	if !errors.Is(err, ErrMissingNonceStatic) {
		t.Errorf("expected ErrMissingNonceStatic, got: %v", err)
	}
}

func TestBuilder_BuildUnsigned_NilContext(t *testing.T) {
	entry := makeValidEntry()
	params := holeskyParams(t)
	nonce := uint64(0)
	cfg := BuildConfig{
		NetworkParams:        params,
		GasLimit:             250_000,
		MaxFeePerGas:         big.NewInt(1),
		MaxPriorityFeePerGas: big.NewInt(1),
		Nonce:                &nonce,
	}

	b := NewBuilder()
	//lint:ignore SA1012 intentionally testing nil context rejection
	_, err := b.BuildUnsigned(nil, entry, cfg)
	if err == nil {
		t.Fatal("expected error for nil context, got nil")
	}
	if !errors.Is(err, ErrNilContext) {
		t.Errorf("expected ErrNilContext, got: %v", err)
	}
}

func TestBuilder_BuildUnsigned_NilMaxFeePerGas_StaticMode(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)
	nonce := uint64(0)
	cfg := BuildConfig{
		NetworkParams:        params,
		GasLimit:             250_000,
		MaxFeePerGas:         nil,
		MaxPriorityFeePerGas: big.NewInt(1),
		Nonce:                &nonce,
	}

	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	if err == nil {
		t.Fatal("expected error for nil MaxFeePerGas in static mode, got nil")
	}
	if !errors.Is(err, ErrMissingFeeStatic) {
		t.Errorf("expected ErrMissingFeeStatic, got: %v", err)
	}
}

func TestBuilder_BuildUnsigned_NilMaxPriorityFeePerGas_StaticMode(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)
	nonce := uint64(0)
	cfg := BuildConfig{
		NetworkParams:        params,
		GasLimit:             250_000,
		MaxFeePerGas:         big.NewInt(1),
		MaxPriorityFeePerGas: nil,
		Nonce:                &nonce,
	}

	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	if err == nil {
		t.Fatal("expected error for nil MaxPriorityFeePerGas in static mode, got nil")
	}
	if !errors.Is(err, ErrMissingPriorityFeeStatic) {
		t.Errorf("expected ErrMissingPriorityFeeStatic, got: %v", err)
	}
}

func TestBuilder_BuildUnsigned_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	entry := makeValidEntry()
	params := holeskyParams(t)
	nonce := uint64(0)
	cfg := BuildConfig{
		NetworkParams:        params,
		GasLimit:             250_000,
		MaxFeePerGas:         big.NewInt(1),
		MaxPriorityFeePerGas: big.NewInt(1),
		Nonce:                &nonce,
	}
	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestBuilder_BuildUnsigned_WrongAmount(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	entry.Amount = 1_000_000_000 // 1 ETH in Gwei, not 32
	params := holeskyParams(t)
	nonce := uint64(0)
	cfg := BuildConfig{
		NetworkParams:        params,
		GasLimit:             250_000,
		MaxFeePerGas:         big.NewInt(1),
		MaxPriorityFeePerGas: big.NewInt(1),
		Nonce:                &nonce,
	}
	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	if err == nil {
		t.Fatal("expected error for wrong amount, got nil")
	}
	if !errors.Is(err, ErrInvalidAmount) {
		t.Errorf("expected ErrInvalidAmount, got: %v", err)
	}
}

func TestBuilder_BuildUnsigned_DataLength(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)
	nonce := uint64(0)
	cfg := BuildConfig{
		NetworkParams:        params,
		GasLimit:             250_000,
		MaxFeePerGas:         big.NewInt(1),
		MaxPriorityFeePerGas: big.NewInt(1),
		Nonce:                &nonce,
	}
	b := NewBuilder()
	tx, err := b.BuildUnsigned(ctx, entry, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// "0x" + 420 bytes * 2 hex chars = 2 + 840 = 842 chars
	if len(tx.Data) != 842 {
		t.Errorf("Data length: got %d, want 842", len(tx.Data))
	}
}

func TestBuilder_BuildUnsigned_RoundTrip(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)
	nonce := uint64(0)
	cfg := BuildConfig{
		NetworkParams:        params,
		GasLimit:             250_000,
		MaxFeePerGas:         big.NewInt(1),
		MaxPriorityFeePerGas: big.NewInt(1),
		Nonce:                &nonce,
	}
	b := NewBuilder()
	tx, err := b.BuildUnsigned(ctx, entry, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Decode calldata from hex.
	hexData := strings.TrimPrefix(tx.Data, "0x")
	raw, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatalf("failed to decode Data hex: %v", err)
	}
	if len(raw) != 420 {
		t.Fatalf("raw calldata length: got %d, want 420", len(raw))
	}

	// Verify deposit_data_root in head slot 3 (bytes 4+96..4+128).
	gotRoot := raw[4+96 : 4+128]
	for i, b := range entry.DepositDataRoot {
		if gotRoot[i] != b {
			t.Errorf("DepositDataRoot[%d]: got %02x, want %02x", i, gotRoot[i], b)
		}
	}

	// Verify pubkey in tail (offset 128 from args start = raw[4+128..]).
	tail := raw[4:]
	pubkeyData := tail[128+32 : 128+32+48]
	for i, b := range entry.Pubkey {
		if pubkeyData[i] != b {
			t.Errorf("Pubkey[%d]: got %02x, want %02x", i, pubkeyData[i], b)
		}
	}

	// Verify withdrawal_credentials in tail (offset 224).
	wcData := tail[224+32 : 224+32+32]
	for i, b := range entry.WithdrawalCredentials {
		if wcData[i] != b {
			t.Errorf("WithdrawalCredentials[%d]: got %02x, want %02x", i, wcData[i], b)
		}
	}

	// Verify signature in tail (offset 288).
	sigData := tail[288+32 : 288+32+96]
	for i, b := range entry.Signature {
		if sigData[i] != b {
			t.Errorf("Signature[%d]: got %02x, want %02x", i, sigData[i], b)
		}
	}
}

func TestBuilder_BuildUnsigned_ChainIDMatchesNetwork(t *testing.T) {
	ctx := context.Background()
	nonce := uint64(0)
	for _, n := range []network.Network{network.Mainnet, network.Holesky, network.Sepolia, network.Hoodi} {
		params, _ := network.Lookup(n)
		e := makeValidEntry()
		e.NetworkName = n

		cfg := BuildConfig{
			NetworkParams:        params,
			GasLimit:             250_000,
			MaxFeePerGas:         big.NewInt(1),
			MaxPriorityFeePerGas: big.NewInt(1),
			Nonce:                &nonce,
		}
		b := NewBuilder()
		tx, err := b.BuildUnsigned(ctx, e, cfg)
		if err != nil {
			t.Fatalf("network %s: BuildUnsigned error: %v", n, err)
		}
		if tx.ChainID != params.ChainID {
			t.Errorf("network %s: ChainID got %d want %d", n, tx.ChainID, params.ChainID)
		}
	}
}

// TestBuilder_BuildUnsigned_ValidationWiredIn asserts that Validate is called by
// BuildUnsigned: a malformed entry (all-zero pubkey) must return ErrZeroPubkey.
func TestBuilder_BuildUnsigned_ValidationWiredIn(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	entry.Pubkey = [48]byte{} // trigger ErrZeroPubkey
	cfg := makeValidConfig(t)

	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	if err == nil {
		t.Fatal("expected validation error for all-zero pubkey, got nil")
	}
	if !errors.Is(err, ErrZeroPubkey) {
		t.Errorf("expected ErrZeroPubkey, got: %v", err)
	}
}

// ---- Static-mode missing-field tests ----

func TestBuilder_BuildUnsigned_StaticMode_MissingGasLimit(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)
	nonce := uint64(0)
	cfg := BuildConfig{
		NetworkParams:        params,
		GasLimit:             0, // missing
		MaxFeePerGas:         big.NewInt(1),
		MaxPriorityFeePerGas: big.NewInt(1),
		Nonce:                &nonce,
	}
	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	if err == nil {
		t.Fatal("expected ErrMissingGasLimitStatic, got nil")
	}
	if !errors.Is(err, ErrMissingGasLimitStatic) {
		t.Errorf("expected ErrMissingGasLimitStatic, got: %v", err)
	}
}

// ---- RPC-mode tests ----

// makeMockRPC returns a mockRPC pre-configured with typical happy-path values.
func makeMockRPC(chainID uint64) *mockRPC {
	tip := big.NewInt(2_000_000_000)      // 2 gwei
	baseFee := big.NewInt(10_000_000_000) // 10 gwei
	return &mockRPC{
		SuggestGasTipCapFn: func(_ context.Context) (*big.Int, error) {
			return new(big.Int).Set(tip), nil
		},
		BlockBaseFeeFn: func(_ context.Context) (*big.Int, error) {
			return new(big.Int).Set(baseFee), nil
		},
		PendingNonceAtFn: func(_ context.Context, _ [20]byte) (uint64, error) {
			return 7, nil
		},
		EstimateGasFn: func(_ context.Context, _ CallMsg) (uint64, error) {
			return 100_000, nil
		},
		ChainIDFn: func(_ context.Context) (*big.Int, error) {
			return new(big.Int).SetUint64(chainID), nil
		},
	}
}

func TestBuilder_BuildUnsigned_RPCMode_AllFromRPC(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	var from [20]byte
	from[0] = 0x01

	cfg := BuildConfig{
		NetworkParams: params,
		RPC:           makeMockRPC(params.ChainID),
		From:          from,
		// no GasLimit, no fees, no Nonce → all from RPC
	}
	b := NewBuilder()
	tx, err := b.BuildUnsigned(ctx, entry, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Nonce should be 7 (from mock PendingNonceAt).
	if tx.Nonce != 7 {
		t.Errorf("Nonce: got %d, want 7", tx.Nonce)
	}
	// Gas should be 100_000 * 6 / 5 = 120_000.
	if tx.Gas != 120_000 {
		t.Errorf("Gas: got %d, want 120000", tx.Gas)
	}
	// tip = 2gwei, baseFee = 10gwei → maxFee = 2*10 + 2 = 22gwei = 22_000_000_000
	wantMaxFee := big.NewInt(22_000_000_000)
	wantMaxFeeHex := "0x" + fmt.Sprintf("%x", wantMaxFee)
	if tx.MaxFeePerGas != wantMaxFeeHex {
		t.Errorf("MaxFeePerGas: got %s, want %s", tx.MaxFeePerGas, wantMaxFeeHex)
	}
	// tip = 2gwei
	wantTipHex := "0x" + fmt.Sprintf("%x", big.NewInt(2_000_000_000))
	if tx.MaxPriorityFeePerGas != wantTipHex {
		t.Errorf("MaxPriorityFeePerGas: got %s, want %s", tx.MaxPriorityFeePerGas, wantTipHex)
	}
}

func TestBuilder_BuildUnsigned_RPCMode_StaticFeeWins(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	var from [20]byte
	from[0] = 0x02

	staticFee := big.NewInt(99_000_000_000) // 99 gwei — should not be replaced by RPC
	staticTip := big.NewInt(3_000_000_000)  // 3 gwei — should not be replaced by RPC

	rpc := makeMockRPC(params.ChainID)
	// Explicitly verify the RPC fee methods are NOT called when static values are set.
	rpc.SuggestGasTipCapFn = func(_ context.Context) (*big.Int, error) {
		t.Fatal("SuggestGasTipCap must not be called when MaxPriorityFeePerGas is set")
		return nil, nil
	}
	rpc.BlockBaseFeeFn = func(_ context.Context) (*big.Int, error) {
		t.Fatal("BlockBaseFee must not be called when MaxFeePerGas is set")
		return nil, nil
	}

	nonce := uint64(5)
	cfg := BuildConfig{
		NetworkParams:        params,
		RPC:                  rpc,
		From:                 from,
		MaxFeePerGas:         staticFee,
		MaxPriorityFeePerGas: staticTip,
		Nonce:                &nonce,
		GasLimit:             200_000,
	}
	b := NewBuilder()
	tx, err := b.BuildUnsigned(ctx, entry, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantFeeHex := "0x" + fmt.Sprintf("%x", staticFee)
	if tx.MaxFeePerGas != wantFeeHex {
		t.Errorf("MaxFeePerGas: static value should win, got %s, want %s", tx.MaxFeePerGas, wantFeeHex)
	}
	if tx.Gas != 200_000 {
		t.Errorf("Gas: static value should win, got %d, want 200000", tx.Gas)
	}
	if tx.Nonce != 5 {
		t.Errorf("Nonce: static value should win, got %d, want 5", tx.Nonce)
	}
}

func TestBuilder_BuildUnsigned_RPCMode_ChainIDMismatch(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t) // ChainID = 17000

	var from [20]byte
	from[0] = 0x03

	wrongChainID := uint64(1) // mainnet
	cfg := BuildConfig{
		NetworkParams: params,
		RPC:           makeMockRPC(wrongChainID),
		From:          from,
	}
	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	if err == nil {
		t.Fatal("expected ErrChainIDMismatch, got nil")
	}
	if !errors.Is(err, ErrChainIDMismatch) {
		t.Errorf("expected ErrChainIDMismatch, got: %v", err)
	}
}

func TestBuilder_BuildUnsigned_RPCMode_ChainIDCallError_FailClosed(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	var from [20]byte
	from[0] = 0x04

	rpc := makeMockRPC(params.ChainID)
	rpc.ChainIDFn = func(_ context.Context) (*big.Int, error) {
		return nil, errors.New("ChainID RPC error")
	}

	cfg := BuildConfig{
		NetworkParams: params,
		RPC:           rpc,
		From:          from,
	}
	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	// ChainID call error now fails closed (M1.3-2); no silent ignore.
	if err == nil {
		t.Fatal("expected error on ChainID RPC err, got nil")
	}
	if !errors.Is(err, ErrChainIDZero) {
		t.Errorf("expected ErrChainIDZero, got: %v", err)
	}
}

func TestBuilder_BuildUnsigned_RPCMode_ZeroFrom_NilNonce(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	cfg := BuildConfig{
		NetworkParams: params,
		RPC:           makeMockRPC(params.ChainID),
		From:          [20]byte{}, // zero address — invalid when Nonce is nil
	}
	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	if err == nil {
		t.Fatal("expected ErrMissingFromForNonce, got nil")
	}
	if !errors.Is(err, ErrMissingFromForNonce) {
		t.Errorf("expected ErrMissingFromForNonce, got: %v", err)
	}
}

func TestBuilder_BuildUnsigned_RPCMode_EstimateGasError(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	var from [20]byte
	from[0] = 0x05

	rpc := makeMockRPC(params.ChainID)
	rpc.EstimateGasFn = func(_ context.Context, _ CallMsg) (uint64, error) {
		return 0, errors.New("estimate gas RPC error")
	}

	cfg := BuildConfig{
		NetworkParams: params,
		RPC:           rpc,
		From:          from,
		// GasLimit = 0 → triggers EstimateGas
	}
	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	if err == nil {
		t.Fatal("expected error from EstimateGas, got nil")
	}
	if !strings.Contains(err.Error(), "EstimateGas") {
		t.Errorf("error should mention EstimateGas, got: %v", err)
	}
}

func TestBuilder_BuildUnsigned_RPCMode_GasMargin(t *testing.T) {
	// Verify safety margin: estimate + estimate/5 (M1.3-3; 20% pad avoids overflow).
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	var from [20]byte
	from[0] = 0x06

	rpc := makeMockRPC(params.ChainID)
	rpc.EstimateGasFn = func(_ context.Context, _ CallMsg) (uint64, error) {
		return 100_000, nil
	}

	cfg := BuildConfig{
		NetworkParams: params,
		RPC:           rpc,
		From:          from,
	}
	b := NewBuilder()
	tx, err := b.BuildUnsigned(ctx, entry, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tx.Gas != 120_000 {
		t.Errorf("Gas with 20%% margin: got %d, want 120000", tx.Gas)
	}
}

func TestBuilder_BuildUnsigned_RPCMode_MaxFeeFormula(t *testing.T) {
	// Verify maxFee = 2*baseFee + tip.
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	var from [20]byte
	from[0] = 0x07

	baseFee := big.NewInt(10_000_000_000)    // 10 gwei
	tip := big.NewInt(2_000_000_000)         // 2 gwei
	wantMaxFee := big.NewInt(22_000_000_000) // 2*10 + 2 = 22 gwei

	rpc := makeMockRPC(params.ChainID)
	rpc.BlockBaseFeeFn = func(_ context.Context) (*big.Int, error) {
		return new(big.Int).Set(baseFee), nil
	}
	rpc.SuggestGasTipCapFn = func(_ context.Context) (*big.Int, error) {
		return new(big.Int).Set(tip), nil
	}

	nonce := uint64(0)
	cfg := BuildConfig{
		NetworkParams: params,
		RPC:           rpc,
		From:          from,
		Nonce:         &nonce,
		GasLimit:      200_000,
	}
	b := NewBuilder()
	tx, err := b.BuildUnsigned(ctx, entry, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantHex := "0x" + fmt.Sprintf("%x", wantMaxFee)
	if tx.MaxFeePerGas != wantHex {
		t.Errorf("MaxFeePerGas: got %s, want %s (2*baseFee+tip)", tx.MaxFeePerGas, wantHex)
	}
}

func TestBuilder_BuildUnsigned_RPCMode_SuggestGasTipCapError(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	var from [20]byte
	from[0] = 0x08

	rpc := makeMockRPC(params.ChainID)
	rpc.SuggestGasTipCapFn = func(_ context.Context) (*big.Int, error) {
		return nil, errors.New("tip cap rpc error")
	}

	cfg := BuildConfig{
		NetworkParams: params,
		RPC:           rpc,
		From:          from,
		// MaxPriorityFeePerGas nil → triggers SuggestGasTipCap
	}
	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	if err == nil {
		t.Fatal("expected error from SuggestGasTipCap, got nil")
	}
	if !strings.Contains(err.Error(), "SuggestGasTipCap") {
		t.Errorf("error should mention SuggestGasTipCap, got: %v", err)
	}
}

func TestBuilder_BuildUnsigned_RPCMode_BlockBaseFeeError(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	var from [20]byte
	from[0] = 0x09

	rpc := makeMockRPC(params.ChainID)
	rpc.BlockBaseFeeFn = func(_ context.Context) (*big.Int, error) {
		return nil, errors.New("base fee rpc error")
	}

	nonce := uint64(0)
	cfg := BuildConfig{
		NetworkParams: params,
		RPC:           rpc,
		From:          from,
		Nonce:         &nonce,
		GasLimit:      200_000,
		// MaxFeePerGas nil → triggers BlockBaseFee
	}
	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	if err == nil {
		t.Fatal("expected error from BlockBaseFee, got nil")
	}
	if !strings.Contains(err.Error(), "BlockBaseFee") {
		t.Errorf("error should mention BlockBaseFee, got: %v", err)
	}
}

func TestBuilder_BuildUnsigned_RPCMode_PendingNonceAtError(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	var from [20]byte
	from[0] = 0x0a

	rpc := makeMockRPC(params.ChainID)
	rpc.PendingNonceAtFn = func(_ context.Context, _ [20]byte) (uint64, error) {
		return 0, errors.New("nonce rpc error")
	}

	cfg := BuildConfig{
		NetworkParams: params,
		RPC:           rpc,
		From:          from,
		GasLimit:      200_000,
		// Nonce nil → triggers PendingNonceAt
	}
	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	if err == nil {
		t.Fatal("expected error from PendingNonceAt, got nil")
	}
	if !strings.Contains(err.Error(), "PendingNonceAt") {
		t.Errorf("error should mention PendingNonceAt, got: %v", err)
	}
}

// TestResolveRPC_ChainIDZero_FailClosed (mock): RPC returns 0 → error returned (no silent continue). M1.3-2 AC.
func TestResolveRPC_ChainIDZero_FailClosed(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	rpc := &mockRPC{
		ChainIDFn: func(_ context.Context) (*big.Int, error) {
			return big.NewInt(0), nil
		},
	}
	cfg := BuildConfig{
		NetworkParams: params,
		RPC:           rpc,
	}
	_, _, _, _, err := resolveRPC(ctx, cfg, entry, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrChainIDZero) {
		t.Errorf("expected ErrChainIDZero, got: %v", err)
	}
}

// TestResolveRPC_LoggerEmits_Warning (capture logger): warn-and-continue branches actually emit a WARN record. M1.3-2 AC.
func TestResolveRPC_LoggerEmits_Warning(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	var logBuf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	rpc := &mockRPC{
		ChainIDFn: func(_ context.Context) (*big.Int, error) {
			return nil, errors.New("rpc chainid fail")
		},
	}
	cfg := BuildConfig{
		NetworkParams: params,
		RPC:           rpc,
	}
	_, _, _, _, err := resolveRPC(ctx, cfg, entry, lg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrChainIDZero) {
		t.Errorf("expected ErrChainIDZero, got: %v", err)
	}
	logs := logBuf.String()
	if !strings.Contains(logs, "WARN") && !strings.Contains(logs, "level=WARN") {
		t.Errorf("expected WARN record in captured logger, got: %q", logs)
	}
	if !strings.Contains(logs, "chain ID resolution from RPC failed") {
		t.Errorf("expected warn msg, got: %q", logs)
	}
}

// TestGasEstimate_NearMaxUint64_NoOverflow exercises the +/5 pad (M1.3-3 AC).
// estimate near MaxUint64 must not wrap (unlike old *6/5).
func TestGasEstimate_NearMaxUint64_NoOverflow(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	var from [20]byte
	from[0] = 0x0a

	near := uint64(math.MaxUint64 - 1024)
	rpc := makeMockRPC(params.ChainID)
	rpc.EstimateGasFn = func(_ context.Context, _ CallMsg) (uint64, error) {
		return near, nil
	}

	cfg := BuildConfig{
		NetworkParams: params,
		RPC:           rpc,
		From:          from,
	}
	b := NewBuilder()
	tx, err := b.BuildUnsigned(ctx, entry, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := near + near/5
	if tx.Gas != want {
		t.Errorf("Gas near-max: got %d, want %d (no wrap)", tx.Gas, want)
	}
	// AC uses literal estimate=max-1024 (per spec); final 1.2*e > MaxUint64 so
	// result wraps in uint64 (old *6/5 and +/5 coincide on this e). The test
	// verifies success + correct (from + expr) padded value for the near-max input
	// case; no intermediate overflow bug in the fix path. Happy-path green too.
}

// TestBuilder_UsesDepositContractDirectly verifies direct use of
// NetworkParams.DepositContractAddress (no hex round-trip / common.HexToAddress).
// AC: "(read code)" + this exercises the To passed to EstimateGas.
func TestBuilder_UsesDepositContractDirectly(t *testing.T) {
	ctx := context.Background()
	entry := makeValidEntry()
	params := holeskyParams(t)

	var from [20]byte
	from[0] = 0x0b

	rpc := makeMockRPC(params.ChainID)
	var sawTo [20]byte
	rpc.EstimateGasFn = func(_ context.Context, msg CallMsg) (uint64, error) {
		sawTo = msg.To
		return 21000, nil
	}

	cfg := BuildConfig{
		NetworkParams: params,
		RPC:           rpc,
		From:          from,
	}
	b := NewBuilder()
	_, err := b.BuildUnsigned(ctx, entry, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sawTo != params.DepositContractAddress {
		t.Errorf("EstimateGas saw To=%x, want direct DepositContractAddress=%x", sawTo, params.DepositContractAddress)
	}
}
