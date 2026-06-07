package tx

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// goldenSignedTx mirrors the fields of signer.SignedTx we need without
// importing the signer package (to avoid a cycle).
type goldenSignedTx struct {
	RawRLP string `json:"rawRLP"`
}

func readGoldenRawRLP(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../../testdata/phase3/holesky/signed_tx_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var g goldenSignedTx
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	return g.RawRLP
}

// TestDecodeRawRLP_EIP2718 asserts that the phase-3 golden RawRLP (an EIP-2718
// type-2 envelope: 0x02 || rlp(...)) is correctly decoded by UnmarshalBinary.
// This test would FAIL if we used rlp.DecodeBytes instead, because the leading
// 0x02 type byte is not valid bare RLP.
func TestDecodeRawRLP_EIP2718(t *testing.T) {
	rawRLP := readGoldenRawRLP(t)

	rawBytes, err := decodeHex(rawRLP)
	if err != nil {
		t.Fatalf("decodeHex: %v", err)
	}

	// Verify that the first byte is the EIP-2718 type byte (0x02 = EIP-1559).
	if len(rawBytes) == 0 || rawBytes[0] != 0x02 {
		t.Fatalf("expected EIP-2718 type byte 0x02, got 0x%02x", rawBytes[0])
	}

	// UnmarshalBinary handles the EIP-2718 envelope correctly.
	var tx types.Transaction
	if err := tx.UnmarshalBinary(rawBytes); err != nil {
		t.Fatalf("UnmarshalBinary failed on EIP-2718 envelope: %v", err)
	}

	// Sanity-check: chain ID should be Holesky (17000).
	if chainID := tx.ChainId().Uint64(); chainID != 17000 {
		t.Errorf("chainID = %d, want 17000", chainID)
	}
}

// TestDecodeRawRLP_RLPDecodeBytes_Breaks documents that rlp.DecodeBytes CANNOT
// handle the EIP-2718 envelope and would fail on real signed tx data. This test
// exists to prove the regression the Must Fix addresses.
func TestDecodeRawRLP_RLPDecodeBytes_Breaks(t *testing.T) {
	rawRLP := readGoldenRawRLP(t)

	rawBytes, err := decodeHex(rawRLP)
	if err != nil {
		t.Fatalf("decodeHex: %v", err)
	}

	// rlp.DecodeBytes on an EIP-2718 envelope should fail because the leading
	// type byte (0x02) makes this non-RLP data.
	var tx types.Transaction
	if err := rlp.DecodeBytes(rawBytes, &tx); err == nil {
		t.Error("expected rlp.DecodeBytes to fail on EIP-2718 type-2 envelope, but it succeeded — this path is unsafe")
	}
}

// TestBlockBaseFee_NilBaseFee_Reject (mock): header with nil BaseFee → ErrNoBaseFee.
func TestBlockBaseFee_NilBaseFee_Reject(t *testing.T) {
	rpc := &mockRPC{
		BlockBaseFeeFn: func(ctx context.Context) (*big.Int, error) {
			return nil, ErrNoBaseFee
		},
	}
	fee, err := rpc.BlockBaseFee(context.Background())
	if fee != nil {
		t.Errorf("expected nil fee, got %v", fee)
	}
	if !errors.Is(err, ErrNoBaseFee) {
		t.Errorf("expected ErrNoBaseFee, got: %v", err)
	}
}

// TestBlockBaseFee_HappyPath (mock): non-nil → returns value.
func TestBlockBaseFee_HappyPath(t *testing.T) {
	want := big.NewInt(123456789012345)
	rpc := &mockRPC{
		BlockBaseFeeFn: func(ctx context.Context) (*big.Int, error) {
			return new(big.Int).Set(want), nil
		},
	}
	got, err := rpc.BlockBaseFee(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Cmp(want) != 0 {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestReceipt_NotFound_RetriesUntilDeadline (mock): mock returns
// ethereum.NotFound 3× then success → success returned. (M1.3-4 AC)
func TestReceipt_NotFound_RetriesUntilDeadline(t *testing.T) {
	calls := 0
	fetch := func(ctx context.Context, h common.Hash) (*types.Receipt, error) {
		calls++
		if calls < 4 {
			return nil, ethereum.NotFound
		}
		return &types.Receipt{
			TxHash:      common.HexToHash("0x1234"),
			Status:      1,
			GasUsed:     12345,
			BlockHash:   common.HexToHash("0xabc"),
			BlockNumber: big.NewInt(99),
		}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rec, err := transactionReceiptWithRetry(ctx, common.HexToHash("0x1234"), fetch)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rec == nil || rec.BlockNumber != 99 {
		t.Errorf("got %+v, want blockNumber=99", rec)
	}
	if calls != 4 {
		t.Errorf("calls = %d, want 4 (3×NotFound + 1 success)", calls)
	}
}

// TestReceipt_NotFound_DeadlineExceeded (mock): NotFound until dl exceeded
// yields ErrReceiptTimeout. (M1.3-4 AC)
func TestReceipt_NotFound_DeadlineExceeded(t *testing.T) {
	calls := 0
	fetch := func(ctx context.Context, h common.Hash) (*types.Receipt, error) {
		calls++
		return nil, ethereum.NotFound
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	// ensure we hit the deadline (via ctx.Err after first NotFound)
	time.Sleep(100 * time.Millisecond)
	rec, err := transactionReceiptWithRetry(ctx, common.HexToHash("0xdead"), fetch)
	if rec != nil {
		t.Errorf("expected nil receipt, got %+v", rec)
	}
	if !errors.Is(err, ErrReceiptTimeout) {
		t.Errorf("expected errors.Is(ErrReceiptTimeout), got: %v", err)
	}
}

// TestReceipt_TransientError_Retries (mock): transient net err twice then
// success → success. (M1.3-4 AC)
func TestReceipt_TransientError_Retries(t *testing.T) {
	calls := 0
	fetch := func(ctx context.Context, h common.Hash) (*types.Receipt, error) {
		calls++
		if calls < 3 {
			return nil, &net.DNSError{IsTimeout: true}
		}
		return &types.Receipt{
			TxHash:      common.HexToHash("0x1"),
			Status:      1,
			GasUsed:     21000,
			BlockHash:   common.HexToHash("0xb"),
			BlockNumber: big.NewInt(42),
		}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rec, err := transactionReceiptWithRetry(ctx, common.HexToHash("0x1"), fetch)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rec == nil || rec.BlockNumber != 42 {
		t.Errorf("got %+v, want blockNumber=42", rec)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3 (2 transient + 1 success)", calls)
	}
}

// TestReceipt_NotFound_NoDeadline_LegacyNilNil (mock): no dl ctx + NotFound
// yields immediate nil, nil (calls==1, no internal retry). Covers bg and
// canceled-non-dl (per review). Critical for pollReceipt/send compat.
func TestReceipt_NotFound_NoDeadline_LegacyNilNil(t *testing.T) {
	for _, name := range []string{"bg", "canceled"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			fetch := func(ctx context.Context, h common.Hash) (*types.Receipt, error) {
				calls++
				return nil, ethereum.NotFound
			}
			ctx := context.Background()
			if name == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			rec, err := transactionReceiptWithRetry(ctx, common.HexToHash("0x1234"), fetch)
			if rec != nil || err != nil {
				t.Errorf("expected nil, nil; got rec=%v err=%v", rec, err)
			}
			if calls != 1 {
				t.Errorf("calls = %d, want 1 (no internal retry)", calls)
			}
		})
	}
}

// TestReceipt_TransientError_DeadlineExceeded (mock): perpetual transient
// under dl ctx -> ErrReceiptTimeout (symmetric to NotFound dl case).
func TestReceipt_TransientError_DeadlineExceeded(t *testing.T) {
	calls := 0
	fetch := func(ctx context.Context, h common.Hash) (*types.Receipt, error) {
		calls++
		return nil, &net.DNSError{IsTimeout: true}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	time.Sleep(100 * time.Millisecond)
	rec, err := transactionReceiptWithRetry(ctx, common.HexToHash("0xdead"), fetch)
	if rec != nil {
		t.Errorf("expected nil receipt, got %+v", rec)
	}
	if !errors.Is(err, ErrReceiptTimeout) {
		t.Errorf("expected errors.Is(ErrReceiptTimeout), got: %v", err)
	}
}
