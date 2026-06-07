package tx

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

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
