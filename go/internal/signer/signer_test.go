package signer_test

import (
	"context"
	"testing"

	"github.com/rootwarp/eth-utils/go/internal/signer"
	"github.com/rootwarp/eth-utils/go/internal/tx"
)

// compile-time interface satisfaction check
var _ signer.Signer = (*fakeSigner)(nil)

type fakeSigner struct {
	name string
}

func (f *fakeSigner) Sign(_ context.Context, unsigned tx.UnsignedTx) (*signer.SignedTx, error) {
	return &signer.SignedTx{
		Unsigned: unsigned,
		From:     "0xdeadbeef",
		Hash:     "0xabc123",
		R:        "0x1",
		S:        "0x2",
		V:        "0",
		RawRLP:   "0xdeadbeef",
	}, nil
}

func (f *fakeSigner) Name() string                    { return f.name }
func (f *fakeSigner) RequiresUserInteraction() bool   { return false }
func (f *fakeSigner) Close() error                    { return nil }

func TestFakeSignerName(t *testing.T) {
	s := &fakeSigner{name: "test-signer"}
	if got := s.Name(); got != "test-signer" {
		t.Errorf("Name() = %q, want %q", got, "test-signer")
	}
}

func TestFakeSignerSign(t *testing.T) {
	s := &fakeSigner{name: "fake"}
	unsigned := tx.UnsignedTx{
		ChainID: 1,
		To:      "0x1234",
		Value:   "0x1",
		Data:    "0xabcd",
		Gas:     21000,
		Type:    "0x2",
	}
	ctx := context.Background()
	signed, err := s.Sign(ctx, unsigned)
	if err != nil {
		t.Fatalf("Sign() returned unexpected error: %v", err)
	}
	if signed == nil {
		t.Fatal("Sign() returned nil SignedTx")
	}
	if signed.From != "0xdeadbeef" {
		t.Errorf("From = %q, want %q", signed.From, "0xdeadbeef")
	}
	if signed.Unsigned.ChainID != unsigned.ChainID {
		t.Errorf("Unsigned.ChainID = %d, want %d", signed.Unsigned.ChainID, unsigned.ChainID)
	}
}

func TestSentinelErrors(t *testing.T) {
	errs := []error{
		signer.ErrUserRejected,
		signer.ErrNoDevice,
		signer.ErrAppNotOpen,
		signer.ErrInvalidKey,
		signer.ErrChainIDMismatch,
		signer.ErrInvalidChainID,
		signer.ErrSignerClosed,
		signer.ErrLedgerNotSupported,
	}
	for _, e := range errs {
		if e == nil {
			t.Error("sentinel error must not be nil")
		}
		if e.Error() == "" {
			t.Errorf("sentinel error %v has empty message", e)
		}
	}
}
