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

func (f *fakeSigner) Name() string                  { return f.name }
func (f *fakeSigner) RequiresUserInteraction() bool { return false }
func (f *fakeSigner) Close() error                  { return nil }

func TestSentinelErrors(t *testing.T) {
	errs := []error{
		signer.ErrUserRejected,
		signer.ErrNoDevice,
		signer.ErrAppNotOpen,
		signer.ErrInvalidKey,
		signer.ErrChainIDMismatch,
		signer.ErrInvalidChainID,
		signer.ErrSignerClosed,
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
