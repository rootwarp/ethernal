//go:build differential_oracle

package ssz

import (
	"testing"

	oracle "github.com/rootwarp/eth-utils/go/internal/ssz/testdata"
)

// TestDifferentialDepositMessageRoot and TestDifferentialDepositDataRoot
// drive our hand-rolled HashTreeRoot against the fastssz oracle (from
// committed generated code) on a small shared seed-anchored corpus.
// This replaces the dead/tautological compute* stubs (see M1.2-7).
// Both must agree exactly on roots for the seeded cases.

func TestDifferentialDepositMessageRoot(t *testing.T) {
	// Seed-anchored corpus (values chosen to exercise paths also covered by
	// ssz_test.go golden cases + all-zero + non-zero amount).
	corpus := []struct {
		Pubkey [48]byte
		WC     [32]byte
		Amount uint64
	}{
		{}, // all zero
		{
			Amount: 32_000_000_000,
		},
		{
			Pubkey: func() (p [48]byte) { p[0] = 0xab; p[47] = 0xff; return p }(),
			WC:     func() (w [32]byte) { w[0] = 0x01; w[31] = 0x02; return w }(),
			Amount: 1,
		},
	}
	for i, c := range corpus {
		ours := DepositMessage{
			Pubkey:                c.Pubkey,
			WithdrawalCredentials: c.WC,
			Amount:                c.Amount,
		}.HashTreeRoot()
		theirs, _ := (&oracle.DepositMessage{
			Pubkey:                c.Pubkey,
			WithdrawalCredentials: c.WC,
			Amount:                c.Amount,
		}).HashTreeRoot()
		if ours != theirs {
			t.Errorf("DepositMessage[%d] root mismatch:\n  ours:   %x\n  theirs: %x", i, ours, theirs)
		}
	}
}

func TestDifferentialDepositDataRoot(t *testing.T) {
	corpus := []struct {
		Pubkey [48]byte
		WC     [32]byte
		Amount uint64
		Sig    [96]byte
	}{
		{}, // all zero
		{
			Amount: 32_000_000_000,
			Sig:    func() (s [96]byte) { s[0] = 0xde; s[95] = 0xad; return s }(),
		},
		{
			Pubkey: func() (p [48]byte) { p[0] = 0x11; p[47] = 0x22; return p }(),
			WC:     func() (w [32]byte) { w[15] = 0x33; return w }(),
			Amount: 32_000_000_000,
			Sig:    func() (s [96]byte) { s[47] = 0x44; s[95] = 0x55; return s }(),
		},
	}
	for i, c := range corpus {
		ours := DepositData{
			Pubkey:                c.Pubkey,
			WithdrawalCredentials: c.WC,
			Amount:                c.Amount,
			Signature:             c.Sig,
		}.HashTreeRoot()
		theirs, _ := (&oracle.DepositData{
			Pubkey:                c.Pubkey,
			WithdrawalCredentials: c.WC,
			Amount:                c.Amount,
			Signature:             c.Sig,
		}).HashTreeRoot()
		if ours != theirs {
			t.Errorf("DepositData[%d] root mismatch:\n  ours:   %x\n  theirs: %x", i, ours, theirs)
		}
	}
}

// FuzzDifferentialDepositMessageRoot and FuzzDifferentialDepositDataRoot
// provide seed-anchored fuzz (per research/05 ex + arch §11.1) driving
// both HTR impls from f.Add seeds (public vectors only); assert agreement.
// Run only under -tags=differential_oracle (tag isolation).
func FuzzDifferentialDepositMessageRoot(f *testing.F) {
	// Seed-anchored (synthetic public; exercise zero + 32gwei + partial bytes like Test*).
	f.Add([]byte{}, []byte{}, uint64(0))
	f.Add([]byte{0xab}, []byte{0x01}, uint64(32_000_000_000))
	f.Add(
		func() []byte { b := make([]byte, 48); b[0] = 0xab; b[47] = 0xff; return b }(),
		func() []byte { b := make([]byte, 32); b[0] = 0x01; b[31] = 0x02; return b }(),
		uint64(1),
	)
	f.Fuzz(func(t *testing.T, pk, wc []byte, amount uint64) {
		if len(pk) > 48 {
			pk = pk[:48]
		}
		if len(wc) > 32 {
			wc = wc[:32]
		}
		var p [48]byte
		copy(p[:], pk)
		var w [32]byte
		copy(w[:], wc)
		ours := DepositMessage{Pubkey: p, WithdrawalCredentials: w, Amount: amount}.HashTreeRoot()
		theirs, _ := (&oracle.DepositMessage{Pubkey: p, WithdrawalCredentials: w, Amount: amount}).HashTreeRoot()
		if ours != theirs {
			t.Errorf("DepositMessage fuzz mismatch")
		}
	})
}

func FuzzDifferentialDepositDataRoot(f *testing.F) {
	f.Add([]byte{}, []byte{}, uint64(0), []byte{})
	f.Add([]byte{0x11}, []byte{0x22}, uint64(32_000_000_000), []byte{0xde})
	f.Fuzz(func(t *testing.T, pk, wc []byte, amount uint64, sig []byte) {
		if len(pk) > 48 {
			pk = pk[:48]
		}
		if len(wc) > 32 {
			wc = wc[:32]
		}
		if len(sig) > 96 {
			sig = sig[:96]
		}
		var p [48]byte
		copy(p[:], pk)
		var w [32]byte
		copy(w[:], wc)
		var s [96]byte
		copy(s[:], sig)
		ours := DepositData{Pubkey: p, WithdrawalCredentials: w, Amount: amount, Signature: s}.HashTreeRoot()
		theirs, _ := (&oracle.DepositData{Pubkey: p, WithdrawalCredentials: w, Amount: amount, Signature: s}).HashTreeRoot()
		if ours != theirs {
			t.Errorf("DepositData fuzz mismatch")
		}
	})
}
