package deposit

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/rootwarp/eth-utils/go/internal/network"
	"github.com/rootwarp/eth-utils/go/internal/ssz"
)

// -----------------------------------------------------------------------------
// Fake Signer implementation
// -----------------------------------------------------------------------------

type fakeSigner struct {
	pubkey  [48]byte
	sig     [96]byte
	signErr error
	onSign  func() // called before returning from Sign; used for ctx cancel tests
}

func (f *fakeSigner) Sign(_ [32]byte) ([96]byte, error) {
	if f.onSign != nil {
		f.onSign()
	}
	return f.sig, f.signErr
}

func (f *fakeSigner) PublicKey() ([48]byte, error) {
	return f.pubkey, nil
}

// -----------------------------------------------------------------------------
// Fake Verifier implementation
// -----------------------------------------------------------------------------

type fakeVerifier struct {
	ok  bool
	err error
}

func (f *fakeVerifier) Verify(_ [48]byte, _ [32]byte, _ [96]byte) (bool, error) {
	return f.ok, f.err
}

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

// hoodParams returns Hoodi testnet params for use in tests.
func hoodiParams() network.Params {
	p, err := network.Lookup(network.Hoodi)
	if err != nil {
		panic(err)
	}
	return p
}

// makePubkey builds a distinct [48]byte pubkey from a single seed byte.
func makePubkey(seed byte) [48]byte {
	var pk [48]byte
	pk[0] = seed
	return pk
}

// makeSig builds a distinct [96]byte signature from a single seed byte.
func makeSig(seed byte) [96]byte {
	var sig [96]byte
	sig[0] = seed
	return sig
}

// -----------------------------------------------------------------------------
// TestGenerate_Success
// -----------------------------------------------------------------------------

// TestGenerate_Success verifies that 3 pubkeys all matching the signer's pubkey
// produce 3 entries with correct fields including DepositDataRoot.
func TestGenerate_Success(t *testing.T) {
	params := hoodiParams()
	pk := makePubkey(0xAA)
	sig := makeSig(0xBB)

	wc := [32]byte{0x01}
	amount := uint64(32_000_000_000)
	cliVer := "2.7.0"

	signer := &fakeSigner{pubkey: pk, sig: sig}
	verifier := &fakeVerifier{ok: true}

	gen := NewGenerator(signer, verifier, params)

	req := Request{
		Network:               network.Hoodi,
		Pubkeys:               [][48]byte{pk, pk, pk},
		WithdrawalCredentials: wc,
		AmountGwei:            amount,
		DepositCLIVersion:     cliVer,
	}

	entries, err := gen.Generate(context.Background(), req)
	if err != nil {
		t.Fatalf("Generate() returned unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("Generate() returned %d entries, want 3", len(entries))
	}

	for i, e := range entries {
		// Pubkey matches input
		if e.Pubkey != pk {
			t.Errorf("entry[%d].Pubkey = %x, want %x", i, e.Pubkey, pk)
		}
		// WithdrawalCredentials propagated
		if e.WithdrawalCredentials != wc {
			t.Errorf("entry[%d].WithdrawalCredentials = %x, want %x", i, e.WithdrawalCredentials, wc)
		}
		// Amount propagated
		if e.Amount != amount {
			t.Errorf("entry[%d].Amount = %d, want %d", i, e.Amount, amount)
		}
		// Signature propagated
		if e.Signature != sig {
			t.Errorf("entry[%d].Signature = %x, want %x", i, e.Signature, sig)
		}
		// ForkVersion matches params
		if e.ForkVersion != params.GenesisForkVersion {
			t.Errorf("entry[%d].ForkVersion = %x, want %x", i, e.ForkVersion, params.GenesisForkVersion)
		}
		// NetworkName matches params
		if e.NetworkName != params.Name {
			t.Errorf("entry[%d].NetworkName = %q, want %q", i, e.NetworkName, params.Name)
		}
		// DepositCLIVersion propagated
		if e.DepositCLIVersion != cliVer {
			t.Errorf("entry[%d].DepositCLIVersion = %q, want %q", i, e.DepositCLIVersion, cliVer)
		}

		// DepositMessageRoot: independently recompute via real ssz package
		expectedMsg := ssz.DepositMessage{
			Pubkey:                pk,
			WithdrawalCredentials: wc,
			Amount:                amount,
		}
		expectedMsgRoot := expectedMsg.HashTreeRoot()
		if e.DepositMessageRoot != expectedMsgRoot {
			t.Errorf("entry[%d].DepositMessageRoot = %x, want %x", i, e.DepositMessageRoot, expectedMsgRoot)
		}

		// DepositDataRoot: independently recompute via real ssz package
		expectedData := ssz.DepositData{
			Pubkey:                pk,
			WithdrawalCredentials: wc,
			Amount:                amount,
			Signature:             sig,
		}
		expectedDataRoot := expectedData.HashTreeRoot()
		if e.DepositDataRoot != expectedDataRoot {
			t.Errorf("entry[%d].DepositDataRoot = %x, want %x", i, e.DepositDataRoot, expectedDataRoot)
		}
	}
}

// -----------------------------------------------------------------------------
// TestGenerate_PubkeyMismatch
// -----------------------------------------------------------------------------

// TestGenerate_PubkeyMismatch verifies that when the signer's pubkey does not
// match the requested pubkey, ErrPubkeyMismatch is returned and no entries are
// emitted.
func TestGenerate_PubkeyMismatch(t *testing.T) {
	params := hoodiParams()
	signerPubkey := makePubkey(0xAA)  // signer has this key
	requestPubkey := makePubkey(0xBB) // but request asks for this key

	signer := &fakeSigner{pubkey: signerPubkey}
	verifier := &fakeVerifier{ok: true}

	gen := NewGenerator(signer, verifier, params)

	req := Request{
		Network:               network.Hoodi,
		Pubkeys:               [][48]byte{requestPubkey},
		WithdrawalCredentials: [32]byte{},
		AmountGwei:            32_000_000_000,
		DepositCLIVersion:     "2.7.0",
	}

	entries, err := gen.Generate(context.Background(), req)
	if !errors.Is(err, ErrPubkeyMismatch) {
		t.Errorf("Generate() error = %v, want errors.Is ErrPubkeyMismatch", err)
	}
	if entries != nil {
		t.Errorf("Generate() returned non-nil entries on mismatch: %v", entries)
	}
}

// -----------------------------------------------------------------------------
// TestGenerate_SelfVerifyFailed
// -----------------------------------------------------------------------------

// TestGenerate_SelfVerifyFailed verifies that when the verifier returns false,
// ErrSelfVerifyFailed is returned and no entries are emitted.
func TestGenerate_SelfVerifyFailed(t *testing.T) {
	params := hoodiParams()
	pk := makePubkey(0xAA)

	signer := &fakeSigner{pubkey: pk, sig: makeSig(0x01)}
	verifier := &fakeVerifier{ok: false} // always fails

	gen := NewGenerator(signer, verifier, params)

	req := Request{
		Network:               network.Hoodi,
		Pubkeys:               [][48]byte{pk},
		WithdrawalCredentials: [32]byte{},
		AmountGwei:            32_000_000_000,
		DepositCLIVersion:     "2.7.0",
	}

	entries, err := gen.Generate(context.Background(), req)
	if !errors.Is(err, ErrSelfVerifyFailed) {
		t.Errorf("Generate() error = %v, want errors.Is ErrSelfVerifyFailed", err)
	}
	if entries != nil {
		t.Errorf("Generate() returned non-nil entries on verify failure: %v", entries)
	}
}

// -----------------------------------------------------------------------------
// TestGenerate_ContextCancel
// -----------------------------------------------------------------------------

// TestGenerate_ContextCancel verifies that when the context is cancelled
// mid-loop (before iteration 2), Generate returns the ctx error and nil slice.
func TestGenerate_ContextCancel(t *testing.T) {
	params := hoodiParams()
	pk := makePubkey(0xAA)

	ctx, cancel := context.WithCancel(context.Background())

	// The fake signer's onSign hook cancels the context on the first Sign call.
	// Iteration 1 completes its Sign, then the ctx check at the top of iteration 2
	// sees ctx.Err() and returns it immediately.
	signer := &fakeSigner{
		pubkey: pk,
		sig:    makeSig(0x01),
		onSign: cancel,
	}
	verifier := &fakeVerifier{ok: true}

	gen := NewGenerator(signer, verifier, params)

	req := Request{
		Network:               network.Hoodi,
		Pubkeys:               [][48]byte{pk, pk}, // two pubkeys; second will be cancelled
		WithdrawalCredentials: [32]byte{},
		AmountGwei:            32_000_000_000,
		DepositCLIVersion:     "2.7.0",
	}

	entries, err := gen.Generate(ctx, req)
	if err == nil {
		t.Fatal("Generate() returned nil error, want ctx error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Generate() error = %v, want context.Canceled", err)
	}
	if entries != nil {
		t.Errorf("Generate() returned non-nil entries on context cancel: %v", entries)
	}
}

// -----------------------------------------------------------------------------
// TestGenerate_PublicKeyError
// -----------------------------------------------------------------------------

// fakeErrorSigner is a signer whose PublicKey() always returns an error.
type fakeErrorSigner struct {
	pubkeyErr error
}

func (f *fakeErrorSigner) Sign(_ [32]byte) ([96]byte, error) {
	return [96]byte{}, nil
}

func (f *fakeErrorSigner) PublicKey() ([48]byte, error) {
	return [48]byte{}, f.pubkeyErr
}

// TestGenerate_PublicKeyError verifies that an error from signer.PublicKey()
// is propagated directly (not wrapped in ErrPubkeyMismatch).
func TestGenerate_PublicKeyError(t *testing.T) {
	params := hoodiParams()
	wantErr := fmt.Errorf("pubkey fetch failure")

	signer := &fakeErrorSigner{pubkeyErr: wantErr}
	verifier := &fakeVerifier{ok: true}

	gen := NewGenerator(signer, verifier, params)

	req := Request{
		Network:               network.Hoodi,
		Pubkeys:               [][48]byte{makePubkey(0x01)},
		WithdrawalCredentials: [32]byte{},
		AmountGwei:            32_000_000_000,
		DepositCLIVersion:     "2.7.0",
	}

	entries, err := gen.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("Generate() returned nil error, want pubkey error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("Generate() error = %v, want %v", err, wantErr)
	}
	if entries != nil {
		t.Errorf("Generate() returned non-nil entries on pubkey error: %v", entries)
	}
}

// -----------------------------------------------------------------------------
// TestGenerate_SignError
// -----------------------------------------------------------------------------

// fakeSignErrorSigner returns a fixed pubkey but fails on Sign.
type fakeSignErrorSigner struct {
	pubkey  [48]byte
	signErr error
}

func (f *fakeSignErrorSigner) Sign(_ [32]byte) ([96]byte, error) {
	return [96]byte{}, f.signErr
}

func (f *fakeSignErrorSigner) PublicKey() ([48]byte, error) {
	return f.pubkey, nil
}

// TestGenerate_SignError verifies that an error from signer.Sign() is propagated.
func TestGenerate_SignError(t *testing.T) {
	params := hoodiParams()
	pk := makePubkey(0x01)
	wantErr := fmt.Errorf("hardware signer offline")

	signer := &fakeSignErrorSigner{pubkey: pk, signErr: wantErr}
	verifier := &fakeVerifier{ok: true}

	gen := NewGenerator(signer, verifier, params)

	req := Request{
		Network:               network.Hoodi,
		Pubkeys:               [][48]byte{pk},
		WithdrawalCredentials: [32]byte{},
		AmountGwei:            32_000_000_000,
		DepositCLIVersion:     "2.7.0",
	}

	entries, err := gen.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("Generate() returned nil error, want sign error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("Generate() error = %v, want %v", err, wantErr)
	}
	if entries != nil {
		t.Errorf("Generate() returned non-nil entries on sign error: %v", entries)
	}
}

// -----------------------------------------------------------------------------
// TestGenerate_VerifyError
// -----------------------------------------------------------------------------

// TestGenerate_VerifyError verifies that an error from verifier.Verify() is
// propagated (distinct from ErrSelfVerifyFailed which is the !ok path).
func TestGenerate_VerifyError(t *testing.T) {
	params := hoodiParams()
	pk := makePubkey(0x01)
	wantErr := fmt.Errorf("HSM verify timeout")

	signer := &fakeSigner{pubkey: pk, sig: makeSig(0x01)}
	verifier := &fakeVerifier{ok: false, err: wantErr} // error takes priority

	gen := NewGenerator(signer, verifier, params)

	req := Request{
		Network:               network.Hoodi,
		Pubkeys:               [][48]byte{pk},
		WithdrawalCredentials: [32]byte{},
		AmountGwei:            32_000_000_000,
		DepositCLIVersion:     "2.7.0",
	}

	entries, err := gen.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("Generate() returned nil error, want verify error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("Generate() error = %v, want %v", err, wantErr)
	}
	if entries != nil {
		t.Errorf("Generate() returned non-nil entries on verify error: %v", entries)
	}
}

func TestGenerate_NetworkMismatch(t *testing.T) {
	params := hoodiParams()
	pk := makePubkey(0x01)
	signer := &fakeSigner{pubkey: pk}
	verifier := &fakeVerifier{ok: true}
	gen := NewGenerator(signer, verifier, params)

	// Pass mainnet in the request but the generator is for hoodi.
	req := Request{
		Network:           network.Mainnet,
		Pubkeys:           [][48]byte{pk},
		AmountGwei:        32_000_000_000,
		DepositCLIVersion: "2.7.0",
	}
	entries, err := gen.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("Generate() returned nil error, want network mismatch error")
	}
	if entries != nil {
		t.Errorf("Generate() returned non-nil entries on network mismatch")
	}
}

func TestGenerate_EmptyPubkeys(t *testing.T) {
	params := hoodiParams()
	signer := &fakeSigner{}
	verifier := &fakeVerifier{ok: true}
	gen := NewGenerator(signer, verifier, params)

	req := Request{
		Network:           network.Hoodi,
		Pubkeys:           nil,
		AmountGwei:        32_000_000_000,
		DepositCLIVersion: "2.7.0",
	}
	entries, err := gen.Generate(context.Background(), req)
	if err != nil {
		t.Fatalf("Generate() with no pubkeys returned error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Generate() with no pubkeys returned %d entries, want 0", len(entries))
	}
}
