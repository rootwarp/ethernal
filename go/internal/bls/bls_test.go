package bls_test

import (
	"bytes"
	"testing"

	"github.com/rootwarp/eth-utils/go/internal/bls"
)

// TestInitIdempotent verifies Init can be called more than once without error or panic.
func TestInitIdempotent(t *testing.T) {
	if err := bls.Init(); err != nil {
		t.Fatalf("first Init() = %v, want nil", err)
	}
	if err := bls.Init(); err != nil {
		t.Fatalf("second Init() = %v, want nil", err)
	}
}

// TestNewSignerRejectsWrongLength verifies NewSigner returns an error when the
// secret is not exactly 32 bytes.
func TestNewSignerRejectsWrongLength(t *testing.T) {
	if err := bls.Init(); err != nil {
		t.Fatalf("Init() = %v", err)
	}

	cases := []struct {
		name   string
		secret []byte
	}{
		{"empty", []byte{}},
		{"too short 16 bytes", bytes.Repeat([]byte{0x01}, 16)},
		{"too long 33 bytes", bytes.Repeat([]byte{0x01}, 33)},
		{"too long 64 bytes", bytes.Repeat([]byte{0x01}, 64)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bls.NewSigner(tc.secret)
			if err == nil {
				t.Errorf("NewSigner(%d bytes) returned nil error, want error", len(tc.secret))
			}
		})
	}
}

// TestRoundTrip signs a root with key A and verifies it with key A's pubkey.
// This is the primary correctness gate for the BLS pipeline.
func TestRoundTrip(t *testing.T) {
	if err := bls.Init(); err != nil {
		t.Fatalf("Init() = %v", err)
	}

	secret := bytes.Repeat([]byte{0x01}, 32)
	signer, err := bls.NewSigner(secret)
	if err != nil {
		t.Fatalf("NewSigner() = %v", err)
	}

	var signingRoot [32]byte
	copy(signingRoot[:], bytes.Repeat([]byte{0xab}, 32))

	sig, err := signer.Sign(signingRoot)
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}

	pub, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() = %v", err)
	}

	verifier := bls.DefaultVerifier()
	ok, err := verifier.Verify(pub, signingRoot, sig)
	if err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if !ok {
		t.Error("Verify() = false, want true for valid round-trip")
	}
}

// TestVerifyRejection signs with key A but verifies with key B's pubkey, expecting false.
func TestVerifyRejection(t *testing.T) {
	if err := bls.Init(); err != nil {
		t.Fatalf("Init() = %v", err)
	}

	secretA := bytes.Repeat([]byte{0x01}, 32)
	secretB := bytes.Repeat([]byte{0x02}, 32)

	signerA, err := bls.NewSigner(secretA)
	if err != nil {
		t.Fatalf("NewSigner(A) = %v", err)
	}
	signerB, err := bls.NewSigner(secretB)
	if err != nil {
		t.Fatalf("NewSigner(B) = %v", err)
	}

	var signingRoot [32]byte
	copy(signingRoot[:], bytes.Repeat([]byte{0xcd}, 32))

	// Sign with key A
	sig, err := signerA.Sign(signingRoot)
	if err != nil {
		t.Fatalf("Sign(A) = %v", err)
	}

	// Verify with key B's pubkey — must fail
	pubB, err := signerB.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey(B) = %v", err)
	}

	verifier := bls.DefaultVerifier()
	ok, err := verifier.Verify(pubB, signingRoot, sig)
	if err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if ok {
		t.Error("Verify() = true, want false when verifying with wrong pubkey")
	}
}

// TestCallerSecretUnmodified verifies that NewSigner does not zeroize the caller's slice.
func TestCallerSecretUnmodified(t *testing.T) {
	if err := bls.Init(); err != nil {
		t.Fatalf("Init() = %v", err)
	}

	original := bytes.Repeat([]byte{0x03}, 32)
	secret := make([]byte, 32)
	copy(secret, original)

	_, err := bls.NewSigner(secret)
	if err != nil {
		t.Fatalf("NewSigner() = %v", err)
	}

	if !bytes.Equal(secret, original) {
		t.Error("NewSigner modified the caller's secret slice, expected no modification")
	}
}

// TestPublicKeyLength verifies PublicKey returns exactly 48 bytes (non-zero).
func TestPublicKeyLength(t *testing.T) {
	if err := bls.Init(); err != nil {
		t.Fatalf("Init() = %v", err)
	}

	secret := bytes.Repeat([]byte{0x05}, 32)
	signer, err := bls.NewSigner(secret)
	if err != nil {
		t.Fatalf("NewSigner() = %v", err)
	}

	pub, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() = %v", err)
	}

	var zeroKey [48]byte
	if pub == zeroKey {
		t.Error("PublicKey() returned all-zero key, expected non-zero")
	}
}

// TestSignatureLength verifies Sign returns a 96-byte signature (non-zero).
func TestSignatureLength(t *testing.T) {
	if err := bls.Init(); err != nil {
		t.Fatalf("Init() = %v", err)
	}

	secret := bytes.Repeat([]byte{0x07}, 32)
	signer, err := bls.NewSigner(secret)
	if err != nil {
		t.Fatalf("NewSigner() = %v", err)
	}

	var root [32]byte
	root[0] = 0xff

	sig, err := signer.Sign(root)
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}

	var zeroSig [96]byte
	if sig == zeroSig {
		t.Error("Sign() returned all-zero signature, expected non-zero")
	}
}
