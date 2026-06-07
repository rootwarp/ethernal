// Package bls is a thin, Ethereum-flavoured wrapper around
// github.com/herumi/bls-eth-go-binary. It owns the one-time process-global
// initialisation of the herumi library and exposes the Signer and Verifier
// interfaces used by the deposit pipeline.
//
// Zeroize on Signer (M1.1-6) wipes only the Go-side struct: s.sk = bls.SecretKey{}.
// Per ADR-006: no process exit leaves secret material in **Go-managed** memory
// but herumi's C-side `mcl` scalar persists until process exit. Honest framing
// per PRD §3.2 metric 12 and architecture §15 / §6.2 (see research/03 §4).
package bls

import (
	"errors"
	"fmt"
	"sync"

	bls "github.com/herumi/bls-eth-go-binary/bls"
)

var (
	initOnce sync.Once
	initErr  error
)

// ErrSecretZero is returned by NewSigner when the 32-byte secret is the
// all-zero scalar (after successful Deserialize). Per M1.2-1 / architecture §15 / GO-036.
var ErrSecretZero = errors.New("bls: secret key is zero")

// Init initialises the herumi BLS library for the BLS12-381 curve.
// The explicit SetETHmode(EthModeDraft07) call is redundant with what herumi's
// Init does internally (EthModeDraft07 == EthModeLatest == 3), but is kept for
// clarity and forward-safety. Calling Init more than once is a no-op; it always
// returns the result of the first call.
func Init() error {
	initOnce.Do(func() {
		if err := bls.Init(bls.BLS12_381); err != nil {
			initErr = fmt.Errorf("bls: herumi Init: %w", err)
			return
		}
		if err := bls.SetETHmode(bls.EthModeDraft07); err != nil {
			initErr = fmt.Errorf("bls: herumi SetETHmode: %w", err)
		}
	})
	return initErr
}

// Signer can sign a 32-byte signing root and expose the corresponding 48-byte
// compressed BLS public key. The underlying secret key is never accessible
// after construction.
type Signer interface {
	Sign(signingRoot [32]byte) (sig [96]byte, err error)
	PublicKey() (pub [48]byte, err error)
	Zeroize() // M1.1-6: Go-side only wipe per architecture §15 / §6.2
}

// Verifier can verify a BLS signature against a public key and signing root.
// It is stateless; a single instance may be used concurrently.
type Verifier interface {
	Verify(pub [48]byte, signingRoot [32]byte, sig [96]byte) (bool, error)
}

// signer is the unexported concrete implementation of Signer.
type signer struct {
	sk bls.SecretKey
}

// NewSigner constructs a Signer from a 32-byte BLS secret.
//
// secret must be the big-endian representation of the BLS12-381 scalar, as
// produced by EIP-2333 key derivation and stored in EIP-2335 keystores.
// The scalar must be less than the curve order r (EIP-2333 guarantees this).
//
// The caller retains ownership of the secret slice and is responsible for
// zeroizing it after this call returns. NewSigner makes an internal copy,
// loads it into herumi, and immediately zeroizes the local copy — but it
// never modifies the caller's slice.
//
// Returns an error if len(secret) != 32, the secret is the zero scalar
// (ErrSecretZero, per architecture §15 / M1.2-1), or herumi rejects the key material.
func NewSigner(secret []byte) (Signer, error) {
	if err := Init(); err != nil {
		return nil, fmt.Errorf("bls: not initialized: %w", err)
	}
	if len(secret) != 32 {
		return nil, fmt.Errorf("bls: secret must be 32 bytes, got %d", len(secret))
	}

	// Copy into a local buffer so we can zeroize it independently of the
	// caller's slice. The caller retains ownership of their original slice.
	localCopy := make([]byte, 32)
	copy(localCopy, secret)
	defer func() {
		for i := range localCopy {
			localCopy[i] = 0
		}
	}()

	s := &signer{}
	if err := s.sk.Deserialize(localCopy); err != nil {
		return nil, fmt.Errorf("bls: Deserialize failed")
	}
	if s.sk.IsZero() {
		return nil, ErrSecretZero
	}
	return s, nil
}

// Sign hashes msg via the ETH BLS ciphersuite and returns the 96-byte
// compressed G2 signature.
func (s *signer) Sign(signingRoot [32]byte) ([96]byte, error) {
	if s.sk.IsZero() {
		return [96]byte{}, errors.New("bls: signer zeroized (Go-side only)")
	}
	herSig := s.sk.SignByte(signingRoot[:])
	if herSig == nil {
		return [96]byte{}, errors.New("bls: SignByte returned nil")
	}
	raw := herSig.Serialize()
	if len(raw) != 96 {
		return [96]byte{}, fmt.Errorf("bls: unexpected signature length %d", len(raw))
	}
	var out [96]byte
	copy(out[:], raw)
	return out, nil
}

// PublicKey returns the compressed 48-byte G1 public key for this signer.
func (s *signer) PublicKey() ([48]byte, error) {
	if s.sk.IsZero() {
		return [48]byte{}, errors.New("bls: signer zeroized (Go-side only)")
	}
	pk := s.sk.GetPublicKey()
	if pk == nil {
		return [48]byte{}, errors.New("bls: GetPublicKey returned nil")
	}
	raw := pk.Serialize()
	if len(raw) != 48 {
		return [48]byte{}, fmt.Errorf("bls: unexpected pubkey length %d", len(raw))
	}
	var out [48]byte
	copy(out[:], raw)
	return out, nil
}

// Zeroize wipes the Go-side bls.SecretKey struct (per M1.1-6 / architecture §15).
// The C-side mcl scalar inside herumi persists until process exit (ADR-006;
// documented honestly per PRD §3.2 metric 12; see research/03 §4).
func (s *signer) Zeroize() {
	s.sk = bls.SecretKey{}
}

// verifier is the unexported concrete implementation of Verifier.
type verifier struct{}

// DefaultVerifier returns a stateless Verifier backed by herumi. Multiple
// calls always return an equivalent instance; the result is safe to share.
func DefaultVerifier() Verifier {
	return &verifier{}
}

// Verify deserializes pub and sig, then calls herumi's VerifyByte against
// signingRoot. Returns (false, nil) on a valid but non-matching signature;
// only returns a non-nil error when the key or signature bytes are malformed.
func (v *verifier) Verify(pub [48]byte, signingRoot [32]byte, sig [96]byte) (bool, error) {
	if err := Init(); err != nil {
		return false, fmt.Errorf("bls: not initialized: %w", err)
	}
	var hPub bls.PublicKey
	if err := hPub.Deserialize(pub[:]); err != nil {
		return false, fmt.Errorf("bls: deserialize pubkey: %w", err)
	}

	var hSig bls.Sign
	if err := hSig.Deserialize(sig[:]); err != nil {
		return false, fmt.Errorf("bls: deserialize signature: %w", err)
	}

	return hSig.VerifyByte(&hPub, signingRoot[:]), nil
}

// ErrPubkeyInvalid is returned by ValidatePubkeyBytes when the 48-byte
// compressed point is not a valid BLS12-381 G1 point (off-curve, bad encoding,
// etc.). Mirrors architecture §6.6 / §15; used by both deposit and tx layers
// (M0 enables the check; M1.2-2 will also reject identity via ErrPubkeyZero).
var ErrPubkeyInvalid = errors.New("bls: pubkey is not a valid G1 point")

// ValidatePubkeyBytes checks that b is a valid compressed BLS12-381 G1 point.
// Init must have been called (or will be called internally). Returns nil if valid.
func ValidatePubkeyBytes(pub [48]byte) error {
	if err := Init(); err != nil {
		return fmt.Errorf("bls: not initialized: %w", err)
	}
	var hPub bls.PublicKey
	if err := hPub.Deserialize(pub[:]); err != nil {
		return fmt.Errorf("%w: %v", ErrPubkeyInvalid, err)
	}
	return nil
}
