package signer

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/core/types"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/rootwarp/eth-utils/go/internal/cli"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

const localSignerName = "local"

// LocalSigner signs EIP-1559 transactions using a raw secp256k1 private key
// held in memory. The key bytes are zeroized when Close is called.
//
// SECURITY: For development and CI only. Real-fund usage MUST use Ledger
// (Phase 3.3+). The key MUST come from a secure source (environment variable;
// see NewLocalSignerFromEnv). It MUST NEVER appear in argv or shell history.
type LocalSigner struct {
	mu     sync.Mutex // guards key and closed together (M1.1-3 / GO-021 / arch §9.3); write path under mu establishes "key non-nil iff !closed" invariant (ctor: non-nil + !closed; Close: zero then nil key then closed)
	key    []byte     // 32-byte secp256k1 scalar; zeroized on Close; niled under mu on transition to closed
	closed atomic.Bool
}

// NewLocalSignerFromHex constructs a LocalSigner from a hex-encoded 32-byte
// private key (with or without 0x prefix). Returns ErrInvalidKey for any
// length/format/curve failure — no key material appears in the error.
//
// Prefer NewLocalSignerFromEnv in CLI code so the key never appears in argv.
func NewLocalSignerFromHex(hexKey string) (*LocalSigner, error) {
	stripped := strings.TrimPrefix(hexKey, "0x")
	if len(stripped) != 64 {
		return nil, fmt.Errorf("expected 32-byte (64 hex char) private key: %w", ErrInvalidKey)
	}
	b, err := hex.DecodeString(stripped)
	if err != nil {
		return nil, fmt.Errorf("private key is not valid hex: %w", ErrInvalidKey)
	}
	// Validate as secp256k1 scalar (rejects zero, values >= curve order, etc.).
	if _, err := gethcrypto.ToECDSA(b); err != nil {
		for i := range b {
			b[i] = 0
		}
		return nil, fmt.Errorf("invalid secp256k1 private key: %w", ErrInvalidKey)
	}
	keyCopy := make([]byte, 32)
	copy(keyCopy, b)
	for i := range b {
		b[i] = 0
	}
	return &LocalSigner{key: keyCopy}, nil
}

// NewLocalSignerFromEnv reads a hex-encoded private key from the named
// environment variable and constructs a LocalSigner. The env var is unset
// via os.Unsetenv(envVar) right before every return (defense-in-depth per
// M1.1-5 / architecture §8.4 / FR-P1-B4 GO-017 secp side; callers need not
// remember). Rejection paths also unset so an attacker cannot read post-hoc.
//
// Only the variable NAME appears in errors; the value is never included.
func NewLocalSignerFromEnv(envVar string) (*LocalSigner, error) {
	value := os.Getenv(envVar)
	nameForErr := envVar
	if len(envVar) > 32 {
		nameForErr = cli.Redact(envVar, 4)
	}
	if value == "" {
		_ = os.Unsetenv(envVar)
		return nil, fmt.Errorf("environment variable %q is not set or empty: %w", nameForErr, ErrInvalidKey)
	}
	s, err := NewLocalSignerFromHex(value)
	if err != nil {
		_ = os.Unsetenv(envVar)
		return nil, fmt.Errorf("environment variable %q: %w", nameForErr, ErrInvalidKey)
	}
	_ = os.Unsetenv(envVar)
	return s, nil
}

// testSignDecodeBuffer holds the header to the per-Sign decode buffer `b`
// (after zeroing) for instrumentation in TestSign_ZeroizesIntermediates
// (M1.1-5 AC; "instrumented in test build" per plan). Same-package access
// from local_internal_test.go only.
var testSignDecodeBuffer []byte

// Sign produces a signed EIP-1559 transaction for the given unsigned tx.
// ctx is honored for cancellation; local signing is fast but the check
// ensures callers that pre-cancel don't get a spurious success.
func (s *LocalSigner) Sign(ctx context.Context, unsigned internaltx.UnsignedTx) (*SignedTx, error) {
	if s.closed.Load() {
		return nil, ErrSignerClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p, err := parseUnsignedTx(unsigned)
	if err != nil {
		return nil, err
	}

	dynTx := &types.DynamicFeeTx{
		ChainID:   p.chainID,
		Nonce:     unsigned.Nonce,
		GasTipCap: p.tip,
		GasFeeCap: p.maxFee,
		Gas:       unsigned.Gas,
		To:        &p.to,
		Value:     p.value,
		Data:      p.data,
	}
	tx := types.NewTx(dynTx)

	ethSigner := types.LatestSignerForChainID(p.chainID)

	// Guarded copy of key under mu; signing work (SignTx etc) off-lock per M1.1-3 / arch §9.3.
	// Per-Sign zeroize of decode buffer `b` + intermediates (M1.1-5).
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return nil, ErrSignerClosed
	}
	b := make([]byte, 32)
	copy(b, s.key)
	s.mu.Unlock()
	testSignDecodeBuffer = b
	defer func() {
		for i := range b {
			b[i] = 0
		}
	}()

	// FR-P1-B4 (GO-017 secp side): *ecdsa.PrivateKey.D (*big.Int) words cannot
	// be wiped via stdlib API (no Destroy/zeroize on big.Int limbs). We zero
	// the input decode buffer `b` (and Sign-local values) after use/on errs
	// via defer (honest framing per architecture §8.4 + M1.1-5 impl notes).
	priv, err := gethcrypto.ToECDSA(b)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signing key: %w", ErrInvalidKey)
	}

	signedTx, err := types.SignTx(tx, ethSigner, priv)
	if err != nil {
		return nil, fmt.Errorf("SignTx: %w", err)
	}

	v, r, sig := signedTx.RawSignatureValues()

	from, err := types.Sender(ethSigner, signedTx)
	if err != nil {
		return nil, fmt.Errorf("sender recovery failed: %w", err)
	}
	expectedAddr := gethcrypto.PubkeyToAddress(priv.PublicKey)
	if from != expectedAddr {
		return nil, fmt.Errorf("recovered sender %s does not match key address %s", from.Hex(), expectedAddr.Hex())
	}

	// MarshalBinary produces the EIP-2718 envelope: 0x02 || rlp(...)
	// which is what eth_sendRawTransaction expects for type-2 transactions.
	raw, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("MarshalBinary: %w", err)
	}

	return &SignedTx{
		Unsigned: unsigned,
		From:     from.Hex(),
		Hash:     signedTx.Hash().Hex(),
		R:        "0x" + r.Text(16),
		S:        "0x" + sig.Text(16),
		V:        v.Text(10), // decimal "0" or "1" for EIP-1559 y-parity
		RawRLP:   "0x" + hex.EncodeToString(raw),
	}, nil
}

func (s *LocalSigner) Name() string                  { return localSignerName }
func (s *LocalSigner) RequiresUserInteraction() bool { return false }

// Close zeroizes the in-memory key bytes. Subsequent Sign calls return
// ErrSignerClosed. Idempotent.
func (s *LocalSigner) Close() error {
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return nil
	}
	for i := range s.key {
		s.key[i] = 0
	}
	s.key = nil
	s.closed.Store(true)
	s.mu.Unlock()
	return nil
}

// Compile-time assertion.
var _ Signer = (*LocalSigner)(nil)
