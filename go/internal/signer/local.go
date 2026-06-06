package signer

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/core/types"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"

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
	key    []byte // 32-byte secp256k1 scalar; zeroized on Close
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
		return nil, fmt.Errorf("invalid secp256k1 private key: %w", ErrInvalidKey)
	}
	keyCopy := make([]byte, 32)
	copy(keyCopy, b)
	return &LocalSigner{key: keyCopy}, nil
}

// NewLocalSignerFromEnv reads a hex-encoded private key from the named
// environment variable and constructs a LocalSigner. The variable is NOT
// cleared by this constructor — callers should unsetenv it after construction.
//
// Only the variable NAME appears in errors; the value is never included.
func NewLocalSignerFromEnv(envVar string) (*LocalSigner, error) {
	value := os.Getenv(envVar)
	if value == "" {
		return nil, fmt.Errorf("environment variable %q is not set or empty: %w", envVar, ErrInvalidKey)
	}
	s, err := NewLocalSignerFromHex(value)
	if err != nil {
		return nil, fmt.Errorf("environment variable %q: %w", envVar, ErrInvalidKey)
	}
	return s, nil
}

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

	priv, err := gethcrypto.ToECDSA(s.key)
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
	if s.closed.Swap(true) {
		return nil
	}
	for i := range s.key {
		s.key[i] = 0
	}
	return nil
}

// Compile-time assertion.
var _ Signer = (*LocalSigner)(nil)
