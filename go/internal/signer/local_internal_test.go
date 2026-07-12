package signer

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"

	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// localUnsigned returns a valid UnsignedTx for local signer tests.
func localUnsigned() internaltx.UnsignedTx {
	return internaltx.UnsignedTx{
		ChainID:              17000,
		To:                   "0x4242424242424242424242424242424242424242",
		Value:                "0x1bc16d674ec800000",
		MaxFeePerGas:         "0x4a817c800",
		MaxPriorityFeePerGas: "0x3b9aca00",
		Gas:                  250000,
		Type:                 "0x2",
	}
}

// newLocalSigner creates a LocalSigner with a fresh random key for tests.
func newLocalSigner(t *testing.T) *LocalSigner {
	t.Helper()
	priv, err := gethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := NewLocalSignerFromHex(hex.EncodeToString(gethcrypto.FromECDSA(priv)))
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	return s
}

func TestParseUnsignedTx_InvalidValue(t *testing.T) {
	unsigned := localUnsigned()
	unsigned.Value = "0xgg"
	_, err := parseUnsignedTx(unsigned)
	if err == nil {
		t.Fatal("expected error for invalid Value hex")
	}
}

func TestParseUnsignedTx_InvalidData(t *testing.T) {
	unsigned := localUnsigned()
	unsigned.Data = "0xnotvalidhex"
	_, err := parseUnsignedTx(unsigned)
	if err == nil {
		t.Fatal("expected error for invalid Data hex")
	}
}

func TestLocalSigner_Sign_InvalidValue(t *testing.T) {
	s := newLocalSigner(t)
	defer s.Close()

	unsigned := localUnsigned()
	unsigned.Value = "0xgg"
	_, err := s.Sign(context.Background(), unsigned)
	if err == nil {
		t.Fatal("expected error for invalid Value hex")
	}
}

func TestLocalSigner_Sign_InvalidData(t *testing.T) {
	s := newLocalSigner(t)
	defer s.Close()

	unsigned := localUnsigned()
	unsigned.Data = "0xnotvalidhex"
	_, err := s.Sign(context.Background(), unsigned)
	if err == nil {
		t.Fatal("expected error for invalid Data hex")
	}
}

func TestLocalSigner_Sign_PreCancelledContext(t *testing.T) {
	s := newLocalSigner(t)
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := s.Sign(ctx, localUnsigned())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestLocalSigner_Sign_Closed(t *testing.T) {
	s := newLocalSigner(t)
	_ = s.Close()

	_, err := s.Sign(context.Background(), localUnsigned())
	if !errors.Is(err, ErrSignerClosed) {
		t.Fatalf("expected ErrSignerClosed, got %v", err)
	}
}

func TestNewLocalSignerFromEnv_BadKeyValue(t *testing.T) {
	t.Setenv("TEST_ENV_BADKEY", "0xdeadbeefnotvalidhex")
	_, err := NewLocalSignerFromEnv("TEST_ENV_BADKEY")
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for bad key in env var, got %v", err)
	}
	// Error must mention the var name but not the key value.
	if !strings.Contains(err.Error(), "TEST_ENV_BADKEY") {
		t.Errorf("error should mention env var name: %v", err)
	}
}

func TestLocalSigner_Address_InvalidKey(t *testing.T) {
	// White-box: a signer holding a non-canonical (all-zero) scalar cannot
	// arise via the validating constructors, but Address must still surface
	// ErrInvalidKey rather than panic on the parse failure.
	s := &LocalSigner{key: make([]byte, 32)}
	if _, err := s.Address(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("want ErrInvalidKey for non-canonical key, got %v", err)
	}
}

func TestLocalSigner_Close_ZeroizesKey(t *testing.T) {
	priv, err := gethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyHex := hex.EncodeToString(gethcrypto.FromECDSA(priv))
	s, err := NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for i, b := range s.key {
		if b != 0 {
			t.Errorf("key[%d] = 0x%02x after Close, want 0x00", i, b)
		}
	}
}
