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
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort

	unsigned := localUnsigned()
	unsigned.Value = "0xgg"
	_, err := s.Sign(context.Background(), unsigned)
	if err == nil {
		t.Fatal("expected error for invalid Value hex")
	}
}

func TestLocalSigner_Sign_InvalidData(t *testing.T) {
	s := newLocalSigner(t)
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort

	unsigned := localUnsigned()
	unsigned.Data = "0xnotvalidhex"
	_, err := s.Sign(context.Background(), unsigned)
	if err == nil {
		t.Fatal("expected error for invalid Data hex")
	}
}

func TestLocalSigner_Sign_PreCancelledContext(t *testing.T) {
	s := newLocalSigner(t)
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort

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

// TestParseUnsignedTx_BadTo_NotHex: non-hex to (e.g. trailing g) → ErrInvalidToAddress (per AC).
func TestParseUnsignedTx_BadTo_NotHex(t *testing.T) {
	unsigned := localUnsigned()
	unsigned.To = "0x424242424242424242424242424242424242424g" // len=42 but invalid hex digit
	_, err := parseUnsignedTx(unsigned)
	if !errors.Is(err, ErrInvalidToAddress) {
		t.Fatalf("expected ErrInvalidToAddress for non-hex To, got %v", err)
	}
}

// TestParseUnsignedTx_BadTo_WrongLength: 41/43-char to → ErrInvalidToAddress (per AC; follows M0.4-1 len style).
func TestParseUnsignedTx_BadTo_WrongLength(t *testing.T) {
	base := localUnsigned()
	tests := []struct {
		name string
		to   string
	}{
		{"41char", "0x424242424242424242424242424242424242424"},   // drop last
		{"43char", "0x42424242424242424242424242424242424242422"}, // extra
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := base
			u.To = tt.to
			_, err := parseUnsignedTx(u)
			if !errors.Is(err, ErrInvalidToAddress) {
				t.Fatalf("expected ErrInvalidToAddress for wrong-len To %q, got %v", tt.to, err)
			}
		})
	}
}

// TestParseUnsignedTx_BadTo_NotDepositContract: valid 42-hex EIP-55-ish but wrong contract for chain → sentinel (per AC).
func TestParseUnsignedTx_BadTo_NotDepositContract(t *testing.T) {
	unsigned := localUnsigned()                                // chainID 17000 = holesky (0x42..)
	unsigned.To = "0x00000000219ab540356cBB839Cbe05303d7705Fa" // mainnet/hoodi contract (valid hex+len, IsHex true, but != holesky's)
	_, err := parseUnsignedTx(unsigned)
	if !errors.Is(err, ErrInvalidToAddress) {
		t.Fatalf("expected ErrInvalidToAddress for non-deposit To, got %v", err)
	}
}

// TestParseUnsignedTx_HappyPath exercises correct contract +42-hex still works (existing fixtures pass; AC).
func TestParseUnsignedTx_HappyPath(t *testing.T) {
	_, err := parseUnsignedTx(localUnsigned())
	if err != nil {
		t.Fatalf("happy path (correct 42-hex deposit contract for chain) failed: %v", err)
	}
}

// TestSign_ZeroizesIntermediates: after Sign returns, the byte slice `b` (instrumented via testSignDecodeBuffer) is zero (M1.1-5 AC).
func TestSign_ZeroizesIntermediates(t *testing.T) {
	s := newLocalSigner(t)
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort

	_, err := s.Sign(context.Background(), localUnsigned())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	for i, bb := range testSignDecodeBuffer {
		if bb != 0 {
			t.Errorf("b[%d] = 0x%02x after Sign return, want 0x00 (M1.1-5; instrumented decode buffer zeroized per-Sign)", i, bb)
		}
	}
}

// TestParseUnsignedTx_NegativeFields_Reject (M1.5-2 AC table-driven): value, maxFee, tip
// .Sign()<0 rejected with "field: negative: %w" ErrInvalidInput so Is works.
func TestParseUnsignedTx_NegativeFields_Reject(t *testing.T) {
	base := localUnsigned()
	tests := []struct {
		name string
		set  func(*internaltx.UnsignedTx)
	}{
		{"value", func(u *internaltx.UnsignedTx) { u.Value = "0x-1" }},
		{"maxFee", func(u *internaltx.UnsignedTx) { u.MaxFeePerGas = "0x-4a817c800" }},
		{"tip", func(u *internaltx.UnsignedTx) { u.MaxPriorityFeePerGas = "0x-3b9aca00" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := base
			tt.set(&u)
			_, err := parseUnsignedTx(u)
			if err == nil {
				t.Fatalf("expected error for %s negative field", tt.name)
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("expected errors.Is(ErrInvalidInput) for %s neg, got %v", tt.name, err)
			}
		})
	}
}

// TestParseUnsignedTx_LegacyTxType_Reject (M1.5-2 AC): Type:"0x0" yields ErrUnsupportedTxType.
func TestParseUnsignedTx_LegacyTxType_Reject(t *testing.T) {
	unsigned := localUnsigned()
	unsigned.Type = "0x0"
	_, err := parseUnsignedTx(unsigned)
	if !errors.Is(err, ErrUnsupportedTxType) {
		t.Fatalf("expected ErrUnsupportedTxType for Type 0x0, got %v", err)
	}
}
