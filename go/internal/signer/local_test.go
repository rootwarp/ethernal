package signer_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/rootwarp/eth-utils/go/internal/signer"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// validHexKey generates a fresh valid private key hex string for tests.
func validHexKey(t *testing.T) (string, string) {
	t.Helper()
	priv, err := gethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyHex := hex.EncodeToString(gethcrypto.FromECDSA(priv))
	addrHex := gethcrypto.PubkeyToAddress(priv.PublicKey).Hex()
	return keyHex, addrHex
}

func holeskyUnsignedTx() internaltx.UnsignedTx {
	return internaltx.UnsignedTx{
		ChainID:              17000,
		To:                   "0x4242424242424242424242424242424242424242",
		Value:                "0x1BC16D674EC80000", // 2 ETH in wei
		Data:                 "0xabcd",
		Gas:                  21000,
		MaxFeePerGas:         "0x3B9ACA00", // 1 gwei
		MaxPriorityFeePerGas: "0x3B9ACA00", // 1 gwei
		Nonce:                0,
		Type:                 "0x2",
	}
}

func TestNewLocalSignerFromHex_Valid(t *testing.T) {
	keyHex, wantAddr := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort

	signed, err := s.Sign(context.Background(), holeskyUnsignedTx())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !strings.EqualFold(signed.From, wantAddr) {
		t.Errorf("From = %q, want %q", signed.From, wantAddr)
	}
}

func TestNewLocalSignerFromHex_ValidWithPrefix(t *testing.T) {
	keyHex, _ := validHexKey(t)
	_, err := signer.NewLocalSignerFromHex("0x" + keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex with 0x prefix: %v", err)
	}
}

func TestNewLocalSignerFromHex_InvalidLength(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"too_short", "ab"},
		{"63_hex_chars", "0x" + strings.Repeat("a", 63)},
		{"65_hex_chars", "0x" + strings.Repeat("a", 65)},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := signer.NewLocalSignerFromHex(tc.input)
			if !errors.Is(err, signer.ErrInvalidKey) {
				t.Errorf("want ErrInvalidKey, got %v", err)
			}
		})
	}
}

func TestNewLocalSignerFromHex_BadHex(t *testing.T) {
	badInput := "0x" + strings.Repeat("z", 64) // 'z' is not valid hex
	_, err := signer.NewLocalSignerFromHex(badInput)
	if !errors.Is(err, signer.ErrInvalidKey) {
		t.Errorf("want ErrInvalidKey for bad hex, got %v", err)
	}
}

func TestNewLocalSignerFromHex_ZeroScalar(t *testing.T) {
	zeroKey := strings.Repeat("0", 64)
	_, err := signer.NewLocalSignerFromHex(zeroKey)
	if !errors.Is(err, signer.ErrInvalidKey) {
		t.Errorf("want ErrInvalidKey for zero scalar, got %v", err)
	}
}

func TestNewLocalSignerFromHex_ErrorDoesNotIncludeKey(t *testing.T) {
	badInput := "0x" + strings.Repeat("f", 63) // wrong length, but memorable bytes
	_, err := signer.NewLocalSignerFromHex(badInput)
	if err == nil {
		t.Fatal("expected error")
	}
	// The error must not leak the input bytes.
	if strings.Contains(err.Error(), strings.Repeat("f", 63)) {
		t.Error("error message contains key material")
	}
}

func TestNewLocalSignerFromEnv_Set(t *testing.T) {
	keyHex, _ := validHexKey(t)
	t.Setenv("TEST_LOCAL_SIGNER_KEY", keyHex)
	s, err := signer.NewLocalSignerFromEnv("TEST_LOCAL_SIGNER_KEY")
	if err != nil {
		t.Fatalf("NewLocalSignerFromEnv: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort

	_, err = s.Sign(context.Background(), holeskyUnsignedTx())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
}

func TestNewLocalSignerFromEnv_Missing(t *testing.T) {
	t.Setenv("TEST_MISSING_KEY", "")
	_, err := signer.NewLocalSignerFromEnv("TEST_MISSING_KEY")
	if err == nil {
		t.Fatal("expected error for empty env var")
	}
	// Error must reference the var name but not contain key material.
	if !strings.Contains(err.Error(), "TEST_MISSING_KEY") {
		t.Errorf("error should mention env var name, got: %v", err)
	}
}

// TestNewLocalSignerFromEnv_UnsetsEnv: after construction, os.Getenv(envVar) == "" (M1.1-5 AC).
func TestNewLocalSignerFromEnv_UnsetsEnv(t *testing.T) {
	keyHex, _ := validHexKey(t)
	envVar := "TEST_LOCAL_SIGNER_UNSETS"
	t.Setenv(envVar, keyHex)
	s, err := signer.NewLocalSignerFromEnv(envVar)
	if err != nil {
		t.Fatalf("NewLocalSignerFromEnv: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort

	if got := os.Getenv(envVar); got != "" {
		t.Errorf("after construction, os.Getenv(%q) = %q, want empty (M1.1-5 AC TestNewLocalSignerFromEnv_UnsetsEnv)", envVar, got)
	}
}

// TestNewLocalSignerFromEnv_BadValue_StillUnsets: rejection path also unsets the env var (M1.1-5 AC).
func TestNewLocalSignerFromEnv_BadValue_StillUnsets(t *testing.T) {
	envVar := "TEST_LOCAL_SIGNER_BAD_UNSET"
	t.Setenv(envVar, "0xdeadbeefnotvalidhex") // triggers bad value in NewFromHex
	_, err := signer.NewLocalSignerFromEnv(envVar)
	if !errors.Is(err, signer.ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}
	if got := os.Getenv(envVar); got != "" {
		t.Errorf("rejection path must still unset so attacker can't read post-hoc: os.Getenv(%q)=%q, want empty (M1.1-5 AC)", envVar, got)
	}
}

func TestLocalSigner_Sign_RoundTrip(t *testing.T) {
	keyHex, _ := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort

	unsigned := holeskyUnsignedTx()
	signed, err := s.Sign(context.Background(), unsigned)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Decode the RawRLP back.
	rawHex := strings.TrimPrefix(signed.RawRLP, "0x")
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("hex.DecodeString RawRLP: %v", err)
	}

	// Verify the raw bytes decode without error via RoundTrip check.
	if len(raw) < 2 {
		t.Fatalf("RawRLP too short: %d bytes", len(raw))
	}
	// Type-2 transactions have 0x02 prefix byte.
	if raw[0] != 0x02 {
		t.Errorf("RawRLP[0] = 0x%02x, want 0x02 (EIP-2718 type-2)", raw[0])
	}

	// Basic field checks.
	if signed.Hash == "" || !strings.HasPrefix(signed.Hash, "0x") {
		t.Errorf("Hash = %q, want 0x-prefixed", signed.Hash)
	}
	if signed.R == "" || !strings.HasPrefix(signed.R, "0x") {
		t.Errorf("R = %q, want 0x-prefixed", signed.R)
	}
	if signed.S == "" || !strings.HasPrefix(signed.S, "0x") {
		t.Errorf("S = %q, want 0x-prefixed", signed.S)
	}
	if signed.V != "0" && signed.V != "1" {
		t.Errorf("V = %q, want decimal 0 or 1", signed.V)
	}
	if !strings.HasPrefix(signed.From, "0x") {
		t.Errorf("From = %q, want 0x-prefixed", signed.From)
	}
	if signed.Unsigned.ChainID != unsigned.ChainID {
		t.Errorf("Unsigned.ChainID = %d, want %d", signed.Unsigned.ChainID, unsigned.ChainID)
	}
}

func TestLocalSigner_Sign_SenderRecovery(t *testing.T) {
	priv, err := gethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyHex := hex.EncodeToString(gethcrypto.FromECDSA(priv))
	wantAddr := gethcrypto.PubkeyToAddress(priv.PublicKey).Hex()

	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort

	signed, err := s.Sign(context.Background(), holeskyUnsignedTx())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !strings.EqualFold(signed.From, wantAddr) {
		t.Errorf("From = %q, want %q", signed.From, wantAddr)
	}
}

func TestLocalSigner_Sign_ChainID17000(t *testing.T) {
	keyHex, _ := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort

	unsigned := holeskyUnsignedTx()
	signed, err := s.Sign(context.Background(), unsigned)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signed.Unsigned.ChainID != 17000 {
		t.Errorf("ChainID = %d, want 17000", signed.Unsigned.ChainID)
	}
}

func TestLocalSigner_Sign_Cancelled(t *testing.T) {
	keyHex, _ := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	_, err = s.Sign(ctx, holeskyUnsignedTx())
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled, got %v", err)
	}
}

func TestLocalSigner_Close_Idempotent(t *testing.T) {
	keyHex, _ := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestLocalSigner_Sign_AfterClose(t *testing.T) {
	keyHex, _ := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err = s.Sign(context.Background(), holeskyUnsignedTx())
	if !errors.Is(err, signer.ErrSignerClosed) {
		t.Errorf("want ErrSignerClosed, got %v", err)
	}
}

func TestLocalSigner_Name(t *testing.T) {
	keyHex, _ := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	if s.Name() != "local" {
		t.Errorf("Name() = %q, want %q", s.Name(), "local")
	}
}

func TestLocalSigner_RequiresUserInteraction(t *testing.T) {
	keyHex, _ := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	if s.RequiresUserInteraction() {
		t.Error("RequiresUserInteraction() = true, want false")
	}
}

func TestLocalSigner_Address_ReturnsKeyAddress(t *testing.T) {
	keyHex, wantAddr := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	defer s.Close()

	addr, err := s.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	if !strings.EqualFold(addr.Hex(), wantAddr) {
		t.Errorf("Address() = %q, want %q", addr.Hex(), wantAddr)
	}
}

func TestLocalSigner_Address_AfterClose(t *testing.T) {
	keyHex, _ := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := s.Address(); !errors.Is(err, signer.ErrSignerClosed) {
		t.Errorf("want ErrSignerClosed, got %v", err)
	}
}

// --- Must Fix 1: ChainID=0 rejection ---

func TestLocalSigner_Sign_ChainID0_Rejected(t *testing.T) {
	keyHex, _ := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	unsigned := holeskyUnsignedTx()
	unsigned.ChainID = 0
	_, err = s.Sign(context.Background(), unsigned)
	if !errors.Is(err, signer.ErrInvalidChainID) {
		t.Fatalf("want ErrInvalidChainID, got %v", err)
	}
}

// --- Must Fix 2: Empty/invalid gas field rejection ---

func TestLocalSigner_Sign_EmptyMaxFeePerGas_Rejected(t *testing.T) {
	keyHex, _ := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	unsigned := holeskyUnsignedTx()
	unsigned.MaxFeePerGas = ""
	_, err = s.Sign(context.Background(), unsigned)
	if err == nil {
		t.Fatal("expected error for empty MaxFeePerGas")
	}
}

func TestLocalSigner_Sign_EmptyMaxPriorityFeePerGas_Rejected(t *testing.T) {
	keyHex, _ := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	unsigned := holeskyUnsignedTx()
	unsigned.MaxPriorityFeePerGas = ""
	_, err = s.Sign(context.Background(), unsigned)
	if err == nil {
		t.Fatal("expected error for empty MaxPriorityFeePerGas")
	}
}

func TestLocalSigner_Sign_InvalidMaxFeeHex_Rejected(t *testing.T) {
	keyHex, _ := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	unsigned := holeskyUnsignedTx()
	unsigned.MaxFeePerGas = "0xgg"
	_, err = s.Sign(context.Background(), unsigned)
	if err == nil {
		t.Fatal("expected error for invalid MaxFeePerGas hex")
	}
}

func TestLocalSigner_Sign_InvalidMaxPriorityFeeHex_Rejected(t *testing.T) {
	keyHex, _ := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	unsigned := holeskyUnsignedTx()
	unsigned.MaxPriorityFeePerGas = "0xgg"
	_, err = s.Sign(context.Background(), unsigned)
	if err == nil {
		t.Fatal("expected error for invalid MaxPriorityFeePerGas hex")
	}
}

// TestLocalSigner_Sign_VariousChainIDs verifies signing works for mainnet and other chains.
func TestLocalSigner_Sign_VariousChainIDs(t *testing.T) {
	keyHex, _ := validHexKey(t)
	for _, chainID := range []uint64{1, 11155111, 17000} {
		t.Run(fmt.Sprintf("chainID_%d", chainID), func(t *testing.T) {
			s, err := signer.NewLocalSignerFromHex(keyHex)
			if err != nil {
				t.Fatalf("NewLocalSignerFromHex: %v", err)
			}
			defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort

			unsigned := holeskyUnsignedTx()
			unsigned.ChainID = chainID
			// Set To to the deposit contract for *this* chainID so the M0.6-1
			// cross-check in parseUnsignedTx passes (existing test updated for
			// the strict boundary; 5/goerli dropped as unsupported network).
			switch chainID {
			case 1:
				unsigned.To = "0x00000000219ab540356cBB839Cbe05303d7705Fa"
			case 11155111:
				unsigned.To = "0x7f02C3E3c98b133055B8B348B2Ac625669Ed295D"
			default:
				unsigned.To = "0x4242424242424242424242424242424242424242"
			}
			signed, err := s.Sign(context.Background(), unsigned)
			if err != nil {
				t.Fatalf("Sign chainID=%d: %v", chainID, err)
			}
			if signed.V != "0" && signed.V != "1" {
				t.Errorf("V = %q, want decimal 0 or 1", signed.V)
			}
		})
	}
}

// TestNewLocalSignerFromEnv_NoLeak for both Missing-var and Invalid-value paths (architecture §11.7).
// Bad cases use long key-like arg to exercise redaction; happy unchanged covered by prior tests; uses errors.Is.
func TestNewLocalSignerFromEnv_NoLeak(t *testing.T) {
	tests := []struct {
		name   string
		envVar string
		setVal string // if non-empty, setenv to this (for invalid-value path)
	}{
		{
			name:   "missing_var_keylike",
			envVar: "0x" + strings.Repeat("a", 64), // long, triggers redact in error; would have leaked before
		},
		{
			name:   "invalid_value_path",
			envVar: "TEST_NEW_NOLEAK_BAD",
			setVal: "not-a-64-hex-value",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setVal != "" {
				t.Setenv(tc.envVar, tc.setVal)
			}
			_, err := signer.NewLocalSignerFromEnv(tc.envVar)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, signer.ErrInvalidKey) {
				t.Errorf("want errors.Is(ErrInvalidKey), got %v", err)
			}
			errStr := err.Error()
			if len(tc.envVar) > 32 && strings.Contains(errStr, tc.envVar) {
				t.Errorf("envVar arg (or keylike) leaked into err: %s", errStr)
			}
			if tc.name == "missing_var_keylike" {
				if !strings.Contains(errStr, "… (len=") {
					t.Errorf("redacted marker missing from err for keylike: %s", errStr)
				}
			}
		})
	}
}

// TestLocalSigner_RaceSignClose exercises 100 concurrent Sign+Close pairs under the
// mutex (per M1.1-3 AC). Must be run with -race -count=100; asserts no data race and
// post-close returns ErrSignerClosed. Existing happy paths (e.g. TestLocalSigner_Sign_RoundTrip)
// remain green; TestLocalSigner_Sign_AfterClose (note name variant) covers the named AC.
func TestLocalSigner_RaceSignClose(t *testing.T) {
	keyHex, _ := validHexKey(t)
	s, err := signer.NewLocalSignerFromHex(keyHex)
	if err != nil {
		t.Fatalf("NewLocalSignerFromHex: %v", err)
	}
	// no defer Close here; we race it

	const pairs = 100
	var wg sync.WaitGroup
	for i := 0; i < pairs; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = s.Sign(context.Background(), holeskyUnsignedTx())
		}()
		go func() {
			defer wg.Done()
			_ = s.Close()
		}()
	}
	wg.Wait()

	// final state: closed
	_, err = s.Sign(context.Background(), holeskyUnsignedTx())
	if !errors.Is(err, signer.ErrSignerClosed) {
		t.Errorf("after race, want ErrSignerClosed, got %v", err)
	}
}
