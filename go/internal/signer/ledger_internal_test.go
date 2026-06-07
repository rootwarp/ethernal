package signer

// No t.Parallel() here — tests share the newLedgerHub global via withMockHub.

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"

	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

func internaltxUnsigned() internaltx.UnsignedTx {
	return internaltx.UnsignedTx{
		ChainID:              1,
		To:                   "0x00000000219ab540356cBB839Cbe05303d7705Fa", // mainnet deposit contract (42-hex, matches LookupByChainID(1))
		Value:                "0x1",
		MaxFeePerGas:         "0x3B9ACA00",
		MaxPriorityFeePerGas: "0x3B9ACA00",
		Gas:                  21000,
		Type:                 "0x2",
	}
}

// mockHub implements ledgerHub for tests.
type mockHub struct {
	wallets []ledgerWallet
}

func (m *mockHub) Wallets() []ledgerWallet { return m.wallets }

// mockWallet implements ledgerWallet for tests.
// Each method is a replaceable function field so tests can control behavior.
type mockWallet struct {
	URLFn    func() accounts.URL
	OpenFn   func(passphrase string) error
	CloseFn  func() error
	StatusFn func() (string, error)
	DeriveFn func(path accounts.DerivationPath, pin bool) (accounts.Account, error)
	SignTxFn func(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)
}

func (m *mockWallet) URL() accounts.URL {
	if m.URLFn != nil {
		return m.URLFn()
	}
	return accounts.URL{}
}
func (m *mockWallet) Open(p string) error {
	if m.OpenFn != nil {
		return m.OpenFn(p)
	}
	return nil
}
func (m *mockWallet) Close() error {
	if m.CloseFn != nil {
		return m.CloseFn()
	}
	return nil
}
func (m *mockWallet) Status() (string, error) {
	if m.StatusFn != nil {
		return m.StatusFn()
	}
	return "ok", nil
}
func (m *mockWallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	if m.DeriveFn != nil {
		return m.DeriveFn(path, pin)
	}
	return accounts.Account{}, nil
}
func (m *mockWallet) SignTx(acc accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if m.SignTxFn != nil {
		return m.SignTxFn(acc, tx, chainID)
	}
	return nil, errors.New("not implemented")
}

// withMockHub replaces newLedgerHub for the duration of a test.
func withMockHub(t *testing.T, hub ledgerHub) {
	t.Helper()
	orig := newLedgerHub
	newLedgerHub = func() (ledgerHub, error) { return hub, nil }
	t.Cleanup(func() { newLedgerHub = orig })
}

// synthSignedTx signs the given unsigned tx using a generated key and returns
// the signed tx plus the derived address. Used to produce a valid mock return value.
func synthSignedTx(t *testing.T, unsigned internaltx.UnsignedTx) (*types.Transaction, accounts.Account) {
	t.Helper()
	priv, err := gethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	addr := gethcrypto.PubkeyToAddress(priv.PublicKey)

	chainID := new(big.Int).SetUint64(unsigned.ChainID)
	value, _ := new(big.Int).SetString(strings.TrimPrefix(unsigned.Value, "0x"), 16)
	maxFee, _ := new(big.Int).SetString(strings.TrimPrefix(unsigned.MaxFeePerGas, "0x"), 16)
	maxPrio, _ := new(big.Int).SetString(strings.TrimPrefix(unsigned.MaxPriorityFeePerGas, "0x"), 16)

	var data []byte
	if dh := strings.TrimPrefix(unsigned.Data, "0x"); dh != "" {
		data, _ = hex.DecodeString(dh)
	}

	to := common.HexToAddress(unsigned.To)
	dynTx := &types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     unsigned.Nonce,
		GasTipCap: maxPrio,
		GasFeeCap: maxFee,
		Gas:       unsigned.Gas,
		To:        &to,
		Value:     value,
		Data:      data,
	}
	tx := types.NewTx(dynTx)
	signer := types.LatestSignerForChainID(chainID)
	signed, err := types.SignTx(tx, signer, priv)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}
	return signed, accounts.Account{Address: addr}
}

// --- Tests ---

func TestLedgerSigner_NoDevice(t *testing.T) {
	withMockHub(t, &mockHub{wallets: nil})

	_, err := NewLedgerSigner()
	if !errors.Is(err, ErrNoDevice) {
		t.Fatalf("expected ErrNoDevice, got %v", err)
	}
}

func TestLedgerSigner_AppNotOpen_FromOpen(t *testing.T) {
	w := &mockWallet{
		OpenFn: func(_ string) error { return errors.New("ledger: 6e00 app not open") },
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	_, err := NewLedgerSigner()
	if !errors.Is(err, ErrAppNotOpen) {
		t.Fatalf("expected ErrAppNotOpen, got %v", err)
	}
}

func TestLedgerSigner_AppNotOpen_FromStatus(t *testing.T) {
	w := &mockWallet{
		OpenFn:   func(_ string) error { return nil },
		StatusFn: func() (string, error) { return "", errors.New("ethereum app not open on device") },
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	_, err := NewLedgerSigner()
	if !errors.Is(err, ErrAppNotOpen) {
		t.Fatalf("expected ErrAppNotOpen, got %v", err)
	}
}

func TestLedgerSigner_StatusFailure_Generic(t *testing.T) {
	w := &mockWallet{
		OpenFn:   func(_ string) error { return nil },
		StatusFn: func() (string, error) { return "", errors.New("usb: device disconnected") },
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	_, err := NewLedgerSigner()
	if !errors.Is(err, ErrDeviceUnavailable) {
		t.Fatalf("expected ErrDeviceUnavailable (with real cause) for generic status error, got %v", err)
	}
}

func TestLedgerSigner_OpenFailure_Generic(t *testing.T) {
	w := &mockWallet{
		OpenFn: func(_ string) error { return errors.New("usb: device disconnected") },
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	_, err := NewLedgerSigner()
	if !errors.Is(err, ErrDeviceUnavailable) {
		t.Fatalf("expected ErrDeviceUnavailable (with real cause), got %v", err)
	}
}

// TestNewLedgerSigner_OpenFailed_DeviceUnavailable verifies the AC for M0.2-2:
// when Open fails (device was enumerated) with a non-app-not-open error, we
// return ErrDeviceUnavailable (not ErrNoDevice), the real cause from usbwallet
// is attached via %w (recoverable via errors.Is and unwrap logic), and per
// spec we call w.Close() on the Open failure branch (though this test does not
// assert the close count; see Status test).
func TestNewLedgerSigner_OpenFailed_DeviceUnavailable(t *testing.T) {
	openErr := errors.New("usb: device busy (held by Ledger Live or udev)")
	w := &mockWallet{
		OpenFn: func(_ string) error { return openErr },
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	_, err := NewLedgerSigner()
	if !errors.Is(err, ErrDeviceUnavailable) {
		t.Fatalf("expected ErrDeviceUnavailable, got %v", err)
	}
	// underlying cause is unwrappable (via errors.Is on the chain, which
	// walks Unwrap()error / Unwrap()[]error ; also call errors.Unwrap for the
	// AC phrasing).
	if !errors.Is(err, openErr) {
		t.Fatalf("underlying cause not recoverable via unwrap chain; err=%v", err)
	}
	if u := errors.Unwrap(err); u != nil {
		// for double-%w (wrapErrors) this is nil; Is above already verified attachment
		if !errors.Is(u, openErr) {
			// ignore for multi case
		}
	}
}

// TestNewLedgerSigner_StatusFailed_DeviceUnavailable verifies the AC:
// Status fails after successful Open -> ErrDeviceUnavailable with real cause;
// and that w.Close() *was* invoked (counted via mock CloseFn).
func TestNewLedgerSigner_StatusFailed_DeviceUnavailable(t *testing.T) {
	statusErr := errors.New("usb: status read failed, device present but unavailable")
	closeCalls := 0
	w := &mockWallet{
		OpenFn:   func(_ string) error { return nil },
		StatusFn: func() (string, error) { return "", statusErr },
		CloseFn:  func() error { closeCalls++; return nil },
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	_, err := NewLedgerSigner()
	if !errors.Is(err, ErrDeviceUnavailable) {
		t.Fatalf("expected ErrDeviceUnavailable, got %v", err)
	}
	if closeCalls != 1 {
		t.Fatalf("w.Close() was not invoked (or not exactly once); calls=%d", closeCalls)
	}
	// cause attached (via Is which uses unwrap)
	if !errors.Is(err, statusErr) {
		t.Fatalf("underlying status cause not attached; err=%v", err)
	}
}

func TestLedgerSigner_DiscoverySuccess(t *testing.T) {
	w := &mockWallet{}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Name() != "ledger" {
		t.Errorf("Name() = %q, want %q", s.Name(), "ledger")
	}
	if !s.RequiresUserInteraction() {
		t.Error("RequiresUserInteraction() = false, want true")
	}
	_ = s.Close()
}

func TestLedgerSigner_HubInitError(t *testing.T) {
	orig := newLedgerHub
	newLedgerHub = func() (ledgerHub, error) { return nil, errors.New("hub failed") }
	t.Cleanup(func() { newLedgerHub = orig })

	_, err := NewLedgerSigner()
	if err == nil {
		t.Fatal("expected error from hub init, got nil")
	}
}

func TestLedgerSigner_DeriveFailure(t *testing.T) {
	w := &mockWallet{
		DeriveFn: func(_ accounts.DerivationPath, _ bool) (accounts.Account, error) {
			return accounts.Account{}, errors.New("derive: device busy")
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	_, err := NewLedgerSigner()
	if err == nil {
		t.Fatal("expected error from Derive, got nil")
	}
}

func TestLedgerSigner_Close_Idempotent(t *testing.T) {
	closeCalls := 0
	w := &mockWallet{
		CloseFn: func() error { closeCalls++; return nil },
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Errorf("first Close() error: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close() error: %v", err)
	}
	if closeCalls != 1 {
		t.Errorf("wallet.Close called %d times, want 1", closeCalls)
	}
}

// --- Sign tests ---

func TestLedgerSigner_Sign_Success(t *testing.T) {
	unsigned := internaltxUnsigned()
	synth, acc := synthSignedTx(t, unsigned)

	w := &mockWallet{
		DeriveFn: func(_ accounts.DerivationPath, _ bool) (accounts.Account, error) {
			return acc, nil
		},
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			return synth, nil
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	result, err := s.Sign(context.Background(), unsigned)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if result.Unsigned.ChainID != unsigned.ChainID {
		t.Errorf("Unsigned.ChainID = %d, want %d", result.Unsigned.ChainID, unsigned.ChainID)
	}
	if !strings.HasPrefix(result.Hash, "0x") || result.Hash == "" {
		t.Errorf("Hash = %q, want 0x-prefixed non-empty", result.Hash)
	}
	if !strings.HasPrefix(result.RawRLP, "0x02") {
		t.Errorf("RawRLP = %q, want 0x02-prefixed (EIP-2718 type-2)", result.RawRLP[:min(10, len(result.RawRLP))])
	}
	if result.V != "0" && result.V != "1" {
		t.Errorf("V = %q, want decimal 0 or 1", result.V)
	}
	if result.R == "" {
		t.Error("R is empty")
	}
	if result.S == "" {
		t.Error("S is empty")
	}
	if !strings.HasPrefix(result.From, "0x") {
		t.Errorf("From = %q, want 0x-prefixed", result.From)
	}
}

func TestLedgerSigner_Sign_UserRejected(t *testing.T) {
	w := &mockWallet{
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			return nil, errors.New("user rejected the transaction")
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	_, err = s.Sign(context.Background(), internaltxUnsigned())
	if !errors.Is(err, ErrUserRejected) {
		t.Fatalf("expected ErrUserRejected, got %v", err)
	}
}

func TestLedgerSigner_Sign_UserRejected_APDU6985(t *testing.T) {
	w := &mockWallet{
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			return nil, errors.New("apdu error: 6985")
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	_, err = s.Sign(context.Background(), internaltxUnsigned())
	if !errors.Is(err, ErrUserRejected) {
		t.Fatalf("expected ErrUserRejected for APDU 6985, got %v", err)
	}
}

func TestLedgerSigner_Sign_ChainIDMismatch(t *testing.T) {
	w := &mockWallet{
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			return nil, errors.New("ledger: chain unknown or mismatch")
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	_, err = s.Sign(context.Background(), internaltxUnsigned())
	if !errors.Is(err, ErrChainIDMismatch) {
		t.Fatalf("expected ErrChainIDMismatch, got %v", err)
	}
}

func TestLedgerSigner_Sign_ChainIDMismatch_APDU6a80(t *testing.T) {
	w := &mockWallet{
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			return nil, errors.New("apdu error: 6a80 chain rejected")
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	_, err = s.Sign(context.Background(), internaltxUnsigned())
	if !errors.Is(err, ErrChainIDMismatch) {
		t.Fatalf("expected ErrChainIDMismatch for APDU 6a80, got %v", err)
	}
}

func TestLedgerSigner_Sign_GenericError(t *testing.T) {
	w := &mockWallet{
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			return nil, errors.New("usb: write timeout")
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	_, err = s.Sign(context.Background(), internaltxUnsigned())
	if err == nil {
		t.Fatal("expected non-nil error for generic SignTx failure")
	}
	if errors.Is(err, ErrUserRejected) || errors.Is(err, ErrChainIDMismatch) {
		t.Errorf("expected generic error, got sentinel: %v", err)
	}
}

func TestLedgerSigner_Sign_ChainID0_Rejected(t *testing.T) {
	w := &mockWallet{}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	unsigned := internaltxUnsigned()
	unsigned.ChainID = 0
	_, err = s.Sign(context.Background(), unsigned)
	if !errors.Is(err, ErrInvalidChainID) {
		t.Fatalf("expected ErrInvalidChainID for ChainID=0, got %v", err)
	}
}

func TestLedgerSigner_Sign_EmptyMaxFeePerGas(t *testing.T) {
	w := &mockWallet{}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	unsigned := internaltxUnsigned()
	unsigned.MaxFeePerGas = ""
	_, err = s.Sign(context.Background(), unsigned)
	if err == nil {
		t.Fatal("expected error for empty MaxFeePerGas")
	}
}

func TestLedgerSigner_Sign_EmptyMaxPriorityFeePerGas(t *testing.T) {
	w := &mockWallet{}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	unsigned := internaltxUnsigned()
	unsigned.MaxPriorityFeePerGas = ""
	_, err = s.Sign(context.Background(), unsigned)
	if err == nil {
		t.Fatal("expected error for empty MaxPriorityFeePerGas")
	}
}

func TestLedgerSigner_Sign_InvalidMaxFeeHex(t *testing.T) {
	w := &mockWallet{}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	unsigned := internaltxUnsigned()
	unsigned.MaxFeePerGas = "0xgg"
	_, err = s.Sign(context.Background(), unsigned)
	if err == nil {
		t.Fatal("expected error for invalid MaxFeePerGas hex")
	}
}

func TestLedgerSigner_Sign_PreCancelledContext(t *testing.T) {
	w := &mockWallet{}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = s.Sign(ctx, internaltxUnsigned())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestLedgerSigner_Sign_ContextCancelledMidSign(t *testing.T) {
	// readyCh signals that SignTxFn has started (goroutine is blocked).
	// blockCh blocks SignTxFn until test cleanup.
	readyCh := make(chan struct{})
	blockCh := make(chan struct{})
	t.Cleanup(func() { close(blockCh) })

	w := &mockWallet{
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			close(readyCh) // signal: goroutine is now blocked
			<-blockCh
			return nil, errors.New("cancelled by test cleanup")
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := s.Sign(ctx, internaltxUnsigned())
		errCh <- err
	}()

	// Wait for SignTxFn to be executing (goroutine is blocked on blockCh).
	<-readyCh
	cancel()

	signErr := <-errCh
	if !errors.Is(signErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", signErr)
	}
}

func TestLedgerSigner_Sign_Closed(t *testing.T) {
	w := &mockWallet{}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	_ = s.Close()

	_, err = s.Sign(context.Background(), internaltxUnsigned())
	if !errors.Is(err, ErrSignerClosed) {
		t.Fatalf("expected ErrSignerClosed, got %v", err)
	}
}

func TestLedgerSigner_Sign_UserRejected_Denied(t *testing.T) {
	w := &mockWallet{
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			return nil, errors.New("transaction denied by user")
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	_, err = s.Sign(context.Background(), internaltxUnsigned())
	if !errors.Is(err, ErrUserRejected) {
		t.Fatalf("expected ErrUserRejected for 'denied', got %v", err)
	}
}

// TestLedgerSigner_Sign_AmbiguousError_ChainCancelledByUser verifies that an error
// containing both "cancel" (user-rejection indicator) and "chain" is classified as
// ErrUserRejected. The isChainIDMismatchErr heuristic requires "unknown" or "mismatch"
// or "6a80"/"6a81" in addition to "chain", so "user cancelled chain operation" does
// NOT match the chain-ID heuristic — it falls through to the user-rejected check.
// This is documented behavior; TODO: refine after real hardware testing.
func TestLedgerSigner_Sign_AmbiguousError_ChainCancelledByUser(t *testing.T) {
	w := &mockWallet{
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			return nil, errors.New("user cancelled chain operation")
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	_, err = s.Sign(context.Background(), internaltxUnsigned())
	// "user cancelled chain operation" contains "chain" + "cancel" but NOT
	// "unknown"/"mismatch"/"6a80"/"6a81", so isChainIDMismatchErr returns false.
	// isUserRejectedErr matches "cancel" → ErrUserRejected.
	if !errors.Is(err, ErrUserRejected) {
		t.Fatalf("expected ErrUserRejected for ambiguous cancel+chain error, got %v", err)
	}
}

func TestLedgerSigner_Sign_ChainIDMismatch_APDU6a81(t *testing.T) {
	w := &mockWallet{
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			return nil, errors.New("apdu error: 6a81 chain not supported")
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	_, err = s.Sign(context.Background(), internaltxUnsigned())
	if !errors.Is(err, ErrChainIDMismatch) {
		t.Fatalf("expected ErrChainIDMismatch for APDU 6a81, got %v", err)
	}
}

// TestLedgerSigner_Sign_AppNotOpen_APDU6d00 verifies that APDU code 6d00
// in a SignTx error is treated as a generic ledger error (not a user rejection).
// The isAppNotOpenErr heuristic only applies at construction time (Open/Status);
// during Sign, 6d00 would be an unexpected app state, mapped to a generic error.
func TestLedgerSigner_Sign_UnknownAPDUCode_NotSentinel(t *testing.T) {
	w := &mockWallet{
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			return nil, errors.New("apdu error: 6f00 unknown error")
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	_, err = s.Sign(context.Background(), internaltxUnsigned())
	if err == nil {
		t.Fatal("expected non-nil error for unknown APDU code")
	}
	if errors.Is(err, ErrUserRejected) || errors.Is(err, ErrChainIDMismatch) {
		t.Errorf("unexpected sentinel for unknown APDU error: %v", err)
	}
}

func TestLedgerSigner_Sign_InvalidMaxPrioHex(t *testing.T) {
	w := &mockWallet{}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	unsigned := internaltxUnsigned()
	unsigned.MaxPriorityFeePerGas = "0xzz"
	_, err = s.Sign(context.Background(), unsigned)
	if err == nil {
		t.Fatal("expected error for invalid MaxPriorityFeePerGas hex")
	}
}

func TestLedgerSigner_Sign_InvalidData(t *testing.T) {
	w := &mockWallet{}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	unsigned := internaltxUnsigned()
	unsigned.Data = "0xnotvalidhex"
	_, err = s.Sign(context.Background(), unsigned)
	if err == nil {
		t.Fatal("expected error for invalid Data hex")
	}
}

func TestLedgerSigner_Sign_AppNotOpen_APDU6e01(t *testing.T) {
	w := &mockWallet{
		OpenFn: func(_ string) error { return errors.New("ledger: apdu 6e01 returned") },
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	_, err := NewLedgerSigner()
	if !errors.Is(err, ErrAppNotOpen) {
		t.Fatalf("expected ErrAppNotOpen for 6e01, got %v", err)
	}
}

func TestLedgerSigner_Sign_AppNotOpen_TextHint(t *testing.T) {
	w := &mockWallet{
		OpenFn: func(_ string) error { return errors.New("please open the ethereum app on your ledger") },
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	_, err := NewLedgerSigner()
	if !errors.Is(err, ErrAppNotOpen) {
		t.Fatalf("expected ErrAppNotOpen for text hint, got %v", err)
	}
}

func TestLedgerSigner_Sign_ConfirmationPrompt(t *testing.T) {
	unsigned := internaltxUnsigned()
	synth, acc := synthSignedTx(t, unsigned)

	w := &mockWallet{
		DeriveFn: func(_ accounts.DerivationPath, _ bool) (accounts.Account, error) {
			return acc, nil
		},
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			return synth, nil
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort

	var buf bytes.Buffer
	s.setConfirmationPrompt(&buf)

	_, err = s.Sign(context.Background(), unsigned)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	prompt := buf.String()
	if !strings.Contains(strings.ToLower(prompt), "ledger") && !strings.Contains(strings.ToLower(prompt), "confirm") {
		t.Errorf("confirmation prompt %q does not contain 'ledger' or 'confirm'", prompt)
	}
}

// --- M0.2-3 cross-check tests (sender + all fields) ---

func TestLedgerSigner_Sign_SenderMismatch(t *testing.T) {
	unsigned := internaltxUnsigned()
	// Derive will return goodAcc; SignTxFn returns tx recovered to a different addr.
	privGood, err := gethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey good: %v", err)
	}
	addrGood := gethcrypto.PubkeyToAddress(privGood.PublicKey)
	goodAcc := accounts.Account{Address: addrGood}

	badSynth, _ := synthSignedTx(t, unsigned) // different key inside synth

	w := &mockWallet{
		DeriveFn: func(_ accounts.DerivationPath, _ bool) (accounts.Account, error) {
			return goodAcc, nil
		},
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			return badSynth, nil
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	_, err = s.Sign(context.Background(), unsigned)
	if !errors.Is(err, ErrSenderMismatch) {
		t.Fatalf("expected ErrSenderMismatch, got %v", err)
	}
}

func TestLedgerSigner_Sign_FieldMismatch(t *testing.T) {
	unsigned := internaltxUnsigned()

	// Gen one good key; Derive returns its addr; all bad txs below are signed by it
	// so sender recovery matches (field mismatch is what triggers ErrSenderMismatch).
	privGood, err := gethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey good: %v", err)
	}
	addrGood := gethcrypto.PubkeyToAddress(privGood.PublicKey)
	goodAcc := accounts.Account{Address: addrGood}

	chainID := new(big.Int).SetUint64(unsigned.ChainID)
	value, _ := new(big.Int).SetString(strings.TrimPrefix(unsigned.Value, "0x"), 16)
	maxFee, _ := new(big.Int).SetString(strings.TrimPrefix(unsigned.MaxFeePerGas, "0x"), 16)
	maxPrio, _ := new(big.Int).SetString(strings.TrimPrefix(unsigned.MaxPriorityFeePerGas, "0x"), 16)
	var data []byte
	if dh := strings.TrimPrefix(unsigned.Data, "0x"); dh != "" {
		data, _ = hex.DecodeString(dh)
	}
	to := common.HexToAddress(unsigned.To)

	makeBad := func(t *testing.T, mod func(*types.DynamicFeeTx)) *types.Transaction {
		dyn := &types.DynamicFeeTx{
			ChainID:   new(big.Int).Set(chainID),
			Nonce:     unsigned.Nonce,
			GasTipCap: new(big.Int).Set(maxPrio),
			GasFeeCap: new(big.Int).Set(maxFee),
			Gas:       unsigned.Gas,
			To:        &to,
			Value:     new(big.Int).Set(value),
			Data:      append([]byte(nil), data...),
		}
		mod(dyn)
		tx := types.NewTx(dyn)
		signer := types.LatestSignerForChainID(dyn.ChainID) // use (possibly modded) chain for this bad tx
		signed, signErr := types.SignTx(tx, signer, privGood)
		if signErr != nil {
			t.Fatalf("SignTx for bad: %v", signErr)
		}
		return signed
	}

	cases := []struct {
		name string
		mod  func(*types.DynamicFeeTx)
	}{
		{"nonce", func(d *types.DynamicFeeTx) { d.Nonce++ }},
		{"to", func(d *types.DynamicFeeTx) {
			o := common.HexToAddress("0x000000000000000000000000000000000000beef")
			d.To = &o
		}},
		{"value", func(d *types.DynamicFeeTx) { d.Value = new(big.Int).Add(d.Value, big.NewInt(1)) }},
		{"chainID", func(d *types.DynamicFeeTx) { d.ChainID = new(big.Int).Add(d.ChainID, big.NewInt(1)) }},
		{"maxFee", func(d *types.DynamicFeeTx) { d.GasFeeCap = new(big.Int).Add(d.GasFeeCap, big.NewInt(1)) }},
		{"tip", func(d *types.DynamicFeeTx) { d.GasTipCap = new(big.Int).Add(d.GasTipCap, big.NewInt(1)) }},
		{"gasLimit", func(d *types.DynamicFeeTx) { d.Gas++ }},
		{"data", func(d *types.DynamicFeeTx) { d.Data = append(d.Data, 0x01) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			badTx := makeBad(t, tc.mod)
			w := &mockWallet{
				DeriveFn: func(_ accounts.DerivationPath, _ bool) (accounts.Account, error) {
					return goodAcc, nil
				},
				SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
					return badTx, nil
				},
			}
			withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

			s, nerr := NewLedgerSigner()
			if nerr != nil {
				t.Fatalf("NewLedgerSigner: %v", nerr)
			}
			defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
			s.setConfirmationPrompt(&bytes.Buffer{})

			_, serr := s.Sign(context.Background(), unsigned)
			if !errors.Is(serr, ErrSenderMismatch) {
				t.Fatalf("expected ErrSenderMismatch for field %s, got %v", tc.name, serr)
			}
		})
	}
}

func TestLedgerSigner_Sign_Success_CrossCheck(t *testing.T) {
	// Happy path: synth produces tx matching the requested fields + signed by the Derive acc.
	// After cross-check (sender + fields) this must return (*SignedTx, nil) i.e. no ErrSenderMismatch.
	unsigned := internaltxUnsigned()
	synth, acc := synthSignedTx(t, unsigned)

	w := &mockWallet{
		DeriveFn: func(_ accounts.DerivationPath, _ bool) (accounts.Account, error) {
			return acc, nil
		},
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			return synth, nil
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: signer close err (if any) irrelevant to test assertions; test teardown best-effort
	s.setConfirmationPrompt(&bytes.Buffer{})

	result, err := s.Sign(context.Background(), unsigned)
	if err != nil {
		t.Fatalf("Sign happy cross-check: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil SignedTx on happy-path matching fields/sender")
	}
}

// --- M1.1-4 AC tests (fake wallet; smallest exact per plan) ---

func TestLedgerSigner_CloseAfterCancel_StderrMessage(t *testing.T) {
	// Mirrors TestLedgerSigner_Sign_ContextCancelledMidSign pattern exactly
	// (readyCh + blockCh + go Sign + cancel + drain) but asserts the reject
	// message was emitted to the (captured) confirmationPrompt on the Close
	// after cancel path. Uses fake that hangs on SignTx so inFlight remains set.
	readyCh := make(chan struct{})
	blockCh := make(chan struct{})
	t.Cleanup(func() { close(blockCh) })

	w := &mockWallet{
		SignTxFn: func(_ accounts.Account, _ *types.Transaction, _ *big.Int) (*types.Transaction, error) {
			close(readyCh)
			<-blockCh
			return nil, errors.New("test cleanup")
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner()
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { _ = s.Close() }() // ignore: best-effort
	var buf bytes.Buffer
	s.setConfirmationPrompt(&buf)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, e := s.Sign(ctx, internaltxUnsigned())
		errCh <- e
	}()

	<-readyCh
	cancel()
	<-errCh // Sign returned Canceled; inFlight left true

	if cerr := s.Close(); cerr != nil {
		t.Errorf("Close after cancel: %v", cerr)
	}
	if !strings.Contains(buf.String(), "reject on device to unblock") {
		t.Errorf("captured stderr %q does not contain exact \"reject on device to unblock\"", buf.String())
	}
}

func TestLedgerSigner_CloseTimeout_WarningEmitted(t *testing.T) {
	// Fake wallet Close hangs forever; ctor option compresses 30s to ms;
	// injected logger (via setter, per existing set*ForTest pattern) captures
	// the WARN at LevelWarn; Close must return promptly without hanging.
	hangCh := make(chan struct{})
	w := &mockWallet{
		CloseFn: func() error {
			<-hangCh
			return nil
		},
	}
	withMockHub(t, &mockHub{wallets: []ledgerWallet{w}})

	s, err := NewLedgerSigner(withCloseTimeout(5 * time.Millisecond))
	if err != nil {
		t.Fatalf("NewLedgerSigner: %v", err)
	}
	defer func() { close(hangCh); _ = s.Close() }()

	var logBuf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	s.setLoggerForTest(lg)

	if cerr := s.Close(); cerr != nil {
		t.Errorf("Close under timeout returned err: %v", cerr)
	}
	logs := logBuf.String()
	if !strings.Contains(logs, "abandoning HID handle after timeout") || !strings.Contains(logs, "leaked") {
		t.Errorf("WARN not emitted (or wrong text) in captured logger: %q", logs)
	}
}
