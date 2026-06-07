// Package signer — Ledger hardware wallet signer.
//
// ledger_cgo.go (//go:build cgo) provides the real usbwallet transport via
// geth's accounts/usbwallet. The whole module requires CGO (transitively via
// herumi BLS), so there is no supported !cgo path.
//
// Coverage: ledger.go (orchestration) + ledger_internal_test.go (mock) achieve
// ≥80% for the package without exercising ledger_cgo.go (requires CGO).

package signer

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/types"

	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

const ledgerSignerName = "ledger"

// LedgerSigner signs transactions via a Ledger hardware wallet.
// The private key never leaves the device.
//
// Construct with NewLedgerSigner. Close must be called to release the HID handle.
type LedgerSigner struct {
	wallet             ledgerWallet
	account            accounts.Account
	closed             atomic.Bool
	confirmationPrompt io.Writer
	closeTimeout       time.Duration
	logger             *slog.Logger
	inFlight           atomic.Bool // remains true if a SignTx goroutine was started but not reaped (i.e. canceled path); Close uses this to emit the reject message and knows the SignTx goro will be leaked on timeout.
}

// NewLedgerSigner discovers the first connected Ledger, opens the Ethereum app,
// and derives the account at m/44'/60'/0'/0/0 (accounts.DefaultBaseDerivationPath).
//
// Returns ErrNoDevice if no Ledger is detected.
// Returns ErrAppNotOpen if a Ledger is found but the Ethereum app is not open.
func NewLedgerSigner(opts ...ledgerOption) (*LedgerSigner, error) {
	hub, err := newLedgerHub()
	if err != nil {
		return nil, fmt.Errorf("ledger hub init: %w", err)
	}

	wallets := hub.Wallets()
	if len(wallets) == 0 {
		return nil, ErrNoDevice
	}

	w := wallets[0]

	if err := w.Open(""); err != nil {
		if isAppNotOpenErr(err) {
			_ = w.Close()
			return nil, ErrAppNotOpen
		}
		_ = w.Close()
		return nil, fmt.Errorf("ledger init failed: %w: %w", ErrDeviceUnavailable, err)
	}

	// Check Status — Open can succeed even when the Ethereum app isn't active.
	_, statusErr := w.Status()
	if statusErr != nil {
		if isAppNotOpenErr(statusErr) {
			_ = w.Close()
			return nil, ErrAppNotOpen
		}
		_ = w.Close()
		return nil, fmt.Errorf("ledger status check failed: %w: %w", ErrDeviceUnavailable, statusErr)
	}

	acc, err := w.Derive(accounts.DefaultBaseDerivationPath, true)
	if err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("ledger derive failed: %w", err)
	}

	ls := &LedgerSigner{
		wallet:             w,
		account:            acc,
		confirmationPrompt: os.Stderr,
		closeTimeout:       30 * time.Second,
	}
	for _, o := range opts {
		o(ls)
	}
	return ls, nil
}

// setConfirmationPrompt sets the writer for "please confirm on device" messages.
// Used in tests to capture or silence the prompt.
func (s *LedgerSigner) setConfirmationPrompt(w io.Writer) {
	s.confirmationPrompt = w
}

// ledgerOption configures NewLedgerSigner (test-only for now; keeps call sites
// unchanged since variadic).
type ledgerOption func(*LedgerSigner)

// withCloseTimeout is the constructor option exposing configurable timeout
// (default 30s) for tests that must compress the Close timeout path.
func withCloseTimeout(d time.Duration) ledgerOption {
	return func(ls *LedgerSigner) { ls.closeTimeout = d }
}

// setLoggerForTest injects *slog.Logger used for the WARN on Close timeout.
// Mirrors setConfirmationPrompt pattern; used only in tests.
func (s *LedgerSigner) setLoggerForTest(l *slog.Logger) {
	s.logger = l
}

// isAppNotOpenErr returns true when err suggests the Ethereum app is not open.
// Matches known APDU error codes (6e00, 6e01) [CLA not supported]; 6d00 (INS not supported) is for some paths per current geth accounts/usbwallet/ledger + APDU spec. Textual hints require both "app" AND ("not open" OR "open the") to reduce false positives.
// TODO(3.6): replace with exact strings from real hardware test.
func isAppNotOpenErr(err error) bool {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "6e00") || strings.Contains(msg, "6e01") {
		return true
	}
	return strings.Contains(msg, "app") &&
		(strings.Contains(msg, "not open") || strings.Contains(msg, "open the"))
}

// isUserRejectedErr returns true when err indicates the user rejected signing on the device.
// Heuristic: checks for "rejected", "denied", "cancel", or APDU code "6985".
// TODO(3.6): refine after real hardware testing confirms exact error strings.
func isUserRejectedErr(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "rejected") ||
		strings.Contains(msg, "denied") ||
		strings.Contains(msg, "cancel") ||
		strings.Contains(msg, "6985")
}

// isChainIDMismatchErr returns true when err indicates the Ledger refused the chain ID.
// Heuristic: checks for "chain" combined with "unknown", "mismatch", "6a80", or "6a81".
// TODO(3.6): refine after real hardware testing confirms exact error strings.
func isChainIDMismatchErr(err error) bool {
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "chain") {
		return false
	}
	return strings.Contains(msg, "unknown") ||
		strings.Contains(msg, "mismatch") ||
		strings.Contains(msg, "6a80") ||
		strings.Contains(msg, "6a81")
}

// Sign produces a signed EIP-1559 transaction by sending the transaction to the
// Ledger device for user confirmation.
//
// Blocks on user confirmation on the device. Honors ctx for cancellation, but the
// device-side signing operation may still complete after ctx cancellation — the
// goroutine will drop the result. This is a known trade-off: Ledger APDU exchanges
// cannot be interrupted mid-flight; the goroutine leaks only until the user
// presses a button (or the device times out).
func (s *LedgerSigner) Sign(ctx context.Context, unsigned internaltx.UnsignedTx) (*SignedTx, error) {
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
	unsignedTx := types.NewTx(dynTx)

	_, _ = fmt.Fprintf(s.confirmationPrompt, "Please confirm the transaction on your Ledger device...\n") // ignore: best-effort prompt to the (test-injectable) confirmation writer

	type signResult struct {
		signed *types.Transaction
		err    error
	}
	ch := make(chan signResult, 1)
	go func() {
		signed, err := s.wallet.SignTx(s.account, unsignedTx, p.chainID)
		ch <- signResult{signed, err}
	}()
	s.inFlight.Store(true)

	var r signResult
	select {
	case <-ctx.Done():
		// leave inFlight=true: Close will see it, emit reject-to-unblock, and on timeout the SignTx goro is (documented) leaked
		return nil, ctx.Err()
	case r = <-ch:
		s.inFlight.Store(false)
	}

	if r.err != nil {
		// Check chain-ID mismatch before user-rejected: "6a80 chain rejected"
		// contains "rejected" but is a chain-ID error, not a user decision.
		if isChainIDMismatchErr(r.err) {
			return nil, fmt.Errorf("ledger rejected chain ID %d: %w", unsigned.ChainID, ErrChainIDMismatch)
		}
		if isUserRejectedErr(r.err) {
			return nil, fmt.Errorf("user rejected signing on ledger: %w", ErrUserRejected)
		}
		return nil, fmt.Errorf("ledger SignTx: %w", r.err)
	}

	signedTx := r.signed

	// Cross-check per M0.2-3 (GO-023), architecture §6.9/§15:
	// recover sender using the *returned* tx's ChainId() (not request p.chainID),
	// compare against s.account.Address; also field-compare all specified fields
	// on the parsed *types.Transaction (accessors, not raw RLP) vs the requested
	// unsignedTx we built. Any mismatch -> ErrSenderMismatch (exit 3).
	recovered, recErr := types.Sender(types.LatestSignerForChainID(signedTx.ChainId()), signedTx)
	if recErr != nil {
		return nil, fmt.Errorf("sender recovery failed: %w", recErr)
	}
	if recovered != s.account.Address {
		return nil, ErrSenderMismatch
	}
	// Field compares (nonce/to/value/data/chainID/maxFee/tip/gasLimit).
	if signedTx.Nonce() != unsignedTx.Nonce() ||
		signedTx.Gas() != unsignedTx.Gas() ||
		signedTx.GasFeeCap().Cmp(unsignedTx.GasFeeCap()) != 0 ||
		signedTx.GasTipCap().Cmp(unsignedTx.GasTipCap()) != 0 ||
		signedTx.Value().Cmp(unsignedTx.Value()) != 0 ||
		signedTx.ChainId().Cmp(unsignedTx.ChainId()) != 0 ||
		!bytes.Equal(signedTx.Data(), unsignedTx.Data()) {
		return nil, ErrSenderMismatch
	}
	reqTo, retTo := unsignedTx.To(), signedTx.To()
	if (reqTo == nil) != (retTo == nil) || (reqTo != nil && *reqTo != *retTo) {
		return nil, ErrSenderMismatch
	}

	ethSigner := types.LatestSignerForChainID(p.chainID)

	v, rVal, sVal := signedTx.RawSignatureValues()

	from, err := types.Sender(ethSigner, signedTx)
	if err != nil {
		return nil, fmt.Errorf("sender recovery failed: %w", err)
	}

	// MarshalBinary produces the EIP-2718 envelope: 0x02 || rlp(...)
	raw, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("MarshalBinary: %w", err)
	}

	return &SignedTx{
		Unsigned: unsigned,
		From:     from.Hex(),
		Hash:     signedTx.Hash().Hex(),
		R:        "0x" + rVal.Text(16),
		S:        "0x" + sVal.Text(16),
		V:        v.Text(10), // decimal "0" or "1" for EIP-1559 y-parity
		RawRLP:   "0x" + hex.EncodeToString(raw),
	}, nil
}

func (s *LedgerSigner) Name() string                  { return ledgerSignerName }
func (s *LedgerSigner) RequiresUserInteraction() bool { return true }

// Close releases the HID handle. Idempotent.
//
// When Close is reached via a canceled Sign (ctx.Err() != nil path that left
// a goroutine inside wallet.SignTx), Close first emits the exact message
// "reject on device to unblock" to the confirmation prompt (stderr in prod)
// so the operator knows to reject on the device and unblock the pending APDU.
// It then runs wallet.Close under a bounded timeout (default 30 s; overridable
// via constructor option for tests). On timeout it logs at WARN (via the
// injected *slog.Logger or fallback to stderr) and returns; the goroutine
// blocked in wallet.SignTx is leaked. The leak is unavoidable: geth's
// usbwallet cannot interrupt an in-flight APDU exchange (architecture §9.5,
// research/03 §1).
func (s *LedgerSigner) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	if s.inFlight.Load() {
		_, _ = fmt.Fprintf(s.confirmationPrompt, "reject on device to unblock\n")
	}

	to := s.closeTimeout
	if to <= 0 {
		to = 30 * time.Second
	}
	done := make(chan error, 1)
	go func() {
		done <- s.wallet.Close()
	}()
	timer := time.NewTimer(to)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		if s.logger != nil {
			s.logger.Warn("abandoning HID handle after timeout; goroutine waiting on wallet.SignTx is leaked (unavoidable per geth `wallet.SignTx` cannot be interrupted mid-APDU)", "timeout", to)
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "WARN: abandoning HID handle after timeout; goroutine waiting on wallet.SignTx is leaked (unavoidable per geth `wallet.SignTx` cannot be interrupted mid-APDU) (timeout=%s)\n", to)
		}
		return nil
	}
}

// Compile-time assertion.
var _ Signer = (*LedgerSigner)(nil)
