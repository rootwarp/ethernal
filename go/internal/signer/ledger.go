// Package signer — Ledger hardware wallet signer.
//
// Build-tag isolation: this file has no build tag and compiles everywhere.
// ledger_cgo.go (//go:build cgo) provides the real usbwallet transport.
// ledger_nocgo.go (//go:build !cgo) provides a stub returning ErrLedgerNotSupported.
//
// Note: the repo already requires CGO transitively via herumi/bls-eth-go-binary,
// so CGO_ENABLED=0 go build ./... does not succeed for the module as a whole.
// The non-CGO stub is retained for hygiene and to let callers that guard Ledger
// usage behind a flag compile without the HID transport.
//
// Coverage: ledger.go (orchestration) + ledger_internal_test.go (mock) achieve
// ≥80% for the package without exercising ledger_cgo.go (requires CGO) or
// ledger_nocgo.go (excluded when CGO is on).

package signer

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"

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
	wallet              ledgerWallet
	account             accounts.Account
	closed              atomic.Bool
	confirmationPrompt  io.Writer
}

// NewLedgerSigner discovers the first connected Ledger, opens the Ethereum app,
// and derives the account at m/44'/60'/0'/0/0 (accounts.DefaultBaseDerivationPath).
//
// Returns ErrLedgerNotSupported if the binary was built without CGO.
// Returns ErrNoDevice if no Ledger is detected.
// Returns ErrAppNotOpen if a Ledger is found but the Ethereum app is not open.
func NewLedgerSigner() (*LedgerSigner, error) {
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
			return nil, ErrAppNotOpen
		}
		return nil, fmt.Errorf("ledger init failed: %w", ErrNoDevice)
	}

	// Check Status — Open can succeed even when the Ethereum app isn't active.
	_, statusErr := w.Status()
	if statusErr != nil {
		if isAppNotOpenErr(statusErr) {
			_ = w.Close()
			return nil, ErrAppNotOpen
		}
		_ = w.Close()
		return nil, fmt.Errorf("ledger status check failed: %w", ErrNoDevice)
	}

	acc, err := w.Derive(accounts.DefaultBaseDerivationPath, true)
	if err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("ledger derive failed: %w", err)
	}

	return &LedgerSigner{wallet: w, account: acc, confirmationPrompt: os.Stderr}, nil
}

// setConfirmationPrompt sets the writer for "please confirm on device" messages.
// Used in tests to capture or silence the prompt.
func (s *LedgerSigner) setConfirmationPrompt(w io.Writer) {
	s.confirmationPrompt = w
}

// isAppNotOpenErr returns true when err suggests the Ethereum app is not open.
// Matches known APDU error codes (6e00, 6e01, 6d00) and textual hints.
// The textual heuristic requires both "app" AND ("not open" OR "open the") to
// reduce false positives (e.g. "snapshot not found in app" no longer matches).
// TODO(3.6): replace with exact strings from real hardware test.
func isAppNotOpenErr(err error) bool {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "6e00") || strings.Contains(msg, "6e01") || strings.Contains(msg, "6d00") {
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

	fmt.Fprintf(s.confirmationPrompt, "Please confirm the transaction on your Ledger device...\n")

	type signResult struct {
		signed *types.Transaction
		err    error
	}
	ch := make(chan signResult, 1)
	go func() {
		signed, err := s.wallet.SignTx(s.account, unsignedTx, p.chainID)
		ch <- signResult{signed, err}
	}()

	var r signResult
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r = <-ch:
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
func (s *LedgerSigner) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	return s.wallet.Close()
}

// Compile-time assertion.
var _ Signer = (*LedgerSigner)(nil)
