package signer

import "errors"

var (
	// ErrUserRejected indicates the user rejected the signing request on a
	// hardware device. Exit code 3 (signer/crypto error) — but distinct
	// semantically from a true crypto failure.
	ErrUserRejected = errors.New("user rejected signing on device")

	// ErrNoDevice indicates no Ledger device was found.
	ErrNoDevice = errors.New("no Ledger device found")

	// ErrAppNotOpen indicates a Ledger is connected but the Ethereum app
	// is not open.
	ErrAppNotOpen = errors.New("ledger Ethereum app is not open")

	// ErrInvalidKey indicates the private key bytes are not a valid
	// secp256k1 scalar. Generic to keep key material out of error text.
	ErrInvalidKey = errors.New("invalid private key")

	// ErrChainIDMismatch indicates the signer cannot produce a signature
	// for the requested chain ID (e.g., Ledger refuses an unknown network).
	ErrChainIDMismatch = errors.New("chain ID mismatch")

	// ErrInvalidChainID indicates the unsigned transaction has chain ID 0 or
	// another value the signer cannot handle (distinct from ErrChainIDMismatch,
	// which is a mismatch between two otherwise-valid IDs).
	ErrInvalidChainID = errors.New("invalid chain ID")

	// ErrSignerClosed indicates Sign was called after Close.
	ErrSignerClosed = errors.New("signer is closed")

	// ErrLedgerNotSupported indicates the binary was built without CGO, so the
	// Ledger HID transport is unavailable. Rebuild with CGO_ENABLED=1.
	ErrLedgerNotSupported = errors.New("ledger support requires CGO_ENABLED=1; rebuild with cgo enabled")
)
