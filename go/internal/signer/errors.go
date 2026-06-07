package signer

import "errors"

var (
	// ErrUserRejected indicates the user rejected the signing request on a
	// hardware device. Exit code 3 (signer/crypto error) — but distinct
	// semantically from a true crypto failure.
	ErrUserRejected = errors.New("user rejected signing on device")

	// ErrNoDevice indicates no Ledger device was found.
	ErrNoDevice = errors.New("no Ledger device found")

	// ErrDeviceUnavailable indicates a Ledger device was enumerated (wallets
	// list non-empty) but Open or Status failed for a reason other than the
	// Ethereum app not being open (e.g. USB error, permissions, device busy).
	// The real usbwallet error is wrapped with %w for cause recovery.
	ErrDeviceUnavailable = errors.New("ledger device present but unavailable")

	// ErrSenderMismatch indicates after Ledger signs and returns the tx,
	// either the sender recovered via types.Sender(types.LatestSignerForChainID(returned.ChainId()), returned)
	// does not equal s.account.Address, or any of the fields nonce/to/value/data/chainID/maxFee/tip/gasLimit
	// diverged from the requested tx (using types.Transaction accessors).
	// Exit code 3 per architecture §15.
	ErrSenderMismatch = errors.New("recovered sender does not match key/account address")

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

	// ErrInvalidToAddress indicates the To field in the unsigned transaction
	// failed strict validation in parseUnsignedTx: !common.IsHexAddress || len != 42,
	// or the address is not the deposit contract for unsigned.ChainID (via network.LookupByChainID).
	// Exit code 2 (input validation) per architecture §15 and M0.6-1.
	ErrInvalidToAddress = errors.New("to is not a valid 0x-prefixed 42-char address")

	// ErrInvalidInput indicates a user/configuration error such as a negative
	// numeric field inside an unsigned tx. Field-specific wrappers (e.g.
	// "value: negative: %w") allow callers to errors.Is the broad class.
	// Exit code 2 per M1.5-2 / FR-P1-F2.
	// NOTE (naming collision): dual with cmd/eth-deposit-tx.ErrInvalidInput (same string,
	// different pkgs); pre-existing after this addition (to enable exact %w style + export
	// for tests/contract without cycles). Full unification + ExitCodeFor Is(signer.Err*)
	// deferred to M1.5-9 per "smallest" scope. (See also ErrUnsupportedTxType below.)
	ErrInvalidInput = errors.New("invalid input")

	// ErrUnsupportedTxType indicates parseUnsignedTx saw Type != "0x2".
	// Exit code 2 (input validation) per architecture §15 and M1.5-2.
	ErrUnsupportedTxType = errors.New("unsupported tx type (expected 0x2)")
)
