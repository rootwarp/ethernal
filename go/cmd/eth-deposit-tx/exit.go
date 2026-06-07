// Package main — exit code conventions for eth-deposit-tx:
//
//	0 — success
//	2 — user / configuration errors (bad input, validation, unknown network,
//	    missing/malformed file, invalid hex, out-of-bounds --index, negative fees)
//	3 — signer / crypto errors (bad key, no Ledger device, Ethereum app not open,
//	    chain ID mismatch, signer closed)
//	4 — user abort (SIGINT / context.Canceled / Ledger device rejection)
//	5 — broadcast / RPC errors (dial failure, eth_sendRawTransaction error,
//	    chain ID mismatch between signed tx and RPC node)
//	1 — fallback for any other error
package main

import (
	"context"
	"errors"
	"fmt"

	ucli "github.com/urfave/cli/v2"

	"github.com/rootwarp/eth-utils/go/internal/signer"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// ErrInvalidInput is the sentinel for user / configuration errors (exit code 2).
// Wrap low-level errors with WrapInputErr so ExitCodeFor maps them correctly.
var ErrInvalidInput = errors.New("invalid input")

// ErrUserAborted is the sentinel for SIGINT / context cancellation (exit code 4).
var ErrUserAborted = errors.New("user aborted")

// ExitCodeFor maps err to an exit code per the eth-deposit-tx convention.
func ExitCodeFor(err error) int {
	if err == nil {
		return 0
	}
	// Exit code 4: context cancellation (SIGINT) or explicit abort.
	if errors.Is(err, context.Canceled) || errors.Is(err, ErrUserAborted) {
		return 4
	}
	// Exit code 2: user / configuration errors (typed sentinel).
	if errors.Is(err, ErrInvalidInput) {
		return 2
	}
	// Exit code 2: urfave/cli validation errors that set code 2.
	var ec ucli.ExitCoder
	if errors.As(err, &ec) && ec.ExitCode() == 2 {
		return 2
	}
	// Exit code 4: user rejected signing on hardware device.
	if errors.Is(err, signer.ErrUserRejected) {
		return 4
	}
	// Exit code 3: signer / crypto errors.
	if errors.Is(err, signer.ErrSignerClosed) ||
		errors.Is(err, signer.ErrNoDevice) ||
		errors.Is(err, signer.ErrDeviceUnavailable) ||
		errors.Is(err, signer.ErrAppNotOpen) ||
		errors.Is(err, signer.ErrInvalidKey) ||
		errors.Is(err, signer.ErrInvalidChainID) ||
		errors.Is(err, signer.ErrChainIDMismatch) ||
		errors.Is(err, signer.ErrLedgerNotSupported) ||
		errors.Is(err, signer.ErrSenderMismatch) {
		return 3
	}
	// Exit code 5: broadcast / RPC errors.
	if errors.Is(err, internaltx.ErrRPCDial) ||
		errors.Is(err, internaltx.ErrBroadcastFailed) ||
		errors.Is(err, internaltx.ErrBroadcastChainIDMismatch) {
		return 5
	}
	// Fallback.
	return 1
}

// WrapInputErr wraps a low-level error with ErrInvalidInput so ExitCodeFor
// routes it to exit code 2. Use for validation failures originating outside
// the urfave/cli flag-parsing layer.
func WrapInputErr(what string, err error) error {
	return fmt.Errorf("%s: %w: %w", what, ErrInvalidInput, err)
}
