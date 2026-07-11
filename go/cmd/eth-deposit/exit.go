// Package main — exit code conventions for eth-deposit:
//
//	0 — success
//	2 — user / configuration errors (bad input, validation, unknown network,
//	    missing/malformed file, invalid hex, out-of-bounds --index, negative fees,
//	    build-side RPC chain-ID mismatch)
//	3 — signer / crypto errors (bad key, no Ledger device, Ethereum app not open,
//	    signer-side chain ID mismatch, signer closed)
//	4 — user abort (SIGINT / context.Canceled / Ledger device rejection)
//	5 — broadcast / RPC errors (dial failure, gas/nonce estimation failure,
//	    eth_sendRawTransaction error, broadcast-side chain ID mismatch between
//	    signed tx and RPC node)
//	1 — fallback for any other error
package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	ucli "github.com/urfave/cli/v3"

	"github.com/rootwarp/eth-utils/go/internal/deposit"
	"github.com/rootwarp/eth-utils/go/internal/keystore"
	"github.com/rootwarp/eth-utils/go/internal/signer"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// ErrInvalidInput is the sentinel for user / configuration errors (exit code 2).
// Wrap low-level errors with WrapInputErr so ExitCodeFor maps them correctly.
var ErrInvalidInput = errors.New("invalid input")

// ErrUserAborted is the sentinel for SIGINT/SIGTERM / context cancellation (exit code 4).
var ErrUserAborted = errors.New("user aborted")

// ExitCodeFor maps err to an exit code per the eth-deposit convention.
func ExitCodeFor(err error) int {
	if err == nil {
		return 0
	}
	// Exit code 4: context cancellation (SIGINT) or explicit abort.
	//
	// This check precedes the exit-5 RPC block deliberately. When a SIGINT
	// cancels an in-flight RPC estimation call, the resulting error wraps BOTH
	// context.Canceled and ErrRPCEstimation (builder.go's two-%w tagging). We
	// classify that as a user abort (4), not an RPC failure (5): the operator
	// chose to stop. A genuine connectivity failure that does not carry
	// context.Canceled falls through to the exit-5 block below and stays 5.
	if errors.Is(err, context.Canceled) || errors.Is(err, ErrUserAborted) {
		return 4
	}
	// Exit code 2: user / configuration errors (tx typed sentinel).
	if errors.Is(err, ErrInvalidInput) {
		return 2
	}
	// Exit code 2: build-side RPC configuration errors (tx).
	if errors.Is(err, internaltx.ErrChainIDMismatch) ||
		errors.Is(err, internaltx.ErrMissingFromForNonce) {
		return 2
	}
	// Exit code 2: user / configuration errors (gen).
	if errors.Is(err, keystore.ErrKeystoreMissing) ||
		errors.Is(err, keystore.ErrKeystoreMalformed) ||
		errors.Is(err, keystore.ErrKeystoreVersion) ||
		errors.Is(err, keystore.ErrEnvVarEmpty) ||
		errors.Is(err, keystore.ErrKeystoreNotFound) ||
		errors.Is(err, keystore.ErrNoTTY) ||
		errors.Is(err, deposit.ErrPubkeyMismatch) ||
		errors.Is(err, errMainnetAckRequired) ||
		errors.Is(err, ErrDepositCLINotFound) {
		return 2
	}
	// Exit code 2: urfave/cli validation errors that set code 2.
	var ec ucli.ExitCoder
	if errors.As(err, &ec) && ec.ExitCode() == 2 {
		return 2
	}
	// Exit code 4: user rejected signing on hardware device (tx).
	if errors.Is(err, signer.ErrUserRejected) {
		return 4
	}
	// Exit code 3: signer / crypto errors (tx).
	if errors.Is(err, signer.ErrSignerClosed) ||
		errors.Is(err, signer.ErrNoDevice) ||
		errors.Is(err, signer.ErrDeviceUnavailable) ||
		errors.Is(err, signer.ErrAppNotOpen) ||
		errors.Is(err, signer.ErrInvalidKey) ||
		errors.Is(err, signer.ErrInvalidChainID) ||
		errors.Is(err, signer.ErrChainIDMismatch) ||
		errors.Is(err, signer.ErrSenderMismatch) {
		return 3
	}
	// Exit code 3: crypto / signer errors and external verification failures (gen).
	if errors.Is(err, keystore.ErrWrongPassphrase) ||
		errors.Is(err, deposit.ErrSelfVerifyFailed) ||
		errors.Is(err, errBLSInit) ||
		errors.Is(err, ErrDepositCLIFailed) {
		return 3
	}
	// Exit code 5: broadcast / RPC errors (tx).
	if errors.Is(err, internaltx.ErrRPCDial) ||
		errors.Is(err, internaltx.ErrRPCEstimation) ||
		errors.Is(err, internaltx.ErrBroadcastFailed) ||
		errors.Is(err, internaltx.ErrBroadcastChainIDMismatch) ||
		errors.Is(err, internaltx.ErrReceiptReverted) ||
		errors.Is(err, internaltx.ErrReceiptTimeout) ||
		errors.Is(err, internaltx.ErrNoBaseFee) {
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
