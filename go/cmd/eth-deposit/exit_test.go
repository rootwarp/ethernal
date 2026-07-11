package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	ucli "github.com/urfave/cli/v3"

	"github.com/rootwarp/eth-utils/go/internal/keystore"
	"github.com/rootwarp/eth-utils/go/internal/signer"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

func TestExitCodeFor(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},
		{"ErrInvalidInput direct", ErrInvalidInput, 2},
		{"ErrInvalidInput wrapped via WrapInputErr", WrapInputErr("--flag", errors.New("bad")), 2},
		{"ErrInvalidInput wrapped via fmt.Errorf %w", fmt.Errorf("wrap: %w", ErrInvalidInput), 2},
		{"context.Canceled", context.Canceled, 4},
		{"ErrUserAborted", ErrUserAborted, 4},
		{"ErrUserAborted wrapped", fmt.Errorf("outer: %w", ErrUserAborted), 4},
		{"ucli.Exit code 2", ucli.Exit("bad input", 2), 2},
		{"ucli.Exit code 1", ucli.Exit("other", 1), 1},
		{"unknown error", errors.New("some unexpected error"), 1},
		// Signer sentinel errors → exit 3.
		{"ErrSignerClosed direct", signer.ErrSignerClosed, 3},
		{"ErrNoDevice direct", signer.ErrNoDevice, 3},
		{"ErrAppNotOpen direct", signer.ErrAppNotOpen, 3},
		{"ErrInvalidKey direct", signer.ErrInvalidKey, 3},
		{"ErrInvalidChainID direct", signer.ErrInvalidChainID, 3},
		{"ErrChainIDMismatch direct", signer.ErrChainIDMismatch, 3},
		{"ErrSignerClosed wrapped", fmt.Errorf("sign: %w", signer.ErrSignerClosed), 3},
		// User rejection → exit 4.
		{"ErrUserRejected direct", signer.ErrUserRejected, 4},
		{"ErrUserRejected wrapped", fmt.Errorf("ledger: %w", signer.ErrUserRejected), 4},
		// Broadcast / RPC sentinel errors → exit 5.
		{"ErrRPCDial direct", internaltx.ErrRPCDial, 5},
		{"ErrBroadcastFailed direct", internaltx.ErrBroadcastFailed, 5},
		{"ErrBroadcastChainIDMismatch direct", internaltx.ErrBroadcastChainIDMismatch, 5},
		{"ErrBroadcastFailed wrapped", fmt.Errorf("rpc: %w", internaltx.ErrBroadcastFailed), 5},
		// P1-5: RPC gas/fee/nonce estimation-call failure → exit 5 (load-bearing;
		// buildUnsignedTx returns it unwrapped, so this ExitCodeFor mapping is the
		// only route off the exit-1 fallback). The wrapped case mirrors builder.go's
		// two-%w form (NOT WrapInputErr), i.e. the shape P2-2 will surface.
		//
		// NOTE: end-to-end exit-5 on the real CLI path activates with P2-2. Today
		// main.go blanket-wraps BuildUnsigned errors with WrapInputErr/ErrInvalidInput,
		// which short-circuits at the exit-2 branch above before this line can fire
		// (architecture §2.1 ordering hazard). P2-2's check-before-wrap fix removes
		// that short-circuit; these unit tests verify the mapping directly meanwhile.
		{"ErrRPCEstimation direct", internaltx.ErrRPCEstimation, 5},
		{"ErrRPCEstimation wrapped", fmt.Errorf("%w: SuggestGasTipCap: %w", internaltx.ErrRPCEstimation, errors.New("dial timeout")), 5},
		// P1-5: build-side RPC configuration errors → exit 2. Tested with the BARE
		// sentinel (NOT WrapInputErr, which would drag in ErrInvalidInput and match
		// the earlier exit-2 branch, leaving this block unexercised).
		{"ErrChainIDMismatch direct (tx build-side config)", internaltx.ErrChainIDMismatch, 2},
		{"ErrMissingFromForNonce direct", internaltx.ErrMissingFromForNonce, 2},
		// P1-5: no-TTY passphrase error → exit 2, direct and wrapped through the
		// keystore.go "passphrase source: %w" chain that carries it to ExitCodeFor.
		{"keystore.ErrNoTTY direct", keystore.ErrNoTTY, 2},
		{"keystore.ErrNoTTY wrapped (passphrase source)", fmt.Errorf("passphrase source: %w", keystore.ErrNoTTY), 2},
		// P1-5: hook-shaped required-flag usage error → exit 2 (regression guard for
		// the P1-4 OnUsageError hook; already handled by the existing ExitCoder branch).
		{"hook-shaped required-flag error", ucli.Exit("Required flag \"x\" not set", 2), 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExitCodeFor(tc.err)
			if got != tc.want {
				t.Errorf("ExitCodeFor(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

func TestWrapInputErr(t *testing.T) {
	inner := errors.New("bad hex value")
	wrapped := WrapInputErr("--max-fee-per-gas", inner)

	if !errors.Is(wrapped, ErrInvalidInput) {
		t.Error("wrapped error should satisfy errors.Is(ErrInvalidInput)")
	}
	if !errors.Is(wrapped, inner) {
		t.Error("wrapped error should satisfy errors.Is(inner)")
	}
	if ExitCodeFor(wrapped) != 2 {
		t.Errorf("ExitCodeFor(WrapInputErr(...)) = %d, want 2", ExitCodeFor(wrapped))
	}
}

// TestExitCodeFor_BuildUnsignedErrorPath verifies that a BuildUnsigned error
// wrapped via WrapInputErr routes to exit code 2 via the ErrInvalidInput
// sentinel branch (not the ucli.ExitCoder branch).
func TestExitCodeFor_BuildUnsignedErrorPath(t *testing.T) {
	err := WrapInputErr("build", internaltx.ErrMissingFeeStatic)
	if !errors.Is(err, ErrInvalidInput) {
		t.Error("WrapInputErr(build, ErrMissingFeeStatic) must satisfy errors.Is(ErrInvalidInput)")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("ExitCodeFor(WrapInputErr(build, ErrMissingFeeStatic)) = %d, want 2", got)
	}
}

// TestExitCodeFor_RequiredFlagsSubstring_Exit2 (M1.5-1 AC): a synthetic
// error string matching urfave/cli's errRequiredFlags format (which is
// unexported, not an ExitCoder, and would otherwise map to 1) is caught by
// the substring fallback and maps to exit 2. Both singular and plural forms.
func TestExitCodeFor_RequiredFlagsSubstring_Exit2(t *testing.T) {
	singular := fmt.Errorf(`Required flag "input-file" not set`)
	if got := ExitCodeFor(singular); got != 2 {
		t.Errorf("ExitCodeFor(singular required) = %d, want 2", got)
	}
	plural := fmt.Errorf(`Required flags "input-file, signer" not set`)
	if got := ExitCodeFor(plural); got != 2 {
		t.Errorf("ExitCodeFor(plural required) = %d, want 2", got)
	}
}
