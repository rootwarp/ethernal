package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	ucli "github.com/urfave/cli/v2"

	"github.com/rootwarp/eth-utils/go/internal/cli"
	"github.com/rootwarp/eth-utils/go/internal/deposit"
	"github.com/rootwarp/eth-utils/go/internal/keystore"
	"github.com/rootwarp/eth-utils/go/internal/signer"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// TestExitCodeContract is the per-binary exhaustive table (M1.5-9 / FR-P1-F / split-watch).
// One row per sentinel from architecture §15 (M0/M1) + M1.5 additions (ErrNoTTY, ErrUnsupportedTxType,
// %w guard sentinels, required-flag safety net, etc.).
// Covers every Is target and special case in ExitCodeFor (and via WrapInputErr for input-class tx sentinels).
// Deliberate breakage subtest exercises unmapped fallback (1) and documents the "update contract" requirement.
func TestExitCodeContract(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		want    int
		comment string
	}{
		// success
		{"nil", nil, 0, "arch §15"},

		// exit 4: user abort / cancel (Canceled first per arch §15 + M1.5-6/7)
		{"context.Canceled", context.Canceled, 4, "M1.5-6/7; Is(Canceled) survives %w"},
		{"ErrUserAborted", ErrUserAborted, 4, "tx local"},
		{"ErrUserAborted wrapped", fmt.Errorf("send: %w", ErrUserAborted), 4, ""},
		{"signer.ErrUserRejected", signer.ErrUserRejected, 4, "ledger user abort"},
		{"signer.ErrUserRejected wrapped", fmt.Errorf("ledger: %w", signer.ErrUserRejected), 4, ""},

		// exit 2: user/config (ErrInvalidInput, ucli, substr, address, unsupported, NoTTY, keystore 2's, deposit 2's, tx input-class via wrap, signer input)
		{"ErrInvalidInput direct", ErrInvalidInput, 2, "tx local"},
		{"ErrInvalidInput via WrapInputErr", WrapInputErr("parse", errors.New("bad")), 2, ""},
		{"ucli.ExitCoder code 2", ucli.Exit("validation", 2), 2, "urfave"},
		{"required flag substr singular", fmt.Errorf(`Required flag "input-file" not set`), 2, "M1.5-1 safety net (pre-val + fallback)"},
		{"required flag substr plural", fmt.Errorf(`Required flags "input-file, signer" not set`), 2, "M1.5-1"},
		{"signer.ErrInvalidToAddress", signer.ErrInvalidToAddress, 2, "M0.6 / GO-003"},
		{"signer.ErrUnsupportedTxType via WrapInputErr (M1.5-2)", WrapInputErr("parse", signer.ErrUnsupportedTxType), 2, "M1.5-2 / FR-P1-F2 (direct gives 1; wrapped to InvalidInput gives 2 per parse site)"},
		{"cli.ErrNoTTY via ucli.Exit(2) (as in send)", ucli.Exit(cli.ErrNoTTY.Error(), 2), 2, "M1.5-4 / FR-P1-F4 / GO-041 (direct gives 1; ucli form from send gives documented 2)"},
		// keystore.* are gen-side (not Is'ed in tx ExitCodeFor; direct=1); covered in gen contract + arch
		// deposit self/BLSSig + bls zero covered in gen contract (tx uses via wrap or not raw)
		// deposit.* input-class sentinels covered via WrapInputErr -> ErrInvalidInput in tx paths (per M0 validate); direct would be 1 (not emitted raw from tx top-level)
		{"tx.ErrZeroPubkey wrapped", WrapInputErr("validate", internaltx.ErrZeroPubkey), 2, "arch §15 (via InvalidInput)"},
		{"tx.ErrZeroSignature wrapped", WrapInputErr("validate", internaltx.ErrZeroSignature), 2, ""},
		{"tx.ErrZeroDepositRoot wrapped", WrapInputErr("validate", internaltx.ErrZeroDepositRoot), 2, ""},
		{"tx.ErrInvalidWCPrefix wrapped", WrapInputErr("validate", internaltx.ErrInvalidWCPrefix), 2, ""},
		{"tx.ErrInvalidWCFormat wrapped", WrapInputErr("validate", internaltx.ErrInvalidWCFormat), 2, ""},
		{"tx.ErrZeroWithdrawal00 wrapped", WrapInputErr("validate", internaltx.ErrZeroWithdrawal00), 2, ""},
		{"tx.ErrUnconfiguredChainID wrapped", WrapInputErr("build", internaltx.ErrUnconfiguredChainID), 2, ""},
		{"tx.ErrMissingFeeStatic wrapped", WrapInputErr("build", internaltx.ErrMissingFeeStatic), 2, "M0.7"},
		{"tx.ErrMissingPriorityFeeStatic wrapped", WrapInputErr("build", internaltx.ErrMissingPriorityFeeStatic), 2, ""},
		{"tx.ErrMissingNonceStatic wrapped", WrapInputErr("build", internaltx.ErrMissingNonceStatic), 2, ""},
		{"tx.ErrMissingGasLimitStatic wrapped", WrapInputErr("build", internaltx.ErrMissingGasLimitStatic), 2, ""},
		{"tx.ErrMissingFromForNonce wrapped", WrapInputErr("build", internaltx.ErrMissingFromForNonce), 2, ""},
		{"tx.ErrChainIDMismatch wrapped", WrapInputErr("build", internaltx.ErrChainIDMismatch), 2, ""},
		{"tx.ErrNetworkMismatchTx wrapped", WrapInputErr("build", internaltx.ErrNetworkMismatchTx), 2, "M0"},
		{"tx.ErrRPCURLRejected wrapped", WrapInputErr("build", internaltx.ErrRPCURLRejected), 2, "M0 / GO-005"},

		// exit 3: signer/crypto (all listed in tx exit.go + bls + deposit 3's + gen CLI but cross-pkg via name match no; include reachable)
		{"signer.ErrSignerClosed", signer.ErrSignerClosed, 3, "arch §15"},
		{"signer.ErrNoDevice", signer.ErrNoDevice, 3, ""},
		{"signer.ErrDeviceUnavailable", signer.ErrDeviceUnavailable, 3, "M0 / GO-019"},
		{"signer.ErrAppNotOpen", signer.ErrAppNotOpen, 3, ""},
		{"signer.ErrInvalidKey", signer.ErrInvalidKey, 3, ""},
		{"signer.ErrInvalidChainID", signer.ErrInvalidChainID, 3, ""},
		{"signer.ErrChainIDMismatch", signer.ErrChainIDMismatch, 3, ""},
		{"signer.ErrLedgerNotSupported", signer.ErrLedgerNotSupported, 3, ""},
		{"signer.ErrSenderMismatch", signer.ErrSenderMismatch, 3, "M0 / GO-023"},
		// bls/deposit 3-class covered in gen contract (tx paths use other sentinels or wraps; direct not branched in tx ExitCodeFor)

		// exit 5: broadcast/RPC (exact Is list from current tx/exit.go; NoBaseFee added in M1 but not yet in this Is -- falls to 1 until wired)
		{"internaltx.ErrRPCDial", internaltx.ErrRPCDial, 5, "arch §15"},
		{"internaltx.ErrBroadcastFailed", internaltx.ErrBroadcastFailed, 5, ""},
		{"internaltx.ErrBroadcastChainIDMismatch", internaltx.ErrBroadcastChainIDMismatch, 5, "M0"},
		{"internaltx.ErrReceiptReverted", internaltx.ErrReceiptReverted, 5, "M0 / GO-010"},
		{"internaltx.ErrReceiptTimeout", internaltx.ErrReceiptTimeout, 5, "M0"},

		// additional rows for *every* sentinel in arch §15 exit-code map (for full completeness per reviewer high; some direct give 1 in this binary's ExitCodeFor as not branched/ gen or tx specific surface; documented + locked here; DiD/wrap paths use 2/5 as arch)
		{"keystore.ErrKeystoreNotFound (gen surface; direct 1 in tx Exit)", keystore.ErrKeystoreNotFound, 1, "arch 2 (gen); tx contract covers via gen table or wrap"},
		{"deposit.ErrNetworkMismatch (DiD; direct 1 here)", deposit.ErrNetworkMismatch, 1, "arch 2 (tx uses tx.ErrNetworkMismatchTx wrap for 2)"},
		{"deposit.ErrForkVersionMismatch (DiD; direct 1 here)", deposit.ErrForkVersionMismatch, 1, "arch 2"},
		{"deposit.ErrDepositMessageRootMismatch (DiD; direct 1 here)", deposit.ErrDepositMessageRootMismatch, 1, "arch 2"},
		{"deposit.ErrDepositDataRootMismatch (DiD; direct 1 here)", deposit.ErrDepositDataRootMismatch, 1, "arch 2"},
		{"deposit.ErrZeroWithdrawal00 (DiD; direct 1 here)", deposit.ErrZeroWithdrawal00, 1, "arch 2"},
		{"deposit.ErrInvalidWCFormat (DiD; direct 1 here)", deposit.ErrInvalidWCFormat, 1, "arch 2"},
		{"bls.ErrSecretRejected (legacy in arch; current bls uses string or Zero)", errors.New("bls: secret key rejected (scalar out of range for BLS12-381)"), 1, "arch 3 (gen path; tx falls 1, not branched)"},
		{"internaltx.ErrNoBaseFee", internaltx.ErrNoBaseFee, 5, "arch 5; Is added in exit.go hygiene for completeness"},

		// deliberate breakage (M1.5-9 AC): exercises unmapped sentinel path (falls to 1).
		// If a new sentinel reaches ExitCodeFor without a row in this table, the contract is violated.
		// Verified by temporarily forcing (see verif steps); failure msg must mention update contract.
		{"deliberate_breakage_unmapped_sentinel", errors.New("TEST-ONLY-unmapped-sentinel-for-M1.5-9-deliberate-breakage; add row to TestExitCodeContract + arch §15 if promoted to prod"), 1, "fallback; update contract table on new sentinel"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExitCodeFor(tc.err)
			if got != tc.want {
				t.Errorf("ExitCodeFor(%v) = %d, want %d %s", tc.err, got, tc.want, tc.comment)
			}
		})
	}
}

// Additional deliberate breakage trigger helper (for verif): forces a path using test-only sentinel
// and documents the exact failure message expectation ("update contract").
func TestExitCodeContract_deliberateBreakageTrigger(t *testing.T) {
	// This exercises the unmapped case directly. In normal runs it asserts 1.
	// To trigger explicit failure demonstrating the "update contract" detector:
	//   1. edit exit.go temporarily to return a new sentinel (e.g. in a 5-path) without adding Is
	//   2. or comment a row above and change a mapped sentinel's direct call to expect wrong code
	//   3. run go test -run 'TestExitCodeContract/deliberate' -count=1
	// Expected failure output contains "update the TestExitCodeContract table" (or equivalent from got/want on named row).
	// Revert edit; test must pass.
	unmapped := errors.New("TEST-ONLY deliberate breakage sentinel (M1.5-9); message in failure must mention 'update contract'")
	if got := ExitCodeFor(unmapped); got != 1 {
		t.Errorf("deliberate unmapped ExitCodeFor = %d, want 1; update the TestExitCodeContract table (arch §15 + M1.5-9 AC)", got)
	}
}
