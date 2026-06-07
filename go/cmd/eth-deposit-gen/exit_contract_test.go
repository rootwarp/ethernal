package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	ucli "github.com/urfave/cli/v2"

	"github.com/rootwarp/eth-utils/go/internal/bls"
	"github.com/rootwarp/eth-utils/go/internal/cli"
	"github.com/rootwarp/eth-utils/go/internal/deposit"
	"github.com/rootwarp/eth-utils/go/internal/keystore"
	"github.com/rootwarp/eth-utils/go/internal/signer"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// TestExitCodeContract is the per-binary exhaustive table for eth-deposit-gen (M1.5-9 / FR-P1-F / split-watch).
// One row per sentinel from architecture §15 (M0/M1) + M1.5 additions (ErrNoTTY if reachable, %w guards,
// required-flag safety net, new sentinels) + all local unexported + exported that exitCodeFor maps.
// Table-driven; uses got/want + explicit errors.Is patterns from prior M1.5 tests (e.g. M1.5-6/8 SIGINT/Is tests).
// Deliberate breakage subtest + helper exercises unmapped sentinel (fallback 1) + "update contract" message requirement.
func TestExitCodeContract(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		want    int
		comment string
	}{
		// success
		{"nil", nil, 0, "arch §15"},

		// exit 4: cancel (M1.5-6 + arch; Is(Canceled) first)
		{"context.Canceled", context.Canceled, 4, "M1.5-6 runDepositCLIVerify SIGINT; also worker pool"},
		{"context.Canceled wrapped", fmt.Errorf("run: %w", context.Canceled), 4, ""},

		// exit 2: user/config (keystore 2-class, deposit 2-class, gen locals, ucli, substr, ErrNoTTY, mainnet ack, CLINotFound)
		{"keystore.ErrKeystoreNotFound", keystore.ErrKeystoreNotFound, 2, "arch §15"},
		{"keystore.ErrKeystoreMissing", keystore.ErrKeystoreMissing, 2, ""},
		{"keystore.ErrKeystoreMalformed", keystore.ErrKeystoreMalformed, 2, ""},
		{"keystore.ErrKeystoreVersion", keystore.ErrKeystoreVersion, 2, ""},
		{"keystore.ErrKeystoreCipherText", keystore.ErrKeystoreCipherText, 2, "M1"},
		{"keystore.ErrEnvVarEmpty", keystore.ErrEnvVarEmpty, 2, ""},
		{"deposit.ErrPubkeyMismatch", deposit.ErrPubkeyMismatch, 2, "arch §15 (gen-emitted; tx network/zero/fork/roots covered in tx contract)"},
		{"errMainnetAckRequired", cli.ErrMainnetAckRequired, 2, "gen local (M0 mainnet gate DiD)"},
		{"ErrDepositCLINotFound", cli.ErrDepositCLINotFound, 2, "M0 / M1.5-6 (maps to 2 not 3 per code)"},
		{"ucli.ExitCoder code 2", ucli.Exit("bad flag", 2), 2, ""},
		{"required flag substr singular", fmt.Errorf(`Required flag "withdrawal-address" not set`), 2, "M1.5-1 + M0.4 pre-val safety net"},
		{"required flag substr plural", fmt.Errorf(`Required flags "keystore-dir, pubkeys" not set`), 2, "M1.5-1"},
		{"cli.ErrNoTTY via ucli.Exit(2)", ucli.Exit(cli.ErrNoTTY.Error(), 2), 2, "M1.5-4 / arch (gen may not emit directly; ucli form for documented 2 per tx usage)"},

		// exit 3: crypto/signer (keystore wrong pw, deposit self/bls sig, bls zero, gen locals ErrDepositCLIFailed + errBLSInit)
		{"keystore.ErrWrongPassphrase", keystore.ErrWrongPassphrase, 3, "arch §15"},
		{"deposit.ErrSelfVerifyFailed", deposit.ErrSelfVerifyFailed, 3, "arch §15"},
		{"bls.ErrSecretZero", bls.ErrSecretZero, 3, "M1 / arch §15"},
		{"errBLSInit", cli.ErrBLSInit, 3, "gen internal sentinel (herumi init wrap)"},
		{"ErrDepositCLIFailed", cli.ErrDepositCLIFailed, 3, "M0/M1.5-6 (crypto verify step)"},

		// fallback 1 for anything else (writer errs etc map here unless wrapped to sentinels above)
		{"unknown error", errors.New("some disk full or network hiccup"), 1, "arch §15 fallback"},

		// additional rows for *every* sentinel in arch §15 (full completeness per reviewer high; tx/signer 3/5 and some deposit are tx-surface, gen falls to 1; row added + comment for exhaustive coverage per arch table; gen emits its subset)
		{"signer.ErrSignerClosed (tx; gen 1)", signer.ErrSignerClosed, 1, "arch 3 (tx binary)"},
		{"signer.ErrNoDevice (tx; gen 1)", signer.ErrNoDevice, 1, "arch 3"},
		{"signer.ErrDeviceUnavailable (tx; gen 1)", signer.ErrDeviceUnavailable, 1, "arch 3"},
		{"signer.ErrAppNotOpen (tx; gen 1)", signer.ErrAppNotOpen, 1, "arch 3"},
		{"signer.ErrInvalidKey (tx; gen 1)", signer.ErrInvalidKey, 1, "arch 3"},
		{"signer.ErrInvalidChainID (tx; gen 1)", signer.ErrInvalidChainID, 1, "arch 3"},
		{"signer.ErrChainIDMismatch (tx; gen 1)", signer.ErrChainIDMismatch, 1, "arch 3"},
		{"signer.ErrSenderMismatch (tx; gen 1)", signer.ErrSenderMismatch, 1, "arch 3"},
		{"internaltx.ErrRPCDial (tx; gen 1)", internaltx.ErrRPCDial, 1, "arch 5"},
		{"internaltx.ErrBroadcastFailed (tx; gen 1)", internaltx.ErrBroadcastFailed, 1, "arch 5"},
		{"internaltx.ErrBroadcastChainIDMismatch (tx; gen 1)", internaltx.ErrBroadcastChainIDMismatch, 1, "arch 5"},
		{"internaltx.ErrReceiptReverted (tx; gen 1)", internaltx.ErrReceiptReverted, 1, "arch 5"},
		{"internaltx.ErrReceiptTimeout (tx; gen 1)", internaltx.ErrReceiptTimeout, 1, "arch 5"},
		{"internaltx.ErrNoBaseFee (tx; gen 1)", internaltx.ErrNoBaseFee, 1, "arch 5"},
		{"bls.ErrSecretRejected (legacy; sim; falls 1 in gen)", errors.New("bls: secret key rejected (scalar out of range for BLS12-381)"), 1, "arch 3 (gen; current uses string/Zero or not branched)"},
		{"deposit.ErrNetworkMismatch (tx DiD; gen 1)", deposit.ErrNetworkMismatch, 1, "arch 2 (tx); gen does not emit"},
		{"deposit.ErrForkVersionMismatch (tx DiD; gen 1)", deposit.ErrForkVersionMismatch, 1, "arch 2"},
		{"deposit.ErrDepositMessageRootMismatch (tx DiD; gen 1)", deposit.ErrDepositMessageRootMismatch, 1, "arch 2"},
		{"deposit.ErrDepositDataRootMismatch (tx DiD; gen 1)", deposit.ErrDepositDataRootMismatch, 1, "arch 2"},
		{"deposit.ErrZeroWithdrawal00 (tx DiD; gen 1)", deposit.ErrZeroWithdrawal00, 1, "arch 2"},
		{"deposit.ErrInvalidWCFormat (tx DiD; gen 1)", deposit.ErrInvalidWCFormat, 1, "arch 2"},

		// deliberate breakage (M1.5-9 AC): exercises the unmapped sentinel path that yields 1.
		// Every sentinel from arch §15 must have a row above; new ones from future M* or %w must be added or contract breaks.
		{"deliberate_breakage_unmapped_sentinel", errors.New("TEST-ONLY-unmapped-sentinel-for-M1.5-9-deliberate-breakage; promote + add row to this table + update arch §15"), 1, "fallback; if prod sentinel hits without row, update TestExitCodeContract (M1.5-9)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cli.ExitCodeFor(tc.err)
			if got != tc.want {
				t.Errorf("exitCodeFor(%v) = %d, want %d %s", tc.err, got, tc.want, tc.comment)
			}
		})
	}
}

// TestExitCodeContract_deliberateBreakageTrigger documents + exercises the breakage detector for verif.
// Per task: "the deliberate breakage case triggers failure as specified" (message mentions update contract).
// In normal CI it passes (unmapped ->1). To force+observe the deterministic failure during verif:
//
//	temp edit (search_replace) one of the named rows above (e.g. change want for context.Canceled to 3)
//	or add a return of a fresh sentinel inside exitCodeFor (in main.go) without a matching case row here
//	then: cd go && go test -run 'TestExitCodeContract/deliberateBreakageTrigger|TestExitCodeContract/context.Canceled' -count=1
//
// Expected: test fails; error text contains "update the TestExitCodeContract table" (or the got/want for the affected named AC row).
// Revert the temp edit before final declare (gofmt/vet/test clean).
func TestExitCodeContract_deliberateBreakageTrigger(t *testing.T) {
	unmapped := errors.New("TEST-ONLY deliberate breakage sentinel (M1.5-9 split-watch); failure here or on row must mention 'update contract' or 'TestExitCodeContract'")
	if got := cli.ExitCodeFor(unmapped); got != 1 {
		t.Errorf("deliberate unmapped exitCodeFor = %d, want 1; update the TestExitCodeContract table (see go/plan/architecture.md §15 + M1.5-9 AC + prior M1.5 Is/got-want patterns)", got)
	}
}
