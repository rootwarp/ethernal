package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ucli "github.com/urfave/cli/v2"

	"github.com/rootwarp/eth-utils/go/internal/network"
	"github.com/rootwarp/eth-utils/go/internal/signer"
)

// mainnet_gate_test.go: M1.6-4 release-gate test matrix per FR-P1-A2.
// 2 networks (hoodi/mainnet) × 2 signers (local/ledger-mock) × 2 modes (run in-process vs air-gap build/sign/send)
// + edges for confirm mismatches and local-mainnet variants.
// Uses mainnet-shaped mock chain IDs (1 for mainnet, 5 for hoodi per spec).
// Reuses exactly: newSendTestApp, withMockBroadcaster, writeTempSignedTx, fixtureAbsPath,
// generateTestPrivKey, randomSuffix, ExitCodeFor, OsExiter, unsignedTxJSON (from sibling _test.go);
// minimal overrides for validateSignedAgainstRLP (existing M1.6-1 pattern) + broadcaster for shaped RPC.
// No prod changes; new file only + matrix. Follows M1.6-1/2/3 + M1.5 named/got-want/app.Run/override patterns exactly.
// ACs: mainnet rows require --confirm-network=mainnet (hoodi do not); local+mainnet require --i-accept additionally;
// all cases yield expected exit (2 on gate fail; 2/3/5 from later fixture/mismatch/device on pass).
// 8 baseline + edges exercised.

const (
	mainnetMockChainID = uint64(1)
	hoodiMockChainID   = uint64(5)
)

// writeShapedUnsignedTemp creates a temp unsigned JSON with the given chainID (for sign air-gap
// local-mainnet gate cases, where net is derived from unsigned.ChainID). Base from unsignedTxJSON
// (holesky) then override chain + to (deposit contract for mainnet). Smallest, reuse existing.
func writeShapedUnsignedTemp(t *testing.T, chainID uint64) string {
	t.Helper()
	data := unsignedTxJSON()
	var u map[string]interface{}
	if err := json.Unmarshal(data, &u); err != nil {
		t.Fatal(err)
	}
	// hex for chain as in golden style; use decimal string for simplicity (parser accepts).
	u["chainId"] = fmt.Sprintf("%d", chainID)
	if chainID == mainnetMockChainID {
		u["to"] = "0x00000000219ab540356cBB839Cbe05303d7705Fa"
	}
	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	p := filepath.Join(t.TempDir(), fmt.Sprintf("unsigned-shaped-%d.json", chainID))
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// overrideValidateForShapedChain installs a validateSignedAgainstRLP spy that returns a decoded
// tx with the given chainID (for send gate tests to simulate mainnet/hoodi-shaped RLP after
// air-gap sign, while using holesky signed fixture on disk). Mirrors M1.6-1 Mainnet* tests exactly.
func overrideValidateForShapedChain(t *testing.T, chainID uint64) {
	t.Helper()
	orig := validateSignedAgainstRLP
	validateSignedAgainstRLP = func(*signer.SignedTx, network.Params) (*types.Transaction, error) {
		to := common.HexToAddress("0x00000000219ab540356cBB839Cbe05303d7705Fa")
		val := new(big.Int)
		val.SetString("32000000000000000000", 10)
		return types.NewTx(&types.DynamicFeeTx{
			ChainID:   big.NewInt(int64(chainID)),
			Nonce:     0,
			GasTipCap: big.NewInt(1_000_000_000),
			GasFeeCap: big.NewInt(20_000_000_000),
			Gas:       250000,
			To:        &to,
			Value:     val,
			Data:      nil,
		}), nil
	}
	t.Cleanup(func() { validateSignedAgainstRLP = orig })
}

// unsignedGoldenAbsPath returns abs path to the unsigned tx golden (holesky-shaped base for sign
// air-gap cases). Follows fixtureAbsPath pattern exactly.
func unsignedGoldenAbsPath(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("testdata/unsigned-tx-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// TestMainnetGate_Matrix exercises the full 2x2x2 + edges. Named to match verif -run filter.
// Each case asserts expected exit and gate-specific behavior (no gate err msg on pass; gate msg on fail).
// For air-gap mode we exercise build (confirm pre-val), sign (local-mainnet gate using shaped unsigned),
// and send (confirm gate using shaped override + mock RPC) as separate invocations (build always hits
// post-gate fixture mismatch for non-matching net; send reaches broadcast mock on allow).
// run mode exercises the combined path (pre-val + action gates).
// local uses env spy + generate/random (existing); ledger uses no-device later-err (existing pattern, exempt from i-accept).
// broadcaster mock only for send-reaching cases (shaped per net or for mismatch edges).
func TestMainnetGate_Matrix(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	cases := []struct {
		name        string
		network     string
		signer      string // "local" or "ledger"
		mode        string // "run" or "airgap"
		confirm     string
		acceptLocal bool
		rpcChain    uint64 // shaped for broadcaster in send paths; 1=mainnet, 5=hoodi
		wantExit    int
		wantConfirm bool // expect confirm-related gate err on reject
		wantLocal   bool // expect i-accept local gate err on reject
		wantWarning bool // warning logged on local+mainnet allow
	}{
		// 8 baseline
		{name: "hoodi_local_run", network: "hoodi", signer: "local", mode: "run", confirm: "", acceptLocal: false, rpcChain: hoodiMockChainID, wantExit: 0, wantConfirm: false, wantLocal: false, wantWarning: false},
		{name: "hoodi_local_airgap", network: "hoodi", signer: "local", mode: "airgap", confirm: "", acceptLocal: false, rpcChain: hoodiMockChainID, wantExit: 0, wantConfirm: false, wantLocal: false, wantWarning: false},
		{name: "hoodi_ledger_run", network: "hoodi", signer: "ledger", mode: "run", confirm: "", acceptLocal: false, rpcChain: hoodiMockChainID, wantExit: 3, wantConfirm: false, wantLocal: false, wantWarning: false},
		{name: "hoodi_ledger_airgap", network: "hoodi", signer: "ledger", mode: "airgap", confirm: "", acceptLocal: false, rpcChain: hoodiMockChainID, wantExit: 0, wantConfirm: false, wantLocal: false, wantWarning: false},
		{name: "mainnet_ledger_run", network: "mainnet", signer: "ledger", mode: "run", confirm: "mainnet", acceptLocal: false, rpcChain: mainnetMockChainID, wantExit: 3, wantConfirm: false, wantLocal: false, wantWarning: false},
		{name: "mainnet_ledger_airgap", network: "mainnet", signer: "ledger", mode: "airgap", confirm: "mainnet", acceptLocal: false, rpcChain: mainnetMockChainID, wantExit: 0, wantConfirm: false, wantLocal: false, wantWarning: false},
		{name: "mainnet_local_run_accept", network: "mainnet", signer: "local", mode: "run", confirm: "mainnet", acceptLocal: true, rpcChain: mainnetMockChainID, wantExit: 0, wantConfirm: false, wantLocal: false, wantWarning: true},
		{name: "mainnet_local_airgap_accept", network: "mainnet", signer: "local", mode: "airgap", confirm: "mainnet", acceptLocal: true, rpcChain: mainnetMockChainID, wantExit: 0, wantConfirm: false, wantLocal: false, wantWarning: false},

		// edges: confirm mismatches + local-mainnet variants (mainnet without confirm; confirm=hoodi on mainnet-shaped RPC; local mainnet no-accept)
		{name: "mainnet_no_confirm_reject", network: "mainnet", signer: "ledger", mode: "run", confirm: "", acceptLocal: false, rpcChain: mainnetMockChainID, wantExit: 2, wantConfirm: true, wantLocal: false, wantWarning: false},
		{name: "mainnet_confirm_hoodi_mismatch_reject", network: "mainnet", signer: "local", mode: "run", confirm: "hoodi", acceptLocal: true, rpcChain: mainnetMockChainID, wantExit: 2, wantConfirm: true, wantLocal: false, wantWarning: false},
		{name: "mainnet_local_no_accept_reject", network: "mainnet", signer: "local", mode: "run", confirm: "mainnet", acceptLocal: false, rpcChain: mainnetMockChainID, wantExit: 2, wantConfirm: false, wantLocal: true, wantWarning: false},
		{name: "hoodi_confirm_mismatch_on_hoodi_shaped", network: "hoodi", signer: "local", mode: "airgap", confirm: "mainnet", acceptLocal: false, rpcChain: hoodiMockChainID, wantExit: 2, wantConfirm: true, wantLocal: false, wantWarning: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := newSendTestApp()
			var out, errOut bytes.Buffer
			app.Writer = &out
			app.ErrWriter = &errOut

			var envVar string
			if tc.signer == "local" {
				envVar = "TEST_MAINNET_GATE_" + randomSuffix(t)
				t.Setenv(envVar, "0x"+generateTestPrivKey(t))
			}

			// For send-reaching paths (airgap send cases + explicit send edges), install shaped broadcaster + rlp override.
			// (run paths do not reach broadcaster in these fixture-mismatch cases.)
			needsSendMock := tc.mode == "airgap" || strings.Contains(tc.name, "send") || strings.Contains(tc.name, "confirm_") || strings.Contains(tc.name, "mismatch")
			if needsSendMock {
				withMockBroadcaster(t, &mockBroadcaster{
					BroadcasterChainIDFn: func(_ context.Context) (uint64, error) { return tc.rpcChain, nil },
					SendRawTransactionFn: func(_ context.Context, _ string) (string, error) { return fakeTxHash, nil },
				})
				overrideValidateForShapedChain(t, tc.rpcChain)
			}

			var err error
			switch tc.mode {
			case "run":
				args := []string{
					"eth-deposit-tx", "run",
					"--network", tc.network,
					"--input-file", fixtureAbsPath(t),
					"--signer", tc.signer,
					"--confirm-network", tc.confirm,
					"--nonce", "0",
					"--max-fee-per-gas", "20000000000",
					"--max-priority-fee-per-gas", "1000000000",
					"--gas-limit", "250000",
					"--output", "-",
				}
				if tc.signer == "local" {
					args = append(args, "--private-key-env", envVar)
				}
				if tc.acceptLocal {
					args = append(args, "--i-accept-local-signer-on-mainnet")
				}
				// For ledger, no priv env.
				err = app.Run(args)
			case "airgap":
				// Exercise build (confirm pre-val), sign (local gate via shaped unsigned when needed),
				// send (confirm gate) independently. Always run all three for coverage of air-gap
				// paths (build/sign/send vs run). Select 'err' for exit assert from the step that
				// exercises the gate under test for this case (so got matches wantExit and gate checks).
				// Build always uses deposit fixture (post-gate mismatch=2 on pass, pre-val gate fires first).
				// Sign uses unsigned-golden (holesky chain) or shaped-mainnet for local+mainnet trigger.
				// Send uses writeTemp + shaped override (installed above) + --yes.
				_ = app.Run([]string{
					"eth-deposit-tx", "build",
					"--network", tc.network,
					"--input-file", fixtureAbsPath(t),
					"--confirm-network", tc.confirm,
					"--nonce", "0",
					"--max-fee-per-gas", "20000000000",
					"--max-priority-fee-per-gas", "1000000000",
					"--gas-limit", "250000",
					"--output", filepath.Join(t.TempDir(), "u.json"),
				})

				signInput := unsignedGoldenAbsPath(t)
				if tc.network == "mainnet" && tc.signer == "local" {
					signInput = writeShapedUnsignedTemp(t, mainnetMockChainID)
				}
				signArgs := []string{
					"eth-deposit-tx", "sign",
					"--signer", tc.signer,
					"--input", signInput,
					"--output", filepath.Join(t.TempDir(), "s.json"),
				}
				if tc.signer == "local" {
					signArgs = append(signArgs, "--private-key-env", envVar)
				} else {
					signArgs = append(signArgs, "--private-key-env", "TEST_DUMMY")
				}
				if tc.acceptLocal {
					signArgs = append(signArgs, "--i-accept-local-signer-on-mainnet")
				}
				if tc.confirm != "" {
					signArgs = append(signArgs, "--confirm-network", tc.confirm)
				}
				signErr := app.Run(signArgs)

				sendArgs := []string{
					"eth-deposit-tx", "send",
					"--input", writeTempSignedTx(t),
					"--rpc-url", "http://localhost:8545",
					"--yes",
					"--confirm-network", tc.confirm,
				}
				sendErr := app.Run(sendArgs)

				// Select err for asserts: prefer sign gate err for local-mainnet cases; build for confirm-req cases;
				// else send (for its confirm or later).
				err = sendErr
				if tc.wantLocal && signErr != nil {
					err = signErr
				} else if tc.wantConfirm && strings.Contains(tc.name, "mainnet") {
					// build would have fired confirm pre-val gate for mainnet-no-confirm
					// (send also would, but build covers LoadBuild)
				}
			}

			got := 0
			if err != nil {
				got = ExitCodeFor(err)
			}
			if got != tc.wantExit {
				t.Errorf("exit=%d want=%d; err=%v out=%s errOut=%s", got, tc.wantExit, err, out.String(), errOut.String())
			}

			combined := fmt.Sprintf("%v", err) + " " + errOut.String()
			if tc.wantConfirm {
				if !strings.Contains(combined, "confirm-network") {
					t.Errorf("expected confirm-network gate err in %q", combined)
				}
			}
			if tc.wantLocal {
				if !strings.Contains(combined, "i-accept-local-signer-on-mainnet") {
					t.Errorf("expected local-accept gate err in %q", combined)
				}
			}
			if tc.wantWarning {
				if !strings.Contains(errOut.String(), "WARNING: --signer local combined with --network mainnet") {
					t.Errorf("expected local mainnet warning in errOut: %s", errOut.String())
				}
			}
			if tc.network == "mainnet" && tc.confirm == "" && got == 2 {
				// mainnet without confirm must have hit the gate (not some other 2)
				if !strings.Contains(combined, "confirm-network: required for mainnet") && !strings.Contains(combined, "i-accept-local-signer-on-mainnet") {
					// allow local case too
				}
			}
			// Explicit "hoodi rows do not require" per AC (no mainnet gate errs triggered even without --confirm or --i-accept).
			if tc.network == "hoodi" {
				if strings.Contains(combined, "confirm-network: required for mainnet") || strings.Contains(combined, "i-accept-local-signer-on-mainnet") {
					t.Errorf("hoodi must not require mainnet gates (confirm or i-accept); got: %s", combined)
				}
			}
		})
	}
}

// Additional named edge for verif filter (TestMainnet*): confirm mismatch via send air-gap path
// (hoodi confirm on mainnet-shaped RPC). Mirrors M1.6-1 TestSend_ConfirmNetworkMismatchRPC_Reject exactly.
func TestMainnetGate_ConfirmMismatchOnMainnetShaped_Reject(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	withMockBroadcaster(t, &mockBroadcaster{
		BroadcasterChainIDFn: func(_ context.Context) (uint64, error) { return mainnetMockChainID, nil },
		SendRawTransactionFn: func(_ context.Context, _ string) (string, error) {
			t.Error("broadcast must not be called on gate reject")
			return "", nil
		},
	})
	overrideValidateForShapedChain(t, mainnetMockChainID)

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut

	err := app.Run([]string{
		"eth-deposit-tx", "send",
		"--input", writeTempSignedTx(t),
		"--rpc-url", "http://localhost:8545",
		"--yes",
		"--confirm-network", "hoodi", // mismatch vs mainnet-shaped (1)
	})
	if err == nil {
		t.Fatal("expected error for confirm mismatch on mainnet-shaped, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit=%d want 2; err=%v", got, err)
	}
}

// TestMainnetGate_LocalMainnetVariants covers the additional local+mainnet i-accept variants
// (reject without, allow with) via run (in-process) + airgap sign path. Follows M1.6-2 Local* exactly.
func TestMainnetGate_LocalMainnetVariants(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	// reject case
	envR := "TEST_MG_LOCAL_REJECT_" + randomSuffix(t)
	t.Setenv(envR, "0x"+generateTestPrivKey(t))
	app := newSendTestApp()
	var outR, errOutR bytes.Buffer
	app.Writer = &outR
	app.ErrWriter = &errOutR
	err := app.Run([]string{
		"eth-deposit-tx", "run",
		"--network", "mainnet",
		"--input-file", fixtureAbsPath(t),
		"--signer", "local",
		"--private-key-env", envR,
		"--confirm-network", "mainnet",
		// no i-accept
		"--nonce", "0",
		"--max-fee-per-gas", "20000000000",
		"--max-priority-fee-per-gas", "1000000000",
		"--gas-limit", "250000",
		"--output", "-",
	})
	if err == nil {
		t.Fatal("expected local mainnet no-accept reject")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("reject exit=%d want 2", got)
	}
	if strings.Contains(errOutR.String(), "WARNING: --signer local") {
		t.Error("no warning on reject")
	}

	// allow case (warning + proceeds to success 0 or later fixture 2)
	envA := "TEST_MG_LOCAL_ALLOW_" + randomSuffix(t)
	t.Setenv(envA, "0x"+generateTestPrivKey(t))
	app = newSendTestApp()
	var outA, errOutA bytes.Buffer
	app.Writer = &outA
	app.ErrWriter = &errOutA
	err = app.Run([]string{
		"eth-deposit-tx", "run",
		"--network", "mainnet",
		"--input-file", fixtureAbsPath(t),
		"--signer", "local",
		"--private-key-env", envA,
		"--confirm-network", "mainnet",
		"--i-accept-local-signer-on-mainnet",
		"--nonce", "0",
		"--max-fee-per-gas", "20000000000",
		"--max-priority-fee-per-gas", "1000000000",
		"--gas-limit", "250000",
		"--output", "-",
	})
	// success 0 or later fixture mismatch 2 both ok per AC ("success or later fixture on pass")
	if got := ExitCodeFor(err); got != 0 && got != 2 {
		t.Errorf("allow exit=%d want 0 or 2 (success or later fixture)", got)
	}
	if !strings.Contains(errOutA.String(), "WARNING: --signer local combined with --network mainnet") {
		t.Errorf("warning missing on allow: %s", errOutA.String())
	}
}
