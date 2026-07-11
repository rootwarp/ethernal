package main

import (
	"bytes"
	"context"
	"math/big"
	"strings"
	"testing"

	ucli "github.com/urfave/cli/v3"

	"github.com/rootwarp/eth-utils/go/internal/signer"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// withNoDialEthRPC traps any dial attempt: a config-time gate under test must
// fire before buildUnsignedTx reaches the RPC seam. If it doesn't, the trap fails
// the test loudly instead of letting a real/mocked dial mask the regression.
func withNoDialEthRPC(t *testing.T) {
	t.Helper()
	orig := newEthRPC
	newEthRPC = func(ctx context.Context, rpcURL string) (internaltx.EthRPC, error) {
		t.Fatal("newEthRPC called: the config-time gate should fire before any dial")
		return nil, nil
	}
	t.Cleanup(func() { newEthRPC = orig })
}

// Case 10: run --signer local + --rpc-url with --nonce omitted derives From from
// the key, so resolveRPC's PendingNonceAt and the 32-ETH EstimateGas both receive
// the non-zero derived sender (not the zero address), and the run succeeds.
func TestRunCommand_LocalSigner_RPCDerivesFrom(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_RUN_LOCAL_FROM_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	// Expected sender, derived via the production signer path (same key the run
	// derivation and the later signing step both read from the env var).
	s, err := signer.NewLocalSignerFromEnv(envVar)
	if err != nil {
		t.Fatalf("derive expected address: %v", err)
	}
	wantAddr, err := s.Address()
	_ = s.Close()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	wantFrom := [20]byte(wantAddr)
	if wantFrom == ([20]byte{}) {
		t.Fatal("test key derived a zero address")
	}

	var nonceFrom, estimateFrom [20]byte
	withMockEthRPC(t, &mockEthRPC{
		ChainIDFn:          func(context.Context) (*big.Int, error) { return big.NewInt(int64(holeskyChainID)), nil },
		SuggestGasTipCapFn: func(context.Context) (*big.Int, error) { return big.NewInt(1_000_000_000), nil },
		BlockBaseFeeFn:     func(context.Context) (*big.Int, error) { return big.NewInt(10_000_000_000), nil },
		PendingNonceAtFn: func(_ context.Context, account [20]byte) (uint64, error) {
			nonceFrom = account
			return 3, nil
		},
		EstimateGasFn: func(_ context.Context, msg internaltx.CallMsg) (uint64, error) {
			estimateFrom = msg.From
			return 200_000, nil
		},
	})

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out

	err = app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--rpc-url", "http://node.example",
		"--signer", "local",
		"--private-key-env", envVar,
		// --nonce omitted → PendingNonceAt runs with the derived From;
		// --gas-limit omitted → EstimateGas runs with the derived From.
	})
	if err != nil {
		t.Fatalf("run local+rpc: %v", err)
	}
	if nonceFrom != wantFrom {
		t.Errorf("PendingNonceAt From = %x, want derived %x", nonceFrom, wantFrom)
	}
	if estimateFrom != wantFrom {
		t.Errorf("EstimateGas From = %x, want derived %x", estimateFrom, wantFrom)
	}
	if out.Len() == 0 {
		t.Error("expected signed tx output, got empty")
	}
}

// Regression guard for the UNCONDITIONAL derivation (arch §1.5 "why drop the
// Nonce==nil gate"): with --nonce explicit but --gas-limit omitted, PendingNonceAt
// is skipped yet EstimateGas still needs a funded From. If the derivation were
// (re-)gated on Nonce==nil, From would stay zero here and EstimateGas would
// capture the zero address — so this pins that From is derived regardless of
// whether --nonce was supplied.
func TestRunCommand_LocalSigner_RPCDerivesFromForGasEstimateWithExplicitNonce(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_RUN_LOCAL_GASONLY_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	s, err := signer.NewLocalSignerFromEnv(envVar)
	if err != nil {
		t.Fatalf("derive expected address: %v", err)
	}
	wantAddr, err := s.Address()
	_ = s.Close()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	wantFrom := [20]byte(wantAddr)

	var estimateFrom [20]byte
	withMockEthRPC(t, &mockEthRPC{
		ChainIDFn:          func(context.Context) (*big.Int, error) { return big.NewInt(int64(holeskyChainID)), nil },
		SuggestGasTipCapFn: func(context.Context) (*big.Int, error) { return big.NewInt(1_000_000_000), nil },
		BlockBaseFeeFn:     func(context.Context) (*big.Int, error) { return big.NewInt(10_000_000_000), nil },
		PendingNonceAtFn: func(context.Context, [20]byte) (uint64, error) {
			t.Fatal("PendingNonceAt must not run: --nonce is explicit")
			return 0, nil
		},
		EstimateGasFn: func(_ context.Context, msg internaltx.CallMsg) (uint64, error) {
			estimateFrom = msg.From
			return 200_000, nil
		},
	})

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out

	err = app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--rpc-url", "http://node.example",
		"--signer", "local",
		"--private-key-env", envVar,
		"--nonce", "5", // explicit nonce → PendingNonceAt skipped
		// --gas-limit omitted → EstimateGas still needs the derived From
	})
	if err != nil {
		t.Fatalf("run local+rpc (explicit nonce): %v", err)
	}
	if estimateFrom != wantFrom {
		t.Errorf("EstimateGas From = %x, want derived %x (derivation must be unconditional, not gated on Nonce==nil)", estimateFrom, wantFrom)
	}
}

// The local-signer derivation runs before the build/dial, so a bad key in
// --signer local + --rpc-url mode surfaces as exit 3 at derivation (not a dial
// error). Exit 3 (not 5) is the discriminator that the derive block ran first;
// it also covers the derive-block error return. No mock is injected: if the
// derivation wrongly did not fire, the build would really dial http://node.example
// and fail with exit 5.
func TestRunCommand_LocalSigner_RPCBadKey_Exit3(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_RUN_LOCAL_BADKEY_" + randomSuffix(t)
	t.Setenv(envVar, "0xdeadbeefnotahexkey")

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--rpc-url", "http://node.example",
		"--signer", "local",
		"--private-key-env", envVar,
	})
	if err == nil {
		t.Fatal("expected bad-key error, got nil")
	}
	if got := ExitCodeFor(err); got != 3 {
		t.Errorf("exit code = %d, want 3 (derivation failed before dialing); err = %v", got, err)
	}
}

// Case 11: run --signer ledger + --rpc-url with --nonce omitted → From stays zero
// (N1: no early device query). The config-time gate (requireLedgerFlagsForRPC)
// now rejects this up front with exit 2 naming both flags — before any file read,
// dial, or device interaction. This supersedes the resolveRPC
// ErrMissingFromForNonce backstop (still covered at builder level); the gate
// catches it first.
func TestRunCommand_LedgerSigner_RPCNonceOmitted_Exit2(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	withNoDialEthRPC(t) // the gate must fire before any dial

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--rpc-url", "http://node.example",
		"--signer", "ledger",
		// --nonce omitted
	})
	if err == nil {
		t.Fatal("expected config-time exit 2, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
	if !strings.Contains(err.Error(), "--nonce") || !strings.Contains(err.Error(), "--gas-limit") {
		t.Errorf("error should name both --nonce and --gas-limit, got: %v", err)
	}
}

// The gas-omitted half: --nonce set but --gas-limit omitted still needs a funded
// From for EstimateGas, which ledger cannot provide — gated at config time.
func TestRunCommand_LedgerSigner_RPCGasOmitted_Exit2(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	withNoDialEthRPC(t)

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--rpc-url", "http://node.example",
		"--signer", "ledger",
		"--nonce", "5", // nonce set; --gas-limit omitted
	})
	if err == nil {
		t.Fatal("expected config-time exit 2, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
	if !strings.Contains(err.Error(), "--gas-limit") {
		t.Errorf("error should name --gas-limit, got: %v", err)
	}
}

// With both --nonce and --gas-limit supplied, the gate passes and the run
// proceeds to signing — which fails with no Ledger device (exit 3), NOT the
// gate's exit-2 error. A mock is injected so the build reaches the sign step.
func TestRunCommand_LedgerSigner_RPCBothFlags_PassesGate(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	withMockEthRPC(t, &mockEthRPC{
		ChainIDFn:          func(context.Context) (*big.Int, error) { return big.NewInt(int64(holeskyChainID)), nil },
		SuggestGasTipCapFn: func(context.Context) (*big.Int, error) { t.Fatal("explicit flags → no fee resolve"); return nil, nil },
		BlockBaseFeeFn:     func(context.Context) (*big.Int, error) { t.Fatal("explicit flags → no fee resolve"); return nil, nil },
		PendingNonceAtFn: func(context.Context, [20]byte) (uint64, error) {
			t.Fatal("explicit nonce → no nonce resolve")
			return 0, nil
		},
		EstimateGasFn: func(context.Context, internaltx.CallMsg) (uint64, error) {
			t.Fatal("explicit gas → no gas resolve")
			return 0, nil
		},
	})

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--rpc-url", "http://node.example",
		"--signer", "ledger",
		"--nonce", "5",
		"--gas-limit", "250000",
		"--max-fee-per-gas", "20000000000",
		"--max-priority-fee-per-gas", "1000000000",
	})
	if err == nil {
		t.Fatal("expected a downstream ledger no-device error after passing the gate")
	}
	if strings.Contains(err.Error(), "requires both --nonce and --gas-limit") {
		t.Errorf("gate should have passed with both flags set, got the gate error: %v", err)
	}
	if got := ExitCodeFor(err); got != 3 {
		t.Errorf("exit code = %d, want 3 (ledger no device, past the gate); err = %v", got, err)
	}
}

// TestRequireLedgerFlagsForRPC exercises the gate condition directly.
func TestRequireLedgerFlagsForRPC(t *testing.T) {
	nonce := func() *uint64 { n := uint64(5); return &n }
	cases := []struct {
		name    string
		cfg     RunConfig
		wantErr bool
	}{
		{"offline ledger (no rpc)", RunConfig{Signer: "ledger", Build: &Config{}}, false},
		{"ledger rpc nonce omitted", RunConfig{Signer: "ledger", Build: &Config{RPCURL: "http://n", GasLimit: 250_000}}, true},
		{"ledger rpc gas omitted", RunConfig{Signer: "ledger", Build: &Config{RPCURL: "http://n", Nonce: nonce()}}, true},
		{"ledger rpc both omitted", RunConfig{Signer: "ledger", Build: &Config{RPCURL: "http://n"}}, true},
		{"ledger rpc both set", RunConfig{Signer: "ledger", Build: &Config{RPCURL: "http://n", Nonce: nonce(), GasLimit: 250_000}}, false},
		{"local rpc both omitted (exempt)", RunConfig{Signer: "local", Build: &Config{RPCURL: "http://n"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireLedgerFlagsForRPC(&tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if got := ExitCodeFor(err); got != 2 {
					t.Errorf("exit code = %d, want 2; err = %v", got, err)
				}
				if !strings.Contains(err.Error(), "--nonce") || !strings.Contains(err.Error(), "--gas-limit") {
					t.Errorf("error should name both flags, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Errorf("expected nil, got: %v", err)
			}
		})
	}
}
