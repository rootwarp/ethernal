package main

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	ucli "github.com/urfave/cli/v3"

	"github.com/rootwarp/eth-utils/go/internal/signer"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

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
// (N1: no early device query), so resolveRPC returns ErrMissingFromForNonce →
// exit 2, before any signing or device interaction. Exit 2 (not 3=ErrNoDevice) is
// the discriminator that proves the ledger was never touched.
func TestRunCommand_LedgerSigner_RPCNonceOmitted_Exit2(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	withMockEthRPC(t, &mockEthRPC{
		ChainIDFn:          func(context.Context) (*big.Int, error) { return big.NewInt(int64(holeskyChainID)), nil },
		SuggestGasTipCapFn: func(context.Context) (*big.Int, error) { return big.NewInt(1_000_000_000), nil },
		BlockBaseFeeFn:     func(context.Context) (*big.Int, error) { return big.NewInt(10_000_000_000), nil },
		PendingNonceAtFn: func(context.Context, [20]byte) (uint64, error) {
			t.Fatal("PendingNonceAt must not run: ledger From is zero → ErrMissingFromForNonce first")
			return 0, nil
		},
		EstimateGasFn: func(context.Context, internaltx.CallMsg) (uint64, error) {
			t.Fatal("EstimateGas must not run for a zero From")
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
		// --nonce omitted
	})
	if err == nil {
		t.Fatal("expected ErrMissingFromForNonce exit 2, got nil")
	}
	if !errors.Is(err, internaltx.ErrMissingFromForNonce) {
		t.Errorf("error should be ErrMissingFromForNonce, got: %v", err)
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2 (not 3 — no device interaction); err = %v", got, err)
	}
}
