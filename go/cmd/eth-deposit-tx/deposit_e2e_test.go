//go:build e2e

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ucli "github.com/urfave/cli/v2"

	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// phase3KeyPath and phase3UnsignedPath point to the Phase 3 Holesky golden fixtures
// relative to this package's working directory.
const (
	phase3FixtureDir = "../../testdata/phase3/holesky"
	phase3KeyFile    = phase3FixtureDir + "/private_key.txt"
	phase3UnsignedTx = phase3FixtureDir + "/unsigned_tx.json"
)

// newE2EApp returns a full app including send, matching the production app minus signal handling.
func newE2EApp() *ucli.App {
	return &ucli.App{
		Name:           "eth-deposit-tx",
		Version:        "dev",
		Commands:       []*ucli.Command{buildCommand(), signCommand(), runCommand(), sendCommand()},
		ExitErrHandler: func(_ *ucli.Context, _ error) {},
	}
}

// readPhase3Key reads and trims the synthetic private key from the Phase 3 fixture.
func readPhase3Key(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(phase3KeyFile)
	if err != nil {
		t.Fatalf("resolve key path: %v", err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read key file %s: %v", abs, err)
	}
	return strings.TrimSpace(string(raw))
}

// TestE2E_LocalSigner_FullPipeline_NoRPC exercises the run subcommand
// (build + sign in one step) using the Phase 3 synthetic key and unsigned tx fixture.
// No RPC call is made. The test verifies the output SignedTx structure and
// that RawRLP starts with the EIP-1559 type prefix 0x02.
func TestE2E_LocalSigner_FullPipeline_NoRPC(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	key := readPhase3Key(t)
	const envVar = "E2E_TEST_PRIVKEY_PIPELINE"
	t.Setenv(envVar, key)

	dir := t.TempDir()
	outFile := filepath.Join(dir, "signed.json")

	app := newE2EApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut

	absDepositFixture, err := filepath.Abs("testdata/deposit-fixture.json")
	if err != nil {
		t.Fatalf("resolve deposit fixture path: %v", err)
	}

	err = app.Run([]string{
		"eth-deposit-tx", "run",
		"--network", "holesky",
		"--input-file", absDepositFixture,
		"--signer", "local",
		"--output", outFile,
		"--private-key-env", envVar,
	})
	if err != nil {
		t.Fatalf("run subcommand failed: %v\nstderr: %s", err, errOut.String())
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("signed.json not written: %v", err)
	}

	var signed map[string]interface{}
	if err := json.Unmarshal(data, &signed); err != nil {
		t.Fatalf("signed.json is not valid JSON: %v\n%s", err, data)
	}

	// Verify all expected fields are present.
	for _, field := range []string{"unsigned", "from", "hash", "r", "s", "v", "rawRLP"} {
		if _, ok := signed[field]; !ok {
			t.Errorf("signed.json missing field %q", field)
		}
	}

	// Verify EIP-1559 prefix on rawRLP.
	rawRLP, _ := signed["rawRLP"].(string)
	if !strings.HasPrefix(rawRLP, "0x02") {
		t.Errorf("rawRLP must start with 0x02 (EIP-1559 type prefix), got: %q", rawRLP)
	}

	// Verify companion .raw file was written.
	rawFile := filepath.Join(dir, "signed.raw")
	rawContent, err := os.ReadFile(rawFile)
	if err != nil {
		t.Fatalf("signed.raw not written: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(rawContent)), "0x02") {
		t.Errorf("signed.raw must start with 0x02, got: %q", strings.TrimSpace(string(rawContent)))
	}

	// Verify the unsigned nested field has expected Holesky chain ID.
	unsignedField, _ := signed["unsigned"].(map[string]interface{})
	if unsignedField == nil {
		t.Fatal("signed.unsigned is nil or wrong type")
	}
	chainID, _ := unsignedField["chainId"].(float64)
	if uint64(chainID) != 17000 {
		t.Errorf("unsigned.chainId = %v, want 17000 (holesky)", chainID)
	}
}

// TestE2E_LocalSigner_BuildSignSendMock exercises the full build → sign → send
// pipeline end-to-end using the mock broadcaster. No real RPC is contacted.
//
// This test:
//   - Runs the sign subcommand on the Phase 3 golden unsigned tx fixture.
//   - Injects a mock broadcaster via the newBroadcaster package var.
//   - Runs the send subcommand on the resulting signed tx.
//   - Verifies the tx hash appears in the output.
func TestE2E_LocalSigner_BuildSignSendMock(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	key := readPhase3Key(t)
	const envVar = "E2E_TEST_PRIVKEY_SEND"
	t.Setenv(envVar, key)

	absUnsigned, err := filepath.Abs(phase3UnsignedTx)
	if err != nil {
		t.Fatalf("resolve unsigned tx path: %v", err)
	}

	dir := t.TempDir()
	signedFile := filepath.Join(dir, "signed.json")

	// Step 1: sign the Phase 3 unsigned tx with the synthetic key.
	signApp := newE2EApp()
	var signOut, signErr bytes.Buffer
	signApp.Writer = &signOut
	signApp.ErrWriter = &signErr

	if err := signApp.Run([]string{
		"eth-deposit-tx", "sign",
		"--signer", "local",
		"--input", absUnsigned,
		"--output", signedFile,
		"--private-key-env", envVar,
	}); err != nil {
		t.Fatalf("sign step failed: %v\nstderr: %s", err, signErr.String())
	}

	// Step 2: inject mock broadcaster and run send --yes.
	const mockTxHash = "0xdeadbeef00000000000000000000000000000000000000000000000000000001"
	withMockBroadcaster(t, &mockBroadcaster{
		// Phase 3 fixture has chainId 17000 (Holesky).
		BroadcasterChainIDFn: func(_ context.Context) (uint64, error) { return 17000, nil },
		SendRawTransactionFn: func(_ context.Context, rawRLP string) (string, error) {
			// Confirm the RLP we receive starts with the EIP-1559 prefix.
			if !strings.HasPrefix(rawRLP, "0x02") {
				t.Errorf("broadcaster received rawRLP without 0x02 prefix: %q", rawRLP)
			}
			return mockTxHash, nil
		},
	})

	sendApp := newE2EApp()
	var sendOut, sendErr bytes.Buffer
	sendApp.Writer = &sendOut
	sendApp.ErrWriter = &sendErr

	if err := sendApp.Run([]string{
		"eth-deposit-tx", "send",
		"--input", signedFile,
		"--rpc-url", "http://mock.localhost:8545",
		"--yes",
	}); err != nil {
		t.Fatalf("send step failed: %v\nstderr: %s", err, sendErr.String())
	}

	outStr := sendOut.String()
	if !strings.Contains(outStr, mockTxHash) {
		t.Errorf("send output missing mock tx hash %q; got:\n%s", mockTxHash, outStr)
	}
	if !strings.Contains(outStr, "holesky.etherscan.io") {
		t.Errorf("send output missing holesky explorer URL; got:\n%s", outStr)
	}

	// Confirm the prompt summary was written to stderr.
	errStr := sendErr.String()
	for _, want := range []string{"32.000000 ETH", "17000", "Broadcasting"} {
		if !strings.Contains(errStr, want) {
			t.Errorf("send stderr missing %q; got:\n%s", want, errStr)
		}
	}
}

// TestE2E_SendMock_ReceiptPolling verifies the receipt polling path via the mock
// broadcaster, exercising the full send → wait → receipt flow without network I/O.
func TestE2E_SendMock_ReceiptPolling(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	const mockTxHash = "0x1111111111111111111111111111111111111111111111111111111111111111"

	mockRec := &internaltx.Receipt{
		TransactionHash: mockTxHash,
		Status:          1,
		BlockNumber:     99999,
		BlockHash:       "0xaaaa",
		GasUsed:         200000,
	}

	withMockBroadcaster(t, &mockBroadcaster{
		BroadcasterChainIDFn: func(_ context.Context) (uint64, error) { return 17000, nil },
		SendRawTransactionFn: func(_ context.Context, _ string) (string, error) { return mockTxHash, nil },
		TransactionReceiptFn: func(_ context.Context, _ string) (*internaltx.Receipt, error) {
			return mockRec, nil
		},
	})

	recFile := filepath.Join(t.TempDir(), "receipt.json")

	app := newE2EApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut

	if err := app.Run([]string{
		"eth-deposit-tx", "send",
		"--input", writeTempSignedTx(t), // reuse helper from send_test.go
		"--rpc-url", "http://mock.localhost:8545",
		"--yes",
		"--receipt-output", recFile,
		"--receipt-timeout", "5s",
	}); err != nil {
		t.Fatalf("send with receipt failed: %v", err)
	}

	data, err := os.ReadFile(recFile)
	if err != nil {
		t.Fatalf("receipt file not written: %v", err)
	}

	var rec internaltx.Receipt
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("receipt file not valid JSON: %v", err)
	}
	if rec.BlockNumber != 99999 {
		t.Errorf("receipt.BlockNumber = %d, want 99999", rec.BlockNumber)
	}
	if rec.Status != 1 {
		t.Errorf("receipt.Status = %d, want 1", rec.Status)
	}

	if !strings.Contains(out.String(), "status=success") {
		t.Errorf("output missing receipt status; got: %s", out.String())
	}
}

// TestRun_HoodiEndToEnd_RPCURL (e2e tag, real hoodi): run with --rpc-url against real hoodi RPC
// (no --nonce/fees) succeeds end-to-end (M1.3-5 AC). Uses real dial + resolveRPC path + local sign.
// Sender key is test-only; no broadcast is performed.
func TestRun_HoodiEndToEnd_RPCURL(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	key := readPhase3Key(t)
	const envVar = "E2E_RUN_HOODI_RPC_KEY"
	t.Setenv(envVar, key)

	dir := t.TempDir()
	outFile := filepath.Join(dir, "signed-hoodi-rpc.json")

	app := newE2EApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut

	// Use the committed hoodi deposit_data fixture (network matches --network hoodi).
	absDepositFixture, err := filepath.Abs("../../testdata/hoodi/deposit_data-2026-06-07T06:11:44.170453Z-4f7dc6a8.json")
	if err != nil {
		t.Fatalf("resolve hoodi deposit fixture: %v", err)
	}

	// Public hoodi RPC used for M0.11/M1.3 e2e (per release notes + plan).
	const hoodiRPC = "https://rpc.hoodi.ethpandaops.io"
	err = app.Run([]string{
		"eth-deposit-tx", "run",
		"--network", "hoodi",
		"--input-file", absDepositFixture,
		"--signer", "local",
		"--output", outFile,
		"--private-key-env", envVar,
		"--rpc-url", hoodiRPC,
		// no --nonce / --max-fee* : resolved via real RPC (chainID guard + fees + nonce)
	})
	if err != nil {
		t.Fatalf("run --rpc-url against real hoodi failed: %v\nstderr: %s", err, errOut.String())
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("signed.json not written: %v", err)
	}
	var signed map[string]interface{}
	if err := json.Unmarshal(data, &signed); err != nil {
		t.Fatalf("signed.json not valid JSON: %v\n%s", err, data)
	}
	for _, field := range []string{"unsigned", "from", "hash", "r", "s", "v", "rawRLP"} {
		if _, ok := signed[field]; !ok {
			t.Errorf("signed.json missing field %q", field)
		}
	}
}
