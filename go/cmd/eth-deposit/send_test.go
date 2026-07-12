package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ucli "github.com/urfave/cli/v3"

	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// mockBroadcaster is a test double for EthBroadcaster using the function-field pattern.
type mockBroadcaster struct {
	SendRawTransactionFn func(ctx context.Context, rawRLP string) (string, error)
	TransactionReceiptFn func(ctx context.Context, txHash string) (*internaltx.Receipt, error)
	BroadcasterChainIDFn func(ctx context.Context) (uint64, error)
	CloseFn              func()
}

func (m *mockBroadcaster) SendRawTransaction(ctx context.Context, rawRLP string) (string, error) {
	if m.SendRawTransactionFn == nil {
		panic("mockBroadcaster.SendRawTransaction not set")
	}
	return m.SendRawTransactionFn(ctx, rawRLP)
}

func (m *mockBroadcaster) TransactionReceipt(ctx context.Context, txHash string) (*internaltx.Receipt, error) {
	if m.TransactionReceiptFn == nil {
		return nil, nil
	}
	return m.TransactionReceiptFn(ctx, txHash)
}

func (m *mockBroadcaster) BroadcasterChainID(ctx context.Context) (uint64, error) {
	if m.BroadcasterChainIDFn == nil {
		panic("mockBroadcaster.BroadcasterChainID not set")
	}
	return m.BroadcasterChainIDFn(ctx)
}

func (m *mockBroadcaster) Close() {
	if m.CloseFn != nil {
		m.CloseFn()
	}
}

// compile-time assertion
var _ internaltx.EthBroadcaster = (*mockBroadcaster)(nil)

// goldenSignedTxPath is the phase-3 holesky signed tx golden fixture.
const goldenSignedTxPath = "../../testdata/phase3/holesky/signed_tx_golden.json"

// signedTxFixture reads the signed tx golden fixture.
func signedTxFixture(t *testing.T) []byte {
	t.Helper()
	abs, err := filepath.Abs(goldenSignedTxPath)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read signed tx fixture: %v", err)
	}
	return data
}

// writeTempSignedTx writes the signed tx fixture to a temp file and returns its path.
func writeTempSignedTx(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signed.json")
	if err := os.WriteFile(path, signedTxFixture(t), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// withMockBroadcaster replaces the package-level broadcaster factory with a mock
// and restores the original after the test.
func withMockBroadcaster(t *testing.T, mock *mockBroadcaster) {
	t.Helper()
	orig := newBroadcaster
	newBroadcaster = func(ctx context.Context, rpcURL string) (internaltx.EthBroadcaster, error) {
		return mock, nil
	}
	t.Cleanup(func() { newBroadcaster = orig })
}

// newSendTestApp returns a minimal app with all subcommands.
func newSendTestApp() *ucli.Command {
	return &ucli.Command{
		Name:           "eth-deposit",
		Version:        "dev",
		Commands:       []*ucli.Command{buildCommand(), signCommand(), runCommand(), sendCommand()},
		ExitErrHandler: func(_ context.Context, _ *ucli.Command, _ error) {},
	}
}

const holeskyChainID = uint64(17000)
const fakeTxHash = "0xe00d2e5332902ab8638737b7e99df242306ee82838401f15f92eda9a64f9893a"

func TestSendCommand_HappyPath(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	withMockBroadcaster(t, &mockBroadcaster{
		BroadcasterChainIDFn: func(_ context.Context) (uint64, error) { return holeskyChainID, nil },
		SendRawTransactionFn: func(_ context.Context, _ string) (string, error) { return fakeTxHash, nil },
	})

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut

	err := app.Run(context.Background(), []string{
		"eth-deposit", "send",
		"--input", writeTempSignedTx(t),
		"--rpc-url", "http://localhost:8545",
		"--yes",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	outStr := out.String()
	if !strings.Contains(outStr, fakeTxHash) {
		t.Errorf("output missing tx hash; got: %s", outStr)
	}
	if !strings.Contains(outStr, "holesky.etherscan.io") {
		t.Errorf("output missing explorer URL; got: %s", outStr)
	}

	// Verify the confirmation prompt was printed to stderr with the expected fields.
	errStr := errOut.String()
	for _, want := range []string{"32.000000 ETH", "chain ID 17000", "holesky", "Broadcasting"} {
		if !strings.Contains(errStr, want) {
			t.Errorf("stderr prompt missing %q; got:\n%s", want, errStr)
		}
	}
}

func TestSendCommand_ConfirmPrompt_Accept(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	withMockBroadcaster(t, &mockBroadcaster{
		BroadcasterChainIDFn: func(_ context.Context) (uint64, error) { return holeskyChainID, nil },
		SendRawTransactionFn: func(_ context.Context, _ string) (string, error) { return fakeTxHash, nil },
	})

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut
	app.Reader = strings.NewReader("holesky\n")

	err := app.Run(context.Background(), []string{
		"eth-deposit", "send",
		"--input", writeTempSignedTx(t),
		"--rpc-url", "http://localhost:8545",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), fakeTxHash) {
		t.Errorf("output missing tx hash after accept; got: %s", out.String())
	}
}

func TestSendCommand_ConfirmPrompt_Reject(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	broadcastCalled := false
	withMockBroadcaster(t, &mockBroadcaster{
		BroadcasterChainIDFn: func(_ context.Context) (uint64, error) { return holeskyChainID, nil },
		SendRawTransactionFn: func(_ context.Context, _ string) (string, error) {
			broadcastCalled = true
			return fakeTxHash, nil
		},
	})

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut
	app.Reader = strings.NewReader("mainnet\n") // wrong network name

	err := app.Run(context.Background(), []string{
		"eth-deposit", "send",
		"--input", writeTempSignedTx(t),
		"--rpc-url", "http://localhost:8545",
	})
	if err == nil {
		t.Fatal("expected error for rejected confirmation, got nil")
	}
	if got := ExitCodeFor(err); got != 4 {
		t.Errorf("exit code = %d, want 4; err = %v", got, err)
	}
	if broadcastCalled {
		t.Error("broadcast should not have been called after rejection")
	}
}

func TestSendCommand_ConfirmPrompt_EOF(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	broadcastCalled := false
	withMockBroadcaster(t, &mockBroadcaster{
		BroadcasterChainIDFn: func(_ context.Context) (uint64, error) { return holeskyChainID, nil },
		SendRawTransactionFn: func(_ context.Context, _ string) (string, error) {
			broadcastCalled = true
			return fakeTxHash, nil
		},
	})

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut
	app.Reader = strings.NewReader("") // EOF immediately

	err := app.Run(context.Background(), []string{
		"eth-deposit", "send",
		"--input", writeTempSignedTx(t),
		"--rpc-url", "http://localhost:8545",
	})
	if err == nil {
		t.Fatal("expected error for EOF, got nil")
	}
	if got := ExitCodeFor(err); got != 4 {
		t.Errorf("exit code = %d, want 4; err = %v", got, err)
	}
	if broadcastCalled {
		t.Error("broadcast should not have been called after EOF")
	}
}

func TestSendCommand_ChainIDMismatch(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	// Fixture has chainID 17000 (holesky); mock returns chainID 1 (mainnet).
	withMockBroadcaster(t, &mockBroadcaster{
		BroadcasterChainIDFn: func(_ context.Context) (uint64, error) { return 1, nil },
		SendRawTransactionFn: func(_ context.Context, _ string) (string, error) {
			t.Error("broadcast should not be called on chain ID mismatch")
			return "", nil
		},
	})

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut

	err := app.Run(context.Background(), []string{
		"eth-deposit", "send",
		"--input", writeTempSignedTx(t),
		"--rpc-url", "http://localhost:8545",
		"--yes",
	})
	if err == nil {
		t.Fatal("expected error for chain ID mismatch, got nil")
	}
	if got := ExitCodeFor(err); got != 5 {
		t.Errorf("exit code = %d, want 5; err = %v", got, err)
	}
	if !errors.Is(err, internaltx.ErrBroadcastChainIDMismatch) {
		t.Errorf("expected ErrBroadcastChainIDMismatch; got: %v", err)
	}
}

func TestSendCommand_RPCFailure(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	rpcErr := fmt.Errorf("%w: node returned error", internaltx.ErrBroadcastFailed)
	withMockBroadcaster(t, &mockBroadcaster{
		BroadcasterChainIDFn: func(_ context.Context) (uint64, error) { return holeskyChainID, nil },
		SendRawTransactionFn: func(_ context.Context, _ string) (string, error) { return "", rpcErr },
	})

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut

	err := app.Run(context.Background(), []string{
		"eth-deposit", "send",
		"--input", writeTempSignedTx(t),
		"--rpc-url", "http://localhost:8545",
		"--yes",
	})
	if err == nil {
		t.Fatal("expected error for RPC failure, got nil")
	}
	if got := ExitCodeFor(err); got != 5 {
		t.Errorf("exit code = %d, want 5; err = %v", got, err)
	}
}

func TestSendCommand_MissingRPC(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut

	err := app.Run(context.Background(), []string{
		"eth-deposit", "send",
		"--input", writeTempSignedTx(t),
		// no --rpc-url
	})
	if err == nil {
		t.Fatal("expected error for missing --rpc-url, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
}

func TestSendCommand_InvalidInput(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	withMockBroadcaster(t, &mockBroadcaster{
		BroadcasterChainIDFn: func(_ context.Context) (uint64, error) { return holeskyChainID, nil },
		SendRawTransactionFn: func(_ context.Context, _ string) (string, error) { return fakeTxHash, nil },
	})

	badFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badFile, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut

	err := app.Run(context.Background(), []string{
		"eth-deposit", "send",
		"--input", badFile,
		"--rpc-url", "http://localhost:8545",
		"--yes",
	})
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
}

func TestSendCommand_BroadcastReceiptWrite(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	mockRec := &internaltx.Receipt{
		TransactionHash: fakeTxHash,
		Status:          1,
		BlockNumber:     12345,
		BlockHash:       "0xabc",
		GasUsed:         100000,
	}

	withMockBroadcaster(t, &mockBroadcaster{
		BroadcasterChainIDFn: func(_ context.Context) (uint64, error) { return holeskyChainID, nil },
		SendRawTransactionFn: func(_ context.Context, _ string) (string, error) { return fakeTxHash, nil },
		TransactionReceiptFn: func(_ context.Context, _ string) (*internaltx.Receipt, error) {
			return mockRec, nil
		},
	})

	recFile := filepath.Join(t.TempDir(), "receipt.json")

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut

	err := app.Run(context.Background(), []string{
		"eth-deposit", "send",
		"--input", writeTempSignedTx(t),
		"--rpc-url", "http://localhost:8545",
		"--yes",
		"--receipt-output", recFile,
		"--receipt-timeout", "5s",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(recFile)
	if err != nil {
		t.Fatalf("receipt file not written: %v", err)
	}
	var rec internaltx.Receipt
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("receipt file is not valid JSON: %v\n%s", err, data)
	}
	if rec.TransactionHash != fakeTxHash {
		t.Errorf("receipt.TransactionHash = %q, want %q", rec.TransactionHash, fakeTxHash)
	}
	if rec.BlockNumber != 12345 {
		t.Errorf("receipt.BlockNumber = %d, want 12345", rec.BlockNumber)
	}

	info, err := os.Stat(recFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("receipt file permissions = %04o, want 0600", perm)
	}
}

func TestSendCommand_ConfirmPrompt_CaseInsensitive(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	withMockBroadcaster(t, &mockBroadcaster{
		BroadcasterChainIDFn: func(_ context.Context) (uint64, error) { return holeskyChainID, nil },
		SendRawTransactionFn: func(_ context.Context, _ string) (string, error) { return fakeTxHash, nil },
	})

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut
	app.Reader = strings.NewReader("Holesky\n") // mixed case

	err := app.Run(context.Background(), []string{
		"eth-deposit", "send",
		"--input", writeTempSignedTx(t),
		"--rpc-url", "http://localhost:8545",
	})
	if err != nil {
		t.Fatalf("unexpected error for case-insensitive confirm: %v", err)
	}
}

func TestSendCommand_WaitForReceipt_Timeout(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	withMockBroadcaster(t, &mockBroadcaster{
		BroadcasterChainIDFn: func(_ context.Context) (uint64, error) { return holeskyChainID, nil },
		SendRawTransactionFn: func(_ context.Context, _ string) (string, error) { return fakeTxHash, nil },
		TransactionReceiptFn: func(_ context.Context, _ string) (*internaltx.Receipt, error) {
			return nil, nil // never mined
		},
	})

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut

	err := app.Run(context.Background(), []string{
		"eth-deposit", "send",
		"--input", writeTempSignedTx(t),
		"--rpc-url", "http://localhost:8545",
		"--yes",
		"--wait-for-receipt",
		"--receipt-timeout", "100ms",
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error should mention timeout; got: %v", err)
	}
}

func TestSendCommand_MissingInput(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut

	err := app.Run(context.Background(), []string{
		"eth-deposit", "send",
		"--rpc-url", "http://localhost:8545",
		"--yes",
	})
	if err == nil {
		t.Fatal("expected error for missing --input, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
}

func TestSendSubcommand_Help(t *testing.T) {
	app := newSendTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	_ = app.Run(context.Background(), []string{"eth-deposit", "send", "--help"})

	s := buf.String()
	if !strings.Contains(s, "rpc-url") {
		t.Errorf("send --help missing --rpc-url flag, got: %s", s)
	}
	if !strings.Contains(s, "yes") {
		t.Errorf("send --help missing --yes flag, got: %s", s)
	}
}

func TestSendCommand_RPCDialFailure(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	origNewBroadcaster := newBroadcaster
	newBroadcaster = func(ctx context.Context, rpcURL string) (internaltx.EthBroadcaster, error) {
		return nil, fmt.Errorf("%w: %s: connection refused", internaltx.ErrRPCDial, rpcURL)
	}
	t.Cleanup(func() { newBroadcaster = origNewBroadcaster })

	app := newSendTestApp()
	var out, errOut bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &errOut

	err := app.Run(context.Background(), []string{
		"eth-deposit", "send",
		"--input", writeTempSignedTx(t),
		"--rpc-url", "http://localhost:9999",
		"--yes",
	})
	if err == nil {
		t.Fatal("expected error for dial failure, got nil")
	}
	if got := ExitCodeFor(err); got != 5 {
		t.Errorf("exit code = %d, want 5; err = %v", got, err)
	}
}
