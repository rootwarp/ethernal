package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ucli "github.com/urfave/cli/v3"
)

// TestBuild_GoldenOutput compares the exact JSON produced by build (with default
// gas/nonce params) against testdata/unsigned-tx-golden.json.
// Set UPDATE_GOLDEN=1 to regenerate the golden file.
func TestBuild_GoldenOutput(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(code int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	fixture := fixtureAbsPath(t)

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out

	err := app.Run(context.Background(), []string{
		"eth-deposit", "build",
		"--network", "holesky",
		"--input-file", fixture,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	goldenPath := filepath.Join("testdata", "unsigned-tx-golden.json")

	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(goldenPath, out.Bytes(), 0o644); err != nil {
			t.Fatalf("could not update golden file: %v", err)
		}
		t.Logf("golden file updated: %s", goldenPath)
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("could not read golden file %s: %v (run with UPDATE_GOLDEN=1 to create it)", goldenPath, err)
	}

	got := out.Bytes()
	if !bytes.Equal(got, want) {
		t.Errorf("golden mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestMain_BuildsCleanly(t *testing.T) {
	cmd := exec.Command("go", "build", "-o", "/dev/null", ".")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build ./cmd/eth-deposit failed: %v\n%s", err, output)
	}
}

func TestApp_Help(t *testing.T) {
	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	_ = app.Run(context.Background(), []string{"eth-deposit", "--help"})

	s := buf.String()
	if !strings.Contains(s, "eth-deposit") {
		t.Errorf("help output missing app name")
	}
	if !strings.Contains(s, "build") || !strings.Contains(s, "sign") || !strings.Contains(s, "run") {
		t.Errorf("help output missing expected subcommands build/sign/run")
	}
}

func TestApp_Version(t *testing.T) {
	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	_ = app.Run(context.Background(), []string{"eth-deposit", "--version"})

	s := buf.String()
	if !strings.Contains(s, "dev") && !strings.Contains(s, "eth-deposit") {
		t.Errorf("version output unexpected: %s", s)
	}
}

func TestBuildSubcommand_Help(t *testing.T) {
	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	_ = app.Run(context.Background(), []string{"eth-deposit", "build", "--help"})

	s := buf.String()
	if !strings.Contains(s, "input-file") {
		t.Errorf("build --help missing expected flag, got: %s", s)
	}
}

func TestSignSubcommand_Help(t *testing.T) {
	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	_ = app.Run(context.Background(), []string{"eth-deposit", "sign", "--help"})

	s := buf.String()
	if !strings.Contains(s, "signer") {
		t.Errorf("sign --help missing expected --signer flag, got: %s", s)
	}
	if !strings.Contains(s, "ledger") {
		t.Errorf("sign --help missing ledger mention, got: %s", s)
	}
}

func TestBuildSubcommand_Action_Success(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(code int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	fixture := fixtureAbsPath(t)

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out

	err := app.Run(context.Background(), []string{"eth-deposit", "build", "--network", "holesky", "--input-file", fixture})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var tx map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &tx); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out.String())
	}
	for _, field := range []string{"chainId", "to", "value", "data", "gas", "maxFeePerGas", "maxPriorityFeePerGas", "nonce", "type"} {
		if _, ok := tx[field]; !ok {
			t.Errorf("output JSON missing field %q", field)
		}
	}
	if tx["type"] != "0x2" {
		t.Errorf("type: got %v, want 0x2", tx["type"])
	}
	if data, _ := tx["data"].(string); !strings.HasPrefix(data, "0x22895118") {
		t.Errorf("data must start with deposit() selector, got: %s", data)
	}
}

func TestBuildSubcommand_Action_StdinInput(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(code int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	fixture := fixtureAbsPath(t)
	rawData, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out
	app.Reader = bytes.NewReader(rawData)

	err = app.Run(context.Background(), []string{"eth-deposit", "build", "--network", "holesky", "--input-file", "-"})
	if err != nil {
		t.Fatalf("stdin input: unexpected error: %v", err)
	}
	if !json.Valid(out.Bytes()) {
		t.Errorf("stdin input: output is not valid JSON: %s", out.String())
	}
}

func TestBuildSubcommand_Action_StdoutDefault(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(code int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	fixture := fixtureAbsPath(t)

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out

	// No --output flag: output goes to stdout (app.Writer)
	err := app.Run(context.Background(), []string{"eth-deposit", "build", "--network", "holesky", "--input-file", fixture})
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(out.Bytes()) {
		t.Errorf("stdout default: output is not valid JSON: %s", out.String())
	}
}

func TestBuildSubcommand_Action_OutputToFile(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(code int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	fixture := fixtureAbsPath(t)
	outFile := filepath.Join(t.TempDir(), "unsigned.json")

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{"eth-deposit", "build", "--network", "holesky",
		"--input-file", fixture, "--output", outFile})
	if err != nil {
		t.Fatalf("output to file: unexpected error: %v", err)
	}
	written, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("could not read output file: %v", err)
	}
	if !json.Valid(written) {
		t.Errorf("output file: not valid JSON: %s", string(written))
	}
}

func TestBuildSubcommand_Action_MissingInputFile(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(code int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{"eth-deposit", "build", "--network", "holesky",
		"--input-file", "/nonexistent/path/deposit.json"})
	if err == nil {
		t.Fatal("expected error for missing input file, got nil")
	}
}

func TestBuildSubcommand_Action_InvalidJSON(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(code int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	badFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badFile, []byte("not json at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{"eth-deposit", "build", "--network", "holesky", "--input-file", badFile})
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestBuildSubcommand_Action_IndexOutOfBounds(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(code int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	fixture := fixtureAbsPath(t)

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	// fixture has 1 entry (index 0); request index 5
	err := app.Run(context.Background(), []string{"eth-deposit", "build", "--network", "holesky",
		"--input-file", fixture, "--index", "5"})
	if err == nil {
		t.Fatal("expected error for out-of-bounds index, got nil")
	}
}

func TestBuildSubcommand_Action_BadNetwork(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(code int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out

	err := app.Run(context.Background(), []string{"eth-deposit", "build", "--network", "badnet", "--input-file", "deposit.json"})
	if err == nil {
		t.Fatal("expected error for unknown network, got nil")
	}
}

func TestBuildSubcommand_InputAlias(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(code int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &bytes.Buffer{}

	// --input is an alias for --input-file on build.
	err := app.Run(context.Background(), []string{
		"eth-deposit", "build",
		"--network", "holesky",
		"--input", fixtureAbsPath(t),
	})
	if err != nil {
		t.Fatalf("--input alias: unexpected error: %v", err)
	}
	if !json.Valid(out.Bytes()) {
		t.Errorf("--input alias: output is not valid JSON: %s", out.String())
	}
}

func TestBuildSubcommand_Action_OutputDash_IsStdout(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(code int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	fixture := fixtureAbsPath(t)

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &bytes.Buffer{}

	err := app.Run(context.Background(), []string{
		"eth-deposit", "build",
		"--network", "holesky",
		"--input-file", fixture,
		"--output", "-",
	})
	if err != nil {
		t.Fatalf("--output -: unexpected error: %v", err)
	}
	if !json.Valid(out.Bytes()) {
		t.Errorf("--output -: output is not valid JSON: %s", out.String())
	}
}

// newTestApp returns a minimal app instance for testing (avoids side effects of the real main).
func newTestApp() *ucli.Command {
	return &ucli.Command{
		Name:     "eth-deposit",
		Usage:    "Create and sign Ethereum deposit transactions from deposit data JSON",
		Version:  "dev",
		Commands: []*ucli.Command{buildCommand(), signCommand(), runCommand()},
	}
}

// fixtureAbsPath returns the absolute path to the shared test deposit fixture.
func fixtureAbsPath(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("testdata/deposit-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// TestBuild_RPCURL_StillRejected verifies M0.7-8a reject path is unchanged for build (M1.3-5 AC).
// run is the only path that wires --rpc-url (hybrid).
func TestBuild_RPCURL_StillRejected(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run([]string{
		"eth-deposit-tx", "build",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--rpc-url", "http://example.invalid",
	})
	if err == nil {
		t.Fatal("expected build --rpc-url to be rejected, got nil")
	}
	if code := ExitCodeFor(err); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(err.Error(), "reserved for v1") {
		t.Errorf("error should contain reject guidance: %v", err)
	}
}
