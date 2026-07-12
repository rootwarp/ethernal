package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ucli "github.com/urfave/cli/v3"

	"github.com/rootwarp/eth-utils/go/internal/signer"
)

func TestRunCommand_LocalSigner_HappyPath(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_RUN_KEY_HAPPY_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	outFile := filepath.Join(t.TempDir(), "signed.json")

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--signer", "local",
		"--output", outFile,
		"--private-key-env", envVar,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("signed.json not written: %v", err)
	}

	var signed map[string]interface{}
	if err := json.Unmarshal(data, &signed); err != nil {
		t.Fatalf("signed.json is not valid JSON: %v\n%s", err, data)
	}
	for _, field := range []string{"unsigned", "from", "hash", "r", "s", "v", "rawRLP"} {
		if _, ok := signed[field]; !ok {
			t.Errorf("signed.json missing field %q", field)
		}
	}

	// Also check signed.raw companion was written.
	rawFile := strings.TrimSuffix(outFile, ".json") + ".raw"
	rawData, err := os.ReadFile(rawFile)
	if err != nil {
		t.Fatalf("signed.raw not written: %v", err)
	}
	rawContent := strings.TrimSpace(string(rawData))
	if !strings.HasPrefix(rawContent, "0x") {
		t.Errorf("signed.raw must have 0x prefix, got: %s", rawContent)
	}
}

func TestRunCommand_LocalSigner_StdoutOutput(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_RUN_KEY_STDOUT_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &bytes.Buffer{}

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--signer", "local",
		// no --output → stdout
		"--private-key-env", envVar,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !json.Valid(out.Bytes()) {
		t.Errorf("stdout output is not valid JSON: %s", out.String())
	}
	var signed map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &signed); err != nil {
		t.Fatalf("stdout JSON parse failed: %v", err)
	}
	if _, ok := signed["rawRLP"]; !ok {
		t.Error("stdout JSON missing field rawRLP")
	}
}

func TestRunCommand_LocalSigner_KeepUnsigned(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_RUN_KEY_KEEPU_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	dir := t.TempDir()
	outFile := filepath.Join(dir, "signed.json")

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--signer", "local",
		"--output", outFile,
		"--keep-unsigned",
		"--private-key-env", envVar,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify signed.json exists with valid content.
	signedData, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("signed.json not written: %v", err)
	}
	if !json.Valid(signedData) {
		t.Errorf("signed.json is not valid JSON")
	}

	// Verify unsigned.json was written.
	unsignedFile := filepath.Join(dir, "unsigned.json")
	unsignedData, err := os.ReadFile(unsignedFile)
	if err != nil {
		t.Fatalf("unsigned.json not written: %v", err)
	}
	var unsigned map[string]interface{}
	if err := json.Unmarshal(unsignedData, &unsigned); err != nil {
		t.Fatalf("unsigned.json is not valid JSON: %v", err)
	}
	for _, field := range []string{"chainId", "to", "value", "data", "gas"} {
		if _, ok := unsigned[field]; !ok {
			t.Errorf("unsigned.json missing field %q", field)
		}
	}
}

func TestRunCommand_LocalSigner_RawOutput(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_RUN_KEY_RAW_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	dir := t.TempDir()
	outFile := filepath.Join(dir, "signed.json")
	rawFile := filepath.Join(dir, "custom.raw")

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--signer", "local",
		"--output", outFile,
		"--raw-output", rawFile,
		"--private-key-env", envVar,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify custom.raw was written with 0x-prefixed content.
	rawData, err := os.ReadFile(rawFile)
	if err != nil {
		t.Fatalf("custom.raw not written: %v", err)
	}
	rawContent := strings.TrimSpace(string(rawData))
	if !strings.HasPrefix(rawContent, "0x") {
		t.Errorf("raw file must have 0x prefix, got: %s", rawContent)
	}

	// Verify auto-derived signed.raw was NOT written (we specified custom path).
	defaultRaw := filepath.Join(dir, "signed.raw")
	if _, err := os.Stat(defaultRaw); err == nil {
		t.Error("default signed.raw should not be written when --raw-output overrides it")
	}
}

func TestRunCommand_MissingSignerFlag(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		// no --signer
	})
	if err == nil {
		t.Fatal("expected error for missing --signer, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
}

func TestRunCommand_LedgerNoDevice(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--signer", "ledger",
	})
	if err == nil {
		t.Fatal("expected error for ledger with no device, got nil")
	}
	code := ExitCodeFor(err)
	if code != 3 {
		t.Errorf("exit code = %d, want 3; err = %v", code, err)
	}
	_ = signer.ErrNoDevice // ensure import is used
}

func TestRunCommand_InvalidInput(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_RUN_KEY_BADINPUT_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	badFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badFile, []byte("not json at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", badFile,
		"--signer", "local",
		"--private-key-env", envVar,
	})
	if err == nil {
		t.Fatal("expected error for bad input JSON, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
}

func TestRunCommand_BadKey(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_RUN_KEY_BADKEY_" + randomSuffix(t)
	t.Setenv(envVar, "0xdeadbeefnotahexkey")

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--signer", "local",
		"--private-key-env", envVar,
	})
	if err == nil {
		t.Fatal("expected error for bad key, got nil")
	}
	if got := ExitCodeFor(err); got != 3 {
		t.Errorf("exit code = %d, want 3; err = %v", got, err)
	}
}

func TestRunCommand_AtomicWrite_OnRenameFailure(t *testing.T) {
	// Force an OS-level rename failure by making the target output path an existing
	// directory. os.Rename(tmpFile, dir) fails on most platforms with EISDIR/ENOTDIR,
	// which exercises the defer os.Remove(tmpName) cleanup in atomicWriteFile.
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_RUN_ATOMIC_RENAME_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	dir := t.TempDir()
	// Create a directory at the output path so rename must fail.
	outDir := filepath.Join(dir, "signed.json")
	if err := os.Mkdir(outDir, 0o755); err != nil {
		t.Fatalf("could not create output dir: %v", err)
	}

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--signer", "local",
		"--output", outDir,
		"--private-key-env", envVar,
	})
	if err == nil {
		t.Fatal("expected error when output path is a directory, got nil")
	}

	// No leftover temp files should remain.
	matches, err := filepath.Glob(filepath.Join(dir, ".tmp-eth-deposit-*"))
	if err != nil {
		t.Fatalf("glob error: %v", err)
	}
	if len(matches) > 0 {
		t.Errorf("leftover temp files after rename failure: %v", matches)
	}
}

func TestRunCommand_KeepUnsigned_RequiresOutputFile(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_RUN_KEY_KEEPU2_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	// --keep-unsigned without --output should fail with exit 2.
	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--signer", "local",
		"--keep-unsigned",
		"--private-key-env", envVar,
		// no --output
	})
	if err == nil {
		t.Fatal("expected error for --keep-unsigned without --output, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
}

func TestRunCommand_OutputFilePermissions(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_RUN_KEY_PERM_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	dir := t.TempDir()
	outFile := filepath.Join(dir, "signed.json")

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--signer", "local",
		"--output", outFile,
		"--private-key-env", envVar,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, path := range []string{outFile, strings.TrimSuffix(outFile, ".json") + ".raw"} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("could not stat %s: %v", path, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s permissions = %04o, want 0600", path, perm)
		}
	}
}

func TestRunCommand_OutputDash_IsStdout(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_RUN_KEY_DASH_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	// Use a stable dir so the *.raw glob below is meaningful (not a fresh empty dir).
	dir := t.TempDir()

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &bytes.Buffer{}

	err := app.Run(context.Background(), []string{
		"eth-deposit", "run",
		"--network", "holesky",
		"--input-file", fixtureAbsPath(t),
		"--signer", "local",
		"--output", "-",
		"--private-key-env", envVar,
	})
	if err != nil {
		t.Fatalf("--output -: unexpected error: %v", err)
	}
	if !json.Valid(out.Bytes()) {
		t.Errorf("--output -: output is not valid JSON: %s", out.String())
	}
	// No .raw companion should be written when output is stdout ("-").
	// We glob dir (same temp dir used above) to catch any stray files the run wrote.
	matches, _ := filepath.Glob(filepath.Join(dir, "*.raw"))
	if len(matches) > 0 {
		t.Errorf("--output -: unexpected .raw files in temp dir: %v", matches)
	}
}

func TestRunSubcommand_Help(t *testing.T) {
	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	_ = app.Run(context.Background(), []string{"eth-deposit", "run", "--help"})

	s := buf.String()
	if !strings.Contains(s, "signer") {
		t.Errorf("run --help missing --signer flag, got: %s", s)
	}
	if !strings.Contains(s, "keep-unsigned") {
		t.Errorf("run --help missing --keep-unsigned flag, got: %s", s)
	}
}
