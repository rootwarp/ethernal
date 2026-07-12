package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	ucli "github.com/urfave/cli/v3"

	"github.com/rootwarp/eth-utils/go/internal/signer"
)

// generateTestPrivKey returns a fresh random secp256k1 private key as hex (no 0x prefix).
func generateTestPrivKey(t *testing.T) string {
	t.Helper()
	key, err := gethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generateTestPrivKey: %v", err)
	}
	return hex.EncodeToString(gethcrypto.FromECDSA(key))
}

// unsignedTxJSON returns JSON for a valid UnsignedTx (Holesky chainId=17000).
func unsignedTxJSON() []byte {
	raw, _ := os.ReadFile(filepath.Join("testdata", "unsigned-tx-golden.json"))
	return raw
}

func TestSignCommand_LocalSigner_Success(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_SIGN_KEY_SUCCESS_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	inFile := filepath.Join(t.TempDir(), "unsigned.json")
	if err := os.WriteFile(inFile, unsignedTxJSON(), 0o644); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(t.TempDir(), "signed.json")

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "local",
		"--input", inFile,
		"--output", outFile,
		"--private-key-env", envVar,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output file not written: %v", err)
	}

	var signed map[string]interface{}
	if err := json.Unmarshal(data, &signed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, data)
	}
	for _, field := range []string{"unsigned", "from", "hash", "r", "s", "v", "rawRLP"} {
		if _, ok := signed[field]; !ok {
			t.Errorf("output JSON missing field %q", field)
		}
	}
}

func TestSignCommand_LocalSigner_MissingEnvKey(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_SIGN_KEY_MISSING_" + randomSuffix(t)
	// intentionally not set

	inFile := filepath.Join(t.TempDir(), "unsigned.json")
	if err := os.WriteFile(inFile, unsignedTxJSON(), 0o644); err != nil {
		t.Fatal(err)
	}

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "local",
		"--input", inFile,
		"--private-key-env", envVar,
	})
	if err == nil {
		t.Fatal("expected error for missing env key, got nil")
	}
	if got := ExitCodeFor(err); got != 3 {
		t.Errorf("exit code = %d, want 3; err = %v", got, err)
	}
	if !strings.Contains(err.Error(), envVar) {
		t.Errorf("error should mention env var name %q; got: %v", envVar, err)
	}
}

func TestSignCommand_LocalSigner_BadKey(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_SIGN_KEY_BAD_" + randomSuffix(t)
	badKey := "0xdeadbeefnotahexkey"
	t.Setenv(envVar, badKey)

	inFile := filepath.Join(t.TempDir(), "unsigned.json")
	if err := os.WriteFile(inFile, unsignedTxJSON(), 0o644); err != nil {
		t.Fatal(err)
	}

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "local",
		"--input", inFile,
		"--private-key-env", envVar,
	})
	if err == nil {
		t.Fatal("expected error for bad key, got nil")
	}
	if got := ExitCodeFor(err); got != 3 {
		t.Errorf("exit code = %d, want 3; err = %v", got, err)
	}
	// Error must not contain the raw key bytes.
	if strings.Contains(err.Error(), "deadbeef") {
		t.Errorf("error message must not contain key material: %v", err)
	}
}

func TestSignCommand_InvalidSigner(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	inFile := filepath.Join(t.TempDir(), "unsigned.json")
	if err := os.WriteFile(inFile, unsignedTxJSON(), 0o644); err != nil {
		t.Fatal(err)
	}

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "foo",
		"--input", inFile,
	})
	if err == nil {
		t.Fatal("expected error for invalid signer, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
}

func TestSignCommand_MissingInput(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "local",
		// no --input
	})
	if err == nil {
		t.Fatal("expected error for missing --input, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
}

func TestSignCommand_InvalidInputJSON(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_SIGN_KEY_BADINPUT_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	badFile := filepath.Join(t.TempDir(), "garbage.json")
	if err := os.WriteFile(badFile, []byte("this is not json at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "local",
		"--input", badFile,
		"--private-key-env", envVar,
	})
	if err == nil {
		t.Fatal("expected error for invalid input JSON, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
}

func TestSignCommand_LocalSigner_StdinInput(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_SIGN_KEY_STDIN_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	outFile := filepath.Join(t.TempDir(), "signed.json")

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out
	app.Reader = bytes.NewReader(unsignedTxJSON())

	err := app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "local",
		"--input", "-",
		"--output", outFile,
		"--private-key-env", envVar,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output file not written: %v", err)
	}
	if !json.Valid(data) {
		t.Errorf("output is not valid JSON: %s", data)
	}
}

func TestSignCommand_LocalSigner_StdoutOutput(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_SIGN_KEY_STDOUT_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	inFile := filepath.Join(t.TempDir(), "unsigned.json")
	if err := os.WriteFile(inFile, unsignedTxJSON(), 0o644); err != nil {
		t.Fatal(err)
	}

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &bytes.Buffer{}

	err := app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "local",
		"--input", inFile,
		// no --output — should write to stdout
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
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if _, ok := signed["rawRLP"]; !ok {
		t.Error("stdout JSON missing field rawRLP")
	}
}

func TestSignCommand_Ledger_NotSupported_OnCGOPath(t *testing.T) {
	// Ledger support requires a real device and CGO build; this path always
	// yields an error (ErrNoDevice or ErrLedgerNotSupported) without hardware.
	// We verify the error is non-nil and exit code 3 is returned.
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	inFile := filepath.Join(t.TempDir(), "unsigned.json")
	if err := os.WriteFile(inFile, unsignedTxJSON(), 0o644); err != nil {
		t.Fatal(err)
	}

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "ledger",
		"--input", inFile,
	})
	if err == nil {
		t.Fatal("expected error for ledger with no device, got nil")
	}
	// Without real hardware: ErrNoDevice or ErrLedgerNotSupported — both exit 3.
	// If by some chance we're on non-CGO, ErrLedgerNotSupported → exit 3 too.
	code := ExitCodeFor(err)
	if code != 3 {
		t.Errorf("exit code = %d, want 3; err = %v", code, err)
	}
	_ = signer.ErrNoDevice // just to ensure the import is used
}

func TestSignCommand_InvalidEnvVarName_Lowercase(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	inFile := filepath.Join(t.TempDir(), "unsigned.json")
	if err := os.WriteFile(inFile, unsignedTxJSON(), 0o644); err != nil {
		t.Fatal(err)
	}

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "local",
		"--input", inFile,
		"--private-key-env", "my_lowercase_var",
	})
	if err == nil {
		t.Fatal("expected error for lowercase env var name, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
}

func TestSignCommand_InvalidEnvVarName_KeyPassedDirectly(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	inFile := filepath.Join(t.TempDir(), "unsigned.json")
	if err := os.WriteFile(inFile, unsignedTxJSON(), 0o644); err != nil {
		t.Fatal(err)
	}

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	// Simulate user accidentally passing the actual hex key as the env var name.
	err := app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "local",
		"--input", inFile,
		"--private-key-env", "0x" + generateTestPrivKey(t),
	})
	if err == nil {
		t.Fatal("expected error when hex key passed as env var name, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
	if !strings.Contains(err.Error(), "POSIX") {
		t.Errorf("error should mention POSIX; got: %v", err)
	}
}

func TestSignCommand_OutputWriteError_Exit2(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_SIGN_KEY_WRITEERR_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	inFile := filepath.Join(t.TempDir(), "unsigned.json")
	if err := os.WriteFile(inFile, unsignedTxJSON(), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a read-only directory; writing a file inside it should fail.
	roDir := filepath.Join(t.TempDir(), "readonly")
	if err := os.MkdirAll(roDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) }) // restore for cleanup
	outFile := filepath.Join(roDir, "signed.json")

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "local",
		"--input", inFile,
		"--output", outFile,
		"--private-key-env", envVar,
	})
	if err == nil {
		t.Fatal("expected error for unwritable output file, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
}

func TestSignCommand_OutputFilePermissions(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_SIGN_KEY_PERM_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	inFile := filepath.Join(t.TempDir(), "unsigned.json")
	if err := os.WriteFile(inFile, unsignedTxJSON(), 0o644); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(t.TempDir(), "signed.json")

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err := app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "local",
		"--input", inFile,
		"--output", outFile,
		"--private-key-env", envVar,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatalf("could not stat output file: %v", err)
	}
	// Must be 0o600 (owner read/write only).
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("output file permissions = %04o, want 0600", perm)
	}
}

func TestSignCommand_OutputDash_IsStdout(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_SIGN_KEY_DASH_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	inFile := filepath.Join(t.TempDir(), "unsigned.json")
	if err := os.WriteFile(inFile, unsignedTxJSON(), 0o644); err != nil {
		t.Fatal(err)
	}

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &bytes.Buffer{}

	err := app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "local",
		"--input", inFile,
		"--output", "-",
		"--private-key-env", envVar,
	})
	if err != nil {
		t.Fatalf("--output -: unexpected error: %v", err)
	}

	if !json.Valid(out.Bytes()) {
		t.Errorf("--output -: output is not valid JSON: %s", out.String())
	}

	var signed map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &signed); err != nil {
		t.Fatalf("stdout JSON parse failed: %v", err)
	}
	if _, ok := signed["rawRLP"]; !ok {
		t.Error("stdout JSON missing field rawRLP")
	}
}

// randomSuffix returns a short random hex string for unique env var names.
func randomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return strings.ToUpper(hex.EncodeToString(b))
}
