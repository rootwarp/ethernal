package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	ucli "github.com/urfave/cli/v3"

	"github.com/rootwarp/eth-utils/go/internal/signer"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
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
		"eth-deposit-tx", "sign",
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
		"eth-deposit-tx", "sign",
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
		"eth-deposit-tx", "sign",
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
		"eth-deposit-tx", "sign",
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
		"eth-deposit-tx", "sign",
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
		"eth-deposit-tx", "sign",
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
		"eth-deposit-tx", "sign",
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
		"eth-deposit-tx", "sign",
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
	// Ledger support requires a real device and CGO build (module is CGO-only via herumi).
	// This path always yields ErrNoDevice without hardware.
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
		"eth-deposit-tx", "sign",
		"--signer", "ledger",
		"--input", inFile,
	})
	if err == nil {
		t.Fatal("expected error for ledger with no device, got nil")
	}
	// Without real hardware: ErrNoDevice (exit 3).
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
		"eth-deposit-tx", "sign",
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
		"eth-deposit-tx", "sign",
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
		"eth-deposit-tx", "sign",
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
		"eth-deposit-tx", "sign",
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
		"eth-deposit-tx", "sign",
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

// TestSign_NonDepositRecipient_WithOverride_Allowed: override flag set + non-deposit `To` → no exit-2 reject.
// (exact AC name per M0.6-2 plan; follows M0.6-1 parse test + sign cmd style; uses errors.Is)
func TestSign_NonDepositRecipient_WithOverride_Allowed(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_SIGN_NONDEPOSIT_OVERRIDE_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	// Build unsigned JSON with valid 42-hex To that is NOT the deposit contract for chainId=17000 (holesky).
	var u map[string]interface{}
	if err := json.Unmarshal(unsignedTxJSON(), &u); err != nil {
		t.Fatal(err)
	}
	u["to"] = "0x00000000219ab540356cBB839Cbe05303d7705Fa" // mainnet/hoodi contract (valid hex/len)
	badJSON, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	badJSON = append(badJSON, '\n')

	inFile := filepath.Join(t.TempDir(), "unsigned-non-deposit.json")
	if err := os.WriteFile(inFile, badJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &bytes.Buffer{}

	err = app.Run([]string{
		"eth-deposit-tx", "sign",
		"--signer", "local",
		"--input", inFile,
		"--output", "-",
		"--private-key-env", envVar,
		"--allow-non-deposit-recipient",
	})
	if err != nil {
		t.Fatalf("with --allow-non-deposit-recipient, expected success for non-deposit To, got err: %v", err)
	}
	if !json.Valid(out.Bytes()) {
		t.Errorf("signed output not valid JSON with override: %s", out.String())
	}
}

// TestSign_NonDepositRecipient_NoOverride_Reject: override absent → exit 2.
// (exact AC name; errors.Is on sentinel; exit via ExitCodeFor per cmd contract)
func TestSign_NonDepositRecipient_NoOverride_Reject(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	envVar := "TEST_SIGN_NONDEPOSIT_NOOVERRIDE_" + randomSuffix(t)
	t.Setenv(envVar, "0x"+generateTestPrivKey(t))

	// Same non-deposit To as above.
	var u map[string]interface{}
	if err := json.Unmarshal(unsignedTxJSON(), &u); err != nil {
		t.Fatal(err)
	}
	u["to"] = "0x00000000219ab540356cBB839Cbe05303d7705Fa"
	badJSON, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	badJSON = append(badJSON, '\n')

	inFile := filepath.Join(t.TempDir(), "unsigned-non-deposit.json")
	if err := os.WriteFile(inFile, badJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err = app.Run([]string{
		"eth-deposit-tx", "sign",
		"--signer", "local",
		"--input", inFile,
		"--private-key-env", envVar,
		// deliberately no --allow-non-deposit-recipient
	})
	if err == nil {
		t.Fatal("expected error for non-deposit To without override, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
	if !errors.Is(err, signer.ErrInvalidToAddress) {
		t.Fatalf("expected errors.Is(ErrInvalidToAddress), got %v", err)
	}
}

// TestLoadSignConfig_RejectKeyValueNoLeak (architecture §11.7): set --private-key-env to a known sentinel string (simulating key value); error message contains only the redacted form; full string not present. Also verifies "treat as compromised" warning on stderr.
func TestLoadSignConfig_RejectKeyValueNoLeak(t *testing.T) {
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

	sentinel := "0x" + generateTestPrivKey(t)
	err := app.Run([]string{
		"eth-deposit-tx", "sign",
		"--signer", "local",
		"--input", inFile,
		"--private-key-env", sentinel,
	})
	if err == nil {
		t.Fatal("expected error for key value as --private-key-env, got nil")
	}
	if got := ExitCodeFor(err); got != 2 {
		t.Errorf("exit code = %d, want 2; err = %v", got, err)
	}
	errStr := err.Error()
	if strings.Contains(errStr, sentinel) {
		t.Errorf("full sentinel key leaked into error: %s", errStr)
	}
	if !strings.Contains(errStr, "… (len=") {
		t.Errorf("redacted form missing from error: %s", errStr)
	}
	if !strings.Contains(buf.String(), "treated as compromised") {
		t.Errorf("warning not visible on stderr: %s", buf.String())
	}
}

// TestSignUnsignedTx_UnsupportedSigner_ErrInvalidInput (equivalent to
// TestSignUnsignedTx_UnknownSigner_NoPanic_ErrInvalidInput per issue AC in
// m1.5-cli-contract-exit-codes.md:115) covers the switch default in
// signUnsignedTx (M1.5-5 / FR-P1-F5 / GO-051): unknown cfg.Signer yields
// ErrInvalidInput (so ExitCodeFor gives 2) with no nil-interface panic on the
// deferred Close or later uses. Happy paths for "local"/"ledger" are unchanged
// (existing tests). Direct call to the extracted func per M1.5 patterns.
func TestSignUnsignedTx_UnsupportedSigner_ErrInvalidInput(t *testing.T) {
	_, err := signUnsignedTx(context.Background(), &SignConfig{Signer: "unsupported"}, nil, internaltx.UnsignedTx{})
	if err == nil {
		t.Fatal("expected error for unsupported signer, got nil")
	}
	if got := errors.Is(err, ErrInvalidInput); !got {
		t.Fatalf("errors.Is(err, ErrInvalidInput) = %v, want true (err=%v)", got, err)
	}
}
