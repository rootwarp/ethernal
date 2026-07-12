package cli_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ucli "github.com/urfave/cli/v3"

	blspkg "github.com/rootwarp/eth-utils/go/internal/bls"
	icli "github.com/rootwarp/eth-utils/go/internal/cli"
	"github.com/rootwarp/eth-utils/go/internal/network"
)

// validPubkey and validPubkey2 hold real BLS12-381 G1 compressed points, initialised
// in TestMain from known fixed secrets so they pass ValidatePubkeyBytes.
var (
	validPubkey  string
	validPubkey2 string
)

func TestMain(m *testing.M) {
	if err := blspkg.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "bls.Init: %v\n", err)
		os.Exit(1)
	}
	// Derive pubkeys from two known fixed secrets.
	secret1 := make([]byte, 32)
	secret1[0] = 1
	s1, err := blspkg.NewSigner(secret1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bls.NewSigner(1): %v\n", err)
		os.Exit(1)
	}
	pub1, err := s1.PublicKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "PublicKey(1): %v\n", err)
		os.Exit(1)
	}
	validPubkey = fmt.Sprintf("%x", pub1[:])

	secret2 := make([]byte, 32)
	secret2[0] = 2
	s2, err := blspkg.NewSigner(secret2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bls.NewSigner(2): %v\n", err)
		os.Exit(1)
	}
	pub2, err := s2.PublicKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "PublicKey(2): %v\n", err)
		os.Exit(1)
	}
	validPubkey2 = fmt.Sprintf("%x", pub2[:])

	os.Exit(m.Run())
}

// runApp is a helper that invokes the app with the given args and captures stderr.
// It returns the Config received by the run callback (if called), stderr output, and any error.
// ExitErrHandler is overridden to prevent os.Exit from being called during tests.
func runApp(t *testing.T, args []string) (cfg icli.Config, stderr string, runCalled bool, err error) {
	t.Helper()

	var errBuf bytes.Buffer
	var capturedCfg icli.Config
	called := false

	app := icli.NewApp(func(ctx context.Context, c icli.Config) error {
		capturedCfg = c
		called = true
		return nil
	})
	app.Writer = io.Discard // suppress urfave/cli help text on required-flag errors
	app.ErrWriter = &errBuf
	// Suppress os.Exit during tests: ExitErrHandler is called by urfave/cli
	// when an ExitCoder error is returned from Action. We override it so that
	// the error propagates back to the caller instead of calling os.Exit.
	app.ExitErrHandler = func(_ context.Context, _ *ucli.Command, _ error) {}

	fullArgs := append([]string{"eth-deposit"}, args...)
	err = app.Run(context.Background(), fullArgs)
	return capturedCfg, errBuf.String(), called, err
}

// TestMissingRequiredFlags verifies that omitting each required flag returns an error.
func TestMissingRequiredFlags(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir() // a real directory for --keystore-dir

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "missing_keystore_dir",
			args:    []string{"--pubkeys", "0x" + validPubkey, "--network", "hoodi", "--output-dir", dir},
			wantErr: true,
		},
		{
			name:    "missing_pubkeys",
			args:    []string{"--keystore-dir", ksDir, "--network", "hoodi", "--output-dir", dir},
			wantErr: true,
		},
		{
			name:    "missing_network",
			args:    []string{"--keystore-dir", ksDir, "--pubkeys", "0x" + validPubkey, "--output-dir", dir},
			wantErr: true,
		},
		{
			name:    "missing_output_dir",
			args:    []string{"--keystore-dir", ksDir, "--pubkeys", "0x" + validPubkey, "--network", "hoodi"},
			wantErr: true,
		},
		{
			name:    "all_required_flags_present",
			args:    []string{"--keystore-dir", ksDir, "--pubkeys", "0x" + validPubkey, "--network", "hoodi", "--output-dir", dir},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := runApp(t, tc.args)
			if tc.wantErr && err == nil {
				t.Errorf("runApp(%v) error = nil, want error", tc.args)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("runApp(%v) error = %v, want nil", tc.args, err)
			}
		})
	}
}

// TestInvalidNetwork verifies that an unknown --network value returns an error before run is called.
func TestInvalidNetwork(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()

	tests := []struct {
		network string
		wantErr bool
	}{
		{"hoodi", false},
		{"mainnet", false},
		{"sepolia", true},
		{"HOODI", true},
		{"Mainnet", true},
		{"", true},
	}

	for _, tc := range tests {
		t.Run("network_"+tc.network, func(t *testing.T) {
			args := []string{
				"--keystore-dir", ksDir,
				"--pubkeys", "0x" + validPubkey,
				"--network", tc.network,
				"--output-dir", dir,
			}
			// Empty network will be a missing flag scenario; add it anyway
			if tc.network == "" {
				args = []string{
					"--keystore-dir", ksDir,
					"--pubkeys", "0x" + validPubkey,
					"--output-dir", dir,
				}
			}
			// Mainnet requires the ack flag; supply it so this test focuses on
			// network parsing only, not on the mainnet-ack gate.
			if tc.network == "mainnet" {
				args = append(args, "--i-understand-this-is-mainnet")
			}
			_, _, called, err := runApp(t, args)
			if tc.wantErr {
				if err == nil {
					t.Errorf("runApp network=%q error = nil, want error", tc.network)
				}
				if called {
					t.Errorf("runApp network=%q: run was called, want it not called on error", tc.network)
				}
			} else {
				if err != nil {
					t.Errorf("runApp network=%q error = %v, want nil", tc.network, err)
				}
			}
		})
	}
}

// TestPubkeyHexLength verifies that pubkeys with wrong hex length return an error.
func TestPubkeyHexLength(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()

	tests := []struct {
		name    string
		pubkeys string
		wantErr bool
	}{
		{
			name:    "correct_length_no_prefix",
			pubkeys: validPubkey,
			wantErr: false,
		},
		{
			name:    "correct_length_with_prefix",
			pubkeys: "0x" + validPubkey,
			wantErr: false,
		},
		{
			name:    "too_short",
			pubkeys: "0x" + validPubkey[:94],
			wantErr: true,
		},
		{
			name:    "too_long",
			pubkeys: "0x" + validPubkey + "ab",
			wantErr: true,
		},
		{
			name:    "empty",
			pubkeys: "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{
				"--keystore-dir", ksDir,
				"--pubkeys", tc.pubkeys,
				"--network", "hoodi",
				"--output-dir", dir,
			}
			_, _, _, err := runApp(t, args)
			if tc.wantErr && err == nil {
				t.Errorf("pubkeys=%q: error = nil, want error", tc.pubkeys)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("pubkeys=%q: error = %v, want nil", tc.pubkeys, err)
			}
		})
	}
}

// TestPubkeyInvalidHexChars verifies that non-hex characters in pubkeys return an error.
func TestPubkeyInvalidHexChars(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()

	// Replace some chars with non-hex
	invalidHex := strings.Repeat("g", 96) // 'g' is not a hex char
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", invalidHex,
		"--network", "hoodi",
		"--output-dir", dir,
	}
	_, _, _, err := runApp(t, args)
	if err == nil {
		t.Error("runApp with invalid hex chars: error = nil, want error")
	}
}

// TestPubkeyMixedPrefix verifies that mixing 0x-prefixed and unprefixed pubkeys returns an error.
func TestPubkeyMixedPrefix(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()

	// First has 0x, second does not
	mixed := "0x" + validPubkey + "," + validPubkey2
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", mixed,
		"--network", "hoodi",
		"--output-dir", dir,
	}
	_, _, _, err := runApp(t, args)
	if err == nil {
		t.Errorf("runApp with mixed prefix pubkeys: error = nil, want error")
	}
}

// TestNonexistentOutputDir verifies that a non-existent output dir returns an error.
func TestNonexistentOutputDir(t *testing.T) {
	ksDir := t.TempDir()
	nonExistent := filepath.Join(t.TempDir(), "does-not-exist")
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", "0x" + validPubkey,
		"--network", "hoodi",
		"--output-dir", nonExistent,
	}
	_, _, _, err := runApp(t, args)
	if err == nil {
		t.Errorf("runApp with nonexistent output dir: error = nil, want error")
	}
}

// TestReadOnlyOutputDir verifies that a non-writable output dir returns an error.
func TestReadOnlyOutputDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("read-only dir test skipped: running as root")
	}

	// Create a subdir and make it read-only
	parent := t.TempDir()
	roDir := filepath.Join(parent, "readonly")
	if err := os.Mkdir(roDir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	// Register cleanup to restore perms so t.TempDir() cleanup can remove it
	t.Cleanup(func() {
		os.Chmod(roDir, 0o755) //nolint:errcheck
	})
	if err := os.Chmod(roDir, 0o555); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	ksDir := t.TempDir()
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", "0x" + validPubkey,
		"--network", "hoodi",
		"--output-dir", roDir,
	}
	_, _, _, err := runApp(t, args)
	if err == nil {
		t.Errorf("runApp with read-only output dir: error = nil, want error")
	}
}

// TestSinglePubkeyHappyPath verifies that a single valid pubkey passes through correctly.
func TestSinglePubkeyHappyPath(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", "0x" + validPubkey,
		"--network", "hoodi",
		"--output-dir", dir,
	}
	cfg, stderr, called, err := runApp(t, args)
	if err != nil {
		t.Fatalf("runApp: %v", err)
	}
	if !called {
		t.Fatal("run callback was not called")
	}

	// Verify Config fields
	if cfg.KeystoreDir != ksDir {
		t.Errorf("KeystoreDir = %q, want %q", cfg.KeystoreDir, ksDir)
	}
	if cfg.Network != network.Hoodi {
		t.Errorf("Network = %q, want %q", cfg.Network, network.Hoodi)
	}
	if cfg.OutputDir != dir {
		t.Errorf("OutputDir = %q, want %q", cfg.OutputDir, dir)
	}
	if len(cfg.Pubkeys) != 1 {
		t.Fatalf("len(Pubkeys) = %d, want 1", len(cfg.Pubkeys))
	}

	// Verify banner on stderr
	if !strings.Contains(stderr, "eth-deposit gen:") {
		t.Errorf("stderr = %q, want banner containing %q", stderr, "eth-deposit gen:")
	}
	if !strings.Contains(stderr, "network=hoodi") {
		t.Errorf("stderr = %q, want banner containing %q", stderr, "network=hoodi")
	}
	if !strings.Contains(stderr, "count=1") {
		t.Errorf("stderr = %q, want banner containing %q", stderr, "count=1")
	}
}

// TestMultiPubkeyHappyPath verifies that multiple valid pubkeys pass through correctly.
func TestMultiPubkeyHappyPath(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	pubkeys := "0x" + validPubkey + ",0x" + validPubkey2
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", pubkeys,
		"--network", "hoodi",
		"--output-dir", dir,
	}
	cfg, stderr, called, err := runApp(t, args)
	if err != nil {
		t.Fatalf("runApp: %v", err)
	}
	if !called {
		t.Fatal("run callback was not called")
	}
	if len(cfg.Pubkeys) != 2 {
		t.Fatalf("len(Pubkeys) = %d, want 2", len(cfg.Pubkeys))
	}

	// Banner must contain first and last pubkey
	if !strings.Contains(stderr, "count=2") {
		t.Errorf("stderr = %q, want banner containing %q", stderr, "count=2")
	}
	// first and last should appear in banner
	if !strings.Contains(stderr, "first_pubkey=") {
		t.Errorf("stderr = %q, want banner containing %q", stderr, "first_pubkey=")
	}
	if !strings.Contains(stderr, "last_pubkey=") {
		t.Errorf("stderr = %q, want banner containing %q", stderr, "last_pubkey=")
	}
}

// TestPassphraseEnvOptional verifies that --passphrase-env is optional and propagated.
func TestPassphraseEnvOptional(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()

	t.Run("without_passphrase_env", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("runApp: %v", err)
		}
		if !called {
			t.Fatal("run callback was not called")
		}
		if cfg.PassphraseEnv != "" {
			t.Errorf("PassphraseEnv = %q, want empty string", cfg.PassphraseEnv)
		}
	})

	t.Run("with_passphrase_env", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
			"--passphrase-env", "MY_PASSPHRASE",
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("runApp: %v", err)
		}
		if !called {
			t.Fatal("run callback was not called")
		}
		if cfg.PassphraseEnv != "MY_PASSPHRASE" {
			t.Errorf("PassphraseEnv = %q, want %q", cfg.PassphraseEnv, "MY_PASSPHRASE")
		}
	})
}

// TestBannerFormat verifies the confirmation banner format more precisely.
func TestBannerFormat(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", "0x" + validPubkey + ",0x" + validPubkey2,
		"--network", "hoodi",
		"--output-dir", dir,
	}
	_, stderr, _, err := runApp(t, args)
	if err != nil {
		t.Fatalf("runApp: %v", err)
	}

	// Assert full banner structure: network, first/last pubkey (0x-prefixed hex), count.
	want := fmt.Sprintf("eth-deposit gen: network=hoodi first_pubkey=0x%s last_pubkey=0x%s count=2",
		validPubkey, validPubkey2)
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr banner = %q\nwant to contain %q", stderr, want)
	}
}

// TestUnprefixedPubkeys verifies that all-unprefixed pubkeys are also accepted.
func TestUnprefixedPubkeys(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", validPubkey + "," + validPubkey2,
		"--network", "hoodi",
		"--output-dir", dir,
	}
	cfg, _, called, err := runApp(t, args)
	if err != nil {
		t.Fatalf("runApp with unprefixed pubkeys: %v", err)
	}
	if !called {
		t.Fatal("run callback was not called")
	}
	if len(cfg.Pubkeys) != 2 {
		t.Errorf("len(Pubkeys) = %d, want 2", len(cfg.Pubkeys))
	}
}

// TestNetworkParsedBeforeOtherWork verifies that invalid network is rejected before run is called.
func TestNetworkParsedBeforeOtherWork(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", "0x" + validPubkey,
		"--network", "invalidnet",
		"--output-dir", dir,
	}
	_, _, called, err := runApp(t, args)
	if err == nil {
		t.Error("runApp with invalid network: error = nil, want error")
	}
	if called {
		t.Error("run was called with invalid network, want it not called")
	}
}

// TestOutputDirIsFile verifies that passing a file path as --output-dir returns an error.
func TestOutputDirIsFile(t *testing.T) {
	ksDir := t.TempDir()
	// Create a file (not a directory)
	f, err := os.CreateTemp(t.TempDir(), "not-a-dir-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	f.Close()
	filePath := f.Name()

	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", "0x" + validPubkey,
		"--network", "hoodi",
		"--output-dir", filePath,
	}
	_, _, _, err = runApp(t, args)
	if err == nil {
		t.Errorf("runApp with file as output-dir: error = nil, want error")
	}
}

// TestErrorIsExitCoder verifies that validation errors returned by the app are
// ucli.ExitCoder values with exit code 1, matching the urfave/cli convention.
func TestErrorIsExitCoder(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", "not-valid-hex!!!",
		"--network", "hoodi",
		"--output-dir", dir,
	}
	_, _, _, err := runApp(t, args)
	if err == nil {
		t.Fatal("runApp with invalid pubkeys: error = nil, want error")
	}

	exitErr, ok := err.(ucli.ExitCoder)
	if !ok {
		t.Fatalf("error type %T is not ucli.ExitCoder", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("ExitCode = %d, want 2 (validation error per PRD)", exitErr.ExitCode())
	}
}

// TestMainnetWithoutAck verifies that --network mainnet without --i-understand-this-is-mainnet
// returns exit code 2 and never invokes the run callback.
func TestMainnetWithoutAck(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", "0x" + validPubkey,
		"--network", "mainnet",
		"--output-dir", dir,
		// Intentionally omitting --i-understand-this-is-mainnet
	}
	_, stderr, called, err := runApp(t, args)
	if err == nil {
		t.Fatal("runApp mainnet without ack: error = nil, want error")
	}
	if called {
		t.Fatal("run callback was invoked without mainnet ack, want it not called")
	}

	exitErr, ok := err.(ucli.ExitCoder)
	if !ok {
		t.Fatalf("error type %T is not ucli.ExitCoder", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("ExitCode = %d, want 2", exitErr.ExitCode())
	}
	if !strings.Contains(err.Error(), "mainnet selected") {
		t.Errorf("error message %q does not contain %q", err.Error(), "mainnet selected")
	}
	// Guard must fire before printBanner: no pubkey data should appear on stderr.
	if strings.Contains(stderr, "first_pubkey=") {
		t.Errorf("banner must not be emitted when ack is absent; stderr = %q", stderr)
	}
}

// TestMainnetWithExplicitFalseAck verifies that --i-understand-this-is-mainnet=false
// (the explicit boolean-false form) is equivalent to omitting the flag and still
// triggers exit code 2. This locks in urfave/cli v2 last-value-wins semantics so
// that a library upgrade cannot silently change the behaviour.
func TestMainnetWithExplicitFalseAck(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", "0x" + validPubkey,
		"--network", "mainnet",
		"--output-dir", dir,
		"--i-understand-this-is-mainnet=false", // explicit negation — gate must still fire
	}
	_, stderr, called, err := runApp(t, args)
	if err == nil {
		t.Fatal("runApp mainnet with explicit false ack: error = nil, want error")
	}
	if called {
		t.Fatal("run callback was invoked with ack=false, want it not called")
	}
	exitErr, ok := err.(ucli.ExitCoder)
	if !ok {
		t.Fatalf("error type %T is not ucli.ExitCoder", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("ExitCode = %d, want 2", exitErr.ExitCode())
	}
	if strings.Contains(stderr, "first_pubkey=") {
		t.Errorf("banner must not be emitted when ack is false; stderr = %q", stderr)
	}
}

// TestMainnetAckRepeatedOverride verifies last-value-wins semantics for repeated
// boolean flags. Providing the ack flag then immediately negating it must still
// trigger exit code 2 (the final value of false governs the gate).
func TestMainnetAckRepeatedOverride(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", "0x" + validPubkey,
		"--network", "mainnet",
		"--output-dir", dir,
		"--i-understand-this-is-mainnet",       // first: true
		"--i-understand-this-is-mainnet=false", // second (last): false → gate fires
	}
	_, _, called, err := runApp(t, args)
	if err == nil {
		t.Fatal("runApp mainnet with ack overridden to false: error = nil, want error")
	}
	if called {
		t.Fatal("run callback was invoked, want it not called when final ack value is false")
	}
	exitErr, ok := err.(ucli.ExitCoder)
	if !ok {
		t.Fatalf("error type %T is not ucli.ExitCoder", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("ExitCode = %d, want 2", exitErr.ExitCode())
	}
}

// TestMainnetWithAck verifies that --network mainnet --i-understand-this-is-mainnet
// allows signing to proceed and emits a banner containing "MAINNET" (uppercase).
func TestMainnetWithAck(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", "0x" + validPubkey,
		"--network", "mainnet",
		"--output-dir", dir,
		"--i-understand-this-is-mainnet",
	}
	cfg, stderr, called, err := runApp(t, args)
	if err != nil {
		t.Fatalf("runApp mainnet with ack: %v", err)
	}
	if !called {
		t.Fatal("run callback was not called")
	}
	if cfg.Network != network.Mainnet {
		t.Errorf("Network = %q, want mainnet", cfg.Network)
	}
	if !cfg.MainnetAck {
		t.Error("MainnetAck = false, want true")
	}
	if !strings.Contains(stderr, "MAINNET") {
		t.Errorf("banner %q does not contain %q", stderr, "MAINNET")
	}
}

// TestHoodiWithAckFlag verifies that --network hoodi --i-understand-this-is-mainnet
// proceeds normally and the banner shows lowercase "hoodi" (not "HOODI").
func TestHoodiWithAckFlag(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	args := []string{
		"--keystore-dir", ksDir,
		"--pubkeys", "0x" + validPubkey,
		"--network", "hoodi",
		"--output-dir", dir,
		"--i-understand-this-is-mainnet", // supplying the ack flag on hoodi is harmless
	}
	cfg, stderr, called, err := runApp(t, args)
	if err != nil {
		t.Fatalf("runApp hoodi with ack flag: %v", err)
	}
	if !called {
		t.Fatal("run callback was not called")
	}
	if cfg.Network != network.Hoodi {
		t.Errorf("Network = %q, want hoodi", cfg.Network)
	}
	if !strings.Contains(stderr, "network=hoodi") {
		t.Errorf("banner %q does not contain %q", stderr, "network=hoodi")
	}
	if strings.Contains(stderr, "MAINNET") {
		t.Errorf("banner %q unexpectedly contains MAINNET for hoodi network", stderr)
	}
}

// TestDryRunFlag verifies that --dry-run is parsed and propagated to Config.DryRun.
func TestDryRunFlag(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()

	t.Run("default_false", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("runApp: %v", err)
		}
		if !called {
			t.Fatal("run callback was not called")
		}
		if cfg.DryRun {
			t.Errorf("DryRun = true, want false when flag is absent")
		}
	})

	t.Run("explicit_true", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
			"--dry-run",
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("runApp: %v", err)
		}
		if !called {
			t.Fatal("run callback was not called")
		}
		if !cfg.DryRun {
			t.Errorf("DryRun = false, want true when --dry-run is set")
		}
	})
}

// TestVerboseFlag verifies that --verbose is accepted, defaults to false, and is
// propagated correctly in Config.
func TestVerboseFlag(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()

	t.Run("defaults_to_false", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("runApp: %v", err)
		}
		if !called {
			t.Fatal("run callback was not called")
		}
		if cfg.Verbose {
			t.Error("Verbose = true, want false by default")
		}
	})

	t.Run("set_to_true", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
			"--verbose",
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("runApp: %v", err)
		}
		if !called {
			t.Fatal("run callback was not called")
		}
		if !cfg.Verbose {
			t.Error("Verbose = false, want true when --verbose is passed")
		}
	})
}

// TestJSONLogsFlag verifies that --json-logs is accepted, defaults to false, and is
// propagated correctly in Config.
func TestJSONLogsFlag(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()

	t.Run("defaults_to_false", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("runApp: %v", err)
		}
		if !called {
			t.Fatal("run callback was not called")
		}
		if cfg.JSONLogs {
			t.Error("JSONLogs = true, want false by default")
		}
	})

	t.Run("set_to_true", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
			"--json-logs",
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("runApp: %v", err)
		}
		if !called {
			t.Fatal("run callback was not called")
		}
		if !cfg.JSONLogs {
			t.Error("JSONLogs = false, want true when --json-logs is passed")
		}
	})
}

// TestParallelFlag verifies that --parallel is accepted, defaults to 1, is validated,
// and is propagated correctly in Config.
func TestParallelFlag(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()

	t.Run("defaults_to_1", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("runApp: %v", err)
		}
		if !called {
			t.Fatal("run callback was not called")
		}
		if cfg.Parallel != 1 {
			t.Errorf("Parallel = %d, want 1 (default)", cfg.Parallel)
		}
	})

	t.Run("valid_N_propagates", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
			"--parallel", "4",
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("runApp: %v", err)
		}
		if !called {
			t.Fatal("run callback was not called")
		}
		if cfg.Parallel != 4 {
			t.Errorf("Parallel = %d, want 4", cfg.Parallel)
		}
	})

	t.Run("zero_rejected_exit2", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
			"--parallel", "0",
		}
		_, _, called, err := runApp(t, args)
		if err == nil {
			t.Fatal("runApp with --parallel 0: error = nil, want error")
		}
		if called {
			t.Fatal("run callback was invoked, want it not called on validation error")
		}
		exitErr, ok := err.(ucli.ExitCoder)
		if !ok {
			t.Fatalf("error type %T is not ucli.ExitCoder", err)
		}
		if exitErr.ExitCode() != 2 {
			t.Errorf("ExitCode = %d, want 2", exitErr.ExitCode())
		}
	})

	t.Run("negative_rejected_exit2", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
			"--parallel", "-1",
		}
		_, _, called, err := runApp(t, args)
		if err == nil {
			t.Fatal("runApp with --parallel -1: error = nil, want error")
		}
		if called {
			t.Fatal("run callback was invoked, want it not called on validation error")
		}
		exitErr, ok := err.(ucli.ExitCoder)
		if !ok {
			t.Fatalf("error type %T is not ucli.ExitCoder", err)
		}
		if exitErr.ExitCode() != 2 {
			t.Errorf("ExitCode = %d, want 2", exitErr.ExitCode())
		}
	})

	t.Run("too_large_rejected_exit2", func(t *testing.T) {
		// N > runtime.NumCPU()*4 must be rejected.
		// Use a very large number guaranteed to exceed any CPU count * 4.
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
			"--parallel", "99999",
		}
		_, _, called, err := runApp(t, args)
		if err == nil {
			t.Fatal("runApp with --parallel 99999: error = nil, want error")
		}
		if called {
			t.Fatal("run callback was invoked, want it not called on validation error")
		}
		exitErr, ok := err.(ucli.ExitCoder)
		if !ok {
			t.Fatalf("error type %T is not ucli.ExitCoder", err)
		}
		if exitErr.ExitCode() != 2 {
			t.Errorf("ExitCode = %d, want 2", exitErr.ExitCode())
		}
	})

	t.Run("error_message_contains_parallel", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
			"--parallel", "0",
		}
		_, _, _, err := runApp(t, args)
		if err == nil {
			t.Fatal("runApp with --parallel 0: error = nil, want error")
		}
		if !strings.Contains(err.Error(), "--parallel") {
			t.Errorf("error message %q does not mention --parallel", err.Error())
		}
	})
}

// false and is propagated correctly in Config.
func TestVerifyWithDepositCLIFlag(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()

	t.Run("defaults_to_false", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("runApp: %v", err)
		}
		if !called {
			t.Fatal("run callback was not called")
		}
		if cfg.VerifyWithDepositCLI {
			t.Error("VerifyWithDepositCLI = true, want false by default")
		}
	})

	t.Run("set_to_true", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
			"--verify-with-deposit-cli",
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("runApp: %v", err)
		}
		if !called {
			t.Fatal("run callback was not called")
		}
		if !cfg.VerifyWithDepositCLI {
			t.Error("VerifyWithDepositCLI = false, want true when --verify-with-deposit-cli is passed")
		}
	})
}

// TestDepositCLIPathFlag verifies that --deposit-cli-path defaults to "deposit" and is
// propagated correctly in Config.
func TestDepositCLIPathFlag(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()

	t.Run("defaults_to_deposit", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("runApp: %v", err)
		}
		if !called {
			t.Fatal("run callback was not called")
		}
		if cfg.DepositCLIPath != "deposit" {
			t.Errorf("DepositCLIPath = %q, want %q", cfg.DepositCLIPath, "deposit")
		}
	})

	t.Run("custom_path", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
			"--deposit-cli-path", "/usr/local/bin/deposit",
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("runApp: %v", err)
		}
		if !called {
			t.Fatal("run callback was not called")
		}
		if cfg.DepositCLIPath != "/usr/local/bin/deposit" {
			t.Errorf("DepositCLIPath = %q, want %q", cfg.DepositCLIPath, "/usr/local/bin/deposit")
		}
	})
}

// TestKeystoreDirValidation verifies that --keystore-dir must point to an existing,
// readable directory, matching AC3 of Issue #25.
// TestKeystoreDirValidation verifies that --keystore-dir must point to an existing,
// readable directory, matching AC3 of Issue #25.
func TestKeystoreDirValidation(t *testing.T) {
	dir := t.TempDir()

	t.Run("nonexistent_dir", func(t *testing.T) {
		nonExistent := filepath.Join(t.TempDir(), "no-such-dir")
		args := []string{
			"--keystore-dir", nonExistent,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
		}
		_, _, _, err := runApp(t, args)
		if err == nil {
			t.Errorf("runApp with nonexistent keystore-dir: error = nil, want error")
		}
	})

	t.Run("file_instead_of_dir", func(t *testing.T) {
		// Create a regular file and pass it as --keystore-dir
		f, err := os.CreateTemp(t.TempDir(), "not-a-dir-*")
		if err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
		f.Close()
		args := []string{
			"--keystore-dir", f.Name(),
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", dir,
		}
		_, _, _, err = runApp(t, args)
		if err == nil {
			t.Errorf("runApp with file as keystore-dir: error = nil, want error")
		}
	})
}

// TestOutputDirConditionalRequiredness covers F3: --output-dir is required (and
// validated) only when NOT in --dry-run mode. In dry-run the flag may be absent
// or point at an invalid path — validation is skipped because DryRunWriter writes
// to stdout and never touches disk. Outside dry-run a missing or invalid
// --output-dir maps to exit code 2, matching the other manual validations.
func TestOutputDirConditionalRequiredness(t *testing.T) {
	ksDir := t.TempDir() // a real, readable directory for --keystore-dir
	// A path that does not exist, so validateOutputDir would fail if it ran.
	invalidDir := filepath.Join(t.TempDir(), "does-not-exist")

	t.Run("dry_run_without_output_dir_succeeds", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--dry-run",
			// no --output-dir
		}
		cfg, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("dry-run without --output-dir: error = %v, want nil", err)
		}
		if !called {
			t.Fatal("run callback was not called; validation should pass in dry-run")
		}
		if cfg.OutputDir != "" {
			t.Errorf("OutputDir = %q, want empty string when --output-dir is omitted", cfg.OutputDir)
		}
		if !cfg.DryRun {
			t.Error("DryRun = false, want true")
		}
	})

	t.Run("dry_run_with_invalid_output_dir_succeeds", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", invalidDir, // would fail validateOutputDir if it ran
			"--dry-run",
		}
		_, _, called, err := runApp(t, args)
		if err != nil {
			t.Fatalf("dry-run with invalid --output-dir: error = %v, want nil (validation skipped)", err)
		}
		if !called {
			t.Fatal("run callback was not called; output-dir validation must be skipped in dry-run")
		}
	})

	t.Run("no_dry_run_without_output_dir_exits_2", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			// no --dry-run, no --output-dir
		}
		_, _, called, err := runApp(t, args)
		if err == nil {
			t.Fatal("missing --output-dir without --dry-run: error = nil, want error")
		}
		if called {
			t.Error("run callback was invoked, want it not called on validation error")
		}
		exitErr, ok := err.(ucli.ExitCoder)
		if !ok {
			t.Fatalf("error type %T is not ucli.ExitCoder", err)
		}
		if exitErr.ExitCode() != 2 {
			t.Errorf("ExitCode = %d, want 2", exitErr.ExitCode())
		}
		if !strings.Contains(err.Error(), "required flag not set") {
			t.Errorf("error message %q does not mention %q", err.Error(), "required flag not set")
		}
	})

	t.Run("no_dry_run_with_invalid_output_dir_exits_2", func(t *testing.T) {
		args := []string{
			"--keystore-dir", ksDir,
			"--pubkeys", "0x" + validPubkey,
			"--network", "hoodi",
			"--output-dir", invalidDir,
			// no --dry-run
		}
		_, _, called, err := runApp(t, args)
		if err == nil {
			t.Fatal("invalid --output-dir without --dry-run: error = nil, want error")
		}
		if called {
			t.Error("run callback was invoked, want it not called on validation error")
		}
		exitErr, ok := err.(ucli.ExitCoder)
		if !ok {
			t.Fatalf("error type %T is not ucli.ExitCoder", err)
		}
		if exitErr.ExitCode() != 2 {
			t.Errorf("ExitCode = %d, want 2", exitErr.ExitCode())
		}
	})
}
