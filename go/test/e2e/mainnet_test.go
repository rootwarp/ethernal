// Package e2e contains end-to-end golden-file integration tests for the
// eth-deposit gen deposit pipeline. These tests are NOT skipped by default;
// they run as part of the normal `go test ./...` invocation.
//
// The golden fixtures in testdata/mainnet/ were generated programmatically from
// the same fixed 32-byte BLS secret used by the hoodi golden fixtures, using the
// Go implementation itself (self-referential / Option A). They prove internal
// self-consistency of the full pipeline for the mainnet network parameters:
// keystore load → BLS sign → SSZ hash → JSON marshal.
//
// # Why self-referential fixtures?
//
// staking-deposit-cli v1.2.2 (installed) only accepts mnemonic-derived BLS keys
// via the `existing-mnemonic` subcommand. Our golden test key is a raw 32-byte
// fixed secret (not derived from any mnemonic), so the CLI cannot regenerate
// deposits for the same pubkey. Cross-validating with staking-deposit-cli is a
// Phase 3 follow-up that requires choosing a test key from a real mnemonic.
//
// The critical mainnet correctness property that IS verified here:
// - The BLS domain is computed with GenesisForkVersion=[0x00,0x00,0x00,0x00]
// - fork_version == "00000000" in the output JSON
// - network_name == "mainnet" in the output JSON
// These differ from hoodi ([0x10,0x00,0x09,0x10] / "10000910" / "hoodi"),
// proving that the mainnet path through the deposit pipeline is exercised.
package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	ucli "github.com/urfave/cli/v3"

	"github.com/rootwarp/eth-utils/go/internal/bls"
	icli "github.com/rootwarp/eth-utils/go/internal/cli"
	"github.com/rootwarp/eth-utils/go/internal/deposit"
	"github.com/rootwarp/eth-utils/go/internal/keystore"
	"github.com/rootwarp/eth-utils/go/internal/network"
	"github.com/rootwarp/eth-utils/go/internal/output"
)

// mainnetTestdataDir is the path to the mainnet golden fixture directory,
// relative to this test file's package directory.
const mainnetTestdataDir = "../../testdata/mainnet"

// TestMainnetGoldenDeposit is the mainnet golden-file integration test. It:
//  1. Loads testdata/mainnet/keystore.json via the real keystore.Loader
//  2. Decrypts with the passphrase from testdata/mainnet/passphrase.txt
//  3. Derives pubkeys from testdata/mainnet/pubkeys.txt
//  4. Runs deposit.Generator.Generate for Mainnet with those pubkeys
//  5. Serializes via output.DryRunWriter to an in-memory buffer
//  6. Parses both actual and expected JSON and compares field-by-field
//
// In particular, it asserts that fork_version == "00000000" and
// network_name == "mainnet", confirming the mainnet signing domain is used.
func TestMainnetGoldenDeposit(t *testing.T) {
	// --- Load fixtures from testdata/mainnet/ ---

	keystorePath := mainnetTestdataDir + "/keystores/keystore.json"
	passphrasePath := mainnetTestdataDir + "/passphrase.txt"
	pubkeysPath := mainnetTestdataDir + "/pubkeys.txt"
	expectedPath := mainnetTestdataDir + "/deposit_data-expected.json"

	// Load passphrase.
	passRaw, err := os.ReadFile(passphrasePath)
	if err != nil {
		t.Fatalf("read passphrase.txt: %v", err)
	}
	pw := strings.TrimRight(string(passRaw), "\r\n")

	// Load pubkeys.
	pubkeysRaw, err := os.ReadFile(pubkeysPath)
	if err != nil {
		t.Fatalf("read pubkeys.txt: %v", err)
	}
	pubkeyLines := strings.Split(strings.TrimSpace(string(pubkeysRaw)), "\n")
	if len(pubkeyLines) == 1 && pubkeyLines[0] == "" {
		t.Fatal("pubkeys.txt is empty")
	}

	pubkeys := make([][48]byte, len(pubkeyLines))
	for i, line := range pubkeyLines {
		line = strings.TrimSpace(line)
		b, err := hex.DecodeString(line)
		if err != nil {
			t.Fatalf("pubkeys.txt line %d: decode hex %q: %v", i, line, err)
		}
		if len(b) != 48 {
			t.Fatalf("pubkeys.txt line %d: want 48 bytes, got %d", i, len(b))
		}
		copy(pubkeys[i][:], b)
	}

	// Load keystore via real Loader.
	loader := keystore.NewLoader()
	key, err := loader.Load(context.Background(), keystorePath, &bytesPassphraseSource{pw: pw})
	if err != nil {
		t.Fatalf("keystore.Load: %v", err)
	}
	defer key.Zeroize()

	// --- Initialise BLS and build the signing pipeline ---

	if err := bls.Init(); err != nil {
		t.Fatalf("bls.Init: %v", err)
	}

	signer, err := bls.NewSigner(key.Secret)
	if err != nil {
		t.Fatalf("bls.NewSigner: %v", err)
	}
	verifier := bls.DefaultVerifier()

	params, err := network.Lookup(network.Mainnet)
	if err != nil {
		t.Fatalf("network.Lookup(Mainnet): %v", err)
	}

	gen := deposit.NewGenerator(signer, verifier, params)

	req := deposit.Request{
		Network:               network.Mainnet,
		Pubkeys:               pubkeys,
		WithdrawalCredentials: goldenWithdrawalCredentials,
		AmountGwei:            goldenAmountGwei,
		DepositCLIVersion:     goldenCLIVersion,
	}

	entries, err := gen.Generate(context.Background(), req)
	if err != nil {
		t.Fatalf("deposit.Generator.Generate: %v", err)
	}

	// --- Serialize via DryRunWriter ---

	var buf bytes.Buffer
	w := output.NewDryRunWriter(&buf)
	_, _, err = w.Write(context.Background(), "", entries, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("output.DryRunWriter.Write: %v", err)
	}

	// --- Load expected JSON ---

	expectedRaw, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("read deposit_data-expected.json: %v", err)
	}

	// --- Parse both actual and expected ---

	var actualEntries []goldenDepositEntry
	if err := json.Unmarshal(buf.Bytes(), &actualEntries); err != nil {
		t.Fatalf("parse actual JSON: %v\nactual:\n%s", err, buf.String())
	}

	var expectedEntries []goldenDepositEntry
	if err := json.Unmarshal(expectedRaw, &expectedEntries); err != nil {
		t.Fatalf("parse expected JSON: %v\nexpected:\n%s", err, string(expectedRaw))
	}

	// --- Field-by-field comparison ---

	if len(actualEntries) != len(expectedEntries) {
		t.Fatalf("entry count mismatch: actual=%d expected=%d", len(actualEntries), len(expectedEntries))
	}

	for i := range actualEntries {
		compareGoldenEntry(t, i, actualEntries[i], expectedEntries[i])
	}

	// --- Invariant assertions specific to mainnet ---

	for i, e := range actualEntries {
		if e.ForkVersion != "00000000" {
			t.Errorf("entry[%d].fork_version = %q, want %q (mainnet GenesisForkVersion)",
				i, e.ForkVersion, "00000000")
		}
		if e.NetworkName != "mainnet" {
			t.Errorf("entry[%d].network_name = %q, want %q",
				i, e.NetworkName, "mainnet")
		}
	}
}

// TestMainnetBanner verifies that the confirmation banner printed to stderr
// before the signing pipeline contains the literal string "mainnet". This
// proves that the CLI layer correctly identifies the network in the banner when
// --network mainnet is passed.
func TestMainnetBanner(t *testing.T) {
	if err := bls.Init(); err != nil {
		t.Fatalf("bls.Init: %v", err)
	}

	// Load the pubkey hex from testdata/mainnet/pubkeys.txt so the banner test
	// uses the same key as the golden deposit test.
	pubkeysRaw, err := os.ReadFile(mainnetTestdataDir + "/pubkeys.txt")
	if err != nil {
		t.Fatalf("read pubkeys.txt: %v", err)
	}
	pubkeyHex := strings.TrimSpace(string(pubkeysRaw))

	// Build the CLI app with a no-op run function so we capture only the banner.
	// We deliberately skip the deposit pipeline here; banner printing happens
	// inside the app.Action before run() is invoked.
	var bannerBuf bytes.Buffer
	runCalled := false

	app := icli.NewApp(func(_ context.Context, _ icli.Config) error {
		runCalled = true
		return nil
	})
	app.Writer = io.Discard // suppress urfave help-text noise
	app.ErrWriter = &bannerBuf
	app.ExitErrHandler = func(_ context.Context, _ *ucli.Command, _ error) {} // prevent os.Exit in tests

	args := []string{
		"eth-deposit",
		"--network", "mainnet",
		"--i-understand-this-is-mainnet",
		"--keystore-dir", mainnetTestdataDir + "/keystores",
		"--pubkeys", pubkeyHex,
		"--output-dir", t.TempDir(),
	}

	if err := app.Run(context.Background(), args); err != nil {
		t.Fatalf("app.Run: %v", err)
	}

	if !runCalled {
		t.Fatal("run callback was not invoked; banner may not have been printed")
	}

	banner := bannerBuf.String()
	// Issue #14: the banner uppercases "MAINNET" as an additional visual safety
	// cue. We check for the case-insensitive presence of "mainnet" and the exact
	// "MAINNET" token that the banner format produces.
	if !strings.Contains(strings.ToLower(banner), "mainnet") {
		t.Errorf("banner does not contain %q (case-insensitive); got %q", "mainnet", banner)
	}
	if !strings.Contains(banner, "network=MAINNET") {
		t.Errorf("banner does not contain %q; got %q", "network=MAINNET", banner)
	}
}

// TestRefreshMainnetGolden regenerates all files in testdata/mainnet/ from the
// same fixed goldenSecret used by the hoodi fixtures. It is skipped unless the
// REFRESH_GOLDEN env var is set.
//
// To refresh:
//
//	REFRESH_GOLDEN=1 go test -run TestRefreshMainnetGolden ./test/e2e/
func TestRefreshMainnetGolden(t *testing.T) {
	if os.Getenv("REFRESH_GOLDEN") == "" {
		t.Skip("REFRESH_GOLDEN not set; skipping fixture refresh")
	}

	if err := refreshMainnetGoldenFixtures(t); err != nil {
		t.Fatalf("refresh mainnet golden fixtures: %v", err)
	}
	t.Log("mainnet golden fixtures refreshed in testdata/mainnet/")
}

// refreshMainnetGoldenFixtures regenerates all files in testdata/mainnet/.
// It uses the same goldenSecret as the hoodi fixtures so both fixture sets
// share identical keystore.json, passphrase.txt, and pubkeys.txt. Only
// deposit_data-expected.json differs (different fork version / network name).
func refreshMainnetGoldenFixtures(t *testing.T) error {
	t.Helper()

	// Ensure BLS is initialized.
	if err := bls.Init(); err != nil {
		return fmt.Errorf("bls.Init: %w", err)
	}

	// Derive the real BLS public key from the shared goldenSecret.
	signer, err := bls.NewSigner(goldenSecret[:])
	if err != nil {
		return fmt.Errorf("bls.NewSigner: %w", err)
	}
	pub, err := signer.PublicKey()
	if err != nil {
		return fmt.Errorf("signer.PublicKey: %w", err)
	}
	pubHex := hex.EncodeToString(pub[:])

	// Encrypt the secret using wealdtech keystorev4 (same params as hoodi).
	keystoreBytes, err := encryptToKeystoreJSON(t, goldenSecret[:], goldenPassphrase, pubHex)
	if err != nil {
		return fmt.Errorf("encrypt keystore: %w", err)
	}

	// Run the full deposit pipeline for mainnet.
	verifier := bls.DefaultVerifier()
	params, err := network.Lookup(network.Mainnet)
	if err != nil {
		return fmt.Errorf("network.Lookup(Mainnet): %w", err)
	}
	gen := deposit.NewGenerator(signer, verifier, params)

	req := deposit.Request{
		Network:               network.Mainnet,
		Pubkeys:               [][48]byte{pub},
		WithdrawalCredentials: goldenWithdrawalCredentials,
		AmountGwei:            goldenAmountGwei,
		DepositCLIVersion:     goldenCLIVersion,
	}
	entries, err := gen.Generate(context.Background(), req)
	if err != nil {
		return fmt.Errorf("Generate: %w", err)
	}

	var depositBuf bytes.Buffer
	w := output.NewDryRunWriter(&depositBuf)
	_, _, err = w.Write(context.Background(), "", entries, time.Unix(0, 0))
	if err != nil {
		return fmt.Errorf("DryRunWriter.Write: %w", err)
	}

	// Write all files.
	if err := os.MkdirAll(mainnetTestdataDir+"/keystores", 0o750); err != nil {
		return fmt.Errorf("mkdir testdata/mainnet/keystores: %w", err)
	}

	files := map[string][]byte{
		mainnetTestdataDir + "/keystores/keystore.json":    keystoreBytes,
		mainnetTestdataDir + "/passphrase.txt":             []byte(goldenPassphrase),
		mainnetTestdataDir + "/pubkeys.txt":                []byte(pubHex),
		mainnetTestdataDir + "/deposit_data-expected.json": depositBuf.Bytes(),
	}
	for path, data := range files {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(data))
	}

	return nil
}
