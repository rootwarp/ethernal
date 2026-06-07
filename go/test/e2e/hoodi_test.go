// Package e2e contains end-to-end golden-file integration tests for the
// eth-deposit-gen deposit pipeline. These tests are NOT skipped by default;
// they run as part of the normal `go test ./...` invocation.
//
// The golden fixtures in testdata/hoodi/ were generated programmatically from a
// fixed 32-byte BLS secret using the Go implementation itself (Option A). They
// prove internal self-consistency of the full pipeline: keystore load → BLS sign
// → SSZ hash → JSON marshal. They do NOT prove byte-for-byte compatibility with
// the staking-deposit-cli v2.7.0 Python tool (that tool was not available at the
// time of Phase 1; re-validation against the real CLI is a Phase 2 follow-up).
package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rootwarp/eth-utils/go/internal/atomicio"
	"github.com/rootwarp/eth-utils/go/internal/bls"
	"github.com/rootwarp/eth-utils/go/internal/deposit"
	"github.com/rootwarp/eth-utils/go/internal/keystore"
	"github.com/rootwarp/eth-utils/go/internal/network"
	"github.com/rootwarp/eth-utils/go/internal/output"
)

// testdataDir is the path to the hoodi golden fixture directory relative to
// this test file's package directory. go test sets the working directory to the
// package directory, so this is a stable relative path.
const testdataDir = "../../testdata/hoodi"

// goldenSecret is the fixed 32-byte BLS secret used to generate all hoodi
// golden fixtures. This value is committed intentionally — it is a test-only
// key and MUST NEVER be used on any real network.
//
// The first byte 0x6a is chosen so that the big-endian scalar is less than the
// BLS12-381 curve order r = 0x73eda753... (required by SecretKey.Deserialize).
// EIP-2333 key derivation always produces scalars < r, so this constraint
// matches real-world keystore secrets.
var goldenSecret = [32]byte{
	0x6a, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
	0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
	0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
	0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01,
}

// goldenPassphrase is the plaintext passphrase protecting the hoodi keystore.
// Test-only — never use on a real network.
const goldenPassphrase = "hoodi-golden-test-passphrase"

// goldenAmountGwei is 32 ETH in Gwei.
const goldenAmountGwei = uint64(32_000_000_000)

// goldenCLIVersion is the deposit_cli_version field in the fixture JSON.
// Matches the CLIVersion constant in main.go.
const goldenCLIVersion = "2.7.0"

// withdrawalAddressFromKeys returns the deterministic --withdrawal-address from
// testdata/keys.json (per M0.10-1 and architecture §11.4). Used by golden rigs
// so regenerated fixtures carry a real 0x01 credential derived from M0.4-2.
func withdrawalAddressFromKeys(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../testdata/keys.json")
	if err != nil {
		t.Fatalf("read testdata/keys.json: %v", err)
	}
	var k struct {
		WithdrawalAddress string `json:"withdrawal_address"`
	}
	if err := json.Unmarshal(b, &k); err != nil {
		t.Fatalf("parse keys.json: %v", err)
	}
	if k.WithdrawalAddress == "" {
		t.Fatal("keys.json missing withdrawal_address")
	}
	return k.WithdrawalAddress
}

// deriveWC01 is the test copy of deriveWithdrawalCredential01 (M0.4-2).
// 0x01 || 0x00*11 || addr[20]. Smallest mechanical duplication for e2e rig update.
func deriveWC01(addr string) [32]byte {
	var cred [32]byte
	cred[0] = 0x01
	a := common.HexToAddress(addr)
	copy(cred[12:], a[:])
	return cred
}

// goldenDepositEntry is the deserialized shape of one entry in deposit_data.json.
// Field names match the Launchpad JSON schema exactly.
type goldenDepositEntry struct {
	Pubkey                string `json:"pubkey"`
	WithdrawalCredentials string `json:"withdrawal_credentials"`
	Amount                uint64 `json:"amount"`
	Signature             string `json:"signature"`
	DepositMessageRoot    string `json:"deposit_message_root"`
	DepositDataRoot       string `json:"deposit_data_root"`
	ForkVersion           string `json:"fork_version"`
	NetworkName           string `json:"network_name"`
	DepositCLIVersion     string `json:"deposit_cli_version"`
}

// bytesPassphraseSource implements keystore.PassphraseSource from a static string.
type bytesPassphraseSource struct {
	pw string
}

func (b *bytesPassphraseSource) Read() ([]byte, error) {
	return []byte(b.pw), nil
}

// TestHoodiGoldenDeposit is the M1 exit-gate integration test. It:
//  1. Loads testdata/hoodi/keystore.json via the real keystore.Loader
//  2. Decrypts with the passphrase from testdata/hoodi/passphrase.txt
//  3. Derives pubkeys from testdata/hoodi/pubkeys.txt
//  4. Runs deposit.Generator.Generate for Hoodi with those pubkeys
//  5. Serializes via output.DryRunWriter to an in-memory buffer
//  6. Parses both actual and expected JSON and compares field-by-field
//
// Any divergence is reported with the entry index and offending field.
func TestHoodiGoldenDeposit(t *testing.T) {
	// --- Load fixtures from testdata/hoodi/ ---

	keystorePath := testdataDir + "/keystores/keystore.json"
	passphrasePath := testdataDir + "/passphrase.txt"
	pubkeysPath := testdataDir + "/pubkeys.txt"
	expectedPath := testdataDir + "/deposit_data-expected.json"

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

	params, err := network.Lookup(network.Hoodi)
	if err != nil {
		t.Fatalf("network.Lookup(Hoodi): %v", err)
	}

	gen := deposit.NewGenerator(signer, verifier, params)

	req := deposit.Request{
		Network:               network.Hoodi,
		Pubkeys:               pubkeys,
		WithdrawalCredentials: deriveWC01(withdrawalAddressFromKeys(t)),
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
}

// compareGoldenEntry performs a field-by-field comparison of two golden entries.
// Each mismatch is reported individually with the entry index and field name.
func compareGoldenEntry(t *testing.T, idx int, actual, expected goldenDepositEntry) {
	t.Helper()

	type fieldCheck struct {
		name     string
		actual   string
		expected string
	}
	// Amount is compared separately (uint64).
	fields := []fieldCheck{
		{"pubkey", actual.Pubkey, expected.Pubkey},
		{"withdrawal_credentials", actual.WithdrawalCredentials, expected.WithdrawalCredentials},
		{"signature", actual.Signature, expected.Signature},
		{"deposit_message_root", actual.DepositMessageRoot, expected.DepositMessageRoot},
		{"deposit_data_root", actual.DepositDataRoot, expected.DepositDataRoot},
		{"fork_version", actual.ForkVersion, expected.ForkVersion},
		{"network_name", actual.NetworkName, expected.NetworkName},
		{"deposit_cli_version", actual.DepositCLIVersion, expected.DepositCLIVersion},
	}

	for _, f := range fields {
		if f.actual != f.expected {
			t.Errorf("entry[%d].%s mismatch:\n  actual:   %q\n  expected: %q",
				idx, f.name, f.actual, f.expected)
		}
	}

	if actual.Amount != expected.Amount {
		t.Errorf("entry[%d].amount mismatch: actual=%d expected=%d",
			idx, actual.Amount, expected.Amount)
	}
}

// TestRefreshHoodiGolden regenerates all files in testdata/hoodi/ from the
// fixed goldenSecret. It is skipped unless the REFRESH_GOLDEN env var is set.
//
// To refresh:
//
//	REFRESH_GOLDEN=1 go test -run TestRefreshHoodiGolden ./test/e2e/
func TestRefreshHoodiGolden(t *testing.T) {
	if os.Getenv("REFRESH_GOLDEN") == "" {
		t.Skip("REFRESH_GOLDEN not set; skipping fixture refresh")
	}

	if err := refreshGoldenFixtures(t); err != nil {
		t.Fatalf("refresh golden fixtures: %v", err)
	}
	t.Log("golden fixtures refreshed in testdata/hoodi/")
}

// refreshGoldenFixtures regenerates all files in testdata/hoodi/. It is also
// called by the Makefile's refresh-golden target (via REFRESH_GOLDEN=1).
func refreshGoldenFixtures(t *testing.T) error {
	t.Helper()

	// Ensure BLS is initialized.
	if err := bls.Init(); err != nil {
		return fmt.Errorf("bls.Init: %w", err)
	}

	// Derive the real BLS public key from goldenSecret.
	signer, err := bls.NewSigner(goldenSecret[:])
	if err != nil {
		return fmt.Errorf("bls.NewSigner: %w", err)
	}
	pub, err := signer.PublicKey()
	if err != nil {
		return fmt.Errorf("signer.PublicKey: %w", err)
	}
	pubHex := hex.EncodeToString(pub[:])

	// Encrypt the secret using wealdtech keystorev4. We use scrypt with the
	// default cost (N=2^18) so decrypt in CI is fast enough (< 1 second).
	keystoreBytes, err := encryptToKeystoreJSON(t, goldenSecret[:], goldenPassphrase, pubHex)
	if err != nil {
		return fmt.Errorf("encrypt keystore: %w", err)
	}

	// Run the full deposit pipeline.
	verifier := bls.DefaultVerifier()
	params, err := network.Lookup(network.Hoodi)
	if err != nil {
		return fmt.Errorf("network.Lookup: %w", err)
	}
	gen := deposit.NewGenerator(signer, verifier, params)

	req := deposit.Request{
		Network:               network.Hoodi,
		Pubkeys:               [][48]byte{pub},
		WithdrawalCredentials: deriveWC01(withdrawalAddressFromKeys(t)),
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
	if err := os.MkdirAll(testdataDir+"/keystores", 0o750); err != nil {
		return fmt.Errorf("mkdir testdata/hoodi/keystores: %w", err)
	}

	files := map[string][]byte{
		testdataDir + "/keystores/keystore.json":    keystoreBytes,
		testdataDir + "/passphrase.txt":             []byte(goldenPassphrase),
		testdataDir + "/pubkeys.txt":                []byte(pubHex),
		testdataDir + "/deposit_data-expected.json": depositBuf.Bytes(),
	}
	for path, data := range files {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(data))
	}

	// Write one artifact using atomicio naming (M0.3) so fixture dir contains
	// deposit_data-<RFC3339Nano>-<sha256[:4]>.json (M0.10-1 AC + reviewer check).
	if _, _, err := atomicio.WriteFileWithSuffix(testdataDir, "deposit_data", "json", depositBuf.Bytes(), 0o600, time.Now()); err != nil {
		return fmt.Errorf("atomicio scheme demo write: %w", err)
	}

	return nil
}

// encryptToKeystoreJSON encrypts secret with passphrase and returns the
// serialized EIP-2335 v4 keystore JSON bytes. pubHex is the lowercase hex
// pubkey stored in the keystore's "pubkey" field.
//
// Uses scrypt with the default cost power (N=2^18=262144), which is the
// same value used by staking-deposit-cli v2.7.0. Decryption takes roughly
// 0.2–0.5 seconds on modern hardware — acceptable for a CI fixture test
// that decrypts once per test run.
func encryptToKeystoreJSON(t *testing.T, secret []byte, passphrase, pubHex string) ([]byte, error) {
	t.Helper()
	// WithCipher("scrypt") without WithCost → defaultCostPower=18 (N=2^18=262144).
	enc := keystorev4.New(keystorev4.WithCipher("scrypt"), keystorev4.WithCost(t, 18))
	crypto, err := enc.Encrypt(secret, passphrase)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	ks := map[string]any{
		"crypto":  crypto,
		"pubkey":  pubHex,
		"version": 4,
		"uuid":    "10000000-0000-0000-0000-000000000001",
		"path":    "m/12381/3600/0/0/0",
	}

	data, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal keystore: %w", err)
	}
	return data, nil
}
