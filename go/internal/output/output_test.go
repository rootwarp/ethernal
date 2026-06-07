package output

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rootwarp/eth-utils/go/internal/deposit"
	"github.com/rootwarp/eth-utils/go/internal/network"
)

// testEntries returns 2 deposit.Entry values with known, deterministic test data.
// All byte fields are all-zeros, Amount=32_000_000_000, DepositCLIVersion="2.7.0",
// NetworkName="hoodi", ForkVersion=[4]byte{0x10,0x00,0x09,0x10}.
func testEntries() []deposit.Entry {
	forkVersion := [4]byte{0x10, 0x00, 0x09, 0x10}
	entry := deposit.Entry{
		Pubkey:                [48]byte{},
		WithdrawalCredentials: [32]byte{},
		Amount:                32_000_000_000,
		Signature:             [96]byte{},
		DepositMessageRoot:    [32]byte{},
		DepositDataRoot:       [32]byte{},
		ForkVersion:           forkVersion,
		NetworkName:           network.Hoodi,
		DepositCLIVersion:     "2.7.0",
	}
	return []deposit.Entry{entry, entry}
}

// goldenBytes reads and returns the committed golden fixture.
func goldenBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/deposit_data-expected.json")
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}
	return b
}

// -----------------------------------------------------------------------------
// TestNewDryRunWriter_GoldenMatch
//
// Serialize the 2-entry fixture via DryRunWriter and diff byte-for-byte against
// the committed golden file.
// -----------------------------------------------------------------------------

func TestNewDryRunWriter_GoldenMatch(t *testing.T) {
	entries := testEntries()

	var buf bytes.Buffer
	w := NewDryRunWriter(&buf)

	now := time.Unix(1_700_000_000, 0) // deterministic, unused for path in dry-run
	_, sha256hex, err := w.Write(context.Background(), "", entries, now)
	if err != nil {
		t.Fatalf("DryRunWriter.Write() error: %v", err)
	}

	got := buf.Bytes()
	want := goldenBytes(t)

	if !bytes.Equal(got, want) {
		t.Errorf("JSON output does not match golden file.\ngot:\n%s\nwant:\n%s", got, want)
	}

	// Verify sha256hex matches hex(sha256(got))
	h := sha256.Sum256(got)
	wantHex := hex.EncodeToString(h[:])
	if sha256hex != wantHex {
		t.Errorf("sha256hex = %q, want %q", sha256hex, wantHex)
	}
}

// -----------------------------------------------------------------------------
// TestNewDryRunWriter_ReturnsEmptyPath
// -----------------------------------------------------------------------------

func TestNewDryRunWriter_ReturnsEmptyPath(t *testing.T) {
	var buf bytes.Buffer
	w := NewDryRunWriter(&buf)

	path, _, err := w.Write(context.Background(), "", testEntries(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "" {
		t.Errorf("DryRunWriter path = %q, want empty string", path)
	}
}

// -----------------------------------------------------------------------------
// TestNewFSWriter_Success
//
// Write entries to a temp dir, verify the returned path, file contents match
// the golden fixture, and the sha256hex is correct.
// -----------------------------------------------------------------------------

func TestNewFSWriter_Success(t *testing.T) {
	dir := t.TempDir()
	entries := testEntries()

	now := time.Unix(1_700_000_000, 0)
	w := NewFSWriter()

	path, sha256hex, err := w.Write(context.Background(), dir, entries, now)
	if err != nil {
		t.Fatalf("FSWriter.Write() error: %v", err)
	}

	// Verify the returned path has the correct format.
	expectedFilename := "deposit_data-1700000000.json"
	if filepath.Base(path) != expectedFilename {
		t.Errorf("returned path base = %q, want %q", filepath.Base(path), expectedFilename)
	}
	if filepath.Dir(path) != dir {
		t.Errorf("returned path dir = %q, want %q", filepath.Dir(path), dir)
	}

	// Read the written file and compare to golden.
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}

	want := goldenBytes(t)
	if !bytes.Equal(fileBytes, want) {
		t.Errorf("written file does not match golden.\ngot:\n%s\nwant:\n%s", fileBytes, want)
	}

	// Verify sha256hex.
	h := sha256.Sum256(fileBytes)
	wantHex := hex.EncodeToString(h[:])
	if sha256hex != wantHex {
		t.Errorf("sha256hex = %q, want %q", sha256hex, wantHex)
	}
}

// -----------------------------------------------------------------------------
// TestNewFSWriter_NoTmpFileAfterSuccess
//
// After a successful Write, no .tmp file should remain in the directory.
// -----------------------------------------------------------------------------

func TestNewFSWriter_NoTmpFileAfterSuccess(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)

	w := NewFSWriter()
	_, _, err := w.Write(context.Background(), dir, testEntries(), now)
	if err != nil {
		t.Fatalf("FSWriter.Write() error: %v", err)
	}

	// Scan the directory for any .tmp files.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("tmp file left behind after successful write: %q", e.Name())
		}
	}
}

// -----------------------------------------------------------------------------
// TestNewFSWriter_FileNameContainsUnixTimestamp
// -----------------------------------------------------------------------------

func TestNewFSWriter_FileNameContainsUnixTimestamp(t *testing.T) {
	dir := t.TempDir()
	ts := int64(1_234_567_890)
	now := time.Unix(ts, 0)

	w := NewFSWriter()
	path, _, err := w.Write(context.Background(), dir, testEntries(), now)
	if err != nil {
		t.Fatalf("FSWriter.Write() error: %v", err)
	}

	expectedName := "deposit_data-1234567890.json"
	if filepath.Base(path) != expectedName {
		t.Errorf("filename = %q, want %q", filepath.Base(path), expectedName)
	}
}

// -----------------------------------------------------------------------------
// TestToJSONEntry_HexEncoding
//
// Verify hex encoding: no 0x prefix, lowercase.
// -----------------------------------------------------------------------------

func TestToJSONEntry_HexEncoding(t *testing.T) {
	var pubkey [48]byte
	pubkey[0] = 0xAB
	pubkey[1] = 0xCD

	var wc [32]byte
	wc[0] = 0xEF

	var sig [96]byte
	sig[0] = 0x12
	sig[1] = 0x34

	var msgRoot [32]byte
	msgRoot[0] = 0xAA

	var dataRoot [32]byte
	dataRoot[0] = 0xBB

	entry := deposit.Entry{
		Pubkey:                pubkey,
		WithdrawalCredentials: wc,
		Amount:                32_000_000_000,
		Signature:             sig,
		DepositMessageRoot:    msgRoot,
		DepositDataRoot:       dataRoot,
		ForkVersion:           [4]byte{0x10, 0x00, 0x09, 0x10},
		NetworkName:           network.Hoodi,
		DepositCLIVersion:     "2.7.0",
	}

	je := toJSONEntry(entry)

	// No 0x prefix.
	if strings.HasPrefix(je.Pubkey, "0x") {
		t.Errorf("Pubkey has 0x prefix: %q", je.Pubkey)
	}
	// Lowercase.
	if je.Pubkey != strings.ToLower(je.Pubkey) {
		t.Errorf("Pubkey is not lowercase: %q", je.Pubkey)
	}
	// Length: 48 bytes = 96 hex chars.
	if len(je.Pubkey) != 96 {
		t.Errorf("Pubkey hex length = %d, want 96", len(je.Pubkey))
	}

	// WithdrawalCredentials: 32 bytes = 64 hex chars.
	if strings.HasPrefix(je.WithdrawalCredentials, "0x") {
		t.Errorf("WithdrawalCredentials has 0x prefix")
	}
	if len(je.WithdrawalCredentials) != 64 {
		t.Errorf("WithdrawalCredentials hex length = %d, want 64", len(je.WithdrawalCredentials))
	}

	// Signature: 96 bytes = 192 hex chars.
	if len(je.Signature) != 192 {
		t.Errorf("Signature hex length = %d, want 192", len(je.Signature))
	}

	// ForkVersion: 4 bytes = 8 hex chars.
	if len(je.ForkVersion) != 8 {
		t.Errorf("ForkVersion hex length = %d, want 8", len(je.ForkVersion))
	}

	// Amount is a number in JSON.
	b, _ := json.Marshal(je)
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(b, &raw)
	amtRaw := string(raw["amount"])
	if strings.HasPrefix(amtRaw, `"`) {
		t.Errorf("amount is encoded as a string in JSON, want number: %s", amtRaw)
	}
}

// -----------------------------------------------------------------------------
// TestJSONFieldOrder
//
// Verify the JSON field order matches the spec exactly.
// -----------------------------------------------------------------------------

func TestJSONFieldOrder(t *testing.T) {
	entries := testEntries()[:1]

	var buf bytes.Buffer
	w := NewDryRunWriter(&buf)
	_, _, err := w.Write(context.Background(), "", entries, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse first object's keys in order.
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))

	// consume '['
	if _, err := dec.Token(); err != nil {
		t.Fatal(err)
	}
	// consume '{'
	if _, err := dec.Token(); err != nil {
		t.Fatal(err)
	}

	expectedFields := []string{
		"pubkey",
		"withdrawal_credentials",
		"amount",
		"signature",
		"deposit_message_root",
		"deposit_data_root",
		"fork_version",
		"network_name",
		"deposit_cli_version",
	}

	for i, want := range expectedFields {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("reading key %d: %v", i, err)
		}
		key, ok := tok.(string)
		if !ok {
			t.Fatalf("expected string key at position %d, got %T", i, tok)
		}
		if key != want {
			t.Errorf("field[%d] = %q, want %q", i, key, want)
		}
		// consume the value token
		if _, err := dec.Token(); err != nil {
			t.Fatalf("reading value %d: %v", i, err)
		}
	}
}

// -----------------------------------------------------------------------------
// TestNewDryRunWriter_SHA256MatchesFSWriter
//
// Both writers over the same entries must produce the same sha256hex.
// -----------------------------------------------------------------------------

func TestNewDryRunWriter_SHA256MatchesFSWriter(t *testing.T) {
	dir := t.TempDir()
	entries := testEntries()
	now := time.Unix(1_700_000_000, 0)

	var buf bytes.Buffer
	dryW := NewDryRunWriter(&buf)
	_, drySHA, err := dryW.Write(context.Background(), "", entries, now)
	if err != nil {
		t.Fatalf("DryRunWriter error: %v", err)
	}

	fsW := NewFSWriter()
	_, fsSHA, err := fsW.Write(context.Background(), dir, entries, now)
	if err != nil {
		t.Fatalf("FSWriter error: %v", err)
	}

	if drySHA != fsSHA {
		t.Errorf("sha256hex mismatch: dry=%q fs=%q", drySHA, fsSHA)
	}
}

// -----------------------------------------------------------------------------
// TestNewFSWriter_NonExistentDir
//
// Writing to a non-existent directory should return an error.
// -----------------------------------------------------------------------------

func TestNewFSWriter_NonExistentDir(t *testing.T) {
	nonExistent := filepath.Join(t.TempDir(), "does-not-exist")

	w := NewFSWriter()
	_, _, err := w.Write(context.Background(), nonExistent, testEntries(), time.Now())
	if err == nil {
		t.Error("FSWriter.Write() succeeded for non-existent dir, want error")
	}
}

// -----------------------------------------------------------------------------
// errorWriter is an io.Writer that always returns an error.
// -----------------------------------------------------------------------------

type errorWriter struct{}

func (e *errorWriter) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("simulated write failure")
}

// -----------------------------------------------------------------------------
// TestNewDryRunWriter_WriteError
//
// When the underlying writer fails, DryRunWriter.Write should return the error.
// -----------------------------------------------------------------------------

func TestNewDryRunWriter_WriteError(t *testing.T) {
	w := NewDryRunWriter(&errorWriter{})
	_, _, err := w.Write(context.Background(), "", testEntries(), time.Now())
	if err == nil {
		t.Error("DryRunWriter.Write() succeeded despite underlying write error, want error")
	}
}
