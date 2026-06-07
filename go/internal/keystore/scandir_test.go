package keystore_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/rootwarp/eth-utils/go/internal/keystore"
)

// writeKeystoreFile writes a minimal EIP-2335-like JSON file with the given
// pubkey (and optional extra field override) to a temp directory.
// Returns the file path.
func writeKeystoreFile(t *testing.T, dir, filename, pubkeyHex string) string {
	t.Helper()
	ks := map[string]any{
		"pubkey":  pubkeyHex,
		"version": 4,
	}
	data, err := json.Marshal(ks)
	if err != nil {
		t.Fatalf("marshal keystore: %v", err)
	}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write keystore file: %v", err)
	}
	return path
}

// writeRawFile writes arbitrary bytes to a named file in dir.
func writeRawFile(t *testing.T, dir, filename string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write raw file: %v", err)
	}
	return path
}

// TestScanDir covers the table-driven cases from Issue #25 AC7.
func TestScanDir(t *testing.T) {
	t.Run("dir_does_not_exist", func(t *testing.T) {
		nonExistent := filepath.Join(t.TempDir(), "no-such-dir")
		_, err := keystore.ScanDir(nonExistent, nil)
		if err == nil {
			t.Fatal("ScanDir(nonExistent) error = nil, want error")
		}
	})

	t.Run("empty_dir_returns_empty_index", func(t *testing.T) {
		dir := t.TempDir()
		idx, err := keystore.ScanDir(dir, nil)
		if err != nil {
			t.Fatalf("ScanDir(empty dir) error = %v, want nil", err)
		}
		if len(idx) != 0 {
			t.Errorf("ScanDir(empty dir) len = %d, want 0", len(idx))
		}
	})

	t.Run("single_matching_keystore", func(t *testing.T) {
		dir := t.TempDir()
		const pubkey = "aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd"
		wantPath := writeKeystoreFile(t, dir, "keystore.json", pubkey)

		idx, err := keystore.ScanDir(dir, nil)
		if err != nil {
			t.Fatalf("ScanDir error = %v, want nil", err)
		}
		if len(idx) != 1 {
			t.Fatalf("ScanDir len = %d, want 1", len(idx))
		}

		got, ok := idx.Lookup(pubkey)
		if !ok {
			t.Fatalf("Lookup(%q) ok = false, want true", pubkey)
		}
		if got != wantPath {
			t.Errorf("Lookup(%q) path = %q, want %q", pubkey, got, wantPath)
		}
	})

	t.Run("pubkey_with_0x_prefix_normalized", func(t *testing.T) {
		dir := t.TempDir()
		const bare = "aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd"
		// Keystore file stores with 0x prefix (common in staking-deposit-cli output)
		writeKeystoreFile(t, dir, "keystore.json", "0x"+bare)

		idx, err := keystore.ScanDir(dir, nil)
		if err != nil {
			t.Fatalf("ScanDir error = %v", err)
		}
		// Lookup with the bare hex (no prefix) should still find it
		_, ok := idx.Lookup(bare)
		if !ok {
			t.Errorf("Lookup(%q) after 0x-prefixed write: ok = false, want true", bare)
		}
		// Lookup with 0x prefix should also work (Lookup normalizes)
		_, ok = idx.Lookup("0x" + bare)
		if !ok {
			t.Errorf("Lookup(0x+%q) ok = false, want true", bare)
		}
	})

	t.Run("mixed_valid_and_invalid_json", func(t *testing.T) {
		dir := t.TempDir()
		const goodPubkey = "aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd"
		goodPath := writeKeystoreFile(t, dir, "good.json", goodPubkey)

		// Invalid JSON — should be silently skipped
		writeRawFile(t, dir, "bad.json", []byte("not-json!!!"))

		// Valid JSON but no pubkey field — should be silently skipped
		noPubkeyData, _ := json.Marshal(map[string]any{"version": 4})
		writeRawFile(t, dir, "nopubkey.json", noPubkeyData)

		// A non-.json file — should be ignored entirely
		writeRawFile(t, dir, "notes.txt", []byte("just notes"))

		idx, err := keystore.ScanDir(dir, nil)
		if err != nil {
			t.Fatalf("ScanDir error = %v, want nil", err)
		}
		// Only the valid keystore should be indexed
		if len(idx) != 1 {
			t.Errorf("ScanDir len = %d, want 1 (only good.json)", len(idx))
		}
		got, ok := idx.Lookup(goodPubkey)
		if !ok {
			t.Fatalf("Lookup(%q) ok = false, want true", goodPubkey)
		}
		if got != goodPath {
			t.Errorf("Lookup path = %q, want %q", got, goodPath)
		}
	})

	t.Run("pubkey_not_found_via_lookup", func(t *testing.T) {
		dir := t.TempDir()
		const indexedPubkey = "aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd"
		writeKeystoreFile(t, dir, "keystore.json", indexedPubkey)

		idx, err := keystore.ScanDir(dir, nil)
		if err != nil {
			t.Fatalf("ScanDir error = %v", err)
		}

		_, ok := idx.Lookup("ffffffff00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd")
		if ok {
			t.Error("Lookup(unknown pubkey) ok = true, want false")
		}
	})

	t.Run("multiple_keystores", func(t *testing.T) {
		dir := t.TempDir()
		const pubkey1 = "aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd"
		const pubkey2 = "bbccddee00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd"
		path1 := writeKeystoreFile(t, dir, "validator1.json", pubkey1)
		path2 := writeKeystoreFile(t, dir, "validator2.json", pubkey2)

		idx, err := keystore.ScanDir(dir, nil)
		if err != nil {
			t.Fatalf("ScanDir error = %v", err)
		}
		if len(idx) != 2 {
			t.Fatalf("ScanDir len = %d, want 2", len(idx))
		}

		got1, ok1 := idx.Lookup(pubkey1)
		if !ok1 {
			t.Fatalf("Lookup(pubkey1) ok = false")
		}
		if got1 != path1 {
			t.Errorf("Lookup(pubkey1) path = %q, want %q", got1, path1)
		}

		got2, ok2 := idx.Lookup(pubkey2)
		if !ok2 {
			t.Fatalf("Lookup(pubkey2) ok = false")
		}
		if got2 != path2 {
			t.Errorf("Lookup(pubkey2) path = %q, want %q", got2, path2)
		}
	})

	t.Run("directory_entry_skipped", func(t *testing.T) {
		dir := t.TempDir()
		// Create a subdirectory named something.json — should NOT be indexed
		subdir := filepath.Join(dir, "subdir.json")
		if err := os.Mkdir(subdir, 0o750); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}

		idx, err := keystore.ScanDir(dir, nil)
		if err != nil {
			t.Fatalf("ScanDir error = %v", err)
		}
		if len(idx) != 0 {
			t.Errorf("ScanDir len = %d, want 0 (directory should be skipped)", len(idx))
		}
	})
}

// TestErrKeystoreNotFound verifies the sentinel is defined and is an error.
func TestErrKeystoreNotFound(t *testing.T) {
	if keystore.ErrKeystoreNotFound == nil {
		t.Fatal("ErrKeystoreNotFound is nil")
	}
	if !errors.Is(keystore.ErrKeystoreNotFound, keystore.ErrKeystoreNotFound) {
		t.Fatal("errors.Is(ErrKeystoreNotFound, ErrKeystoreNotFound) = false")
	}
}

// TestScanDir_ReadError_WarnLogged (mock unreadable dir entry): warning record present in injected logger.
func TestScanDir_ReadError_WarnLogged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm-based read error simulation via Chmod(0o000) requires POSIX owner bits for owner EACCES on os.ReadFile (Unix-oriented per AC2 test design)")
	}
	dir := t.TempDir()
	// Create a .json file then make it unreadable to trigger the read-err path inside ScanDir.
	badPath := writeRawFile(t, dir, "unreadable.json", []byte(`{"pubkey":"aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd","version":4}`))
	if err := os.Chmod(badPath, 0o000); err != nil {
		t.Fatalf("Chmod unreadable: %v", err)
	}
	defer func() { _ = os.Chmod(badPath, 0o600) }() // best-effort restore for cleanup

	var logBuf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	idx, err := keystore.ScanDir(dir, lg)
	if err != nil {
		t.Fatalf("ScanDir error = %v, want nil (read err inside is skipped)", err)
	}
	if len(idx) != 0 {
		t.Errorf("ScanDir len = %d, want 0 (unreadable entry skipped)", len(idx))
	}

	logs := logBuf.String()
	if !strings.Contains(logs, "WARN") && !strings.Contains(logs, "level=WARN") {
		t.Errorf("expected WARN record in captured logger, got: %q", logs)
	}
	if !strings.Contains(logs, "skipping file (read error)") {
		t.Errorf("expected read error warn msg, got: %q", logs)
	}
}

// TestScanDir_Symlink_Skipped: symlink (named *.json) in dir → skipped + WARN logged.
// Uses writeRawFile + os.Symlink (exact style from M1.4-2's writeRaw+Chmod read-err test;
// no new helpers).
func TestScanDir_Symlink_Skipped(t *testing.T) {
	dir := t.TempDir()
	// Target does not end in .json so only the symlink entry is a .json candidate.
	target := writeRawFile(t, dir, "target.txt", []byte(`{"pubkey":"aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd","version":4}`))
	symPath := filepath.Join(dir, "symlink.json")
	if err := os.Symlink(target, symPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	var logBuf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	idx, err := keystore.ScanDir(dir, lg)
	if err != nil {
		t.Fatalf("ScanDir error = %v, want nil (symlink skipped)", err)
	}
	if len(idx) != 0 {
		t.Errorf("ScanDir len = %d, want 0 (symlink entry skipped, target not .json)", len(idx))
	}

	logs := logBuf.String()
	if !strings.Contains(logs, "WARN") && !strings.Contains(logs, "level=WARN") {
		t.Errorf("expected WARN record in captured logger, got: %q", logs)
	}
	if !strings.Contains(logs, "skipping file (non-regular)") {
		t.Errorf("expected non-regular skip warn msg, got: %q", logs)
	}
}

// TestScanDir_FIFO_Skipped (Unix-only, mocked): FIFO named *.json → skipped + WARN logged
// before any open/read (prevents hang). Uses syscall.Mkfifo + writeRaw+Chmod test style;
// no new helpers. Skips on windows like the read-err AC test.
func TestScanDir_FIFO_Skipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("FIFO creation via syscall.Mkfifo is Unix-only (per AC; mocked via type check)")
	}
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "fifo.json")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	// Do not open/write the fifo; the IsRegular check must skip before os.Open/ReadFile.

	var logBuf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	idx, err := keystore.ScanDir(dir, lg)
	if err != nil {
		t.Fatalf("ScanDir error = %v, want nil (fifo skipped)", err)
	}
	if len(idx) != 0 {
		t.Errorf("ScanDir len = %d, want 0 (fifo entry skipped)", len(idx))
	}

	logs := logBuf.String()
	if !strings.Contains(logs, "WARN") && !strings.Contains(logs, "level=WARN") {
		t.Errorf("expected WARN record in captured logger, got: %q", logs)
	}
	if !strings.Contains(logs, "skipping file (non-regular)") {
		t.Errorf("expected non-regular skip warn msg, got: %q", logs)
	}
}
