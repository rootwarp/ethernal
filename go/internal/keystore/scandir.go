package keystore

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// ErrKeystoreNotFound is returned when a pubkey's keystore cannot be found in
// the DirectoryIndex. Callers use errors.Is to detect it; it maps to exit code 2.
var ErrKeystoreNotFound = errors.New("keystore not found for pubkey")

// DirectoryIndex maps a lowercase, 0x-prefix-stripped pubkey hex string to the
// absolute filesystem path of the keystore file that declares it.
//
// Callers must not mutate the map; use Lookup for safe read access.
type DirectoryIndex map[string]string

// Lookup returns the path of the keystore file for the given pubkey hex.
// pubkeyHex is normalized (lowercased, 0x prefix stripped) before lookup so
// callers may pass prefixed or unprefixed hex.
func (d DirectoryIndex) Lookup(pubkeyHex string) (string, bool) {
	normalized := strings.ToLower(strings.TrimPrefix(pubkeyHex, "0x"))
	p, ok := d[normalized]
	return p, ok
}

// pubkeyEnvelope is the minimal JSON shape needed to read the pubkey field from
// an EIP-2335 keystore without performing any decryption.
type pubkeyEnvelope struct {
	Pubkey string `json:"pubkey"`
}

// ScanDir reads all *.json files in dir and builds a DirectoryIndex mapping each
// file's "pubkey" field to its absolute path. No decryption or wealdtech calls
// are made; only the top-level "pubkey" JSON field is parsed.
//
// Files that lack a "pubkey" field or contain invalid JSON are silently skipped
// (a Debug message is emitted per skipped file if logger non-nil). Read errors
// are logged at Warn. Directories and non-.json entries are also skipped.
//
// A non-nil error is returned only if dir cannot be listed at all (e.g. it does
// not exist or the caller lacks read permission).
//
// (Internal signature break documented in MIGRATION.md per M1.4-2 / GO-028; all
// in-tree callers were updated.)
func ScanDir(dir string, logger *slog.Logger) (DirectoryIndex, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err // bare return (pre-existing; GO-046 / %w audit deferred to M1.5 per narrow M1.4-2 scope + no %w changes decision)
	}

	index := make(DirectoryIndex, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}

		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			if logger != nil {
				logger.Warn("keystore.ScanDir: skipping file (read error)", "path", path, "error", err)
			}
			continue
		}

		var env pubkeyEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			if logger != nil {
				logger.Debug("keystore.ScanDir: skipping file (invalid JSON)", "path", path, "error", err)
			}
			continue
		}

		if env.Pubkey == "" {
			if logger != nil {
				logger.Debug("keystore.ScanDir: skipping file (missing pubkey field)", "path", path)
			}
			continue
		}

		normalized := strings.ToLower(strings.TrimPrefix(env.Pubkey, "0x"))
		index[normalized] = path
	}

	return index, nil
}
