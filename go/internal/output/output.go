// Package output serializes []deposit.Entry to the Launchpad JSON schema and
// writes deposit_data-<unix_ts>.json atomically to the output directory.
//
// Two implementations are provided:
//   - FSWriter: writes to disk using a tmp→rename atomic sequence.
//   - DryRunWriter: writes JSON bytes to an io.Writer (e.g. os.Stdout) instead
//     of disk. Intended for --dry-run mode.
//
// Both implementations compute and return the sha256 hex digest of the JSON
// bytes so callers can verify integrity without re-reading the file.
package output

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rootwarp/eth-utils/go/internal/deposit"
)

// Writer serializes a slice of deposit entries to JSON and persists them.
// Implementations must be safe to call multiple times with different inputs.
type Writer interface {
	// Write serializes entries to the Launchpad JSON schema. The now parameter
	// provides the timestamp used in the output filename.
	//
	// FSWriter returns (finalPath, sha256hex, nil) on success.
	// DryRunWriter returns ("", sha256hex, nil) — path is always empty.
	Write(ctx context.Context, dir string, entries []deposit.Entry, now time.Time) (path string, sha256hex string, err error)
}

// jsonEntry is a private struct whose field order matches the Launchpad JSON
// schema exactly. encoding/json marshals struct fields in declaration order,
// which guarantees byte-for-byte compatibility with the official staking-deposit-cli.
type jsonEntry struct {
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

// toJSONEntry converts a deposit.Entry to a jsonEntry, encoding all byte fields
// as lowercase hex strings without the "0x" prefix.
func toJSONEntry(e deposit.Entry) jsonEntry {
	return jsonEntry{
		Pubkey:                hex.EncodeToString(e.Pubkey[:]),
		WithdrawalCredentials: hex.EncodeToString(e.WithdrawalCredentials[:]),
		Amount:                e.Amount,
		Signature:             hex.EncodeToString(e.Signature[:]),
		DepositMessageRoot:    hex.EncodeToString(e.DepositMessageRoot[:]),
		DepositDataRoot:       hex.EncodeToString(e.DepositDataRoot[:]),
		ForkVersion:           hex.EncodeToString(e.ForkVersion[:]),
		NetworkName:           string(e.NetworkName),
		DepositCLIVersion:     e.DepositCLIVersion,
	}
}

// marshalEntries converts a slice of deposit.Entry values to compact JSON bytes
// formatted as a JSON array. Uses json.Marshal (no indentation) to match the
// official staking-deposit-cli output format.
func marshalEntries(entries []deposit.Entry) ([]byte, error) {
	je := make([]jsonEntry, len(entries))
	for i, e := range entries {
		je[i] = toJSONEntry(e)
	}
	return json.Marshal(je)
}

// digestHex computes the SHA-256 digest of b and returns it as a lowercase
// hex string.
func digestHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// -----------------------------------------------------------------------------
// FSWriter
// -----------------------------------------------------------------------------

type fsWriter struct{}

// NewFSWriter returns a Writer that persists deposit data to disk using an
// atomic tmp→rename sequence. The temporary file is named
// .deposit_data-<ts>.json.tmp and is removed on both success and failure.
func NewFSWriter() Writer {
	return &fsWriter{}
}

// Write serializes entries and atomically writes them to
// dir/deposit_data-<now.Unix()>.json. It returns the final file path and the
// SHA-256 hex digest of the JSON bytes.
//
// Atomic sequence:
//  1. Marshal entries to JSON.
//  2. Write bytes to dir/.deposit_data-<ts>.json.tmp.
//  3. Sync the file.
//  4. Close the file.
//  5. Rename to the final path.
//
// On any failure the temporary file is removed so no stale artifacts remain.
func (w *fsWriter) Write(_ context.Context, dir string, entries []deposit.Entry, now time.Time) (string, string, error) {
	data, err := marshalEntries(entries)
	if err != nil {
		return "", "", fmt.Errorf("output: marshal entries: %w", err)
	}

	ts := now.Unix()
	filename := fmt.Sprintf("deposit_data-%d.json", ts)
	tmpName := fmt.Sprintf(".deposit_data-%d.json.tmp", ts)

	finalPath := filepath.Join(dir, filename)
	tmpPath := filepath.Join(dir, tmpName)

	// Open the temporary file for writing.
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", "", fmt.Errorf("output: open tmp file: %w", err)
	}

	// Ensure cleanup on any failure path before rename.
	// fileClosed tracks whether f was already closed so the defer does not
	// double-close on the rename-failure path.
	committed := false
	fileClosed := false
	defer func() {
		if !committed {
			if !fileClosed {
				f.Close() //nolint:errcheck
			}
			os.Remove(tmpPath) //nolint:errcheck
		}
	}()

	if _, err := f.Write(data); err != nil {
		return "", "", fmt.Errorf("output: write tmp file: %w", err)
	}

	if err := f.Sync(); err != nil {
		return "", "", fmt.Errorf("output: sync tmp file: %w", err)
	}

	if err := f.Close(); err != nil {
		return "", "", fmt.Errorf("output: close tmp file: %w", err)
	}
	fileClosed = true

	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", "", fmt.Errorf("output: rename tmp to final: %w", err)
	}

	committed = true
	return finalPath, digestHex(data), nil
}

// -----------------------------------------------------------------------------
// DryRunWriter
// -----------------------------------------------------------------------------

type dryRunWriter struct {
	w io.Writer
}

// NewDryRunWriter returns a Writer that writes JSON bytes to w instead of disk.
// It is intended for --dry-run mode. The returned path is always empty; the
// sha256hex is computed over the same JSON bytes that would be written to disk.
func NewDryRunWriter(w io.Writer) Writer {
	return &dryRunWriter{w: w}
}

// Write serializes entries and writes the JSON bytes to the underlying
// io.Writer. It returns ("", sha256hex, nil) on success.
func (d *dryRunWriter) Write(_ context.Context, _ string, entries []deposit.Entry, _ time.Time) (string, string, error) {
	data, err := marshalEntries(entries)
	if err != nil {
		return "", "", fmt.Errorf("output: marshal entries: %w", err)
	}

	if _, err := d.w.Write(data); err != nil {
		return "", "", fmt.Errorf("output: write dry-run output: %w", err)
	}

	return "", digestHex(data), nil
}
