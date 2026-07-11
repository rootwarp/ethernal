package keystore

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestTermPromptSource_NoTTY forces the controlling-terminal open to fail and
// asserts the returned error is tagged ErrNoTTY and points the user at the
// --passphrase-env escape hatch. The opener is injected so the test never
// touches the real /dev/tty (which is non-deterministic under `go test`:
// absent it fails, present it would block on ReadPassword).
func TestTermPromptSource_NoTTY(t *testing.T) {
	openErr := errors.New("no such device or address")
	src := &termPromptSource{
		w: &bytes.Buffer{},
		openTTY: func() (*os.File, error) {
			return nil, openErr
		},
	}

	_, err := src.Read()
	if err == nil {
		t.Fatal("Read() error = nil, want ErrNoTTY")
	}
	if !errors.Is(err, ErrNoTTY) {
		t.Errorf("Read() error = %v, want errors.Is ErrNoTTY", err)
	}
	if !strings.Contains(err.Error(), "--passphrase-env") {
		t.Errorf("Read() error = %q, want message naming --passphrase-env", err)
	}
	// The underlying open error should be surfaced for diagnostics.
	if !strings.Contains(err.Error(), openErr.Error()) {
		t.Errorf("Read() error = %q, want it to include the open failure %q", err, openErr)
	}
}
