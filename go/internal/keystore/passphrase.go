package keystore

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// envSource is a PassphraseSource that reads from a named environment variable.
type envSource struct {
	varName string
}

// NewEnvSource returns a PassphraseSource that reads os.Getenv(varName).
// If the variable is unset or empty, Read returns ErrEnvVarEmpty (exit code 2).
func NewEnvSource(varName string) PassphraseSource {
	return &envSource{varName: varName}
}

// Read returns the passphrase from the environment variable.
func (e *envSource) Read() ([]byte, error) {
	val := os.Getenv(e.varName)
	if val == "" {
		return nil, fmt.Errorf("%w: %s", ErrEnvVarEmpty, e.varName)
	}
	return []byte(val), nil
}

// termPromptSource is a PassphraseSource that reads from /dev/tty with echo
// suppression, writing a prompt to a provided writer.
type termPromptSource struct {
	w io.Writer
	// openTTY opens the controlling terminal. It is a field so tests can force
	// the no-TTY error path without depending on the real /dev/tty, which is
	// non-deterministic under `go test`.
	openTTY func() (*os.File, error)
}

// NewTermPromptSource returns a PassphraseSource that prompts on w and reads
// the passphrase from /dev/tty using golang.org/x/term.ReadPassword.
// Echo is suppressed so the passphrase is never displayed.
func NewTermPromptSource(w io.Writer) PassphraseSource {
	return &termPromptSource{w: w, openTTY: openControllingTTY}
}

// openControllingTTY opens the process's controlling terminal for read/write.
func openControllingTTY() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// Read prompts the user and reads a passphrase from /dev/tty without echo.
func (t *termPromptSource) Read() ([]byte, error) {
	tty, err := t.openTTY()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open /dev/tty (%v); for non-interactive or piped use, supply the passphrase via --passphrase-env VAR", ErrNoTTY, err)
	}
	defer tty.Close()

	fmt.Fprint(t.w, "Keystore passphrase: ")

	pw, err := term.ReadPassword(int(tty.Fd()))
	// Print a newline after the (suppressed) input.
	fmt.Fprintln(t.w)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}

	return pw, nil
}
