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

func (e *envSource) Zeroize() {}

// termPromptSource is a PassphraseSource that reads from /dev/tty with echo
// suppression, writing a prompt to a provided writer.
type termPromptSource struct {
	w io.Writer
}

// NewTermPromptSource returns a PassphraseSource that prompts on w and reads
// the passphrase from /dev/tty using golang.org/x/term.ReadPassword.
// Echo is suppressed so the passphrase is never displayed.
func NewTermPromptSource(w io.Writer) PassphraseSource {
	return &termPromptSource{w: w}
}

// Read prompts the user and reads a passphrase from /dev/tty without echo.
func (t *termPromptSource) Read() ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open tty: %w", err)
	}
	defer func() { _ = tty.Close() }() // ignore: best-effort tty close after read; does not affect returned passphrase or error

	_, _ = fmt.Fprint(t.w, "Keystore passphrase: ") // ignore: best-effort prompt write (to stderr typically)

	pw, err := term.ReadPassword(int(tty.Fd()))
	// Print a newline after the (suppressed) input.
	_, _ = fmt.Fprintln(t.w) // ignore: best-effort newline after prompt
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}

	return pw, nil
}

func (t *termPromptSource) Zeroize() {}
