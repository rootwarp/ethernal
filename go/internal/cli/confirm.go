package cli

import (
	"errors"
	"io"
	"os"

	"golang.org/x/term"
)

// ErrNoTTY is returned by ConfirmReader when neither the provided stdin nor
// /dev/tty can supply a controlling terminal for interactive confirmation.
var ErrNoTTY = errors.New("no controlling TTY available; --yes required")

// ConfirmReader returns a reader suitable for confirmation prompts per
// architecture §15.
//
// If stdin is a *os.File that term.IsTerminal reports as a TTY, it is returned
// directly with a no-op cleanup func.
//
// Otherwise /dev/tty is opened (O_RDWR); the returned reader is that file and
// the cleanup func closes it (best-effort, errors ignored per repo pattern).
//
// If neither is possible, ErrNoTTY is returned with a no-op cleanup.
// The caller is responsible for calling the cleanup func exactly once (e.g. via
// defer) and for deciding whether to treat ErrNoTTY as exit 2 (when --yes is
// not set).
func ConfirmReader(stdin io.Reader) (r io.Reader, cleanup func(), err error) {
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return f, func() {}, nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, func() {}, ErrNoTTY
	}
	return tty, func() { _ = tty.Close() }, nil // ignore: best-effort close of /dev/tty
}
