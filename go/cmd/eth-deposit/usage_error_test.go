package main

import (
	"bytes"
	"context"
	"testing"

	ucli "github.com/urfave/cli/v3"
)

// newFullTestApp returns all five subcommands with the production usage-error
// hook applied, so tests can assert exit-2 mapping for missing required flags
// and bad flag values across the whole command surface.
func newFullTestApp() *ucli.Command {
	app := &ucli.Command{
		Name:     "eth-deposit",
		Version:  "dev",
		Commands: []*ucli.Command{genCommand(), buildCommand(), signCommand(), runCommand(), sendCommand()},
	}
	applyUsageErrorHook(app)
	return app
}

// runUsageErr runs the full app with args and returns the error, suppressing any
// real os.Exit that urfave's default ExitCoder handler would trigger.
func runUsageErr(t *testing.T, args ...string) error {
	t.Helper()
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	app := newFullTestApp()
	app.Writer = &bytes.Buffer{}
	app.ErrWriter = &bytes.Buffer{}
	return app.Run(context.Background(), args)
}

// TestUsageError_ExitsTwo covers F2: every subcommand must map a usage error
// (missing required flag, or a bad flag value) to exit code 2, not the exit-1
// fallback. The buggy bucket before the hook was build/gen/sign/run.
func TestUsageError_ExitsTwo(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"build missing --input-file", []string{"eth-deposit", "build", "--network", "holesky"}},
		{"gen missing required flags", []string{"eth-deposit", "gen"}},
		{"sign missing --signer", []string{"eth-deposit", "sign"}},
		{"run missing --input-file", []string{"eth-deposit", "run"}},
		{"build bad --index value", []string{"eth-deposit", "build", "--network", "holesky", "--input-file", "x", "--index", "abc"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runUsageErr(t, tc.args...)
			if err == nil {
				t.Fatalf("%s: got nil error, want a usage error mapping to exit 2", tc.name)
			}
			if got := ExitCodeFor(err); got != 2 {
				t.Errorf("%s: ExitCodeFor(%v) = %d, want 2", tc.name, err, got)
			}
		})
	}
}
