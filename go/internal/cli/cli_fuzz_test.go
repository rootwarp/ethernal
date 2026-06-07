package cli

import (
	"flag"
	"strings"
	"testing"

	ucli "github.com/urfave/cli/v2"
)

// FuzzParsePubkeys fuzzes the pubkey parsing logic to ensure it never panics,
// regardless of the input. Run with: go test -fuzz FuzzParsePubkeys ./internal/cli/
func FuzzParsePubkeys(f *testing.F) {
	// Seed corpus: valid and interesting inputs
	validPubkey := "93247f2209abcacfe7b55561da7ae6c4f1df5d7f36a2f4f11e0f5f9d0aa2e7e8b9d0a1c2e3f4a5b6c7d8e9f0a1b2c3d4"
	validPubkey2 := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"

	f.Add([]byte(validPubkey))
	f.Add([]byte("0x" + validPubkey))
	f.Add([]byte(validPubkey + "," + validPubkey2))
	f.Add([]byte("0x" + validPubkey + ",0x" + validPubkey2))
	f.Add([]byte(""))
	f.Add([]byte(","))
	f.Add([]byte("0x"))
	f.Add([]byte("0xgg"))
	f.Add([]byte(string(make([]byte, 200))))
	f.Add([]byte("ABCDEF" + validPubkey[:90]))
	f.Add([]byte("0x" + validPubkey + "," + validPubkey2)) // mixed prefix

	f.Fuzz(func(t *testing.T, data []byte) {
		// parsePubkeys must never panic regardless of input.
		// Errors are acceptable; panics are not.
		_, _ = parsePubkeys(string(data)) // ignore: fuzz only cares about panics; returned errors (or nils) are expected/ignored
	})
}

// TestRequireNoArgs_Reject (AC for M0.4-7): when a positional arg is present,
// returns ucli.Exit with code 2 whose message contains the offending arg.
func TestRequireNoArgs_Reject(t *testing.T) {
	app := ucli.NewApp()
	fs := flag.NewFlagSet("test", 0)
	_ = fs.Parse([]string{"foo"}) // "foo" becomes a positional arg
	c := ucli.NewContext(app, fs, nil)
	err := requireNoArgs(c)
	if err == nil {
		t.Fatal("requireNoArgs with positional arg: err = nil, want error")
	}
	exitErr, ok := err.(ucli.ExitCoder)
	if !ok {
		t.Fatalf("error type %T is not ucli.ExitCoder", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Errorf("ExitCode = %d, want 2", exitErr.ExitCode())
	}
	if !strings.Contains(err.Error(), "foo") {
		t.Errorf("error message %q does not contain the arg %q", err.Error(), "foo")
	}
}

// TestRequireNoArgs_Accept (AC for M0.4-7): with zero positional args,
// returns nil (no error).
func TestRequireNoArgs_Accept(t *testing.T) {
	app := ucli.NewApp()
	fs := flag.NewFlagSet("test", 0)
	// no args parsed → NArg()==0
	c := ucli.NewContext(app, fs, nil)
	if err := requireNoArgs(c); err != nil {
		t.Errorf("requireNoArgs with zero args: got err = %v, want nil", err)
	}
}
