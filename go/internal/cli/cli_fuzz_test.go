package cli

import (
	"testing"
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
		parsePubkeys(string(data)) //nolint:errcheck
	})
}
