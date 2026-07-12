// gen_fixtures_test.go — run with -run TestGenerateFixtures to regenerate
// testdata/keystore-scrypt.json and testdata/keystore-pbkdf2.json.
// This file is intentionally committed; normal test runs skip this test.
//
// To regenerate:
//
//	go test -run TestGenerateFixtures ./internal/keystore/
package keystore_test

import (
	"encoding/json"
	"os"
	"testing"

	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
)

// TestGenerateFixtures writes the testdata fixture keystores.
// It is skipped unless the environment variable GENERATE_FIXTURES is set.
func TestGenerateFixtures(t *testing.T) {
	if os.Getenv("GENERATE_FIXTURES") == "" {
		t.Skip("GENERATE_FIXTURES not set; skipping fixture generation")
	}

	pubkey := testPubkeyHex

	for _, tc := range []struct {
		cipher string
		path   string
	}{
		{"scrypt", "testdata/keystore-scrypt.json"},
		{"pbkdf2", "testdata/keystore-pbkdf2.json"},
	} {
		var enc *keystorev4.Encryptor
		if tc.cipher == "scrypt" {
			// costPower=2 → N=4; intentionally fast for CI (test fixture only).
			enc = keystorev4.New(keystorev4.WithCipher("scrypt"), keystorev4.WithCost(t, 2))
		} else {
			// costPower=2 → C=4 PBKDF2 iterations; intentionally fast for CI.
			enc = keystorev4.New(keystorev4.WithCost(t, 2))
		}

		crypto, err := enc.Encrypt(testSecret, testPassphrase)
		if err != nil {
			t.Fatalf("encrypt %s: %v", tc.cipher, err)
		}

		ks := map[string]any{
			"crypto":  crypto,
			"pubkey":  pubkey,
			"version": 4,
			"uuid":    "00000000-0000-0000-0000-000000000001",
			"path":    "m/12381/3600/0/0/0",
		}

		data, err := json.MarshalIndent(ks, "", "  ")
		if err != nil {
			t.Fatalf("marshal %s: %v", tc.cipher, err)
		}

		if err := os.WriteFile(tc.path, data, 0600); err != nil {
			t.Fatalf("write %s: %v", tc.path, err)
		}
		t.Logf("wrote %s (%s KDF, low-cost test fixture)", tc.path, tc.cipher)
	}
}
