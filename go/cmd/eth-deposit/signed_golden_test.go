package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ucli "github.com/urfave/cli/v3"
)

// TestPhase3_HoleskyLocalSignerGolden signs the Phase 3 unsigned fixture with the
// synthetic key and asserts byte-for-byte equality with the committed golden file.
// Set UPDATE_PHASE3_GOLDEN=1 to regenerate.
func TestPhase3_HoleskyLocalSignerGolden(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	repoRoot := findRepoRoot(t)
	fixtureDir := filepath.Join(repoRoot, "go", "testdata", "phase3", "holesky")
	unsignedPath := filepath.Join(fixtureDir, "unsigned_tx.json")
	goldenPath := filepath.Join(fixtureDir, "signed_tx_golden.json")
	keyFile := filepath.Join(fixtureDir, "private_key.txt")

	// Read the synthetic test key.
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("could not read synthetic key file %s: %v", keyFile, err)
	}
	key := strings.TrimSpace(string(keyBytes))

	// Use a unique env var name for this test run.
	const envVarName = "TEST_PHASE3_GOLDEN_KEY"
	t.Setenv(envVarName, key)

	outFile := filepath.Join(t.TempDir(), "signed_tx.json")

	app := newTestApp()
	var buf bytes.Buffer
	app.Writer = &buf
	app.ErrWriter = &buf

	err = app.Run(context.Background(), []string{
		"eth-deposit", "sign",
		"--signer", "local",
		"--input", unsignedPath,
		"--output", outFile,
		"--private-key-env", envVarName,
	})
	if err != nil {
		t.Fatalf("sign command failed: %v\nstderr: %s", err, buf.String())
	}

	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("could not read output file: %v", err)
	}

	if os.Getenv("UPDATE_PHASE3_GOLDEN") != "" {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("could not update phase3 golden: %v", err)
		}
		t.Logf("phase3 golden updated: %s", goldenPath)
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("could not read golden file %s: %v (run with UPDATE_PHASE3_GOLDEN=1 to create it)", goldenPath, err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("phase3 golden mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}
}
