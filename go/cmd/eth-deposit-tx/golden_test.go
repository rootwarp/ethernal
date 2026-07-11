package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	ucli "github.com/urfave/cli/v3"
)

// TestPhase2_HoleskyGolden runs build with the phase2 Holesky synthetic fixture
// and asserts the output matches the committed golden file byte-for-byte.
// Set UPDATE_PHASE2_GOLDEN=1 to regenerate.
func TestPhase2_HoleskyGolden(t *testing.T) {
	orig := ucli.OsExiter
	ucli.OsExiter = func(code int) {}
	t.Cleanup(func() { ucli.OsExiter = orig })

	repoRoot := findRepoRoot(t)
	fixture := filepath.Join(repoRoot, "go", "testdata", "phase2", "holesky", "deposit_data_single.json")
	goldenPath := filepath.Join(repoRoot, "go", "testdata", "phase2", "holesky", "unsigned_tx_golden.json")

	app := newTestApp()
	var out bytes.Buffer
	app.Writer = &out
	app.ErrWriter = &out

	err := app.Run(context.Background(), []string{
		"eth-deposit-tx", "build",
		"--network", "holesky",
		"--input-file", fixture,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if os.Getenv("UPDATE_PHASE2_GOLDEN") != "" {
		if err := os.WriteFile(goldenPath, out.Bytes(), 0o644); err != nil {
			t.Fatalf("could not update phase2 golden file: %v", err)
		}
		t.Logf("phase2 golden file updated: %s", goldenPath)
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("could not read phase2 golden file %s: %v (run with UPDATE_PHASE2_GOLDEN=1 to create it)", goldenPath, err)
	}

	got := out.Bytes()
	if !bytes.Equal(got, want) {
		t.Errorf("phase2 golden mismatch\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// findRepoRoot walks up from the test file location to find the go.mod root.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	dir := abs
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Dir(dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod found)")
		}
		dir = parent
	}
}
