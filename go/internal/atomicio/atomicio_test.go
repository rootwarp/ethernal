package atomicio

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestWriteFile_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "happy.json")

	// 1 MiB random data per AC.
	data := make([]byte, 1<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}

	gotPath, err := WriteFile(path, data, 0o600)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if gotPath != path {
		t.Errorf("gotPath = %q, want %q", gotPath, path)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("contents do not match input")
	}

	// No stray .tmp left behind.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover temp file after success: %s", e.Name())
		}
	}
}

func TestWriteFile_NoClobber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exists.json")
	orig := []byte("original content")
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err := WriteFile(path, []byte("new data that must not appear"), 0o600)
	if !errors.Is(err, ErrClobber) {
		t.Fatalf("err = %v, want ErrClobber", err)
	}

	// Original untouched.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Errorf("original was clobbered")
	}
}

func TestWriteFile_TempFailureCleansUp(t *testing.T) {
	dir := t.TempDir()
	// not-a-dir is a regular file; Dir(target) will cause CreateTemp to fail.
	notDir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(notDir, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed notdir: %v", err)
	}
	target := filepath.Join(notDir, "target.json")

	_, err := WriteFile(target, []byte("data"), 0o600)
	if !errors.Is(err, ErrTempCreate) {
		t.Fatalf("err = %v, want ErrTempCreate", err)
	}

	// No .tmp files left in the parent dir (none were created).
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") || strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover .tmp after temp-create failure: %s", e.Name())
		}
	}
}

func TestWriteFile_PermApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "perm.json")
	data := []byte("perm test")
	wantPerm := os.FileMode(0o644)

	_, err := WriteFile(path, data, wantPerm)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	gotPerm := fi.Mode().Perm()
	if gotPerm != wantPerm {
		t.Errorf("perm = %04o, want %04o", gotPerm, wantPerm)
	}
}

// TestWriteFile_ParallelStress_1024 exercises concurrent writers to distinct
// deposit_data-* paths in the same dir (covers the 1024 unique no-clobber
// acceptance from the M0.3 exit criteria using only WriteFile).
func TestWriteFile_ParallelStress_1024(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	paths := sync.Map{}
	const N = 1024
	for i := 0; i < N; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			data := make([]byte, 64)
			rand.Read(data)
			final := filepath.Join(dir, "deposit_data-"+formatInt(i)+".json")
			p, err := WriteFile(final, data, 0o600)
			if err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
			if p != final {
				t.Errorf("path %s != %s", p, final)
			}
			if _, dup := paths.LoadOrStore(p, true); dup {
				t.Errorf("collision: %s", p)
			}
			got, _ := os.ReadFile(p)
			if !bytes.Equal(got, data) {
				t.Errorf("mismatch %d", i)
			}
		}()
	}
	wg.Wait()
	files, _ := os.ReadDir(dir)
	if len(files) != N {
		t.Fatalf("expected %d files, got %d", N, len(files))
	}
}

func formatInt(i int) string {
	// minimal no-fmt helper for filename (avoids importing fmt in test if not needed, but we could; keep small)
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b [20]byte
	j := len(b)
	for i > 0 {
		j--
		b[j] = digits[i%10]
		i /= 10
	}
	return string(b[j:])
}
