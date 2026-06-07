package atomicio

import (
	"errors"
	"os"
	"path/filepath"
)

// Sentinels for WriteFile failure modes. Callers use errors.Is to distinguish.
var (
	ErrClobber    = errors.New("refusing to clobber existing file")
	ErrTempCreate = errors.New("create temp file failed")
	ErrSync       = errors.New("sync failed")
	ErrRename     = errors.New("rename to final failed")
)

// WriteFile writes data to path using a temp+rename sequence. The temp file is
// created in filepath.Dir(path) so the rename is intra-filesystem and atomic.
// Returns the same path on success.
func WriteFile(path string, data []byte, perm os.FileMode) (string, error) {
	dir := filepath.Dir(path)

	// Refuse to clobber: Lstat returns nil err means the final path exists.
	if _, err := os.Lstat(path); err == nil {
		return "", ErrClobber
	}

	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return "", ErrTempCreate
	}
	tmpName := f.Name()

	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err := f.Chmod(perm); err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", ErrSync
	}
	if err := f.Close(); err != nil {
		return "", err
	}

	if err := os.Rename(tmpName, path); err != nil {
		return "", ErrRename
	}
	committed = true

	// Best-effort parent directory fsync (required for durability on POSIX).
	// On macOS the open+Sync on a dir fd is often a no-op (see research/06 §A);
	// we document the limitation here rather than in doc.go per instructions to
	// avoid changing the M0.1-7 scaffold.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	return path, nil
}
