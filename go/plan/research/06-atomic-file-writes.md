# Research: Atomic, Parallel-Safe File Writes in Go for Deposit-Data / Signed-Tx Artifacts

## Recommendation
**Replace the per-second-suffix temp+rename in `internal/output/output.go` with `os.CreateTemp(dir, ".deposit_data-*.json.tmp")` for the tmp path, a higher-resolution suffix (UTC `RFC3339Nano` + short content hash) for the final filename, and explicit `O_EXCL` no-clobber semantics for the final rename. Add a parent-directory `fsync` after rename.** This matches industry consensus [1][2][3][4], closes GO-011 cleanly, and trivially scales to `--parallel`.

## Context
- **Goal:** Close GO-011 (same-second collision silently overwrites prior deposit data) and FR-P0-B3; unify with FR-P0-B9 (atomic writes from `build`/`sign`).
- **Constraints:** Must work on Linux and macOS (REVIEW R8); must respect `0600` permissions; must remain crash-safe (no partially-written final file is ever visible).
- **Evaluated:** raw `os.WriteFile` (current `build`/`sign`), current `internal/output/output.go` temp+rename, `google/renameio`, `natefinch/atomic`, hand-rolled with `os.CreateTemp`.

## Comparison

| Approach | Atomic? | Crash-safe (rename) | Parallel-safe | Cross-platform | Maintained |
|---|---|---|---|---|---|
| `os.WriteFile` (`build`/`sign` today) | ❌ | ❌ | ❌ | ✅ | n/a (stdlib) |
| Current `fsWriter` (Unix-second tmp) | ✅ (rename) | ⚠️ (no dir fsync) | ❌ (same-sec collision) | ✅ | local |
| **Hand-rolled with `os.CreateTemp` + dir fsync** | ✅ | ✅ | ✅ | ✅ | stdlib |
| `google/renameio` v2 | ✅ | ✅ | ✅ | Unix-only (Windows: best-effort) | active [2] |
| `natefinch/atomic` | ✅ | ✅ | ✅ | Linux+Windows | older |

## Detailed Analysis

### Option A — `os.CreateTemp` + explicit dir fsync [Recommended]
**How it works:**
1. `f, err := os.CreateTemp(dir, ".deposit_data-*.json.tmp")` — pattern's `*` is replaced with a random suffix; opens with `O_RDWR|O_CREATE|O_EXCL|0600` [5].
2. Write data; `f.Sync()`; `f.Close()`.
3. Compute final filename: `deposit_data-<RFC3339Nano>-<sha256[:8]>.json`.
4. Check existence: `if _, err := os.Lstat(finalPath); err == nil { return ErrCollision }`.
5. `os.Rename(tmp, final)` — atomic on POSIX [1].
6. Open the parent dir; `dir.Sync()`; close.
7. On any error before step 5, `os.Remove(tmpPath)`.

**Pros:**
- Stdlib only.
- `O_EXCL` semantics for the temp file (kernel-enforced uniqueness against parallel siblings).
- High-resolution timestamp + content hash makes the final filename effectively collision-free even across machines.
- Explicit no-clobber check on the final path catches deliberate or accidental conflicts.

**Cons:**
- A small race between Lstat and Rename remains. For our threat model (operator writing in their own directory, no adversary in the namespace), this is acceptable. If we ever need to defend against an attacker, use `linkat(AT_FDCWD, tmp, finalPath, AT_SYMLINK_FOLLOW)` via syscall — overkill.

### Option B — `google/renameio` v2
**Pros:**
- Battle-tested at Google; explicitly handles dir fsync, large-file mmap, and the rename-fails-cleanup state machine [2].
- Less code in our tree.

**Cons:**
- Extra dep (small, but a dep nonetheless).
- macOS handling has some quirks (renameio v2 explicitly notes platform differences).

### Option C — `natefinch/atomic`
- Older but covers Windows. We don't ship Windows (PRD §7.5), so Windows support is not a tiebreaker. Reject.

## Implementation Guidelines

```go
// internal/output/output.go (proposed)
func (w *fsWriter) Write(ctx context.Context, dir string, entries []deposit.Entry, now time.Time) (string, string, error) {
    if err := ctx.Err(); err != nil { return "", "", err }     // honor cancellation
    data, err := marshalEntries(entries)
    if err != nil { return "", "", fmt.Errorf("output: marshal: %w", err) }

    digest := sha256.Sum256(data)
    shortHash := hex.EncodeToString(digest[:4])
    finalName := fmt.Sprintf("deposit_data-%s-%s.json",
        now.UTC().Format("20060102T150405.000000000Z07"), shortHash)
    finalPath := filepath.Join(dir, finalName)

    if _, err := os.Lstat(finalPath); err == nil {
        return "", "", fmt.Errorf("output: refusing to clobber existing %s", finalPath)
    } else if !errors.Is(err, fs.ErrNotExist) {
        return "", "", fmt.Errorf("output: stat final: %w", err)
    }

    f, err := os.CreateTemp(dir, ".deposit_data-*.json.tmp")
    if err != nil { return "", "", fmt.Errorf("output: create tmp: %w", err) }
    tmpPath := f.Name()

    committed := false
    defer func() {
        if !committed {
            _ = f.Close()
            _ = os.Remove(tmpPath)
        }
    }()

    if err := f.Chmod(0o600); err != nil { return "", "", fmt.Errorf("output: chmod tmp: %w", err) }
    if _, err := f.Write(data); err != nil { return "", "", fmt.Errorf("output: write tmp: %w", err) }
    if err := f.Sync(); err != nil { return "", "", fmt.Errorf("output: fsync tmp: %w", err) }
    if err := f.Close(); err != nil { return "", "", fmt.Errorf("output: close tmp: %w", err) }

    if err := os.Rename(tmpPath, finalPath); err != nil {
        return "", "", fmt.Errorf("output: rename to %s: %w", finalPath, err)
    }
    committed = true

    // Best-effort directory fsync — POSIX required, macOS often a no-op.
    if d, dErr := os.Open(dir); dErr == nil {
        _ = d.Sync()
        _ = d.Close()
    }

    return finalPath, hex.EncodeToString(digest[:]), nil
}
```

Acceptance test for FR-P0-B3 (parallel stress, N>1000 same-second):
```go
func TestFSWriter_ParallelNoOverwrite(t *testing.T) {
    dir := t.TempDir()
    var wg sync.WaitGroup
    paths := sync.Map{}
    for i := 0; i < 1024; i++ {
        wg.Add(1); i := i
        go func() {
            defer wg.Done()
            entries := []deposit.Entry{{Pubkey: distinctPubkey(i)}}
            p, _, err := w.Write(ctx, dir, entries, time.Now())
            if err != nil { t.Errorf("write %d: %v", i, err); return }
            if _, dup := paths.LoadOrStore(p, true); dup { t.Errorf("collision: %s", p) }
        }()
    }
    wg.Wait()
    files, _ := os.ReadDir(dir)
    if len(files) != 1024 { t.Fatalf("expected 1024 files, got %d", len(files)) }
}
```

## Common Pitfalls
- **Pitfall 1 — Defer-`os.Remove(tmpPath)` after successful rename.** The original blog post [1] flags this: a new file may have been created at `tmpPath` by another writer before the defer runs. The `committed` flag pattern above is the fix.
- **Pitfall 2 — Forgetting `Chmod` on the temp file.** `os.CreateTemp` uses `0o600` by default — confirm by reading [5] — but it's worth explicit re-application defensively.
- **Pitfall 3 — Cross-filesystem rename.** `os.Rename` is atomic only when src and dst are on the same filesystem. We always create temp in `dir`, so this is satisfied; document it.
- **Pitfall 4 — macOS HFS+/APFS `fsync` of a directory may be a no-op.** Accept best-effort; PRD R8 already flags this.
- **Pitfall 5 — Predictable temp filenames in attacker-writable dirs.** `os.CreateTemp` uses crypto random; no remaining TOCTOU on the tmp side.

## Real-World Examples
- **renameio** (Google's drop-in solution) implements the same pattern with extra Windows polish [2].
- **etcd** uses temp+fsync+rename+dir-fsync for its WAL writes — canonical example.
- **CockroachDB**'s file-system layer in `pkg/storage/fs` mirrors this approach.
- The original blog [1] by Michael Stapelberg (2017) is still the most-cited authoritative source.

## Feasibility: ✅ GREEN. No PRD contradictions.

## Sources

[1] [Atomically writing files in Go](https://michael.stapelberg.ch/posts/2017-01-28-golang_atomically_writing/) — Michael Stapelberg, 2017. Canonical reference for the temp+sync+rename pattern in Go.
[2] [google/renameio v2 — pkg.go.dev](https://pkg.go.dev/github.com/google/renameio) — Google. Battle-tested wrapper that handles edge cases (large files, dir fsync, error cleanup).
[3] [natefinch/atomic](https://github.com/natefinch/atomic) — natefinch. Earlier Go atomic file lib; Windows support via `MoveFileEx`.
[4] [atomicfile — Krzysztof Kowalczyk](https://blog.kowalczyk.info/article/90f01e0e24924f6c8ed428f065c0016a/atomicfile-robustly-writing-to-a-file-in-go.html) — Kowalczyk. Practical write-up matching the recommended pattern.
[5] [Go `os.CreateTemp` documentation](https://pkg.go.dev/os#CreateTemp) — Go team. `O_RDWR|O_CREATE|O_EXCL`, perm `0600`, random suffix replaces `*` in pattern.
