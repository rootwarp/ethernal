# Research: urfave/cli v2 Contract Fixes — Required Flags, Positional Args, /dev/tty Confirmation

## Verdict
**All three FR-P1-F items (F1 required-flag exit code, F4 /dev/tty confirmation under stdin pipe) and FR-P0-B6 (positional-arg rejection) are implementable with the public urfave/cli v2 surface plus a tiny `os.OpenFile("/dev/tty", …)` helper.** The urfave/cli `requiredFlagsErr` is package-internal — `errors.Is/As` against it from outside the package does not work; the practical fix is **prefix-match the error string** in our exit-code mapper, OR **pre-validate flags in the Load*Config functions** before urfave/cli's built-in check runs.

## Findings

### 1. FR-P1-F1 — required-flag missing must exit 2, not 1 (GO-015)

**Internals:** urfave/cli v2 emits errors via an internal `errRequiredFlags` type [1]:
```
Required flag "X" not set            (single)
Required flags "X, Y" not set        (multiple)
```
The type is **unexported** ([cli/errors.go on main](https://github.com/urfave/cli/blob/main/errors.go) [2]), so `errors.Is` against a sentinel will not work. Two viable fixes:

**Option A — substring detect in our `ExitCodeFor` helper** (one-liner):
```go
func ExitCodeFor(err error) int {
    if err == nil { return 0 }
    if strings.HasPrefix(err.Error(), "Required flag ") || strings.HasPrefix(err.Error(), "Required flags ") {
        return 2
    }
    // ... existing sentinel chain
}
```
**Risk:** locale-fragile (current urfave/cli has only the English message; PR #1701 changed the format once already [3]). Acceptable for our pinned dep.

**Option B — pre-validate in `LoadRunConfig`/`LoadSignConfig`** before urfave/cli's check fires:
```go
for _, name := range []string{"network", "input-file"} {
    if c.String(name) == "" {
        return nil, ucli.Exit(fmt.Sprintf("--%s is required", name), 2)
    }
}
```
**Best practice:** combine both. Pre-validate in Load* (controls error wording and exit code), and keep the substring fallback as a safety net.

### 2. FR-P0-B6 — reject unexpected positional args (GO-040)

`c.NArg()` returns the count of positional args after flag parsing [4][5]; urfave/cli does not reject extras by default. One-line fix in every command's Action:
```go
if c.NArg() > 0 {
    return ucli.Exit(fmt.Sprintf("unexpected positional argument(s): %v (did you mean comma-separated --pubkeys?)", c.Args().Slice()), 2)
}
```
**Where to add it:** every `Action:` in the apps' command definitions. Recommend a tiny `requireNoArgs(c)` helper in `internal/cli` so it's a single audit point.

### 3. FR-P1-F4 — confirmation must read from `/dev/tty` when `--input -` exhausts stdin (GO-041)

Current `send.go:213` uses `bufio.NewReader(c.App.Reader)`. When `--input -` was set, that reader is already at EOF — guaranteed user-aborted exit-4 even when the operator is at the keyboard.

**Fix:** when stdin is not the user's terminal, route the confirmation prompt to `/dev/tty`:
```go
// internal/cli/confirm.go (proposed)
func confirmReader(stdin io.Reader) (io.Reader, func(), error) {
    // If stdin is a TTY, use it.
    if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
        return f, func(){}, nil
    }
    tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
    if err != nil {
        // No TTY available; reject unless --yes
        return nil, func(){}, ErrNoTTY
    }
    return tty, func() { tty.Close() }, nil
}
```
Call from `send.go`:
```go
if !cfg.Yes {
    r, closeFn, err := confirmReader(c.App.Reader)
    defer closeFn()
    if errors.Is(err, ErrNoTTY) {
        return ucli.Exit("no controlling TTY; pass --yes to proceed non-interactively", 2)
    }
    reader := bufio.NewReader(r)
    input, _ := reader.ReadString('\n')
    ...
}
```

This mirrors the canonical Go pattern for password-style input [6][7]: open `/dev/tty` explicitly when stdin is a pipe. Same approach is used in `passphrase.go:46` (`os.OpenFile("/dev/tty", os.O_RDWR, 0)`) — pattern is already in our codebase.

### 4. Bonus — `x/term.IsTerminal` for detection

The `term.IsTerminal(fd int) bool` check is the standard Go way to detect TTY [8]. Use it before opening `/dev/tty` to avoid opening a real device when stdin already is one (the common case for `--input /path/file.json` invocations).

### 5. Concurrent passphrase prompts (FR-P0-C5, GO-007) — `/dev/tty` race precedent

Critical precedent from age/gopass [9]: **gopass deliberately sets `Concurrency() = 1` for the age backend** to avoid multiple passphrase prompts. Their pattern is "agent caches the passphrase". For our `--parallel > 1` case, the analogous fix is:

```go
// internal/keystore/passphrase.go (proposed)
type cachingPromptSource struct {
    inner  PassphraseSource
    once   sync.Once
    cached []byte
    err    error
    mu     sync.Mutex
}
func (c *cachingPromptSource) Read() ([]byte, error) {
    c.once.Do(func() { c.cached, c.err = c.inner.Read() })
    if c.err != nil { return nil, c.err }
    c.mu.Lock(); defer c.mu.Unlock()
    out := make([]byte, len(c.cached))   // fresh copy; loader zeroizes
    copy(out, c.cached)
    return out, nil
}
func (c *cachingPromptSource) Zeroize() {
    c.mu.Lock(); defer c.mu.Unlock()
    for i := range c.cached { c.cached[i] = 0 }
    c.cached = nil
}
```
Wrap the existing `termPromptSource` once in `runWithDeps`, before the worker pool spins up. `sync.Once` makes the prompt fire exactly once even if N workers race; the returned slice is a fresh copy per call to honor the loader's zeroize contract. End-of-run, call `Zeroize()` on the cache.

**Alternative per FR-P0-C5 acceptance criteria:** reject `--parallel > 1` when TTY source is selected. Less ergonomic but simpler — pick the wrapper.

## Implementation Guidelines

1. **Pre-validate required flags in `Load*Config`** before urfave/cli's check runs; keep substring detect as safety net in `ExitCodeFor`.
2. **Add `requireNoArgs(c)` helper** in `internal/cli`; call from every `Action:` in eth-deposit-gen and eth-deposit-tx commands.
3. **Add `confirmReader(stdin)` helper** wrapping `term.IsTerminal` + `/dev/tty` open; use from `send.go` and any other confirmation site.
4. **Wrap `termPromptSource` in a `cachingPromptSource`** for `--parallel > 1`; one prompt fires for all workers; cache zeroized at run end.

## Common Pitfalls
- **Pitfall 1 — urfave/cli's `Before:` hook.** If you add a `Before:` that returns an error, urfave/cli runs it after flag-parsing but before `Action:`. PR #1247 [10] notes `--help` triggering required-flag errors; if we add `Before:`, the same trap applies — make sure `--help` exits 0 first.
- **Pitfall 2 — `c.Args().Slice()` mutates a slice.** Print via `%v`, don't mutate.
- **Pitfall 3 — `os.OpenFile("/dev/tty")` on Windows.** No-op; PRD §7.5 says Windows is unsupported, so safe.
- **Pitfall 4 — `term.IsTerminal` on a closed fd.** Returns false; always check before closing.
- **Pitfall 5 — `bufio.NewReader(tty).ReadString('\n')` returns "\n" on bare Enter.** Trim before comparing; current code does this.

## Real-World Examples
- **age / gopass:** Concurrency=1 to avoid duplicate prompts [9]. Our caching wrapper is the more ergonomic version of the same idea.
- **ssh-agent:** classic single-prompt-and-cache. Same pattern.
- **`docker run -i`:** opens `/dev/tty` for interactive prompts when stdin is piped. Same precedent.

## Feasibility: ✅ GREEN. No PRD contradictions.

## Sources

[1] [urfave/cli issue #1701 — Missing required flag error uses alias](https://github.com/urfave/cli/issues/1701) — urfave/cli. Confirms `errRequiredFlags` produces strings of the form `Required flag "X" not set` / `Required flags "X, Y" not set`.
[2] [urfave/cli errors.go](https://github.com/urfave/cli/blob/main/errors.go) — urfave/cli. `requiredFlagsErr` interface and unexported `errRequiredFlags` struct.
[3] [urfave/cli PR #1285 — Fix help with required flags](https://github.com/urfave/cli/pull/1285) — urfave/cli. Help-command handling fix; confirms the error path.
[4] [urfave/cli docs — Arguments](https://cli.urfave.org/v1/examples/arguments/) — urfave/cli. `c.NArg()` / `c.Args()` API.
[5] [urfave/cli issue #991 — Flags treated as args](https://github.com/urfave/cli/issues/991) — urfave/cli. Pattern for detecting unexpected positional args.
[6] [Go term package docs](https://pkg.go.dev/golang.org/x/term) — Go team. `IsTerminal(fd int) bool`, `ReadPassword(fd int)`.
[7] [golang/go issue #19909 — ReadPassword on redirected stdin](https://github.com/golang/go/issues/19909) — Go team. Canonical pattern: open `/dev/tty` directly when stdin is a pipe.
[8] [Implementing Secure Password Input in Go CLI](https://zerotohero.dev/inbox/secure-password-input/) — Reference walkthrough of `/dev/tty` + `term.ReadPassword`.
[9] [gopass age backend Concurrency=1 pattern](https://pkg.go.dev/github.com/gopasspw/gopass/internal/backend/crypto/age) — gopass. "Concurrency function returns 1 for `age` since otherwise it prompts for the identity password for each worker." Our caching wrapper is the more ergonomic variant.
[10] [urfave/cli issue #1247 — Help with required flags](https://github.com/urfave/cli/issues/1247) — urfave/cli. Help-command interaction with required-flag check.
