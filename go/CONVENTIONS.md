# Go Conventions

Coding conventions for the Go code in this repository. Rules are stated
tersely so they work both as a contributor guide and as context for AI
coding tools.

This document distills the de facto community standards. Where it is
silent, follow these references, in order of precedence:

1. [Effective Go](https://go.dev/doc/effective_go)
2. [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments)
3. [Google Go Style Guide](https://google.github.io/styleguide/go/)

## Formatting

- `gofmt` is law. All code must be gofmt-formatted; formatting is never
  debated in review.
- Group imports into three blocks separated by blank lines: standard
  library, external modules, this module. Keep each block sorted
  (`goimports` does this).
- No hard line-length limit, but wrap long lines for readability.
  Prefer refactoring over wrapping when a line is long because it does
  too much.
- One statement per line. No semicolons to join statements.

```go
import (
    "fmt"
    "os"

    "github.com/ethereum/go-ethereum/common"

    "github.com/rootwarp/eth-utils/go/internal/keystore"
)
```

## Naming

- Use `MixedCaps` or `mixedCaps`, never underscores.
- Acronyms keep consistent case: `userID`, `parseURL`, `httpClient`,
  not `userId`, `parseUrl`, `HttpClient`.
- Name length scales with scope: `i` for a loop index, `keystorePath`
  for a package-level variable. Short names in small scopes are good Go.
- Package names: short, lowercase, single word, no underscores or
  MixedCaps. Avoid grab-bag names like `util`, `common`, `helpers`,
  `misc`.
- Don't stutter: the package name is part of the identifier.
  `keystore.Load`, not `keystore.LoadKeystore`.
- Receiver names: one or two characters, consistent across all methods
  of a type. Never `this` or `self`.
- Single-method interfaces are named by the method plus `-er`:
  `Reader`, `Signer`, `Validator`.
- Getters drop the `Get` prefix: `obj.Owner()`, not `obj.GetOwner()`.
  Setters keep `Set`: `obj.SetOwner(o)`.
- Exported names start with an uppercase letter and require a doc
  comment; everything else stays unexported.

```go
// Bad
func (keystore *Keystore) GetPublicKey() {}
var user_count int

// Good
func (k *Keystore) PublicKey() {}
var userCount int
```

## Package Design

- Keep packages small and single-purpose. A package's name should
  describe what it provides, not what it contains.
- Put code that must not be imported by other modules under
  `internal/`.
- No import cycles. If two packages need each other, the abstraction
  boundary is wrong — extract a third package or merge them.
- Avoid `init()` functions with side effects (I/O, global mutation,
  registration magic). Prefer explicit initialization from `main` or a
  constructor.
- Keep `main` packages thin: parse flags, wire dependencies, call into
  `internal/` packages. Logic lives in libraries so it can be tested.
- Avoid package-level mutable state. Pass dependencies explicitly.

## Error Handling

- Errors are values. Handle every error: return it, act on it, or — in
  rare, justified cases — explicitly discard it with `_` and a comment.
- Handle or return, never both. Logging an error and then returning it
  leads to duplicate reports upstream.
- Add context when wrapping, and use `%w` so callers can `errors.Is` /
  `errors.As`:

```go
// Bad
if err != nil {
    return err
}

// Good
if err != nil {
    return fmt.Errorf("load keystore %s: %w", path, err)
}
```

- Error strings: lowercase, no trailing punctuation (they get wrapped
  into larger messages). `errors.New("connection refused")`, not
  `errors.New("Connection refused.")`.
- Sentinel errors are named `ErrXxx` and declared with `errors.New`.
  Custom error types are named `XxxError`.
- Don't `panic` in library code. Panics are for programmer errors
  (impossible states), not for expected failures like bad input or
  missing files. `main` may exit via a single top-level error path.
- Check errors from `Close` on writable resources; a failed close on a
  file you wrote means lost data.
- Keep the happy path at minimal indentation: handle the error and
  return early, then continue unindented.

```go
// Bad
if err == nil {
    if data != nil {
        process(data)
    }
}

// Good
if err != nil {
    return fmt.Errorf("fetch: %w", err)
}
if data == nil {
    return errors.New("empty response")
}
process(data)
```

## Comments and Documentation

- Every exported identifier has a doc comment: a full sentence that
  starts with the identifier's name.

```go
// Load reads and decrypts the keystore file at path using passphrase.
func Load(path, passphrase string) (*Keystore, error) {
```

- Exactly one file per package carries the package comment
  (`// Package deposit implements ...`). For multi-file packages,
  prefer a dedicated `doc.go`.
- Comment *why*, not *what*. Code says what it does; comments explain
  intent, invariants, and surprising decisions.
- Delete commented-out code. Git remembers.
- Mark known gaps with `// TODO(name): description` so they are
  greppable and owned.

## Testing

- Tests live next to the code: `foo.go` → `foo_test.go`, same package
  (use `package foo_test` only when you need to break an import cycle
  or test the public API surface deliberately).
- Prefer table-driven tests with subtests:

```go
func TestParseAmount(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    uint64
        wantErr bool
    }{
        {name: "valid", input: "32000000000", want: 32_000_000_000},
        {name: "empty", input: "", wantErr: true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := ParseAmount(tt.input)
            if (err != nil) != tt.wantErr {
                t.Fatalf("ParseAmount(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
            }
            if got != tt.want {
                t.Errorf("ParseAmount(%q) = %d, want %d", tt.input, got, tt.want)
            }
        })
    }
}
```

- Name comparison variables `got` and `want`, and report failures as
  `got X, want Y` with enough input context to debug from the message
  alone.
- Use `t.Errorf` to keep checking after a failure; `t.Fatalf` only when
  continuing makes no sense.
- Call `t.Helper()` in test helpers so failures point at the caller.
- Fixtures go in `testdata/` (the toolchain ignores it).
- Use `t.TempDir()` and `t.Cleanup` instead of manual temp-file
  management.
- Don't test unexported plumbing exhaustively; test behavior through
  the package's API where practical.

## Concurrency

- Don't start a goroutine without knowing how and when it stops. Every
  goroutine needs a clear exit path (context cancellation, channel
  close, or bounded work).
- `context.Context` is the first parameter, named `ctx`. Never store a
  context in a struct; pass it through call chains.

```go
func (c *Client) Send(ctx context.Context, tx *Transaction) error {
```

- Share memory by communicating: prefer channels for handing off
  ownership and signaling; prefer mutexes for protecting simple shared
  state. Don't force one where the other is natural.
- The zero-value `sync.Mutex` is ready to use; embed it unexported and
  document what it guards.
- Libraries should not leak goroutines past the call that started them
  unless the API explicitly hands lifecycle control to the caller
  (e.g., returns a `Close`/`Stop`).
- Run tests with `-race` locally and in CI when touching concurrent
  code.

## General Style

- Guard clauses over nesting: return early on errors and edge cases so
  the main logic reads top-to-bottom.
- Make the zero value useful. A `var buf bytes.Buffer` works without
  initialization; design types the same way when possible.
- Accept interfaces, return concrete types. Define interfaces where
  they are consumed, not where types are implemented.
- Keep interfaces small. One or two methods is the Go norm.
- Avoid naked returns; use them only in very short functions, if ever.
- Declare variables close to first use, not in a block at the top.
- Use `var x []T` (nil slice) over `x := []T{}` unless you specifically
  need a non-nil empty slice (e.g., JSON `[]` vs `null`).
- Pass small structs by value; use pointers when the callee must mutate
  the receiver/argument or the struct is large.
- Don't add abstraction speculatively. Introduce an interface, a layer,
  or a generic when a second concrete use exists, not before.
