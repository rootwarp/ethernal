# Research — urfave/cli v3 required-flag error handling (PRD F2)

**Version pinned:** `github.com/urfave/cli/v3 v3.10.1` (`go.mod:9`). Source read from the
module cache; behavior **empirically verified** with a standalone program.

## Why `build`/`gen` exit 1 but `sign`/`run`/`send` exit 2

**Two different code paths produce the "missing required flag" error:**

1. **`build` + `gen` use urfave's built-in `Required: true`.** `build` marks `input-file`
   required (`cmd/eth-deposit/main.go:126`; also `run.go:176`); `gen` marks four flags
   required — `keystore-dir`, `pubkeys`, `network`, `output-dir`
   (`internal/cli/cli.go:112,117,122,127`). When any is missing, urfave's
   `checkAllRequiredFlags` (`command.go:420-455`) returns `*errRequiredFlags`
   (`errors.go:52-62`).
   - **`*errRequiredFlags` does NOT implement `ExitCoder`.** Only `exitError` (produced by
     `ucli.Exit`) implements `ExitCode()` (`errors.go:96-137`). So in `ExitCodeFor`, the
     `errors.As(err, &ec) && ec.ExitCode() == 2` check (`exit.go:59-61`) is false, no
     sentinel matches, and it hits the **exit-1 fallback** (`exit.go:91`). That is the bug.
   - The root app sets `ExitErrHandler` to a no-op (`main.go:79`), so urfave's own printer
     is suppressed and `main` computes the code itself: `os.Exit(ExitCodeFor(err))`
     (`main.go:82-85`). `handleExitCoder` returns the raw error unchanged when
     `ExitErrHandler` is set (`command.go:323-326`), so the plain `*errRequiredFlags`
     reaches `ExitCodeFor`.

2. **`sign` + `run` + `send` do manual checks** returning `ucli.Exit(msg, 2)** — e.g.
   `sign.go:45`, `run.go:48`, `send.go:47,52`. `ucli.Exit` yields an `exitError` with
   `ExitCode()==2`, matched at `exit.go:59-61` → exit 2. (`sign` also marks `--signer`
   `Required: true` at `sign.go:104`, so a missing `--signer` there hits the *same* bug as
   build/gen — worth noting the buggy bucket is really "any urfave `Required` flag".)

### Empirical confirmation

A minimal urfave/cli v3 `v3.10.1` program (root `ExitErrHandler` no-op, subcommand with a
`Required: true` flag) invoked with the flag missing:

```
withHook=false: err="Required flag \"input-file\" not set"  implementsExitCoder=false  mappedExitCode=1
withHook=true:  err="Required flag \"input-file\" not set"  implementsExitCoder=true   mappedExitCode=2
```

Confirms: the raw required-flag error is not an `ExitCoder` (→ fallback 1), and a
`OnUsageError` hook that returns `ucli.Exit(err.Error(), 2)` makes it an `ExitCoder`
with code 2 (→ 2).

## Recommendation: a shared `OnUsageError` hook — NOT string-matching in `ExitCodeFor`

`*errRequiredFlags` is **unexported**, so `ExitCodeFor` cannot type-assert it; the only
in-`ExitCodeFor` option would be fragile string-matching of `"Required flag(s) … not set"`.
The clean, typed alternative is urfave's intended interception point:

**Set a shared `OnUsageError` on every subcommand that returns `ucli.Exit(err.Error(), 2)`.**

- `OnUsageError` is invoked exactly at the required-flags check
  (`command_run.go:346-350`): if set, urfave replaces the error with the hook's return
  value and skips its own "Incorrect Usage" print. Because the hook returns an
  `exitError{code:2}`, `ExitCodeFor` maps it via the existing `exit.go:59-61` branch — no
  new `ExitCodeFor` logic and no new sentinel.
- **Bonus uniformity:** `OnUsageError` also fires for *all other* usage errors — flag
  parse failures (`command_run.go:189-190`), mutually-exclusive groups
  (`command_run.go:261-262`), and argument-parse errors (`command_run.go:372-373`). These
  are all user/configuration errors that should exit 2 anyway, so a single hook fixes the
  whole class (e.g. a bad `--index=abc` `IntFlag`), not just required flags. This is
  strictly more correct and satisfies F2.2's "uniform, not per-flag manual checks that can
  drift again."

**Single wiring point.** `OnUsageError` is read from the *subcommand* (`cmd.OnUsageError`),
not inherited from root, so it must be present on each command. Set it in one loop in
`main()` after the app is built, since every subcommand (including `gen`, which
`genCommand()` returns as a plain `*ucli.Command` via `cli.NewApp` — `gen.go:53-55`) is a
mutable `*ucli.Command` in `app.Commands`:

```go
onUsageErr := func(_ context.Context, _ *ucli.Command, err error, _ bool) error {
    return ucli.Exit(err.Error(), 2)
}
for _, c := range app.Commands {
    c.OnUsageError = onUsageErr
}
```

## Decisions / caveats for the architect

- **`OnUsageError` suppresses urfave's "Incorrect Usage: …" banner and help dump**
  (`command_run.go:346-360`). That is fine and desirable: it makes `build`/`gen` behave
  like `sign`/`run`/`send`, which already print a one-line `ucli.Exit` message. State it
  as an intentional decision, not a regression.
- **Tests to update (PRD C4):** any test asserting exit 1 for a missing required flag on
  `build`/`gen` is codifying the bug and must be flipped to expect 2. `ExitCodeFor`'s own
  unit tests live in `cmd/eth-deposit/exit_test.go`; add a case for a required-flag error
  wrapped by the hook, and cover the manual `ucli.Exit(…,2)` paths.
- Keeping the existing manual `ucli.Exit(…,2)` validations in `sign`/`run`/`send` is
  harmless (they already produce code 2); the hook is a backstop that also catches urfave's
  `Required: true` flags they declare (e.g. `sign --signer`).
