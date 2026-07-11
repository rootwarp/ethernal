# Research — Conditional requiredness for `gen --dry-run` (PRD F3)

**Question:** `--output-dir` is declared `Required: true` (`internal/cli/cli.go:124-128`),
so urfave enforces it before the Action runs — but `--dry-run` writes no file. What is the
standard urfave/cli v3 pattern for "required unless another flag is set"?

## The constraint

`Required: true` is enforced by urfave's `checkAllRequiredFlags` (`command.go:420-455`)
**before** the Action runs, with no conditional hook — a required flag is unconditionally
required. urfave v3 has flag-level `Validator`/`Action` callbacks, but they run per-flag
and do **not** receive the state of *other* flags, so they cannot express "required unless
`--dry-run`". (The `MutuallyExclusiveFlags` group is about conflicts, not conditional
requiredness, and doesn't fit either.)

## Recommendation: drop `Required` on `--output-dir`, validate in the Action

This is the idiomatic urfave v3 pattern for cross-flag conditional requiredness, and it
matches how `gen` *already* does all its validation — the Action is a sequence of manual
`ucli.Exit(…, 2)` checks (`cli.go:168-214`), not declarative `Required` flags for the
value-bearing inputs.

**Concretely:**
1. Remove `Required: true` from the `output-dir` flag (`cli.go:124-128`).
2. In the Action, replace the current unconditional block
   (`cli.go:200-204`) with a dry-run-aware one:
   ```go
   outputDir := cmd.String("output-dir")
   if !cmd.Bool("dry-run") {
       if outputDir == "" {
           return ucli.Exit("--output-dir: required flag not set", 2)   // F3.2
       }
       if err := validateOutputDir(outputDir); err != nil {             // cli.go:316
           return ucli.Exit(fmt.Sprintf("--output-dir: %v", err), 2)    // F3.2
       }
   }
   // dry-run: skip both the presence check and validateOutputDir (F3.1)
   ```
3. Read `--dry-run` before this check (it is already read into `Config.DryRun` at
   `cli.go:223`; just hoist the `cmd.Bool("dry-run")` read up, or inline it).

**Why this is consistent and correct:**
- **F3.1:** with `--dry-run`, neither the presence check nor `validateOutputDir` runs, so
  omitting or passing a bad `--output-dir` no longer fails. `DryRunWriter` writes JSON to
  stdout and never touches `output-dir` (`gen.go:81-86`), so nothing downstream needs it.
- **F3.2:** without `--dry-run`, a missing or invalid `--output-dir` still returns
  `ucli.Exit(…, 2)` → exit 2, identical to today.
- **Interaction with F2:** the exit codes stay 2 whether the missing flag is caught by the
  `OnUsageError` hook (for the flags that remain `Required: true`) or by this manual
  `ucli.Exit(…, 2)` check. Uniform.
- `--verify-with-deposit-cli` is already skipped in dry-run (`gen.go:412`,
  `cli.go:157-158`), so there is no second consumer of `output-dir` to worry about.

**Rejected alternative:** keeping `Required: true` and special-casing dry-run is impossible
without patching urfave — `checkAllRequiredFlags` runs before any Action or flag callback
can observe `--dry-run`. The Action-level check is the only clean option and is what the
codebase already favors.
