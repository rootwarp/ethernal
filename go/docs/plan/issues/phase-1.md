# Phase 1 — Foundations (P0/P1 primitives)

Sentinels, injection-seam prerequisites, address accessor, and exit-code mappings that
Phase 2 depends on, plus the two findings that are self-contained at this layer (F2, F5).
All items are package-isolated and parallel-friendly.

**Phase entry:** clean `develop`; architecture approved (task #21 done).
**Phase exit / Milestone M1:** module builds; `go test ./...` green; F2 + F5 closed; all F1
primitives (`ErrRPCEstimation`+tagging, `exit.go` mappings, `LocalSigner.Address()`) merged;
golden fixtures byte-identical.

Stream split (per project-plan §Phase-1 Parallelization): **Stream A = P1-1, P1-2, P1-5**;
**Stream B = P1-3, P1-4.**

---

## P1-1 — `internal/tx` RPC-estimation sentinel + tag the four `resolveRPC` call failures

- **Stream:** A (critical-path F1 foundation)
- **Points:** 2
- **Dependencies:** none
- **Findings:** F1 (foundation for F1.5)

**Description.** Implements architecture §2.2.

- `internal/tx/errors.go` — add `ErrRPCEstimation` to the broadcast/exit-5 sentinel group:
  ```go
  // ErrRPCEstimation tags a gas/fee/nonce estimation CALL failure in RPC mode
  // (SuggestGasTipCap / BlockBaseFee / PendingNonceAt / EstimateGas). Exit code 5.
  // Distinct from ErrRPCDial (connection) and ErrChainIDMismatch (config).
  ErrRPCEstimation = errors.New("RPC estimation call failed")
  ```
- `internal/tx/builder.go` — tag the four `resolveRPC` call failures using the **two-`%w`**
  form, **preserving the method-name substring** each error already carries
  (`builder_test.go:567,666,698,728` assert `strings.Contains(err.Error(), "<Method>")`):

  | Line | New form |
  |---|---|
  | `builder.go:109` | `fmt.Errorf("%w: SuggestGasTipCap: %w", ErrRPCEstimation, err)` |
  | `builder.go:118` | `fmt.Errorf("%w: BlockBaseFee: %w", ErrRPCEstimation, bErr)` |
  | `builder.go:133` | `fmt.Errorf("%w: PendingNonceAt: %w", ErrRPCEstimation, err)` |
  | `builder.go:158` | `fmt.Errorf("%w: EstimateGas: %w", ErrRPCEstimation, eErr)` |

- Do **not** tag `ErrChainIDMismatch` (`builder.go:97`) or `ErrMissingFromForNonce`
  (`builder.go:129`) — those are config errors (exit 2), not connectivity.
- Tests (`internal/tx`, `package tx`, per arch §8.2): to each of the four existing
  call-failure tests (`builder_test.go:543,641,670,702`) add an assertion that the error
  satisfies `errors.Is(err, ErrRPCEstimation)` (keep the existing substring assertions).
  Add a guard asserting `ErrChainIDMismatch` and `ErrMissingFromForNonce` are **not**
  `errors.Is(err, ErrRPCEstimation)`.

**Acceptance criteria.**
- The four `resolveRPC` call failures satisfy `errors.Is(err, ErrRPCEstimation)` **and** still
  contain their method-name substring.
- `ErrChainIDMismatch` and `ErrMissingFromForNonce` are **not** tagged `ErrRPCEstimation`.
- `go test ./internal/tx/...` green; RPC-mode success test (`builder_test.go:360-402`) still
  passes unchanged (two-`%w` tagging does not alter resolved field values).

---

## P1-2 — `LocalSigner.Address()` accessor

- **Stream:** A (critical-path F1 foundation)
- **Points:** 1
- **Dependencies:** none
- **Findings:** F1 (foundation for `run` local `From`)

**Description.** Implements architecture §1.5 (signer half).

- `internal/signer/local.go` — add `Address()` on the concrete `*LocalSigner` **only** (never
  on the `Signer` interface, so Ledger is never forced to expose an address offline — N1):
  ```go
  func (s *LocalSigner) Address() (common.Address, error) {
      if s.closed.Load() {
          return common.Address{}, ErrSignerClosed
      }
      priv, err := gethcrypto.ToECDSA(s.key)
      if err != nil {
          return common.Address{}, fmt.Errorf("failed to parse signing key: %w", ErrInvalidKey)
      }
      return gethcrypto.PubkeyToAddress(priv.PublicKey), nil
  }
  ```
- Add `"github.com/ethereum/go-ethereum/common"` to `local.go` imports (`gethcrypto` already
  imported). No new module (C5 — `common` already in the go.mod graph).
- Tests (`internal/signer`): `Address()` returns the key's address; a closed signer
  (`Close()` called) returns `ErrSignerClosed`.

**Acceptance criteria.**
- `LocalSigner.Address()` returns the address derived from the in-memory key.
- A closed signer returns `ErrSignerClosed`.
- `Address()` is **not** on the `Signer` interface (Ledger unaffected — N1).
- `go test ./internal/signer/...` green.

---

## P1-3 — F5 no-TTY passphrase sentinel + hint (complete)

- **Stream:** B (parallel)
- **Points:** 2
- **Dependencies:** none
- **Findings:** F5 (message + sentinel; exit mapping lands in P1-5)

**Description.** Implements architecture §6. All of F5's message/sentinel work lands here (the
exit-2 mapping is P1-5, which imports this sentinel).

- `internal/keystore/keystore.go` — add to the `var (...)` block (`keystore.go:18-36`):
  ```go
  // ErrNoTTY is returned when an interactive passphrase prompt is needed but no
  // controlling terminal is available (piped/non-interactive use). Exit code 2.
  ErrNoTTY = errors.New("no controlling terminal for passphrase prompt")
  ```
- `internal/keystore/passphrase.go` — wrap the `/dev/tty` open failure (`passphrase.go:46-48`)
  with the sentinel and the `--passphrase-env` hint:
  ```go
  tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
  if err != nil {
      return nil, fmt.Errorf("%w: cannot open /dev/tty (%v); for non-interactive or piped use, supply the passphrase via --passphrase-env VAR", ErrNoTTY, err)
  }
  ```
  The chain is preserved through `keystore.go:127` (`"passphrase source: %w"`) and gen's worker
  plumbing (`gen.go:328-331`), so `errors.Is(err, keystore.ErrNoTTY)` holds downstream.
- Tests (`internal/keystore`, per arch §8.2): force the `/dev/tty` open failure and assert the
  returned error is `errors.Is(…, ErrNoTTY)` and its message contains `--passphrase-env`. If the
  tty open cannot be forced in-process, refactor the open into an injectable func for the test;
  the sentinel→exit-2 mapping is separately covered in P1-5's `exit_test.go`.

**Acceptance criteria** (from plan Phase-1 exit criteria / PRD M5):
- The no-TTY passphrase error is `errors.Is(…, keystore.ErrNoTTY)` and its message names
  `--passphrase-env`.
- `go test ./internal/keystore/...` green.

---

## P1-4 — F2 usage-error hook (complete)

- **Stream:** B (parallel)
- **Points:** 2
- **Dependencies:** none
- **Findings:** F2 (fully resolves F2 for all five subcommands)

**Description.** Implements architecture §3. Resolves F2 for all five subcommands via one shared
hook (research 03: urfave's `*errRequiredFlags` is unexported and not an `ExitCoder`, so it falls
to exit 1; `OnUsageError` is urfave's intended interception point).

- `cmd/eth-deposit/main.go` (or `exit.go`) — add (code given verbatim in arch §3.1):
  ```go
  func onUsageError(_ context.Context, _ *ucli.Command, err error, _ bool) error {
      return ucli.Exit(err.Error(), 2)
  }
  func applyUsageErrorHook(app *ucli.Command) {
      for _, c := range app.Commands {
          c.OnUsageError = onUsageError
      }
  }
  ```
  Signature verified against urfave v3.10.1:
  `func(ctx context.Context, cmd *Command, err error, isSubcommand bool) error`.
- `main()` — call `applyUsageErrorHook(app)` immediately after the `app := &ucli.Command{...}`
  literal (after `Commands` is populated), before `app.Run`. `ExitErrHandler` stays the no-op
  (`main.go:79`) — no `ExitCodeFor` change; the hook rewrites the error to `ucli.Exit(...,2)`,
  which `ExitCodeFor` already maps via `exit.go:59-61`.
- `cmd/eth-deposit` test support — add `newFullTestApp()` (all five subcommands with the hook
  applied; code verbatim in arch §3.4). Do **not** disturb existing `newTestApp`/`newE2EApp`.
- Tests (per arch §8.2 "F2 required-flag tests", asserting `ExitCodeFor(err) == 2`): `build`
  without `--input-file`; `gen` without `--keystore-dir`/`--pubkeys`/`--network`; `sign` without
  `--signer` (the flag PRD understates — `sign.go:104`); `run` without `--input-file`; and a bad
  flag value (e.g. `--index abc`) on `build`.

**Acceptance criteria** (from plan Phase-1 exit criteria / PRD M3, F2.1):
- A missing required flag exits **2** on **all five** subcommands (verified per subcommand via
  `newFullTestApp`; the buggy bucket was build/gen/sign/run).
- A bad flag value also exits **2** (the hook covers the whole usage-error class — F2.2).
- No existing test that asserts exit 1 for a missing required flag exists to flip (arch §8.1) —
  the work is purely additive.
- `go test ./cmd/eth-deposit/...` green.

---

## P1-5 — `cmd/eth-deposit/exit.go` sentinel mappings

- **Stream:** A (critical-path F1 foundation)
- **Points:** 1
- **Dependencies:** **P1-1** (imports `ErrRPCEstimation`), **P1-3** (imports `keystore.ErrNoTTY`)
- **Findings:** F1.5, F5 (exit mapping)

**Description.** Implements architecture §2.3 + §6 (mapping half). Adds four sentinel→code
mappings; the exit-code header-**comment** prose is deferred to the Phase 3 doc pass (P3-2).

- `cmd/eth-deposit/exit.go`:
  1. **`internaltx.ErrRPCEstimation` → 5 (LOAD-BEARING).** Add to the exit-5 block
     (`exit.go:85-88`), next to `ErrRPCDial`. Because Phase 2 returns it **unwrapped**,
     `ExitCodeFor` is the only thing mapping it to 5 — omitting this line sends it to the exit-1
     fallback.
  2. **`internaltx.ErrChainIDMismatch` → 2** and **`internaltx.ErrMissingFromForNonce` → 2**
     (documentary; the Phase-2 wrap also yields 2). Add after the `ErrInvalidInput` check
     (`exit.go:44`) as a labeled "build-side RPC configuration errors (tx)" block.
  3. **`keystore.ErrNoTTY` → 2.** Add to the keystore exit-2 group (`exit.go:48-56`).
- Tests (`cmd/eth-deposit/exit_test.go`, per arch §8.2): `ErrRPCEstimation` → 5 (direct +
  wrapped); `ErrChainIDMismatch` → 2; `ErrMissingFromForNonce` → 2; `keystore.ErrNoTTY` → 2
  (direct **and** wrapped `"passphrase source: %w"`); a hook-shaped required-flag error
  `ucli.Exit("Required flag \"x\" not set", 2)` → 2.

**Acceptance criteria** (from plan Phase-1 exit criteria):
- `exit_test.go` maps `ErrRPCEstimation`→5, `ErrChainIDMismatch`→2, `ErrMissingFromForNonce`→2,
  `keystore.ErrNoTTY`→2, each direct and (where applicable) wrapped.
- Coherence (F4.3): the three chain-ID sentinels map to distinct codes —
  `internaltx.ErrChainIDMismatch`→2, `signer.ErrChainIDMismatch`→3 (`exit.go:73`),
  `internaltx.ErrBroadcastChainIDMismatch`→5 (`exit.go:87`).
- `go test ./cmd/eth-deposit/...` green.

---

### Phase 1 totals

| Item | Stream | Points |
|---|---|---|
| P1-1 | A | 2 |
| P1-2 | A | 1 |
| P1-3 | B | 2 |
| P1-4 | B | 2 |
| P1-5 | A | 1 |
| **Total** | | **8** |
