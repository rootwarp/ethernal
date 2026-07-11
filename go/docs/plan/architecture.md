# Architecture — eth-deposit Findings-Resolution Release

**Status:** Implementation-ready
**Inputs:** `docs/plan/prd.md` (approved), `docs/plan/research/` (approved, adopted)
**Scope:** `go/` — `cmd/eth-deposit/`, `internal/tx/`, `internal/signer/`, `internal/keystore/`, `internal/cli/`, `docs/USER-GUIDE.md`
**Date:** 2026-07-12

This document is the single source of truth for a code-writer. It gives exact signatures,
sentinel names, a file-by-file change list, and the test plan. It adopts the research
recommendations verbatim except where a defect is noted; none were found.

---

## 0. Module boundaries (unchanged responsibilities)

The fix must not blur these seams. They are stated so each change lands in the right package.

| Package | Owns | This release adds |
|---|---|---|
| `cmd/eth-deposit` | flag parsing, config load, dialing the RPC, exit-code mapping, orchestration | RPC dial seam, `--from` flag, `Config.From`, default-fill relocation, `OnUsageError` hook, exit-code map entries, doc text |
| `internal/tx` | pure builder logic; RPC *interface* (`EthRPC`); the `*ethClient` adapter | `ErrRPCEstimation` sentinel + tag 4 call sites; drop dead `BuildConfig.RPCURL`; remove stale comment |
| `internal/signer` | address derivation + signing | `LocalSigner.Address()` (concrete type only, **not** the `Signer` interface — Ledger stays offline-safe, N1) |
| `internal/keystore` | keystore load + TTY passphrase errors | `ErrNoTTY` sentinel + hint message |
| `internal/cli` | `gen` flag schema + validation | drop `Required` on `--output-dir`; Action-gated validation |

**The builder never dials.** It consumes `cfg.RPC EthRPC`; the cmd layer decides whether to
dial and injects the client. This mirrors `send` exactly (`send.go:22-25,169-173`).

---

## 1. F1 — Wire real RPC estimation into `build` and `run` (P0)

### 1.1 The injection seam (cmd layer)

Add a package-level `var` in `cmd/eth-deposit/main.go`, mirroring `newBroadcaster`
(`send.go:22-25`):

```go
// newEthRPC is the production EthRPC factory. Tests override this to inject a fake.
var newEthRPC = func(ctx context.Context, rpcURL string) (internaltx.EthRPC, error) {
	return internaltx.NewEthClient(ctx, rpcURL)
}
```

`*ethClient` already satisfies `EthRPC` (compile-time assertion at `rpc_client.go:157`), so no
adapter is needed. `NewEthClient` returns `(*ethClient, error)`; the seam widens the return to
the `EthRPC` interface via Go's implicit conversion in the `return` statement — identical to
`newBroadcaster`.

**Nil-interface guard (required):** on dial failure `NewEthClient` returns `(nil, err)`; the seam
then returns a non-nil `EthRPC` wrapping a nil `*ethClient`. Callers MUST check `err` and return
**before** using or deferring `Close()` on the client — exactly as `send.go:169-173` does. Never
`defer client.Close()` before the `err != nil` check.

### 1.2 Dial + lifecycle in `buildUnsignedTx`

`buildUnsignedTx` (`main.go:216-261`) is the single owner of the client, so both `build` and
`run` inherit identical lifecycle handling (`run` calls it at `run.go:239`). New shape:

```go
func buildUnsignedTx(ctx context.Context, cfg *Config, rawData []byte) (*internaltx.UnsignedTx, error) {
	// ... entries parse / index / entry.Validate() unchanged (main.go:217-231) ...

	buildCfg := internaltx.BuildConfig{
		NetworkParams:        cfg.NetworkParams,
		From:                 cfg.From,          // NEW
		GasLimit:             cfg.GasLimit,
		MaxFeePerGas:         cfg.MaxFeePerGas,
		MaxPriorityFeePerGas: cfg.MaxPriorityFeePerGas,
		Nonce:                cfg.Nonce,
	}                                            // RPCURL field REMOVED (see 1.6)

	if cfg.RPCURL != "" {
		// --- RPC mode: dial, inject, resolve-from-node ---
		client, err := newEthRPC(ctx, cfg.RPCURL)
		if err != nil {
			return nil, err                      // ErrRPCDial → exit 5, unwrapped (never reaches WrapInputErr)
		}
		defer client.Close()
		buildCfg.RPC = client
		// Leave gas=0 / fees=nil / nonce=nil so resolveRPC fills them.
	} else {
		// --- Offline mode: fill hardcoded defaults (F1.4 / C3) ---
		if buildCfg.MaxFeePerGas == nil {
			buildCfg.MaxFeePerGas = defaultMaxFeePerGas()
		}
		if buildCfg.MaxPriorityFeePerGas == nil {
			buildCfg.MaxPriorityFeePerGas = defaultMaxPriorityFeePerGas()
		}
		if buildCfg.GasLimit == 0 {
			buildCfg.GasLimit = defaultGasLimit
		}
		if buildCfg.Nonce == nil {
			var z uint64
			buildCfg.Nonce = &z
		}
	}

	builder := internaltx.NewBuilder()
	unsignedTx, err := builder.BuildUnsigned(ctx, entry, buildCfg)
	if err != nil {
		if errors.Is(err, internaltx.ErrRPCEstimation) {
			return nil, err                      // connectivity failure → exit 5, escapes the wrap
		}
		return nil, WrapInputErr("build", err)   // everything else → exit 2 (offline contract preserved)
	}
	return unsignedTx, nil
}
```

This is the whole of the default-fill relocation (PRD F1.2): the block currently at
`main.go:241-253` moves wholesale into the `else` (offline) branch. In RPC mode the fields stay
unset so `resolveRPC` (`builder.go:105,114,125,138`) fills them; explicit flags still win because
`resolveRPC` only fills nil/zero fields.

Add `"errors"` to `main.go`'s imports (currently not imported there).

### 1.3 The second default-fill spot — `config.go:74` (the trap)

`LoadBuildConfig` eagerly sets `gasLimit := defaultGasLimit` (`config.go:74`), so `Config.GasLimit`
is **always** non-zero even when `--gas-limit` is omitted. If only `main.go` is fixed, an RPC-mode
build with `--gas-limit` omitted still arrives with `GasLimit=250000`, and `resolveRPC` skips
`EstimateGas` (it guards on `gasLimit == 0`, `builder.go:139`) — the P0, merely relocated.

**Change (`config.go:74`):**

```go
var gasLimit uint64            // was: gasLimit := defaultGasLimit
if s := c.String("gas-limit"); s != "" {
	// ... unchanged: ParseUint, v==0 → error, gasLimit = v ...
}
```

The explicit-`"0"`→error path is keyed on `s != ""` (`config.go:75,80`), so an explicit
`--gas-limit 0` still errors. Only the *unset* case changes: `Config.GasLimit` is now `0`, and the
offline branch in `buildUnsignedTx` restores `250000`. Golden outputs stay byte-identical (offline
path), and `TestLoadBuildConfig_Defaults` must flip its `GasLimit` assertion (see §8).

### 1.4 `Config.From` and the `--from` flag

**`config.go` — add field:**

```go
// From is the sender address, parsed from --from. Zero value means unset.
// Used only in RPC mode to fetch the pending nonce when --nonce is omitted.
From [20]byte
```

**`config.go` — parse in `LoadBuildConfig`** (universal; harmless for `run`, which does not declare
`--from`: `c.String("from")` returns `""` for an undeclared flag — verified against urfave v3.10.1
`flag_string.go:56-64` / `command.go:611-619`, and no `InvalidFlagAccessHandler` is set so it is
silent):

```go
if s := c.String("from"); s != "" {
	h := strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 20 {
		return nil, ucli.Exit(fmt.Sprintf("--from: invalid address %q: must be a 20-byte hex address", s), 2)
	}
	copy(cfg.From[:], b)
}
```

Add `encoding/hex` and `strings` to `config.go` imports. (Do **not** use `common.HexToAddress`: it
is lenient and silently truncates/pads, defeating validation.)

**`main.go` — add the flag to `buildCommand()` only** (build and run keep separate flag lists;
build's are inline at `main.go:121-172`, run's come from `buildFlags()` at `run.go:169-222`):

```go
&ucli.StringFlag{
	Name:    "from",
	Usage:   "Sender address (0x-prefixed, 20-byte hex). Required with --rpc-url when --nonce is omitted, to fetch the pending nonce.",
	Sources: ucli.EnvVars("ETH_DEPOSIT_TX_FROM"),
},
```

Do **not** add `--from` to `buildFlags()` / `run` (see §1.5 for run's `From`).

**`main.go` — build-specific conditional-required check** in `buildCommand().Action`, after
`LoadBuildConfig` returns and before reading input (this belongs in build's Action, not shared
`LoadBuildConfig`, because run derives `From` differently):

```go
if cfg.RPCURL != "" && cfg.From == ([20]byte{}) && (cfg.Nonce == nil || cfg.GasLimit == 0) {
	return ucli.Exit("--from: required when --rpc-url is set and --nonce or --gas-limit is omitted "+
		"(the sender is needed to fetch the pending nonce and to estimate gas for the 32-ETH deposit call)", 2)
}
```

This gives a clear exit-2 message at config time. `resolveRPC`'s `ErrMissingFromForNonce`
(`builder.go:128-129`) remains the backstop for the nonce path.

**PRD deviation (documented per mandate — a concrete defect in PRD F1.3's literal text).** PRD F1.3
requires `--from` "only when `--rpc-url` is given and `--nonce` is omitted." That is insufficient:
`resolveRPC` also passes `cfg.From` into `EstimateGas` (`builder.go:151`) with `value = 32 ETH`
(`builder.go:153`). When `--gas-limit` is omitted, `EstimateGas` fires (`builder.go:139`) and most
nodes reject a 32-ETH call from the zero address as "insufficient funds" — surfacing as
`ErrRPCEstimation` → a confusing exit **5** at runtime instead of a clean config error. The
gate above therefore also requires `--from` when `--gas-limit` is omitted, converting that runtime
failure into a config-time exit **2**. This is a strict tightening (it never *relaxes* the PRD
rule) and must be flagged to the team-lead for PRD sync.

### 1.5 Deriving `From` for `run`

**`internal/signer/local.go` — add `Address()` on the concrete `*LocalSigner`** (not on the
`Signer` interface, so Ledger is never forced to expose an address offline — N1):

```go
// Address derives the sender address from the in-memory key. Returns
// ErrSignerClosed if the key has been zeroized. Used by "run --signer local"
// to populate BuildConfig.From for RPC nonce resolution.
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

Add `"github.com/ethereum/go-ethereum/common"` to `local.go` imports (`gethcrypto` already
imported).

**`run.go` — early derive-and-close in `runAction`**, inserted between step 1 (read deposit data)
and step 2 (`buildUnsignedTx`, `run.go:239`):

```go
// Local signer + RPC mode: derive From so resolveRPC can fetch the pending
// nonce AND estimate gas (both need a funded sender; EstimateGas carries the
// 32-ETH value, builder.go:151-153). The signer is constructed early only to
// read the address, then closed (key zeroized); signUnsignedTx re-constructs
// it below. Derive whenever RPC mode is on — it is cheap and harmless when the
// address ends up unused (both nonce and gas explicit).
if cfg.Signer == "local" && cfg.Build.RPCURL != "" {
	s, err := signer.NewLocalSignerFromEnv(cfg.PrivateKeyEnvVar)
	if err != nil {
		return fmt.Errorf("local signer: %w", err) // ErrInvalidKey → exit 3
	}
	addr, aerr := s.Address()
	_ = s.Close()
	if aerr != nil {
		return fmt.Errorf("local signer: %w", aerr)
	}
	cfg.Build.From = [20]byte(addr)
}
```

**Why drop the `Nonce == nil` gate** (my §1.5 addition, not a PRD requirement): PRD F1.3 says only
"derive `From` from the held key" for run-local. Because `EstimateGas` also needs a funded `From`,
deriving unconditionally in RPC mode makes gas estimation accurate for the `--nonce`-set +
`--gas-limit`-omitted combo — a pure improvement, no PRD conflict.

**Security posture (state in a code comment):** the key is read twice — once here, once in
`signUnsignedTx` (`sign.go:187`) — and each `LocalSigner` zeroizes its buffer on `Close`. Reading
from the env var is idempotent (`local.go:58`). `signUnsignedTx`'s signature is deliberately left
untouched so the shared sign path (used by the standalone `sign` command) is unaffected.

**`run --signer ledger`:** `From` stays zero. With `--nonce` omitted, `resolveRPC` returns
`ErrMissingFromForNonce` → exit 2 (§2). Do **not** query the device for its address (N1). No
`--from` flag is added to `run` (optional per PRD; not added). The operator must pass `--nonce` for
`run --signer ledger` in RPC mode; document this in `run --help` (§6).

### 1.6 Remove dead `BuildConfig.RPCURL`

`BuildConfig.RPCURL` (`interface.go:52-53`) is set only at `main.go:235` and is **never read** by
the builder (it branches on `cfg.RPC`). No `internal/tx` test constructs it (verified:
`builder_test.go` / `golden_test.go` `BuildConfig{}` literals omit it). Therefore:

- **Delete** the `RPCURL string` field and its `// reserved for Issue 2.5 … unused here` comment
  from `interface.go:52-53`.
- **Delete** the `RPCURL: cfg.RPCURL,` line from the `BuildConfig{...}` literal in
  `buildUnsignedTx` (`main.go:235`).

Keep the cmd-layer `Config.RPCURL` (`config.go:41-43`) — it is the source of truth for the dial
decision and is covered by `config_test.go`.

### 1.7 Fee/gas math — wire `resolveRPC` unchanged

Per research 05: `maxFee = 2·baseFee + tip` is byte-for-byte go-ethereum's `bind` formula; the 20%
gas margin (`estimate * 6 / 5`) is a safe over-estimate. `resolveRPC` (`builder.go:91-165`) is
correct as written — **no formula change.** The only edit to `resolveRPC` is error tagging (§2.2).

### 1.8 Behavior matrix (build and run)

| Scenario | `RPC` set? | Fields resolved | Result | Exit |
|---|---|---|---|---|
| Offline, explicit flags | no | static (flags) | unsigned tx, golden-identical | 0 |
| Offline, flags omitted | no | static defaults (250k/20g/1g/0) | unsigned tx, golden-identical | 0 |
| RPC + all gas/nonce flags explicit | yes | flags win in `resolveRPC` (no node calls except ChainID) | unsigned tx from flags | 0 |
| RPC + fields unset | yes | tip/baseFee/nonce/gas from node | unsigned tx reflecting live network | 0 |
| RPC unreachable (dial) | — | — | `ErrRPCDial`, unwrapped | **5** |
| RPC reachable, estimation call fails | yes | call error tagged `ErrRPCEstimation` | unwrapped | **5** |
| RPC chain-ID ≠ configured | yes | `ErrChainIDMismatch` (wrapped) | config error | **2** |
| RPC + nonce omitted + `From` zero (build no `--from`; ledger) | yes | `ErrMissingFromForNonce` (wrapped) | config error | **2** |
| build: RPC + `--nonce` set + `--gas-limit` omitted + no `--from` | — | rejected at config load (`EstimateGas` needs a funded `From` for the 32-ETH call) | config error | **2** |
| run-local: RPC (any nonce/gas) | yes | `From` always derived from the key | resolves nonce/gas as needed | 0 |
| build: `--from` bad hex | — | rejected at config load | config error | **2** |
| RPC ChainID() *call* itself errors | yes | warn-and-continue (swallowed, `builder.go:93-102`) | proceeds, no chain-ID check | 0 (or later per field) |

The last row is intentional and must be preserved: only a *mismatch* errors; a failed `ChainID()`
call is not promoted to exit 5.

---

## 2. F1.5 — Error classification survives wiring (P0)

### 2.1 The ordering problem

`ExitCodeFor` checks `ErrInvalidInput` (`exit.go:44`) **before** the exit-5 sentinel block
(`exit.go:85`). Today `buildUnsignedTx` blanket-wraps every builder error with `WrapInputErr`
(→ `ErrInvalidInput`), so once RPC is wired a connectivity failure would wrongly map to 2.

**Decision: check-before-wrap (not reorder `ExitCodeFor`).** In `buildUnsignedTx` (§1.2), test for
the RPC-connectivity sentinel and return it *unwrapped* so it bypasses the `ErrInvalidInput` branch
and reaches the exit-5 block; wrap everything else as today.

**Justification for not reordering `ExitCodeFor`:** the `ErrInvalidInput`-before-exit-5 order is
relied on by the offline exit-2 contract and its codifying test
(`TestExitCodeFor_BuildUnsignedErrorPath`, `exit_test.go:78-84`) — every static sentinel and every
`Validate` failure reaches exit 2 *because* it is wrapped. Reordering is a blunt, wide-blast-radius
change; check-before-wrap localizes the RPC-vs-input decision to the one call site that has the
context. A single error is never both wrapped-`ErrInvalidInput` and `ErrRPCEstimation`, so there is
no ambiguity.

### 2.2 New sentinel + tagging (`internal/tx`)

**`errors.go` — add to the broadcast/exit-5 group:**

```go
// ErrRPCEstimation tags a gas/fee/nonce estimation CALL failure in RPC mode
// (SuggestGasTipCap / BlockBaseFee / PendingNonceAt / EstimateGas). Exit code 5.
// Distinct from ErrRPCDial (connection) and ErrChainIDMismatch (config).
ErrRPCEstimation = errors.New("RPC estimation call failed")
```

**`builder.go` — tag the four `resolveRPC` call failures** while **preserving the method-name
substring** (`builder_test.go:567,666,698,728` assert `strings.Contains(err.Error(), "<Method>")`).
Use the two-`%w` form so both sentinels remain matchable:

| Line | Current | New |
|---|---|---|
| `builder.go:109` | `fmt.Errorf("SuggestGasTipCap: %w", err)` | `fmt.Errorf("%w: SuggestGasTipCap: %w", ErrRPCEstimation, err)` |
| `builder.go:118` | `fmt.Errorf("BlockBaseFee: %w", bErr)` | `fmt.Errorf("%w: BlockBaseFee: %w", ErrRPCEstimation, bErr)` |
| `builder.go:133` | `fmt.Errorf("PendingNonceAt: %w", err)` | `fmt.Errorf("%w: PendingNonceAt: %w", ErrRPCEstimation, err)` |
| `builder.go:158` | `fmt.Errorf("EstimateGas: %w", eErr)` | `fmt.Errorf("%w: EstimateGas: %w", ErrRPCEstimation, eErr)` |

Do **not** tag `ErrChainIDMismatch` (`builder.go:97`) or `ErrMissingFromForNonce`
(`builder.go:129`) — they are config errors (exit 2), not connectivity.

### 2.3 `ExitCodeFor` map additions (`exit.go`)

Three additions; note which are load-bearing:

1. **`internaltx.ErrRPCEstimation` → 5 (LOAD-BEARING).** Add to the exit-5 block (`exit.go:85-88`),
   next to `ErrRPCDial`. Because `buildUnsignedTx` returns it *unwrapped*, `ExitCodeFor` is the
   **only** thing mapping it to 5 — omit this line and it falls to the exit-1 fallback.

   ```go
   if errors.Is(err, internaltx.ErrRPCDial) ||
   	errors.Is(err, internaltx.ErrRPCEstimation) ||   // NEW
   	errors.Is(err, internaltx.ErrBroadcastFailed) ||
   	errors.Is(err, internaltx.ErrBroadcastChainIDMismatch) {
   	return 5
   }
   ```

2. **`internaltx.ErrChainIDMismatch` → 2 (documentary).** Add to the exit-2 tx region. The wrap
   already yields 2 (build-side stays wrapped), but PRD F1.5/F4.3 call for an explicit line for
   coherence with the other two chain-ID paths. Place after the `ErrInvalidInput` check
   (`exit.go:44`):

   ```go
   // Exit code 2: build-side RPC configuration errors (tx).
   if errors.Is(err, internaltx.ErrChainIDMismatch) ||
   	errors.Is(err, internaltx.ErrMissingFromForNonce) {
   	return 2
   }
   ```

3. **`internaltx.ErrMissingFromForNonce` → 2 (documentary).** Same block as above; also covered by
   the wrap.

**Coherence check (F4.3):** three distinct chain-ID sentinels now map explicitly —
`internaltx.ErrChainIDMismatch` (build-side config) → **2**, `signer.ErrChainIDMismatch`
(signer-side, `exit.go:73`) → **3**, `internaltx.ErrBroadcastChainIDMismatch` (broadcast-side,
`exit.go:87`) → **5**.

---

## 3. F2 — Missing-required-flag errors exit 2 everywhere (P0)

### 3.1 The shared `OnUsageError` hook

`*errRequiredFlags` is unexported and not an `ExitCoder`, so it falls to exit 1 (research 03,
empirically verified). The fix is urfave's intended interception point, invoked exactly at the
required-flags check (`command_run.go:346-350`, confirmed) and also for flag-parse /
mutually-exclusive / argument-parse errors — one hook fixes the whole usage-error class.

**`main.go` (or `exit.go`) — add:**

```go
// onUsageError converts urfave usage errors (missing required flag, unknown
// flag, bad flag value, arg-parse failures) into an exit-code-2 ExitCoder,
// so every subcommand agrees that usage errors are user/config errors (F2).
func onUsageError(_ context.Context, _ *ucli.Command, err error, _ bool) error {
	return ucli.Exit(err.Error(), 2)
}

// applyUsageErrorHook sets onUsageError on every subcommand of app. OnUsageError
// is read from the subcommand (not inherited from root), so it must be set on
// each. Must be called after the command list is built.
func applyUsageErrorHook(app *ucli.Command) {
	for _, c := range app.Commands {
		c.OnUsageError = onUsageError
	}
}
```

Signature verified against v3.10.1:
`func(ctx context.Context, cmd *Command, err error, isSubcommand bool) error`.

### 3.2 Wiring

- **`main()`:** call `applyUsageErrorHook(app)` immediately after the `app := &ucli.Command{...}`
  literal (after `Commands` is populated), before `app.Run`.
- **Interaction with `ExitErrHandler`:** unchanged. `ExitErrHandler` stays the no-op
  (`main.go:79`); `handleExitCoder` returns the error unchanged, and `main` computes
  `ExitCodeFor(err)`. The hook fires *earlier* (at the required-flags check) and rewrites the error
  to `ucli.Exit(...,2)`, which `ExitCodeFor` maps via the existing `ucli.ExitCoder && ==2` branch
  (`exit.go:59-61`). No new `ExitCodeFor` logic.
- **slog output:** unchanged. `main` still logs `slog.Error("fatal", "err", err)`. The hook
  suppresses urfave's own "Incorrect Usage" banner + help dump — an **intentional** decision that
  makes `build`/`gen` behave like `sign`/`run`/`send` (which already print a one-line message), not
  a regression.

### 3.3 The buggy bucket the hook fixes

Every `Required: true` flag whose error previously fell to exit 1:

| Subcommand | `Required:true` flag(s) | Was | Now |
|---|---|---|---|
| `build` | `input-file` (`main.go:126`) | 1 | 2 |
| `gen` | `keystore-dir`, `pubkeys`, `network` (`cli.go:112,117,122`) — `output-dir` dropped by F3 | 1 | 2 |
| `sign` | `signer` (`sign.go:104`) — **PRD understates this; sign had a buggy flag too** | 1 | 2 |
| `run` | `input-file` (via `buildFlags()`, `run.go:176`) | 1 | 2 |
| `send` | none (`Required:true`) | 2 (manual `ucli.Exit`) | 2 (hook is backstop only) |

Existing manual `ucli.Exit(...,2)` checks in `sign`/`run`/`send` are kept (harmless; already
exit 2). The hook is the uniform mechanism (F2.2).

### 3.4 Test constructor (needed for M3)

`newTestApp()` (`main_test.go:365-372`) wires only build/sign/run; `newE2EApp()`
(`deposit_e2e_test.go:28-35`) adds send but not gen. Neither applies the hook. Add a full-app
constructor that both mirrors production and is reachable per-subcommand:

```go
// newFullTestApp returns all five subcommands with the production usage-error
// hook applied, so tests can assert exit-2 mapping for missing required flags.
func newFullTestApp() *ucli.Command {
	app := &ucli.Command{
		Name:     "eth-deposit",
		Version:  "dev",
		Commands: []*ucli.Command{genCommand(), buildCommand(), signCommand(), runCommand(), sendCommand()},
	}
	applyUsageErrorHook(app)
	return app
}
```

(Also call `applyUsageErrorHook` inside the existing `newTestApp`/`newE2EApp` if their tests grow
exit-code assertions; otherwise leave them so current tests stay stable.)

---

## 4. F3 — `gen --dry-run` must not require `--output-dir` (P1)

urfave cannot express conditional requiredness (`checkAllRequiredFlags` runs before any Action;
research 04). Move the check into the Action, matching `gen`'s existing manual-validation style.

**`internal/cli/cli.go` — two edits:**

1. Remove `Required: true` from the `output-dir` flag (`cli.go:124-128`).
2. Replace the unconditional validation block (`cli.go:200-204`) with a dry-run-gated one:

```go
// 4. Validate --output-dir (skipped in dry-run: DryRunWriter never touches disk).
outputDir := cmd.String("output-dir")
if !cmd.Bool("dry-run") {
	if outputDir == "" {
		return ucli.Exit("--output-dir: required flag not set", 2)   // F3.2
	}
	if err := validateOutputDir(outputDir); err != nil {             // cli.go:316
		return ucli.Exit(fmt.Sprintf("--output-dir: %v", err), 2)    // F3.2
	}
}
```

`cmd.Bool("dry-run")` is already read into `Config.DryRun` at `cli.go:223`; reading it here early is
fine. `DryRunWriter` writes JSON to stdout and never uses `output-dir` (`gen.go:81-86`);
`--verify-with-deposit-cli` is already skipped in dry-run (`gen.go:412`). No downstream consumer of
`output-dir` remains in dry-run.

**Interaction with F2:** exit codes stay 2 whether the missing flag is caught by the hook (for the
flags still `Required:true`) or by this manual `ucli.Exit(…,2)`. Uniform.

---

## 5. F4 — Disambiguate chain-ID mismatch in docs (P1, doc-only)

No behavior change. Three chain-ID paths must read coherently: build-side config → 2, signer-side
→ 3, broadcast-side → 5.

**`main.go:7-14` header comment — replace with:**

```go
// Exit codes:
//
//	0 — success
//	1 — unexpected / internal error
//	2 — user / configuration error (bad input, unknown network, missing file,
//	    missing required flag, build-side RPC chain-ID mismatch)
//	3 — signer / crypto error (bad key, no device, app not open,
//	    signer-side chain-ID mismatch)
//	4 — user abort (SIGINT or Ledger rejection)
//	5 — broadcast / RPC error (dial failure, gas/nonce estimation failure,
//	    eth_sendRawTransaction error, broadcast-side chain-ID mismatch)
```

**`exit.go:1-11` header comment** — add build-side to the exit-2 line and label the exit-3 chain-ID
as signer-side (the 3-vs-5 split is already there; add the new build-side 2 case):
- exit-2 line: append "build-side RPC chain-ID mismatch".
- exit-3 line: "chain ID mismatch" → "signer-side chain ID mismatch".

**Per-subcommand `--help` exit-code lists** (also satisfies F1.6, since `build`/`run` can now reach
exit 5):

- **build** (`main.go:116-119`) — add exit 5, note `--from`/chain-ID under 2:
  ```
  Exit codes:
    0  Success
    2  User / configuration error (missing/invalid input, bad --network, out-of-range
       --index, missing required flag, missing --from for RPC nonce/gas estimation,
       RPC chain-ID mismatch)
    5  RPC error (endpoint unreachable, gas/nonce estimation failed)
    1  Unexpected internal error
  ```
- **run** (`run.go:130-135`) — add exit 5 and the ledger `--nonce` note:
  ```
  Exit codes:
    0  Success
    2  User / configuration error (missing file, bad --network, missing --signer,
       missing --nonce for ledger RPC mode, RPC chain-ID mismatch)
    3  Signer / crypto error (bad key, no Ledger device, Ethereum app not open)
    4  User abort (Ctrl-C or rejection on Ledger device)
    5  RPC error (endpoint unreachable, gas/nonce estimation failed)
    1  Unexpected internal error
  ```
- **sign** (`sign.go:94-98`) — clarify exit 3: "signer-side chain-ID mismatch (bad key, no Ledger
  device, Ethereum app not open, signer-side chain-ID mismatch)".
- **send** (`send.go:104-108`) — clarify exit 5: "…chain ID mismatch" → "broadcast-side chain ID
  mismatch".

The one-line root summary (`main.go:70`) may stay coarse; no change required.

---

## 6. F5 — No-TTY passphrase error hints at `--passphrase-env` and exits 2 (P1)

**`internal/keystore/keystore.go` — add sentinel** to the `var (...)` block (`keystore.go:18-36`):

```go
// ErrNoTTY is returned when an interactive passphrase prompt is needed but no
// controlling terminal is available (piped/non-interactive use). Exit code 2.
ErrNoTTY = errors.New("no controlling terminal for passphrase prompt")
```

**`internal/keystore/passphrase.go` — wrap the `/dev/tty` open failure** with the sentinel and the
hint (`passphrase.go:46-48`):

```go
tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
if err != nil {
	return nil, fmt.Errorf("%w: cannot open /dev/tty (%v); for non-interactive or piped use, supply the passphrase via --passphrase-env VAR", ErrNoTTY, err)
}
```

The chain is preserved through `keystore.go:127` (`"passphrase source: %w"`) and gen's worker
result plumbing (passed as-is, `gen.go:328-331`), so `errors.Is(err, keystore.ErrNoTTY)` holds at
`ExitCodeFor`.

**`cmd/eth-deposit/exit.go` — map to 2** in the keystore exit-2 group (`exit.go:48-56`):

```go
errors.Is(err, keystore.ErrKeystoreNotFound) ||
	errors.Is(err, keystore.ErrNoTTY) ||   // NEW
	errors.Is(err, deposit.ErrPubkeyMismatch) ||
```

---

## 7. F6 — Document the `.raw` companion output (P2, verify/polish)

**Already present:** `run --help` (`run.go:89-99`) documents `signed.raw`, the 0x prefix, the
"only when --output is a file" condition, and the `--raw-output` override. `USER-GUIDE.md:487-489`
documents `signed_tx.raw (0o600)` and its use for `cast publish`/curl.

**Polish checklist (small edits only):**

1. `USER-GUIDE.md:488` — make the `0x` prefix explicit: "just the `rawRLP` hex (**0x-prefixed**)".
2. `USER-GUIDE.md:488` — state the condition: add "written **only when `--output` is a file path**;
   with stdout output no `.raw` is produced." (mirrors `run.go:96-98`).
3. Confirm `0o600` appears in both `run --help` and `USER-GUIDE.md` — `USER-GUIDE.md:488` has it;
   `run --help` prose (`run.go:91-94`) does not name the mode. Optional: add "(mode 0600)" to the
   `signed.raw` line in `run --help` for parity.

No net-new sections; no behavior change (N3).

---

## 8. Test architecture

### 8.1 Existing tests that MUST change (deliberate, per C4)

| Test | File:line | Change | Why |
|---|---|---|---|
| `TestLoadBuildConfig_Defaults` | `config_test.go:64-66` | `cfg.GasLimit` assert: `defaultGasLimit` → **`0`** | F1.2: `Config.GasLimit` is now 0 when `--gas-limit` unset; the offline branch restores 250k downstream |

That is the **only** existing assertion the contract change breaks. Verified:
- No test asserts exit **1** for a *missing required flag* (the `gen_test.go` `want 1` cases at
  `:281`/`:508` are disk-full / scanner = legitimately internal error; the `exitCoder1` case at
  `:322` is `ucli.Exit(...,1)` mapping, unrelated). So C4's "flip the exit-1 tests" applies to
  **zero** existing tests — F2's test work is purely additive.
- `config_test.go` `GasLimitZero`/`GasLimitEnvVar`/`AllFlagsSet` are unaffected (explicit/env values
  still populate `Config.GasLimit`).
- Golden tests stay byte-identical (offline path unchanged): `TestBuild_GoldenOutput`
  (`main_test.go:19`), `internal/tx/golden_test.go`, `signed_golden_test.go`. Do **not** update the
  golden fixtures.

### 8.2 New tests

**`internal/tx` (builder, `package tx`):**
- RPC-mode success already covered (`builder_test.go:360-402`) — re-run to confirm the two-`%w`
  tagging didn't change field values.
- Add: each of the 4 call-failure tests (`builder_test.go:543,641,670,702`) additionally asserts
  `errors.Is(err, ErrRPCEstimation)` (they currently assert only the substring — keep that).
- Add: `ErrChainIDMismatch` / `ErrMissingFromForNonce` are **not** `errors.Is(err, ErrRPCEstimation)`
  (guard against over-tagging).

**`cmd/eth-deposit` (via the `newEthRPC` seam — cmd tests supply their own fake implementing the
exported `internaltx.EthRPC`; the `package tx` `mockRPC` is unexported and unavailable here):**
- `withMockEthRPC(t, fake)` helper mirroring `withMockBroadcaster` (`send_test.go:86-90`): swaps
  `newEthRPC`, restores on cleanup.
- A cmd-level fake `EthRPC` (function-field pattern like `mockBroadcaster`).
- Cases, asserting `ExitCodeFor(err)` on the returned error:
  1. **Offline unchanged** — build, no `--rpc-url`, no gas flags → success; fields = defaults.
  2. **RPC + unset fields** — fake returns tip/baseFee/nonce/gas; assert the unsigned tx reflects
     them (`maxFee = 2·baseFee + tip`, `gas = estimate·6/5`, nonce from fake) and `newEthRPC` was
     invoked.
  3. **RPC + explicit flags win** — set all flags; fake `t.Fatal`s if a resolve call fires (except
     `ChainID`).
  4. **RPC unreachable** — `newEthRPC` returns `ErrRPCDial` → exit **5**; `Close` not called.
  5. **RPC estimation call fails** — fake `EstimateGas` returns error → tagged `ErrRPCEstimation`
     → exit **5**.
  6. **RPC chain-ID mismatch** — fake `ChainID` returns a different id → `ErrChainIDMismatch`
     → exit **2**.
  7. **build RPC + nonce omitted + no `--from`** → config-time exit **2** (§1.4 check).
  8. **build RPC + `--nonce` set + `--gas-limit` omitted + no `--from`** → config-time exit **2**
     (the gas-estimation half of the §1.4 gate; the seam-fake would otherwise hide this because it
     ignores `CallMsg.From`).
  9. **build `--from` bad hex** → exit **2**.
  10. **run `--signer local` + RPC + nonce omitted** — `From` derived from the key; fake
     `PendingNonceAt` and `EstimateGas` receive that non-zero address; success. (Use the phase-3
     synthetic key fixture; assert `CallMsg.From` is the derived address, not zero.)
  11. **run `--signer ledger` + RPC + nonce omitted** → `ErrMissingFromForNonce` → exit **2**
      (no device interaction).

**F2 required-flag tests (`newFullTestApp`), asserting `ExitCodeFor(err) == 2`:**
- `build` without `--input-file`; `gen` without `--keystore-dir`/`--pubkeys`/`--network`; `sign`
  without `--signer`; `run` without `--input-file`; and a bad flag value (e.g. `--index abc`) on
  build → all exit 2.

**F3 (`internal/cli` or cmd gen tests):**
- `gen --dry-run` with no `--output-dir` → success (JSON to stdout), exit 0.
- `gen --dry-run` with an invalid `--output-dir` → success (validation skipped).
- `gen` without `--dry-run` and no `--output-dir` → exit 2.
- `gen` without `--dry-run` and invalid `--output-dir` → exit 2 (unchanged).

**F5 (`internal/keystore` + `cmd/eth-deposit/exit_test.go`):**
- keystore unit: `termPromptSource.Read()` with `/dev/tty` unavailable → `errors.Is(ErrNoTTY)` and
  message contains `--passphrase-env`. (May need to gate on an environment where `/dev/tty` fails,
  or refactor the tty-open into an injectable func; if injection is out of scope, cover the
  sentinel mapping in `exit_test.go` and the message in a keystore-level test that forces the open
  failure.)
- `exit_test.go`: `keystore.ErrNoTTY` → 2 (direct and wrapped `"passphrase source: %w"`).

**`exit_test.go` additions (sentinel map):**
- `internaltx.ErrRPCEstimation` → 5 (direct + wrapped).
- `internaltx.ErrChainIDMismatch` → 2, `internaltx.ErrMissingFromForNonce` → 2.
- A hook-shaped required-flag error: `ucli.Exit("Required flag \"x\" not set", 2)` → 2 (documents
  the F2 mechanism at the map level).

**e2e (`-tags=e2e`, `deposit_e2e_test.go`):**
- Add `genCommand()` to `newE2EApp` if a gen e2e case is added; apply `applyUsageErrorHook`.
- Hybrid `build`/`run --rpc-url` against a mock or a local anvil (the `verify` skill provides
  anvil): gas/nonce omitted → assert the tx fields reflect anvil's live tip, base fee, and pending
  nonce (M1/M6). Where anvil is unavailable in CI, the deterministic seam-fake cases (8.2) provide
  coverage; the anvil case is the integration confirmation.

### 8.3 Module-boundary guardrails for tests
- cmd tests inject through `newEthRPC` (exported interface) — never reach into `package tx`
  internals.
- builder tests stay in `package tx` with the existing unexported `mockRPC`.
- signer address derivation is tested in `internal/signer` (`Address()` on `*LocalSigner`, incl.
  closed → `ErrSignerClosed`).
- keystore TTY error is tested in `internal/keystore`.

---

## 9. File-by-file change summary

| File | Change |
|---|---|
| `cmd/eth-deposit/main.go` | add `newEthRPC` seam + `"errors"` import; rewrite `buildUnsignedTx` (dial+inject, offline-gated default fill, check-before-wrap, drop `RPCURL:` from literal, set `From:`); add `--from` flag to `buildCommand()`; add build-Action conditional `--from` check; add `onUsageError`+`applyUsageErrorHook`, call it in `main()`; update header comment + build `--help` exit codes |
| `cmd/eth-deposit/config.go` | add `Config.From [20]byte`; `gasLimit` unset → `0` (drop eager default); parse+validate `--from` (`encoding/hex`, `strings`) |
| `cmd/eth-deposit/exit.go` | map `ErrRPCEstimation`→5 (load-bearing), `ErrChainIDMismatch`/`ErrMissingFromForNonce`→2 (documentary), `keystore.ErrNoTTY`→2; update header comment |
| `cmd/eth-deposit/run.go` | early derive-and-close `From` for `--signer local` RPC mode; update run `--help` exit codes; optional `.raw` mode note |
| `cmd/eth-deposit/sign.go` | clarify exit-3 chain-ID wording in `--help` |
| `cmd/eth-deposit/send.go` | clarify exit-5 chain-ID wording ("broadcast-side") in `--help` |
| `internal/tx/interface.go` | delete dead `RPCURL` field + stale comment |
| `internal/tx/errors.go` | add `ErrRPCEstimation` |
| `internal/tx/builder.go` | tag 4 `resolveRPC` call failures with `ErrRPCEstimation` (preserve method substrings) |
| `internal/signer/local.go` | add `Address() (common.Address, error)`; import `common` |
| `internal/keystore/keystore.go` | add `ErrNoTTY` sentinel |
| `internal/keystore/passphrase.go` | wrap `/dev/tty` open failure with `ErrNoTTY` + `--passphrase-env` hint |
| `internal/cli/cli.go` | drop `Required` on `--output-dir`; dry-run-gated validation in Action |
| `docs/USER-GUIDE.md` | replace "Phase 4 / accepted-but-stored" `--rpc-url` row + `--nonce` row; add `--from` row; polish `.raw` (0x prefix, file-only condition) |
| `cmd/eth-deposit/config_test.go` | flip `GasLimit` default assertion to `0` |
| test files | additive: seam-fake cmd tests, F2 required-flag tests, F3 dry-run tests, F5 keystore/exit tests, `exit_test.go` sentinel cases, `newFullTestApp` |

---

## 10. Invariants preserved (traceability)

- **C1 exit contract:** only F2/F5 (incorrect mappings) and F1.5 (newly reachable) change; all
  correct paths untouched (check-before-wrap keeps `ExitCodeFor` ordering stable).
- **C2 golden:** offline path (default fill) is byte-identical; fixtures not regenerated.
- **C3 air-gapped:** no `--rpc-url` ⇒ offline branch ⇒ 250k/20g/1g/nonce-0 unchanged.
- **C4 tests:** all pass; the single deliberate flip (`config_test.go` GasLimit) + additive new
  tests documented.
- **C5 no new deps:** reuses `ethclient` (via existing `NewEthClient`) and go-ethereum `common`
  (already in the module); no new modules.
- **N1 ledger:** `Address()` is on `*LocalSigner` only; ledger `From` stays zero, no early device
  query.
- **N3 `.raw`:** documented, not altered.
