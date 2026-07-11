# Phase 2 — Hybrid RPC wiring (F1, P0)

Make `--rpc-url` real: dial the node, inject the client, relocate default-fill so unset
gas/fee/nonce resolve from the node in RPC mode while offline stays byte-identical; add
`--from` with the tightened gate; derive `From` for `run --signer local`; preserve error
classification through the wiring (F1.5).

**Phase entry / Milestone gate:** M1 (needs `ErrRPCEstimation`+tagging from P1-1,
`exit.go` mappings from P1-5, `LocalSigner.Address()` from P1-2).
**Phase exit / Milestone M2:** hybrid mode resolves nonce/fees from node; offline golden
byte-identical; RPC error classification correct (dial/estimation→5, chain-ID/`--from`→2).

All three issues are **Stream A** and edit `config.go`/`main.go`/`run.go`, so they run in a
serial chain (P2-1 → P2-2 → P2-3). Behavior-matrix test cases (arch §8.2) are folded into the
issue that introduces the behavior — there is no separate test-only issue.

> **Collapse rationale (project-plan §Phase-2 note + Risk R1):** arch work items 2a (seam),
> 2b (default-fill relocation), and 2d (drop dead `RPCURL`) all rewrite `buildUnsignedTx` and
> are mutually coupled — 2a alone does nothing until 2b relocates the eager default-fill, and
> 2d is compile-coupled. They are combined into **P2-2**. 2b's two sites (`config.go:74` +
> `main.go:241-253`) remain **one indivisible commit** inside P2-2 (Risk R1).

---

## P2-1 — `--from` flag, `Config.From`, and the tightened config-time gate

- **Stream:** A
- **Points:** 2
- **Dependencies:** none (Phase-2 entry gate M1; no hard code dep on other issues — it is the
  `config.go` prerequisite the rest of Phase 2 builds on)
- **Findings:** F1.3, part of F1.6 (the `--from` Usage string)

**Description.** Implements architecture §1.4. Adds the sender flag and its strict validation
plus the build-side conditional-required gate. Consumption of `Config.From` by `buildUnsignedTx`
lands in P2-2.

- `cmd/eth-deposit/config.go` — add field:
  ```go
  // From is the sender address, parsed from --from. Zero value means unset.
  // Used only in RPC mode to fetch the pending nonce when --nonce is omitted.
  From [20]byte
  ```
  and parse in `LoadBuildConfig` (universal; `c.String("from")` returns `""` for `run`, which
  does not declare `--from` — verified against urfave v3.10.1):
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
  Add `encoding/hex` and `strings` imports. Do **not** use `common.HexToAddress` (it is lenient
  and silently truncates/pads).
- `cmd/eth-deposit/main.go` — add the flag to **`buildCommand()` only** (not `buildFlags()`/run):
  ```go
  &ucli.StringFlag{
      Name:    "from",
      Usage:   "Sender address (0x-prefixed, 20-byte hex). Required with --rpc-url when --nonce or --gas-limit is omitted, to fetch the pending nonce and estimate gas.",
      Sources: ucli.EnvVars("ETH_DEPOSIT_TX_FROM"),
  },
  ```
- `cmd/eth-deposit/main.go` — build-Action gate, after `LoadBuildConfig` returns, before
  reading input (the **tightened** rule — PRD F1.3 as synced, Risk R5 RESOLVED):
  ```go
  if cfg.RPCURL != "" && cfg.From == ([20]byte{}) && (cfg.Nonce == nil || cfg.GasLimit == 0) {
      return ucli.Exit("--from: required when --rpc-url is set and --nonce or --gas-limit is omitted "+
          "(the sender is needed to fetch the pending nonce and to estimate gas for the 32-ETH deposit call)", 2)
  }
  ```
  > **Note:** this gate reads `cfg.GasLimit == 0` for "unset", which requires the P2-2
  > `config.go:74` change (eager default removed). Until P2-2 merges, `GasLimit` is never 0 so
  > the `--gas-limit`-omitted half is inert. Land the gate here but its `--gas-limit` half only
  > becomes live once P2-2 merges — both are Stream A, sequential, so this is consistent within
  > the release branch. (The `--nonce`-omitted half is fully live in P2-1.)

**Acceptance criteria** (arch §1.8 matrix rows + plan Phase-2 exit criteria):
- `build --rpc-url` with `--nonce` **or** `--gas-limit` omitted and no `--from` → exit **2** at
  config load (matrix rows 8 & 9).
- `build --from` bad hex → exit **2** at config load (matrix row 11).
- When both `--nonce` and `--gas-limit` are supplied, `--from` is **not** required.
- `run` (no `--from` flag declared) is unaffected: `c.String("from")` returns `""`, no error.
- Tests cover: missing-`--from` for the nonce-omitted half → 2; missing-`--from` for the
  gas-omitted half → 2; bad-hex `--from` → 2 (arch §8.2 cases 7, 8, 9 — config-time, no RPC
  fake needed).
- `go test ./cmd/eth-deposit/...` green.

---

## P2-2 — Dial + inject seam, default-fill relocation, drop dead `RPCURL` (indivisible)

- **Stream:** A
- **Points:** 4  *(at the 2-day ceiling; justified by the indivisible default-fill commit + seam-fake test scaffolding)*
- **Dependencies:** **P2-1** (`Config.From` field, consumed here), **P1-1** (`ErrRPCEstimation`
  sentinel), **P1-5** (`ErrRPCEstimation`→5 mapping — load-bearing for the exit-5 result)
- **Findings:** F1.1, F1.2, F1.5, F1.6 (`--rpc-url` inline Usage), collapses arch 2a+2b+2d

**Description.** Implements architecture §1.1–§1.3, §1.6, §2.1. This is the whole
`buildUnsignedTx` rewrite plus both default-fill sites plus removal of the dead field.

- `cmd/eth-deposit/main.go` — add the injection seam (mirrors `newBroadcaster`, `send.go:22-25`):
  ```go
  var newEthRPC = func(ctx context.Context, rpcURL string) (internaltx.EthRPC, error) {
      return internaltx.NewEthClient(ctx, rpcURL)
  }
  ```
  Add `"errors"` to `main.go` imports.
- `cmd/eth-deposit/main.go` — rewrite `buildUnsignedTx` (`main.go:216-261`) per arch §1.2:
  set `From: cfg.From` in the `BuildConfig` literal; **remove** `RPCURL: cfg.RPCURL`; in RPC mode
  (`cfg.RPCURL != ""`) dial via `newEthRPC`, **check `err` and return before any `defer
  client.Close()`** (nil-interface guard, mirrors `send.go:169-173`), set `buildCfg.RPC`, and
  leave gas/fees/nonce unset so `resolveRPC` fills them; in the offline `else` branch fill the
  hardcoded defaults (the block relocated wholesale from `main.go:241-253`). After
  `builder.BuildUnsigned`, use **check-before-wrap**: if `errors.Is(err, ErrRPCEstimation)`
  return it **unwrapped** (→ exit 5); otherwise `return WrapInputErr("build", err)` (→ exit 2,
  offline contract preserved). On dial failure return the error unwrapped (→ exit 5 via
  `ErrRPCDial`).
- `cmd/eth-deposit/config.go` — **`config.go:74`** (the second default-fill trap, **same commit**
  as the `main.go` relocation — Risk R1): change `gasLimit := defaultGasLimit` to
  `var gasLimit uint64`; the explicit-`"0"`→error path stays (keyed on `s != ""` at
  `config.go:75,80`). `Config.GasLimit` is now `0` when `--gas-limit` is omitted; the offline
  branch restores `250000`.
- `cmd/eth-deposit/config_test.go` — flip `TestLoadBuildConfig_Defaults` `GasLimit` assertion
  from `defaultGasLimit` to **`0`** (the single deliberate existing-test change; arch §8.1).
- `internal/tx/interface.go` — **delete** the dead `RPCURL string` field + `// reserved for
  Issue 2.5 … unused here` comment (`interface.go:52-53`). Compile-coupled — same commit.
- `cmd/eth-deposit/main.go` — update the build command **description** and the `--rpc-url`
  **inline Usage string** (`main.go:96`, `main.go:149`) to describe the now-real hybrid behavior;
  remove any "accepted-but-stored / Phase 4 wiring" phrasing from these inline strings. *(Per
  plan coordination note, Phase 2 owns the inline flag Usage strings; the exit-code prose and the
  `USER-GUIDE.md` narrative rows are owned by P3-2.)*
- Tests (`cmd/eth-deposit`, per arch §8.2 — seam-fake infra lives here): add `withMockEthRPC(t,
  fake)` (mirrors `withMockBroadcaster`, `send_test.go:86-90`) and a cmd-level fake `EthRPC`
  (function-field pattern like `mockBroadcaster`; must implement the **exported**
  `internaltx.EthRPC` — the `package tx` `mockRPC` is unavailable here). Cases 1–6, asserting
  `ExitCodeFor(err)`:
  1. offline, no `--rpc-url`, no gas flags → success; fields = defaults.
  2. RPC + unset fields → tx reflects fake's tip/baseFee/nonce/gas (`maxFee = 2·baseFee + tip`,
     `gas = estimate·6/5`); `newEthRPC` invoked.
  3. RPC + all gas/nonce flags explicit → flags win; fake `t.Fatal`s if any resolve call other
     than `ChainID` fires.
  4. RPC unreachable → `newEthRPC` returns `ErrRPCDial` → exit **5**; `Close` not called.
  5. RPC estimation call fails → fake `EstimateGas` errors → tagged `ErrRPCEstimation` → exit **5**.
  6. RPC chain-ID mismatch → fake `ChainID` returns a different id → `ErrChainIDMismatch` → exit **2**.
- Golden byte-identity (C2/C3/M7): run all `*_golden_test.go` unchanged; do **not** regenerate
  fixtures.

**Acceptance criteria** (arch §1.8 matrix rows 1–7, 10, 13 + plan Phase-2 exit criteria):
- Hybrid build (fake or anvil) with `--gas-limit`/`--nonce` omitted → tx with
  `maxFee = 2·baseFee + tip`, `gas = estimate·6/5`, nonce = the node's **pending nonce**.
- Explicit gas/nonce flags in RPC mode win (no resolve call other than `ChainID` fires).
- Unreachable `--rpc-url` → exit **5**; reachable node whose estimation call fails → exit **5**.
- RPC chain-ID **mismatch** → exit **2**; a failed `ChainID()` **call** (not a mismatch) does not
  promote to exit 5 (matrix last row — warn-and-continue, `builder.go:93-102`).
- Offline builds remain **250 000 / 20 gwei / 1 gwei / nonce 0**; all `*_golden_test.go`
  byte-identical (diff empty); fixtures not regenerated.
- `TestLoadBuildConfig_Defaults` asserts `GasLimit == 0`.
- `go test ./...` green.

---

## P2-3 — `run --signer local` `From` derivation

- **Stream:** A (run path; touches `run.go`, disjoint from build path — may be developed in
  parallel by Stream B and merged after P2-2)
- **Points:** 2
- **Dependencies:** **P1-2** (`LocalSigner.Address()`), **P2-1** (`Config.From`/`cfg.Build.From`),
  **P2-2** (the seam-fake infra + `From` consumption in `buildUnsignedTx` make this testable/green)
- **Findings:** F1.3 (run half), F1.6 (run's `--rpc-url` inline Usage, if stale)

**Description.** Implements architecture §1.5 (run half).

- `cmd/eth-deposit/run.go` — early derive-and-close in `runAction`, between reading deposit data
  (step 1) and `buildUnsignedTx` (`run.go:239`): for `--signer local` in RPC mode, construct the
  signer via `NewLocalSignerFromEnv`, read `Address()`, `Close()` (zeroize), set
  `cfg.Build.From = [20]byte(addr)` (code verbatim in arch §1.5). Derive **unconditionally** in
  RPC mode (drops the `Nonce == nil` gate so `EstimateGas` also gets a funded `From`). State the
  key-read-twice security posture in a code comment (arch §1.5); do **not** touch
  `signUnsignedTx`'s signature.
- `run --signer ledger`: `From` stays zero; do **not** query the device (N1). No `--from` flag is
  added to `run`.
- If run's `--rpc-url` inline Usage string (`run.go:196-200`, via `buildFlags()`) carries stale
  "accepted-but-stored / Phase 4" phrasing, de-stale it here (inline Usage strings are Phase 2's
  per the coordination note; exit-code prose is P3-2).
- Tests (`cmd/eth-deposit`, per arch §8.2 cases 10, 11): 
  10. `run --signer local --rpc-url`, nonce omitted → `From` derived from the key; fake
      `PendingNonceAt`/`EstimateGas` receive the **non-zero** derived address (assert
      `CallMsg.From` is the derived address, not zero); success. Use the phase-3 synthetic key
      fixture.
  11. `run --signer ledger --rpc-url`, nonce omitted → `ErrMissingFromForNonce` → exit **2**,
      no device interaction.

**Acceptance criteria** (arch §1.8 matrix rows 10, 12 + plan Phase-2 exit criteria):
- `run --signer local --rpc-url` (nonce omitted) resolves nonce/gas using the key-derived
  **non-zero** `From`.
- `run --signer ledger --rpc-url` (nonce omitted) exits **2** with no device interaction.
- `go test ./cmd/eth-deposit/...` green.

---

### Phase 2 totals

| Item | Stream | Points |
|---|---|---|
| P2-1 | A | 2 |
| P2-2 | A | 4 |
| P2-3 | A | 2 |
| **Total** | | **8** |
