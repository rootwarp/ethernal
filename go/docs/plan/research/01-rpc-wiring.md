# Research — Wiring ethclient into build/run (PRD F1)

**Question set:** where to construct the client, lifecycle/close, how `BuildConfig.RPC`
is defined and whether the existing `ethClient` satisfies it, how `run` derives the
`From` address, how the default-filling must change, and how error classification
survives wiring. Grounded in repo code; every claim cites `file:line`.

---

## 1. Where to construct the client — **cmd layer, not the builder**

**Recommendation:** dial the RPC in the cmd layer (`buildUnsignedTx`,
`cmd/eth-deposit/main.go:216`), assign the result to `BuildConfig.RPC`, and pass the
config into `builder.BuildUnsigned`. The builder stays pure: it consumes `cfg.RPC`
(an interface) and never dials. This is exactly how `send` already works.

- The builder already takes a live client through the config and branches on it:
  `resolveFields` (`internal/tx/builder.go:77-82`) calls `resolveStatic` when
  `cfg.RPC == nil` and `resolveRPC` otherwise. No dialing happens inside `internal/tx`.
- `send` establishes the precedent for a cmd-layer dial with an injectable seam:
  `newBroadcaster` is a package-level `var` that wraps `internaltx.NewEthClient`
  (`cmd/eth-deposit/send.go:22-25`), dialed in the action with `defer broadcaster.Close()`
  (`send.go:169-173`). Mirror this for `build`/`run`.

**Testability seam (do this):** add a cmd-level `var newEthRPC = func(ctx, url) (internaltx.EthRPC, error) { return internaltx.NewEthClient(ctx, url) }`
so `build`/`run` tests can inject a fake. This is necessary because the existing
`mockRPC` (`internal/tx/rpc_mock_test.go:10`) is **unexported and lives in `package tx`** —
cmd tests cannot use it. Cmd tests must supply their own fake implementing the
**exported** `internaltx.EthRPC` interface, injected through this seam (the same
pattern `send_test.go` uses to override `newBroadcaster`).

## 2. Does the existing `ethClient` satisfy `BuildConfig.RPC`? — **Yes, already**

- `BuildConfig.RPC` has type `EthRPC` (`internal/tx/interface.go:57`), the minimal
  five-method surface `SuggestGasTipCap` / `BlockBaseFee` / `PendingNonceAt` /
  `EstimateGas` / `ChainID` + `Close` (`interface.go:13-26`).
- `NewEthClient(ctx, url)` returns `*ethClient` (`internal/tx/rpc_client.go:48-54`),
  and `*ethClient` carries compile-time assertions for **both** interfaces:
  `var _ EthRPC = (*ethClient)(nil)` and `var _ EthBroadcaster = (*ethClient)(nil)`
  (`rpc_client.go:157-158`). The `EthRPC` methods are implemented at
  `rpc_client.go:116-144`.
- `NewEthClient` returns the *unexported* concrete type, but the cmd package can still
  assign it to the exported `internaltx.EthRPC` interface (all its methods are exported).
  This is the identical cross-package assignment `send` already performs with
  `EthBroadcaster` (`send.go:23-24`). **No new interface or adapter is needed.**

## 3. Lifecycle / close

- Dial only when `cfg.RPCURL != ""`. On success, `defer client.Close()` in the cmd
  function that owns the client (`buildUnsignedTx`), so the connection is released on
  every return path. `EthRPC.Close()` exists (`interface.go:24-25`,
  `rpc_client.go:110-112`).
- **Dial failure is already exit-5-tagged:** `NewEthClient` wraps connection errors
  with `ErrRPCDial` (`rpc_client.go:48-53`), and `ErrRPCDial` is in the exit-5 group
  (`cmd/eth-deposit/exit.go:85`). A dial failure returns from the cmd layer *before*
  the builder runs, so it never passes through `WrapInputErr` — it maps to exit 5 for
  free (satisfies PRD M2). No change needed for the dial path.
- `run` calls `buildUnsignedTx` (`run.go:239`), so whichever function owns the dial
  must own the `Close`. Keep the dial inside `buildUnsignedTx` so both `build` and
  `run` inherit identical lifecycle handling.

## 4. Deriving `From` for `run` (PRD F1.3)

**`--signer local`:** the `LocalSigner` holds the private key but **exposes no address
accessor today.** `Sign` computes the address internally via
`gethcrypto.PubkeyToAddress(priv.PublicKey)` (`internal/signer/local.go:116`), and the
`Signer` interface has no address method (`internal/signer/signer.go:16-34`).

- **Recommendation:** add an exported `Address()` method to `*LocalSigner` (return
  `common.Address`; `run` converts to `[20]byte` for `BuildConfig.From`). Keep it on
  the **concrete** `LocalSigner`, *not* on the `Signer` interface, so Ledger is never
  forced to expose an address offline (respects N1).
- **Ordering:** `From` must be set *before* the build, because `resolveRPC` needs it to
  fetch the nonce (`builder.go:128-131`). Today `run` builds first, then signs inside
  `signUnsignedTx` which constructs the signer (`sign.go:181-197`). For RPC mode +
  local + nonce omitted, `run` must construct the local signer (or derive its address)
  *before* `buildUnsignedTx`. Re-reading the key from the env var is idempotent and
  cheap (`NewLocalSignerFromEnv`, `local.go:58`), so a lightweight early derivation is
  acceptable; the architecture decides whether to thread the address or the signer.
- Only do this when `--rpc-url` is set **and** `--nonce` is omitted — otherwise `From`
  is unused and derivation can be skipped.

**`--signer ledger`:** leave `From` zero. With `--nonce` omitted, `resolveRPC` returns
`ErrMissingFromForNonce` (`builder.go:128-129`, `errors.go:20`) → exit 2 (see §6). The
PRD requires the operator to pass `--nonce` for `run --signer ledger` in RPC mode; a
`--from` flag on `run` is optional and not required by the PRD.

## 5. Default-filling must move to the offline branch (PRD F1.2) — **two spots, one is sneaky**

Unset gas/fee/nonce are currently pre-filled unconditionally, which would defeat
RPC resolution even after `RPC` is wired. **Fees and nonce are filled in one place;
gas-limit is filled in _two_ places** — the second is easy to miss:

- **Fees + nonce (single spot):** `buildUnsignedTx` fills `MaxFeePerGas`→20 gwei,
  `MaxPriorityFeePerGas`→1 gwei, `Nonce`→0 (`main.go:241-253`). `config.go` correctly
  leaves these `nil` when the flag is absent (`config.go:87` `maxFee` stays nil,
  `config.go:113` `nonce` stays nil).
- **Gas-limit (TWO spots — the trap):** `LoadBuildConfig` eagerly sets
  `gasLimit := defaultGasLimit` (`config.go:74`), so `Config.GasLimit` is **always
  non-zero** even when `--gas-limit` is omitted. `buildUnsignedTx` then has a redundant
  backstop at `main.go:247-249`. Consequence if only `main.go` is fixed: an RPC-mode
  build with `--gas-limit` omitted still arrives at the builder with `GasLimit=250000`,
  and `resolveRPC` **skips `EstimateGas`** because it guards on `gasLimit == 0`
  (`builder.go:139`). That is the original P0, merely relocated.

**Recommendation:**
- Change `config.go:74` to leave `GasLimit = 0` when `--gas-limit` is unset. The
  explicit-`"0"`→error check is keyed on `s != ""` (`config.go:75,80`) so it is
  preserved; an explicit `--gas-limit 0` still errors.
- In `buildUnsignedTx`, gate all default fills on **offline mode** (`cfg.RPCURL == ""`):
  fill gas→250000 / fee→20 gwei / tip→1 gwei / nonce→0 only when no RPC URL was given.
  In RPC mode, leave gas `0`, fees `nil`, nonce `nil` so `resolveRPC` fills them.
- Explicit flags still win inside `resolveRPC` (tip `builder.go:105`, maxFee
  `builder.go:114`, nonce `builder.go:125`, gas `builder.go:138-139`).
- Offline defaults are unchanged (PRD F1.4 / C3): 250000 / 20 gwei / 1 gwei / nonce 0,
  keeping golden outputs byte-identical.

## 6. Error classification must survive wiring (PRD F1.5) — **surgical, not a blunt un-wrap**

Today `buildUnsignedTx` blanket-wraps **every** builder error with `WrapInputErr("build", …)`
(`main.go:258`), tagging it `ErrInvalidInput`; `ExitCodeFor` checks `ErrInvalidInput`
(`exit.go:44`) **before** the exit-5 sentinels (`exit.go:85`). Once RPC is wired, an
estimation-time connectivity failure would wrongly resolve to exit 2.

**Do NOT simply stop wrapping** — the offline/static path *depends* on the wrap for its
exit 2: the static sentinels `ErrMissingFeeStatic` / `ErrMissingPriorityFeeStatic` /
`ErrMissingNonceStatic` / `ErrMissingGasLimitStatic` (`errors.go:14-17`) and all
`Validate` failures reach exit 2 only because they are wrapped, and
`TestExitCodeFor_BuildUnsignedErrorPath` (`exit_test.go:78-84`) codifies exactly that.
Blunt removal breaks the offline exit-2 contract.

**Surgical rule — only RPC-connectivity failures escape the wrap:**

1. **Tag the four currently-untagged `resolveRPC` call failures** — `SuggestGasTipCap`
   (`builder.go:107-110`), `BlockBaseFee` (`builder.go:116-119`), `PendingNonceAt`
   (`builder.go:131-134`), `EstimateGas` (`builder.go:156-159`) — with a sentinel that
   maps to exit 5. Cleanest is a **new `internaltx.ErrRPCEstimation`** added to the
   exit-5 group in `ExitCodeFor` (`exit.go:85-88`) alongside `ErrRPCDial`; reusing
   `ErrRPCDial` also works but is semantically "dial", not "call".
2. **In `buildUnsignedTx`:** `if errors.Is(err, internaltx.ErrRPCEstimation) { return err }`
   (unwrapped → exit 5); **else** `WrapInputErr("build", err)` as today (→ exit 2).
3. This lands `ErrChainIDMismatch` (`builder.go:97`, `errors.go:21`) and
   `ErrMissingFromForNonce` (`errors.go:20`) on **exit 2 for free**: they stay wrapped →
   `ErrInvalidInput` → caught at `exit.go:44` before the exit-5 block.

**Also add an explicit `ErrChainIDMismatch` → 2 line in `ExitCodeFor`.** PRD F1.5 calls
for it and it is currently absent from `ExitCodeFor` entirely. The wrap already yields
code 2, but an explicit sentinel (a) documents intent, (b) is robust if the wrap ever
changes, and (c) makes the three chain-ID paths coherent with F4: build-side config
error → 2, signer-side → 3 (`exit.go:72-73`), broadcast-side → 5 (`exit.go:87`).

**Two guardrails for the architect:**
- The **chain-ID _call_ failure is intentionally swallowed** (`builder.go:93-102`,
  warn-and-continue) — only a *mismatch* errors. Do **not** promote a failed `ChainID()`
  call to exit 5; leave the warn-and-continue semantics as-is.
- `build`'s new `--from` must **parse + validate the hex address**; an invalid value is a
  config error → exit 2 (parse it in `LoadBuildConfig` with `ucli.Exit(…, 2)`, matching
  the other numeric-flag validators there).

## 7. Documentation (PRD F1.6)

Update the over-promising help text and guide once behavior is real: `build`/`run`
descriptions and the `--rpc-url` usage strings (`main.go:95-96,149`; `run.go:197-200`)
and `USER-GUIDE.md:246` ("Phase 4 wiring / accepted-but-stored"). Also drop the stale
`interface.go:52-53` comment that says `RPCURL` is "reserved… unused here", and document
the new `--from` flag.
