# Research — eth-deposit Findings-Resolution Release

Research for PRD `docs/plan/prd.md`. Each topic recommends **one** approach, grounded in
repo code (`file:line`), the go-ethereum / urfave/cli source in the module cache, an
empirical urfave/cli v3 test, and ecosystem docs. The architecture stage (task #21) builds
on these.

## Files

1. [`01-rpc-wiring.md`](01-rpc-wiring.md) — Wiring ethclient into `build`/`run` (PRD F1):
   construction point, lifecycle, `From` derivation, default-fill relocation, error split.
2. [`02-from-flag-prior-art.md`](02-from-flag-prior-art.md) — `--from` prior art (PRD F1.3):
   cast / ethdo conventions confirm the PRD's rule.
3. [`03-urfave-required-flag-exit-codes.md`](03-urfave-required-flag-exit-codes.md) —
   Required-flag exit codes (PRD F2): why build/gen exit 1, and the fix.
4. [`04-conditional-required-dry-run.md`](04-conditional-required-dry-run.md) —
   `gen --dry-run` conditional requiredness (PRD F3).
5. [`05-eip1559-fee-formula.md`](05-eip1559-fee-formula.md) — EIP-1559 formula sanity check
   (PRD F1): matches go-ethereum; wire as-is.

## Recommendations at a glance

- **F1 — construct the client in the cmd layer** (`buildUnsignedTx`), assign to
  `BuildConfig.RPC`, `defer Close`. The existing `*ethClient` from `NewEthClient` already
  satisfies `EthRPC` (`rpc_client.go:157`) — no adapter. Add a `newEthRPC` injection seam
  mirroring `send`'s `newBroadcaster`. Add `Address()` to `*LocalSigner` for `run`'s local
  `From`. **Relocate default-filling to the offline branch — and fix `config.go:74`, which
  eagerly fills gas-limit in a _second_ place** that would otherwise re-introduce the P0.
  **Error split is surgical:** tag only the RPC-connectivity call failures with a new
  exit-5 sentinel that escapes `WrapInputErr`; keep wrapping everything else (the offline
  exit-2 path depends on the wrap). Add an explicit `ErrChainIDMismatch → 2` line.

- **F2 — one shared `OnUsageError` hook** returning `ucli.Exit(err.Error(), 2)`, set on
  every subcommand via a loop in `main()`. The urfave required-flag error is unexported and
  not an `ExitCoder`, so it falls to exit 1; the hook (urfave's intended interception point)
  converts it and also uniformly fixes all other usage errors. **Empirically verified.**

- **F3 — drop `Required` on `--output-dir`; validate in the Action** gated on `!dry-run`
  (returns `ucli.Exit(…, 2)`), matching gen's existing manual-validation style. urfave
  cannot express conditional requiredness declaratively.

- **F5 (supporting note)** — the no-TTY passphrase fix needs a recognizable sentinel (e.g.
  `keystore.ErrNoTTY`) added to the exit-2 keystore group in `ExitCodeFor` (`exit.go:48-56`);
  it currently falls to exit-1 fallback. (Detailed design deferred to architecture; called
  out here because it shares the `ExitCodeFor` sentinel-mapping mechanism with F1/F2.)

- **F5 fee/gas math (F1)** — `maxFee = 2·baseFee + tip` is byte-for-byte go-ethereum's
  `bind` formula (`base.go:35,281-284`); the 20% gas margin is a conservative add-on. Wire
  `resolveRPC` as-is; no redesign.
