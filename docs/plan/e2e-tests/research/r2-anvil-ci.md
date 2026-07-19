# R2 — Anvil live tier + CI wiring

## Verdict (up front)

**Two tiers, isolated, exactly as the PRD assumes (A-2/C-5). The live tier shells out to the local `anvil`/`cast` binaries, keyed on an ephemeral port, and is `#[ignore]`-gated so it never blocks a PR.** anvil `1.7.1` is installed on this machine and all the mechanics the live tier needs — ephemeral-port binding, sub-100 ms readiness, `anvil_setBalance`/`anvil_setNonce` cheatcodes — work out of the box. In CI, install Foundry with the commit-pinned action:

```yaml
- uses: foundry-rs/foundry-toolchain@b00af27efadbc7b4ca8b82abbd903b17cc874d2a # v1.9.0
  with:
    version: v1.3.6   # pin the binary too; do NOT float on `stable`
```

Cadence recommendation (OQ-2): **not PR-blocking.** The hermetic tier gates PRs; the live tier runs nightly + on release + on manual dispatch. Local runs **skip with a clear message** when `anvil` is absent (A-6/OQ-3), never fail.

---

## Local toolchain (empirical)

```
$ which anvil cast foundryup
/Users/nil/.foundry/bin/{anvil,cast,foundryup}
$ anvil --version  →  anvil 1.7.1 (commit 4072e487, 2026-05-08)
$ cast  --version  →  cast  1.7.1
```

### Ephemeral port + readiness + cheatcodes (all verified on 1.7.1)

Driving a real anvil the way the live harness will:

```
chosen ephemeral port: 49924            # bind 127.0.0.1:0, read back the port, hand it to anvil --port
anvil --chain-id 560048 --port 49924 --silent &
readiness after 79ms, chain-id=560048  # poll cast chain-id every ~50ms until it answers
anvil_setBalance 0x1a64...14F1 0x21e19e0c9bab2400000  → balance = 10000000000000000000000 wei (10000 ETH)
anvil_setNonce   0x1a64...14F1 0x7                     → nonce   = 7
```

**Findings that shape the harness:**

- **Ephemeral port strategy (A-3, replaces the skill's fixed `8599`):** bind a `TcpListener` to `127.0.0.1:0`, read `.local_addr().port()`, drop the listener, pass that port to `anvil --port`. This is the same pattern the existing `Stub` uses (`TcpListener::bind("127.0.0.1:0")`, `tests/common/mod.rs:202`). There is a tiny bind-close-respawn race, but it is the standard approach and parallel-test-safe in practice. *Alternative (more robust, from prior art):* pass `--port 0` and read anvil's own `Listening on 127.0.0.1:<port>` stdout line to discover the actual port — this eliminates the race entirely (see [r5-prior-art.md](r5-prior-art.md), the alloy `node-bindings` pattern). Recommend the stdout-scrape variant, since the harness must read anvil stdout anyway (next point).
- **Readiness probe:** ~79 ms to first `eth_chainId` answer here. Poll `eth_chainId` (raw JSON-RPC over the port, or `cast chain-id`) on a ~50 ms interval with a few-second timeout; do **not** use a fixed sleep. If scraping the `Listening on` line for the port, that same line doubles as the readiness signal.
- **Do not let anvil's stdout buffer fill.** If the harness pipes anvil's stdout it must keep draining it, or anvil blocks once the pipe buffer fills (documented foundry gotcha). Either drain it on a thread or use `--silent` and probe via RPC. With `--silent` + RPC readiness there is no stdout to drain; with `--port 0` you need stdout, so drain it.
- **Teardown:** kill the child on drop and reap (same discipline as `Stub`'s shutdown flag + join). Use a unique `TempDir` if any anvil state file is needed; none is for these tests.
- **Cheatcodes are anvil built-ins** (Hardhat-compatible `anvil_*` namespace) — no extra setup, confirmed on 1.7.1. `anvil_setBalance` funds the phase-3 sender (T-6); `anvil_setNonce` seeds a nonzero nonce for the real-node nonce-resolution probe (T-13a).
- **chain-id 560048 (hoodi)** is accepted verbatim; it need not be a "real" network to anvil.

---

## CI: how Foundry gets installed (respecting the SHA-pin convention, `9bec2c2`)

The repo pins every action to a full commit SHA (`ci.yml`: `actions/checkout@34e1148…`, `dtolnay/rust-toolchain@4cda84d…`, `Swatinem/rust-cache@e18b497…`). The live-tier job installs Foundry the same way:

- **Action + pin (independently verified):** `foundry-rs/foundry-toolchain@b00af27efadbc7b4ca8b82abbd903b17cc874d2a` = tag **v1.9.0** (2026-07-06). Re-verified directly here, not taken on trust: `gh api repos/foundry-rs/foundry-toolchain/commits/v1.9.0 --jq .sha` → `b00af27efadbc7b4ca8b82abbd903b17cc874d2a` (the `commits/<ref>` form dereferences the tag straight to the commit SHA). Conservative fallback if a ~2-week-old release is undesirable: **v1.8.0** = `c7450ba673e133f5ee30098b3b54f444d3a2ca2d` (also re-verified the same way).
- **Pin the binary version too.** The `@<sha>` locks the *action*; its `version:` input defaults to `stable`, which **floats** — a different Foundry build each run, defeating the repo's determinism goal. Set an explicit `version: vX.Y.Z` (e.g. match the locally-used `1.7.1`, or a chosen pin like `v1.3.6`). foundryup verifies binary hashes against GitHub build attestations, reinforcing the pin.
- **What the action does:** Node-24 JS action that runs `foundryup --install <version>`, putting `forge`/`cast`/`anvil`/`chisel` on PATH. Install is prebuilt-binary download (no compile), **~10–30 s** on `ubuntu-latest`, plus its optional `~/.foundry/cache` restore.
- **Alternative (rejected): pinned `foundryup` curl-install.** `curl -L https://foundry.paradigm.xyz | bash` is **not** SHA-pinnable the way an action is — you trust whatever the endpoint serves at run time. It undercuts the very hardening the repo adopted in `9bec2c2`. Use the pinned action.

### Proposed job shape (separate job, isolated per C-5)

```yaml
  live:
    name: E2E live (anvil)
    runs-on: ubuntu-latest
    # not on every PR — see cadence below
    steps:
      - uses: actions/checkout@<pinned>
      - uses: dtolnay/rust-toolchain@<pinned> (stable)
      - uses: Swatinem/rust-cache@<pinned>
      - uses: foundry-rs/foundry-toolchain@b00af27efadbc7b4ca8b82abbd903b17cc874d2a # v1.9.0
        with: { version: v1.3.6 }
      - run: make e2e-live      # cargo test --workspace --test 'e2e*' -- --include-ignored  (or a dedicated target)
```

The existing `test` job (hermetic: `make lint` / `make test` / `make e2e-mock` / ledger compile-check) is unchanged and stays the PR gate. The PTY ceremony tests (T-2..T-5, T-9..T-12) run inside that hermetic `make test` — they need **no** external toolchain (R1), so they do **not** belong in the live job.

---

## Cadence (OQ-2) — recommendation

**Not PR-blocking.** Prior art (reth `#[ignore]`s network tests and runs them out-of-band) and the PRD's own G7/C-5 both point the same way: real-node flakiness (port races, receipt-poll timing, gas) must never block a PR.

- **Every PR:** hermetic tier only (existing `test` job + PTY tests).
- **Nightly (`schedule:`) + on release tag + `workflow_dispatch`:** the `live` job.
- **Skip-vs-fail when anvil is absent locally (A-6/OQ-3):** live-tier tests detect a missing `anvil` binary and **return early with an eprintln! notice** (a passing no-op), never a failure — a contributor without Foundry still gets a green `make test`. CI's `live` job always has it via the pinned action, so the coverage is real where it counts. (`#[ignore]` already keeps them out of the default run; the skip-on-missing is a second guard for when someone runs `--include-ignored` locally without Foundry.)

---

## Verdict

Two isolated tiers. Hermetic tier (incl. all PTY tests) gates PRs. Live tier shells out to `anvil`/`cast`, uses an ephemeral port (prefer the `--port 0` + `Listening on` stdout-scrape for zero race), an RPC readiness poll, and the `anvil_setBalance`/`anvil_setNonce` cheatcodes — all verified on local anvil 1.7.1. In CI it is a **separate, non-PR-blocking job** (nightly + release + manual) installing Foundry via `foundry-rs/foundry-toolchain@b00af27efadbc7b4ca8b82abbd903b17cc874d2a # v1.9.0` with a pinned `version:`. Missing anvil locally → skip-with-message. **OQ-2 → not PR-blocking; OQ-3 → skip-with-message locally, CI installs.**

## Consequences for architecture

- Add `tests/common/anvil.rs` (an `Anvil` guard mirroring `Stub`: spawn on ephemeral port, readiness-probe, kill+reap on `Drop`, plus thin `set_balance`/`set_nonce`/`rpc` helpers over the same dependency-free HTTP the `Stub` already speaks — or shell `cast rpc`). No Rust EVM dependency (C-1).
- Live tests are `#[ignore]` + named `e2e_*` so a `--test 'e2e*' -- --include-ignored` selector (extending the existing `make e2e-mock` convention) runs them. See [r3-test-gating.md](r3-test-gating.md).
- Add a `make e2e-live` target and a separate CI `live` job (schedule + release + dispatch), Foundry via the pinned action + pinned `version:`.
- Fund the phase-3 sender (`0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1`) with `anvil_setBalance` before the T-6 pipe chain; assert the deposit-contract balance grows 32 ETH/deposit.
- Each live test detects a missing `anvil` binary and skips-with-notice (A-6).
