# R3 — Test gating mechanics

## Verdict (up front)

**Use `#[ignore]` + `--include-ignored`, selected by an `e2e*` test-binary name filter — the convention the repo already established.** No cargo features, no separate test binary indirection, no env-var guard. The `Makefile` already ships `e2e-mock: cargo test --workspace --test 'e2e*' -- --include-ignored`; the live tier is the same mechanism with the new anvil tests marked `#[ignore]`. This fits the existing structure with the least new machinery and honors C-5's tier isolation.

---

## How the ~130 tests are organized today (the constraint)

`bins/ethernal/tests/` is **one file per surface**, each compiled into its own test binary that pulls in `mod common;` (`tests/common/mod.rs`). Files:

```
exit_usage.rs          key_e2e.rs             account_e2e.rs
key_secret_hygiene.rs  account_secret_hygiene.rs
gen.rs   build.rs   build_rpc.rs   sign.rs   run.rs   run_rpc.rs   send.rs
e2e_pipeline.rs        redact_boundary.rs
```

Naming is **behavioral, not tiered**: `*_e2e` = full-pipeline-through-the-binary, `*_rpc` = drives the real RPC client against the in-process `Stub`, `exit_usage` = exit-code matrix. Tests are plain `#[test]` functions; **there is currently not a single `#[ignore]` in the tree** (verified by grep). Everything is hermetic today.

The one tiering hook that already exists is in the `Makefile`:

```make
e2e-mock:
	cargo test --workspace --test 'e2e*' -- --include-ignored
```

`--test 'e2e*'` selects test binaries whose name starts with `e2e` (today: `e2e_pipeline`). `--include-ignored` is currently a **no-op** (nothing is ignored) — a forward-looking hook. This is the seam the live tier plugs into.

---

## The options, weighed

| Mechanism | Fit with existing structure | Verdict |
|---|---|---|
| **`#[ignore]` + `--include-ignored`** | The `Makefile`/CI already use this exact form (`e2e-mock`). reth gates its network tests the same way (prior art). Zero new concepts. | **Chosen.** |
| Cargo feature (`--features live`) | Would need a `[features]` block in `bins/ethernal/Cargo.toml` and `#[cfg(feature = "live")]` on every live test; features don't compose cleanly with `--workspace` test runs and add a second axis. reth uses `#[ignore]`, not features, for this. | Rejected — more machinery, no benefit. |
| Separate test binary (`tests/live/…`) | Rust flattens `tests/*.rs` into binaries anyway; a subdir needs a `[[test]]` path entry and still needs a run-selector. Doesn't remove the need to *not run it by default*. | Rejected — indirection without payoff. |
| Env-var guard (`if env::var("LIVE").is_err() { return }`) | Silent skips look like passes; no CI-visible signal that the tier ran; easy to leave permanently off. | Rejected as the *gate* (but keep a runtime **skip-with-message** for a *missing anvil binary* — that is a different concern; see R2/A-6). |

**Why `#[ignore]` wins concretely:** default `cargo test` (hermetic PR gate) skips ignored tests automatically — so the PTY ceremony tests (which are hermetic and must run every PR) stay as plain `#[test]`, while only the anvil tests get `#[ignore]`. The live CI job and `make e2e-live` run `--include-ignored`. One attribute, no config surface, and the existing `make e2e-mock` selector generalizes.

---

## Concrete gating layout

- **PTY ceremony tests (T-2..T-5, T-9..T-12):** plain `#[test]` (+ `#[cfg(unix)]`), hermetic, in `tests/` (e.g. `ceremony_key.rs` / `ceremony_account.rs`, or fold into `key_e2e.rs`/`account_e2e.rs`). Run every PR under `make test`. **Not** `#[ignore]`.
- **Live anvil tests (T-6, T-13):** `#[ignore]` + a runtime skip-with-message when `anvil` is absent (R2/A-6). Put them in a binary matched by the `e2e*` selector — e.g. `e2e_live.rs` (keeps `--test 'e2e*'` working) — or broaden the selector. Run via `--include-ignored` in the live job only.
- **Selector:** keep `--test 'e2e*'` so `e2e_pipeline.rs` (hermetic Stub pipeline) and `e2e_live.rs` (anvil) are the "end-to-end pipeline" family; `--include-ignored` pulls in the ignored live tests. If a live test lands in a non-`e2e*` file, switch the live target to `cargo test --workspace -- --ignored` (runs only ignored tests across all binaries) — cleaner if the live tests are scattered.

`make e2e-mock` stays as-is (hermetic pipeline, PR tier). Add `make e2e-live` for the ignored tier.

---

## Verdict

`#[ignore]` for the anvil tier, run with `--include-ignored` via an `e2e*`-named binary selector — the repo's own established pattern (`Makefile` `e2e-mock`) and reth's convention. Hermetic PTY tests stay plain `#[test]` and run every PR. No features, no env-var gate, no separate-binary indirection.

## Consequences for architecture

- Mark only the anvil-backed tests `#[ignore]`; leave PTY/ceremony tests as plain `#[cfg(unix)] #[test]`.
- Name the live-tier file `e2e_live.rs` (or broaden the Makefile selector to `-- --ignored`) so `make e2e-live` / the CI `live` job select it via `--include-ignored`.
- Keep `make e2e-mock` unchanged; add `make e2e-live` and wire the separate CI job (see [r2-anvil-ci.md](r2-anvil-ci.md)).
- Live tests carry a second, runtime **skip-with-message** for a missing `anvil` binary — the `#[ignore]` gate and the skip-on-missing serve different purposes (default-off vs. no-Foundry-locally); keep both.
