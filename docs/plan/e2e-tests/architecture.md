# Architecture — End-to-End Test Suite for `ethernal`

**Inputs:** [`prd.md`](prd.md) (binding *what/why*: T-1..T-19, P0/P1/P2, C-1..C-6, coverage matrix — **as
amended by the binding scope decision of 2026-07-19 deferring the PTY tier**),
[`research/r1..r5`](research/) (settled verdicts — treated here as decisions, not options; r1's PTY verdict
is deferred by that decision), and the test tree as it exists on `develop` @ `584c404`. Style precedent:
[`../audit-gaps/architecture.md`](../audit-gaps/architecture.md) — this doc owns the *module boundaries,
harness API surface, file→requirement map, build/CI seams, and failure-mode design*, written against
verified `file:line`, not against the research prose.

> **Scope decision (binding, 2026-07-19):** *"Building a new PTY driver is not in scope for this stage.
> Assume the mnemonic is GIVEN by the user."* This architecture is revised accordingly: **`tests/common/pty.rs`
> and `tests/common/ceremony.rs` are removed** from the module layout (preserved as a [Deferred: PTY tier](#deferred-pty-tier)
> subsection pointing at r1); **`tests/common/anvil.rs`, `decrypt_v3`, the CI design (D-6/D-8/D-9), and the
> scrypt override all stand**; **T-3 lands in `account_e2e.rs`** (recover + `decrypt_v3`), not a PTY file.

**Scope shape.** This is not a greenfield system. It is an **additive extension of a mature ~130-test
integration suite** (`bins/ethernal/tests/`, one file per surface, all driving the real
`CARGO_BIN_EXE_ethernal` against a hand-rolled `Stub` + committed goldens). The job this stage is to add
one new capability the current harness structurally cannot reach — an **anvil driver** for a real-EVM
broadcast — plus a handful of hermetic golden/guard tests and the `decrypt_v3` round-trip, and to wire the
anvil tier into CI as an isolated, non-PR-blocking gate. (The PTY driver for the interactive `new` ceremony
is **deferred** — see [Deferred: PTY tier](#deferred-pty-tier).) The deliverable is a **harness + file-map +
build/CI seam design**.

## The crux: one new dependency-free harness beside `Stub`, one test-only crate feature, zero product-behavior change

Verified against the four `Cargo.toml`s, the workspace `resolver = "2"` (`Cargo.toml:2`), and the
existing `tests/common/mod.rs`: the entire change surface is confined to **test code + build config +
one feature-gated test-only helper**. No `bins/ethernal/src/**` behavior changes. No crate boundary moves.
No new third-party dependency — the anvil harness shells out to the `anvil` binary (live tier only), and
`decrypt_v3` reuses `ethernal-keystore`'s in-crate crypto.

```
tests/common/anvil.rs    NEW  Anvil guard over the anvil binary, --port 0 scrape — live tier
tests/common/mod.rs      EDIT +pub mod anvil; + fixture accessors                 — additive
crates/ethernal-keystore CONFIG+ test-support feature → pub fn decrypt_v3 (R4)    — compiled out of release
Cargo.toml (workspace)   CONFIG [profile.dev.package.scrypt] opt-level = 3        — build-only (recover-path scrypt)
Makefile / CI            CONFIG e2e-live target + separate non-blocking live job  — config-only
────────────────────────────────────────────────────────────────────────────────
tests/common/pty.rs      DEFERRED  PtySession over libc::openpty (r1)             — future PTY stage
tests/common/ceremony.rs DEFERRED  prompt tables + drive_new/drive_recover        — future PTY stage
```

Guiding constraints carried verbatim from the PRD: **zero new third-party deps** (C-1); **hermetic tier
deterministic + network-free, mnemonic *given* via the `ABANDON_12` fixture** (C-2); **reuse `common/mod.rs`
conventions** — `ethernal()` env-scrub builder, `TempDir`, `Stub`, fixture accessors (C-3); **anvil harness
`#[cfg(unix)]`** (C-4); **two isolated CI tiers** (C-5); **synthetic secrets only, anvil-only broadcast** (C-6).

---

## Decided open questions

The research verdicts (r1–r5) are settled and adopted as decisions. This table records them plus the
places where the architecture **tightens or overrides** a verdict; the overrides are called out
explicitly in the final report to the lead.

| # | Question | Decision | Rationale |
|---|---|---|---|
| ~~D-1~~ | PTY driver: hand-roll vs dev-dep? (OQ-1) | **DEFERRED (binding scope decision 2026-07-19).** The settled verdict — hand-roll `PtySession` over `libc` `openpty` — is preserved in [Deferred: PTY tier](#deferred-pty-tier); no PTY harness is built this stage. | The scope decision defers the whole ceremony tier; the mnemonic is *given* via a fixture and driven through `recover`. r1 stays valid for the future stage. |
| D-2 | Live tier gating (OQ-2) | **`#[ignore]` + a runtime skip-with-message; run via `-- --ignored`.** Not PR-blocking. Live job = nightly + release-tag + manual dispatch. | R3/R2: the repo's own `e2e-mock` precedent and reth's convention; C-5/G7 forbid real-node flakiness on the PR path. |
| D-3 | Anvil provisioning locally (OQ-3) | **Skip-with-`eprintln!`-notice when `anvil` is absent** (a passing no-op); CI installs Foundry via the pinned action. | R2/A-6: a contributor without Foundry still gets a green `make test`; the `#[ignore]` gate + skip-on-missing serve different purposes and both stay. |
| D-4 | v3 keystore validation depth (OQ-4) | **Add a test-only `decrypt_v3` behind an `ethernal-keystore` `test-support` feature** (reuses in-crate crypto, compiled out of release). T-3 = structural + `decrypt_v3`→secret→address == keystore `address` == `account recover` address. | R4: address-match alone leaves the v3 **encrypt** path unverified (`address` is written independent of the ciphertext, `encrypt_v3.rs:183`). The Q3 veto forbids only an *in-binary* reader; a feature-gated test decrypt honors it and restores parity with the v4 `Loader` round-trip. |
| D-5 | `run --rpc-url` live (T-17)? (OQ-5) | **Defer / P2.** | R5 concurs with the PRD: `run` is `build`+`sign` composed, both live-exercised by T-6; the in-process hand-off is hermetically covered by `run::local_signer_happy_path`. |
| **D-6** | **Live-tier test-binary name + Makefile selector** (override of R3's "keep `e2e-mock` unchanged") | **Name the file `e2e_live.rs`; DROP `--include-ignored` from `make e2e-mock`; add `make e2e-live` = `cargo test --workspace --test 'e2e*' -- --ignored`.** | R3 missed that once live tests are `#[ignore]` **inside an `e2e*` binary**, `e2e-mock`'s existing `--include-ignored` would pull them into the *hermetic* PR tier. Dropping it is **behavior-neutral today** (nothing is ignored yet) and correct going forward. See [Build & CI](#build-profile-and-ci). |
| **D-7** | **Anvil cheatcode transport** (tighten of R2's "or shell `cast rpc`") | **Hand-roll a ~30-line dependency-free HTTP JSON-RPC POST in `anvil.rs`; require only the `anvil` binary on PATH, not `cast`.** | Keeps cheatcodes in-process and synchronous, avoids brittle `cast` stdout parsing, and reuses the same dependency-free HTTP the `Stub` already proves works (`common/mod.rs`). Narrows the skip-check to `anvil` alone. |
| **D-8** | **Live-tier CI placement** (tighten of R2's same-file job) | **A separate workflow file `.github/workflows/e2e-live.yml`** keyed only on `schedule` + `workflow_dispatch` + release tags — not a job added to `ci.yml`. | Leaves the PR-gating `ci.yml` untouched (boundary), and isolates the live tier's triggers cleanly instead of gating an in-file job with `if:` on `github.event_name`. |
| **D-9** | **T-6 assertion wording** (honesty correction on G4) | **Assert "a valid Ethereum tx was accepted by a real EVM **and** 32 ETH moved to the deposit-contract address," NOT "the deposit contract validated the deposit."** | `SKILL.md:25` runs **bare anvil** (`--chain-id 560048`, empty genesis, no fork). The hoodi deposit contract has **no code** there, so `send` is a value transfer to a codeless address: `status 0x1` + balance-grows-32-ETH holds *regardless of deposit_data validity*. That still proves exactly the Stub's gap (real signature/nonce/gas/chain-id/RLP acceptance + on-chain state change, G4); deposit-**contract-logic** validation stays with the manual/real-network path (a fork or `anvil_setCode`+bytecode fixture is out of scope — network dep or new fixture, and does not match the skill). |

### PRD amendments (explicit)

- **Scope decision (2026-07-19)** defers the PTY tier: T-1/T-2/T-4/T-5/T-9/T-10/T-11/T-12·new leave this
  stage's scope (Non-goals). **T-3 is rescoped** to `account recover` + `decrypt_v3` (lands in
  `account_e2e.rs`); **T-12·recover** is kept (extends `key_e2e.rs`/`account_e2e.rs`). D-1 is deferred; D-4
  (`decrypt_v3`) is what makes the rescoped T-3 non-vacuous.
- **Amend T-6 / G4** per D-9: the on-chain claim is *valid-tx-accepted + value-moved*, not
  *deposit-contract-accepted*. G4's "the thing the Stub cannot prove" is unchanged and still met; only
  the wording is made precise so the suite does not over-claim.
- **Amend T-14 / A-2** per D-6: `make e2e-mock` loses its (currently no-op) `--include-ignored`; the
  live tier runs under a new `make e2e-live`. No other PRD decision changes.

---

## Component diagram

```
                         cargo test --workspace                cargo test ... -- --ignored
                     (make test / make e2e-mock)                     (make e2e-live)
                               │  HERMETIC (every PR)                     │  LIVE (nightly/release/manual)
   ┌───────────────────────────┼──────────────────────────────┐          │
   ▼            ▼               ▼                              ▼          ▼
 exit_usage  key_e2e        gen.rs (+T-7/8/19)              send.rs      e2e_live.rs
 (existing)  account_e2e    (existing +goldens)             (+T-15/16)   (T-6, T-13)  #[ignore]
   …~130…    (+T-3 recover→decrypt_v3, +T-12·recover)                     │
                               │                                          │
                               ▼                                          ▼
        ┌──────────────────────────────────  tests/common/  ──────────────────────────────┐
        │  mod.rs         ethernal()  ·  TempDir  ·  Stub  ·  fixture accessors  (existing) │
        │                 + hoodi_expected_deposit_data() / mainnet_*() accessors  (edit)   │
        │  anvil.rs       Anvil: try_spawn / url / set_balance / set_nonce / rpc / Drop     │  NEW (live, cfg(unix))
        └───────────────────────────────────────────────────┬─────────────────────────────┘
                                                             │
                                                 `anvil` binary  (--port 0, scrape "Listening on")
                                                             │
   real target/debug/ethernal (hermetic tests)     real EVM state + anvil_* cheatcodes
                     │
   crates/ethernal-keystore [feature = "test-support"] → pub fn decrypt_v3  (T-3, compiled out of release)

   DEFERRED (future PTY stage): tests/common/{pty.rs, ceremony.rs}, key_ceremony_pty.rs,
     account_ceremony_pty.rs, recover_prompt_pty.rs  →  see “Deferred: PTY tier”
```

---

## Module layout

### The given-mnemonic model (how T-3 replaces the ceremony) — verified against the code

The scope decision makes the mnemonic *given*, so the suite reaches the keystore-write crypto through the
**non-interactive `recover` path**, which the existing tests already drive. Verified end-to-end in
`key_cmd.rs` / `account_cmd.rs`:

- **`recover` needs no TTY.** `run_key_recover` / `run_account_recover` read the mnemonic via
  `RecoverMnemonicSource`, which reads **full piped stdin** when `!stdin_is_tty()` (`key_cmd.rs:772-808`);
  the keystore passphrase comes from `--passphrase-env VAR` → `EnvSource` (no prompt) when set
  (`key_cmd.rs:150-160`, `account_cmd.rs:145-155`); the 25th-word mnemonic passphrase is non-interactive in
  its `Raw`/`Env` forms (`resolve_mnemonic_passphrase`, `key_cmd.rs:403-427`). Only the bare-flag `Prompt`
  form and the `/dev/tty` mnemonic prompt need a terminal — both deferred.
- **`recover` runs the *same* write crypto as `new`.** Both `new` and `recover` end in the shared
  `finish_from_mnemonic` (derive → `encrypt`/`encrypt_v3` at `ScryptParams::STANDARD` → `write_new_0600`
  `0600`). So the keystore-write half of the ceremony **is** e2e-exercised; only the TTY dialogue is not.
- **Fixture (single source of truth).** `ABANDON_12` (`abandon…about`) already lives in `key_e2e.rs:25`
  and `account_e2e.rs:34`, with known-answer seeds (`5eb00bbd…` empty-pass EOA, `c55257c3…` TREZOR BLS),
  addresses in `testdata/eoa/cross-recovery.json`, and pubkeys in `testdata/keygen/pubkeys.json`. **Reuse
  it**; no new fixture. T-3 lands in `account_e2e.rs` beside `account_recover_keystores_match_fixture` (that
  test does structural + address checks but **never decrypts** — `decrypt_v3` supplies exactly the missing
  round-trip). T-12·recover extends `key_e2e.rs`/`account_e2e.rs`.

### `tests/common/anvil.rs` — the anvil harness (T-6, T-13)

### `tests/common/anvil.rs` — the anvil harness (T-6, T-13)

An `Anvil` guard mirroring `Stub`'s lifecycle discipline (spawn / kill+reap on `Drop`). Modeled on
alloy `node-bindings` (R5): spawn the `anvil` binary with `--port 0`, **scrape `Listening on
127.0.0.1:<port>` from stdout** to learn the actual bound port (zero bind-close-respawn race), drain
stdout on a thread (or anvil blocks once the pipe fills — foundry #3414), and RPC-poll `eth_chainId`
as the readiness backstop.

```rust
#[cfg(unix)]
pub struct Anvil { url: String, child: Child, /* stdout drain handle */ }

impl Anvil {
    /// Skip-aware spawn: returns None (after an eprintln! notice) when the `anvil`
    /// binary is absent (D-3/A-6); panics only on a genuine spawn/readiness failure
    /// when anvil IS present. Chain-id defaults to 560048 (hoodi, A-3).
    pub fn try_spawn(chain_id: u64) -> Option<Anvil>;

    pub fn url(&self) -> &str;                              // pass as --rpc-url

    /// Hand-rolled dependency-free JSON-RPC POST (D-7). Requires only `anvil`.
    pub fn rpc(&self, method: &str, params: Value) -> Value;
    pub fn set_balance(&self, addr: &str, wei: &str);      // anvil_setBalance (T-6)
    pub fn set_nonce(&self, addr: &str, n: u64);           // anvil_setNonce   (T-13a)
}

impl Drop for Anvil { /* kill + reap */ }
```

Every live test opens with the skip guard, so a missing toolchain is a green no-op, never a red:

```rust
#[test]
#[ignore = "live tier: needs the anvil binary; run via `make e2e-live`"]
fn e2e_live_full_pipe_chain_moves_32_eth() {
    let Some(anvil) = common::anvil::Anvil::try_spawn(560048) else { return }; // skip-with-notice
    // ...
}
```

**Consequences.** The live tier needs no Rust EVM dependency (C-1) and only the `anvil` binary (D-7).
Cheatcodes are in-process and synchronous. The `Drop` guarantees no anvil child outlives a panicking
test.

### New and extended test files — the file → requirement map

| File | Status | Requirements | Tier |
|---|---|---|---|
| `tests/common/anvil.rs` | **new** | T-1 (anvil harness) | live |
| `tests/common/mod.rs` | **edit** | `pub mod anvil;` + `hoodi_expected_deposit_data()`, `mainnet_*()` accessors | — |
| `tests/account_e2e.rs` | **edit** | **T-3** (recover → v3 + `decrypt_v3` round-trip + address), **T-12·recover** (symlink on the recover/stdin path) | hermetic |
| `tests/key_e2e.rs` | **edit** | **T-12·recover** (symlink on the recover/stdin path) | hermetic |
| `tests/e2e_live.rs` | **new** | **T-6** (live pipe chain, D-9 wording), **T-13** (nonce-resolution probe + wrong-network reject) | live, `#[ignore]` |
| `tests/gen.rs` | **edit** | **T-7** (hoodi golden byte-diff), **T-8** (mainnet guard + golden + pipe-no-`--passphrase-env`), **T-19** (`--parallel` determinism) | hermetic |
| `tests/send.rs` | **edit** | **T-15** (`ws://` reject exit 5), **T-16** (SIGINT during estimation exit 4) | hermetic |
| `docs/plan/e2e-tests/verify-parity.md` (or meta-test) | **new** | **T-18** (verify-skill parity checklist; PTY ceremony carve-out) | doc |
| ~~`tests/common/pty.rs`~~ · ~~`tests/common/ceremony.rs`~~ · ~~`tests/key_ceremony_pty.rs`~~ · ~~`tests/account_ceremony_pty.rs`~~ · ~~`tests/recover_prompt_pty.rs`~~ | **DEFERRED** | ~~T-1 PTY, T-2, T-4, T-5, T-9, T-10, T-11, T-12·new~~ | future PTY stage |

T-3 lands in `account_e2e.rs` (recover + `decrypt_v3`), not a PTY file. T-12·recover extends both
`*_e2e.rs` (no PTY needed). The PTY ceremony files (`*_ceremony_pty.rs`, `recover_prompt_pty.rs`) and the
`common/pty.rs`/`ceremony.rs` harness are **deferred** — see [Deferred: PTY tier](#deferred-pty-tier).

**Consequences.** The existing ~130 tests keep their files; only `common/mod.rs`, `gen.rs`, the two
`*_e2e.rs`, and `send.rs` gain **additive** items. No existing test is renamed, moved, or changed.

---

## `decrypt_v3` test-support feature (T-3, R4/D-4)

**Touch-points, exactly:**

```toml
# crates/ethernal-keystore/Cargo.toml
[features]
test-support = []          # exposes decrypt_v3, reusing crate-internal crypto
```

```rust
// crates/ethernal-keystore/src/lib.rs
#[cfg(feature = "test-support")]
mod decrypt_v3;
#[cfg(feature = "test-support")]
pub use decrypt_v3::decrypt_v3;
```

```rust
// crates/ethernal-keystore/src/decrypt_v3.rs  (NEW, ~35 lines, feature-gated)
//! Test-only v3 (Web3 Secret Storage) decrypt. NOT compiled into the release
//! binary (Q3 veto forbids an in-binary reader; resolver-2 + this cfg keep it out).
use crate::crypto::{self, Aes128Ctr};      // derive_scrypt, v3_mac, Aes128Ctr — already crate-internal
use zeroize::Zeroizing;
// parse JSON → read kdfparams/cipherparams/ciphertext/mac
// → derive_scrypt(RAW password, salt, n,r,p,dklen)
// → verify v3_mac(dk, ct) == mac  (MAC-before-decrypt; constant-time compare)
// → Aes128Ctr::apply_keystream  → return Zeroizing<[u8;32]>
pub fn decrypt_v3(json: &[u8], password: &[u8]) -> Result<Zeroizing<[u8; 32]>, KeystoreError> { /* … */ }
```

It **reuses** `crypto::{derive_scrypt, Aes128Ctr, v3_mac}` verbatim (all `pub(crate)`,
`crypto.rs:13,69,135`), so it cannot drift from `encrypt_v3`'s writer — the exact symmetry the v4
`Loader` round-trip already gives BLS. **No new dependency, no new lockfile entry.**

**Test-crate activation** — one line, in the bin's previously-empty `[dev-dependencies]`:

```toml
# bins/ethernal/Cargo.toml
[dev-dependencies]
ethernal-keystore = { workspace = true, features = ["test-support"] }
```

The bin already depends on `ethernal-keystore` in `[dependencies]`; this dev-deps line exists **only to
flip on the feature for test builds**, not to make the crate visible (integration tests already see
`[dependencies]` — `key_e2e.rs` uses `ethernal_keystore` today with an empty `[dev-dependencies]`).

**The stays-out-of-release guarantee** is a **toolchain property, not a CI check**: under
`resolver = "2"` (confirmed `Cargo.toml:2`), dev-dependency features are unified **only** for
test/bench/example builds, so `cargo build --release --bin ethernal` does not enable `test-support` and
`decrypt_v3` is `#[cfg]`-compiled out. This is a *security* property (Q3), so it is stated as an
invariant. A `cargo tree -e normal --package ethernal` inspection is a best-effort backstop for the
live/release CI job, but its exact form is an implementation detail — a symbol grep would be vacuous
(nothing in `src/` calls `decrypt_v3`, so dead-code elimination drops it regardless), and `cargo tree`
does not cleanly model the release-vs-test feature split. The guarantee is the cfg gate + resolver 2;
the backstop only documents it.

T-3 validation becomes: **structural** (v3 shape, `aes-128-ctr`, scrypt kdf, keccak `mac`, top-level
`address`, geth `UTC--…` filename, `0600`) + **`decrypt_v3(json, pass)` → secret → derive address →
assert == keystore `address` == the `ABANDON_12` fixture address** (from `testdata/eoa/cross-recovery.json`).
The keystore is produced by `account recover` on the fixture mnemonic (piped stdin + `--passphrase-env`);
the `decrypt_v3` round-trip is the piece the existing `account_recover_keystores_match_fixture` lacks
(it checks structure + `address` but never decrypts the ciphertext). This proves derivation *and* v3
encrypt self-consistency through the binary — independent of how the keystore was produced, so it holds
for the deferred ceremony write path too.

---

## Build, profile, and CI

### Scrypt debug-speed override — kept, now justified by the *recover* path (measured on develop @ `584c404`)

The scope decision removed the ceremony tests, but the override is **still required** — the *recover*-path
e2e tests run the identical production scrypt. `cargo test` drives the **debug** binary; `key recover` /
`account recover` encrypt each keystore at `ScryptParams::STANDARD` (`n=262144`) with **no cheap-param
hook** (S-4 forbids injection; `account_recover_help_has_no_entropy_or_time_flag` asserts its absence).
**Measured** (`account_e2e::account_recover_keystores_match_fixture`, COUNT=2 keystores):

| Profile | Test wall-time | Per keystore |
|---|---|---|
| debug default (no override) | **~39 s** | ~19–20 s |
| `[profile.dev.package.scrypt] opt-level = 3` | **~1.2 s** | ~0.6 s |

That is ~19 s/keystore unoptimized — far above the 5 s/keystore threshold — and the existing suite already
pays it (this is why `make test` is "scrypt-heavy" today). The fix, in the workspace root:

```toml
# Cargo.toml (workspace root)
[profile.dev.package.scrypt]
opt-level = 3
```

**Blast radius:** only the `scrypt` crate is compiled optimized under the dev-derived profile that
`cargo test` uses; every workspace crate and every other dependency stays at `opt-level = 0`, so
incremental workspace builds are unaffected. **Robust fallback** if a future scrypt moves its hot loop into
its `salsa20` dependency: `[profile.dev.package."*"] opt-level = 2` (optimize all deps, leave workspace
crates unoptimized). This override also speeds T-3 (recover), T-7/T-19 (hoodi keystore decrypt), and the
existing recover suite — land it early (its own issue, E1-1) so no scrypt-touching test runs unoptimized.

### Makefile (D-6)

```make
## e2e-mock: hermetic e2e pipeline (Stub, no network) — PR tier
e2e-mock:
	cargo test --workspace --test 'e2e*'          # was: ... -- --include-ignored  (dropped, see D-6)

## e2e-live: live anvil tier (#[ignore]d) — nightly/release/manual, NOT PR-blocking
e2e-live:
	cargo test --workspace --test 'e2e*' -- --ignored
```

Dropping `--include-ignored` from `e2e-mock` is **behavior-neutral today** (nothing is `#[ignore]`d in
the tree — R3 verified) and is what keeps the live tier out of the hermetic gate once `e2e_live.rs`
lands. `-- --ignored` on `e2e-live` runs **only** the ignored live tests in the `e2e*` binaries. This
stage's new hermetic tests (T-3 in `account_e2e.rs`, T-7/T-8/T-19 in `gen.rs`, T-12·recover in the
`*_e2e.rs`) are *not* `e2e*`-named and *not* ignored, so they run in plain `make test` on every PR — no
Makefile change needed for them.

### CI (T-14, C-5, D-8)

`ci.yml` is **unchanged** — the existing `test` job (`make lint` → `make test` → `make e2e-mock` →
ledger compile-check) remains the PR gate and now transparently runs this stage's new hermetic tests
(T-3, T-7/T-8/T-19, T-12·recover) inside `make test` (they need no external toolchain). A **new, separate
workflow** isolates the live tier:

```yaml
# .github/workflows/e2e-live.yml  (NEW — separate file so ci.yml's PR gate is untouched)
name: e2e-live
on:
  schedule:    [{ cron: "0 7 * * *" }]      # nightly
  workflow_dispatch:                         # manual
  push:        { tags: ["v*.*.*"] }          # release tags
jobs:
  live:
    name: E2E live (anvil)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5      # v4.3.1 (match ci.yml pin)
      - uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4 # stable (match ci.yml pin)
      - uses: Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32     # v2 (match ci.yml pin)
      - uses: foundry-rs/foundry-toolchain@b00af27efadbc7b4ca8b82abbd903b17cc874d2a  # v1.9.0 (R2, re-verified)
        with: { version: v1.3.6 }            # pin the binary too — do NOT float on `stable` (R2)
      - run: make e2e-live
```

**Trigger choice (concrete, single set):** `schedule` (nightly 07:00 UTC) + `workflow_dispatch`
(manual) + `push` on `v*.*.*` tags (release). This satisfies OQ-2's "not PR-blocking" while still
gating releases and giving on-demand runs. All actions are commit-SHA-pinned to match the `9bec2c2`
hardening; the Foundry action **and** its `version:` are both pinned (R2's second-pin finding — the
action's `version:` input floats on `stable` otherwise).

**No retry / no `continue-on-error`:** the live job is not PR-blocking, so a nightly failure is a real
signal to fix, not noise to mask. Per-poll timing tolerance lives inside the tests' own generous poll
loops (readiness, receipt), not in job-level retries that would hide genuine flakes.

---

## Interfaces & data ownership

**Fixture reuse (no new committed fixtures — A-5).**

| Fixture | Consumed by | Accessor |
|---|---|---|
| `ABANDON_12` mnemonic + `testdata/eoa/cross-recovery.json` (addresses) | **T-3** | existing `ABANDON_12` const + `load_fixture()` in `account_e2e.rs` |
| `testdata/hoodi/{keystores,passphrase.txt,pubkeys.txt}` | T-6, T-7, T-19 | existing `hoodi_keystores()`, `hoodi_passphrase()`, `hoodi_pubkey()` |
| `testdata/hoodi/deposit_data-expected.json` | T-7, T-19 | **new** `hoodi_expected_deposit_data()` |
| `testdata/mainnet/{keystores,passphrase.txt,pubkeys.txt,deposit_data-expected.json}` | T-8 | **new** `mainnet_*()` accessors |
| `testdata/phase3/holesky/*` + `PHASE3_KEY`, sender `0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1` | T-6, T-13 | existing consts + `phase3_*()` |

T-3's keystores come from `account recover` on the **committed `ABANDON_12` fixture** (empty
mnemonic-passphrase → empty-pass EOA seed `5eb00bbd…`), whose per-index addresses are already frozen in
`cross-recovery.json` — the source of truth for the `decrypt_v3` → derived-address assertion. No new
fixture. The live pipe chain's "32 ETH moved" assertion reads the deposit-contract address from the
**built tx's `to` field**, so no address needs committing.

**Assertion helpers.** T-3 keystore assertions reuse the existing patterns from `account_e2e.rs`
(structural JSON field checks, `v3_files()` sort + `parse_v3_filename` helpers) and add the v3
`decrypt_v3` round-trip — the one thing `account_recover_keystores_match_fixture` does not do (it checks
structure + `address` but never decrypts the ciphertext).

---

## Failure-mode design

| Failure mode | Design response |
|---|---|
| **Anvil port race** | Eliminated by `--port 0` + scraping anvil's own `Listening on 127.0.0.1:<port>` line (R5/R2) — the port comes from anvil, not from a bind-close-respawn guess. That same line doubles as an early readiness signal; `eth_chainId` polling is the backstop. |
| **Anvil stdout buffer fills** | A background drain thread reads anvil stdout to EOF (foundry #3414); without it anvil blocks. Required because `--port 0` mode needs stdout (so no `--silent` there). |
| **Missing `anvil` locally** | `Anvil::try_spawn` returns `None` after an `eprintln!` notice → the test is a green no-op (D-3). Distinct from the `#[ignore]` gate: `#[ignore]` = default-off; skip-on-missing = no-Foundry-locally under `--ignored`. Both stay. |
| **Child leak on panic** | `Drop` on `Anvil` kills + reaps; a panicking live test never leaks an anvil node. |
| **Recover-test scrypt cost** | Production `n=262144` scrypt makes each recover-encrypt keystore ~19 s in debug; the `[profile.dev.package.scrypt] opt-level = 3` override (measured ~39 s → ~1.2 s for COUNT=2) keeps the hermetic tier fast. Land it first (E1-1). |
| **CI flake stance** | No job retries, no `continue-on-error`. Live tier is non-PR-blocking, so nightly failures surface honestly. |

---

## Boundaries — what does NOT change

- **The existing ~130 tests are untouched.** `common/mod.rs` gains new `pub mod` lines and two fixture
  accessors (additive); `gen.rs`, `key_e2e.rs`, `account_e2e.rs`, `send.rs` gain **new** `#[test]`
  items. No existing test is renamed, relocated, or altered.
- **No `bins/ethernal/src/**` behavior change.** The suite tests the binary as it ships; the recover path
  is driven exactly as the existing `key_e2e`/`account_e2e` tests drive it.
- **The only production-tree change is a *test-only, feature-gated* addition:** the `ethernal-keystore`
  `test-support` feature + `decrypt_v3` module, compiled out of the release binary (resolver 2 + cfg).
  No product code path consumes it (Q3 honored).
- **Build config only, no behavior:** the `[profile.dev.package.scrypt]` override changes debug build
  optimization, not any runtime behavior or any release artifact.
- **`ci.yml` (the PR gate) is unchanged;** the live tier is a new, separate workflow file.
- **No new third-party dependency** anywhere (C-1): anvil shells to the `anvil` binary, `decrypt_v3`
  reuses in-crate crypto.
- **Out of scope (Non-goals):** the interactive `new`-ceremony PTY tier (deferred 2026-07-19), ledger
  hardware signing, real mainnet/testnet broadcast, cross-tool keystore import parity, performance/fuzz,
  new commands/flags, Windows/non-Unix support.

---

## Deferred decisions (true coin-flips)

- **DD-1 — MOOT this stage.** ~~T-5 file placement (ceremony files vs `*_secret_hygiene.rs`).~~ T-5 is
  deferred with the PTY tier; recover-path hygiene stays in the existing `*_secret_hygiene.rs`.
- **DD-2 — T-16 (SIGINT) home.** Extend `send.rs` (chosen) vs a small dedicated `signals.rs`. P2, low
  stakes; the SIGINT-to-child mechanic is the same either way.
- **DD-3 — T-18 form.** A checklist doc (`verify-parity.md`) vs a lightweight meta-test that greps
  `SKILL.md` steps against test names. Recommend the doc for v1 (a meta-test risks its own drift); the
  planner may prefer the meta-test for enforcement.
- **DD-4 — nightly cron time.** `0 7 * * *` is a placeholder; any low-traffic UTC hour is fine.
- **DD-5 — pinned Foundry `version:`.** `v1.3.6` (R2's example) vs matching the locally-verified
  `1.7.1`. A determinism pin, not a correctness one; pick one at planning and record it.

---

## Risks

- **R-1 — scrypt override not landed first.** Without `[profile.dev.package.scrypt] opt-level = 3`, the
  *recover*-path e2e tests (T-3 and the existing `key_e2e`/`account_e2e` suite) run ~19 s/keystore in
  debug (~39 s for COUNT=2, measured). *Mitigation:* land it in E1-1, first, ahead of anything scrypt-
  touching; make it a review checklist item.
- **R-2 — resolver flipped to "1".** If someone ever sets `resolver = "1"`, dev-dep feature unification
  would leak `test-support` into the release binary — a Q3 violation. *Mitigation:* the invariant is
  documented here and in the `decrypt_v3` module header; a `cargo tree` backstop in the live job
  documents (not guarantees) it. Low likelihood (resolver 2 is the workspace default and confirmed).
- **R-4 — anvil `Listening on` format drift.** A future anvil could reword its readiness line.
  *Mitigation:* the pinned `version:` freezes the `Listening on` format, with `eth_chainId` polling as a
  format-independent readiness backstop.
- **R-5 — T-6 over-claiming.** Guarded by D-9: the assertion is scoped to valid-tx-accepted + value-
  moved on bare anvil; deposit-contract-logic validation is explicitly left to the manual/real-network
  path so G4 stays honest.
- **R-6 — anvil cheatcode / version drift.** A Foundry release could change `anvil_setBalance`/
  `anvil_setNonce` semantics. *Mitigation:* the pinned `version:` in CI; local skip-on-missing means a
  drifted local anvil fails loudly in the live tier only, never on a PR.

---

## Deferred: PTY tier

**Deferred by the binding scope decision of 2026-07-19** — *"Building a new PTY driver is not in scope for
this stage. Assume the mnemonic is GIVEN by the user."* This section preserves the design so a future stage
can pick it up without re-deriving it; **nothing here is built this stage.** Full verdict:
[`research/r1-pty-driver.md`](research/r1-pty-driver.md) (hand-roll over `libc`, R1 spiked the whole real
`key new` ceremony to an on-disk v4 keystore in ~140 SLOC, 0 new deps).

**What it would add back:** `tests/common/pty.rs` (`PtySession` over `libc::openpty` + `Command::pre_exec`
setsid/TIOCSCTTY, `poll`-based expect loop, `Drop` kill+reap; `#[cfg(unix)]`, no `[dev-dependencies]`
entry — `libc` is already a bin dependency), `tests/common/ceremony.rs` (prompt-string constants + a
`drive_new_ceremony`/`drive_recover_prompt` capture-and-replay loop, keyed on the R1 transcript), and the
test files `key_ceremony_pty.rs`, `account_ceremony_pty.rs`, `recover_prompt_pty.rs`. Condensed API:

```rust
#[cfg(unix)]
impl PtySession {
    pub fn spawn(cmd: Command) -> io::Result<PtySession>;               // stdin+stdout+stderr on the slave
    pub fn spawn_split_stderr(cmd: Command) -> io::Result<PtySession>;  // stderr on a plain pipe (T-5 hygiene)
    pub fn expect(&mut self, needle: &str, timeout: Duration) -> String; // panics on timeout WITH transcript
    pub fn expect_err(&mut self, needle: &str, timeout: Duration) -> String;
    pub fn send_line(&mut self, line: &str);
    pub fn wait(&mut self) -> ExitStatus;
    pub fn transcript(&self) -> &str;        // T-11 scrollback scan
    pub fn stderr_capture(&self) -> &str;    // T-5 absence check
}
```

**Requirements it would discharge:** T-1 (PTY harness), T-2 (`key new` ceremony), T-4 (mismatch abort),
T-5 (new-path hygiene, split-stderr), T-9 (`/dev/tty` recover prompt), T-10 (mnemonic-passphrase over the
ceremony), T-11 (scrollback clear), T-12·new (symlink on the ceremony). Meanwhile each is guarded this stage by an
in-crate unit test in `key_cmd`/`account_cmd` (see the PRD coverage matrix) — **not** by the manual verify
skill, which is `gen → build → sign → send` and never runs the ceremony (the ceremony is a documented T-18
carve-out). **Not deferred, and kept this stage by rescoping to the non-interactive path:** T-3 (v3 via
`account recover` + `decrypt_v3`) and T-12·recover (symlink warning on `recover`).

The scrypt override (E1-1) is **not** part of this deferral — it is required by the *recover*-path tests
that ship this stage and stays.
