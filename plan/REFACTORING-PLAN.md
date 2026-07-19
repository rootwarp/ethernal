# ethernal — Refactoring Plan

## Executive summary

`ethernal` is a Rust workspace: four dependency-minimal library crates
(`ethernal-core`, `ethernal-keystore`, `ethernal-signer`, `ethernal-tx`) under a
single binary (`bins/ethernal`) that exposes the CLI namespaces
`validator` / `account` / `deposit` / `tx`.

**Library crates are healthy.** Boundaries are deliberate — especially
`ethernal-keystore` (zero internal deps) and the BLS/EIP-2335 vs secp256k1/v3
domain split. **Almost all refactoring value is in the binary crate**, which has
no `lib.rs`, no shared `test_support`, and grows helpers by copy-paste.

| Layer | LOC (approx) | Health |
|-------|-------------:|--------|
| `ethernal-core` | ~2.9k prod | Good — single responsibility modules |
| `ethernal-keystore` | ~2.5k prod | Good — dep-free crypto boundary |
| `ethernal-signer` | ~2.5k prod | Good — trait seam (`Signer`) |
| `ethernal-tx` | ~2.3k prod | Good — build / RPC / redact |
| `bins/ethernal` | ~11.8k total (~4.5k prod / ~7.3k tests) | Fair — duplication + convention drift |

**Headline opportunity:** one-time investment in shared bin-internal homes
(`test_support`, TTY helpers, `fs_util` / `keystore_cli` hoists) eliminates a
large amount of copy-paste with almost no behavioral risk. Finish the
`key → validator` rename and normalize conventions. Deeper
`validator`/`account` merges are **tradeoffs**, not clear wins — divergence is
load-bearing security separation.

This document is both an **architecture assessment** (SOLID, simplicity,
conventions) and an **executable process** (phases, gates, backlog).

---

## 1. Current architecture

```text
                    bins/ethernal  (CLI only — no lib.rs)
                   ┌────────────────────────────────────┐
                   │ main → *_cli (clap) → *_cmd (run)  │
                   │ errors · logging · fs_util · config│
                   └───────────────┬────────────────────┘
                                   │
          ┌────────────┬───────────┼───────────┬────────────┐
          ▼            ▼           ▼           ▼            │
   ethernal-core  keystore    signer        tx              │
   bip39/bls/hd   EIP-2335    Local/Ledger  builder/RPC     │
   deposit/ssz    Web3 v3     SignedTx      UnsignedTx ◄────┘
   network/out    (no ethernal deps)
```

**Crate edges (acyclic, intentional):**

| Crate | Depends on | Does not depend on |
|-------|------------|--------------------|
| `core` | (leaf) | all others |
| `keystore` | (leaf: crypto only) | all `ethernal-*` |
| `tx` | `core` | keystore, signer |
| `signer` | `tx` (`UnsignedTx`) | core, keystore |
| `bin` | all four | — |

**Bin module pattern (mostly consistent):**

| Concern | Modules | Role |
|---------|---------|------|
| CLI parse | `*_cli.rs`, `*_cmd::command` | clap surface, config load, banners |
| Pipeline | `*_cmd.rs` | injectable `*Deps`, production + test seams |
| Shared CLI | `keystore_cli`, `fs_util`, `config`, `errors`, `logging` | cross-namespace helpers |

**What is already good (do not “fix”):**

- Library SRP and dep-minimality.
- Injectable `GenDeps` / `ValidatorDeps` / `AccountDeps` (testability without mocks framework).
- Security domain separation (BLS vs secp; EIP-2335 NFKD vs v3 RAW passphrase).
- Exit-code contract documented and tested.
- Verify-before-write, secret zeroization, RPC URL redaction, EIP-55 no-echo.

---

## 2. SOLID assessment

### S — Single Responsibility

| Area | Status | Notes |
|------|--------|-------|
| Library crates | **Strong** | One concern per module (`deposit`, `ssz`, `encrypt` vs `encrypt_v3`). |
| Bin `*_cli` vs `*_cmd` | **Mostly good** | Parse vs run is split for validator/account/gen; **tx path mixes** clap + run in `build_cmd` / `sign_cmd` / `send_cmd` / `run_cmd` (acceptable size today). |
| Bin mega-files | **Weak** | `validator_cmd` 2150 / `account_cmd` 1938 / `gen_cmd` 1748 LOC — 60–73% is inline tests. Production logic is ~500 LOC; file size is a packaging problem. |
| Misplaced responsibility | **Weak** | Neutral keygen primitives live in `validator_cmd` but are imported by `account_cmd` (sideways dependency). `atomic_write_file` lives in `run_cmd` but is used by `send_cmd`. |

### O — Open/Closed

| Area | Status | Notes |
|------|--------|-------|
| `Signer` trait / `EthRpc` / `PassphraseSource` / `Entropy` | **Strong** | New implementations without rewriting pipelines. |
| `*Deps` injection | **Strong** | Pipelines open to test doubles; closed to production wiring changes. |
| Full keygen merge trait | **N/A by design** | Closing validator+account behind one driver is optional (T3.2) and must not collapse crypto tails. |

### L — Liskov Substitution

| Area | Status | Notes |
|------|--------|-------|
| Trait objects in deps | **Strong** | Fakes substitute for OS entropy, passphrase, mnemonic source, RPC. |
| `write_new_0600` vs overwrite writer | **Deliberate non-substitutable** | Refuse-overwrite (keystore) vs overwrite-allowed (tx artifacts) must stay separate entry points — not one “writer” with a flag that callers can get wrong. |

### I — Interface Segregation

| Area | Status | Notes |
|------|--------|-------|
| Small traits | **Strong** | `MnemonicSource`, `PassphraseSource`, `Entropy`, `KeyLoader`, `Signer`. |
| Fat deps structs | **Acceptable** | `GenDeps` / `ValidatorDeps` / `AccountDeps` bundle seams for one pipeline; do not flatten into a mega-struct (T3.3). |

### D — Dependency Inversion

| Area | Status | Notes |
|------|--------|-------|
| Production pipelines | **Strong** | Depend on traits; OS/TTY/env wired at the edge. |
| Bin module graph | **Strong** | Neutrals live in `keygen`; `account_cmd` and `validator_cmd` both depend on `keygen` only (T2.3). |

### SOLID → backlog mapping

| Principle gap | Backlog items |
|---------------|---------------|
| S — shared homes / file packaging | T1.1–T1.5, T2.1–T2.2, T2.7 |
| D — sideways dependency | T2.3, T2.4–T2.6 |
| O/I — keep seams, don’t merge domains | T3.1–T3.3 (reject naive merge) |
| Conventions / naming (supports all) | T1.6–T1.8, T2.9 |

---

## 3. Simplification diagnosis

### 3.1 Real duplication (simplify)

| Pattern | Copies | Action |
|---------|-------:|--------|
| `struct Tmp` temp-dir helper | 8–9 | Shared `test_support` (T1.1) |
| `ENV_LOCK` for env-mutating tests | 2 | One process-wide lock (T1.1) — also a **correctness** fix |
| Keygen test doubles (`FixedEntropy`, …) | 2 modules | `test_support` (T1.1) |
| `stderr_is_tty` / `open_tty_writer` | 2–3 | One `pub(crate)` home (T1.2) |
| `validate_output_dir` | 2 | Keep in `fs_util` only (T1.3) |
| `map_encrypt_err` ≡ `map_passphrase_err` | per file | Collapse within file (T1.4); shared mappers later (T2.6) |
| `discard_logger` wrappers | 3 | Call `Logger::discard()` (T1.5) |
| `ValidatorConfig` / `AccountConfig` + load/banner | twin | `KeygenConfig` + namespace label (T2.4–T2.5) |
| write-once-retry keystore write | 2 | ✅ `write_with_retry` skeleton (T2.2) |
| Redundant `.map_err(map_bip39_err)?` | many | Bare `?` where `From` exists (T2.9 A) |

### 3.2 Apparent duplication (do **not** “simplify”)

| Pattern | Why keep separate |
|---------|-------------------|
| `validator_*` vs `account_*` pipelines | RAW vs NFKD passphrase; BLS vs secp; EIP-2335 vs v3; filename policy |
| `write_new_0600` vs `atomic_write_file` | Refuse-overwrite vs overwrite-allowed |
| `civil_from_days` in keystore + logging | keystore must stay free of `ethernal-core` |
| Dual `keccak256` helpers | Intentional stack separation |
| `GenDeps` vs keygen deps | Different domain (deposit vs key ceremony) |

**Rule of thumb:** if two paths differ in **crypto, secret handling, or exit-code meaning**, keep them separate and share only the scaffolding around them.

### 3.3 Complexity hotspots (file size)

| File | Total | Prod | Tests | Issue |
|------|------:|-----:|------:|-------|
| `validator_cmd.rs` | 2150 | ~850 | ~60% | Inline tests + unfinished rename |
| `account_cmd.rs` | 1938 | ~517 | ~73% | Sideways imports from validator |
| `gen_cmd.rs` | 1748 | ~509 | ~71% | Large but cohesive pipeline |
| `gen_cli.rs` | 1147 | ~412 | ~64% | Same packaging issue |

Relocating `#[cfg(test)]` to sibling `*_tests.rs` (T2.7) is pure packaging — no behavior change, much easier review.

---

## 4. Code conventions baseline

### 4.1 Already established (preserve)

| Convention | Where |
|------------|--------|
| Workspace edition 2021, shared deps in root `Cargo.toml` | root |
| Exit codes 0–5 documented and tested | `errors.rs`, `main.rs` |
| Module-level `//!` docs with security notes | most modules |
| `Zeroizing` for secrets; no secrets in `Debug`/logs | keygen, keystore, signer |
| Injectable `*Deps` + `*_with_deps` for unit tests | gen/validator/account |
| Golden / fixture tests for crypto and JSON | crates + `testdata/` |
| `make lint` = clippy `-D warnings` + rustfmt check | `Makefile` |
| Feature `ledger` gated | signer + bin |

### 4.2 Gaps to close

| Gap | Evidence | Fix |
|-----|----------|-----|
| Incomplete `key → validator` rename | `run_validator_new`, `ValidatorDeps` still | T1.6 |
| Name collision | CLI `resolve_mnemonic_passphrase` (parse) vs cmd (resolve secrets) | T1.7 → `parse_mnemonic_passphrase_form` |
| `pub` vs `pub(crate)` in bin | 61 `pub fn` vs 15 `pub(crate) fn`; bin has no external API | Prefer `pub(crate)` for bin surface (T1.8f) |
| Dead field | `Params::default_rpc_url` always `""` | T1.8a |
| Version string leak | `Box::leak` in `root_command` | `LazyLock` (T1.8c) |
| Error mapper noise | Identical wrappers + hand-rolled `Display` | T1.4, T2.9 |
| Cross-namespace import | ~~`account_cmd` → `validator_cmd`~~ → both → `keygen` | ✅ T2.3 |
| Test scaffolding drift | 8× `Tmp`, 2× `ENV_LOCK` | T1.1 |

### 4.3 Target conventions (after refactor)

1. **Visibility:** bin items are `pub(crate)` unless integration tests need them via a future `lib.rs` (not planned). Library crates keep intentional `pub` API.
2. **Naming:** CLI namespace names match runtime (`run_validator_*`, `ValidatorDeps`). Parser functions use `parse_*`; secret materializers use `resolve_*` / `read_*`.
3. **Shared homes:** neutral keygen → `keygen` module (T2.3); CLI forms/flags → `keystore_cli`; fs probes → `fs_util`; atomic overwrite writes → `core::output`; test-only → `test_support`.
4. **Error mapping:** use `?` + `From` when the variant maps 1:1; keep explicit mappers only when exit code **differs** from `From` (e.g. keystore write → exit 3).
5. **Tests:** shared fixtures in `test_support`; large white-box suites in sibling `*_tests.rs`; domain listers (`keystore-*.json` vs `UTC--*`) stay distinct.
6. **No secret-path DRY:** never share code that touches passphrase normalization or encrypt entry points across BLS/v3 without an explicit security review.

---

## 5. Security / correctness invariants (non-negotiable)

Every change is checked against these. **None of the Tier 1/2 items below break them as scoped.**

1. **Secret zeroization** — mnemonic, passphrase, raw keys in `Zeroizing` / explicit zeroize on drop.
2. **Redacting `Debug`** — configs never print secrets.
3. **RPC-URL redaction** — credentials stripped before log/error surfaces.
4. **Verify-before-write** — BLS signatures re-verified; deposit JSON schema parity.
5. **EIP-55 no-echo** — checksum errors must not return a paste-ready wrong address.
6. **Passphrase divergence** — Web3 v3 uses **RAW** bytes; EIP-2335 uses **NFKD** inside keystore encrypt. Never unify.
7. **SIGINT async-safety** — handler only atomic cancel; token initialized before install.
8. **Domain separation** — BLS/EIP-2335 vs secp256k1/v3 stacks, help text, filenames stay apart.
9. **Exit-code contract** — especially keystore write → 3 vs gen `Output` → 1 (“architecture fork a”).

---

## 6. Refactoring process

### 6.1 Principles

1. **Behavior-preserving first.** Land mechanical dedup before any design merge.
2. **One concern per PR.** Do not mix rename + extraction + crypto moves.
3. **Gate every PR:** `make lint && make test`. For keygen crypto paths, prefer unit suites with `ScryptParams::FAST` plus existing e2e where relevant.
4. **Security-sensitive tails last / optional.** Optional keygen driver (T3.2) only after scaffolding is stable; full namespace merge (T3.1) is **rejected** unless requirements change.
5. **Record decisions.** Rejected merges stay written down so “obvious DRY” is not re-litigated.

### 6.2 Phases

```text
Phase 0  Baseline          inventory + freeze conventions (this doc)
Phase 1  Mechanical DRY    Tier 1 — batch-friendly, low risk
Phase 2  Shared homes      Tier 2 dependency-order extractions
Phase 3  Packaging         test relocation, wordlist cache, error cleanup
Phase 4  Judgment          Tier 3 only if still wanted after 1–3
```

#### Phase 0 — Baseline (done when this doc is accepted)

- [x] Architecture + SOLID assessment
- [x] Invariants listed
- [x] Backlog tiered
- [ ] Maintainer signs off on **T3.1 rejected** (or reopens with new requirements)
- [ ] Optional: add `CONTRIBUTING` / `docs` note pointing at target conventions §4.3

#### Phase 1 — Mechanical (1–2 PRs)

**Order inside phase:**

1. **T1.1** shared `test_support` (unblocks clean later work) — **done**
2. **T1.2** TTY helpers — **done**
3. **T1.3–T1.8** remaining cleanups — **done**

| ID | Change | Effort | Risk |
|----|--------|:------:|:----:|
| T1.1 | ✅ `#[cfg(test)] mod test_support` — `Tmp`, `ENV_LOCK`, keygen fakes | M | low |
| T1.2 | ✅ Shared `stderr_is_tty` / `stdin_is_tty` / `open_tty_writer` | S | low |
| T1.3 | ✅ Single `validate_output_dir` in `fs_util` | S | low |
| T1.4 | ✅ Collapse identical `map_*` pairs per file | S | low |
| T1.5 | ✅ Drop `discard_logger` wrappers | S | low |
| T1.6 | ✅ `run_key_*` → `run_validator_*`, `KeyDeps` → `ValidatorDeps` | S | low |
| T1.7 | ✅ Parser rename `parse_mnemonic_passphrase_form` | S | low |
| T1.8 | ✅ Dead field, overflow msg const, version `LazyLock`, hoist `public_key`, `pub(crate)`, … | S | low |

**Exit criteria:** no duplicate `Tmp` / TTY helpers / `validate_output_dir`; rename complete; `make lint` + `make test` green. — **Phase 1 met**

#### Phase 2 — Structural shared homes (one PR per item recommended)

**Dependency order:**

```text
T2.3 (fix account→validator import)
  └─► T2.4 / T2.5 / T2.6 (config, banner, mappers on shared home)

T2.1 (atomic write → core::output)  ── independent
T2.2 (write_with_retry)             ── independent (or after T2.1)
```

| ID | Change | Effort | Risk |
|----|--------|:------:|:----:|
| T2.1 | `atomic_write_file` → `core::output` overwrite-allowed API ✅ | M | low |
| T2.2 | ✅ Extract `write_with_retry` for keystore write skeleton | M | low |
| T2.3 | ✅ Hoist ceremony/mnemonic neutrals to `keygen` module | M | low |
| T2.4 | `KeygenConfig` + aliases for validator/account | M | low |
| T2.5 | Shared keygen banner writer (folds into T2.4 if same PR) | S | low |
| T2.6 | Shared `map_*_err` where safe; keep domain mappers local | S | low |

**Exit criteria:** `account_cmd` does not import `validator_cmd`; neutral keygen lives in shared module; fs write primitives sit next to their semantic cousins.

#### Phase 3 — Packaging & local cleanup

| ID | Change | Effort | Risk |
|----|--------|:------:|:----:|
| T2.7 | Move large `#[cfg(test)]` blocks to `*_tests.rs` | M | low |
| T2.8 | Cache BIP-39 wordlist (`LazyLock`) | S | low |
| T2.9 A | Delete redundant map wrappers; use `?` | M | low |
| T2.9 B | `thiserror` on `AppError` | M | **medium** — defer |
| T2.10 | `bls::init` no-op plumbing | S | medium — prefer leave |

**Exit criteria:** largest bin files are majority production code; error path noise reduced without changing exit codes.

#### Phase 4 — Judgment (optional; explicit decisions)

| ID | Decision | Recommendation |
|----|----------|----------------|
| T3.1 | Full validator/account namespace merge | **Reject** (invariants 6, 8) |
| T3.2 | Shared keygen driver trait | Optional; medium risk; only after Phase 2 |
| T3.3 | Merge Deps structs | **Keep separate** |
| T3.4 | Unify `civil_from_days` | **Leave** (keystore dep isolation) |
| T3.5 | Unify `keccak256` | **Leave** |

### 6.3 PR checklist (every change)

```text
[ ] Touches only one tier item (or a documented batch of Tier 1)
[ ] Invariants 1–9 reviewed for this diff
[ ] No new account↔validator crypto path sharing
[ ] make lint
[ ] make test
[ ] If keygen encrypt path: unit tests with FAST scrypt still pass
[ ] If exit codes touched: errors.rs exit_code tests still pin contract
[ ] Commit message states what moved and why (not just “cleanup”)
```

### 6.4 Rollback / risk control

- Prefer pure moves + re-exports over simultaneous logic edits.
- For renames: single compiler-driven PR; no partial rename left on `develop`.
- For extractions: land move with identical function bodies first; simplify call sites in a follow-up if needed.
- Do not enable T3.2 without both unit suites **and** any open manual parity sessions (H9 / A5-M).

### 6.5 Success metrics

| Metric | Today | Target after Phases 1–3 |
|--------|-------|-------------------------|
| Duplicate `struct Tmp` in bin | 8 | 1 (`test_support`) — **achieved** |
| `account_cmd` → `validator_cmd` imports | yes | none |
| `run_key_*` / `KeyDeps` names | present | gone — **achieved** (`run_validator_*` / `ValidatorDeps`) |
| Bin files >1500 LOC with >50% tests | 3 | 0 (tests relocated) |
| Identical TTY helpers | 3 copies | 1 module — **achieved** |
| `make lint` / `make test` | green | stay green |

---

## 7. Detailed backlog

Findings below are grouped by confidence. Line numbers are approximate anchors from the tree as of this plan; use symbols/names if lines drift.

### How to read tiers

- **Tier 1 — Mechanical, high-confidence.** Behavior-preserving, compiler-checked or test-only. Safe to land in a batch. Gate on `make lint` + `make test`.
- **Tier 2 — Structural, behavior-preserving.** Moves across module/crate boundaries or shared abstractions. Own review each.
- **Tier 3 — Judgment calls.** Design decisions; several are tradeoffs, not recommendations.

---

### Tier 1 — Mechanical, high-confidence

#### T1.1 — Shared `#[cfg(test)] mod test_support` ✅ **done**

**What.** Bin has no shared test-support module; every inline test re-declares scaffolding.

**Evidence.**
- `struct Tmp(PathBuf)` + `Drop` ×8: `validator_cli`, `account_cli`, `gen_cli`, `keystore_cli`, `gen_cmd`, `validator_cmd`, `account_cmd`, `fs_util` (perms-restore variant).
- `static ENV_LOCK: Mutex<()>` in `validator_cli` and `account_cli` — two locks do not serialize across files.
- Keygen doubles `FixedEntropy` / `CancelOnFill` / `FixedPassphrase` / `ShortPassphrase` / `ScriptedLines` duplicated in `validator_cmd` and `account_cmd`.

**Change.** Declare `#[cfg(test)] pub(crate) mod test_support` from `main.rs`. Canonical `Tmp::new(prefix)` with **always-on** 0o755 restore before `remove_dir_all` (superset of `fs_util` behavior). Single `ENV_LOCK`. Shared fakes. Keep `keystore_files()` vs `v3_files()` domain listers **distinct**.

**Strictly test-scoped.** Do not fold production `PassphraseSource` / NFKD paths into this module.

**Acceptance criteria:**
- [x] Single `test_support` module declared under bin with `#[cfg(test)]`
- [x] All duplicate `struct Tmp` in bin replaced by shared `Tmp`
- [x] Single `ENV_LOCK` used by env-mutating bin tests (CLI + residual cmd wrappers)
- [x] Keygen test doubles shared (not duplicated in validator_cmd and account_cmd)
- [x] Domain listers remain distinct (`keystore_files` vs `v3_files`)
- [x] `make lint` and `make test` green
- [x] No production behavior change

**Risk:** low. **Effort:** M.

#### T1.2 — Deduplicate TTY helpers ✅ **done**

**Evidence.** `stderr_is_tty` in `gen_cmd`, `validator_cmd`, `account_cmd`; `open_tty_writer` in validator/account; `isatty` also open-coded in `keystore_cli::require_tty_for_new`.

**Change.** One `pub(crate)` home (`fs_util` or `keystore_cli`). Preserve SAFETY comments and S-2 no-stderr-fallback docs verbatim.

**Acceptance criteria:**
- [x] Single home for TTY helpers (`pub(crate)` in `fs_util`)
- [x] No duplicate `stderr_is_tty` / `open_tty_writer` bodies across gen/validator/account
- [x] SAFETY / S-2 docs preserved
- [x] `make lint` and `make test` green
- [x] No production behavior change

**Risk:** low. **Effort:** S.

#### T1.3 — Single `validate_output_dir`

**Evidence.** Identical bodies in `keystore_cli` (pub(crate)) and `gen_cli` (private).

**Change.** Hoist to `fs_util` next to `probe_dir_writable`. Do **not** have `gen_cli` call `keystore_cli` (wrong domain coupling).

- [x] `validate_output_dir` only in `fs_util`
- [x] `keystore_cli` + `gen_cli` (+ account/validator CLI) call `fs_util::validate_output_dir`
- [x] No `gen_cli` → `keystore_cli` coupling for this helper
- [x] `make lint` and `make test` green

**Risk:** low. **Effort:** S.

#### T1.4 — Collapse identical `map_encrypt_err` / `map_passphrase_err`

**Evidence.** Same body `AppError::Keystore(e)` in both cmd files; exit-code split is in `exit_code_for`.

**Change.** One mapper per file. **Do not** replace `map_write_err` with `AppError::from` — that yields exit 1 and breaks keystore write → 3.

- [x] One `map_encrypt_err` per cmd file (`validator_cmd`, `account_cmd`); `map_passphrase_err` removed
- [x] `map_write_err` preserved (exit 3)
- [x] `make lint` and `make test` green

**Risk:** low. **Effort:** S.

#### T1.5 — Delete `discard_logger` wrappers

**Evidence.** `Logger::discard()` exists; three test modules re-wrap it.

**Change.** Call `Logger::discard()` directly. Keep `#[allow(dead_code)]` on `discard` for non-test builds.

- [x] No `discard_logger` wrappers
- [x] `Logger::discard()` used directly in gen/validator/account cmd tests
- [x] `#[allow(dead_code)]` retained on `Logger::discard`
- [x] `make lint` and `make test` green

**Risk:** low. **Effort:** S.

#### T1.6 — Finish `key → validator` rename

**Evidence.** `run_key_new`, `run_key_recover`, `KeyDeps` vs account’s `run_account_*` / `AccountDeps`.

**Change.** Rename to `run_validator_*`, `ValidatorDeps`; update CLI call sites and docs. Leave library `KeyPath` / `KeyLoader` alone.

- [x] `run_key_*` / `KeyDeps` gone; `run_validator_*` / `ValidatorDeps` present
- [x] CLI call sites and docs updated
- [x] Library `KeyPath` / `KeyLoader` untouched
- [x] `make lint` and `make test` green

**Risk:** low. **Effort:** S.

#### T1.7 — Disambiguate `resolve_mnemonic_passphrase`

**Evidence.** Parser in `keystore_cli` vs secret resolver in `validator_cmd` share one name.

**Change.** Parser → `parse_mnemonic_passphrase_form`. Leave cmd resolver name/behavior.

- [x] Parser renamed `parse_mnemonic_passphrase_form`
- [x] Cmd secret resolver still `resolve_mnemonic_passphrase`
- [x] `make lint` and `make test` green

**Risk:** low. **Effort:** S.

#### T1.8 — Small local cleanups (batch)

| # | What | Change |
|---|------|--------|
| a | Dead `Params::default_rpc_url` | Remove field + initializers |
| b | Overflow message ×4 | `START_INDEX_OVERFLOW_MSG` const in `keystore_cli` |
| c | `Box::leak` version string | `LazyLock<String>` once |
| d | `signer.public_key()` in deposit loop | Hoist before loop |
| e | Identical `TipFn`/`BaseFeeFn` aliases | Optional `U128Fn` |
| f | `pub` vs `pub(crate)` in bin | Prefer `pub(crate)` for cmd surface |

- [x] a–f applied (`U128Fn` for tip/base-fee; cmd surface `pub(crate)`)
- [x] `make lint` and `make test` green

**Risk:** low. **Effort:** S.

---

### Tier 2 — Structural, behavior-preserving

#### T2.1 — Overwrite-allowed atomic writer → `core::output` ✅ **done**

**Evidence.** `run_cmd::atomic_write_file` used by `send_cmd`; `core::output::write_new_0600` is refuse-overwrite only.

**Change.** Add sibling `write_atomic` with overwrite-allowed semantics. **Do not** collapse onto `write_new_0600`. Preserve modes per call site (0644/0600). Move bin call sites from local `atomic_write_file` to the shared API. Remove local helper after migration.

**Acceptance criteria:**
- [x] Overwrite-allowed atomic writer lives in `core::output` (sibling of `write_new_0600`)
- [x] `write_new_0600` remains refuse-overwrite only (separate API)
- [x] Modes preserved at call sites (0644 unsigned companion; 0600 signed/raw/receipt)
- [x] Local `run_cmd::atomic_write_file` removed
- [x] `make lint` && `make test` green
- [x] No behavior change for refuse-overwrite keystore writes

**Risk:** low. **Effort:** M.

#### T2.2 — `write_with_retry` skeleton — **done**

**Evidence.** `write_keystore_at` / `write_v3_at` share control flow; differ only in filename + bump.

**Change.** Shared helper taking two filename closures; domain schemas stay in closures. Exit-3 mapping stays at call site.

**Done.** `keystore_cli::write_with_retry(out_dir, json, primary_filename, retry_filename)` owns the
try → `AlreadyExists` → retry-once → propagate control flow via `write_new_0600`. Domain wrappers
remain: `validator_cmd::write_keystore_at` (path + `now_unix` / `+1`) and `account_cmd::write_v3_at`
(address + secs/nanos / `nanos.wrapping_add(1)`). Call sites still `map_write_err` → exit 3.

**Risk:** low. **Effort:** M.

#### T2.3 — Fix sideways dependency (`account` → `validator`) — ✅ done

**Evidence.** `account_cmd` imported `check_cancel`, `resolve_mnemonic_passphrase`, `run_ceremony`, `MnemonicSource`, … from `validator_cmd`.

**Change (landed).** New `keygen` module owns neutrals (`MnemonicSource`, `StdinMnemonicSource`, `RecoverMnemonicSource`, `MinLenPassphrase`, `resolve_mnemonic_passphrase`, `run_ceremony`, `check_cancel`, `zeroizing_trim`, `CLEAR_SCROLLBACK_TWICE`). Ceremony display error is namespace-generic (`failed to display mnemonic on controlling terminal: …`). `account_cmd` and `validator_cmd` both import `keygen` only; Zeroizing paths preserved. Domain encrypt tails remain separate.

**Risk:** low. **Effort:** M.

#### T2.4 — `KeygenConfig` behind namespace label

**Evidence.** `ValidatorConfig` / `AccountConfig` field-identical; load/banner twins.

**Change.** One `KeygenConfig` + aliases; shared load/banner with namespace string. **Keep separate clap help** (account must not mention BLS/EIP-2335 — existing test).

**Risk:** low. **Effort:** M.

#### T2.5 — Shared keygen banner writer

Folds into T2.4 if same PR. Leave `gen_cli::print_banner` separate.

**Risk:** low. **Effort:** S.

#### T2.6 — Shared `map_*_err` for the five identical mappers

Keep `map_hd_err` vs `map_bip32_err`/`map_signer_err` domain-local. Keep exit-3 `map_write_err` out of gen path.

**Risk:** low. **Effort:** S.

#### T2.7 — Relocate large inline tests to sibling files

`#[cfg(test)] #[path = "validator_cmd_tests.rs"] mod tests;` pattern. Decoupled from T1.1.

**Risk:** low. **Effort:** M.

#### T2.8 — Cache BIP-39 wordlist

`LazyLock<Vec<&'static str>>` with empty-line filter preserved. Optional separate `HashMap` for O(1) validate; do not drop ordered Vec.

**Risk:** low. **Effort:** S.

#### T2.9 — `AppError` cleanup

- **Part A (do):** delete pure forwarder mappers; use `?`. Keep `map_write_err` and `map_entropy_err`.
- **Part B (defer):** `thiserror` derive — `Aborted` empty/non-empty Display needs care; avoid `"user aborted: "` trailing space regression.

**Risk:** A low; B medium. **Effort:** M.

#### T2.10 — `bls::init()` no-op

**Prefer leave** plumbing for Go parity and exit-code tests. Optional `#[deprecated]`. Do not delete `AppError::BlsInit`.

**Risk:** medium if removed. **Effort:** S.

---

### Tier 3 — Judgment calls

#### T3.1 — Full `validator` / `account` merge — **REJECTED**

Duplication wraps load-bearing divergence (invariants 6 and 8). Share scaffolding via Tier 1/2 only. Revisit only if product requirements change.

#### T3.2 — Optional shared keygen driver

After T2.3/T2.4, optional trait for the outer loop only; encrypt/derive tails stay in impls. Pass passphrase as `&[u8]` from driver-owned `Zeroizing`. Medium risk; status quo is defensible.

#### T3.3 — Keep three `Deps` structs separate

`GenDeps` is a different domain. Keygen pair only consolidates with T3.2.

#### T3.4 — `civil_from_days` dual copies — leave

Unifying would force `keystore` → `core` edge and forfeit keystore self-containment.

#### T3.5 — `keccak256` copies — leave

Trivial wrappers; intentional stack separation.

---

## 8. Considered and rejected

**Move `SignedTx` into `ethernal-tx` to drop signer→tx.** Rejected — premise wrong. `UnsignedTx` is pervasive input to signing; `SignedTx` is signer-local. Edge is fundamental.

**Naive DRY of validator + account encrypt tails.** Rejected — invariants 6 and 8.

**New util crate for 12-line date algorithm.** Rejected — over-engineering.

---

## 9. Suggested sequencing (summary)

1. **Phase 1 (Tier 1):** T1.1 first, then T1.2, then T1.3–T1.8. One or two PRs. Gate: `make lint` + `make test`.
2. **Phase 2 (Tier 2 homes):** T2.3 + T2.1/T2.2 first; then T2.4–T2.6. Separate reviews.
3. **Phase 3:** T2.7, T2.8, T2.9 A. Defer T2.9 B / T2.10.
4. **Phase 4:** Only conscious Tier 3 decisions; T3.1 stays rejected unless requirements change.

---

## 10. Out of scope (this plan)

- New product features or CLI UX redesign
- Splitting the bin into a `lib.rs` + thin main (nice later; not required for Phase 1–3)
- Changing network list, deposit contract addresses, or golden fixtures
- Windows support
- Replacing clap / scrypt / blst

---

## 11. Document history

| Date | Note |
|------|------|
| 2026-07-19 | Initial detailed tier plan |
| 2026-07-19 | Added SOLID assessment, conventions baseline, phased process, success metrics; re-validated evidence against tree (`Tmp`×8, sideways import, `run_key_*`, `Box::leak`, dead `default_rpc_url`) |
| 2026-07-19 | T1.1 landed: shared `test_support` (`Tmp`, `ENV_LOCK`, keygen fakes) |
| 2026-07-19 | T1.2 landed: TTY helpers centralized in `fs_util` |
| 2026-07-19 | T1.3–T1.8 landed: `validate_output_dir` hoist, map collapse, discard_logger removal, `run_validator_*`/`ValidatorDeps`, parser rename, local cleanups a–f |
| 2026-07-19 | T2.3 landed: neutrals hoisted to `keygen`; `account_cmd` no longer imports `validator_cmd`; ceremony error namespace-generic |
