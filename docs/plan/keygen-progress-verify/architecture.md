# Architecture — keygen progress reporting + BLS verification

**Binding for the issue breakdown.** Where this document and the PRD disagree, this document
wins and the divergence is recorded in §9.

Inputs: [`prd.md`](prd.md) (PR-1…PR-20, checks C1–C4) · [`research/index.md`](research/index.md)
(R1–R3).

---

## 1. Shape of the change

One new module, two edited modules, one edited crate-free error enum. No crate API changes, no
new dependencies, no new threads.

```
bins/ethernal/src/
  progress.rs        NEW   Progress enum (moved) + PhaseReporter (transient line renderer)
  validator_cmd.rs   EDIT  per-phase reporting + C1–C4 in the per-index loop
  errors.rs          EDIT  AppError::KeyVerifyFailed + exit-code arm (→ 3)
  validator_cli.rs   EDIT  --no-verify flag → ValidatorConfig.verify_keystore
  gen_cmd.rs         EDIT  re-export shim only (Progress moves out)
  account_cmd.rs     EDIT  import path only (behavior byte-identical)
  keystore_cli.rs    EDIT  InMemoryPassphrase (shared neutral, see D-6)
docs/USER-GUIDE.md   EDIT  flag + verification semantics
CHANGELOG.md         EDIT  one entry
```

Crates (`ethernal-core`, `ethernal-keystore`) are **untouched**. Every primitive C1–C4 needs is
already public (R3 §1). This is deliberate: the change stays inside the binary, so the audited
crypto crates keep their current review surface.

## 2. New module: `bins/ethernal/src/progress.rs`

### 2.1 Ownership

`Progress` moves here from `gen_cmd.rs:39` verbatim (same variants, same doc comment intent).
`gen_cmd` keeps `pub use crate::progress::Progress;` so `gen_cmd::Progress` still resolves and
the `gen`/`account` call sites need no edit beyond the import line. Rationale: `gen_cmd`
owning a type that `validator_cmd` and `account_cmd` both import is the same misplacement the
recent refactor commits have been correcting (`27792a4` hoisted keygen neutrals into
`keygen.rs`; `2c9807b` centralized TTY helpers in `fs_util.rs`).

### 2.2 `PhaseReporter`

```rust
/// One in-flight unit of work, rendered as a transient single line on a TTY and
/// as nothing at all off-TTY.
pub(crate) struct PhaseReporter<'a> {
    out: &'a mut dyn Write,
    mode: Progress,
    dirty: bool,          // a transient line is currently on screen
}

#[derive(Clone, Copy)]
pub(crate) enum Phase { Deriving, Checking, Encrypting, Writing, Verifying }

impl<'a> PhaseReporter<'a> {
    pub(crate) fn new(out: &'a mut dyn Write, mode: Progress) -> Self;

    /// Render `[{done_before}+1/{total}] {phase}…` in place. Infallible (PR-7).
    /// No-op when `mode == NonTty`.
    pub(crate) fn phase(&mut self, index_1based: usize, total: usize, phase: Phase);

    /// Erase the transient line if one is on screen, leaving the cursor at column 0
    /// on a clean line. Infallible. Idempotent.
    pub(crate) fn clear(&mut self);

    /// Borrow the underlying writer after clearing, for the caller's durable line.
    pub(crate) fn out(&mut self) -> &mut dyn Write;
}

impl Drop for PhaseReporter<'_> {
    fn drop(&mut self) { self.clear() }   // invariant I-3, on every exit path
}
```

Rendering, `Progress::Tty` only:

- `phase()` writes `\r\x1b[K[{i}/{n}] {label}...` then flushes, and sets `dirty`.
- `clear()` writes `\r\x1b[K` + flush when `dirty`, then clears the flag.
- `\x1b[K` (erase-to-end-of-line) is required, not optional — `\r` alone leaves the tail of a
  longer previous label on screen (R1 §4).
- Labels: `deriving`, `checking`, `encrypting`, `writing`, `verifying`. Lowercase, no
  punctuation beyond the ellipsis, and **never** the token `WARNING` (PR-9).

`Progress::NonTty`: every method is a no-op. Off-TTY progress stays exactly what it is
today — one structured log event per completed key (§4.3).

### 2.3 Why a struct and not a free function

`emit_progress` in `gen_cmd` is stateless because it only ever appends. A transient line needs
one bit of state (`dirty`) so that `clear()` is correct when called from an error path where no
phase line was ever drawn. Keeping that bit inside the reporter is what makes PR-3 ("scrollback
after a run is what it is today") hold on **every** exit path, including cancel and error —
the same discipline `run_ceremony` uses to guarantee its scrollback clear fires on all paths
(`keygen.rs:137`).

## 3. Verification module placement

C1–C4 live in `validator_cmd.rs` as one private function, not in a new module and not in a
crate:

```rust
/// C1–C3, pre-write. Cheap, mandatory, no flag.
fn verify_derived_key(
    sk_bytes: &[u8],            // Zeroizing-owned by the caller
    pubkey: &[u8; 48],
    index: u32,
    path_str: &str,
) -> Result<(), AppError>;

/// C4, post-write. Reads the file back through the loader.
fn verify_written_keystore(
    loader: &dyn KeyLoader,
    file: &Path,
    pw: &dyn PassphraseSource,
    sk_bytes: &[u8],
    pubkey_hex: &str,
    index: u32,
) -> Result<(), AppError>;
```

Rationale for keeping them in the binary: they compose existing crate APIs and encode a
*product* policy (which checks, when, what exit code). `ethernal-core`/`-keystore` stay
policy-free. If `account_cmd` ever gains the parity feature (PR-20, deferred), the shared parts
move to `keygen.rs` — the established home for namespace-neutral keygen helpers — at that time,
not speculatively now.

### 3.1 C3's probe root

```rust
/// Domain-separated probe for the C3 proof-of-possession round trip.
/// sha256(b"ethernal/keygen-selfcheck/v1"), fixed, never persisted.
const SELFCHECK_ROOT: [u8; 32] = /* precomputed */;
```

Fixed rather than per-key (PRD §6 open question resolved): the adversary model is "our own code
or hardware is wrong", not a chosen-message attack, and a constant keeps the check
deterministic under test. Domain separation ensures a probe signature could never be mistaken
for a consensus-domain signature if one ever escaped the process — it does not; the signature
is dropped immediately.

## 4. The per-index loop, after

Current loop: `validator_cmd.rs:313`–`375`. New shape (same function,
`finish_from_mnemonic`):

```
for i in 0..count:
    check_cancel
    reporter.phase(i+1, n, Deriving)
    derived   = hd::derive_path(seed, signing(index))
    sk_bytes  = derived.to_bytes()          // Zeroizing<[u8;32]>
    pubkey    = derived.public_key()

    reporter.phase(i+1, n, Checking)
    verify_derived_key(...)                 // C1, C2, C3   — mandatory

    reporter.phase(i+1, n, Encrypting)
    salt/iv/uuid from entropy
    json      = encrypt(...)                // ~310 ms

    check_cancel
    reporter.phase(i+1, n, Writing)
    final_path = write_keystore_at(...)     // create_new, 0600

    if cfg.verify_keystore:                 // C4 — default on, --no-verify skips
        reporter.phase(i+1, n, Verifying)
        verify_written_keystore(...)        // ~310 ms

    reporter.clear()
    emit_key_progress(... , verified)       // durable line — byte-identical (PR-4)
    written.push(...)
```

### 4.1 Ordering invariants

- **I-1.** C1–C3 run **before** `encrypt`. Encrypting a secret that fails its own consistency
  check wastes 310 ms and, worse, could write a file the tool then has to explain.
- **I-2.** C4 runs **after** `write_keystore_at` and reads `final_path` from disk (PR-13). Not
  the in-memory `json` buffer — the check exists to catch bad writes.
- **I-3.** `reporter.clear()` precedes every durable write to `summary_out`, including
  `print_key_summary` **and every error path**. The explicit calls cover the happy path; the
  `Drop` impl covers the `?` returns (`check_cancel`, `derive_path`, the entropy fills,
  `encrypt`, `write_keystore_at`, `verify_*`), where the error is printed from `main.rs`
  outside this struct's scope and would otherwise land on a live phase line. Structural
  precedent: `run_ceremony` result-captures so its scrollback clear fires on every exit path
  (`keygen.rs:135`). `clear()` is idempotent, so belt and braces is free.
- **I-4.** Progress starts only after `run_ceremony` returns. Today's call ordering already
  guarantees this (`validator_cmd.rs:226` → `:236`); it is now an invariant with a comment,
  because `clear_after_ceremony` wipes the screen and any earlier progress output would be
  erased with it (R1 §4).
- **I-5.** Cancel checks keep their current positions. A SIGINT between phases still exits 4
  with *k* complete keystores, and `cancel_mid_run_leaves_k_complete_keystores`
  (`validator_cmd.rs:1030`) must stay green unmodified.

### 4.2 The passphrase for C4

`keystore_pass: Zeroizing<Vec<u8>>` already exists at `validator_cmd.rs:303`. C4 needs a
`&dyn PassphraseSource`; see D-6.

### 4.3 Durable output, unchanged and extended

`emit_key_progress` (`validator_cmd.rs:389`) keeps its TTY line **byte-identical**:

```
keystore {done}/{total}: {path} (pubkey=0x{hex})
```

The `NonTty` arm gains one k/v on the existing `keystore written` event (PR-18):

```
("verified", "full"|"derived-only")
```

`full` = C1–C4 ran; `derived-only` = `--no-verify`, C1–C3 ran. `print_key_summary`
(`validator_cmd.rs:420`) is untouched.

## 5. Errors and exit codes

New typed variant in `bins/ethernal/src/errors.rs`, modelled on
`DepositError::SelfVerifyFailed`:

```rust
/// A post-derivation or post-write self-check failed (C1–C4). Never carries key
/// material — check name, index, HD path, file path, pubkey only. Exit code 3.
KeyVerifyFailed {
    check: &'static str,      // "C1" | "C2" | "C3" | "C4"
    index: u32,
    path: String,             // HD path for C1–C3, file path for C4
    detail: String,           // no secrets (PR-16)
},
```

`exit_code_for` arm: `AppError::KeyVerifyFailed { .. } => 3`, placed with the other exit-3
crypto arms (`errors.rs:274`–`279`).

**Why a typed variant.** Routing through `AppError::Keystore(KeystoreError::…)` yields exit
**2** for every variant except `WrongPassphrase`/`Encrypt` (`errors.rs:260`), and
`AppError::Bls(_)` falls through to the fallback **1** (`errors.rs:74`). Both are wrong for a
self-check failure, and a bare `AppError::Exit { code: 3 }` (the `map_write_err` idiom) is not
matchable in tests.

**C4 failure message** must satisfy PR-15 — name the path, state it was not removed:

```
keystore self-check failed for index {i} ({check}): {detail}
  file: {path}
  the file was NOT removed; do not use it. No further keys were created.
```

## 6. CLI surface

`validator_cli.rs`: one new flag on **both** `new` and `recover`.

```
--no-verify    Skip the post-write keystore decrypt round-trip (C4).
               Derivation self-checks (C1-C3) always run and cannot be skipped.
               Halves wall-clock at the cost of the strongest correctness check.
```

`ValidatorConfig` (`validator_cli.rs:32`) gains `pub verify_keystore: bool` (**true** by
default; `--no-verify` sets it false). Named as the positive so every call site reads
`if cfg.verify_keystore`.

When false, one stderr notice before the loop:

```
WARNING: --no-verify — keystores will not be decrypted back after writing.
```

This is the only new `WARNING` line, it is emitted once per run, and it cannot fire in the
default path — so `tests/validator_e2e.rs:444` ("exactly one WARNING") stays green (PR-9).

## 7. Test seams

`ValidatorDeps` (`validator_cmd.rs:42`) gains exactly one field:

```rust
/// EIP-2335 loader used by the C4 round trip. Production: `&Loader`.
/// Tests inject a failing loader to prove C4 is live (PR-19).
pub loader: &'a (dyn KeyLoader + Sync),
```

Precedent: `GenDeps` already injects `loader: &'a (dyn KeyLoader + Sync)` (`gen_cmd.rs:56`).
Nothing else in the struct changes — in particular `summary_out: &'a mut dyn Write` keeps its
type, which is the whole point of D-2.

Existing test constructors (`run_with`, `run_recover_with`, the two `*_secret_hygiene_*` tests,
the ceremony tests) each add one field initializer. That is the full blast radius on existing
tests; **no existing assertion changes** (M-5).

`ScryptParams::FAST` is already injected by unit tests, so C4's second scrypt does not slow the
unit suite. The e2e tests run production `STANDARD` and **do** get ~2× slower on the
keystore-writing paths — quantified in the project plan's risk table, and the reason
`--no-verify` exists for the heaviest fixtures if it comes to that.

## 8. Decisions

| # | Decision | Rationale | Rejected alternative |
|---|---|---|---|
| **D-1** | No progress-bar dependency; hand-rolled `\r` + `\x1b[K` | ~20 lines vs. a supply-chain addition to an air-gapped keygen tool heading for release attestation; the in-tree renderer already exists | `indicatif` (+`console`, `unicode-width`) |
| **D-2** | Phase-boundary granularity; **no spinner thread** | scrypt is one blocking call with `p=1` and no hook (R2 §3); a thread forces `summary_out: &mut dyn Write` to become shareable across ~10 test sites and two namespaces, to animate a 310 ms block | background render thread |
| **D-3** | Extract `progress.rs` as a **separate, behavior-free commit** before the feature | `Progress` in `gen_cmd` is a known misplacement; separating it keeps the feature diff readable and the refactor bisectable | fold the move into the feature commit |
| **D-4** | C3 probe root = fixed, domain-separated constant | deterministic under test, leaks nothing, adversary model is broken-hardware not chosen-message | per-key random root |
| **D-5** | C4 failure → leave the file, stop the run, exit 3 | preserves evidence; consistent with never-overwrite/`create_new` write discipline; deletion is irreversible and a transient read error must not destroy a good keystore | unlink; rename to `*.invalid` |
| **D-6** | C4's passphrase comes from an in-process `InMemoryPassphrase` holding `Zeroizing<Vec<u8>>`, placed in `keystore_cli.rs` | no re-prompt, no second env read; `keystore_cli` already hosts namespace-neutral keystore CLI helpers (`write_with_retry`); `test_support::FixedPassphrase` is test-only | re-invoke the original `PassphraseSource` per key |
| **D-7** | C1–C3 mandatory, only C4 behind `--no-verify` | cost asymmetry is ~5 orders of magnitude; a flag to skip free checks is a footgun with no benefit | one flag gating all four |
| **D-8** | `account` namespace unchanged this stage | C4-for-accounts needs `decrypt_v3` promoted out of `#[cfg(feature = "test-support")]` — an API-surface decision deserving its own review, not a mechanical copy | widen scope silently |

## 9. Divergences from the PRD

None material. Two refinements:

- PRD §6 open question (C3 probe root) is **resolved** here as D-4.
- PR-18's "verification outcome" is specified concretely as `verified=full|derived-only` on the
  existing `keystore written` event, rather than a new event — keeps CI log volume unchanged.

## 10. File → requirement map

| File | Requirements |
|---|---|
| `bins/ethernal/src/progress.rs` (new) | PR-1, PR-2, PR-3, PR-5, PR-6, PR-7, PR-9 |
| `bins/ethernal/src/validator_cmd.rs` | PR-1…PR-4, PR-8, PR-11…PR-14, PR-16…PR-19 |
| `bins/ethernal/src/errors.rs` | PR-14, PR-15, PR-16 |
| `bins/ethernal/src/validator_cli.rs` | PR-12 |
| `bins/ethernal/src/keystore_cli.rs` | PR-17 |
| `bins/ethernal/src/gen_cmd.rs`, `account_cmd.rs` | D-3 (import/re-export only; no behavior) |
| `docs/USER-GUIDE.md`, `CHANGELOG.md` | PR-12 documentation |

## 11. What explicitly does not change

Keystore JSON bytes · filenames · `0600` mode · `create_new` write semantics · the mnemonic
ceremony and its scrollback clear · `print_key_summary` · the `keystore i/N:` durable line ·
`gen` / `account` runtime behavior · every crate under `crates/` · exit codes 0–5 semantics ·
the `--count`/`--start-index`/passphrase flag surface.

---

**Downstream:** [`project-plan.md`](project-plan.md) · [`issues/index.md`](issues/index.md)
