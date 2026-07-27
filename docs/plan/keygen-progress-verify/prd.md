# PRD — `validator` keygen progress reporting + BLS key verification

**Status:** draft · **Date:** 2026-07-25 · **Target branch:** `develop`
**Plan root:** `docs/plan/keygen-progress-verify/`

---

## 1. Summary

Two changes to the `ethernal validator new` / `validator recover` key-creation loop
(`bins/ethernal/src/validator_cmd.rs:313`):

1. **Progress reporting while keys are being created** — the loop currently emits one line
   *after* each keystore is written (`emit_key_progress`, `validator_cmd.rs:389`). During the
   work itself the terminal is silent. Make the operator see what the tool is doing.
2. **BLS key verification after creation** — the loop writes a keystore without ever proving
   that the key material it just wrote is usable: no sk↔pk consistency check, no signature
   round-trip, no decrypt-back-and-compare. Add those checks.

They ship as **one plan** because they interact: the decrypt round-trip costs a second scrypt
at the same cost as the encrypt, so it **doubles wall-clock per key**. A progress indicator
designed without modelling the verify phase would reach "done" and then hang for the same
duration again. Verification is also the strongest argument *for* the progress bar: it makes a
tool that already felt slow twice as slow.

## 2. Problem

### 2.1 Silence during key creation

`ScryptParams::STANDARD` is `n=262144, r=8, p=1, dklen=32` (`encrypt.rs:108`). **Measured on
this machine** (Apple Silicon, `--release`, `scrypt` 0.11 with the workspace's
`[profile.dev.package.scrypt] opt-level = 3`): **≈ 310 ms per scrypt invocation**
(3 runs: 311 / 309 / 310 ms; see [`research/r2-scrypt-cost-and-hooks.md`](research/r2-scrypt-cost-and-hooks.md)).

| `--count` | today (encrypt only) | with round-trip verify (2× scrypt) |
|---|---|---|
| 1 | ~0.3 s | ~0.6 s |
| 10 | ~3.1 s | ~6.2 s |
| 100 | ~31 s | ~62 s |
| 500 | ~2.6 min | ~5.2 min |

An air-gapped bastion or an older Xeon is realistically 2–4× slower, so a 100-key run on the
target deployment is minutes of an unchanging terminal. The operator cannot distinguish
"working" from "hung on a blocked entropy source" — and this tool is run on air-gapped hosts
where `/dev/random` stalls and cold storage I/O hangs are exactly the failure modes in scope.

### 2.2 No proof the written key works

Today's per-index path is `derive → encrypt → write → print` with **no verification**:

- The 48-byte pubkey printed in the summary and used downstream (`deposit gen` indexes
  keystores by pubkey) comes from `DerivedSk::public_key()` (`hd.rs:73`) and is written into
  the keystore JSON *by the caller*. Nothing re-derives it from the secret that was actually
  encrypted.
- `KeyLoader` explicitly **does not** validate that the JSON `pubkey` field matches the
  encrypted secret ("the loader does not validate its length or that it matches
  `Key::secret`", `keystore.rs:29`). So a mismatch is caught by nobody, at any stage.
- The keystore file is never read back. A truncated write, a filesystem that lies about
  `fsync`, or a memory-corrupted ciphertext produces a file the operator discovers is
  unusable only when they try to attest — after the deposit is already on-chain and 32 ETH is
  locked to a pubkey nobody holds the key for.

This is the one **deliberate deviation** from deposit-cli that the audit flagged as still
open: *"Runtime post-write decrypt verify optional / test-heavy (deposit-cli always
verifies)"* (`1.Projects/ethernal/0.README.md`, "Deliberate deviations"). The project's own
core crate states the opposite as its driving constraint — *"the driving correctness
constraint is 'verify-before-write': every BLS signature is re-verified immediately after
signing"* (`crates/ethernal-core/src/lib.rs:5`) — and `deposit gen` honours it
(`Generator::new` takes a `Verifier`, `deposit.rs:164`). The keygen path does not.

## 3. Users and success

**Primary user:** a staking operator running `ethernal validator new --count N` on an
air-gapped or bastion host, one ceremony, no retries, 32 ETH per key at stake.

**Success metrics**

| # | Metric | Target |
|---|---|---|
| M-1 | Longest terminal silence during a run | ≤ ~1 s on this machine's hardware profile; bounded by one scrypt, never by `N × scrypt` |
| M-2 | Keystores written that cannot be decrypted back to the derived secret | 0 — and any such event is a hard, non-zero exit, not a warning |
| M-3 | Wall-clock regression from verification | ≤ 2.2× today's, and opt-out documented |
| M-4 | New third-party dependencies | 0 |
| M-5 | Existing test suite | green with no assertion rewritten to accommodate new output |

## 4. Requirements

Priority: **P0** ship-blocking · **P1** ship with it unless it forces a redesign · **P2** nice
to have, may be deferred with a written disposition.

### 4.1 Progress reporting

| # | Pri | Requirement |
|---|---|---|
| **PR-1** | P0 | While key *i* of *N* is being created, the operator sees which **phase** is in flight: `deriving` → `checking` → `encrypting` → `writing` → `verifying`. The indicator updates at every phase boundary. |
| **PR-2** | P0 | Longest gap between two indicator updates is **one scrypt**, never a whole key and never the whole run. |
| **PR-3** | P0 | On a TTY the transient phase line is rendered in place (`\r`) and **erased** before the persistent per-key line is written. Scrollback after a run contains exactly the lines it contains today. |
| **PR-4** | P0 | The existing persistent line `keystore {done}/{total}: {path} (pubkey=0x{hex})` and the end summary `wrote N keystores` are **byte-identical** to today's. No downstream parser or test breaks. |
| **PR-5** | P0 | Non-TTY (`Progress::NonTty`, pipes/CI) emits **no** `\r` and no per-phase noise: one structured log event per completed key, as today, extended with the verification outcome. |
| **PR-6** | P0 | Progress text contains no secret material — no mnemonic, seed, secret key, or passphrase. Indices, counts, paths, pubkeys and phase names only. |
| **PR-7** | P0 | Progress rendering is **infallible**: a write/flush error on the progress sink never changes the run's exit status (same fail-open discipline as `clear_after_ceremony`, `keygen.rs:93`). |
| **PR-8** | P1 | `validator recover` gets the same treatment — it shares `finish_from_mnemonic` (`validator_cmd.rs:292`), so this is automatic, but it must be asserted, not assumed. |
| **PR-9** | P1 | Progress lines must never contain the token `WARNING` — the symlink e2e test counts `WARNING` lines and asserts exactly one (`tests/validator_e2e.rs:444`). |
| **PR-10** | P2 | Elapsed / ETA after the first key completes. Needs a clock seam (`ValidatorDeps` injects `now_unix: i64`, not a monotonic clock) and makes output non-deterministic under test. See [`issues/deferred.md`](issues/deferred.md). |

**Explicitly out of scope:** an animated spinner *during* a single scrypt call. `scrypt` 0.11
exposes one blocking `scrypt(password, salt, params, output)` (`lib.rs:89`) with no progress
callback, and `p=1` means it cannot even be chunked by parallelism factor. A spinner would
require a second thread, which forces `summary_out: &'a mut dyn Write`
(`validator_cmd.rs:54`) to become shareable and ripples through every test that injects a
`Vec<u8>` plus the parallel `account_cmd` seam. Rejected — see
[`research/r1-progress-rendering.md`](research/r1-progress-rendering.md) and architecture
decision **D-2**.

### 4.2 BLS key verification

Four checks, named **C1–C4**. C1–C3 are microseconds-to-milliseconds and run **before** the
keystore is written; C4 costs a full scrypt and runs **after**.

| # | Check | Cost | When |
|---|---|---|---|
| **C1** | `new_signer(sk)?.public_key()?` equals `derived.public_key()` — the pubkey about to be published is the one this secret actually produces | µs | pre-write |
| **C2** | `validate_pubkey_bytes(pubkey)` — valid compressed G1, in subgroup, not identity (`bls.rs`) | µs | pre-write |
| **C3** | Sign a fixed 32-byte domain-separated probe root and `Verifier::verify` it against the pubkey — proof of possession; the same self-verify discipline `deposit gen` already applies | ~2 ms | pre-write |
| **C4** | Read the **written file** back through `KeyLoader::load` with the same passphrase; assert the recovered secret equals the derived secret **and** the JSON `pubkey` field equals the derived pubkey | ~310 ms (scrypt) | post-write |

| # | Pri | Requirement |
|---|---|---|
| **PR-11** | P0 | C1–C3 run for every key on both `validator new` and `validator recover`, are **not** optional, and have no flag to disable them. They are free; making them skippable is a footgun with no upside. |
| **PR-12** | P0 | C4 runs by default. A `--no-verify` flag skips **only C4** (help text must say so explicitly). Using it prints a `WARNING:`-prefixed notice to stderr. |
| **PR-13** | P0 | C4 reads the **file on disk**, not the in-memory JSON buffer — the point is to catch a bad write, not to re-check arithmetic. |
| **PR-14** | P0 | Any failed check aborts the run **immediately** (no further indices are processed) with **exit 3** (crypto/signer class, `main.rs:8`), via a typed `AppError` variant, not a bare `Exit{code:3}` string. |
| **PR-15** | P0 | On a C4 failure the offending file is **left on disk** and the error names its exact path and states the file was not removed and must not be used. Rationale: the write path is `create_new`-exclusive and never overwrites; silently unlinking cuts against that discipline and destroys the evidence an operator needs. Quarantine-rename was considered and rejected (D-5). |
| **PR-16** | P0 | Verification failure messages carry no secret material — check name, index, HD path, file path, pubkey; never the secret, and never a "expected X got Y" dump of key bytes. |
| **PR-17** | P0 | C4 re-supplies the keystore passphrase from the already-in-memory `Zeroizing` buffer via an in-process `PassphraseSource`; it must not re-prompt, re-read the env var, or leave a non-zeroized copy (`PassphraseSource::read` returns a plain `Vec` — the caller must re-wrap, `passphrase.rs:27`). |
| **PR-18** | P1 | The per-key non-TTY log event and the completion line reflect that verification happened, so a CI log is evidence of verification. |
| **PR-19** | P1 | A **negative test** proves each check is live: a fake loader / tampered file drives C4 to fail and the test asserts exit 3 and that the run stopped. A check with no failing test is indistinguishable from dead code. |
| **PR-20** | P2 | Parity for `account new` / `account recover` (secp256k1 / v3). Deferred with a written disposition: the v3 decrypt path is `#[cfg(feature = "test-support")]`-gated (`keystore/src/lib.rs`), so C4-for-accounts requires promoting `decrypt_v3` to a production API — a real API-surface decision, not a mechanical copy. See [`issues/deferred.md`](issues/deferred.md). |

## 5. Non-goals

- No new third-party dependency (`indicatif`, `console`, `crossterm`). D-1.
- No spinner thread / no change to the `&mut dyn Write` progress seam. D-2.
- No `--json-logs` flag for `validator` (it exists only on `gen`, `gen_cli.rs:146`; the
  validator logger is hard-wired to `Format::Text`, `validator_cmd.rs:73`). Deferred.
- No change to keystore file format, filename convention, permissions, or write semantics.
- No change to the mnemonic ceremony or its scrollback clear.
- No parallelism in the keygen loop. (Note for a future plan: with verification the loop is
  ~620 ms/key of pure CPU; parallelising is the obvious next lever and is *out of scope here*
  because it interacts with cancel semantics and per-keystore entropy draws.)

## 6. Assumptions and open questions

1. **Assumed:** ~2.2× wall-clock for the default path is acceptable given `--no-verify`
   exists. If a large-batch operator objects, the escape hatch is already specified.
2. **Assumed:** phase-boundary granularity satisfies "progress bar". Nothing renders inside a
   single scrypt without a thread; the PRD states this rather than leaving it to implementation.
3. **Open:** whether C3's probe root should be a fixed constant or derived per-key. A fixed
   constant is simpler and leaks nothing (the signature is never persisted); a per-key root
   proves marginally more. Architecture picks the fixed constant (D-4).

## 7. Acceptance

The feature is done when, on `develop`:

- `make lint && make test` green, with **no existing assertion modified**.
- A `--count 3` run on a TTY shows a live phase line and, afterwards, scrollback identical in
  shape to today's plus nothing transient.
- A `--count 3` run piped to a file contains no `\r` and one structured event per key
  including the verification outcome.
- A tampered keystore forces exit 3, the run stops at that index, and the file is still there.
- `--no-verify` skips only C4, warns, and is documented in `docs/USER-GUIDE.md`.

---

**Downstream:** [`research/index.md`](research/index.md) · [`architecture.md`](architecture.md) ·
[`project-plan.md`](project-plan.md) · [`issues/index.md`](issues/index.md)
