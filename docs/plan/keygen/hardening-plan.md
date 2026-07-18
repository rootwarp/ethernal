# Dev Plan — Keygen Post-Merge Hardening (review 2026-07-18)

**Scope:** Resolve every finding of [`review-2026-07-18.md`](review-2026-07-18.md) — 1 Medium,
19 Low/Informational, and the open manual cross-tool parity gate — before tagging a release.
**Inputs:** the review (binding finding list), [`architecture.md`](architecture.md),
[`project-plan.md`](project-plan.md). Priorities follow the review's "Recommended fix order".
**Sizing:** 1 story point ≈ half a working day. Every issue ≤ 3 pts.
**Merge model:** per-issue fast-forward on `develop`, commits tagged `[H-#]`; every merge green
(`make test && make lint`). No behavior change ships without a test or an explicit CHANGELOG entry (H8).

Every review finding lands in exactly one issue below or in
[Dispositions](#dispositions--findings-resolved-by-decision-no-code-change). Nothing is dropped silently.

---

## Traceability — finding → resolution

| Review finding | Severity | Resolved by |
|---|---|---|
| M1 / K1-L3 / K3-M1 — `UnknownWord` token echoed to stderr/logs | Medium | **H1** |
| K5-L1 — no pipeline defense for withdrawal creds (zero address / `[0u8;32]`) | Low | **H2** |
| K5-L2 — banner omits withdrawal address | Low | **H2** |
| K5-L4 — `0X`-prefix / bare-address rejection untested | Low | **H2** |
| K5-L5 — dead OR-disjunct in two `gen` integration assertions | Low | **H2** |
| K1-L1 — un-zeroized `indices` vectors + mnemonic-join residue | Low | **H3** |
| K1-L2 — `to_seed` lossy-decodes non-UTF-8 mnemonic passphrase | Low | **H3** |
| K1-L4 — SHA-256 digests of entropy not zeroized | Low | **H3** |
| K1 test note — no 24-word checksum-flip negative test | note | **H3** |
| K3-L3 — SIGINT handler armed before `CancelToken` init | Low | **H4** |
| K3-L2 — `--start-index + --count` overflow checked inside write loop | Low | **H4** |
| K5-L3 — exit code timing-dependent under heterogeneous failures | Low | **H4** |
| K3-L4 — writability probe follows symlinks (both CLIs) | Low | **H5** |
| K3-L5 — same-second filename collision | Low (by design) | **H5** |
| K2-L1 — `write_new_0600` crash window leaves 0-byte stub | Low | **H6** |
| K2-L2 — no parent-directory fsync after rename | Low | **H6** |
| K2-L4 — no upper bound on scrypt n/r/p/dklen (decrypt DoS) | Low | **H7** |
| K2-L3 — non-UTF-8 passphrase leaves un-zeroized lossy copy | Low | **H7** |
| K2-L5 — `PassphraseTooShort` says "characters", measures bytes | Low | **H7** |
| K2 info — `checksum_message` fail-open on short dk | Info | **H7** |
| K2 info — `EncryptInput` salt/iv uniqueness + plain-`Vec` `read()` footguns | Info | **H7** (doc comments) |
| K5-L6 — `--from` asymmetry documented against the wrong command | Low | **H8** |
| K2 info — `--passphrase-env` persists in process environment | Info | **H8** (operator note) |
| K5-info-7 — 0x01 deposit roots have no independent CI oracle | Info | **H9** (manual session) |
| Open gate — manual ethstaker-deposit-cli parity session (M-K4 G1/G2) | gate | **H9** |
| K5-info-8 — "no `--entropy`" E2E assertion greps `--help` | Info | Disposition D1 |
| K5-info-9 — raw `--mnemonic-passphrase` in argv | Info | Disposition D2 |
| K3 speculative — EINTR exit-code edge, unbounded stdin/`--count` | spec. | Disposition D3 |
| K3-L5 residual — write-failure exit-3 breadth | by design | Disposition D4 |

## All issues

| ID | Title | Pts | Depends on | Findings |
|---|---|---|---|---|
| H1 | `Bip39Error::UnknownWord` → 1-based position; error-path secret-hygiene test; align `architecture.md` | 1 | — | M1 |
| H2 | Withdrawal-address safety: zero-address reject, pipeline creds guard, banner echo, strictness tests, dead-disjunct cleanup | 2 | — | K5-L1, L2, L4, L5 |
| H3 | `core::bip39` secret-residue hardening + fail-closed passphrase decode + 24-word negative vector | 2 | H1 | K1-L1, L2, L4, note |
| H4 | bin correctness: SIGINT init order, upfront index-range validation, deterministic error selection | 1 | — | K3-L3, K3-L2, K5-L3 |
| H5 | bin fs hardening: symlink-safe writability probe (both CLIs), same-second collision retry | 2 | — | K3-L4, K3-L5 |
| H6 | `core::output::write_new_0600`: eliminate 0-byte-stub window, parent-dir fsync | 2 | — | K2-L1, L2 |
| H7 | `keystore` hardening: scrypt decrypt ceiling, zeroized lossy copy, message wording, fail-closed checksum guard, footgun docs | 1 | — | K2-L3, L4, L5, info |
| H8 | docs: `--from` naming fix, `--passphrase-env` operator note, CHANGELOG for all H-series behavior changes | 1 | H1, H2, H3 | K5-L6, K2-info |
| H9 | **Manual** cross-tool parity session (M-K4 G1/G2) — run + record, pinned versions | 1 | H1–H8 | open gate, K5-info-7 |

**Total: 13 points** (≈ 6.5 person-days single-dev). Two independent streams:
**core/keystore** (H1 → H3, H6, H7) and **bin/gen** (H2, H4, H5) can interleave; H1→H3 is the
only hard code dependency (both edit `bip39.rs`). H8 lands after the behavior-changing issues it
documents; H9 runs last against the fully-merged tree.

**Recommended merge order (review priority):** H1 → H2 → H3 → H4 → H5 → H6 → H7 → H8 → H9.

## Milestone gate

**M-H (release-ready):** all H1–H8 merged green; every review finding either fixed with a test or
dispositioned below; extended secret-hygiene test covers the invalid-mnemonic error path; H9 parity
session recorded in the [progress log](#progress-log) with pinned tool/client versions. This closes
the review's pre-release recommendation and the M-K4 external-correctness loop.

---

## H1 — `UnknownWord` reports word position, never the token

**Points:** 1 · **Depends on:** — · **Findings:** M1 (= K1-L3, K3-M1)

**Goal:** On `key recover`, a mnemonic token that fails wordlist membership must never reach
stderr or the structured logger (S-2 hard property). Report the failing word's **1-based position**
instead. Root cause is a spec/contract inconsistency: `architecture.md:80-84` specifies the
token-echoing message — the doc changes with the code.

**Implementation notes**
- `crates/core/src/bip39.rs:19` — change `UnknownWord(String)` (`bip39: unknown word {0:?}`) to
  `UnknownWord(usize)` with message `bip39: unknown word at position {0}` (1-based). The variant
  derives `PartialEq`; update every constructing/matching site.
- `crates/core/src/bip39.rs:103` (`validate_mnemonic` word loop) — on lookup miss, return
  `UnknownWord(i + 1)` from the enumerated position instead of `(*w).to_string()`.
- Downstream is display-only — `bins/eth-deposit/src/key_cmd.rs:271`, `errors.rs:121`,
  `main.rs:134` need no structural change; confirm nothing else formats the token.
- `docs/plan/keygen/architecture.md:80-84` — update the specified message format to the
  position form, and note the S-2 rationale so the contradiction cannot re-enter.
- Defense-in-depth (cheap, do it): the fix removes the token at the *source*; no `main.rs`
  log-boundary scrubbing needed. If a future variant re-introduces payloads, the new hygiene test
  below is the tripwire.

**Acceptance criteria**
- [x] `key recover` with a non-wordlist token (e.g. `wroth`) → exit 2; stderr and the structured
  log contain `unknown word at position N` and **do not contain the token** — S-2.
- [x] Position is 1-based and correct for a failure at the first, a middle, and the last word.
- [x] New error-path hygiene test (below) green; existing K3-4 hygiene tests unchanged and green.
- [x] `architecture.md` message spec matches the implementation.

**Test plan**
- Unit (`bip39.rs`): `validate_mnemonic` with a bad word at positions 1, 7, 12 → `UnknownWord(1|7|12)`;
  `Display` output contains no input token.
- Integration (extend the K3-4 hygiene suite, `bins/eth-deposit/tests/`): drive `key recover` with a
  mnemonic containing a distinctive invalid token via piped stdin → assert exit 2 and that the token
  bytes appear in **no** captured channel (stdout/stderr/log buffer). This is the test the review
  notes was missing (`secret_hygiene_*` only ran valid mnemonics).

**Notes** — Bounding from the review: the leaked token is by construction not a wordlist word, so
only typo/corruption tokens ever leaked; still a hard S-2 violation. Message change is user-visible
→ CHANGELOG entry in H8.

---

## H2 — Withdrawal-address safety and strictness tests

**Points:** 2 · **Depends on:** — · **Findings:** K5-L1, K5-L2, K5-L4, K5-L5

**Goal:** Guard the one field where wrong-but-valid = permanent stake loss: refuse the zero
address, add a pipeline-level creds guard (defense-in-depth mirroring the mainnet-ack re-check),
show the destination in the pre-signing banner, and pin the EIP-55 strictness contract with tests.

**Implementation notes**
- **Zero-address reject (CLI):** `bins/eth-deposit/src/gen_cli.rs` `load_config` — after
  `signer::validate_eip55_address` returns the 20 bytes, reject `[0u8; 20]` → exit 2 with a clear
  message (the all-digit zero address self-checksums, so EIP-55 alone passes it — review K5-L1(a)).
  Policy lives in the CLI; `validate_eip55_address` stays a pure EIP-55 primitive.
- **Pipeline creds guard (defense-in-depth):** `bins/eth-deposit/src/gen_cmd.rs` — next to the
  mainnet-ack re-check (`gen_cmd.rs:108`), reject `cfg.withdrawal_credentials == [0u8; 32]`
  (placeholder — covers a future non-CLI `GenConfig` caller, K5-L1(b)) **and** creds with prefix
  `0x01` whose 20-byte address tail is all-zero (burn address). Error → exit 2. Stays safe for a
  future legitimate 0x00-BLS mode (a real 0x00 cred has a non-zero BLS-key hash tail).
- **Banner echo:** `gen_cli.rs:391-405` `print_banner` — append
  `withdrawal_address=0x<EIP-55> withdrawal_credentials=0x<64hex>`; derive the display address from
  `cfg.withdrawal_credentials[12..]` via the already-exported `signer::eip55_checksum` (no new edge).
- **Strictness tests (K5-L4):** `crates/signer` unit tests — `validate_eip55_address` rejects an
  `0X`-prefixed and a bare (no-prefix) otherwise-valid address. Pins today's strict behavior
  (`signer/src/lib.rs:30-47`) against a lenient-prefix refactor.
- **Dead disjunct (K5-L5):** `bins/eth-deposit/tests/gen.rs:353-356,391-394` — drop the
  always-true `|| contains("--withdrawal-address")` so each assertion pins *why* rejection happened.

**Acceptance criteria**
- [x] `gen --withdrawal-address 0x0000000000000000000000000000000000000000` → exit 2, no output
  written; message names the zero address explicitly.
- [x] Pipeline rejects all-zero `[u8;32]` creds and `0x01‖0¹¹‖0²⁰` creds → exit 2, no output
  written, independent of how `GenConfig` was constructed.
- [x] Banner shows the EIP-55 address + full creds hex before signing; asserted by a banner test.
- [x] `0X`-prefix and bare-address forms → `Err` in signer unit tests.
- [x] The two integration assertions each pin the specific rejection message; suite green.

**Test plan** — command-level tests in `tests/gen.rs` for the zero-address exit-2 and the banner
content; a unit test constructing `GenConfig` directly with placeholder creds to hit the pipeline
guard; signer unit tests for the two prefix forms; run the K4-1 E2E to confirm the golden is
untouched (guards only reject, never transform).

**Notes** — Zero-address rejection is a (desirable) behavior change → CHANGELOG in H8.

---

## H3 — `core::bip39` secret-residue hardening + fail-closed passphrase

**Points:** 2 · **Depends on:** H1 (same file) · **Findings:** K1-L1, K1-L2, K1-L4, K1 test note

**Goal:** Close the remaining secret-residue gaps in `bip39.rs` (the 11-bit index vectors are a
bit-for-bit encoding of entropy+checksum), fail closed on a non-UTF-8 mnemonic passphrase instead
of silently deriving a wrong seed, and pin 24-word checksum rejection against regression.

**Implementation notes**
- **Index vectors (K1-L1, top-priority K1 fix):** `bip39.rs:57` (`entropy_to_mnemonic`) and
  `bip39.rs:99` (`validate_mnemonic`) — `Zeroizing::new(Vec::with_capacity(word_count))` for both
  `indices` vectors.
- **Mnemonic assembly (K1-L1):** `bip39.rs:78-82` — replace the `Vec<&str>` + `join(" ")` with a
  pre-sized `Zeroizing<String>` built via `push_str`/`push(' ')`, so no intermediate allocation
  carries the words outside a zeroizing wrapper.
- **Digest scrub (K1-L4):** `bip39.rs:54,112,133,135` — make the `Sha256::digest` outputs mutable
  and zeroize them after the checksum bits are consumed (defense-in-depth; digest is one-way).
- **Fail-closed passphrase (K1-L2):** `bip39.rs:163` `to_seed` — replace
  `String::from_utf8_lossy(...)` with strict `std::str::from_utf8`; on failure return a new
  `Bip39Error::PassphraseNotUtf8` (no payload — S-2). Signature changes to
  `Result<Zeroizing<[u8; 64]>, Bip39Error>`; the sole production caller
  (`bins/eth-deposit/src/key_cmd.rs:311` area) propagates via the existing `Bip39 → exit 2` map.
  Update the doc comment that currently blesses lossy replacement. Rationale: a mis-encoded
  "25th word" must error, not derive an unrecoverable-anywhere seed.
- **24-word negative vector:** alongside `validate_checksum_flip` (`bip39.rs:298`, cs_bits=4 only)
  add a 24-word (cs_bits=8) checksum-flip rejection test — covers the `key new` default size.

**Acceptance criteria**
- [x] Both `indices` vectors and the mnemonic assembly string are `Zeroizing`; no non-zeroizing
  intermediate holds entropy-equivalent material (review-listed sites all covered).
- [x] `to_seed` with an invalid-UTF-8 passphrase → `Err(PassphraseNotUtf8)`; via `key recover`
  → exit 2; the error output contains no passphrase bytes.
- [x] All Trezor vectors and the frozen K4-1 E2E golden are byte-identical (pure hardening —
  outputs must not change for valid inputs).
- [x] 24-word checksum-flip test rejects with `Bip39Error::Checksum`.

**Test plan** — existing Trezor/EIP-2333/E2E suites as the no-behavior-change oracle; new unit
tests: invalid-UTF-8 passphrase error, 24-word flip. Hygiene suite (incl. H1's new error-path
test) re-run green.

**Notes** — `to_seed`'s `Result` return and the invalid-UTF-8 error are API/edge behavior changes
→ CHANGELOG in H8. Env-sourced passphrases are the realistic non-UTF-8 vector.

---

## H4 — bin correctness: SIGINT order, upfront range validation, deterministic errors

**Points:** 1 · **Depends on:** — · **Findings:** K3-L3, K3-L2, K5-L3

**Implementation notes**
- **SIGINT init order (K3-L3, pre-existing since `e699229`):** `bins/eth-deposit/src/main.rs:98-99`
  — swap to `let cancel = global_cancel();` **before** `install_sigint_handler();` so the handler
  can never run `OnceLock::get_or_init` (heap allocation, not async-signal-safe) inside a signal
  context. Makes the safety comment at `main.rs:59-60` true for every invocation. One line; serves
  all six subcommands.
- **Upfront overflow validation (K3-L2):** `bins/eth-deposit/src/key_cli.rs` `load_config` —
  validate `start_index.checked_add(count - 1)` fits `u32` → exit 2 *before* any ceremony or
  write. Keep the in-loop `checked_add` at `key_cmd.rs:322` as now-unreachable defense. Fixes the
  "config error reported after real writes" contract break
  (`--start-index 4294967295 --count 2` currently persists the `u32::MAX` keystore first).
- **Deterministic error selection (K5-L3):** `bins/eth-deposit/src/gen_cmd.rs:197-217` — track
  `(index, error)` and keep the **lowest-index** non-cancellation error instead of first-received,
  so the reported exit code no longer varies with worker scheduling. Preserve the existing
  cancellation-vs-real preference. Observability-only (no output is written on any error path).

**Acceptance criteria**
- [x] `global_cancel()` is initialized before the handler is installed (code-order asserted by
  review; add a comment stating the invariant).
- [x] `key new`/`key recover` with an overflowing `--start-index`/`--count` → exit 2 with **zero**
  files written (integration test asserts empty output dir).
- [x] With two pubkeys failing for different reasons, the reported error is the lowest-index one on
  every run (unit test with deterministic failure injection).

**Test plan** — integration test for the overflow-before-write property; `gen_cmd` unit test
injecting per-index failures and asserting stable selection; full suite green.

---

## H5 — bin fs hardening: symlink-safe probe, same-second collision retry

**Points:** 2 · **Depends on:** — · **Findings:** K3-L4, K3-L5

**Implementation notes**
- **Writability probe (K3-L4, both CLIs):** `bins/eth-deposit/src/key_cli.rs:338-346` and its
  `gen_cli.rs` original — replace `File::create` (follows symlinks; predictable name
  `.eth-deposit-probe-<pid>` → pre-planted-symlink truncation in a world-writable dir) with
  `OpenOptions::new().write(true).create_new(true).mode(0o600)`. `create_new`/`O_EXCL` fails on an
  existing symlink rather than following it. Stop discarding the `remove_file` error — a probe
  that can be created but not removed is a broken dir; fold it into the "not writable" error.
  Extract the probe into one shared helper so the two CLIs cannot drift again.
- **Same-second collision (K3-L5, "[by design]" — resolved with a convention-preserving retry):**
  `bins/eth-deposit/src/key_cmd.rs:360` — filenames are `<HD-path>-<unix-seconds>`; two runs in
  the same second with overlapping indices collide, and a same-second `key new` rerun runs the
  full irreversible ceremony before dying at the write. On `OutputError::AlreadyExists` for a
  *timestamped* filename, retry once with `now_unix + 1` (bounded, one bump) before propagating
  exit 3. Never overwrites anything (`write_new_0600` stays `create_new`-exclusive); filename
  convention (staking-deposit-cli mirror) unchanged; deterministic in tests via the injected
  `deps.now_unix`.

**Acceptance criteria**
- [x] Probe path: a symlink pre-planted at the probe name causes a clean "not writable"-class
  error (exit 2) and the symlink **target is untouched** — asserted by a test with a symlink to a
  canary file.
- [x] Probe failure to remove surfaces as an error, not silence.
- [x] One shared probe helper used by both `key` and `gen` CLIs.
- [x] With a pre-existing keystore at the exact timestamped path, the write lands at `ts+1`
  instead of failing; a collision at both `ts` and `ts+1` → exit 3 (`AlreadyExists`), matching the
  current refuse-overwrite contract.

**Test plan** — unit tests for the shared probe helper (symlink canary, unremovable-probe via a
read-only dir); `key_cmd` test with frozen `now_unix` and a pre-created colliding file asserting
the `ts+1` retry and the double-collision exit 3.

---

## H6 — `write_new_0600`: no stub window, parent-dir fsync

**Points:** 2 · **Depends on:** — · **Findings:** K2-L1, K2-L2

**Goal:** Remove the crash window in which the `create_new` reservation exists but the rename
hasn't happened (kill there leaves a 0-byte 0600 stub that blocks every retry with
`AlreadyExists` until an operator deletes it), and make the newly-created file survive power loss
after reported success.

**Implementation notes**
- Current flow (`crates/core/src/output.rs:283-302`): write+sync unique tmp → `create_new` an
  empty reservation at `final_path` → `rename(tmp, final)`. The reservation *is* the stub.
- **Primary fix — link-then-unlink publish:** after tmp is written and synced,
  `fs::hard_link(tmp.path(), final_path)`:
  - `AlreadyExists` → `OutputError::AlreadyExists` (refuse-overwrite preserved, still atomic —
    `link(2)` fails if the name exists).
  - success → the final entry appears with 0600 **and full contents** in one atomic step (same
    inode as the synced tmp); let the existing `TmpGuard` drop remove the tmp *entry* (do **not**
    `disarm` — the inode lives on under `final_path`). No intermediate state exists at
    `final_path`, ever.
  - `EPERM`/`ENOTSUP`-class failure (filesystems without hard links) → fall back to the current
    reservation+rename sequence unchanged, keeping today's behavior as the floor.
- **Parent-dir fsync (K2-L2):** after a successful publish, `File::open` the parent directory and
  `sync_all()`; map failure to a new `OutputError::SyncDir` (the function's contract is "reported
  success ⇒ durable"). The review notes `FsWriter` shares this gap — apply the same dir-fsync
  there opportunistically if the diff stays small; otherwise leave a `TODO` citing K2-L2.
- macOS note: plain `fcntl` fsync semantics are weaker than `F_FULLFSYNC`; standard `sync_all` on
  the dir fd is the accepted portable baseline here — document the choice in a comment.

**Acceptance criteria**
- [x] Refuse-overwrite behavior unchanged: existing-file target → `AlreadyExists`, no tmp left.
- [x] On the primary (hard-link) path there is **no** point where `final_path` exists without its
  full contents — asserted structurally: no `create_new` reservation call remains on that path.
- [x] Interrupted-write simulation (error injected between tmp-sync and publish) leaves *nothing*
  at `final_path` and no stray tmp after guard drop — a retry then succeeds (the K2-L1 operator
  footgun is gone).
- [x] Successful write fsyncs the parent dir; `SyncDir` failure surfaces as an error.
- [x] All existing `write_new_0600` tests (0600-before-bytes, no-tmp-on-handled-errors, gen/key
  call sites) green unchanged.

**Test plan** — extend `output.rs` unit tests: hard-link publish round-trip, AlreadyExists via
pre-existing final, retry-after-simulated-crash, permissions still 0600; run keystore-writing
integration suites (`key new`/`recover`, K4-1 E2E) as regression oracle.

**Notes** — `renameat2(RENAME_NOREPLACE)` was the review's alternative; link-then-unlink is chosen
because it is portable POSIX (macOS included — this repo develops on darwin) with no raw syscall
shim, and the fallback keeps exotic filesystems working.

---

## H7 — `keystore` hardening: decrypt ceiling, zeroized lossy copy, wording, guards

**Points:** 1 · **Depends on:** — · **Findings:** K2-L3, K2-L4, K2-L5, K2 informational

**Implementation notes**
- **Scrypt decrypt ceiling (K2-L4, pre-existing):** `crates/keystore/src/crypto.rs:38-55`
  `derive_scrypt` — reject hostile parameters before allocating: require
  `128 * n * r ≤ 1 GiB` (memory formula; spec vector `n=2^18, r=8` = 256 MiB passes with 4×
  headroom), `p ≤ 16`, `dklen ∈ 32..=128`. Named consts with the formula in a doc comment.
  Shared function ⇒ encrypt (fixed params) and decrypt (attacker-controlled at
  `keystore.rs:300-317`) are both covered. Clear error → existing decrypt error path.
- **Zeroized lossy copy (K2-L3):** `crypto.rs:22` `normalize_passphrase` — wrap the decoded text
  in `Zeroizing` before NFKD (`Zeroizing::new(String::from_utf8_lossy(passphrase).into_owned())`)
  so the invalid-UTF-8 branch never leaves an un-zeroized owned copy. (Unreachable today; both
  production sources deliver valid UTF-8 — pure defense-in-depth, and unlike `to_seed` this path
  keeps lossy semantics: EIP-2335 decrypt must accept whatever bytes unlock existing keystores.)
- **Message wording (K2-L5):** `crates/keystore/src/error.rs:113` — `PassphraseTooShort` says
  "characters" but `passphrase.rs:167-175` measures bytes (the security-correct measure). Change
  the message to "bytes".
- **Fail-closed checksum guard (K2 info):** `checksum_message` — turn the currently-unreachable
  short-`dk` fail-open into an explicit error/`assert` in release builds too.
- **Footgun doc comments (K2 info):** `EncryptInput` — document that salt/iv/uuid uniqueness is
  the caller's responsibility (real caller draws fresh CSPRNG bytes) and that `read()` returns a
  plain `Vec` the caller must re-wrap in `Zeroizing` (as the real caller does).

**Acceptance criteria**
- [x] A keystore JSON with `n=2^25, r=8` (or any params over the ceiling) is rejected on load
  with a clear error and **without** the multi-GB allocation — new decrypt test.
- [x] EIP-2335 spec-vector encrypt/decrypt and the existing fixture round-trips green (ceiling
  must not touch legitimate parameters).
- [x] `PassphraseTooShort` message says "bytes"; test asserting the message updated.
- [x] Lossy-decode branch holds only `Zeroizing` buffers; `checksum_message` fails closed on
  short dk in release builds.

**Test plan** — new hostile-params decrypt unit test (assert error kind, bound the test's own
memory by construction); existing keystore suite as regression oracle.

---

## H8 — docs: `--from` naming, `--passphrase-env` note, CHANGELOG

**Points:** 1 · **Depends on:** H1, H2, H3 (documents their behavior changes) · **Findings:** K5-L6, K2 info

**Implementation notes**
- **`--from` asymmetry naming (K5-L6):** `--from` is **build-only** (`run` derives the sender from
  its signing key). Fix `README.md:86`, `USER-GUIDE.md:277`, `CHANGELOG.md:64-65` ("build/run's
  `--from`" → "build's `--from`") and the plan docs (`project-plan.md:105`, `phase-k5.md` — "gen's
  `--from`" → "build's `--from`"). Direction and strict side of the documented asymmetry are
  already correct — naming only.
- **`--passphrase-env` operator note (K2 info):** add a USER-GUIDE note that the variable persists
  in the process environment for the process lifetime (inherent to env-passing; recommend a
  dedicated shell/session). Skip if review of the existing text shows it already covered.
- **CHANGELOG entries** for every user-visible H-series change: H1 (`unknown word` message now
  positional, token no longer echoed), H2 (`gen` rejects the zero withdrawal address; banner now
  echoes address+creds), H3 (invalid-UTF-8 mnemonic passphrase now errors with exit 2 instead of
  silently deriving a different seed), H5 (same-second collision retry), H7 (hostile-keystore
  scrypt ceiling on load).

**Acceptance criteria**
- [ ] No doc in the repo attributes `--from` to `run` or `gen` (`grep` sweep clean).
- [ ] USER-GUIDE carries the env-persistence note; CHANGELOG lists each behavior change above.
- [ ] `make lint` (incl. any doc checks) green.

---

## H9 — Manual cross-tool parity session (M-K4 G1/G2) — run and record

**Points:** 1 · **Depends on:** H1–H8 merged (run against the release candidate) ·
**Findings:** open gate, K5-info-7

**Goal:** Close the external-correctness loop: the 0x01 deposit roots have no independent CI
oracle (K5-info-7 — the keygen golden is a self-generated regression lock), so this session is
what anchors the stack to the outside world before a real-fund release.

**Procedure (operator-run; Claude prepares the checklist, the user executes the TTY ceremony)**
1. Pin and record versions: **ethstaker-deposit-cli** release (the maintained fork —
   staking-deposit-cli is deprecated), validator client + version, OS.
2. **G2 — pubkey parity:** same mnemonic + mnemonic passphrase into ethstaker-deposit-cli and
   `eth-deposit key recover`; compare signing pubkeys **index-for-index** across the tested range.
3. **G1 — client import:** import an `eth-deposit`-created keystore into ≥1 validator client;
   verify it decrypts and the client derives the same pubkey.
4. Cross-check one deposit-data JSON (roots + creds) against ethstaker output for the same inputs.
5. Record the session — versions, inputs (non-secret: indices, network, address), results — in
   [`project-plan.md`](project-plan.md) progress log (`project-plan.md:129` row) and mirror the
   outcome in the [progress log](#progress-log) below.

**Acceptance criteria**
- [ ] G1 and G2 recorded as passed with pinned versions in the progress log; any mismatch is a
  release blocker filed as a new issue.

---

## Dispositions — findings resolved by decision (no code change)

| # | Finding | Decision |
|---|---|---|
| D1 | K5-info-8 — "no `--entropy` flag" E2E assertion greps `--help` (would miss a hidden flag) | **Accept.** The real determinism guarantee is the byte-stable golden under production `OsEntropy` (stronger than any flag grep); grep already confirmed no hidden flags exist. |
| D2 | K5-info-9 — raw `--mnemonic-passphrase` visible in argv | **Accept (by design).** Documented ps/history note in USER-GUIDE + CHANGELOG; env/prompt forms recommended; value is Zeroizing + Debug-redacted. Shipped in K4-2. |
| D3 | K3 speculative — EINTR→exit-2 edge under non-default signal semantics; unbounded stdin `read_to_string` / `--count` | **Accept.** Local single-user CLI; default signal semantics hold (H4 fixes the one real SIGINT defect); bounding stdin/count adds contract surface with no realistic threat. Revisit only if the CLI ever runs unattended/serverside. |
| D4 | K3 note — all write failures (not just overwrite) map to exit 3 | **Accept (intentional).** Keeps `gen`'s `Output→1` contract distinct; confirmed deliberate in the K3-4 review. |

Review-confirmed **verified non-issues** (K1 §"Verified non-issues", K2 diff-verified invariants)
require no action and are listed here only for completeness of the traceability sweep.

## Progress log

| Issue | Status | Commit | Gate result |
|---|---|---|---|
| H1 | done | 2e7f682 | review PASS (0 findings); S-2 token hygiene fixed |
| H2 | done | 54f2700 | review PASS (0 findings) |
| H3 | done | fc0daab | review PASS (0 findings) |
| H4 | done | 3b6c66f | review PASS (0 findings) |
| H5 | done | 1997b5e | review PASS (0 blocking) |
| H6 | done | 57174d6 | review PASS; inject race fixed |
| H7 | done | 1c847ec | review PASS (0 blockers) |
| H8 | todo | | |
| H9 | todo (manual) | — | M-K4 G1/G2 session — versions to be pinned here |
| M-H | open | | all findings fixed or dispositioned; parity session recorded |
