# Phase A3 — `signer` address helper + `account` namespace + ceremony reuse

**Theme:** Bridge the two new primitives (A1 derivation, A2 v3 writer) into a working `account new`
command: expose the secp256k1 address helper from `signer`, widen the BLS ceremony/mnemonic/passphrase
plumbing to `pub(crate)` for **reuse in place** (visibility-only, no logic duplication), add the
`account` clap namespace, and compose the per-index derive→address→encrypt→write pipeline behind an
injectable `AccountDeps` seam. Stream A critical path joins stream B here.
**Issues:** A3-1, A3-2, A3-3, A3-4, A3-5 · **Points:** 7 · **Execution:** A3-1/A3-2 (stream B) land
early; A3-4 is the six-way fan-in after A1, A2, A3-1..3.
**Milestone gate — M-A3:** `account new` green — TTY-only guard (non-TTY → exit 2 before any
generation), display + full re-entry ceremony (mismatch/abort → exit 4, nothing on disk), `--count N`
writes N v3 files at `0600` with parsing `UTC--` filenames, EIP-55 addresses in the stderr summary;
`signer::secret_to_address` vectors (abandon addresses + non-canonical/zero scalar → `InvalidKey`)
green; **secret-hygiene test green** (mnemonic/seed/chain-code/scalar/both passphrases never on
stdout/stderr/logger — BLS `no_secret_in_logs` harness reused).

Signatures from [`architecture.md`](../architecture.md) §"`signer::secret_to_address`", §"bin —
`account_cli`/`account_cmd`", §"Exit-code mapping", §"Secret lifecycle"; reuse/wire points from
[`research/existing-code-map.md`](../research/existing-code-map.md).

---

## A3-1 — `signer::secret_to_address` + abandon address vector

**Points:** 1 · **Stream:** B · **Depends on:** — · **Milestone:** M-A3

**Goal:** Factor the address-from-secret guts of `LocalSigner::address` into a reusable `pub fn` and
export it, so the `account` path computes an Ethereum address from a 32-byte secp256k1 secret with the
`0 < k < n` canonical guard for free. Delivers the EIP-55 **address** half of M-A1 (which `core` cannot
compute — no keccak). Satisfies F-2 (address + canonical-scalar validation).

**Implementation notes**
- Change `crates/ethernal-signer/src/local.rs`: factor the guts of `LocalSigner::address`
  (`local.rs:140-149`) into `pub fn secret_to_address(secret: &[u8;32]) -> Result<[u8;20],
  SignerError>` = `SigningKey::from_slice(secret)` (enforces `0 < k < n`; `InvalidKey` on
  non-canonical) → `pubkey_address(sk.verifying_key())` (= `keccak256(uncompressed[1..])[12..]`).
  `LocalSigner::address` **delegates** to it so there is ONE copy.
- Change `crates/ethernal-signer/src/lib.rs`: `pub use local::secret_to_address;`. `eip55_checksum`
  is already `pub` (`lib.rs:21`). No new dep, no new edge (`signer` already has `k256` + `sha3`).

**Acceptance criteria**
- [x] `secret_to_address` maps the **Ethereum BIP-44** secrets (from A1-2) to their EIP-55 addresses:
  `1ab42cc4…fb12b727` → `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` and `9a983cb3…f1b55b6` →
  `0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0` (via `eip55_checksum` of the returned 20 bytes) — F-2,
  C-1, G4, **delivers the M-A1 address clause** (research/bip32-secp256k1.md §"Ethereum BIP-44 vector").
- [x] a **non-canonical** scalar (all-zero, or a 32-byte value `≥ n`) → `SignerError::InvalidKey`
  (via `SigningKey::from_slice`) — F-2 (architecture §"`signer::secret_to_address`").
- [x] `LocalSigner::address` delegates to `secret_to_address` (single implementation; existing signer
  tests still green) — regression.
- [x] `cargo tree -p ethernal-signer` shows no new crate edge; `eip55_checksum` remains `pub` —
  architecture §Design note (b).

**Test plan**
- Unit tests in `signer`: the two abandon secrets → their EIP-55 addresses; zero scalar → `InvalidKey`;
  a `≥ n` 32-byte input → `InvalidKey`; a delegation test asserting `LocalSigner::address` and
  `secret_to_address` agree for a known key.

**Notes**
- Keccak/EIP-55/address derivation has exactly **one home — `signer`** (architecture Design note (b));
  the v3 writer (A2) receives the address as 20 bytes and never learns `k256`/the pubkey. The bin
  bridges `hd_secp256k1` (secret) → `signer` (address) → `encrypt_v3`.

---

## A3-2 — `pub(crate)` widening of `key_cli` / `key_cmd` shared items

**Points:** 1 · **Stream:** B · **Depends on:** — · **Milestone:** M-A3

**Goal:** Widen a handful of the shipped BLS `key_cli`/`key_cmd` items to `pub(crate)` so the new
`account_cli`/`account_cmd` can **reuse the ceremony/mnemonic/passphrase plumbing in place** — zero
logic duplication, visibility-only churn (the safest option against the security code, architecture
Design note (c)). No behavior change. Land early on `develop` (H1–H8 merged, no in-flight H-code on
these files → near-zero conflict risk, R5).

**Implementation notes**
- Change `bins/ethernal/src/key_cli.rs`: widen to `pub(crate)` (from `pub`/private as noted) —
  `MnemonicPassphraseForm` + `resolve_mnemonic_passphrase` (clap layer), `require_tty_for_new`,
  `validate_output_dir`, `shared_args`.
- Change `bins/ethernal/src/key_cmd.rs`: widen to `pub(crate)` — `MnemonicSource` +
  `StdinMnemonicSource` + `RecoverMnemonicSource`; `run_ceremony`, `resolve_mnemonic_passphrase`
  (runtime), `MinLenPassphrase`, `check_cancel`, `zeroizing_trim`.
- **No behavior change** — visibility only. (`keystore` side `NewKeystorePassphrase`/`EnvSource`/
  `require_min_len` are already `pub` — reused verbatim, no change here.)

**Acceptance criteria**
- [x] each item in the reuse table (architecture §"Shared with the `key` path") is `pub(crate)` and
  compiles; no signature or body change — architecture Design note (c).
- [x] the existing `key_cmd`/`key_cli` test suite stays **green** (this is the regression gate for a
  visibility-only change) — R5.
- [x] `key new` / `key recover` behavior is byte-identical (no golden/exit change) — U-3, R5.

**Test plan**
- `make test && make lint` green — the existing BLS suite is the gate. No new tests (visibility-only).

**Notes**
- Reuse **in place**, not extract-a-module and not copy (architecture Design note (c)). Copying would
  duplicate S-1/S-2 security code (rejected); extracting a neutral `mnemonic_flow.rs` is deferred to
  revisit once H9 closes. This issue unblocks A3-3 (which calls the widened `key_cli` helpers).

---

## A3-3 — `account_cli` + `AccountConfig` — clap namespace, TTY guard, validation

**Points:** 2 · **Stream:** A · **Depends on:** A3-2 · **Milestone:** M-A3

**Goal:** Add the nested `account` clap namespace and its config/validation scaffolding — `account new`
/ `account recover` subcommands, `--count`/`--output-dir`/`--start-index`, the three-form
`--mnemonic-passphrase` (reused forms), the `account new` non-TTY guard, and `main.rs` dispatch —
without runtime derivation yet. Satisfies U-3 (namespace), F-5 (TTY guard), F-8/F-11 (flags), F-16
(clear config errors).

**Implementation notes**
- New `bins/ethernal/src/account_cli.rs`: `command()` building the `account` group
  (`subcommand_required(true).arg_required_else_help(true)`) with `new_command()` (TTY-only) and
  `recover_command()` (+ `--start-index`). Mirror `key_cli::command()`; reuse its `shared_args`,
  `validate_output_dir`, `MnemonicPassphraseForm` (all widened in A3-2).
- `struct AccountConfig { mode: AccountMode, count: u32, output_dir: String, start_index: u32,
  passphrase_env: String, mnemonic_passphrase: MnemonicPassphraseForm }` — identical shape to
  `KeyConfig` **minus** pubkey/withdrawal concerns (EOA = one keypair, no withdrawal key, no key-type
  flag — F-8, U-3).
- `pub(crate) fn run_new(m, cancel)` / `run_recover(m, cancel)` — `run_new` calls the reused
  `require_tty_for_new` **first** (F-5), then loads `AccountConfig`.
- Change `bins/ethernal/src/main.rs`: add the nested `account` subcommand + dispatch arm next to the
  `key` arm (`main.rs:115`), passing `global_cancel()`. The existing verbs stay flat.
- Flags: `--count N` (default 1, ≥ 1), `--output-dir DIR` (reuse `validate_output_dir`), `--start-index
  N` (recover only), keystore passphrase (`--passphrase-env` / prompt-with-confirm default), and the
  three-form `--mnemonic-passphrase` (raw argv / `--mnemonic-passphrase-env` / bare-prompt; `num_args(0..=1)`;
  raw and env `conflicts_with`; empty default — the reused clap mechanics from keygen).

**Acceptance criteria**
- [x] `ethernal account new` and `ethernal account recover` parse under a `subcommand_required`
  `account` group; the existing `key`/`gen`/… verbs are unchanged and the `key` help does not mention
  EOA — U-3 (architecture §"bin — `account_cli`").
- [x] `--count` defaults to 1; `--output-dir` is validated writable (reused `validate_output_dir`);
  `--start-index` exists on `recover` only — F-8, F-11.
- [x] the three `--mnemonic-passphrase` forms parse (raw / `-env` / bare-prompt); absent → empty
  default; raw and env are mutually exclusive — F-12.
- [x] `account new` exits **2 before any generation** when stdin or stdout is not a TTY (reused
  `require_tty_for_new`); `account recover` is exempt — F-5, S-2.
- [x] a bad `--count` or unwritable `--output-dir` → exit 2 with a specific message — F-16, F-9.

**Test plan**
- clap parse tests: flag presence/defaults; the three mnemonic-passphrase forms resolve to the right
  variant; raw/env mutual exclusion.
- A non-TTY guard test (in the `bins/ethernal/tests/` exit-usage style) asserting `account new` → exit
  2 with nothing written.
- A `validate_output_dir` negative test (missing / non-writable → exit 2).

**Notes**
- `AccountConfig` has no withdrawal/key-type field — the `account` namespace **is** the type selector
  (Q1 binding, U-3). Depends on A3-2 for the widened `key_cli` helpers; independent of A1/A2 (pure
  clap/config), so it overlaps A1 on the schedule.

---

## A3-4 — `account_cmd` — `AccountDeps` seam + `account new` derive→encrypt→write pipeline

**Points:** 2 · **Stream:** A · **Depends on:** A3-3, A3-1, A3-2, A1-2, A2-1, A2-2 · **Milestone:** M-A3

**Goal:** Implement `account new` end-to-end behind an injectable `AccountDeps` seam: draw entropy →
mnemonic, resolve the mnemonic passphrase, run the reused display-once + full-re-entry ceremony, then
per index derive (`hd_secp256k1`) → address (`signer`) → encrypt (`encrypt_v3`) → filename
(`v3_filename`) → write (`write_new_0600`), SIGINT-clean, with an EIP-55-address progress/summary.
This is the six-way fan-in. Satisfies F-1, F-2, F-3, F-4, F-6, F-7, F-12, F-15, S-1, S-2, S-4, S-5, U-1.

**Implementation notes**
- New `bins/ethernal/src/account_cmd.rs`:
  `struct AccountDeps<'a> { cfg, entropy: &dyn Entropy, keystore_pw: &dyn PassphraseSource,
  mnemonic_src: &dyn MnemonicSource, tty_writer: &mut dyn Write, summary_out: &mut dyn Write,
  progress: Progress, logger: &Logger, timestamp: Timestamp }` (`Timestamp { unix_secs: i64, nanos:
  u32 }` — nanos are load-bearing for the `UTC--` filename; this one field is why `AccountDeps` is
  its own struct, not shared with `KeyDeps`).
- `pub fn run_account_new(cfg, cancel) -> Result<(), AppError>` (production wrapper: `OsEntropy`,
  `NewKeystorePassphrase::new(stderr)` or `EnvSource`+`require_min_len`, real tty writer, wall-clock
  `Timestamp`) → `run_account_new_with_deps(deps, cancel)`. `main.rs` dispatch (from A3-3) calls it.
- Pipeline (architecture §"Data flow — `account new`"): `entropy.fill 32B` →
  `bip39::entropy_to_mnemonic` (reused) → resolve mnemonic passphrase (flag>env>prompt-**confirm**;
  empty ok) → **ceremony** (reused `run_ceremony`: display once on `tty_writer`, require full
  re-entry; mismatch/SIGINT → `Aborted` exit 4, nothing on disk) → keystore passphrase (RAW bytes,
  ≥8) → `bip39::to_seed` → for `i in start..start+count`: `hd_secp256k1::derive_path(seed,
  Bip44Path::eoa(i))` → `secret_bytes()` → `signer::secret_to_address(&sk)` (also validates `0<k<n`)
  → `entropy.fill` salt(32)/iv(16)/uuid(16) → `encrypt_v3{ scrypt: STANDARD, password: RAW }` →
  `v3_filename(addr, ts.secs, ts.nanos)` → `write_new_0600(dir/name, json)` → progress
  `eip55_checksum(addr)` + path to stderr.
- **`account new` mnemonic passphrase is fully honored here** (not stubbed for A4-2) — the bare-prompt
  form is **confirm** (double-entry) on `new`; captured before derivation; `Zeroizing` (F-12).
- SIGINT: reused `check_cancel` checkpoints at each prompt and before each write (S-5). Ceremony
  completes before any write → SIGINT during it leaves **zero** files; with `--count N`, SIGINT after
  *k* writes leaves *k* complete keystores.
- Progress per key + end-of-run summary (paths + **EIP-55 addresses**) to `summary_out`/stderr, TTY
  /non-TTY split like `gen` (F-15).
- `FixedEntropy` (deterministic mnemonic + salt/iv/uuid) + scripted mnemonic/passphrase sources + a
  fixed `Timestamp` live in this file's `#[cfg(test)]` only — no hidden entropy/time flag ships (S-4).

**Acceptance criteria**
- [ ] `account new` generates a fresh 24-word mnemonic from 256-bit `OsEntropy` with a valid checksum
  — F-1, S-4.
- [ ] the reused ceremony displays once via `tty_writer` and requires full re-entry before **any**
  keystore is written; mismatch → retry or clean abort (exit 4); nothing on disk until re-entry
  matches — F-6, U-1, S-5.
- [ ] per index: secret derived at `m/44'/60'/0'/0/i`, address via `secret_to_address`, encrypted v3
  (scrypt `STANDARD`, RAW passphrase), filename via `v3_filename`, written `0600` / atomic /
  refuse-overwrite — F-2, F-3, F-4, S-3.
- [ ] `--count N` writes N v3 files whose `UTC--…` filenames parse and whose top-level `address`
  matches the derived address; the stderr summary lists EIP-55 addresses — F-8, F-15.
- [ ] keystore passphrase uses `NewKeystorePassphrase` (confirm, ≥8) or `--passphrase-env` +
  `require_min_len(8)`, fed **raw** to `encrypt_v3` — F-7, C-4.
- [ ] the mnemonic passphrase is resolved flag>env>prompt-confirm, captured before derivation, empty
  valid, `Zeroizing` (fully honored by `new`) — F-12.
- [ ] the `AccountDeps` seam injects entropy/keystore_pw/mnemonic_src/tty_writer/summary_out/timestamp;
  `FixedEntropy` + fixed `Timestamp` are `#[cfg(test)]`-only — S-4, testability.
- [ ] SIGINT before any write leaves zero keystores; with `--count N`, SIGINT after *k* writes leaves
  *k* complete keystores — S-5.
- [ ] entropy, mnemonic, seed, every chain code, every `secret_bytes`, and both passphrases are
  `Zeroizing` at every hop — S-1.

**Test plan**
- `AccountDeps`-seam tests with `FixedEntropy` + fake prompt sources + a fixed `Timestamp` + buffers:
  happy path writes N v3 files whose `crypto`/`address` are internally consistent and whose filenames
  parse; mismatched re-entry → retry then abort (exit 4, no files); passphrase `<8` → exit 2; SIGINT
  mid-run leaves *k* complete files.
- A non-TTY integration assertion (`account new` guard → exit 2) if not already covered by A3-3.

**Notes**
- 2 pts, the fan-in bottleneck (six direct deps: A3-3 CLI, A3-1 address, A3-2 widening, A1-2
  `derive_path`, A2-1 `encrypt_v3`, A2-2 `v3_filename`). Kept intact per the plan. `AccountDeps`
  differs from `KeyDeps` only in the address-summary and the nanos-carrying `timestamp`.
- Real-terminal echo-off is exercised only in the combined manual session (A5-M); unit tests drive
  every ceremony branch via the injectable `tty_writer` + fake sources.

---

## A3-5 — exit-map (`Bip32 => 3`) + `account new` secret-hygiene test

**Points:** 1 · **Stream:** A · **Depends on:** A3-4 · **Milestone:** M-A3

**Goal:** Wire the one new exit-code arm and the call-site write mapping, and add the automated
secret-hygiene test proving no secret reaches stdout/stderr/logs. Satisfies F-9 (exit map), S-2/G5
(no leakage), and preserves `gen`'s `Output → 1`.

**Implementation notes**
- Change `bins/ethernal/src/errors.rs`: add `AppError::Bip32(Bip32Error) => 3` (mirroring
  `Hd(HdError) => 3` at `errors.rs:265`) + its `Display`/`From`. `encrypt_v3` failure reuses
  `Keystore(Encrypt{..}) => 3` (existing); `signer::secret_to_address` `InvalidKey` uses the existing
  `Signer(InvalidKey) => 3`.
- Keystore **write** errors (`OutputError`, incl. overwrite-refusal F-4) are mapped
  `map_err(|e| AppError::Exit{msg, code:3})` **at the `account_cmd` call site** — not a global
  `OutputError` arm — so `gen`'s `Output` stays `→ 1` (keygen fork (a), `errors.rs:625`).
- Bad `--count` / non-TTY `new` / passphrase `<8` / bad range use `AppError::Exit{code:2}` (already
  wired via reused helpers).
- New secret-hygiene test in `bins/ethernal/tests/` modeled on the BLS `no_secret_in_logs` /
  `redact_boundary` harness: run the `AccountDeps` seam with a fixed mnemonic, route the one-time
  display to `tty_writer`, and assert the secrets never appear in captured stdout/stderr/logger.

**Acceptance criteria**
- [ ] exit map holds: `Bip32Error` (derive master/child) → 3; `encrypt_v3` failure → 3;
  `secret_to_address` `InvalidKey` → 3; keystore write (incl. overwrite-refusal) → 3 at the call site;
  bad `--count`/non-TTY `new`/passphrase `<8`/bad range → 2; ceremony mismatch/abort + SIGINT → 4;
  unexpected-internal stays 1 — F-9 (architecture §"Exit-code mapping").
- [ ] the secret-hygiene test asserts the mnemonic, seed, **chain codes**, **scalar/secret bytes**,
  and **both** passphrases (raw + hex) never appear in stdout/stderr/logger buffers; the one-time
  mnemonic display goes **only** to `tty_writer`; the **address is present** (public) — S-2, G5.
- [ ] `gen`'s `OutputError → 1` contract is unchanged (its writer-error test still passes) —
  regression (architecture §"Exit-code mapping").

**Test plan**
- Unit tests asserting each `AppError` variant → its expected code (2/3/4/1), including the new
  `Bip32 => 3`.
- The integration secret-hygiene test (grep-style absence assertions over captured buffers for the
  fixed mnemonic / seed / chain-code / scalar bytes, raw and hex).
- Re-run `gen`'s exit/writer tests to confirm the fallback is unchanged.

**Notes**
- The write error is mapped at the call site (not globally) so the shared `OutputError` keeps `gen`'s
  exit-1 contract — the one `errors.rs` edit is the `Bip32` arm.
