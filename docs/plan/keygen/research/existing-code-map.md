# Research — existing-code map & extension points (keygen)

**Question:** where exactly does keygen plug into the current code, and what blocks the planned
design (private fields, missing pub APIs, non-reusable helpers)?

**Verdict: the plan is buildable, with four concrete blockers to plan around.** (1) The
keystore decrypt-side structs are all private and `Deserialize`-only — making them
"bidirectional" means adding `Serialize` + constructors (K2-1). (2) The reusable crypto
helpers (`normalize_passphrase`, `derive_key`) are private. (3) `core::output`'s atomic writer
is deposit-data-specific and its `open_0600` is private — keygen can't call it directly.
(4) The existing `TermPromptSource` prompts **once** (no confirm), so the "prompt-with-confirm"
encryption passphrase (F-7) is a new capability, and the exit-code map sends keystore-**write**
errors to the fallback code 1 unless a new arm is added. `getrandom` is genuinely new (absent
from the workspace `Cargo.toml`).

---

## `crates/keystore` — encrypt side (K2-1, K2-2)

**Decrypt model is private + `Deserialize`-only** (`crates/keystore/src/keystore.rs`):
- `Envelope` (95), `Crypto` (106), `CryptoModule` (115), `ScryptParams` (125),
  `Pbkdf2Params` (135), `CipherParams` (144) are all **non-`pub`** and derive only
  `Deserialize`. `Envelope.crypto` is `Option<serde_json::Value>` (loosely typed, keystore.rs:97).
  - **Blocker for "bidirectional Envelope":** to *write*, K2-1 needs either `Serialize` +
    public constructors on these (and a typed `crypto` instead of `serde_json::Value`, to
    control field **order** for byte-identity), or a parallel set of encrypt-side structs
    (`#[derive(Serialize)]`) in a new `keystore::encrypt` module. A typed struct with fields in
    declared order is the reliable way to reproduce the spec vector's `crypto` bytes (serde
    serializes struct fields in declaration order — the same trick `core::output::JsonEntryOut`
    uses, output.rs:58).
- **Reusable crypto, but private:** `normalize_passphrase` (298) + `is_stripped_control` (310),
  `derive_key` (317, handles the scrypt call we need), and `decode_hex` (370) are private fns;
  `normalize_pubkey` (223) is `pub(crate)`. K2-1 must expose these (or a shared internal module)
  so encrypt and decrypt use **the exact same** normalization + scrypt call. The AES type
  `Aes128Ctr = Ctr128BE<Aes128>` (23) is symmetric — reuse it for encrypt.
- **`Key`** (31) is `pub` with `pub secret: Vec<u8>` + `pub pubkey_hex: String`, zeroizes on drop
  and on `Key::zeroize`, redacts in `Debug`. Reusable; the encryptor's input is a 32-byte SK, not
  a `Key`, so this mostly matters for the round-trip test.
- **Loader round-trip:** `Loader`/`KeyLoader::load` (150-219) is the existing, fixture-proven
  decrypt path — the M-K2 gate decrypts our output through it unchanged.

**`KeystoreError`** (`crates/keystore/src/error.rs`): variants cover decrypt/scan/passphrase.
There is **no** encrypt/write-failure variant — K2-2 adds one (e.g. `KeystoreWrite`) or reuses
the bin's `AppError::Exit{code:3}` at the call site. See the exit-code note below.

**Passphrase sources** (`crates/keystore/src/passphrase.rs`):
- `PassphraseSource` trait (21) + `EnvSource` (28, `--passphrase-env`) + `TermPromptSource` (63)
  are reusable for the **keystore** passphrase (F-7). `EnvSource` reads a non-empty env var.
- **Gap:** `TermPromptSource::read` prompts **once** ("Keystore passphrase: ", passphrase.rs:113)
  — it does **not** confirm. F-7 / U-2 want prompt-**with-confirm** for *creating* keystores
  (enter twice to avoid locking yourself out). The decrypt flow never needed confirm. So "reuse
  `PassphraseSource`" holds at the trait level, but a **new confirm-capable implementation** (or a
  confirm mode on `TermPromptSource`) is required for K2/K3, plus the **≥8-char minimum** check
  (F-7) which lives in neither source today. `TermPromptSource::with_opener` (81) is the private
  test seam (injectable `/dev/tty` opener) — the pattern to copy for testing the new source.

---

## `crates/core` — derivation, output, cancellation (K1-2, K2-2)

- **`bls.rs`:** `new_signer(secret: &[u8]) -> BlsSigner` (91; copies+zeroizes its local),
  `Signer::public_key() -> [u8;48]` (116), `validate_pubkey_bytes` (152). **No EIP-2333
  derivation is exposed here** — `blst`'s `derive_master_eip2333`/`derive_child_eip2333` are not
  wrapped. K1-2 (`core::hd`) calls `blst::min_pk::SecretKey` directly (blst is already a `core`
  dep) and bridges to signing via `sk.to_bytes()` → `new_signer(bytes)`. See `eip-2333-2334.md`
  for signatures. (Minor: this round-trips the SK through a 32-byte buffer — wrap it in
  `Zeroizing`.)
- **`output.rs`:** `FsWriter` does the atomic **tmp→fsync→rename**, `0600` sequence we want, but:
  - the `Writer` trait (40) is **deposit-data-specific** — it takes `&[Entry]`, serializes the
    Launchpad schema, and hard-codes the `deposit_data-<ts>.json` filename (138-139);
  - `open_0600` (163) — the reusable "create/truncate + `0o600`" helper — is **private**.
  - **Blocker:** keygen can't call `Writer`/`FsWriter` for keystores (wrong shape, wrong
    filename). K2-2 either **extracts a generic atomic-write helper** (`open_0600` + tmp→rename +
    overwrite-refusal, made `pub`) into `core::output` and reuses it, or re-implements the ~15
    lines in `keystore::write`. Extracting is cleaner and keeps one audited atomic-write path.
    Note the current `FsWriter` **truncates/overwrites** (`create(true).truncate(true)`,
    output.rs:165) — keygen must instead **refuse to overwrite** (F-4): use
    `OpenOptions::create_new(true)` (fails if the target exists) for the temp/final files.
- **`cancel.rs`:** `CancelToken` (12) — clone-cheap atomic flag, `cancel()`/`is_cancelled()`.
  Reusable as-is for the SIGINT-clean ceremony (S-5). `main` already installs a SIGINT handler
  that calls `global_cancel().cancel()` (`bins/eth-deposit/src/main.rs:56-66`).
- **`deposit.rs`:** `Request.withdrawal_credentials` flow and the K5 wire point are covered in
  `withdrawal-credentials.md`. `Entry::validate()` does not touch credentials.

---

## `bins/eth-deposit` — CLI wiring (K3-1, K3-2, K3-3)

- **Subcommand wiring** (`src/main.rs`): `root_command()` (68) adds each verb via
  `.subcommand(<mod>::command())`; `main` dispatches on `matches.subcommand()` (103-118). To add
  the nested `key` namespace (U-3), add `.subcommand(Command::new("key").subcommand_required(true)
  .subcommand(key_new::command()).subcommand(key_recover::command()))`, and match
  `Some(("key", sub))` → `sub.subcommand()`. SIGINT handler + `global_cancel()` are already wired
  (50-66) — pass `cancel` into the key handlers like the others.
- **Flag schema + validation pattern** (`src/gen_cli.rs`): `command()` (61) defines clap args;
  `load_config` (170) runs an explicit **validation order** and prints a banner. Precedence
  **flag > env > default** is via clap's `env` feature (workspace dep `clap` has `features =
  ["env"]`) plus the `non_empty` guard (config.rs:160). Copy this shape for `key new`/`key recover`
  (`--count`, `--output-dir`, `--start-index`, passphrase flags, `--mnemonic-passphrase`,
  `--withdrawal-address` on `gen`). The **conditional-required** check for `--output-dir`
  (gen_cli.rs:205-211) is the exact pattern for the K5 "require `--withdrawal-address`" gate.
- **Strict address parsing** (`src/config.rs`): `parse_from_flag` (142) is the strict 20-byte
  hex model to copy for `--withdrawal-address` (strip `0x`, `hex::decode`, require len 20, else
  exit 2). It is **lenient on case / no EIP-55** — see `withdrawal-credentials.md` for the
  checksum decision.
- **`gen_cmd.rs`:** `default_withdrawal_creds()` (31) and the `process_pubkey` `Request` build
  (300-309) are the K5 wire points. The per-key **progress + summary** rendering (TTY vs non-TTY,
  emit_progress 326, print_gen_summary 359) is the template for the keygen per-key progress
  (F-15). `TermPromptSource::new(std::io::stderr())` injection at gen_cmd.rs:131 shows how the
  passphrase source is constructed in production; tests inject fakes via the `GenDeps` seam.
- **Exit-code map** (`src/errors.rs`): `exit_code_for` (208). Mechanisms for keygen:
  - `AppError::Exit { msg, code }` carries an explicit code — use for the ≥8-char passphrase
    (2), bad mnemonic (2), ceremony/TTY guards (2).
  - `AppError::Aborted(_)` → **4** (211) — use for SIGINT and the ceremony mismatch/abort (F-6).
  - **Blocker:** crypto/keystore-**write** failures must be **3** (F-9), but there is **no
    `AppError::Output` arm** — `Output`/generic errors fall to `_ => 1` (272). K3-3 must add an
    explicit exit-3 arm (or raise `AppError::Exit{code:3}`) for keystore-write/derivation errors;
    do **not** let them reach the fallback.
  - `KeystoreError::WrongPassphrase → 3` (227) is decrypt-only; not reached by keygen.
- **Secret-hygiene test** (K3-3): `tests/redact_boundary.rs` exists as the boundary-test pattern;
  `gen_cmd.rs`'s `no_secret_in_logs` test (tests around gen_cmd.rs:1410) is the template —
  assert the mnemonic/seed/SK bytes (raw and hex) never appear in captured stdout/stderr/logs.

---

## Dependencies

- **`getrandom` is genuinely new** — it is **not** in the workspace `[workspace.dependencies]`
  (`Cargo.toml`). Everything else keygen needs is already there: `blst`, `sha2` (Sha256+Sha512),
  `pbkdf2`, `hmac`, `scrypt`, `aes`, `ctr`, `zeroize`, `unicode-normalization`, `hex`, `serde`,
  `serde_json`, `clap`(env), `rpassword`, `libc`. No `uuid`, no `hkdf`, no `bip39` crate (all
  hand-rolled per D-1).

## Implications for our implementation

1. **K2-1 makes the keystore model bidirectional** by adding `Serialize` + constructors (typed
   `crypto`, fields in declaration order) — or a parallel encrypt-side struct set — and by
   exposing `normalize_passphrase` + the scrypt `derive_key` for shared use. This is the single
   largest structural change; it is the reason K2-1 is 3 pts.
2. **K2-2 needs a generic atomic 0600 writer with overwrite-refusal.** Extract one from
   `core::output` (`open_0600` → `pub`, switch to `create_new` for refuse-overwrite) rather than
   forking the logic. Keystore filename per `eip-2335-keystore.md`.
3. **K3 needs a new confirm-with-min-length passphrase source** (F-7) — the trait is reusable,
   the concrete `TermPromptSource` is single-prompt. Model the injectable TTY-opener seam on
   `TermPromptSource::with_opener` for tests.
4. **K3-3 must add exit-code arms** so keystore-write/derivation errors map to 3 (not the
   fallback 1); mnemonic/passphrase/TTY errors map to 2; SIGINT/ceremony-abort map to 4 via
   `Aborted`.
5. **`key` nested subcommand** slots into `root_command()` cleanly; reuse `global_cancel()` and
   the `gen` progress/summary/banner patterns. The withdrawal pubkey is derived but **unused by
   v1 credentials** (consistent with F-14 deferral) — say so in code comments so it doesn't read
   as dead code.
