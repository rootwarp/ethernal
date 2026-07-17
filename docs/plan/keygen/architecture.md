# Architecture — Validator Key Generation (`key new` / `key recover`, K5 `gen`)

**Inputs:** [`prd.md`](prd.md) (binding requirements + RESOLVED open questions), [`overview.md`](overview.md)
(locked decisions), [`research/`](research/) (specs + `existing-code-map.md` extension points).
This doc owns the *module boundaries, signatures, dependency direction, and secret lifecycle*.
It is written against the code as it exists (verified `file:line` below), not against the research prose.

## The crux: dependency direction

Verified from the `Cargo.toml`s: `core` and `keystore` are **siblings** — neither depends on the
other; the bin depends on both; `signer → tx`. There are **no cycles**, and keygen must not add one.

```
bins/eth-deposit ──▶ core        (bip39, hd, entropy, output, deposit, bls)
        │        ──▶ keystore    (encrypt, decrypt, passphrase)         core ✗──▶ keystore
        │        ──▶ signer ─▶ tx (EIP-55 exposure lives here)          keystore ✗──▶ core
```

Two design forces follow, and they drive every placement decision below:

1. **`keystore` must not gain a `→ core` edge.** Reusing `core`'s Entropy trait or `core::output`'s
   atomic writer *from inside* `keystore` would pull `blst` and the whole deposit pipeline into the
   pure EIP-2335 crate. So: **`keystore::encrypt` is a pure function** — it takes already-drawn
   `salt`/`iv`/`uuid` bytes and returns JSON bytes + a filename. Randomness is drawn in the bin (via
   `core::entropy`) and passed down; the **filesystem write happens in the bin** (via a new generic
   `core::output` primitive). `keystore` owns *format + crypto*, never RNG or the write syscall.
2. **Shared components (`EnvSource`, `PassphraseSource`, `OutputError`, `CancelToken`) keep their
   behavior for `gen`.** Keygen composes them; it never edits them. The F-7 8-char minimum is
   keygen-only (§Passphrases), never a change to the shared `EnvSource` that `gen`'s decrypt path
   relies on accepting any non-empty value.

## Module map

| Crate / module | New/changed | Responsibility |
|---|---|---|
| `core::entropy` | **new** | `Entropy` trait + `OsEntropy` (`getrandom`). The one new dep (D-1). |
| `core::bip39` | **new** | Wordlist (embedded+pinned), entropy↔mnemonic, checksum, `to_seed`. Pure, Zeroizing. |
| `core::hd` | **new** | EIP-2334 path model; EIP-2333 master/child/path derivation via `blst`. Pure. |
| `core::output::write_new_0600` | **new pub fn** | Generic atomic `0600` write, `create_new` (refuse overwrite). Reused by the bin. |
| `core::deposit::eth1_withdrawal_credentials` | **new pub fn** | `0x01 ‖ 0x00×11 ‖ addr20` constructor (K5). |
| `keystore::crypto` | **refactor** | Extract `normalize_passphrase`, scrypt-derive, `Aes128Ctr`, checksum to `pub(crate)`; shared by decrypt (existing) + encrypt (new). |
| `keystore::encrypt` | **new** | EIP-2335 v4 scrypt keystore *creation*: `Serialize` structs (declaration-order), UUID-v4 format, filename. Pure. |
| `keystore::passphrase::NewKeystorePassphrase` | **new** | Confirm-twice + ≥8-char interactive source (F-7). New `PassphraseSource` impl. |
| `signer::eip55` exposure | **changed vis** | Make EIP-55 checksum/validation `pub` for K5 `--withdrawal-address`. |
| `bins/eth-deposit/src/key_cli.rs` | **new** | `key` clap namespace, `KeyConfig`, TTY guards, dir/count validation. |
| `bins/eth-deposit/src/key_cmd.rs` | **new** | `run_key_new/recover_with_deps` (injectable `KeyDeps`): entropy→bip39→hd→encrypt→write, ceremony, SIGINT. |
| `bins/eth-deposit/src/main.rs` | **changed** | Add nested `key` subcommand + dispatch. |
| `bins/eth-deposit/src/gen_cli.rs` / `gen_cmd.rs` | **changed** | K5: `--withdrawal-address`, require-choice gate, thread creds into `Request`. |
| `bins/eth-deposit/src/errors.rs` | **changed** | Typed arms for keygen-owned errors; call-site `Exit{3}` for the shared write error. |

## Public API sketches

### `core::entropy` (K1-3) — the only new dependency

```rust
pub trait Entropy: Sync {
    /// Fills `buf` with cryptographically secure random bytes.
    fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError>;
}
pub struct OsEntropy;                       // getrandom::fill; the release RNG (S-4)
impl Entropy for OsEntropy { /* ... */ }
#[derive(Debug, thiserror::Error)] pub enum EntropyError { #[error("entropy: {0}")] Os(String) }
```

`OsEntropy` is the **only** production `Entropy`. The deterministic impl (`FixedEntropy`) lives in the
bin's `#[cfg(test)]` (§Testability) — **no hidden entropy flag in the release binary** (S-4). Neither
`bip39` nor `keystore::encrypt` reference `Entropy`; the bin draws bytes and passes them down.

### `core::bip39` (K1-1) — pure, Trezor-vector-gated

```rust
pub const WORDLIST: &str = include_str!("english.txt");     // pinned by sha256 test (2f5eed53…)
/// 16/20/24/28/32-byte entropy → space-joined mnemonic (24 words for 32 bytes). Zeroizing output.
pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<Zeroizing<String>, Bip39Error>;
/// Validate word membership + checksum; accept 12/15/18/21/24 words (NFKD, lowercase, ws-collapse).
pub fn validate_mnemonic(mnemonic: &str) -> Result<(), Bip39Error>;
/// seed = PBKDF2-HMAC-SHA512(NFKD(mnemonic), NFKD("mnemonic"+passphrase), 2048, 64).
pub fn to_seed(mnemonic: &str, mnemonic_passphrase: &[u8]) -> Zeroizing<[u8; 64]>;

#[derive(Debug, thiserror::Error)] pub enum Bip39Error {   // all user-input → exit 2
    #[error("bip39: unknown word {0:?}")] UnknownWord(String),
    #[error("bip39: word count {0} not in {{12,15,18,21,24}}")] WordCount(usize),
    #[error("bip39: checksum mismatch")] Checksum,
}
```

Adds `pbkdf2`, `hmac`, `unicode-normalization` to `core`'s manifest — **all already
`[workspace.dependencies]`**, so D-1 ("getrandom only") holds. `key new` draws 32 bytes of `Entropy`
into a `Zeroizing<[u8;32]>` and calls `entropy_to_mnemonic`; `key recover` calls `validate_mnemonic`
first. Both then call `to_seed`; the mnemonic passphrase (raw flag / env / prompt — see Design notes
(c)) is captured *before* derivation on both paths, independent of the `key new` mnemonic re-entry
ceremony (F-12).

### `core::hd` (K1-2) — EIP-2333/2334 via `blst`, pure

```rust
pub struct KeyPath(Vec<u32>);
impl KeyPath {
    pub fn signing(index: u32) -> Self;      // m/12381/3600/index/0/0
    pub fn withdrawal(index: u32) -> Self;   // m/12381/3600/index/0   (v1-derived, credential-unused)
    pub fn to_string(&self) -> String;       // "m/12381/3600/<i>/0/0"  → keystore `path`
}
/// Opaque EIP-2333 secret key; wraps blst::min_pk::SecretKey (self-zeroizes on drop).
pub struct DerivedSk(/* blst SecretKey */);
impl DerivedSk {
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]>;   // big-endian; feeds new_signer + keystore secret
    pub fn public_key(&self) -> [u8; 48];            // compressed G1; keystore `pubkey`
}
pub fn derive_master(seed: &[u8]) -> Result<DerivedSk, HdError>;   // handles blst's 32-byte-min Result
pub fn derive_child(parent: &DerivedSk, index: u32) -> DerivedSk;  // infallible (EIP-2333)
pub fn derive_path(seed: &[u8], path: &KeyPath) -> Result<DerivedSk, HdError>;  // fold derive_child

#[derive(Debug, thiserror::Error)] pub enum HdError {  // crypto → exit 3
    #[error("hd: derive master: {0}")] Master(String),
}
```

`derive_master`/`derive_child` are gated directly by the four official EIP-2333 vectors (compare
`to_bytes()` hex — see `research/eip-2333-2334.md`). EIP-2334 has no vectors of its own; correctness
is proven downstream by the deposit pubkeys (G2 / K4 E2E). `derive_master` calls `blst`'s
`derive_master_eip2333`, whose `Result` is handled even though a 64-byte seed never trips the guard.

### `keystore::encrypt` (K2-1) — pure EIP-2335 v4 writer

```rust
pub struct EncryptInput<'a> {
    pub secret: &'a [u8],        // 32-byte BLS SK (big-endian)
    pub password: &'a [u8],      // raw keystore passphrase; normalized inside
    pub path: &'a str,           // "m/12381/3600/<i>/0/0"
    pub pubkey: &'a [u8],        // 48-byte signing pubkey → `pubkey` field
    pub salt: [u8; 32],          // drawn by the bin (Entropy); spec-vector-injectable
    pub iv: [u8; 16],
    pub uuid_bytes: [u8; 16],    // formatted to uuid-v4 internally
}
/// Encrypt to an EIP-2335 v4 scrypt keystore. Returns the serialized JSON bytes.
pub fn encrypt(input: &EncryptInput) -> Result<Vec<u8>, KeystoreError>;
/// staking-deposit-cli filename: keystore-m_12381_3600_<i>_0_0-<unixtime>.json
pub fn keystore_filename(path: &str, unix_secs: i64) -> String;
```

Internally: `crypto::normalize_passphrase` → `crypto::derive_scrypt(n=262144,r=8,p=1,dklen=32)` →
`Aes128Ctr(dk[0..16], iv)` over `secret` → `sha256(dk[16..32] ‖ ct)` checksum → `Serialize` struct
whose fields are declared in EIP-2335 order (`crypto{kdf,checksum,cipher}` · `description` · `pubkey`
· `path` · `uuid` · `version`), reproducing the spec vector's bytes (serde emits fields in
declaration order — the trick `core::output::JsonEntryOut` already uses, `output.rs:58`). `description`
is `""` for real output. **Parallel encrypt-side structs**, not a retrofit of the loosely-typed
`Deserialize` `Envelope` (whose `crypto` is `serde_json::Value`, `keystore.rs:97`) — a purpose-built
`Serialize` struct is the reliable way to pin byte order. The shared `keystore::crypto` module makes
encrypt and decrypt agree exactly (the round-trip gate, M-K2).

### `keystore::passphrase::NewKeystorePassphrase` (K2/K3) — confirm + min-length

```rust
pub struct NewKeystorePassphrase { /* writer + injectable /dev/tty opener, per TermPromptSource */ }
impl NewKeystorePassphrase { pub fn new<W: Write + Send + 'static>(w: W) -> Self; }
impl PassphraseSource for NewKeystorePassphrase {   // prompt twice, require match, require len ≥ 8
    fn read(&self) -> Result<Vec<u8>, KeystoreError>;
}
/// Keygen-only length gate, applied to the --passphrase-env path too (never edits EnvSource).
pub fn require_min_len(pw: &[u8], min: usize) -> Result<(), KeystoreError>;  // → exit 2
```

Reuses the existing `PassphraseSource` trait + the `with_opener` test seam (`passphrase.rs:81`). The
existing `TermPromptSource` prompts **once** and is left untouched for `gen`. The 8-char minimum is
enforced by this source (interactive) and by `require_min_len` on the env path — **keygen-only**, so
`gen`'s decrypt path keeps accepting any non-empty passphrase.

### `core::output::write_new_0600` (K2-2) — generic atomic writer, refuse-overwrite

```rust
/// Atomic 0600 write with overwrite refusal: create_new tmp → write → fsync → rename.
/// Errors if `final_path` already exists (F-4). Removes the tmp on any failure.
pub fn write_new_0600(final_path: &Path, bytes: &[u8]) -> Result<(), OutputError>;
```

Extracted alongside `FsWriter` (the single audited atomic-write path). Unlike the private `open_0600`
(`output.rs:163`, which `create(true).truncate(true)` **overwrites**), this uses
`OpenOptions::create_new(true)` on both tmp and final so an existing keystore is never clobbered.
`OutputError` gains `AlreadyExists`. The bin composes: `encrypt(...)` → `write_new_0600(dir.join(name), &bytes)`.

### `signer` EIP-55 exposure (K5)

```rust
// crates/signer/src/lib.rs — new pub export
pub use local::eip55_checksum;                              // was pub(crate) (local.rs:293)
/// Strict EIP-55: strip 0x, hex-decode, require 20 bytes, require input == eip55_checksum(bytes).
/// Rejects lowercase (F-13, binding). Returns the raw 20 bytes.
pub fn validate_eip55_address(s: &str) -> Result<[u8; 20], String>;
```

The bin already depends on `signer`; `gen_cli` calls `validate_eip55_address`. No new crate edge, no
new dep (keccak lives in `signer` via `sha3`).

## Exit-code mapping (`errors.rs`, K3-3)

Keygen-**owned** errors get typed variants + explicit `exit_code_for` arms (repo style: operators grep
these, the map distinguishes them — `error.rs:8`). The keystore **write** reuses the shared
`OutputError`, which **must stay `→ 1` for `gen`** (pinned by `gen_cmd.rs`'s `writer_error_exit1`), so
it is mapped **at the call site**, not globally.

| Source | Class | Exit | Mechanism |
|---|---|---|---|
| `Bip39Error` (bad word/count/checksum) | user input | **2** | new `AppError::Bip39(_) => 2` arm |
| passphrase < 8, non-TTY `new`, bad `--count`, bad address | user/config | **2** | `AppError::Exit{code:2}` |
| `HdError`, `keystore::encrypt` failure | crypto | **3** | new arms (`Hd(_) => 3`; `KeystoreError` encrypt variant `=> 3`) |
| keystore **write** (`OutputError`, incl. overwrite-refusal) | keystore-write | **3** | **call-site** `map_err(|e| AppError::Exit{msg, code:3})` |
| ceremony mismatch/abort, SIGINT | user abort | **4** | `AppError::Aborted(_) => 4` (existing) |

`AppError::Output(_)` stays at the `_ => 1` fallback — untouched, so `gen`'s behavior is unchanged.
(A `keystore`-owned write path would instead give a clean typed `KeystoreError` write arm — noted as a
tradeoff in Design notes fork (a).)

## Secret lifecycle & zeroization

```
[key new] OsEntropy.fill ─▶ Zeroizing<[u8;32]> entropy ─bip39::entropy_to_mnemonic─▶ Zeroizing<String> mnemonic
[key recover] TTY/stdin ─▶ Zeroizing<String> mnemonic ─bip39::validate_mnemonic─┘        │
                                                                                          │  key new CEREMONY (TTY only):
                                                                                          │   display once → require full re-entry
                                                                                          │   → compare → mismatch/SIGINT = Aborted(4)
                                                                                          ▼   (no keystore written until match)
                                    bip39::to_seed(mnemonic, mnemonic_passphrase) ─▶ Zeroizing<[u8;64]> seed
                                                                                          │ hd::derive_path
                                                                                          ▼
                                              hd::DerivedSk (blst SecretKey, self-zeroizing on drop)
                                                    │ .to_bytes()                    │ .public_key() → [u8;48]
                                                    ▼                                ▼
                                     Zeroizing<[u8;32]> sk_bytes ──▶ bls::new_signer (copies+zeroizes) → pubkey check
                                                    │
                                                    ▼
        keystore::encrypt{secret=sk_bytes, password=keystore_pass (Zeroizing), salt, iv, uuid, pubkey, path}
                                                    │ normalize → scrypt → AES-128-CTR → sha256 checksum
                                                    ▼
                            Vec<u8> keystore JSON (ciphertext only; plaintext SK never serialized)
                                                    │ core::output::write_new_0600 (create_new tmp → fsync → rename, 0600)
                                                    ▼
                            keystore-m_12381_3600_<i>_0_0-<unixtime>.json
```

**Zeroizing at every hop:** `entropy`, `mnemonic` (String), `seed`, every `sk_bytes`, the keystore
passphrase, and the mnemonic passphrase — all `Zeroizing`; `blst`'s `SecretKey`/`DerivedSk` self-zeroize
on drop; `new_signer` already copies-then-zeroizes its local (`bls.rs:96`). Matches the `keystore::Key`
invariant (S-1).

**S-2 (no secret on stdout/stderr/logs):** the mnemonic reaches the terminal **only** during the `key
new` ceremony, via an injectable TTY writer distinct from stdout/stderr/logger. Seed, SKs, and both
passphrases are never rendered.

**SIGINT & no-partial-file (S-5):** `main` already installs the SIGINT handler →
`global_cancel().cancel()` (`main.rs:56-66`); pass the token into the key handlers like the others.
`CancelToken` checkpoints sit **at each prompt** and **before each keystore write**. The guarantee is
**per-file**: `write_new_0600`'s `create_new` tmp + rename means no half-written or `.tmp` artifact,
and overwrite-refusal means no clobber. With `--count N`, SIGINT after *k* files leaves *k* complete,
valid keystores (not whole-run transactionality). On `key new`, the ceremony completes before *any*
write, so SIGINT during it leaves **zero** keystores.

## Data formats

- **Keystore JSON** — EIP-2335 v4 (`research/eip-2335-keystore.md`): `crypto{kdf:scrypt(n=262144,r=8,
  p=1,dklen=32,salt), checksum:sha256, cipher:aes-128-ctr(iv)}` · `description:""` · `pubkey`(48h) ·
  `path:"m/12381/3600/<i>/0/0"` · `uuid`(v4) · `version:4`. UUID v4 hand-formatted from 16 bytes
  (version nibble `4`, variant `10`; `8-4-4-4-12`) — no `uuid` crate (D-1).
- **Filename** — `keystore-m_12381_3600_<i>_0_0-<unixtime>.json` (unix **seconds**; `/`→`_`).
- **Output-dir layout** — `--output-dir DIR` (existing, writable — mirror `gen`'s
  `validate_output_dir`, `gen_cli.rs:325`) holds one signing keystore per validator; `key recover`
  uses `--start-index`/`--count` for the index range. Only the **signing** keystore is written; the
  withdrawal key stays recoverable from the mnemonic (staking-deposit-cli parity).

## K5 — `gen` changes (precise wire points)

1. **Flag** — `gen_cli::command()` adds `--withdrawal-address ADDR` (optional String).
2. **Resolve** — in `load_config`, after existing validations: parse via
   `signer::validate_eip55_address` (exit 2 on bad hex/length/checksum), build the credential with
   `core::deposit::eth1_withdrawal_credentials(addr)` = `0x01 ‖ 0x00×11 ‖ addr20`, store the resolved
   `[u8;32]` on a new `GenConfig::withdrawal_credentials` field.
3. **Require-choice gate (PRD Q2, binding)** — in `load_config`, a conditional check (mirror the
   `--output-dir` check at `gen_cli.rs:205-211`), **not** clap `required(true)`: absent
   `--withdrawal-address` → exit 2 with a clear message, so `--dry-run` and a future 0x00 flag stay
   expressible.
4. **Thread through** — `process_pubkey` uses `cfg.withdrawal_credentials` in the `Request`
   (`gen_cmd.rs:304`) instead of `default_withdrawal_creds()`; downstream SSZ roots + JSON update for
   free (`Request.withdrawal_credentials` flows into both `DepositMessage` and `DepositData`,
   `deposit.rs:101`). `default_withdrawal_creds()` stays as the documented placeholder for the deferred
   0x00 path (F-14) but is unreachable under the gate.

## Testability

- **Injection seams.** `core::bip39`/`core::hd`/`keystore::encrypt` are pure — unit-tested by passing
  bytes directly (no trait needed): Trezor vectors for bip39 (incl. the 24-word `abandon×23 art` and a
  `TREZOR`-passphrase case), the four EIP-2333 vectors for hd, and the EIP-2335 scrypt spec vector for
  encrypt (inject the vector's `salt`/`iv`/`uuid_bytes`+password+secret → assert the `crypto` section
  byte-for-byte, then decrypt through the existing `Loader` and assert round-trip — M-K2).
- **Bin seam.** `run_key_new_with_deps(deps, cancel)` / `run_key_recover_with_deps(...)` take a
  `KeyDeps { entropy: &dyn Entropy, keystore_pw: &dyn PassphraseSource, mnemonic_src, tty_writer,
  writer, logger, ... }` — the `GenDeps` pattern (`gen_cmd.rs:46`). Tests inject `FixedEntropy`
  (deterministic mnemonic + salt/iv/uuid), fake prompt sources, and buffers. `FixedEntropy` lives in
  the bin's `#[cfg(test)]` — reachable from unit tests only, **never the release binary** (S-4).
- **Secret-hygiene (G5/S-2).** Model on `gen_cmd.rs`'s `no_secret_in_logs` (`:1410`) and
  `tests/redact_boundary.rs`: run the deps-seam with a fixed mnemonic, route the one-time mnemonic
  display to the injectable **TTY writer**, and assert the mnemonic/seed/SK bytes (raw + hex) never
  appear in the **stdout/stderr/logger** buffers.
- **E2E fixture chain (K4-1).** `key recover` with the fixed test mnemonic `abandon…about` (12 words)
  + `--mnemonic-passphrase-env` = `TREZOR` → seed `c55257c3…463b04` = EIP-2333 case-0 seed → known
  master/child SKs → committed expected **signing + withdrawal pubkeys per index** → `gen` (BLS-verify
  on) → validated deposit data. One fixture chains BIP-39 → EIP-2333 → EIP-2335 → deposit. No hidden
  flags: binary-level determinism comes from `key recover` with the fixed mnemonic, not entropy
  injection (PRD S-4 / Q4).

## Design notes (forks recorded per the gate instruction)

- **(a) Keystore write location — chose `core::output` primitive + bin composition over
  `keystore::write`.** *Chosen* because it keeps the single audited atomic-write path and avoids a
  `keystore → core` edge (the overriding constraint). *Counter-pressure, stated honestly:* the
  "most-consistent-with-existing-codebase" tiebreaker points the **other way** — `core::output::FsWriter`
  establishes "the format-owning crate owns its atomic writer," and the plan skeleton (`overview.md`
  K2-2) literally names `keystore::write`. The tradeoff: our choice moves the write syscall out of
  `keystore` (which becomes pure format+crypto) and costs a call-site `Exit{3}` mapping for the shared
  `OutputError`; the alternative would keep the write in `keystore` with a clean typed `KeystoreError`
  write arm, at the cost of a new heavy crate dependency. The dependency-direction constraint wins.
- **(b) EIP-55 home — chose `pub` from `signer` over moving to `core`.** The encoder already exists in
  `signer` (which has `sha3`/keccak) and the bin already links `signer`; exposing it adds no dep and no
  edge. *Alternative:* move EIP-55 to `core` and add `sha3` to `core` — rejected because it drags keccak
  into the deposit-core crate for one address helper.
- **(c) `--mnemonic-passphrase` accepts raw value, env var, or prompt — USER DECISION (2026-07-17
  architecture gate).** PRD F-12 fixes the flag *name*; the *how* was architecture's to specify, and the
  gate decided the flag MUST **also accept a raw argv value** (parity precedent: ethstaker-deposit-cli
  takes the mnemonic password as an argument in non-interactive mode). Three input forms, precedence per
  the repo's **flag > env > default** convention:
    1. `--mnemonic-passphrase VALUE` — raw value on argv (flag; highest precedence).
    2. `--mnemonic-passphrase-env VAR` — read from env var `VAR` (env).
    3. `--mnemonic-passphrase` (bare, no value) — interactive prompt; on `key new` the prompt is
       **confirmed** (double-entry), since a mistyped 25th word silently yields unrecoverable keys. The
       confirm applies to this form only — raw and env values are taken as-is.
    4. none — **empty** (default; full staking-deposit-cli parity).
  It stays a *distinct* secret from the keystore passphrase (F-7): no 8-char minimum, empty is valid.
  Unlike the keystore passphrase, the raw-value form is offered here (F-7's passphrase keeps
  prompt-with-confirm or `--passphrase-env` only — it gains no raw form). Whatever the source, the value
  is wrapped in `Zeroizing` on read.
  **Security note (carry into the USER-GUIDE, K4-2):** a raw `--mnemonic-passphrase VALUE` is visible in
  the process table (`ps`) and shell history; the env and prompt forms are recommended, and the raw form
  is documented as a **scripting convenience, not for high-value mnemonics**. This is a recorded user
  decision, not to be relitigated.
- **`key new` vs `key recover` I/O split.** `key new` is **TTY-only**: guard `isatty(0) && isatty(1)`
  at entry (via `libc`, already a bin dep) and exit 2 *before* generating (F-5). `key recover` accepts
  a piped **stdin** mnemonic or a TTY prompt (F-10) — the gate is new-only.
