# Phase K2 — Keystore creation

**Theme:** Make the EIP-2335 keystore model bidirectional (pure scrypt-v4 writer), add a generic atomic
overwrite-refusing 0600 writer to `core`, and add a confirm-with-minimum passphrase source. Stream B —
overlaps K1/K3.
**Issues:** K2-1, K2-2, K2-3 · **Points:** 5 · **Execution:** overlaps K1/K3 (before K3-2 consumes them).
**Milestone gate — M-K2:** the EIP-2335 scrypt **spec vector reproduced byte-for-byte** (injected
salt/iv/uuid, non-ASCII NFKD password); the created keystore round-trips through the **existing** decrypt
`Loader`; wrong passphrase rejected; `write_new_0600` refuses to overwrite.

Signatures from [`architecture.md`](../architecture.md) §"Public API sketches"; the EIP-2335 spec vector
from [`research/eip-2335-keystore.md`](../research/eip-2335-keystore.md) §"Spec scrypt test vector";
extension points from [`research/existing-code-map.md`](../research/existing-code-map.md).

---

## K2-1 — `keystore::crypto` refactor + `keystore::encrypt` — pure EIP-2335 v4 scrypt writer

**Points:** 3 · **Stream:** B · **Depends on:** — · **Milestone:** M-K2

**Goal:** Add a pure EIP-2335 v4 scrypt keystore *writer* that byte-matches the spec vector and
round-trips through the existing decrypt `Loader`, by extracting the shared crypto primitives so encrypt
and decrypt agree exactly. `encrypt` takes already-drawn `salt`/`iv`/`uuid` bytes (no `Entropy`, no
`keystore → core` edge). Satisfies F-3 (EIP-2335 v4 scrypt, Loader round-trip), C-1/C-3/G4 (spec vector +
filename), D-1 (no `uuid` crate). This is the single largest structural change (hence 3 pts).

**Implementation notes**
- Extract the reusable decrypt-side crypto into a shared `pub(crate)` module `crates/keystore/src/crypto.rs`
  (or `pub(crate)` in `keystore.rs`): `normalize_passphrase` + `is_stripped_control` (`keystore.rs:298-313`),
  the scrypt derive (`derive_key`, `keystore.rs:317`, `log_n = n.trailing_zeros()`), the `Aes128Ctr =
  Ctr128BE<Aes128>` type (`keystore.rs:23`), and the `sha256(dk[16..32] ‖ ct)` checksum
  (`keystore.rs:264-267`). Decrypt keeps using them unchanged — this is what makes encrypt/decrypt agree
  (the round-trip gate).
- New `crates/keystore/src/encrypt.rs`; register `pub mod encrypt;` in `crates/keystore/src/lib.rs`.
- Public API (architecture §`keystore::encrypt`): `EncryptInput<'a>{ secret, password, path, pubkey, salt:
  [u8;32], iv: [u8;16], uuid_bytes: [u8;16] }`; `encrypt(&EncryptInput) -> Result<Vec<u8>, KeystoreError>`;
  `keystore_filename(path: &str, unix_secs: i64) -> String`.
- Serialization: a **purpose-built `#[derive(Serialize)]` struct set** whose fields are declared in EIP-2335
  order — `crypto{kdf,checksum,cipher}` · `description` · `pubkey` · `path` · `uuid` · `version` — because
  serde emits struct fields in declaration order (the trick `core::output::JsonEntryOut` uses,
  `output.rs:58`). Do **not** retrofit the loosely-typed `Deserialize` `Envelope` (its `crypto` is
  `serde_json::Value`, `keystore.rs:97`) — that cannot pin byte order.
- Internal pipeline: `normalize_passphrase(password)` → scrypt `n=262144,r=8,p=1,dklen=32` → `Aes128Ctr(dk[0..16],
  iv).apply_keystream(secret)` → checksum `sha256(dk[16..32] ‖ ct)`. `description` is `""` for real output.
- UUID v4 hand-formatted from `uuid_bytes` inside `encrypt`: set the version nibble to `4` and variant bits
  to `10`, render `8-4-4-4-12`. No `uuid` crate (D-1).
- Add the EIP-2335 scrypt **spec vector** as a new fixture `crates/keystore/testdata/eip2335-scrypt-vector.json`
  (see Notes — the existing `keystore-scrypt.json` is *not* the spec vector).
- `KeystoreError` gains an encrypt-failure variant (maps to exit 3 at K3-4).

**Acceptance criteria**
- [x] `encrypt` fed the spec vector's `salt` (`d4e56740…`), `iv` (`264daa3f…`), `uuid_bytes` (→
  `1d85ae20-35c5-4611-98e8-aa14a633906f`), password `𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑`, and secret
  `0x000000000019d668…8ce26f` reproduces the vector JSON **byte-for-byte** (crypto section + top-level field
  order) — F-3, C-1, C-3, G4 (research/eip-2335-keystore.md §"Spec scrypt test vector"; fixture
  `crates/keystore/testdata/eip2335-scrypt-vector.json`).
- [x] the encrypt-side normalization is the **same** `normalize_passphrase` as decrypt: `NFKD(𝔱𝔢𝔰𝔱…🔑)`
  → `testpassword🔑` (UTF-8 `7465737470617373776f7264f09f9491`) — F-3, C-1.
- [x] a keystore produced by `encrypt` round-trips through the existing `Loader`: decrypt → recovered secret
  == the input 32-byte SK — F-3, C-3 (M-K2 core criterion).
- [x] decrypting our output with the wrong passphrase → `KeystoreError::WrongPassphrase` — F-3.
- [x] `keystore_filename("m/12381/3600/7/0/0", 1_700_000_000)` == `keystore-m_12381_3600_7_0_0-1700000000.json`
  (unix **seconds**, `/`→`_`) — C-3, F-4.
- [x] UUID formatted from 16 bytes has version nibble `4` and variant `10`, `8-4-4-4-12` shape; no `uuid`
  crate in the dep tree — D-1.
- [x] real output writes `description: ""` and `version: 4`; the plaintext SK is never serialized (only the
  ciphertext `cipher.message`) — F-3, S-1, S-2.

**Test plan**
- Byte-for-byte gate: serialize with the injected spec `salt`/`iv`/`uuid` + password + secret; assert equality
  against `crates/keystore/testdata/eip2335-scrypt-vector.json`.
- Round-trip gate: `encrypt` a known SK with a random-ish salt/iv/uuid, then `Loader::load` and assert the
  secret matches; a wrong-passphrase variant asserts `WrongPassphrase`.
- Unit tests for `keystore_filename` and the UUID formatter; a normalization-equality test proving the shared
  `normalize_passphrase` yields identical bytes on the encrypt and decrypt sides.

**Notes**
- **The existing `crates/keystore/testdata/keystore-scrypt.json` is NOT the EIP-2335 spec vector** — it uses
  `n:4` (a deliberately weak/fast fixture for the decrypt tests), a different salt (`615dbe34…`), iv
  (`8375eae1…`), and uuid (`00000000-…-0001`). K2-1 must **add** the real spec vector (`n:262144`, salt
  `d4e56740…`) as `crates/keystore/testdata/eip2335-scrypt-vector.json` for the byte-for-byte M-K2 gate. Flagged
  in `index.md`.
- `encrypt` is **pure** (takes `salt`/`iv`/`uuid_bytes` as parameters) so `keystore` gains no `→ core` edge;
  the bin draws the bytes via `core::entropy` and passes them down.
- Refactor into a shared `crypto.rs` vs `pub(crate)` in `keystore.rs` is an implementation call —
  codebase-consistent choice: one shared module so decrypt and encrypt use the identical primitives.

---

## K2-2 — `core::output::write_new_0600` — generic atomic 0600 writer, refuse-overwrite

**Points:** 1 · **Stream:** B · **Depends on:** — · **Milestone:** M-K2

**Goal:** Add a generic atomic `0600` write primitive to `core::output` that **refuses to overwrite** an
existing file, so the bin can compose `encrypt(...) → write_new_0600(...)` without pulling the write syscall
into `keystore`. Satisfies S-3 (atomic 0600, no overwrite) and F-4 (refuse overwrite → exit 3, mapped at the
call site).

**Implementation notes**
- Change `crates/core/src/output.rs`: add `pub fn write_new_0600(final_path: &Path, bytes: &[u8]) ->
  Result<(), OutputError>` alongside the existing `FsWriter`.
- Sequence: `create_new` tmp in the target dir → write → fsync → `rename` to `final_path`; remove the tmp on
  any failure. Use `OpenOptions::create_new(true)` on **both** tmp and final so an existing keystore is never
  clobbered — unlike the private `open_0600` (`output.rs:163`, `create(true).truncate(true)`, which
  overwrites).
- `OutputError` gains an `AlreadyExists` variant.
- Leave `FsWriter` / the deposit-data write path (`Writer`, `open_0600`, `deposit_data-<ts>.json`) untouched —
  `gen`'s behavior must not change (its `OutputError` stays `→ exit 1`, K3-4/R2).

**Acceptance criteria**
- [x] `write_new_0600` writes `bytes` atomically at mode `0600` (tmp → fsync → rename) — S-3, F-4.
- [x] a second `write_new_0600` to an existing `final_path` returns `OutputError::AlreadyExists` (no clobber) —
  F-4, S-3.
- [x] a failure between create and rename leaves **no** `.tmp` artifact behind — S-5, S-3.
- [x] the existing `FsWriter` / deposit-data path is unchanged; `gen`'s goldens and `writer_error_exit1` still
  pass — regression (architecture §Exit-code mapping, R2).

**Test plan**
- Unit tests in `output.rs`: write to a fresh temp path → assert `0600` mode and contents; write again → assert
  `AlreadyExists`; simulate a write failure (e.g. unwritable dir) and assert no leftover tmp; run the existing
  `output.rs` tests to confirm `FsWriter` is untouched.

**Notes**
- The bin composes the write: `encrypt(...)` returns the JSON bytes, then `write_new_0600(dir.join(keystore_filename(...)),
  &bytes)`. The write error is mapped to **exit 3 at the call site** (K3-4), because the shared `OutputError`
  must remain `→ 1` for `gen`.

---

## K2-3 — `keystore::passphrase::NewKeystorePassphrase` — confirm-twice + ≥8-char source

**Points:** 1 · **Stream:** B · **Depends on:** — · **Milestone:** M-K2

**Goal:** Add a new `PassphraseSource` that prompts twice, requires the two entries to match, and enforces the
F-7 8-character minimum — plus a `require_min_len` helper for the `--passphrase-env` path. Keygen-only; the
existing single-prompt `TermPromptSource` and `EnvSource` stay untouched so `gen`'s decrypt path keeps
accepting any non-empty passphrase. Satisfies F-7 and U-2.

**Implementation notes**
- Change `crates/keystore/src/passphrase.rs`: add `NewKeystorePassphrase` implementing the existing
  `PassphraseSource` trait (`passphrase.rs:21`); `new<W: Write + Send + 'static>(w: W) -> Self`. `read()` prompts
  twice, requires a match, requires len ≥ 8.
- Add `pub fn require_min_len(pw: &[u8], min: usize) -> Result<(), KeystoreError>` (→ exit 2) for the
  `--passphrase-env` path — enforced **only** by keygen, never by editing `EnvSource`.
- Reuse the private `with_opener` `/dev/tty` seam pattern (`passphrase.rs:81`) for testability.
- Do **not** modify `EnvSource` (`passphrase.rs:28`) or `TermPromptSource` (`passphrase.rs:63`); the single-prompt
  behavior stays for `gen`.

**Acceptance criteria**
- [x] `NewKeystorePassphrase::read` prompts twice, rejects a mismatch, and rejects `< 8` chars with a clear
  message — F-7, U-2, F-16.
- [x] `require_min_len(pw, 8)` enforces the ≥8 minimum on the `--passphrase-env` path (keygen-only) — F-7.
- [x] `EnvSource` and `TermPromptSource` are unchanged; a single-prompt read still accepts any non-empty
  passphrase (`gen` decrypt path unaffected) — architecture §"Shared components keep their behavior".
- [x] the new source is tested through the injectable `with_opener` seam (no real terminal) — testability.

**Test plan**
- `#[cfg(test)]` using `with_opener` with a scripted fake tty: matching entries → `Ok`; mismatched entries →
  `Err`; a 7-char entry → `Err`, an 8-char entry → `Ok`. Boundary test for `require_min_len` (7 → `Err`, 8 →
  `Ok`). A test asserting `TermPromptSource` still prompts once.

**Notes**
- The 8-char minimum is the keygen keystore passphrase (F-7) only — it must **not** apply to the mnemonic
  passphrase (F-12, empty valid) nor to `gen`'s decrypt passphrase.
