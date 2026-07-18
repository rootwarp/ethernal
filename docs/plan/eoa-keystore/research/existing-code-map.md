# Research — existing-code map, reuse inventory & dependency placement (EOA keystore)

**Question:** what in `ethernal-keystore`, `ethernal-core`, and `ethernal-signer` is directly
reusable for the v3 EOA writer, what is **EIP-2335-shaped and must not be bent**, and where does the
new BIP-32 module live given the dependency graph?

**Verdict: most of the plumbing is reusable, but three EIP-2335-specific pieces must NOT be reused
and two crates gain a dependency.** Reuse (unchanged): the BIP-39 seed path, the `Entropy` trait,
the scrypt/AES primitives, the atomic `0600` writer, the passphrase sources, and the signer's
keccak/EIP-55/address helpers. **Do not reuse:** `normalize_passphrase` (EIP-2335 NFKD; v3 uses raw
bytes — see `web3-v3-keystore.md`), `checksum_message` (SHA-256; v3 needs a Keccak MAC), and the
`keystore::encrypt` v4 writer + its filename (v3 has a different JSON shape and `UTC--` filename).
Two manifest edits: add **`sha3`** to `ethernal-keystore` (Keccak MAC), and add **`k256`** (+ the
already-present `hmac`/`sha2`) to whichever crate hosts the new BIP-32 module. `getrandom`, `hmac`,
`sha2`, `scrypt`, `aes`, `ctr`, `zeroize`, `hex`, `serde`, `unicode-normalization` are all already
present — **no new third-party crate enters the workspace** (D-1 holds).

---

## Reuse inventory (green = reuse as-is; red = EIP-2335-shaped, do not bend)

### `ethernal-core` — seed, entropy, output (all reusable unchanged)

- **`bip39::to_seed(mnemonic, mnemonic_passphrase) -> Zeroizing<[u8; 64]>`**
  (`core/src/bip39.rs:178`) — **reuse verbatim.** The BIP-39 seed is tree-agnostic; the same seed
  feeds both the BLS (`m/12381/…`) and EOA (`m/44'/60'/…`) trees. This is the mechanical basis of
  the PRD's "cross-recovery" property. Mnemonic passphrase (F-12) is already handled here (raw →
  UTF-8-checked → NFKD salt).
- **`bip39::entropy_to_mnemonic` (`:50`), `validate_mnemonic` (`:106`)** — reuse verbatim for
  `account new` generation and `account recover` validation (F-1, F-11); the 1-based bad-word
  reporting (H1) is already inside.
- **`entropy::{Entropy, OsEntropy}`** (`core/src/entropy.rs:10,17`) — **reuse verbatim** for all
  randomness: BIP-39 entropy, scrypt salt (32 B), AES IV (16 B), UUID (16 B). The injectable trait
  is exactly the S-4 seam the v3 byte-gate needs to pin salt/iv/uuid.
- **`output::write_new_0600(final_path, bytes)`** (`core/src/output.rs:342`, `pub`) — **reuse
  verbatim** for F-4/S-3. It is the H6 link-then-unlink atomic `0600` publisher with
  overwrite-refusal (`create_new`), and — unlike the note in the *BLS* research — it was **already
  extracted and made `pub`** during keygen. The v3 writer calls it directly; no new writer needed.
  (Filename differs — the v3 `UTC--…` name is computed by the caller, see below.)
- **`hd` (`core/src/hd.rs`)** — BLS/`blst` only (EIP-2333). **Not reusable**, but it is the
  structural template for the new secp256k1 module (`KeyPath` newtype, `derive_master`/
  `derive_child`/`derive_path` fold, `DerivedSk` with zeroize-on-drop). Mirror its shape.

### `ethernal-keystore` — crypto primitives (mixed)

- 🟢 **`crypto::derive_scrypt(password, salt, n, r, p, dklen) -> Zeroizing<Vec<u8>>`**
  (`keystore/src/crypto.rs:68`) — **reuse.** Same scrypt profile; already parameterized and already
  hardened (the H7 memory ceiling `128·n·r ≤ 1 GiB`, `p ≤ 16`, `dklen ∈ 32..=128`). Currently
  `pub(crate)` → expose it (or a v3 wrapper) so the EOA writer shares the identical call.
- 🟢 **`crypto::Aes128Ctr` = `ctr::Ctr128BE<aes::Aes128>`** (`crypto.rs:12`) — **reuse.** v3 uses
  the same AES-128-CTR with `dk[0..16]` and the full-16-byte-IV-as-counter semantics. `pub(crate)`
  → expose.
- 🟢 **`encrypt::format_uuid_v4([u8;16]) -> String`** (`keystore/src/encrypt.rs:198`) — **reuse.** v3
  `id` is a UUID v4, identical formatting. `pub(crate)` → expose.
- 🔴 **`crypto::normalize_passphrase` (`crypto.rs:34`) — DO NOT REUSE for v3.** EIP-2335 mandates
  NFKD + control-strip; geth/MetaMask v3 use **raw bytes**. Reusing it breaks cross-tool unlock for
  non-ASCII passphrases (the key finding in `web3-v3-keystore.md`). v3 passes raw passphrase bytes
  to `derive_scrypt`.
- 🔴 **`crypto::checksum_message` (`crypto.rs:113`) — DO NOT REUSE.** Hardcodes `sha2::Sha256`. v3
  needs `mac = keccak256(dk[16..32] ‖ ct)`. Add a small `v3_mac(dk, ct)` over `sha3::Keccak256`
  (the dk-split rule `dk[16..32]` is the same; only the hash changes).
- 🔴 **`encrypt::{EncryptInput, encrypt, KeystoreOut, CryptoOut, …}` (`encrypt.rs`) — DO NOT REUSE.**
  These are EIP-2335 v4 by construction: `crypto.{kdf,checksum,cipher}` as `{function,params,
  message}` objects, top-level `pubkey`/`path`/`uuid`/`version:4`, `secret`/`pubkey` length checks
  of 32/48. v3 needs its **own** `#[derive(Serialize)]` struct set (`crypto.cipher`/`cipherparams`/
  `ciphertext`/`kdf`/`kdfparams`/`mac`, top-level `address`/`id`/`version:3`) — same
  declaration-order-serialization trick, different fields. **This is a new writer**, per PRD F-3.
- 🔴 **`encrypt::keystore_filename` (`encrypt.rs:190`) — DO NOT REUSE.** Produces
  `keystore-<path>-<unixsecs>.json`; v3 needs `UTC--<iso8601>--<address>` (see
  `web3-v3-keystore.md`). New filename function.
- 🟢 **Passphrase sources** (`keystore/src/passphrase.rs`, re-exported in `lib.rs`): **reuse.**
  `NewKeystorePassphrase` (prompt-with-confirm, already enforces the ≥8-byte minimum via
  `require_min_len` / `KEYSTORE_PASSPHRASE_MIN_LEN`), `EnvSource` (`--passphrase-env`),
  `TermPromptSource`, `PassphraseSource` trait — all already exist (the *BLS* research's "prompt
  -with-confirm doesn't exist yet" gap was closed during keygen). F-7/U-2 reuse these verbatim.
  **Reminder:** the ≥8-byte minimum is the **keystore** passphrase's; it does not apply to the
  mnemonic passphrase (F-12), which stays in `bip39::to_seed`.

### `ethernal-signer` — address, keccak, EIP-55 (reusable; some need exposing)

- 🟢 **`eip55_checksum(&[u8; 20]) -> String`** (`signer/src/local.rs:293`, `pub`, re-exported in
  `lib.rs:21`) — **reuse** for the display address (F-15) and, lowercased-without-`0x`, the file
  `address` field.
- 🟡 **`pubkey_address(&VerifyingKey) -> [u8; 20]`** (`local.rs:258`) and **`keccak256(&[u8]) ->
  [u8;32]`** (`local.rs:250`) — **reuse**, but both are `pub(crate)`. Expose them (or a small
  `address_from_verifying_key` helper) so the EOA path computes the address without duplicating the
  `keccak256(uncompressed[1..])[12..]` logic. `to_encoded_point(false)` (uncompressed) is already
  the exact call at `local.rs:259`.
- 🟢 **`SigningKey::from_slice(&[u8])`** — the signer already relies on it enforcing `0 < k < n`
  (`local.rs:101`). The EOA path bridges `Scalar` → 32 bytes → `SigningKey::from_slice` → address
  and (later, in the `sign --keystore` follow-up) into `LocalSigner`.
- 🟢 **`validate_eip55_address(&str)`** (`signer/src/lib.rs:30`) — available if any address input
  needs validating (not needed for v1 create/recover, which derive addresses).

---

## Dependency deltas (exact, cross-checked against Cargo.lock)

Workspace has (Cargo.lock): `k256 0.13.4`, `elliptic-curve 0.13.8`, `hmac 0.12.1`, `sha2 0.10.9`,
`sha3 0.10.9`, `scrypt 0.11.0`, `aes 0.8.4`, `ctr 0.9.2`, `zeroize 1`, `getrandom 0.3`, `hex 0.4`,
`serde`/`serde_json`, `unicode-normalization`. **No new third-party crate is required.** Per-crate:

| Crate | Has already | Needs added | For |
|---|---|---|---|
| `ethernal-keystore` | scrypt, aes, ctr, hmac, sha2, zeroize, hex, serde | **`sha3`** | v3 Keccak-256 MAC |
| host of BIP-32 module | (depends on host) | **`k256`** (+ `hmac`, `sha2` if not present) | secp256k1 scalar/point + HMAC-SHA512 |

**BIP-32 module placement is a Stage-4 (architecture) decision — here is the constraint.** The
module needs three things together: `k256` (Scalar/ProjectivePoint), `hmac`, and `sha2::Sha512`.
No existing crate has all three:

- `ethernal-core` — has `hmac` + `sha2`, **no `k256`**. (Also the natural sibling to `core::hd`.)
- `ethernal-signer` — has `k256` (+ `sha3`), **no `hmac`/`sha2`**.
- `ethernal-keystore` — has `hmac` + `sha2`, **no `k256`** (and is gaining `sha3`).

So exactly one dependency edge is added wherever it lands. **Recommendation:** put it in
`ethernal-core` as `core::hd_secp256k1` (or `core::bip32`), mirroring `core::hd`, and add `k256` to
`core` — keeps both HD trees side-by-side in one crate, and `core` already owns `bip39::to_seed`
that feeds it. Adding `k256` to `core` is the smallest conceptual change (one derivation crate). The
alternative (put it in `signer` next to the address code, add `hmac`+`sha2` there) couples
derivation to the signer and adds two edges. Final call is Stage 4's; both compile.

---

## Exit-code / error mapping (reuse the existing contract)

The exit-code contract (F-9) and its arms already exist from keygen — the EOA path reuses them:
`AppError::Exit{code:2}` for user/config (bad mnemonic word/count, passphrase < 8, unwritable
dir, TTY guard), `AppError::Exit{code:3}` / keystore-write errors for crypto/keystore-write, and
`AppError::Aborted → 4` for SIGINT/ceremony-abort (F-6/S-5). A new `KeystoreError` variant for v3
encrypt (or reuse `Encrypt`) maps to 3. No new exit-code plumbing beyond wiring the `account`
handlers to the existing map. The SIGINT handler + `global_cancel()` and the `CancelToken`
(`core/src/cancel.rs`) are already installed in `main` — pass `cancel` into the `account` handlers
like the others.

## Implications for our implementation

1. **New `keystore::encrypt_v3` module** (parallel to `encrypt`): its own `EncryptInput`
   (secret 32 B, raw password, `address`, salt/iv/uuid, **scrypt params**), its own v3 Serialize
   structs, `v3_mac` over `sha3::Keccak256`, reusing `derive_scrypt` + `Aes128Ctr`. Add `sha3` to
   the crate manifest. Do **not** call `normalize_passphrase` or `checksum_message`.
2. **New `core::hd_secp256k1`** hand-rolling BIP-32 over `k256` (see `bip32-secp256k1.md`); add
   `k256` to `core`. Zeroize scalars + chain codes (S-1).
3. **Expose (make `pub`)**: `crypto::derive_scrypt`, `crypto::Aes128Ctr`, `encrypt::format_uuid_v4`
   in `ethernal-keystore`; `keccak256` + `pubkey_address` (or an `address_from_verifying_key`) in
   `ethernal-signer`.
4. **Reuse verbatim**: `bip39::to_seed`, `entropy::OsEntropy`, `output::write_new_0600`, the four
   passphrase types + `require_min_len`, `eip55_checksum`.
5. **`account` namespace** slots into `root_command()` exactly like the nested `key` group (U-3):
   `Command::new("account").subcommand_required(true).subcommand(account_new::command())
   .subcommand(account_recover::command())`. Reuse the `key` group's flag-schema, progress/summary,
   and passphrase-source-injection patterns.
