# Architecture — EOA Keystore Generation (`account new` / `account recover`)

**Inputs:** [`prd.md`](prd.md) (approved, two binding vetoes — Q1 new `account` namespace, Q3
`sign --keystore` deferred), [`research/`](research/) (D-1 verdict + `existing-code-map.md`
extension points + `web3-v3-keystore.md` byte rules), and the sibling
[`../keygen/architecture.md`](../keygen/architecture.md) whose module discipline this doc mirrors.
This doc owns the *module boundaries, real signatures, dependency-graph delta, and secret
lifecycle*. It is written against the code as it exists (verified `file:line` below), not the
research prose. Every design decision cites the requirement IDs (F-\*/S-\*/C-\*) it satisfies.

---

## The crux: dependency direction (unchanged, one edge added per crate)

Verified from the `Cargo.toml`s: `core`, `keystore`, and `signer` are **siblings**; the bin depends
on all three; `signer → tx`. There are **no crate→crate edges** among `core`/`keystore`/`signer`,
no cycles, and this feature must not add one.

```
bins/ethernal ──▶ core        (bip39, hd, entropy, output;  + NEW core::hd_secp256k1)
        │      ──▶ keystore    (crypto, encrypt, passphrase; + NEW keystore::encrypt_v3)
        │      ──▶ signer ─▶ tx (keccak/EIP-55/address)      core ✗──▶ keystore   keystore ✗──▶ core
                                                             keystore ✗──▶ signer  core ✗──▶ signer
```

Dependency-graph **delta** (all internal edges stay exactly as-is; only third-party edges grow, and
only by enabling features / adding already-vendored crates — D-1 holds, no new third-party crate):

| Crate | Manifest change | Why |
|---|---|---|
| `ethernal-core` | **add `k256`** (workspace dep; enable its **`zeroize`** feature — see §S-1) | secp256k1 `Scalar`/`ProjectivePoint` + HMAC-SHA512 (already has `hmac`+`sha2`) for BIP-32 |
| `ethernal-keystore` | **add `sha3`** (workspace dep) | Web3 v3 Keccak-256 MAC |
| `ethernal-signer` | none | one existing helper is exposed (`secret_to_address`); `eip55_checksum` already `pub` |
| `bins/ethernal` | none | new modules only; already links all three crates |

Three design forces, inherited from the BLS side and driving every placement below:

1. **`keystore` stays pure format+crypto — no `→ core`, no `→ signer` edge.** The v3 writer takes
   already-drawn `salt`/`iv`/`uuid` **and the 20-byte Ethereum address** as inputs and returns JSON
   bytes; it never draws RNG, never touches the filesystem, and never learns about `k256` or the
   public key. Randomness is drawn in the bin (via `core::entropy`); the **address is computed in the
   bin** (via `signer`); the **write happens in the bin** (via `core::output::write_new_0600`). This
   is the same purity the EIP-2335 `keystore::encrypt` already has (`encrypt.rs:34`).
2. **BIP-32 is a derivation primitive, so it lives in `core` next to `core::hd`.** `core` already
   owns `bip39::to_seed` (the seed that feeds it) and both `hmac`+`sha2`; adding `k256` is the one
   new edge. Putting it in `signer` (the alternative) would add two edges (`hmac`+`sha2`), couple
   pure math to the tx-signing crate, and split the two HD trees across crates (§Design notes (a)).
3. **The `account` path reuses the BLS ceremony/mnemonic/passphrase plumbing in place**, composing
   it — never editing its behavior. The differences (secp256k1 derivation, v3 format, `UTC--`
   filename, address-not-pubkey identity) are isolated in new modules; the shared front half
   (entropy→mnemonic→passphrase→ceremony→seed) is reused (§CLI wiring, §Design notes (c)).

## Module map

| Crate / module | New/changed | Responsibility |
|---|---|---|
| `core::hd_secp256k1` | **new** | Hand-rolled BIP-32 secp256k1 over `k256` (D-1). BIP-44 path model, master/child/path derivation, canonical-scalar + chain-code zeroization. Pure. |
| `keystore::crypto::v3_mac` | **new pub(crate) fn** | `keccak256(dk[16..32] ‖ ct)` over `sha3::Keccak256` (F-3). Sits beside the EIP-2335 `checksum_message` (SHA-256) — v3 does **not** reuse it (C-4 sibling). |
| `keystore::encrypt_v3` | **new** | Web3 Secret Storage **v3** scrypt writer: own `Serialize` structs, raw passphrase (no NFKD), parameterized scrypt, `UTC--` filename. Pure. |
| `keystore` reuse | **vis unchanged** | `crypto::derive_scrypt`, `crypto::Aes128Ctr`, `encrypt::format_uuid_v4` are already `pub(crate)`; `encrypt_v3` is in-crate, so they need **no** new visibility (refines the research note that said "make pub"). |
| `signer::secret_to_address` | **new pub fn** | `&[u8;32] → Result<[u8;20]>` = `SigningKey::from_slice` (0<k<n guard, F-2) → `pubkey_address`. Factored from `LocalSigner::address` (`local.rs:140`). `eip55_checksum` already `pub` (`lib.rs:21`). |
| `bins/ethernal/src/account_cli.rs` | **new** | `account` clap namespace, `AccountConfig`, TTY guard, dir/count/index validation — mirrors `key_cli`, reuses its shared helpers. |
| `bins/ethernal/src/account_cmd.rs` | **new** | `run_account_new/recover_with_deps` (injectable `AccountDeps`): entropy→bip39→hd_secp256k1→encrypt_v3→write, ceremony, SIGINT. Owns only the per-index derive/encrypt/filename/display loop. |
| `bins/ethernal/src/{key_cli.rs,key_cmd.rs}` | **changed vis** | Widen a handful of shared items to `pub(crate)` for reuse (no behavior change; §CLI wiring). |
| `bins/ethernal/src/main.rs` | **changed** | Add nested `account` subcommand + dispatch (mirrors the `key` arm, `main.rs:115`). |
| `bins/ethernal/src/errors.rs` | **changed** | One new arm: `AppError::Bip32(_) => 3` (crypto). Keystore-write stays call-site `Exit{3}`; `encrypt_v3` reuses `KeystoreError::Encrypt` (already → 3). |

## Public API sketches (real signatures)

### `core::hd_secp256k1` — hand-rolled BIP-32 (D-1, F-2, S-1)

```rust
use k256::Scalar;
use zeroize::Zeroizing;

const HARDENED: u32 = 0x8000_0000;

/// A BIP-44 Ethereum account path: m/44'/60'/0'/0/<address_index> (F-2).
/// account' is fixed at 0'; only address_index varies (PRD F-2 / MetaMask "Account i").
pub struct Bip44Path([u32; 5]);
impl Bip44Path {
    pub fn eoa(address_index: u32) -> Self {
        Self([44 | HARDENED, 60 | HARDENED, 0 | HARDENED, 0, address_index])
    }
    pub fn indices(&self) -> &[u32] { &self.0 }
}
impl std::fmt::Display for Bip44Path { /* "m/44'/60'/0'/0/<i>" — path is public, safe to log */ }

/// An extended private key: (secret scalar, 32-byte chain code).
/// Chain codes are secret-equivalent (they permit sibling derivation) and are
/// zeroized like keys (S-1). `Drop` scrubs the scalar (see §S-1 for the k256 caveat).
pub struct ExtendedPrivKey {
    scalar: Scalar,                    // NOT Copy at the struct level; Drop zeroizes it
    chain_code: Zeroizing<[u8; 32]>,
}
impl ExtendedPrivKey {
    /// master: I = HMAC-SHA512("Bitcoin seed", seed); k = parse256(I[..32]), c = I[32..].
    /// Rejects I_L ≥ n (from_repr → None) or I_L == 0. Seed is the existing 64-byte
    /// BIP-39 seed from core::bip39::to_seed (unchanged).
    pub fn master(seed: &[u8]) -> Result<Self, Bip32Error>;

    /// CKDpriv at `index`. Hardened iff index ≥ 2^31: data = 0x00 ‖ ser256(k_par) ‖ ser32(i);
    /// non-hardened: data = serP(point(k_par)) ‖ ser32(i) (33-byte compressed pubkey).
    /// k_i = parse256(I_L) + k_par (mod n); rejects I_L ≥ n or k_i == 0 (BIP-32 skip rule).
    pub fn derive_child(&self, index: u32) -> Result<Self, Bip32Error>;

    /// Folds derive_child over the master key for the whole path.
    pub fn derive_path(seed: &[u8], path: &Bip44Path) -> Result<Self, Bip32Error>;

    /// 32-byte big-endian secret. Feeds signer::secret_to_address and encrypt_v3.secret.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]>;
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Bip32Error {                                    // crypto → exit 3 (mirrors HdError)
    #[error("bip32: derive master: {0}")] Master(String),
    #[error("bip32: invalid child key at index {0} (I_L ≥ n or k_i = 0)")] InvalidChildKey(u32),
}
```

The exact `k256 0.13.4` public API is proven in [`research/bip32-secp256k1.md`](research/bip32-secp256k1.md):
`Scalar::from_repr` (parse `I_L`, `None` iff `≥ n`), `Scalar + Scalar` (mod-n add), `Scalar::is_zero`,
`Scalar::to_bytes`, `ProjectivePoint::GENERATOR * scalar` → `to_encoded_point(true)` (compressed, for
the non-hardened `0/i` levels). Trait imports: `k256::elliptic_curve::ff::PrimeField` and
`::sec1::ToEncodedPoint`. `derive_child` returns `Result` so the BIP-32 `I_L ≥ n`/`k_i = 0` skip rule
(C-1) is a rejection, not a silent wrong key — unreachable on the fixed path but part of the
primitive. Gated by BIP-32 Test Vector 1 + the Ethereum BIP-44 `abandon…about` vector (§Test strategy).

### `keystore::encrypt_v3` — pure Web3 v3 writer (F-3, F-4, C-1, C-4)

```rust
/// scrypt cost parameters, injectable so the CI byte-gate (G3) runs at n=8192
/// while production emits n=262144 (both read-compatible — readers take n from JSON).
#[derive(Clone, Copy)]
pub struct ScryptParams { pub n: u64, pub r: u32, pub p: u32, pub dklen: usize }
impl ScryptParams {
    /// geth-standard / repo profile (F-3). The CLI passes this; the byte-gate injects {n:8192,..}.
    pub const STANDARD: ScryptParams = ScryptParams { n: 262_144, r: 8, p: 1, dklen: 32 };
}

pub struct EncryptV3Input<'a> {
    /// 32-byte secp256k1 secret key (big-endian). Canonicality (0<k<n) is the caller's
    /// job — the bin validates via signer::secret_to_address before calling.
    pub secret: &'a [u8],
    /// RAW keystore passphrase bytes — fed straight to scrypt, NO normalization (C-4).
    /// The passphrase SOURCES already return raw bytes; encrypt_v3 must NOT call
    /// crypto::normalize_passphrase (that is EIP-2335-only; reusing it breaks G1/C-2).
    pub password: &'a [u8],
    /// The 20-byte Ethereum address (from signer). Written lowercase-no-0x to the JSON
    /// `address` field and to the UTC-- filename. Passed in so keystore stays k256-free.
    pub address: [u8; 20],
    pub salt: [u8; 32],          // drawn by the bin (Entropy); injectable for the byte-gate
    pub iv: [u8; 16],
    pub uuid_bytes: [u8; 16],    // formatted to uuid-v4 via encrypt::format_uuid_v4
    pub scrypt: ScryptParams,
}

/// Encrypt to a Web3 Secret Storage v3 scrypt keystore. Returns compact JSON bytes.
/// Pipeline: derive_scrypt(RAW pw, salt, n,r,p,dklen) → AES-128-CTR(dk[0..16], iv) over
/// secret → mac = keccak256(dk[16..32] ‖ ct) → serialize v3 structs. Rejects secret.len()!=32
/// with KeystoreError::Encrypt (→ exit 3). version:3, cipher:aes-128-ctr, kdf:scrypt.
pub fn encrypt_v3(input: &EncryptV3Input<'_>) -> Result<Vec<u8>, KeystoreError>;

/// geth filename: UTC--<YYYY>-<MM>-<DD>T<HH>-<MM>-<SS>.<9-nanos>Z--<40-hex-addr-no-0x> (F-4).
/// Pure: converts unix time → UTC calendar via a hand-rolled civil_from_days (no chrono/time
/// in the workspace — see §Filename). Colons rendered as dashes (filesystem-safe).
pub fn v3_filename(address: &[u8; 20], unix_secs: i64, nanos: u32) -> String;
```

v3 `Serialize` structs are **purpose-built** (parallel to `encrypt::KeystoreOut`, not a reuse), with
fields in declaration order (serde emits in declaration order — the `output.rs:58` trick):

```rust
#[derive(Serialize)] struct KeystoreV3Out { crypto: CryptoV3Out, id: String, address: String, version: i64 }
#[derive(Serialize)] struct CryptoV3Out {
    cipher: &'static str,           // "aes-128-ctr"
    cipherparams: CipherParamsV3,   // { iv }
    ciphertext: String,
    kdf: &'static str,              // "scrypt"
    kdfparams: ScryptParamsV3,      // { dklen, n, p, r, salt }
    mac: String,
}
```

`address` is `hex::encode(address)` (lowercase, no `0x` — geth stores lowercase; MetaMask recomputes,
foundry tolerates/omits it — `web3-v3-keystore.md`). The G3 byte-gate compares `crypto`
**values** (`ciphertext`/`mac`/`salt`/`iv`), not a whole-file diff (external tools disagree on key
order/whitespace). The new `crypto::v3_mac`:

```rust
// keystore/src/crypto.rs — beside checksum_message (SHA-256), NOT a replacement for it
pub(crate) fn v3_mac(dk: &[u8], ciphertext: &[u8]) -> [u8; 32] {   // keccak256(dk[16..32] ‖ ct)
    assert!(dk.len() >= 32, "v3_mac requires dk.len() >= 32, got {}", dk.len());
    let mut h = sha3::Keccak256::new();
    h.update(&dk[16..32]); h.update(ciphertext); h.finalize().into()
}
```

`derive_scrypt` is reused **as-is** with the raw password (its H7 memory ceiling `128·n·r ≤ 1 GiB`,
`p ≤ 16`, `dklen ∈ 32..=128` already bounds the injected params). `Aes128Ctr` and `format_uuid_v4`
reused in-crate. **No** call to `normalize_passphrase`, **no** call to `checksum_message` (C-4).

### `signer::secret_to_address` — address ownership (F-2, resolves the ugly-edge question)

```rust
// crates/ethernal-signer/src/lib.rs — new pub export (eip55_checksum already pub, lib.rs:21)
pub use local::secret_to_address;

// crates/ethernal-signer/src/local.rs — the guts of LocalSigner::address (local.rs:140-149),
// factored so there is ONE copy (LocalSigner::address delegates to it).
/// Ethereum address for a 32-byte secp256k1 secret. Validates 0 < k < n via
/// SigningKey::from_slice (F-2 belt-and-suspenders) — returns InvalidKey on a non-canonical scalar.
pub fn secret_to_address(secret: &[u8; 32]) -> Result<[u8; 20], SignerError> {
    let sk = SigningKey::from_slice(secret)
        .map_err(|_| SignerError::context("invalid secp256k1 private key", SignerError::InvalidKey))?;
    Ok(pubkey_address(sk.verifying_key()))     // keccak256(uncompressed[1..])[12..]
}
```

**The rule:** keccak / EIP-55 / address derivation has exactly **one home — `signer`** (which already
owns `sha3` + `k256`; the BLS side set this precedent, keygen fork (b)). The v3 writer receives the
address as 20 bytes and never learns about `k256` or the pubkey; the bin bridges
`hd_secp256k1` → `signer` → `encrypt_v3`. This costs one redundant point-multiply per key (the
derivation already computed points internally, and `secret_to_address` recomputes the pubkey from the
secret) — the price buys the canonical-scalar guard (`0<k<n`) for free and keeps both `keystore` and
`core` free of an address edge. `eip55_checksum(&address)` gives the display form (F-15); the file
field is lowercase.

### bin — `account_cli` / `account_cmd` + shared plumbing

`account new` / `account recover` mirror `key new` / `key recover` exactly; the clap group slots into
`root_command()` next to `key` (`main.rs:94`):

```rust
// account_cli.rs
pub fn command() -> Command {                       // "account" group, subcommand_required
    Command::new("account")
        .about("Generate or recover Web3 v3 (geth/foundry/MetaMask) EOA keystores from a BIP-39 mnemonic")
        .subcommand_required(true).arg_required_else_help(true)
        .subcommand(new_command())                  // TTY-only (F-5)
        .subcommand(recover_command())              // + --start-index (F-8)
}
pub fn run_new(m: &ArgMatches, cancel: &CancelToken) -> Result<(), AppError>;      // require_tty_for_new first
pub fn run_recover(m: &ArgMatches, cancel: &CancelToken) -> Result<(), AppError>;

/// Validated inputs — identical shape to KeyConfig MINUS pubkey/withdrawal concerns.
/// EOA has one keypair: no withdrawal key, no key-type flag (F-8, U-3).
pub struct AccountConfig {
    pub mode: AccountMode,                          // New | Recover
    pub count: u32,                                 // ≥ 1 (F-8)
    pub output_dir: String,
    pub start_index: u32,                           // recover only (F-8)
    pub passphrase_env: String,
    pub mnemonic_passphrase: MnemonicPassphraseForm, // reused from key_cli (F-12)
}
```

**Shared with the `key` path, and HOW (reuse-in-place, not copy, not extract — §Design notes (c)):**
the key-kind-agnostic front half is reused by widening a few `key_cmd`/`key_cli` items to `pub(crate)`
and calling them from `account_cmd`/`account_cli` — **zero logic duplication, visibility-only churn to
the shipped BLS code** (safest against the in-flight H9 hardening):

| Reused item | Home | Change | Requirement |
|---|---|---|---|
| `MnemonicPassphraseForm` + `resolve_mnemonic_passphrase` (clap layer) | `key_cli` | already `pub` / widen to `pub(crate)` | F-12 |
| `require_tty_for_new`, `validate_output_dir`, `shared_args` (clap) | `key_cli` | already `pub` / widen | F-5, F-8 |
| `MnemonicSource` + `StdinMnemonicSource` + `RecoverMnemonicSource` | `key_cmd` | widen to `pub(crate)` | F-6, F-10 |
| `run_ceremony`, `resolve_mnemonic_passphrase` (runtime), `MinLenPassphrase`, `check_cancel`, `zeroizing_trim` | `key_cmd` | widen to `pub(crate)` | F-6, F-7, F-12, S-5 |
| `NewKeystorePassphrase` / `EnvSource` / `require_min_len` | `keystore` | reuse verbatim (already `pub`) | F-7 |

`account_cmd` owns **only** what differs — the injectable deps and the per-index loop:

```rust
// account_cmd.rs
pub struct AccountDeps<'a> {
    pub cfg: &'a AccountConfig,
    pub entropy: &'a dyn Entropy,                    // mnemonic entropy + per-file salt/iv/uuid (S-4)
    pub keystore_pw: &'a dyn PassphraseSource,       // NewKeystorePassphrase or env+min-len (F-7)
    pub mnemonic_src: &'a dyn MnemonicSource,        // reused key_cmd trait (F-6/F-10)
    pub tty_writer: &'a mut dyn Write,               // one-time mnemonic display (S-2); sink on recover
    pub summary_out: &'a mut dyn Write,              // progress + summary → stderr (F-15)
    pub progress: Progress,
    pub logger: &'a Logger,
    /// Wall-clock for the UTC-- filename; secs+nanos (NOT just secs — geth uses 9-digit nanos).
    /// Injectable for a deterministic filename vector.
    pub timestamp: Timestamp,                        // { unix_secs: i64, nanos: u32 }
}
pub fn run_account_new(cfg: &AccountConfig, cancel: &CancelToken) -> Result<(), AppError>;
pub fn run_account_recover(cfg: &AccountConfig, cancel: &CancelToken) -> Result<(), AppError>;
pub fn run_account_new_with_deps(deps: &mut AccountDeps<'_>, cancel: &CancelToken) -> Result<(), AppError>;
pub fn run_account_recover_with_deps(deps: &mut AccountDeps<'_>, cancel: &CancelToken) -> Result<(), AppError>;
```

`AccountDeps` differs from `KeyDeps` only in the summary showing **addresses** (not pubkeys) and the
`timestamp` field carrying nanos (KeyDeps has `now_unix: i64` because BLS filenames are whole-second).
This one-field divergence is why `account_cmd` keeps its own deps struct rather than sharing `KeyDeps`.

## Data flow

**`account new`** (TTY-only, F-5):

```
require_tty_for_new (F-5) ─▶ load AccountConfig (count/dir/start-index=0/passphrase forms)
OsEntropy.fill 32B ─▶ Zeroizing entropy ─bip39::entropy_to_mnemonic─▶ Zeroizing<String> 24-word mnemonic (F-1)
resolve mnemonic passphrase (flag>env>prompt-confirm; empty ok)                                     (F-12)
run_ceremony: display once on tty_writer → require full re-entry → mismatch/SIGINT = Aborted(4)     (F-6, S-5)
keystore passphrase: NewKeystorePassphrase (confirm+≥8) or env+require_min_len — returns RAW bytes  (F-7, C-4)
bip39::to_seed(mnemonic, mnemonic_pass) ─▶ Zeroizing<[u8;64]> seed                                   (shared seed)
for i in start..start+count:                                                                         (F-8)
    hd_secp256k1::derive_path(seed, Bip44Path::eoa(i)) ─▶ ExtendedPrivKey ─.secret_bytes()▶ Zeroizing<[u8;32]> sk
    signer::secret_to_address(&sk) ─▶ [u8;20] addr   (also validates 0<k<n, F-2)
    entropy.fill salt(32)/iv(16)/uuid(16)                                                            (S-4)
    encrypt_v3{ secret=sk, password=RAW ks_pass, address=addr, salt, iv, uuid, scrypt=STANDARD } ─▶ JSON  (F-3, C-4)
    v3_filename(addr, ts.secs, ts.nanos) ─▶ write_new_0600(dir/name, json)  (0600, atomic, refuse-overwrite)  (F-4, S-3)
    progress: eip55_checksum(addr) + path (stderr)                                                   (F-15)
```

**`account recover`** (F-10): identical, minus the `new`-only steps — no TTY-only gate, no
entropy/mnemonic generation, no ceremony. Read the existing mnemonic (TTY prompt or piped stdin) →
`bip39::validate_mnemonic` (12/15/18/21/24 words; bad word by 1-based position, bad checksum → exit 2,
F-11) → mnemonic passphrase (single-entry) → the same seed→derive→encrypt→write tail. `--start-index`
selects the range `[start, start+count)`.

## Exit-code mapping (F-9, errors.rs)

Reuses the existing contract verbatim; only one new arm. Keystore **write** stays call-site `Exit{3}`
so `AppError::Output` remains gen's fallback-1 (keygen fork (a), pinned by `errors.rs:625`).

| Source | Class | Exit | Mechanism |
|---|---|---|---|
| `Bip39Error` (bad word/count/checksum), passphrase < 8, non-TTY `new`, bad `--count`/range, unwritable dir | user/config | **2** | existing `Bip39(_) => 2`, `Keystore(_) => 2`, `Exit{code:2}` |
| `Bip32Error` (derive master/child), `encrypt_v3` failure | crypto | **3** | **new** `AppError::Bip32(_) => 3`; `Keystore(Encrypt{..}) => 3` (existing) |
| `signer::secret_to_address` `InvalidKey` (non-canonical scalar) | crypto | **3** | existing `Signer(InvalidKey) => 3` |
| keystore **write** (`OutputError`, incl. overwrite refusal F-4) | keystore-write | **3** | call-site `map_err(|e| AppError::Exit{msg, code:3})` |
| ceremony mismatch/abort, SIGINT | user abort | **4** | existing `Aborted(_) => 4` (F-6, S-5) |

The only `errors.rs` edit: add `Bip32(Bip32Error)` (mirroring `Hd(HdError) => 3` at `errors.rs:265`)
+ its `Display`/`From`. Everything else is already wired.

## Secret lifecycle & zeroization (S-1, S-2)

**Zeroizing at every hop** (mirrors the BLS lifecycle, extended to the secp256k1 tree): `entropy`,
`mnemonic` (String), both passphrases, `seed`, every `secret_bytes()`, and **every BIP-32 chain
code** are `Zeroizing`. The HMAC-SHA512 output `I` (`I_L`/`I_R`) is scrubbed after splitting into
scalar+chain-code. `ExtendedPrivKey` for master and each intermediate child drops as the `derive_path`
fold advances, scrubbing its scalar+chain-code.

**S-1 caveat — the k256 `Scalar` scrubbing story (raised at Stage 4 per the research):**
`k256::Scalar` is `Copy` and does not self-zeroize (unlike `blst`'s `SecretKey`, which the BLS side
relies on). The **guaranteed floor** is: all serialized 32-byte key forms and all chain codes are
`Zeroizing`. For the live scalar, `ExtendedPrivKey` is **not** `Copy`, so its `Drop` can call
`self.scalar.zeroize()` — which requires enabling `k256`'s **`zeroize`** feature (adds
`elliptic-curve/zeroize`; already-vendored, no new crate; also applies to `signer`'s `k256` —
harmless). **To confirm at implementation:** that `k256 0.13.4` `Scalar: Zeroize` compiles under the
added feature (the D-1 empirical run used only `["ecdsa","std"]`, so this is unproven, not proven). If
it does not, the byte-form zeroization stands as the floor — the same API-boundary guarantee the
existing `signer` gives (its `key: [u8;32]` is zeroized, but `SigningKey::from_slice` makes an
internal copy, `local.rs:98-101`). Transient in-register arithmetic copies are outside API control for
all Rust stack crypto; this is documented honestly, not papered over.

**S-2 (no secret on stdout/stderr/logs):** the mnemonic reaches only the injectable `tty_writer`
during the `account new` ceremony (never stdout/stderr/logger); seed, chain codes, scalars, and both
passphrases are never rendered. A bad mnemonic word is reported by 1-based position, not token
(inherited from `bip39`, H1). **The address is public** and is printed (EIP-55, F-15) and logged.

**S-5 (SIGINT, no partial file):** `main` already installs the handler → `global_cancel()`
(`main.rs:105`); the `account` handlers take `cancel` like the others. `check_cancel` checkpoints sit
at each prompt and before each write; `write_new_0600`'s link-then-unlink publish (H6) means no
half-written or `.tmp` artifact, and `create_new`-exclusive means no clobber. With `--count N`, SIGINT
after *k* files leaves *k* complete keystores; on `account new` the ceremony completes before any
write, so SIGINT during it leaves **zero**.

## Filename + collision policy (F-4, geth `UTC--` convention)

`v3_filename` produces `UTC--<YYYY>-<MM>-<DD>T<HH>-<MM>-<SS>.<9-digit-nanos>Z--<40-hex-addr-no-0x>`,
e.g. `UTC--2026-07-18T14-22-05.123456789Z--9858effd232b4033e47d90003d41ec34ecaeda94`
(`web3-v3-keystore.md`). **The calendar conversion is the non-obvious part:** the workspace has no
`chrono`/`time` (verified, root `Cargo.toml`), so `unix_secs → (Y,M,D,h,m,s)` UTC is **hand-rolled**
(Howard Hinnant's `civil_from_days`, ~15 lines, no `unsafe`) inside `keystore::encrypt_v3`, keeping
the function **pure** (D-1) and unit-testable against a fixed vector. The `libc::gmtime_r` alternative
was rejected: `libc` is a bin-only dep (not a `keystore` dep), and pulling it into the pure keystore
crate to format a filename is the wrong edge.

**Collision policy** (mirrors BLS H5 same-second retry): within one run each index derives a **distinct
address**, so filenames are unique regardless of timestamp. A collision can only arise re-running the
same index+mnemonic into the same dir at the same nanosecond (astronomically unlikely with 9-digit
precision). `write_new_0600` is the safety net (`create_new` → `AlreadyExists`); on `AlreadyExists`
the writer retries once with `nanos + 1` before propagating (→ exit 3). `write_new_0600` stays
`create_new`-exclusive — it never overwrites (F-4, S-3).

## Data formats

- **Keystore JSON** — Web3 Secret Storage v3 (`web3-v3-keystore.md`): `crypto.cipher = aes-128-ctr`
  (`cipherparams.iv`), `crypto.kdf = scrypt` (`kdfparams` `{dklen:32,n:262144,p:1,r:8,salt}`),
  `crypto.mac = keccak256(dk[16..32] ‖ ct)`; top-level `id` (uuid v4), `address` (40 hex, lowercase,
  no `0x`), `version:3`. Compact `serde_json::to_vec`. **Not** EIP-2335 v4 — the existing
  `keystore::encrypt`/`Loader` are BLS-only and untouched (F-3, U-3).
- **Filename** — `UTC--<iso8601-nanos>Z--<addr-no-0x>` (above). Contrast the BLS
  `keystore-m_12381_3600_<i>_0_0-<unixsecs>.json` — different consumer, different convention (F-4).
- **Output-dir layout** — `--output-dir DIR` (existing, writable — reuse `validate_output_dir`) holds
  one v3 keystore per index; `account recover` uses `--start-index`/`--count` for the range. One
  keypair per index — no withdrawal split (F-8).

## Test strategy (which CI vector gates which module — C-1, G3, G4, G5)

| Module | Gate (all reproduced in CI, values in the research docs) | Requirement |
|---|---|---|
| `core::hd_secp256k1` | **BIP-32 Test Vector 1** (master + hardened `m/0'` + non-hardened `m/0'/1`, keys *and* chain codes) — the primitive gate covering both CKDpriv branches; plus the **Ethereum BIP-44 vector** (`abandon…about`, empty passphrase, `m/44'/60'/0'/0/{0,1}`, keys + EIP-55 addresses matching `cast`) as the E2E gate | C-1, G4 |
| `keystore::encrypt_v3` | **G3 byte-gate**: inject the verified `cast` fixture `{secret, password=testpassword (raw), salt, iv, n=8192,r=8,p=1}` → assert produced `ciphertext == a5ae5118…` and `mac == 8163019b…` byte-for-byte (`web3-v3-keystore.md`); plus a self encrypt→decrypt round-trip and `secret.len()!=32` rejection | C-1, G3, G4 |
| `keystore::v3_filename` | fixed vector `(addr, 2026-07-18T14:22:05.123456789Z) → UTC--2026-07-18T14-22-05.123456789Z--<addr>` (proves the hand-rolled civil_from_days) | F-4 |
| `signer::secret_to_address` | the `abandon` BIP-44 addresses (`0x9858…Eda94`, `0x6Fac…b9C0`); non-canonical scalar (zero / ≥ n) → `InvalidKey` | F-2 |
| bin `account_cmd` (deps seam) | happy-path writes N v3 files, 0600, filenames parse; ceremony mismatch → exit 4, no files; SIGINT after k → k complete files; short passphrase → exit 2; **secret-hygiene** (mnemonic/seed/scalar/passphrase never on stdout/stderr/logger — reuse the BLS `no_secret_in_logs` harness) | F-5/6/7, S-2, S-5, G5 |
| **Cross-tool parity (manual, per release — the sole consumer proof, C-2/C-3)** | `cast wallet address --mnemonic … --mnemonic-index i` == our address (G2); `cast wallet decrypt-keystore` / geth / MetaMask unlock a keystore we wrote (G1); recorded in the progress log, any mismatch blocks release — mechanical checklist in `research/cross-tool-parity.md` | C-2, G1, G2 |

The bin seam injects `FixedEntropy` (deterministic mnemonic + salt/iv/uuid), scripted mnemonic/
passphrase sources, a fixed `Timestamp`, and buffers — all in the bin's `#[cfg(test)]`, so no hidden
entropy/time flag ships (S-4). Determinism at the binary level comes from `account recover` with a
fixed mnemonic, not from entropy injection.

## Design notes (forks recorded per the gate instruction)

- **(a) BIP-32 lives in `core::hd_secp256k1`, not `signer`.** *Chosen* because BIP-32 is a derivation
  primitive (a sibling to `core::hd`), `core` already owns `bip39::to_seed` + `hmac`+`sha2`, and it
  adds exactly **one** edge (`k256`). *Alternative — put it in `signer`* (which already has `k256` +
  the address code, so a single `derive_eoa(seed,i) → (secret,address)` would be possible): rejected
  because it adds **two** edges (`hmac`+`sha2`), couples pure math to the tx-signing crate, and splits
  the two HD trees across crates (BLS in `core::hd`, secp in `signer`) — an asymmetry the symmetric
  `core::hd` + `core::hd_secp256k1` avoids. *Recorded cost of the choice:* `core` now links two curve
  libraries (`blst` + `k256`). A third option — a new `ethernal-hd` crate — is more edges/ceremony
  for one module; rejected.

- **(b) Address is a parameter to a pure `encrypt_v3`; keccak/EIP-55 stay in `signer`.** *Chosen* to
  keep `keystore` free of `k256`/pubkey knowledge and free of a `keystore → signer` edge (which would
  drag `signer → tx` into the pure format crate). The bin bridges `core` (secret) → `signer` (address)
  → `keystore` (encrypt). Reuses the keygen fork (b) precedent (EIP-55 exposed from `signer`, not
  moved to `core`). *Alternatives:* (i) `keystore` computes the address internally → needs a
  `keystore → signer` edge, rejected; (ii) move a keccak-address helper into `core` + add `sha3` to
  `core` → drags keccak into the deposit-core crate for one helper, rejected (same reason keygen (b)
  rejected it). *Cost:* one redundant point-multiply per key; it buys the `0<k<n` canonical guard
  (F-2) for free.

- **(c) `account` reuses the BLS ceremony/mnemonic/passphrase plumbing IN PLACE (visibility-widen),
  not by extracting a shared module, not by copying.** All three options give a **single**
  implementation of the S-1/S-2 ceremony code (copying is the only one that duplicates it, and is
  rejected outright — a security-code divergence risk). The discriminator is therefore *module
  organization vs. churn*, not DRY. *Chosen — reuse in place:* widen a handful of `key_cmd`/`key_cli`
  items to `pub(crate)` and call them from `account_cmd`/`account_cli`. This is **visibility-only
  change** to the shipped, mid-hardening BLS path (H9 parity still open), so it carries near-zero
  regression risk, gated by the existing `key_cmd`/`key_cli` test suite staying green. *Alternative —
  extract a neutral shared module* (`mnemonic_flow.rs`): defensible as house-style module discipline,
  but it buys only a better name at the cost of real churn across the 1900-line `key_cmd.rs` while it
  is being hardened; recorded as the alternative to revisit once H9 closes. *Note:* the shared boundary
  is the front half (entropy→mnemonic→passphrase→ceremony→seed + keystore-passphrase sourcing); the
  per-index derive/encrypt/filename/display tail is **not** shared (it diverges by curve, format,
  filename, and identity). Sequencing of the visibility change vs. the new modules is a Stage-5
  concern, not architecture's.

- **(d) v3 passphrase min-length uses the reused sources verbatim; the ≥8 gate measures the
  NFKD-normalized length while the KDF gets RAW bytes.** The passphrase sources (`NewKeystorePassphrase`,
  `EnvSource` + `MinLenPassphrase`) already **return raw bytes** — `require_min_len` normalizes only to
  *measure* the ≥8 length (`passphrase.rs:173`), and v4 `encrypt` applies `normalize_passphrase` itself
  at encrypt-time (`encrypt.rs:124`). So `encrypt_v3` simply **omits** the `normalize_passphrase` call
  and feeds the source's raw bytes to `derive_scrypt` — C-4 satisfied, sources reused unchanged. The
  only residual: the interactive/env ≥8 gate is measured on the normalized form, marginally *stricter*
  than geth (which counts raw bytes) for non-ASCII/control-padded passphrases. This never affects the
  raw KDF input or interop (it only refuses to *create* some weak-ish passphrases geth would accept —
  fail-safe). Exact raw-byte min-length parity would need `require_min_len` parameterized; recorded as a
  minor, non-blocking open point rather than a shipped-code edit.

## Non-goals (v1 scope cut — honoring the PRD)

Explicitly **out of this architecture** (deferred, per PRD [Non-goals] and the Q3 veto):

- **In-binary consumption (`ethernal sign --keystore`) and the v3 *reader*** — the named follow-up.
  v1 ships **no** v3 decrypt path; the hostile-input hardening (bound scrypt `n/r/p/dklen`,
  MAC-before-decrypt, reject non-canonical scalar, no key bytes in errors — the dropped S-6) moves
  with it. This is why cross-tool import (C-2) is the sole consumer validation and a hard release gate.
- **Custom `--hd-path`** (F-17, Q4) — fixed `m/44'/60'/0'/0/i` only; `account'` fixed at `0'`.
- **Raw-key `account import`** (Q5), **other mnemonic languages** (English only), **pbkdf2 v3
  creation** (scrypt only), **Ledger-derived EOA via this feature**, **key management verbs** (no
  delete/rotate/re-encrypt/inspect), **non-mainnet coin types** (`60'` only).
- **The BLS `key`/EIP-2335 path is untouched** — no `--type` flag, no shared writer, no format switch
  (Q1 binding, U-3). `keystore::encrypt`/`crypto::checksum_message`/`normalize_passphrase` stay
  EIP-2335-only.

## Requirement traceability (where the design satisfies each ID)

| ID | Satisfied by |
|---|---|
| F-1 | `core::bip39::entropy_to_mnemonic` reused; ceremony via reused `run_ceremony` |
| F-2 | `core::hd_secp256k1::derive_path(Bip44Path::eoa(i))`; `signer::secret_to_address` (address + 0<k<n) |
| F-3 | `keystore::encrypt_v3` + `crypto::v3_mac` (keccak); scrypt STANDARD; v3 structs |
| F-4 | `v3_filename` (UTC--) + `core::output::write_new_0600` (0600, atomic, refuse-overwrite) |
| F-5 | reused `require_tty_for_new` (bin) |
| F-6 | reused `run_ceremony` (display-once + re-entry, exit 4 on abort) |
| F-7 | reused `NewKeystorePassphrase`/`EnvSource`+`require_min_len` (≥8) |
| F-8 | `AccountConfig` `--count`/`--output-dir`/`--start-index`; no withdrawal/type flag |
| F-9 | `errors.rs` map (+ `Bip32 => 3`); call-site `Exit{3}` for write |
| F-10/F-11 | `account recover` reads TTY/stdin, `bip39::validate_mnemonic` (12–24 words, 1-based bad word) |
| F-12 | reused `MnemonicPassphraseForm` + `resolve_mnemonic_passphrase` (three forms, empty default) |
| F-15 | progress/summary with EIP-55 addresses (public) |
| S-1 | `Zeroizing` at every hop + chain-code zeroize + `ExtendedPrivKey` Drop (k256 caveat documented) |
| S-2 | mnemonic only to `tty_writer`; secrets never rendered; address is public |
| S-3 | `write_new_0600` 0600/atomic/no-overwrite |
| S-4 | `Entropy` trait for entropy+salt+iv+uuid; `FixedEntropy` test-only; no hidden flag |
| S-5 | `check_cancel` at prompts + before writes; per-file atomicity |
| C-1 | BIP-32/BIP-44 vectors + v3 encrypt byte-gate in CI |
| C-2/C-3 | manual cross-tool parity (cast/geth/MetaMask) — sole consumer proof, hard gate |
| C-4 | `encrypt_v3` feeds RAW passphrase bytes to `derive_scrypt`; never `normalize_passphrase` |
| U-3 | separate `account` namespace; BLS `key` untouched |
