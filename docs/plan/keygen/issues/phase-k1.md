# Phase K1 — Derivation primitives

**Theme:** Pure BIP-39 / EIP-2333-2334 derivation + the one new dependency, gated by official
spec vectors. Stream A critical path; no CLI, no I/O.
**Issues:** K1-1, K1-2, K1-3 · **Points:** 4 · **Execution:** first (K1 → K2/K3 → K5 → K4).
**Milestone gate — M-K1:** BIP-39 official Trezor vectors (incl. `abandon×23 art` 24-word and
the `"TREZOR"`-passphrase cases) **and** the four official EIP-2333 vectors green; the embedded
wordlist sha256 pin (`2f5eed53…`) asserted. Paths cite the repo-root layout (`crates/core/src/…`).

Signatures below are transcribed from [`architecture.md`](../architecture.md) §"Public API sketches";
vectors from [`research/bip39.md`](../research/bip39.md) and
[`research/eip-2333-2334.md`](../research/eip-2333-2334.md). Do not re-derive the long hex here —
cite the research doc + section and inline only the short discriminating anchors.

---

## K1-1 — `core::bip39` — wordlist, entropy→mnemonic, checksum validation, `to_seed`

**Points:** 2 · **Stream:** A · **Depends on:** — · **Milestone:** M-K1

**Goal:** Hand-roll BIP-39 as a pure, zeroizing module: embed + pin the English wordlist, convert
entropy→mnemonic with a valid checksum (`key new`), validate an existing mnemonic
(`key recover`), and derive the 64-byte PBKDF2-HMAC-SHA512 seed with the optional mnemonic
passphrase. Satisfies F-1 (fresh 24-word mnemonic), F-11 (12–24-word validation), F-12 (mnemonic
passphrase into the seed), C-1/G4 (vector conformance), D-1 (no new crypto dep).

**Implementation notes**
- New `crates/core/src/bip39.rs`; register `pub mod bip39;` in `crates/core/src/lib.rs`.
- Embed the wordlist as source, not testdata: `pub const WORDLIST: &str =
  include_str!("english.txt");` → new file `crates/core/src/english.txt` (2048 words, LF, **trailing
  newline**, 13116 bytes).
- Public API (architecture §`core::bip39`): `entropy_to_mnemonic(&[u8]) ->
  Result<Zeroizing<String>, Bip39Error>` (16/20/24/28/32-byte entropy → 12/15/18/21/24 words;
  `key new` uses 32 bytes → 24 words); `validate_mnemonic(&str) -> Result<(), Bip39Error>`;
  `to_seed(mnemonic: &str, mnemonic_passphrase: &[u8]) -> Zeroizing<[u8;64]>`.
- `Bip39Error` variants `UnknownWord(String)`, `WordCount(usize)`, `Checksum` — all user-input,
  map to exit 2 (wired in K3-4).
- Checksum: `CS = ENT/32` bits = first `CS` bits of `SHA256(entropy)`; 11-bit group indexing.
- `to_seed`: `pbkdf2::pbkdf2_hmac::<sha2::Sha512>(NFKD(mnemonic), NFKD("mnemonic"+passphrase),
  2048, &mut [0u8;64])`. NFKD via `unicode-normalization`; lowercase + collapse whitespace for
  `validate_mnemonic` lookup.
- Manifest: add `pbkdf2`, `hmac`, `unicode-normalization` to `crates/core/Cargo.toml` — all three are
  already `[workspace.dependencies]`, so D-1 ("getrandom is the only new dep") holds.
- Copy the full Trezor `english` vector array (~24 entries) to `crates/core/testdata/bip39-vectors.json`.

**Acceptance criteria**
- [ ] `entropy_to_mnemonic` reproduces every Trezor `english` vector, incl. `abandon×11 about` (12w,
  entropy `00…00`) and the 24-word `abandon×23 art` — F-1, C-1, G4
  (research/bip39.md §"Official Trezor test vectors").
- [ ] `validate_mnemonic` accepts 12/15/18/21/24-word mnemonics after NFKD+lowercase+ws-collapse, and
  returns `UnknownWord` / `WordCount` / `Checksum` respectively for a bad word, a bad count, and a
  tampered checksum — F-11, F-16, C-1.
- [ ] `to_seed` reproduces the 64-byte seed for every Trezor vector (all use passphrase `"TREZOR"`),
  incl. the chain anchor `abandon×11 about` + `"TREZOR"` → `c55257c3…463b04` — F-2, F-12, C-1, G4.
- [ ] wordlist pin test: `sha256(WORDLIST.as_bytes())` == `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`
  and `WORDLIST.len() == 13116` — D-1, C-1 (research/bip39.md §"Wordlist source + pin"; hash is
  trailing-newline-sensitive).
- [ ] entropy buffer, mnemonic `String`, and 64-byte seed are `Zeroizing` — S-1.
- [ ] `cargo tree -p eth-deposit-core` shows no new dependency (pbkdf2/hmac/unicode-normalization
  already present) — D-1.

**Test plan**
- `#[cfg(test)]` in `bip39.rs`, table-driven over `crates/core/testdata/bip39-vectors.json`:
  entropy→mnemonic and mnemonic→seed for the whole `english` array.
- Dedicated wordlist sha256/length pin test (guards a corrupted paste of `english.txt`).
- Negative tests: unknown word, wrong word count (e.g. 13 words), single-bit checksum flip; an
  NFKD/case test (uppercase + doubled spaces normalizes to the canonical mnemonic).

**Notes**
- The wordlist is **embedded source** (`crates/core/src/english.txt`, pinned by the sha256 test), not
  a testdata fixture. Embed the canonical 13116-byte trailing-newline form and pin `2f5eed53…`; the
  no-newline form hashes differently (`187db04a…`) and must not be used.

---

## K1-2 — `core::hd` — EIP-2334 path model + EIP-2333 derivation via `blst`

**Points:** 1 · **Stream:** A · **Depends on:** — · **Milestone:** M-K1

**Goal:** Thin, pure wrapper over `blst`'s EIP-2333 primitives plus the fixed EIP-2334 path model —
seed → master SK → per-index signing/withdrawal SK + 48-byte pubkey. No hand-rolled HKDF/Lamport
tree. Satisfies F-2 (derive signing keys + pubkeys per index) and C-1/G4 (EIP-2333 vectors).

**Implementation notes**
- New `crates/core/src/hd.rs`; register `pub mod hd;` in `crates/core/src/lib.rs`. `blst` is already a
  `core` dep — no manifest change.
- Public API (architecture §`core::hd`): `KeyPath` with `signing(i)` = `m/12381/3600/i/0/0`,
  `withdrawal(i)` = `m/12381/3600/i/0`, `to_string()`; `DerivedSk` with `to_bytes() ->
  Zeroizing<[u8;32]>` (big-endian) and `public_key() -> [u8;48]` (compressed G1); `derive_master(seed)
  -> Result<DerivedSk, HdError>`, `derive_child(&parent, index) -> DerivedSk` (infallible),
  `derive_path(seed, &KeyPath) -> Result<DerivedSk, HdError>` (fold `derive_child`).
- `derive_master` wraps `blst::min_pk::SecretKey::derive_master_eip2333` and **handles its `Result`**
  (blst enforces a 32-byte-min IKM in Rust; a 64-byte seed never trips it, but don't `unwrap` a
  caller-facing path). `HdError::Master(String)` → exit 3 (wired in K3-4).
- `public_key()` mirrors `core::bls` (`sk_to_pk` → compressed 48 bytes); confirm it equals
  `new_signer(to_bytes()).public_key()` so the keystore `pubkey` and the signer agree.
- Only the **signing** key is written by keygen; `withdrawal(i)` is derived (E2E honesty) but unused by
  v1 credentials (0x00 deferred, F-14) — say so in a code comment so it doesn't read as dead code.

**Acceptance criteria**
- [ ] `derive_master` + `derive_child` reproduce all four official EIP-2333 vectors (compare
  `to_bytes()` hex), incl. case 0: seed `c55257c3…463b04` → master `0d7359d5…45070`, child(0)
  `2d18bd6c…50f8e` — F-2, C-1, G4 (research/eip-2333-2334.md §"Official EIP-2333 test vectors").
- [ ] `KeyPath::signing(i).to_string()` == `"m/12381/3600/<i>/0/0"` and `withdrawal(i)` omits the final
  `/0` — F-2, C-1 (EIP-2334 structure).
- [ ] `derive_path(case0_seed, &KeyPath::signing(0))` derives a stable SK via the folded child chain
  `master → 12381 → 3600 → 0 → 0 → 0` — F-2.
- [ ] `public_key()` == `core::bls::new_signer(derived.to_bytes()).public_key()` for a derived key — F-2.
- [ ] `to_bytes()` returns `Zeroizing<[u8;32]>`; `DerivedSk` relies on blst's self-zeroizing `SecretKey`
  on drop — S-1.
- [ ] `derive_master`'s `Result` is propagated (no `unwrap`), mapping to `HdError` — F-2, F-9.

**Test plan**
- `#[cfg(test)]` over the four EIP-2333 vectors (seeds/master/child hex inline from the research table
  or a small `crates/core/testdata/eip2333-vectors.json`).
- A `derive_path` test asserting the signing SK for case-0 seed at index 0; a `to_string()` test for
  both `signing`/`withdrawal` at a couple of indices.

**Notes**
- **Depends on `—`, not K1-1** (the overview had K1-2 → K1-1). `core::hd` is pure over raw seed bytes
  and is gated by the EIP-2333 vectors directly (feed the vectors' seeds), so it needs nothing from
  `bip39`. The BIP-39→EIP-2333 join is proven end-to-end at K4-1 (case-0 seed = the abandon×11+TREZOR
  BIP-39 seed).
- EIP-2334 ships no seed→SK vectors of its own; the full path is gated downstream (K4-1 automated +
  the manual cross-tool session).

---

## K1-3 — `core::entropy` — `getrandom` dep + `Entropy` trait

**Points:** 1 · **Stream:** A · **Depends on:** — · **Milestone:** M-K1

**Goal:** Add the single new dependency (`getrandom`, D-1) behind a small injectable `Entropy` trait so
keystore/mnemonic randomness is drawn in the bin and unit-testable against fixed salt/iv/uuid. Satisfies
S-4 (OS CSPRNG only; no hidden entropy flag in the release binary).

**Implementation notes**
- New `crates/core/src/entropy.rs`; register `pub mod entropy;` in `crates/core/src/lib.rs`.
- Add `getrandom` to the workspace `[workspace.dependencies]` (`Cargo.toml`) and to
  `crates/core/Cargo.toml` — the **only** new dependency in the whole feature.
- Public API (architecture §`core::entropy`): `pub trait Entropy: Sync { fn fill(&self, buf: &mut [u8])
  -> Result<(), EntropyError>; }`; `pub struct OsEntropy;` (`getrandom::fill`); `EntropyError::Os(String)`.
- `OsEntropy` is the **only** production `Entropy`. The deterministic `FixedEntropy` lives in the bin's
  `#[cfg(test)]` (K3-2) — never here, never in the release binary (S-4).
- `bip39` and `keystore::encrypt` do **not** reference `Entropy`; the bin draws bytes and passes them
  down (keeps `keystore` free of a `→ core` edge).

**Acceptance criteria**
- [ ] `OsEntropy::fill` fills the whole buffer via `getrandom` and returns `EntropyError::Os` on backend
  failure — S-4.
- [ ] `getrandom` is added as the **only** new dependency (workspace + `core` manifest); nothing else new
  — D-1.
- [ ] `Entropy: Sync` so it is usable behind `&dyn Entropy` in the `KeyDeps` seam — testability.
- [ ] No deterministic/override `Entropy` and no `--entropy-*` flag exists in `core` or the release binary
  (`grep` for an entropy override comes back empty outside `#[cfg(test)]`) — S-4.

**Test plan**
- `#[cfg(test)]` in `entropy.rs`: two `OsEntropy::fill` calls into a 32-byte buffer differ (non-degenerate)
  and the buffer is fully written.

**Notes**
- The **UUID-v4 formatter moved out of K1-3** (the overview placed it here). Per the architecture delta,
  `keystore::encrypt` formats the UUID from its `uuid_bytes: [u8;16]` input internally (K2-1); K1-3 is
  entropy-only. The 16 UUID bytes are just another `Entropy::fill` draw in the bin.
