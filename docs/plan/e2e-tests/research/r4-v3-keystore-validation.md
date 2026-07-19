# R4 — v3 keystore validation depth

## Verdict (up front)

**Yes — a test-only v3 decrypt can be assembled entirely from crypto already in the workspace, and it is worth adding, because structural + recover-address-cross-check does NOT prove the ciphertext decrypts to the key behind the keystore's `address`.** The Q3 veto forbids a v3 reader *in the shipped binary*; it does not forbid test-only decrypt code (the eoa-keystore plan itself uses `cast wallet decrypt-keystore` as an external decrypt oracle). Recommended shape: a `#[cfg(feature = "test-support")] pub fn decrypt_v3(...)` **inside `ethernal-keystore`**, reusing the crate's existing `crypto::{derive_scrypt, Aes128Ctr, v3_mac}` — **zero new dependencies, zero new lockfile entries, and it never enters the release binary.** OQ-4 → add the decrypt helper (stronger than the PRD's structural-only v1); recover-cross-check + structural remains the acceptable floor.

---

## Why address-match alone is not enough (the finding)

T-3's proposed validation is structural (`version:3`, cipher, kdf, mac, `address`, `UTC--…` filename, `0600`) **plus** a recover cross-check: feed the captured mnemonic to `account recover` and assert the derived address equals the `new` keystore's `address` field.

That proves **derivation** is correct (mnemonic → secret → address) but **not encryption**. In `encrypt_v3` (`crates/ethernal-keystore/src/encrypt_v3.rs`), the JSON `address` field is written straight from the caller-supplied address (`hex::encode(input.address)`, line 183) — it is **independent of the ciphertext**. The ciphertext and MAC come from a separate path: `derive_scrypt(password, salt) → AES-128-CTR(dk[0..16], iv) over secret → keccak256(dk[16..32] ‖ ct)`. A bug that corrupts only that path (wrong dk slice, wrong iv application, MAC over the wrong bytes) would still emit a **correct `address`** and pass every structural + recover-cross-check assertion, while producing a keystore that **no tool could unlock**.

This is an asymmetry the suite should not accept silently: the **v4** BLS path already closes exactly this gap via the `keystore::Loader` round-trip (`key_e2e` decrypts what `key new`/`recover` wrote and compares the secret). The **v3** path has no in-binary reader, so without a test decrypt it has *nothing* proving encrypt self-consistency end-to-end through the binary.

What *is* already anchored: the crate-level **G3 byte-gate** (`encrypt_v3.rs` test `g3_byte_gate_cast_fixture_ciphertext_and_mac`) reproduces a real `cast`-produced ciphertext+mac byte-for-byte with injected fixed salt/iv — so the **algorithm** is proven at `n=8192`. The e2e decrypt adds the missing piece: the **binary's** wiring (real CSPRNG salt/iv, real derived secret, production `n=262144`) yields a self-consistent file.

---

## Feasibility: can a test-only decrypt be assembled from in-workspace crates?

**Yes, trivially — the primitives already exist and are already used for decrypt.** `crates/ethernal-keystore/src/crypto.rs` exports (crate-internal) everything a v3 decrypt needs:

- `derive_scrypt(password, salt, n, r, p, dklen)` — already the shared encrypt/decrypt KDF, with the hostile-param ceilings (`128·n·r ≤ 1 GiB`, `p ≤ 16`, `dklen ∈ 32..=128`) baked in.
- `Aes128Ctr = ctr::Ctr128BE<aes::Aes128>` — CTR is symmetric, so the same `apply_keystream` decrypts.
- `v3_mac(dk, ct) = keccak256(dk[16..32] ‖ ct)` — for MAC-before-decrypt.

Crate versions in `Cargo.lock` (no additions needed): `scrypt 0.11.0`, `aes 0.8.4`, `ctr 0.9.2`, `sha3 0.10.9`, `hex 0.4`, `serde_json 1`. The crate's own `encrypt_v3` unit tests already perform a full AES-CTR decrypt round-trip inline (`encrypt_v3_round_trip_aes_ctr`, line 408) — the exact ~15 lines a `decrypt_v3` would formalize.

A v3 decrypt is: parse JSON → read `kdfparams`/`cipherparams`/`ciphertext`/`mac` → `derive_scrypt` → **verify `v3_mac` before decrypt** → `Aes128Ctr::apply_keystream` → return the 32-byte secret. ~30–40 lines.

---

## The Q3 veto: what it actually forbids (verified against the repo)

From `docs/plan/eoa-keystore/prd.md` (found in git history — the plan tree isn't in this working checkout):

> **Q3 — RESOLVED (user veto, 2026-07-18, binding): follow-up feature, not v1.** v1 is keystore *creation* only. The v3 reader, `sign --keystore`, and the S-6 hostile-input hardening all move to a named follow-up. Consequence: v1 has **no in-binary consumer**.

> In-binary consumption of these keystores (`ethernal sign --keystore`) is a named follow-up… the follow-up adds the v3 *reader* and the hostile-input hardening that a reader requires.

The veto is scoped to the **shipped binary**: no `sign --keystore`, no runtime consumer, no hostile-input-hardened reader in the product. It is **not** a prohibition on decrypt code anywhere. Corroboration: the eoa-keystore project plan itself validates decrypt via `cast wallet decrypt-keystore` (an *external* oracle) precisely "because v1 ships no in-binary v3 reader," and the whole C-2 cross-tool session is external decrypt. A **test-only** decrypt of a keystore the test *just wrote* (trusted input — known params, not attacker-controlled) does not implicate the S-6 hostile-input concerns at all, and never links into `ethernal` the product.

**Conclusion: a test-support decrypt is consistent with the veto.** The line the veto draws is "nothing in the shipped binary consumes a keystore," and a feature-gated test helper honors it.

---

## Recommended shape (and why it beats bin dev-deps)

**Primary: `#[cfg(feature = "test-support")] pub fn decrypt_v3` in `ethernal-keystore`.**

```toml
# crates/ethernal-keystore/Cargo.toml
[features]
test-support = []          # exposes decrypt_v3, reusing crate-internal crypto
```
```toml
# bins/ethernal/Cargo.toml
[dev-dependencies]
ethernal-keystore = { workspace = true, features = ["test-support"] }
```

- **No new dependency, no new lockfile entry** — reuses `crypto::{derive_scrypt, Aes128Ctr, v3_mac}`.
- **Never in the release binary — but this property depends on `resolver = "2"`.** The workspace sets `resolver = "2"` (`Cargo.toml:2`, confirmed), under which dev-dependency features are unified only for test/bench/example builds, **not** for `cargo build`. So `cargo build --release --bin ethernal` does not enable `test-support`, and `decrypt_v3` is `#[cfg]`-compiled out of the product. (Under the legacy resolver "1" this guarantee would not hold — worth stating because it is a *security* property, not just hygiene. The bin already depends on `ethernal-keystore` normally; the dev-deps line only adds the feature for test builds.)
- **Guaranteed symmetry** — it decrypts with the exact primitives `encrypt_v3` encrypts with, so it cannot drift from the writer (unlike a re-implementation).
- Honors C-1 more faithfully than the alternative: the bin's `[dev-dependencies]` gains one line naming an *internal* crate, not four external crypto crates.

**Fallback: hand-roll ~30 lines in `bins/ethernal/tests/common/`** with `[dev-dependencies]` on `scrypt`/`aes`/`ctr`/`sha3` (all already in `Cargo.lock`, so still **no new lockfile entries**). Rejected as primary only because it duplicates decrypt logic that could drift and adds four external names to the previously-empty `[dev-dependencies]`.

**Minimum floor (matches the PRD as-written):** structural + recover-address-cross-check, **no** decrypt. Acceptable for v1, but leaves the encrypt-self-consistency gap above open (mitigated, not closed, by the crate G3 byte-gate). If the decrypt helper is deferred, the T-3 doc should state explicitly that v3 encrypt-through-the-binary is *not* round-trip-verified and relies on the crate byte-gate + the manual cross-tool session.

---

## Verdict

Add a test-only `decrypt_v3` behind an `ethernal-keystore` `test-support` feature, reusing the crate's existing crypto (no new deps, no lockfile churn, compiled out of the release binary). It closes the real gap that structural + address-match leaves open — that the v3 ciphertext actually decrypts to the key behind its `address` — and restores parity with the v4 `Loader` round-trip. This is consistent with the Q3 veto, which forbids only an **in-binary** reader/consumer. **OQ-4 → add the test decrypt (strong option); structural + recover-cross-check is the acceptable floor.**

## Consequences for architecture

- Add `test-support` feature to `crates/ethernal-keystore/Cargo.toml` exposing `pub fn decrypt_v3(json: &[u8], password: &[u8]) -> Result<Zeroizing<[u8;32]>, _>` (MAC-verify before decrypt), reusing `crypto::{derive_scrypt, Aes128Ctr, v3_mac}`. Add the feature to the bin's `[dev-dependencies]` only.
- T-3 validation becomes: structural (v3 shape, `0600`, `UTC--` filename) + **decrypt_v3 → secret → derive address → assert == keystore `address` == `account recover` address**. This proves derivation *and* encryption self-consistency through the binary.
- Confirm in CI that `cargo build --release --bin ethernal` does not pull `test-support` (feature-unification check); the shipped binary must contain no decrypt path (Q3).
- If the team prefers the PRD's v1 floor, keep structural + recover-cross-check and annotate T-3 that v3 encrypt-through-the-binary is anchored only by the crate G3 byte-gate + the manual cross-tool session — do not silently imply round-trip parity with v4.
