# Research — BIP-32 secp256k1 derivation (the D-1 gate)

**Questions:** (Q1/D-1) Can BIP-32 secp256k1 derivation be hand-rolled over the `k256`
already in the workspace using only its **public** API — scalar parse-with-mod-n-check, scalar
add mod n, zero/`≥ n` rejection, 32-byte serialize, and compressed-pubkey derivation? (Q2) What
BIP-32 corner cases must the implementation and tests cover?

**VERDICT — hand-roll is feasible; no new derivation dependency (D-1 holds, empirically proven).**
`k256 = "=0.13.4"` with the workspace's exact features (`default-features = false, features =
["ecdsa", "std"]`) exposes everything needed through its public API. I compiled a throwaway crate
against that exact pin + `hmac`/`sha2`/`sha3` and hand-rolled full BIP-32 (master + hardened +
non-hardened CKDpriv) using only `k256::{Scalar, ProjectivePoint, FieldBytes}` and the `PrimeField`
/ `ToEncodedPoint` traits — no `bip32`/`coins-bip32`/alloy dependency. It reproduces **BIP-32
official Test Vector 1** (master, `m/0'` hardened, `m/0'/1` non-hardened — private keys *and* chain
codes) and the **Ethereum BIP-44 vector** (`abandon…about`, empty passphrase, `m/44'/60'/0'/0/0`
and `…/0/1` — private keys *and* EIP-55 addresses, matching `cast wallet` ground truth). The
empirical run is reproduced below. **D-1 does not loosen; the "minimal auditable dep" story stands
(BIP-32 joins BIP-39 as hand-rolled).** The only manifest change for derivation is adding `k256`
(and `hmac`+`sha2`, already workspace deps) to whichever crate hosts the module — a
placement question, not a new third-party crate (see `existing-code-map.md`).

---

## Q1 / D-1 — the exact k256 0.13.4 public API used

Feature graph (verified in `~/.cargo/registry/.../k256-0.13.4/Cargo.toml`): the workspace enables
`ecdsa`, and `ecdsa = ["arithmetic", "ecdsa-core/signing", "ecdsa-core/verifying", "sha256"]`, so
**`arithmetic` is transitively on**. `k256/src/lib.rs:52-53` then re-exports, gated on `arithmetic`:
`pub use arithmetic::{affine::AffinePoint, projective::ProjectivePoint, scalar::Scalar};`. So
`Scalar`/`ProjectivePoint`/`AffinePoint` are public **under the features the workspace already
sets** — no manifest feature change needed.

Every BIP-32 primitive maps to a public method (all confirmed compiling in the run below):

| BIP-32 need | k256 0.13.4 public API | Source |
|---|---|---|
| Parse 32-byte `IL` as scalar, **reject `≥ n`** | `Scalar::from_repr(FieldBytes) -> CtOption<Scalar>` (`PrimeField`); `None` iff `≥ n` | `arithmetic/scalar.rs:332` |
| Child `= IL + k_par` **mod n** | `impl Add<Scalar> for Scalar` (and `&`-variants); reduction is mod n | `arithmetic/scalar.rs:545`; `const fn add` at `:101` |
| Reject **`IL ≥ n`** | `from_repr` returns `None` (the parse *is* the check) | `:332` |
| Reject child **`= 0`** | `Scalar::is_zero(&self) -> Choice` | `arithmetic/scalar.rs:86` |
| Serialize scalar → 32 BE bytes | `Scalar::to_bytes(&self) -> FieldBytes` (`to_repr` aliases it) | `:91`, `:337` |
| Compressed pubkey (non-hardened HMAC input) | `(ProjectivePoint::GENERATOR * scalar).to_affine().to_encoded_point(true)` → 33 bytes | `sec1::ToEncodedPoint` |
| Uncompressed pubkey (for the address) | same, `to_encoded_point(false)` → 65 bytes | same |
| Final-scalar validity `0 < k < n` (belt-and-suspenders) | `k256::ecdsa::SigningKey::from_slice(&[u8])` errors unless `0 < k < n` (already used at `signer/src/local.rs:101`) | — |

`NonZeroScalar` (`k256/src/lib.rs:145`, i.e. `elliptic_curve::NonZeroScalar<Secp256k1>`) is also
public with `new(Scalar) -> CtOption` / `from_repr` — an alternative way to fold the non-zero check
into the type, if the implementer prefers it over an explicit `is_zero()`.

**Trait imports required** (the only non-obvious ergonomics): `use k256::elliptic_curve::ff::
PrimeField;` (for `from_repr`) and `use k256::elliptic_curve::sec1::ToEncodedPoint;` (for
`to_encoded_point`). Both re-export cleanly through `k256::elliptic_curve`.

**One deprecation nit:** build the `FieldBytes` for `from_repr` with `*FieldBytes::from_slice(b)`
(or `FieldBytes::try_from(b)`), not the deprecated `FieldBytes::clone_from_slice` (the throwaway
used the deprecated form and got one warning — cosmetic).

### Dependency comparison (only relevant if the verdict had flipped — it did not)

For the record, had `k256` not exposed these: `bip32` (v0.5, `iqlusion`) is the natural pick —
it *is* built on `k256`/`elliptic-curve`, has `zeroize` support and `Mnemonic`/`XPrv` types, and a
small tree; `coins-bip32` (used by ethers/alloy tooling) pulls a heavier `coins-*` stack; alloy has
no standalone BIP-32 crate (it re-exports `coins-bip32`). **None are needed** — hand-roll wins on
dep-tree size and matches the repo's BIP-39-hand-rolled philosophy (D-1).

---

## Q2 — BIP-32 spec corner cases the implementation + tests must cover

Source: [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).

1. **Master from seed.** `I = HMAC-SHA512(key = "Bitcoin seed", data = seed)`; `I_L` = master key,
   `I_R` = master chain code. The HMAC key is the ASCII literal `Bitcoin seed` (12 bytes) — a
   different key than BIP-39's PBKDF2 salt. Our seed is the existing 64-byte BIP-39 seed from
   `core::bip39::to_seed` (unchanged). Invalid iff `I_L = 0` or `I_L ≥ n` (astronomically rare;
   `from_repr` + `is_zero` catch it).
2. **Hardened vs non-hardened CKDpriv** — the HMAC *data* differs:
   - **Hardened** (`i ≥ 2³¹`): `data = 0x00 ‖ ser256(k_par) ‖ ser32(i)` (uses the parent **private**
     key). Our path's `44'/60'/0'` levels.
   - **Non-hardened** (`i < 2³¹`): `data = serP(point(k_par)) ‖ ser32(i)` where `serP` is the
     **33-byte compressed** public key of the parent. Our path's `0/i` levels. This is why the
     compressed-pubkey op is load-bearing (and why the D-1 check had to include it) — a BLS-style
     "private key only" tree would be wrong for the `0/i` levels.
   - Both: `k_i = parse256(I_L) + k_par (mod n)`, `c_i = I_R`.
   - `ser32(i)` is **big-endian** u32; `ser256` is 32-byte big-endian.
3. **The `I_L ≥ n` / `k_i = 0` skip rule.** BIP-32 says: if `parse256(I_L) ≥ n` **or** the resulting
   `k_i = 0`, the child at index `i` is *invalid* — **skip to the next index** `i+1`. Probability
   `< 2⁻¹²⁷` per step, so it is never hit in practice, but the code must not silently produce a
   wrong key: parse via `from_repr` (returns `None` on `≥ n`) and check `is_zero()` on the sum. For
   our **fixed** path `m/44'/60'/0'/0/i` the "skip" is effectively unreachable, but the derivation
   primitive must still implement reject-then-advance (a test can force it only with a crafted
   scalar; realistically this is an assert/`Result`, not a retry loop, given the fixed path).
4. **Chain-code secrecy (S-1).** `I_R`/`c_i` are **secret-equivalent** — holding a chain code + a
   parent public key lets an attacker derive all non-hardened siblings. Zeroize every chain code
   like a key (the PRD S-1 already says this; it is not optional).
5. **Both derivation forms are exercised by our path.** `m/44'/60'/0'/0/i` = hardened `44'`, `60'`,
   `0'` then non-hardened `0`, `i`. Any test that only checks a hardened-only or non-hardened-only
   chain would miss half the code. The vectors below cover both.

### Which published vectors exercise what (all verified locally)

BIP-32 has five official test vectors. For CI:

- **Test Vector 1** (`seed = 000102030405060708090a0b0c0d0e0f`) — exercises master, hardened
  (`m/0'`), and non-hardened (`m/0'/1`) in one chain. **This is the primitive gate.** Private keys
  and chain codes (base58-decoded from the official `xprv`, checksum-verified locally):

  | Path | private key (hex) | chain code (hex) |
  |---|---|---|
  | `m` | `e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35` | `873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508` |
  | `m/0'` | `edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea` | `47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141` |
  | `m/0'/1` | `3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368` | `2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19` |

  (Test Vectors **2–3** are longer non-hardened/edge chains; **4** covers leading-zero private-key
  padding; **5** is an *invalid-key rejection* set. TV1 is sufficient for our fixed path; TV4 is a
  cheap add if we want the leading-zero `ser256` padding covered, TV5 if we want an explicit
  invalid-input test.)

- **Ethereum BIP-44 vector** (`abandon abandon … about`, **empty** mnemonic passphrase) — the
  end-to-end gate that ties derivation to the address and to real tooling. **Seed (empty
  passphrase, computed locally via PBKDF2-HMAC-SHA512):**
  `5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4`.

  | Path | private key (hex) | address (EIP-55) |
  |---|---|---|
  | `m/44'/60'/0'/0/0` | `1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727` | `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` |
  | `m/44'/60'/0'/0/1` | `9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6` | `0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0` |

  **Ground truth is `cast wallet` (foundry 1.7.1), captured locally** — not recall:
  `cast wallet private-key "<abandon…>" 0` → the `…fb12b727` key above (an earlier recalled
  value `…dada52bc9c` was **wrong**; verify against `cast`, never memory). `cast wallet address
  --mnemonic "<abandon…>" --mnemonic-index 0` → `0x9858…Eda94`. The index-`i` form and the
  `m/44'/60'/0'/0/i` derivation-path form return identical keys (confirmed for `i=0`).

  **⚠ Do not cross the seeds:** this is the *same mnemonic* as EIP-2333 case-0 in the BLS research,
  but that used passphrase `TREZOR` (seed `c55257c3…`); the Ethereum address vector uses the
  **empty** passphrase (seed `5eb00bbd…`). Different seed, different tree.

---

## Empirical run (the load-bearing proof)

Throwaway crate `Cargo.toml` — **exact** workspace pin and features:

```toml
k256 = { version = "=0.13.4", default-features = false, features = ["ecdsa", "std"] }
hmac = "=0.12.1"
sha2 = "=0.10.9"
sha3 = "=0.10.9"
```

The implementation (public API only) — master + CKDpriv, both branches:

```rust
use hmac::{Hmac, Mac};
use k256::elliptic_curve::ff::PrimeField;         // Scalar::from_repr
use k256::elliptic_curve::sec1::ToEncodedPoint;   // to_encoded_point
use k256::{FieldBytes, ProjectivePoint, Scalar};
use sha2::Sha512;
type HmacSha512 = Hmac<Sha512>;
const HARDENED: u32 = 0x8000_0000;

// master: I = HMAC-SHA512("Bitcoin seed", seed); key = from_repr(I[..32]); cc = I[32..]
// child:  data = if hardened { 0x00 ‖ k_par.to_bytes() } else { compressed_pubkey(k_par) };
//         data ‖= i.to_be_bytes();  I = HMAC-SHA512(cc_par, data);
//         il = from_repr(I[..32])  // None => IL >= n, skip
//         key_i = il + k_par;      assert !key_i.is_zero();   cc_i = I[32..]
// pubkey: (ProjectivePoint::GENERATOR * key).to_affine().to_encoded_point(compressed)
```

Output (`cargo run --release`, compiled in 5.14s, one deprecation warning):

```
[PASS] TV1 m privkey / chaincode
[PASS] TV1 m/0' privkey (hardened) / chaincode
[PASS] TV1 m/0'/1 privkey (non-hardened) / chaincode
[PASS] abandon m/44'/60'/0'/0/0 privkey (cast ground truth)
[PASS] abandon m/44'/60'/0'/0/0 address (EIP-55, cast)  -> 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
[PASS] abandon m/44'/60'/0'/0/1 privkey (cast ground truth)
[PASS] abandon m/44'/60'/0'/0/1 address (EIP-55, cast)  -> 0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0
ALL BIP-32 / BIP-44 VECTORS MATCH — hand-roll over k256 public API works.
```

The full source is preserved at `/private/tmp/.../scratchpad`-adjacent throwaway (`/tmp/bip32check`);
it can be lifted into a `core` unit test almost verbatim (the vectors above become the fixture).

---

## Implications for our implementation

1. **New module (mirrors `core::hd`) hand-rolls BIP-32 over `k256`** — call it e.g.
   `core::hd_secp256k1` / `bip32`. Types: an `ExtPriv { key: Scalar, chain_code: Zeroizing<[u8;32]> }`
   with `master(seed)`, `derive_child(index)`, `derive_path(&[u32])`. **Zeroize the chain code and
   the secret byte representations** (S-1): wrap the HMAC-SHA512 output (`I_L`/`I_R`) and every
   serialized 32-byte key in `Zeroizing`. **Caveat for Stage 4:** `k256::Scalar` is `Copy` and does
   **not** self-zeroize, and `NonZeroScalar` is `Copy` too (`elliptic-curve/src/scalar/nonzero.rs:101`)
   — so the *live in-register scalar* cannot be scrubbed via a type choice. Zeroizing the byte forms
   is the achievable guarantee; if S-1 is read to require scrubbing the in-register scalar itself,
   that is a real `k256` limitation to raise at Stage 4 (the BLS side sidesteps it because `blst`'s
   `SecretKey` self-zeroizes — `k256`'s `Scalar` does not).
2. **Path model:** `m/44'/60'/0'/0/i` = `[44|H, 60|H, 0|H, 0, i]` with `H = 0x8000_0000`. Only
   `address_index = i` varies; `account' = 0'` is fixed (F-2). Reuse a `KeyPath`-style newtype like
   `core::hd::KeyPath`.
3. **Gate with the vectors above** (M-equivalent milestone): TV1 (primitive, hardened+non-hardened)
   + the two abandon rows (E2E to address). The throwaway is the ready-made test body.
4. **Address derivation reuses `ethernal-signer`:** `keccak256(uncompressed_pubkey[1..])[12..]` is
   already `pubkey_address(&VerifyingKey)` (`signer/src/local.rs:258`) and EIP-55 is
   `eip55_checksum` (`local.rs:293`, `pub`). The derived `Scalar` → `SigningKey::from_slice(&bytes)`
   → `VerifyingKey` bridges into those. See `existing-code-map.md`.
5. **`from_repr` + `is_zero` are the whole safety story for the scalar** — no manual big-int compare
   against `n`. `SigningKey::from_slice` on the final key is a cheap redundant `0 < k < n` guard that
   also yields the signer type for free.
