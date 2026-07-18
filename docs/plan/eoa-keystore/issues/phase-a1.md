# Phase A1 — Derivation primitive (`core::hd_secp256k1`)

**Theme:** Hand-rolled BIP-32 secp256k1 over the workspace `k256` (D-1, proven feasible in
[`research/bip32-secp256k1.md`](../research/bip32-secp256k1.md)) — master/child/path derivation of
the BIP-44 Ethereum tree `m/44'/60'/0'/0/i`, gated by published spec vectors. Pure `core`; no CLI,
no I/O. Stream A critical path.
**Issues:** A1-1, A1-2 · **Points:** 4 · **Execution:** first (with A2 in parallel on stream B).
**Milestone gate — M-A1:** BIP-32 Test Vector 1 (master + hardened `m/0'` + non-hardened `m/0'/1`,
**keys *and* chain codes**) **and** the Ethereum BIP-44 vector (`abandon…about`, empty passphrase,
`m/44'/60'/0'/0/{0,1}` **secrets** `1ab42cc4…`/`9a983cb3…` matching `cast wallet private-key`) green
in CI. **`k256` `zeroize`-feature decision recorded** (R1, A1-1). The EIP-55 **address** half of the
M-A1 clause (`0x9858…`/`0x6Fac…`) is delivered by **A3-1**, not A1 — computing an Ethereum address
needs `signer`'s keccak, which `core` does not have (architecture Design note (b)); A3-1 is stream B
/ deps `—`, so it lands alongside A1 and the milestone still closes on time.

Signatures below are transcribed from [`architecture.md`](../architecture.md) §"`core::hd_secp256k1`";
vectors from [`research/bip32-secp256k1.md`](../research/bip32-secp256k1.md). Do not re-derive the
long hex — cite the research doc + section and inline only the short discriminating anchors.

---

## A1-1 — `core::hd_secp256k1` primitive — `ExtendedPrivKey` master/child + `k256`/`zeroize`

**Points:** 3 · **Stream:** A · **Depends on:** — · **Milestone:** M-A1

**Goal:** Add `k256` to `core` and hand-roll the BIP-32 secp256k1 primitive as a pure, zeroizing
module: `ExtendedPrivKey` (secret scalar + chain code), `master(seed)`, and `derive_child(index)`
covering **both** CKDpriv branches (hardened + non-hardened), gated by BIP-32 official Test Vector 1.
Resolve the `k256` `zeroize`-feature question (R1) at implementation. Satisfies F-2 (derivation
primitive), S-1 (zeroize scalars + chain codes), C-1/G4 (BIP-32 vectors), D-1 (no new crate — `k256`
is already vendored).

**Implementation notes**
- New `crates/ethernal-core/src/hd_secp256k1.rs`; register `pub mod hd_secp256k1;` in
  `crates/ethernal-core/src/lib.rs`. Mirror the shape of `core::hd` (the BLS sibling).
- Manifest: add `k256` to `crates/ethernal-core/Cargo.toml` (workspace dep, `default-features =
  false, features = ["ecdsa", "std"]` — the exact workspace pin; `arithmetic` is transitively on, so
  `Scalar`/`ProjectivePoint` are public — see research §"Q1 / D-1"). Enable the **`zeroize`** feature
  **iff** the A1-1 confirm below succeeds. `hmac`+`sha2` are already `core` deps (HMAC-SHA512). No new
  third-party crate (D-1).
- Public API (architecture §"`core::hd_secp256k1`"):
  - `struct ExtendedPrivKey { scalar: Scalar, chain_code: Zeroizing<[u8;32]> }` — **not** `Copy`.
  - `master(seed: &[u8]) -> Result<Self, Bip32Error>`: `I = HMAC-SHA512("Bitcoin seed", seed)`;
    `k = parse256(I[..32])`, `c = I[32..]`. Reject `I_L ≥ n` (`Scalar::from_repr` → `None`) or
    `I_L == 0` (`is_zero`). Seed is the existing 64-byte `core::bip39::to_seed` output (unchanged).
  - `derive_child(&self, index: u32) -> Result<Self, Bip32Error>`: **hardened** (`index ≥ 2³¹`)
    `data = 0x00 ‖ ser256(k_par) ‖ ser32(i)`; **non-hardened** `data = serP(point(k_par)) ‖ ser32(i)`
    (33-byte compressed pubkey via `ProjectivePoint::GENERATOR * scalar` → `to_encoded_point(true)`).
    `k_i = parse256(I_L) + k_par (mod n)` (`Scalar + Scalar`); reject `I_L ≥ n` or `k_i == 0` (the
    BIP-32 skip rule → `InvalidChildKey`, a rejection not a silent wrong key). `c_i = I_R`.
  - `secret_bytes(&self) -> Zeroizing<[u8;32]>` (32-byte big-endian, via `Scalar::to_bytes`).
- Trait imports: `use k256::elliptic_curve::ff::PrimeField;` (`from_repr`) and
  `use k256::elliptic_curve::sec1::ToEncodedPoint;`. Build `FieldBytes` with `*FieldBytes::from_slice(b)`,
  **not** the deprecated `clone_from_slice` (research §"One deprecation nit").
- `Bip32Error` variants `Master(String)`, `InvalidChildKey(u32)` — `#[derive(thiserror::Error)]`,
  crypto → exit 3 (wired in A3-5). Do not embed key bytes in the message (S-2).
- **S-1 zeroization:** scrub the HMAC-SHA512 output `I` (`I_L`/`I_R`) after splitting; every chain
  code is `Zeroizing`; `secret_bytes()` returns `Zeroizing`.

**Confirm at implementation (R1 — the one genuinely unverified thing; M-A1 names this decision):**
enable `k256`'s `zeroize` feature and test whether `k256 0.13.4` `Scalar: Zeroize` compiles.
- **If it compiles:** implement `Drop for ExtendedPrivKey` calling `self.scalar.zeroize()`; keep the
  feature enabled (it also applies to `signer`'s `k256` — harmless). Record "scalar scrubbed on drop".
- **If it does not:** leave the feature off; the **guaranteed floor** stands — all serialized 32-byte
  key forms and all chain codes are `Zeroizing` (the same API-boundary guarantee `signer` gives). Add
  a module comment documenting the floor and the `k256` limitation. Record "byte-form floor".
  Whichever branch is taken is **written down**, not papered over.

**Acceptance criteria**
- [ ] `master` + `derive_child` reproduce **BIP-32 Test Vector 1** — `m`, hardened `m/0'`, and
  non-hardened `m/0'/1`, comparing **both private keys and chain codes** (`m` key `e8f32e72…`, cc
  `873dff81…`; `m/0'` key `edb2e14f…`, cc `47fdacbd…`; `m/0'/1` key `3c6cb8d0…`, cc `2a785763…`) —
  F-2, C-1, G4 (research/bip32-secp256k1.md §"Which published vectors exercise what").
- [ ] `master` rejects `I_L ≥ n` and `I_L == 0`; `derive_child` returns `InvalidChildKey(i)` on
  `I_L ≥ n` or `k_i == 0` (the skip rule is a `Result` rejection, not a silent wrong key) — C-1
  (research §"Q2" corner case 3).
- [ ] the non-hardened branch uses the **33-byte compressed** parent pubkey as HMAC data and the
  hardened branch uses `0x00 ‖ ser256(k_par)`; `m/0'/1` (non-hardened) passing proves the compressed
  -pubkey path — F-2, C-1 (research §"Q2" corner case 2; both branches load-bearing for our path).
- [ ] `Bip32Error` messages embed **no** key/chain-code bytes — S-2.
- [ ] every chain code and `secret_bytes()` is `Zeroizing`; the HMAC output `I` is scrubbed after the
  split — S-1.
- [ ] **R1 decision recorded:** either `ExtendedPrivKey::drop` scrubs the scalar under the enabled
  `k256` `zeroize` feature (branch A), **or** a module comment documents the byte-form/chain-code
  `Zeroizing` floor as the guarantee with the feature left off (branch B) — S-1, M-A1
  (architecture §"S-1 caveat"; project-plan R1).
- [ ] `cargo tree -p ethernal-core` shows `k256` added and **no** new third-party crate beyond it —
  D-1.

**Test plan**
- `#[cfg(test)]` in `hd_secp256k1.rs`, table-driven over BIP-32 TV1 (keys + chain codes inline from
  the research table, or a small `crates/ethernal-core/testdata/bip32-tv1.json`).
- Negative tests: a crafted scalar forcing `InvalidChildKey`; assert `Bip32Error` renders with no key
  bytes.
- (Optional, cheap) TV4 leading-zero `ser256` padding if we want that edge covered (research §"Which
  published vectors").

**Notes**
- BIP-32 lives in `core::hd_secp256k1`, **not** `signer` (architecture Design note (a)) — adds exactly
  one edge (`k256`); keeps both HD trees (`core::hd` BLS + `core::hd_secp256k1` secp) side-by-side.
- The address is **not** computed here — `core` has no keccak. The `secret_bytes()` output bridges to
  `signer::secret_to_address` (A3-1) in the bin.

---

## A1-2 — `Bip44Path` + `derive_path` + Ethereum BIP-44 secret vector

**Points:** 1 · **Stream:** A · **Depends on:** A1-1 · **Milestone:** M-A1

**Goal:** Add the fixed BIP-44 Ethereum path model and the `derive_path` fold over the A1-1 primitive,
gated by the Ethereum `abandon…about` BIP-44 **secret** vector against `cast wallet` ground truth.
Satisfies F-2 (`m/44'/60'/0'/0/i` derivation) and C-1/G4 (BIP-44 vector).

**Implementation notes**
- Add to `crates/ethernal-core/src/hd_secp256k1.rs`:
  - `struct Bip44Path([u32;5])` with `eoa(address_index: u32) -> Self` = `[44|H, 60|H, 0|H, 0,
    address_index]` (`H = 0x8000_0000`); `indices(&self) -> &[u32]`; `Display` → `"m/44'/60'/0'/0/<i>"`
    (path is public, safe to log — S-2). Only `address_index` varies; `account'` fixed at `0'` (F-2).
  - `ExtendedPrivKey::derive_path(seed: &[u8], path: &Bip44Path) -> Result<Self, Bip32Error>` — folds
    `derive_child` over `master(seed)` for the five path indices.
- The path mixes both branches (`44'/60'/0'` hardened, then `0/i` non-hardened) — so `derive_path`
  exercises the full A1-1 primitive.

**Acceptance criteria**
- [ ] `Bip44Path::eoa(i)` yields `[0x8000002C, 0x8000003C, 0x80000000, 0, i]` and `Display` renders
  `"m/44'/60'/0'/0/<i>"` — F-2 (architecture §"`core::hd_secp256k1`").
- [ ] `derive_path` over the **Ethereum BIP-44 vector** (`abandon…about`, **empty** passphrase, seed
  `5eb00bbd…`) reproduces the secp256k1 **secrets** at `m/44'/60'/0'/0/0` (`1ab42cc412b618bd…fb12b727`)
  and `m/44'/60'/0'/0/1` (`9a983cb3d832fbde…f1b55b6`), byte-for-byte against `cast wallet private-key`
  ground truth — F-2, C-1, G4 (research/bip32-secp256k1.md §"Ethereum BIP-44 vector").
- [ ] the seed is the **empty-passphrase** seed `5eb00bbd…` (**not** the `TREZOR` seed `c55257c3…`
  used by the BLS EIP-2333 tree — different tree, do not cross the seeds) — C-1 (research §"⚠ Do not
  cross the seeds").
- [ ] `secret_bytes()` for each derived key is `Zeroizing` — S-1.

**Test plan**
- `#[cfg(test)]` extending the A1-1 tests: feed seed `5eb00bbd…` (inline, or a
  `bip44-eth-vector.json` fixture), assert the two derived secrets match the cast-verified hex.
- A `Bip44Path::eoa(i)` / `Display` unit test at a couple of indices.

**Notes**
- **Secrets only here.** The EIP-55 **addresses** for these same secrets (`0x9858…Eda94`,
  `0x6Fac…b9C0`) are gated in **A3-1** via `signer::secret_to_address`, because computing an Ethereum
  address needs keccak (in `signer`, not `core`; architecture Design note (b)). Together A1-2 (secret)
  + A3-1 (secret → address) close the full M-A1 `abandon` clause.
- No seed→SK vector for the fixed path exists beyond `abandon`; the E2E address chain is re-gated at
  A5-1 (automated) and the combined manual session A5-M.
