# Phase A2 — v3 keystore writer (`keystore::encrypt_v3`)

**Theme:** A pure Web3 Secret Storage **v3** (scrypt) keystore writer beside the existing EIP-2335 v4
writer — reusing the repo's scrypt/AES primitives but **not** its EIP-2335 checksum or passphrase
normalization (both are import-breaking traps for v3). Own `Serialize` structs, a Keccak-256 MAC, the
raw-passphrase KDF path, and the geth `UTC--` filename. Pure `keystore`; no RNG, no filesystem, no
`k256`. Stream B — overlaps A1.
**Issues:** A2-1, A2-2 · **Points:** 4 · **Execution:** parallel with A1 (before A3-4 consumes them).
**Milestone gate — M-A2:** the G3 byte-gate reproduces the verified `cast` fixture **byte-for-byte**
(injected `{secret, password=testpassword raw, salt, iv, n=8192,r=8,p=1}` → `ciphertext == a5ae5118…`
and `mac == 8163019b…`); a non-ASCII passphrase derives its `dk` from **raw** bytes (C-4 guard); self
encrypt round-trip green; `secret.len()!=32` rejected (→ exit 3); `v3_filename` fixed vector
(`…T14-22-05.123456789Z--<addr>`) green.

Signatures from [`architecture.md`](../architecture.md) §"`keystore::encrypt_v3`"; byte rules,
fixture, and the raw-passphrase finding from [`research/web3-v3-keystore.md`](../research/web3-v3-keystore.md);
reuse/no-reuse split from [`research/existing-code-map.md`](../research/existing-code-map.md).

---

## A2-1 — `crypto::v3_mac` + `sha3` dep + `keystore::encrypt_v3` (writer, structs, G3 byte-gate)

**Points:** 3 · **Stream:** B · **Depends on:** — · **Milestone:** M-A2

**Goal:** Add the pure v3 scrypt writer that reproduces a real `cast`-produced keystore's `crypto`
values byte-for-byte, feeding the passphrase to scrypt as **raw bytes** (never `normalize_passphrase`)
and computing the integrity tag with **Keccak-256** (never the EIP-2335 SHA-256 checksum). Satisfies
F-3 (v3 scrypt + Keccak MAC + `address`/`id`/`version:3`), C-1/C-3/G3/G4 (byte-gate), C-4 (raw
passphrase), D-1 (`sha3` already vendored — no new crate). This is A2's structural core (hence 3 pts).

**Implementation notes**
- Manifest: add `sha3` to `crates/ethernal-keystore/Cargo.toml` (workspace dep already — for the
  Keccak-256 MAC). No new third-party crate (D-1).
- New `pub(crate) fn crypto::v3_mac(dk: &[u8], ciphertext: &[u8]) -> [u8;32]` in
  `crates/ethernal-keystore/src/crypto.rs`, **beside** `checksum_message` (SHA-256), **not** a
  replacement: `assert!(dk.len() >= 32)` then `keccak256(dk[16..32] ‖ ciphertext)` over
  `sha3::Keccak256`. Same dk-split rule as EIP-2335; only the hash differs.
- New `crates/ethernal-keystore/src/encrypt_v3.rs`; register `pub mod encrypt_v3;` in
  `crates/ethernal-keystore/src/lib.rs`.
- Public API (architecture §"`keystore::encrypt_v3`"):
  - `struct ScryptParams { n: u64, r: u32, p: u32, dklen: usize }` with `const STANDARD = {262_144,
    8, 1, 32}` (geth-standard / repo profile). Injectable so the byte-gate runs `n=8192` while
    production emits `n=262144` (both read-compatible — readers take `n` from JSON).
  - `struct EncryptV3Input<'a> { secret: &[u8], password: &[u8], address: [u8;20], salt: [u8;32],
    iv: [u8;16], uuid_bytes: [u8;16], scrypt: ScryptParams }`.
  - `encrypt_v3(&EncryptV3Input) -> Result<Vec<u8>, KeystoreError>`: `derive_scrypt(RAW password,
    salt, n,r,p,dklen)` → `Aes128Ctr(dk[0..16], iv).apply_keystream(secret)` → `mac = v3_mac(dk, ct)`
    → serialize v3 structs → compact `serde_json::to_vec`. Reject `secret.len() != 32` with
    `KeystoreError::Encrypt` (→ exit 3).
- **Reuse in-crate (no visibility change — architecture §"`keystore` reuse"):** `crypto::derive_scrypt`,
  `crypto::Aes128Ctr`, and `encrypt::format_uuid_v4` are already `pub(crate)`; `encrypt_v3` is in the
  same crate, so it calls them directly. (This refines the research-map note that said "make pub".)
- **RAW passphrase (C-4, R2):** feed `input.password` straight to `derive_scrypt`. Do **NOT** call
  `crypto::normalize_passphrase` (EIP-2335 NFKD) — reusing it makes any non-ASCII passphrase produce a
  keystore geth/MetaMask cannot unlock, silently breaking G1/C-2. Do **NOT** call `checksum_message`.
- v3 `Serialize` structs are **purpose-built** (parallel to `encrypt::KeystoreOut`, not a reuse), in
  declaration order (serde emits in declaration order — the `output.rs:58` trick):
  `KeystoreV3Out { crypto, id, address, version }` where `CryptoV3Out { cipher:"aes-128-ctr",
  cipherparams:{iv}, ciphertext, kdf:"scrypt", kdfparams:{dklen,n,p,r,salt}, mac }`. `address` =
  `hex::encode(address)` (lowercase, no `0x` — geth stores lowercase; MetaMask recomputes; foundry
  tolerates). `version` = `3`.
- Add the verified `cast` fixture as `crates/ethernal-keystore/testdata/web3-v3-cast-fixture.json`
  (the JSON in research §"CI byte-reproduction fixture") for the byte-gate.
- `KeystoreError` reuses/gains an encrypt-failure variant (`Encrypt` already maps → 3).

**Acceptance criteria**
- [ ] G3 byte-gate: `encrypt_v3` fed the fixture's `secret 7a28b5ba…`, `password="testpassword"`
  (raw), `salt d64e482e…`, `iv fdf4d6e4…`, and `ScryptParams{n:8192,r:8,p:1,dklen:32}` produces
  `ciphertext == a5ae5118b012fe13…296ba611` and `mac == 8163019b12c28075…e0ba5d6b` **byte-for-byte** —
  F-3, C-1, C-3, G3, G4 (research/web3-v3-keystore.md §"CI byte-reproduction fixture"; fixture
  `testdata/web3-v3-cast-fixture.json`).
- [ ] **C-4 raw-passphrase guard:** for a **non-ASCII / NFKD-unstable** passphrase (e.g. a fullwidth
  or combining-mark string), the `dk` `encrypt_v3` derives equals `derive_scrypt(RAW utf8_bytes, …)`
  and **differs** from `derive_scrypt(normalize_passphrase(pw), …)` — proving `encrypt_v3` never
  normalizes (the ASCII byte-gate alone cannot catch this, as `testpassword` is NFKD-stable) — C-4, R2
  (research §"the passphrase-normalization trap").
- [ ] `v3_mac(dk, ct)` = `keccak256(dk[16..32] ‖ ct)` over `sha3::Keccak256`, and it is a **new**
  function beside `checksum_message` (SHA-256), which is unchanged — F-3 (architecture §"`crypto::v3_mac`").
- [ ] a self encrypt round-trip decrypts `ciphertext` back to the input secret using
  `dk[0..16]`/`iv` (encrypt-side symmetry check — v1 ships no in-binary v3 reader, so this is the
  automated decrypt-direction anchor) — F-3, C-3.
- [ ] `secret.len() != 32` → `KeystoreError::Encrypt` (→ exit 3) — F-3, F-9.
- [ ] the emitted JSON has `version: 3`, `crypto.cipher: "aes-128-ctr"`, `crypto.kdf: "scrypt"`,
  top-level `address` (lowercase, no `0x`) and `id` (uuid v4 from `uuid_bytes`); the plaintext secret
  is never serialized (only `ciphertext`) — F-3, S-1, S-2.
- [ ] `encrypt_v3` draws no RNG and does no filesystem I/O (salt/iv/uuid are inputs); `keystore` gains
  no `→ core` / `→ signer` edge; `cargo tree -p ethernal-keystore` shows `sha3` added, no new crate —
  D-1 (architecture §"design force 1").

**Test plan**
- Byte-gate over `testdata/web3-v3-cast-fixture.json`: inject the fixture's salt/iv/secret/password +
  `n=8192`; assert `ciphertext`/`mac` equal the fixture values.
- A dedicated non-ASCII passphrase test comparing `dk_raw` vs `dk_normalized` (C-4 guard).
- Round-trip: `encrypt_v3` a known 32-byte secret with a random-ish salt/iv/uuid, then AES-CTR-decrypt
  the `ciphertext` and assert the recovered secret matches; a `secret.len()!=32` rejection test.

**Notes**
- The byte-gate runs at the **light** profile `n=8192` (≈ms) because `cast wallet import` writes light;
  production emits `n=262144` (F-3). scrypt is parameter-agnostic — same pipeline. Production-`n`
  correctness is anchored by the C-2 cross-tool session (A5-M) plus the round-trip above (research
  §"Scrypt-profile note"; project-plan R4).
- The fixture `cast` produced omits the top-level `address` field; our writer **includes** it
  (geth-compatible, foundry-tolerated). The byte-gate compares `crypto` **values**, not a whole-file
  diff (external tools disagree on key order/whitespace — research §"Field order note").

---

## A2-2 — `v3_filename` — hand-rolled `civil_from_days` + fixed vector

**Points:** 1 · **Stream:** B · **Depends on:** A2-1 · **Milestone:** M-A2

**Goal:** Add the pure geth `UTC--` filename function, converting a unix timestamp to a UTC calendar
without pulling `chrono`/`time` into the workspace. Satisfies F-4 (geth-recognizable filename) and R6
(hand-rolled calendar conversion, vector-locked).

**Implementation notes**
- Add to `crates/ethernal-keystore/src/encrypt_v3.rs`:
  `pub fn v3_filename(address: &[u8;20], unix_secs: i64, nanos: u32) -> String` →
  `UTC--<YYYY>-<MM>-<DD>T<HH>-<MM>-<SS>.<9-digit-nanos>Z--<40-hex-addr-no-0x>`. Colons rendered as
  **dashes** (filesystem-safe), 9-digit nanoseconds, literal trailing `Z`, address lowercase no `0x`.
- The `unix_secs → (Y,M,D,h,m,s)` UTC conversion is **hand-rolled** (Howard Hinnant's
  `civil_from_days`, ~15 lines, no `unsafe`) — the workspace has no `chrono`/`time` (verified, root
  `Cargo.toml`), and `libc::gmtime_r` is a bin-only dep (pulling it into pure `keystore` is the wrong
  edge — architecture §"Filename"). Keeps `v3_filename` pure and unit-testable.
- `encrypt_v3` does **not** call `v3_filename` — the bin computes the filename separately and passes
  the path to `write_new_0600` (data flow). So A2-2's logic is independent of A2-1; it depends on A2-1
  only for the `encrypt_v3` module scaffold + `sha3`/manifest already registered.

**Acceptance criteria**
- [ ] `v3_filename(addr, 1_752_849_725, 123_456_789)` (2026-07-18T14:22:05.123456789Z) ==
  `UTC--2026-07-18T14-22-05.123456789Z--<40-hex-addr-no-0x>` — F-4 (architecture §"Filename +
  collision policy"; research/web3-v3-keystore.md §"Filename convention").
- [ ] colons are dashes, nanos are 9 digits (zero-padded), the address is lowercase without `0x`, and
  the literal `Z` is present — F-4.
- [ ] `civil_from_days` is a pure function with no `unsafe` and no `chrono`/`time`/`libc` dependency;
  `cargo tree -p ethernal-keystore` gains no calendar crate — R6, D-1.

**Test plan**
- `#[cfg(test)]` fixed-vector test for the timestamp above; a couple of extra dates spanning a leap
  year and a month boundary to exercise `civil_from_days`.

**Notes**
- Collision policy (F-4): within a run each index derives a distinct address → distinct filename; a
  same-nanosecond re-run collision is caught by `write_new_0600`'s `create_new` (retry once with
  `nanos+1`, then exit 3). `write_new_0600` never overwrites (architecture §"Collision policy").
