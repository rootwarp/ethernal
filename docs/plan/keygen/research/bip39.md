# Research — BIP-39 mnemonic + seed (hand-rolled)

**Question:** what exactly must we hand-roll for BIP-39 (entropy → words, checksum, seed),
which wordlist do we embed and how do we pin it, and do the official Trezor vectors and
ethstaker-deposit-cli behavior agree with the overview's plan?

**Verdict: hand-roll BIP-39 as planned — all inputs verified.** I derived the seed for the
all-zero 12-word Trezor vector locally and it matches the published value exactly; I fetched
the canonical English wordlist and hashed it myself (the pinned sha256 below is **not** a
value I trusted from memory — a half-remembered hash was wrong). No new crypto dependency is
needed: `pbkdf2` + `sha2` (`Sha512`) + `hmac` + `unicode-normalization` are already workspace
deps; only `getrandom` is new (for entropy, covered in K1-3).

## What we hand-roll

### 1. Entropy → mnemonic (generation, `key new`)
- Entropy `ENT` bits: 128/160/192/224/**256** for 12/15/18/21/24 words. `key new` uses **256
  bits** (24 words) only (D-1, non-goal: custom sizes not exposed).
- Checksum `CS = ENT / 32` bits = the first `CS` bits of `SHA256(entropy)`.
- Concatenate `entropy || checksum` → split into groups of **11 bits**; each 11-bit group
  (0–2047) indexes the wordlist. `24 words × 11 = 264 = 256 + 8` (CS = 8 bits for 256-bit
  entropy).

### 2. Mnemonic validation (recovery, `key recover`)
- Accept **12/15/18/21/24** words (`MS ∈ {12,15,18,21,24}`; `ENT = MS×11 × 32/33`).
- Map each word → its 11-bit index (reject any word not in the list).
- Re-split the bitstream into `ENT` entropy bits + `CS` checksum bits; recompute
  `SHA256(entropy)[:CS]` and require equality. A bad word **or** bad checksum → exit 2.
- Normalize input for lookup: BIP-39 mandates **NFKD** on the mnemonic; also lowercase +
  collapse whitespace to single spaces (staking-deposit-cli splits on any whitespace).

### 3. Mnemonic → seed
```
seed = PBKDF2( password  = NFKD(mnemonic) UTF-8,
               salt      = NFKD("mnemonic" + passphrase) UTF-8,
               c         = 2048,
               dklen     = 64 bytes,
               PRF       = HMAC-SHA512 )
```
- The passphrase (BIP-39 "25th word") is **empty by default**; when set it is NFKD-normalized
  and appended to the literal `"mnemonic"`. This is a distinct secret from the keystore
  passphrase (PRD F-12); the 8-char minimum does **not** apply, empty is valid.
- In Rust: `pbkdf2::pbkdf2_hmac::<sha2::Sha512>(mnemonic_nfkd, salt_nfkd, 2048, &mut [0u8; 64])`.

**Verified locally:** `NFKD("abandon …(×11)… about")` + salt `NFKD("mnemonic" + "TREZOR")`,
PBKDF2-HMAC-SHA512, 2048 rounds, 64 bytes →
`c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04`,
which is the published Trezor seed **and** EIP-2333 test-case-0's seed.

## Wordlist source + pin

- **Source:** `bip-0039/english.txt` in
  [bitcoin/bips](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt) (the
  canonical 2048-word English list; identical to trezor/python-mnemonic's `english.txt`).
- **Pinned sha256 (of the file *including* its trailing newline):**
  `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`
  - 2048 lines, **13116 bytes**, LF line endings, final byte `0x0a`.
  - This is the value trezor/python-mnemonic and staking-deposit-cli pin. **The hash is
    trailing-newline-sensitive:** the same 2048 words *without* the final newline hash to
    `187db04a869dd9bc7be80d21a86497d692c0db6abd3aa8cb6be5d618ff757fae`. Embed the file with the
    trailing newline and assert the 13116-byte / `2f5eed53…` form, or (safer for a Rust
    `include_str!`) embed the 2048 words and assert a hash you compute over *your* exact bytes
    — either way, gate it with a `const`-time sha256 check in a test so a corrupted paste is
    caught.
  - First word `abandon` = index 0; last word `zoo` = index 2047.

## Official Trezor test vectors (all use passphrase `"TREZOR"`)

From [trezor/python-mnemonic `vectors.json`](https://github.com/trezor/python-mnemonic/blob/master/vectors.json)
(`english` array; entries are `[entropy, mnemonic, seed, xprv]`). Good news for us: the fixed
passphrase `"TREZOR"` exercises our `--mnemonic-passphrase` path (PRD F-12), so we can gate
both empty- and non-empty-passphrase seed derivation.

| entropy | mnemonic (abbreviated) | seed (64-byte hex) |
|---|---|---|
| `00000000000000000000000000000000` | `abandon ×11 about` (12w) | `c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04` |
| `7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f` | `legal winner thank year wave sausage worth useful legal winner thank yellow` | `2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607` |
| `80808080808080808080808080808080` | `letter advice cage absurd amount doctor acoustic avoid letter advice cage above` | `d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8` |
| `ffffffffffffffffffffffffffffffff` | `zoo ×11 wrong` (12w) | `ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069` |
| `0000000000000000000000000000000000000000000000000000000000000000` | `abandon ×23 art` (24w) | `bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8` |

(The `abandon ×23 art` 24-word entry is a good second gate: it exercises the 256-bit /
8-bit-checksum path that `key new` uses.) A full port of the `english` array is ~24 entries;
K1-1 should copy them all from `vectors.json` and assert entropy→mnemonic→seed for each.

## staking-deposit-cli / ethstaker-deposit-cli behavior

- **Word-count default:** both default generation to **24 words** (256-bit entropy) — matches
  `key new` F-1.
- **Language:** we ship **English only** in v1 (non-goal: other languages). ethstaker-deposit-cli
  supports many languages via per-language wordlists + a language-specific normalization; our
  scope avoids that entirely.
- **Fork/maintenance status (matters for the parity target in G2):**
  [ethereum/staking-deposit-cli is deprecated](https://github.com/ethereum/staking-deposit-cli)
  (the repo title carries a "⚠️ [Deprecated] ⚠️" banner); the actively maintained successor is
  [ethstaker/ethstaker-deposit-cli](https://github.com/ethstaker/ethstaker-deposit-cli). The
  BIP-39 logic is unchanged between them. **Use ethstaker-deposit-cli as the cross-tool parity
  reference (G2)** — this is already what the PRD/overview name for G2, and it is the correct
  choice; the repo's `--verify-with-deposit-cli` still shells out to the older `deposit` binary,
  which is a separate (decrypt-side) concern.

## Implications for our implementation

1. **No new crypto dep.** `sha2::Sha256` (checksum), `sha2::Sha512` + `pbkdf2::pbkdf2_hmac`
   (seed), `unicode-normalization` (NFKD) are all present. `getrandom` (K1-3) is the only add.
2. **Embed the wordlist via `include_str!`** and pin it with a sha256 test. Pin over *your*
   embedded bytes; document that the canonical upstream form is the 13116-byte trailing-newline
   file (`2f5eed53…`).
3. **NFKD everywhere a secret string is hashed** — the mnemonic *and* the passphrase, on both
   `key new` and `key recover`. Capture the passphrase *before* seed derivation on both paths
   (F-12).
4. **Gate K1-1 (M-K1) with the full Trezor `english` set**, both entropy→mnemonic and
   mnemonic→seed, including at least one non-empty-passphrase case (all Trezor vectors use
   `"TREZOR"`, so this is automatic).
5. **Recovery accepts 12–24 words; generation emits 24.** Validate word membership and checksum
   before deriving; bad word / bad checksum → exit 2 with a specific message (F-11, F-16).
6. **Zeroize** the mnemonic string, entropy bytes, and 64-byte seed (`Zeroizing`), per S-1.
