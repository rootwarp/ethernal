# Research — Web3 Secret Storage v3 keystore (scrypt) creation

**Question:** what exact bytes, field shape, MAC, filename, and address encoding must our v3
writer reproduce so geth / foundry (`cast`) / MetaMask import and **unlock** it (G1/C-2, a hard
release requirement), and what is a CI byte-reproduction fixture (G3/C-1) whose values are
**verified**, not recalled?

**Verdict: the v3 pipeline is scrypt → AES-128-CTR → *Keccak-256* MAC, and it reuses the repo's
existing scrypt/AES primitives but NOT its EIP-2335 checksum or passphrase normalization.** Two
hard divergences from the EIP-2335 (BLS) writer, both confirmed against go-ethereum source and
verified empirically: (1) the integrity tag is **`mac = keccak256(dk[16..32] ‖ ciphertext)`**, not
EIP-2335's `sha256` checksum; (2) geth/MetaMask feed the passphrase to scrypt as **raw bytes with
no NFKD/normalization** — so the v3 writer must **not** call `keystore::crypto::normalize_passphrase`
(see the finding below; this is the most import-breaking trap). I generated a real v3 keystore with
`cast` and reproduced its `ciphertext` and `mac` **byte-for-byte** in a clean-room run (below) —
that is the CI fixture.

---

## v3 JSON structure and field shape

Source: [Web3 Secret Storage Definition](https://ethereum.org/developers/docs/data-structures-and-encoding/web3-secret-storage/),
[go-ethereum `accounts/keystore/passphrase.go` + `key.go`](https://github.com/ethereum/go-ethereum/tree/master/accounts/keystore).

```json
{
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": { "iv": "<16-byte hex>" },
    "ciphertext": "<32-byte hex>",
    "kdf": "scrypt",
    "kdfparams": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "<32-byte hex>" },
    "mac": "<32-byte hex, keccak256>"
  },
  "id": "<uuid v4>",
  "address": "<40 hex, lowercase, NO 0x>",
  "version": 3
}
```

**This is structurally different from EIP-2335 v4** (which the existing `keystore::encrypt` writes)
and the two writers must not be merged (PRD Q1/U-3):

| | EIP-2335 v4 (BLS, existing) | Web3 v3 (EOA, new) |
|---|---|---|
| `crypto.kdf` | object `{function, params, message}` | string `"scrypt"` + separate `kdfparams` |
| cipher block | `crypto.cipher = {function, params, message}` | `crypto.cipher` (str) + `cipherparams` + `ciphertext` |
| integrity | `crypto.checksum.message = sha256(dk[16..32] ‖ ct)` | `crypto.mac = keccak256(dk[16..32] ‖ ct)` |
| identity field | `pubkey` (48-byte hex) + `path` | `address` (20-byte lowercase hex, no `0x`) |
| id field | `uuid` | `id` |
| `version` | `4` | `3` |

**Field order note (G3 byte-gate):** unlike the EIP-2335 byte-gate, external v3 tools do **not**
agree on JSON key order or whitespace (geth pretty-prints; foundry pretty-prints; our writer emits
compact `serde_json::to_vec`). So the G3 gate must compare the **`crypto` values**
(`ciphertext`, `mac`, `salt`, `iv`) and the decrypted secret — not a whole-file byte diff against a
foreign tool. Reproduce with a typed `#[derive(Serialize)]` struct set in declaration order (same
trick as `keystore::encrypt::KeystoreOut`), asserting the produced `ciphertext`/`mac` equal the
fixture's.

## Encryption process (what the writer does)

1. **Passphrase → raw bytes (NO normalization).** geth: `derivedKey, _ := scrypt.Key(auth, salt,
   n, r, p, dkLen)` with `auth` the raw `[]byte` of the password — **no NFKD, no control-strip.**
   MetaMask (`@ethereumjs/wallet` / `ethereumjs-wallet`) likewise uses raw UTF-8 bytes. See the
   finding below.
2. **`dk = scrypt(password, salt, n=262144, r=8, p=1, dklen=32)`** — identical profile and identical
   Rust call to the BLS side; reuse `keystore::crypto::derive_scrypt` (it is already parameterized
   and hardened). Salt = 32 random bytes.
3. **`ciphertext = AES-128-CTR(key = dk[0..16], iv = 16 random bytes, plaintext = secret)`** — the
   secret is the **32-byte secp256k1 private key** (big-endian). CTR is symmetric; reuse
   `keystore::crypto::Aes128Ctr` (= `ctr::Ctr128BE<aes::Aes128>`) + `apply_keystream`, exactly as
   the BLS encrypt does. geth uses `derivedKey[:16]` as the AES key and the whole 16-byte IV as the
   initial 128-bit big-endian counter (matches our `Ctr128BE` and Go's `cipher.NewCTR`).
4. **`mac = keccak256(dk[16..32] ‖ ciphertext)`** — **Keccak-256, not SHA-256.** geth:
   `mac := crypto.Keccak256(derivedKey[16:32], cipherText)`. Needs `sha3::Keccak256` (add `sha3` to
   the keystore crate — workspace dep already, see `existing-code-map.md`). The dk split
   (`[0..16]` cipher key, `[16..32]` MAC key) is the **same** as EIP-2335; only the hash differs.
5. **`address`** = `keccak256(uncompressed_pubkey[1..])[12..]`, lowercase hex, **no `0x`**
   (`ethernal-signer`'s `pubkey_address`; then `hex::encode`, do not EIP-55 the *file* field —
   geth stores lowercase). The EIP-55 form is for **display** only (F-15).
6. **`id`** = UUID v4 from 16 random bytes — reuse `keystore::encrypt::format_uuid_v4` (currently
   `pub(crate)`; expose it). All randomness (salt, iv, uuid) via the injectable `Entropy` trait
   (S-4), so the byte-gate can pin them.

## Filename convention (geth `UTC--…`)

Source: go-ethereum `accounts/keystore/key.go`:
```go
func keyFileName(keyAddr common.Address) string {
    ts := time.Now().UTC()
    return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
}
func toISO8601(t time.Time) string {           // for UTC, tz = "Z"
    return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s",
        t.Year(), t.Month(), ... t.Nanosecond(), tz)
}
```
So: **`UTC--<YYYY>-<MM>-<DD>T<HH>-<MM>-<SS>.<9-digit-nanos>Z--<40-hex-address-no-0x>`**, e.g.
`UTC--2026-07-18T14-22-05.123456789Z--9858effd232b4033e47d90003d41ec34ecaeda94`. Note: colons in the
ISO-8601 time are rendered as **dashes** (filesystem-safe), nanosecond precision (9 digits), literal
trailing `Z`, address **lowercase without `0x`**. This is what geth/foundry keystore directories
scan for. (Contrast the BLS filename `keystore-m_12381_3600_i_0_0-<unixsecs>.json` — different
consumer, different convention, F-4.)

---

## CI byte-reproduction fixture (G3 / C-1) — VERIFIED, real-tool-sourced

The published "testpassword" vectors on the wiki/ethereum.org did **not** all recompute (one
fetched copy failed my scrypt check — likely a transcription error in the rendered page). Rather
than ship an unverified fixture, I generated a real v3 keystore with `cast wallet import` and
reproduced every crypto value in a clean-room run. **Use this as the CI byte-gate.**

**Inputs** (secret is the canonical Web3 test key; password `testpassword`):
- secret (plaintext) = `7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d`
- password = `testpassword` (raw bytes, no NFKD)
- salt = `d64e482e89fcf3347581ee24419ac767585213bee5d34f4e1d9ff35e27cc4e5f`
- iv = `fdf4d6e499712b16289796551e79640c`
- scrypt params = **`n=8192, r=8, p=1, dklen=32`** (see profile note)

**Keystore `cast` produced** (verbatim; round-trip-decrypted by `cast wallet decrypt-keystore` back
to the secret above — proof foundry reads it):
```json
{
  "crypto": {
    "cipher": "aes-128-ctr",
    "cipherparams": { "iv": "fdf4d6e499712b16289796551e79640c" },
    "ciphertext": "a5ae5118b012fe13922fac29e5689452ea27d1ecd6f1311f8fbe2aaa296ba611",
    "kdf": "scrypt",
    "kdfparams": { "dklen": 32, "n": 8192, "p": 1, "r": 8,
      "salt": "d64e482e89fcf3347581ee24419ac767585213bee5d34f4e1d9ff35e27cc4e5f" },
    "mac": "8163019b12c28075a5d50502e46fe9d819280ccf09d992230ae03e21e0ba5d6b"
  },
  "id": "98453a0c-0f41-4b6e-a18e-0b1b387d3b39",
  "version": 3
}
```

**Interop finding (`address` field is require-vs-tolerate, Q3):** foundry's `cast` **omits** the
top-level `address` field (the file above has none); geth **includes** it (lowercase, no `0x`). Our
writer includes it (F-3) — geth-compatible, and foundry **tolerates** the extra field on read (the
file we wrote with an `address` still round-trips through `cast`). So including `address` is safe
for both. The open question — does geth/MetaMask *require* it or merely prefer it — is a manual-
session check (`cross-tool-parity.md`); including it sidesteps the risk either way.

**Clean-room reproduction (Python `hashlib.scrypt` + `cast keccak` + OpenSSL AES-128-CTR):**
- `dk = scrypt(testpassword, salt, n=8192,r=8,p=1,32)` = `d1cdfdbf65ad65f9eee25ebf72a38726d82f90e858ad413c97b3de6a07737c36`
- `mac = keccak256(dk[16..32] ‖ ciphertext)` = `8163019b12c28075a5d50502e46fe9d819280ccf09d992230ae03e21e0ba5d6b` ✓ (matches the file)
- `AES-128-CTR(dk[0..16], iv, secret)` = `a5ae5118b012fe13922fac29e5689452ea27d1ecd6f1311f8fbe2aaa296ba611` ✓ (matches `ciphertext`)
- `address(secret)` = `008aeeda4d805471df9b2a5b0f38a0c3bcba786b` ✓

So the fixture is internally consistent and our (scrypt → AES-CTR → keccak-MAC) pipeline reproduces
it exactly. **The CI test:** feed the writer `{secret, password, salt, iv, uuid_bytes, n=8192,r=8,
p=1}`, assert the produced `ciphertext` == `a5ae5118…` and `mac` == `8163019b…`.

**Scrypt-profile note (important for CI):** `cast wallet import` uses the **light** profile
`n=8192` (foundry's default), whereas **production writes `n=262144`** (F-3). scrypt is
parameter-agnostic — the pipeline is identical — so the byte-gate SHOULD run at `n=8192` (≈ms,
keeps CI fast; the BLS EIP-2335 test at `n=262144` is ~1–2 s). **Recommendation:** the v3 `encrypt`
function should take scrypt params as an argument (as `derive_scrypt` already does), with the CLI
passing the production `n=262144` profile and the byte-gate injecting `n=8192`. Production-`n`
correctness is then anchored by the C-2 cross-tool session (`cast`/geth unlock a real `n=262144`
file we wrote) plus a self encrypt→decrypt round-trip. A published `n=262144` "testpassword" scrypt
vector also exists (salt `ab0c7876…`, `r=1,p=8`, dk `fac192ce…`, mac `2103ac29…`) but uses
*non-standard* `r=1,p=8` and needs a full 256 MB scrypt to recompute — the self-generated fixture
above is the better CI anchor.

---

## Contradicts / extends the PRD (the passphrase-normalization trap)

**Finding (most important, PRD-relevant): the v3 writer must use the passphrase as RAW bytes and
must NOT reuse `keystore::crypto::normalize_passphrase`.** The PRD's D-1 and F-7 list scrypt /
AES-128-CTR / uuid / `Entropy` as "reused" and are **silent on passphrase normalization** — so the
natural, wrong move is to reuse the EIP-2335 `normalize_passphrase` (NFKD + C0/C1/DEL strip,
`keystore/src/crypto.rs:34`). geth (`scrypt.Key(auth, …)`, no normalization) and MetaMask (raw UTF-8)
do **not** normalize. For an ASCII passphrase this is invisible; for any passphrase containing
non-ASCII or NFKD-unstable or control characters, NFKD-normalizing would derive a **different
`dk`**, producing a keystore whose MAC and ciphertext geth/MetaMask cannot reproduce → **import
fails**. Since geth/foundry/MetaMask import+unlock is the hard release gate (G1/C-2), this would
silently break the feature for exactly the security-conscious users who pick a complex passphrase.
**Decision for the writer:** pass the raw passphrase bytes straight to `derive_scrypt`; do not route
through `normalize_passphrase`. (Enforce the ≥8-byte minimum on the raw bytes, F-7.)

**Related:** `keystore::crypto::checksum_message` hardcodes SHA-256 (`crypto.rs:113`) — it is
EIP-2335-shaped and must **not** be bent to v3. v3 needs a new `keccak256(dk[16..32] ‖ ct)` (a
3-line function over `sha3::Keccak256`). See `existing-code-map.md` for the full reuse/no-reuse
split.

**MetaMask import:** MetaMask imports a v3 JSON via *Import Account → JSON File* and accepts
scrypt v3 (and pbkdf2). It is case-sensitive on the password and requires a well-formed v3 object;
the `address` field's case does not matter to it (it recomputes from the key). No MetaMask-specific
field is required beyond the standard v3 shape above.
