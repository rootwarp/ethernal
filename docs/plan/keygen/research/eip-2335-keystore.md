# Research — EIP-2335 v4 keystore creation (scrypt)

**Question:** what are the exact bytes and field conventions we must reproduce to *write* an
EIP-2335 v4 scrypt keystore that (a) byte-matches the spec's scrypt test vector, (b) is what
staking-deposit-cli / ethstaker-deposit-cli write, and (c) decrypts back through our existing
`crates/keystore` `Loader` and imports into validator clients?

**Verdict: reproduce the scrypt profile as planned — the spec vector is verified end-to-end.**
I independently ran the EIP-2335 scrypt vector through scrypt → checksum → AES-128-CTR and
recovered the published secret exactly (below). The scrypt parameters in the spec vector and
in staking-deposit-cli's writer are **the same** (`n=262144, r=8, p=1, dklen=32`), so
"reproduce the spec vector byte-for-byte" and "write the profile staking-deposit-cli writes"
are the *same* profile — but they differ in the *variable* fields (salt/iv/uuid/path/description),
which is why the overview injects fixed salt/iv/uuid to gate the vector.

## v4 JSON structure and field order

Source: [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335). Top-level field order (what
staking-deposit-cli serializes, declaration order):
`crypto` · `description` · `pubkey` · `path` · `uuid` · `version`. Inside `crypto`, each of
`kdf` / `checksum` / `cipher` is `{ function, params, message }` (in that order).

```json
{
  "crypto": {
    "kdf":      { "function": "scrypt", "params": { "dklen":32,"n":262144,"p":1,"r":8,"salt":"<32-byte hex>" }, "message": "" },
    "checksum": { "function": "sha256", "params": {}, "message": "<32-byte hex>" },
    "cipher":   { "function": "aes-128-ctr", "params": { "iv":"<16-byte hex>" }, "message": "<32-byte hex ciphertext>" }
  },
  "description": "",
  "pubkey": "<48-byte hex>",
  "path": "m/12381/3600/<i>/0/0",
  "uuid": "<uuid v4>",
  "version": 4
}
```

## Encryption process (what our writer must do)

1. **Normalize the passphrase:** NFKD, then strip C0 (`U+0000–U+001F`), C1 (`U+0080–U+009F`),
   and DEL (`U+007F`) control codes; UTF-8 encode. **This is already implemented on the decrypt
   side** — `normalize_passphrase` + `is_stripped_control` in
   `crates/keystore/src/keystore.rs:298-313`. The encrypt side must use the *identical* function
   (see `existing-code-map.md` — it is currently private).
2. **Derive the key:** `dk = scrypt(password, salt, n=262144, r=8, p=1, dklen=32)`. In Rust,
   `scrypt::Params::new(log_n=18, r=8, p=1, dklen=32)` then `scrypt::scrypt(...)` — exactly the
   call already used for decrypt at `keystore.rs:339-346` (`log_n = n.trailing_zeros()`).
3. **cipher:** `ciphertext = AES-128-CTR(key = dk[0..16], iv = <16 random bytes>, secret)`.
   CTR is symmetric, so this is the same `Aes128Ctr` (`Ctr128BE<Aes128>`) type + `apply_keystream`
   the decrypt path uses (`keystore.rs:23, 287-291`).
4. **checksum:** `message = SHA256(dk[16..32] || ciphertext)` (`keystore.rs:264-267`).
5. **secret:** the 32-byte BLS signing SK (big-endian, from `SecretKey::to_bytes()`).
   Decryption-key truncation rule: cipher key = `dk[0..16]`, checksum pre-image uses
   `dk[16..32]` — `dklen=32` splits into exactly these two 16-byte halves.

## Spec scrypt test vector (byte-gate fixture — verified)

Source: EIP-2335 "Test Vectors". **Password (the reason the vector exists):**
`𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑` — U+1D531 U+1D522 U+1D530 U+1D531 U+1D52D U+1D51E U+1D530 U+1D530 U+1D534
U+1D52C U+1D52F U+1D521 (mathematical-fraktur "testpassword") followed by U+1F511 (🔑, key
emoji). It is deliberately non-ASCII to exercise NFKD: `NFKD(pw)` = `"testpassword🔑"`, whose
UTF-8 is `0x7465737470617373776f7264f09f9491`. **A reader who assumes ASCII will break the
normalization path** — verified locally that our NFKD-then-strip yields exactly that hex.

```json
{
  "crypto": {
    "kdf":      { "function":"scrypt","params":{"dklen":32,"n":262144,"p":1,"r":8,
                  "salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":"" },
    "checksum": { "function":"sha256","params":{},
                  "message":"d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484" },
    "cipher":   { "function":"aes-128-ctr","params":{"iv":"264daa3f303d7259501c93d997d84fe6"},
                  "message":"06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f" }
  },
  "description": "This is a test keystore that uses scrypt to secure the secret.",
  "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
  "path": "m/12381/60/3141592653/589793238",
  "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
  "version": 4
}
```
Decrypts to secret `0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`.

**Independent verification (local, Python `hashlib.scrypt` + AES-128-CTR):**
`SHA256(dk[16:32] || cipher_message)` == the vector's checksum message ✓; AES-128-CTR decrypt
with `dk[0:16]` == the vector's secret ✓. So the vector is internally consistent and our
scrypt/CTR/checksum wiring reproduces it. **How the overview gates it (verification strategy
#4):** inject this vector's `salt` and `iv` (and a fixed `uuid`) through the `Entropy` trait,
encrypt the vector's secret with the vector's password, and assert the produced `crypto`
section equals the JSON above byte-for-byte; then decrypt via the existing `Loader` and confirm
the secret round-trips.

The spec also gives a **pbkdf2** vector (same password/secret; `c=262144`, `prf=hmac-sha256`;
checksum `8a9f5d99…febf1`, cipher `cee03fde…c16ad`, path `m/12381/60/0/0`, uuid
`64625def-…`). We do **not** write pbkdf2 (non-goal), but the existing `Loader` decrypts it
(`keystore.rs:349-363`), so it is a free decrypt-side regression fixture.

## What staking-deposit-cli / ethstaker-deposit-cli actually write

From [staking-deposit-cli `key_handling/keystore.py`](https://github.com/ethereum/staking-deposit-cli/blob/master/staking_deposit/key_handling/keystore.py)
and [`credentials.py`](https://github.com/ethereum/staking-deposit-cli/blob/master/staking_deposit/credentials.py)
(master branch; ethstaker-deposit-cli forked this writer and, to the extent verified here, uses
the same scrypt profile and encrypt shape — confirm during the manual G1/G2 session):

- **`ScryptKeystore` KDF params:** `{'dklen': 32, 'n': 2**18, 'r': 8, 'p': 1}` — confirms
  `n=262144`.
- **`Keystore.encrypt(*, secret, password, path='', kdf_salt=None, aes_iv=None)`:** salt =
  `randbits(256).to_bytes(32,'big')` (**32-byte** random salt), aes_iv =
  `randbits(128).to_bytes(16,'big')` (**16-byte** iv), uuid = `str(uuid4())`, **`description`
  defaults to `''`** (empty), `path` = the value passed in.
- **`signing_keystore(password)`:** `ScryptKeystore.encrypt(secret=signing_sk.to_bytes(32,'big'),
  password=password, path=self.signing_key_path)` — i.e. the **signing** key's SK, path
  `m/12381/3600/i/0/0`. **Only the signing keystore is written to disk; the withdrawal key is
  not** (it stays recoverable from the mnemonic). This bounds K2-x scope: we encrypt/write one
  keystore per validator, the signing key.
- **Filename convention:** `'keystore-%s-%i.json' % (keystore.path.replace('/', '_'),
  time.time())` → **`keystore-m_12381_3600_<i>_0_0-<unixtime>.json`** (unix seconds, int). This
  matches the overview's convention and is what validator-client import tooling recognizes.

## Validator-client import requirements (G1)

- **Filename** as above (path with `/`→`_`, unix-seconds suffix). Clients scan a directory of
  `keystore-*.json`.
- The keystore must be a valid EIP-2335 v4 JSON with a matching `pubkey` field; clients derive
  the pubkey from the decrypted SK and cross-check it.
- Client-specific notes to keep in mind for the manual G1 session (not blocking, but the reason
  G1 is "import into ≥1 client"): **Lighthouse** `lighthouse account validator import` reads the
  deposit-cli directory layout and prompts (or takes `--password-file`) per keystore, then
  records it in `validator_definitions.yml`; **Teku** expects each `keystore-*.json` to have a
  sibling password `.txt` of the same basename; **Prysm/Nimbus** import the `keystore-*.json`
  directly with a supplied password. None of these constrain the *file bytes* beyond EIP-2335 +
  the filename — our job is byte-correct keystores + the right filename.

## Implications for our implementation

1. **K2-1 reuses the decrypt-side crypto, run in reverse.** `normalize_passphrase`, the scrypt
   call shape, `Aes128Ctr`, and the `SHA256(dk[16:32]||ct)` checksum all already exist in
   `keystore.rs` for decrypt — the encrypt path is the same primitives with a random salt/iv and
   `apply_keystream` over the *plaintext* secret. See `existing-code-map.md` for which of these
   are currently private and must be exposed.
2. **Write `description: ""`, `path: "m/12381/3600/<i>/0/0"`, `uuid: <v4>`, `version: 4`.** Match
   staking-deposit-cli's empty description; do not copy the spec vector's description string into
   real output (that string is only for the byte-gate fixture).
3. **UUID v4 hand-formatted from 16 random bytes** (D-1: no `uuid` crate) — set version nibble to
   `4` and variant bits to `10`, format `8-4-4-4-12`. Inject the 16 bytes through the `Entropy`
   trait so the byte-gate can pin a fixed uuid.
4. **Salt = 32 random bytes, iv = 16 random bytes**, both from the injectable `Entropy` trait
   (K1-3). The byte-gate injects the vector's `salt`/`iv`.
5. **Filename:** `keystore-m_12381_3600_<i>_0_0-<unixtime>.json`, unix **seconds**. Atomic 0600
   write, refuse overwrite (K2-2; see `existing-code-map.md` for why `core::output`'s atomic
   writer is not directly reusable).
6. **Round-trip gate:** after encrypt, decrypt with the existing `Loader` and assert the secret
   matches — this is the M-K2 milestone and doubles as the "importable by our own `gen`" proof.
