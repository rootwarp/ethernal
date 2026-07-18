//! Pure Web3 Secret Storage v3 (scrypt) keystore writer.
//!
//! Takes already-drawn `salt`/`iv`/`uuid_bytes` (no RNG) and the 20-byte
//! Ethereum address, and returns compact JSON bytes. Randomness and address
//! derivation live outside this module so `keystore` stays free of `core` /
//! `signer` edges.
//!
//! **Not** the EIP-2335 writer ([`crate::encrypt`]): v3 feeds the passphrase to
//! scrypt as **raw bytes** (no NFKD) and tags integrity with **Keccak-256**
//! (not SHA-256).

use ctr::cipher::{KeyIvInit, StreamCipher};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::crypto::{self, Aes128Ctr};
use crate::encrypt::format_uuid_v4;
use crate::error::KeystoreError;

/// scrypt cost parameters, injectable so the CI byte-gate (G3) runs at
/// `n=8192` while production emits `n=262144` (both read-compatible — readers
/// take `n` from JSON).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScryptParams {
    /// CPU/memory cost parameter (power of two).
    pub n: u64,
    /// Block size parameter.
    pub r: u32,
    /// Parallelization parameter.
    pub p: u32,
    /// Derived-key length in bytes (must be ≥ 32 for cipher+MAC split).
    pub dklen: usize,
}

impl ScryptParams {
    /// geth-standard / repo profile (F-3). The CLI passes this; the byte-gate
    /// injects `{n: 8192, r: 8, p: 1, dklen: 32}`.
    pub const STANDARD: ScryptParams = ScryptParams {
        n: 262_144,
        r: 8,
        p: 1,
        dklen: 32,
    };
}

/// Inputs for [`encrypt_v3`]. All randomness is caller-supplied so this
/// function stays pure (no `Entropy`, no filesystem, no `keystore → core`).
///
/// # Caller responsibilities
///
/// - **`salt` / `iv` / `uuid_bytes` uniqueness:** this module does not draw RNG
///   and does not check for reuse. Production callers **must** fill each field
///   with fresh CSPRNG bytes per keystore. Injectable fixed values exist only
///   for the cast byte-gate and tests.
/// - **Passphrase:** `password` is fed to scrypt as **raw bytes**. Do not
///   pre-normalize; geth/MetaMask use raw UTF-8 (C-4).
/// - **`secret` / `address`:** `secret` must be the 32-byte secp256k1 private
///   key; `address` must be the matching 20-byte Ethereum address (computed by
///   the bin via `signer`). Canonicality (`0 < k < n`) is the caller's job.
pub struct EncryptV3Input<'a> {
    /// 32-byte secp256k1 secret key (big-endian).
    pub secret: &'a [u8],
    /// RAW keystore passphrase bytes — fed straight to scrypt, **no**
    /// normalization (C-4).
    pub password: &'a [u8],
    /// The 20-byte Ethereum address. Written lowercase-no-`0x` to the JSON
    /// `address` field.
    pub address: [u8; 20],
    /// 32-byte scrypt salt (drawn by the caller; injectable for the byte-gate).
    pub salt: [u8; 32],
    /// 16-byte AES-128-CTR IV.
    pub iv: [u8; 16],
    /// 16 random bytes; formatted to a UUID v4 string inside [`encrypt_v3`].
    pub uuid_bytes: [u8; 16],
    /// scrypt cost parameters (production: [`ScryptParams::STANDARD`]).
    pub scrypt: ScryptParams,
}

// ---------------------------------------------------------------------------
// Serialize structs — purpose-built Web3 v3 shape (not a reuse of EIP-2335
// KeystoreOut). serde emits fields in declaration order.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct KeystoreV3Out {
    crypto: CryptoV3Out,
    id: String,
    address: String,
    version: i64,
}

#[derive(Serialize)]
struct CryptoV3Out {
    cipher: &'static str,
    cipherparams: CipherParamsV3,
    ciphertext: String,
    kdf: &'static str,
    kdfparams: ScryptParamsV3,
    mac: String,
}

#[derive(Serialize)]
struct CipherParamsV3 {
    iv: String,
}

#[derive(Serialize)]
struct ScryptParamsV3 {
    dklen: usize,
    n: u64,
    p: u32,
    r: u32,
    salt: String,
}

/// Encrypts `input.secret` into a Web3 Secret Storage v3 scrypt keystore JSON.
///
/// Pipeline: `derive_scrypt(RAW password, salt, n,r,p,dklen)` →
/// AES-128-CTR(`dk[0..16]`, `iv`) over secret →
/// `mac = keccak256(dk[16..32] ‖ ct)` → serialize with fields in declaration
/// order. `version` is always `3`.
///
/// Rejects `secret` lengths other than 32 with [`KeystoreError::Encrypt`].
///
/// **Does not** call [`crypto::normalize_passphrase`] or
/// [`crypto::checksum_message`] (C-4 / F-3).
pub fn encrypt_v3(input: &EncryptV3Input<'_>) -> Result<Vec<u8>, KeystoreError> {
    let encrypt_err = |detail: String| KeystoreError::Encrypt { detail };

    if input.secret.len() != 32 {
        return Err(encrypt_err(format!(
            "secret must be 32 bytes, got {}",
            input.secret.len()
        )));
    }

    // RAW passphrase — never normalize (C-4). geth/MetaMask use raw UTF-8.
    let dk = crypto::derive_scrypt(
        input.password,
        &input.salt,
        input.scrypt.n,
        input.scrypt.r,
        input.scrypt.p,
        input.scrypt.dklen,
    )
    .map_err(|e| encrypt_err(format!("kdf: {e}")))?;

    // Belt-and-suspenders: `derive_scrypt` always returns `dklen` bytes and
    // rejects `dklen < 32`; kept for parity with the EIP-2335 encrypt path.
    if dk.len() < 32 {
        return Err(encrypt_err(format!(
            "kdf: derived key too short: {} bytes, need at least 32",
            dk.len()
        )));
    }

    // AES-128-CTR encrypt: ciphertext = keystream XOR secret (CTR is symmetric).
    let mut cipher = Aes128Ctr::new_from_slices(&dk[0..16], &input.iv)
        .map_err(|err| encrypt_err(format!("cipher: invalid key/iv length: {err}")))?;
    let mut ciphertext = Zeroizing::new(input.secret.to_vec());
    cipher.apply_keystream(&mut ciphertext);

    let mac = crypto::v3_mac(&dk, &ciphertext);

    let out = KeystoreV3Out {
        crypto: CryptoV3Out {
            cipher: "aes-128-ctr",
            cipherparams: CipherParamsV3 {
                iv: hex::encode(input.iv),
            },
            ciphertext: hex::encode(ciphertext.as_slice()),
            kdf: "scrypt",
            kdfparams: ScryptParamsV3 {
                dklen: input.scrypt.dklen,
                n: input.scrypt.n,
                p: input.scrypt.p,
                r: input.scrypt.r,
                salt: hex::encode(input.salt),
            },
            mac: hex::encode(mac),
        },
        id: format_uuid_v4(input.uuid_bytes),
        address: hex::encode(input.address),
        version: 3,
    };

    serde_json::to_vec(&out).map_err(|err| encrypt_err(format!("serialize: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ctr::cipher::{KeyIvInit, StreamCipher};

    use crate::crypto::{self, Aes128Ctr};

    /// Canonical Web3 test key (research/web3-v3-keystore.md §CI fixture).
    const FIXTURE_SECRET: [u8; 32] = [
        0x7a, 0x28, 0xb5, 0xba, 0x57, 0xc5, 0x36, 0x03, 0xb0, 0xb0, 0x7b, 0x56, 0xbb, 0xa7, 0x52,
        0xf7, 0x78, 0x4b, 0xf5, 0x06, 0xfa, 0x95, 0xed, 0xc3, 0x95, 0xf5, 0xcf, 0x6c, 0x75, 0x14,
        0xfe, 0x9d,
    ];
    const FIXTURE_PASSWORD: &[u8] = b"testpassword";
    const FIXTURE_SALT: [u8; 32] = [
        0xd6, 0x4e, 0x48, 0x2e, 0x89, 0xfc, 0xf3, 0x34, 0x75, 0x81, 0xee, 0x24, 0x41, 0x9a, 0xc7,
        0x67, 0x58, 0x52, 0x13, 0xbe, 0xe5, 0xd3, 0x4f, 0x4e, 0x1d, 0x9f, 0xf3, 0x5e, 0x27, 0xcc,
        0x4e, 0x5f,
    ];
    const FIXTURE_IV: [u8; 16] = [
        0xfd, 0xf4, 0xd6, 0xe4, 0x99, 0x71, 0x2b, 0x16, 0x28, 0x97, 0x96, 0x55, 0x1e, 0x79, 0x64,
        0x0c,
    ];
    /// UUID `98453a0c-0f41-4b6e-a18e-0b1b387d3b39` (already v4/variant-10).
    const FIXTURE_UUID_BYTES: [u8; 16] = [
        0x98, 0x45, 0x3a, 0x0c, 0x0f, 0x41, 0x4b, 0x6e, 0xa1, 0x8e, 0x0b, 0x1b, 0x38, 0x7d, 0x3b,
        0x39,
    ];
    /// `address(secret)` = `008aeeda4d805471df9b2a5b0f38a0c3bcba786b`.
    const FIXTURE_ADDRESS: [u8; 20] = [
        0x00, 0x8a, 0xee, 0xda, 0x4d, 0x80, 0x54, 0x71, 0xdf, 0x9b, 0x2a, 0x5b, 0x0f, 0x38, 0xa0,
        0xc3, 0xbc, 0xba, 0x78, 0x6b,
    ];
    const FIXTURE_CIPHERTEXT: &str =
        "a5ae5118b012fe13922fac29e5689452ea27d1ecd6f1311f8fbe2aaa296ba611";
    const FIXTURE_MAC: &str = "8163019b12c28075a5d50502e46fe9d819280ccf09d992230ae03e21e0ba5d6b";

    /// cast light profile used by the verified fixture.
    const LIGHT: ScryptParams = ScryptParams {
        n: 8192,
        r: 8,
        p: 1,
        dklen: 32,
    };

    fn fixture_input() -> EncryptV3Input<'static> {
        EncryptV3Input {
            secret: &FIXTURE_SECRET,
            password: FIXTURE_PASSWORD,
            address: FIXTURE_ADDRESS,
            salt: FIXTURE_SALT,
            iv: FIXTURE_IV,
            uuid_bytes: FIXTURE_UUID_BYTES,
            scrypt: LIGHT,
        }
    }

    /// G3 byte-gate: reproduce cast-produced ciphertext + mac byte-for-byte.
    #[test]
    fn g3_byte_gate_cast_fixture_ciphertext_and_mac() {
        let bytes = encrypt_v3(&fixture_input()).expect("encrypt_v3 fixture");
        let val: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

        assert_eq!(val["crypto"]["ciphertext"], FIXTURE_CIPHERTEXT);
        assert_eq!(val["crypto"]["mac"], FIXTURE_MAC);
        assert_eq!(
            val["crypto"]["cipherparams"]["iv"],
            "fdf4d6e499712b16289796551e79640c"
        );
        assert_eq!(
            val["crypto"]["kdfparams"]["salt"],
            "d64e482e89fcf3347581ee24419ac767585213bee5d34f4e1d9ff35e27cc4e5f"
        );
        assert_eq!(val["crypto"]["kdfparams"]["n"], 8192);
        assert_eq!(val["crypto"]["kdfparams"]["r"], 8);
        assert_eq!(val["crypto"]["kdfparams"]["p"], 1);
        assert_eq!(val["crypto"]["kdfparams"]["dklen"], 32);

        // Fixture file crypto values must agree (guards fixture drift).
        let fixture_raw = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/web3-v3-cast-fixture.json"
        ))
        .expect("fixture");
        let fixture_val: serde_json::Value =
            serde_json::from_slice(&fixture_raw).expect("fixture json");
        assert_eq!(
            val["crypto"]["ciphertext"],
            fixture_val["crypto"]["ciphertext"]
        );
        assert_eq!(val["crypto"]["mac"], fixture_val["crypto"]["mac"]);
        assert_eq!(
            val["crypto"]["cipherparams"],
            fixture_val["crypto"]["cipherparams"]
        );
        assert_eq!(
            val["crypto"]["kdfparams"],
            fixture_val["crypto"]["kdfparams"]
        );
    }

    /// Emitted JSON shape: version 3, aes-128-ctr, scrypt, address, id; secret
    /// never serialized.
    #[test]
    fn encrypt_v3_json_shape_and_no_plaintext_secret() {
        let bytes = encrypt_v3(&fixture_input()).expect("encrypt_v3");
        let body = std::str::from_utf8(&bytes).expect("utf-8");
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(val["version"], 3);
        assert_eq!(val["crypto"]["cipher"], "aes-128-ctr");
        assert_eq!(val["crypto"]["kdf"], "scrypt");
        assert_eq!(val["address"], "008aeeda4d805471df9b2a5b0f38a0c3bcba786b");
        assert_eq!(val["id"], "98453a0c-0f41-4b6e-a18e-0b1b387d3b39");
        assert!(val.get("crypto").and_then(|c| c.get("mac")).is_some());

        let secret_hex = hex::encode(FIXTURE_SECRET);
        assert!(
            !body.contains(&secret_hex),
            "plaintext secret must not appear in keystore JSON"
        );
    }

    /// C-4 raw-passphrase guard: non-ASCII / NFKD-unstable password must use
    /// raw UTF-8 for scrypt, not EIP-2335 normalize_passphrase.
    #[test]
    fn c4_raw_passphrase_not_normalized() {
        // Fullwidth digits are NFKD-unstable: "\u{ff11}\u{ff12}…" → "12…" under NFKD.
        let pw = "１２３４５６７８"; // fullwidth 1-8
        let pw_bytes = pw.as_bytes();
        let salt = [0x33u8; 32];
        let n = 16u64;
        let r = 8u32;
        let p = 1u32;
        let dklen = 32usize;

        let dk_raw = crypto::derive_scrypt(pw_bytes, &salt, n, r, p, dklen).expect("raw");
        let normalized = crypto::normalize_passphrase(pw_bytes);
        let dk_norm =
            crypto::derive_scrypt(&normalized, &salt, n, r, p, dklen).expect("normalized");
        assert_ne!(
            dk_raw.as_slice(),
            dk_norm.as_slice(),
            "fixture passphrase must be NFKD-unstable so the guard is meaningful"
        );

        let secret = [0x44u8; 32];
        let iv = [0x55u8; 16];
        let input = EncryptV3Input {
            secret: &secret,
            password: pw_bytes,
            address: [0u8; 20],
            salt,
            iv,
            uuid_bytes: [0x66u8; 16],
            scrypt: ScryptParams { n, r, p, dklen },
        };
        let bytes = encrypt_v3(&input).expect("encrypt_v3");
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let ct_hex = val["crypto"]["ciphertext"].as_str().unwrap();
        let mac_hex = val["crypto"]["mac"].as_str().unwrap();
        let ct = hex::decode(ct_hex).unwrap();
        let mac = hex::decode(mac_hex).unwrap();

        // Expected from RAW dk — must match encrypt_v3 output.
        let mut cipher = Aes128Ctr::new_from_slices(&dk_raw[0..16], &iv).unwrap();
        let mut expected_ct = secret.to_vec();
        cipher.apply_keystream(&mut expected_ct);
        let expected_mac = crypto::v3_mac(&dk_raw, &expected_ct);
        assert_eq!(
            ct, expected_ct,
            "ciphertext must come from raw-passphrase dk"
        );
        assert_eq!(mac, expected_mac, "mac must come from raw-passphrase dk");

        // And must differ from what normalize_passphrase would have produced.
        let mut cipher_n = Aes128Ctr::new_from_slices(&dk_norm[0..16], &iv).unwrap();
        let mut norm_ct = secret.to_vec();
        cipher_n.apply_keystream(&mut norm_ct);
        let norm_mac = crypto::v3_mac(&dk_norm, &norm_ct);
        assert_ne!(ct, norm_ct);
        assert_ne!(mac.as_slice(), norm_mac.as_slice());
    }

    /// Self encrypt round-trip: AES-CTR decrypt recovers the secret.
    #[test]
    fn encrypt_v3_round_trip_aes_ctr() {
        let secret = [0x77u8; 32];
        let password = b"round-trip-v3-password";
        let salt = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let scrypt = ScryptParams {
            n: 16,
            r: 8,
            p: 1,
            dklen: 32,
        };
        let bytes = encrypt_v3(&EncryptV3Input {
            secret: &secret,
            password,
            address: [0xabu8; 20],
            salt,
            iv,
            uuid_bytes: [0xcd; 16],
            scrypt,
        })
        .expect("encrypt_v3");

        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let ct = hex::decode(val["crypto"]["ciphertext"].as_str().unwrap()).unwrap();
        assert_eq!(ct.len(), 32);

        let dk = crypto::derive_scrypt(password, &salt, scrypt.n, scrypt.r, scrypt.p, scrypt.dklen)
            .expect("dk");
        let mut cipher = Aes128Ctr::new_from_slices(&dk[0..16], &iv).unwrap();
        let mut recovered = ct.clone();
        cipher.apply_keystream(&mut recovered);
        assert_eq!(recovered.as_slice(), secret.as_slice());

        // MAC must verify under the same dk.
        let mac = hex::decode(val["crypto"]["mac"].as_str().unwrap()).unwrap();
        assert_eq!(mac.as_slice(), crypto::v3_mac(&dk, &ct).as_slice());
    }

    #[test]
    fn encrypt_v3_rejects_wrong_secret_length() {
        let input = EncryptV3Input {
            secret: &[0u8; 16],
            password: b"pw",
            address: [0u8; 20],
            salt: [0u8; 32],
            iv: [0u8; 16],
            uuid_bytes: [0u8; 16],
            scrypt: ScryptParams {
                n: 16,
                r: 8,
                p: 1,
                dklen: 32,
            },
        };
        let err = encrypt_v3(&input).expect_err("short secret");
        match err {
            KeystoreError::Encrypt { detail } => {
                assert!(
                    detail.contains("secret must be 32 bytes"),
                    "detail = {detail}"
                );
            }
            other => panic!("want Encrypt, got {other:?}"),
        }
    }

    #[test]
    fn scrypt_params_standard_is_geth_profile() {
        assert_eq!(ScryptParams::STANDARD.n, 262_144);
        assert_eq!(ScryptParams::STANDARD.r, 8);
        assert_eq!(ScryptParams::STANDARD.p, 1);
        assert_eq!(ScryptParams::STANDARD.dklen, 32);
    }
}
