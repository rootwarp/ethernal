//! Pure EIP-2335 v4 scrypt keystore writer.
//!
//! Takes already-drawn `salt`/`iv`/`uuid_bytes` (no RNG) and returns compact
//! JSON bytes with fields in EIP-2335 declaration order. Randomness is drawn
//! by the caller; the filesystem write is outside this module.

use ctr::cipher::{KeyIvInit, StreamCipher};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::crypto::{self, Aes128Ctr};
use crate::error::KeystoreError;

// Re-export so callers can depend on `encrypt::ScryptParams` without reaching
// into the v3 module for a shared KDF profile type.
pub use crate::encrypt_v3::ScryptParams;

/// Inputs for [`encrypt`]. All randomness is caller-supplied so this function
/// stays pure (no `Entropy`, no `keystore → core` edge).
///
/// # Caller responsibilities (footguns)
///
/// - **`salt` / `iv` / `uuid_bytes` uniqueness:** this module does not draw RNG
///   and does not check for reuse. Production callers **must** fill each field
///   with fresh CSPRNG bytes per keystore (as `key_cmd` does). Reusing salt or
///   IV across encrypts is a crypto footgun; reusing `uuid_bytes` collides on
///   disk/UUID identity. Injectable fixed values exist only for the EIP-2335
///   spec vector and tests.
/// - **Passphrase lifetime:** `password` is borrowed for the call only; keep
///   the source buffer in [`zeroize::Zeroizing`] (or equivalent) at the call
///   site so secret material is scrubbed after use.
/// - **`scrypt`:** production must pass [`ScryptParams::STANDARD`] (N=2^18).
///   Tests may inject [`ScryptParams::FAST`] to avoid multi-second suite times.
pub struct EncryptInput<'a> {
    /// 32-byte BLS signing secret key (big-endian).
    pub secret: &'a [u8],
    /// Raw keystore passphrase; normalized inside via [`crypto::normalize_passphrase`].
    pub password: &'a [u8],
    /// HD path string written to the `path` field (e.g. `m/12381/3600/0/0/0`).
    pub path: &'a str,
    /// Compressed 48-byte signing public key; written as lowercase hex.
    pub pubkey: &'a [u8],
    /// 32-byte scrypt salt (drawn by the caller; injectable for the spec vector).
    /// **Must be unique and CSPRNG-fresh per keystore** — see struct docs.
    pub salt: [u8; 32],
    /// 16-byte AES-128-CTR IV. **Must be unique and CSPRNG-fresh per keystore.**
    pub iv: [u8; 16],
    /// 16 random bytes; formatted to a UUID v4 string inside [`encrypt`].
    /// **Must be unique and CSPRNG-fresh per keystore.**
    pub uuid_bytes: [u8; 16],
    /// scrypt cost parameters (production: [`ScryptParams::STANDARD`]).
    pub scrypt: ScryptParams,
}

// ---------------------------------------------------------------------------
// Serialize structs — field order is the EIP-2335 / staking-deposit-cli order.
// serde emits struct fields in declaration order (same trick as
// `core::output::JsonEntryOut`).
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct KeystoreOut {
    crypto: CryptoOut,
    description: String,
    pubkey: String,
    path: String,
    uuid: String,
    version: i64,
}

#[derive(Serialize)]
struct CryptoOut {
    kdf: ModuleOut<ScryptParamsOut>,
    checksum: ModuleOut<EmptyParams>,
    cipher: ModuleOut<CipherParamsOut>,
}

#[derive(Serialize)]
struct ModuleOut<P: Serialize> {
    function: &'static str,
    params: P,
    message: String,
}

#[derive(Serialize)]
struct ScryptParamsOut {
    dklen: usize,
    n: u64,
    p: u32,
    r: u32,
    salt: String,
}

#[derive(Serialize)]
struct EmptyParams {}

#[derive(Serialize)]
struct CipherParamsOut {
    iv: String,
}

/// Encrypts `input.secret` into an EIP-2335 v4 scrypt keystore JSON.
///
/// Pipeline: normalize passphrase → scrypt `(n,r,p,dklen)` from
/// [`EncryptInput::scrypt`] → AES-128-CTR → `sha256(dk[16..32] ‖ ct)` checksum
/// → serialize with fields in EIP-2335 order. `description` is always `""`;
/// `version` is always `4`. Production callers pass
/// [`ScryptParams::STANDARD`] (`n=262144,r=8,p=1,dklen=32`).
///
/// Rejects `secret` lengths other than 32 and `pubkey` lengths other than 48
/// with [`KeystoreError::Encrypt`] (EIP-2335 BLS signing key shapes).
pub fn encrypt(input: &EncryptInput<'_>) -> Result<Vec<u8>, KeystoreError> {
    let encrypt_err = |detail: String| KeystoreError::Encrypt { detail };

    if input.secret.len() != 32 {
        return Err(encrypt_err(format!(
            "secret must be 32 bytes, got {}",
            input.secret.len()
        )));
    }
    if input.pubkey.len() != 48 {
        return Err(encrypt_err(format!(
            "pubkey must be 48 bytes, got {}",
            input.pubkey.len()
        )));
    }

    let n = input.scrypt.n;
    let r = input.scrypt.r;
    let p = input.scrypt.p;
    let dklen = input.scrypt.dklen;

    let normalized = crypto::normalize_passphrase(input.password);
    let dk = crypto::derive_scrypt(&normalized, &input.salt, n, r, p, dklen)
        .map_err(|e| encrypt_err(format!("kdf: {e}")))?;

    // Belt-and-suspenders: `derive_scrypt` always returns `dklen` bytes; kept
    // for parity with the decrypt path where `dklen` is attacker-controlled
    // via JSON.
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

    let checksum = crypto::checksum_message(&dk, &ciphertext);

    let out = KeystoreOut {
        crypto: CryptoOut {
            kdf: ModuleOut {
                function: "scrypt",
                params: ScryptParamsOut {
                    dklen,
                    n,
                    p,
                    r,
                    salt: hex::encode(input.salt),
                },
                message: String::new(),
            },
            checksum: ModuleOut {
                function: "sha256",
                params: EmptyParams {},
                message: hex::encode(checksum),
            },
            cipher: ModuleOut {
                function: "aes-128-ctr",
                params: CipherParamsOut {
                    iv: hex::encode(input.iv),
                },
                message: hex::encode(ciphertext.as_slice()),
            },
        },
        description: String::new(),
        pubkey: hex::encode(input.pubkey),
        path: input.path.to_string(),
        uuid: format_uuid_v4(input.uuid_bytes),
        version: 4,
    };

    serde_json::to_vec(&out).map_err(|err| encrypt_err(format!("serialize: {err}")))
}

/// staking-deposit-cli filename: `keystore-<path-with-/-as-_>-<unix_secs>.json`.
pub fn keystore_filename(path: &str, unix_secs: i64) -> String {
    format!("keystore-{}-{unix_secs}.json", path.replace('/', "_"))
}

/// Formats 16 bytes as a UUID v4 string (`8-4-4-4-12` lowercase hex).
///
/// Sets the version nibble to `4` and the variant bits to `10`, then renders
/// the standard dashed form. No `uuid` crate (D-1).
pub(crate) fn format_uuid_v4(mut bytes: [u8; 16]) -> String {
    // version = 4  → high nibble of byte 6
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // variant = 10 → top two bits of byte 8
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keystore_filename_replaces_slashes_and_uses_unix_secs() {
        assert_eq!(
            keystore_filename("m/12381/3600/7/0/0", 1_700_000_000),
            "keystore-m_12381_3600_7_0_0-1700000000.json",
        );
    }

    #[test]
    fn encrypt_rejects_wrong_secret_length() {
        let input = EncryptInput {
            secret: &[0u8; 16],
            password: b"pw",
            path: "m/12381/3600/0/0/0",
            pubkey: &[0u8; 48],
            salt: [0u8; 32],
            iv: [0u8; 16],
            uuid_bytes: [0u8; 16],
            scrypt: ScryptParams::FAST,
        };
        let err = encrypt(&input).expect_err("short secret");
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
    fn encrypt_rejects_wrong_pubkey_length() {
        let input = EncryptInput {
            secret: &[0u8; 32],
            password: b"pw",
            path: "m/12381/3600/0/0/0",
            pubkey: &[0u8; 32],
            salt: [0u8; 32],
            iv: [0u8; 16],
            uuid_bytes: [0u8; 16],
            scrypt: ScryptParams::FAST,
        };
        let err = encrypt(&input).expect_err("short pubkey");
        match err {
            KeystoreError::Encrypt { detail } => {
                assert!(
                    detail.contains("pubkey must be 48 bytes"),
                    "detail = {detail}"
                );
            }
            other => panic!("want Encrypt, got {other:?}"),
        }
    }

    #[test]
    fn format_uuid_v4_sets_version_and_variant() {
        // Spec-vector uuid: 1d85ae20-35c5-4611-98e8-aa14a633906f
        // (already has version=4 and variant=10; formatter must preserve/force them).
        let bytes = [
            0x1d, 0x85, 0xae, 0x20, 0x35, 0xc5, 0x46, 0x11, 0x98, 0xe8, 0xaa, 0x14, 0xa6, 0x33,
            0x90, 0x6f,
        ];
        assert_eq!(
            format_uuid_v4(bytes),
            "1d85ae20-35c5-4611-98e8-aa14a633906f",
        );

        // Force version/variant from random-ish bytes that lack them.
        let mut raw = [0u8; 16];
        raw[0] = 0xab;
        raw[6] = 0x00; // clear version
        raw[8] = 0x00; // clear variant
        let s = format_uuid_v4(raw);
        // 8-4-4-4-12
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        // version nibble is the first hex digit of the third group
        assert!(parts[2].starts_with('4'), "version nibble: {s}");
        // variant: first hex digit of fourth group is 8, 9, a, or b
        let v = u8::from_str_radix(&parts[3][..1], 16).unwrap();
        assert!((0x8..=0xb).contains(&v), "variant bits not 10xx: {s}",);
    }
}
