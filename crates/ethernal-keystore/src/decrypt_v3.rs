//! Test-only Web3 Secret Storage v3 decrypt.
//!
//! Restores encrypt↔decrypt symmetry for v3 (the v4 [`crate::Loader`] already
//! round-trips BLS). **Not** a product surface: the Q3 veto forbids an
//! in-binary v3 reader; no release code path may call this.
//!
//! # Stays-out-of-release invariant (binding)
//!
//! This module is compiled only under `#[cfg(feature = "test-support")]`
//! (see `lib.rs`). Under workspace `resolver = "2"` (root `Cargo.toml`),
//! features introduced solely via a package's `[dev-dependencies]` are
//! unified **only** for that package's test/bench/example builds. The
//! `ethernal` bin enables `test-support` only in `[dev-dependencies]`, so
//! `cargo build --release --bin ethernal` does **not** enable the feature
//! and this module is `#[cfg]`-compiled out of the release binary.
//!
//! `cargo tree -e normal -p ethernal` is a best-effort backstop that
//! documents (does not guarantee) the property; the guarantee is the cfg
//! gate + resolver 2.
//!
//! Pipeline reuses crate-internal
//! [`crypto::derive_scrypt`](crate::crypto::derive_scrypt),
//! [`crypto::Aes128Ctr`](crate::crypto::Aes128Ctr), and
//! [`crypto::v3_mac`](crate::crypto::v3_mac) verbatim so it cannot drift
//! from [`crate::encrypt_v3::encrypt_v3`]. Passphrase is **raw** bytes
//! (no EIP-2335 NFKD), matching the writer (C-4).

use ctr::cipher::{KeyIvInit, StreamCipher};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::crypto::{self, Aes128Ctr};
use crate::error::KeystoreError;

/// Synthetic path used in [`KeystoreError`] variants (no filesystem involved).
const PATH: &str = "<decrypt_v3>";

#[derive(Deserialize)]
struct Envelope {
    crypto: Crypto,
    #[serde(default)]
    version: i64,
}

#[derive(Deserialize)]
struct Crypto {
    cipher: String,
    cipherparams: CipherParams,
    ciphertext: String,
    kdf: String,
    kdfparams: ScryptParams,
    mac: String,
}

#[derive(Deserialize)]
struct CipherParams {
    iv: String,
}

#[derive(Deserialize)]
struct ScryptParams {
    dklen: usize,
    n: u64,
    p: u32,
    r: u32,
    salt: String,
}

/// Decrypt a Web3 Secret Storage v3 (scrypt) keystore JSON to the 32-byte secret.
///
/// Pipeline: parse JSON → `derive_scrypt(RAW password, salt, n, r, p, dklen)` →
/// verify `v3_mac` (**MAC-before-decrypt**, constant-time) → AES-128-CTR →
/// `Zeroizing<[u8; 32]>`.
///
/// # Errors
///
/// - [`KeystoreError::KeystoreMalformed`] — bad JSON, unsupported kdf/cipher,
///   invalid hex, or non-32-byte plaintext.
/// - [`KeystoreError::WrongPassphrase`] — MAC mismatch (`detail: "invalid mac"`).
pub fn decrypt_v3(json: &[u8], password: &[u8]) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    let malformed = |detail: String| KeystoreError::KeystoreMalformed {
        path: PATH.to_string(),
        detail,
    };

    let envelope: Envelope =
        serde_json::from_slice(json).map_err(|err| malformed(format!("json: {err}")))?;

    if envelope.version != 3 {
        return Err(malformed(format!(
            "version must be 3, got {}",
            envelope.version
        )));
    }

    let crypto = envelope.crypto;

    if crypto.kdf != "scrypt" {
        return Err(malformed(format!(
            "kdf: unsupported function {:?}",
            crypto.kdf
        )));
    }
    if crypto.cipher != "aes-128-ctr" {
        return Err(malformed(format!(
            "cipher: unsupported function {:?}",
            crypto.cipher
        )));
    }

    let salt = decode_hex(&crypto.kdfparams.salt, "kdfparams.salt")?;
    let iv = decode_hex(&crypto.cipherparams.iv, "cipherparams.iv")?;
    let ciphertext = decode_hex(&crypto.ciphertext, "ciphertext")?;
    let expected_mac = decode_hex(&crypto.mac, "mac")?;

    // RAW passphrase — never normalize (C-4). geth/MetaMask use raw UTF-8.
    let dk = crypto::derive_scrypt(
        password,
        &salt,
        crypto.kdfparams.n,
        crypto.kdfparams.r,
        crypto.kdfparams.p,
        crypto.kdfparams.dklen,
    )
    .map_err(|e| malformed(format!("kdf: {e}")))?;

    if dk.len() < 32 {
        return Err(malformed(format!(
            "kdf: derived key too short: {} bytes, need at least 32",
            dk.len()
        )));
    }

    // MAC-before-decrypt; constant-time compare (no early exit on first mismatch).
    let computed = crypto::v3_mac(&dk, &ciphertext);
    if !ct_eq(computed.as_slice(), expected_mac.as_slice()) {
        return Err(KeystoreError::WrongPassphrase {
            detail: "invalid mac".to_string(),
        });
    }

    let mut cipher = Aes128Ctr::new_from_slices(&dk[0..16], &iv)
        .map_err(|err| malformed(format!("cipher: invalid key/iv length: {err}")))?;
    let mut plaintext = Zeroizing::new(ciphertext);
    cipher.apply_keystream(&mut plaintext);

    if plaintext.len() != 32 {
        return Err(malformed(format!(
            "plaintext must be 32 bytes, got {}",
            plaintext.len()
        )));
    }

    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&plaintext);
    Ok(secret)
}

fn decode_hex(s: &str, field: &str) -> Result<Vec<u8>, KeystoreError> {
    hex::decode(s).map_err(|err| KeystoreError::KeystoreMalformed {
        path: PATH.to_string(),
        detail: format!("{field}: invalid hex: {err}"),
    })
}

/// Constant-time equality for equal-length slices (MAC verify).
///
/// Length mismatch returns `false` immediately (MAC is always 32 bytes after
/// successful hex decode of a well-formed keystore).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt_v3::{encrypt_v3, EncryptV3Input, ScryptParams};

    /// Light scrypt so the unit test stays fast (same profile as encrypt_v3 tests).
    const LIGHT: ScryptParams = ScryptParams {
        n: 16,
        r: 8,
        p: 1,
        dklen: 32,
    };

    #[test]
    fn decrypt_v3_round_trips_encrypt_v3() {
        let secret = [0x77u8; 32];
        let password = b"round-trip-v3-password";
        let salt = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let bytes = encrypt_v3(&EncryptV3Input {
            secret: &secret,
            password,
            address: [0xabu8; 20],
            salt,
            iv,
            uuid_bytes: [0xcd; 16],
            scrypt: LIGHT,
        })
        .expect("encrypt_v3");

        let recovered = decrypt_v3(&bytes, password).expect("decrypt_v3");
        assert_eq!(recovered.as_slice(), secret.as_slice());
    }

    #[test]
    fn decrypt_v3_wrong_passphrase_is_wrong_passphrase() {
        let secret = [0x88u8; 32];
        let bytes = encrypt_v3(&EncryptV3Input {
            secret: &secret,
            password: b"correct",
            address: [0u8; 20],
            salt: [0x33u8; 32],
            iv: [0x44u8; 16],
            uuid_bytes: [0x55; 16],
            scrypt: LIGHT,
        })
        .expect("encrypt_v3");

        let err = decrypt_v3(&bytes, b"wrong").expect_err("bad password");
        match err {
            KeystoreError::WrongPassphrase { detail } => {
                assert_eq!(detail, "invalid mac");
            }
            other => panic!("want WrongPassphrase, got {other:?}"),
        }
    }
}
