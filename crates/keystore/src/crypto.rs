//! Shared EIP-2335 crypto primitives used by decrypt and encrypt.
//!
//! Keeping normalization, scrypt derivation, AES-128-CTR, and the checksum in
//! one place is what makes encrypt and decrypt agree (the round-trip gate).

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// AES-128 in CTR mode with a 128-bit big-endian counter, matching Go's
/// `cipher.NewCTR` (which treats the whole IV as the initial counter).
pub(crate) type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// Normalizes a passphrase per EIP-2335: convert to NFKD, then strip C0
/// (`U+0000`–`U+001F`), C1 (`U+0080`–`U+009F`), and Delete (`U+007F`) control
/// code points. The result is zeroized on drop.
pub(crate) fn normalize_passphrase(passphrase: &[u8]) -> Zeroizing<Vec<u8>> {
    // Divergence from Go, which normalizes the raw string bytes: we interpret
    // the passphrase as UTF-8 first. This is exact for ASCII/valid-UTF-8
    // passphrases; a non-UTF-8 byte is replaced with U+FFFD (which would change
    // the derived key). Passphrases used here are text.
    let text = String::from_utf8_lossy(passphrase);
    let normalized: String = text.nfkd().filter(|&c| !is_stripped_control(c)).collect();
    Zeroizing::new(normalized.into_bytes())
}

/// Reports whether a code point is stripped by EIP-2335 passphrase
/// normalization: C0, C1, or Delete control codes.
pub(crate) fn is_stripped_control(c: char) -> bool {
    let u = c as u32;
    u <= 0x1f || (0x80..=0x9f).contains(&u) || u == 0x7f
}

/// Derives a scrypt key: `scrypt(password, salt, n, r, p, dklen)`.
///
/// `n` must be a power of two; `log_n = n.trailing_zeros()` is passed to
/// `scrypt::Params::new`, matching the decrypt path.
pub(crate) fn derive_scrypt(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u32,
    p: u32,
    dklen: usize,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if !n.is_power_of_two() {
        return Err(format!("n must be a power of two, got {n}"));
    }
    let log_n = n.trailing_zeros() as u8;
    let params = scrypt::Params::new(log_n, r, p, dklen)
        .map_err(|err| format!("invalid scrypt params: {err}"))?;
    let mut dk = Zeroizing::new(vec![0u8; dklen]);
    scrypt::scrypt(password, salt, &params, &mut dk).map_err(|err| format!("scrypt: {err}"))?;
    Ok(dk)
}

/// Computes the EIP-2335 checksum message: `sha256(dk[16..32] ‖ ciphertext)`.
///
/// `dk` must be at least 32 bytes. Call sites in encrypt/decrypt already reject
/// shorter derived keys; the `debug_assert` + `get` path fails closed in debug
/// and avoids a panic on a future caller that skips the guard.
pub(crate) fn checksum_message(dk: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    debug_assert!(
        dk.len() >= 32,
        "checksum_message requires dk.len() >= 32, got {}",
        dk.len()
    );
    let mut hasher = Sha256::new();
    // Prefer `get` over indexing so a short `dk` is a no-op hash path rather
    // than a panic if a future caller forgets the length guard (release builds).
    if let Some(half) = dk.get(16..32) {
        hasher.update(half);
    }
    hasher.update(ciphertext);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec password: mathematical-fraktur "testpassword" + key emoji.
    /// NFKD → `testpassword🔑` = UTF-8 `7465737470617373776f7264f09f9491`.
    #[test]
    fn normalize_spec_password() {
        let pw = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";
        let got = normalize_passphrase(pw.as_bytes());
        assert_eq!(
            got.as_slice(),
            b"testpassword\xf0\x9f\x94\x91",
            "NFKD+strip must yield testpassword🔑",
        );
        assert_eq!(
            hex::encode(got.as_slice()),
            "7465737470617373776f7264f09f9491"
        );
    }
}
