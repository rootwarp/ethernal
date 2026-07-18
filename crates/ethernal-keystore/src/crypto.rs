//! Shared EIP-2335 crypto primitives used by decrypt and encrypt.
//!
//! Keeping normalization, scrypt derivation, AES-128-CTR, and the checksum in
//! one place is what makes encrypt and decrypt agree (the round-trip gate).

use sha2::{Digest, Sha256};
use sha3::Keccak256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// AES-128 in CTR mode with a 128-bit big-endian counter, matching Go's
/// `cipher.NewCTR` (which treats the whole IV as the initial counter).
pub(crate) type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// Maximum scrypt working-memory cost accepted on decrypt (and encrypt).
///
/// RFC 7914 / scrypt memory footprint is `128 * n * r` bytes. A hostile
/// keystore can set attacker-controlled `n`/`r` in JSON; without a ceiling
/// `n=2^25, r=8` forces multi-GB allocation on load. 1 GiB leaves 4× headroom
/// over the EIP-2335 / staking-deposit-cli profile (`n=2^18, r=8` = 256 MiB).
const SCRYPT_MAX_MEM_BYTES: u64 = 1 << 30; // 1 GiB

/// Upper bound on the scrypt parallelization parameter `p`.
const SCRYPT_MAX_P: u32 = 16;

/// Minimum derived-key length (EIP-2335 needs 32 bytes: 16 cipher + 16 checksum).
const SCRYPT_MIN_DKLEN: usize = 32;

/// Maximum derived-key length accepted (decrypt DoS / absurd param guard).
const SCRYPT_MAX_DKLEN: usize = 128;

/// Normalizes a passphrase per EIP-2335: convert to NFKD, then strip C0
/// (`U+0000`–`U+001F`), C1 (`U+0080`–`U+009F`), and Delete (`U+007F`) control
/// code points. The result is zeroized on drop.
pub(crate) fn normalize_passphrase(passphrase: &[u8]) -> Zeroizing<Vec<u8>> {
    // Divergence from Go, which normalizes the raw string bytes: we interpret
    // the passphrase as UTF-8 first. This is exact for ASCII/valid-UTF-8
    // passphrases; a non-UTF-8 byte is replaced with U+FFFD (which would change
    // the derived key). Passphrases used here are text. Lossy decode is kept
    // (unlike BIP-39 `to_seed`) so existing keystores remain unlockable.
    // Wrap the owned lossy copy in Zeroizing before NFKD so non-UTF-8 never
    // leaves an un-zeroized intermediate (K2-L3).
    let text = Zeroizing::new(String::from_utf8_lossy(passphrase).into_owned());
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
///
/// # Parameter ceiling (K2-L4)
///
/// Rejects before allocating when:
/// - memory cost `128 * n * r` exceeds [`SCRYPT_MAX_MEM_BYTES`] (1 GiB),
/// - `p` exceeds [`SCRYPT_MAX_P`] (16), or
/// - `dklen` is outside [`SCRYPT_MIN_DKLEN`]..=[`SCRYPT_MAX_DKLEN`] (32..=128).
///
/// Encrypt uses fixed safe params; decrypt reads attacker-controlled JSON, so
/// the shared function is the natural place for the bound.
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
    // Memory cost in bytes: 128 * n * r (RFC 7914). Checked arithmetic so a
    // hostile `n`/`r` cannot wrap past the ceiling check.
    let mem_bytes = n
        .checked_mul(u64::from(r))
        .and_then(|nr| nr.checked_mul(128))
        .ok_or_else(|| format!("scrypt memory cost 128*n*r overflows (n={n}, r={r}); rejected"))?;
    if mem_bytes > SCRYPT_MAX_MEM_BYTES {
        return Err(format!(
            "scrypt memory cost 128*n*r = {mem_bytes} exceeds limit of {SCRYPT_MAX_MEM_BYTES} bytes (n={n}, r={r})"
        ));
    }
    if p > SCRYPT_MAX_P {
        return Err(format!("scrypt p={p} exceeds limit of {SCRYPT_MAX_P}"));
    }
    if !(SCRYPT_MIN_DKLEN..=SCRYPT_MAX_DKLEN).contains(&dklen) {
        return Err(format!(
            "scrypt dklen={dklen} out of allowed range {SCRYPT_MIN_DKLEN}..={SCRYPT_MAX_DKLEN}"
        ));
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
/// shorter derived keys. Fails closed with an assert in **all** build profiles
/// if a future caller skips the length guard (K2 info) — never hashes a short
/// `dk` as if the missing half were empty.
pub(crate) fn checksum_message(dk: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    assert!(
        dk.len() >= 32,
        "checksum_message requires dk.len() >= 32, got {}",
        dk.len()
    );
    let mut hasher = Sha256::new();
    hasher.update(&dk[16..32]);
    hasher.update(ciphertext);
    hasher.finalize().into()
}

/// Computes the Web3 Secret Storage v3 MAC: `keccak256(dk[16..32] ‖ ciphertext)`.
///
/// Same derived-key split as EIP-2335 (`dk[0..16]` cipher key, `dk[16..32]` MAC
/// key) but **Keccak-256**, not SHA-256. geth:
/// `mac := crypto.Keccak256(derivedKey[16:32], cipherText)`. Sits beside
/// [`checksum_message`] — do **not** reuse the EIP-2335 checksum for v3.
///
/// `dk` must be at least 32 bytes. Fails closed with an assert in **all** build
/// profiles if a future caller skips the length guard.
pub(crate) fn v3_mac(dk: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    assert!(
        dk.len() >= 32,
        "v3_mac requires dk.len() >= 32, got {}",
        dk.len()
    );
    let mut hasher = Keccak256::new();
    hasher.update(&dk[16..32]);
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

    /// Non-UTF-8 bytes take the lossy branch; result is still Zeroizing-wrapped
    /// and U+FFFD substitution is stable (K2-L3).
    #[test]
    fn normalize_non_utf8_lossy_zeroized_path() {
        let raw = b"ok\xffbad";
        let got = normalize_passphrase(raw);
        // U+FFFD is UTF-8 ef bf bd; ASCII letters unchanged.
        assert_eq!(got.as_slice(), b"ok\xef\xbf\xbdbad");
    }

    /// EIP-2335 / staking-deposit profile memory cost is under the 1 GiB ceiling
    /// (full scrypt for n=2^18 is covered by encrypt/decrypt integration tests).
    #[test]
    fn scrypt_spec_profile_under_memory_ceiling() {
        let n: u64 = 262_144; // 2^18
        let r: u32 = 8;
        let mem = 128u64
            .checked_mul(n)
            .and_then(|x| x.checked_mul(u64::from(r)));
        assert_eq!(mem, Some(256 * 1024 * 1024));
        assert!(mem.unwrap() <= SCRYPT_MAX_MEM_BYTES);
    }

    /// Small legitimate params derive successfully (ceiling does not false-reject).
    #[test]
    fn derive_scrypt_accepts_small_params() {
        let dk = derive_scrypt(b"pw", b"salt", 16, 8, 1, 32).expect("small params ok");
        assert_eq!(dk.len(), 32);
    }

    /// Hostile n=2^25, r=8 would need multi-GB; reject before allocate (K2-L4).
    #[test]
    fn derive_scrypt_rejects_hostile_memory() {
        let n: u64 = 1 << 25; // 2^25
        let r: u32 = 8;
        let err = derive_scrypt(b"pw", b"salt", n, r, 1, 32).expect_err("hostile n/r");
        assert!(
            err.contains("memory cost") || err.contains("exceeds limit"),
            "error should name the memory ceiling: {err}",
        );
        assert!(err.contains(&n.to_string()) || err.contains("n="), "{err}");
    }

    #[test]
    fn derive_scrypt_rejects_high_p() {
        let err = derive_scrypt(b"pw", b"salt", 16, 8, 17, 32).expect_err("p>16");
        assert!(err.contains("p="), "{err}");
    }

    #[test]
    fn derive_scrypt_rejects_dklen_out_of_range() {
        let too_short = derive_scrypt(b"pw", b"salt", 16, 8, 1, 16).expect_err("dklen 16");
        assert!(too_short.contains("dklen"), "{too_short}");
        let too_long = derive_scrypt(b"pw", b"salt", 16, 8, 1, 256).expect_err("dklen 256");
        assert!(too_long.contains("dklen"), "{too_long}");
    }

    #[test]
    fn checksum_message_ok_on_32_byte_dk() {
        let dk = [0xabu8; 32];
        let ct = b"ciphertext";
        let _ = checksum_message(&dk, ct);
    }

    #[test]
    #[should_panic(expected = "checksum_message requires dk.len() >= 32")]
    fn checksum_message_fails_closed_on_short_dk() {
        let short = [0u8; 16];
        let _ = checksum_message(&short, b"ct");
    }

    /// v3 MAC is Keccak-256 of `dk[16..32] ‖ ct` — distinct from the SHA-256
    /// EIP-2335 checksum (same dk split, different hash).
    #[test]
    fn v3_mac_is_keccak_and_differs_from_checksum_message() {
        let dk = [0xabu8; 32];
        let ct = b"ciphertext";
        let mac = v3_mac(&dk, ct);
        let checksum = checksum_message(&dk, ct);
        assert_ne!(
            mac, checksum,
            "keccak MAC and sha256 checksum must differ on this input"
        );
        // Independent recompute over sha3::Keccak256 (not via v3_mac).
        let mut h = Keccak256::new();
        h.update(&dk[16..32]);
        h.update(ct);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(mac, expected);
    }

    #[test]
    #[should_panic(expected = "v3_mac requires dk.len() >= 32")]
    fn v3_mac_fails_closed_on_short_dk() {
        let short = [0u8; 16];
        let _ = v3_mac(&short, b"ct");
    }
}
