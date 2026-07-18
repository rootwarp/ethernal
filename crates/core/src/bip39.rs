//! Hand-rolled BIP-39: English wordlist, entropy↔mnemonic, checksum, and seed.
//!
//! Gated by the official Trezor `english` vectors (passphrase `"TREZOR"`). No
//! new crypto crate: `sha2`, `pbkdf2`/`hmac`, and `unicode-normalization` are
//! workspace deps already.

use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// Canonical BIP-39 English wordlist (2048 words, LF, trailing newline).
/// Pinned by sha256 test — see `research/bip39.md`.
pub const WORDLIST: &str = include_str!("english.txt");

/// Errors from BIP-39 validation and entropy conversion (user-input → exit 2).
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Bip39Error {
    /// A mnemonic word is not in the English wordlist.
    ///
    /// Carries the **1-based** word position only — never the token itself
    /// (S-2: mnemonic material must not reach stderr / structured logs).
    #[error("bip39: unknown word at position {0}")]
    UnknownWord(usize),

    /// Word count is outside the BIP-39 set {12, 15, 18, 21, 24}.
    ///
    /// Also used by [`entropy_to_mnemonic`] for invalid entropy *byte* lengths,
    /// always as `WordCount(0)` (0 is never a valid BIP-39 word count, so it
    /// cannot be confused with a real word-count failure).
    #[error("bip39: word count {0} not in {{12,15,18,21,24}}")]
    WordCount(usize),

    /// Entropy checksum bits do not match SHA256(entropy)[:CS].
    #[error("bip39: checksum mismatch")]
    Checksum,
}

/// Converts raw entropy (16/20/24/28/32 bytes) to a space-joined mnemonic.
///
/// Checksum `CS = ENT/32` bits are the leading bits of `SHA256(entropy)`;
/// the concatenated bitstring is split into 11-bit wordlist indices.
/// Output is zeroized on drop.
pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<Zeroizing<String>, Bip39Error> {
    let word_count = match entropy.len() {
        16 => 12,
        20 => 15,
        24 => 18,
        28 => 21,
        32 => 24,
        // Callers always pass fixed sizes; 0 is never a valid BIP-39 word count
        // so this cannot be mistaken for a real WordCount failure (Issue 4).
        _ => return Err(Bip39Error::WordCount(0)),
    };

    let ent_bits = entropy.len() * 8;
    // CS = ENT/32; first CS bits of SHA256(entropy) appended to the bitstring.
    let hash = Sha256::digest(entropy);
    let words = wordlist_words();

    let mut indices = Vec::with_capacity(word_count);
    for i in 0..word_count {
        let bit_offset = i * 11;
        let mut idx: u16 = 0;
        for b in 0..11 {
            let bit = if bit_offset + b < ent_bits {
                bit_at(entropy, bit_offset + b)
            } else {
                let cs_i = bit_offset + b - ent_bits;
                // Leading CS bits of the SHA-256 digest.
                ((hash[cs_i / 8] >> (7 - (cs_i % 8))) & 1) != 0
            };
            if bit {
                idx |= 1 << (10 - b);
            }
        }
        // CS is at most 8 bits and ENT is aligned, so 11-bit groups never exceed 2047.
        debug_assert!((idx as usize) < 2048);
        indices.push(idx as usize);
    }

    let mnemonic = indices
        .iter()
        .map(|&i| words[i])
        .collect::<Vec<_>>()
        .join(" ");
    Ok(Zeroizing::new(mnemonic))
}

/// Validates word membership and checksum after NFKD + lowercase + whitespace collapse.
///
/// Accepts 12/15/18/21/24-word English mnemonics.
pub fn validate_mnemonic(mnemonic: &str) -> Result<(), Bip39Error> {
    let normalized = normalize_mnemonic(mnemonic);
    let words: Vec<&str> = normalized.split(' ').filter(|w| !w.is_empty()).collect();
    let word_count = words.len();
    if !matches!(word_count, 12 | 15 | 18 | 21 | 24) {
        return Err(Bip39Error::WordCount(word_count));
    }

    let list = wordlist_words();
    // O(n) linear scan is fine for 2048 words × ≤24 lookups in recovery path.
    let mut indices = Vec::with_capacity(word_count);
    for (i, w) in words.iter().enumerate() {
        match list.iter().position(|lw| lw == w) {
            Some(idx) => indices.push(idx),
            // 1-based position; never embed the token (S-2 / H1).
            None => return Err(Bip39Error::UnknownWord(i + 1)),
        }
    }

    let ent_bits = word_count * 11 * 32 / 33;
    let cs_bits = word_count * 11 - ent_bits;
    let ent_bytes = ent_bits / 8;

    let mut entropy = Zeroizing::new(vec![0u8; ent_bytes]);
    let mut checksum_bits: u8 = 0;

    for (i, &idx) in indices.iter().enumerate() {
        for b in 0..11 {
            let bit = ((idx >> (10 - b)) & 1) != 0;
            let bit_pos = i * 11 + b;
            if bit_pos < ent_bits {
                if bit {
                    let byte = bit_pos / 8;
                    let shift = 7 - (bit_pos % 8);
                    entropy[byte] |= 1 << shift;
                }
            } else {
                let cs_i = bit_pos - ent_bits;
                if bit {
                    checksum_bits |= 1 << (cs_bits - 1 - cs_i);
                }
            }
        }
    }

    let hash = Sha256::digest(entropy.as_slice());
    // Leading cs_bits of the digest (cs_bits ∈ {4,5,6,7,8}).
    let expected = hash[0] >> (8 - cs_bits);
    if checksum_bits != expected {
        return Err(Bip39Error::Checksum);
    }
    Ok(())
}

/// Derives the 64-byte BIP-39 seed via PBKDF2-HMAC-SHA512.
///
/// ```text
/// seed = PBKDF2(NFKD+lower+ws-collapse(mnemonic), NFKD("mnemonic" || passphrase), 2048, 64)
/// ```
///
/// The mnemonic is normalized the same way as [`validate_mnemonic`] (NFKD,
/// lowercase, whitespace collapse) so a noisy recover input that passes
/// validation yields the same seed as the canonical form.
///
/// `mnemonic_passphrase` must be UTF-8 text (flag/env/prompt). Non-UTF-8 bytes
/// are lossily replaced with U+FFFD before NFKD — same stance as keystore
/// passphrase handling. Prefer valid UTF-8 only.
///
/// The seed and intermediate secret strings are zeroized on drop.
pub fn to_seed(mnemonic: &str, mnemonic_passphrase: &[u8]) -> Zeroizing<[u8; 64]> {
    // Same normalization as validate_mnemonic: recover path is validate → to_seed
    // on the same user string and must not derive a different seed for case/ws noise.
    let mnemonic_norm = normalize_mnemonic(mnemonic);

    // Passphrase is raw bytes (flag/env/prompt); must be UTF-8 text (see doc above).
    let pass_text = Zeroizing::new(String::from_utf8_lossy(mnemonic_passphrase).into_owned());
    let salt_raw = Zeroizing::new(format!("mnemonic{}", pass_text.as_str()));
    let salt_nfkd = Zeroizing::new(salt_raw.nfkd().collect::<String>());

    let mut seed = Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<Sha512>(
        mnemonic_norm.as_bytes(),
        salt_nfkd.as_bytes(),
        2048,
        seed.as_mut(),
    );
    seed
}

/// NFKD → lowercase → collapse any whitespace run to a single space → trim.
/// Result is zeroized on drop (mnemonic material).
fn normalize_mnemonic(mnemonic: &str) -> Zeroizing<String> {
    let nfkd = Zeroizing::new(mnemonic.nfkd().collect::<String>());
    let lower = Zeroizing::new(nfkd.to_lowercase());
    Zeroizing::new(lower.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn wordlist_words() -> Vec<&'static str> {
    WORDLIST.lines().filter(|l| !l.is_empty()).collect()
}

/// Returns the bit at `bit_index` (MSB-first within each byte) of `data`.
fn bit_at(data: &[u8], bit_index: usize) -> bool {
    let byte = data[bit_index / 8];
    let shift = 7 - (bit_index % 8);
    ((byte >> shift) & 1) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[derive(serde::Deserialize)]
    struct Vectors {
        english: Vec<[String; 4]>,
    }

    fn load_vectors() -> Vectors {
        let raw = include_str!("../testdata/bip39-vectors.json");
        serde_json::from_str(raw).expect("bip39-vectors.json")
    }

    fn decode_hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap_or_else(|e| panic!("hex decode {s:?}: {e}"))
    }

    #[test]
    fn wordlist_pin() {
        assert_eq!(
            WORDLIST.len(),
            13116,
            "wordlist must be 13116 bytes (trailing newline)"
        );
        let digest = Sha256::digest(WORDLIST.as_bytes());
        let hex = hex::encode(digest);
        assert_eq!(
            hex, "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
            "wordlist sha256 pin mismatch"
        );
        let words = wordlist_words();
        assert_eq!(words.len(), 2048);
        assert_eq!(words[0], "abandon");
        assert_eq!(words[2047], "zoo");
    }

    #[test]
    fn trezor_entropy_to_mnemonic() {
        let vectors = load_vectors();
        for (i, row) in vectors.english.iter().enumerate() {
            let entropy = decode_hex(&row[0]);
            let mnemonic = entropy_to_mnemonic(&entropy).unwrap_or_else(|e| {
                panic!("vector {i}: entropy_to_mnemonic failed: {e}");
            });
            assert_eq!(
                mnemonic.as_str(),
                row[1].as_str(),
                "vector {i}: mnemonic mismatch"
            );
        }
    }

    #[test]
    fn trezor_mnemonic_to_seed() {
        let vectors = load_vectors();
        for (i, row) in vectors.english.iter().enumerate() {
            let seed = to_seed(&row[1], b"TREZOR");
            let expected = decode_hex(&row[2]);
            assert_eq!(
                seed.as_slice(),
                expected.as_slice(),
                "vector {i}: seed mismatch"
            );
        }
    }

    #[test]
    fn validate_accepts_all_trezor_mnemonics() {
        let vectors = load_vectors();
        for (i, row) in vectors.english.iter().enumerate() {
            validate_mnemonic(&row[1]).unwrap_or_else(|e| {
                panic!("vector {i}: validate failed: {e}");
            });
        }
    }

    #[test]
    fn validate_unknown_word_reports_1based_position() {
        // Position 1 (first word).
        let err = validate_mnemonic(
            "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap_err();
        assert_eq!(err, Bip39Error::UnknownWord(1));
        let msg = err.to_string();
        assert!(msg.contains("unknown word at position 1"), "msg={msg}");
        assert!(
            !msg.contains("notaword"),
            "token must not appear in Display: {msg}"
        );

        // Position 7 (middle).
        let err = validate_mnemonic(
            "abandon abandon abandon abandon abandon abandon notaword abandon abandon abandon abandon about",
        )
        .unwrap_err();
        assert_eq!(err, Bip39Error::UnknownWord(7));
        let msg = err.to_string();
        assert!(msg.contains("unknown word at position 7"), "msg={msg}");
        assert!(
            !msg.contains("notaword"),
            "token must not appear in Display: {msg}"
        );

        // Position 12 (last word of a 12-word mnemonic).
        let err = validate_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword",
        )
        .unwrap_err();
        assert_eq!(err, Bip39Error::UnknownWord(12));
        let msg = err.to_string();
        assert!(msg.contains("unknown word at position 12"), "msg={msg}");
        assert!(
            !msg.contains("notaword"),
            "token must not appear in Display: {msg}"
        );
    }

    #[test]
    fn validate_word_count() {
        // 13 words — not in {12,15,18,21,24}
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let err = validate_mnemonic(mnemonic).unwrap_err();
        match err {
            Bip39Error::WordCount(13) => {}
            other => panic!("expected WordCount(13), got {other:?}"),
        }
    }

    #[test]
    fn validate_checksum_flip() {
        // Valid 12-word all-zero entropy mnemonic ends with "about"; flip last word.
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        // 12 "abandon" → wrong checksum (valid is 11×abandon + about)
        let err = validate_mnemonic(bad).unwrap_err();
        match err {
            Bip39Error::Checksum => {}
            other => panic!("expected Checksum, got {other:?}"),
        }
    }

    #[test]
    fn validate_nfkd_case_and_whitespace() {
        // Uppercase + doubled spaces must normalize to the canonical form.
        let noisy = "  ABANDON  abandon   ABANDON abandon abandon abandon abandon abandon abandon abandon abandon ABOUT  ";
        validate_mnemonic(noisy).expect("NFKD/case/ws normalization should accept");
    }

    #[test]
    fn to_seed_normalizes_case_and_whitespace() {
        // Regression: validate-accepts-noisy then to_seed must match Trezor seed.
        let noisy = "  ABANDON  abandon   ABANDON abandon abandon abandon abandon abandon abandon abandon abandon ABOUT  ";
        validate_mnemonic(noisy).expect("noisy form validates");
        let seed = to_seed(noisy, b"TREZOR");
        assert_eq!(
            hex::encode(seed.as_slice()),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn abandon_x23_art_24_word() {
        // Explicit 24-word gate for the key-new entropy size (256-bit).
        let entropy = [0u8; 32];
        let mnemonic = entropy_to_mnemonic(&entropy).unwrap();
        let words: Vec<_> = mnemonic.split(' ').collect();
        assert_eq!(words.len(), 24);
        assert!(words.iter().take(23).all(|w| *w == "abandon"));
        assert_eq!(words[23], "art");
        let seed = to_seed(&mnemonic, b"TREZOR");
        assert_eq!(
            hex::encode(seed.as_slice()),
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
        );
    }

    #[test]
    fn entropy_invalid_length_is_word_count_zero() {
        assert_eq!(
            entropy_to_mnemonic(&[0u8; 17]).unwrap_err(),
            Bip39Error::WordCount(0)
        );
        assert_eq!(
            entropy_to_mnemonic(&[]).unwrap_err(),
            Bip39Error::WordCount(0)
        );
    }

    #[test]
    fn round_trip_15_and_21_word() {
        // Trezor vectors skip 15/21-word sizes; self-round-trip covers CS=5/7 paths.
        for &ent_len in &[20usize, 28] {
            let mut entropy = vec![0u8; ent_len];
            // Non-degenerate pattern so checksum bits are exercised.
            for (i, b) in entropy.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(17).wrapping_add(3);
            }
            let mnemonic = entropy_to_mnemonic(&entropy).unwrap_or_else(|e| {
                panic!("entropy_to_mnemonic({ent_len}): {e}");
            });
            let expected_words = if ent_len == 20 { 15 } else { 21 };
            assert_eq!(
                mnemonic.split(' ').count(),
                expected_words,
                "word count for {ent_len}-byte entropy"
            );
            validate_mnemonic(&mnemonic).unwrap_or_else(|e| {
                panic!("validate after {ent_len}-byte entropy: {e}");
            });
            // to_seed is deterministic for the same normalized mnemonic.
            let seed1 = to_seed(&mnemonic, b"");
            let seed2 = to_seed(&mnemonic, b"");
            assert_eq!(seed1.as_slice(), seed2.as_slice());
            // Round-trip: mnemonic → bits must re-validate (checksum path).
            let rederived = entropy_to_mnemonic(&entropy).unwrap();
            assert_eq!(mnemonic.as_str(), rederived.as_str());
        }
    }
}
