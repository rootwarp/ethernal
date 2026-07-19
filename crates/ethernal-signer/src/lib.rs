//! EIP-1559 transaction signers, ported from `go/internal/signer`
//! (issues R3-3 / R3-4): a local raw secp256k1 key signer (development/CI)
//! and a Ledger hardware wallet signer (real funds; HID transport behind
//! the `ledger` cargo feature).
//!
//! SECURITY CONTRACT: no key material ever appears in errors, logs, or
//! argv; the local key buffer is zeroized on close/drop.

mod errors;
mod ledger;
#[cfg(feature = "ledger")]
mod ledger_hid;
mod local;
mod parse;
mod rlp;
mod types;

pub use errors::SignerError;
pub use ledger::LedgerSigner;
pub use local::{
    eip55_checksum, new_local_signer_from_env, new_local_signer_from_hex, secret_to_address,
    LocalSigner, Signer,
};
pub use types::SignedTx;

/// Strict EIP-55 address validation: strip `0x`, hex-decode exactly 20 bytes,
/// and require the input string to equal [`eip55_checksum`] of those bytes.
///
/// Rejects all-lowercase and any checksum-mismatched form (F-13). Returns the
/// raw 20 address bytes on success.
pub fn validate_eip55_address(s: &str) -> Result<[u8; 20], String> {
    let hex_part = s.strip_prefix("0x").unwrap_or(s);
    let decoded = hex::decode(hex_part).map_err(|e| format!("invalid address hex: {e}"))?;
    if decoded.len() != 20 {
        return Err(format!(
            "invalid address length: got {} bytes, want 20",
            decoded.len()
        ));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&decoded);
    // Do not echo eip55_checksum(&addr) in the error: a digit typo would yield a
    // paste-ready EIP-55 form of the *wrong* address and defeat typo resistance.
    if s != eip55_checksum(&addr) {
        return Err("EIP-55 checksum mismatch".to_string());
    }
    Ok(addr)
}

#[cfg(test)]
mod validate_eip55_tests {
    use super::{eip55_checksum, validate_eip55_address};

    /// Known address of the fixed local test key
    /// (`0x01` repeated; see local.rs `eip55_checksum_known_address`).
    const CHECKSUMMED: &str = "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1";
    const ADDR_BYTES: [u8; 20] = [
        0x1a, 0x64, 0x2f, 0x0e, 0x3c, 0x3a, 0xf5, 0x45, 0xe7, 0xac, 0xbd, 0x38, 0xb0, 0x72, 0x51,
        0xb3, 0x99, 0x09, 0x14, 0xf1,
    ];

    #[test]
    fn accepts_checksummed() {
        let got = validate_eip55_address(CHECKSUMMED).expect("checksummed address");
        assert_eq!(got, ADDR_BYTES);
        // Round-trip: decoded bytes re-checksum to the same input.
        assert_eq!(eip55_checksum(&got), CHECKSUMMED);
    }

    #[test]
    fn rejects_lowercase() {
        let lower = CHECKSUMMED.to_ascii_lowercase();
        assert!(
            validate_eip55_address(&lower).is_err(),
            "all-lowercase must be rejected"
        );
    }

    #[test]
    fn rejects_checksum_mismatch_single_nibble_flip() {
        // Flip case of one alphabetic nibble that EIP-55 expects uppercased
        // ('E' at index after 0x in "0x1a642f0E...").
        let mut chars: Vec<char> = CHECKSUMMED.chars().collect();
        // Position 9 is 'E' (0-based in "0x1a642f0E...").
        assert_eq!(chars[9], 'E');
        chars[9] = 'e';
        let flipped: String = chars.into_iter().collect();
        assert_ne!(flipped, CHECKSUMMED);
        assert!(
            validate_eip55_address(&flipped).is_err(),
            "single-nibble case flip must be rejected"
        );
    }

    #[test]
    fn checksum_mismatch_error_does_not_echo_corrected_address() {
        // Digit typo (F1 → F2) with wrong case: must reject without returning a
        // paste-ready EIP-55 of the decoded (wrong) bytes (SEC Finding 1).
        let typo = "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F2";
        let err = validate_eip55_address(typo).expect_err("digit typo must fail");
        assert_eq!(err, "EIP-55 checksum mismatch");
        assert!(
            !err.contains("0x"),
            "error must not include a pasteable 0x address: {err}"
        );
        // Corrected form of the *mistyped* body must not appear either.
        let wrong_bytes: [u8; 20] = [
            0x1a, 0x64, 0x2f, 0x0e, 0x3c, 0x3a, 0xf5, 0x45, 0xe7, 0xac, 0xbd, 0x38, 0xb0, 0x72,
            0x51, 0xb3, 0x99, 0x09, 0x14, 0xf2,
        ];
        let wrong_checksum = eip55_checksum(&wrong_bytes);
        assert!(
            !err.contains(&wrong_checksum),
            "error must not echo EIP-55 of mistyped bytes: {err}"
        );
    }

    #[test]
    fn rejects_wrong_length() {
        // 19 bytes (38 hex chars) and 21 bytes (42 hex chars).
        assert!(validate_eip55_address("0x1a642f0e3c3af545e7acbd38b07251b3990914").is_err());
        assert!(validate_eip55_address("0x1a642f0e3c3af545e7acbd38b07251b3990914f1aa").is_err());
        assert!(validate_eip55_address("0x").is_err());
        assert!(validate_eip55_address("").is_err());
    }

    #[test]
    fn rejects_non_hex() {
        assert!(validate_eip55_address("0xZZ642f0E3c3aF545E7AcBD38b07251B3990914F1").is_err());
        assert!(validate_eip55_address("not-an-address").is_err());
    }

    // H2 / K5-L4: strict prefix contract — only lowercase `0x` is accepted.
    // Pins against a lenient-prefix refactor that would accept `0X` or bare hex.
    #[test]
    fn rejects_0x_uppercase_prefix() {
        // Same body as CHECKSUMMED, but with `0X` instead of `0x`.
        let upper_prefix = format!("0X{}", &CHECKSUMMED[2..]);
        assert_ne!(upper_prefix, CHECKSUMMED);
        assert!(
            validate_eip55_address(&upper_prefix).is_err(),
            "0X-prefixed form must be rejected: {upper_prefix}"
        );
    }

    #[test]
    fn rejects_bare_address_without_0x_prefix() {
        let bare = &CHECKSUMMED[2..]; // drop "0x"
        assert!(
            !bare.starts_with("0x") && !bare.starts_with("0X"),
            "fixture must be bare"
        );
        assert!(
            validate_eip55_address(bare).is_err(),
            "bare (no-prefix) address must be rejected: {bare}"
        );
    }
}
