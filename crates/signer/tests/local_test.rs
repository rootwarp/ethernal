//! Black-box tests for the local signer, ported from
//! `go/internal/signer/local_test.go`.
//!
//! Go tests generated a fresh random key per test (`gethcrypto.GenerateKey`);
//! the port uses fixed deterministic keys so the crate needs no RNG
//! dependency. The expected address is derived through the public
//! `LocalSigner::address()` accessor instead of geth's `PubkeyToAddress`.

use eth_deposit_signer::{
    new_local_signer_from_env, new_local_signer_from_hex, Signer, SignerError,
};
use eth_deposit_tx::UnsignedTx;

/// A valid deterministic 32-byte secp256k1 scalar (Go: validHexKey).
const VALID_KEY_HEX: &str = "0202020202020202020202020202020202020202020202020202020202020202";

fn holesky_unsigned_tx() -> UnsignedTx {
    UnsignedTx {
        chain_id: 17000,
        to: "0x4242424242424242424242424242424242424242".into(),
        value: "0x1BC16D674EC80000".into(), // 2 ETH in wei
        data: "0xabcd".into(),
        gas: 21000,
        max_fee_per_gas: "0x3B9ACA00".into(),          // 1 gwei
        max_priority_fee_per_gas: "0x3B9ACA00".into(), // 1 gwei
        nonce: 0,
        tx_type: "0x2".into(),
        ..UnsignedTx::default()
    }
}

fn addr_hex(addr: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(addr))
}

// Go: TestNewLocalSignerFromHex_Valid
#[test]
fn new_local_signer_from_hex_valid() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).expect("NewLocalSignerFromHex");
    let want_addr = addr_hex(&s.address().unwrap());

    let signed = s.sign(&holesky_unsigned_tx()).expect("Sign");
    assert!(
        signed.from.eq_ignore_ascii_case(&want_addr),
        "From = {:?}, want {:?}",
        signed.from,
        want_addr
    );
    let _ = s.close();
}

// Go: TestNewLocalSignerFromHex_ValidWithPrefix
#[test]
fn new_local_signer_from_hex_valid_with_prefix() {
    new_local_signer_from_hex(&format!("0x{VALID_KEY_HEX}"))
        .expect("NewLocalSignerFromHex with 0x prefix");
}

// Go: TestNewLocalSignerFromHex_InvalidLength
#[test]
fn new_local_signer_from_hex_invalid_length() {
    let cases: &[(&str, String)] = &[
        ("too_short", "ab".to_string()),
        ("63_hex_chars", format!("0x{}", "a".repeat(63))),
        ("65_hex_chars", format!("0x{}", "a".repeat(65))),
        ("empty", String::new()),
    ];
    for (name, input) in cases {
        let err = new_local_signer_from_hex(input).unwrap_err();
        assert!(
            matches!(err.sentinel(), SignerError::InvalidKey),
            "{name}: want InvalidKey, got {err}"
        );
    }
}

// Go: TestNewLocalSignerFromHex_BadHex
#[test]
fn new_local_signer_from_hex_bad_hex() {
    let bad_input = format!("0x{}", "z".repeat(64)); // 'z' is not valid hex
    let err = new_local_signer_from_hex(&bad_input).unwrap_err();
    assert!(
        matches!(err.sentinel(), SignerError::InvalidKey),
        "want InvalidKey for bad hex, got {err}"
    );
}

// Go: TestNewLocalSignerFromHex_ZeroScalar
#[test]
fn new_local_signer_from_hex_zero_scalar() {
    let zero_key = "0".repeat(64);
    let err = new_local_signer_from_hex(&zero_key).unwrap_err();
    assert!(
        matches!(err.sentinel(), SignerError::InvalidKey),
        "want InvalidKey for zero scalar, got {err}"
    );
}

// Go: TestNewLocalSignerFromHex_ErrorDoesNotIncludeKey
#[test]
fn new_local_signer_from_hex_error_does_not_include_key() {
    let bad_input = format!("0x{}", "f".repeat(63)); // wrong length, memorable bytes
    let err = new_local_signer_from_hex(&bad_input).unwrap_err();
    // The error must not leak the input bytes.
    assert!(
        !err.to_string().contains(&"f".repeat(63)),
        "error message contains key material"
    );
}

// Go: TestNewLocalSignerFromEnv_Set
#[test]
fn new_local_signer_from_env_set() {
    std::env::set_var("TEST_LOCAL_SIGNER_KEY_RS", VALID_KEY_HEX);
    let s = new_local_signer_from_env("TEST_LOCAL_SIGNER_KEY_RS").expect("NewLocalSignerFromEnv");
    s.sign(&holesky_unsigned_tx()).expect("Sign");
    let _ = s.close();
    std::env::remove_var("TEST_LOCAL_SIGNER_KEY_RS");
}

// Go: TestNewLocalSignerFromEnv_Missing
#[test]
fn new_local_signer_from_env_missing() {
    std::env::remove_var("TEST_MISSING_KEY_RS");
    let err = new_local_signer_from_env("TEST_MISSING_KEY_RS").unwrap_err();
    // Error must reference the var name but not contain key material.
    assert!(
        err.to_string().contains("TEST_MISSING_KEY_RS"),
        "error should mention env var name, got: {err}"
    );
    assert_eq!(
        err.to_string(),
        "environment variable \"TEST_MISSING_KEY_RS\" is not set or empty: invalid private key"
    );
}

// Go: TestLocalSigner_Sign_RoundTrip
#[test]
fn local_signer_sign_round_trip() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    let unsigned = holesky_unsigned_tx();
    let signed = s.sign(&unsigned).expect("Sign");

    // Decode the RawRLP back.
    let raw_hex = signed.raw_rlp.strip_prefix("0x").expect("0x prefix");
    let raw = hex::decode(raw_hex).expect("hex decode RawRLP");
    assert!(raw.len() >= 2, "RawRLP too short: {} bytes", raw.len());
    // Type-2 transactions have 0x02 prefix byte.
    assert_eq!(raw[0], 0x02, "RawRLP[0] want 0x02 (EIP-2718 type-2)");

    // Basic field checks.
    assert!(signed.hash.starts_with("0x") && signed.hash.len() > 2);
    assert!(signed.r.starts_with("0x") && signed.r.len() > 2);
    assert!(signed.s.starts_with("0x") && signed.s.len() > 2);
    assert!(signed.v == "0" || signed.v == "1", "V = {:?}", signed.v);
    assert!(signed.from.starts_with("0x"));
    assert_eq!(signed.unsigned.chain_id, unsigned.chain_id);
    let _ = s.close();
}

// Go: TestLocalSigner_Sign_SenderRecovery
#[test]
fn local_signer_sign_sender_recovery() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    let want_addr = addr_hex(&s.address().unwrap());

    let signed = s.sign(&holesky_unsigned_tx()).expect("Sign");
    assert!(
        signed.from.eq_ignore_ascii_case(&want_addr),
        "From = {:?}, want {:?}",
        signed.from,
        want_addr
    );
    let _ = s.close();
}

// Go: TestLocalSigner_Sign_ChainID17000
#[test]
fn local_signer_sign_chain_id_17000() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    let signed = s.sign(&holesky_unsigned_tx()).expect("Sign");
    assert_eq!(signed.unsigned.chain_id, 17000);
    let _ = s.close();
}

// Go: TestLocalSigner_Sign_Cancelled
#[test]
fn local_signer_sign_cancelled() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    // Pre-cancelled: the closure reports cancellation immediately.
    let err = s
        .sign_with_cancel(&holesky_unsigned_tx(), &|| true)
        .unwrap_err();
    assert!(
        matches!(err.sentinel(), SignerError::Cancelled),
        "want Cancelled, got {err}"
    );
    let _ = s.close();
}

// Go: TestLocalSigner_Close_Idempotent
#[test]
fn local_signer_close_idempotent() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    assert!(s.close().is_ok(), "first close");
    assert!(s.close().is_ok(), "second close");
}

// Go: TestLocalSigner_Sign_AfterClose
#[test]
fn local_signer_sign_after_close() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    s.close().unwrap();
    let err = s.sign(&holesky_unsigned_tx()).unwrap_err();
    assert!(
        matches!(err.sentinel(), SignerError::SignerClosed),
        "want SignerClosed, got {err}"
    );
}

// Go: TestLocalSigner_Name
#[test]
fn local_signer_name() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    assert_eq!(s.name(), "local");
    let _ = s.close();
}

// Go: TestLocalSigner_RequiresUserInteraction
#[test]
fn local_signer_requires_user_interaction() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    assert!(!s.requires_user_interaction());
    let _ = s.close();
}

// Go: TestLocalSigner_Address_ReturnsKeyAddress
#[test]
fn local_signer_address_returns_key_address() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    // Address must be consistent with the sender recovered from a signature.
    let addr = addr_hex(&s.address().expect("Address"));
    let signed = s.sign(&holesky_unsigned_tx()).unwrap();
    assert!(
        signed.from.eq_ignore_ascii_case(&addr),
        "Address() = {:?}, recovered From = {:?}",
        addr,
        signed.from
    );
    let _ = s.close();
}

// Go: TestLocalSigner_Address_AfterClose
#[test]
fn local_signer_address_after_close() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    s.close().unwrap();
    let err = s.address().unwrap_err();
    assert!(
        matches!(err.sentinel(), SignerError::SignerClosed),
        "want SignerClosed, got {err}"
    );
}

// Go: TestLocalSigner_Sign_ChainID0_Rejected (Must Fix 1)
#[test]
fn local_signer_sign_chain_id_0_rejected() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    let mut unsigned = holesky_unsigned_tx();
    unsigned.chain_id = 0;
    let err = s.sign(&unsigned).unwrap_err();
    assert!(
        matches!(err.sentinel(), SignerError::InvalidChainId),
        "want InvalidChainId, got {err}"
    );
    let _ = s.close();
}

// Go: TestLocalSigner_Sign_EmptyMaxFeePerGas_Rejected (Must Fix 2)
#[test]
fn local_signer_sign_empty_max_fee_per_gas_rejected() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    let mut unsigned = holesky_unsigned_tx();
    unsigned.max_fee_per_gas = String::new();
    assert!(s.sign(&unsigned).is_err());
    let _ = s.close();
}

// Go: TestLocalSigner_Sign_EmptyMaxPriorityFeePerGas_Rejected
#[test]
fn local_signer_sign_empty_max_priority_fee_per_gas_rejected() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    let mut unsigned = holesky_unsigned_tx();
    unsigned.max_priority_fee_per_gas = String::new();
    assert!(s.sign(&unsigned).is_err());
    let _ = s.close();
}

// Go: TestLocalSigner_Sign_InvalidMaxFeeHex_Rejected
#[test]
fn local_signer_sign_invalid_max_fee_hex_rejected() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    let mut unsigned = holesky_unsigned_tx();
    unsigned.max_fee_per_gas = "0xgg".into();
    assert!(s.sign(&unsigned).is_err());
    let _ = s.close();
}

// Go: TestLocalSigner_Sign_InvalidMaxPriorityFeeHex_Rejected
#[test]
fn local_signer_sign_invalid_max_priority_fee_hex_rejected() {
    let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
    let mut unsigned = holesky_unsigned_tx();
    unsigned.max_priority_fee_per_gas = "0xgg".into();
    assert!(s.sign(&unsigned).is_err());
    let _ = s.close();
}

// Go: TestLocalSigner_Sign_VariousChainIDs
#[test]
fn local_signer_sign_various_chain_ids() {
    for chain_id in [1u64, 5, 11155111, 17000] {
        let s = new_local_signer_from_hex(VALID_KEY_HEX).unwrap();
        let mut unsigned = holesky_unsigned_tx();
        unsigned.chain_id = chain_id;
        let signed = s
            .sign(&unsigned)
            .unwrap_or_else(|e| panic!("Sign chainID={chain_id}: {e}"));
        assert!(
            signed.v == "0" || signed.v == "1",
            "chainID={chain_id}: V = {:?}, want decimal 0 or 1",
            signed.v
        );
        let _ = s.close();
    }
}
