//! Encrypt-side tests for EIP-2335 v4 scrypt keystore creation (K2-1).
//!
//! Gates: spec-vector crypto section byte-for-byte, Loader round-trip, wrong
//! passphrase reject, shared normalize_passphrase, real-output field values.

mod common;

use common::*;
use ethernal_keystore::encrypt::{encrypt, EncryptInput, ScryptParams};
use ethernal_keystore::{KeyLoader, KeystoreError, Loader};

/// EIP-2335 scrypt test-vector password: mathematical-fraktur "testpassword" + 🔑.
const SPEC_PASSWORD: &str = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";

/// Secret from the EIP-2335 scrypt test vector.
const SPEC_SECRET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93,
    0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f,
];

const SPEC_PUBKEY_HEX: &str =
    "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";

const SPEC_PUBKEY: [u8; 48] = [
    0x96, 0x12, 0xd7, 0xa7, 0x27, 0xc9, 0xd0, 0xa2, 0x2e, 0x18, 0x5a, 0x1c, 0x76, 0x84, 0x78, 0xdf,
    0xe9, 0x19, 0xca, 0xda, 0x92, 0x66, 0x98, 0x8c, 0xb3, 0x23, 0x59, 0xc1, 0x1f, 0x2b, 0x7b, 0x27,
    0xf4, 0xae, 0x40, 0x40, 0x90, 0x23, 0x82, 0xae, 0x29, 0x10, 0xc1, 0x5e, 0x2b, 0x42, 0x0d, 0x07,
];

const SPEC_PATH: &str = "m/12381/60/3141592653/589793238";

const SPEC_SALT: [u8; 32] = [
    0xd4, 0xe5, 0x67, 0x40, 0xf8, 0x76, 0xae, 0xf8, 0xc0, 0x10, 0xb8, 0x6a, 0x40, 0xd5, 0xf5, 0x67,
    0x45, 0xa1, 0x18, 0xd0, 0x90, 0x6a, 0x34, 0xe6, 0x9a, 0xec, 0x8c, 0x0d, 0xb1, 0xcb, 0x8f, 0xa3,
];

const SPEC_IV: [u8; 16] = [
    0x26, 0x4d, 0xaa, 0x3f, 0x30, 0x3d, 0x72, 0x59, 0x50, 0x1c, 0x93, 0xd9, 0x97, 0xd8, 0x4f, 0xe6,
];

const SPEC_UUID_BYTES: [u8; 16] = [
    0x1d, 0x85, 0xae, 0x20, 0x35, 0xc5, 0x46, 0x11, 0x98, 0xe8, 0xaa, 0x14, 0xa6, 0x33, 0x90, 0x6f,
];

fn encrypt_spec_vector() -> Vec<u8> {
    encrypt(&EncryptInput {
        secret: &SPEC_SECRET,
        password: SPEC_PASSWORD.as_bytes(),
        path: SPEC_PATH,
        pubkey: &SPEC_PUBKEY,
        salt: SPEC_SALT,
        iv: SPEC_IV,
        uuid_bytes: SPEC_UUID_BYTES,
        // Spec vector is N=2^18; must stay STANDARD for byte-identity.
        scrypt: ScryptParams::STANDARD,
    })
    .expect("encrypt(spec vector)")
}

/// Expected compact serialization for the EIP-2335 scrypt vector's `crypto`
/// object, with fields in declaration order (`kdf`·`checksum`·`cipher`, and
/// inside each module `function`·`params`·`message`; scrypt params
/// `dklen`·`n`·`p`·`r`·`salt`). Built from the fixture's values so value
/// drift against `testdata/eip2335-scrypt-vector.json` is caught too.
const EXPECTED_CRYPTO_COMPACT: &str = concat!(
    r#"{"kdf":{"function":"scrypt","params":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""}"#,
    r#","checksum":{"function":"sha256","params":{},"message":"d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"}"#,
    r#","cipher":{"function":"aes-128-ctr","params":{"iv":"264daa3f303d7259501c93d997d84fe6"},"message":"06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"}}"#,
);

/// Crypto section of our output must match the EIP-2335 scrypt vector
/// byte-for-byte (compact JSON, declaration field order). Top-level order is
/// `crypto`·`description`·`pubkey`·`path`·`uuid`·`version`; `description` is
/// `""` for real output (not the vector's explanatory string).
#[test]
fn encrypt_spec_vector_crypto_byte_for_byte() {
    let produced = encrypt_spec_vector();
    let body = std::str::from_utf8(&produced).expect("utf-8 keystore");

    // Full expected document: vector crypto + real-output description "" +
    // vector identity fields, in EIP-2335 top-level order.
    let expected = format!(
        concat!(
            r#"{{"crypto":{crypto},"description":"","pubkey":"{pubkey}","#,
            r#""path":"{path}","uuid":"{uuid}","version":4}}"#,
        ),
        crypto = EXPECTED_CRYPTO_COMPACT,
        pubkey = SPEC_PUBKEY_HEX,
        path = SPEC_PATH,
        uuid = "1d85ae20-35c5-4611-98e8-aa14a633906f",
    );
    assert_eq!(
        body, expected,
        "encrypt output must match vector crypto + ordered top-level fields byte-for-byte",
    );

    // Fixture values must agree with the compact crypto we expect (guards
    // against fixture drift without relying on serde_json Map key order).
    let fixture_raw = std::fs::read(fixture("eip2335-scrypt-vector.json")).unwrap();
    let fixture_val: serde_json::Value = serde_json::from_slice(&fixture_raw).unwrap();
    let produced_val: serde_json::Value = serde_json::from_slice(&produced).unwrap();
    assert_eq!(
        produced_val["crypto"], fixture_val["crypto"],
        "crypto values must match fixture",
    );
    assert_eq!(produced_val["pubkey"], fixture_val["pubkey"]);
    assert_eq!(produced_val["path"], fixture_val["path"]);
    assert_eq!(produced_val["uuid"], fixture_val["uuid"]);
    assert_eq!(produced_val["version"], 4);
    assert_eq!(produced_val["description"], "");

    // Plaintext SK must never appear in the serialized output.
    let secret_hex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    assert!(
        !body.contains(secret_hex),
        "plaintext secret must not appear in keystore JSON",
    );
}

/// Encrypt → write temp file → Loader decrypt recovers the secret.
#[test]
fn encrypt_round_trip_through_loader() {
    let secret = TEST_SECRET;
    // 48 zero bytes as a stand-in pubkey (Loader does not cross-check against SK).
    let pubkey = [0u8; 48];
    let password = b"round-trip-password-ok";
    let salt = [0x11u8; 32];
    let iv = [0x22u8; 16];
    let uuid_bytes = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ];

    let bytes = encrypt(&EncryptInput {
        secret: &secret,
        password,
        path: "m/12381/3600/0/0/0",
        pubkey: &pubkey,
        salt,
        iv,
        uuid_bytes,
        scrypt: ScryptParams::FAST,
    })
    .expect("encrypt");

    // Real output shape (FAST profile — production N is gated by the EIP-2335
    // spec-vector test and by key/account e2e production-path asserts).
    let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(val["description"], "");
    assert_eq!(val["version"], 4);
    assert_eq!(val["crypto"]["kdf"]["function"], "scrypt");
    assert_eq!(val["crypto"]["kdf"]["params"]["n"], ScryptParams::FAST.n);

    let dir = TempDir::new("roundtrip");
    let path = dir.write("keystore.json", &bytes);

    let key = Loader::new()
        .load(
            &path,
            &BytesSource::new(std::str::from_utf8(password).unwrap()),
        )
        .expect("Loader::load");
    assert_eq!(key.secret, secret.as_slice(), "recovered secret mismatch");
}

/// Wrong passphrase on our encrypted keystore → WrongPassphrase.
#[test]
fn encrypt_wrong_passphrase_rejected() {
    let secret = TEST_SECRET;
    let pubkey = [0u8; 48];
    let bytes = encrypt(&EncryptInput {
        secret: &secret,
        password: b"correct-password",
        path: "m/12381/3600/1/0/0",
        pubkey: &pubkey,
        salt: [0x33u8; 32],
        iv: [0x44u8; 16],
        uuid_bytes: [0x55u8; 16],
        scrypt: ScryptParams::FAST,
    })
    .expect("encrypt");

    let dir = TempDir::new("wrongpw");
    let path = dir.write("keystore.json", &bytes);

    let err = Loader::new()
        .load(&path, &BytesSource::new("wrong-password"))
        .expect_err("must reject wrong passphrase");
    assert!(
        matches!(err, KeystoreError::WrongPassphrase { .. }),
        "error = {err:?}, want WrongPassphrase",
    );
}

/// Spec vector encrypt also round-trips through Loader (same password).
#[test]
fn encrypt_spec_vector_round_trip() {
    let produced = encrypt_spec_vector();
    let dir = TempDir::new("spec-rt");
    let path = dir.write("keystore.json", &produced);

    let key = Loader::new()
        .load(&path, &BytesSource::new(SPEC_PASSWORD))
        .expect("Loader::load(spec)");
    assert_eq!(key.secret, SPEC_SECRET.as_slice());
    assert_eq!(key.pubkey_hex, SPEC_PUBKEY_HEX);
}
