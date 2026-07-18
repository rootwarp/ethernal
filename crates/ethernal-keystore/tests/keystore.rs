//! Black-box tests for loading and decrypting EIP-2335 v4 keystores and for the
//! env-var passphrase source. Ported from `go/internal/keystore/keystore_test.go`.
//!
//! The Go tests generated fixtures at runtime via the wealdtech encryptor
//! (`generateFixture`). The Rust crate has no encrypt side (see the NOT PORTED
//! note for `gen_fixtures_test.go`), so tests that need a real encrypted
//! keystore are re-pointed to the committed `testdata/keystore-{pbkdf2,scrypt}.json`
//! fixtures, which encode the same secret and pubkey.

mod common;

use common::*;
use ethernal_keystore::{EnvSource, KeyLoader, KeystoreError, Loader, PassphraseSource};

// Go: TestLoad_ScryptKeystore
#[test]
fn load_scrypt_keystore() {
    let loader = Loader::new();
    let key = loader
        .load(
            &fixture("keystore-scrypt.json"),
            &BytesSource::new(TEST_PASSPHRASE),
        )
        .expect("Load() error");

    assert_eq!(key.secret, TEST_SECRET, "secret mismatch");
    assert_eq!(key.pubkey_hex, TEST_PUBKEY_HEX, "pubkey mismatch");
}

// Go: TestLoad_PBKDF2Keystore
#[test]
fn load_pbkdf2_keystore() {
    let loader = Loader::new();
    let key = loader
        .load(
            &fixture("keystore-pbkdf2.json"),
            &BytesSource::new(TEST_PASSPHRASE),
        )
        .expect("Load() error");

    assert_eq!(key.secret, TEST_SECRET, "secret mismatch");
    assert_eq!(key.pubkey_hex, TEST_PUBKEY_HEX, "pubkey mismatch");
}

// Go: TestLoad_WrongPassphrase
#[test]
fn load_wrong_passphrase() {
    let loader = Loader::new();
    let err = loader
        .load(
            &fixture("keystore-pbkdf2.json"),
            &BytesSource::new("wrongpassword"),
        )
        .expect_err("Load() should fail with WrongPassphrase");

    assert!(
        matches!(err, KeystoreError::WrongPassphrase { .. }),
        "Load() error = {err:?}, want WrongPassphrase",
    );
    // Error-message parity is part of the contract (operators grep these).
    assert_eq!(
        err.to_string(),
        "wrong passphrase: invalid checksum",
        "WrongPassphrase Display string",
    );
}

// Go: TestLoad_MissingFile
#[test]
fn load_missing_file() {
    let loader = Loader::new();
    let err = loader
        .load(
            std::path::Path::new("/nonexistent/path/keystore.json"),
            &BytesSource::new(TEST_PASSPHRASE),
        )
        .expect_err("Load() should fail with KeystoreMissing");

    assert!(
        matches!(err, KeystoreError::KeystoreMissing { .. }),
        "Load() error = {err:?}, want KeystoreMissing",
    );
    assert_eq!(
        err.to_string(),
        "keystore file not found: /nonexistent/path/keystore.json",
        "KeystoreMissing Display string",
    );
}

// Go: TestLoad_MalformedJSON
#[test]
fn load_malformed_json() {
    let dir = TempDir::new("malformed");
    let path = dir.write("keystore.json", b"not-json{{{");

    let loader = Loader::new();
    let err = loader
        .load(&path, &BytesSource::new(TEST_PASSPHRASE))
        .expect_err("Load() should fail with KeystoreMalformed");

    assert!(
        matches!(err, KeystoreError::KeystoreMalformed { .. }),
        "Load() error = {err:?}, want KeystoreMalformed",
    );
    // Path is a temp dir; assert the stable prefix.
    assert!(
        err.to_string().starts_with("keystore JSON malformed: "),
        "KeystoreMalformed Display string = {err}",
    );
}

// Go: TestLoad_VersionNotFour
#[test]
fn load_version_not_four() {
    let ks = serde_json::json!({
        "crypto": {},
        "pubkey": TEST_PUBKEY_HEX,
        "version": 3,
        "uuid": "00000000-0000-0000-0000-000000000002",
        "path": "",
    });
    let dir = TempDir::new("version");
    let path = dir.write("keystore.json", serde_json::to_vec(&ks).unwrap().as_slice());

    let loader = Loader::new();
    let err = loader
        .load(&path, &BytesSource::new(TEST_PASSPHRASE))
        .expect_err("Load() should fail with KeystoreVersion");

    assert!(
        matches!(err, KeystoreError::KeystoreVersion { got: 3, .. }),
        "Load() error = {err:?}, want KeystoreVersion(got=3)",
    );
    let msg = err.to_string();
    assert!(
        msg.starts_with("keystore version must be 4: ") && msg.ends_with(": got 3"),
        "KeystoreVersion Display string = {msg}",
    );
}

// Go: TestKey_Zeroize
#[test]
fn key_zeroize() {
    let loader = Loader::new();
    let mut key = loader
        .load(
            &fixture("keystore-pbkdf2.json"),
            &BytesSource::new(TEST_PASSPHRASE),
        )
        .expect("Load() error");

    key.zeroize();

    // The secret keeps its length but every byte is now zero (Go overwrites in
    // place; the Rust volatile zeroize does the same without changing len).
    assert_eq!(key.secret.len(), 32, "Zeroize() must preserve length");
    assert!(
        key.secret.iter().all(|&b| b == 0x00),
        "Zeroize() left non-zero bytes: {:02x?}",
        key.secret,
    );
}

// Go: TestNewEnvSource_ReadsEnvVar
#[test]
fn new_env_source_reads_env_var() {
    let var = "TEST_KEYSTORE_PW_READS";
    std::env::set_var(var, TEST_PASSPHRASE);

    let src = EnvSource::new(var);
    let got = src.read().expect("Read() error");
    assert_eq!(got, TEST_PASSPHRASE.as_bytes(), "Read() value mismatch");

    std::env::remove_var(var);
}

// Go: TestNewEnvSource_EmptyVarReturnsTypedError
#[test]
fn new_env_source_empty_var_returns_typed_error() {
    let var = "TEST_KEYSTORE_PW_MISSING";
    std::env::remove_var(var);

    let src = EnvSource::new(var);
    let err = src.read().expect_err("Read() should fail with EnvVarEmpty");
    assert!(
        matches!(err, KeystoreError::EnvVarEmpty { .. }),
        "Read() error = {err:?}, want EnvVarEmpty",
    );
    assert_eq!(
        err.to_string(),
        "passphrase environment variable is unset or empty: TEST_KEYSTORE_PW_MISSING",
        "EnvVarEmpty Display string",
    );
}

// Go: TestLoad_ScryptFixtureFile
#[test]
fn load_scrypt_fixture_file() {
    let loader = Loader::new();
    let key = loader
        .load(
            &fixture("keystore-scrypt.json"),
            &BytesSource::new(TEST_PASSPHRASE),
        )
        .expect("Load(testdata/keystore-scrypt.json) error");

    assert_eq!(key.secret.len(), 32, "secret length");
    assert_eq!(key.secret, TEST_SECRET, "secret mismatch");
}

// Go: TestLoad_PBKDF2FixtureFile
#[test]
fn load_pbkdf2_fixture_file() {
    let loader = Loader::new();
    let key = loader
        .load(
            &fixture("keystore-pbkdf2.json"),
            &BytesSource::new(TEST_PASSPHRASE),
        )
        .expect("Load(testdata/keystore-pbkdf2.json) error");

    assert_eq!(key.secret.len(), 32, "secret length");
    assert_eq!(key.secret, TEST_SECRET, "secret mismatch");
}

/// Hostile scrypt params (`n=2^25, r=8`) must be rejected on load with a clear
/// error **without** multi-GB allocation (K2-L4 / H7). Bound by construction:
/// the ceiling fires before `scrypt::Params::new` / buffer alloc.
#[test]
fn load_rejects_hostile_scrypt_memory() {
    let n: u64 = 1 << 25; // 2^25
    let ks = serde_json::json!({
        "crypto": {
            "kdf": {
                "function": "scrypt",
                "params": {
                    "dklen": 32,
                    "n": n,
                    "p": 1,
                    "r": 8,
                    "salt": "00".repeat(32),
                },
                "message": "",
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "00".repeat(32),
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": { "iv": "00".repeat(16) },
                "message": "00".repeat(32),
            },
        },
        "pubkey": TEST_PUBKEY_HEX,
        "version": 4,
        "uuid": "00000000-0000-0000-0000-000000000099",
        "path": "",
    });
    let dir = TempDir::new("hostile-scrypt");
    let path = dir.write("keystore.json", serde_json::to_vec(&ks).unwrap().as_slice());

    let loader = Loader::new();
    let err = loader
        .load(&path, &BytesSource::new(TEST_PASSPHRASE))
        .expect_err("hostile n/r must fail before multi-GB alloc");

    assert!(
        matches!(err, KeystoreError::KeystoreMalformed { .. }),
        "Load() error = {err:?}, want KeystoreMalformed",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("memory cost") || msg.contains("exceeds limit") || msg.contains("scrypt"),
        "error should name the scrypt ceiling: {msg}",
    );
}

// Go: TestLoad_MissingCryptoField
#[test]
fn load_missing_crypto_field() {
    let ks = serde_json::json!({
        "pubkey": TEST_PUBKEY_HEX,
        "version": 4,
        "uuid": "00000000-0000-0000-0000-000000000004",
        "path": "",
        // no "crypto" key — Envelope.crypto is None after parsing
    });
    let dir = TempDir::new("nocrypto");
    let path = dir.write("keystore.json", serde_json::to_vec(&ks).unwrap().as_slice());

    let loader = Loader::new();
    let err = loader
        .load(&path, &BytesSource::new(TEST_PASSPHRASE))
        .expect_err("Load() should fail with KeystoreMalformed");

    assert!(
        matches!(err, KeystoreError::KeystoreMalformed { .. }),
        "Load() error = {err:?}, want KeystoreMalformed",
    );
}

// Go: TestLoad_UnreadableFile
#[cfg(unix)]
#[test]
fn load_unreadable_file() {
    use std::os::unix::fs::PermissionsExt;

    // SAFETY: getuid has no preconditions and is always safe to call.
    if unsafe { libc_getuid() } == 0 {
        // Running as root; chmod 000 has no effect. Skip like the Go test.
        return;
    }

    let dir = TempDir::new("unreadable");
    let path = dir.write("keystore.json", b"{}");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

    let loader = Loader::new();
    let err = loader
        .load(&path, &BytesSource::new(TEST_PASSPHRASE))
        .expect_err("Load() should fail with a read error");

    // Must NOT be KeystoreMissing — the file exists but is unreadable.
    assert!(
        !matches!(err, KeystoreError::KeystoreMissing { .. }),
        "Load() error = {err:?}, must not be KeystoreMissing for permission-denied",
    );

    // Restore permissions so the temp dir can be cleaned up.
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
}

// Minimal getuid shim so the unreadable-file test can skip under root without
// adding a `libc` dependency to this crate.
#[cfg(unix)]
extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}

// Go: TestLoad_PassphraseSourceError
#[test]
fn load_passphrase_source_error() {
    let loader = Loader::new();
    let err = loader
        .load(&fixture("keystore-pbkdf2.json"), &ErrSource)
        .expect_err("Load() should surface the passphrase source error");

    // The wrapped-chain rendering must match Go's `%w` concatenation; this is
    // what pure variant-matching cannot prove.
    assert_eq!(
        err.to_string(),
        "passphrase source: passphrase environment variable is unset or empty: SOURCE_FAILED",
        "PassphraseSource wrapped-chain Display string",
    );

    // Go asserts errors.Is(err, sentinel); the Rust equivalent is that the
    // wrapped inner error is the exact variant the source returned.
    match err {
        KeystoreError::PassphraseSource(inner) => assert!(
            matches!(*inner, KeystoreError::EnvVarEmpty { .. }),
            "wrapped error = {inner:?}, want the source's EnvVarEmpty",
        ),
        other => panic!("Load() error = {other:?}, want PassphraseSource(_)"),
    }
}

// Go: TestLoad_PubkeyNormalized
#[test]
fn load_pubkey_normalized() {
    // Reuse the committed pbkdf2 fixture's real crypto, but swap in a
    // 0x-prefixed, uppercase pubkey as some CLI tools emit.
    let raw = std::fs::read(fixture("keystore-pbkdf2.json")).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let uppercase = format!("0x{}", TEST_PUBKEY_HEX.to_uppercase());
    value["pubkey"] = serde_json::Value::String(uppercase);

    let dir = TempDir::new("normalize");
    let path = dir.write(
        "keystore.json",
        serde_json::to_vec(&value).unwrap().as_slice(),
    );

    let loader = Loader::new();
    let key = loader
        .load(&path, &BytesSource::new(TEST_PASSPHRASE))
        .expect("Load() error");

    assert!(
        !key.pubkey_hex.starts_with("0x"),
        "PubkeyHex has 0x prefix: {}",
        key.pubkey_hex,
    );
    assert_eq!(
        key.pubkey_hex,
        key.pubkey_hex.to_lowercase(),
        "PubkeyHex is not fully lowercase",
    );
    assert_eq!(key.pubkey_hex, TEST_PUBKEY_HEX, "PubkeyHex mismatch");
}
