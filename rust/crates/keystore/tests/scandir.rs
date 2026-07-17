//! Black-box tests for directory scanning and the pubkey index. Ported from
//! `go/internal/keystore/scandir_test.go`. Go's `TestScanDir` table subtests
//! become one `#[test]` each.

mod common;

use std::path::Path;

use common::TempDir;
use eth_deposit_keystore::{scan_dir, KeystoreError};

const PUBKEY_A: &str =
    "aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd";
const PUBKEY_B: &str =
    "bbccddee00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd";

/// Writes a minimal EIP-2335-like JSON file with the given pubkey. Go:
/// `writeKeystoreFile`.
fn write_keystore_file(dir: &TempDir, filename: &str, pubkey_hex: &str) -> std::path::PathBuf {
    let ks = serde_json::json!({ "pubkey": pubkey_hex, "version": 4 });
    dir.write(filename, serde_json::to_vec(&ks).unwrap().as_slice())
}

// Go: TestScanDir/dir_does_not_exist
#[test]
fn scan_dir_dir_does_not_exist() {
    let dir = TempDir::new("scan-missing");
    let non_existent = dir.path().join("no-such-dir");
    assert!(
        scan_dir(&non_existent).is_err(),
        "ScanDir(nonExistent) should error",
    );
}

// Go: TestScanDir/empty_dir_returns_empty_index
#[test]
fn scan_dir_empty_dir_returns_empty_index() {
    let dir = TempDir::new("scan-empty");
    let idx = scan_dir(dir.path()).expect("ScanDir(empty dir) error");
    assert_eq!(idx.len(), 0, "empty dir len");
    assert!(idx.is_empty(), "empty dir is_empty");
}

// Go: TestScanDir/single_matching_keystore
#[test]
fn scan_dir_single_matching_keystore() {
    let dir = TempDir::new("scan-single");
    let want_path = write_keystore_file(&dir, "keystore.json", PUBKEY_A);

    let idx = scan_dir(dir.path()).expect("ScanDir error");
    assert_eq!(idx.len(), 1, "len");

    let got = idx.lookup(PUBKEY_A).expect("Lookup should find pubkey");
    assert_eq!(got, want_path.as_path(), "lookup path");
}

// Go: TestScanDir/pubkey_with_0x_prefix_normalized
#[test]
fn scan_dir_pubkey_with_0x_prefix_normalized() {
    let dir = TempDir::new("scan-0x");
    // Stored with a 0x prefix (as staking-deposit-cli emits).
    write_keystore_file(&dir, "keystore.json", &format!("0x{PUBKEY_A}"));

    let idx = scan_dir(dir.path()).expect("ScanDir error");
    // Lookup with the bare hex (no prefix) finds it.
    assert!(idx.lookup(PUBKEY_A).is_some(), "lookup bare hex");
    // Lookup with a 0x prefix also works (Lookup normalizes).
    assert!(
        idx.lookup(&format!("0x{PUBKEY_A}")).is_some(),
        "lookup 0x-prefixed hex",
    );
}

// Go: TestScanDir/mixed_valid_and_invalid_json
#[test]
fn scan_dir_mixed_valid_and_invalid_json() {
    let dir = TempDir::new("scan-mixed");
    let good_path = write_keystore_file(&dir, "good.json", PUBKEY_A);

    // Invalid JSON — silently skipped.
    dir.write("bad.json", b"not-json!!!");
    // Valid JSON but no pubkey field — silently skipped.
    let no_pubkey = serde_json::json!({ "version": 4 });
    dir.write(
        "nopubkey.json",
        serde_json::to_vec(&no_pubkey).unwrap().as_slice(),
    );
    // A non-.json file — ignored entirely.
    dir.write("notes.txt", b"just notes");

    let idx = scan_dir(dir.path()).expect("ScanDir error");
    assert_eq!(idx.len(), 1, "only good.json should be indexed");
    let got = idx
        .lookup(PUBKEY_A)
        .expect("Lookup should find good pubkey");
    assert_eq!(got, good_path.as_path(), "lookup path");
}

// Go: TestScanDir/pubkey_not_found_via_lookup
#[test]
fn scan_dir_pubkey_not_found_via_lookup() {
    let dir = TempDir::new("scan-notfound");
    write_keystore_file(&dir, "keystore.json", PUBKEY_A);

    let idx = scan_dir(dir.path()).expect("ScanDir error");
    let unknown =
        "ffffffff00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd";
    assert!(idx.lookup(unknown).is_none(), "lookup unknown pubkey");
}

// Go: TestScanDir/multiple_keystores
#[test]
fn scan_dir_multiple_keystores() {
    let dir = TempDir::new("scan-multi");
    let path1 = write_keystore_file(&dir, "validator1.json", PUBKEY_A);
    let path2 = write_keystore_file(&dir, "validator2.json", PUBKEY_B);

    let idx = scan_dir(dir.path()).expect("ScanDir error");
    assert_eq!(idx.len(), 2, "len");

    assert_eq!(idx.lookup(PUBKEY_A).unwrap(), path1.as_path(), "lookup A");
    assert_eq!(idx.lookup(PUBKEY_B).unwrap(), path2.as_path(), "lookup B");
}

// Go: TestScanDir/directory_entry_skipped
#[test]
fn scan_dir_directory_entry_skipped() {
    let dir = TempDir::new("scan-subdir");
    // A subdirectory named like a keystore — must NOT be indexed.
    std::fs::create_dir(dir.path().join("subdir.json")).unwrap();

    let idx = scan_dir(dir.path()).expect("ScanDir error");
    assert_eq!(idx.len(), 0, "directory should be skipped");
}

// Go: TestErrKeystoreNotFound
#[test]
fn err_keystore_not_found() {
    let err = KeystoreError::KeystoreNotFound;
    assert!(
        matches!(err, KeystoreError::KeystoreNotFound),
        "KeystoreNotFound variant should match itself",
    );
    assert_eq!(err.to_string(), "keystore not found for pubkey");
}

// Compile-time check that `lookup` yields a `&Path`, mirroring the Go signature.
#[allow(dead_code)]
fn _lookup_returns_path(idx: &eth_deposit_keystore::DirectoryIndex) -> Option<&Path> {
    idx.lookup("00")
}
