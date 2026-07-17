//! Ported from go/internal/output/output_test.go.
//!
//! Black-box tests against the public output surface. Adaptations:
//!   * Go's `t.TempDir()` is replaced by a local `TempDir` helper over
//!     `std::env::temp_dir()` (no tempfile dependency in the workspace) that
//!     cleans up on drop, including on panic.
//!   * `Writer::write` takes `now_unix: i64` directly instead of a
//!     `time.Time`; the timestamp values are ported unchanged.
//!   * Go's white-box `TestToJSONEntry_HexEncoding` (which calls the private
//!     `toJSONEntry`) is expressed against the public surface by writing a
//!     single entry through `DryRunWriter` and parsing the resulting JSON.
//!   * `TestJSONFieldOrder` verifies key order by asserting the byte offsets of
//!     each quoted key are strictly increasing (a parsed `serde_json::Value`
//!     does not retain insertion order).

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use eth_deposit_core::deposit::Entry;
use eth_deposit_core::output::{DryRunWriter, FsWriter, Writer};

// -----------------------------------------------------------------------------
// Test scaffolding
// -----------------------------------------------------------------------------

/// A unique temp directory that is removed (recursively) on drop, mirroring the
/// cleanup semantics of Go's `t.TempDir()`.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "eth-deposit-core-test-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// An `io::Write` that always fails, mirroring Go's `errorWriter`.
struct ErrorWriter;

impl Write for ErrorWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("simulated write failure"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Two deterministic all-zero-byte entries, mirroring Go's `testEntries()`.
fn test_entries() -> Vec<Entry> {
    let e = Entry {
        amount: 32_000_000_000,
        fork_version: [0x10, 0x00, 0x09, 0x10],
        network_name: "hoodi".to_string(),
        deposit_cli_version: "2.7.0".to_string(),
        ..Entry::default()
    };
    vec![e.clone(), e]
}

/// The committed golden fixture bytes.
fn golden_bytes() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/deposit_data-expected.json");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read golden file {}: {e}", path.display()))
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

// -----------------------------------------------------------------------------
// DryRunWriter tests
// -----------------------------------------------------------------------------

// Go: TestNewDryRunWriter_GoldenMatch
#[test]
fn dry_run_writer_golden_match() {
    let entries = test_entries();

    let mut buf: Vec<u8> = Vec::new();
    let (_, sha256hex) = DryRunWriter::new(&mut buf)
        .write(Path::new(""), &entries, 1_700_000_000)
        .expect("dry-run write");

    let want = golden_bytes();
    assert_eq!(
        String::from_utf8_lossy(&buf),
        String::from_utf8_lossy(&want),
        "JSON output must match the golden fixture byte-for-byte"
    );

    // sha256hex must equal hex(sha256(bytes)).
    assert_eq!(sha256hex, sha256_hex(&buf), "returned sha256hex mismatch");
}

// Go: TestNewDryRunWriter_ReturnsEmptyPath
#[test]
fn dry_run_writer_returns_empty_path() {
    let mut buf: Vec<u8> = Vec::new();
    let (path, _) = DryRunWriter::new(&mut buf)
        .write(Path::new(""), &test_entries(), 0)
        .expect("dry-run write");
    assert_eq!(path, "", "dry-run path must be empty");
}

// Go: TestNewDryRunWriter_WriteError
#[test]
fn dry_run_writer_write_error() {
    let mut w = DryRunWriter::new(ErrorWriter);
    let res = w.write(Path::new(""), &test_entries(), 0);
    assert!(
        res.is_err(),
        "underlying write failure must surface as an error"
    );
}

// Go: TestNewDryRunWriter_SHA256MatchesFSWriter
#[test]
fn dry_run_and_fs_writer_sha256_match() {
    let dir = TempDir::new();
    let entries = test_entries();
    let now = 1_700_000_000;

    let mut buf: Vec<u8> = Vec::new();
    let (_, dry_sha) = DryRunWriter::new(&mut buf)
        .write(Path::new(""), &entries, now)
        .expect("dry-run write");

    let (_, fs_sha) = FsWriter::new()
        .write(dir.path(), &entries, now)
        .expect("fs write");

    assert_eq!(dry_sha, fs_sha, "dry-run and fs sha256hex must match");
}

// -----------------------------------------------------------------------------
// FsWriter tests
// -----------------------------------------------------------------------------

// Go: TestNewFSWriter_Success
#[test]
fn fs_writer_success() {
    let dir = TempDir::new();
    let entries = test_entries();

    let (path, sha256hex) = FsWriter::new()
        .write(dir.path(), &entries, 1_700_000_000)
        .expect("fs write");

    let path_buf = PathBuf::from(&path);
    assert_eq!(
        path_buf.file_name().unwrap().to_str().unwrap(),
        "deposit_data-1700000000.json",
        "filename"
    );
    assert_eq!(path_buf.parent().unwrap(), dir.path(), "parent dir");

    let file_bytes = std::fs::read(&path).expect("read written file");
    let want = golden_bytes();
    assert_eq!(
        String::from_utf8_lossy(&file_bytes),
        String::from_utf8_lossy(&want),
        "written file must match the golden fixture"
    );

    assert_eq!(sha256hex, sha256_hex(&file_bytes), "sha256hex mismatch");
}

// Go: TestNewFSWriter_NoTmpFileAfterSuccess
#[test]
fn fs_writer_no_tmp_after_success() {
    let dir = TempDir::new();
    FsWriter::new()
        .write(dir.path(), &test_entries(), 1_700_000_000)
        .expect("fs write");

    for entry in std::fs::read_dir(dir.path()).expect("read_dir") {
        let name = entry.expect("dir entry").file_name();
        let name = name.to_string_lossy();
        assert!(
            !name.ends_with(".tmp"),
            "tmp file left behind after success: {name}"
        );
    }
}

// Go: TestNewFSWriter_FileNameContainsUnixTimestamp
#[test]
fn fs_writer_filename_contains_unix_timestamp() {
    let dir = TempDir::new();
    let (path, _) = FsWriter::new()
        .write(dir.path(), &test_entries(), 1_234_567_890)
        .expect("fs write");

    let base = PathBuf::from(&path);
    assert_eq!(
        base.file_name().unwrap().to_str().unwrap(),
        "deposit_data-1234567890.json"
    );
}

// Go: TestNewFSWriter_NonExistentDir
#[test]
fn fs_writer_non_existent_dir() {
    let dir = TempDir::new();
    let non_existent = dir.path().join("does-not-exist");

    let res = FsWriter::new().write(&non_existent, &test_entries(), 1_700_000_000);
    assert!(res.is_err(), "writing to a non-existent dir must error");
}

// -----------------------------------------------------------------------------
// JSON encoding / field-order tests
// -----------------------------------------------------------------------------

// Go: TestToJSONEntry_HexEncoding — expressed via the public DryRunWriter path.
#[test]
fn json_hex_encoding() {
    let mut pubkey = [0u8; 48];
    pubkey[0] = 0xAB;
    pubkey[1] = 0xCD;
    let mut wc = [0u8; 32];
    wc[0] = 0xEF;
    let mut sig = [0u8; 96];
    sig[0] = 0x12;
    sig[1] = 0x34;
    let mut msg_root = [0u8; 32];
    msg_root[0] = 0xAA;
    let mut data_root = [0u8; 32];
    data_root[0] = 0xBB;

    let entry = Entry {
        pubkey,
        withdrawal_credentials: wc,
        amount: 32_000_000_000,
        signature: sig,
        deposit_message_root: msg_root,
        deposit_data_root: data_root,
        fork_version: [0x10, 0x00, 0x09, 0x10],
        network_name: "hoodi".to_string(),
        deposit_cli_version: "2.7.0".to_string(),
    };

    let mut buf: Vec<u8> = Vec::new();
    DryRunWriter::new(&mut buf)
        .write(Path::new(""), std::slice::from_ref(&entry), 0)
        .expect("dry-run write");

    // Parse the single-object array and inspect the first object.
    let arr: serde_json::Value = serde_json::from_slice(&buf).expect("parse json");
    let obj = &arr[0];

    let pubkey_hex = obj["pubkey"].as_str().unwrap();
    assert!(
        !pubkey_hex.starts_with("0x"),
        "pubkey must not have 0x prefix"
    );
    assert_eq!(
        pubkey_hex,
        pubkey_hex.to_lowercase(),
        "pubkey must be lowercase"
    );
    assert_eq!(pubkey_hex.len(), 96, "pubkey hex length (48 bytes)");

    let wc_hex = obj["withdrawal_credentials"].as_str().unwrap();
    assert!(!wc_hex.starts_with("0x"), "wc must not have 0x prefix");
    assert_eq!(wc_hex.len(), 64, "wc hex length (32 bytes)");

    assert_eq!(
        obj["signature"].as_str().unwrap().len(),
        192,
        "signature hex length (96 bytes)"
    );
    assert_eq!(
        obj["fork_version"].as_str().unwrap().len(),
        8,
        "fork_version hex length (4 bytes)"
    );

    // Amount must be a JSON number, not a string.
    assert!(obj["amount"].is_number(), "amount must be a JSON number");
    assert!(
        !obj["amount"].is_string(),
        "amount must not be a JSON string"
    );
}

// Go: TestJSONFieldOrder — the object's keys appear in the spec order.
#[test]
fn json_field_order() {
    let entries = &test_entries()[..1];

    let mut buf: Vec<u8> = Vec::new();
    DryRunWriter::new(&mut buf)
        .write(Path::new(""), entries, 0)
        .expect("dry-run write");
    let json = String::from_utf8(buf).expect("utf8");

    let expected_fields = [
        "pubkey",
        "withdrawal_credentials",
        "amount",
        "signature",
        "deposit_message_root",
        "deposit_data_root",
        "fork_version",
        "network_name",
        "deposit_cli_version",
    ];

    // Byte offset of each `"field":` key must be strictly increasing.
    let mut last = 0usize;
    for (i, field) in expected_fields.iter().enumerate() {
        let needle = format!("\"{field}\":");
        let at = json
            .find(&needle)
            .unwrap_or_else(|| panic!("field {field:?} not found in output"));
        if i > 0 {
            assert!(
                at > last,
                "field {field:?} at {at} is out of order (previous ended at {last})"
            );
        }
        last = at;
    }
}
