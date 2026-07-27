//! Adapted port of `cmd/ethernal/redact_boundary_test.go`.
//!
//! Go scrubbed the URL at the log boundary (`internaltx.RedactURLString(err)` in
//! main.go) and the test drove `buildUnsignedTx` directly to inspect the boundary
//! string. Rust has NO boundary scrub: the tx crate redacts by construction, so
//! the rendered error is already safe. The "leak channel is live" precondition
//! (that the transport error really carries the URL) is pinned by the tx crate's
//! own `error_never_contains_raw_url_key` unit test; here we assert the observable
//! contract end-to-end — the binary's stderr never contains the embedded secret
//! and does contain the reduced `scheme://host` form.
//!
//! F7-2 extends the same boundary contract to secret-file errors: the message
//! carries the **path**, never the file **bytes**. Distinctive sentinels make
//! `!output.contains(sentinel)` non-vacuous; every case asserts non-empty output
//! before absence. Structured-log coverage is `deposit gen --json-logs` only —
//! no other namespace defines a structured-log flag (keygen plan X4 defers
//! `--json-logs` for validator).

mod common;

use std::process::Output;

use common::{
    deposit_fixture, ethernal, hoodi_keystores, hoodi_pubkey, secret_file, unsigned_tx_golden,
    write_temp_signed_tx, TempDir,
};

const TEST_FROM: &str = "0x1122330000000000000000000000000000000000";

/// Known EIP-55 checksummed address (matches gen suite fixtures).
const WITHDRAWAL_ADDR: &str = "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1";

// ---------------------------------------------------------------------------
// Existing RPC-URL redaction cases (untouched — F7-2 must not modify them)
// ---------------------------------------------------------------------------

// Go: TestBuild_RPCErrorURLRedactedAtBoundary — a path-embedded key.
#[test]
fn build_rpc_error_url_redacted_path_key() {
    const SECRET: &str = "INTEGRATIONSECRET";
    let url = format!("http://127.0.0.1:1/v3/{SECRET}");

    let out = ethernal()
        .args(["deposit", "build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--rpc-url", &url, "--from", TEST_FROM])
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(5),
        "expected an RPC error against a closed port"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains(SECRET),
        "boundary leaked the secret: {stderr}"
    );
    assert!(
        stderr.contains("http://127.0.0.1:1"),
        "expected scheme://host retained: {stderr}"
    );
}

// A query-string-embedded key (task's `?apikey=SECRET` variant).
#[test]
fn build_rpc_error_url_redacted_query_key() {
    const SECRET: &str = "QUERYSECRET";
    let url = format!("http://127.0.0.1:1/?apikey={SECRET}");

    let out = ethernal()
        .args(["deposit", "build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--rpc-url", &url, "--from", TEST_FROM])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(5));

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains(SECRET), "query key leaked: {stderr}");
    assert!(
        stderr.contains("http://127.0.0.1:1"),
        "expected scheme://host retained: {stderr}"
    );
}

// Go: TestSend_RPCErrorURLRedactedAtBoundary — the send path counterpart.
#[test]
fn send_rpc_error_url_redacted() {
    const SECRET: &str = "SENDINTEGRATIONSECRET";
    let url = format!("http://127.0.0.1:1/v3/{SECRET}");
    let (_dir, signed) = write_temp_signed_tx();

    let out = ethernal()
        .args(["tx", "send", "--input"])
        .arg(&signed)
        .args(["--rpc-url", &url, "--yes"])
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(5),
        "expected a broadcast error against a closed port"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains(SECRET),
        "send boundary leaked the secret: {stderr}"
    );
    assert!(
        stderr.contains("http://127.0.0.1:1"),
        "expected scheme://host retained: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// F7-2 / FR-31 — secret-file failure boundary (path present, bytes absent)
// ---------------------------------------------------------------------------

/// Multi-line passphrase bytes: FR-9 residual `\n` after the single trailing
/// strip. Distinctive sentinel so an empty output cannot satisfy absence.
fn multi_line_passphrase(sentinel: &str) -> Vec<u8> {
    format!("{sentinel}\nextra-line-must-not-leak\n").into_bytes()
}

/// Asserts non-empty combined output, path on stderr, and sentinel absent from
/// both stdout and stderr (M-3 / FR-31).
fn assert_path_named_sentinel_absent(out: &Output, path: &str, sentinel: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");
    // Vacuity guard: !contains(sentinel) is only meaningful on non-empty output.
    assert!(
        !combined.is_empty(),
        "output must be non-empty before absence assert (stdout empty, stderr empty)"
    );
    assert!(
        stderr.contains(path),
        "stderr must name the secret-file path {path}: {stderr}"
    );
    assert!(
        !stdout.contains(sentinel),
        "secret-file contents leaked to stdout: {stdout}"
    );
    assert!(
        !stderr.contains(sentinel),
        "secret-file contents leaked to stderr: {stderr}"
    );
}

// Multi-line `--mnemonic-passphrase-file` fails at config load (path named,
// content never echoed). No TTY / mnemonic required.
#[test]
fn validator_secret_file_failure_path_not_contents() {
    const SENTINEL: &str = "F72_VALIDATOR_MP_SENTINEL_NEVER_LEAK";
    let dir = TempDir::new("f7-2-validator-out");
    let secrets = TempDir::new("f7-2-validator-s");
    let mp = secret_file(&secrets, "mp.pw", &multi_line_passphrase(SENTINEL));
    let path = mp.to_str().expect("utf-8 path");

    let out = ethernal()
        .args(["validator", "recover", "--output-dir"])
        .arg(dir.path())
        .args(["--count", "1", "--mnemonic-passphrase-file"])
        .arg(&mp)
        .output()
        .expect("run validator recover");
    assert_eq!(
        out.status.code(),
        Some(2),
        "multi-line mnemonic-passphrase-file must exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_path_named_sentinel_absent(&out, path, SENTINEL);
}

#[test]
fn account_secret_file_failure_path_not_contents() {
    const SENTINEL: &str = "F72_ACCOUNT_MP_SENTINEL_NEVER_LEAK";
    let dir = TempDir::new("f7-2-account-out");
    let secrets = TempDir::new("f7-2-account-s");
    let mp = secret_file(&secrets, "mp.pw", &multi_line_passphrase(SENTINEL));
    let path = mp.to_str().expect("utf-8 path");

    let out = ethernal()
        .args(["account", "recover", "--output-dir"])
        .arg(dir.path())
        .args(["--count", "1", "--mnemonic-passphrase-file"])
        .arg(&mp)
        .output()
        .expect("run account recover");
    assert_eq!(
        out.status.code(),
        Some(2),
        "multi-line mnemonic-passphrase-file must exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_path_named_sentinel_absent(&out, path, SENTINEL);
}

// deposit gen reads `--passphrase-file` once pre-pool (D-5); multi-line fails
// as PassphraseFile / LineTerminator with the path, never the bytes.
#[test]
fn deposit_gen_secret_file_failure_path_not_contents() {
    const SENTINEL: &str = "F72_GEN_PW_SENTINEL_NEVER_LEAK";
    let secrets = TempDir::new("f7-2-gen-s");
    let pw = secret_file(&secrets, "pw.pw", &multi_line_passphrase(SENTINEL));
    let path = pw.to_str().expect("utf-8 path");

    let out = ethernal()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--dry-run",
            "--passphrase-file",
        ])
        .arg(&pw)
        .args(["--withdrawal-address", WITHDRAWAL_ADDR])
        .output()
        .expect("run deposit gen");
    assert_eq!(
        out.status.code(),
        Some(2),
        "multi-line passphrase-file must exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_path_named_sentinel_absent(&out, path, SENTINEL);
}

// tx sign: non-UTF-8 key file is a SecretFileError path that *does* read the
// bytes (unlike NotFound). Path is named; the ASCII sentinel prefix must not
// appear in any channel.
#[test]
fn tx_sign_secret_file_failure_path_not_contents() {
    const SENTINEL: &str = "F72_TX_SIGN_KEY_SENTINEL_NEVER_LEAK";
    let dir = TempDir::new("f7-2-sign");
    let unsigned = {
        let bytes = std::fs::read(unsigned_tx_golden()).expect("read unsigned golden");
        dir.write("unsigned.json", &bytes)
    };
    // Valid UTF-8 sentinel prefix + a trailing invalid byte → NotUtf8 after open.
    let mut key_bytes = SENTINEL.as_bytes().to_vec();
    key_bytes.push(0xFF);
    let key = secret_file(&dir, "key.hex", &key_bytes);
    let path = key.to_str().expect("utf-8 path");

    let out = ethernal()
        .args(["tx", "sign", "--signer", "local", "--input"])
        .arg(&unsigned)
        .arg("--private-key-file")
        .arg(&key)
        .output()
        .expect("run tx sign");
    assert_eq!(
        out.status.code(),
        Some(2),
        "non-UTF-8 private-key-file must exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_path_named_sentinel_absent(&out, path, SENTINEL);
}

// Structured-log row is deposit gen only: --json-logs is defined at
// gen_cli.rs and nowhere else (validator/account/tx have no structured-log
// flag; a validator --json-logs is deferred by the keygen plan, X4).
#[test]
fn deposit_gen_json_logs_secret_file_failure_path_not_contents() {
    const SENTINEL: &str = "F72_GEN_JSON_PW_SENTINEL_NEVER_LEAK";
    let secrets = TempDir::new("f7-2-gen-json-s");
    let pw = secret_file(&secrets, "pw.pw", &multi_line_passphrase(SENTINEL));
    let path = pw.to_str().expect("utf-8 path");

    let out = ethernal()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--dry-run",
            "--json-logs",
            "--passphrase-file",
        ])
        .arg(&pw)
        .args(["--withdrawal-address", WITHDRAWAL_ADDR])
        .output()
        .expect("run deposit gen --json-logs");
    assert_eq!(
        out.status.code(),
        Some(2),
        "multi-line passphrase-file under --json-logs must exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Log stream (stderr under --json-logs) names the path and never the bytes.
    assert_path_named_sentinel_absent(&out, path, SENTINEL);
}

// ---------------------------------------------------------------------------
// F7-2 / FR-32 — hex-shaped nonexistent path rejected without argument echo
// ---------------------------------------------------------------------------

// FR-19 / FR-32 cross-command leg (guard itself is F6-3's): a nonexistent path
// whose *argument* is hex-shaped is rejected without the argument appearing in
// stdout or stderr. Distinctive sentinel so absence is non-vacuous.
const HEX_GUARD_SENTINEL: &str =
    "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

#[test]
fn private_key_file_hex_shaped_not_found_no_arg_echo() {
    let dir = TempDir::new("f7-2-hexguard");
    let unsigned = {
        let bytes = std::fs::read(unsigned_tx_golden()).expect("read unsigned golden");
        dir.write("unsigned.json", &bytes)
    };

    let out = ethernal()
        .args(["tx", "sign", "--signer", "local", "--input"])
        .arg(&unsigned)
        .arg("--private-key-file")
        .arg(HEX_GUARD_SENTINEL)
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(2),
        "hex-shaped missing path must exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.is_empty(),
        "output must be non-empty before absence assert"
    );
    assert!(
        stderr.contains("looks like a key value, not a path"),
        "FR-19 wording expected: {stderr}"
    );
    assert!(
        !combined.contains(HEX_GUARD_SENTINEL) && !combined.contains("deadbeef"),
        "FR-32: rejected hex-shaped argument must not appear in stdout/stderr: {combined}"
    );
}
