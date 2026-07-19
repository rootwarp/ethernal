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

mod common;

use common::{deposit_fixture, ethernal, write_temp_signed_tx};

const TEST_FROM: &str = "0x1122330000000000000000000000000000000000";

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
