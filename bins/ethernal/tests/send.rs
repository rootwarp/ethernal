//! Binary-driven port of `cmd/ethernal/send_test.go`. Go injected a
//! `mockBroadcaster` via the `newBroadcaster` seam; here `--rpc-url` points at a
//! JSON-RPC stub answering `eth_chainId`, `eth_sendRawTransaction`, and
//! `eth_getTransactionReceipt`. The signed input is the phase-3 signed golden
//! (chainId 17000 = holesky).

mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;

use common::{ethernal, write_temp_signed_tx, Reply, Stub, TempDir, PHASE3_TX_HASH};

const HOLESKY_CHAIN_ID: u64 = 17000;

/// A stub serving chainId=holesky and a send that returns the phase-3 hash.
fn send_ok_stub() -> Stub {
    Stub::start(|method, _| match method {
        "eth_chainId" => Reply::Ok(serde_json::Value::String(common::hex_u64(HOLESKY_CHAIN_ID))),
        "eth_sendRawTransaction" => {
            Reply::Ok(serde_json::Value::String(PHASE3_TX_HASH.to_string()))
        }
        other => Reply::Err(format!("unexpected {other}")),
    })
}

// Go: TestSendCommand_HappyPath
#[test]
fn happy_path() {
    let stub = send_ok_stub();
    let (_dir, signed) = write_temp_signed_tx();

    let out = ethernal()
        .args(["send", "--input"])
        .arg(&signed)
        .args(["--rpc-url", &stub.url, "--yes"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(PHASE3_TX_HASH),
        "output missing tx hash: {stdout}"
    );
    assert!(
        stdout.contains("holesky.etherscan.io"),
        "output missing explorer URL: {stdout}"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    for want in ["32.000000 ETH", "chain ID 17000", "holesky", "Broadcasting"] {
        assert!(stderr.contains(want), "stderr missing {want:?}: {stderr}");
    }
}

// Go: TestSendCommand_ConfirmPrompt_Accept — typing the network name confirms.
#[test]
fn confirm_prompt_accept() {
    let stub = send_ok_stub();
    let (_dir, signed) = write_temp_signed_tx();

    let mut child = ethernal()
        .args(["send", "--input"])
        .arg(&signed)
        .args(["--rpc-url", &stub.url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child.stdin.take().unwrap().write_all(b"holesky\n").unwrap();
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains(PHASE3_TX_HASH));
}

// Go: TestSendCommand_ConfirmPrompt_CaseInsensitive
#[test]
fn confirm_prompt_case_insensitive() {
    let stub = send_ok_stub();
    let (_dir, signed) = write_temp_signed_tx();

    let mut child = ethernal()
        .args(["send", "--input"])
        .arg(&signed)
        .args(["--rpc-url", &stub.url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child.stdin.take().unwrap().write_all(b"Holesky\n").unwrap();
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "case-insensitive confirm; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestSendCommand_ConfirmPrompt_Reject → exit 4, no broadcast.
#[test]
fn confirm_prompt_reject() {
    let stub = send_ok_stub();
    let (_dir, signed) = write_temp_signed_tx();

    let mut child = ethernal()
        .args(["send", "--input"])
        .arg(&signed)
        .args(["--rpc-url", &stub.url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child.stdin.take().unwrap().write_all(b"mainnet\n").unwrap();
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(4));
    assert!(
        !stub.called("eth_sendRawTransaction"),
        "broadcast must not fire after rejection"
    );
}

// Go: TestSendCommand_ConfirmPrompt_EOF → exit 4, no broadcast.
#[test]
fn confirm_prompt_eof() {
    let stub = send_ok_stub();
    let (_dir, signed) = write_temp_signed_tx();

    let mut child = ethernal()
        .args(["send", "--input"])
        .arg(&signed)
        .args(["--rpc-url", &stub.url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    // Close stdin immediately (EOF before any newline).
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(4));
    assert!(
        !stub.called("eth_sendRawTransaction"),
        "broadcast must not fire after EOF"
    );
}

// Go: TestSendCommand_ChainIDMismatch → exit 5, no broadcast.
#[test]
fn chain_id_mismatch() {
    let stub = Stub::start(|method, _| match method {
        "eth_chainId" => Reply::Ok(serde_json::Value::String(common::hex_u64(1))), // mainnet != holesky
        "eth_sendRawTransaction" => {
            Reply::Ok(serde_json::Value::String(PHASE3_TX_HASH.to_string()))
        }
        other => Reply::Err(format!("unexpected {other}")),
    });
    let (_dir, signed) = write_temp_signed_tx();

    let out = ethernal()
        .args(["send", "--input"])
        .arg(&signed)
        .args(["--rpc-url", &stub.url, "--yes"])
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(5),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !stub.called("eth_sendRawTransaction"),
        "broadcast must not fire on chain-ID mismatch"
    );
}

// Go: TestSendCommand_RPCFailure — a node-rejected broadcast → exit 5.
#[test]
fn rpc_failure() {
    let stub = Stub::start(|method, _| match method {
        "eth_chainId" => Reply::Ok(serde_json::Value::String(common::hex_u64(HOLESKY_CHAIN_ID))),
        "eth_sendRawTransaction" => Reply::Err("node returned error".to_string()),
        other => Reply::Err(format!("unexpected {other}")),
    });
    let (_dir, signed) = write_temp_signed_tx();

    let out = ethernal()
        .args(["send", "--input"])
        .arg(&signed)
        .args(["--rpc-url", &stub.url, "--yes"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(5));
}

// Go: TestSendCommand_RPCDialFailure — a closed port → exit 5. (Rust dials
// lazily, so the failure surfaces at the first call, chainId; still exit 5.)
#[test]
fn rpc_dial_failure() {
    let (_dir, signed) = write_temp_signed_tx();

    let out = ethernal()
        .args(["send", "--input"])
        .arg(&signed)
        .args(["--rpc-url", "http://127.0.0.1:1", "--yes"])
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(5),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestSendCommand_MissingRPC → exit 2.
#[test]
fn missing_rpc() {
    let (_dir, signed) = write_temp_signed_tx();

    let out = ethernal()
        .args(["send", "--input"])
        .arg(&signed)
        .args(["--yes"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestSendCommand_MissingInput → exit 2.
#[test]
fn missing_input() {
    let out = ethernal()
        .args(["send", "--rpc-url", "http://localhost:8545", "--yes"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestSendCommand_InvalidInput → exit 2.
#[test]
fn invalid_input() {
    let stub = send_ok_stub();
    let dir = TempDir::new("send-badinput");
    let bad = dir.write("bad.json", b"not json");

    let out = ethernal()
        .args(["send", "--input"])
        .arg(&bad)
        .args(["--rpc-url", &stub.url, "--yes"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestSendCommand_BroadcastReceiptWrite — receipt file written, mode 0600.
#[test]
fn broadcast_receipt_write() {
    let stub = Stub::start(|method, _| match method {
        "eth_chainId" => Reply::Ok(serde_json::Value::String(common::hex_u64(HOLESKY_CHAIN_ID))),
        "eth_sendRawTransaction" => {
            Reply::Ok(serde_json::Value::String(PHASE3_TX_HASH.to_string()))
        }
        "eth_getTransactionReceipt" => Reply::Ok(serde_json::json!({
            "transactionHash": PHASE3_TX_HASH,
            "status": "0x1",
            "blockNumber": common::hex_u64(12345),
            "blockHash": "0xabc",
            "gasUsed": common::hex_u64(100000),
        })),
        other => Reply::Err(format!("unexpected {other}")),
    });
    let (_dir, signed) = write_temp_signed_tx();
    let rec_dir = TempDir::new("send-receipt");
    let rec_file = rec_dir.join("receipt.json");

    let out = ethernal()
        .args(["send", "--input"])
        .arg(&signed)
        .args(["--rpc-url", &stub.url, "--yes", "--receipt-output"])
        .arg(&rec_file)
        .args(["--receipt-timeout", "5s"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let rec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&rec_file).expect("receipt written")).unwrap();
    assert_eq!(rec["transactionHash"], PHASE3_TX_HASH);
    assert_eq!(rec["blockNumber"], 12345);

    let mode = std::fs::metadata(&rec_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "receipt file must be 0600");
}

// Go: TestSendCommand_WaitForReceipt_Timeout — receipt never mined → timeout error.
#[test]
fn wait_for_receipt_timeout() {
    let stub = Stub::start(|method, _| match method {
        "eth_chainId" => Reply::Ok(serde_json::Value::String(common::hex_u64(HOLESKY_CHAIN_ID))),
        "eth_sendRawTransaction" => {
            Reply::Ok(serde_json::Value::String(PHASE3_TX_HASH.to_string()))
        }
        "eth_getTransactionReceipt" => Reply::Ok(serde_json::Value::Null), // never mined
        other => Reply::Err(format!("unexpected {other}")),
    });
    let (_dir, signed) = write_temp_signed_tx();

    let out = ethernal()
        .args(["send", "--input"])
        .arg(&signed)
        .args([
            "--rpc-url",
            &stub.url,
            "--yes",
            "--wait-for-receipt",
            "--receipt-timeout",
            "100ms",
        ])
        .output()
        .expect("run");
    assert!(!out.status.success(), "expected timeout error");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("timed out"),
        "error should mention timeout: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestSendSubcommand_Help
#[test]
fn send_subcommand_help() {
    let out = ethernal()
        .args(["send", "--help"])
        .output()
        .expect("run");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("rpc-url"), "send --help missing --rpc-url");
    assert!(s.contains("yes"), "send --help missing --yes");
}
