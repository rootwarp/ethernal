//! Port of `cmd/ethernal/deposit_e2e_test.go` (Go: `//go:build e2e`) — the
//! full build → sign → send pipeline. Go injected a mock broadcaster; here send
//! runs against a JSON-RPC stub that records the broadcast RLP, which must equal
//! the signed golden's `rawRLP` (the phase-3 fixtures align).

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{
    deposit_fixture, ethernal, phase3_signed_golden, phase3_unsigned, Reply, Stub, TempDir,
    PHASE3_KEY,
};

const HOLESKY_CHAIN_ID: u64 = 17000;
const KEY_ENV: &str = "TEST_ETHERNAL_KEY";
const MOCK_TX_HASH: &str = "0xdeadbeef00000000000000000000000000000000000000000000000000000001";

// Go: TestE2E_LocalSigner_FullPipeline_NoRPC — `run` (build + sign) with no RPC.
#[test]
fn local_signer_full_pipeline_no_rpc() {
    let dir = TempDir::new("e2e-pipeline");
    let out_file = dir.join("signed.json");

    let out = ethernal()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--output"])
        .arg(&out_file)
        .args(["--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let signed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out_file).expect("signed.json")).unwrap();
    for field in ["unsigned", "from", "hash", "r", "s", "v", "rawRLP"] {
        assert!(signed.get(field).is_some(), "signed.json missing {field}");
    }
    assert!(
        signed["rawRLP"].as_str().unwrap().starts_with("0x02"),
        "rawRLP must be EIP-1559"
    );
    assert_eq!(signed["unsigned"]["chainId"], 17000);

    let raw = std::fs::read_to_string(dir.join("signed.raw")).expect("signed.raw");
    assert!(
        raw.trim().starts_with("0x02"),
        "signed.raw must start with 0x02"
    );
}

// Go: TestE2E_LocalSigner_BuildSignSendMock — sign the phase-3 unsigned tx, then
// send against a stub. The broadcast RLP must equal the signed golden's rawRLP.
#[test]
fn local_signer_build_sign_send_mock() {
    let dir = TempDir::new("e2e-bss");
    let signed_file = dir.join("signed.json");

    // Step 1: sign the phase-3 unsigned tx.
    let sign_out = ethernal()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["sign", "--signer", "local", "--input"])
        .arg(phase3_unsigned())
        .arg("--output")
        .arg(&signed_file)
        .args(["--private-key-env", KEY_ENV])
        .output()
        .expect("sign");
    assert!(
        sign_out.status.success(),
        "sign stderr: {}",
        String::from_utf8_lossy(&sign_out.stderr)
    );

    // Step 2: send against the stub.
    let stub = Stub::start(|method, _| match method {
        "eth_chainId" => Reply::Ok(serde_json::Value::String(common::hex_u64(HOLESKY_CHAIN_ID))),
        "eth_sendRawTransaction" => Reply::Ok(serde_json::Value::String(MOCK_TX_HASH.to_string())),
        other => Reply::Err(format!("unexpected {other}")),
    });

    let send_out = ethernal()
        .args(["send", "--input"])
        .arg(&signed_file)
        .args(["--rpc-url", &stub.url, "--yes"])
        .output()
        .expect("send");
    assert!(
        send_out.status.success(),
        "send stderr: {}",
        String::from_utf8_lossy(&send_out.stderr)
    );

    let stdout = String::from_utf8_lossy(&send_out.stdout);
    assert!(
        stdout.contains(MOCK_TX_HASH),
        "output missing mock tx hash: {stdout}"
    );
    assert!(
        stdout.contains("holesky.etherscan.io"),
        "output missing explorer URL: {stdout}"
    );

    let stderr = String::from_utf8_lossy(&send_out.stderr);
    for want in ["32.000000 ETH", "17000", "Broadcasting"] {
        assert!(stderr.contains(want), "stderr missing {want:?}: {stderr}");
    }

    // The broadcast RLP must equal the signed golden's rawRLP.
    let golden: serde_json::Value =
        serde_json::from_slice(&std::fs::read(phase3_signed_golden()).unwrap()).unwrap();
    let want_rlp = golden["rawRLP"].as_str().unwrap();
    let params = stub
        .params_of("eth_sendRawTransaction")
        .expect("broadcast happened");
    let got_rlp = params[0].as_str().unwrap();
    assert_eq!(
        got_rlp.to_lowercase(),
        want_rlp.to_lowercase(),
        "broadcast RLP mismatch"
    );
}

// Go: TestE2E_SendMock_ReceiptPolling — the send → wait → receipt path.
#[test]
fn send_mock_receipt_polling() {
    const RECEIPT_TX_HASH: &str =
        "0x1111111111111111111111111111111111111111111111111111111111111111";
    let stub = Stub::start(|method, _| match method {
        "eth_chainId" => Reply::Ok(serde_json::Value::String(common::hex_u64(HOLESKY_CHAIN_ID))),
        "eth_sendRawTransaction" => {
            Reply::Ok(serde_json::Value::String(RECEIPT_TX_HASH.to_string()))
        }
        "eth_getTransactionReceipt" => Reply::Ok(serde_json::json!({
            "transactionHash": RECEIPT_TX_HASH,
            "status": "0x1",
            "blockNumber": common::hex_u64(99999),
            "blockHash": "0xaaaa",
            "gasUsed": common::hex_u64(200000),
        })),
        other => Reply::Err(format!("unexpected {other}")),
    });

    let (_dir, signed) = common::write_temp_signed_tx();
    let rec_dir = TempDir::new("e2e-receipt");
    let rec_file = rec_dir.join("receipt.json");

    let out = ethernal()
        .args(["send", "--input"])
        .arg(&signed)
        .args(["--rpc-url", &stub.url, "--yes", "--receipt-output"])
        .arg(&rec_file)
        .args(["--receipt-timeout", "5s"])
        .output()
        .expect("send");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let rec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&rec_file).expect("receipt written")).unwrap();
    assert_eq!(rec["blockNumber"], 99999);
    assert_eq!(rec["status"], 1);

    assert!(
        String::from_utf8_lossy(&out.stdout).contains("status=success"),
        "output missing receipt status: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    let mode = std::fs::metadata(&rec_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "receipt file must be 0600");
}
