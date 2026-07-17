//! Binary-driven port of `cmd/eth-deposit/run_rpc_test.go`: `run` in RPC mode.
//! The local signer derives `From` from its key so the node can resolve
//! nonce/gas; the ledger signer cannot, so the config-time gate rejects it. The
//! address derived from `PHASE3_KEY` is the `from` field of the phase-3 signed
//! golden.

mod common;

use common::{deposit_fixture, eth_deposit, Stub, PHASE3_KEY};

const HOLESKY_CHAIN_ID: u64 = 17000;
/// The Ethereum address derived from `PHASE3_KEY` (checksum form from the golden).
const DERIVED_FROM: &str = "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1";
const KEY_ENV: &str = "TEST_ETH_DEPOSIT_KEY";

fn eq_addr(got: &str, want: &str) -> bool {
    got.to_lowercase() == want.to_lowercase()
}

// Go: TestRunCommand_LocalSigner_RPCDerivesFrom — with nonce and gas omitted,
// both PendingNonceAt and EstimateGas receive the derived sender.
#[test]
fn local_signer_rpc_derives_from() {
    let stub = Stub::build_ok(HOLESKY_CHAIN_ID, 1_000_000_000, 10_000_000_000, 3, 200_000);

    let out = eth_deposit()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args([
            "--rpc-url",
            &stub.url,
            "--signer",
            "local",
            "--private-key-env",
            KEY_ENV,
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let nonce_from = stub
        .params_of("eth_getTransactionCount")
        .expect("nonce fetched");
    assert!(
        eq_addr(nonce_from[0].as_str().unwrap(), DERIVED_FROM),
        "PendingNonceAt From mismatch"
    );
    let est = stub.params_of("eth_estimateGas").expect("estimate ran");
    assert!(
        eq_addr(est[0]["from"].as_str().unwrap(), DERIVED_FROM),
        "EstimateGas From mismatch"
    );
}

// Go: TestRunCommand_LocalSigner_RPCDerivesFromForGasEstimateWithExplicitNonce —
// derivation is unconditional: an explicit --nonce skips PendingNonceAt, but
// EstimateGas still receives the derived From.
#[test]
fn local_signer_rpc_derives_from_for_gas_with_explicit_nonce() {
    let stub = Stub::start(|method, _| match method {
        "eth_chainId" => {
            common::Reply::Ok(serde_json::Value::String(common::hex_u64(HOLESKY_CHAIN_ID)))
        }
        "eth_maxPriorityFeePerGas" => {
            common::Reply::Ok(serde_json::Value::String(common::hex_u128(1_000_000_000)))
        }
        "eth_getBlockByNumber" => common::Reply::Ok(
            serde_json::json!({ "baseFeePerGas": common::hex_u128(10_000_000_000) }),
        ),
        "eth_getTransactionCount" => common::Reply::Err("PendingNonceAt must not run".to_string()),
        "eth_estimateGas" => common::Reply::Ok(serde_json::Value::String(common::hex_u64(200_000))),
        other => common::Reply::Err(format!("unexpected {other}")),
    });

    let out = eth_deposit()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args([
            "--rpc-url",
            &stub.url,
            "--signer",
            "local",
            "--private-key-env",
            KEY_ENV,
            "--nonce",
            "5",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !stub.called("eth_getTransactionCount"),
        "explicit --nonce must skip PendingNonceAt"
    );
    let est = stub.params_of("eth_estimateGas").expect("estimate ran");
    assert!(
        eq_addr(est[0]["from"].as_str().unwrap(), DERIVED_FROM),
        "EstimateGas From must be derived even with explicit nonce"
    );
}

// Go: TestRunCommand_LocalSigner_RPCBadKey_Exit3 — a bad key fails at derivation
// (exit 3) before any dial.
#[test]
fn local_signer_rpc_bad_key_exit3() {
    let out = eth_deposit()
        .env(KEY_ENV, "0xdeadbeefnotahexkey")
        .args(["run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args([
            "--rpc-url",
            "http://node.example",
            "--signer",
            "local",
            "--private-key-env",
            KEY_ENV,
        ])
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestRunCommand_LedgerSigner_RPCNonceOmitted_Exit2 — the gate rejects ledger
// + rpc with nonce omitted, naming both flags, before any dial.
#[test]
fn ledger_signer_rpc_nonce_omitted_exit2() {
    let out = eth_deposit()
        .args(["run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--rpc-url", "http://node.example", "--signer", "ledger"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--nonce") && stderr.contains("--gas-limit"),
        "error should name both flags: {stderr}"
    );
}

// Go: TestRunCommand_LedgerSigner_RPCGasOmitted_Exit2 — --nonce set but gas
// omitted still fails the gate.
#[test]
fn ledger_signer_rpc_gas_omitted_exit2() {
    let out = eth_deposit()
        .args(["run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args([
            "--rpc-url",
            "http://node.example",
            "--signer",
            "ledger",
            "--nonce",
            "5",
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--gas-limit"),
        "error should name --gas-limit"
    );
}

// Go: TestRunCommand_LedgerSigner_RPCBothFlags_PassesGate — with both flags set
// the gate passes; signing then fails with no device (exit 3), NOT the gate error.
#[test]
fn ledger_signer_rpc_both_flags_passes_gate() {
    let stub = Stub::build_ok(HOLESKY_CHAIN_ID, 0, 0, 0, 0);

    let out = eth_deposit()
        .args(["run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args([
            "--rpc-url",
            &stub.url,
            "--signer",
            "ledger",
            "--nonce",
            "5",
            "--gas-limit",
            "250000",
            "--max-fee-per-gas",
            "20000000000",
            "--max-priority-fee-per-gas",
            "1000000000",
        ])
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("requires both --nonce and --gas-limit"),
        "gate should have passed with both flags: {stderr}"
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "expected ledger no-device past the gate; stderr: {stderr}"
    );
}
