//! Binary-driven port of `cmd/ethernal/run_rpc_test.go`: `run` in RPC mode.
//! The local signer derives `From` from its key so the node can resolve
//! nonce/gas; the ledger signer cannot, so the config-time gate rejects it. The
//! address derived from `PHASE3_KEY` is the `from` field of the phase-3 signed
//! golden.

mod common;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{deposit_fixture, ethernal, secret_file, Stub, TempDir, PHASE3_KEY};

const HOLESKY_CHAIN_ID: u64 = 17000;
/// The Ethereum address derived from `PHASE3_KEY` (checksum form from the golden).
const DERIVED_FROM: &str = "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1";

fn eq_addr(got: &str, want: &str) -> bool {
    got.to_lowercase() == want.to_lowercase()
}

// Go: TestRunCommand_LocalSigner_RPCDerivesFrom — with nonce and gas omitted,
// both PendingNonceAt and EstimateGas receive the derived sender.
#[test]
fn local_signer_rpc_derives_from() {
    let stub = Stub::build_ok(HOLESKY_CHAIN_ID, 1_000_000_000, 10_000_000_000, 3, 200_000);
    let dir = TempDir::new("run-rpc-from");
    let key_file = secret_file(&dir, "key.hex", PHASE3_KEY.as_bytes());

    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--rpc-url", &stub.url, "--signer", "local"])
        .arg("--private-key-file")
        .arg(&key_file)
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
    let dir = TempDir::new("run-rpc-nonce");
    let key_file = secret_file(&dir, "key.hex", PHASE3_KEY.as_bytes());

    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--rpc-url", &stub.url, "--signer", "local"])
        .arg("--private-key-file")
        .arg(&key_file)
        .args(["--nonce", "5"])
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
    let dir = TempDir::new("run-rpc-badkey");
    let key_file = secret_file(&dir, "key.hex", b"0xdeadbeefnotahexkey");

    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--rpc-url", "http://node.example", "--signer", "local"])
        .arg("--private-key-file")
        .arg(&key_file)
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
    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
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
    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
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

    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
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

// ---------------------------------------------------------------------------
// F6-2 / FR-33 / R-5 — read-once evidence in **RPC mode**
// ---------------------------------------------------------------------------
//
// The two-signer path is gated on `signer == "local" && !rpc_url.is_empty()`.
// A test without `--rpc-url` passes vacuously: offline `run` only ever
// constructed one signer (R-5). Both rows below require RPC mode; dropping
// `--rpc-url` would make them stop testing the read-once fix.

// F6-2 / FR-22: `tx run --signer local --rpc-url <stub>` with a process-
// substitution key source must succeed.
//
// RPC mode is required: without `--rpc-url` there is only one LocalSigner
// construction, so the defect is invisible. Reverting the read-once fix
// (re-opening the path at sign time after `from` derivation) makes the second
// open of `<(...)` return zero bytes → bad-key / empty-key failure.
#[test]
fn local_signer_rpc_process_sub_key_succeeds() {
    let stub = Stub::build_ok(HOLESKY_CHAIN_ID, 1_000_000_000, 10_000_000_000, 3, 200_000);

    let bin = env!("CARGO_BIN_EXE_ethernal");
    let input = deposit_fixture().display().to_string();
    let rpc = &stub.url;
    // PHASE3_KEY is 0x + 64 hex — safe unquoted inside bash -c.
    let key = PHASE3_KEY;
    // Process substitution requires a shell. Paths have no spaces (TempDir/fixture).
    let script = format!(
        "{bin} tx run \
            --network holesky \
            --input-file {input} \
            --rpc-url {rpc} \
            --signer local \
            --private-key-file <(printf '%s' {key})"
    );

    // Scrub the same ETHERNAL_TX_* fallbacks ethernal() removes so a runner
    // env cannot mask flags (common::ethernal cannot wrap bash -c).
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(&script);
    for v in [
        "ETHERNAL_TX_INPUT_FILE",
        "ETHERNAL_TX_NETWORK",
        "ETHERNAL_TX_OUTPUT",
        "ETHERNAL_TX_INDEX",
        "ETHERNAL_TX_RPC_URL",
        "ETHERNAL_TX_GAS_LIMIT",
        "ETHERNAL_TX_MAX_FEE_PER_GAS",
        "ETHERNAL_TX_MAX_PRIORITY_FEE_PER_GAS",
        "ETHERNAL_TX_NONCE",
        "ETHERNAL_TX_FROM",
        "ETHERNAL_TX_PRIVATE_KEY",
    ] {
        cmd.env_remove(v);
    }
    let out = cmd.output().expect("run tx run RPC with process-sub key");
    assert!(
        out.status.success(),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    // Smoke: signed JSON on stdout (no --output).
    let signed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("signed JSON on stdout");
    assert!(signed.get("rawRLP").is_some(), "missing rawRLP");
}

// F6-2 / FR-22 / R4 M-d: named mkfifo as --private-key-file under RPC mode must
// complete. Pre-fix the measured failure is an indefinite block (second open of
// the FIFO after `from` derivation), not an error — so this test imposes its own
// wall-clock deadline, kills the child on expiry, and fails rather than hanging CI.
//
// RPC mode is required: without `--rpc-url` there is only one open, so the test
// would pass vacuously and stop guarding the read-once fix (R-5). Reverting that
// fix makes this hang until the deadline (then fail).
// Start the writer before the read (M-4: shell out to mkfifo; no new dependency).
#[cfg(unix)]
#[test]
fn local_signer_rpc_named_fifo_completes_under_deadline() {
    use std::io::Read;

    let stub = Stub::build_ok(HOLESKY_CHAIN_ID, 1_000_000_000, 10_000_000_000, 3, 200_000);
    let fifo_dir = TempDir::new("run-rpc-fifo");
    let fifo = fifo_dir.join("key.fifo");

    let st = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("spawn mkfifo");
    assert!(st.success(), "mkfifo failed: {st}");

    // Wall-clock deadline: a single RPC-mode run finishes well under this;
    // if the read-once fix is reverted the second open blocks and we kill + fail.
    const DEADLINE: Duration = Duration::from_secs(15);

    // Start the writer *before* the read: open(O_WRONLY) blocks until run opens
    // for read; then write + close for EOF. Do not join on the timeout path —
    // a blocked open with no living reader would hang the test.
    let fifo_w = fifo.clone();
    let key_bytes = PHASE3_KEY.as_bytes().to_vec();
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo_w)
            .expect("open FIFO for write");
        f.write_all(&key_bytes).expect("write key to FIFO");
    });

    let mut child = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--rpc-url", &stub.url, "--signer", "local"])
        .arg("--private-key-file")
        .arg(&fifo)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tx run RPC with named FIFO");

    let start = Instant::now();
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => break,
            None if start.elapsed() > DEADLINE => {
                let _ = child.kill();
                let _ = child.wait();
                // Detach writer: do not join (may still be blocked if open never
                // rendezvoused). Process exit reaps the thread.
                std::mem::forget(writer);
                panic!(
                    "tx run --signer local --rpc-url with named FIFO exceeded \
                     {DEADLINE:?} wall-clock; kill+fail rather than hang CI. \
                     Reverting the read-once fix (second LocalSigner open of the \
                     key path in RPC mode after from-derivation) produces this \
                     indefinite block (R4 M-d / R-5). Without --rpc-url this test \
                     would pass vacuously — RPC mode is required."
                );
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut r) = child.stdout.take() {
        r.read_to_end(&mut stdout).expect("read stdout");
    }
    if let Some(mut r) = child.stderr.take() {
        r.read_to_end(&mut stderr).expect("read stderr");
    }
    let status = child.wait().expect("reap run child");
    writer.join().expect("FIFO writer thread");

    assert!(
        status.success(),
        "FIFO RPC-mode run must complete under deadline; stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&stderr),
        String::from_utf8_lossy(&stdout)
    );
    let signed: serde_json::Value = serde_json::from_slice(&stdout).expect("signed JSON on stdout");
    assert!(signed.get("rawRLP").is_some(), "missing rawRLP");
}
