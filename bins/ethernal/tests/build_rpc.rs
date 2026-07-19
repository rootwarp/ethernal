//! Binary-driven port of `cmd/ethernal/buildrpc_test.go`. Go injected a fake
//! `EthRPC` via the `newEthRPC` seam; the Rust binary is a separate process, so
//! each test points `--rpc-url` at a local JSON-RPC stub (`common::Stub`) and
//! drives the REAL client. The RPC-mode env-var fallbacks (`FromEnvVar`,
//! `RPCURL` env-vs-flag) also live here since they need a stub to observe.

mod common;

use common::{deposit_fixture, ethernal, hex_u128, hex_u64, Reply, Stub};

const HOLESKY_CHAIN_ID: u64 = 17000;
// Go: `testFrom = [20]byte{0x11, 0x22, 0x33}`.
const TEST_FROM: &str = "0x1122330000000000000000000000000000000000";

fn build_json(out: &std::process::Output) -> serde_json::Value {
    assert!(
        out.status.success(),
        "build failed (code {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("build stdout is valid JSON")
}

// Go: TestBuildUnsignedTx_OfflineDefaults — offline build fills the static
// air-gapped defaults and never dials.
#[test]
fn offline_defaults() {
    let out = ethernal()
        .args(["deposit", "build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .output()
        .expect("run");
    let tx = build_json(&out);
    assert_eq!(tx["gas"], 250_000);
    assert_eq!(tx["maxFeePerGas"], hex_u128(20_000_000_000));
    assert_eq!(tx["maxPriorityFeePerGas"], hex_u128(1_000_000_000));
    assert_eq!(tx["nonce"], 0);
}

// Go: TestBuildUnsignedTx_RPCResolvesUnsetFields — RPC resolves tip/baseFee/
// nonce/gas; the 32-ETH EstimateGas carries the non-zero From.
#[test]
fn rpc_resolves_unset_fields() {
    let tip = 3_000_000_000u128;
    let base_fee = 7_000_000_000u128;
    let fake_nonce = 99u64;
    let estimate = 210_000u64;
    let want_gas = estimate * 6 / 5;
    let want_max_fee = 2 * base_fee + tip;

    let stub = Stub::build_ok(HOLESKY_CHAIN_ID, tip, base_fee, fake_nonce, estimate);

    let out = ethernal()
        .args(["deposit", "build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--rpc-url", &stub.url, "--from", TEST_FROM])
        .output()
        .expect("run");
    let tx = build_json(&out);
    assert_eq!(tx["gas"], want_gas);
    assert_eq!(tx["maxFeePerGas"], hex_u128(want_max_fee));
    assert_eq!(tx["maxPriorityFeePerGas"], hex_u128(tip));
    assert_eq!(tx["nonce"], fake_nonce);

    // The 32-ETH estimation call must carry the funded sender.
    let params = stub
        .params_of("eth_estimateGas")
        .expect("estimateGas called");
    let from = params[0]["from"].as_str().unwrap();
    assert_eq!(from.to_lowercase(), TEST_FROM.to_lowercase());
}

// Go: TestBuildUnsignedTx_RPCExplicitFlagsWin — explicit flags win; only the
// ChainID check fires, no fee/nonce/gas resolution.
#[test]
fn rpc_explicit_flags_win() {
    let stub = Stub::build_ok(HOLESKY_CHAIN_ID, 0, 0, 0, 0);

    let out = ethernal()
        .args(["deposit", "build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args([
            "--rpc-url",
            &stub.url,
            "--from",
            TEST_FROM,
            "--gas-limit",
            "300000",
            "--max-fee-per-gas",
            "25000000000",
            "--max-priority-fee-per-gas",
            "2000000000",
            "--nonce",
            "7",
        ])
        .output()
        .expect("run");
    let tx = build_json(&out);
    assert_eq!(tx["gas"], 300_000);
    assert_eq!(tx["nonce"], 7);
    assert_eq!(tx["maxFeePerGas"], hex_u128(25_000_000_000));

    let methods = stub.methods();
    assert_eq!(
        methods,
        vec!["eth_chainId".to_string()],
        "only ChainID should fire"
    );
}

// Go: TestBuildUnsignedTx_RPCUnreachable — a closed port fails during resolution.
// (Rust dials lazily, so this surfaces as an estimation-call failure, still exit
// 5; the RpcDial-at-construction path is covered separately by the ws:// case in
// the tx crate.)
#[test]
fn rpc_unreachable_exit5() {
    let out = ethernal()
        .args(["deposit", "build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        // Port 1 is reserved/closed; connect fails fast.
        .args(["--rpc-url", "http://127.0.0.1:1", "--from", TEST_FROM])
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(5),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestBuildUnsignedTx_RPCEstimationFails — a failing EstimateGas call →
// exit 5.
#[test]
fn rpc_estimation_fails_exit5() {
    let stub = Stub::start(|method, _| match method {
        "eth_chainId" => Reply::Ok(serde_json::Value::String(hex_u64(HOLESKY_CHAIN_ID))),
        "eth_maxPriorityFeePerGas" => Reply::Ok(serde_json::Value::String(hex_u128(1_000_000_000))),
        "eth_getBlockByNumber" => {
            Reply::Ok(serde_json::json!({ "baseFeePerGas": hex_u128(10_000_000_000) }))
        }
        "eth_getTransactionCount" => Reply::Ok(serde_json::Value::String(hex_u64(5))),
        "eth_estimateGas" => Reply::Err("insufficient funds for gas * price + value".to_string()),
        other => Reply::Err(format!("unexpected {other}")),
    });

    let out = ethernal()
        .args(["deposit", "build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--rpc-url", &stub.url, "--from", TEST_FROM])
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(5),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestBuildUnsignedTx_RPCChainIDMismatch — a mismatching chain ID is a config
// error → exit 2.
#[test]
fn rpc_chain_id_mismatch_exit2() {
    let stub = Stub::build_ok(1, 1_000_000_000, 10_000_000_000, 5, 200_000); // mainnet != holesky

    let out = ethernal()
        .args(["deposit", "build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--rpc-url", &stub.url, "--from", TEST_FROM])
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestBuildUnsignedTx_RPCChainIDCallError_WarnAndContinue — a failed ChainID
// *call* (not a mismatch) is swallowed; the build proceeds.
#[test]
fn rpc_chain_id_call_error_warn_and_continue() {
    let stub = Stub::start(|method, _| match method {
        "eth_chainId" => Reply::Err("the method eth_chainId does not exist".to_string()),
        "eth_maxPriorityFeePerGas" => Reply::Ok(serde_json::Value::String(hex_u128(1_000_000_000))),
        "eth_getBlockByNumber" => {
            Reply::Ok(serde_json::json!({ "baseFeePerGas": hex_u128(10_000_000_000) }))
        }
        "eth_getTransactionCount" => Reply::Ok(serde_json::Value::String(hex_u64(5))),
        "eth_estimateGas" => Reply::Ok(serde_json::Value::String(hex_u64(200_000))),
        other => Reply::Err(format!("unexpected {other}")),
    });

    let out = ethernal()
        .args(["deposit", "build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--rpc-url", &stub.url, "--from", TEST_FROM])
        .output()
        .expect("run");
    let tx = build_json(&out);
    assert_eq!(
        tx["nonce"], 5,
        "resolution should proceed after a swallowed ChainID error"
    );
}

// Go: TestLoadBuildConfig_EnvVarOverride — --rpc-url resolved from the env var is
// honored (the stub is contacted).
#[test]
fn rpc_url_env_var_override() {
    let stub = Stub::build_ok(HOLESKY_CHAIN_ID, 1_000_000_000, 10_000_000_000, 5, 200_000);

    let out = ethernal()
        .env("ETHERNAL_TX_RPC_URL", &stub.url)
        .args(["deposit", "build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        // explicit nonce+gas+fees so only ChainID is contacted; no --from needed.
        .args([
            "--nonce",
            "7",
            "--gas-limit",
            "250000",
            "--max-fee-per-gas",
            "20000000000",
            "--max-priority-fee-per-gas",
            "1000000000",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stub.called("eth_chainId"),
        "env-var rpc-url was not contacted"
    );
}

// Go: TestLoadBuildConfig_FlagBeatsEnvVar — the --rpc-url flag wins over the env
// var: the flag's (matching) stub succeeds while the env's (mismatching) stub
// would fail with exit 2.
#[test]
fn rpc_url_flag_beats_env_var() {
    let env_stub = Stub::build_ok(1, 1, 1, 1, 1); // mismatch → would exit 2 if used
    let flag_stub = Stub::build_ok(HOLESKY_CHAIN_ID, 1_000_000_000, 10_000_000_000, 5, 200_000);

    let out = ethernal()
        .env("ETHERNAL_TX_RPC_URL", &env_stub.url)
        .args(["deposit", "build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--rpc-url", &flag_stub.url])
        .args([
            "--nonce",
            "7",
            "--gas-limit",
            "250000",
            "--max-fee-per-gas",
            "20000000000",
            "--max-priority-fee-per-gas",
            "1000000000",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "flag rpc-url should win; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        flag_stub.called("eth_chainId"),
        "flag stub should be contacted"
    );
    assert!(
        !env_stub.called("eth_chainId"),
        "env stub must NOT be contacted"
    );
}

// Go: TestBuild_RPCRequiresFromWhenNonceOmitted — the config-time gate fires
// (exit 2, error names --from) before any dial when --rpc-url is set but --from
// and --nonce are both omitted.
#[test]
fn rpc_requires_from_when_nonce_omitted() {
    let out = ethernal()
        .args(["deposit", "build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        // port 0 is never dialed: the gate fires first.
        .args(["--rpc-url", "http://127.0.0.1:0"])
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--from"),
        "error should name --from"
    );
}

// Go: TestBuild_FromNotRequiredWithNonceAndGas — with both --nonce and
// --gas-limit set, --from is not required; PendingNonceAt and EstimateGas (the
// From-consuming calls) are skipped.
#[test]
fn from_not_required_with_nonce_and_gas() {
    let stub = Stub::build_ok(HOLESKY_CHAIN_ID, 1_000_000_000, 10_000_000_000, 0, 0);

    let out = ethernal()
        .args(["deposit", "build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args([
            "--rpc-url",
            &stub.url,
            "--nonce",
            "7",
            "--gas-limit",
            "250000",
            "--max-fee-per-gas",
            "20000000000",
            "--max-priority-fee-per-gas",
            "1000000000",
            // no --from
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "--from should not be required; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !stub.called("eth_getTransactionCount"),
        "PendingNonceAt must be skipped"
    );
    assert!(
        !stub.called("eth_estimateGas"),
        "EstimateGas must be skipped"
    );
}

// Go: TestLoadBuildConfig_FromEnvVar — --from resolved from the env var funds the
// nonce/gas calls (observable: the calls carry the env address).
#[test]
fn from_env_var() {
    let stub = Stub::build_ok(HOLESKY_CHAIN_ID, 1_000_000_000, 10_000_000_000, 5, 200_000);

    let out = ethernal()
        .env("ETHERNAL_TX_FROM", TEST_FROM)
        .args(["deposit", "build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        // nonce+gas omitted → both PendingNonceAt and EstimateGas run with From.
        .args(["--rpc-url", &stub.url])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let nonce_params = stub
        .params_of("eth_getTransactionCount")
        .expect("nonce fetched");
    assert_eq!(
        nonce_params[0].as_str().unwrap().to_lowercase(),
        TEST_FROM.to_lowercase()
    );
}
