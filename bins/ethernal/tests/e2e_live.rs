//! Live e2e tier — real EVM via the Foundry `anvil` binary.
//!
//! Every test here is `#[ignore]`-gated so the hermetic `make test` tier never
//! runs them. Each test also opens with a skip-with-notice guard so a missing
//! `anvil` binary is a green no-op under `--ignored` (D-3).
//!
//! E6-1: anvil harness smoke. E6-2: live gen|build|sign|send pipe chain (T-6).
//! E6-3: hybrid RPC probes — nonce resolution + wrong-network interactive send (T-13).

mod common;

#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::process::Stdio;

#[cfg(unix)]
use common::anvil::Anvil;
#[cfg(unix)]
use common::{
    ethernal, hoodi_expected_deposit_data, hoodi_keystores, hoodi_passphrase, hoodi_pubkey,
    write_temp_signed_tx, PHASE3_KEY,
};

/// Hoodi chain id (A-3 / verify skill).
#[cfg(unix)]
const HOODI_CHAIN_ID: u64 = 560048;

/// Sender derived from [`PHASE3_KEY`] (phase-3 synthetic key).
#[cfg(unix)]
const PHASE3_SENDER: &str = "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1";

/// 10_000 ETH in wei (hex) — same fund amount as the verify skill.
#[cfg(unix)]
const FUND_WEI_HEX: &str = "0x21e19e0c9bab2400000";

/// 32 ETH in wei — one deposit's value transfer.
#[cfg(unix)]
const THIRTY_TWO_ETH_WEI: u128 = 32_000_000_000_000_000_000;

#[cfg(unix)]
const PASS_ENV: &str = "TEST_HOODI_PASSPHRASE";
#[cfg(unix)]
const KEY_ENV: &str = "TEST_ETHERNAL_KEY";

/// Smoke: spawn anvil on hoodi chain-id, round-trip `eth_chainId`, Drop reaps.
#[cfg(unix)]
#[test]
#[ignore = "live tier: needs the anvil binary; run via `make e2e-live`"]
fn anvil_harness_eth_chain_id() {
    let Some(a) = Anvil::try_spawn(HOODI_CHAIN_ID) else {
        return;
    };

    let result = a.rpc("eth_chainId", serde_json::json!([]));
    let hex = result
        .as_str()
        .unwrap_or_else(|| panic!("eth_chainId result not a string: {result:?}"));
    let id = u64::from_str_radix(hex.trim_start_matches("0x"), 16)
        .unwrap_or_else(|e| panic!("parse eth_chainId {hex:?}: {e}"));
    assert_eq!(id, HOODI_CHAIN_ID, "eth_chainId round-trip");

    // Explicit drop so a failed reap would surface here; Drop kills + waits.
    drop(a);
}

/// T-6 / E6-2: live `gen | build | sign | send --wait-for-receipt` against anvil.
///
/// **D-9 wording (do not over-claim):** this asserts that a valid Ethereum tx was
/// accepted by a real EVM **and** that 32 ETH moved to the deposit-contract
/// address. It does **not** assert that the deposit contract validated the
/// deposit — bare anvil (`--chain-id 560048`, empty genesis) has no
/// deposit-contract code, so `send` is a value transfer to a codeless address.
/// Deposit-contract-logic validation stays on the manual/real-network path.
#[cfg(unix)]
#[test]
#[ignore = "live tier: needs the anvil binary; run via `make e2e-live`"]
fn e2e_live_full_pipe_chain_moves_32_eth() {
    let Some(anvil) = Anvil::try_spawn(HOODI_CHAIN_ID) else {
        return;
    };

    // Fund the phase-3 sender so the 32 ETH deposit + gas can clear.
    anvil.set_balance(PHASE3_SENDER, FUND_WEI_HEX);

    // --- gen --dry-run (hoodi fixtures) ---
    let gen = ethernal()
        .env(PASS_ENV, hoodi_passphrase())
        .args(["gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--dry-run",
            "--passphrase-env",
            PASS_ENV,
            "--withdrawal-address",
            PHASE3_SENDER,
        ])
        .output()
        .expect("spawn gen");
    assert!(
        gen.status.success(),
        "gen failed: {}",
        String::from_utf8_lossy(&gen.stderr)
    );

    // --- build --input-file - (stdin from gen) ---
    let build = run_with_stdin(
        ethernal().args([
            "build",
            "--network",
            "hoodi",
            "--input-file",
            "-",
            "--nonce",
            "0",
        ]),
        &gen.stdout,
    );
    assert!(
        build.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    // Deposit-contract address comes from the built tx's `to` (no hardcode).
    let built: serde_json::Value = serde_json::from_slice(&build.stdout).expect("built tx JSON");
    let deposit_to = built["to"].as_str().expect("built tx missing `to` field");
    let n_deposits: u128 = 1; // hoodi fixture is a single-validator deposit

    let bal_before = eth_balance(&anvil, deposit_to);

    // --- sign --input - | send --yes --input - --rpc-url <anvil> --wait-for-receipt ---
    let sign = run_with_stdin(
        ethernal().env(KEY_ENV, PHASE3_KEY).args([
            "sign",
            "--signer",
            "local",
            "--input",
            "-",
            "--private-key-env",
            KEY_ENV,
        ]),
        &build.stdout,
    );
    assert!(
        sign.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let send = run_with_stdin(
        ethernal().args([
            "send",
            "--yes",
            "--input",
            "-",
            "--rpc-url",
            anvil.url(),
            "--wait-for-receipt",
        ]),
        &sign.stdout,
    );
    assert!(
        send.status.success(),
        "send failed: stdout={} stderr={}",
        String::from_utf8_lossy(&send.stdout),
        String::from_utf8_lossy(&send.stderr)
    );

    // (a) successful receipt (valid-tx-accepted by a real EVM).
    let send_stdout = String::from_utf8_lossy(&send.stdout);
    assert!(
        send_stdout.contains("status=success"),
        "expected successful receipt in send stdout: {send_stdout}"
    );

    // (b) value-moved: deposit-contract address balance grew by 32 ETH / deposit.
    let bal_after = eth_balance(&anvil, deposit_to);
    let want = bal_before
        .checked_add(THIRTY_TWO_ETH_WEI.checked_mul(n_deposits).expect("n*32eth"))
        .expect("balance overflow");
    assert_eq!(
        bal_after, want,
        "deposit-contract {deposit_to} balance did not grow by 32 ETH per deposit \
         (before={bal_before}, after={bal_after}, want={want})"
    );

    drop(anvil);
}

/// T-13(a) / E6-3: `build --rpc-url <anvil> --from <addr>` with nonce/gas omitted
/// resolves nonce from the real node. Real-node analog of
/// `build_rpc::rpc_resolves_unset_fields`.
#[cfg(unix)]
#[test]
#[ignore = "live tier: needs the anvil binary; run via `make e2e-live`"]
fn e2e_live_build_resolves_nonce_from_anvil() {
    let Some(anvil) = Anvil::try_spawn(HOODI_CHAIN_ID) else {
        return;
    };

    // Fund sender so eth_estimateGas can clear a 32 ETH value transfer.
    anvil.set_balance(PHASE3_SENDER, FUND_WEI_HEX);

    // Seed a nonzero pending nonce; build must pick this up (not default 0).
    let want_nonce: u64 = 42;
    anvil.set_nonce(PHASE3_SENDER, want_nonce);

    let out = ethernal()
        .args(["build", "--network", "hoodi", "--input-file"])
        .arg(hoodi_expected_deposit_data())
        .args(["--rpc-url", anvil.url(), "--from", PHASE3_SENDER])
        .output()
        .expect("spawn build");
    assert!(
        out.status.success(),
        "build failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let tx: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("build stdout is valid JSON");
    assert_eq!(
        tx["nonce"], want_nonce,
        "built tx nonce must match anvil_setNonce value; tx={tx}"
    );

    drop(anvil);
}

/// T-13(b) / E6-3: interactive `send` (no `--yes`) against anvil with the wrong
/// network name → exit 4. Real-node analog of `send::confirm_prompt_reject`.
///
/// Uses holesky chain-id + the phase-3 signed golden so the chain-id check passes
/// and the confirm prompt is reached.
#[cfg(unix)]
#[test]
#[ignore = "live tier: needs the anvil binary; run via `make e2e-live`"]
fn e2e_live_send_wrong_network_name_exit4() {
    const HOLESKY_CHAIN_ID: u64 = 17000;

    let Some(anvil) = Anvil::try_spawn(HOLESKY_CHAIN_ID) else {
        return;
    };

    let (_dir, signed) = write_temp_signed_tx();

    let mut child = ethernal()
        .args(["send", "--input"])
        .arg(&signed)
        .args(["--rpc-url", anvil.url()])
        // no --yes → interactive confirm
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn send");
    {
        let mut w = child.stdin.take().expect("stdin piped");
        // Wrong network name (signed tx is holesky).
        w.write_all(b"mainnet\n").expect("write wrong network name");
    }
    let out = child.wait_with_output().expect("wait send");
    assert_eq!(
        out.status.code(),
        Some(4),
        "wrong-network confirm must exit 4; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    drop(anvil);
}

/// Run `cmd` with `stdin` bytes and capture stdout/stderr.
#[cfg(unix)]
fn run_with_stdin(cmd: &mut std::process::Command, stdin: &[u8]) -> std::process::Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        let mut w = child.stdin.take().expect("stdin piped");
        w.write_all(stdin).expect("write stdin");
    }
    child.wait_with_output().expect("wait")
}

/// `eth_getBalance(addr, "latest")` → wei as u128.
#[cfg(unix)]
fn eth_balance(anvil: &Anvil, addr: &str) -> u128 {
    let result = anvil.rpc("eth_getBalance", serde_json::json!([addr, "latest"]));
    let hex = result
        .as_str()
        .unwrap_or_else(|| panic!("eth_getBalance result not a string: {result:?}"));
    parse_hex_u128(hex)
}

#[cfg(unix)]
fn parse_hex_u128(s: &str) -> u128 {
    let s = s.trim().trim_start_matches("0x");
    if s.is_empty() {
        return 0;
    }
    u128::from_str_radix(s, 16).unwrap_or_else(|e| panic!("parse hex quantity {s:?}: {e}"))
}
