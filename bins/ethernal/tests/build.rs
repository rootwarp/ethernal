//! Binary-driven port of `cmd/ethernal/{main_test.go,golden_test.go}` build
//! cases plus the offline `GasLimitEnvVar` config fallback. RPC-mode build cases
//! live in `build_rpc.rs`; white-box `LoadBuildConfig` cases live in the
//! `config.rs` `#[cfg(test)]` module.

mod common;

use std::io::Write;
use std::process::Stdio;

use common::{
    deposit_fixture, ethernal, phase2_fixture, phase2_golden, unsigned_tx_golden, TempDir,
};

// Go: TestBuild_GoldenOutput — build output must equal the committed golden
// byte-for-byte.
#[test]
fn build_golden_output() {
    let out = ethernal()
        .args(["build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .output()
        .expect("run build");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let want = std::fs::read(unsigned_tx_golden()).expect("read golden");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&want),
        "golden mismatch"
    );
}

// Go: TestPhase2_HoleskyGolden — phase-2 synthetic fixture builds to its golden.
#[test]
fn phase2_holesky_golden() {
    let out = ethernal()
        .args(["build", "--network", "holesky", "--input-file"])
        .arg(phase2_fixture())
        .output()
        .expect("run build");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let want = std::fs::read(phase2_golden()).expect("read phase2 golden");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&want),
        "phase2 golden mismatch"
    );
}

// Go: TestApp_Help
#[test]
fn app_help() {
    let out = ethernal().arg("--help").output().expect("run --help");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("ethernal"), "help missing app name: {s}");
    for sub in ["build", "sign", "run"] {
        assert!(s.contains(sub), "help missing subcommand {sub}: {s}");
    }
}

// Go: TestApp_Version
#[test]
fn app_version() {
    let out = ethernal().arg("--version").output().expect("run --version");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("dev") || s.contains("ethernal"),
        "version output unexpected: {s}"
    );
}

// Go: TestBuildSubcommand_Help
#[test]
fn build_subcommand_help() {
    let out = ethernal().args(["build", "--help"]).output().expect("run");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("input-file"), "build --help missing flag: {s}");
}

// Go: TestSignSubcommand_Help
#[test]
fn sign_subcommand_help() {
    let out = ethernal().args(["sign", "--help"]).output().expect("run");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("signer"), "sign --help missing --signer: {s}");
    assert!(s.contains("ledger"), "sign --help missing ledger: {s}");
}

// Go: TestBuildSubcommand_Action_Success
#[test]
fn build_action_success() {
    let out = ethernal()
        .args(["build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .output()
        .expect("run");
    assert!(out.status.success());
    let tx: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    for field in [
        "chainId",
        "to",
        "value",
        "data",
        "gas",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
        "nonce",
        "type",
    ] {
        assert!(tx.get(field).is_some(), "missing field {field}");
    }
    assert_eq!(tx["type"], "0x2");
    let data = tx["data"].as_str().unwrap();
    assert!(
        data.starts_with("0x22895118"),
        "data must start with deposit() selector: {data}"
    );
}

// Go: TestBuildSubcommand_Action_StdinInput
#[test]
fn build_action_stdin_input() {
    let raw = std::fs::read(deposit_fixture()).expect("read fixture");
    let mut child = ethernal()
        .args(["build", "--network", "holesky", "--input-file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child.stdin.take().unwrap().write_all(&raw).unwrap();
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("valid JSON from stdin");
}

// Go: TestBuildSubcommand_Action_StdoutDefault
#[test]
fn build_action_stdout_default() {
    let out = ethernal()
        .args(["build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .output()
        .expect("run");
    assert!(out.status.success());
    serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("stdout is valid JSON");
}

// Go: TestBuildSubcommand_Action_OutputToFile
#[test]
fn build_action_output_to_file() {
    let dir = TempDir::new("build-out");
    let out_file = dir.join("unsigned.json");
    let out = ethernal()
        .args(["build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .arg("--output")
        .arg(&out_file)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let written = std::fs::read(&out_file).expect("read output file");
    serde_json::from_slice::<serde_json::Value>(&written).expect("output file is valid JSON");
}

// Go: TestBuildSubcommand_Action_OutputDash_IsStdout
#[test]
fn build_action_output_dash_is_stdout() {
    let out = ethernal()
        .args(["build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--output", "-"])
        .output()
        .expect("run");
    assert!(out.status.success());
    serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("--output - is valid JSON");
}

// Go: TestBuildSubcommand_InputAlias — `--input` aliases `--input-file`.
#[test]
fn build_input_alias() {
    let out = ethernal()
        .args(["build", "--network", "holesky", "--input"])
        .arg(deposit_fixture())
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("--input alias is valid JSON");
}

// Go: TestBuildSubcommand_Action_MissingInputFile → exit 2.
#[test]
fn build_action_missing_input_file() {
    let out = ethernal()
        .args([
            "build",
            "--network",
            "holesky",
            "--input-file",
            "/nonexistent/path/deposit.json",
        ])
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestBuildSubcommand_Action_InvalidJSON → exit 2.
#[test]
fn build_action_invalid_json() {
    let dir = TempDir::new("build-badjson");
    let bad = dir.write("bad.json", b"not json at all");
    let out = ethernal()
        .args(["build", "--network", "holesky", "--input-file"])
        .arg(&bad)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestBuildSubcommand_Action_IndexOutOfBounds → exit 2.
#[test]
fn build_action_index_out_of_bounds() {
    let out = ethernal()
        .args(["build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--index", "5"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestBuildSubcommand_Action_BadNetwork → exit 2.
#[test]
fn build_action_bad_network() {
    let out = ethernal()
        .args([
            "build",
            "--network",
            "badnet",
            "--input-file",
            "deposit.json",
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestLoadBuildConfig_GasLimitEnvVar — env fallback resolves the gas limit;
// observable in the offline build's `gas` field. (Binary-driven because clap
// reads process env at parse time.)
#[test]
fn build_gas_limit_env_var() {
    let out = ethernal()
        .env("ETHERNAL_TX_GAS_LIMIT", "500000")
        .args(["build", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tx: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(tx["gas"], 500000, "env-var gas limit not applied");
}
