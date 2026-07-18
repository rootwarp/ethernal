//! Binary-driven port of the REAL gen pipeline cases from `gen_test.go`
//! (`TestGenDryRun_NoOutputDir_RealPipelineEmitsJSON`) and the
//! `--verify-with-deposit-cli` feature (`TestVerifyDepositCLI_*`), the latter
//! using a fake `deposit` shell script on PATH.
//!
//! The CLI-validation matrix (`internal/cli/cli_test.go`) is a white-box port in
//! the `gen_cli.rs` `#[cfg(test)]` module — it exercises `load_config`
//! (validate/banner only), matching Go's no-op run callback which never runs the
//! pipeline. Driving the binary here would instead run the real pipeline.
//!
//! K5-2: every successful `gen` invocation must pass `--withdrawal-address`
//! (require-choice gate); command-level tests also cover the gate and EIP-55
//! rejects.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{eth_deposit, hoodi_keystores, hoodi_passphrase, hoodi_pubkey, TempDir};

const PASS_ENV: &str = "TEST_HOODI_PASSPHRASE";

/// Known EIP-55 checksummed address (signer local test key).
const WITHDRAWAL_ADDR: &str = "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1";
/// Expected hex (no 0x) of 0x01 ‖ 11 zero ‖ addr20 for [`WITHDRAWAL_ADDR`].
const WITHDRAWAL_CREDS_HEX: &str =
    "0100000000000000000000001a642f0e3c3af545e7acbd38b07251b3990914f1";

// Go: TestGenDryRun_NoOutputDir_RealPipelineEmitsJSON — the real pipeline over
// the committed hoodi fixtures emits the deposit JSON to stdout in dry-run mode.
#[test]
fn gen_dry_run_real_pipeline_emits_json() {
    let out = eth_deposit()
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
            WITHDRAWAL_ADDR,
        ])
        .output()
        .expect("run gen");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let entries: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout is JSON");
    let arr = entries.as_array().expect("array");
    assert_eq!(arr.len(), 1, "one deposit entry");
    assert_eq!(arr[0]["pubkey"], hoodi_pubkey());
    assert_eq!(
        arr[0]["withdrawal_credentials"].as_str().unwrap(),
        WITHDRAWAL_CREDS_HEX,
        "0x01 execution-address credentials must appear in deposit data"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("eth-deposit gen:"),
        "banner missing: {stderr}"
    );
    assert!(
        stderr.contains("wrote <stdout>"),
        "dry-run summary must use <stdout>: {stderr}"
    );
}

// The non-dry-run pipeline writes deposit_data-<ts>.json into --output-dir.
#[test]
fn gen_writes_output_file() {
    let out_dir = TempDir::new("gen-out");
    let out = eth_deposit()
        .env(PASS_ENV, hoodi_passphrase())
        .args(["gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--output-dir",
        ])
        .arg(out_dir.path())
        .args([
            "--passphrase-env",
            PASS_ENV,
            "--withdrawal-address",
            WITHDRAWAL_ADDR,
        ])
        .output()
        .expect("run gen");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let files: Vec<_> = std::fs::read_dir(out_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.starts_with("deposit_data-") && n.ends_with(".json")
        })
        .collect();
    assert_eq!(
        files.len(),
        1,
        "expected one deposit_data file, got {files:?}"
    );
    let data = std::fs::read(files[0].path()).expect("read deposit_data");
    let entries: serde_json::Value = serde_json::from_slice(&data).expect("JSON");
    assert_eq!(
        entries[0]["withdrawal_credentials"].as_str().unwrap(),
        WITHDRAWAL_CREDS_HEX
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("wrote ") && stderr.contains("network=hoodi"),
        "summary: {stderr}"
    );
}

/// Writes an executable `deposit` script that exits `code`, returns its dir.
fn fake_deposit_cli(code: i32) -> TempDir {
    let dir = TempDir::new("fake-cli");
    let script = format!("#!/bin/sh\nexit {code}\n");
    let path = dir.write("deposit", script.as_bytes());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

fn path_with(prefix: &std::path::Path) -> String {
    let existing = std::env::var("PATH").unwrap_or_default();
    format!("{}:{}", prefix.display(), existing)
}

// Go: TestVerifyDepositCLI_FlagSet_StubReturnsNil — a passing external CLI lets
// the pipeline succeed.
#[test]
fn verify_with_deposit_cli_passes() {
    let cli_dir = fake_deposit_cli(0);
    let out_dir = TempDir::new("gen-verify-ok");

    let out = eth_deposit()
        .env(PASS_ENV, hoodi_passphrase())
        .env("PATH", path_with(cli_dir.path()))
        .args(["gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--output-dir",
        ])
        .arg(out_dir.path())
        .args([
            "--passphrase-env",
            PASS_ENV,
            "--verify-with-deposit-cli",
            "--withdrawal-address",
            WITHDRAWAL_ADDR,
        ])
        .output()
        .expect("run gen");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestVerifyDepositCLI_FlagSet_StubReturnsFailed — a non-zero external CLI
// exit → exit 3.
#[test]
fn verify_with_deposit_cli_fails_exit3() {
    let cli_dir = fake_deposit_cli(1);
    let out_dir = TempDir::new("gen-verify-fail");

    let out = eth_deposit()
        .env(PASS_ENV, hoodi_passphrase())
        .env("PATH", path_with(cli_dir.path()))
        .args(["gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--output-dir",
        ])
        .arg(out_dir.path())
        .args([
            "--passphrase-env",
            PASS_ENV,
            "--verify-with-deposit-cli",
            "--withdrawal-address",
            WITHDRAWAL_ADDR,
        ])
        .output()
        .expect("run gen");
    assert_eq!(
        out.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestVerifyDepositCLI_FlagSet_StubReturnsNotFound — a missing external CLI
// binary → exit 2 (DepositCliNotFound).
#[test]
fn verify_with_deposit_cli_not_found_exit2() {
    let out_dir = TempDir::new("gen-verify-notfound");
    // Point --deposit-cli-path at a path that does not exist.
    let missing = out_dir.join("no-such-deposit-binary");

    let out = eth_deposit()
        .env(PASS_ENV, hoodi_passphrase())
        .args(["gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--output-dir",
        ])
        .arg(out_dir.path())
        .args([
            "--passphrase-env",
            PASS_ENV,
            "--verify-with-deposit-cli",
            "--deposit-cli-path",
        ])
        .arg(&missing)
        .args(["--withdrawal-address", WITHDRAWAL_ADDR])
        .output()
        .expect("run gen");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestVerifyDepositCLI_DryRun_NeverCalled — verify is skipped in dry-run even
// with the flag set (the failing script would abort otherwise).
#[test]
fn verify_with_deposit_cli_skipped_in_dry_run() {
    let cli_dir = fake_deposit_cli(1); // would fail if it ran

    let out = eth_deposit()
        .env(PASS_ENV, hoodi_passphrase())
        .env("PATH", path_with(cli_dir.path()))
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
            "--verify-with-deposit-cli",
            "--withdrawal-address",
            WITHDRAWAL_ADDR,
        ])
        .output()
        .expect("run gen");
    assert!(
        out.status.success(),
        "verify must be skipped in dry-run; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// K5-2: absent --withdrawal-address → exit 2 (require-choice gate).
#[test]
fn gen_without_withdrawal_address_exit2() {
    let out = eth_deposit()
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
        ])
        .output()
        .expect("run gen");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--withdrawal-address"), "stderr: {stderr}");
    assert!(stderr.contains("required flag not set"), "stderr: {stderr}");
}

// K5-2: lowercase --withdrawal-address → exit 2 (strict EIP-55).
#[test]
fn gen_withdrawal_address_lowercase_exit2() {
    let lower = WITHDRAWAL_ADDR.to_ascii_lowercase();
    let out = eth_deposit()
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
            &lower,
        ])
        .output()
        .expect("run gen");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // H2 / K5-L5: pin *why* rejection happened (drop always-true flag-name disjunct).
    assert!(
        stderr.contains("EIP-55 checksum mismatch"),
        "stderr: {stderr}"
    );
}

// K5-2: checksum-mismatched --withdrawal-address → exit 2.
#[test]
fn gen_withdrawal_address_checksum_mismatch_exit2() {
    // Flip case of one alphabetic nibble ('E' → 'e' at index 9).
    let mut chars: Vec<char> = WITHDRAWAL_ADDR.chars().collect();
    assert_eq!(chars[9], 'E');
    chars[9] = 'e';
    let flipped: String = chars.into_iter().collect();

    let out = eth_deposit()
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
            &flipped,
        ])
        .output()
        .expect("run gen");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // H2 / K5-L5: pin *why* rejection happened (drop always-true flag-name disjunct).
    assert!(
        stderr.contains("EIP-55 checksum mismatch"),
        "stderr: {stderr}"
    );
}

// H2 / K5-L1: zero address self-checksums under EIP-55 but is refused → exit 2, no deposit output.
#[test]
fn gen_withdrawal_address_zero_exit2() {
    let out = eth_deposit()
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
            "0x0000000000000000000000000000000000000000",
        ])
        .output()
        .expect("run gen");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "zero address must not produce deposit JSON: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("zero address"),
        "stderr must name the zero address: {stderr}"
    );
}

// H2 / K5-L2: pre-signing banner echoes EIP-55 withdrawal address + full creds hex.
#[test]
fn gen_banner_echoes_withdrawal_address_and_credentials() {
    let out = eth_deposit()
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
            WITHDRAWAL_ADDR,
        ])
        .output()
        .expect("run gen");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!("withdrawal_address={WITHDRAWAL_ADDR}")),
        "banner must show EIP-55 address: {stderr}"
    );
    assert!(
        stderr.contains(&format!("withdrawal_credentials=0x{WITHDRAWAL_CREDS_HEX}")),
        "banner must show full credentials hex: {stderr}"
    );
}
