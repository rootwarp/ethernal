//! Binary-driven port of `cmd/ethernal/run_test.go` (offline `run` = build +
//! sign in one step). RPC-mode `run` cases live in `run_rpc.rs`.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{deposit_fixture, ethernal, TempDir, PHASE3_KEY};

const KEY_ENV: &str = "TEST_ETHERNAL_KEY";

// Go: TestRunCommand_LocalSigner_HappyPath
#[test]
fn local_signer_happy_path() {
    let dir = TempDir::new("run-ok");
    let out_file = dir.join("signed.json");

    let out = ethernal()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["tx", "run", "--network", "holesky", "--input-file"])
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

    let data = std::fs::read(&out_file).expect("signed.json written");
    let signed: serde_json::Value = serde_json::from_slice(&data).expect("valid JSON");
    for field in ["unsigned", "from", "hash", "r", "s", "v", "rawRLP"] {
        assert!(signed.get(field).is_some(), "missing field {field}");
    }

    let raw_file = dir.join("signed.raw");
    let raw = std::fs::read_to_string(&raw_file).expect("signed.raw written");
    assert!(
        raw.trim().starts_with("0x"),
        "raw must have 0x prefix: {raw}"
    );
}

// Go: TestRunCommand_LocalSigner_StdoutOutput
#[test]
fn local_signer_stdout_output() {
    let out = ethernal()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let signed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert!(signed.get("rawRLP").is_some());
}

// Go: TestRunCommand_LocalSigner_KeepUnsigned
#[test]
fn local_signer_keep_unsigned() {
    let dir = TempDir::new("run-keepu");
    let out_file = dir.join("signed.json");

    let out = ethernal()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--output"])
        .arg(&out_file)
        .args(["--keep-unsigned", "--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let signed = std::fs::read(&out_file).expect("signed.json");
    serde_json::from_slice::<serde_json::Value>(&signed).expect("signed valid JSON");

    let unsigned_file = dir.join("unsigned.json");
    let unsigned: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&unsigned_file).expect("unsigned.json")).unwrap();
    for field in ["chainId", "to", "value", "data", "gas"] {
        assert!(unsigned.get(field).is_some(), "unsigned missing {field}");
    }
}

// Go: TestRunCommand_LocalSigner_RawOutput
#[test]
fn local_signer_raw_output() {
    let dir = TempDir::new("run-raw");
    let out_file = dir.join("signed.json");
    let raw_file = dir.join("custom.raw");

    let out = ethernal()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--output"])
        .arg(&out_file)
        .arg("--raw-output")
        .arg(&raw_file)
        .args(["--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let raw = std::fs::read_to_string(&raw_file).expect("custom.raw written");
    assert!(raw.trim().starts_with("0x"));
    // The auto-derived signed.raw must NOT exist when --raw-output overrides it.
    assert!(
        !dir.join("signed.raw").exists(),
        "default signed.raw should not be written"
    );
}

// Go: TestRunCommand_MissingSignerFlag → exit 2.
#[test]
fn missing_signer_flag() {
    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestRunCommand_LedgerNoDevice → exit 3.
#[test]
fn ledger_no_device() {
    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "ledger"])
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestRunCommand_InvalidInput → exit 2.
#[test]
fn invalid_input() {
    let dir = TempDir::new("run-badinput");
    let bad = dir.write("bad.json", b"not json at all");

    let out = ethernal()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(&bad)
        .args(["--signer", "local", "--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestRunCommand_BadKey → exit 3.
#[test]
fn bad_key() {
    let out = ethernal()
        .env(KEY_ENV, "0xdeadbeefnotahexkey")
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
}

// Go: TestRunCommand_AtomicWrite_OnRenameFailure — an existing directory at the
// output path makes the rename fail; no temp files may be left behind.
#[test]
fn atomic_write_on_rename_failure() {
    let dir = TempDir::new("run-rename");
    let out_dir = dir.join("signed.json");
    std::fs::create_dir(&out_dir).expect("mkdir output path");

    let out = ethernal()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--output"])
        .arg(&out_dir)
        .args(["--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert!(
        !out.status.success(),
        "expected error when output path is a directory"
    );

    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".tmp-ethernal-")
        })
        .collect();
    assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
}

// Go: TestRunCommand_KeepUnsigned_RequiresOutputFile → exit 2.
#[test]
fn keep_unsigned_requires_output_file() {
    let out = ethernal()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args([
            "--signer",
            "local",
            "--keep-unsigned",
            "--private-key-env",
            KEY_ENV,
        ])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestRunCommand_OutputFilePermissions → signed.json and signed.raw are 0600.
#[test]
fn output_file_permissions() {
    let dir = TempDir::new("run-perm");
    let out_file = dir.join("signed.json");

    let out = ethernal()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--output"])
        .arg(&out_file)
        .args(["--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert!(out.status.success());
    for path in [out_file.clone(), dir.join("signed.raw")] {
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{path:?} must be 0600");
    }
}

// Go: TestRunCommand_OutputDash_IsStdout — "-" writes JSON to stdout and no .raw.
#[test]
fn output_dash_is_stdout() {
    let dir = TempDir::new("run-dash");

    let out = ethernal()
        .env(KEY_ENV, PHASE3_KEY)
        .current_dir(dir.path())
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args([
            "--signer",
            "local",
            "--output",
            "-",
            "--private-key-env",
            KEY_ENV,
        ])
        .output()
        .expect("run");
    assert!(out.status.success());
    serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("valid JSON");

    let raws: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".raw"))
        .collect();
    assert!(
        raws.is_empty(),
        "no .raw file should be written for stdout: {raws:?}"
    );
}

// Go: TestRunSubcommand_Help
#[test]
fn run_subcommand_help() {
    let out = ethernal()
        .args(["tx", "run", "--help"])
        .output()
        .expect("run");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("signer"), "run --help missing --signer");
    assert!(
        s.contains("keep-unsigned"),
        "run --help missing --keep-unsigned"
    );
}
