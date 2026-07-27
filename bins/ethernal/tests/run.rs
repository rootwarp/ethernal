//! Binary-driven port of `cmd/ethernal/run_test.go` (offline `run` = build +
//! sign in one step). RPC-mode `run` cases live in `run_rpc.rs`.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use common::{deposit_fixture, ethernal, secret_file, TempDir, PHASE3_KEY};

/// Writes `PHASE3_KEY` at mode 0600 and returns the path (FR-17 hygiene).
fn phase3_key_file(dir: &TempDir) -> PathBuf {
    secret_file(dir, "key.hex", PHASE3_KEY.as_bytes())
}

// Go: TestRunCommand_LocalSigner_HappyPath
#[test]
fn local_signer_happy_path() {
    let dir = TempDir::new("run-ok");
    let out_file = dir.join("signed.json");
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--output"])
        .arg(&out_file)
        .arg("--private-key-file")
        .arg(&key_file)
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
    let dir = TempDir::new("run-stdout");
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local"])
        .arg("--private-key-file")
        .arg(&key_file)
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
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--output"])
        .arg(&out_file)
        .arg("--keep-unsigned")
        .arg("--private-key-file")
        .arg(&key_file)
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
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--output"])
        .arg(&out_file)
        .arg("--raw-output")
        .arg(&raw_file)
        .arg("--private-key-file")
        .arg(&key_file)
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

// FR-24: --signer local with no --private-key-file → exit 2 naming the flag.
#[test]
fn private_key_file_required_for_local() {
    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--private-key-file"),
        "error should name --private-key-file: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// FR-6: --private-key-file - → exit 2.
#[test]
fn private_key_file_dash_exit2() {
    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--private-key-file", "-"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--private-key-file"),
        "error should name the flag: {stderr}"
    );
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
// R-4: bad JSON + good key → exit 2 (read_input still precedes signer construction
// for the file-read step; parse failure is at build). Exit-code assertion fixed.
#[test]
fn invalid_input() {
    let dir = TempDir::new("run-badinput");
    let bad = dir.write("bad.json", b"not json at all");
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(&bad)
        .args(["--signer", "local"])
        .arg("--private-key-file")
        .arg(&key_file)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestRunCommand_BadKey → exit 3.
// R-4: bad hex + good fixture → exit 3 (InvalidKey, not file-policy).
#[test]
fn bad_key() {
    let dir = TempDir::new("run-badkey");
    let key_file = secret_file(&dir, "key.hex", b"0xdeadbeefnotahexkey");

    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local"])
        .arg("--private-key-file")
        .arg(&key_file)
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
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--output"])
        .arg(&out_dir)
        .arg("--private-key-file")
        .arg(&key_file)
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
    let dir = TempDir::new("run-keep-noout");
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--keep-unsigned"])
        .arg("--private-key-file")
        .arg(&key_file)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestRunCommand_OutputFilePermissions → signed.json and signed.raw are 0600.
#[test]
fn output_file_permissions() {
    let dir = TempDir::new("run-perm");
    let out_file = dir.join("signed.json");
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--output"])
        .arg(&out_file)
        .arg("--private-key-file")
        .arg(&key_file)
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
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .current_dir(dir.path())
        .args(["tx", "run", "--network", "holesky", "--input-file"])
        .arg(deposit_fixture())
        .args(["--signer", "local", "--output", "-"])
        .arg("--private-key-file")
        .arg(&key_file)
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
    assert!(
        s.contains("private-key-file"),
        "run --help missing --private-key-file"
    );
    // FR-30: local signer is a file path, not an environment-variable source.
    assert!(
        !s.contains("environment variable") && !s.to_ascii_lowercase().contains("env var"),
        "run --help must not describe an environment-variable key source: {s}"
    );
}
