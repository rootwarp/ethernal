//! Binary-driven port of `cmd/eth-deposit/sign_test.go`. Go swapped `app.Reader`
//! for stdin and generated fresh keys; here the binary reads the key from an env
//! var and stdin is piped. A fixed synthetic key (`PHASE3_KEY`) stands in for
//! Go's `generateTestPrivKey` — the assertions only check field presence and
//! exit codes, not the derived address.

mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;

use common::{eth_deposit, unsigned_tx_golden, TempDir, PHASE3_KEY};

const KEY_ENV: &str = "TEST_ETH_DEPOSIT_KEY";

fn unsigned_input(dir: &TempDir) -> std::path::PathBuf {
    let bytes = std::fs::read(unsigned_tx_golden()).expect("read unsigned golden");
    dir.write("unsigned.json", &bytes)
}

// Go: TestSignCommand_LocalSigner_Success
#[test]
fn local_signer_success() {
    let dir = TempDir::new("sign-ok");
    let in_file = unsigned_input(&dir);
    let out_file = dir.join("signed.json");

    let out = eth_deposit()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .arg("--output")
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
}

// Go: TestSignCommand_LocalSigner_MissingEnvKey → exit 3, error names the env var.
#[test]
fn local_signer_missing_env_key() {
    let dir = TempDir::new("sign-missingkey");
    let in_file = unsigned_input(&dir);

    let out = eth_deposit()
        // KEY_ENV intentionally not set.
        .args(["sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .args(["--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(KEY_ENV),
        "error should name the env var"
    );
}

// Go: TestSignCommand_LocalSigner_BadKey → exit 3, no key material in output.
#[test]
fn local_signer_bad_key() {
    let dir = TempDir::new("sign-badkey");
    let in_file = unsigned_input(&dir);

    let out = eth_deposit()
        .env(KEY_ENV, "0xdeadbeefnotahexkey")
        .args(["sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .args(["--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("deadbeef"),
        "error must not contain key material"
    );
}

// Go: TestSignCommand_InvalidSigner → exit 2.
#[test]
fn invalid_signer() {
    let dir = TempDir::new("sign-badsigner");
    let in_file = unsigned_input(&dir);

    let out = eth_deposit()
        .args(["sign", "--signer", "foo", "--input"])
        .arg(&in_file)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestSignCommand_MissingInput → exit 2.
#[test]
fn missing_input() {
    let out = eth_deposit()
        .args(["sign", "--signer", "local"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestSignCommand_InvalidInputJSON → exit 2.
#[test]
fn invalid_input_json() {
    let dir = TempDir::new("sign-badinput");
    let bad = dir.write("garbage.json", b"this is not json at all");

    let out = eth_deposit()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["sign", "--signer", "local", "--input"])
        .arg(&bad)
        .args(["--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestSignCommand_LocalSigner_StdinInput
#[test]
fn local_signer_stdin_input() {
    let dir = TempDir::new("sign-stdin");
    let out_file = dir.join("signed.json");
    let raw = std::fs::read(unsigned_tx_golden()).expect("read golden");

    let mut child = eth_deposit()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["sign", "--signer", "local", "--input", "-", "--output"])
        .arg(&out_file)
        .args(["--private-key-env", KEY_ENV])
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
    let data = std::fs::read(&out_file).expect("signed.json written");
    serde_json::from_slice::<serde_json::Value>(&data).expect("valid JSON");
}

// Go: TestSignCommand_LocalSigner_StdoutOutput
#[test]
fn local_signer_stdout_output() {
    let dir = TempDir::new("sign-stdout");
    let in_file = unsigned_input(&dir);

    let out = eth_deposit()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .args(["--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let signed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert!(signed.get("rawRLP").is_some(), "stdout missing rawRLP");
}

// Go: TestSignCommand_Ledger_NotSupported_OnCGOPath → exit 3 (no device).
#[test]
fn ledger_not_supported_exit3() {
    let dir = TempDir::new("sign-ledger");
    let in_file = unsigned_input(&dir);

    let out = eth_deposit()
        .args(["sign", "--signer", "ledger", "--input"])
        .arg(&in_file)
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestSignCommand_InvalidEnvVarName_Lowercase → exit 2.
#[test]
fn invalid_env_var_name_lowercase() {
    let dir = TempDir::new("sign-lower");
    let in_file = unsigned_input(&dir);

    let out = eth_deposit()
        .args(["sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .args(["--private-key-env", "my_lowercase_var"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestSignCommand_InvalidEnvVarName_KeyPassedDirectly → exit 2, mentions POSIX.
#[test]
fn invalid_env_var_name_key_passed_directly() {
    let dir = TempDir::new("sign-keyname");
    let in_file = unsigned_input(&dir);

    let out = eth_deposit()
        .args(["sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .args(["--private-key-env", PHASE3_KEY]) // a hex key passed as the var NAME
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("POSIX"),
        "error should mention POSIX"
    );
}

// Go: TestSignCommand_OutputWriteError_Exit2 → an unwritable output dir → exit 2.
#[test]
fn output_write_error_exit2() {
    let dir = TempDir::new("sign-writeerr");
    let in_file = unsigned_input(&dir);
    let ro_dir = dir.join("readonly");
    std::fs::create_dir(&ro_dir).unwrap();
    std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let out_file = ro_dir.join("signed.json");

    let out = eth_deposit()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .arg("--output")
        .arg(&out_file)
        .args(["--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    // restore perms for cleanup
    let _ = std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o700));
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestSignCommand_OutputFilePermissions → signed file is mode 0600.
#[test]
fn output_file_permissions() {
    let dir = TempDir::new("sign-perm");
    let in_file = unsigned_input(&dir);
    let out_file = dir.join("signed.json");

    let out = eth_deposit()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .arg("--output")
        .arg(&out_file)
        .args(["--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert!(out.status.success());
    let mode = std::fs::metadata(&out_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "signed file must be 0600");
}

// Go: TestSignCommand_OutputDash_IsStdout
#[test]
fn output_dash_is_stdout() {
    let dir = TempDir::new("sign-dash");
    let in_file = unsigned_input(&dir);

    let out = eth_deposit()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .args(["--output", "-", "--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert!(out.status.success());
    let signed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert!(signed.get("rawRLP").is_some());
}

// Go: TestPhase3_HoleskyLocalSignerGolden — signing the phase-3 unsigned fixture
// with the synthetic key reproduces the signed golden byte-for-byte.
#[test]
fn phase3_local_signer_golden() {
    let dir = TempDir::new("sign-golden");
    let out_file = dir.join("signed_tx.json");

    let out = eth_deposit()
        .env(KEY_ENV, PHASE3_KEY)
        .args(["sign", "--signer", "local", "--input"])
        .arg(common::phase3_unsigned())
        .arg("--output")
        .arg(&out_file)
        .args(["--private-key-env", KEY_ENV])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let got = std::fs::read(&out_file).expect("read signed output");
    let want = std::fs::read(common::phase3_signed_golden()).expect("read signed golden");
    assert_eq!(
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&want),
        "phase3 signed golden mismatch"
    );
}
