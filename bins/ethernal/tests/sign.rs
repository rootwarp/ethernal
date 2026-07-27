//! Binary-driven port of `cmd/ethernal/sign_test.go`. Go swapped `app.Reader`
//! for stdin and generated fresh keys; here the binary reads the key from a
//! file and stdin is piped. A fixed synthetic key (`PHASE3_KEY`) stands in for
//! Go's `generateTestPrivKey` — the assertions only check field presence and
//! exit codes, not the derived address.

mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;

use common::{ethernal, secret_file, unsigned_tx_golden, TempDir, PHASE3_KEY};

fn unsigned_input(dir: &TempDir) -> PathBuf {
    let bytes = std::fs::read(unsigned_tx_golden()).expect("read unsigned golden");
    dir.write("unsigned.json", &bytes)
}

/// Writes `PHASE3_KEY` at mode 0600 and returns the path (FR-17 hygiene).
fn phase3_key_file(dir: &TempDir) -> PathBuf {
    secret_file(dir, "key.hex", PHASE3_KEY.as_bytes())
}

// Go: TestSignCommand_LocalSigner_Success
#[test]
fn local_signer_success() {
    let dir = TempDir::new("sign-ok");
    let in_file = unsigned_input(&dir);
    let out_file = dir.join("signed.json");
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .args(["tx", "sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .arg("--output")
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
}

// Missing key file → exit 2 (FR-13: file-policy, not crypto). Names the path.
#[test]
fn local_signer_missing_key_file() {
    let dir = TempDir::new("sign-missingkey");
    let in_file = unsigned_input(&dir);
    let missing = dir.join("no-such-key.hex");

    let out = ethernal()
        .args(["tx", "sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .arg("--private-key-file")
        .arg(&missing)
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(missing.to_str().unwrap()),
        "error should name the path"
    );
}

// Bad key hex → exit 3, no key material in output.
#[test]
fn local_signer_bad_key() {
    let dir = TempDir::new("sign-badkey");
    let in_file = unsigned_input(&dir);
    let key_file = secret_file(&dir, "key.hex", b"0xdeadbeefnotahexkey");

    let out = ethernal()
        .args(["tx", "sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .arg("--private-key-file")
        .arg(&key_file)
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

    let out = ethernal()
        .args(["tx", "sign", "--signer", "foo", "--input"])
        .arg(&in_file)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestSignCommand_MissingInput → exit 2.
#[test]
fn missing_input() {
    let out = ethernal()
        .args(["tx", "sign", "--signer", "local"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// FR-24: --signer local with no --private-key-file → exit 2 naming the flag.
#[test]
fn private_key_file_required_for_local() {
    let dir = TempDir::new("sign-nokeyflag");
    let in_file = unsigned_input(&dir);

    let out = ethernal()
        .args(["tx", "sign", "--signer", "local", "--input"])
        .arg(&in_file)
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
    let dir = TempDir::new("sign-dashkey");
    let in_file = unsigned_input(&dir);

    let out = ethernal()
        .args(["tx", "sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .args(["--private-key-file", "-"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--private-key-file"),
        "error should name the flag: {stderr}"
    );
}

// Go: TestSignCommand_InvalidInputJSON → exit 2.
// R-4: exit-code assertion and body intent must stay (bad JSON before key use).
#[test]
fn invalid_input_json() {
    let dir = TempDir::new("sign-badinput");
    let bad = dir.write("garbage.json", b"this is not json at all");
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .args(["tx", "sign", "--signer", "local", "--input"])
        .arg(&bad)
        .arg("--private-key-file")
        .arg(&key_file)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// Go: TestSignCommand_LocalSigner_StdinInput
#[test]
fn local_signer_stdin_input() {
    let dir = TempDir::new("sign-stdin");
    let out_file = dir.join("signed.json");
    let key_file = phase3_key_file(&dir);
    let raw = std::fs::read(unsigned_tx_golden()).expect("read golden");

    let mut child = ethernal()
        .args([
            "tx", "sign", "--signer", "local", "--input", "-", "--output",
        ])
        .arg(&out_file)
        .arg("--private-key-file")
        .arg(&key_file)
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
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .args(["tx", "sign", "--signer", "local", "--input"])
        .arg(&in_file)
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
    assert!(signed.get("rawRLP").is_some(), "stdout missing rawRLP");
}

// Go: TestSignCommand_Ledger_NotSupported_OnCGOPath → exit 3 (no device).
#[test]
fn ledger_not_supported_exit3() {
    let dir = TempDir::new("sign-ledger");
    let in_file = unsigned_input(&dir);

    let out = ethernal()
        .args(["tx", "sign", "--signer", "ledger", "--input"])
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

// Go: TestSignCommand_OutputWriteError_Exit2 → an unwritable output dir → exit 2.
#[test]
fn output_write_error_exit2() {
    let dir = TempDir::new("sign-writeerr");
    let in_file = unsigned_input(&dir);
    let key_file = phase3_key_file(&dir);
    let ro_dir = dir.join("readonly");
    std::fs::create_dir(&ro_dir).unwrap();
    std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let out_file = ro_dir.join("signed.json");

    let out = ethernal()
        .args(["tx", "sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .arg("--output")
        .arg(&out_file)
        .arg("--private-key-file")
        .arg(&key_file)
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
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .args(["tx", "sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .arg("--output")
        .arg(&out_file)
        .arg("--private-key-file")
        .arg(&key_file)
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
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .args(["tx", "sign", "--signer", "local", "--input"])
        .arg(&in_file)
        .args(["--output", "-"])
        .arg("--private-key-file")
        .arg(&key_file)
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
    let key_file = phase3_key_file(&dir);

    let out = ethernal()
        .args(["tx", "sign", "--signer", "local", "--input"])
        .arg(common::phase3_unsigned())
        .arg("--output")
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

    let got = std::fs::read(&out_file).expect("read signed output");
    let want = std::fs::read(common::phase3_signed_golden()).expect("read signed golden");
    assert_eq!(
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&want),
        "phase3 signed golden mismatch"
    );
}

// FR-30: long_about / --signer help describe a path, not an environment variable.
#[test]
fn sign_help_describes_path_argument() {
    let out = ethernal()
        .args(["tx", "sign", "--help"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("private-key-file"),
        "sign --help missing --private-key-file: {s}"
    );
    // Old wording (FR-30 deleted): must not present local as an env source.
    assert!(
        !s.contains("environment variable") && !s.to_ascii_lowercase().contains("env var"),
        "sign --help must not describe an environment-variable key source: {s}"
    );
    assert!(
        s.contains("file") || s.contains("PATH") || s.contains("path"),
        "long_about / help must describe a path argument: {s}"
    );
}
