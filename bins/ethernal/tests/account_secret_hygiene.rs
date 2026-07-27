//! Secret-hygiene integration check for `account recover` (A4-1 / S-1 / S-2 / G5).
//!
//! Binary-level companion to the `AccountDeps` unit tests in `account_cmd.rs`:
//! pipe a fixed mnemonic, encrypt with `--passphrase-file`, and assert the
//! mnemonic, seed hex, and both passphrases never appear on stdout/stderr.
//! Full injectible-logger coverage lives in the unit seam; this guards the
//! production log path end-to-end on the distinct recover-stdin input surface.
//!
//! # F7-1 / FR-31 — eight file-mode error paths
//!
//! Architecture §9 **replaced** FR-31's "bad hex" and "wrong passphrase" rows with
//! **CR** and **non-UTF-8**. The two dropped rows are pre-existing paths with no new
//! file-mode leak vector and are already covered elsewhere; the two added rows are
//! **new failure modes the file source creates**. Do not restore the PRD list from
//! the requirement ID without reading architecture §9.
//!
//! Every error case uses a distinctive sentinel so `!output.contains(sentinel)` is a
//! real assertion (an empty output cannot satisfy it). The production log stream for
//! these commands is stderr (`Logger::stderr` in `main`); assertions cover stdout,
//! stderr, and that log stream together.

mod common;

use common::{ethernal, secret_file, TempDir};
use std::io::Write;
use std::path::Path;
use std::process::{Output, Stdio};

const ABANDON_12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// BIP-39 TREZOR seed for ABANDON_12.
const TREZOR_SEED_HEX: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
const KEYSTORE_PW: &str = "password1";
const MNEMONIC_PW: &str = "TREZOR";

#[test]
fn account_recover_secrets_absent_from_stderr() {
    let dir = TempDir::new("account-hygiene");
    let secrets = TempDir::new("account-hygiene-secrets");
    let ks_path = secret_file(&secrets, "ks.pw", KEYSTORE_PW.as_bytes());
    let mp_path = secret_file(&secrets, "mp.pw", MNEMONIC_PW.as_bytes());

    let mut child = ethernal()
        .args(["account", "recover", "--output-dir"])
        .arg(dir.path())
        .args([
            "--count",
            "1",
            "--passphrase-file",
            ks_path.to_str().unwrap(),
            "--mnemonic-passphrase-file",
            mp_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    {
        let mut stdin = child.stdin.take().expect("stdin");
        writeln!(stdin, "{ABANDON_12}").expect("write mnemonic");
    }

    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "recover failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    for (label, secret) in [
        ("mnemonic", ABANDON_12),
        ("mnemonic passphrase", MNEMONIC_PW),
        ("keystore passphrase", KEYSTORE_PW),
        ("seed hex", TREZOR_SEED_HEX),
        (
            "mnemonic passphrase hex",
            &hex_encode(MNEMONIC_PW.as_bytes()),
        ),
        (
            "keystore passphrase hex",
            &hex_encode(KEYSTORE_PW.as_bytes()),
        ),
    ] {
        assert!(
            !stderr.contains(secret),
            "{label} leaked to stderr: {stderr}"
        );
        assert!(
            !stdout.contains(secret),
            "{label} leaked to stdout: {stdout}"
        );
    }

    // Banner / progress should still be present on stderr (non-secret).
    assert!(
        stderr.contains("ethernal account recover:"),
        "expected banner on stderr: {stderr}"
    );
    assert!(
        stderr.contains("wrote 1 keystore") || stderr.contains("keystore"),
        "expected progress/summary on stderr: {stderr}"
    );
}

/// Invalid-token recover path must not echo the token to any captured channel
/// (H1 / S-2). Report 1-based position only.
#[test]
fn account_recover_unknown_word_token_absent_from_all_channels() {
    let dir = TempDir::new("account-hygiene-unknown");
    let secrets = TempDir::new("account-hygiene-unknown-s");
    // Distinctive non-wordlist token — if it appears in any channel, hygiene fails.
    const BAD_TOKEN: &str = "wroth";
    // Position 7 (1-based): six abandon + wroth + five abandon.
    let mnemonic = format!(
        "abandon abandon abandon abandon abandon abandon {BAD_TOKEN} abandon abandon abandon abandon about"
    );
    let ks_path = secret_file(&secrets, "ks.pw", KEYSTORE_PW.as_bytes());

    let mut child = ethernal()
        .args(["account", "recover", "--output-dir"])
        .arg(dir.path())
        .args([
            "--count",
            "1",
            "--passphrase-file",
            ks_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    {
        let mut stdin = child.stdin.take().expect("stdin");
        writeln!(stdin, "{mnemonic}").expect("write mnemonic");
    }

    let out = child.wait_with_output().expect("wait");
    assert_eq!(
        out.status.code(),
        Some(2),
        "unknown word must exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stderr.contains("unknown word at position 7"),
        "expected position message on stderr: {stderr}"
    );
    assert!(
        !stderr.contains(BAD_TOKEN),
        "token leaked to stderr: {stderr}"
    );
    assert!(
        !stdout.contains(BAD_TOKEN),
        "token leaked to stdout: {stdout}"
    );
    // Byte-level guard: no channel may contain the raw token bytes.
    assert!(
        !out.stderr
            .windows(BAD_TOKEN.len())
            .any(|w| w == BAD_TOKEN.as_bytes()),
        "token bytes in stderr buffer"
    );
    assert!(
        !out.stdout
            .windows(BAD_TOKEN.len())
            .any(|w| w == BAD_TOKEN.as_bytes()),
        "token bytes in stdout buffer"
    );
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------------------
// F7-1 / FR-31 — eight architecture-§9 error paths on `account recover`
// ---------------------------------------------------------------------------

/// Drive `account recover` with a fixed mnemonic and a single
/// `--passphrase-file` path. Captures stdout + stderr (the log stream is stderr).
fn run_account_recover_ks_file(out_label: &str, ks_path: &Path) -> Output {
    let dir = TempDir::new(out_label);
    let mut child = ethernal()
        .args(["account", "recover", "--output-dir"])
        .arg(dir.path())
        .args([
            "--count",
            "1",
            "--passphrase-file",
            ks_path.to_str().expect("utf-8 path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn account recover");

    {
        let mut stdin = child.stdin.take().expect("stdin");
        writeln!(stdin, "{ABANDON_12}").expect("write mnemonic");
    }
    child.wait_with_output().expect("wait account recover")
}

/// Exit 2 and no channel (stdout / stderr / log-on-stderr) may carry the sentinel.
fn assert_exit2_no_sentinel(out: &Output, sentinel: &str, label: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{label}: expected exit 2; stderr={stderr}"
    );
    // Non-empty output: absence-of-sentinel is not vacuously true on empty streams.
    assert!(
        !stdout.is_empty() || !stderr.is_empty(),
        "{label}: expected non-empty diagnostic on stdout or stderr"
    );
    assert!(
        !stdout.contains(sentinel),
        "{label}: sentinel leaked to stdout: {stdout}"
    );
    assert!(
        !stderr.contains(sentinel),
        "{label}: sentinel leaked to stderr/log: {stderr}"
    );
}

/// not found → exit 2, path named; no content (file never opened).
#[test]
fn account_passphrase_file_not_found_exit2_no_leak() {
    let secrets = TempDir::new("f7-1-acc-nf-s");
    const SENTINEL: &str = "F71_ACC_NOTFOUND_SENTINEL_a3c9";
    let missing = secrets.join("missing-F71_ACC_NOTFOUND.pw");
    let path_str = missing.to_str().unwrap().to_owned();

    let out = run_account_recover_ks_file("f7-1-acc-nf", &missing);
    assert_exit2_no_sentinel(&out, SENTINEL, "not found");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&path_str),
        "not found: message must name path {path_str}, got: {stderr}"
    );
    assert!(
        stderr.contains("not found"),
        "not found: message must say not found, got: {stderr}"
    );
}

/// permission denied (mode `0000`) → exit 2; path named, never content.
///
/// Does not hold when the suite runs as **root** — root bypasses discretionary
/// access control, so chmod 0000 still opens. Skip in that case (crate-level
/// secretfile tests use the same guard).
#[cfg(unix)]
#[test]
fn account_passphrase_file_permission_denied_0000_exit2_no_leak() {
    use std::os::unix::fs::PermissionsExt;

    // SAFETY: getuid has no preconditions and is always safe to call.
    if unsafe { libc::getuid() } == 0 {
        return;
    }

    const SENTINEL: &str = "F71_ACC_PERM_DENIED_SENTINEL_b7e1";
    let secrets = TempDir::new("f7-1-acc-perm-s");
    let ks_path = secret_file(&secrets, "locked.pw", SENTINEL.as_bytes());
    std::fs::set_permissions(&ks_path, std::fs::Permissions::from_mode(0o000)).unwrap();

    let out = run_account_recover_ks_file("f7-1-acc-perm", &ks_path);
    let _ = std::fs::set_permissions(&ks_path, std::fs::Permissions::from_mode(0o600));

    assert_exit2_no_sentinel(&out, SENTINEL, "permission denied 0000");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let path_str = ks_path.to_str().unwrap();
    assert!(
        stderr.contains(path_str),
        "permission denied: message must name path {path_str}, got: {stderr}"
    );
}

/// is-a-directory → exit 2 with FR-14's intended message, not the raw OS string.
#[test]
fn account_passphrase_file_is_directory_fr14_not_os_error21() {
    let secrets = TempDir::new("f7-1-acc-dir-s");
    let dir_as_file = secrets.join("is-a-dir");
    std::fs::create_dir_all(&dir_as_file).expect("mkdir passphrase path");
    let path_str = dir_as_file.to_str().unwrap().to_owned();
    const SENTINEL: &str = "F71_ACC_ISDIR_SENTINEL_c4d2";

    let out = run_account_recover_ks_file("f7-1-acc-dir", &dir_as_file);
    assert_exit2_no_sentinel(&out, SENTINEL, "is-a-directory");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("is a directory") || stderr.contains("path is a directory"),
        "is-a-directory: expected FR-14 message text, got: {stderr}"
    );
    assert!(
        stderr.contains(&path_str),
        "is-a-directory: message must name path {path_str}, got: {stderr}"
    );
    assert!(
        !stderr.contains("Is a directory (os error 21)"),
        "is-a-directory: raw OS string must be absent, got: {stderr}"
    );
    assert!(
        !stderr.contains("os error 21"),
        "is-a-directory: os error 21 must be absent, got: {stderr}"
    );
}

/// empty `--passphrase-file` (0 bytes) → exit 2 (FR-18); never content.
#[test]
fn account_passphrase_file_empty_exit2_no_leak() {
    const SENTINEL: &str = "F71_ACC_EMPTY_SENTINEL_d8f0";
    let secrets = TempDir::new("f7-1-acc-empty-s");
    let ks_path = secret_file(&secrets, "empty.pw", b"");
    let path_str = ks_path.to_str().unwrap().to_owned();

    let out = run_account_recover_ks_file("f7-1-acc-empty", &ks_path);
    assert_exit2_no_sentinel(&out, SENTINEL, "empty passphrase-file");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("empty"),
        "empty: message must name empty, got: {stderr}"
    );
    assert!(
        stderr.contains(&path_str),
        "empty: message must name path {path_str}, got: {stderr}"
    );
}

/// multi-line passphrase file → exit 2 with a **line count**, never content.
#[test]
fn account_passphrase_file_multiline_exit2_line_count_no_leak() {
    const SENTINEL: &str = "F71_ACC_MULTI_SENTINEL_e1a7";
    let secrets = TempDir::new("f7-1-acc-multi-s");
    let bytes = format!("{SENTINEL}\nsecond-line-must-not-leak\n");
    let ks_path = secret_file(&secrets, "multi.pw", bytes.as_bytes());
    let path_str = ks_path.to_str().unwrap().to_owned();

    let out = run_account_recover_ks_file("f7-1-acc-multi", &ks_path);
    assert_exit2_no_sentinel(&out, SENTINEL, "multi-line");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("second-line-must-not-leak"),
        "multi-line: second line leaked: {stderr}"
    );
    assert!(
        stderr.contains("lines") || stderr.contains("line"),
        "multi-line: message must carry a line count, got: {stderr}"
    );
    assert!(
        stderr.contains(&path_str),
        "multi-line: message must name path {path_str}, got: {stderr}"
    );
}

/// CR shapes (`pw\r` / `pw\r\n` / `pw\r\r\n`) → exit 2, "carriage return", never content.
#[test]
fn account_passphrase_file_cr_shapes_exit2_no_leak() {
    const SENTINEL: &str = "F71_ACC_CR_SENTINEL_f2b8";
    for (label, bytes) in [
        ("cr", format!("{SENTINEL}\r").into_bytes()),
        ("crlf", format!("{SENTINEL}\r\n").into_bytes()),
        ("crcrlf", format!("{SENTINEL}\r\r\n").into_bytes()),
    ] {
        let secrets = TempDir::new(&format!("f7-1-acc-cr-s-{label}"));
        let ks_path = secret_file(&secrets, "cr.pw", &bytes);
        let path_str = ks_path.to_str().unwrap().to_owned();

        let out = run_account_recover_ks_file(&format!("f7-1-acc-cr-{label}"), &ks_path);
        assert_exit2_no_sentinel(&out, SENTINEL, &format!("CR {label}"));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("carriage return"),
            "CR {label}: message must name shape 'carriage return', got: {stderr}"
        );
        assert!(
            stderr.contains(&path_str),
            "CR {label}: message must name path {path_str}, got: {stderr}"
        );
    }
}

/// over-size: 4097-byte file of repeated sentinel → exit 2, never truncated content.
#[test]
fn account_passphrase_file_oversize_4097_exit2_no_leak() {
    const SENTINEL: &str = "F71_ACC_OVERSIZE_SENTINEL_g3c1";
    let secrets = TempDir::new("f7-1-acc-over-s");
    let mut bytes = Vec::with_capacity(4097);
    while bytes.len() < 4097 {
        bytes.extend_from_slice(SENTINEL.as_bytes());
    }
    bytes.truncate(4097);
    assert_eq!(bytes.len(), 4097);
    let ks_path = secret_file(&secrets, "over.pw", &bytes);
    let path_str = ks_path.to_str().unwrap().to_owned();

    let out = run_account_recover_ks_file("f7-1-acc-over", &ks_path);
    assert_exit2_no_sentinel(&out, SENTINEL, "over-size 4097");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&path_str),
        "over-size: message must name path {path_str}, got: {stderr}"
    );
}

/// `--passphrase-file /dev/zero` hits the read cap → exit 2 (unix only).
#[cfg(unix)]
#[test]
fn account_passphrase_file_dev_zero_exit2() {
    let out = run_account_recover_ks_file("f7-1-acc-zero", Path::new("/dev/zero"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "/dev/zero: expected exit 2; stderr={stderr}"
    );
    assert!(
        !stdout.is_empty() || !stderr.is_empty(),
        "/dev/zero: expected non-empty diagnostic"
    );
    assert!(
        stderr.len() < 4096,
        "/dev/zero: error message looks truncated-content-sized: len={}",
        stderr.len()
    );
}

/// non-UTF-8 passphrase file → exit 2; never content.
#[test]
fn account_passphrase_file_non_utf8_exit2_no_leak() {
    const SENTINEL: &str = "F71_ACC_NUTF8_SENTINEL_h4d9";
    let secrets = TempDir::new("f7-1-acc-utf8-s");
    let mut bytes = SENTINEL.as_bytes().to_vec();
    bytes.push(0xff);
    bytes.extend_from_slice(b"payload");
    let ks_path = secret_file(&secrets, "bad.pw", &bytes);
    let path_str = ks_path.to_str().unwrap().to_owned();

    let out = run_account_recover_ks_file("f7-1-acc-utf8", &ks_path);
    assert_exit2_no_sentinel(&out, SENTINEL, "non-UTF-8");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&path_str),
        "non-UTF-8: message must name path {path_str}, got: {stderr}"
    );
    assert!(
        stderr.contains("UTF-8") || stderr.contains("utf-8") || stderr.contains("utf8"),
        "non-UTF-8: message should mention UTF-8, got: {stderr}"
    );
}
