//! Binary-driven port of `cmd/ethernal/usage_error_test.go`. Every subcommand
//! must map a usage error (a missing required flag, or a bad flag value) to exit
//! code 2 rather than the exit-1 fallback. In Rust, clap's parse errors call
//! `e.exit()`, which exits with status 2 for usage errors.

mod common;

use common::ethernal;

fn assert_exit2(args: &[&str], name: &str) {
    let out = ethernal().args(args).output().expect("run");
    assert_eq!(
        out.status.code(),
        Some(2),
        "{name}: expected exit 2, got {:?}; stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestUsageError_ExitsTwo (table).
#[test]
fn build_missing_input_file() {
    assert_exit2(
        &["deposit", "build", "--network", "holesky"],
        "build missing --input-file",
    );
}

#[test]
fn gen_missing_required_flags() {
    assert_exit2(&["deposit", "gen"], "gen missing required flags");
}

#[test]
fn sign_missing_signer() {
    assert_exit2(&["tx", "sign"], "sign missing --signer");
}

#[test]
fn run_missing_input_file() {
    assert_exit2(&["tx", "run"], "run missing --input-file");
}

#[test]
fn build_bad_index_value() {
    assert_exit2(
        &[
            "deposit",
            "build",
            "--network",
            "holesky",
            "--input-file",
            "x",
            "--index",
            "abc",
        ],
        "build bad --index value",
    );
}

#[test]
fn validator_missing_subcommand() {
    assert_exit2(&["validator"], "validator missing subcommand");
}

#[test]
fn deposit_missing_subcommand() {
    // arg_required_else_help prints help and exits 2 (clap usage) for bare group.
    assert_exit2(&["deposit"], "deposit missing subcommand");
}

#[test]
fn tx_missing_subcommand() {
    assert_exit2(&["tx"], "tx missing subcommand");
}

#[test]
fn deposit_unknown_leaf() {
    assert_exit2(&["deposit", "nope"], "deposit unknown leaf");
}

#[test]
fn tx_unknown_leaf() {
    assert_exit2(&["tx", "nope"], "tx unknown leaf");
}

#[test]
fn validator_new_missing_output_dir() {
    assert_exit2(&["validator", "new"], "validator new missing --output-dir");
}

#[test]
fn validator_recover_missing_output_dir() {
    assert_exit2(
        &["validator", "recover"],
        "validator recover missing --output-dir",
    );
}

#[test]
fn account_missing_subcommand() {
    assert_exit2(&["account"], "account missing subcommand");
}

#[test]
fn account_new_missing_output_dir() {
    assert_exit2(&["account", "new"], "account new missing --output-dir");
}

#[test]
fn account_recover_missing_output_dir() {
    assert_exit2(
        &["account", "recover"],
        "account recover missing --output-dir",
    );
}

/// F-5: `validator new` must exit 2 before generating when stdin/stdout are not TTYs.
/// Integration tests drive the binary with piped stdio, so isatty fails.
#[test]
fn validator_new_non_tty_exits_two() {
    let dir = common::TempDir::new("validator-new-nontty");
    let out = ethernal()
        .args(["validator", "new", "--output-dir"])
        .arg(dir.path())
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(2),
        "validator new non-TTY: expected exit 2, got {:?}; stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("interactive terminal") || stderr.contains("TTY") || stderr.contains("tty"),
        "expected TTY guard message, got: {stderr}"
    );
    // No keystore or other output files written.
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read out dir")
        .collect();
    assert!(
        entries.is_empty(),
        "non-TTY validator new must write nothing; found {entries:?}"
    );
}

#[test]
fn validator_new_bad_count_exits_two() {
    // Bad --count is validated after the TTY guard; on non-TTY the guard wins
    // first (still exit 2). Exercise clap-level rejection of a non-u32 count.
    assert_exit2(
        &["validator", "new", "--output-dir", "/tmp", "--count", "abc"],
        "validator new bad --count value",
    );
}

/// F-5: `account new` must exit 2 before generating when stdin/stdout are not TTYs.
/// Integration tests drive the binary with piped stdio, so isatty fails.
#[test]
fn account_new_non_tty_exits_two() {
    let dir = common::TempDir::new("account-new-nontty");
    let out = ethernal()
        .args(["account", "new", "--output-dir"])
        .arg(dir.path())
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(2),
        "account new non-TTY: expected exit 2, got {:?}; stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("interactive terminal") || stderr.contains("TTY") || stderr.contains("tty"),
        "expected TTY guard message, got: {stderr}"
    );
    // No keystore or other output files written.
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read out dir")
        .collect();
    assert!(
        entries.is_empty(),
        "non-TTY account new must write nothing; found {entries:?}"
    );
}

#[test]
fn account_new_bad_count_exits_two() {
    // Bad --count is validated after the TTY guard; on non-TTY the guard wins
    // first (still exit 2). Exercise clap-level rejection of a non-u32 count.
    assert_exit2(
        &["account", "new", "--output-dir", "/tmp", "--count", "abc"],
        "account new bad --count value",
    );
}

#[test]
fn account_recover_nonexistent_output_dir_exits_two() {
    let dir = common::TempDir::new("account-recover-missing-out");
    let missing = dir.path().join("does-not-exist");
    let out = ethernal()
        .args(["account", "recover", "--output-dir"])
        .arg(&missing)
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(2),
        "account recover bad output-dir: expected exit 2, got {:?}; stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn validator_recover_nonexistent_output_dir_exits_two() {
    let dir = common::TempDir::new("validator-recover-missing-out");
    let missing = dir.path().join("does-not-exist");
    let out = ethernal()
        .args(["validator", "recover", "--output-dir"])
        .arg(&missing)
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(2),
        "validator recover bad output-dir: expected exit 2, got {:?}; stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// H4 / K3-L2: overflowing `--start-index + --count` is rejected in load_config
/// (exit 2) before any keystore write — output dir stays empty.
#[test]
fn validator_recover_index_overflow_exits_two_no_writes() {
    use std::io::Write;
    use std::process::Stdio;

    let dir = common::TempDir::new("validator-recover-overflow");
    let secrets = common::TempDir::new("validator-recover-overflow-s");
    let ks_path = common::secret_file(&secrets, "ks.pw", b"password1");
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n";
    let mut child = ethernal()
        .args(["validator", "recover", "--output-dir"])
        .arg(dir.path())
        .args([
            "--count",
            "2",
            "--start-index",
            "4294967295",
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
        stdin
            .write_all(mnemonic.as_bytes())
            .expect("write mnemonic");
    }
    let out = child.wait_with_output().expect("wait");
    assert_eq!(
        out.status.code(),
        Some(2),
        "overflow: expected exit 2, got {:?}; stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("overflows u32") || stderr.contains("overflow"),
        "expected overflow message, got: {stderr}"
    );
    // Config error must not leave any files on disk.
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read out dir")
        .collect();
    assert!(
        entries.is_empty(),
        "overflow must write nothing; found {entries:?}"
    );
}

/// `validator recover` is exempt from the TTY guard: piped mnemonic on non-TTY stdin
/// is accepted (F-10). Uses --passphrase-file so no interactive keystore prompt.
#[test]
fn validator_recover_validates_without_tty() {
    use std::io::Write;
    use std::process::Stdio;

    let dir = common::TempDir::new("validator-recover-ok");
    let secrets = common::TempDir::new("validator-recover-ok-s");
    let ks_path = common::secret_file(&secrets, "ks.pw", b"password1");
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n";
    let mut child = ethernal()
        .args(["validator", "recover", "--output-dir"])
        .arg(dir.path())
        .args([
            "--count",
            "1",
            "--start-index",
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
        stdin
            .write_all(mnemonic.as_bytes())
            .expect("write mnemonic");
    }
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "validator recover should accept piped mnemonic on non-TTY; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ethernal validator recover:"),
        "banner missing: {stderr}"
    );
    assert!(stderr.contains("start_index=1"), "banner: {stderr}");
    assert!(stderr.contains("count=1"), "banner: {stderr}");
    // One keystore at index 1.
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read out")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("keystore-m_12381_3600_1_")
        })
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "expected one keystore at index 1: {entries:?}"
    );
}
