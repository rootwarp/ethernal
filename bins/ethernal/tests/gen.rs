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
use std::path::{Path, PathBuf};
use std::process::Command;

use ethernal_core::bls::{self, Signer};
use ethernal_keystore::encrypt::{encrypt, EncryptInput, ScryptParams};

use common::{
    ethernal, ethernal_no_tty, hoodi_expected_deposit_data, hoodi_keystores, hoodi_passphrase,
    hoodi_pubkey, mainnet_expected_deposit_data, mainnet_keystores, mainnet_passphrase,
    mainnet_pubkey, secret_file, TempDir,
};

/// Known EIP-55 checksummed address (signer local test key).
const WITHDRAWAL_ADDR: &str = "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1";
/// Expected hex (no 0x) of 0x01 ‖ 11 zero ‖ addr20 for [`WITHDRAWAL_ADDR`].
const WITHDRAWAL_CREDS_HEX: &str =
    "0100000000000000000000001a642f0e3c3af545e7acbd38b07251b3990914f1";

/// Writes the hoodi fixture passphrase to a mode-0600 secret file and returns
/// `(dir_keep_alive, path)`.
fn hoodi_passphrase_file() -> (TempDir, PathBuf) {
    let dir = TempDir::new("gen-pw");
    let path = secret_file(&dir, "passphrase.txt", hoodi_passphrase().as_bytes());
    (dir, path)
}

/// Writes the mainnet fixture passphrase to a mode-0600 secret file and returns
/// `(dir_keep_alive, path)`.
fn mainnet_passphrase_file() -> (TempDir, PathBuf) {
    let dir = TempDir::new("gen-pw-mainnet");
    let path = secret_file(&dir, "passphrase.txt", mainnet_passphrase().as_bytes());
    (dir, path)
}

// Go: TestGenDryRun_NoOutputDir_RealPipelineEmitsJSON — the real pipeline over
// the committed hoodi fixtures emits the deposit JSON to stdout in dry-run mode.
#[test]
fn gen_dry_run_real_pipeline_emits_json() {
    let (_pw_dir, pw) = hoodi_passphrase_file();
    let out = ethernal()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--dry-run",
            "--passphrase-file",
        ])
        .arg(&pw)
        .args(["--withdrawal-address", WITHDRAWAL_ADDR])
        .output()
        .expect("run gen");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // T-7: full golden equality (subsumes prior field-level pubkey/creds asserts).
    let want = std::fs::read(hoodi_expected_deposit_data()).expect("read hoodi golden");
    assert_eq!(
        out.stdout,
        want,
        "gen dry-run stdout must be byte-identical to testdata/hoodi/deposit_data-expected.json\n\
         got: {}\nwant: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&want)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ethernal gen:"), "banner missing: {stderr}");
    assert!(
        stderr.contains("wrote <stdout>"),
        "dry-run summary must use <stdout>: {stderr}"
    );
}

// T-19 / E5-3: gen --parallel must produce the same deposit JSON as the serial path
// (byte-identical to the T-7 hoodi golden). Guards ordering/nondeterminism in the
// concurrent keystore-decryption path.
#[test]
fn gen_parallel_matches_hoodi_golden() {
    let (_pw_dir, pw) = hoodi_passphrase_file();
    let out = ethernal()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--dry-run",
            "--parallel",
            "2",
            "--passphrase-file",
        ])
        .arg(&pw)
        .args(["--withdrawal-address", WITHDRAWAL_ADDR])
        .output()
        .expect("run gen --parallel");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let want = std::fs::read(hoodi_expected_deposit_data()).expect("read hoodi golden");
    assert_eq!(
        out.stdout,
        want,
        "gen --parallel dry-run stdout must be byte-identical to testdata/hoodi/deposit_data-expected.json\n\
         got: {}\nwant: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&want)
    );
}

// The non-dry-run pipeline writes deposit_data-<ts>.json into --output-dir.
#[test]
fn gen_writes_output_file() {
    let out_dir = TempDir::new("gen-out");
    let (_pw_dir, pw) = hoodi_passphrase_file();
    let out = ethernal()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--output-dir",
        ])
        .arg(out_dir.path())
        .args(["--passphrase-file"])
        .arg(&pw)
        .args(["--withdrawal-address", WITHDRAWAL_ADDR])
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
    let want = std::fs::read(hoodi_expected_deposit_data()).expect("read hoodi golden");
    assert_eq!(
        data,
        want,
        "deposit_data file must be byte-identical to testdata/hoodi/deposit_data-expected.json\n\
         got: {}\nwant: {}",
        String::from_utf8_lossy(&data),
        String::from_utf8_lossy(&want)
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
    let (_pw_dir, pw) = hoodi_passphrase_file();

    let out = ethernal()
        .env("PATH", path_with(cli_dir.path()))
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--output-dir",
        ])
        .arg(out_dir.path())
        .args(["--passphrase-file"])
        .arg(&pw)
        .args([
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
    let (_pw_dir, pw) = hoodi_passphrase_file();

    let out = ethernal()
        .env("PATH", path_with(cli_dir.path()))
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--output-dir",
        ])
        .arg(out_dir.path())
        .args(["--passphrase-file"])
        .arg(&pw)
        .args([
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
    let (_pw_dir, pw) = hoodi_passphrase_file();
    // Point --deposit-cli-path at a path that does not exist.
    let missing = out_dir.join("no-such-deposit-binary");

    let out = ethernal()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--output-dir",
        ])
        .arg(out_dir.path())
        .args(["--passphrase-file"])
        .arg(&pw)
        .args(["--verify-with-deposit-cli", "--deposit-cli-path"])
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
    let (_pw_dir, pw) = hoodi_passphrase_file();

    let out = ethernal()
        .env("PATH", path_with(cli_dir.path()))
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--dry-run",
            "--passphrase-file",
        ])
        .arg(&pw)
        .args([
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
    let (_pw_dir, pw) = hoodi_passphrase_file();
    let out = ethernal()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--dry-run",
            "--passphrase-file",
        ])
        .arg(&pw)
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
    let (_pw_dir, pw) = hoodi_passphrase_file();
    let out = ethernal()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--dry-run",
            "--passphrase-file",
        ])
        .arg(&pw)
        .args(["--withdrawal-address", &lower])
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

    let (_pw_dir, pw) = hoodi_passphrase_file();
    let out = ethernal()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--dry-run",
            "--passphrase-file",
        ])
        .arg(&pw)
        .args(["--withdrawal-address", &flipped])
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
    let (_pw_dir, pw) = hoodi_passphrase_file();
    let out = ethernal()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--dry-run",
            "--passphrase-file",
        ])
        .arg(&pw)
        .args([
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
    let (_pw_dir, pw) = hoodi_passphrase_file();
    let out = ethernal()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--dry-run",
            "--passphrase-file",
        ])
        .arg(&pw)
        .args(["--withdrawal-address", WITHDRAWAL_ADDR])
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

// T-8 / E5-2: gen --network mainnet without --i-understand-this-is-mainnet → exit 2.
#[test]
fn gen_mainnet_without_ack_exit2() {
    let (_pw_dir, pw) = mainnet_passphrase_file();
    let out = ethernal()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(mainnet_keystores())
        .args([
            "--pubkeys",
            &mainnet_pubkey(),
            "--network",
            "mainnet",
            "--dry-run",
            "--passphrase-file",
        ])
        .arg(&pw)
        .args(["--withdrawal-address", WITHDRAWAL_ADDR])
        .output()
        .expect("run gen");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--i-understand-this-is-mainnet"),
        "stderr must name the mainnet ack flag: {stderr}"
    );
}

// T-8 / E5-2: with the flag, mainnet gen proceeds and byte-matches the golden.
#[test]
fn gen_mainnet_with_ack_matches_golden() {
    let (_pw_dir, pw) = mainnet_passphrase_file();
    let out = ethernal()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(mainnet_keystores())
        .args([
            "--pubkeys",
            &mainnet_pubkey(),
            "--network",
            "mainnet",
            "--i-understand-this-is-mainnet",
            "--dry-run",
            "--passphrase-file",
        ])
        .arg(&pw)
        .args(["--withdrawal-address", WITHDRAWAL_ADDR])
        .output()
        .expect("run gen");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let want = std::fs::read(mainnet_expected_deposit_data()).expect("read mainnet golden");
    assert_eq!(
        out.stdout,
        want,
        "gen mainnet dry-run stdout must be byte-identical to testdata/mainnet/deposit_data-expected.json\n\
         got: {}\nwant: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&want)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("MAINNET"),
        "mainnet banner must be uppercase: {stderr}"
    );
}

// T-8 / E5-2: gen without --passphrase-file when there is no controlling TTY →
// exit 2 naming --passphrase-file.
//
// Must use `ethernal_no_tty` (setsid): plain `.output()` still inherits the
// runner's controlling terminal, so under interactive `make test` the child
// would open /dev/tty and block forever on the passphrase prompt.
#[test]
fn gen_pipe_without_passphrase_file_exit2() {
    let out = ethernal_no_tty()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--dry-run",
            "--withdrawal-address",
            WITHDRAWAL_ADDR,
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
    assert!(
        stderr.contains("--passphrase-file"),
        "stderr must name --passphrase-file: {stderr}"
    );
}

// FR-6: --passphrase-file - is rejected at config load (secret_file_arg).
#[test]
fn gen_passphrase_file_dash_exit2() {
    let out = ethernal()
        .args(["deposit", "gen", "--keystore-dir"])
        .arg(hoodi_keystores())
        .args([
            "--pubkeys",
            &hoodi_pubkey(),
            "--network",
            "hoodi",
            "--dry-run",
            "--passphrase-file",
            "-",
            "--withdrawal-address",
            WITHDRAWAL_ADDR,
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
    assert!(
        stderr.contains("--passphrase-file"),
        "stderr must name the flag: {stderr}"
    );
}

/// Builds `n` FAST-scrypt EIP-2335 keystores under `dir` with a shared passphrase
/// and returns the comma-joined 0x-prefixed pubkeys. FAST scrypt keeps the suite
/// snappy; gen decrypts whatever `n` is in the keystore JSON.
fn write_fast_keystores(dir: &Path, n: usize, passphrase: &[u8]) -> String {
    let mut pks = Vec::with_capacity(n);
    for i in 0..n {
        let mut secret = [0u8; 32];
        secret[0] = (i + 1) as u8;
        secret[31] = 0x42; // ensure non-zero scalar material for blst
        let signer = bls::new_signer(&secret).expect("new_signer");
        let pk = signer.public_key().expect("public_key");
        let mut salt = [0u8; 32];
        salt[0] = (i + 1) as u8;
        let mut iv = [0u8; 16];
        iv[0] = (i + 1) as u8;
        let mut uuid = [0u8; 16];
        uuid[0] = (i + 1) as u8;
        let json = encrypt(&EncryptInput {
            secret: &secret,
            password: passphrase,
            path: "m/12381/3600/0/0/0",
            pubkey: &pk,
            salt,
            iv,
            uuid_bytes: uuid,
            scrypt: ScryptParams::FAST,
        })
        .expect("encrypt keystore");
        std::fs::write(dir.join(format!("keystore-{i}.json")), json).expect("write keystore");
        pks.push(format!("0x{}", hex::encode(pk)));
    }
    pks.join(",")
}

// F5-1 / D-5 / FR-22: --parallel 4 over ≥4 pubkeys with a process-substitution
// passphrase source must succeed.
//
// Reverting the read-once hoist (putting FileSource::new / .read() inside the
// worker or letting each worker open the path) makes this fail: process-sub
// paths under /dev/fd/N are single-shot — the second concurrent open returns
// zero bytes and surfaces as a wrong-passphrase error on an arbitrary pubkey.
#[test]
fn gen_parallel4_process_sub_passphrase_succeeds() {
    let ks_dir = TempDir::new("gen-parallel4-ks");
    // Alphanumeric only so it is safe unquoted inside the bash -c script.
    let passphrase = b"testpassphraseok";
    let pubkeys = write_fast_keystores(ks_dir.path(), 4, passphrase);

    let bin = env!("CARGO_BIN_EXE_ethernal");
    let ks = ks_dir.path().display().to_string();
    let pw = std::str::from_utf8(passphrase).unwrap();
    // Process substitution requires a shell. Paths have no spaces (TempDir).
    let script = format!(
        "{bin} deposit gen \
            --keystore-dir {ks} \
            --pubkeys {pubkeys} \
            --network hoodi \
            --dry-run \
            --parallel 4 \
            --passphrase-file <(printf '%s' {pw}) \
            --withdrawal-address {WITHDRAWAL_ADDR}"
    );

    let out = Command::new("bash")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("run gen --parallel 4 with process-sub");
    assert!(
        out.status.success(),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    // Four deposit entries in the Launchpad JSON array.
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("deposit JSON on stdout");
    let arr = v.as_array().expect("top-level array");
    assert_eq!(
        arr.len(),
        4,
        "expected 4 deposit entries, got {}",
        arr.len()
    );
}
