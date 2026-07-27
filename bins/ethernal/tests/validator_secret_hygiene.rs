//! Secret-hygiene integration check for `validator recover` (K3-4 / S-2 / G5).
//!
//! Binary-level companion to the `ValidatorDeps` unit tests in `validator_cmd.rs`: pipe a
//! fixed mnemonic, encrypt with `--passphrase-file`, and assert the mnemonic,
//! seed hex, and both passphrases never appear on stderr (where progress,
//! banner, and fatal logs go). Full injectible-logger coverage lives in the
//! unit seam; this guards the production log path end-to-end.

mod common;

use common::{ethernal, secret_file, TempDir};
use std::io::Write;
use std::process::Stdio;

const ABANDON_12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// BIP-39 TREZOR seed for ABANDON_12.
const TREZOR_SEED_HEX: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
const KEYSTORE_PW: &str = "password1";
const MNEMONIC_PW: &str = "TREZOR";

#[test]
fn validator_recover_secrets_absent_from_stderr() {
    let dir = TempDir::new("key-hygiene");
    let secrets = TempDir::new("key-hygiene-secrets");
    let ks_path = secret_file(&secrets, "ks.pw", KEYSTORE_PW.as_bytes());
    let mp_path = secret_file(&secrets, "mp.pw", MNEMONIC_PW.as_bytes());

    let mut child = ethernal()
        .args(["validator", "recover", "--output-dir"])
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
        stderr.contains("ethernal validator recover:"),
        "expected banner on stderr: {stderr}"
    );
    assert!(
        stderr.contains("wrote 1 keystore") || stderr.contains("keystore"),
        "expected progress/summary on stderr: {stderr}"
    );
}

/// Invalid-token recover path must not echo the token to any captured channel
/// (H1 / M1 / S-2). Report 1-based position only.
#[test]
fn validator_recover_unknown_word_token_absent_from_all_channels() {
    let dir = TempDir::new("key-hygiene-unknown");
    let secrets = TempDir::new("key-hygiene-unknown-s");
    // Distinctive non-wordlist token — if it appears in any channel, hygiene fails.
    const BAD_TOKEN: &str = "wroth";
    // Position 7 (1-based): six abandon + wroth + five abandon.
    let mnemonic = format!(
        "abandon abandon abandon abandon abandon abandon {BAD_TOKEN} abandon abandon abandon abandon about"
    );
    let ks_path = secret_file(&secrets, "ks.pw", KEYSTORE_PW.as_bytes());

    let mut child = ethernal()
        .args(["validator", "recover", "--output-dir"])
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
