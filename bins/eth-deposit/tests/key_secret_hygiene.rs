//! Secret-hygiene integration check for `key recover` (K3-4 / S-2 / G5).
//!
//! Binary-level companion to the `KeyDeps` unit tests in `key_cmd.rs`: pipe a
//! fixed mnemonic, encrypt with `--passphrase-env`, and assert the mnemonic,
//! seed hex, and both passphrases never appear on stderr (where progress,
//! banner, and fatal logs go). Full injectible-logger coverage lives in the
//! unit seam; this guards the production log path end-to-end.

mod common;

use common::eth_deposit;
use std::io::Write;
use std::process::Stdio;

const ABANDON_12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// BIP-39 TREZOR seed for ABANDON_12.
const TREZOR_SEED_HEX: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
const KEYSTORE_PW: &str = "password1";
const MNEMONIC_PW: &str = "TREZOR";

#[test]
fn key_recover_secrets_absent_from_stderr() {
    let dir = common::TempDir::new("key-hygiene");
    let ks_var = format!("ETH_DEPOSIT_HYGIENE_KS_{}", std::process::id());
    let mp_var = format!("ETH_DEPOSIT_HYGIENE_MP_{}", std::process::id());

    let mut child = eth_deposit()
        .args(["key", "recover", "--output-dir"])
        .arg(dir.path())
        .args([
            "--count",
            "1",
            "--passphrase-env",
            &ks_var,
            "--mnemonic-passphrase-env",
            &mp_var,
        ])
        .env(&ks_var, KEYSTORE_PW)
        .env(&mp_var, MNEMONIC_PW)
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
        stderr.contains("eth-deposit key recover:"),
        "expected banner on stderr: {stderr}"
    );
    assert!(
        stderr.contains("wrote 1 keystore") || stderr.contains("keystore"),
        "expected progress/summary on stderr: {stderr}"
    );
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
