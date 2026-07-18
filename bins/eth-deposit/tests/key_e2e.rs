//! K4-1 — in-binary E2E: fixed mnemonic → `key recover` → keystores →
//! `gen --withdrawal-address` (BLS self-verify on) → byte-stable deposit data.
//!
//! Determinism is via the fixed BIP-39 mnemonic + TREZOR passphrase through
//! `key recover` — **no** hidden `--entropy-*` flag (S-4 / PRD Q4).
//!
//! Fixtures (frozen once post-K5, real 0x01 creds):
//!   tests/testdata/keygen/pubkeys.json
//!   tests/testdata/keygen/deposit_data-golden.json

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use ethernal_core::bip39;
use ethernal_core::hd::{self, KeyPath};
use ethernal_keystore::{KeyLoader, Loader, PassphraseSource};

use common::{crate_testdata, eth_deposit, TempDir};

// --- chain anchor: BIP-39 abandon×11 about + "TREZOR" = EIP-2333 case-0 seed ---

const ABANDON_12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEMONIC_PASS: &str = "TREZOR";
const TREZOR_SEED_HEX: &str =
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
const KEYSTORE_PW: &str = "password1";
/// Known EIP-55 checksummed address (same as gen.rs / signer local test key).
const WITHDRAWAL_ADDR: &str = "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1";
const WITHDRAWAL_CREDS_HEX: &str =
    "0100000000000000000000001a642f0e3c3af545e7acbd38b07251b3990914f1";
/// Two indices so multi-key ordering is frozen in the golden.
const COUNT: u32 = 2;

fn keygen_testdata() -> PathBuf {
    crate_testdata().join("keygen")
}

fn pubkeys_fixture() -> PathBuf {
    keygen_testdata().join("pubkeys.json")
}

fn deposit_data_golden() -> PathBuf {
    keygen_testdata().join("deposit_data-golden.json")
}

#[derive(Debug, serde::Deserialize)]
struct PubkeysFixture {
    seed_hex: String,
    withdrawal_address: String,
    indices: Vec<IndexFixture>,
}

#[derive(Debug, serde::Deserialize)]
struct IndexFixture {
    index: u32,
    signing_path: String,
    withdrawal_path: String,
    signing_pubkey: String,
    withdrawal_pubkey: String,
}

struct FixedPw(Vec<u8>);
impl PassphraseSource for FixedPw {
    fn read(&self) -> Result<Vec<u8>, ethernal_keystore::KeystoreError> {
        Ok(self.0.clone())
    }
}

fn load_pubkeys_fixture() -> PubkeysFixture {
    let raw = std::fs::read_to_string(pubkeys_fixture()).expect("read pubkeys.json");
    serde_json::from_str(&raw).expect("parse pubkeys.json")
}

/// Run `key recover` with the fixed mnemonic over stdin; return the output dir.
fn run_key_recover(out_dir: &Path, count: u32) {
    let ks_var = format!("ETH_DEPOSIT_K4_KS_{}", std::process::id());
    let mp_var = format!("ETH_DEPOSIT_K4_MP_{}", std::process::id());

    let mut child = eth_deposit()
        .args(["key", "recover", "--output-dir"])
        .arg(out_dir)
        .args([
            "--count",
            &count.to_string(),
            "--start-index",
            "0",
            "--passphrase-env",
            &ks_var,
            "--mnemonic-passphrase-env",
            &mp_var,
        ])
        .env(&ks_var, KEYSTORE_PW)
        .env(&mp_var, MNEMONIC_PASS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn key recover");

    {
        let mut stdin = child.stdin.take().expect("stdin");
        writeln!(stdin, "{ABANDON_12}").expect("write mnemonic");
    }

    let out = child.wait_with_output().expect("wait key recover");
    assert!(
        out.status.success(),
        "key recover failed (exit {:?}): stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("eth-deposit key recover:"),
        "banner missing: {stderr}"
    );
    // S-4: no entropy-injection flag on the recover surface.
    assert!(
        !stderr.to_lowercase().contains("entropy"),
        "unexpected entropy mention (determinism must be mnemonic-only): {stderr}"
    );
}

fn keystore_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("read keystore dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("keystore-") && n.ends_with(".json"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    files
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Seed from the fixed mnemonic + TREZOR matches the EIP-2333 case-0 anchor
/// and the committed fixture; HD-derived signing + withdrawal pubkeys match
/// the fixture index-for-index.
#[test]
fn recover_seed_and_pubkeys_match_fixture() {
    let fx = load_pubkeys_fixture();
    assert_eq!(fx.seed_hex, TREZOR_SEED_HEX);
    assert_eq!(fx.withdrawal_address, WITHDRAWAL_ADDR);

    let seed = bip39::to_seed(ABANDON_12, MNEMONIC_PASS.as_bytes()).unwrap();
    assert_eq!(
        hex::encode(seed.as_slice()),
        TREZOR_SEED_HEX,
        "BIP-39 seed must be EIP-2333 case-0 / Trezor vector"
    );
    assert_eq!(hex::encode(seed.as_slice()), fx.seed_hex);

    assert_eq!(fx.indices.len(), COUNT as usize);
    for entry in &fx.indices {
        let signing = hd::derive_path(seed.as_slice(), &KeyPath::signing(entry.index))
            .expect("derive signing");
        let withdrawal = hd::derive_path(seed.as_slice(), &KeyPath::withdrawal(entry.index))
            .expect("derive withdrawal");
        assert_eq!(
            hex::encode(signing.public_key()),
            entry.signing_pubkey,
            "signing pubkey index {}",
            entry.index
        );
        assert_eq!(
            hex::encode(withdrawal.public_key()),
            entry.withdrawal_pubkey,
            "withdrawal pubkey index {}",
            entry.index
        );
        assert_eq!(
            KeyPath::signing(entry.index).to_string(),
            entry.signing_path
        );
        assert_eq!(
            KeyPath::withdrawal(entry.index).to_string(),
            entry.withdrawal_path
        );
    }
}

/// Binary `key recover` writes keystores whose signing pubkeys match the
/// fixture; Loader round-trip recovers the HD-derived secret.
#[test]
fn key_recover_keystores_match_fixture_and_loader_round_trip() {
    let fx = load_pubkeys_fixture();
    let dir = TempDir::new("k4-recover");
    run_key_recover(dir.path(), COUNT);

    let files = keystore_files(dir.path());
    assert_eq!(
        files.len(),
        COUNT as usize,
        "expected {COUNT} keystores, got {files:?}"
    );

    let seed = bip39::to_seed(ABANDON_12, MNEMONIC_PASS.as_bytes()).unwrap();
    let loader = Loader::new();
    let pw = FixedPw(KEYSTORE_PW.as_bytes().to_vec());

    for f in &files {
        let raw = std::fs::read(f).expect("read keystore");
        let v: serde_json::Value = serde_json::from_slice(&raw).expect("keystore JSON");
        assert_eq!(v["version"], 4);
        assert_eq!(v["crypto"]["kdf"]["function"], "scrypt");

        let name = f.file_name().unwrap().to_string_lossy();
        // keystore-m_12381_3600_<i>_0_0-<ts>.json
        let idx: u32 = name
            .split('_')
            .nth(3)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("index in filename: {name}"));
        let want = fx
            .indices
            .iter()
            .find(|e| e.index == idx)
            .unwrap_or_else(|| panic!("fixture missing index {idx}"));

        let pubkey_field = v["pubkey"].as_str().expect("pubkey field");
        assert_eq!(
            pubkey_field, want.signing_pubkey,
            "keystore JSON pubkey index {idx}"
        );
        assert_eq!(v["path"].as_str().unwrap(), want.signing_path);

        let key = loader.load(f, &pw).expect("Loader::load");
        assert_eq!(key.pubkey_hex, want.signing_pubkey);

        let derived = hd::derive_path(seed.as_slice(), &KeyPath::signing(idx)).unwrap();
        assert_eq!(
            key.secret.as_slice(),
            derived.to_bytes().as_slice(),
            "Loader secret must match HD signing key index {idx}"
        );
        assert_eq!(key.pubkey_hex, hex::encode(derived.public_key()));
    }
}

/// Full front-of-pipeline: `key recover` → `gen --withdrawal-address` (BLS
/// self-verify on by default) → deposit data with real 0x01 creds, byte-stable
/// against the committed golden.
#[test]
fn key_recover_then_gen_deposit_data_byte_stable() {
    let fx = load_pubkeys_fixture();
    let dir = TempDir::new("k4-e2e");
    run_key_recover(dir.path(), COUNT);

    let pubkeys_csv: String = fx
        .indices
        .iter()
        .map(|e| e.signing_pubkey.as_str())
        .collect::<Vec<_>>()
        .join(",");

    let ks_var = format!("ETH_DEPOSIT_K4_GEN_KS_{}", std::process::id());
    let out = eth_deposit()
        .env(&ks_var, KEYSTORE_PW)
        .args(["gen", "--keystore-dir"])
        .arg(dir.path())
        .args([
            "--pubkeys",
            &pubkeys_csv,
            "--network",
            "hoodi",
            "--dry-run",
            "--passphrase-env",
            &ks_var,
            "--withdrawal-address",
            WITHDRAWAL_ADDR,
        ])
        .output()
        .expect("run gen");
    assert!(
        out.status.success(),
        "gen failed (exit {:?}): stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("eth-deposit gen:"),
        "gen banner missing: {stderr}"
    );
    assert!(
        stderr.contains("wrote <stdout>"),
        "dry-run summary: {stderr}"
    );

    // Real 0x01 credentials in every entry.
    let entries: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is deposit JSON");
    let arr = entries.as_array().expect("array");
    assert_eq!(arr.len(), COUNT as usize);
    for (i, entry) in arr.iter().enumerate() {
        assert_eq!(
            entry["withdrawal_credentials"].as_str().unwrap(),
            WITHDRAWAL_CREDS_HEX,
            "entry[{i}] must carry 0x01 execution-address credentials"
        );
        assert_eq!(
            entry["pubkey"].as_str().unwrap(),
            fx.indices[i].signing_pubkey,
            "entry[{i}] pubkey order"
        );
        assert_eq!(entry["network_name"], "hoodi");
        assert_eq!(entry["amount"], 32_000_000_000u64);
    }

    // Byte-stable against the committed golden (compact JSON, no pretty-print).
    let golden = std::fs::read(deposit_data_golden()).expect("read deposit_data-golden.json");
    assert_eq!(
        out.stdout,
        golden,
        "deposit data must be byte-identical to tests/testdata/keygen/deposit_data-golden.json\n\
         got: {}\nwant: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&golden)
    );
}

/// CLI surface has no hidden entropy-injection flag: determinism is the fixed
/// mnemonic through recover (S-4).
#[test]
fn key_recover_help_has_no_entropy_flag() {
    let out = eth_deposit()
        .args(["key", "recover", "--help"])
        .output()
        .expect("help");
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    let help_l = help.to_lowercase();
    assert!(
        !help_l.contains("--entropy") && !help_l.contains("entropy-"),
        "key recover must not expose an entropy flag (S-4): {help}"
    );
    assert!(
        help.contains("--mnemonic-passphrase-env"),
        "expected mnemonic-passphrase-env in help: {help}"
    );
}
