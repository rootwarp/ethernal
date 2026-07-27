//! A5-1 — in-binary E2E + cross-recovery fixture.
//!
//! Fixed BIP-39 mnemonic (`abandon…about`) + **empty** mnemonic passphrase →
//! seed `5eb00bbd…` through `account recover` → Web3 v3 keystores at 0600 with
//! `UTC--` filenames and cast-vector addresses; same seed feeds BLS
//! `core::hd` (`m/12381/3600/i/0/0`) and EOA `core::hd_secp256k1`
//! (`m/44'/60'/0'/0/i`).
//!
//! Determinism is the fixed mnemonic through recover — **no** hidden
//! `--entropy-*` / `--time-*` flag (S-4). BLS pubkeys are regression-locked
//! (committed fixture), not an external EIP-2333 vector (case-0 is
//! abandon+TREZOR → `c55257c3…`).
//!
//! Fixtures (frozen once):
//!   tests/testdata/eoa/cross-recovery.json

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use ethernal_core::bip39;
use ethernal_core::hd::{self, KeyPath};
use ethernal_core::hd_secp256k1::{self, Bip44Path};
use ethernal_core::output::{write_new_0600, OutputError};
use ethernal_keystore::decrypt_v3;
use ethernal_keystore::encrypt_v3::{v3_filename, ScryptParams};
use ethernal_signer::{eip55_checksum, secret_to_address};

use common::{crate_testdata, ethernal, secret_file, TempDir};

// --- chain anchor: BIP-39 abandon×11 about + empty passphrase = cast vector ---

const ABANDON_12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// Empty-passphrase seed (Ethereum BIP-44 / cast). NOT the TREZOR seed c55257c3….
const EMPTY_SEED_HEX: &str = concat!(
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1",
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
);
const KEYSTORE_PW: &str = "password1";
const COUNT: u32 = 2;

fn eoa_testdata() -> PathBuf {
    crate_testdata().join("eoa")
}

fn cross_recovery_fixture() -> PathBuf {
    eoa_testdata().join("cross-recovery.json")
}

#[derive(Debug, serde::Deserialize)]
struct CrossRecoveryFixture {
    seed_hex: String,
    mnemonic: String,
    mnemonic_passphrase: String,
    indices: Vec<IndexFixture>,
}

#[derive(Debug, serde::Deserialize)]
struct IndexFixture {
    index: u32,
    eoa_path: String,
    eoa_private_key: String,
    address: String,
    eip55: String,
    bls_signing_path: String,
    bls_signing_pubkey: String,
    bls_withdrawal_path: String,
    bls_withdrawal_pubkey: String,
}

fn load_fixture() -> CrossRecoveryFixture {
    let raw = std::fs::read_to_string(cross_recovery_fixture()).expect("read cross-recovery.json");
    serde_json::from_str(&raw).expect("parse cross-recovery.json")
}

/// Run `account recover` with the fixed mnemonic over stdin (empty mnemonic
/// passphrase — no `--mnemonic-passphrase*` flag). Returns (stdout, stderr).
fn run_account_recover(out_dir: &Path, count: u32) -> (String, String, bool) {
    let secrets = TempDir::new("a5-secrets");
    let ks_path = secret_file(&secrets, "ks.pw", KEYSTORE_PW.as_bytes());

    let mut child = ethernal()
        .args(["account", "recover", "--output-dir"])
        .arg(out_dir)
        .args([
            "--count",
            &count.to_string(),
            "--start-index",
            "0",
            "--passphrase-file",
            ks_path.to_str().unwrap(),
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

    let out = child.wait_with_output().expect("wait account recover");
    drop(secrets);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (stdout, stderr, out.status.success())
}

fn v3_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("read keystore dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("UTC--"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    files
}

/// Parse a geth `UTC--YYYY-MM-DDTHH-MM-SS.<9-nanos>Z--<40-hex>` name back to
/// `(address, unix_secs, nanos)` and prove it round-trips through [`v3_filename`].
fn parse_v3_filename(name: &str) -> ([u8; 20], i64, u32) {
    assert!(
        name.starts_with("UTC--"),
        "filename must start with UTC--: {name}"
    );
    let rest = &name["UTC--".len()..];
    let (datetime, addr_hex) = rest
        .rsplit_once("--")
        .unwrap_or_else(|| panic!("missing --address separator: {name}"));
    // datetime = YYYY-MM-DDTHH-MM-SS.nnnnnnnnnZ
    assert!(
        datetime.ends_with('Z'),
        "datetime must end with Z: {datetime}"
    );
    let dt = &datetime[..datetime.len() - 1];
    let (date_time, nanos_s) = dt
        .split_once('.')
        .unwrap_or_else(|| panic!("missing nanos fraction: {datetime}"));
    let nanos: u32 = nanos_s
        .parse()
        .unwrap_or_else(|_| panic!("nanos parse: {nanos_s}"));
    assert_eq!(nanos_s.len(), 9, "nanos must be 9 digits: {nanos_s}");

    // date_time = YYYY-MM-DDTHH-MM-SS
    let (date, time) = date_time
        .split_once('T')
        .unwrap_or_else(|| panic!("missing T: {date_time}"));
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next().unwrap().parse().unwrap();
    let month: u32 = date_parts.next().unwrap().parse().unwrap();
    let day: u32 = date_parts.next().unwrap().parse().unwrap();
    let mut time_parts = time.split('-');
    let hour: u32 = time_parts.next().unwrap().parse().unwrap();
    let min: u32 = time_parts.next().unwrap().parse().unwrap();
    let sec: u32 = time_parts.next().unwrap().parse().unwrap();

    let days = days_from_civil(year, month, day);
    let unix_secs = days * 86_400 + (hour as i64) * 3600 + (min as i64) * 60 + sec as i64;

    let addr_bytes = hex::decode(addr_hex).expect("address hex");
    assert_eq!(addr_bytes.len(), 20, "address length in {name}");
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&addr_bytes);

    // Round-trip through v3_filename.
    let rebuilt = v3_filename(&addr, unix_secs, nanos);
    assert_eq!(
        rebuilt, name,
        "v3_filename round-trip failed\n got: {rebuilt}\nwant: {name}"
    );
    (addr, unix_secs, nanos)
}

/// Howard Hinnant's `days_from_civil` (inverse of `civil_from_days` in encrypt_v3).
fn days_from_civil(mut y: i64, m: u32, d: u32) -> i64 {
    y -= i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * (m as u64 + if m > 2 { 0 } else { 12 } - 3) + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Seed from fixed mnemonic + empty passphrase matches the cast/BIP-44 anchor
/// and the committed fixture; both HD trees (BLS + EOA) produce the fixture
/// keys/addresses index-for-index (cross-recovery property).
#[test]
fn recover_seed_and_cross_recovery_match_fixture() {
    let fx = load_fixture();
    assert_eq!(fx.mnemonic, ABANDON_12);
    assert_eq!(fx.mnemonic_passphrase, "");
    assert_eq!(fx.seed_hex, EMPTY_SEED_HEX);
    assert!(
        fx.seed_hex.starts_with("5eb00bbd"),
        "must be empty-passphrase seed, not TREZOR c55257c3…"
    );
    assert!(!fx.seed_hex.starts_with("c55257c3"));

    let seed = bip39::to_seed(ABANDON_12, b"").unwrap();
    assert_eq!(
        hex::encode(seed.as_slice()),
        EMPTY_SEED_HEX,
        "BIP-39 seed must be empty-passphrase / cast vector"
    );
    assert_eq!(hex::encode(seed.as_slice()), fx.seed_hex);

    assert_eq!(fx.indices.len(), COUNT as usize);
    for entry in &fx.indices {
        // --- EOA half (cast-vector anchored) ---
        let eoa_path = Bip44Path::eoa(entry.index);
        assert_eq!(eoa_path.to_string(), entry.eoa_path);
        let derived =
            hd_secp256k1::ExtendedPrivKey::derive_path(seed.as_slice(), &eoa_path).expect("eoa");
        let sk = derived.secret_bytes();
        assert_eq!(
            hex::encode(sk.as_slice()),
            entry.eoa_private_key,
            "EOA secret index {}",
            entry.index
        );
        let addr = secret_to_address(&sk).expect("address");
        assert_eq!(
            hex::encode(addr),
            entry.address,
            "address index {}",
            entry.index
        );
        let eip55 = eip55_checksum(&addr);
        assert_eq!(eip55, entry.eip55, "EIP-55 index {}", entry.index);

        // --- BLS half (regression-locked, same seed) ---
        let signing =
            hd::derive_path(seed.as_slice(), &KeyPath::signing(entry.index)).expect("bls signing");
        let withdrawal = hd::derive_path(seed.as_slice(), &KeyPath::withdrawal(entry.index))
            .expect("bls withdrawal");
        assert_eq!(
            hex::encode(signing.public_key()),
            entry.bls_signing_pubkey,
            "BLS signing pubkey index {}",
            entry.index
        );
        assert_eq!(
            hex::encode(withdrawal.public_key()),
            entry.bls_withdrawal_pubkey,
            "BLS withdrawal pubkey index {}",
            entry.index
        );
        assert_eq!(
            KeyPath::signing(entry.index).to_string(),
            entry.bls_signing_path
        );
        assert_eq!(
            KeyPath::withdrawal(entry.index).to_string(),
            entry.bls_withdrawal_path
        );
    }
}

/// Binary `account recover` writes v3 keystores whose addresses match the cast
/// fixture; files are 0600 with `UTC--` names that parse back through
/// [`v3_filename`]; crypto fields are internally consistent.
#[test]
fn account_recover_keystores_match_fixture() {
    let fx = load_fixture();
    let dir = TempDir::new("a5-recover");
    let (_stdout, stderr, ok) = run_account_recover(dir.path(), COUNT);
    assert!(ok, "account recover failed: stderr={stderr}");
    assert!(
        stderr.contains("ethernal account recover:"),
        "banner missing: {stderr}"
    );
    // S-4: no entropy-injection mention; determinism is mnemonic-only.
    assert!(
        !stderr.to_lowercase().contains("entropy"),
        "unexpected entropy mention (determinism must be mnemonic-only): {stderr}"
    );
    assert!(
        stderr.contains("wrote 2 keystores") || stderr.contains("keystore"),
        "progress/summary: {stderr}"
    );

    let files = v3_files(dir.path());
    assert_eq!(
        files.len(),
        COUNT as usize,
        "expected {COUNT} keystores, got {files:?}"
    );

    // Index files by the address suffix in the filename.
    let mut by_addr: std::collections::HashMap<String, PathBuf> = std::collections::HashMap::new();
    for f in &files {
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        let (addr, _secs, _nanos) = parse_v3_filename(&name);
        let addr_hex = hex::encode(addr);
        by_addr.insert(addr_hex, f.clone());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(f).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "mode for {f:?}");
        }
    }

    for entry in &fx.indices {
        let f = by_addr
            .get(&entry.address)
            .unwrap_or_else(|| panic!("missing keystore for address {}", entry.address));
        let raw = std::fs::read(f).expect("read keystore");
        let v: serde_json::Value = serde_json::from_slice(&raw).expect("keystore JSON");

        assert_eq!(v["version"], 3);
        assert_eq!(
            v["address"].as_str().unwrap(),
            entry.address,
            "JSON address index {}",
            entry.index
        );
        assert_eq!(v["crypto"]["cipher"], "aes-128-ctr");
        assert_eq!(v["crypto"]["kdf"], "scrypt");
        assert_eq!(
            v["crypto"]["kdfparams"]["n"],
            ScryptParams::STANDARD.n,
            "production scrypt N"
        );
        assert_eq!(v["crypto"]["kdfparams"]["r"], ScryptParams::STANDARD.r);
        assert_eq!(v["crypto"]["kdfparams"]["p"], ScryptParams::STANDARD.p);
        assert!(v["crypto"]["ciphertext"].as_str().is_some());
        assert!(v["crypto"]["mac"].as_str().is_some());
        assert!(v["id"].as_str().is_some());

        // EIP-55 address appears in the progress/summary on stderr.
        assert!(
            stderr.contains(&entry.eip55),
            "summary missing EIP-55 {} : {stderr}",
            entry.eip55
        );

        // Plaintext secret must never appear in the keystore JSON.
        assert!(
            !String::from_utf8_lossy(&raw).contains(&entry.eoa_private_key),
            "plaintext secret leaked into keystore JSON"
        );
    }
}

/// T-3 / E3-1 — v3 correctness via `account recover` + `decrypt_v3`.
///
/// Structural address-match alone leaves the encrypt path unproven (`address`
/// is written independent of the ciphertext). `decrypt_v3` closes that gap:
/// decrypt → secret → derive address == keystore `address` == fixture address.
#[test]
fn account_recover_decrypt_v3_round_trip_matches_fixture() {
    let fx = load_fixture();
    let dir = TempDir::new("e3-1-decrypt-v3");
    let (_stdout, stderr, ok) = run_account_recover(dir.path(), COUNT);
    assert!(ok, "account recover failed: stderr={stderr}");

    let files = v3_files(dir.path());
    assert_eq!(
        files.len(),
        COUNT as usize,
        "expected {COUNT} keystores, got {files:?}"
    );

    let mut by_addr: std::collections::HashMap<String, PathBuf> = std::collections::HashMap::new();
    for f in &files {
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        let (addr, _secs, _nanos) = parse_v3_filename(&name);
        by_addr.insert(hex::encode(addr), f.clone());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(f).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "mode for {f:?}");
        }
    }

    for entry in &fx.indices {
        let f = by_addr
            .get(&entry.address)
            .unwrap_or_else(|| panic!("missing keystore for address {}", entry.address));
        let raw = std::fs::read(f).expect("read keystore");
        let v: serde_json::Value = serde_json::from_slice(&raw).expect("keystore JSON");

        // Structural v3 (version / cipher / scrypt / mac / address / filename / 0600).
        assert_eq!(v["version"], 3, "version index {}", entry.index);
        assert_eq!(
            v["address"].as_str().unwrap(),
            entry.address,
            "JSON address index {}",
            entry.index
        );
        assert_eq!(v["crypto"]["cipher"], "aes-128-ctr");
        assert_eq!(v["crypto"]["kdf"], "scrypt");
        assert_eq!(
            v["crypto"]["kdfparams"]["n"],
            ScryptParams::STANDARD.n,
            "production scrypt N"
        );
        assert_eq!(v["crypto"]["kdfparams"]["r"], ScryptParams::STANDARD.r);
        assert_eq!(v["crypto"]["kdfparams"]["p"], ScryptParams::STANDARD.p);
        assert!(
            v["crypto"]["ciphertext"].as_str().is_some(),
            "ciphertext index {}",
            entry.index
        );
        // Web3 v3 MAC is Keccak-256 over derived-key[16..32] || ciphertext.
        let mac = v["crypto"]["mac"].as_str().expect("mac present");
        assert_eq!(
            mac.len(),
            64,
            "keccak-256 mac is 32 bytes hex, index {}",
            entry.index
        );
        assert!(v["id"].as_str().is_some(), "id index {}", entry.index);

        // decrypt_v3 → secret → address == keystore address == fixture address/eip55.
        let secret = decrypt_v3(&raw, KEYSTORE_PW.as_bytes())
            .unwrap_or_else(|e| panic!("decrypt_v3 index {}: {e}", entry.index));
        let derived = secret_to_address(&secret)
            .unwrap_or_else(|e| panic!("secret_to_address index {}: {e}", entry.index));
        let derived_hex = hex::encode(derived);
        let ks_addr = v["address"].as_str().unwrap();
        assert_eq!(
            derived_hex, ks_addr,
            "decrypt-derived address != keystore address, index {}",
            entry.index
        );
        assert_eq!(
            derived_hex, entry.address,
            "decrypt-derived address != fixture address, index {}",
            entry.index
        );
        assert_eq!(
            eip55_checksum(&derived),
            entry.eip55,
            "decrypt-derived EIP-55 != fixture, index {}",
            entry.index
        );
    }
}

/// A second recover into the same dir never overwrites existing keystores
/// (F-4 / S-3): original file bytes stay intact. Fresh wall-clock filenames
/// may add new files; `write_new_0600` on an existing path refuses (AlreadyExists).
#[test]
fn account_recover_second_run_does_not_overwrite() {
    let dir = TempDir::new("a5-overwrite");
    let (_stdout, stderr, ok) = run_account_recover(dir.path(), COUNT);
    assert!(ok, "first recover failed: {stderr}");

    let files = v3_files(dir.path());
    assert_eq!(files.len(), COUNT as usize);
    let snapshots: Vec<(PathBuf, Vec<u8>)> = files
        .iter()
        .map(|p| (p.clone(), std::fs::read(p).expect("read")))
        .collect();

    // Library-level refuse-overwrite on the paths the binary produced.
    for (path, original) in &snapshots {
        let err = write_new_0600(path, b"should-not-land").expect_err("must refuse");
        assert!(
            matches!(err, OutputError::AlreadyExists),
            "expected AlreadyExists for {path:?}, got {err:?}"
        );
        assert_eq!(
            std::fs::read(path).unwrap(),
            *original,
            "write_new_0600 must not clobber {path:?}"
        );
    }

    // Second full binary run: new wall-clock names → additional files OK; originals intact.
    let (_stdout2, stderr2, ok2) = run_account_recover(dir.path(), COUNT);
    assert!(
        ok2,
        "second recover should succeed with fresh timestamps: {stderr2}"
    );
    for (path, original) in &snapshots {
        assert_eq!(
            std::fs::read(path).unwrap(),
            *original,
            "second run must not overwrite {path:?}"
        );
    }
    let after = v3_files(dir.path());
    assert!(
        after.len() >= COUNT as usize,
        "expected at least original files; got {after:?}"
    );
}

/// G4 / GHSA-c6rv-g6pj-r6qx — batch salt/IV/id must be pairwise-distinct under
/// real OS entropy. `recover --count 3` exercises the encrypt-time CSPRNG loop
/// without a TTY; fields are compared as raw JSON (no decrypt).
/// EOA v3 identifier is top-level `id` (NOT `uuid` — G4-2 amended).
///
/// Bite-proof (local, throwaway, never commit): temporarily wire FixedEntropy /
/// fixed bytes in place of OsEntropy in the CLI encrypt path, rebuild, run only
/// this test and `key_recover_batch_salt_iv_uuid_pairwise_distinct` → salt/iv
/// HashSets collapse to size 1 → both go red; revert before any commit.
#[test]
fn account_recover_batch_salt_iv_id_pairwise_distinct() {
    let dir = TempDir::new("g4-account-batch");
    let (_stdout, stderr, ok) = run_account_recover(dir.path(), 3);
    assert!(ok, "account recover failed: stderr={stderr}");

    let files = v3_files(dir.path());
    assert_eq!(files.len(), 3, "expected 3 keystores, got {files:?}");

    let mut salts = Vec::with_capacity(3);
    let mut ivs = Vec::with_capacity(3);
    let mut ids = Vec::with_capacity(3);
    let mut addresses = Vec::with_capacity(3);

    for f in &files {
        let raw = std::fs::read(f).expect("read keystore");
        let v: serde_json::Value = serde_json::from_slice(&raw).expect("keystore JSON");
        salts.push(
            v["crypto"]["kdfparams"]["salt"]
                .as_str()
                .expect("salt")
                .to_owned(),
        );
        ivs.push(
            v["crypto"]["cipherparams"]["iv"]
                .as_str()
                .expect("iv")
                .to_owned(),
        );
        ids.push(v["id"].as_str().expect("id").to_owned());
        addresses.push(v["address"].as_str().expect("address").to_owned());
    }

    assert_eq!(
        salts.iter().collect::<std::collections::HashSet<_>>().len(),
        3,
        "salts must be pairwise-distinct across the batch: {salts:?}"
    );
    assert_eq!(
        ivs.iter().collect::<std::collections::HashSet<_>>().len(),
        3,
        "ivs must be pairwise-distinct across the batch: {ivs:?}"
    );
    assert_eq!(
        ids.iter().collect::<std::collections::HashSet<_>>().len(),
        3,
        "ids must be pairwise-distinct across the batch: {ids:?}"
    );
    assert_eq!(
        addresses
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3,
        "addresses must be pairwise-distinct (3 real accounts, not copies): {addresses:?}"
    );
}

/// CLI surface has no hidden entropy/time-injection flag: determinism is the
/// fixed mnemonic through recover (S-4).
#[test]
fn account_recover_help_has_no_entropy_or_time_flag() {
    let out = ethernal()
        .args(["account", "recover", "--help"])
        .output()
        .expect("help");
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    let help_l = help.to_lowercase();
    assert!(
        !help_l.contains("--entropy") && !help_l.contains("entropy-"),
        "account recover must not expose an entropy flag (S-4): {help}"
    );
    assert!(
        !help_l.contains("--time") && !help_l.contains("timestamp"),
        "account recover must not expose a time/timestamp flag (S-4): {help}"
    );
    assert!(
        help.contains("--mnemonic-passphrase"),
        "expected mnemonic-passphrase in help: {help}"
    );
    assert!(
        help.contains("--start-index"),
        "expected start-index in help: {help}"
    );
}

/// T-12·recover / E4-2 — symlinked `--output-dir` on the recover/stdin path
/// emits the documented WARNING (`1736843`) and still writes keystores.
#[cfg(unix)]
#[test]
fn account_recover_symlinked_output_dir_warns_and_writes() {
    use std::os::unix::fs::symlink;

    let base = TempDir::new("e4-2-account-symlink");
    let real = base.join("real-out");
    std::fs::create_dir(&real).expect("create real-out");
    let link = base.join("link-out");
    symlink(&real, &link).expect("symlink link-out -> real-out");
    let resolved = std::fs::canonicalize(&real).expect("canonicalize real-out");

    let (_stdout, stderr, ok) = run_account_recover(&link, 1);
    assert!(ok, "account recover failed: stderr={stderr}");
    assert!(
        stderr.contains("ethernal account recover:"),
        "banner missing: {stderr}"
    );

    let warning_lines: Vec<_> = stderr.lines().filter(|l| l.contains("WARNING")).collect();
    assert_eq!(
        warning_lines.len(),
        1,
        "expected exactly one WARNING, got: {stderr}"
    );
    assert!(
        warning_lines[0].contains("is a symlink")
            && warning_lines[0].contains("keystores will be written to"),
        "documented symlink warning text: {stderr}"
    );
    assert!(
        warning_lines[0].contains(link.to_str().unwrap()),
        "must name given path: {stderr}"
    );
    assert!(
        warning_lines[0].contains(resolved.to_str().unwrap()),
        "must name resolved path: {stderr}"
    );

    // Warn + still write (into the real dir via the symlink).
    let files = v3_files(&real);
    assert_eq!(
        files.len(),
        1,
        "expected 1 keystore under real path, got {files:?}"
    );
    assert_eq!(
        v3_files(&link).len(),
        1,
        "keystores must also be visible via symlink path"
    );
}

// ---------------------------------------------------------------------------
// F4-3 / FR-12 — S-C byte-rule matrix (v3 keystore passphrase, raw bytes)
// ---------------------------------------------------------------------------

/// Distinctive S-C keystore passphrase (≥ KEYSTORE_PASSPHRASE_MIN_LEN after FR-8).
/// Plan matrix writes "pw"; e2e needs ≥8 bytes for MinLenPassphrase.
const SC_PASSPHRASE: &str = "F43_SC_pw";

/// Run `account recover` with a custom keystore passphrase file (bytes written
/// via `common::secret_file` — no terminator added). Returns (stderr, success, exit).
fn run_account_recover_ks(
    out_dir: &Path,
    count: u32,
    ks_bytes: &[u8],
) -> (String, bool, Option<i32>) {
    let secrets = TempDir::new("f4-3-sc-secrets");
    let ks_path = secret_file(&secrets, "ks.pw", ks_bytes);

    let mut child = ethernal()
        .args(["account", "recover", "--output-dir"])
        .arg(out_dir)
        .args([
            "--count",
            &count.to_string(),
            "--start-index",
            "0",
            "--passphrase-file",
            ks_path.to_str().unwrap(),
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

    let out = child.wait_with_output().expect("wait account recover");
    drop(secrets);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (stderr, out.status.success(), out.status.code())
}

/// FR-12 S-C: `pw` vs `pw\n` → same effective passphrase after FR-8 → mutually
/// decryptable v3 keystores (decrypt either keystore with the stripped bytes).
/// Production scrypt; `--count 1`.
#[test]
fn account_recover_sc_trailing_nl_identical_decryptable_v3() {
    let dir_plain = TempDir::new("f4-3-sc-plain");
    let dir_nl = TempDir::new("f4-3-sc-nl");

    let (stderr_plain, ok_plain, _) =
        run_account_recover_ks(dir_plain.path(), 1, SC_PASSPHRASE.as_bytes());
    assert!(
        ok_plain,
        "account recover (plain pw) failed: {stderr_plain}"
    );
    let nl_bytes = format!("{SC_PASSPHRASE}\n");
    let (stderr_nl, ok_nl, _) = run_account_recover_ks(dir_nl.path(), 1, nl_bytes.as_bytes());
    assert!(ok_nl, "account recover (pw\\n) failed: {stderr_nl}");

    let files_plain = v3_files(dir_plain.path());
    let files_nl = v3_files(dir_nl.path());
    assert_eq!(files_plain.len(), 1, "plain: {files_plain:?}");
    assert_eq!(files_nl.len(), 1, "nl: {files_nl:?}");

    let raw_plain = std::fs::read(&files_plain[0]).expect("read plain keystore");
    let raw_nl = std::fs::read(&files_nl[0]).expect("read nl keystore");
    let pw = SC_PASSPHRASE.as_bytes();

    // Mutual decrypt: each keystore opens with the FR-8-stripped passphrase.
    let secret_from_plain = decrypt_v3(&raw_plain, pw).expect("decrypt plain keystore with pw");
    let secret_from_nl = decrypt_v3(&raw_nl, pw).expect("decrypt nl keystore with pw");
    assert_eq!(
        secret_from_plain.as_slice(),
        secret_from_nl.as_slice(),
        "pw and pw\\n must yield the same EOA secret (identical derived key)"
    );

    // Cross-check via address fields (structural identity of the recovered account).
    let v_plain: serde_json::Value = serde_json::from_slice(&raw_plain).unwrap();
    let v_nl: serde_json::Value = serde_json::from_slice(&raw_nl).unwrap();
    assert_eq!(
        v_plain["address"].as_str(),
        v_nl["address"].as_str(),
        "addresses must match"
    );
    let derived = secret_to_address(&secret_from_plain).expect("address");
    assert_eq!(hex::encode(derived), v_plain["address"].as_str().unwrap());
}

/// FR-12 / FR-9 S-C CR rows: `pw\r`, `pw\r\n`, `pw\r\r\n` each exit 2.
///
/// This row — not S-B — is the automated evidence that FR-9's widened residual
/// clause (reject every residual `\r`) is live. S-B passes under
/// `normalize_passphrase` whether or not FR-8/FR-9 exist.
#[test]
fn account_recover_sc_cr_shapes_exit2() {
    // Distinctive sentinel so a content leak is unambiguous (M-3).
    const SENTINEL: &str = "F43_SC_pw";
    for (label, bytes) in [
        ("cr", &b"F43_SC_pw\r"[..]),
        ("crlf", &b"F43_SC_pw\r\n"[..]),
        ("crcrlf", &b"F43_SC_pw\r\r\n"[..]),
    ] {
        // Comment required by F4-3 acceptance: this row, not S-B, is the evidence
        // FR-9's widened clause is live — do not delete as "duplicate coverage".
        let dir = TempDir::new(&format!("f4-3-sc-{label}"));
        let secrets = TempDir::new(&format!("f4-3-sc-s-{label}"));
        let ks_path = secret_file(&secrets, "ks.pw", bytes);
        let path_str = ks_path.to_str().unwrap().to_owned();

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
            writeln!(stdin, "{ABANDON_12}").expect("write mnemonic");
        }
        let out = child.wait_with_output().expect("wait");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(2),
            "S-C {label}: expected exit 2; stderr={stderr}"
        );
        assert!(
            stderr.contains("carriage return"),
            "S-C {label}: message must name shape 'carriage return', got: {stderr}"
        );
        assert!(
            stderr.contains(&path_str),
            "S-C {label}: message must name path {path_str}, got: {stderr}"
        );
        assert!(
            !stderr.contains(SENTINEL),
            "S-C {label}: passphrase content leaked into error: {stderr}"
        );
        assert!(
            v3_files(dir.path()).is_empty(),
            "S-C {label}: must not write a keystore on CR reject"
        );
    }
}
