//! M2 early smoke test: the full core pipeline (BLS sign → SSZ roots →
//! Launchpad JSON) must reproduce the committed hoodi golden fixture
//! byte-for-byte from the fixed test secret.
//!
//! Go: TestHoodiGoldenDeposit (test/e2e/hoodi_test.go), minus the keystore
//! decrypt step, which is covered by the keystore crate (R1-5) and the
//! bin-level golden gate (R2-4).

use std::path::Path;

use ethernal_core::bls;
use ethernal_core::cancel::CancelToken;
use ethernal_core::deposit::{Generator, Request};
use ethernal_core::network::{self, Network};
use ethernal_core::output::{DryRunWriter, Writer};

/// The fixed 32-byte BLS secret used to generate all hoodi golden fixtures.
/// Test-only — MUST NEVER be used on any real network.
const GOLDEN_SECRET: [u8; 32] = [
    0x6a, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01,
];

/// Historical type-0x00 BLS withdrawal placeholder (mainnet golden still uses this).
const GOLDEN_WITHDRAWAL_CREDENTIALS_00: [u8; 32] = [0u8; 32];

/// 0x01 ‖ 11 zero ‖ signer local test key `0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1`.
/// Matches the post-K5 `gen --withdrawal-address` path that regenerates the hoodi golden.
const GOLDEN_WITHDRAWAL_CREDENTIALS_HOODI: [u8; 32] = {
    let mut c = [0u8; 32];
    c[0] = 0x01;
    // 1a642f0e3c3af545e7acbd38b07251b3990914f1
    c[12] = 0x1a;
    c[13] = 0x64;
    c[14] = 0x2f;
    c[15] = 0x0e;
    c[16] = 0x3c;
    c[17] = 0x3a;
    c[18] = 0xf5;
    c[19] = 0x45;
    c[20] = 0xe7;
    c[21] = 0xac;
    c[22] = 0xbd;
    c[23] = 0x38;
    c[24] = 0xb0;
    c[25] = 0x72;
    c[26] = 0x51;
    c[27] = 0xb3;
    c[28] = 0x99;
    c[29] = 0x09;
    c[30] = 0x14;
    c[31] = 0xf1;
    c
};

fn testdata(rel: &str) -> std::path::PathBuf {
    // crates/core -> ../../testdata
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

fn run_golden(net: Network, dir: &str, withdrawal_credentials: [u8; 32]) {
    let pubkeys_raw = std::fs::read_to_string(testdata(&format!("{dir}/pubkeys.txt"))).unwrap();
    let expected = std::fs::read(testdata(&format!("{dir}/deposit_data-expected.json"))).unwrap();

    let mut pubkeys = Vec::new();
    for line in pubkeys_raw.trim().lines() {
        let bytes = hex::decode(line.trim().trim_start_matches("0x")).unwrap();
        let mut pk = [0u8; 48];
        pk.copy_from_slice(&bytes);
        pubkeys.push(pk);
    }
    assert!(!pubkeys.is_empty(), "no pubkeys in fixture");

    let signer = bls::new_signer(&GOLDEN_SECRET).expect("golden secret must be a valid scalar");
    assert_eq!(
        signer.public_key().unwrap(),
        pubkeys[0],
        "derived pubkey must match fixture pubkeys.txt"
    );

    let verifier = bls::default_verifier();
    let generator = Generator::new(&signer, &verifier, network::lookup(net));
    let entries = generator
        .generate(
            &Request {
                network: net,
                pubkeys,
                withdrawal_credentials,
                amount_gwei: 32_000_000_000,
                deposit_cli_version: "2.7.0".to_string(),
            },
            &CancelToken::new(),
        )
        .expect("generate");

    let mut buf = Vec::new();
    let (path, sha) = DryRunWriter::new(&mut buf)
        .write(Path::new("."), &entries, 0)
        .expect("dry-run write");
    assert_eq!(path, "", "dry-run writer must return an empty path");
    assert_eq!(sha.len(), 64);

    assert_eq!(
        String::from_utf8_lossy(&buf),
        String::from_utf8_lossy(&expected),
        "generated JSON must be byte-identical to the golden fixture"
    );
}

use ethernal_core::bls::Signer as _;

#[test]
fn hoodi_golden_deposit_byte_identical() {
    run_golden(Network::Hoodi, "hoodi", GOLDEN_WITHDRAWAL_CREDENTIALS_HOODI);
}

#[test]
fn mainnet_golden_deposit_byte_identical() {
    run_golden(
        Network::Mainnet,
        "mainnet",
        GOLDEN_WITHDRAWAL_CREDENTIALS_00,
    );
}
