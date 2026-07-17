//! M2 early smoke test: the full core pipeline (BLS sign → SSZ roots →
//! Launchpad JSON) must reproduce the committed hoodi golden fixture
//! byte-for-byte from the fixed test secret.
//!
//! Go: TestHoodiGoldenDeposit (test/e2e/hoodi_test.go), minus the keystore
//! decrypt step, which is covered by the keystore crate (R1-5) and the
//! bin-level golden gate (R2-4).

use std::path::Path;

use eth_deposit_core::bls;
use eth_deposit_core::cancel::CancelToken;
use eth_deposit_core::deposit::{Generator, Request};
use eth_deposit_core::network::{self, Network};
use eth_deposit_core::output::{DryRunWriter, Writer};

/// The fixed 32-byte BLS secret used to generate all hoodi golden fixtures.
/// Test-only — MUST NEVER be used on any real network.
const GOLDEN_SECRET: [u8; 32] = [
    0x6a, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01,
];

/// Matches defaultWithdrawalCreds() in the Go cmd: type 0x00 BLS withdrawal.
const GOLDEN_WITHDRAWAL_CREDENTIALS: [u8; 32] = [0u8; 32];

fn testdata(rel: &str) -> std::path::PathBuf {
    // crates/core -> ../../testdata
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(rel)
}

fn run_golden(net: Network, dir: &str) {
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
                withdrawal_credentials: GOLDEN_WITHDRAWAL_CREDENTIALS,
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

use eth_deposit_core::bls::Signer as _;

#[test]
fn hoodi_golden_deposit_byte_identical() {
    run_golden(Network::Hoodi, "hoodi");
}

#[test]
fn mainnet_golden_deposit_byte_identical() {
    run_golden(Network::Mainnet, "mainnet");
}
