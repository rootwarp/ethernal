//! Golden test: signing the Phase 3 Holesky fixture with the synthetic key
//! must reproduce the committed golden file byte-for-byte.
//!
//! Ported from `go/cmd/eth-deposit/signed_golden_test.go`
//! (TestPhase3_HoleskyLocalSignerGolden), inlined at the crate level: the
//! Go test drove the `sign` CLI command, whose output framing is
//! `json.MarshalIndent(signed, "", "  ")` plus a trailing newline —
//! matched here with `serde_json::to_string_pretty` + `'\n'`.

use std::fs;
use std::path::Path;

use ethernal_signer::{new_local_signer_from_hex, Signer};
use ethernal_tx::UnsignedTx;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/phase3/holesky")
        .join(name)
}

// Go: TestPhase3_HoleskyLocalSignerGolden
#[test]
fn phase3_holesky_local_signer_golden() {
    let unsigned_raw =
        fs::read_to_string(fixture_path("unsigned_tx.json")).expect("read unsigned_tx.json");
    let unsigned: UnsignedTx = serde_json::from_str(&unsigned_raw).expect("parse unsigned_tx.json");

    let key = fs::read_to_string(fixture_path("private_key.txt")).expect("read private_key.txt");
    let signer = new_local_signer_from_hex(key.trim()).expect("construct signer");

    let signed = signer.sign(&unsigned).expect("sign");
    let _ = signer.close();

    let mut got = serde_json::to_string_pretty(&signed).expect("marshal signed tx");
    got.push('\n');

    let want = fs::read_to_string(fixture_path("signed_tx_golden.json")).expect("read golden file");

    assert_eq!(
        got, want,
        "phase3 golden mismatch\ngot:\n{got}\nwant:\n{want}"
    );
}
