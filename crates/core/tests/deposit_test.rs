//! Ported from go/internal/deposit/deposit_test.go and
//! go/internal/deposit/json_test.go.
//!
//! Black-box tests against the public deposit surface. The Go generation tests
//! use fake Signer/Verifier implementations; here we implement the same fakes
//! against the `bls::{Signer, Verifier}` traits.
//!
//! Adaptation notes:
//!   * Go returns `(entries, err)` and asserts `entries != nil` on the error
//!     path. Under Rust's `Result`, an `Err` carries no entries, so those
//!     checks are vacuous and are folded into the variant assertion.
//!   * Go's `Signer.PublicKey`/`Sign` and `Verifier.Verify` return the untyped
//!     `error`; the Rust traits return `BlsError`, so the "error propagation"
//!     fakes surface a concrete `BlsError` variant, which `Generator::generate`
//!     wraps as `DepositError::Bls(_)` (distinct from `PubkeyMismatch` /
//!     `SelfVerifyFailed`).
//!   * The JSON read-side tests build wire JSON via `serde_json` rather than
//!     marshalling the private `jsonEntry` struct.

use eth_deposit_core::bls::{BlsError, Signer, Verifier};
use eth_deposit_core::cancel::CancelToken;
use eth_deposit_core::deposit::{
    entries_from_json, entry_from_json, eth1_withdrawal_credentials, DepositError, Entry,
    Generator, Request,
};
use eth_deposit_core::network::{self, Network};
use eth_deposit_core::ssz;

// -----------------------------------------------------------------------------
// Fake Signer / Verifier
// -----------------------------------------------------------------------------

/// Mirrors Go's `fakeSigner`. When `cancel_on_sign` is set, calling `sign`
/// cancels that token — used to drive the mid-loop cancellation test. The
/// token must be a clone that shares state with the one passed to `generate`.
struct FakeSigner {
    pubkey: [u8; 48],
    sig: [u8; 96],
    sign_err: Option<BlsError>,
    pubkey_err: Option<BlsError>,
    cancel_on_sign: Option<CancelToken>,
}

impl FakeSigner {
    fn new(pubkey: [u8; 48], sig: [u8; 96]) -> Self {
        FakeSigner {
            pubkey,
            sig,
            sign_err: None,
            pubkey_err: None,
            cancel_on_sign: None,
        }
    }
}

impl Signer for FakeSigner {
    fn sign(&self, _signing_root: [u8; 32]) -> Result<[u8; 96], BlsError> {
        if let Some(tok) = &self.cancel_on_sign {
            tok.cancel();
        }
        if let Some(e) = &self.sign_err {
            return Err(e.clone());
        }
        Ok(self.sig)
    }

    fn public_key(&self) -> Result<[u8; 48], BlsError> {
        if let Some(e) = &self.pubkey_err {
            return Err(e.clone());
        }
        Ok(self.pubkey)
    }
}

/// Mirrors Go's `fakeVerifier`. `err` takes priority over `ok`, matching the
/// Go semantics where a non-nil error is returned regardless of the bool.
struct FakeVerifier {
    ok: bool,
    err: Option<BlsError>,
}

impl Verifier for FakeVerifier {
    fn verify(
        &self,
        _pubkey: [u8; 48],
        _signing_root: [u8; 32],
        _sig: [u8; 96],
    ) -> Result<bool, BlsError> {
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        Ok(self.ok)
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn hoodi_params() -> network::Params {
    network::lookup(Network::Hoodi)
}

fn make_pubkey(seed: u8) -> [u8; 48] {
    let mut pk = [0u8; 48];
    pk[0] = seed;
    pk
}

fn make_sig(seed: u8) -> [u8; 96] {
    let mut sig = [0u8; 96];
    sig[0] = seed;
    sig
}

// -----------------------------------------------------------------------------
// Generate tests (Go: deposit_test.go)
// -----------------------------------------------------------------------------

// Go: TestGenerate_Success
#[test]
fn generate_success() {
    let params = hoodi_params();
    let pk = make_pubkey(0xAA);
    let sig = make_sig(0xBB);

    let mut wc = [0u8; 32];
    wc[0] = 0x01;
    let amount = 32_000_000_000u64;
    let cli_ver = "2.7.0";

    let signer = FakeSigner::new(pk, sig);
    let verifier = FakeVerifier {
        ok: true,
        err: None,
    };

    let gen = Generator::new(&signer, &verifier, params.clone());

    let req = Request {
        network: Network::Hoodi,
        pubkeys: vec![pk, pk, pk],
        withdrawal_credentials: wc,
        amount_gwei: amount,
        deposit_cli_version: cli_ver.to_string(),
    };

    let entries = gen.generate(&req, &CancelToken::new()).expect("generate");
    assert_eq!(entries.len(), 3, "expected 3 entries");

    for (i, e) in entries.iter().enumerate() {
        assert_eq!(e.pubkey, pk, "entry[{i}] pubkey");
        assert_eq!(e.withdrawal_credentials, wc, "entry[{i}] wc");
        assert_eq!(e.amount, amount, "entry[{i}] amount");
        assert_eq!(e.signature, sig, "entry[{i}] signature");
        assert_eq!(
            e.fork_version, params.genesis_fork_version,
            "entry[{i}] fork_version"
        );
        assert_eq!(
            e.network_name,
            params.name.to_string(),
            "entry[{i}] network"
        );
        assert_eq!(e.deposit_cli_version, cli_ver, "entry[{i}] cli version");

        // DepositMessageRoot: independently recompute via the real ssz code.
        let expected_msg_root = ssz::DepositMessage {
            pubkey: pk,
            withdrawal_credentials: wc,
            amount,
        }
        .hash_tree_root();
        assert_eq!(
            e.deposit_message_root, expected_msg_root,
            "entry[{i}] deposit_message_root"
        );

        // DepositDataRoot: independently recompute via the real ssz code.
        let expected_data_root = ssz::DepositData {
            pubkey: pk,
            withdrawal_credentials: wc,
            amount,
            signature: sig,
        }
        .hash_tree_root();
        assert_eq!(
            e.deposit_data_root, expected_data_root,
            "entry[{i}] deposit_data_root"
        );
    }
}

// Go: TestGenerate_PubkeyMismatch
#[test]
fn generate_pubkey_mismatch() {
    let params = hoodi_params();
    let signer_pubkey = make_pubkey(0xAA);
    let request_pubkey = make_pubkey(0xBB);

    let signer = FakeSigner::new(signer_pubkey, [0u8; 96]);
    let verifier = FakeVerifier {
        ok: true,
        err: None,
    };

    let gen = Generator::new(&signer, &verifier, params);

    let req = Request {
        network: Network::Hoodi,
        pubkeys: vec![request_pubkey],
        withdrawal_credentials: [0u8; 32],
        amount_gwei: 32_000_000_000,
        deposit_cli_version: "2.7.0".to_string(),
    };

    let err = gen.generate(&req, &CancelToken::new()).unwrap_err();
    assert!(
        matches!(err, DepositError::PubkeyMismatch { .. }),
        "want PubkeyMismatch, got {err:?}"
    );
}

// Go: TestGenerate_SelfVerifyFailed
#[test]
fn generate_self_verify_failed() {
    let params = hoodi_params();
    let pk = make_pubkey(0xAA);

    let signer = FakeSigner::new(pk, make_sig(0x01));
    let verifier = FakeVerifier {
        ok: false,
        err: None,
    };

    let gen = Generator::new(&signer, &verifier, params);

    let req = Request {
        network: Network::Hoodi,
        pubkeys: vec![pk],
        withdrawal_credentials: [0u8; 32],
        amount_gwei: 32_000_000_000,
        deposit_cli_version: "2.7.0".to_string(),
    };

    let err = gen.generate(&req, &CancelToken::new()).unwrap_err();
    assert!(
        matches!(err, DepositError::SelfVerifyFailed { .. }),
        "want SelfVerifyFailed, got {err:?}"
    );
}

// Go: TestGenerate_ContextCancel — cancellation observed at the top of the
// second iteration after the first Sign cancels the shared token.
#[test]
fn generate_cancellation() {
    let params = hoodi_params();
    let pk = make_pubkey(0xAA);

    // One token, shared by clone between the signer hook and `generate`.
    let cancel = CancelToken::new();

    let mut signer = FakeSigner::new(pk, make_sig(0x01));
    signer.cancel_on_sign = Some(cancel.clone());
    let verifier = FakeVerifier {
        ok: true,
        err: None,
    };

    let gen = Generator::new(&signer, &verifier, params);

    let req = Request {
        network: Network::Hoodi,
        pubkeys: vec![pk, pk], // second iteration will observe cancellation
        withdrawal_credentials: [0u8; 32],
        amount_gwei: 32_000_000_000,
        deposit_cli_version: "2.7.0".to_string(),
    };

    let err = gen.generate(&req, &cancel).unwrap_err();
    assert!(
        matches!(err, DepositError::Cancelled),
        "want Cancelled, got {err:?}"
    );
}

// Go: TestGenerate_PublicKeyError — a PublicKey() error is propagated directly
// (as DepositError::Bls), not turned into a PubkeyMismatch.
#[test]
fn generate_public_key_error() {
    let params = hoodi_params();

    let mut signer = FakeSigner::new([0u8; 48], [0u8; 96]);
    signer.pubkey_err = Some(BlsError::BadPubkey("pubkey fetch failure".to_string()));
    let verifier = FakeVerifier {
        ok: true,
        err: None,
    };

    let gen = Generator::new(&signer, &verifier, params);

    let req = Request {
        network: Network::Hoodi,
        pubkeys: vec![make_pubkey(0x01)],
        withdrawal_credentials: [0u8; 32],
        amount_gwei: 32_000_000_000,
        deposit_cli_version: "2.7.0".to_string(),
    };

    let err = gen.generate(&req, &CancelToken::new()).unwrap_err();
    assert!(
        matches!(err, DepositError::Bls(_)),
        "want Bls (not PubkeyMismatch), got {err:?}"
    );
    assert!(
        err.to_string().contains("pubkey fetch failure"),
        "underlying message must be preserved: {err}"
    );
}

// Go: TestGenerate_SignError — a Sign() error is propagated (as DepositError::Bls).
#[test]
fn generate_sign_error() {
    let params = hoodi_params();
    let pk = make_pubkey(0x01);

    let mut signer = FakeSigner::new(pk, [0u8; 96]);
    signer.sign_err = Some(BlsError::BadSignature(
        "hardware signer offline".to_string(),
    ));
    let verifier = FakeVerifier {
        ok: true,
        err: None,
    };

    let gen = Generator::new(&signer, &verifier, params);

    let req = Request {
        network: Network::Hoodi,
        pubkeys: vec![pk],
        withdrawal_credentials: [0u8; 32],
        amount_gwei: 32_000_000_000,
        deposit_cli_version: "2.7.0".to_string(),
    };

    let err = gen.generate(&req, &CancelToken::new()).unwrap_err();
    assert!(matches!(err, DepositError::Bls(_)), "want Bls, got {err:?}");
    assert!(err.to_string().contains("hardware signer offline"));
}

// Go: TestGenerate_VerifyError — a Verify() error is propagated (as
// DepositError::Bls), distinct from the !ok SelfVerifyFailed path.
#[test]
fn generate_verify_error() {
    let params = hoodi_params();
    let pk = make_pubkey(0x01);

    let signer = FakeSigner::new(pk, make_sig(0x01));
    let verifier = FakeVerifier {
        ok: false, // error takes priority
        err: Some(BlsError::BadPubkey("HSM verify timeout".to_string())),
    };

    let gen = Generator::new(&signer, &verifier, params);

    let req = Request {
        network: Network::Hoodi,
        pubkeys: vec![pk],
        withdrawal_credentials: [0u8; 32],
        amount_gwei: 32_000_000_000,
        deposit_cli_version: "2.7.0".to_string(),
    };

    let err = gen.generate(&req, &CancelToken::new()).unwrap_err();
    assert!(
        matches!(err, DepositError::Bls(_)),
        "want Bls (not SelfVerifyFailed), got {err:?}"
    );
    assert!(err.to_string().contains("HSM verify timeout"));
}

// Go: TestGenerate_NetworkMismatch
#[test]
fn generate_network_mismatch() {
    let params = hoodi_params();
    let pk = make_pubkey(0x01);
    let signer = FakeSigner::new(pk, [0u8; 96]);
    let verifier = FakeVerifier {
        ok: true,
        err: None,
    };
    let gen = Generator::new(&signer, &verifier, params);

    // Request states mainnet but the generator is configured for hoodi.
    let req = Request {
        network: Network::Mainnet,
        pubkeys: vec![pk],
        withdrawal_credentials: [0u8; 32],
        amount_gwei: 32_000_000_000,
        deposit_cli_version: "2.7.0".to_string(),
    };

    let err = gen.generate(&req, &CancelToken::new()).unwrap_err();
    assert!(
        matches!(err, DepositError::NetworkMismatch { .. }),
        "want NetworkMismatch, got {err:?}"
    );
}

// Go: TestGenerate_EmptyPubkeys
#[test]
fn generate_empty_pubkeys() {
    let params = hoodi_params();
    let signer = FakeSigner::new([0u8; 48], [0u8; 96]);
    let verifier = FakeVerifier {
        ok: true,
        err: None,
    };
    let gen = Generator::new(&signer, &verifier, params);

    let req = Request {
        network: Network::Hoodi,
        pubkeys: vec![],
        withdrawal_credentials: [0u8; 32],
        amount_gwei: 32_000_000_000,
        deposit_cli_version: "2.7.0".to_string(),
    };

    let entries = gen
        .generate(&req, &CancelToken::new())
        .expect("empty pubkeys must not error");
    assert_eq!(entries.len(), 0, "expected 0 entries");
}

// -----------------------------------------------------------------------------
// JSON read-side tests (Go: json_test.go)
// -----------------------------------------------------------------------------

/// Builds a wire-JSON object with valid values for all fields, mirroring
/// Go's `validRawEntry`. Returned as a `serde_json::Value` so individual
/// fields can be mutated before serialization.
fn valid_raw_entry() -> serde_json::Value {
    serde_json::json!({
        "pubkey": "ab".repeat(48),
        "withdrawal_credentials": "cd".repeat(32),
        "amount": 32_000_000_000u64,
        "signature": "ef".repeat(96),
        "deposit_message_root": "01".repeat(32),
        "deposit_data_root": "02".repeat(32),
        "fork_version": "10000910",
        "network_name": "hoodi",
        "deposit_cli_version": "2.7.0",
    })
}

fn to_bytes(v: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("marshal json")
}

// Go: TestEntryFromJSON_Valid
#[test]
fn entry_from_json_valid() {
    let data = to_bytes(&valid_raw_entry());
    let e = entry_from_json(&data).expect("entry_from_json");

    assert_eq!(e.network_name, "hoodi");
    assert_eq!(e.amount, 32_000_000_000);
    assert_eq!(e.deposit_cli_version, "2.7.0");
    assert_eq!(e.pubkey[0], 0xab, "pubkey first byte");
}

// Go: TestEntryFromJSON_0xPrefixedHex
#[test]
fn entry_from_json_0x_prefixed_hex() {
    let mut raw = valid_raw_entry();
    for field in [
        "pubkey",
        "withdrawal_credentials",
        "signature",
        "deposit_message_root",
        "deposit_data_root",
        "fork_version",
    ] {
        let s = raw[field].as_str().unwrap().to_string();
        raw[field] = serde_json::Value::String(format!("0x{s}"));
    }
    let data = to_bytes(&raw);
    entry_from_json(&data).expect("0x-prefixed fields must parse");
}

// Go: TestEntryFromJSON_InvalidHex
#[test]
fn entry_from_json_invalid_hex() {
    let mut raw = valid_raw_entry();
    raw["pubkey"] = serde_json::Value::String("ZZ".repeat(48));
    let data = to_bytes(&raw);
    assert!(
        entry_from_json(&data).is_err(),
        "invalid hex pubkey must error"
    );
}

// Go: TestEntryFromJSON_WrongLength
#[test]
fn entry_from_json_wrong_length() {
    let cases: &[(&str, &str, String)] = &[
        ("pubkey_short", "pubkey", "ab".repeat(47)),
        ("pubkey_long", "pubkey", "ab".repeat(49)),
        (
            "withdrawal_credentials_short",
            "withdrawal_credentials",
            "cd".repeat(31),
        ),
        ("signature_short", "signature", "ef".repeat(95)),
        (
            "deposit_message_root_short",
            "deposit_message_root",
            "01".repeat(31),
        ),
        (
            "deposit_data_root_short",
            "deposit_data_root",
            "02".repeat(31),
        ),
        ("fork_version_short", "fork_version", "100009".to_string()), // 3 bytes
        (
            "fork_version_long",
            "fork_version",
            "1000091011".to_string(),
        ), // 5 bytes
    ];

    for (name, field, value) in cases {
        let mut raw = valid_raw_entry();
        raw[*field] = serde_json::Value::String(value.clone());
        let data = to_bytes(&raw);
        assert!(
            entry_from_json(&data).is_err(),
            "case {name}: wrong length must error"
        );
    }
}

// Go: TestEntriesFromJSON_Array
#[test]
fn entries_from_json_array() {
    let raw = valid_raw_entry();
    let arr = serde_json::Value::Array(vec![raw.clone(), raw]);
    let data = to_bytes(&arr);
    let entries = entries_from_json(&data).expect("entries_from_json");
    assert_eq!(entries.len(), 2);
}

// Go: TestEntriesFromJSON_EmptyArray
#[test]
fn entries_from_json_empty_array() {
    let entries = entries_from_json(b"[]").expect("empty array");
    assert_eq!(entries.len(), 0);
}

// Go: TestEntriesFromJSON_InvalidEntry — error must name the failing index.
#[test]
fn entries_from_json_invalid_entry() {
    let good = valid_raw_entry();
    let mut bad = valid_raw_entry();
    bad["pubkey"] = serde_json::Value::String("ZZ".repeat(48));

    let arr = serde_json::Value::Array(vec![good, bad]);
    let data = to_bytes(&arr);

    let err = entries_from_json(&data).unwrap_err();
    assert!(
        err.to_string().contains("entry[1]"),
        "error {err} does not name the failing index"
    );
}

// Go: TestEntriesFromJSON_GoldenFile — the golden `gen` output parses cleanly.
#[test]
fn entries_from_json_golden_file() {
    let data = br#"[{"pubkey":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","withdrawal_credentials":"0000000000000000000000000000000000000000000000000000000000000000","amount":32000000000,"signature":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","deposit_message_root":"0000000000000000000000000000000000000000000000000000000000000000","deposit_data_root":"0000000000000000000000000000000000000000000000000000000000000000","fork_version":"10000910","network_name":"hoodi","deposit_cli_version":"2.7.0"},{"pubkey":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","withdrawal_credentials":"0000000000000000000000000000000000000000000000000000000000000000","amount":32000000000,"signature":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","deposit_message_root":"0000000000000000000000000000000000000000000000000000000000000000","deposit_data_root":"0000000000000000000000000000000000000000000000000000000000000000","fork_version":"10000910","network_name":"hoodi","deposit_cli_version":"2.7.0"}]"#;
    let entries = entries_from_json(data).expect("golden must parse");
    assert_eq!(entries.len(), 2);
}

// -----------------------------------------------------------------------------
// Validate tests (Go: json_test.go)
// -----------------------------------------------------------------------------

/// A well-formed Entry with non-zero meaningful values, mirroring Go's base.
fn valid_entry() -> Entry {
    let mut e = Entry::default();
    e.pubkey[0] = 0xAB;
    e.signature[0] = 0xCD;
    e.deposit_data_root[0] = 0xEF;
    e.amount = 32_000_000_000;
    e.network_name = "hoodi".to_string();
    e
}

// Go: TestValidate_Valid
#[test]
fn validate_valid() {
    valid_entry().validate().expect("valid entry must pass");
}

// Go: TestValidate_Invalid — each invariant failure is caught with a
// descriptive message.
#[test]
fn validate_invalid() {
    struct Case {
        name: &'static str,
        mutate: fn(&mut Entry),
        want_substr: &'static str,
    }
    let cases = [
        Case {
            name: "zero_pubkey",
            mutate: |e| e.pubkey = [0u8; 48],
            want_substr: "pubkey",
        },
        Case {
            name: "zero_signature",
            mutate: |e| e.signature = [0u8; 96],
            want_substr: "signature",
        },
        Case {
            name: "zero_deposit_data_root",
            mutate: |e| e.deposit_data_root = [0u8; 32],
            want_substr: "deposit_data_root",
        },
        Case {
            name: "zero_amount",
            mutate: |e| e.amount = 0,
            want_substr: "amount",
        },
        Case {
            name: "unknown_network",
            mutate: |e| e.network_name = "goerli".to_string(),
            want_substr: "network_name",
        },
    ];

    for c in &cases {
        let mut e = valid_entry();
        (c.mutate)(&mut e);
        let err = e
            .validate()
            .expect_err(&format!("case {}: expected error", c.name));
        assert!(
            err.to_string().contains(c.want_substr),
            "case {}: error {err:?} does not mention {:?}",
            c.name,
            c.want_substr
        );
    }
}

// -----------------------------------------------------------------------------
// eth1_withdrawal_credentials (K5-1)
// -----------------------------------------------------------------------------

#[test]
fn eth1_withdrawal_credentials_layout() {
    let addr: [u8; 20] = [
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11,
    ];
    let wc = eth1_withdrawal_credentials(addr);
    assert_eq!(wc.len(), 32);
    assert_eq!(wc[0], 0x01, "prefix must be ETH1_ADDRESS_WITHDRAWAL_PREFIX");
    assert_eq!(&wc[1..12], &[0u8; 11], "bytes 1..12 must be zero");
    assert_eq!(&wc[12..32], &addr, "bytes 12..32 must equal the address");
    // Full expected layout used by phase2 fixture / validation tests.
    let mut want = [0u8; 32];
    want[0] = 0x01;
    want[12..].copy_from_slice(&addr);
    assert_eq!(wc, want);
}
