//! Ported from go/internal/bls/bls_test.go.
//!
//! Black-box tests against the public BLS surface. `Signer`/`Verifier` traits
//! must be in scope to call `sign`/`public_key`/`verify` on the concrete
//! `BlsSigner`/`BlsVerifier`.

use eth_deposit_core::bls::{self, Signer, Verifier};

// Go: TestInitIdempotent
#[test]
fn init_idempotent() {
    bls::init().expect("first init");
    bls::init().expect("second init");
}

// Go: TestNewSignerRejectsWrongLength
#[test]
fn new_signer_rejects_wrong_length() {
    bls::init().expect("init");

    let cases: [(&str, Vec<u8>); 4] = [
        ("empty", vec![]),
        ("too short 16 bytes", vec![0x01; 16]),
        ("too long 33 bytes", vec![0x01; 33]),
        ("too long 64 bytes", vec![0x01; 64]),
    ];

    for (name, secret) in cases {
        assert!(
            bls::new_signer(&secret).is_err(),
            "new_signer({name}, {} bytes) should have errored",
            secret.len()
        );
    }
}

// Go: TestRoundTrip — sign with key A, verify with A's pubkey → true.
#[test]
fn round_trip() {
    bls::init().expect("init");

    let secret = [0x01u8; 32];
    let signer = bls::new_signer(&secret).expect("new_signer");

    let signing_root = [0xabu8; 32];
    let sig = signer.sign(signing_root).expect("sign");
    let pub_key = signer.public_key().expect("public_key");

    let verifier = bls::default_verifier();
    let ok = verifier.verify(pub_key, signing_root, sig).expect("verify");
    assert!(ok, "verify must return true for a valid round-trip");
}

// Go: TestVerifyRejection — sign with A, verify with B's pubkey → false.
#[test]
fn verify_rejection() {
    bls::init().expect("init");

    let secret_a = [0x01u8; 32];
    let secret_b = [0x02u8; 32];

    let signer_a = bls::new_signer(&secret_a).expect("new_signer A");
    let signer_b = bls::new_signer(&secret_b).expect("new_signer B");

    let signing_root = [0xcdu8; 32];
    let sig = signer_a.sign(signing_root).expect("sign A");

    let pub_b = signer_b.public_key().expect("public_key B");

    let verifier = bls::default_verifier();
    let ok = verifier.verify(pub_b, signing_root, sig).expect("verify");
    assert!(!ok, "verify with the wrong pubkey must return false");
}

// Go: TestCallerSecretUnmodified — new_signer must not zeroize the caller's slice.
#[test]
fn caller_secret_unmodified() {
    bls::init().expect("init");

    let original = [0x03u8; 32];
    let secret = original;

    let _ = bls::new_signer(&secret).expect("new_signer");

    assert_eq!(
        secret, original,
        "new_signer must not modify the caller's secret"
    );
}

// Go: TestPublicKeyLength — public key is exactly 48 bytes and non-zero.
#[test]
fn public_key_non_zero() {
    bls::init().expect("init");

    let secret = [0x05u8; 32];
    let signer = bls::new_signer(&secret).expect("new_signer");
    let pub_key = signer.public_key().expect("public_key");

    assert_eq!(pub_key.len(), 48);
    assert_ne!(pub_key, [0u8; 48], "public key must be non-zero");
}

// Go: TestSignatureLength — signature is exactly 96 bytes and non-zero.
#[test]
fn signature_non_zero() {
    bls::init().expect("init");

    let secret = [0x07u8; 32];
    let signer = bls::new_signer(&secret).expect("new_signer");

    let mut root = [0u8; 32];
    root[0] = 0xff;

    let sig = signer.sign(root).expect("sign");
    assert_eq!(sig.len(), 96);
    assert_ne!(sig, [0u8; 96], "signature must be non-zero");
}
