//! Black-box tests for the `Signer` trait surface, ported from
//! `go/internal/signer/signer_test.go`.

use ethernal_signer::{SignedTx, Signer, SignerError};
use ethernal_tx::UnsignedTx;

struct FakeSigner {
    name: &'static str,
}

impl Signer for FakeSigner {
    fn sign_with_cancel(
        &self,
        unsigned: &UnsignedTx,
        _is_cancelled: &dyn Fn() -> bool,
    ) -> Result<SignedTx, SignerError> {
        Ok(SignedTx {
            unsigned: unsigned.clone(),
            from: "0xdeadbeef".into(),
            hash: "0xabc123".into(),
            r: "0x1".into(),
            s: "0x2".into(),
            v: "0".into(),
            raw_rlp: "0xdeadbeef".into(),
        })
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn requires_user_interaction(&self) -> bool {
        false
    }

    fn close(&self) -> Result<(), SignerError> {
        Ok(())
    }
}

// Go: compile-time interface satisfaction check (var _ signer.Signer = ...)
#[allow(dead_code)]
fn assert_fake_signer_is_object_safe(s: &FakeSigner) -> &dyn Signer {
    s
}

// Go: TestFakeSignerName
#[test]
fn fake_signer_name() {
    let s = FakeSigner {
        name: "test-signer",
    };
    assert_eq!(s.name(), "test-signer");
}

// Go: TestFakeSignerSign
#[test]
fn fake_signer_sign() {
    let s = FakeSigner { name: "fake" };
    let unsigned = UnsignedTx {
        chain_id: 1,
        to: "0x1234".into(),
        value: "0x1".into(),
        data: "0xabcd".into(),
        gas: 21000,
        tx_type: "0x2".into(),
        ..UnsignedTx::default()
    };
    let signed = s.sign(&unsigned).expect("Sign");
    assert_eq!(signed.from, "0xdeadbeef");
    assert_eq!(signed.unsigned.chain_id, unsigned.chain_id);
}

// Go: TestSentinelErrors
#[test]
fn sentinel_errors() {
    let errs = [
        SignerError::UserRejected,
        SignerError::NoDevice,
        SignerError::AppNotOpen,
        SignerError::InvalidKey,
        SignerError::ChainIdMismatch,
        SignerError::InvalidChainId,
        SignerError::SignerClosed,
        SignerError::LedgerNotSupported,
    ];
    for e in errs {
        assert!(
            !e.to_string().is_empty(),
            "sentinel {e:?} has empty message"
        );
    }
}

// Rust-only: sentinel messages are the Go texts verbatim (part of the
// observable contract; the exit-code map greps on them).
#[test]
fn sentinel_error_texts_match_go() {
    let cases = [
        (SignerError::UserRejected, "user rejected signing on device"),
        (SignerError::NoDevice, "no Ledger device found"),
        (SignerError::AppNotOpen, "ledger Ethereum app is not open"),
        (SignerError::InvalidKey, "invalid private key"),
        (SignerError::ChainIdMismatch, "chain ID mismatch"),
        (SignerError::InvalidChainId, "invalid chain ID"),
        (SignerError::SignerClosed, "signer is closed"),
        (
            SignerError::LedgerNotSupported,
            "ledger support requires the 'ledger' cargo feature; rebuild with --features ledger",
        ),
    ];
    for (err, want) in cases {
        assert_eq!(err.to_string(), want);
    }
}
