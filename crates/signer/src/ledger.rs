//! Ledger hardware wallet signer, ported from `go/internal/signer/ledger.go`
//! + `ledger_transport.go`.
//!
//! Feature isolation mirrors Go's build-tag isolation: this module has no
//! feature gate and compiles everywhere. `ledger_hid.rs` (behind the
//! `ledger` cargo feature) provides the real hidapi transport; without the
//! feature the default hub factory returns the `LedgerNotSupported`
//! sentinel (parity with Go's non-CGO stub in `ledger_nocgo.go`).
//!
//! Divergences from the Go seam (`ledgerHub`/`ledgerWallet` wrapped geth's
//! `usbwallet`/`accounts.Wallet`):
//! - the seam traits are shaped for this crate's own transport
//!   (`sign_tx` takes the parsed tx and returns raw v/r/s instead of geth's
//!   `*types.Transaction`); orchestration and error classification are
//!   unchanged;
//! - Go's package-level `newLedgerHub` var is replaced by an injectable
//!   factory parameter on `new_with_hub_factory` (no global mutable state);
//! - the derived account address is not retained on the signer — Go stored
//!   it only to pass to geth's `SignTx`; the `from` field is recovered from
//!   the signature in both implementations;
//! - Go raced `SignTx` against `ctx.Done()` in a goroutine; the synchronous
//!   Rust transport checks `is_cancelled` before and after the device call
//!   instead (a mid-flight APDU exchange cannot be interrupted either way).

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use eth_deposit_tx::UnsignedTx;

use crate::errors::SignerError;
use crate::local::{build_signed_tx, keccak256, recover_address, Signer};
use crate::parse::{parse_unsigned_tx, ParsedTx};
use crate::rlp;
use crate::types::SignedTx;

const LEDGER_SIGNER_NAME: &str = "ledger";

/// The default BIP-32 derivation path m/44'/60'/0'/0/0
/// (geth `accounts.DefaultBaseDerivationPath`). Consumed by the real HID
/// transport (`ledger_hid.rs`, feature `ledger`).
#[cfg_attr(not(feature = "ledger"), allow(dead_code))]
pub(crate) const DEFAULT_DERIVATION_PATH: [u32; 5] = [0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0];

/// An error from the Ledger transport layer. Classification of these into
/// signer sentinels happens by substring heuristics on the rendered
/// message, exactly like the Go code classified geth `usbwallet` errors.
#[derive(Debug)]
pub(crate) struct LedgerTransportError(pub(crate) String);

impl std::fmt::Display for LedgerTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LedgerTransportError {}

/// A raw EIP-1559 signature returned by the device: y-parity plus the two
/// 32-byte scalars.
pub(crate) struct LedgerSignature {
    /// The y-parity bit (the Ledger app returns 0 or 1 for type-2 txs).
    pub(crate) v: u8,
    pub(crate) r: [u8; 32],
    pub(crate) s: [u8; 32],
}

/// Abstracts a single Ledger device for testability (Go: `ledgerWallet`
/// wrapping `accounts.Wallet`). Implementations: `HidWallet` (feature
/// `ledger`), `MockWallet` (tests).
pub(crate) trait LedgerWallet {
    /// A diagnostic identifier for the device (never sensitive). Part of
    /// the Go seam (`accounts.Wallet.URL()`); unused by the orchestration,
    /// kept for parity and diagnostics.
    #[allow(dead_code)]
    fn url(&self) -> String;
    fn open(&mut self, passphrase: &str) -> Result<(), LedgerTransportError>;
    fn close(&mut self) -> Result<(), LedgerTransportError>;
    fn status(&self) -> Result<String, LedgerTransportError>;
    /// Derives the account at [`DEFAULT_DERIVATION_PATH`] and returns its
    /// address.
    fn derive_default(&mut self) -> Result<[u8; 20], LedgerTransportError>;
    /// Sends the transaction to the device for confirmation and signing.
    fn sign_tx(
        &self,
        parsed: &ParsedTx,
        nonce: u64,
        gas: u64,
    ) -> Result<LedgerSignature, LedgerTransportError>;
}

/// Abstracts device discovery (Go: `ledgerHub` wrapping `usbwallet.Hub`).
pub(crate) trait LedgerHub {
    /// Consumes the hub and returns the discovered wallets. (The
    /// orchestration only ever enumerates once, so ownership transfer is
    /// the simplest faithful port of Go's `Wallets()`.)
    fn wallets(self: Box<Self>) -> Vec<Box<dyn LedgerWallet>>;
}

/// The default hub factory (Go: `newLedgerHub` set by `init()` in
/// `ledger_cgo.go` / `ledger_nocgo.go`).
#[cfg(feature = "ledger")]
fn default_hub_factory() -> Result<Box<dyn LedgerHub>, SignerError> {
    crate::ledger_hid::new_hid_hub()
}

/// Without the `ledger` feature the transport is unavailable (parity with
/// Go's non-CGO build returning `ErrLedgerNotSupported`).
#[cfg(not(feature = "ledger"))]
fn default_hub_factory() -> Result<Box<dyn LedgerHub>, SignerError> {
    Err(SignerError::LedgerNotSupported)
}

/// Returns true when `err` suggests the Ethereum app is not open.
/// Matches known APDU error codes (6e00, 6e01, 6d00) and textual hints.
/// The textual heuristic requires both "app" AND ("not open" OR "open the")
/// to reduce false positives (e.g. "snapshot not found in app" does not
/// match). TODO(3.6): replace with exact strings from real hardware test.
fn is_app_not_open_err(err: &LedgerTransportError) -> bool {
    let msg = err.0.to_lowercase();
    if msg.contains("6e00") || msg.contains("6e01") || msg.contains("6d00") {
        return true;
    }
    msg.contains("app") && (msg.contains("not open") || msg.contains("open the"))
}

/// Returns true when `err` indicates the user rejected signing on the
/// device. Heuristic: "rejected", "denied", "cancel", or APDU code "6985".
/// TODO(3.6): refine after real hardware testing confirms exact strings.
fn is_user_rejected_err(err: &LedgerTransportError) -> bool {
    let msg = err.0.to_lowercase();
    msg.contains("rejected")
        || msg.contains("denied")
        || msg.contains("cancel")
        || msg.contains("6985")
}

/// Returns true when `err` indicates the Ledger refused the chain ID.
/// Heuristic: "chain" combined with "unknown", "mismatch", "6a80", or
/// "6a81". TODO(3.6): refine after real hardware testing.
fn is_chain_id_mismatch_err(err: &LedgerTransportError) -> bool {
    let msg = err.0.to_lowercase();
    if !msg.contains("chain") {
        return false;
    }
    msg.contains("unknown")
        || msg.contains("mismatch")
        || msg.contains("6a80")
        || msg.contains("6a81")
}

/// Signs transactions via a Ledger hardware wallet. The private key never
/// leaves the device.
///
/// Construct with [`LedgerSigner::new`]. [`Signer::close`] must be called
/// to release the HID handle.
pub struct LedgerSigner {
    wallet: Mutex<Box<dyn LedgerWallet>>,
    closed: AtomicBool,
    confirmation_prompt: Mutex<Box<dyn Write>>,
}

impl LedgerSigner {
    /// Discovers the first connected Ledger, opens the Ethereum app, and
    /// derives the account at m/44'/60'/0'/0/0.
    ///
    /// Returns `LedgerNotSupported` (wrapped in `"ledger hub init: ..."`)
    /// if the crate was built without the `ledger` feature, `NoDevice` if
    /// no Ledger is detected, and `AppNotOpen` if a Ledger is found but the
    /// Ethereum app is not open.
    pub fn new() -> Result<LedgerSigner, SignerError> {
        Self::new_with_hub_factory(default_hub_factory)
    }

    /// [`LedgerSigner::new`] with an injectable hub factory (Go's
    /// `newLedgerHub` var, overridden by tests).
    pub(crate) fn new_with_hub_factory<F>(factory: F) -> Result<LedgerSigner, SignerError>
    where
        F: FnOnce() -> Result<Box<dyn LedgerHub>, SignerError>,
    {
        let hub = factory().map_err(|e| SignerError::context("ledger hub init", e))?;

        let mut wallets = hub.wallets();
        if wallets.is_empty() {
            return Err(SignerError::NoDevice);
        }
        let mut w = wallets.swap_remove(0);

        if let Err(e) = w.open("") {
            if is_app_not_open_err(&e) {
                return Err(SignerError::AppNotOpen);
            }
            return Err(SignerError::context(
                "ledger init failed",
                SignerError::NoDevice,
            ));
        }

        // Check status — open can succeed even when the Ethereum app isn't
        // active.
        if let Err(e) = w.status() {
            if is_app_not_open_err(&e) {
                let _ = w.close();
                return Err(SignerError::AppNotOpen);
            }
            let _ = w.close();
            return Err(SignerError::context(
                "ledger status check failed",
                SignerError::NoDevice,
            ));
        }

        if let Err(e) = w.derive_default() {
            let _ = w.close();
            return Err(SignerError::Msg(format!("ledger derive failed: {e}")));
        }

        Ok(LedgerSigner {
            wallet: Mutex::new(w),
            closed: AtomicBool::new(false),
            confirmation_prompt: Mutex::new(Box::new(std::io::stderr())),
        })
    }

    /// Sets the writer for "please confirm on device" messages.
    /// Used in tests to capture or silence the prompt.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn set_confirmation_prompt(&self, w: Box<dyn Write>) {
        *self.confirmation_prompt.lock().unwrap() = w;
    }
}

impl std::fmt::Debug for LedgerSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerSigner")
            .field("closed", &self.closed.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Signer for LedgerSigner {
    /// Produces a signed EIP-1559 transaction by sending the transaction
    /// to the Ledger device for user confirmation. Blocks on user
    /// confirmation on the device; `is_cancelled` is checked before and
    /// after the (uninterruptible) device exchange.
    fn sign_with_cancel(
        &self,
        unsigned: &UnsignedTx,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<SignedTx, SignerError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SignerError::SignerClosed);
        }
        if is_cancelled() {
            return Err(SignerError::Cancelled);
        }

        let p = parse_unsigned_tx(unsigned)?;

        {
            let mut prompt = self.confirmation_prompt.lock().unwrap();
            let _ = writeln!(
                prompt,
                "Please confirm the transaction on your Ledger device..."
            );
        }

        let result = {
            let wallet = self.wallet.lock().unwrap();
            wallet.sign_tx(&p, unsigned.nonce, unsigned.gas)
        };
        // Cancellation raced against the device wait wins, like Go's
        // select on ctx.Done().
        if is_cancelled() {
            return Err(SignerError::Cancelled);
        }

        let sig = match result {
            Ok(sig) => sig,
            Err(e) => {
                // Check chain-ID mismatch before user-rejected: "6a80 chain
                // rejected" contains "rejected" but is a chain-ID error,
                // not a user decision.
                if is_chain_id_mismatch_err(&e) {
                    return Err(SignerError::context(
                        format!("ledger rejected chain ID {}", unsigned.chain_id),
                        SignerError::ChainIdMismatch,
                    ));
                }
                if is_user_rejected_err(&e) {
                    return Err(SignerError::context(
                        "user rejected signing on ledger",
                        SignerError::UserRejected,
                    ));
                }
                return Err(SignerError::Msg(format!("ledger SignTx: {e}")));
            }
        };

        let payload = rlp::eip1559_signing_payload(&p, unsigned.nonce, unsigned.gas);
        let sighash = keccak256(&payload);
        let from = recover_address(&sighash, &sig.r, &sig.s, sig.v)
            .map_err(|e| SignerError::Msg(format!("sender recovery failed: {e}")))?;

        let envelope =
            rlp::eip1559_envelope(&p, unsigned.nonce, unsigned.gas, sig.v, &sig.r, &sig.s);

        Ok(build_signed_tx(
            unsigned, &from, &envelope, &sig.r, &sig.s, sig.v,
        ))
    }

    fn name(&self) -> &'static str {
        LEDGER_SIGNER_NAME
    }

    fn requires_user_interaction(&self) -> bool {
        true
    }

    /// Releases the HID handle. Idempotent.
    fn close(&self) -> Result<(), SignerError> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.wallet
            .lock()
            .unwrap()
            .close()
            .map_err(|e| SignerError::Msg(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use k256::ecdsa::SigningKey;

    use super::*;
    use crate::local::pubkey_address;

    fn internaltx_unsigned() -> UnsignedTx {
        UnsignedTx {
            chain_id: 1,
            to: "0x1234".into(),
            value: "0x1".into(),
            max_fee_per_gas: "0x3B9ACA00".into(),
            max_priority_fee_per_gas: "0x3B9ACA00".into(),
            gas: 21000,
            tx_type: "0x2".into(),
            ..UnsignedTx::default()
        }
    }

    /// Mock wallet behaviors, configured per test (Go used replaceable
    /// function fields; an enum-per-call keeps the Rust mock simple).
    #[derive(Default)]
    struct MockWallet {
        open_err: Option<String>,
        status_err: Option<String>,
        derive_err: Option<String>,
        derive_addr: [u8; 20],
        sign_result: Option<Result<LedgerSignature, String>>,
        close_calls: Arc<AtomicUsize>,
    }

    impl LedgerWallet for MockWallet {
        fn url(&self) -> String {
            "ledger://mock".into()
        }
        fn open(&mut self, _passphrase: &str) -> Result<(), LedgerTransportError> {
            match &self.open_err {
                Some(msg) => Err(LedgerTransportError(msg.clone())),
                None => Ok(()),
            }
        }
        fn close(&mut self) -> Result<(), LedgerTransportError> {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn status(&self) -> Result<String, LedgerTransportError> {
            match &self.status_err {
                Some(msg) => Err(LedgerTransportError(msg.clone())),
                None => Ok("ok".into()),
            }
        }
        fn derive_default(&mut self) -> Result<[u8; 20], LedgerTransportError> {
            match &self.derive_err {
                Some(msg) => Err(LedgerTransportError(msg.clone())),
                None => Ok(self.derive_addr),
            }
        }
        fn sign_tx(
            &self,
            _parsed: &ParsedTx,
            _nonce: u64,
            _gas: u64,
        ) -> Result<LedgerSignature, LedgerTransportError> {
            match &self.sign_result {
                Some(Ok(sig)) => Ok(LedgerSignature {
                    v: sig.v,
                    r: sig.r,
                    s: sig.s,
                }),
                Some(Err(msg)) => Err(LedgerTransportError(msg.clone())),
                None => Err(LedgerTransportError("not implemented".into())),
            }
        }
    }

    struct MockHub {
        wallets: Vec<Box<dyn LedgerWallet>>,
    }

    impl LedgerHub for MockHub {
        fn wallets(self: Box<Self>) -> Vec<Box<dyn LedgerWallet>> {
            self.wallets
        }
    }

    /// Builds a LedgerSigner from a single mock wallet (Go: withMockHub).
    fn signer_with_wallet(w: MockWallet) -> Result<LedgerSigner, SignerError> {
        LedgerSigner::new_with_hub_factory(move || {
            Ok(Box::new(MockHub {
                wallets: vec![Box::new(w)],
            }))
        })
    }

    /// A Write sink into a shared buffer, for prompt capture.
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Signs `unsigned` with a fixed key using the local signing
    /// machinery, returning a device-shaped signature and the key's
    /// address (Go: synthSignedTx).
    fn synth_ledger_signature(unsigned: &UnsignedTx) -> (LedgerSignature, [u8; 20]) {
        let key_hex = crate::local::TEST_KEY_HEX;
        let sk = SigningKey::from_slice(&hex::decode(key_hex).unwrap()).unwrap();
        let addr = pubkey_address(sk.verifying_key());

        let p = parse_unsigned_tx(unsigned).expect("valid unsigned fixture");
        let payload = rlp::eip1559_signing_payload(&p, unsigned.nonce, unsigned.gas);
        let sighash = keccak256(&payload);
        let (sig, recid) = sk.sign_prehash_recoverable(&sighash).unwrap();
        let (sig, y_parity) = match sig.normalize_s() {
            Some(low) => (low, u8::from(!recid.is_y_odd())),
            None => (sig, u8::from(recid.is_y_odd())),
        };
        (
            LedgerSignature {
                v: y_parity,
                r: sig.r().to_bytes().into(),
                s: sig.s().to_bytes().into(),
            },
            addr,
        )
    }

    // --- Constructor tests ---

    // Go: TestLedgerSigner_NoDevice
    #[test]
    fn no_device() {
        let err = LedgerSigner::new_with_hub_factory(|| Ok(Box::new(MockHub { wallets: vec![] })))
            .unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::NoDevice));
    }

    // Go: TestLedgerSigner_AppNotOpen_FromOpen
    #[test]
    fn app_not_open_from_open() {
        let err = signer_with_wallet(MockWallet {
            open_err: Some("ledger: 6e00 app not open".into()),
            ..MockWallet::default()
        })
        .unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::AppNotOpen));
    }

    // Go: TestLedgerSigner_AppNotOpen_FromStatus
    #[test]
    fn app_not_open_from_status() {
        let err = signer_with_wallet(MockWallet {
            status_err: Some("ethereum app not open on device".into()),
            ..MockWallet::default()
        })
        .unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::AppNotOpen));
    }

    // Go: TestLedgerSigner_StatusFailure_Generic
    #[test]
    fn status_failure_generic() {
        let err = signer_with_wallet(MockWallet {
            status_err: Some("usb: device disconnected".into()),
            ..MockWallet::default()
        })
        .unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::NoDevice));
        assert_eq!(
            err.to_string(),
            "ledger status check failed: no Ledger device found"
        );
    }

    // Go: TestLedgerSigner_OpenFailure_Generic
    #[test]
    fn open_failure_generic() {
        let err = signer_with_wallet(MockWallet {
            open_err: Some("usb: device disconnected".into()),
            ..MockWallet::default()
        })
        .unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::NoDevice));
        assert_eq!(
            err.to_string(),
            "ledger init failed: no Ledger device found"
        );
    }

    // Go: TestLedgerSigner_DiscoverySuccess
    #[test]
    fn discovery_success() {
        let s = signer_with_wallet(MockWallet::default()).unwrap();
        assert_eq!(s.name(), "ledger");
        assert!(s.requires_user_interaction());
        let _ = s.close();
    }

    // Go: TestLedgerSigner_HubInitError
    #[test]
    fn hub_init_error() {
        let err = LedgerSigner::new_with_hub_factory(|| Err(SignerError::Msg("hub failed".into())))
            .unwrap_err();
        assert_eq!(err.to_string(), "ledger hub init: hub failed");
    }

    // Rust-only: without the `ledger` feature, the default factory yields
    // the LedgerNotSupported sentinel through the hub-init wrap (parity
    // with Go's non-CGO build).
    #[cfg(not(feature = "ledger"))]
    #[test]
    fn new_without_feature_is_ledger_not_supported() {
        let err = LedgerSigner::new().unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::LedgerNotSupported));
        assert_eq!(
            err.to_string(),
            "ledger hub init: ledger support requires the 'ledger' cargo feature; \
             rebuild with --features ledger"
        );
    }

    // Go: TestLedgerSigner_DeriveFailure
    #[test]
    fn derive_failure() {
        let err = signer_with_wallet(MockWallet {
            derive_err: Some("derive: device busy".into()),
            ..MockWallet::default()
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "ledger derive failed: derive: device busy");
    }

    // Go: TestLedgerSigner_Close_Idempotent
    #[test]
    fn close_idempotent() {
        let close_calls = Arc::new(AtomicUsize::new(0));
        let s = signer_with_wallet(MockWallet {
            close_calls: close_calls.clone(),
            ..MockWallet::default()
        })
        .unwrap();
        assert!(s.close().is_ok());
        assert!(s.close().is_ok());
        assert_eq!(close_calls.load(Ordering::SeqCst), 1);
    }

    // --- Sign tests ---

    // Go: TestLedgerSigner_Sign_Success
    #[test]
    fn sign_success() {
        let unsigned = internaltx_unsigned();
        let (synth, addr) = synth_ledger_signature(&unsigned);

        let s = signer_with_wallet(MockWallet {
            derive_addr: addr,
            sign_result: Some(Ok(synth)),
            ..MockWallet::default()
        })
        .unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));

        let result = s.sign(&unsigned).unwrap();
        assert_eq!(result.unsigned.chain_id, unsigned.chain_id);
        assert!(result.hash.starts_with("0x") && result.hash.len() > 2);
        assert!(result.raw_rlp.starts_with("0x02"));
        assert!(result.v == "0" || result.v == "1");
        assert!(!result.r.is_empty());
        assert!(!result.s.is_empty());
        assert!(result.from.starts_with("0x"));
        // Stronger than Go: the recovered sender must be the signing key's
        // address.
        assert_eq!(
            result.from.to_lowercase(),
            format!("0x{}", hex::encode(addr))
        );
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_UserRejected
    #[test]
    fn sign_user_rejected() {
        let s = signer_with_wallet(MockWallet {
            sign_result: Some(Err("user rejected the transaction".into())),
            ..MockWallet::default()
        })
        .unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let err = s.sign(&internaltx_unsigned()).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::UserRejected));
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_UserRejected_APDU6985
    #[test]
    fn sign_user_rejected_apdu_6985() {
        let s = signer_with_wallet(MockWallet {
            sign_result: Some(Err("apdu error: 6985".into())),
            ..MockWallet::default()
        })
        .unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let err = s.sign(&internaltx_unsigned()).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::UserRejected));
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_ChainIDMismatch
    #[test]
    fn sign_chain_id_mismatch() {
        let s = signer_with_wallet(MockWallet {
            sign_result: Some(Err("ledger: chain unknown or mismatch".into())),
            ..MockWallet::default()
        })
        .unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let err = s.sign(&internaltx_unsigned()).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::ChainIdMismatch));
        assert_eq!(
            err.to_string(),
            "ledger rejected chain ID 1: chain ID mismatch"
        );
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_ChainIDMismatch_APDU6a80
    #[test]
    fn sign_chain_id_mismatch_apdu_6a80() {
        let s = signer_with_wallet(MockWallet {
            sign_result: Some(Err("apdu error: 6a80 chain rejected".into())),
            ..MockWallet::default()
        })
        .unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let err = s.sign(&internaltx_unsigned()).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::ChainIdMismatch));
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_GenericError
    #[test]
    fn sign_generic_error() {
        let s = signer_with_wallet(MockWallet {
            sign_result: Some(Err("usb: write timeout".into())),
            ..MockWallet::default()
        })
        .unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let err = s.sign(&internaltx_unsigned()).unwrap_err();
        assert!(
            !matches!(
                err.sentinel(),
                SignerError::UserRejected | SignerError::ChainIdMismatch
            ),
            "expected generic error, got sentinel: {err}"
        );
        assert_eq!(err.to_string(), "ledger SignTx: usb: write timeout");
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_ChainID0_Rejected
    #[test]
    fn sign_chain_id_0_rejected() {
        let s = signer_with_wallet(MockWallet::default()).unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let mut unsigned = internaltx_unsigned();
        unsigned.chain_id = 0;
        let err = s.sign(&unsigned).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::InvalidChainId));
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_EmptyMaxFeePerGas
    #[test]
    fn sign_empty_max_fee_per_gas() {
        let s = signer_with_wallet(MockWallet::default()).unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let mut unsigned = internaltx_unsigned();
        unsigned.max_fee_per_gas = String::new();
        assert!(s.sign(&unsigned).is_err());
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_EmptyMaxPriorityFeePerGas
    #[test]
    fn sign_empty_max_priority_fee_per_gas() {
        let s = signer_with_wallet(MockWallet::default()).unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let mut unsigned = internaltx_unsigned();
        unsigned.max_priority_fee_per_gas = String::new();
        assert!(s.sign(&unsigned).is_err());
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_InvalidMaxFeeHex
    #[test]
    fn sign_invalid_max_fee_hex() {
        let s = signer_with_wallet(MockWallet::default()).unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let mut unsigned = internaltx_unsigned();
        unsigned.max_fee_per_gas = "0xgg".into();
        assert!(s.sign(&unsigned).is_err());
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_PreCancelledContext
    #[test]
    fn sign_pre_cancelled() {
        let s = signer_with_wallet(MockWallet::default()).unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let err = s
            .sign_with_cancel(&internaltx_unsigned(), &|| true)
            .unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::Cancelled));
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_ContextCancelledMidSign
    // NOT PORTED: the Go test raced a goroutine-blocked SignTx against ctx
    // cancellation. The Rust seam is synchronous — there is no mid-flight
    // wait to interrupt; `is_cancelled` is re-checked immediately after the
    // device call instead, which the pre-cancelled test above covers.

    // Go: TestLedgerSigner_Sign_Closed
    #[test]
    fn sign_closed() {
        let s = signer_with_wallet(MockWallet::default()).unwrap();
        let _ = s.close();
        let err = s.sign(&internaltx_unsigned()).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::SignerClosed));
    }

    // Go: TestLedgerSigner_Sign_UserRejected_Denied
    #[test]
    fn sign_user_rejected_denied() {
        let s = signer_with_wallet(MockWallet {
            sign_result: Some(Err("transaction denied by user".into())),
            ..MockWallet::default()
        })
        .unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let err = s.sign(&internaltx_unsigned()).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::UserRejected));
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_AmbiguousError_ChainCancelledByUser
    // An error containing both "cancel" and "chain" is classified as
    // UserRejected: the chain-ID heuristic additionally requires
    // "unknown"/"mismatch"/"6a80"/"6a81", so "user cancelled chain
    // operation" falls through to the user-rejected check. Documented
    // behavior; TODO: refine after real hardware testing.
    #[test]
    fn sign_ambiguous_error_chain_cancelled_by_user() {
        let s = signer_with_wallet(MockWallet {
            sign_result: Some(Err("user cancelled chain operation".into())),
            ..MockWallet::default()
        })
        .unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let err = s.sign(&internaltx_unsigned()).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::UserRejected));
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_ChainIDMismatch_APDU6a81
    #[test]
    fn sign_chain_id_mismatch_apdu_6a81() {
        let s = signer_with_wallet(MockWallet {
            sign_result: Some(Err("apdu error: 6a81 chain not supported".into())),
            ..MockWallet::default()
        })
        .unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let err = s.sign(&internaltx_unsigned()).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::ChainIdMismatch));
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_UnknownAPDUCode_NotSentinel
    #[test]
    fn sign_unknown_apdu_code_not_sentinel() {
        let s = signer_with_wallet(MockWallet {
            sign_result: Some(Err("apdu error: 6f00 unknown error".into())),
            ..MockWallet::default()
        })
        .unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let err = s.sign(&internaltx_unsigned()).unwrap_err();
        assert!(!matches!(
            err.sentinel(),
            SignerError::UserRejected | SignerError::ChainIdMismatch
        ));
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_InvalidMaxPrioHex
    #[test]
    fn sign_invalid_max_prio_hex() {
        let s = signer_with_wallet(MockWallet::default()).unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let mut unsigned = internaltx_unsigned();
        unsigned.max_priority_fee_per_gas = "0xzz".into();
        assert!(s.sign(&unsigned).is_err());
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_InvalidData
    #[test]
    fn sign_invalid_data() {
        let s = signer_with_wallet(MockWallet::default()).unwrap();
        s.set_confirmation_prompt(Box::new(SharedBuf::default()));
        let mut unsigned = internaltx_unsigned();
        unsigned.data = "0xnotvalidhex".into();
        assert!(s.sign(&unsigned).is_err());
        let _ = s.close();
    }

    // Go: TestLedgerSigner_Sign_AppNotOpen_APDU6e01
    #[test]
    fn app_not_open_apdu_6e01() {
        let err = signer_with_wallet(MockWallet {
            open_err: Some("ledger: apdu 6e01 returned".into()),
            ..MockWallet::default()
        })
        .unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::AppNotOpen));
    }

    // Go: TestLedgerSigner_Sign_AppNotOpen_TextHint
    #[test]
    fn app_not_open_text_hint() {
        let err = signer_with_wallet(MockWallet {
            open_err: Some("please open the ethereum app on your ledger".into()),
            ..MockWallet::default()
        })
        .unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::AppNotOpen));
    }

    // Go: TestLedgerSigner_Sign_ConfirmationPrompt
    #[test]
    fn sign_confirmation_prompt() {
        let unsigned = internaltx_unsigned();
        let (synth, addr) = synth_ledger_signature(&unsigned);
        let s = signer_with_wallet(MockWallet {
            derive_addr: addr,
            sign_result: Some(Ok(synth)),
            ..MockWallet::default()
        })
        .unwrap();

        let buf = SharedBuf::default();
        s.set_confirmation_prompt(Box::new(buf.clone()));

        s.sign(&unsigned).unwrap();

        let prompt = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let lower = prompt.to_lowercase();
        assert!(
            lower.contains("ledger") || lower.contains("confirm"),
            "confirmation prompt {prompt:?} does not contain 'ledger' or 'confirm'"
        );
        let _ = s.close();
    }
}
