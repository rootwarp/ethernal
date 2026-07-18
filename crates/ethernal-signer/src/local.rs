//! The `Signer` trait (ported from `go/internal/signer/signer.go`) and the
//! local raw-key signer (ported from `go/internal/signer/local.go`), plus
//! the shared secp256k1/Keccak helpers both signer implementations use
//! (the Go code delegated these to go-ethereum's `crypto` package).

use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};
use zeroize::{Zeroize, Zeroizing};

use ethernal_tx::UnsignedTx;

use crate::errors::SignerError;
use crate::parse::parse_unsigned_tx;
use crate::rlp;
use crate::types::SignedTx;

const LOCAL_SIGNER_NAME: &str = "local";

/// Abstracts the act of producing an EIP-1559 signature for an
/// `UnsignedTx`. Concrete implementations include [`LocalSigner`] (raw
/// private key from env var) and [`crate::LedgerSigner`] (hardware wallet,
/// behind the `ledger` cargo feature).
///
/// SECURITY CONTRACT: implementations MUST NOT log, persist, or otherwise
/// expose private key material. Errors returned to callers must not include
/// raw key bytes, partial signatures, or any sensitive material.
///
/// Cancellation: Go's `Sign(ctx, ...)` honored `context.Context`. The Rust
/// port takes an `is_cancelled` closure instead (the signer crate does not
/// depend on `ethernal_core`; the bin passes `|| token.is_cancelled()`).
/// Implementations check it between units of work; a cancelled sign returns
/// [`SignerError::Cancelled`].
pub trait Signer {
    /// Produces a `SignedTx` for the given unsigned transaction, checking
    /// `is_cancelled` between units of work (especially important for
    /// Ledger, where signing blocks on user confirmation).
    fn sign_with_cancel(
        &self,
        unsigned: &UnsignedTx,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<SignedTx, SignerError>;

    /// [`Signer::sign_with_cancel`] with a never-cancelled closure.
    fn sign(&self, unsigned: &UnsignedTx) -> Result<SignedTx, SignerError> {
        self.sign_with_cancel(unsigned, &|| false)
    }

    /// A short human-readable identifier for the signer ("local",
    /// "ledger") — used in logs and error messages, never sensitive.
    fn name(&self) -> &'static str;

    /// Reports whether sign blocks on a user action (e.g., pressing buttons
    /// on a Ledger). The CLI uses this to print "please confirm on device"
    /// messages.
    fn requires_user_interaction(&self) -> bool;

    /// Releases any resources held by the signer (HID handle for Ledger,
    /// zeroized key buffer for local). Idempotent.
    fn close(&self) -> Result<(), SignerError>;
}

/// Signs EIP-1559 transactions using a raw secp256k1 private key held in
/// memory. The key bytes are zeroized when [`Signer::close`] is called (and
/// on drop).
///
/// SECURITY: For development and CI only. Real-fund usage MUST use Ledger.
/// The key MUST come from a secure source (environment variable; see
/// [`new_local_signer_from_env`]). It MUST NEVER appear in argv or shell
/// history.
pub struct LocalSigner {
    /// 32-byte secp256k1 scalar; zeroized on close. Behind a `Mutex`
    /// because `close` takes `&self` (Go zeroized a slice in place).
    key: Mutex<[u8; 32]>,
    closed: AtomicBool,
}

/// Constructs a [`LocalSigner`] from a hex-encoded 32-byte private key
/// (with or without 0x prefix). Returns the `InvalidKey` sentinel for any
/// length/format/curve failure — no key material appears in the error.
///
/// Prefer [`new_local_signer_from_env`] in CLI code so the key never
/// appears in argv.
pub fn new_local_signer_from_hex(hex_key: &str) -> Result<LocalSigner, SignerError> {
    let stripped = hex_key.strip_prefix("0x").unwrap_or(hex_key);
    if stripped.len() != 64 {
        return Err(SignerError::context(
            "expected 32-byte (64 hex char) private key",
            SignerError::InvalidKey,
        ));
    }
    let decoded = Zeroizing::new(hex::decode(stripped).map_err(|_| {
        SignerError::context("private key is not valid hex", SignerError::InvalidKey)
    })?);
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    // Validate as secp256k1 scalar (rejects zero, values >= curve order, etc.).
    if SigningKey::from_slice(&key).is_err() {
        key.zeroize();
        return Err(SignerError::context(
            "invalid secp256k1 private key",
            SignerError::InvalidKey,
        ));
    }
    Ok(LocalSigner {
        key: Mutex::new(key),
        closed: AtomicBool::new(false),
    })
}

/// Reads a hex-encoded private key from the named environment variable and
/// constructs a [`LocalSigner`]. The variable is NOT cleared by this
/// constructor — callers should remove it after construction.
///
/// Only the variable NAME appears in errors; the value is never included.
pub fn new_local_signer_from_env(env_var: &str) -> Result<LocalSigner, SignerError> {
    let value = Zeroizing::new(std::env::var(env_var).unwrap_or_default());
    if value.is_empty() {
        return Err(SignerError::context(
            format!("environment variable {env_var:?} is not set or empty"),
            SignerError::InvalidKey,
        ));
    }
    new_local_signer_from_hex(&value).map_err(|_| {
        SignerError::context(
            format!("environment variable {env_var:?}"),
            SignerError::InvalidKey,
        )
    })
}

/// Derives the Ethereum address for a 32-byte secp256k1 secret.
///
/// Validates the scalar via `SigningKey::from_slice` (`0 < k < n`); returns
/// [`SignerError::InvalidKey`] for the zero scalar or any value `≥ n`. On
/// success returns the 20-byte address
/// `keccak256(uncompressed_pubkey[1..])[12..]`.
pub fn secret_to_address(secret: &[u8; 32]) -> Result<[u8; 20], SignerError> {
    let sk = SigningKey::from_slice(secret).map_err(|_| {
        SignerError::context("failed to parse signing key", SignerError::InvalidKey)
    })?;
    Ok(pubkey_address(sk.verifying_key()))
}

impl LocalSigner {
    /// Derives the Ethereum address for the in-memory signing key.
    /// It is defined on the concrete `LocalSigner` only, deliberately NOT
    /// on the [`Signer`] trait, so a hardware signer (Ledger) is never
    /// forced to expose an address without a connected device.
    pub fn address(&self) -> Result<[u8; 20], SignerError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(SignerError::SignerClosed);
        }
        let key = self.key.lock().unwrap();
        secret_to_address(&key)
    }
}

impl Signer for LocalSigner {
    /// Produces a signed EIP-1559 transaction for the given unsigned tx.
    /// `is_cancelled` is checked upfront; local signing is fast but the
    /// check ensures callers that pre-cancel don't get a spurious success.
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

        let sk = {
            let key = self.key.lock().unwrap();
            SigningKey::from_slice(&*key).map_err(|_| {
                SignerError::context("failed to parse signing key", SignerError::InvalidKey)
            })?
        };

        let payload = rlp::eip1559_signing_payload(&p, unsigned.nonce, unsigned.gas);
        let sighash = keccak256(&payload);

        // RFC6979 deterministic recoverable signature, then explicit low-s
        // normalization (flipping the recovery parity when s is negated) —
        // matching geth/libsecp256k1's canonical output.
        let (sig, recid) = sk
            .sign_prehash_recoverable(&sighash)
            .map_err(|e| SignerError::Msg(format!("SignTx: {e}")))?;
        let (sig, y_parity) = normalize_low_s(sig, recid);
        let r: [u8; 32] = sig.r().to_bytes().into();
        let s: [u8; 32] = sig.s().to_bytes().into();

        // Sender recovery + self-check against the key's own address.
        let from = recover_address(&sighash, &r, &s, y_parity)
            .map_err(|e| SignerError::Msg(format!("sender recovery failed: {e}")))?;
        let expected = pubkey_address(sk.verifying_key());
        if from != expected {
            return Err(SignerError::Msg(format!(
                "recovered sender {} does not match key address {}",
                eip55_checksum(&from),
                eip55_checksum(&expected)
            )));
        }

        // The EIP-2718 envelope: 0x02 || rlp(...) — what
        // eth_sendRawTransaction expects for type-2 transactions.
        let envelope = rlp::eip1559_envelope(&p, unsigned.nonce, unsigned.gas, y_parity, &r, &s);

        Ok(build_signed_tx(
            unsigned, &from, &envelope, &r, &s, y_parity,
        ))
    }

    fn name(&self) -> &'static str {
        LOCAL_SIGNER_NAME
    }

    fn requires_user_interaction(&self) -> bool {
        false
    }

    /// Zeroizes the in-memory key bytes. Subsequent sign calls return
    /// `SignerClosed`. Idempotent.
    fn close(&self) -> Result<(), SignerError> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.key.lock().unwrap().zeroize();
        Ok(())
    }
}

impl Drop for LocalSigner {
    fn drop(&mut self) {
        if let Ok(key) = self.key.get_mut() {
            key.zeroize();
        }
    }
}

/// Manual `Debug` so key material can never leak through formatting.
impl std::fmt::Debug for LocalSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSigner")
            .field("closed", &self.closed.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

// --- Shared signing helpers (Go used go-ethereum's crypto package) ---

/// Keccak-256 of `data`.
pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// The Ethereum address of a public key:
/// `keccak256(uncompressed_pubkey[1..])[12..]`.
pub(crate) fn pubkey_address(vk: &VerifyingKey) -> [u8; 20] {
    let point = vk.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// Ensures the signature is low-s (EIP-2 canonical form), flipping the
/// recovery parity when s is negated. Returns the (possibly normalized)
/// signature and the y-parity bit.
fn normalize_low_s(sig: Signature, recid: RecoveryId) -> (Signature, u8) {
    match sig.normalize_s() {
        Some(low) => (low, u8::from(!recid.is_y_odd())),
        None => (sig, u8::from(recid.is_y_odd())),
    }
}

/// Recovers the signer's address from a signature over `sighash`
/// (go-ethereum `types.Sender` equivalent). The error string is embedded
/// into a `"sender recovery failed: ..."` message by callers.
pub(crate) fn recover_address(
    sighash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    y_parity: u8,
) -> Result<[u8; 20], String> {
    let sig = Signature::from_scalars(*r, *s).map_err(|e| e.to_string())?;
    let recid = RecoveryId::from_byte(y_parity).ok_or_else(|| "invalid recovery id".to_string())?;
    let vk = VerifyingKey::recover_from_prehash(sighash, &sig, recid).map_err(|e| e.to_string())?;
    Ok(pubkey_address(&vk))
}

/// EIP-55 checksummed 0x-prefixed address string (go-ethereum
/// `common.Address.Hex()` equivalent).
pub fn eip55_checksum(addr: &[u8; 20]) -> String {
    let lower = hex::encode(addr);
    let hash = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
        if c.is_ascii_alphabetic() && nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Renders a big-endian byte quantity like Go's `"0x" + big.Int.Text(16)`:
/// lowercase hex without leading zeros; `"0x0"` for zero.
pub(crate) fn hex_quantity(b: &[u8]) -> String {
    let first = b.iter().position(|&x| x != 0);
    match first {
        None => "0x0".to_string(),
        Some(i) => {
            let mut out = format!("0x{:x}", b[i]);
            for byte in &b[i + 1..] {
                let _ = write!(out, "{byte:02x}");
            }
            out
        }
    }
}

/// Assembles the `SignedTx` wire struct shared by the local and Ledger
/// signers: keccak tx hash, 0x-hex envelope, big-int-text r/s and decimal
/// y-parity v.
pub(crate) fn build_signed_tx(
    unsigned: &UnsignedTx,
    from: &[u8; 20],
    envelope: &[u8],
    r: &[u8; 32],
    s: &[u8; 32],
    y_parity: u8,
) -> SignedTx {
    SignedTx {
        unsigned: unsigned.clone(),
        from: eip55_checksum(from),
        hash: format!("0x{}", hex::encode(keccak256(envelope))),
        r: hex_quantity(r),
        s: hex_quantity(s),
        v: y_parity.to_string(), // decimal "0" or "1" for EIP-1559 y-parity
        raw_rlp: format!("0x{}", hex::encode(envelope)),
    }
}

/// A valid deterministic test key (well below the curve order), shared by
/// the local and ledger test suites. Go tests used
/// `gethcrypto.GenerateKey()`; the port uses a fixed key so the crate needs
/// no RNG dependency.
#[cfg(test)]
pub(crate) const TEST_KEY_HEX: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";

#[cfg(test)]
mod tests {
    use super::*;

    fn local_unsigned() -> UnsignedTx {
        UnsignedTx {
            chain_id: 17000,
            to: "0x4242424242424242424242424242424242424242".into(),
            value: "0x1bc16d674ec800000".into(),
            max_fee_per_gas: "0x4a817c800".into(),
            max_priority_fee_per_gas: "0x3b9aca00".into(),
            gas: 250000,
            tx_type: "0x2".into(),
            ..UnsignedTx::default()
        }
    }

    fn new_local_signer() -> LocalSigner {
        new_local_signer_from_hex(TEST_KEY_HEX).expect("test key must be valid")
    }

    // Go: TestLocalSigner_Sign_InvalidValue
    #[test]
    fn sign_invalid_value() {
        let s = new_local_signer();
        let mut unsigned = local_unsigned();
        unsigned.value = "0xgg".into();
        assert!(s.sign(&unsigned).is_err());
        let _ = s.close();
    }

    // Go: TestLocalSigner_Sign_InvalidData
    #[test]
    fn sign_invalid_data() {
        let s = new_local_signer();
        let mut unsigned = local_unsigned();
        unsigned.data = "0xnotvalidhex".into();
        assert!(s.sign(&unsigned).is_err());
        let _ = s.close();
    }

    // Go: TestLocalSigner_Sign_PreCancelledContext
    #[test]
    fn sign_pre_cancelled() {
        let s = new_local_signer();
        let err = s.sign_with_cancel(&local_unsigned(), &|| true).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::Cancelled));
        let _ = s.close();
    }

    // Go: TestLocalSigner_Sign_Closed
    #[test]
    fn sign_closed() {
        let s = new_local_signer();
        let _ = s.close();
        let err = s.sign(&local_unsigned()).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::SignerClosed));
    }

    // Go: TestNewLocalSignerFromEnv_BadKeyValue
    #[test]
    fn from_env_bad_key_value() {
        std::env::set_var("TEST_ENV_BADKEY_RS", "0xdeadbeefnotvalidhex");
        let err = new_local_signer_from_env("TEST_ENV_BADKEY_RS").unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::InvalidKey));
        // Error must mention the var name but not the key value.
        let msg = err.to_string();
        assert!(
            msg.contains("TEST_ENV_BADKEY_RS"),
            "missing var name: {msg}"
        );
        assert!(!msg.contains("deadbeef"), "leaks key material: {msg}");
        assert_eq!(
            msg,
            "environment variable \"TEST_ENV_BADKEY_RS\": invalid private key"
        );
        std::env::remove_var("TEST_ENV_BADKEY_RS");
    }

    // Go: TestLocalSigner_Address_InvalidKey
    // White-box: a signer holding a non-canonical (all-zero) scalar cannot
    // arise via the validating constructors, but address() must still
    // surface InvalidKey rather than panic on the parse failure.
    #[test]
    fn address_invalid_key() {
        let s = LocalSigner {
            key: Mutex::new([0u8; 32]),
            closed: AtomicBool::new(false),
        };
        let err = s.address().unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::InvalidKey));
    }

    // Go: TestLocalSigner_Close_ZeroizesKey
    #[test]
    fn close_zeroizes_key() {
        let s = new_local_signer();
        s.close().unwrap();
        let key = s.key.lock().unwrap();
        assert_eq!(*key, [0u8; 32], "key not zeroized after close");
    }

    // Rust-only: exact error message parity for the wrapped constructor errors.
    #[test]
    fn constructor_error_messages_match_go() {
        let err = new_local_signer_from_hex("ab").unwrap_err();
        assert_eq!(
            err.to_string(),
            "expected 32-byte (64 hex char) private key: invalid private key"
        );
        let err = new_local_signer_from_hex(&"z".repeat(64)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "private key is not valid hex: invalid private key"
        );
        let err = new_local_signer_from_hex(&"0".repeat(64)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid secp256k1 private key: invalid private key"
        );
    }

    // Rust-only: EIP-55 helper against the known address of the test key
    // (documented in rust/testdata/phase3/holesky/README.md).
    #[test]
    fn eip55_checksum_known_address() {
        let s = new_local_signer();
        let addr = s.address().unwrap();
        assert_eq!(
            eip55_checksum(&addr),
            "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1"
        );
        let _ = s.close();
    }

    // A3-1: Ethereum BIP-44 abandon vectors (cast wallet ground truth).
    // Path m/44'/60'/0'/0/0 and …/0/1, empty passphrase; see
    // docs/plan/eoa-keystore/research/bip32-secp256k1.md.
    #[test]
    fn secret_to_address_abandon_bip44_vectors() {
        let cases: [(&str, &str); 2] = [
            (
                "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
                "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            ),
            (
                "9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6",
                "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0",
            ),
        ];
        for (secret_hex, want_eip55) in cases {
            let mut secret = [0u8; 32];
            hex::decode_to_slice(secret_hex, &mut secret).expect("fixture hex");
            let addr = secret_to_address(&secret).expect("canonical secret");
            assert_eq!(eip55_checksum(&addr), want_eip55, "secret {secret_hex}");
        }
    }

    // A3-1: non-canonical scalars (zero and ≥ n) → InvalidKey.
    #[test]
    fn secret_to_address_rejects_non_canonical() {
        // Zero scalar.
        let err = secret_to_address(&[0u8; 32]).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::InvalidKey));

        // secp256k1 order n (exactly n is invalid: need 0 < k < n).
        // n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        let mut ge_n = [0u8; 32];
        ge_n.copy_from_slice(&n);
        let err = secret_to_address(&ge_n).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::InvalidKey));

        // All-0xff is well above n.
        let err = secret_to_address(&[0xffu8; 32]).unwrap_err();
        assert!(matches!(err.sentinel(), SignerError::InvalidKey));
    }

    // A3-1: LocalSigner::address and secret_to_address agree for a known key.
    #[test]
    fn address_delegates_to_secret_to_address() {
        let s = new_local_signer();
        let via_signer = s.address().unwrap();
        let mut secret = [0u8; 32];
        hex::decode_to_slice(TEST_KEY_HEX, &mut secret).unwrap();
        let via_fn = secret_to_address(&secret).unwrap();
        assert_eq!(via_signer, via_fn);
        assert_eq!(
            eip55_checksum(&via_fn),
            "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1"
        );
        let _ = s.close();
    }

    // Rust-only: big.Int.Text(16) rendering semantics.
    #[test]
    fn hex_quantity_semantics() {
        assert_eq!(hex_quantity(&[0, 0, 0]), "0x0");
        assert_eq!(hex_quantity(&[]), "0x0");
        assert_eq!(hex_quantity(&[0x01]), "0x1");
        assert_eq!(hex_quantity(&[0x00, 0x0f, 0x20]), "0xf20");
        assert_eq!(hex_quantity(&[0xab, 0xcd]), "0xabcd");
    }
}
