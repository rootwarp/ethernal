//! A thin, Ethereum-flavoured wrapper around the `blst` BLS12-381
//! implementation (the Go tree wraps herumi/bls-eth-go-binary; both implement
//! the same ETH ciphersuite, proven equivalent by the golden fixtures). It
//! exposes the [`Signer`] and [`Verifier`] traits used by the deposit
//! pipeline.
//!
//! Unlike herumi, blst requires no process-global initialisation; [`init`] is
//! kept as a no-op for call-site parity with the Go tree.

use blst::min_pk as blst_core;
use blst::BLST_ERROR;
use zeroize::Zeroize;

/// The domain separation tag of the ETH BLS signature ciphersuite
/// (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`), matching herumi's
/// `EthModeDraft07` used by the Go implementation.
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Errors from BLS key handling, signing, and verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlsError {
    /// The secret is not exactly 32 bytes.
    #[error("bls: secret must be 32 bytes, got {0}")]
    BadSecretLength(usize),

    /// The 32-byte secret is not a valid BLS12-381 scalar (zero or >= r).
    /// Mirrors Go's "bls: Deserialize" failure.
    #[error("bls: Deserialize: {0}")]
    BadSecret(String),

    /// The 48-byte pubkey is not a valid compressed G1 point in the subgroup.
    #[error("bls: invalid G1 point: {0}")]
    BadPubkey(String),

    /// The 96-byte signature is not a valid compressed G2 point.
    #[error("bls: deserialize signature: {0}")]
    BadSignature(String),
}

/// Can sign a 32-byte signing root and expose the corresponding 48-byte
/// compressed BLS public key. The underlying secret key is never accessible
/// after construction.
pub trait Signer {
    /// Hashes the signing root via the ETH BLS ciphersuite and returns the
    /// 96-byte compressed G2 signature.
    fn sign(&self, signing_root: [u8; 32]) -> Result<[u8; 96], BlsError>;

    /// Returns the compressed 48-byte G1 public key for this signer.
    fn public_key(&self) -> Result<[u8; 48], BlsError>;
}

/// Can verify a BLS signature against a public key and signing root.
/// It is stateless; a single instance may be used concurrently.
pub trait Verifier: Sync {
    /// Deserializes `pubkey` and `sig`, then verifies against `signing_root`.
    /// Returns `Ok(false)` on a valid but non-matching signature; only returns
    /// an error when the key or signature bytes are malformed.
    fn verify(
        &self,
        pubkey: [u8; 48],
        signing_root: [u8; 32],
        sig: [u8; 96],
    ) -> Result<bool, BlsError>;
}

/// No-op kept for call-site parity with the Go tree, where the herumi library
/// requires one-time process-global initialisation. blst needs none.
pub fn init() -> Result<(), BlsError> {
    Ok(())
}

/// The concrete [`Signer`] backed by a blst secret key.
///
/// blst's `SecretKey` zeroizes its scalar on drop.
pub struct BlsSigner {
    sk: blst_core::SecretKey,
}

/// Constructs a [`Signer`] from a 32-byte BLS secret.
///
/// `secret` must be the big-endian representation of the BLS12-381 scalar, as
/// produced by EIP-2333 key derivation and stored in EIP-2335 keystores.
/// The scalar must be less than the curve order r (EIP-2333 guarantees this).
///
/// The caller retains ownership of the secret slice and is responsible for
/// zeroizing it after this call returns. `new_signer` makes an internal copy,
/// loads it into blst, and immediately zeroizes the local copy — it never
/// modifies the caller's slice.
///
/// Returns an error if `secret.len() != 32` or blst rejects the key material.
pub fn new_signer(secret: &[u8]) -> Result<BlsSigner, BlsError> {
    if secret.len() != 32 {
        return Err(BlsError::BadSecretLength(secret.len()));
    }

    // Copy into a local buffer so we can zeroize it independently of the
    // caller's slice.
    let mut local_copy = [0u8; 32];
    local_copy.copy_from_slice(secret);

    let result = blst_core::SecretKey::from_bytes(&local_copy);
    local_copy.zeroize();

    match result {
        Ok(sk) => Ok(BlsSigner { sk }),
        Err(e) => Err(BlsError::BadSecret(format!("{e:?}"))),
    }
}

impl Signer for BlsSigner {
    fn sign(&self, signing_root: [u8; 32]) -> Result<[u8; 96], BlsError> {
        let sig = self.sk.sign(&signing_root, DST, &[]);
        Ok(sig.compress())
    }

    fn public_key(&self) -> Result<[u8; 48], BlsError> {
        Ok(self.sk.sk_to_pk().compress())
    }
}

/// The stateless concrete [`Verifier`].
#[derive(Debug, Clone, Copy, Default)]
pub struct BlsVerifier;

/// Returns a stateless [`Verifier`] backed by blst. Multiple calls always
/// return an equivalent instance; the result is safe to share.
pub fn default_verifier() -> BlsVerifier {
    BlsVerifier
}

impl Verifier for BlsVerifier {
    fn verify(
        &self,
        pubkey: [u8; 48],
        signing_root: [u8; 32],
        sig: [u8; 96],
    ) -> Result<bool, BlsError> {
        let pk = blst_core::PublicKey::key_validate(&pubkey)
            .map_err(|e| BlsError::BadPubkey(format!("{e:?}")))?;
        let s = blst_core::Signature::uncompress(&sig)
            .map_err(|e| BlsError::BadSignature(format!("{e:?}")))?;

        // sig_groupcheck=true: reject signatures outside the G2 subgroup, the
        // same strictness herumi applies in ETH mode.
        let err = s.verify(true, &signing_root, DST, &[], &pk, true);
        Ok(err == BLST_ERROR::BLST_SUCCESS)
    }
}

/// Checks that `pubkey` is a valid compressed BLS12-381 G1 point (on curve,
/// in the subgroup, not the identity). Returns `Ok(())` if valid.
pub fn validate_pubkey_bytes(pubkey: [u8; 48]) -> Result<(), BlsError> {
    blst_core::PublicKey::key_validate(&pubkey)
        .map(|_| ())
        .map_err(|e| BlsError::BadPubkey(format!("{e:?}")))
}
