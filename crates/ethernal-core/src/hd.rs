//! EIP-2333 / EIP-2334 hierarchical derivation via `blst`.
//!
//! Thin wrapper over `blst::min_pk::SecretKey::{derive_master_eip2333,
//! derive_child_eip2333}`. No hand-rolled HKDF/Lamport tree. Gated by the four
//! official EIP-2333 vectors (see `research/eip-2333-2334.md`).

use blst::min_pk as blst_core;
use zeroize::Zeroizing;

/// Errors from EIP-2333 master derivation (crypto → exit 3).
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum HdError {
    /// `derive_master_eip2333` rejected the IKM (e.g. shorter than 32 bytes).
    #[error("hd: derive master: {0}")]
    Master(String),
}

/// An EIP-2334 derivation path as an ordered list of child indices after `m`.
///
/// - Signing:    `m/12381/3600/<i>/0/0`
/// - Withdrawal: `m/12381/3600/<i>/0`
///
/// `withdrawal(i)` is derived for E2E honesty but unused by v1 credentials
/// (0x00 withdrawal credentials are deferred; only the signing key is written).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPath(Vec<u32>);

impl KeyPath {
    /// Signing key path: `m/12381/3600/<index>/0/0`.
    pub fn signing(index: u32) -> Self {
        Self(vec![12381, 3600, index, 0, 0])
    }

    /// Withdrawal key path: `m/12381/3600/<index>/0`.
    ///
    /// Derived for E2E honesty against ethstaker-deposit-cli but unused by v1
    /// credentials (0x00 deferred). Kept so path coverage stays complete.
    pub fn withdrawal(index: u32) -> Self {
        Self(vec![12381, 3600, index, 0])
    }

    /// Returns the child-index sequence after `m`.
    pub fn indices(&self) -> &[u32] {
        &self.0
    }
}

impl std::fmt::Display for KeyPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "m")?;
        for i in &self.0 {
            write!(f, "/{i}")?;
        }
        Ok(())
    }
}

/// Opaque EIP-2333 secret key wrapping `blst::min_pk::SecretKey`
/// (self-zeroizes its scalar on drop).
pub struct DerivedSk(blst_core::SecretKey);

impl DerivedSk {
    /// 32-byte big-endian scalar. Feeds `bls::new_signer` and keystore encrypt.
    /// Zeroized on drop.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// Compressed 48-byte G1 public key (keystore `pubkey` field).
    ///
    /// Equivalent to `bls::new_signer(self.to_bytes()).public_key()` for a
    /// derived key — both use `sk_to_pk` → compress.
    pub fn public_key(&self) -> [u8; 48] {
        self.0.sk_to_pk().compress()
    }
}

/// Derives the master secret key from a BIP-39 seed (or any IKM ≥ 32 bytes).
///
/// Wraps `blst::min_pk::SecretKey::derive_master_eip2333`. Propagates the
/// `Result` (blst enforces a 32-byte minimum IKM in Rust); a 64-byte BIP-39
/// seed never trips that guard.
pub fn derive_master(seed: &[u8]) -> Result<DerivedSk, HdError> {
    blst_core::SecretKey::derive_master_eip2333(seed)
        .map(DerivedSk)
        .map_err(|e| HdError::Master(format!("{e:?}")))
}

/// Derives a child secret key at `index` (infallible per EIP-2333 / blst).
pub fn derive_child(parent: &DerivedSk, index: u32) -> DerivedSk {
    DerivedSk(parent.0.derive_child_eip2333(index))
}

/// Derives the key at `path` by folding `derive_child` over the master key.
pub fn derive_path(seed: &[u8], path: &KeyPath) -> Result<DerivedSk, HdError> {
    let mut sk = derive_master(seed)?;
    for &index in path.indices() {
        sk = derive_child(&sk, index);
    }
    Ok(sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::{new_signer, Signer};

    /// Official EIP-2333 vectors: (seed_hex, master_sk_hex, child_index, child_sk_hex).
    const EIP2333_VECTORS: &[(&str, &str, u32, &str)] = &[
        (
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            "0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070",
            0,
            "2d18bd6c14e6d15bf8b5085c9b74f3daae3b03cc2014770a599d8c1539e50f8e",
        ),
        (
            // Case 1 seed is decimal digits encoded as a hex string (not a number).
            "3141592653589793238462643383279502884197169399375105820974944592",
            "41c9e07822b092a93fd6797396338c3ada4170cc81829fdfce6b5d34bd5e7ec7",
            3141592653,
            "384843fad5f3d777ea39de3e47a8f999ae91f89e42bffa993d91d9782d152a0f",
        ),
        (
            "0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
            "3cfa341ab3910a7d00d933d8f7c4fe87c91798a0397421d6b19fd5b815132e80",
            4294967295,
            "40e86285582f35b28821340f6a53b448588efa575bc4d88c32ef8567b8d9479b",
        ),
        (
            "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
            "2a0e28ffa5fbbe2f8e7aad4ed94f745d6bf755c51182e119bb1694fe61d3afca",
            42,
            "455c0dc9fccb3395825d92a60d2672d69416be1c2578a87a7a3d3ced11ebb88d",
        ),
    ];

    fn decode_hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap_or_else(|e| panic!("hex decode {s:?}: {e}"))
    }

    #[test]
    fn eip2333_four_vectors() {
        for (i, (seed_hex, master_hex, child_index, child_hex)) in
            EIP2333_VECTORS.iter().enumerate()
        {
            let seed = decode_hex(seed_hex);
            let master = derive_master(&seed).unwrap_or_else(|e| {
                panic!("case {i}: derive_master failed: {e}");
            });
            assert_eq!(
                hex::encode(master.to_bytes().as_slice()),
                *master_hex,
                "case {i}: master SK mismatch"
            );
            let child = derive_child(&master, *child_index);
            assert_eq!(
                hex::encode(child.to_bytes().as_slice()),
                *child_hex,
                "case {i}: child SK mismatch"
            );
        }
    }

    #[test]
    fn keypath_to_string() {
        assert_eq!(KeyPath::signing(0).to_string(), "m/12381/3600/0/0/0");
        assert_eq!(KeyPath::signing(7).to_string(), "m/12381/3600/7/0/0");
        assert_eq!(KeyPath::withdrawal(0).to_string(), "m/12381/3600/0/0");
        assert_eq!(KeyPath::withdrawal(42).to_string(), "m/12381/3600/42/0");
    }

    #[test]
    fn derive_path_signing_case0() {
        let seed = decode_hex(EIP2333_VECTORS[0].0);
        // signing(0) = master → 12381 → 3600 → 0 → 0 → 0
        let sk = derive_path(&seed, &KeyPath::signing(0)).unwrap();
        // Just assert stability: re-deriving yields the same bytes.
        let sk2 = derive_path(&seed, &KeyPath::signing(0)).unwrap();
        assert_eq!(sk.to_bytes().as_slice(), sk2.to_bytes().as_slice());

        // Manual fold matches derive_path.
        let mut manual = derive_master(&seed).unwrap();
        for idx in [12381u32, 3600, 0, 0, 0] {
            manual = derive_child(&manual, idx);
        }
        assert_eq!(sk.to_bytes().as_slice(), manual.to_bytes().as_slice());
    }

    #[test]
    fn public_key_matches_bls_signer() {
        let seed = decode_hex(EIP2333_VECTORS[0].0);
        let derived = derive_master(&seed).unwrap();
        let pk_hd = derived.public_key();
        let signer = new_signer(derived.to_bytes().as_slice()).unwrap();
        let pk_bls = signer.public_key().unwrap();
        assert_eq!(pk_hd, pk_bls);
    }

    #[test]
    fn derive_master_rejects_short_ikm() {
        match derive_master(&[0u8; 16]) {
            Err(HdError::Master(_)) => {}
            Ok(_) => panic!("expected HdError::Master for short IKM"),
        }
    }
}
