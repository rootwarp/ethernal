//! Hand-rolled BIP-32 secp256k1 hierarchical derivation over `k256`.
//!
//! Pure module: master key from seed, single-step CKDpriv (hardened +
//! non-hardened), fixed BIP-44 Ethereum path model, and path fold.
//! Gated by BIP-32 official Test Vector 1 (keys **and** chain codes) and the
//! Ethereum BIP-44 `abandon…about` secret vector (empty passphrase vs `cast`).
//!
//! # S-1 zeroization — R1 decision: **scalar scrubbed on drop**
//!
//! `k256` 0.13.4 has **no** separate `zeroize` cargo feature (confirmed against
//! the crate feature list). `Scalar` implements [`Zeroize`] unconditionally via
//! `DefaultIsZeroes`, so `ExtendedPrivKey::drop` calls `self.scalar.zeroize()`.
//! Every chain code is [`Zeroizing`]; [`ExtendedPrivKey::secret_bytes`] returns
//! `Zeroizing`; the HMAC-SHA512 output `I` is scrubbed after the `I_L`/`I_R`
//! split.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, ProjectivePoint, Scalar};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;

/// BIP-32 hardened-index offset (`2³¹`).
const HARDENED: u32 = 0x8000_0000;

/// HMAC key for BIP-32 master derivation (ASCII literal, 12 bytes).
const BITCOIN_SEED: &[u8] = b"Bitcoin seed";

/// Errors from BIP-32 master / child derivation (crypto → exit 3).
///
/// Messages never embed key or chain-code bytes (S-2).
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Bip32Error {
    /// Master key rejected (`I_L ≥ n` or `I_L == 0`).
    #[error("bip32: derive master: {0}")]
    Master(String),

    /// Child at `index` rejected (`I_L ≥ n` or resulting `k_i == 0`).
    #[error("bip32: invalid child key at index {0} (I_L ≥ n or k_i = 0)")]
    InvalidChildKey(u32),
}

/// A BIP-44 Ethereum account path: `m/44'/60'/0'/0/<address_index>` (F-2).
///
/// `account'` is fixed at `0'`; only `address_index` varies (PRD F-2 /
/// MetaMask "Account i"). Path strings are public and safe to log (S-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip44Path([u32; 5]);

impl Bip44Path {
    /// EOA path for MetaMask-style account `address_index`.
    ///
    /// Indices: `[44|H, 60|H, 0|H, 0, address_index]` with `H = 2³¹`.
    pub fn eoa(address_index: u32) -> Self {
        // account' is fixed at 0' (== HARDENED); only address_index varies (F-2).
        Self([44 | HARDENED, 60 | HARDENED, HARDENED, 0, address_index])
    }

    /// Child-index sequence after `m` (five levels).
    pub fn indices(&self) -> &[u32] {
        &self.0
    }
}

impl std::fmt::Display for Bip44Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Fixed prefix; only the final address_index varies.
        write!(f, "m/44'/60'/0'/0/{}", self.0[4])
    }
}

/// An extended private key: secret scalar + 32-byte chain code.
///
/// Not `Copy`. Chain codes are secret-equivalent (they permit non-hardened
/// sibling derivation) and are zeroized like keys (S-1). `Drop` scrubs the
/// live scalar (R1: scalar scrubbed on drop).
pub struct ExtendedPrivKey {
    scalar: Scalar,
    chain_code: Zeroizing<[u8; 32]>,
}

impl Drop for ExtendedPrivKey {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

impl ExtendedPrivKey {
    /// Master key from seed: `I = HMAC-SHA512("Bitcoin seed", seed)`;
    /// `k = parse256(I[..32])`, `c = I[32..]`.
    ///
    /// Rejects `I_L ≥ n` (`Scalar::from_repr` → `None`) or `I_L == 0`.
    /// Seed is typically the 64-byte BIP-39 seed from `core::bip39::to_seed`.
    pub fn master(seed: &[u8]) -> Result<Self, Bip32Error> {
        let mut mac =
            HmacSha512::new_from_slice(BITCOIN_SEED).expect("HMAC-SHA512 accepts any key length");
        mac.update(seed);
        let mut i = Zeroizing::new(mac.finalize().into_bytes());

        // S-1: both halves Zeroizing from the split; full I scrubbed after copy.
        let mut il = Zeroizing::new([0u8; 32]);
        let mut ir = Zeroizing::new([0u8; 32]);
        il.copy_from_slice(&i[..32]);
        ir.copy_from_slice(&i[32..]);
        i.zeroize();

        // `ir` moves in (Ok → chain_code; Err → Zeroizing drop); `il` drops Zeroizing.
        Self::from_master_halves(&il, ir)
    }

    /// CKDpriv at `index`.
    ///
    /// - **Hardened** (`index ≥ 2³¹`): `data = 0x00 ‖ ser256(k_par) ‖ ser32(i)`
    /// - **Non-hardened**: `data = serP(point(k_par)) ‖ ser32(i)` (33-byte
    ///   compressed parent pubkey)
    ///
    /// `k_i = parse256(I_L) + k_par (mod n)`; rejects `I_L ≥ n` or `k_i == 0`
    /// (BIP-32 skip rule as a `Result` rejection). `c_i = I_R`.
    pub fn derive_child(&self, index: u32) -> Result<Self, Bip32Error> {
        // Both branches produce a 37-byte HMAC message.
        let mut data = Zeroizing::new([0u8; 37]);
        if index >= HARDENED {
            data[0] = 0x00;
            let mut sk = self.scalar.to_bytes();
            data[1..33].copy_from_slice(&sk);
            sk.zeroize();
        } else {
            let point = (ProjectivePoint::GENERATOR * self.scalar).to_affine();
            let encoded = point.to_encoded_point(true);
            let bytes = encoded.as_bytes();
            debug_assert_eq!(bytes.len(), 33, "compressed secp256k1 pubkey is 33 bytes");
            data[..33].copy_from_slice(bytes);
        }
        data[33..37].copy_from_slice(&index.to_be_bytes());

        let mut mac = HmacSha512::new_from_slice(self.chain_code.as_slice())
            .expect("HMAC-SHA512 accepts 32-byte key");
        mac.update(data.as_slice());
        data.zeroize();

        let mut i = Zeroizing::new(mac.finalize().into_bytes());
        let mut il = Zeroizing::new([0u8; 32]);
        let mut ir = Zeroizing::new([0u8; 32]);
        il.copy_from_slice(&i[..32]);
        ir.copy_from_slice(&i[32..]);
        i.zeroize();

        self.child_from_halves(index, &il, ir)
    }

    /// Folds [`derive_child`](Self::derive_child) over [`master`](Self::master)
    /// for the five BIP-44 path indices (F-2).
    ///
    /// Mixes both CKDpriv branches: `44'/60'/0'` hardened, then `0/i`
    /// non-hardened.
    pub fn derive_path(seed: &[u8], path: &Bip44Path) -> Result<Self, Bip32Error> {
        let mut key = Self::master(seed)?;
        for &index in path.indices() {
            key = key.derive_child(index)?;
        }
        Ok(key)
    }

    /// 32-byte big-endian secret scalar. Feeds signer / keystore encrypt.
    /// Zeroized on drop.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut bytes = self.scalar.to_bytes();
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&bytes);
        // FieldBytes is Zeroize but not ZeroizeOnDrop — scrub the stack temp.
        bytes.zeroize();
        out
    }

    /// Assemble master from already-split `I_L`/`I_R` (also used by negative tests).
    ///
    /// `ir` is `Zeroizing`: moved into `chain_code` on Ok, scrubbed on Err drop.
    fn from_master_halves(il: &[u8; 32], ir: Zeroizing<[u8; 32]>) -> Result<Self, Bip32Error> {
        let scalar = parse_scalar_nonzero(il)
            .ok_or_else(|| Bip32Error::Master("I_L is zero or ≥ n".to_owned()))?;
        Ok(Self {
            scalar,
            chain_code: ir,
        })
    }

    /// Assemble child from already-split `I_L`/`I_R` at `index`.
    ///
    /// `ir` is `Zeroizing`: moved into `chain_code` on Ok, scrubbed on Err drop.
    /// Intermediate scalars (`I_L`, `k_i`) are scrubbed explicitly (`Scalar` is
    /// `Copy` + `Zeroize` but not `ZeroizeOnDrop`).
    fn child_from_halves(
        &self,
        index: u32,
        il: &[u8; 32],
        ir: Zeroizing<[u8; 32]>,
    ) -> Result<Self, Bip32Error> {
        // Child: reject I_L ≥ n only at parse; I_L == 0 is fine if k_i ≠ 0.
        let mut il_scalar = parse_scalar(il).ok_or(Bip32Error::InvalidChildKey(index))?;
        let mut child_key = il_scalar + self.scalar;
        il_scalar.zeroize();
        if bool::from(child_key.is_zero()) {
            child_key.zeroize();
            return Err(Bip32Error::InvalidChildKey(index));
        }
        Ok(Self {
            scalar: child_key,
            chain_code: ir,
        })
    }
}

/// Parse 32 BE bytes as a scalar; `None` iff `≥ n` (or otherwise invalid repr).
fn parse_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    // FieldBytes::from([u8;32]) avoids the deprecated GenericArray::from_slice.
    let fb = FieldBytes::from(*bytes);
    Scalar::from_repr(fb).into()
}

/// Parse and also reject the zero scalar (master-key validity).
fn parse_scalar_nonzero(bytes: &[u8; 32]) -> Option<Scalar> {
    let s = parse_scalar(bytes)?;
    if bool::from(s.is_zero()) {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP-32 Test Vector 1: (path label, seed_hex, steps as child indices,
    /// expected private key hex, expected chain code hex).
    ///
    /// Source: docs/plan/eoa-keystore/research/bip32-secp256k1.md
    /// (base58-decoded from official xprv, checksum-verified).
    struct Tv1Row {
        label: &'static str,
        /// Child indices after master (empty = master only).
        indices: &'static [u32],
        privkey: &'static str,
        chain_code: &'static str,
    }

    const TV1_SEED: &str = "000102030405060708090a0b0c0d0e0f";

    const TV1: &[Tv1Row] = &[
        Tv1Row {
            label: "m",
            indices: &[],
            privkey: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
            chain_code: "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        },
        Tv1Row {
            label: "m/0'",
            indices: &[HARDENED], // 0'
            privkey: "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
            chain_code: "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
        },
        Tv1Row {
            label: "m/0'/1",
            indices: &[HARDENED, 1], // 0' then non-hardened 1
            privkey: "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
            chain_code: "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
        },
    ];

    fn decode_hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap_or_else(|e| panic!("hex decode {s:?}: {e}"))
    }

    fn derive_tv1(indices: &[u32]) -> ExtendedPrivKey {
        let seed = decode_hex(TV1_SEED);
        let mut key = ExtendedPrivKey::master(&seed).expect("TV1 master");
        for &i in indices {
            key = key
                .derive_child(i)
                .unwrap_or_else(|e| panic!("derive_child({i}): {e}"));
        }
        key
    }

    #[test]
    fn bip32_tv1_keys_and_chain_codes() {
        for row in TV1 {
            let key = derive_tv1(row.indices);
            assert_eq!(
                hex::encode(key.secret_bytes().as_slice()),
                row.privkey,
                "{}: private key mismatch",
                row.label
            );
            assert_eq!(
                hex::encode(key.chain_code.as_slice()),
                row.chain_code,
                "{}: chain code mismatch",
                row.label
            );
        }
    }

    #[test]
    fn non_hardened_uses_compressed_pubkey_path() {
        // m/0'/1 is the non-hardened step; matching TV1 proves the 33-byte
        // compressed parent-pubkey HMAC data path is correct.
        let key = derive_tv1(&[HARDENED, 1]);
        assert_eq!(
            hex::encode(key.secret_bytes().as_slice()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
    }

    #[test]
    fn master_rejects_il_ge_n_and_zero() {
        // All 0xFF ≥ secp256k1 order n.
        match ExtendedPrivKey::from_master_halves(&[0xff; 32], Zeroizing::new([0u8; 32])) {
            Err(Bip32Error::Master(msg)) => {
                assert!(!msg.contains("ff"), "must not embed I_L bytes");
            }
            Ok(_) => panic!("expected Master for I_L ≥ n"),
            Err(e) => panic!("expected Master for I_L ≥ n, got {e}"),
        }
        // I_L == 0.
        match ExtendedPrivKey::from_master_halves(&[0u8; 32], Zeroizing::new([0u8; 32])) {
            Err(Bip32Error::Master(_)) => {}
            Ok(_) => panic!("expected Master for I_L == 0"),
            Err(e) => panic!("expected Master for I_L == 0, got {e}"),
        }
        // Valid TV1 master I_L is accepted.
        let il = decode_hex("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&il);
        assert!(ExtendedPrivKey::from_master_halves(&arr, Zeroizing::new([0u8; 32])).is_ok());
    }

    #[test]
    fn derive_child_rejects_il_ge_n_and_ki_zero() {
        let parent = derive_tv1(&[]);
        let index = 42u32;

        // I_L ≥ n → InvalidChildKey(index).
        match parent.child_from_halves(index, &[0xff; 32], Zeroizing::new([0u8; 32])) {
            Err(Bip32Error::InvalidChildKey(i)) => assert_eq!(i, index),
            Ok(_) => panic!("expected InvalidChildKey for I_L ≥ n"),
            Err(e) => panic!("expected InvalidChildKey for I_L ≥ n, got {e}"),
        }

        // k_i = 0 when I_L = -k_par → InvalidChildKey(index).
        let mut neg = -parent.scalar;
        let mut neg_bytes = neg.to_bytes();
        neg.zeroize();
        let mut il = [0u8; 32];
        il.copy_from_slice(&neg_bytes);
        neg_bytes.zeroize();
        match parent.child_from_halves(index, &il, Zeroizing::new([0u8; 32])) {
            Err(Bip32Error::InvalidChildKey(i)) => assert_eq!(i, index),
            Ok(_) => panic!("expected InvalidChildKey for k_i == 0"),
            Err(e) => panic!("expected InvalidChildKey for k_i == 0, got {e}"),
        }
        il.zeroize();
    }

    #[test]
    fn bip32_error_messages_embed_no_key_bytes() {
        let master_err = Bip32Error::Master("I_L is zero or ≥ n".to_owned());
        let child_err = Bip32Error::InvalidChildKey(0x8000_0000);
        let master_s = master_err.to_string();
        let child_s = child_err.to_string();

        // Discriminating anchors from TV1 must not appear in error text.
        for leak in [
            "e8f32e72", "edb2e14f", "3c6cb8d0", "873dff81", "47fdacbd", "2a785763",
        ] {
            assert!(
                !master_s.contains(leak),
                "Master error leaked key material: {master_s}"
            );
            assert!(
                !child_s.contains(leak),
                "InvalidChildKey error leaked key material: {child_s}"
            );
        }
        assert!(master_s.starts_with("bip32: derive master:"));
        assert!(child_s.contains("invalid child key at index"));
    }

    #[test]
    fn secret_bytes_is_zeroizing() {
        let key = derive_tv1(&[]);
        let bytes = key.secret_bytes();
        // Type-level: Zeroizing<[u8;32]>. Runtime: matches TV1 master key.
        assert_eq!(
            hex::encode(bytes.as_slice()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        // chain_code field is Zeroizing (compile-time via field type).
        assert_eq!(key.chain_code.len(), 32);
    }

    // --- A1-2: Bip44Path + derive_path + Ethereum BIP-44 secrets ---

    #[test]
    fn bip44_path_eoa_indices_and_display() {
        let p0 = Bip44Path::eoa(0);
        assert_eq!(p0.indices(), &[0x8000_002C, 0x8000_003C, 0x8000_0000, 0, 0]);
        assert_eq!(p0.to_string(), "m/44'/60'/0'/0/0");

        let p1 = Bip44Path::eoa(1);
        assert_eq!(p1.indices(), &[0x8000_002C, 0x8000_003C, 0x8000_0000, 0, 1]);
        assert_eq!(p1.to_string(), "m/44'/60'/0'/0/1");

        let p42 = Bip44Path::eoa(42);
        assert_eq!(p42.indices()[4], 42);
        assert_eq!(p42.to_string(), "m/44'/60'/0'/0/42");
    }

    /// Ethereum BIP-44 vector: mnemonic `abandon … about`, **empty** passphrase.
    ///
    /// Seed `5eb00bbd…` (NOT the TREZOR-passphrase seed `c55257c3…` used by BLS
    /// EIP-2333 case-0). Secrets vs `cast wallet private-key` ground truth.
    /// Source: docs/plan/eoa-keystore/research/bip32-secp256k1.md
    const BIP44_ETH_SEED: &str = concat!(
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1",
        "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
    );

    /// (address_index, expected secret hex). Addresses gated in A3-1.
    const BIP44_ETH_SECRETS: &[(u32, &str)] = &[
        (
            0,
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
        ),
        (
            1,
            "9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6",
        ),
    ];

    #[test]
    fn bip44_eth_abandon_secrets_empty_passphrase() {
        // Guard: must not use the TREZOR / BLS case-0 seed.
        assert!(
            !BIP44_ETH_SEED.starts_with("c55257c3"),
            "must use empty-passphrase seed 5eb00bbd…, not TREZOR seed"
        );
        assert!(BIP44_ETH_SEED.starts_with("5eb00bbd"));

        let seed = decode_hex(BIP44_ETH_SEED);
        assert_eq!(seed.len(), 64, "BIP-39 seed is 64 bytes");

        for &(index, expected) in BIP44_ETH_SECRETS {
            let path = Bip44Path::eoa(index);
            let key = ExtendedPrivKey::derive_path(&seed, &path)
                .unwrap_or_else(|e| panic!("derive_path index {index}: {e}"));
            let secret = key.secret_bytes();
            assert_eq!(
                hex::encode(secret.as_slice()),
                expected,
                "m/44'/60'/0'/0/{index}: secret mismatch vs cast"
            );
            // secret_bytes returns Zeroizing (type-level + drop scrub).
            let _: &Zeroizing<[u8; 32]> = &secret;
        }
    }
}
