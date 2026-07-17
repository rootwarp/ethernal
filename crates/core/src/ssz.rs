//! Hand-rolled `hash_tree_root` implementations for the four fixed-size SSZ
//! structs used in the Ethereum validator deposit pipeline: [`DepositMessage`],
//! [`DepositData`], [`ForkData`], and [`SigningData`]. SHA-256 (`sha2` crate)
//! is the only hash function used.
//!
//! The algorithm follows the standard SSZ Container hash_tree_root as defined
//! in the Ethereum consensus spec (<https://github.com/ethereum/consensus-specs>):
//! each field's chunk subtree is computed first, then the resulting field roots
//! are merkleized into the container root. Byte-vector fields (Bytes48, Bytes96)
//! are split into 32-byte chunks, padded right with zeros, and their own subtree
//! root replaces them as a leaf in the container tree — this is distinct from a
//! flat concatenation of all chunks at once.

use sha2::{Digest, Sha256};

/// The SSZ container that must be signed to produce a valid deposit signature.
/// It contains the validator pubkey, withdrawal credentials, and the deposit
/// amount in Gwei.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositMessage {
    pub pubkey: [u8; 48],
    pub withdrawal_credentials: [u8; 32],
    pub amount: u64,
}

impl DepositMessage {
    /// Computes the SSZ hash_tree_root of a DepositMessage.
    /// Layout:
    ///   - field 0 (pubkey): merkleize([pubkey[0:32], pubkey[32:48]+16zeros]) → pubkey_root
    ///   - field 1 (withdrawal_credentials): 32-byte chunk as-is
    ///   - field 2 (amount): uint64_chunk(amount)
    ///   - root: merkleize([pubkey_root, wc_chunk, amount_chunk], limit=3)
    pub fn hash_tree_root(&self) -> [u8; 32] {
        let pubkey_root = byte_vector_root(&self.pubkey);
        let wc_chunk = self.withdrawal_credentials;
        let amount_chunk = uint64_chunk(self.amount);
        merkleize(&[pubkey_root, wc_chunk, amount_chunk], 3)
    }
}

/// The SSZ container that forms the deposit data root stored on-chain.
/// It extends [`DepositMessage`] with the BLS signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositData {
    pub pubkey: [u8; 48],
    pub withdrawal_credentials: [u8; 32],
    pub amount: u64,
    pub signature: [u8; 96],
}

impl DepositData {
    /// Computes the SSZ hash_tree_root of a DepositData.
    /// Layout:
    ///   - field 0 (pubkey): merkleize([pubkey[0:32], pubkey[32:48]+16zeros]) → pubkey_root
    ///   - field 1 (withdrawal_credentials): 32-byte chunk as-is
    ///   - field 2 (amount): uint64_chunk(amount)
    ///   - field 3 (signature): merkleize([sig[0:32], sig[32:64], sig[64:96]], limit=3) → sig_root
    ///   - root: merkleize([pubkey_root, wc_chunk, amount_chunk, sig_root], limit=4)
    pub fn hash_tree_root(&self) -> [u8; 32] {
        let pubkey_root = byte_vector_root(&self.pubkey);
        let wc_chunk = self.withdrawal_credentials;
        let amount_chunk = uint64_chunk(self.amount);
        let sig_root = byte_vector_root(&self.signature);
        merkleize(&[pubkey_root, wc_chunk, amount_chunk, sig_root], 4)
    }
}

/// The SSZ container used to compute the signing domain for a given fork
/// version and genesis validators root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkData {
    pub current_version: [u8; 4],
    pub genesis_validators_root: [u8; 32],
}

impl ForkData {
    /// Computes the SSZ hash_tree_root of a ForkData.
    /// Layout:
    ///   - field 0 (current_version): [u8;4] padded right to 32 bytes
    ///   - field 1 (genesis_validators_root): 32-byte chunk as-is
    ///   - root: merkleize([version_chunk, gvr_chunk], limit=2)
    pub fn hash_tree_root(&self) -> [u8; 32] {
        let mut version_chunk = [0u8; 32];
        version_chunk[..4].copy_from_slice(&self.current_version);
        let gvr_chunk = self.genesis_validators_root;
        merkleize(&[version_chunk, gvr_chunk], 2)
    }
}

/// The SSZ container whose hash_tree_root is the signing root for a BLS
/// signature over an object in a given domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningData {
    pub object_root: [u8; 32],
    pub domain: [u8; 32],
}

impl SigningData {
    /// Computes the SSZ hash_tree_root of a SigningData.
    /// Layout:
    ///   - field 0 (object_root): 32-byte chunk as-is
    ///   - field 1 (domain): 32-byte chunk as-is
    ///   - root: merkleize([object_root, domain], limit=2)
    pub fn hash_tree_root(&self) -> [u8; 32] {
        merkleize(&[self.object_root, self.domain], 2)
    }
}

/// Computes the domain value used when signing a deposit message.
/// It returns `domain_type[0:4] || ForkData{fork_version, gvr}.hash_tree_root()[0:28]`.
///
/// Per the consensus spec, the 32-byte domain is split: the first 4 bytes are
/// the domain type and the remaining 28 bytes are taken from the fork data root.
pub fn compute_domain(domain_type: [u8; 4], fork_version: [u8; 4], gvr: [u8; 32]) -> [u8; 32] {
    let fd = ForkData {
        current_version: fork_version,
        genesis_validators_root: gvr,
    };
    let fd_root = fd.hash_tree_root();
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fd_root[..28]);
    domain
}

/// Returns the signing root for an SSZ object given its hash_tree_root and the
/// domain. This is the value that is BLS-signed.
/// It returns `SigningData{object_root, domain}.hash_tree_root()`.
pub fn compute_signing_root(object_root: [u8; 32], domain: [u8; 32]) -> [u8; 32] {
    SigningData {
        object_root,
        domain,
    }
    .hash_tree_root()
}

/// Computes the subtree root for a fixed-size byte vector by splitting `b`
/// into 32-byte chunks (right-padding the last chunk if needed) and
/// merkleizing with limit = number of chunks (rounded up to next pow2).
///
/// This is used for Bytes48 (pubkey → 2 chunks) and Bytes96 (signature → 3
/// chunks) fields inside container structs.
pub fn byte_vector_root(b: &[u8]) -> [u8; 32] {
    // Split b into 32-byte chunks. The last chunk is right-padded with zeros.
    let num_chunks = b.len().div_ceil(32);
    let mut chunks = vec![[0u8; 32]; num_chunks];
    for (i, chunk) in chunks.iter_mut().enumerate() {
        let start = i * 32;
        let end = (start + 32).min(b.len());
        chunk[..end - start].copy_from_slice(&b[start..end]);
    }
    merkleize(&chunks, num_chunks)
}

/// Computes the SSZ merkle root of the given chunks.
/// The chunk slice is padded with zero chunks to the smallest power of two
/// that is >= max(len(chunks), limit). Then adjacent pairs are hashed with
/// SHA-256 bottom-up until a single 32-byte root remains.
///
/// For a single chunk (after padding to pow2=1), the chunk itself is returned.
pub fn merkleize(chunks: &[[u8; 32]], limit: usize) -> [u8; 32] {
    let n = chunks.len().max(limit);
    // Find next power of two >= n.
    let mut size = 1usize;
    while size < n {
        size <<= 1;
    }
    // Build working buffer: copy chunks, pad the rest with zero chunks.
    let mut padded = vec![[0u8; 32]; size];
    padded[..chunks.len()].copy_from_slice(chunks);

    // Pairwise SHA-256 bottom-up.
    while size > 1 {
        let half = size >> 1;
        for i in 0..half {
            padded[i] = sha256_pair(&padded[2 * i], &padded[2 * i + 1]);
        }
        padded.truncate(half);
        size = half;
    }
    padded[0]
}

/// Encodes a u64 as a 32-byte SSZ chunk.
/// The value is placed in the low 8 bytes in little-endian order; the
/// remaining 24 bytes are zero.
pub fn uint64_chunk(v: u64) -> [u8; 32] {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&v.to_le_bytes());
    chunk
}

/// Right-pads `b` with zero bytes to the given size and returns a new vector.
/// The input slice is never modified.
pub fn pad_right(b: &[u8], size: usize) -> Vec<u8> {
    if b.len() >= size {
        return b.to_vec();
    }
    let mut out = vec![0u8; size];
    out[..b.len()].copy_from_slice(b);
    out
}

/// Computes SHA-256(a || b).
fn sha256_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}
