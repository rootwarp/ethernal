//! Ported from go/internal/ssz/ssz_test.go and go/internal/ssz/ssz_fuzz_test.go.
//!
//! Black-box tests against the public SSZ surface. The Go tests are white-box
//! (`package ssz`) and reference the unexported `sha256Pair` helper; here we
//! provide a local `sha256_pair` over the `sha2` crate so the independent
//! reference computations match the production code.

use sha2::{Digest, Sha256};

use ethernal_core::ssz::{
    compute_domain, compute_signing_root, merkleize, pad_right, uint64_chunk, DepositData,
    DepositMessage, ForkData, SigningData,
};

/// Local reference implementation of SHA-256(a || b), mirroring the unexported
/// `sha256Pair` used inside the Go test package.
fn sha256_pair(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// Decodes a hex string into a fixed [u8; 32], mirroring the Go `mustDecodeHex`
/// helper (which supports upper/lowercase).
fn decode_hex32(h: &str) -> [u8; 32] {
    let bytes = hex::decode(h).expect("valid hex");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

// -----------------------------------------------------------------------------
// uint64Chunk tests
// -----------------------------------------------------------------------------

// Go: TestUint64Chunk/zero
#[test]
fn uint64_chunk_zero() {
    let got = uint64_chunk(0);
    assert_eq!(got, [0u8; 32], "uint64_chunk(0) must be all zeros");
}

// Go: TestUint64Chunk/one
#[test]
fn uint64_chunk_one() {
    let got = uint64_chunk(1);
    let mut want = [0u8; 32];
    want[..8].copy_from_slice(&1u64.to_le_bytes());
    assert_eq!(got, want);
}

// Go: TestUint64Chunk/32_000_000_000
#[test]
fn uint64_chunk_32gwei() {
    const V: u64 = 32_000_000_000;
    let got = uint64_chunk(V);
    let mut want = [0u8; 32];
    want[..8].copy_from_slice(&V.to_le_bytes());
    assert_eq!(got, want);
}

// -----------------------------------------------------------------------------
// padRight tests
// -----------------------------------------------------------------------------

// Go: TestPadRight/empty_to_32
#[test]
fn pad_right_empty_to_32() {
    let got = pad_right(&[], 32);
    assert_eq!(got.len(), 32);
    assert!(got.iter().all(|&b| b == 0), "all bytes must be zero");
}

// Go: TestPadRight/input_shorter_than_size
#[test]
fn pad_right_input_shorter_than_size() {
    let input = [0x01, 0x02, 0x03, 0x04];
    let got = pad_right(&input, 8);
    let want = [0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(got, want);
}

// Go: TestPadRight/input_equal_to_size
#[test]
fn pad_right_input_equal_to_size() {
    let input = [0xAA, 0xBB];
    let got = pad_right(&input, 2);
    assert_eq!(got, vec![0xAA, 0xBB]);
}

// Go: TestPadRight/original_not_mutated
#[test]
fn pad_right_original_not_mutated() {
    let input = [0x01, 0x02];
    let _ = pad_right(&input, 4);
    // In Rust `pad_right` takes `&[u8]` and cannot mutate the caller's slice;
    // this asserts the same observable contract as the Go test.
    assert_eq!(input.len(), 2);
    assert_eq!(input, [0x01, 0x02]);
}

// -----------------------------------------------------------------------------
// merkleize tests
// -----------------------------------------------------------------------------

// Go: TestMerkleize (table of 6 cases with hardcoded roots ported verbatim)
#[test]
fn merkleize_known_roots() {
    let zero = [0u8; 32];
    let cases: &[(&str, Vec<[u8; 32]>, usize, &str)] = &[
        (
            "1_chunk_limit_1",
            vec![zero],
            1,
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "2_chunks_limit_2",
            vec![zero, zero],
            2,
            "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        ),
        (
            "3_chunks_limit_3_padded_to_4",
            vec![zero, zero, zero],
            3,
            "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
        ),
        (
            "4_chunks_limit_4",
            vec![zero, zero, zero, zero],
            4,
            "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
        ),
        (
            "5_chunks_limit_5_padded_to_8",
            vec![zero, zero, zero, zero, zero],
            5,
            "c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c",
        ),
        (
            "8_chunks_limit_8",
            vec![zero, zero, zero, zero, zero, zero, zero, zero],
            8,
            "c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c",
        ),
    ];

    for (name, chunks, limit, want_hex) in cases {
        let got = merkleize(chunks, *limit);
        let want = decode_hex32(want_hex);
        assert_eq!(got, want, "case {name}");
    }
}

// -----------------------------------------------------------------------------
// ForkData.HashTreeRoot tests
// -----------------------------------------------------------------------------

// Go: TestForkDataHashTreeRoot/all_zeros
#[test]
fn fork_data_htr_all_zeros() {
    let fd = ForkData {
        current_version: [0u8; 4],
        genesis_validators_root: [0u8; 32],
    };
    let got = fd.hash_tree_root();
    let want = decode_hex32("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
    assert_eq!(got, want);
}

// Go: TestForkDataHashTreeRoot/non_zero_version
#[test]
fn fork_data_htr_non_zero_version() {
    let fd = ForkData {
        current_version: [0x01, 0x02, 0x03, 0x04],
        genesis_validators_root: [0u8; 32],
    };
    let got = fd.hash_tree_root();
    // Independent recompute: chunk0 = version padded to 32, chunk1 = gvr.
    let mut c0 = [0u8; 32];
    c0[..4].copy_from_slice(&fd.current_version);
    let want = sha256_pair(c0, fd.genesis_validators_root);
    assert_eq!(got, want);
}

// -----------------------------------------------------------------------------
// SigningData.HashTreeRoot tests
// -----------------------------------------------------------------------------

// Go: TestSigningDataHashTreeRoot/all_zeros
#[test]
fn signing_data_htr_all_zeros() {
    let sd = SigningData {
        object_root: [0u8; 32],
        domain: [0u8; 32],
    };
    let got = sd.hash_tree_root();
    let want = decode_hex32("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
    assert_eq!(got, want);
}

// Go: TestSigningDataHashTreeRoot/known_object_and_domain
#[test]
fn signing_data_htr_known_object_and_domain() {
    let mut object_root = [0u8; 32];
    object_root[0] = 0x01;
    let mut domain = [0u8; 32];
    domain[0] = 0x02;
    let sd = SigningData {
        object_root,
        domain,
    };
    let got = sd.hash_tree_root();
    let want = sha256_pair(sd.object_root, sd.domain);
    assert_eq!(got, want);
}

// -----------------------------------------------------------------------------
// DepositMessage.HashTreeRoot tests
// -----------------------------------------------------------------------------

/// Reference implementation for a DepositMessage root, computed from first
/// principles via the local `sha256_pair` — mirrors `computeDepositMessageRoot`.
fn compute_deposit_message_root(msg: &DepositMessage) -> [u8; 32] {
    let mut pk0 = [0u8; 32];
    pk0.copy_from_slice(&msg.pubkey[..32]);
    let mut pk1 = [0u8; 32];
    pk1[..16].copy_from_slice(&msg.pubkey[32..48]);
    let pubkey_root = sha256_pair(pk0, pk1);

    let wc_chunk = msg.withdrawal_credentials;
    let amount_chunk = uint64_chunk(msg.amount);

    let zero_chunk = [0u8; 32];
    let h01 = sha256_pair(pubkey_root, wc_chunk);
    let h23 = sha256_pair(amount_chunk, zero_chunk);
    sha256_pair(h01, h23)
}

// Go: TestDepositMessageHashTreeRoot/all_zeros
#[test]
fn deposit_message_htr_all_zeros() {
    let msg = DepositMessage {
        pubkey: [0u8; 48],
        withdrawal_credentials: [0u8; 32],
        amount: 0,
    };
    let got = msg.hash_tree_root();
    let want = decode_hex32("da6d807bf795106146e5822775d914b0277a65240f650ed4c8a7ca77824e5adf");
    assert_eq!(got, want);
}

// Go: TestDepositMessageHashTreeRoot/with_amount_32gwei
#[test]
fn deposit_message_htr_with_amount_32gwei() {
    let msg = DepositMessage {
        pubkey: [0u8; 48],
        withdrawal_credentials: [0u8; 32],
        amount: 32_000_000_000,
    };
    let got = msg.hash_tree_root();
    // Verbatim anchor from Go.
    let want = decode_hex32("239baae74829c617635cf3c579a355107ef752700f246b0bd10b50b05e16fd3e");
    assert_eq!(got, want);
    // And the independent first-principles recompute must agree.
    assert_eq!(got, compute_deposit_message_root(&msg));
}

// -----------------------------------------------------------------------------
// DepositData.HashTreeRoot tests
// -----------------------------------------------------------------------------

/// Reference implementation for a DepositData root — mirrors
/// `computeDepositDataRoot`.
fn compute_deposit_data_root(data: &DepositData) -> [u8; 32] {
    let mut pk0 = [0u8; 32];
    pk0.copy_from_slice(&data.pubkey[..32]);
    let mut pk1 = [0u8; 32];
    pk1[..16].copy_from_slice(&data.pubkey[32..48]);
    let pubkey_root = sha256_pair(pk0, pk1);

    let wc_chunk = data.withdrawal_credentials;
    let amount_chunk = uint64_chunk(data.amount);

    let mut sig0 = [0u8; 32];
    sig0.copy_from_slice(&data.signature[..32]);
    let mut sig1 = [0u8; 32];
    sig1.copy_from_slice(&data.signature[32..64]);
    let mut sig2 = [0u8; 32];
    sig2.copy_from_slice(&data.signature[64..96]);
    let sig_pad = [0u8; 32];
    let sig_h01 = sha256_pair(sig0, sig1);
    let sig_h23 = sha256_pair(sig2, sig_pad);
    let sig_root = sha256_pair(sig_h01, sig_h23);

    let h01 = sha256_pair(pubkey_root, wc_chunk);
    let h23 = sha256_pair(amount_chunk, sig_root);
    sha256_pair(h01, h23)
}

// Go: TestDepositDataHashTreeRoot/all_zeros
#[test]
fn deposit_data_htr_all_zeros() {
    let data = DepositData {
        pubkey: [0u8; 48],
        withdrawal_credentials: [0u8; 32],
        amount: 0,
        signature: [0u8; 96],
    };
    let got = data.hash_tree_root();
    let want = decode_hex32("7d3bfa54172d8642a6c081084ce35542555a2998f48c5c9cd17f2d7a0754f3eb");
    assert_eq!(got, want);
}

// Go: TestDepositDataHashTreeRoot/with_amount_32gwei
#[test]
fn deposit_data_htr_with_amount_32gwei() {
    let data = DepositData {
        pubkey: [0u8; 48],
        withdrawal_credentials: [0u8; 32],
        amount: 32_000_000_000,
        signature: [0u8; 96],
    };
    let got = data.hash_tree_root();
    let want = decode_hex32("05125366a514ddd17fc8158440399c02d631cdb991dffa30623107f27e43673d");
    assert_eq!(got, want);
    assert_eq!(got, compute_deposit_data_root(&data));
}

// -----------------------------------------------------------------------------
// ComputeDomain tests
// -----------------------------------------------------------------------------

// Go: TestComputeDomain/all_zeros
#[test]
fn compute_domain_all_zeros() {
    let domain_type = [0u8; 4];
    let fork_version = [0u8; 4];
    let gvr = [0u8; 32];

    let got = compute_domain(domain_type, fork_version, gvr);

    let fd = ForkData {
        current_version: fork_version,
        genesis_validators_root: gvr,
    };
    let fd_root = fd.hash_tree_root();
    let mut want = [0u8; 32];
    want[..4].copy_from_slice(&domain_type);
    want[4..].copy_from_slice(&fd_root[..28]);
    assert_eq!(got, want);
}

// Go: TestComputeDomain/domain_deposit_with_hoodi_fork
#[test]
fn compute_domain_deposit_with_hoodi_fork() {
    let domain_type = [0x03, 0x00, 0x00, 0x00];
    let fork_version = [0x10, 0x00, 0x09, 0x10];
    let gvr = [0u8; 32];

    let got = compute_domain(domain_type, fork_version, gvr);

    // First 4 bytes must be the domain type.
    assert_eq!(&got[..4], &[0x03, 0x00, 0x00, 0x00]);
    // Bytes 4-31 must match the first 28 bytes of ForkData.hash_tree_root().
    let fd = ForkData {
        current_version: fork_version,
        genesis_validators_root: gvr,
    };
    let fd_root = fd.hash_tree_root();
    assert_eq!(&got[4..], &fd_root[..28]);
}

// -----------------------------------------------------------------------------
// ComputeSigningRoot tests
// -----------------------------------------------------------------------------

// Go: TestComputeSigningRoot/all_zeros
#[test]
fn compute_signing_root_all_zeros() {
    let object_root = [0u8; 32];
    let domain = [0u8; 32];

    let got = compute_signing_root(object_root, domain);

    let want = SigningData {
        object_root,
        domain,
    }
    .hash_tree_root();
    assert_eq!(got, want);
}

// Go: TestComputeSigningRoot/non_zero_inputs
#[test]
fn compute_signing_root_non_zero_inputs() {
    let mut object_root = [0u8; 32];
    object_root[0] = 0x01;
    object_root[1] = 0x02;
    object_root[2] = 0x03;
    let mut domain = [0u8; 32];
    domain[0] = 0xFF;

    let got = compute_signing_root(object_root, domain);
    let want = SigningData {
        object_root,
        domain,
    }
    .hash_tree_root();
    assert_eq!(got, want);
}

// -----------------------------------------------------------------------------
// Property tests ported from the Go fuzz targets.
//
// Go: FuzzMerkleize — asserts merkleize never panics and is deterministic.
// Go: FuzzUint64Chunk — asserts uint64Chunk never panics, is deterministic,
// high 24 bytes are always zero, and the length contract holds.
//
// The Go targets randomize; here we sweep a fixed, systematic input space so
// the test is deterministic while still exercising the same invariants.
// -----------------------------------------------------------------------------

/// Builds `num_chunks` 32-byte chunks from a seed byte, so different seeds
/// produce distinct byte patterns.
fn seeded_chunks(num_chunks: usize, seed: u8) -> Vec<[u8; 32]> {
    let mut chunks = vec![[0u8; 32]; num_chunks];
    for (i, chunk) in chunks.iter_mut().enumerate() {
        for (j, b) in chunk.iter_mut().enumerate() {
            *b = seed
                .wrapping_add(i as u8)
                .wrapping_mul(31)
                .wrapping_add(j as u8);
        }
    }
    chunks
}

// Go: FuzzMerkleize (deterministic property port).
#[test]
fn fuzz_merkleize_deterministic_no_panic() {
    // Mirror the fuzz clamps: limit in [1, 16], chunk count in [1, limit].
    let seeds: [u8; 4] = [0x00, 0x01, 0x7f, 0xff];
    for limit in 1..=16usize {
        for num_chunks in 1..=limit {
            for &seed in &seeds {
                let chunks = seeded_chunks(num_chunks, seed);
                let r1 = merkleize(&chunks, limit);
                let r2 = merkleize(&chunks, limit);
                assert_eq!(
                    r1, r2,
                    "merkleize non-deterministic (chunks={num_chunks}, limit={limit}, seed={seed:#x})"
                );
            }
        }
    }
}

// Additional systematic merkleize invariants derived from the SSZ contract:
// a single chunk with limit 1 returns the chunk itself, and padding to the
// next power of two is stable across equivalent (len, limit) shapes.
#[test]
fn merkleize_single_chunk_identity_and_zero_edge() {
    let chunk = seeded_chunks(1, 0x42)[0];
    assert_eq!(
        merkleize(&[chunk], 1),
        chunk,
        "single chunk, limit 1 is identity"
    );

    // Zero-chunk, limit 0 pads to a single zero chunk.
    assert_eq!(merkleize(&[], 0), [0u8; 32]);
}

// Go: FuzzUint64Chunk (deterministic property port).
#[test]
fn fuzz_uint64_chunk_invariants() {
    let mut values: Vec<u64> = vec![0, 1, 32_000_000_000, u64::MAX];
    // A systematic spread of single-bit and mixed patterns.
    for shift in 0..64 {
        values.push(1u64 << shift);
    }
    values.extend([0xDEAD_BEEF, 0x0123_4567_89AB_CDEF, 0xFFFF_0000_FFFF_0000]);

    for &v in &values {
        let r1 = uint64_chunk(v);
        let r2 = uint64_chunk(v);
        assert_eq!(r1, r2, "uint64_chunk({v}) non-deterministic");

        // High 24 bytes must always be zero.
        assert!(
            r1[8..].iter().all(|&b| b == 0),
            "uint64_chunk({v}) high bytes must be zero"
        );

        // Low 8 bytes must be the little-endian encoding of v.
        assert_eq!(&r1[..8], &v.to_le_bytes());

        // Length contract (guaranteed by the type, asserted for parity).
        assert_eq!(r1.len(), 32);
    }
}
