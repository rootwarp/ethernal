// Package ssz provides hand-rolled hash_tree_root implementations for the four
// fixed-size SSZ structs used in the Ethereum validator deposit pipeline:
// DepositMessage, DepositData, ForkData, and SigningData. SHA-256 from
// crypto/sha256 (stdlib) is the only hash function used.
//
// The algorithm follows the standard SSZ Container hash_tree_root as defined in
// the Ethereum consensus spec (https://github.com/ethereum/consensus-specs):
// each field's chunk subtree is computed first, then the resulting field roots
// are merkleized into the container root. Byte-vector fields (Bytes48, Bytes96)
// are split into 32-byte chunks, padded right with zeros, and their own subtree
// root replaces them as a leaf in the container tree — this is distinct from a
// flat concatenation of all chunks at once.
//
// Note: earlier research notes (since removed) contained per-field chunk tables
// written before the container-merkleize pattern was confirmed. Those tables
// described leaf chunks correctly but did not reflect that each multi-chunk
// field is first reduced to a subtree root before the top-level merkleize step.
// This implementation is authoritative.
package ssz

import (
	"crypto/sha256"
	"encoding/binary"
)

// DepositMessage is the SSZ container that must be signed to produce a valid
// deposit signature. It contains the validator pubkey, withdrawal credentials,
// and the deposit amount in Gwei.
type DepositMessage struct {
	Pubkey                [48]byte
	WithdrawalCredentials [32]byte
	Amount                uint64
}

// HashTreeRoot computes the SSZ hash_tree_root of a DepositMessage.
// Layout:
//   - field 0 (pubkey): merkleize([pubkey[0:32], pubkey[32:48]+16zeros]) → pubkeyRoot
//   - field 1 (withdrawal_credentials): 32-byte chunk as-is
//   - field 2 (amount): uint64Chunk(amount)
//   - root: merkleize([pubkeyRoot, wc_chunk, amount_chunk], limit=3)
func (m DepositMessage) HashTreeRoot() [32]byte {
	pubkeyRoot := byteVectorRoot(m.Pubkey[:])
	wcChunk := m.WithdrawalCredentials
	amountChunk := uint64Chunk(m.Amount)
	return merkleize([][32]byte{pubkeyRoot, wcChunk, amountChunk}, 3)
}

// DepositData is the SSZ container that forms the deposit data root stored
// on-chain. It extends DepositMessage with the BLS signature.
type DepositData struct {
	Pubkey                [48]byte
	WithdrawalCredentials [32]byte
	Amount                uint64
	Signature             [96]byte
}

// HashTreeRoot computes the SSZ hash_tree_root of a DepositData.
// Layout:
//   - field 0 (pubkey): merkleize([pubkey[0:32], pubkey[32:48]+16zeros]) → pubkeyRoot
//   - field 1 (withdrawal_credentials): 32-byte chunk as-is
//   - field 2 (amount): uint64Chunk(amount)
//   - field 3 (signature): merkleize([sig[0:32], sig[32:64], sig[64:96]], limit=3) → sigRoot
//   - root: merkleize([pubkeyRoot, wc_chunk, amount_chunk, sigRoot], limit=4)
func (d DepositData) HashTreeRoot() [32]byte {
	pubkeyRoot := byteVectorRoot(d.Pubkey[:])
	wcChunk := d.WithdrawalCredentials
	amountChunk := uint64Chunk(d.Amount)
	sigRoot := byteVectorRoot(d.Signature[:])
	return merkleize([][32]byte{pubkeyRoot, wcChunk, amountChunk, sigRoot}, 4)
}

// ForkData is the SSZ container used to compute the signing domain for a given
// fork version and genesis validators root.
type ForkData struct {
	CurrentVersion        [4]byte
	GenesisValidatorsRoot [32]byte
}

// HashTreeRoot computes the SSZ hash_tree_root of a ForkData.
// Layout:
//   - field 0 (current_version): [4]byte padded right to 32 bytes
//   - field 1 (genesis_validators_root): 32-byte chunk as-is
//   - root: merkleize([version_chunk, gvr_chunk], limit=2)
func (f ForkData) HashTreeRoot() [32]byte {
	var versionChunk [32]byte
	copy(versionChunk[:], f.CurrentVersion[:])
	gvrChunk := f.GenesisValidatorsRoot
	return merkleize([][32]byte{versionChunk, gvrChunk}, 2)
}

// SigningData is the SSZ container whose hash_tree_root is the signing root
// for a BLS signature over an object in a given domain.
type SigningData struct {
	ObjectRoot [32]byte
	Domain     [32]byte
}

// HashTreeRoot computes the SSZ hash_tree_root of a SigningData.
// Layout:
//   - field 0 (object_root): 32-byte chunk as-is
//   - field 1 (domain): 32-byte chunk as-is
//   - root: merkleize([object_root, domain], limit=2)
func (s SigningData) HashTreeRoot() [32]byte {
	return merkleize([][32]byte{s.ObjectRoot, s.Domain}, 2)
}

// ComputeDomain computes the domain value used when signing a deposit message.
// It returns domainType[0:4] || ForkData{forkVersion, gvr}.HashTreeRoot()[0:28].
//
// Per the consensus spec, the 32-byte domain is split: the first 4 bytes are
// the domain type and the remaining 28 bytes are taken from the fork data root.
func ComputeDomain(domainType [4]byte, forkVersion [4]byte, gvr [32]byte) [32]byte {
	fd := ForkData{
		CurrentVersion:        forkVersion,
		GenesisValidatorsRoot: gvr,
	}
	fdRoot := fd.HashTreeRoot()
	var domain [32]byte
	copy(domain[:4], domainType[:])
	copy(domain[4:], fdRoot[:28])
	return domain
}

// ComputeSigningRoot returns the signing root for an SSZ object given its
// hash_tree_root and the domain. This is the value that is BLS-signed.
// It returns SigningData{objectRoot, domain}.HashTreeRoot().
func ComputeSigningRoot(objectRoot [32]byte, domain [32]byte) [32]byte {
	sd := SigningData{
		ObjectRoot: objectRoot,
		Domain:     domain,
	}
	return sd.HashTreeRoot()
}

// byteVectorRoot computes the subtree root for a fixed-size byte vector by
// splitting b into 32-byte chunks (right-padding the last chunk if needed)
// and merkleizing with limit = number of chunks (rounded up to next pow2).
//
// This is used for Bytes48 (pubkey → 2 chunks) and Bytes96 (signature → 3
// chunks) fields inside container structs.
func byteVectorRoot(b []byte) [32]byte {
	// Split b into 32-byte chunks. The last chunk is right-padded with zeros.
	numChunks := (len(b) + 31) / 32
	chunks := make([][32]byte, numChunks)
	for i := 0; i < numChunks; i++ {
		start := i * 32
		end := start + 32
		if end > len(b) {
			end = len(b)
		}
		copy(chunks[i][:], b[start:end])
	}
	return merkleize(chunks, numChunks)
}

// merkleize computes the SSZ merkle root of the given chunks.
// The chunk slice is padded with zero chunks to the smallest power of two
// that is >= max(len(chunks), limit). Then adjacent pairs are hashed with
// SHA-256 bottom-up until a single 32-byte root remains.
//
// For a single chunk (after padding to pow2=1), the chunk itself is returned.
func merkleize(chunks [][32]byte, limit int) [32]byte {
	n := len(chunks)
	if limit > n {
		n = limit
	}
	// Find next power of two >= n.
	size := 1
	for size < n {
		size <<= 1
	}
	// Build working slice: copy chunks, pad the rest with zero chunks.
	padded := make([][32]byte, size)
	copy(padded, chunks)

	// Pairwise SHA-256 bottom-up.
	for size > 1 {
		half := size >> 1
		for i := 0; i < half; i++ {
			padded[i] = sha256Pair(padded[2*i], padded[2*i+1])
		}
		padded = padded[:half]
		size = half
	}
	return padded[0]
}

// uint64Chunk encodes a uint64 as a 32-byte SSZ chunk.
// The value is placed in the low 8 bytes in little-endian order; the
// remaining 24 bytes are zero.
func uint64Chunk(v uint64) [32]byte {
	var chunk [32]byte
	binary.LittleEndian.PutUint64(chunk[:8], v)
	return chunk
}

// padRight right-pads b with zero bytes to the given size and returns a new
// slice. The input slice is never modified.
func padRight(b []byte, size int) []byte {
	if len(b) >= size {
		out := make([]byte, len(b))
		copy(out, b)
		return out
	}
	out := make([]byte, size)
	copy(out, b)
	return out
}

// sha256Pair computes SHA-256(a || b) and returns the result as a [32]byte.
func sha256Pair(a, b [32]byte) [32]byte {
	h := sha256.New()
	h.Write(a[:])
	h.Write(b[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
