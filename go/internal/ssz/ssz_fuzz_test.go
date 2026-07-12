package ssz

import (
	"testing"
)

// FuzzMerkleize fuzzes the merkleize function with arbitrary chunk data and
// chunk counts to detect panics or non-determinism. It verifies that:
//  1. The function never panics.
//  2. The result is deterministic (same input produces same output).
func FuzzMerkleize(f *testing.F) {
	// Seed corpus: interesting edge cases.
	var zeroChunk [32]byte
	var oneChunk [32]byte
	oneChunk[0] = 0x01

	f.Add(uint8(1), zeroChunk[:])
	f.Add(uint8(2), zeroChunk[:])
	f.Add(uint8(3), zeroChunk[:])
	f.Add(uint8(4), zeroChunk[:])
	f.Add(uint8(8), oneChunk[:])

	f.Fuzz(func(t *testing.T, limitByte uint8, chunkData []byte) {
		// Clamp limit to [1, 16] to keep the test tractable.
		limit := int(limitByte)
		if limit < 1 {
			limit = 1
		}
		if limit > 16 {
			limit = 16
		}

		// Build up to limit chunks from chunkData. Each chunk is 32 bytes.
		numChunks := len(chunkData) / 32
		if numChunks < 1 {
			numChunks = 1
		}
		if numChunks > limit {
			numChunks = limit
		}

		chunks := make([][32]byte, numChunks)
		for i := range chunks {
			start := i * 32
			if start+32 <= len(chunkData) {
				copy(chunks[i][:], chunkData[start:start+32])
			}
		}

		// Must not panic.
		result1 := merkleize(chunks, limit)

		// Must be deterministic.
		result2 := merkleize(chunks, limit)
		if result1 != result2 {
			t.Errorf("merkleize is non-deterministic: got %x then %x", result1, result2)
		}
	})
}

// FuzzUint64Chunk fuzzes the uint64Chunk function with arbitrary uint64 values
// to detect panics and verify determinism and invariants.
func FuzzUint64Chunk(f *testing.F) {
	// Seed corpus.
	f.Add(uint64(0))
	f.Add(uint64(1))
	f.Add(uint64(32_000_000_000))
	f.Add(uint64(^uint64(0))) // max uint64

	f.Fuzz(func(t *testing.T, v uint64) {
		// Must not panic.
		result1 := uint64Chunk(v)

		// Must be deterministic.
		result2 := uint64Chunk(v)
		if result1 != result2 {
			t.Errorf("uint64Chunk(%d) is non-deterministic: got %x then %x", v, result1, result2)
		}

		// High 24 bytes must always be zero.
		for i := 8; i < 32; i++ {
			if result1[i] != 0 {
				t.Errorf("uint64Chunk(%d): byte[%d] = %d, want 0", v, i, result1[i])
			}
		}

		// The chunk must be exactly 32 bytes (guaranteed by the type, but
		// asserting the size contract explicitly).
		if len(result1) != 32 {
			t.Errorf("uint64Chunk(%d): len = %d, want 32", v, len(result1))
		}
	})
}
