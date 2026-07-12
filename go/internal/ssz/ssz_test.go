package ssz

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// -----------------------------------------------------------------------------
// uint64Chunk tests
// -----------------------------------------------------------------------------

func TestUint64Chunk(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		got := uint64Chunk(0)
		var want [32]byte
		if got != want {
			t.Errorf("uint64Chunk(0) = %x, want all zeros", got)
		}
	})

	t.Run("one", func(t *testing.T) {
		got := uint64Chunk(1)
		var want [32]byte
		binary.LittleEndian.PutUint64(want[:8], 1)
		if got != want {
			t.Errorf("uint64Chunk(1) = %x, want %x", got, want)
		}
	})

	t.Run("32_000_000_000", func(t *testing.T) {
		const v uint64 = 32_000_000_000
		got := uint64Chunk(v)
		var want [32]byte
		binary.LittleEndian.PutUint64(want[:8], v)
		if got != want {
			t.Errorf("uint64Chunk(32_000_000_000) = %x, want %x", got, want)
		}
	})
}

// -----------------------------------------------------------------------------
// padRight tests
// -----------------------------------------------------------------------------

func TestPadRight(t *testing.T) {
	t.Run("empty_to_32", func(t *testing.T) {
		got := padRight([]byte{}, 32)
		if len(got) != 32 {
			t.Errorf("len = %d, want 32", len(got))
		}
		for i, b := range got {
			if b != 0 {
				t.Errorf("byte[%d] = %d, want 0", i, b)
			}
		}
	})

	t.Run("input_shorter_than_size", func(t *testing.T) {
		input := []byte{0x01, 0x02, 0x03, 0x04}
		got := padRight(input, 8)
		want := []byte{0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00}
		if len(got) != len(want) {
			t.Fatalf("len = %d, want %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("byte[%d] = %d, want %d", i, got[i], want[i])
			}
		}
	})

	t.Run("input_equal_to_size", func(t *testing.T) {
		input := []byte{0xAA, 0xBB}
		got := padRight(input, 2)
		if len(got) != 2 || got[0] != 0xAA || got[1] != 0xBB {
			t.Errorf("padRight(%x, 2) = %x, want same", input, got)
		}
	})

	t.Run("original_not_mutated", func(t *testing.T) {
		input := []byte{0x01, 0x02}
		_ = padRight(input, 4)
		if len(input) != 2 {
			t.Errorf("input was mutated, len = %d", len(input))
		}
	})
}

// -----------------------------------------------------------------------------
// merkleize tests
// -----------------------------------------------------------------------------

// knownRoot is the SHA-256 of 64 zero bytes, i.e. merkleize of two zero chunks.
// This equals f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b
func twoZeroChunksHash() [32]byte {
	var a, b [32]byte
	h := sha256.New()
	h.Write(a[:])
	h.Write(b[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func TestMerkleize(t *testing.T) {
	zero := [32]byte{}
	twoHash := twoZeroChunksHash()

	tests := []struct {
		name   string
		chunks [][32]byte
		limit  int
		// wantFn computes expected value dynamically from SHA-256 to avoid hardcoding.
		// We store as a string hex for readability in the description.
		wantHex string
	}{
		{
			name:    "1_chunk_limit_1",
			chunks:  [][32]byte{zero},
			limit:   1,
			wantHex: "0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:    "2_chunks_limit_2",
			chunks:  [][32]byte{zero, zero},
			limit:   2,
			wantHex: "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
		},
		{
			name:    "3_chunks_limit_3_padded_to_4",
			chunks:  [][32]byte{zero, zero, zero},
			limit:   3,
			wantHex: "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
		},
		{
			name:    "4_chunks_limit_4",
			chunks:  [][32]byte{zero, zero, zero, zero},
			limit:   4,
			wantHex: "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
		},
		{
			name:    "5_chunks_limit_5_padded_to_8",
			chunks:  [][32]byte{zero, zero, zero, zero, zero},
			limit:   5,
			wantHex: "c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c",
		},
		{
			name:    "8_chunks_limit_8",
			chunks:  [][32]byte{zero, zero, zero, zero, zero, zero, zero, zero},
			limit:   8,
			wantHex: "c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c",
		},
	}

	_ = twoHash // used for documentation

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := merkleize(tc.chunks, tc.limit)
			wantBytes := mustDecodeHex(t, tc.wantHex)
			var want [32]byte
			copy(want[:], wantBytes)
			if got != want {
				t.Errorf("merkleize(%d chunks, limit=%d) = %x, want %x", len(tc.chunks), tc.limit, got, want)
			}
		})
	}
}

// mustDecodeHex decodes a hex string or fails the test.
func mustDecodeHex(t *testing.T, h string) []byte {
	t.Helper()
	b := make([]byte, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		var v byte
		for _, c := range []byte(h[i : i+2]) {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v |= c - 'A' + 10
			default:
				t.Fatalf("invalid hex char %q", c)
			}
		}
		b[i/2] = v
	}
	return b
}

// -----------------------------------------------------------------------------
// ForkData.HashTreeRoot tests
// -----------------------------------------------------------------------------

func TestForkDataHashTreeRoot(t *testing.T) {
	tests := []struct {
		name    string
		fd      ForkData
		wantHex string
	}{
		{
			name:    "all_zeros",
			fd:      ForkData{},
			wantHex: "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
		},
		{
			name: "non_zero_version",
			fd: ForkData{
				CurrentVersion:        [4]byte{0x01, 0x02, 0x03, 0x04},
				GenesisValidatorsRoot: [32]byte{},
			},
			// computed dynamically below
			wantHex: "", // set in test body
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := tc.fd.HashTreeRoot()

			if tc.wantHex != "" {
				wantBytes := mustDecodeHex(t, tc.wantHex)
				var want [32]byte
				copy(want[:], wantBytes)
				if got != want {
					t.Errorf("ForkData%+v.HashTreeRoot() = %x, want %x", tc.fd, got, want)
				}
			} else {
				// Compute expected value directly for the non-zero case.
				// chunk0 = current_version padded to 32 bytes
				chunk0 := padRight(tc.fd.CurrentVersion[:], 32)
				var c0 [32]byte
				copy(c0[:], chunk0)
				// chunk1 = genesis_validators_root as-is
				c1 := tc.fd.GenesisValidatorsRoot
				want := sha256Pair(c0, c1)
				if got != want {
					t.Errorf("ForkData%+v.HashTreeRoot() = %x, want %x", tc.fd, got, want)
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// SigningData.HashTreeRoot tests
// -----------------------------------------------------------------------------

func TestSigningDataHashTreeRoot(t *testing.T) {
	tests := []struct {
		name    string
		sd      SigningData
		wantHex string
	}{
		{
			name:    "all_zeros",
			sd:      SigningData{},
			wantHex: "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
		},
		{
			name: "known_object_and_domain",
			sd: SigningData{
				ObjectRoot: [32]byte{0x01},
				Domain:     [32]byte{0x02},
			},
			// SHA-256([0x01, 0...] || [0x02, 0...])
			wantHex: "", // computed dynamically
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := tc.sd.HashTreeRoot()

			if tc.wantHex != "" {
				wantBytes := mustDecodeHex(t, tc.wantHex)
				var want [32]byte
				copy(want[:], wantBytes)
				if got != want {
					t.Errorf("SigningData%+v.HashTreeRoot() = %x, want %x", tc.sd, got, want)
				}
			} else {
				want := sha256Pair(tc.sd.ObjectRoot, tc.sd.Domain)
				if got != want {
					t.Errorf("SigningData%+v.HashTreeRoot() = %x, want %x", tc.sd, got, want)
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// DepositMessage.HashTreeRoot tests
// -----------------------------------------------------------------------------

func TestDepositMessageHashTreeRoot(t *testing.T) {
	tests := []struct {
		name    string
		msg     DepositMessage
		wantHex string
	}{
		{
			name:    "all_zeros",
			msg:     DepositMessage{},
			wantHex: "da6d807bf795106146e5822775d914b0277a65240f650ed4c8a7ca77824e5adf",
		},
		{
			// Independent anchor: computed from first principles — not via the
			// same sha256Pair helpers used in production. Verifies that changing
			// the amount propagates correctly through the container merkle tree.
			name: "with_amount_32gwei",
			msg: DepositMessage{
				Pubkey:                [48]byte{},
				WithdrawalCredentials: [32]byte{},
				Amount:                32_000_000_000,
			},
			wantHex: "239baae74829c617635cf3c579a355107ef752700f246b0bd10b50b05e16fd3e",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := tc.msg.HashTreeRoot()

			if tc.wantHex != "" {
				wantBytes := mustDecodeHex(t, tc.wantHex)
				var want [32]byte
				copy(want[:], wantBytes)
				if got != want {
					t.Errorf("DepositMessage.HashTreeRoot() = %x, want %x", got, want)
				}
			} else {
				// Compute expected value for the dynamic case.
				want := computeDepositMessageRoot(t, tc.msg)
				if got != want {
					t.Errorf("DepositMessage.HashTreeRoot() = %x, want %x", got, want)
				}
			}
		})
	}
}

// computeDepositMessageRoot is the reference implementation used in tests.
func computeDepositMessageRoot(t *testing.T, msg DepositMessage) [32]byte {
	t.Helper()
	// pubkey: merkleize 2 chunks → pubkeyRoot
	var pk0 [32]byte
	copy(pk0[:], msg.Pubkey[:32])
	var pk1 [32]byte
	copy(pk1[:], msg.Pubkey[32:48]) // low 16 bytes; high 16 remain zero
	pubkeyRoot := sha256Pair(pk0, pk1)

	// wc chunk
	wcChunk := msg.WithdrawalCredentials

	// amount chunk
	amountChunk := uint64Chunk(msg.Amount)

	// merkleize([pubkeyRoot, wcChunk, amountChunk], limit=3 → padded to 4)
	var zeroChunk [32]byte
	h01 := sha256Pair(pubkeyRoot, wcChunk)
	h23 := sha256Pair(amountChunk, zeroChunk)
	return sha256Pair(h01, h23)
}

// -----------------------------------------------------------------------------
// DepositData.HashTreeRoot tests
// -----------------------------------------------------------------------------

func TestDepositDataHashTreeRoot(t *testing.T) {
	tests := []struct {
		name    string
		data    DepositData
		wantHex string
	}{
		{
			name:    "all_zeros",
			data:    DepositData{},
			wantHex: "7d3bfa54172d8642a6c081084ce35542555a2998f48c5c9cd17f2d7a0754f3eb",
		},
		{
			// Independent anchor: verifies the amount field propagates through
			// the container tree correctly with a non-zero value.
			name: "with_amount_32gwei",
			data: DepositData{
				Amount: 32_000_000_000,
			},
			wantHex: "05125366a514ddd17fc8158440399c02d631cdb991dffa30623107f27e43673d",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := tc.data.HashTreeRoot()

			if tc.wantHex != "" {
				wantBytes := mustDecodeHex(t, tc.wantHex)
				var want [32]byte
				copy(want[:], wantBytes)
				if got != want {
					t.Errorf("DepositData.HashTreeRoot() = %x, want %x", got, want)
				}
			} else {
				want := computeDepositDataRoot(t, tc.data)
				if got != want {
					t.Errorf("DepositData.HashTreeRoot() = %x, want %x", got, want)
				}
			}
		})
	}
}

// computeDepositDataRoot is the reference implementation used in tests.
func computeDepositDataRoot(t *testing.T, data DepositData) [32]byte {
	t.Helper()
	// pubkeyRoot (same as DepositMessage)
	var pk0 [32]byte
	copy(pk0[:], data.Pubkey[:32])
	var pk1 [32]byte
	copy(pk1[:], data.Pubkey[32:48])
	pubkeyRoot := sha256Pair(pk0, pk1)

	wcChunk := data.WithdrawalCredentials
	amountChunk := uint64Chunk(data.Amount)

	// sigRoot: 3 chunks padded to 4
	var sig0, sig1, sig2, sigPad [32]byte
	copy(sig0[:], data.Signature[:32])
	copy(sig1[:], data.Signature[32:64])
	copy(sig2[:], data.Signature[64:96])
	sigH01 := sha256Pair(sig0, sig1)
	sigH23 := sha256Pair(sig2, sigPad)
	sigRoot := sha256Pair(sigH01, sigH23)

	// merkleize([pubkeyRoot, wcChunk, amountChunk, sigRoot], limit=4)
	h01 := sha256Pair(pubkeyRoot, wcChunk)
	h23 := sha256Pair(amountChunk, sigRoot)
	return sha256Pair(h01, h23)
}

// -----------------------------------------------------------------------------
// ComputeDomain tests
// -----------------------------------------------------------------------------

func TestComputeDomain(t *testing.T) {
	t.Run("all_zeros", func(t *testing.T) {
		domainType := [4]byte{}
		forkVersion := [4]byte{}
		gvr := [32]byte{}

		got := ComputeDomain(domainType, forkVersion, gvr)

		// Expected: domainType[0:4] || ForkData{forkVersion, gvr}.HashTreeRoot()[0:28]
		fd := ForkData{CurrentVersion: forkVersion, GenesisValidatorsRoot: gvr}
		fdRoot := fd.HashTreeRoot()
		var want [32]byte
		copy(want[:4], domainType[:])
		copy(want[4:], fdRoot[:28])

		if got != want {
			t.Errorf("ComputeDomain() = %x, want %x", got, want)
		}
	})

	t.Run("domain_deposit_with_hoodi_fork", func(t *testing.T) {
		domainType := [4]byte{0x03, 0x00, 0x00, 0x00}
		forkVersion := [4]byte{0x10, 0x00, 0x09, 0x10}
		gvr := [32]byte{}

		got := ComputeDomain(domainType, forkVersion, gvr)

		// First 4 bytes must be the domain type.
		if got[0] != 0x03 || got[1] != 0x00 || got[2] != 0x00 || got[3] != 0x00 {
			t.Errorf("domain type bytes wrong: got %x", got[:4])
		}
		// Bytes 4-31 must match the first 28 bytes of ForkData.HashTreeRoot().
		fd := ForkData{CurrentVersion: forkVersion, GenesisValidatorsRoot: gvr}
		fdRoot := fd.HashTreeRoot()
		for i := 0; i < 28; i++ {
			if got[i+4] != fdRoot[i] {
				t.Errorf("byte[%d] = %x, want %x", i+4, got[i+4], fdRoot[i])
			}
		}
	})
}

// -----------------------------------------------------------------------------
// ComputeSigningRoot tests
// -----------------------------------------------------------------------------

func TestComputeSigningRoot(t *testing.T) {
	t.Run("all_zeros", func(t *testing.T) {
		objectRoot := [32]byte{}
		domain := [32]byte{}

		got := ComputeSigningRoot(objectRoot, domain)

		// Expected: SigningData{objectRoot, domain}.HashTreeRoot()
		sd := SigningData{ObjectRoot: objectRoot, Domain: domain}
		want := sd.HashTreeRoot()

		if got != want {
			t.Errorf("ComputeSigningRoot() = %x, want %x", got, want)
		}
	})

	t.Run("non_zero_inputs", func(t *testing.T) {
		objectRoot := [32]byte{0x01, 0x02, 0x03}
		domain := [32]byte{0xFF}

		got := ComputeSigningRoot(objectRoot, domain)

		sd := SigningData{ObjectRoot: objectRoot, Domain: domain}
		want := sd.HashTreeRoot()

		if got != want {
			t.Errorf("ComputeSigningRoot() = %x, want %x", got, want)
		}
	})
}
