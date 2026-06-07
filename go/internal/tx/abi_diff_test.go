package tx

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// Note on [SEC] INFO dep surface: accounts/abi (and geth v1.17.3) is test-only use here;
// already transitive dep (via ethclient etc from M0.2-1 + builder/rpc paths); no change to
// go.mod; see go.mod:8 + research/05:108 + architecture §11.2. govulncheck surface unchanged
// for this encode-only usage. No build tag (per impl notes).

// depositABIJSON is the ABI JSON for the deposit(bytes,bytes,bytes,bytes32) function.
// Embedded at top of file per M1.2-6 implementation notes + research/05 addendum + architecture §11.2.
// Exact string from research/05:112-120 for embed fidelity (ABI cross-check source of truth).
// PR-controlled test file: per [SEC] HIGH bypass finding, changes to this const (or test logic) require
// manual re-cross against canonical deposit ABI + geth (outside PR's go.mod); this is the defense gate
// (analog to M1.2-5 oracle). Divergence detection uses bytes.Equal (no shared code path).
const depositABIJSON = `[{
    "name":"deposit","type":"function",
    "inputs":[
        {"name":"pubkey","type":"bytes"},
        {"name":"withdrawal_credentials","type":"bytes"},
        {"name":"signature","type":"bytes"},
        {"name":"deposit_data_root","type":"bytes32"}
    ]
}]`

func TestPackDeposit_AgainstGethABI(t *testing.T) {
	parsed, err := abi.JSON(strings.NewReader(depositABIJSON))
	if err != nil {
		t.Fatal(err)
	}
	// Concrete vector (follows existing LengthWithRandomBytes + RoundTrip patterns in abi_test.go; exercises dynamic+static layout).
	var pk [48]byte
	var wc [32]byte
	var sig [96]byte
	var root [32]byte
	for i := range pk {
		pk[i] = byte(i + 0xab)
	}
	for i := range wc {
		wc[i] = byte(i + 0xcd)
	}
	for i := range sig {
		sig[i] = byte(i + 0xef)
	}
	root[0] = 0x42

	args := []any{pk[:], wc[:], sig[:], root}
	geth, err := parsed.Pack("deposit", args...)
	if err != nil {
		t.Fatal(err)
	}
	ours := PackDeposit(pk, wc, sig, root)
	if !bytes.Equal(geth, ours) {
		// Opaque mismatch (no %x of full calldata) to avoid embedding privkey-derived sig bytes
		// (even from synthetic vectors) in t.Fatal / CI logs / artifacts. Per [SEC] MED Finding 2
		// (cleartext sigs in t.Fatalf + fuzz corpus) + M0.8 secret hygiene + prior SEC roots-in-logs
		// pattern (ssz_oracle_test.go:92 comment uses %x only for public roots). Use "non-mismatch"
		// %x visibility only in happy-path tests (abi_test.go); for this cross use t.Error opaque
		// + local edit for debug if needed. Synthetic corpus enforced below.
		t.Error("ABI mismatch")
	}
}

func FuzzPackDeposit_AgainstGethABI(f *testing.F) {
	// Seed-anchored fuzz driving both encoders (per M1.2-6 + exact Fuzz* patterns from ssz_oracle_test.go:102+).
	// Public synthetic only; trims to field sizes; asserts byte equality (no divergence).
	f.Add([]byte{}, []byte{}, []byte{}, []byte{})
	f.Add(
		bytes.Repeat([]byte{0xab}, 48),
		bytes.Repeat([]byte{0xcd}, 32),
		bytes.Repeat([]byte{0xef}, 96),
		bytes.Repeat([]byte{0x42}, 32),
	)
	f.Add(
		func() []byte { b := make([]byte, 50); b[0] = 0x11; b[47] = 0xff; return b }(),
		func() []byte { b := make([]byte, 33); b[31] = 0x22; return b }(),
		func() []byte { b := make([]byte, 100); b[95] = 0x33; return b }(),
		func() []byte { b := make([]byte, 32); b[0] = 0x44; return b }(),
	)
	f.Fuzz(func(t *testing.T, pkB, wcB, sigB, rootB []byte) {
		if len(pkB) > 48 {
			pkB = pkB[:48]
		}
		if len(wcB) > 32 {
			wcB = wcB[:32]
		}
		if len(sigB) > 96 {
			sigB = sigB[:96]
		}
		if len(rootB) > 32 {
			rootB = rootB[:32]
		}
		var pk [48]byte
		copy(pk[:], pkB)
		var wc [32]byte
		copy(wc[:], wcB)
		var sig [96]byte
		copy(sig[:], sigB)
		var root [32]byte
		copy(root[:], rootB)

		parsed, err := abi.JSON(strings.NewReader(depositABIJSON))
		if err != nil {
			t.Fatal(err)
		}
		args := []any{pk[:], wc[:], sig[:], root}
		geth, err := parsed.Pack("deposit", args...)
		if err != nil {
			t.Fatal(err)
		}
		ours := PackDeposit(pk, wc, sig, root)
		if !bytes.Equal(geth, ours) {
			// Synthetic corpus enforcement: seeds are only repeats/markers/empty (never keys.json,
			// phase fixtures, or real bls_secret_hex per [SEC] MED on sig material in fuzz corpus).
			// Opaque t.Error (no %x dump of sig-containing calldata) for log hygiene; failing input
			// is auto-added to corpus by fuzz for local repro. Error handling: fatal only on parse
			// (rare); mismatch records via t.Error for visibility without leaking. Matches ssz_oracle
			// + cli_fuzz patterns exactly.
			t.Errorf("PackDeposit fuzz mismatch")
		}
	})
}
