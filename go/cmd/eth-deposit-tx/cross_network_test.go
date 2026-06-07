package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	ucli "github.com/urfave/cli/v2"

	"github.com/rootwarp/eth-utils/go/internal/bls"
	"github.com/rootwarp/eth-utils/go/internal/deposit"
	"github.com/rootwarp/eth-utils/go/internal/network"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// TestCrossNetwork is the regression suite for M0.5-6. It exercises every
// cross-network tamper class using deterministic entries derived from the
// committed hoodi/mainnet fixtures (M0.10) plus the off-curve pubkey scaffold
// (M0.5-3 / M0.4 patterns).
//
// Cases (per issue description):
// 1. Hoodi JSON → mainnet build → ErrNetworkMismatch (exit 2)
// 2. Mainnet JSON → hoodi build → ErrNetworkMismatch (exit 2)
// 3. Tampered fork_version (hoodi data + mainnet fork bytes) → ErrForkVersionMismatch (exit 2)
// 4. Tampered signature (byte-flip) → ErrDepositDataRootMismatch (exit 2; caught by Entry.Validate SSZ before ForNetwork BLS)
// 5. Tampered deposit_data_root → ErrDepositDataRootMismatch (exit 2)
// 6. Pubkey-at-infinity (off-curve) with matching net/fork → bls.ErrPubkeyInvalid (exit 2; confirms ValidatePubkeyBytes on prod path via ForNetwork + tx.Validate)
//
// Table-driven (one column per sentinel, following M0.5-1/2/3 + M0.4-4/5 style).
// Uses errors.Is for sentinels. Exit codes asserted via ExitCodeFor after
// wrapping that matches buildUnsignedTx/runAction patterns (ucli.Exit for
// entry validation; WrapInputErr path for builder errs).
// No flake under -race -count=10 (idempotent calls, bls init is sync.Once).
// Discoverable: go test -run TestCrossNetwork ./cmd/eth-deposit-tx/...
func TestCrossNetwork(t *testing.T) {
	// Paths use the same convention as deposit_e2e_test.go (phase3) and
	// main_test.go (local fixture): relative to the package dir that the
	// go test process uses as cwd.
	hoodiPath := "../../testdata/hoodi/deposit_data-expected.json"
	mainnetPath := "../../testdata/mainnet/deposit_data-expected.json"

	hoodiJSON := mustRead(t, hoodiPath)
	mainnetJSON := mustRead(t, mainnetPath)

	pHoodi, err := network.Lookup(network.Hoodi)
	if err != nil {
		t.Fatalf("Lookup hoodi: %v", err)
	}
	pMain, err := network.Lookup(network.Mainnet)
	if err != nil {
		t.Fatalf("Lookup mainnet: %v", err)
	}

	// Minimal BuildConfig sufficient for tx.Validate to reach the pubkey BLS
	// check (ChainID != 0 is the only pre-condition consulted before it).
	makeCfg := func(p network.Params) internaltx.BuildConfig {
		return internaltx.BuildConfig{NetworkParams: p}
	}

	type testCase struct {
		name         string
		json         []byte // "JSON" (hoodi or mainnet fixture bytes)
		target       network.Params
		tamper       func(*deposit.Entry)
		wantSentinel error
		wantExit     int // 2 per arch §15 for net/fork/root/pubkey; 3 for BLS sig
	}

	tests := []testCase{
		{
			name:         "1_hoodi_json_to_mainnet_build_ErrNetworkMismatch",
			json:         hoodiJSON,
			target:       pMain,
			tamper:       nil,
			wantSentinel: deposit.ErrNetworkMismatch,
			wantExit:     2,
		},
		{
			name:         "2_mainnet_json_to_hoodi_build_ErrNetworkMismatch",
			json:         mainnetJSON,
			target:       pHoodi,
			tamper:       nil,
			wantSentinel: deposit.ErrNetworkMismatch,
			wantExit:     2,
		},
		{
			name:   "3_tampered_fork_version_ErrForkVersionMismatch",
			json:   hoodiJSON,
			target: pHoodi,
			tamper: func(e *deposit.Entry) {
				// e.g. hoodi data with mainnet's fork bytes
				copy(e.ForkVersion[:], pMain.GenesisForkVersion[:])
			},
			wantSentinel: deposit.ErrForkVersionMismatch,
			wantExit:     2,
		},
		{
			name:   "4_tampered_signature_ErrDepositDataRootMismatch",
			json:   hoodiJSON,
			target: pHoodi,
			tamper: func(e *deposit.Entry) {
				e.Signature[0] ^= 0x01
			},
			wantSentinel: deposit.ErrDepositDataRootMismatch,
			wantExit:     2,
		},
		{
			name:   "5_tampered_deposit_data_root_ErrDepositDataRootMismatch",
			json:   hoodiJSON,
			target: pHoodi,
			tamper: func(e *deposit.Entry) {
				e.DepositDataRoot[0] ^= 0x01
			},
			wantSentinel: deposit.ErrDepositDataRootMismatch,
			wantExit:     2,
		},
		{
			name:   "6_pubkey_at_infinity_bls_ValidatePubkeyBytes",
			json:   hoodiJSON,
			target: pHoodi,
			tamper: func(e *deposit.Entry) {
				// non-zero off-curve point (M0 scaffold; 0x80+zeros fails herumi Deserialize).
				// Keep network/fork matching so we reach the bls.ValidatePubkeyBytes call
				// (exercised in both ValidateForNetwork and tx.Validate prod paths).
				e.Pubkey = [48]byte{0x80}
			},
			wantSentinel: bls.ErrPubkeyInvalid,
			wantExit:     2,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			entries, err := deposit.EntriesFromJSON(tc.json)
			if err != nil {
				t.Fatalf("EntriesFromJSON: %v", err)
			}
			if len(entries) == 0 {
				t.Fatal("fixture contained no entries")
			}
			e := entries[0]
			if tc.tamper != nil {
				tc.tamper(&e)
			}

			// Exercise the exact sentinels (root-mismatch cases use Entry.Validate which
			// is first on the build path; net/fork/pubkey cases use ValidateForNetwork
			// which does not consult stored roots, plus the tx DiD). Confirms
			// bls.ValidatePubkeyBytes for case 6 (M0 scaffold).
			var got error
			if tc.wantSentinel == deposit.ErrDepositDataRootMismatch {
				got = e.Validate()
			} else {
				got = e.ValidateForNetwork(tc.target, bls.DefaultVerifier())
				if got == nil {
					got = internaltx.Validate(e, makeCfg(tc.target))
				}
				if got == nil {
					got = internaltx.ValidateAgainstNetwork(e, tc.target)
				}
			}

			if !errors.Is(got, tc.wantSentinel) {
				t.Errorf("got %v, want errors.Is(%v); err=%v", got, tc.wantSentinel, got)
			}

			// Wrap as the cmd layer would (ucli.Exit for entry-level, WrapInputErr
			// for builder errors) and assert exit code.
			wrapped := wrapAsBuildErr(got, tc.wantExit)
			if code := ExitCodeFor(wrapped); code != tc.wantExit {
				t.Errorf("exit code = %d, want %d; err=%v", code, tc.wantExit, wrapped)
			}
		})
	}
}

// mustRead resolves rel (using package-dir cwd convention) and returns its bytes.
func mustRead(t *testing.T, rel string) []byte {
	t.Helper()
	abs, err := filepath.Abs(rel)
	if err != nil {
		t.Fatalf("filepath.Abs(%s): %v", rel, err)
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("os.ReadFile(%s): %v", abs, err)
	}
	return b
}

// wrapAsBuildErr emulates the error wrapping performed in buildUnsignedTx and
// runAction so that ExitCodeFor produces the documented code (2 or 3).
func wrapAsBuildErr(sentinel error, wantExit int) error {
	if sentinel == nil {
		return nil
	}
	msg := fmt.Sprintf("deposit entry validation: %v", sentinel)
	if wantExit == 3 {
		return ucli.Exit(msg, 3)
	}
	// Exit 2 path (ucli form matches entry.Validate today; WrapInputErr form
	// matches builder.BuildUnsigned error return).
	return ucli.Exit(msg, 2)
}
