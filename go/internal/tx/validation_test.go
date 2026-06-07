package tx

import (
	"errors"
	"math/big"
	"testing"

	"github.com/rootwarp/eth-utils/go/internal/bls"
	"github.com/rootwarp/eth-utils/go/internal/deposit"
	"github.com/rootwarp/eth-utils/go/internal/network"
)

// validPubkey is a deterministic real BLS12-381 compressed G1 point (derived
// from fixed secret with [0]=0x42) so makeValidEntry / makeBase produce entries
// that pass the (now-enabled) bls.ValidatePubkeyBytes check in tx.Validate.
// Mirrors the construction pattern in internal/deposit/json_test.go.
var validPubkey = [48]byte{
	0x86, 0x7e, 0x2b, 0x29, 0xb8, 0xa2, 0xa7, 0xf4, 0x9d, 0x94, 0x4d, 0xaf, 0x7b, 0xf5, 0xe2, 0xad,
	0x3f, 0x0a, 0x75, 0x6a, 0xbf, 0x0f, 0x46, 0xee, 0xf1, 0x59, 0xfb, 0x7a, 0xf0, 0xb6, 0x48, 0x1c,
	0x4c, 0x19, 0x40, 0xf4, 0x2d, 0x63, 0xf2, 0x4c, 0x56, 0xa9, 0xa0, 0x86, 0x5b, 0x1a, 0x16, 0x94,
}

// makeValidEntry returns a deposit.Entry that passes every Validate check.
// WithdrawalCredentials use the 0x01 format: 0x01 || 11 zero bytes || 20-byte address.
func makeValidEntry() deposit.Entry {
	var e deposit.Entry
	e.Pubkey = validPubkey
	// 0x01 prefix, bytes 1–11 zero, bytes 12–31 non-zero eth1 address
	e.WithdrawalCredentials[0] = 0x01
	// bytes 1–11 remain zero (already zero from var)
	for i := 12; i < 32; i++ {
		e.WithdrawalCredentials[i] = 0x11
	}
	for i := range e.Signature {
		e.Signature[i] = 0xcd
	}
	for i := range e.DepositDataRoot {
		e.DepositDataRoot[i] = 0xef
	}
	e.Amount = 32_000_000_000
	e.NetworkName = network.Holesky
	return e
}

// makeValidConfig returns a BuildConfig that passes every Validate check.
func makeValidConfig(t *testing.T) BuildConfig {
	t.Helper()
	params, err := network.Lookup(network.Holesky)
	if err != nil {
		t.Fatal(err)
	}
	return BuildConfig{
		NetworkParams:        params,
		GasLimit:             250_000,
		MaxFeePerGas:         big.NewInt(20_000_000_000),
		MaxPriorityFeePerGas: big.NewInt(1_000_000_000),
	}
}

func TestValidate_Baseline(t *testing.T) {
	err := Validate(makeValidEntry(), makeValidConfig(t))
	if err != nil {
		t.Fatalf("expected nil error for valid entry+cfg, got: %v", err)
	}
}

func TestValidate_WCPrefix_0x00_Valid(t *testing.T) {
	e := makeValidEntry()
	// 0x00 prefix: all remaining bytes can be any value (BLS withdrawal)
	e.WithdrawalCredentials = [32]byte{}
	e.WithdrawalCredentials[0] = 0x00
	e.WithdrawalCredentials[31] = 0x01 // make non-zero elsewhere so root is not all-zero
	if err := Validate(e, makeValidConfig(t)); err != nil {
		t.Fatalf("0x00 WC prefix should be valid, got: %v", err)
	}
}

func TestValidate_WCPrefix_0x01_Valid(t *testing.T) {
	e := makeValidEntry()
	// 0x01 prefix properly formed
	e.WithdrawalCredentials = [32]byte{}
	e.WithdrawalCredentials[0] = 0x01
	for i := 12; i < 32; i++ {
		e.WithdrawalCredentials[i] = 0x22
	}
	if err := Validate(e, makeValidConfig(t)); err != nil {
		t.Fatalf("0x01 WC prefix (valid format) should pass, got: %v", err)
	}
}

func TestValidate_WCPrefix_0x02_Valid(t *testing.T) {
	e := makeValidEntry()
	// 0x02 prefix properly formed
	e.WithdrawalCredentials = [32]byte{}
	e.WithdrawalCredentials[0] = 0x02
	for i := 12; i < 32; i++ {
		e.WithdrawalCredentials[i] = 0x33
	}
	if err := Validate(e, makeValidConfig(t)); err != nil {
		t.Fatalf("0x02 WC prefix (valid format) should pass, got: %v", err)
	}
}

func TestValidate_Table(t *testing.T) {
	cfg := makeValidConfig(t)

	tests := []struct {
		name    string
		mutate  func(*deposit.Entry, *BuildConfig)
		wantErr error
	}{
		{
			name: "chain ID zero",
			mutate: func(_ *deposit.Entry, c *BuildConfig) {
				c.NetworkParams.ChainID = 0
			},
			wantErr: ErrUnconfiguredChainID,
		},
		{
			name: "wrong amount",
			mutate: func(e *deposit.Entry, _ *BuildConfig) {
				e.Amount = 1_000_000_000
			},
			wantErr: ErrInvalidAmount,
		},
		{
			name: "all-zero pubkey",
			mutate: func(e *deposit.Entry, _ *BuildConfig) {
				e.Pubkey = [48]byte{}
			},
			wantErr: ErrZeroPubkey,
		},
		{
			name: "all-zero signature",
			mutate: func(e *deposit.Entry, _ *BuildConfig) {
				e.Signature = [96]byte{}
			},
			wantErr: ErrZeroSignature,
		},
		{
			name: "all-zero deposit data root",
			mutate: func(e *deposit.Entry, _ *BuildConfig) {
				e.DepositDataRoot = [32]byte{}
			},
			wantErr: ErrZeroDepositRoot,
		},
		{
			name: "WC prefix 0x03 (invalid)",
			mutate: func(e *deposit.Entry, _ *BuildConfig) {
				e.WithdrawalCredentials = [32]byte{}
				e.WithdrawalCredentials[0] = 0x03
			},
			wantErr: ErrInvalidWCPrefix,
		},
		{
			name: "WC prefix 0x01 with non-zero padding at index 5",
			mutate: func(e *deposit.Entry, _ *BuildConfig) {
				e.WithdrawalCredentials = [32]byte{}
				e.WithdrawalCredentials[0] = 0x01
				e.WithdrawalCredentials[5] = 0xFF
			},
			wantErr: ErrInvalidWCFormat,
		},
		{
			name: "WC prefix 0x02 with non-zero padding at index 5",
			mutate: func(e *deposit.Entry, _ *BuildConfig) {
				e.WithdrawalCredentials = [32]byte{}
				e.WithdrawalCredentials[0] = 0x02
				e.WithdrawalCredentials[5] = 0xFF
			},
			wantErr: ErrInvalidWCFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := makeValidEntry()
			c := cfg
			tt.mutate(&e, &c)
			err := Validate(e, c)
			if err == nil {
				t.Fatalf("expected error wrapping %v, got nil", tt.wantErr)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected errors.Is(%v), got: %v", tt.wantErr, err)
			}
		})
	}
}

// TestTxValidate_WC_Reject table mirrors M0.4-4's coverage (5 cases); asserts
// via errors.Is against the tx sentinels (ErrZeroWithdrawal00 for 0x00 all-zero;
// ErrInvalidWCFormat for bad 0x01/0x02 padding; ErrInvalidWCPrefix for other prefix).
func TestTxValidate_WC_Reject(t *testing.T) {
	makeBase := func() deposit.Entry {
		var e deposit.Entry
		e.Pubkey = validPubkey
		e.Signature[0] = 0xCD
		e.DepositDataRoot[0] = 0xEF
		e.Amount = 32_000_000_000
		e.NetworkName = network.Holesky
		e.WithdrawalCredentials[0] = 0x01 // base good; mut will override
		return e
	}

	cfg := makeValidConfig(t)

	tests := []struct {
		name    string
		mutFn   func(*deposit.Entry)
		wantErr error
	}{
		{
			name:    "zero_0x00_allzero",
			mutFn:   func(e *deposit.Entry) { e.WithdrawalCredentials = [32]byte{} },
			wantErr: ErrZeroWithdrawal00,
		},
		{
			name: "0x01_nonzero_byte1",
			mutFn: func(e *deposit.Entry) {
				e.WithdrawalCredentials = [32]byte{}
				e.WithdrawalCredentials[0] = 0x01
				e.WithdrawalCredentials[1] = 0x01 // non-zero in 1..11
			},
			wantErr: ErrInvalidWCFormat,
		},
		{
			name: "0x01_nonzero_byte11",
			mutFn: func(e *deposit.Entry) {
				e.WithdrawalCredentials = [32]byte{}
				e.WithdrawalCredentials[0] = 0x01
				e.WithdrawalCredentials[11] = 0x01 // non-zero in 1..11
			},
			wantErr: ErrInvalidWCFormat,
		},
		{
			name: "0x02_nonzero_byte5",
			mutFn: func(e *deposit.Entry) {
				e.WithdrawalCredentials = [32]byte{}
				e.WithdrawalCredentials[0] = 0x02
				e.WithdrawalCredentials[5] = 0x02 // non-zero in 1..11
			},
			wantErr: ErrInvalidWCFormat,
		},
		{
			name: "bad_prefix_0xff",
			mutFn: func(e *deposit.Entry) {
				e.WithdrawalCredentials = [32]byte{}
				e.WithdrawalCredentials[0] = 0xff
			},
			wantErr: ErrInvalidWCPrefix,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			e := makeBase()
			tc.mutFn(&e)
			err := Validate(e, cfg)
			if err == nil {
				t.Fatalf("Validate() = nil, want error wrapping %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Validate() error = %v: not errors.Is(%v)", err, tc.wantErr)
			}
		})
	}
}

// TestDID_ZeroWC_DoubleReject verifies cross-layer regression: the *same*
// all-zero 0x00 entry is rejected at both deposit.Entry.Validate and tx.Validate
// layers (via errors.Is on the package-specific sentinels).
func TestDID_ZeroWC_DoubleReject(t *testing.T) {
	e := makeValidEntry()
	e.WithdrawalCredentials = [32]byte{} // the same all-zero 0x00 WC
	c := makeValidConfig(t)

	// deposit layer (M0.4-4)
	if err := e.Validate(); err == nil || !errors.Is(err, deposit.ErrZeroWithdrawal00) {
		t.Fatalf("Entry.Validate(zero-0x00): got %v, want wrap deposit.ErrZeroWithdrawal00", err)
	}

	// tx layer (M0.4-5)
	if err := Validate(e, c); err == nil || !errors.Is(err, ErrZeroWithdrawal00) {
		t.Fatalf("tx.Validate(zero-0x00): got %v, want wrap ErrZeroWithdrawal00", err)
	}
}

// TestTxValidate_PubkeyInvalid_OffCurve exercises the (re-enabled) production
// path for bls.ValidatePubkeyBytes inside tx.Validate. A non-zero but
// off-curve compressed G1 point must be rejected with exactly bls.ErrPubkeyInvalid
// (bypassing the earlier zero-pubkey sentinel). Mirrors deposit side (M0.5-1)
// and satisfies AC for M0.5-3.
func TestTxValidate_PubkeyInvalid_OffCurve(t *testing.T) {
	e := makeValidEntry()
	// Hand-crafted off-curve (non-zero so zero check passes; fails G1 Deserialize).
	// 0x80 prefix + zeros is rejected by herumi (and thus our ValidatePubkeyBytes).
	e.Pubkey = [48]byte{0x80}
	c := makeValidConfig(t)

	err := Validate(e, c)
	if err == nil {
		t.Fatal("expected bls pubkey error, got nil")
	}
	if !errors.Is(err, bls.ErrPubkeyInvalid) {
		t.Errorf("expected errors.Is(err, bls.ErrPubkeyInvalid), got: %v", err)
	}
}

// TestTxValidateAgainstNetwork_NetworkMismatch: hoodi entry vs mainnet params → ErrNetworkMismatchTx.
// (AC) Mirrors deposit TestValidateForNetwork_NetworkMismatch but tx DiD layer.
func TestTxValidateAgainstNetwork_NetworkMismatch(t *testing.T) {
	pHoodi, err := network.Lookup(network.Hoodi)
	if err != nil {
		t.Fatalf("Lookup hoodi: %v", err)
	}
	pMain, err := network.Lookup(network.Mainnet)
	if err != nil {
		t.Fatalf("Lookup mainnet: %v", err)
	}
	e := makeValidEntry()
	e.NetworkName = pHoodi.Name
	e.ForkVersion = pHoodi.GenesisForkVersion
	if err := ValidateAgainstNetwork(e, pMain); err == nil || !errors.Is(err, ErrNetworkMismatchTx) {
		t.Fatalf("ValidateAgainstNetwork(hoodi entry, mainnet params) error = %v, want errors.Is(ErrNetworkMismatchTx)", err)
	}
}

// TestTxValidateAgainstNetwork_ForkMismatch: mismatched fork_version → wrapped sentinel (deposit.ErrForkVersionMismatch via %w).
// (AC)
func TestTxValidateAgainstNetwork_ForkMismatch(t *testing.T) {
	pHoodi, err := network.Lookup(network.Hoodi)
	if err != nil {
		t.Fatalf("Lookup hoodi: %v", err)
	}
	e := makeValidEntry()
	e.NetworkName = pHoodi.Name
	e.ForkVersion = pHoodi.GenesisForkVersion
	// Tamper the fork version bytes (any change triggers mismatch).
	e.ForkVersion[0] ^= 0xff
	err = ValidateAgainstNetwork(e, pHoodi)
	if err == nil {
		t.Fatal("ValidateAgainstNetwork(tampered fork_version) = nil, want wrapped sentinel")
	}
	if !errors.Is(err, deposit.ErrForkVersionMismatch) {
		t.Errorf("ValidateAgainstNetwork(tampered fork_version) error = %v, want errors.Is(deposit.ErrForkVersionMismatch)", err)
	}
}

// TestDID_NetworkBinding_DoubleReject verifies cross-layer regression: the *same*
// hoodi entry (name+fork) is rejected at tx.ValidateAgainstNetwork even if
// Entry.ValidateForNetwork call is bypassed (the key DiD proof for M0.5-4).
// Mirrors TestDID_ZeroWC_DoubleReject (M0.4-5) pattern + uses deposit call + tx call.
func TestDID_NetworkBinding_DoubleReject(t *testing.T) {
	pHoodi, err := network.Lookup(network.Hoodi)
	if err != nil {
		t.Fatalf("Lookup hoodi: %v", err)
	}
	pMain, err := network.Lookup(network.Mainnet)
	if err != nil {
		t.Fatalf("Lookup mainnet: %v", err)
	}
	e := makeValidEntry()
	e.NetworkName = pHoodi.Name
	e.ForkVersion = pHoodi.GenesisForkVersion

	// deposit layer (M0.5-1)
	if err := e.ValidateForNetwork(pMain, bls.DefaultVerifier()); err == nil || !errors.Is(err, deposit.ErrNetworkMismatch) {
		t.Fatalf("Entry.ValidateForNetwork(hoodi, mainnet): got %v, want wrap deposit.ErrNetworkMismatch", err)
	}

	// tx layer (M0.5-4) -- still trips even if deposit gate above bypassed/skipped
	if err := ValidateAgainstNetwork(e, pMain); err == nil || !errors.Is(err, ErrNetworkMismatchTx) {
		t.Fatalf("tx.ValidateAgainstNetwork(hoodi, mainnet): got %v, want wrap ErrNetworkMismatchTx", err)
	}
}

// TestTxValidateAgainstNetwork_HappyPath: well-formed matching entry+params → nil.
// Covers the 4th AC (happy path).
func TestTxValidateAgainstNetwork_HappyPath(t *testing.T) {
	pHoodi, err := network.Lookup(network.Hoodi)
	if err != nil {
		t.Fatalf("Lookup hoodi: %v", err)
	}
	e := makeValidEntry()
	e.NetworkName = pHoodi.Name
	e.ForkVersion = pHoodi.GenesisForkVersion
	if err := ValidateAgainstNetwork(e, pHoodi); err != nil {
		t.Errorf("ValidateAgainstNetwork(well-formed hoodi entry vs hoodi params) unexpected error: %v", err)
	}
}
