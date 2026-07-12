package tx

import (
	"errors"
	"math/big"
	"testing"

	"github.com/rootwarp/eth-utils/go/internal/deposit"
	"github.com/rootwarp/eth-utils/go/internal/network"
)

// makeValidEntry returns a deposit.Entry that passes every Validate check.
// WithdrawalCredentials use the 0x01 format: 0x01 || 11 zero bytes || 20-byte address.
func makeValidEntry() deposit.Entry {
	var e deposit.Entry
	for i := range e.Pubkey {
		e.Pubkey[i] = 0xab
	}
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
