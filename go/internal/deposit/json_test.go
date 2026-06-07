package deposit

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/rootwarp/eth-utils/go/internal/bls"
	"github.com/rootwarp/eth-utils/go/internal/network"
	"github.com/rootwarp/eth-utils/go/internal/ssz"
)

// validRawEntry returns a jsonEntry with valid values for all fields.
func validRawEntry() jsonEntry {
	return jsonEntry{
		Pubkey:                strings.Repeat("ab", 48),
		WithdrawalCredentials: strings.Repeat("cd", 32),
		Amount:                32_000_000_000,
		Signature:             strings.Repeat("ef", 96),
		DepositMessageRoot:    strings.Repeat("01", 32),
		DepositDataRoot:       strings.Repeat("02", 32),
		ForkVersion:           "10000910",
		NetworkName:           "hoodi",
		DepositCLIVersion:     "2.7.0",
	}
}

func marshalJSONArray(rs []jsonEntry) ([]byte, error) {
	return json.Marshal(rs)
}

// TestEntriesFromJSON_Array verifies parsing a JSON array of entries.
func TestEntriesFromJSON_Array(t *testing.T) {
	raw := validRawEntry()
	data, err := marshalJSONArray([]jsonEntry{raw, raw})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	entries, err := EntriesFromJSON(data)
	if err != nil {
		t.Fatalf("EntriesFromJSON() error = %v, want nil", err)
	}
	if len(entries) != 2 {
		t.Errorf("EntriesFromJSON() returned %d entries, want 2", len(entries))
	}
}

// TestEntriesFromJSON_EmptyArray verifies that an empty JSON array returns
// empty slice and no error.
func TestEntriesFromJSON_EmptyArray(t *testing.T) {
	entries, err := EntriesFromJSON([]byte(`[]`))
	if err != nil {
		t.Fatalf("EntriesFromJSON([]) error = %v, want nil", err)
	}
	if len(entries) != 0 {
		t.Errorf("EntriesFromJSON([]) returned %d entries, want 0", len(entries))
	}
}

// TestEntriesFromJSON_InvalidEntry verifies that a bad entry inside the array
// produces an error naming the index.
func TestEntriesFromJSON_InvalidEntry(t *testing.T) {
	good := validRawEntry()
	bad := validRawEntry()
	bad.Pubkey = strings.Repeat("ZZ", 48)

	data, err := marshalJSONArray([]jsonEntry{good, bad})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, err = EntriesFromJSON(data)
	if err == nil {
		t.Fatal("EntriesFromJSON() with bad entry[1]: want error, got nil")
	}
	if !strings.Contains(err.Error(), "entry[1]") {
		t.Errorf("error %q does not name the failing index", err.Error())
	}
}

// TestEntriesFromJSON_GoldenFile verifies that the golden output from
// eth-deposit-gen is parseable by EntriesFromJSON.
func TestEntriesFromJSON_GoldenFile(t *testing.T) {
	data, err := os.ReadFile("../../testdata/hoodi/deposit_data-expected.json")
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	entries, err := EntriesFromJSON(data)
	if err != nil {
		t.Fatalf("EntriesFromJSON(golden) error = %v", err)
	}
	if len(entries) == 0 {
		t.Errorf("got %d entries from golden fixture, want >0", len(entries))
	}
}

// ---------------------------------------------------------------------------
// Validate tests
// ---------------------------------------------------------------------------

// TestValidate_Valid verifies that a well-formed Entry with non-zero meaningful
// values passes Validate.
func TestValidate_Valid(t *testing.T) {
	var e Entry
	e.Pubkey[0] = 0xAB
	e.Signature[0] = 0xCD
	e.DepositDataRoot[0] = 0xEF
	e.Amount = 32_000_000_000
	e.NetworkName = network.Hoodi
	e.WithdrawalCredentials[0] = 0x01 // canonical shape (0x01 + 11x00 + addr)

	msg := ssz.DepositMessage{
		Pubkey:                e.Pubkey,
		WithdrawalCredentials: e.WithdrawalCredentials,
		Amount:                e.Amount,
	}
	e.DepositMessageRoot = msg.HashTreeRoot()
	data := ssz.DepositData{
		Pubkey:                e.Pubkey,
		WithdrawalCredentials: e.WithdrawalCredentials,
		Amount:                e.Amount,
		Signature:             e.Signature,
	}
	e.DepositDataRoot = data.HashTreeRoot()

	if err := e.Validate(); err != nil {
		t.Errorf("Validate() on valid entry: unexpected error: %v", err)
	}
}

// TestValidate_Invalid verifies that each individual invariant failure is
// caught and the error message is descriptive.
func TestValidate_Invalid(t *testing.T) {
	makeBase := func() Entry {
		var e Entry
		e.Pubkey[0] = 0xAB
		e.Signature[0] = 0xCD
		e.DepositDataRoot[0] = 0xEF
		e.Amount = 32_000_000_000
		e.NetworkName = network.Hoodi
		e.WithdrawalCredentials[0] = 0x01 // canonical shape passes new WC checks
		return e
	}

	tests := []struct {
		name    string
		mutFn   func(*Entry)
		wantErr string
	}{
		{
			name:    "zero_pubkey",
			mutFn:   func(e *Entry) { e.Pubkey = [48]byte{} },
			wantErr: "pubkey",
		},
		{
			name:    "zero_signature",
			mutFn:   func(e *Entry) { e.Signature = [96]byte{} },
			wantErr: "signature",
		},
		{
			name:    "zero_deposit_data_root",
			mutFn:   func(e *Entry) { e.DepositDataRoot = [32]byte{} },
			wantErr: "deposit_data_root",
		},
		{
			name:    "zero_amount",
			mutFn:   func(e *Entry) { e.Amount = 0 },
			wantErr: "amount",
		},
		{
			name:    "unknown_network",
			mutFn:   func(e *Entry) { e.NetworkName = "goerli" },
			wantErr: "network_name",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			e := makeBase()
			tc.mutFn(&e)
			err := e.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate() error = %q: does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestEntry_Validate_WC_Reject is the table-driven coverage for the DiD WC
// shape checks added to Entry.Validate. Each case must return an error
// satisfying errors.Is(err, the expected sentinel).
func TestEntry_Validate_WC_Reject(t *testing.T) {
	makeBase := func() Entry {
		var e Entry
		e.Pubkey[0] = 0xAB
		e.Signature[0] = 0xCD
		e.Amount = 32_000_000_000
		e.NetworkName = network.Hoodi
		e.WithdrawalCredentials[0] = 0x01 // base good; mutFn will override for reject cases
		return e
	}

	tests := []struct {
		name    string
		mutFn   func(*Entry)
		wantErr error
	}{
		{
			name:    "zero_0x00_allzero",
			mutFn:   func(e *Entry) { e.WithdrawalCredentials = [32]byte{} },
			wantErr: ErrZeroWithdrawal00,
		},
		{
			name: "0x01_nonzero_byte1",
			mutFn: func(e *Entry) {
				e.WithdrawalCredentials[0] = 0x01
				e.WithdrawalCredentials[1] = 0x01 // non-zero in 1..11
			},
			wantErr: ErrInvalidWCFormat,
		},
		{
			name: "0x01_nonzero_byte11",
			mutFn: func(e *Entry) {
				e.WithdrawalCredentials[0] = 0x01
				e.WithdrawalCredentials[11] = 0x01 // non-zero in 1..11
			},
			wantErr: ErrInvalidWCFormat,
		},
		{
			name: "0x02_nonzero_byte5",
			mutFn: func(e *Entry) {
				e.WithdrawalCredentials[0] = 0x02
				e.WithdrawalCredentials[5] = 0x02 // non-zero in 1..11
			},
			wantErr: ErrInvalidWCFormat,
		},
		{
			name: "bad_prefix_0xff",
			mutFn: func(e *Entry) {
				e.WithdrawalCredentials[0] = 0xff
			},
			wantErr: ErrInvalidWCFormat,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			e := makeBase()
			tc.mutFn(&e)
			err := e.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error wrapping %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Validate() error = %v: not errors.Is(%v)", err, tc.wantErr)
			}
		})
	}
}

// TestEntry_Validate_WC_Accept confirms that the canonical 0x01 layout
// (0x01 || 0x00*11 || 20-byte addr) passes the WC shape checks (when the
// rest of the Entry also satisfies the other Validate rules).
func TestEntry_Validate_WC_Accept(t *testing.T) {
	var e Entry
	e.Pubkey[0] = 0xAB
	e.Signature[0] = 0xCD
	e.DepositDataRoot[0] = 0xEF
	e.Amount = 32_000_000_000
	e.NetworkName = network.Hoodi
	// canonical 0x01: 0x01 + 11 zero bytes + 20-byte address (non-zero tail is fine)
	e.WithdrawalCredentials[0] = 0x01
	// bytes 1-11 stay zero (default)
	e.WithdrawalCredentials[12] = 0x01 // start of "addr" part
	e.WithdrawalCredentials[31] = 0x02 // some non-zero in addr part

	msg := ssz.DepositMessage{
		Pubkey:                e.Pubkey,
		WithdrawalCredentials: e.WithdrawalCredentials,
		Amount:                e.Amount,
	}
	e.DepositMessageRoot = msg.HashTreeRoot()
	data := ssz.DepositData{
		Pubkey:                e.Pubkey,
		WithdrawalCredentials: e.WithdrawalCredentials,
		Amount:                e.Amount,
		Signature:             e.Signature,
	}
	e.DepositDataRoot = data.HashTreeRoot()

	if err := e.Validate(); err != nil {
		t.Errorf("Validate() on canonical 0x01 WC entry: unexpected error: %v", err)
	}
}

// validSignedEntryForParams constructs a minimal Entry whose pubkey is a
// real on-curve BLS G1 point (derived via NewSigner) and whose signature
// is a real signature over the DepositMessage for the target's deposit
// domain. The resulting entry satisfies the BLS parts of
// ValidateForNetwork(target, bls.DefaultVerifier()).
func validSignedEntryForParams(t *testing.T, p network.Params) Entry {
	t.Helper()

	// Small fixed secret produces a deterministic valid pubkey (see cli_test.go pattern).
	secret := make([]byte, 32)
	secret[0] = 0x42
	snr, err := bls.NewSigner(secret)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	pub, err := snr.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	wc := [32]byte{}
	wc[0] = 0x01
	wc[31] = 0x02 // non-zero tail ok for 0x01
	amount := uint64(32_000_000_000)

	msg := ssz.DepositMessage{
		Pubkey:                pub,
		WithdrawalCredentials: wc,
		Amount:                amount,
	}
	msgRoot := msg.HashTreeRoot()
	domain := ssz.ComputeDomain(network.DomainDeposit(), p.GenesisForkVersion, network.ZeroGenesisValidatorsRoot())
	signingRoot := ssz.ComputeSigningRoot(msgRoot, domain)

	sig, err := snr.Sign(signingRoot)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	var e Entry
	e.Pubkey = pub
	e.WithdrawalCredentials = wc
	e.Amount = amount
	e.Signature = sig
	e.DepositMessageRoot = msgRoot
	copy(e.ForkVersion[:], p.GenesisForkVersion[:])
	e.NetworkName = p.Name
	e.DepositCLIVersion = "2.7.0"
	return e
}

// ---------------------------------------------------------------------------
// ValidateForNetwork tests (M0.5-1)
// ---------------------------------------------------------------------------

func TestValidateForNetwork_NetworkMismatch(t *testing.T) {
	pHoodi := hoodiParams()
	pMain, err := network.Lookup(network.Mainnet)
	if err != nil {
		t.Fatalf("Lookup mainnet: %v", err)
	}
	e := validSignedEntryForParams(t, pHoodi)
	if err := e.ValidateForNetwork(pMain, bls.DefaultVerifier()); !errors.Is(err, ErrNetworkMismatch) {
		t.Errorf("ValidateForNetwork(hoodi entry, mainnet params) error = %v, want errors.Is(ErrNetworkMismatch)", err)
	}
}

func TestValidateForNetwork_ForkVersionMismatch(t *testing.T) {
	pHoodi := hoodiParams()
	e := validSignedEntryForParams(t, pHoodi)
	// Tamper the fork version bytes (any change triggers mismatch).
	e.ForkVersion[0] ^= 0xff
	if err := e.ValidateForNetwork(pHoodi, bls.DefaultVerifier()); !errors.Is(err, ErrForkVersionMismatch) {
		t.Errorf("ValidateForNetwork(tampered fork_version) error = %v, want errors.Is(ErrForkVersionMismatch)", err)
	}
}

func TestValidateForNetwork_BadBLSSig(t *testing.T) {
	pHoodi := hoodiParams()
	e := validSignedEntryForParams(t, pHoodi)
	// Byte-flip in the signature field.
	e.Signature[0] ^= 0x01
	err := e.ValidateForNetwork(pHoodi, bls.DefaultVerifier())
	if err == nil {
		t.Fatal("ValidateForNetwork(flipped signature) = nil, want ErrBLSSignatureInvalid")
	}
	if !errors.Is(err, ErrBLSSignatureInvalid) {
		t.Errorf("ValidateForNetwork(flipped signature) error = %v, want errors.Is(ErrBLSSignatureInvalid)", err)
	}
}

func TestValidateForNetwork_HappyPath(t *testing.T) {
	pHoodi := hoodiParams()
	e := validSignedEntryForParams(t, pHoodi)
	if err := e.ValidateForNetwork(pHoodi, bls.DefaultVerifier()); err != nil {
		t.Errorf("ValidateForNetwork(well-formed hoodi entry vs hoodi params) unexpected error: %v", err)
	}
}

func TestEntryValidate_SignatureTampered_DataRootMismatch(t *testing.T) {
	tests := []struct{ name string }{{name: "sig"}}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			pHoodi := hoodiParams()
			e := validSignedEntryForParams(t, pHoodi)
			data := ssz.DepositData{
				Pubkey:                e.Pubkey,
				WithdrawalCredentials: e.WithdrawalCredentials,
				Amount:                e.Amount,
				Signature:             e.Signature,
			}
			e.DepositDataRoot = data.HashTreeRoot()
			e.Signature[0] ^= 0x01
			if err := e.Validate(); !errors.Is(err, ErrDepositDataRootMismatch) {
				t.Errorf("Validate(flipped signature) error = %v, want errors.Is(ErrDepositDataRootMismatch)", err)
			}
		})
	}
}

func TestEntryValidate_PubkeyTampered_MessageRootMismatch(t *testing.T) {
	tests := []struct{ name string }{{name: "pubkey"}}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			pHoodi := hoodiParams()
			e := validSignedEntryForParams(t, pHoodi)
			data := ssz.DepositData{
				Pubkey:                e.Pubkey,
				WithdrawalCredentials: e.WithdrawalCredentials,
				Amount:                e.Amount,
				Signature:             e.Signature,
			}
			e.DepositDataRoot = data.HashTreeRoot()
			e.Pubkey[0] ^= 0x01
			if err := e.Validate(); !errors.Is(err, ErrDepositMessageRootMismatch) {
				t.Errorf("Validate(flipped pubkey) error = %v, want errors.Is(ErrDepositMessageRootMismatch)", err)
			}
		})
	}
}

func TestEntryValidate_AmountTampered_MessageRootMismatch(t *testing.T) {
	tests := []struct{ name string }{{name: "amount"}}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			pHoodi := hoodiParams()
			e := validSignedEntryForParams(t, pHoodi)
			data := ssz.DepositData{
				Pubkey:                e.Pubkey,
				WithdrawalCredentials: e.WithdrawalCredentials,
				Amount:                e.Amount,
				Signature:             e.Signature,
			}
			e.DepositDataRoot = data.HashTreeRoot()
			e.Amount ^= 1
			if err := e.Validate(); !errors.Is(err, ErrDepositMessageRootMismatch) {
				t.Errorf("Validate(tampered amount) error = %v, want errors.Is(ErrDepositMessageRootMismatch)", err)
			}
		})
	}
}
