package deposit

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/rootwarp/eth-utils/go/internal/network"
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

func marshalJSONEntry(r jsonEntry) ([]byte, error) {
	return json.Marshal(r)
}

func marshalJSONArray(rs []jsonEntry) ([]byte, error) {
	return json.Marshal(rs)
}

// TestEntryFromJSON_Valid verifies round-trip for a well-formed entry.
func TestEntryFromJSON_Valid(t *testing.T) {
	raw := validRawEntry()
	data, err := marshalJSONEntry(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	e, err := EntryFromJSON(data)
	if err != nil {
		t.Fatalf("EntryFromJSON() error = %v, want nil", err)
	}
	if e.NetworkName != network.Hoodi {
		t.Errorf("NetworkName = %q, want %q", e.NetworkName, network.Hoodi)
	}
	if e.Amount != 32_000_000_000 {
		t.Errorf("Amount = %d, want 32_000_000_000", e.Amount)
	}
	if e.DepositCLIVersion != "2.7.0" {
		t.Errorf("DepositCLIVersion = %q, want %q", e.DepositCLIVersion, "2.7.0")
	}
	// Verify pubkey bytes were copied correctly.
	wantFirstByte := byte(0xab)
	if e.Pubkey[0] != wantFirstByte {
		t.Errorf("Pubkey[0] = 0x%02x, want 0x%02x", e.Pubkey[0], wantFirstByte)
	}
}

// TestEntryFromJSON_0xPrefixedHex verifies that "0x"-prefixed hex strings are
// accepted for all hex fields.
func TestEntryFromJSON_0xPrefixedHex(t *testing.T) {
	raw := validRawEntry()
	raw.Pubkey = "0x" + raw.Pubkey
	raw.WithdrawalCredentials = "0x" + raw.WithdrawalCredentials
	raw.Signature = "0x" + raw.Signature
	raw.DepositMessageRoot = "0x" + raw.DepositMessageRoot
	raw.DepositDataRoot = "0x" + raw.DepositDataRoot
	raw.ForkVersion = "0x" + raw.ForkVersion

	data, err := marshalJSONEntry(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, err = EntryFromJSON(data)
	if err != nil {
		t.Errorf("EntryFromJSON() with 0x-prefixed fields error = %v, want nil", err)
	}
}

// TestEntryFromJSON_InvalidHex verifies that non-hex characters produce an error.
func TestEntryFromJSON_InvalidHex(t *testing.T) {
	raw := validRawEntry()
	raw.Pubkey = strings.Repeat("ZZ", 48) // invalid hex
	data, err := marshalJSONEntry(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, err = EntryFromJSON(data)
	if err == nil {
		t.Error("EntryFromJSON() with invalid hex pubkey: want error, got nil")
	}
}

// TestEntryFromJSON_WrongLength verifies that hex strings of incorrect decoded
// length produce clear errors.
func TestEntryFromJSON_WrongLength(t *testing.T) {
	tests := []struct {
		name  string
		mutFn func(*jsonEntry)
	}{
		{
			name:  "pubkey_short",
			mutFn: func(r *jsonEntry) { r.Pubkey = strings.Repeat("ab", 47) },
		},
		{
			name:  "pubkey_long",
			mutFn: func(r *jsonEntry) { r.Pubkey = strings.Repeat("ab", 49) },
		},
		{
			name:  "withdrawal_credentials_short",
			mutFn: func(r *jsonEntry) { r.WithdrawalCredentials = strings.Repeat("cd", 31) },
		},
		{
			name:  "signature_short",
			mutFn: func(r *jsonEntry) { r.Signature = strings.Repeat("ef", 95) },
		},
		{
			name:  "deposit_message_root_short",
			mutFn: func(r *jsonEntry) { r.DepositMessageRoot = strings.Repeat("01", 31) },
		},
		{
			name:  "deposit_data_root_short",
			mutFn: func(r *jsonEntry) { r.DepositDataRoot = strings.Repeat("02", 31) },
		},
		{
			name:  "fork_version_short",
			mutFn: func(r *jsonEntry) { r.ForkVersion = "100009" }, // 3 bytes
		},
		{
			name:  "fork_version_long",
			mutFn: func(r *jsonEntry) { r.ForkVersion = "1000091011" }, // 5 bytes
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			raw := validRawEntry()
			tc.mutFn(&raw)
			data, err := marshalJSONEntry(raw)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			_, err = EntryFromJSON(data)
			if err == nil {
				t.Errorf("EntryFromJSON() with %s: want error, got nil", tc.name)
			}
		})
	}
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
	// This is the content of go/internal/output/testdata/deposit_data-expected.json
	data := []byte(`[{"pubkey":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","withdrawal_credentials":"0000000000000000000000000000000000000000000000000000000000000000","amount":32000000000,"signature":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","deposit_message_root":"0000000000000000000000000000000000000000000000000000000000000000","deposit_data_root":"0000000000000000000000000000000000000000000000000000000000000000","fork_version":"10000910","network_name":"hoodi","deposit_cli_version":"2.7.0"},{"pubkey":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","withdrawal_credentials":"0000000000000000000000000000000000000000000000000000000000000000","amount":32000000000,"signature":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","deposit_message_root":"0000000000000000000000000000000000000000000000000000000000000000","deposit_data_root":"0000000000000000000000000000000000000000000000000000000000000000","fork_version":"10000910","network_name":"hoodi","deposit_cli_version":"2.7.0"}]`)
	entries, err := EntriesFromJSON(data)
	if err != nil {
		t.Fatalf("EntriesFromJSON(golden) error = %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("got %d entries, want 2", len(entries))
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
		e.DepositDataRoot[0] = 0xEF
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

	if err := e.Validate(); err != nil {
		t.Errorf("Validate() on canonical 0x01 WC entry: unexpected error: %v", err)
	}
}
