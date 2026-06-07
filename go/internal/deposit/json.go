// Package deposit — this file adds Launchpad-compatible JSON unmarshalling and
// semantic validation to Entry. It is the read-side companion to the write-side
// serialisation in internal/output.
package deposit

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rootwarp/eth-utils/go/internal/bls"
	"github.com/rootwarp/eth-utils/go/internal/network"
	"github.com/rootwarp/eth-utils/go/internal/ssz"
)

// jsonEntry is the wire representation of a single entry in a Launchpad
// deposit_data-*.json file. Field names and types must match exactly what
// eth-deposit-gen and the official staking-deposit-cli produce.
type jsonEntry struct {
	Pubkey                string `json:"pubkey"`
	WithdrawalCredentials string `json:"withdrawal_credentials"`
	Amount                uint64 `json:"amount"`
	Signature             string `json:"signature"`
	DepositMessageRoot    string `json:"deposit_message_root"`
	DepositDataRoot       string `json:"deposit_data_root"`
	ForkVersion           string `json:"fork_version"`
	NetworkName           string `json:"network_name"`
	DepositCLIVersion     string `json:"deposit_cli_version"`
}

// decodeHex decodes a hex string that may or may not carry a "0x" prefix.
func decodeHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return hex.DecodeString(s)
}

// decodeFixedHex decodes a hex string into a fixed-length byte slice and
// returns an error if the decoded length does not match wantLen.
func decodeFixedHex(field, s string, wantLen int) ([]byte, error) {
	b, err := decodeHex(s)
	if err != nil {
		return nil, fmt.Errorf("deposit: %s: invalid hex %q: %w", field, s, err)
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf("deposit: %s: got %d bytes, want %d", field, len(b), wantLen)
	}
	return b, nil
}

// EntryFromJSON parses a single Launchpad-format JSON object (not array) into
// an Entry. The JSON may contain additional unknown fields which are silently
// ignored.
//
// Accepted hex strings may be "0x"-prefixed or unprefixed (lowercase or mixed
// case). Length invariants are enforced:
//   - pubkey:                 48 bytes
//   - withdrawal_credentials: 32 bytes
//   - signature:              96 bytes
//   - deposit_message_root:   32 bytes
//   - deposit_data_root:      32 bytes
//   - fork_version:            4 bytes
func EntryFromJSON(data []byte) (Entry, error) {
	var raw jsonEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return Entry{}, fmt.Errorf("deposit: unmarshal entry: %w", err)
	}
	return entryFromRaw(raw)
}

// entryFromRaw converts a decoded jsonEntry to an Entry, enforcing all length
// invariants.
func entryFromRaw(raw jsonEntry) (Entry, error) {
	pubkeyBytes, err := decodeFixedHex("pubkey", raw.Pubkey, 48)
	if err != nil {
		return Entry{}, err
	}
	wcBytes, err := decodeFixedHex("withdrawal_credentials", raw.WithdrawalCredentials, 32)
	if err != nil {
		return Entry{}, err
	}
	sigBytes, err := decodeFixedHex("signature", raw.Signature, 96)
	if err != nil {
		return Entry{}, err
	}
	msgRootBytes, err := decodeFixedHex("deposit_message_root", raw.DepositMessageRoot, 32)
	if err != nil {
		return Entry{}, err
	}
	dataRootBytes, err := decodeFixedHex("deposit_data_root", raw.DepositDataRoot, 32)
	if err != nil {
		return Entry{}, err
	}
	fvBytes, err := decodeFixedHex("fork_version", raw.ForkVersion, 4)
	if err != nil {
		return Entry{}, err
	}

	var e Entry
	copy(e.Pubkey[:], pubkeyBytes)
	copy(e.WithdrawalCredentials[:], wcBytes)
	e.Amount = raw.Amount
	copy(e.Signature[:], sigBytes)
	copy(e.DepositMessageRoot[:], msgRootBytes)
	copy(e.DepositDataRoot[:], dataRootBytes)
	copy(e.ForkVersion[:], fvBytes)
	e.NetworkName = network.Network(raw.NetworkName)
	e.DepositCLIVersion = raw.DepositCLIVersion

	return e, nil
}

// EntriesFromJSON parses a Launchpad deposit_data-*.json file, which is a
// JSON array of entry objects.
func EntriesFromJSON(data []byte) ([]Entry, error) {
	var raws []jsonEntry
	if err := json.Unmarshal(data, &raws); err != nil {
		return nil, fmt.Errorf("deposit: unmarshal entries array: %w", err)
	}
	entries := make([]Entry, 0, len(raws))
	for i, raw := range raws {
		e, err := entryFromRaw(raw)
		if err != nil {
			return nil, fmt.Errorf("deposit: entry[%d]: %w", i, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Validate checks that e carries semantically meaningful values. It returns a
// descriptive error for each invariant that fails:
//   - Pubkey must not be all-zero (would represent a null key)
//   - Signature must not be all-zero
//   - DepositDataRoot must not be all-zero
//   - Amount must be > 0
//   - NetworkName must be a recognised network
//   - WithdrawalCredentials: 0x00 all-zero body rejected (ErrZeroWithdrawal00); 0x01/0x02 bytes 1-11 must be zero (ErrInvalidWCFormat); other prefixes invalid
func (e Entry) Validate() error {
	// WC shape checks (DiD for hand-crafted JSON that bypasses the gen flag).
	// (a) 0x00 + all-zero body → ErrZeroWithdrawal00
	// (b) 0x01/0x02 with non-zero in 1..11 → ErrInvalidWCFormat
	// (c) any other prefix → ErrInvalidWCFormat
	wc := e.WithdrawalCredentials
	switch wc[0] {
	case 0x00:
		if wc == ([32]byte{}) {
			return ErrZeroWithdrawal00
		}
	case 0x01, 0x02:
		for i := 1; i <= 11; i++ {
			if wc[i] != 0x00 {
				return fmt.Errorf("%w: prefix 0x%02x requires bytes 1–11 to be zero", ErrInvalidWCFormat, wc[0])
			}
		}
	default:
		return fmt.Errorf("%w: got 0x%02x", ErrInvalidWCFormat, wc[0])
	}

	if e.Pubkey == ([48]byte{}) {
		return fmt.Errorf("deposit: validate: pubkey is all-zero")
	}
	if e.Signature == ([96]byte{}) {
		return fmt.Errorf("deposit: validate: signature is all-zero")
	}
	if e.DepositDataRoot == ([32]byte{}) {
		return fmt.Errorf("deposit: validate: deposit_data_root is all-zero")
	}
	if e.Amount == 0 {
		return fmt.Errorf("deposit: validate: amount is zero")
	}
	if _, err := network.Lookup(e.NetworkName); err != nil {
		return fmt.Errorf("deposit: validate: network_name %q is not recognised: %w", e.NetworkName, err)
	}
	return nil
}

// ValidateForNetwork enforces that the Entry is bound to the supplied target
// network parameters (per architecture §15 and ADR-002). It returns a sentinel
// on mismatch:
//
//   - entry.NetworkName == target.Name                  → ErrNetworkMismatch
//   - entry.ForkVersion == target.GenesisForkVersion    → ErrForkVersionMismatch
//   - bls.ValidatePubkeyBytes(entry.Pubkey)             → error from ValidatePubkeyBytes (bls.ErrPubkeyInvalid after M1.2-2)
//   - signature verifies over DepositMessage HTR using
//     compute_domain(DOMAIN_DEPOSIT, target.GenesisForkVersion, ZeroGenesisValidatorsRoot)
//     → ErrBLSSignatureInvalid
//
// The verifier is supplied by the caller (typically bls.DefaultVerifier());
// ValidateForNetwork never constructs one. Network/fork checks happen before
// pubkey or signature verification.
func (e Entry) ValidateForNetwork(target network.Params, v bls.Verifier) error {
	if e.NetworkName != target.Name {
		return ErrNetworkMismatch
	}
	if e.ForkVersion != target.GenesisForkVersion {
		return ErrForkVersionMismatch
	}
	if err := bls.ValidatePubkeyBytes(e.Pubkey); err != nil {
		return err
	}

	domain := ssz.ComputeDomain(
		network.DomainDeposit,
		target.GenesisForkVersion,
		network.ZeroGenesisValidatorsRoot,
	)

	msg := ssz.DepositMessage{
		Pubkey:                e.Pubkey,
		WithdrawalCredentials: e.WithdrawalCredentials,
		Amount:                e.Amount,
	}
	msgRoot := msg.HashTreeRoot()
	signingRoot := ssz.ComputeSigningRoot(msgRoot, domain)

	ok, err := v.Verify(e.Pubkey, signingRoot, e.Signature)
	if err != nil || !ok {
		return ErrBLSSignatureInvalid
	}
	return nil
}
