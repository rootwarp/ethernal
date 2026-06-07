package deposit

import "errors"

// ErrZeroWithdrawal00 is returned by Entry.Validate (and its DiD partner in
// tx.Validate) when withdrawal_credentials has 0x00 prefix but the 32-byte
// value is the all-zero placeholder. This is the critical GO-001 case.
var ErrZeroWithdrawal00 = errors.New("withdrawal_credentials with 0x00 prefix has all-zero body")

// ErrInvalidWCFormat is returned by Entry.Validate when withdrawal_credentials
// has 0x01 or 0x02 prefix but bytes [1:12] are not all zero, or when the
// leading byte is any other value.
var ErrInvalidWCFormat = errors.New("withdrawal_credentials format invalid for prefix")

// ErrNetworkMismatch is returned by Entry.ValidateForNetwork when
// entry.NetworkName does not equal the target network's Name.
var ErrNetworkMismatch = errors.New("entry network does not match target network")

// ErrForkVersionMismatch is returned by Entry.ValidateForNetwork when
// entry.ForkVersion does not equal the target's GenesisForkVersion.
var ErrForkVersionMismatch = errors.New("entry fork_version does not match target genesis_fork_version")

// ErrBLSSignatureInvalid is returned by Entry.ValidateForNetwork when the
// BLS signature fails to verify against the deposit domain computed from
// the target's GenesisForkVersion and ZeroGenesisValidatorsRoot().
var ErrBLSSignatureInvalid = errors.New("BLS signature does not verify against deposit domain")

// ErrDepositMessageRootMismatch is returned by Entry.Validate when the
// stored DepositMessageRoot does not equal the value recomputed via
// ssz.DepositMessage{Pubkey, WithdrawalCredentials, Amount}.HashTreeRoot().
var ErrDepositMessageRootMismatch = errors.New("computed deposit_message_root does not match entry")

// ErrDepositDataRootMismatch is returned by Entry.Validate when the
// stored DepositDataRoot does not equal the value recomputed via
// ssz.DepositData{Pubkey, WithdrawalCredentials, Amount, Signature}.HashTreeRoot().
var ErrDepositDataRootMismatch = errors.New("computed deposit_data_root does not match entry")
