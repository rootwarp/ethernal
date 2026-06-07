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
