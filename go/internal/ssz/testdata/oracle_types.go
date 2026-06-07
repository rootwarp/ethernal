package testdata

// DepositMessage and DepositData are minimal mirrors of the hand-rolled types
// in internal/ssz for the differential fastssz oracle (M1.2-4 / ADR-007 / research/05).
// Struct tags are for sszgen only.

//go:generate go run github.com/ferranbt/fastssz/sszgen -path . -objs DepositMessage,DepositData -output oracle_types_ssz.go

type DepositMessage struct {
	Pubkey                [48]byte `ssz-size:"48"`
	WithdrawalCredentials [32]byte `ssz-size:"32"`
	Amount                uint64   `ssz-size:"8"`
}

type DepositData struct {
	Pubkey                [48]byte `ssz-size:"48"`
	WithdrawalCredentials [32]byte `ssz-size:"32"`
	Amount                uint64   `ssz-size:"8"`
	Signature             [96]byte `ssz-size:"96"`
}
