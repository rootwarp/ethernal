//go:build !cgo

package signer

func init() {
	newLedgerHub = func() (ledgerHub, error) {
		return nil, ErrLedgerNotSupported
	}
}
