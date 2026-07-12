package signer

import (
	"math/big"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/types"
)

// ledgerHub abstracts usbwallet.Hub for testability.
// Implementations: realHub (cgo path), mockHub (tests).
type ledgerHub interface {
	Wallets() []ledgerWallet
}

// ledgerWallet abstracts accounts.Wallet for testability.
// Only the subset of methods required for discovery and signing is included.
// Implementations: realWallet (cgo path), mockWallet (tests).
type ledgerWallet interface {
	URL() accounts.URL
	Open(passphrase string) error
	Close() error
	Status() (string, error)
	Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error)
	SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)
}

// newLedgerHub is set by init() in ledger_cgo.go (CGO builds) or
// ledger_nocgo.go (non-CGO builds). Tests may overwrite it before calling
// NewLedgerSigner.
var newLedgerHub func() (ledgerHub, error)
