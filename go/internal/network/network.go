// Package network is the source of truth for per-network compile-time constants
// used in the deposit signing pipeline.
package network

import (
	"encoding/hex"
	"fmt"
)

// Network identifies an Ethereum consensus network.
type Network string

const (
	// Mainnet is the Ethereum mainnet.
	Mainnet Network = "mainnet"

	// Hoodi is the Hoodi testnet.
	Hoodi Network = "hoodi"

	// Sepolia is the Sepolia testnet.
	Sepolia Network = "sepolia"

	// Holesky is the Holesky testnet.
	Holesky Network = "holesky"
)

// Params holds the per-network constants required by the deposit signing pipeline.
type Params struct {
	Name               Network
	GenesisForkVersion [4]byte

	// ChainID is the EIP-155 chain ID used in transaction signing.
	ChainID uint64

	// DepositContractAddress is the 20-byte execution-layer address of the
	// beacon chain deposit contract on this network.
	// Source: eth-clients/<network>/metadata/config.yaml DEPOSIT_CONTRACT_ADDRESS.
	DepositContractAddress [20]byte

	// DefaultRPCURL is an optional well-known public RPC endpoint for this
	// network. Empty string means no default ships with this tool (callers must
	// supply --rpc-url explicitly).
	DefaultRPCURL string

	// ExplorerURL is the base URL of the block explorer for this network
	// (e.g. "https://etherscan.io"). Used to format tx hash links.
	// Source: etherscan.io per-network subdomains.
	ExplorerURL string
}

// DepositContractAddressHex returns the deposit contract address as a
// lowercase "0x"-prefixed hex string, suitable for display and JSON output.
func (p Params) DepositContractAddressHex() string {
	return "0x" + hex.EncodeToString(p.DepositContractAddress[:])
}

// DomainDeposit is the 4-byte SSZ domain type for deposits (consensus spec constant).
var DomainDeposit = [4]byte{0x03, 0x00, 0x00, 0x00}

// ZeroGenesisValidatorsRoot is the genesis_validators_root used for deposit
// signing — always 32 zero bytes per the consensus spec.
var ZeroGenesisValidatorsRoot = [32]byte{}

// mustParseAddr converts a 40-char hex string (no 0x prefix) to a [20]byte.
// Panics on invalid input — used only for compile-time constant initialisation.
func mustParseAddr(s string) [20]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 20 {
		panic(fmt.Sprintf("network: invalid address constant %q: %v", s, err))
	}
	var addr [20]byte
	copy(addr[:], b)
	return addr
}

// Lookup returns the Params for the given network.
// It returns a descriptive error for any unknown network.
func Lookup(n Network) (Params, error) {
	switch n {
	case Mainnet:
		return Params{
			Name:                   Mainnet,
			GenesisForkVersion:     [4]byte{0x00, 0x00, 0x00, 0x00},
			ChainID:                1,
			DepositContractAddress: mustParseAddr("00000000219ab540356cBB839Cbe05303d7705Fa"),
			DefaultRPCURL:          "",
			ExplorerURL:            "https://etherscan.io",
		}, nil
	case Hoodi:
		return Params{
			Name:                   Hoodi,
			GenesisForkVersion:     [4]byte{0x10, 0x00, 0x09, 0x10},
			ChainID:                560048,
			DepositContractAddress: mustParseAddr("00000000219ab540356cBB839Cbe05303d7705Fa"),
			DefaultRPCURL:          "",
			ExplorerURL:            "https://hoodi.etherscan.io",
		}, nil
	case Sepolia:
		return Params{
			Name:                   Sepolia,
			GenesisForkVersion:     [4]byte{0x90, 0x00, 0x00, 0x69},
			ChainID:                11155111,
			DepositContractAddress: mustParseAddr("7f02C3E3c98b133055B8B348B2Ac625669Ed295D"),
			DefaultRPCURL:          "",
			ExplorerURL:            "https://sepolia.etherscan.io",
		}, nil
	case Holesky:
		return Params{
			Name:                   Holesky,
			GenesisForkVersion:     [4]byte{0x01, 0x01, 0x70, 0x00},
			ChainID:                17000,
			DepositContractAddress: mustParseAddr("4242424242424242424242424242424242424242"),
			DefaultRPCURL:          "",
			ExplorerURL:            "https://holesky.etherscan.io",
		}, nil
	default:
		return Params{}, fmt.Errorf("unknown network %q: must be one of %q, %q, %q, %q",
			n, Mainnet, Hoodi, Sepolia, Holesky)
	}
}

// LookupByChainID returns the Params for the network with the given chain ID.
// Returns an error if no supported network matches.
func LookupByChainID(chainID uint64) (Params, error) {
	for _, n := range []Network{Mainnet, Hoodi, Sepolia, Holesky} {
		p, err := Lookup(n)
		if err != nil {
			continue
		}
		if p.ChainID == chainID {
			return p, nil
		}
	}
	return Params{}, fmt.Errorf("unknown chain ID %d: not a supported network", chainID)
}

// ParseFlag parses a network flag string and returns the corresponding Network.
// It accepts exactly "mainnet", "hoodi", "sepolia", and "holesky" (case-sensitive).
// Any other input returns an error containing the offending value.
func ParseFlag(s string) (Network, error) {
	switch s {
	case string(Mainnet):
		return Mainnet, nil
	case string(Hoodi):
		return Hoodi, nil
	case string(Sepolia):
		return Sepolia, nil
	case string(Holesky):
		return Holesky, nil
	default:
		return "", fmt.Errorf("unsupported network %q: must be one of %q, %q, %q, %q",
			s, Mainnet, Hoodi, Sepolia, Holesky)
	}
}
