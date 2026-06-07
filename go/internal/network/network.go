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

// domainDeposit is the 4-byte SSZ domain type for deposits (consensus spec constant).
// Exported via DomainDeposit() per architecture §6.1 / §15 (GO-038).
var domainDeposit = [4]byte{0x03, 0x00, 0x00, 0x00}

// zeroGenesisValidatorsRoot is the genesis_validators_root used for deposit
// signing — always 32 zero bytes per the consensus spec.
// Exported via ZeroGenesisValidatorsRoot() per architecture §6.1 / §15 (GO-038).
var zeroGenesisValidatorsRoot = [32]byte{}

// DomainDeposit returns the deposit domain by value (callers cannot mutate source).
func DomainDeposit() [4]byte { return domainDeposit }

// ZeroGenesisValidatorsRoot returns the zero genesis_validators_root by value (callers cannot mutate source).
func ZeroGenesisValidatorsRoot() [32]byte { return zeroGenesisValidatorsRoot }

// MinDepositAmountGwei is the minimum deposit amount in Gwei (MIN_ACTIVATION_BALANCE per EIP-7251).
const MinDepositAmountGwei uint64 = 32_000_000_000

// MaxDepositAmountGwei is the maximum deposit amount in Gwei (MAX_EFFECTIVE_BALANCE_ELECTRA per EIP-7251).
const MaxDepositAmountGwei uint64 = 2_048_000_000_000

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

// paramsByName is the single source of truth (per architecture §6.1 / FR-P2-A3 / GO-047).
// All per-network metadata derives from it. Address constants are parsed exactly
// once here (at package init time); a typo panics at process start.
var paramsByName = map[Network]Params{
	Mainnet: {
		Name:                   Mainnet,
		GenesisForkVersion:     [4]byte{0x00, 0x00, 0x00, 0x00},
		ChainID:                1,
		DepositContractAddress: mustParseAddr("00000000219ab540356cBB839Cbe05303d7705Fa"),
		DefaultRPCURL:          "",
		ExplorerURL:            "https://etherscan.io",
	},
	Hoodi: {
		Name:                   Hoodi,
		GenesisForkVersion:     [4]byte{0x10, 0x00, 0x09, 0x10},
		ChainID:                560048,
		DepositContractAddress: mustParseAddr("00000000219ab540356cBB839Cbe05303d7705Fa"),
		DefaultRPCURL:          "",
		ExplorerURL:            "https://hoodi.etherscan.io",
	},
	Sepolia: {
		Name:                   Sepolia,
		GenesisForkVersion:     [4]byte{0x90, 0x00, 0x00, 0x69},
		ChainID:                11155111,
		DepositContractAddress: mustParseAddr("7f02C3E3c98b133055B8B348B2Ac625669Ed295D"),
		DefaultRPCURL:          "",
		ExplorerURL:            "https://sepolia.etherscan.io",
	},
	Holesky: {
		Name:                   Holesky,
		GenesisForkVersion:     [4]byte{0x01, 0x01, 0x70, 0x00},
		ChainID:                17000,
		DepositContractAddress: mustParseAddr("4242424242424242424242424242424242424242"),
		DefaultRPCURL:          "",
		ExplorerURL:            "https://holesky.etherscan.io",
	},
}

// Lookup returns the Params for the given network.
// It returns a descriptive error for any unknown network.
func Lookup(n Network) (Params, error) {
	p, ok := paramsByName[n]
	if !ok {
		return Params{}, fmt.Errorf("unknown network %q: must be one of %q, %q, %q, %q",
			n, Mainnet, Hoodi, Sepolia, Holesky)
	}
	return p, nil
}

// LookupByChainID returns the Params for the network with the given chain ID.
// Returns an error if no supported network matches.
func LookupByChainID(chainID uint64) (Params, error) {
	for _, p := range paramsByName {
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
	for n := range paramsByName {
		if string(n) == s {
			return n, nil
		}
	}
	return "", fmt.Errorf("unsupported network %q: must be one of %q, %q, %q, %q",
		s, Mainnet, Hoodi, Sepolia, Holesky)
}
