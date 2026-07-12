package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	ucli "github.com/urfave/cli/v3"

	"github.com/rootwarp/eth-utils/go/internal/network"
)

// defaultGasLimit is the default gas limit for a deposit() call.
// The deposit() function costs ~200,000 gas; 250,000 provides comfortable headroom.
const defaultGasLimit uint64 = 250_000

// defaultMaxFeePerGas returns 20 Gwei as the fallback EIP-1559 max fee.
// 20 gwei is a testnet baseline; may be too low for mainnet.
func defaultMaxFeePerGas() *big.Int { return big.NewInt(20_000_000_000) }

// defaultMaxPriorityFeePerGas returns 1 Gwei as the fallback EIP-1559 tip.
func defaultMaxPriorityFeePerGas() *big.Int { return big.NewInt(1_000_000_000) }

// Config holds the validated, parsed inputs for eth-deposit build.
type Config struct {
	// Network is the selected Ethereum consensus network.
	Network network.Network

	// NetworkParams is the resolved per-network constants (chain ID, deposit contract, etc.).
	NetworkParams network.Params

	// InputFile is the path to the deposit_data JSON file, or "-" for stdin.
	InputFile string

	// OutputFile is the output path for the unsigned transaction. Empty means stdout.
	OutputFile string

	// Index is the zero-based index into the deposit_data JSON array.
	Index int

	// RPCURL is an optional JSON-RPC endpoint for gas/nonce estimation.
	// Empty means the caller must supply all gas/nonce flags explicitly.
	RPCURL string

	// From is the sender address, parsed from --from. Zero value means unset.
	// Used only in RPC mode to fetch the pending nonce when --nonce is omitted.
	From [20]byte

	// GasLimit is the EIP-1559 gas limit for the deposit transaction.
	GasLimit uint64

	// MaxFeePerGas is the EIP-1559 maximum total fee in wei. Nil if not set.
	MaxFeePerGas *big.Int

	// MaxPriorityFeePerGas is the EIP-1559 miner tip in wei. Nil if not set.
	MaxPriorityFeePerGas *big.Int

	// Nonce is an optional explicit nonce override. Nil means fetch from RPC or require manual flag.
	Nonce *uint64
}

// LoadBuildConfig resolves flag > env > defaults into a typed Config.
// It validates the result before returning. Unknown network or invalid numeric
// inputs produce an error with exit code 2 via ucli.Exit so callers can return
// the error directly to urfave.
func LoadBuildConfig(c *ucli.Command) (*Config, error) {
	// 1. Network — parse and look up constants.
	net, err := network.ParseFlag(c.String("network"))
	if err != nil {
		return nil, ucli.Exit(fmt.Sprintf("--network: %v", err), 2)
	}
	params, err := network.Lookup(net)
	if err != nil {
		return nil, ucli.Exit(fmt.Sprintf("--network: %v", err), 2)
	}

	// 2. Gas limit — string flag so env-var override works alongside flag.
	// Unset means 0 here; the offline branch in buildUnsignedTx restores the
	// static default, while RPC mode leaves it 0 so resolveRPC runs EstimateGas.
	var gasLimit uint64
	if s := c.String("gas-limit"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, ucli.Exit(fmt.Sprintf("--gas-limit: invalid value %q: must be a positive integer", s), 2)
		}
		if v == 0 {
			return nil, ucli.Exit("--gas-limit: must be greater than zero", 2)
		}
		gasLimit = v
	}

	// 3. Max fee per gas — optional, nil when absent.
	var maxFee *big.Int
	if s := c.String("max-fee-per-gas"); s != "" {
		v, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil, ucli.Exit(fmt.Sprintf("--max-fee-per-gas: invalid value %q: must be a decimal integer in wei", s), 2)
		}
		if v.Sign() < 0 {
			return nil, ucli.Exit(fmt.Sprintf("--max-fee-per-gas: value must be non-negative, got %s", s), 2)
		}
		maxFee = v
	}

	// 4. Max priority fee per gas — optional, nil when absent.
	var maxPrioFee *big.Int
	if s := c.String("max-priority-fee-per-gas"); s != "" {
		v, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil, ucli.Exit(fmt.Sprintf("--max-priority-fee-per-gas: invalid value %q: must be a decimal integer in wei", s), 2)
		}
		if v.Sign() < 0 {
			return nil, ucli.Exit(fmt.Sprintf("--max-priority-fee-per-gas: value must be non-negative, got %s", s), 2)
		}
		maxPrioFee = v
	}

	// 5. Nonce — optional, nil when absent.
	var nonce *uint64
	if s := c.String("nonce"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, ucli.Exit(fmt.Sprintf("--nonce: invalid value %q: must be a non-negative integer", s), 2)
		}
		nonce = &v
	}

	cfg := &Config{
		Network:              net,
		NetworkParams:        params,
		InputFile:            c.String("input-file"),
		OutputFile:           c.String("output"),
		Index:                c.Int("index"),
		RPCURL:               c.String("rpc-url"),
		GasLimit:             gasLimit,
		MaxFeePerGas:         maxFee,
		MaxPriorityFeePerGas: maxPrioFee,
		Nonce:                nonce,
	}

	// 6. Sender address — optional, strict 20-byte hex. common.HexToAddress is
	// deliberately avoided: it is lenient and silently truncates/pads.
	if s := c.String("from"); s != "" {
		h := strings.TrimPrefix(s, "0x")
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 20 {
			return nil, ucli.Exit(fmt.Sprintf("--from: invalid address %q: must be a 20-byte hex address", s), 2)
		}
		copy(cfg.From[:], b)
	}

	return cfg, nil
}
