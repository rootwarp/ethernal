package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	ucli "github.com/urfave/cli/v3"

	"github.com/rootwarp/eth-utils/go/internal/cli"
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

	// ConfirmNetwork is the value of --confirm-network (explicit mainnet ack gate).
	// Required for --network mainnet; if set must match the target network name
	// (and decoded-RLP / RPC-derived name where applicable). Pre-validated here
	// per M1.5-1 pattern. --yes does not bypass.
	ConfirmNetwork string

	// IAcceptLocalSignerOnMainnet is the --i-accept-local-signer-on-mainnet flag (M1.6-2).
	// Required (enforced in run/sign Loads/actions) only for --signer local + mainnet.
	// Captured on build/run for symmetry + M1.6-3 pre-val note; on send/sign too.
	IAcceptLocalSignerOnMainnet bool
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

	// Pre-validate --confirm-network (M1.6-1 / M1.5-1 pattern): mainnet requires it;
	// if set must be a supported network name. (Value match vs RLP/RPC happens
	// later in actions.) Consolidated pre-val for both mainnet gates here and in
	// the other three Load*Config per M1.6-3 (early ucli.Exit(2) before setup; reuse
	// M1.5-1 required-flag pre-val pattern exactly; consistent msgs; no dupe lists).
	confirmNet := c.String("confirm-network")
	if net == network.Mainnet && confirmNet == "" {
		return nil, ucli.Exit("--confirm-network: required for mainnet (must equal network name)", 2)
	}
	if confirmNet != "" {
		if _, err := network.ParseFlag(confirmNet); err != nil {
			return nil, ucli.Exit(fmt.Sprintf("--confirm-network: %v", err), 2)
		}
	}

	acceptLocal := c.Bool("i-accept-local-signer-on-mainnet")
	// M1.6-2/M1.6-3 pre-val capture (for "all four" hygiene per reviewer high + M1.6-3 note + M1.6-1 apply sign hygiene pattern). Require for local+mainnet is in LoadRun (where signer known) + action checks (sign); ledger exempt. Store below. Early before gas/etc per M1.5-1.

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
		Network:                     net,
		NetworkParams:               params,
		InputFile:                   c.String("input-file"),
		OutputFile:                  c.String("output"),
		Index:                       c.Int("index"),
		RPCURL:                      c.String("rpc-url"),
		GasLimit:                    gasLimit,
		MaxFeePerGas:                maxFee,
		MaxPriorityFeePerGas:        maxPrioFee,
		Nonce:                       nonce,
		ConfirmNetwork:              confirmNet,
		IAcceptLocalSignerOnMainnet: acceptLocal,
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

// posixEnvVarName matches valid POSIX env var names: uppercase letters, digits,
// underscore; must start with letter or underscore. (Moved here from sign.go
// for M2.2-4 centralization of the signer/env-var validation shared by
// Load*Config funcs.)
var posixEnvVarName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// validateSignerEnv performs the common post-required --signer value check
// ("local" or "ledger") plus the full --private-key-env POSIX-name validation
// with redaction and "treat as compromised" warning. Consumed by both
// LoadSignConfig and LoadRunConfig (M2.2-4 / FR-P2-A15 signer/env-var dedup).
// Preserves M0.8-2 redaction discipline exactly (cli.Redact + ErrWriter
// warning + identical error text). Caller must have already enforced
// non-empty --signer (to preserve per-caller required-error wording).
func validateSignerEnv(c *ucli.Context, signerType string) (envVar string, err error) {
	if signerType != "local" && signerType != "ledger" {
		return "", ucli.Exit(fmt.Sprintf("--signer: unsupported value %q: must be \"local\" or \"ledger\"", signerType), 2)
	}

	envVar = c.String("private-key-env")
	if !posixEnvVarName.MatchString(envVar) {
		_, _ = fmt.Fprintf(c.App.ErrWriter, "WARNING: the rejected value should be treated as compromised\n")
		return "", ucli.Exit(fmt.Sprintf(
			"--private-key-env: %q is not a valid POSIX env var name (must match ^[A-Z_][A-Z0-9_]*$); did you accidentally pass the key value instead of a variable name?",
			cli.Redact(envVar, 4),
		), 2)
	}
	return envVar, nil
}
