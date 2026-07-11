// Package main is the entry point for eth-deposit.
// It sets up the urfave/cli/v3 application and wires the gen, build, sign, run,
// and send subcommands (formerly the separate eth-deposit-gen and
// eth-deposit-tx binaries; merged so the full deposit-data -> broadcast
// pipeline ships as one tool).
//
// Exit codes:
//
//	0 — success
//	1 — unexpected / internal error
//	2 — user / configuration error (bad input, unknown network, missing file, etc.)
//	3 — signer / crypto error (bad key, no device, app not open, chain ID mismatch)
//	4 — user abort (SIGINT or Ledger rejection)
//	5 — broadcast / RPC error (dial failure, eth_sendRawTransaction error)
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	ucli "github.com/urfave/cli/v3"

	"github.com/rootwarp/eth-utils/go/internal/deposit"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// version, commit, and date are set at build time via -ldflags.
// Default values are used for local/dev builds.
// eth-deposit-gen shipped v1.0.0 and eth-deposit-tx was never tagged before
// the two were merged into this binary; see CHANGELOG.md for the merge note.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	go func() { <-ctx.Done(); stop() }()
	defer stop()

	app := &ucli.Command{
		Name:  "eth-deposit",
		Usage: "Generate, build, sign, and broadcast Ethereum Beacon Chain deposit transactions",
		UsageText: `eth-deposit gen [options]
   eth-deposit build [options]
   eth-deposit sign [options]
   eth-deposit run [options]
   eth-deposit send [options]`,
		Version: fmt.Sprintf("%s (commit=%s, built=%s)", version, commit, date),
		Description: `eth-deposit takes BLS validator keystores all the way through to a broadcast
Ethereum deposit transaction for the Beacon Chain deposit contract.

It supports a secure, five-step workflow:
  gen    - Generate Launchpad-compatible deposit_data JSON from BLS validator keystores
  build  - Construct an unsigned transaction (supports offline/air-gapped mode)
  sign   - Sign the transaction, with Ledger hardware as the primary method
  run    - Convenience: build + sign in one step (same machine, no serialization to disk)
  send   - Broadcast a signed tx via JSON-RPC (requires explicit network-name confirmation)

The tool produces standard hex-encoded RLP output ready for eth_sendRawTransaction.

Exit codes: 0=success, 1=internal error, 2=bad input, 3=signer/crypto error, 4=user abort, 5=broadcast/RPC error.`,
		Commands: []*ucli.Command{
			genCommand(),
			buildCommand(),
			signCommand(),
			runCommand(),
			sendCommand(),
		},
		// Suppress urfave's default ExitCoder printer; we log via slog below.
		ExitErrHandler: func(_ context.Context, _ *ucli.Command, _ error) {},
	}
	applyUsageErrorHook(app)

	if err := app.Run(ctx, os.Args); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(ExitCodeFor(err))
	}
}

// onUsageError converts urfave usage errors (missing required flag, unknown
// flag, bad flag value, arg-parse failures) into an exit-code-2 ExitCoder, so
// every subcommand agrees that usage errors are user/config errors (F2).
func onUsageError(_ context.Context, _ *ucli.Command, err error, _ bool) error {
	return ucli.Exit(err.Error(), 2)
}

// applyUsageErrorHook sets onUsageError on every subcommand of app. OnUsageError
// is read from the subcommand (not inherited from root), so it must be set on
// each. Must be called after the command list is built.
func applyUsageErrorHook(app *ucli.Command) {
	for _, c := range app.Commands {
		c.OnUsageError = onUsageError
	}
}

func buildCommand() *ucli.Command {
	return &ucli.Command{
		Name:  "build",
		Usage: "Construct an unsigned deposit transaction from deposit data",
		Description: `Reads a deposit_data JSON file (produced by "eth-deposit gen" or the Ethereum Launchpad)
and produces an unsigned EIP-1559 transaction for the Beacon Chain deposit contract.

Supports offline/air-gapped mode (no --rpc-url required) when all gas and nonce
flags are supplied explicitly, and hybrid mode when --rpc-url is provided.
Output is written to stdout by default; use --output FILE or --output - for explicit stdout.

Examples:

  # Output unsigned tx to stdout (pipe-friendly):
  eth-deposit build --network holesky --input-file deposit_data.json

  # Save unsigned tx to a file for the air-gapped sign step:
  eth-deposit build --network holesky --input-file deposit_data.json --output unsigned.json

  # Read deposit data from stdin (e.g. from a hardware-encrypted volume):
  cat deposit_data.json | eth-deposit build --network holesky --input-file -

  # Offline / air-gapped: supply all gas and nonce explicitly (no RPC needed):
  eth-deposit build --network holesky --input-file deposit_data.json \
    --nonce 7 --gas-limit 250000 \
    --max-fee-per-gas 20000000000 --max-priority-fee-per-gas 1000000000 \
    --output unsigned.json

Exit codes:
  0  Success
  2  User / configuration error (missing file, invalid JSON, bad --network, out-of-range --index)
  1  Unexpected internal error`,
		UsageText: `eth-deposit build --input-file FILE --network NET [options]`,
		Flags: []ucli.Flag{
			&ucli.StringFlag{
				Name:     "input-file",
				Aliases:  []string{"input", "i"},
				Usage:    "Path to deposit_data-*.json file (or '-' for stdin); --input is accepted as a shorter alias",
				Required: true,
				Sources:  ucli.EnvVars("ETH_DEPOSIT_TX_INPUT_FILE"),
			},
			&ucli.StringFlag{
				Name:    "network",
				Aliases: []string{"n"},
				Usage:   "Target network (mainnet, hoodi, sepolia, holesky)",
				Value:   "hoodi",
				Sources: ucli.EnvVars("ETH_DEPOSIT_TX_NETWORK"),
			},
			&ucli.StringFlag{
				Name:    "output",
				Usage:   "Output file for the unsigned transaction (default: stdout)",
				Sources: ucli.EnvVars("ETH_DEPOSIT_TX_OUTPUT"),
			},
			&ucli.IntFlag{
				Name:    "index",
				Usage:   "Index of the deposit entry to use when the JSON contains multiple validators (default: 0)",
				Value:   0,
				Sources: ucli.EnvVars("ETH_DEPOSIT_TX_INDEX"),
			},
			&ucli.StringFlag{
				Name:    "rpc-url",
				Usage:   "JSON-RPC endpoint URL for gas/nonce estimation (optional; when omitted, all gas and nonce flags must be supplied explicitly)",
				Sources: ucli.EnvVars("ETH_DEPOSIT_TX_RPC_URL"),
			},
			&ucli.StringFlag{
				Name:    "gas-limit",
				Usage:   fmt.Sprintf("Gas limit for the deposit transaction (default: %d)", defaultGasLimit),
				Sources: ucli.EnvVars("ETH_DEPOSIT_TX_GAS_LIMIT"),
			},
			&ucli.StringFlag{
				Name:    "max-fee-per-gas",
				Usage:   "EIP-1559 maximum fee per gas in wei (decimal integer, e.g. 20000000000 for 20 Gwei)",
				Sources: ucli.EnvVars("ETH_DEPOSIT_TX_MAX_FEE_PER_GAS"),
			},
			&ucli.StringFlag{
				Name:    "max-priority-fee-per-gas",
				Usage:   "EIP-1559 maximum priority fee per gas in wei (decimal integer, e.g. 1000000000 for 1 Gwei)",
				Sources: ucli.EnvVars("ETH_DEPOSIT_TX_MAX_PRIORITY_FEE_PER_GAS"),
			},
			&ucli.StringFlag{
				Name:    "nonce",
				Usage:   "Override the sender account nonce (non-negative integer; omit to fetch from RPC or set later)",
				Sources: ucli.EnvVars("ETH_DEPOSIT_TX_NONCE"),
			},
			&ucli.StringFlag{
				Name:    "from",
				Usage:   "Sender address (0x-prefixed, 20-byte hex). Required with --rpc-url when --nonce or --gas-limit is omitted, to fetch the pending nonce and estimate gas.",
				Sources: ucli.EnvVars("ETH_DEPOSIT_TX_FROM"),
			},
		},
		Action: func(ctx context.Context, c *ucli.Command) error {
			cfg, err := LoadBuildConfig(c)
			if err != nil {
				return err
			}
			if err := requireFromForRPC(cfg); err != nil {
				return err
			}

			// Read deposit data from file or stdin.
			var rawData []byte
			if cfg.InputFile == "-" {
				rawData, err = io.ReadAll(c.Root().Reader)
			} else {
				rawData, err = os.ReadFile(cfg.InputFile)
			}
			if err != nil {
				return ucli.Exit(fmt.Sprintf("--input-file: %v", err), 2)
			}

			unsignedTx, err := buildUnsignedTx(ctx, cfg, rawData)
			if err != nil {
				return err
			}

			out, err := json.MarshalIndent(unsignedTx, "", "  ")
			if err != nil {
				return ucli.Exit(fmt.Sprintf("build: marshal: %v", err), 2)
			}
			out = append(out, '\n')

			if cfg.OutputFile == "" || cfg.OutputFile == "-" {
				_, err = c.Root().Writer.Write(out)
				return err
			}
			if err := os.WriteFile(cfg.OutputFile, out, 0o644); err != nil {
				return err
			}
			slog.Info("wrote unsigned tx", "path", cfg.OutputFile, "network", cfg.Network)
			return nil
		},
	}
}

// requireFromForRPC enforces the config-time --from requirement for build: in
// RPC mode, when no sender was supplied and either the nonce or the gas limit is
// unset, --from is mandatory. Both the pending-nonce fetch and the 32-ETH gas
// estimation need a funded sender, so a zero From would otherwise surface later
// as a confusing exit-5 estimation failure instead of a clean exit-2 config
// error. resolveRPC's ErrMissingFromForNonce remains the backstop for the nonce
// path. This gate lives in build's Action, not shared LoadBuildConfig, because
// run derives From from the signing key instead.
//
// The cfg.GasLimit == 0 half is inert until P2-2 removes the eager gas default
// in LoadBuildConfig (GasLimit is never 0 today); the cfg.Nonce == nil half is
// live now.
func requireFromForRPC(cfg *Config) error {
	if cfg.RPCURL != "" && cfg.From == ([20]byte{}) && (cfg.Nonce == nil || cfg.GasLimit == 0) {
		return ucli.Exit("--from: required when --rpc-url is set and --nonce or --gas-limit is omitted "+
			"(the sender is needed to fetch the pending nonce and to estimate gas for the 32-ETH deposit call)", 2)
	}
	return nil
}

// buildUnsignedTx converts raw deposit data bytes + build config into an UnsignedTx.
// It is extracted so runAction can call it without re-reading from disk.
func buildUnsignedTx(ctx context.Context, cfg *Config, rawData []byte) (*internaltx.UnsignedTx, error) {
	entries, err := deposit.EntriesFromJSON(rawData)
	if err != nil {
		return nil, ucli.Exit(fmt.Sprintf("--input-file: invalid JSON: %v", err), 2)
	}
	if len(entries) == 0 {
		return nil, ucli.Exit("--input-file: file contains no deposit entries", 2)
	}
	if cfg.Index < 0 || cfg.Index >= len(entries) {
		return nil, ucli.Exit(fmt.Sprintf("--index %d: out of bounds (file has %d entries)", cfg.Index, len(entries)), 2)
	}
	entry := entries[cfg.Index]

	if err := entry.Validate(); err != nil {
		return nil, ucli.Exit(fmt.Sprintf("deposit entry validation: %v", err), 2)
	}

	buildCfg := internaltx.BuildConfig{
		NetworkParams:        cfg.NetworkParams,
		RPCURL:               cfg.RPCURL,
		GasLimit:             cfg.GasLimit,
		MaxFeePerGas:         cfg.MaxFeePerGas,
		MaxPriorityFeePerGas: cfg.MaxPriorityFeePerGas,
		Nonce:                cfg.Nonce,
	}
	if buildCfg.MaxFeePerGas == nil {
		buildCfg.MaxFeePerGas = defaultMaxFeePerGas()
	}
	if buildCfg.MaxPriorityFeePerGas == nil {
		buildCfg.MaxPriorityFeePerGas = defaultMaxPriorityFeePerGas()
	}
	if buildCfg.GasLimit == 0 {
		buildCfg.GasLimit = defaultGasLimit
	}
	if buildCfg.Nonce == nil {
		var z uint64
		buildCfg.Nonce = &z
	}

	builder := internaltx.NewBuilder()
	unsignedTx, err := builder.BuildUnsigned(ctx, entry, buildCfg)
	if err != nil {
		return nil, WrapInputErr("build", err)
	}
	return unsignedTx, nil
}
