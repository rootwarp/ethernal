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
//	2 — user / configuration error (bad input, unknown network, missing file,
//	    missing required flag, build-side RPC chain-ID mismatch)
//	3 — signer / crypto error (bad key, no device, app not open,
//	    signer-side chain-ID mismatch)
//	4 — user abort (SIGINT or Ledger rejection)
//	5 — broadcast / RPC error (dial failure, gas/nonce estimation failure,
//	    eth_sendRawTransaction error, broadcast-side chain-ID mismatch)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT)
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
		// Redact any RPC URL embedded in the error (path/query API keys leak via
		// the stdlib *url.Error from a failed estimation call) before it reaches
		// stderr. RedactURLString scrubs the rendered message; ExitCodeFor still
		// sees the untouched err, so classification is unaffected.
		slog.Error("fatal", "err", internaltx.RedactURLString(err))
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
flags are supplied explicitly, and hybrid mode: with --rpc-url, any gas, fee, or
nonce not passed explicitly is resolved from the node (which needs --from).
Output is written to stdout by default; use --output FILE or --output - for explicit stdout.

Examples:

  # Output unsigned tx to stdout (pipe-friendly):
  eth-deposit build --network holesky --input-file deposit_data.json

  # Hybrid: resolve gas, fees, and nonce from a node (requires --from):
  eth-deposit build --network holesky --input-file deposit_data.json \
    --rpc-url https://holesky.example.com --from 0xYourSenderAddress

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
  2  User / configuration error (missing/invalid input, bad --network, out-of-range
     --index, missing required flag, missing --from for RPC nonce/gas estimation,
     RPC chain-ID mismatch)
  4  User abort (Ctrl-C during RPC estimation)
  5  RPC error (endpoint unreachable, gas/nonce estimation failed)
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
				Usage:   "JSON-RPC endpoint URL. When set, any gas/fee/nonce value not given explicitly is resolved from the node (requires --from); when omitted, the build is fully offline and all gas and nonce flags must be supplied explicitly.",
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
// error. resolveRPC's ErrMissingFromForNonce is now builder-level
// defense-in-depth only — this gate catches the build path first. It lives in
// build's Action, not shared LoadBuildConfig, because run derives From from the
// signing key instead.
//
// Both halves are live: P2-2 removed LoadBuildConfig's eager gas default, so
// cfg.GasLimit == 0 when --gas-limit is omitted and cfg.Nonce == nil when
// --nonce is omitted.
func requireFromForRPC(cfg *Config) error {
	if cfg.RPCURL != "" && cfg.From == ([20]byte{}) && (cfg.Nonce == nil || cfg.GasLimit == 0) {
		return ucli.Exit("--from: required when --rpc-url is set and --nonce or --gas-limit is omitted "+
			"(the sender is needed to fetch the pending nonce and to estimate gas for the 32-ETH deposit call)", 2)
	}
	return nil
}

// newEthRPC is the production EthRPC factory. Tests override this to inject a
// fake. It mirrors newBroadcaster (send.go): NewEthClient returns (*ethClient,
// error) and the seam widens the return to the EthRPC interface.
var newEthRPC = func(ctx context.Context, rpcURL string) (internaltx.EthRPC, error) {
	return internaltx.NewEthClient(ctx, rpcURL)
}

// buildUnsignedTx converts raw deposit data bytes + build config into an UnsignedTx.
// It is extracted so runAction can call it without re-reading from disk.
//
// It owns the RPC client lifecycle for both build and run: in RPC mode it dials
// via newEthRPC and injects the client so the builder resolves unset
// gas/fee/nonce from the node; in offline mode it fills the hardcoded air-gapped
// defaults and never dials, keeping golden output byte-identical.
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
		From:                 cfg.From,
		GasLimit:             cfg.GasLimit,
		MaxFeePerGas:         cfg.MaxFeePerGas,
		MaxPriorityFeePerGas: cfg.MaxPriorityFeePerGas,
		Nonce:                cfg.Nonce,
	}

	if cfg.RPCURL != "" {
		// RPC mode: dial, inject, and leave gas/fees/nonce unset so resolveRPC
		// fills them from the node (explicit flags still win — resolveRPC only
		// fills nil/zero fields). Mirror send.go's nil-interface guard: on dial
		// failure the seam returns a non-nil EthRPC wrapping a nil *ethClient, so
		// check err and return BEFORE deferring Close.
		client, err := newEthRPC(ctx, cfg.RPCURL)
		if err != nil {
			return nil, err // ErrRPCDial → exit 5, unwrapped (never reaches WrapInputErr)
		}
		defer client.Close()
		buildCfg.RPC = client
	} else {
		// Offline / air-gapped mode: fill the hardcoded defaults (F1.4 / C3).
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
	}

	builder := internaltx.NewBuilder()
	unsignedTx, err := builder.BuildUnsigned(ctx, entry, buildCfg)
	if err != nil {
		// Check-before-wrap: an RPC estimation-call failure must reach exit 5
		// unwrapped (ExitCodeFor maps ErrRPCEstimation → 5); everything else is a
		// config/input error and stays wrapped → exit 2, preserving the offline
		// contract. A SIGINT mid-estimation wraps context.Canceled and is mapped
		// to 4 by ExitCodeFor's ordering — see the note there.
		if errors.Is(err, internaltx.ErrRPCEstimation) {
			return nil, err
		}
		return nil, WrapInputErr("build", err)
	}
	return unsignedTx, nil
}
