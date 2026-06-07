// Package main is the entry point for eth-deposit-tx.
// It sets up the urfave/cli/v2 application and wires the build, sign, run, and send subcommands.
//
// Exit codes:
//
//	0 — success
//	1 — unexpected / internal error
//	2 — user / configuration error (bad input, unknown network, missing file, etc.)
//	3 — signer / crypto error (bad key, no device, app not open, chain ID mismatch)
//	4 — user abort (SIGINT/SIGTERM or Ledger rejection)
//	5 — broadcast / RPC error (dial failure, eth_sendRawTransaction error)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	ucli "github.com/urfave/cli/v2"

	"github.com/rootwarp/eth-utils/go/internal/deposit"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// newRPCClient is the factory used to obtain an EthRPC for hybrid --rpc-url on `run` only (M1.3-5).
// build always rejects --rpc-url (M0.7-8a path). Tests override to supply mocks.
var newRPCClient = func(ctx context.Context, rpcURL string) (internaltx.EthRPC, error) {
	return internaltx.NewEthClient(ctx, rpcURL)
}

// version, commit, and date are set at build time via -ldflags.
// Default values are used for local/dev builds.
// Canonical first release: v0.1.0 — signals first usable release, not yet
// feature-complete vs roadmap (mainnet Ledger heuristics deferred to v0.2.0).
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

	app := &ucli.App{
		Name:  "eth-deposit-tx",
		Usage: "Create and sign Ethereum deposit transactions from deposit data JSON",
		UsageText: `eth-deposit-tx build [options]
   eth-deposit-tx sign [options]
   eth-deposit-tx run [options]
   eth-deposit-tx send [options]`,
		Version: fmt.Sprintf("%s (commit=%s, built=%s)", version, commit, date),
		Description: `eth-deposit-tx converts Launchpad-compatible deposit_data JSON into raw Ethereum transactions
for the Beacon Chain deposit contract.

It supports a secure two-phase workflow:
  build  - Construct an unsigned transaction (supports offline/air-gapped mode)
  sign   - Sign the transaction, with Ledger hardware as the primary method
  run    - Convenience: build + sign in one step (same machine, no serialization to disk)
  send   - Broadcast a signed tx via JSON-RPC (requires explicit network-name confirmation)

The tool produces standard hex-encoded RLP output ready for eth_sendRawTransaction.

Exit codes: 0=success, 1=internal error, 2=bad input, 3=signer/crypto error, 4=user abort, 5=broadcast/RPC error.`,
		Commands: []*ucli.Command{
			buildCommand(),
			signCommand(),
			runCommand(),
			sendCommand(),
		},
		// Suppress urfave's default ExitCoder printer; we log via slog below.
		ExitErrHandler: func(_ *ucli.Context, _ error) {},
	}

	if err := app.RunContext(ctx, os.Args); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(ExitCodeFor(err))
	}
}

func buildCommand() *ucli.Command {
	return &ucli.Command{
		Name:  "build",
		Usage: "Construct an unsigned deposit transaction from deposit data",
		Description: `Reads a deposit_data JSON file (produced by eth-deposit-gen or the Ethereum Launchpad)
and produces an unsigned EIP-1559 transaction for the Beacon Chain deposit contract.

Supports offline/air-gapped mode (no --rpc-url required; --rpc-url is rejected for build per M0.7-8a — use "run" for hybrid) when all gas and nonce
flags are supplied explicitly.
Output is written to stdout by default; use --output FILE or --output - for explicit stdout.

Examples:

  # Output unsigned tx to stdout (pipe-friendly):
  eth-deposit-tx build --network holesky --input-file deposit_data.json

  # Save unsigned tx to a file for the air-gapped sign step:
  eth-deposit-tx build --network holesky --input-file deposit_data.json --output unsigned.json

  # Read deposit data from stdin (e.g. from a hardware-encrypted volume):
  cat deposit_data.json | eth-deposit-tx build --network holesky --input-file -

  # Offline / air-gapped: supply all gas and nonce explicitly (no RPC needed):
  eth-deposit-tx build --network holesky --input-file deposit_data.json \
    --nonce 7 --gas-limit 250000 \
    --max-fee-per-gas 20000000000 --max-priority-fee-per-gas 1000000000 \
    --output unsigned.json

Exit codes:
  0  Success
  2  User / configuration error (missing file, invalid JSON, bad --network, out-of-range --index)
  1  Unexpected internal error`,
		UsageText: `eth-deposit-tx build --input-file FILE --network NET [options]`,
		Flags: func() []ucli.Flag {
			// One source of truth: buildFlags (M2.2-3 / FR-P2-A15). Patch only the two
			// command-specific Usages so `build --help` bytes are identical to before.
			fs := buildFlags()
			for _, f := range fs {
				if sf, ok := f.(*ucli.StringFlag); ok {
					if sf.Name == "output" {
						sf.Usage = "Output file for the unsigned transaction (default: stdout)"
					} else if sf.Name == "rpc-url" {
						sf.Usage = "JSON-RPC endpoint URL for gas/nonce estimation (rejected for build; use `run` for hybrid or supply --nonce + fees explicitly)"
					}
				}
			}
			return fs
		}(),
		Action: func(c *ucli.Context) error {
			cfg, err := LoadBuildConfig(c)
			if err != nil {
				return err
			}
			if cfg.RPCURL != "" {
				// build remains strictly offline; reject per M0.7-8a (M1.3-5 keeps for build, wires run only).
				return ucli.Exit(internaltx.ErrRPCURLRejected.Error(), 2)
			}

			// M1.6-1 confirm-network match (build for symmetry; equiv to sendAction
			// post-decode logic). Mainnet required already enforced in LoadBuildConfig.
			if cfg.ConfirmNetwork != "" && cfg.ConfirmNetwork != string(cfg.NetworkParams.Name) {
				return ucli.Exit(fmt.Sprintf("--confirm-network: %q does not match --network %q", cfg.ConfirmNetwork, cfg.NetworkParams.Name), 2)
			}

			// Read deposit data from file or stdin.
			var rawData []byte
			if cfg.InputFile == "-" {
				rawData, err = io.ReadAll(c.App.Reader)
			} else {
				rawData, err = os.ReadFile(cfg.InputFile)
			}
			if err != nil {
				return ucli.Exit(fmt.Sprintf("--input-file: %v", err), 2)
			}

			unsignedTx, err := buildUnsignedTx(c.Context, cfg, rawData, nil, [20]byte{})
			if err != nil {
				return err
			}

			out, err := json.MarshalIndent(unsignedTx, "", "  ")
			if err != nil {
				return ucli.Exit(fmt.Sprintf("build: marshal: %v", err), 2)
			}
			out = append(out, '\n')

			if cfg.OutputFile == "" || cfg.OutputFile == "-" {
				_, err = c.App.Writer.Write(out)
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

// buildUnsignedTx converts raw deposit data bytes + build config into an UnsignedTx.
// It is extracted so runAction can call it without re-reading from disk.
// rpc and from are threaded only for run's hybrid --rpc-url path (M1.3-5); build passes nil/zero.
func buildUnsignedTx(ctx context.Context, cfg *Config, rawData []byte, rpc internaltx.EthRPC, from [20]byte) (*internaltx.UnsignedTx, error) {
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
		RPC:                  rpc,
		From:                 from,
		GasLimit:             cfg.GasLimit,
		MaxFeePerGas:         cfg.MaxFeePerGas,
		MaxPriorityFeePerGas: cfg.MaxPriorityFeePerGas,
		Nonce:                cfg.Nonce,
	}
	// Fill defaults ONLY for static (offline) path. RPC path (run hybrid) leaves nils/0 so resolveRPC fills nonce/fees (and gas if 0).
	if rpc == nil {
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
		return nil, WrapInputErr("build", err)
	}
	return unsignedTx, nil
}
