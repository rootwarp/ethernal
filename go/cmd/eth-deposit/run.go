package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	ucli "github.com/urfave/cli/v3"

	"github.com/rootwarp/eth-utils/go/internal/cli"
	"github.com/rootwarp/eth-utils/go/internal/deposit"
	"github.com/rootwarp/eth-utils/go/internal/network"
	"github.com/rootwarp/eth-utils/go/internal/signer"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// RunConfig holds parsed, validated inputs for the run subcommand,
// combining build (deposit data → unsigned tx) and sign (unsigned tx → signed tx) fields.
type RunConfig struct {
	// Build fields (deposit data → unsigned tx)
	Build *Config

	// Sign fields (unsigned tx → signed tx)
	Signer           string
	PrivateKeyEnvVar string

	// OutputFile is the output path for the signed tx. Empty means stdout.
	OutputFile string

	// KeepUnsigned, when true, also writes the unsigned tx to disk alongside signed.json.
	KeepUnsigned bool

	// RawOutputFile overrides the auto-derived .raw companion filename.
	// If empty and OutputFile is a file path, signed.raw is derived automatically.
	RawOutputFile string

	// IAcceptLocalSignerOnMainnet is the --i-accept-local-signer-on-mainnet flag (M1.6-2).
	// Pre-validated in LoadRunConfig when Signer=local + Network=mainnet (M1.5-1 pattern).
	IAcceptLocalSignerOnMainnet bool
}

// LoadRunConfig parses and validates run subcommand flags.
func LoadRunConfig(c *ucli.Command) (*RunConfig, error) {
	buildCfg, err := LoadBuildConfig(c)
	if err != nil {
		return nil, err
	}

	signerType := c.String("signer")
	if signerType == "" {
		return nil, ucli.Exit("--signer: required flag not set; must be \"local\" or \"ledger\"", 2)
	}
	// Common signer+env validation (post-req) extracted to shared helper (M2.2-4).
	envVar, err := validateSignerEnv(c, signerType)
	if err != nil {
		return nil, err
	}

	keepUnsigned := c.Bool("keep-unsigned")
	outputFile := c.String("output")
	if keepUnsigned && (outputFile == "" || outputFile == "-") {
		return nil, ucli.Exit("--keep-unsigned requires --output to be a file path (cannot be used with stdout)", 2)
	}

	acceptLocal := c.Bool("i-accept-local-signer-on-mainnet")
	// M1.6-2/M1.6-3 pre-val (M1.5-1 pattern + M1.6-3 note): require when local + mainnet.
	// (Happens early, before FS/RPC/build/sign work in runAction; after LoadBuild which does confirm gate.)
	// Hygiene/consolidation for "all four" Loads per reviewer high + M1.6-1 apply + M1.6-3.
	// (Full local+mainnet require for sign stays in action per M1.6-3 note, as net derived from unsigned.)
	if signerType == "local" && buildCfg.Network == network.Mainnet && !acceptLocal {
		return nil, ucli.Exit("--i-accept-local-signer-on-mainnet: required when --signer local and --network mainnet", 2)
	}

	return &RunConfig{
		Build:                       buildCfg,
		Signer:                      signerType,
		PrivateKeyEnvVar:            envVar,
		OutputFile:                  outputFile,
		KeepUnsigned:                keepUnsigned,
		RawOutputFile:               c.String("raw-output"),
		IAcceptLocalSignerOnMainnet: acceptLocal,
	}, nil
}

// runCommand returns the urfave/cli run subcommand definition.
func runCommand() *ucli.Command {
	return &ucli.Command{
		Name:  "run",
		Usage: "Build and sign a deposit transaction in one step (convenience command)",
		Description: `Runs build and sign in-process without writing an intermediate unsigned tx to disk.

Use this when both phases happen on the same machine. For air-gapped workflows
(build offline, transfer, sign on a separate device), use the build and sign
subcommands separately.

Output artifacts:
  signed.json  — the full SignedTx JSON (fields: unsigned, from, hash, r, s, v, rawRLP)
  signed.raw   — companion file (mode 0600) containing only the 0x-prefixed RLP
                 hex, written alongside signed.json when --output is a file path.
                 This is the value to pass to eth_sendRawTransaction. The 0x prefix
                 is included for grep/curl friendliness; strip it if your tool
                 requires raw bytes.

  When --output is omitted or "-", only SignedTx JSON is written to stdout; no .raw
  companion is produced.

  --raw-output PATH overrides the auto-derived companion filename.

Partial-failure behavior:
  If --keep-unsigned is set, the unsigned tx is written before signing. If signing
  then fails, the unsigned tx file is preserved (it is a valid artifact for retry).
  Signed output files use atomic rename (temp file in same directory) so a partial
  write never leaves a corrupt signed.json or signed.raw.

Examples:

  # Local signer — output to stdout (pipe into send):
  ETH_DEPOSIT_TX_PRIVATE_KEY=0x<your-dev-key> eth-deposit run \
    --network holesky \
    --input-file deposit_data.json \
    --signer local

  # Local signer — save to file, then broadcast separately:
  ETH_DEPOSIT_TX_PRIVATE_KEY=0x<your-dev-key> eth-deposit run \
    --network holesky \
    --input-file deposit_data.json \
    --signer local \
    --output signed.json

  # Ledger hardware wallet — keep unsigned tx for audit trail:
  eth-deposit run \
    --network holesky \
    --input-file deposit_data.json \
    --signer ledger \
    --output signed.json \
    --keep-unsigned

  # Note: --signer ledger + --rpc-url (hybrid auto-nonce) requires explicit --nonce (device not opened until sign step).

Exit codes:
  0  Success
  2  User / configuration error (missing file, bad --network, missing --signer)
  3  Signer / crypto error (bad key, no Ledger device, Ethereum app not open)
  4  User abort (Ctrl-C or rejection on Ledger device)
  1  Unexpected internal error`,
		UsageText: `eth-deposit run --input-file FILE --network NET --signer local|ledger [options]`,
		Flags: append(
			buildFlags(),
			// Sign-specific flags (no --input since we build in-process).
			&ucli.StringFlag{
				Name:  "signer",
				Usage: "Signing method: \"local\" (env-var private key) or \"ledger\" (hardware wallet)",
			},
			&ucli.StringFlag{
				Name:  "private-key-env",
				Usage: fmt.Sprintf("Environment variable name holding the hex private key (local signer only; default: %s)", defaultPrivKeyEnvVar),
				Value: defaultPrivKeyEnvVar,
			},
			&ucli.BoolFlag{
				Name:  "keep-unsigned",
				Usage: "Also write the unsigned tx to disk alongside the signed output (requires --output to be a file path)",
			},
			&ucli.StringFlag{
				Name:  "raw-output",
				Usage: "Override the auto-derived .raw companion filename for the RLP hex (default: <output>.raw → signed.raw when --output is signed.json)",
			},
		),
		Action: func(ctx context.Context, c *ucli.Command) error {
			cfg, err := LoadRunConfig(c)
			if err != nil {
				return err
			}
			return runAction(ctx, c, cfg)
		},
	}
}

// buildFlags returns the flag list shared between build and run subcommands.
func buildFlags() []ucli.Flag {
	return []ucli.Flag{
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
			Name:  "confirm-network",
			Usage: "Explicit acknowledgement of the target network name (required for mainnet; must match the network name; --yes does not bypass)",
		},
		&ucli.BoolFlag{
			Name:  "i-accept-local-signer-on-mainnet",
			Usage: "Required when --signer local and --network mainnet: acknowledges risk of using local (hot, env-var) private key for mainnet deposit (irreversible 32 ETH lock; Ledger recommended)",
		},
		&ucli.StringFlag{
			Name:    "output",
			Usage:   "Output file for the signed transaction (default: stdout)",
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
	}
}

// runAction orchestrates the build → sign pipeline in-process.
func runAction(ctx context.Context, c *ucli.Command, cfg *RunConfig) error {
	// 1. Read deposit data.
	var rawData []byte
	var err error
	if cfg.Build.InputFile == "-" {
		rawData, err = io.ReadAll(c.Root().Reader)
	} else {
		rawData, err = os.ReadFile(cfg.Build.InputFile)
	}
	if err != nil {
		return ucli.Exit(fmt.Sprintf("--input-file: %v", err), 2)
	}

	// 2. Build unsigned tx (in-process, no disk write).
	unsigned, err := buildUnsignedTx(ctx, cfg.Build, rawData)
	if err != nil {
		return err
	}

	// 4. Optionally write unsigned tx before signing (so it survives a sign failure).
	if cfg.KeepUnsigned {
		unsignedPath := unsignedPathFor(cfg.OutputFile)
		unsignedJSON, err := json.MarshalIndent(unsigned, "", "  ")
		if err != nil {
			return ucli.Exit(fmt.Sprintf("run: marshal unsigned: %v", err), 2)
		}
		unsignedJSON = append(unsignedJSON, '\n')
		if err := atomicWriteFile(unsignedPath, unsignedJSON, 0o644); err != nil {
			return ucli.Exit(fmt.Sprintf("--keep-unsigned: write %s: %v", unsignedPath, err), 2)
		}
		slog.Info("wrote unsigned tx", "path", unsignedPath)
	}

	// 5. Sign (in-process, no disk round-trip).
	signCfg := &SignConfig{
		Signer:                      cfg.Signer,
		PrivateKeyEnvVar:            cfg.PrivateKeyEnvVar,
		IAcceptLocalSignerOnMainnet: cfg.IAcceptLocalSignerOnMainnet,
	}
	signed, err := signUnsignedTx(ctx, signCfg, c.Root().ErrWriter, *unsigned)
	if err != nil {
		return err
	}

	// 6. Marshal signed tx.
	signedJSON, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return fmt.Errorf("run: marshal signed: %w", err)
	}
	signedJSON = append(signedJSON, '\n')

	// 7. Write output.
	if cfg.OutputFile == "" || cfg.OutputFile == "-" {
		_, err = c.Root().Writer.Write(signedJSON)
		return err
	}

	// Write signed.json atomically.
	if err := atomicWriteFile(cfg.OutputFile, signedJSON, 0o600); err != nil {
		return ucli.Exit(fmt.Sprintf("--output: write %s: %v", cfg.OutputFile, err), 2)
	}
	slog.Info("wrote signed tx", "path", cfg.OutputFile, "signer", cfg.Signer)

	// Write companion .raw file containing only the RLP hex.
	rawPath := cfg.RawOutputFile
	if rawPath == "" {
		rawPath = rawPathFor(cfg.OutputFile)
	}
	rawContent := []byte(signed.RawRLP + "\n")
	if err := atomicWriteFile(rawPath, rawContent, 0o600); err != nil {
		return ucli.Exit(fmt.Sprintf("raw output: write %s: %v", rawPath, err), 2)
	}
	slog.Info("wrote raw RLP", "path", rawPath)

	return nil
}

// atomicWriteFile writes data to path using a temp file + rename so a partial
// write never leaves a corrupt file at the target path. The temp file is created
// in the same directory as path so the rename is guaranteed atomic on a single filesystem.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-eth-deposit-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best-effort cleanup of the temp file if rename never happened.
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// unsignedPathFor derives the unsigned tx file path from the signed output path.
// e.g. "/path/to/signed.json" → "/path/to/unsigned.json"
func unsignedPathFor(signedPath string) string {
	dir := filepath.Dir(signedPath)
	base := filepath.Base(signedPath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	// Replace "signed" with "unsigned" if present, otherwise prepend "unsigned-".
	if strings.Contains(stem, "signed") {
		stem = strings.Replace(stem, "signed", "unsigned", 1)
	} else {
		stem = "unsigned-" + stem
	}
	return filepath.Join(dir, stem+ext)
}

// rawPathFor derives the companion .raw filename from the signed output path.
// e.g. "/path/to/signed.json" → "/path/to/signed.raw"
func rawPathFor(signedPath string) string {
	ext := filepath.Ext(signedPath)
	return strings.TrimSuffix(signedPath, ext) + ".raw"
}

// version, commit, and date are set at build time via -ldflags.
// Default values are used for local/dev builds.
// (Moved here from main.go for thin-main M2.3-5; same package visibility.)
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// newRPCClient is the factory used to obtain an EthRPC for hybrid --rpc-url on `run` only (M1.3-5).
// build always rejects --rpc-url (M0.7-8a path). Tests override to supply mocks.
// (Moved here from main.go for thin-main M2.3-5.)
var newRPCClient = func(ctx context.Context, rpcURL string) (internaltx.EthRPC, error) {
	return internaltx.NewEthClient(ctx, rpcURL)
}

// newTxApp returns the configured urfave app for eth-deposit-tx.
// All command definitions and orchestration wiring live in the cmd package files
// (per M2.3-5 thin-main: main.go itself is now only the entry point).
func newTxApp() *ucli.App {
	return &ucli.App{
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
}

// buildCommand returns the "build" subcommand (moved from main.go for thin main.go per M2.3-5).
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
// (Moved from main.go for thin-main M2.3-5.)
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
