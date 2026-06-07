package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	ucli "github.com/urfave/cli/v2"

	"github.com/rootwarp/eth-utils/go/internal/cli"
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
}

// LoadRunConfig parses and validates run subcommand flags.
func LoadRunConfig(c *ucli.Context) (*RunConfig, error) {
	buildCfg, err := LoadBuildConfig(c)
	if err != nil {
		return nil, err
	}

	signerType := c.String("signer")
	if signerType == "" {
		return nil, ucli.Exit("--signer: required flag not set; must be \"local\" or \"ledger\"", 2)
	}
	if signerType != "local" && signerType != "ledger" {
		return nil, ucli.Exit(fmt.Sprintf("--signer: unsupported value %q: must be \"local\" or \"ledger\"", signerType), 2)
	}

	envVar := c.String("private-key-env")
	if !posixEnvVarName.MatchString(envVar) {
		_, _ = fmt.Fprintf(c.App.ErrWriter, "WARNING: the rejected value should be treated as compromised\n")
		return nil, ucli.Exit(fmt.Sprintf(
			"--private-key-env: %q is not a valid POSIX env var name (must match ^[A-Z_][A-Z0-9_]*$); did you accidentally pass the key value instead of a variable name?",
			cli.Redact(envVar, 4),
		), 2)
	}

	keepUnsigned := c.Bool("keep-unsigned")
	outputFile := c.String("output")
	if keepUnsigned && (outputFile == "" || outputFile == "-") {
		return nil, ucli.Exit("--keep-unsigned requires --output to be a file path (cannot be used with stdout)", 2)
	}

	return &RunConfig{
		Build:            buildCfg,
		Signer:           signerType,
		PrivateKeyEnvVar: envVar,
		OutputFile:       outputFile,
		KeepUnsigned:     keepUnsigned,
		RawOutputFile:    c.String("raw-output"),
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
  signed.raw   — companion file containing only the 0x-prefixed RLP hex, written
                 alongside signed.json when --output is a file path. This is the
                 value to pass to eth_sendRawTransaction. The 0x prefix is included
                 for grep/curl friendliness; strip it if your tool requires raw bytes.

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
  ETH_DEPOSIT_TX_PRIVATE_KEY=0x<your-dev-key> eth-deposit-tx run \
    --network holesky \
    --input-file deposit_data.json \
    --signer local

  # Local signer — save to file, then broadcast separately:
  ETH_DEPOSIT_TX_PRIVATE_KEY=0x<your-dev-key> eth-deposit-tx run \
    --network holesky \
    --input-file deposit_data.json \
    --signer local \
    --output signed.json

  # Ledger hardware wallet — keep unsigned tx for audit trail:
  eth-deposit-tx run \
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
		UsageText: `eth-deposit-tx run --input-file FILE --network NET --signer local|ledger [options]`,
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
		Action: func(c *ucli.Context) error {
			cfg, err := LoadRunConfig(c)
			if err != nil {
				return err
			}
			// M1.6-1 confirm-network match for run (equiv to build/sendAction logic).
			// (Mainnet required pre-validated inside LoadBuildConfig called by LoadRunConfig.)
			if cfg.Build.ConfirmNetwork != "" && cfg.Build.ConfirmNetwork != string(cfg.Build.NetworkParams.Name) {
				return ucli.Exit(fmt.Sprintf("--confirm-network: %q does not match --network %q", cfg.Build.ConfirmNetwork, cfg.Build.NetworkParams.Name), 2)
			}
			return runAction(c, cfg)
		},
	}
}

// buildFlags returns the flag list shared between build and run subcommands.
func buildFlags() []ucli.Flag {
	return []ucli.Flag{
		&ucli.StringFlag{
			Name:    "input-file",
			Aliases: []string{"input", "i"},
			Usage:   "Path to deposit_data-*.json file (or '-' for stdin); --input is accepted as a shorter alias",
			EnvVars: []string{"ETH_DEPOSIT_TX_INPUT_FILE"},
		},
		&ucli.StringFlag{
			Name:    "network",
			Aliases: []string{"n"},
			Usage:   "Target network (mainnet, hoodi, sepolia, holesky)",
			Value:   "hoodi",
			EnvVars: []string{"ETH_DEPOSIT_TX_NETWORK"},
		},
		&ucli.StringFlag{
			Name:  "confirm-network",
			Usage: "Explicit acknowledgement of the target network name (required for mainnet; must match the network name; --yes does not bypass)",
		},
		&ucli.StringFlag{
			Name:    "output",
			Usage:   "Output file for the signed transaction (default: stdout)",
			EnvVars: []string{"ETH_DEPOSIT_TX_OUTPUT"},
		},
		&ucli.IntFlag{
			Name:    "index",
			Usage:   "Index of the deposit entry to use when the JSON contains multiple validators (default: 0)",
			Value:   0,
			EnvVars: []string{"ETH_DEPOSIT_TX_INDEX"},
		},
		&ucli.StringFlag{
			Name:    "rpc-url",
			Usage:   "JSON-RPC endpoint URL for gas/nonce estimation (optional on run for hybrid; when omitted, all gas and nonce flags must be supplied explicitly)",
			EnvVars: []string{"ETH_DEPOSIT_TX_RPC_URL"},
		},
		&ucli.StringFlag{
			Name:    "gas-limit",
			Usage:   fmt.Sprintf("Gas limit for the deposit transaction (default: %d)", defaultGasLimit),
			EnvVars: []string{"ETH_DEPOSIT_TX_GAS_LIMIT"},
		},
		&ucli.StringFlag{
			Name:    "max-fee-per-gas",
			Usage:   "EIP-1559 maximum fee per gas in wei (decimal integer, e.g. 20000000000 for 20 Gwei)",
			EnvVars: []string{"ETH_DEPOSIT_TX_MAX_FEE_PER_GAS"},
		},
		&ucli.StringFlag{
			Name:    "max-priority-fee-per-gas",
			Usage:   "EIP-1559 maximum priority fee per gas in wei (decimal integer, e.g. 1000000000 for 1 Gwei)",
			EnvVars: []string{"ETH_DEPOSIT_TX_MAX_PRIORITY_FEE_PER_GAS"},
		},
		&ucli.StringFlag{
			Name:    "nonce",
			Usage:   "Override the sender account nonce (non-negative integer; omit to fetch from RPC or set later)",
			EnvVars: []string{"ETH_DEPOSIT_TX_NONCE"},
		},
	}
}

// runAction orchestrates the build → sign pipeline in-process.
func runAction(c *ucli.Context, cfg *RunConfig) error {
	// 1. Read deposit data.
	var rawData []byte
	var err error
	if cfg.Build.InputFile == "-" {
		rawData, err = io.ReadAll(c.App.Reader)
	} else {
		rawData, err = os.ReadFile(cfg.Build.InputFile)
	}
	if err != nil {
		return ucli.Exit(fmt.Sprintf("--input-file: %v", err), 2)
	}

	// 2. If --rpc-url provided (run only), construct client for auto nonce/fees (M1.3-5).
	// build path rejects --rpc-url (see main.go); reuse resolveRPC via the EthRPC.
	var rpcClient internaltx.EthRPC
	if rpcURL := cfg.Build.RPCURL; rpcURL != "" {
		rpcClient, err = newRPCClient(c.Context, rpcURL)
		if err != nil {
			return err
		}
		defer rpcClient.Close()
	}

	// 3. Build unsigned tx (in-process, no disk write). Thread rpc + from (for nonce) only on run hybrid.
	var from [20]byte
	if rpcClient != nil && cfg.Build.Nonce == nil && cfg.Signer == "local" {
		// Derive sender addr from priv env (only for run+local+auto-nonce; ledger would require early device open).
		// Avoids ErrMissingFromForNonce in resolveRPC. Follows signer zeroize/unset contract (M0.8/M1.1/GO-017): defer unset on read,
		// zero decode buf b (and nil it) after use; see internal/signer/local.go:49 (NewFromHex) and :136 (Sign).
		// Duplicates parse only for addr (no key retained); sign path still constructs full signer (which will re-read env before its unset).
		hexKey := os.Getenv(cfg.PrivateKeyEnvVar)
		nameForErr := cfg.PrivateKeyEnvVar
		if len(nameForErr) > 32 {
			nameForErr = cli.Redact(nameForErr, 4)
		}
		if hexKey == "" {
			_ = os.Unsetenv(cfg.PrivateKeyEnvVar)
			return fmt.Errorf("local signer: environment variable %q is not set or empty: %w", nameForErr, signer.ErrInvalidKey)
		}
		defer func() { _ = os.Unsetenv(cfg.PrivateKeyEnvVar) }()
		stripped := strings.TrimPrefix(hexKey, "0x")
		if b, decErr := hex.DecodeString(stripped); decErr == nil && len(b) == 32 {
			defer func() {
				for i := range b {
					b[i] = 0
				}
				b = nil
			}()
			if priv, ecdErr := crypto.ToECDSA(b); ecdErr == nil {
				addr := crypto.PubkeyToAddress(priv.PublicKey)
				copy(from[:], addr[:])
			} else {
				return fmt.Errorf("local signer: environment variable %q: %w", nameForErr, signer.ErrInvalidKey)
			}
		} else {
			return fmt.Errorf("local signer: environment variable %q: %w", nameForErr, signer.ErrInvalidKey)
		}
	}
	unsigned, err := buildUnsignedTx(c.Context, cfg.Build, rawData, rpcClient, from)
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
		Signer:           cfg.Signer,
		PrivateKeyEnvVar: cfg.PrivateKeyEnvVar,
	}
	signed, err := signUnsignedTx(c.Context, signCfg, c.App.ErrWriter, *unsigned)
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
		_, err = c.App.Writer.Write(signedJSON)
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
	tmp, err := os.CreateTemp(dir, ".tmp-eth-deposit-tx-*")
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

// Compile-time assertion that signer.SignedTx has the RawRLP field we reference.
var _ = (*signer.SignedTx)(nil)
