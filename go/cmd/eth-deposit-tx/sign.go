package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"

	ucli "github.com/urfave/cli/v2"

	"github.com/rootwarp/eth-utils/go/internal/signer"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

const defaultPrivKeyEnvVar = "ETH_DEPOSIT_TX_PRIVATE_KEY"

// posixEnvVarName matches valid POSIX env var names: uppercase letters, digits,
// underscore; must start with letter or underscore.
var posixEnvVarName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// SignConfig holds parsed, validated inputs for the sign subcommand.
type SignConfig struct {
	// Signer is the resolved signer type: "local" or "ledger".
	Signer string
	// InputFile is the path to the unsigned tx JSON, or "-" for stdin.
	InputFile string
	// OutputFile is the output path for the signed tx. Empty means stdout.
	OutputFile string
	// PrivateKeyEnvVar is the env var name holding the hex private key (local signer only).
	PrivateKeyEnvVar string
}

// LoadSignConfig parses and validates sign subcommand flags.
func LoadSignConfig(c *ucli.Context) (*SignConfig, error) {
	signerType := c.String("signer")
	if signerType != "local" && signerType != "ledger" {
		return nil, ucli.Exit(fmt.Sprintf("--signer: unsupported value %q: must be \"local\" or \"ledger\"", signerType), 2)
	}

	inputFile := c.String("input")
	if inputFile == "" {
		return nil, ucli.Exit("--input: required flag not set", 2)
	}

	envVar := c.String("private-key-env")
	if !posixEnvVarName.MatchString(envVar) {
		return nil, ucli.Exit(fmt.Sprintf(
			"--private-key-env: %q is not a valid POSIX env var name (must match ^[A-Z_][A-Z0-9_]*$); did you accidentally pass the key value instead of a variable name?",
			envVar,
		), 2)
	}

	return &SignConfig{
		Signer:           signerType,
		InputFile:        inputFile,
		OutputFile:       c.String("output"),
		PrivateKeyEnvVar: envVar,
	}, nil
}

// signCommand returns the urfave/cli sign subcommand definition.
func signCommand() *ucli.Command {
	return &ucli.Command{
		Name:  "sign",
		Usage: "Sign a previously built unsigned deposit transaction",
		Description: `Signs an unsigned transaction produced by "eth-deposit-tx build".

Two signing methods are supported:

  --signer local
    Reads a secp256k1 private key from the environment variable named by
    --private-key-env (default: ETH_DEPOSIT_TX_PRIVATE_KEY).

    WARNING: The local signer is FOR DEVELOPMENT ONLY. Never use it with
    real-fund keys. The key must never appear in CLI arguments or shell history.

    Example:
      ETH_DEPOSIT_TX_PRIVATE_KEY=0x<hex-key> eth-deposit-tx sign \
        --signer local --input unsigned.json --output signed.json

  --signer ledger
    Signs using a Ledger hardware wallet. Prerequisites:
      1. Ledger device is connected via USB.
      2. The Ethereum app is open on the device.

    The user will be prompted to confirm the transaction on the device.

    Example:
      eth-deposit-tx sign --signer ledger --input unsigned.json --output signed.json

Exit codes:
  0  Success
  2  User / configuration error (bad --signer, missing --input, invalid JSON)
  3  Signer / crypto error (bad key, no Ledger device, Ethereum app not open)
  4  User abort (Ctrl-C or rejection on Ledger device)`,
		UsageText: `eth-deposit-tx sign --signer local|ledger --input FILE [--output FILE] [--private-key-env VAR]`,
		Flags: []ucli.Flag{
			&ucli.StringFlag{
				Name:     "signer",
				Usage:    "Signing method: \"local\" (env-var private key) or \"ledger\" (hardware wallet)",
				Required: true,
			},
			&ucli.StringFlag{
				Name:    "input",
				Aliases: []string{"i"},
				Usage:   "Path to the unsigned transaction JSON (from build) or '-' for stdin",
			},
			&ucli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "Output file for the signed transaction (default: stdout)",
			},
			&ucli.StringFlag{
				Name:  "private-key-env",
				Usage: fmt.Sprintf("Environment variable name holding the hex private key (local signer only; default: %s)", defaultPrivKeyEnvVar),
				Value: defaultPrivKeyEnvVar,
			},
		},
		Action: func(c *ucli.Context) error {
			cfg, err := LoadSignConfig(c)
			if err != nil {
				return err
			}
			return signAction(c, cfg)
		},
	}
}

// signAction executes the sign workflow. Extracted for testability.
func signAction(c *ucli.Context, cfg *SignConfig) error {
	// 1. Read input.
	var raw []byte
	var err error
	if cfg.InputFile == "-" {
		raw, err = io.ReadAll(c.App.Reader)
	} else {
		raw, err = os.ReadFile(cfg.InputFile)
	}
	if err != nil {
		return ucli.Exit(fmt.Sprintf("--input: %v", err), 2)
	}

	// 2. Parse unsigned tx.
	var unsigned internaltx.UnsignedTx
	if err := json.Unmarshal(raw, &unsigned); err != nil {
		return ucli.Exit(fmt.Sprintf("invalid input JSON: %v", err), 2)
	}

	// 3. Sign.
	signed, err := signUnsignedTx(c.Context, cfg, c.App.ErrWriter, unsigned)
	if err != nil {
		return err
	}

	// 4. Marshal output.
	out, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return fmt.Errorf("sign: marshal: %w", err)
	}
	out = append(out, '\n')

	// 5. Write output.
	if cfg.OutputFile == "" || cfg.OutputFile == "-" {
		_, err = c.App.Writer.Write(out)
		return err
	}
	// 0o600: signed tx bytes contain sensitive metadata (from address, tx hash, etc.)
	if err := os.WriteFile(cfg.OutputFile, out, 0o600); err != nil {
		return ucli.Exit(fmt.Sprintf("--output: %v", err), 2)
	}
	slog.Info("wrote signed tx", "path", cfg.OutputFile, "signer", cfg.Signer)
	return nil
}

// signUnsignedTx constructs a signer and produces a SignedTx for the given unsigned tx.
// errWriter is used for interactive device prompts (may be nil for tests that suppress output).
// It is extracted so runAction can call it without serializing to disk between build and sign.
func signUnsignedTx(ctx context.Context, cfg *SignConfig, errWriter io.Writer, unsigned internaltx.UnsignedTx) (*signer.SignedTx, error) {
	// 1. Construct signer.
	var s signer.Signer
	var err error
	switch cfg.Signer {
	case "local":
		s, err = signer.NewLocalSignerFromEnv(cfg.PrivateKeyEnvVar)
		if err != nil {
			return nil, fmt.Errorf("local signer: %w", err)
		}
	case "ledger":
		s, err = signer.NewLedgerSigner()
		if err != nil {
			return nil, fmt.Errorf("ledger signer: %w", err)
		}
	}
	defer func() { _ = s.Close() }()

	// 2. Prompt if device interaction is needed.
	if s.RequiresUserInteraction() && errWriter != nil {
		_, _ = fmt.Fprintf(errWriter, "Waiting for confirmation on Ledger device...\n") // ignore: best-effort prompt to errWriter
	}

	// 3. Sign.
	signed, err := s.Sign(ctx, unsigned)
	if err != nil {
		return nil, fmt.Errorf("sign (%s): %w", cfg.Signer, err)
	}
	return signed, nil
}
