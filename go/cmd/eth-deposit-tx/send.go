package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"time"

	ucli "github.com/urfave/cli/v2"

	"github.com/rootwarp/eth-utils/go/internal/network"
	"github.com/rootwarp/eth-utils/go/internal/signer"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// newBroadcaster is the production broadcaster factory. Tests override this.
var newBroadcaster = func(ctx context.Context, rpcURL string) (internaltx.EthBroadcaster, error) {
	return internaltx.NewEthClient(ctx, rpcURL)
}

// SendConfig holds parsed, validated inputs for the send subcommand.
type SendConfig struct {
	// InputFile is the path to the signed tx JSON, or "-" for stdin.
	InputFile string
	// RPCURL is the JSON-RPC endpoint for broadcast.
	RPCURL string
	// Yes skips the interactive double-confirmation prompt.
	Yes bool
	// WaitForReceipt polls until the receipt is available.
	WaitForReceipt bool
	// ReceiptTimeout is the maximum time to wait for a receipt.
	ReceiptTimeout time.Duration
	// ReceiptOutputFile is an optional file path to write the receipt JSON.
	ReceiptOutputFile string
}

// LoadSendConfig parses and validates send subcommand flags.
func LoadSendConfig(c *ucli.Context) (*SendConfig, error) {
	inputFile := c.String("input")
	if inputFile == "" {
		return nil, ucli.Exit("--input: required flag not set", 2)
	}

	rpcURL := c.String("rpc-url")
	if rpcURL == "" {
		return nil, ucli.Exit("--rpc-url: required flag not set", 2)
	}

	timeout := c.Duration("receipt-timeout")
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	receiptOutput := c.String("receipt-output")
	waitForReceipt := c.Bool("wait-for-receipt") || receiptOutput != ""

	return &SendConfig{
		InputFile:         inputFile,
		RPCURL:            rpcURL,
		Yes:               c.Bool("yes"),
		WaitForReceipt:    waitForReceipt,
		ReceiptTimeout:    timeout,
		ReceiptOutputFile: receiptOutput,
	}, nil
}

// sendCommand returns the urfave/cli send subcommand definition.
func sendCommand() *ucli.Command {
	return &ucli.Command{
		Name:  "send",
		Usage: "Broadcast a signed deposit transaction via JSON-RPC",
		Description: `Submits a signed transaction (produced by sign or run) to the Ethereum network
via eth_sendRawTransaction.

WARNING: This command broadcasts to the live network and SPENDS REAL ETH.
You will be prompted to type the network name before anything is sent.
Use --yes to bypass the confirmation prompt (for automation only).

Examples:

  # Broadcast with interactive confirmation (type "holesky" when prompted):
  eth-deposit-tx send \
    --input signed.json \
    --rpc-url https://holesky.infura.io/v3/<your-key>

  # Broadcast non-interactively and wait for receipt (CI / automation):
  eth-deposit-tx send \
    --input signed.json \
    --rpc-url https://holesky.infura.io/v3/<your-key> \
    --yes \
    --wait-for-receipt \
    --receipt-output receipt.json

  # Read signed tx from stdin (e.g. piped from run --output -):
  eth-deposit-tx run --signer local ... --output - | \
    eth-deposit-tx send --input - --rpc-url https://... --yes

Exit codes:
  0  Success
  2  User / configuration error (missing flags, invalid JSON)
  4  User abort (Ctrl-C or declined confirmation)
  5  Broadcast / RPC error (dial failure, chain ID mismatch, node rejection)`,
		UsageText: `eth-deposit-tx send --input FILE --rpc-url URL [--yes] [--wait-for-receipt] [--receipt-output FILE]`,
		Flags: []ucli.Flag{
			&ucli.StringFlag{
				Name:    "input",
				Aliases: []string{"i"},
				Usage:   "Path to the signed transaction JSON (from sign or run), or '-' for stdin",
			},
			&ucli.StringFlag{
				Name:    "rpc-url",
				Usage:   "JSON-RPC endpoint URL for broadcast",
				EnvVars: []string{"ETH_DEPOSIT_TX_RPC_URL"},
			},
			&ucli.BoolFlag{
				Name:  "yes",
				Usage: "Skip the interactive confirmation prompt (for non-interactive automation; use with caution)",
			},
			&ucli.BoolFlag{
				Name:  "wait-for-receipt",
				Usage: "Poll until the transaction receipt is available (or --receipt-timeout elapses)",
			},
			&ucli.DurationFlag{
				Name:  "receipt-timeout",
				Usage: "Maximum time to wait for a transaction receipt when --wait-for-receipt is set",
				Value: 60 * time.Second,
			},
			&ucli.StringFlag{
				Name:  "receipt-output",
				Usage: "Write the transaction receipt JSON to this file (implies --wait-for-receipt)",
			},
		},
		Action: func(c *ucli.Context) error {
			cfg, err := LoadSendConfig(c)
			if err != nil {
				return err
			}
			return sendAction(c, cfg)
		},
	}
}

// sendAction executes the send workflow. Extracted for testability.
func sendAction(c *ucli.Context, cfg *SendConfig) error {
	// 1. Read signed tx.
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

	var signed signer.SignedTx
	if err := json.Unmarshal(raw, &signed); err != nil {
		return ucli.Exit(fmt.Sprintf("invalid input JSON: %v", err), 2)
	}

	// 2. Dial RPC.
	broadcaster, err := newBroadcaster(c.Context, cfg.RPCURL)
	if err != nil {
		return err
	}
	defer broadcaster.Close()

	// 3. Verify chain ID.
	rpcChainID, err := broadcaster.BroadcasterChainID(c.Context)
	if err != nil {
		return fmt.Errorf("%w: fetch chain ID: %v", internaltx.ErrBroadcastFailed, err)
	}
	if rpcChainID != signed.Unsigned.ChainID {
		return fmt.Errorf("%w: signed tx has chain ID %d but RPC reports %d",
			internaltx.ErrBroadcastChainIDMismatch, signed.Unsigned.ChainID, rpcChainID)
	}

	// 4. Resolve network for display.
	netParams, err := network.LookupByChainID(rpcChainID)
	if err != nil {
		// Non-fatal: we'll display what we can without a network name.
		netParams = network.Params{
			Name:    network.Network(fmt.Sprintf("chain-%d", rpcChainID)),
			ChainID: rpcChainID,
		}
	}

	// 5. Print the "about to broadcast" prompt.
	valueBigWei, _ := hexToBigInt(signed.Unsigned.Value)
	maxFeeBigWei, _ := hexToBigInt(signed.Unsigned.MaxFeePerGas)

	_, _ = fmt.Fprintf(c.App.ErrWriter, "\n")                                                                               // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, "> You are about to BROADCAST a %s deposit transaction.\n", formatETH(valueBigWei)) // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">   Network:        %s (chain ID %d)\n", netParams.Name, netParams.ChainID)        // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">   From:           %s\n", signed.From)                                            // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">   To (deposit):   %s\n", signed.Unsigned.To)                                     // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">   Value:          %s\n", formatETH(valueBigWei))                                 // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">   Nonce:          %d\n", signed.Unsigned.Nonce)                                  // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">   MaxFeePerGas:   %s\n", formatGwei(maxFeeBigWei))                               // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">   Tx hash:        %s\n", signed.Hash)                                            // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">\n")                                                                              // ignore: best-effort to ErrWriter

	// 6. Confirmation.
	if !cfg.Yes {
		_, _ = fmt.Fprintf(c.App.ErrWriter, "> Type the network name to confirm: ") // ignore: best-effort to ErrWriter
		reader := bufio.NewReader(c.App.Reader)
		input, err := reader.ReadString('\n')
		if err != nil {
			// EOF or any read error → abort
			_, _ = fmt.Fprintf(c.App.ErrWriter, "\nAborted.\n") // ignore: best-effort to ErrWriter
			return fmt.Errorf("%w: %v", ErrUserAborted, err)
		}
		input = strings.TrimSpace(input)
		if !strings.EqualFold(input, string(netParams.Name)) {
			_, _ = fmt.Fprintf(c.App.ErrWriter, "> Confirmation failed (got %q, want %q). Aborted.\n", input, netParams.Name) // ignore: best-effort to ErrWriter
			return ErrUserAborted
		}
	}

	// 7. Broadcast.
	_, _ = fmt.Fprintf(c.App.ErrWriter, "> Broadcasting...\n") // ignore: best-effort to ErrWriter
	txHash, err := broadcaster.SendRawTransaction(c.Context, signed.RawRLP)
	if err != nil {
		return err
	}

	// 8. Print result.
	_, _ = fmt.Fprintf(c.App.Writer, "Tx hash: %s\n", txHash) // ignore: best-effort to Writer
	if netParams.ExplorerURL != "" {
		_, _ = fmt.Fprintf(c.App.Writer, "Explorer: %s/tx/%s\n", netParams.ExplorerURL, txHash) // ignore: best-effort to Writer
	}
	slog.Info("broadcast succeeded", "hash", txHash, "network", netParams.Name)

	// 9. Optionally wait for receipt.
	if cfg.WaitForReceipt {
		rec, err := pollReceipt(c.Context, broadcaster, txHash, cfg.ReceiptTimeout)
		if err != nil {
			return fmt.Errorf("receipt: %w", err)
		}
		if rec != nil {
			statusStr := "success"
			if rec.Status == 0 {
				statusStr = "REVERTED"
			}
			_, _ = fmt.Fprintf(c.App.Writer, "Receipt: status=%s block=%d gasUsed=%d\n",
				statusStr, rec.BlockNumber, rec.GasUsed) // ignore: best-effort to Writer

			if cfg.ReceiptOutputFile != "" {
				recJSON, err := json.MarshalIndent(rec, "", "  ")
				if err != nil {
					return ucli.Exit(fmt.Sprintf("receipt: marshal: %v", err), 2)
				}
				recJSON = append(recJSON, '\n')
				if err := atomicWriteFile(cfg.ReceiptOutputFile, recJSON, 0o600); err != nil {
					return ucli.Exit(fmt.Sprintf("--receipt-output: write %s: %v", cfg.ReceiptOutputFile, err), 2)
				}
				slog.Info("wrote receipt", "path", cfg.ReceiptOutputFile)
			}
		}
	}

	return nil
}

// pollReceipt polls for a transaction receipt until timeout.
func pollReceipt(ctx context.Context, bc internaltx.EthBroadcaster, txHash string, timeout time.Duration) (*internaltx.Receipt, error) {
	pollInterval := 2 * time.Second
	if timeout < pollInterval {
		pollInterval = timeout / 2
		if pollInterval < 10*time.Millisecond {
			pollInterval = 10 * time.Millisecond
		}
	}

	deadline := time.Now().Add(timeout)
	for {
		rec, err := bc.TransactionReceipt(ctx, txHash)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			return rec, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for receipt after %s", timeout)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// hexToBigInt parses a 0x-prefixed hex string into a *big.Int.
func hexToBigInt(s string) (*big.Int, bool) {
	s = strings.TrimPrefix(s, "0x")
	n := new(big.Int)
	_, ok := n.SetString(s, 16)
	return n, ok
}

var (
	weiPerETH  = new(big.Float).SetPrec(256).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	weiPerGwei = new(big.Float).SetPrec(256).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(9), nil))
)

func formatETH(wei *big.Int) string {
	if wei == nil {
		return "0.000000 ETH"
	}
	f := new(big.Float).SetPrec(256).SetInt(wei)
	eth := new(big.Float).Quo(f, weiPerETH)
	v, _ := eth.Float64()
	return fmt.Sprintf("%.6f ETH", v)
}

func formatGwei(wei *big.Int) string {
	if wei == nil {
		return "0.000000 Gwei"
	}
	f := new(big.Float).SetPrec(256).SetInt(wei)
	gwei := new(big.Float).Quo(f, weiPerGwei)
	v, _ := gwei.Float64()
	return fmt.Sprintf("%.6f Gwei", v)
}
