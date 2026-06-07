package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"time"

	ucli "github.com/urfave/cli/v2"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/rootwarp/eth-utils/go/internal/cli"
	"github.com/rootwarp/eth-utils/go/internal/network"
	"github.com/rootwarp/eth-utils/go/internal/signer"
	internaltx "github.com/rootwarp/eth-utils/go/internal/tx"
)

// newBroadcaster is the production broadcaster factory. Tests override this.
var newBroadcaster = func(ctx context.Context, rpcURL string) (internaltx.EthBroadcaster, error) {
	return internaltx.NewEthClient(ctx, rpcURL)
}

// validateSignedAgainstRLP is the production RLP/JSON validator (per M0.6-4/5,
// arch §7.3/§13.1/§15). Assigned at init to the real impl; tests rebind a
// wrapper (capturing orig) for call-order spying exactly as newBroadcaster.
var validateSignedAgainstRLP = realValidateSignedAgainstRLP

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

	// 2. Compute netParams from *declared* JSON chainID (not RPC) so we can
	//    call validateSignedAgainstRLP *before* any broadcaster.ChainID().
	//    (enables TestSendAction_ValidateBeforeBroadcast_Order and validate-first).
	declaredChainID := signed.Unsigned.ChainID
	netParams, lookupErr := network.LookupByChainID(declaredChainID)
	if lookupErr != nil {
		// Non-fatal fallback for display/validate contract check (matches prior behavior).
		netParams = network.Params{
			Name:    network.Network(fmt.Sprintf("chain-%d", declaredChainID)),
			ChainID: declaredChainID,
		}
	}

	// 3. validate-first: RLP vs JSON + deposit contract (M0.6-5 restructure per
	//    arch §7.3/§13.1). Uses declared net for contract check. All divergence
	//    and type errors -> ucli.Exit(...,2) with descriptive msg.
	rlpTx, err := validateSignedAgainstRLP(&signed, netParams)
	if err != nil {
		return err
	}

	// 4. Dial RPC (after validate).
	broadcaster, err := newBroadcaster(c.Context, cfg.RPCURL)
	if err != nil {
		return err
	}
	defer broadcaster.Close()

	// 5. RPC chain ID guard now against the *decoded* rlpTx (not signed.Unsigned).
	rpcChainID, err := broadcaster.BroadcasterChainID(c.Context)
	if err != nil {
		return fmt.Errorf("%w: fetch chain ID: %w", internaltx.ErrBroadcastFailed, err)
	}
	if rpcChainID != rlpTx.ChainId().Uint64() {
		return fmt.Errorf("%w: signed tx has chain ID %d but RPC reports %d",
			internaltx.ErrBroadcastChainIDMismatch, rlpTx.ChainId().Uint64(), rpcChainID)
	}

	// 6. Re-resolve netParams from the now-authoritative (guard-passed) rpc chain.
	netParams, lookupErr = network.LookupByChainID(rpcChainID)
	if lookupErr != nil {
		netParams = network.Params{
			Name:    network.Network(fmt.Sprintf("chain-%d", rpcChainID)),
			ChainID: rpcChainID,
		}
	}

	// 7. Print the "about to broadcast" prompt from *decoded* rlpTx values,
	//    labelled "(decoded from RLP)" (existing prompt code updated to take
	//    decoded; per M0.6-5 AC + arch §13.1). From remains from container.
	valueBigWei := rlpTx.Value()
	maxFeeBigWei := rlpTx.GasFeeCap()
	toStr := "0x0000000000000000000000000000000000000000"
	if rlpTx.To() != nil {
		toStr = rlpTx.To().Hex()
	}
	_, _ = fmt.Fprintf(c.App.ErrWriter, "\n")                                                                               // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, "> You are about to BROADCAST a %s deposit transaction.\n", formatETH(valueBigWei)) // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">   Network:        %s (chain ID %d)\n", netParams.Name, netParams.ChainID)        // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">   From:           %s\n", signed.From)                                            // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">   To (deposit):   %s (decoded from RLP)\n", toStr)                               // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">   Value:          %s (decoded from RLP)\n", formatETH(valueBigWei))              // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">   Nonce:          %d (decoded from RLP)\n", rlpTx.Nonce())                       // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">   MaxFeePerGas:   %s (decoded from RLP)\n", formatGwei(maxFeeBigWei))            // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">   Tx hash:        %s (decoded from RLP)\n", rlpTx.Hash().Hex())                  // ignore: best-effort to ErrWriter
	_, _ = fmt.Fprintf(c.App.ErrWriter, ">\n")                                                                              // ignore: best-effort to ErrWriter

	// 8. Confirmation.
	if !cfg.Yes {
		var confirmR io.Reader
		var cleanup func()
		var cErr error
		if cfg.InputFile == "-" {
			// only for --input - (where app.Reader was consumed for JSON) do we need
			// ConfirmReader to possibly return /dev/tty or ErrNoTTY; for normal file
			// input the pre-existing direct use of (possibly faked-in-test) c.App.Reader
			// for the prompt must be preserved for testability/env independence.
			confirmR, cleanup, cErr = cli.ConfirmReader(c.App.Reader)
			defer cleanup()
			if errors.Is(cErr, cli.ErrNoTTY) {
				return ucli.Exit(cErr.Error(), 2)
			}
		} else {
			confirmR = c.App.Reader
			cleanup = func() {}
			cErr = nil
		}
		_, _ = fmt.Fprintf(c.App.ErrWriter, "> Type the network name to confirm: ") // ignore: best-effort to ErrWriter
		reader := bufio.NewReader(confirmR)
		input, err := reader.ReadString('\n')
		if err != nil {
			// EOF or any read error → abort
			_, _ = fmt.Fprintf(c.App.ErrWriter, "\nAborted.\n") // ignore: best-effort to ErrWriter
			return fmt.Errorf("%w: %w", ErrUserAborted, err)
		}
		input = strings.TrimSpace(input)
		if !strings.EqualFold(input, string(netParams.Name)) {
			_, _ = fmt.Fprintf(c.App.ErrWriter, "> Confirmation failed (got %q, want %q). Aborted.\n", input, netParams.Name) // ignore: best-effort to ErrWriter
			return ErrUserAborted
		}
	}

	// 9. Broadcast.
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
			if rec.Status == 0 {
				return internaltx.ErrReceiptReverted
			}
		}
	}

	return nil
}

// realValidateSignedAgainstRLP implements the GO-004 boundary check: decode
// RawRLP, enforce DynamicFee type, recover+match sender, field-compare all
// critical metadata against the JSON container, enforce deposit contract To
// (no override path in send), and return the decoded tx for prompt/guard use.
// Divergences and type errors surface via ucli.Exit(..., 2) with context so
// operator sees "JSON vs decoded". Follows M0.6-1 parse style + M0.5 validator
// patterns (errors.Is-able sentinels via ucli, no new sentinels here).
func realValidateSignedAgainstRLP(signed *signer.SignedTx, netParams network.Params) (*types.Transaction, error) {
	if signed == nil {
		return nil, ucli.Exit("validate: nil signed tx", 2)
	}
	rawHex := strings.TrimPrefix(signed.RawRLP, "0x")
	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, ucli.Exit(fmt.Sprintf("validate: invalid rawRLP hex: %v", err), 2)
	}
	var decoded types.Transaction
	if err := decoded.UnmarshalBinary(rawBytes); err != nil {
		return nil, ucli.Exit(fmt.Sprintf("validate: RLP decode failed: %v", err), 2)
	}
	if decoded.Type() != types.DynamicFeeTxType {
		return nil, ucli.Exit(fmt.Sprintf("validate: tx type %d is not DynamicFeeTxType", decoded.Type()), 2)
	}
	// Recover sender from RLP using LatestSigner (M0.2 geth).
	s := types.LatestSignerForChainID(decoded.ChainId())
	recovered, err := types.Sender(s, &decoded)
	if err != nil {
		return nil, ucli.Exit(fmt.Sprintf("validate: sender recovery: %v", err), 2)
	}
	if recovered.Hex() != signed.From {
		return nil, ucli.Exit("validate: recovered sender does not match signed.from", 2)
	}
	// Field divergence checks (descriptive for operator, per M0.6-4 notes using
	// errors.Join + context; maps to exit 2).
	var diverges []error
	if decoded.ChainId().Uint64() != signed.Unsigned.ChainID {
		diverges = append(diverges, fmt.Errorf("chainID: json=%d decoded=%d", signed.Unsigned.ChainID, decoded.ChainId().Uint64()))
	}
	toHex := ""
	if decoded.To() != nil {
		toHex = decoded.To().Hex()
	}
	if toHex != signed.Unsigned.To {
		diverges = append(diverges, fmt.Errorf("to: json=%s decoded=%s", signed.Unsigned.To, toHex))
	}
	vJSON, _ := hexToBigInt(signed.Unsigned.Value)
	if vJSON == nil || decoded.Value().Cmp(vJSON) != 0 {
		diverges = append(diverges, fmt.Errorf("value: json=%s decoded=%s", signed.Unsigned.Value, decoded.Value().String()))
	}
	if decoded.Nonce() != signed.Unsigned.Nonce {
		diverges = append(diverges, fmt.Errorf("nonce: json=%d decoded=%d", signed.Unsigned.Nonce, decoded.Nonce()))
	}
	if decoded.Hash().Hex() != signed.Hash {
		diverges = append(diverges, fmt.Errorf("hash: json=%s decoded=%s", signed.Hash, decoded.Hash().Hex()))
	}
	if len(diverges) != 0 {
		return nil, ucli.Exit(fmt.Sprintf("JSON metadata diverges from decoded RLP: %v", errors.Join(diverges...)), 2)
	}
	// Deposit contract cross-check (netParams from caller; no --allow override in send path).
	depositAddr := common.BytesToAddress(netParams.DepositContractAddress[:])
	if decoded.To() == nil || *decoded.To() != depositAddr {
		return nil, ucli.Exit(fmt.Sprintf("decoded To %s is not deposit contract for network", toHex), 2)
	}
	return &decoded, nil
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
			return nil, internaltx.ErrReceiptTimeout
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
