package tx

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/rootwarp/eth-utils/go/internal/cli"
)

// EthBroadcaster broadcasts a signed transaction via JSON-RPC.
type EthBroadcaster interface {
	// SendRawTransaction decodes the 0x-prefixed RLP hex and submits it via
	// eth_sendRawTransaction. Returns the tx hash as a 0x-prefixed hex string.
	SendRawTransaction(ctx context.Context, rawRLP string) (string, error)
	// TransactionReceipt returns the receipt for the given tx hash.
	// The ethClient implementation retries on ethereum.NotFound (not yet mined)
	// and transient network/timeout RPC errors with exponential backoff until
	// the context deadline (if set). On deadline without a receipt it returns
	// nil, ErrReceiptTimeout. When no deadline is set on ctx, NotFound or
	// transient yield immediately (nil,nil for NotFound; the err for transient)
	// so legacy callers such as pollReceipt control their own wait/timeout loop.
	TransactionReceipt(ctx context.Context, txHash string) (*Receipt, error)
	// BroadcasterChainID returns the chain ID of the connected node.
	BroadcasterChainID(ctx context.Context) (uint64, error)
	// Close closes the underlying RPC connection.
	Close()
}

// Receipt is a JSON-friendly summary of an Ethereum transaction receipt.
type Receipt struct {
	TransactionHash   string `json:"transactionHash"`
	Status            uint64 `json:"status"`
	BlockNumber       uint64 `json:"blockNumber"`
	BlockHash         string `json:"blockHash"`
	GasUsed           uint64 `json:"gasUsed"`
	EffectiveGasPrice string `json:"effectiveGasPrice,omitempty"`
}

// ethClient is the concrete implementation backed by go-ethereum's ethclient.
// It satisfies both EthRPC and EthBroadcaster.
type ethClient struct {
	client *ethclient.Client
}

// NewEthClient dials the given RPC URL and returns an ethClient.
// The rpcURL (which may contain API keys) is redacted via cli.Redact in error strings
// to prevent leakage in logs, stderr, or crash reports (addresses GO-049; now exercised
// by run hybrid via newRPCClient).
// Returns an error wrapping ErrRPCDial on connection failure.
func NewEthClient(ctx context.Context, rpcURL string) (*ethClient, error) {
	c, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		// %w (M2.3-4 cleanup after M1.5-8; enables errors.Is on dial err; redaction prefix + §8.2 protects secrets).
		return nil, fmt.Errorf("%w: %s: %w", ErrRPCDial, cli.Redact(rpcURL, 16), err)
	}
	return &ethClient{client: c}, nil
}

// --- EthBroadcaster ---

func (c *ethClient) SendRawTransaction(ctx context.Context, rawRLP string) (string, error) {
	rawBytes, err := decodeHex(rawRLP)
	if err != nil {
		return "", fmt.Errorf("%w: decode rawRLP: %w", ErrBroadcastFailed, err)
	}

	// UnmarshalBinary handles the EIP-2718 typed envelope (0x02 || rlp(...))
	// produced by types.Transaction.MarshalBinary. rlp.DecodeBytes cannot be
	// used here — it would reject the leading type byte.
	var tx types.Transaction
	if err := tx.UnmarshalBinary(rawBytes); err != nil {
		return "", fmt.Errorf("%w: decode EIP-2718: %w", ErrBroadcastFailed, err)
	}

	if err := c.client.SendTransaction(ctx, &tx); err != nil {
		return "", fmt.Errorf("%w: %w", ErrBroadcastFailed, err)
	}
	return tx.Hash().Hex(), nil
}

func (c *ethClient) TransactionReceipt(ctx context.Context, txHash string) (*Receipt, error) {
	hash := common.HexToHash(txHash)
	return transactionReceiptWithRetry(ctx, hash, c.client.TransactionReceipt)
}

func (c *ethClient) BroadcasterChainID(ctx context.Context) (uint64, error) {
	id, err := c.client.ChainID(ctx)
	if err != nil {
		return 0, fmt.Errorf("fetch chain ID: %w", err)
	}
	return id.Uint64(), nil
}

func (c *ethClient) Close() {
	c.client.Close()
}

// --- EthRPC ---

func (c *ethClient) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	return c.client.SuggestGasTipCap(ctx)
}

func (c *ethClient) BlockBaseFee(ctx context.Context) (*big.Int, error) {
	header, err := c.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}
	if header.BaseFee == nil {
		return nil, ErrNoBaseFee
	}
	return header.BaseFee, nil
}

func (c *ethClient) PendingNonceAt(ctx context.Context, account [20]byte) (uint64, error) {
	return c.client.PendingNonceAt(ctx, common.Address(account))
}

func (c *ethClient) EstimateGas(ctx context.Context, msg CallMsg) (uint64, error) {
	return c.client.EstimateGas(ctx, ethereum.CallMsg{
		From:  common.Address(msg.From),
		To:    (*common.Address)(&msg.To),
		Value: msg.Value,
		Data:  msg.Data,
	})
}

// ChainID implements EthRPC.
func (c *ethClient) ChainID(ctx context.Context) (*big.Int, error) {
	return c.client.ChainID(ctx)
}

// decodeHex decodes a 0x-prefixed hex string to bytes.
func decodeHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	return b, nil
}

// transactionReceiptWithRetry is the small helper (per M1.3-4) containing
// the retry logic with 500ms exp backoff. It is called by ethClient and is
// directly exercisable from tests in this package (to exercise retry/Is(NotFound)/transient/dl/legacy paths without test hooks or exported symbols). The ethClient is the only concrete impl using the retrying path.
func transactionReceiptWithRetry(ctx context.Context, hash common.Hash, fetch func(context.Context, common.Hash) (*types.Receipt, error)) (*Receipt, error) {
	const baseBackoff = 500 * time.Millisecond
	backoff := baseBackoff
	for {
		r, err := fetch(ctx, hash)
		if err == nil {
			// r is non-nil per ethclient.TransactionReceipt contract (same as pre-M1.3-4 code)
			rec := &Receipt{
				TransactionHash: r.TxHash.Hex(),
				Status:          r.Status,
				GasUsed:         r.GasUsed,
				BlockHash:       r.BlockHash.Hex(),
			}
			if r.BlockNumber != nil {
				rec.BlockNumber = r.BlockNumber.Uint64()
			}
			if r.EffectiveGasPrice != nil {
				rec.EffectiveGasPrice = "0x" + r.EffectiveGasPrice.Text(16)
			}
			return rec, nil
		}
		if errors.Is(err, ethereum.NotFound) {
			if !hasDeadline(ctx) {
				return nil, nil
			}
			// fallthrough to retry until dl
		} else if isTransient(err) {
			if !hasDeadline(ctx) {
				return nil, err
			}
			// fallthrough to retry until dl
		} else {
			return nil, err
		}
		// NotFound or transient (with dl): retry with backoff
		if ctx.Err() != nil {
			return nil, ErrReceiptTimeout
		}
		if deadlineExceeded(ctx) {
			return nil, ErrReceiptTimeout
		}
		if err := sleepCtx(ctx, backoff); err != nil {
			return nil, ErrReceiptTimeout
		}
		backoff *= 2
		if backoff > 4*time.Second {
			backoff = 4 * time.Second
		}
	}
}

func hasDeadline(ctx context.Context) bool {
	_, ok := ctx.Deadline()
	return ok
}

func deadlineExceeded(ctx context.Context) bool {
	// Prefer ctx.Err() (reliable, includes cancel + timer-delivered dl) before
	// wall-time check (supplement; races possible but fast-path before sleep).
	if ctx.Err() != nil {
		return true
	}
	if dl, ok := ctx.Deadline(); ok && time.Now().After(dl) {
		return true
	}
	return false
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func isTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return true
		}
	}
	return false
}

// compile-time assertions
var _ EthRPC = (*ethClient)(nil)
var _ EthBroadcaster = (*ethClient)(nil)
