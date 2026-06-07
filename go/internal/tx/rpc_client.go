package tx

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// EthBroadcaster broadcasts a signed transaction via JSON-RPC.
type EthBroadcaster interface {
	// SendRawTransaction decodes the 0x-prefixed RLP hex and submits it via
	// eth_sendRawTransaction. Returns the tx hash as a 0x-prefixed hex string.
	SendRawTransaction(ctx context.Context, rawRLP string) (string, error)
	// TransactionReceipt polls once for the receipt of the given tx hash.
	// Returns nil, nil if the tx is not yet mined.
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
// Returns an error wrapping ErrRPCDial on connection failure.
func NewEthClient(ctx context.Context, rpcURL string) (*ethClient, error) {
	c, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrRPCDial, rpcURL, err)
	}
	return &ethClient{client: c}, nil
}

// --- EthBroadcaster ---

func (c *ethClient) SendRawTransaction(ctx context.Context, rawRLP string) (string, error) {
	rawBytes, err := decodeHex(rawRLP)
	if err != nil {
		return "", fmt.Errorf("%w: decode rawRLP: %v", ErrBroadcastFailed, err)
	}

	// UnmarshalBinary handles the EIP-2718 typed envelope (0x02 || rlp(...))
	// produced by types.Transaction.MarshalBinary. rlp.DecodeBytes cannot be
	// used here — it would reject the leading type byte.
	var tx types.Transaction
	if err := tx.UnmarshalBinary(rawBytes); err != nil {
		return "", fmt.Errorf("%w: decode EIP-2718: %v", ErrBroadcastFailed, err)
	}

	if err := c.client.SendTransaction(ctx, &tx); err != nil {
		return "", fmt.Errorf("%w: %v", ErrBroadcastFailed, err)
	}
	return tx.Hash().Hex(), nil
}

func (c *ethClient) TransactionReceipt(ctx context.Context, txHash string) (*Receipt, error) {
	hash := common.HexToHash(txHash)
	r, err := c.client.TransactionReceipt(ctx, hash)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, err
	}
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

func (c *ethClient) BroadcasterChainID(ctx context.Context) (uint64, error) {
	id, err := c.client.ChainID(ctx)
	if err != nil {
		return 0, err
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

// compile-time assertions
var _ EthRPC = (*ethClient)(nil)
var _ EthBroadcaster = (*ethClient)(nil)
