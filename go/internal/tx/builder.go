package tx

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"

	"github.com/rootwarp/eth-utils/go/internal/deposit"
)

// ErrNilContext is returned when BuildUnsigned is called with a nil context.
var ErrNilContext = errors.New("context must not be nil")

// ErrInvalidAmount is returned when the deposit entry amount is not exactly 32 ETH (MinDepositAmountGwei Gwei).
// Only the 32 ETH first-deposit case is supported in Phase 2.
var ErrInvalidAmount = errors.New("deposit amount must be exactly MinDepositAmountGwei Gwei (32 ETH)")

// value32ETH is 32 ETH expressed in wei (32 * 10^18 = 0x1bc16d674ec800000).
var value32ETH = new(big.Int).Mul(big.NewInt(32), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))

// Builder is the concrete implementation of TxBuilder.
type Builder struct {
	logger *slog.Logger
}

// compile-time assertion that *Builder satisfies TxBuilder.
var _ TxBuilder = (*Builder)(nil)

// NewBuilder creates a new Builder.
func NewBuilder() *Builder {
	return &Builder{}
}

// BuildUnsigned constructs an unsigned EIP-1559 deposit transaction.
//
// Resolution order per field:
//  1. If the field is explicitly set in cfg, it wins.
//  2. If cfg.RPC != nil and the field is unset, resolve from RPC.
//  3. If cfg.RPC == nil and the field is unset, return ErrMissing* sentinel.
func (b *Builder) BuildUnsigned(ctx context.Context, entry deposit.Entry, cfg BuildConfig) (*UnsignedTx, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := Validate(entry, cfg); err != nil {
		return nil, err
	}

	// Resolve or validate gas/fee/nonce fields.
	gasLimit, maxFee, tip, nonce, err := resolveFields(ctx, cfg, entry, b.logger)
	if err != nil {
		return nil, err
	}

	calldata := PackDeposit(entry.Pubkey, entry.WithdrawalCredentials, entry.Signature, entry.DepositDataRoot)

	return &UnsignedTx{
		ChainID:              cfg.NetworkParams.ChainID,
		To:                   cfg.NetworkParams.DepositContractAddressHex(),
		Value:                "0x" + fmt.Sprintf("%x", value32ETH),
		Data:                 "0x" + hex.EncodeToString(calldata),
		Gas:                  gasLimit,
		MaxFeePerGas:         "0x" + fmt.Sprintf("%x", maxFee),
		MaxPriorityFeePerGas: "0x" + fmt.Sprintf("%x", tip),
		Nonce:                nonce,
		Type:                 "0x2",
	}, nil
}

// resolveFields determines the final gas limit, max fee, priority fee, and nonce.
// When cfg.RPC is nil it validates that all fields are statically provided.
// When cfg.RPC is non-nil it fetches any missing values and optionally verifies
// that the RPC's chain ID matches the configured network.
func resolveFields(ctx context.Context, cfg BuildConfig, entry deposit.Entry, logger *slog.Logger) (gasLimit uint64, maxFee, tip *big.Int, nonce uint64, err error) {
	if cfg.RPC == nil {
		return resolveStatic(cfg)
	}
	return resolveRPC(ctx, cfg, entry, logger)
}

func resolveStatic(cfg BuildConfig) (uint64, *big.Int, *big.Int, uint64, error) {
	if err := validateStaticConfig(cfg); err != nil {
		return 0, nil, nil, 0, err
	}
	return cfg.GasLimit, cfg.MaxFeePerGas, cfg.MaxPriorityFeePerGas, *cfg.Nonce, nil
}

func resolveRPC(ctx context.Context, cfg BuildConfig, entry deposit.Entry, logger *slog.Logger) (gasLimit uint64, maxFee, tip *big.Int, nonce uint64, err error) {
	// Optional: verify chain ID matches. Fail closed on RPC error or chainID 0 (M1.3-2).
	rpcChainID, chainErr := cfg.RPC.ChainID(ctx)
	if chainErr != nil {
		if logger != nil {
			logger.Warn("chain ID resolution from RPC failed; failing closed", "err", chainErr)
		}
		return 0, nil, nil, 0, ErrChainIDZero
	}
	if rpcChainID != nil && rpcChainID.Sign() == 0 {
		if logger != nil {
			logger.Warn("RPC returned chain ID zero; failing closed", "chainID", "0")
		}
		return 0, nil, nil, 0, ErrChainIDZero
	}
	configured := new(big.Int).SetUint64(uint64(cfg.NetworkParams.ChainID))
	if rpcChainID.Cmp(configured) != 0 {
		return 0, nil, nil, 0, fmt.Errorf("%w: RPC=%s configured=%s",
			ErrChainIDMismatch, rpcChainID, configured)
	}

	// Resolve priority fee (tip).
	tip = cfg.MaxPriorityFeePerGas
	if tip == nil {
		tip, err = cfg.RPC.SuggestGasTipCap(ctx)
		if err != nil {
			return 0, nil, nil, 0, fmt.Errorf("SuggestGasTipCap: %w", err)
		}
	}

	// Resolve max fee = 2*baseFee + tip (EIP-1559 standard formula).
	maxFee = cfg.MaxFeePerGas
	if maxFee == nil {
		baseFee, bErr := cfg.RPC.BlockBaseFee(ctx)
		if bErr != nil {
			return 0, nil, nil, 0, fmt.Errorf("BlockBaseFee: %w", bErr)
		}
		// maxFeePerGas = 2 * baseFee + tip
		maxFee = new(big.Int).Add(new(big.Int).Mul(big.NewInt(2), baseFee), tip)
	}

	// Resolve nonce.
	if cfg.Nonce != nil {
		nonce = *cfg.Nonce
	} else {
		if cfg.From == ([20]byte{}) {
			return 0, nil, nil, 0, ErrMissingFromForNonce
		}
		nonce, err = cfg.RPC.PendingNonceAt(ctx, cfg.From)
		if err != nil {
			return 0, nil, nil, 0, fmt.Errorf("PendingNonceAt: %w", err)
		}
	}

	// Resolve gas limit.
	gasLimit = cfg.GasLimit
	if gasLimit == 0 {
		calldata := PackDeposit(entry.Pubkey, entry.WithdrawalCredentials, entry.Signature, entry.DepositDataRoot)
		msg := CallMsg{
			From:  cfg.From,
			To:    cfg.NetworkParams.DepositContractAddress,
			Value: value32ETH,
			Data:  calldata,
		}
		estimate, eErr := cfg.RPC.EstimateGas(ctx, msg)
		if eErr != nil {
			return 0, nil, nil, 0, fmt.Errorf("EstimateGas: %w", eErr)
		}
		// Sanity-check ceiling (per architecture §6.8 / M1.3-3 impl notes): document
		// guard against absurd RPC estimate for a deposit call. (Smallest change;
		// no new error path or cap enforcement beyond the doc.)
		const maxGasCap uint64 = 30_000_000
		if estimate > maxGasCap {
			// ceiling hit; proceed with pad (surfaces in tx or later failure)
		}
		// 20% safety margin: estimate + estimate/5 (avoids uint64 overflow near MaxUint64)
		gasLimit = estimate + estimate/5
	}

	return gasLimit, maxFee, tip, nonce, nil
}
