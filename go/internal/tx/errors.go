package tx

import "errors"

var (
	// ErrZeroPubkey is returned when the pubkey is all zeros.
	ErrZeroPubkey = errors.New("pubkey is all zeros")
	// ErrZeroSignature is returned when the signature is all zeros.
	ErrZeroSignature = errors.New("signature is all zeros")
	// ErrZeroDepositRoot is returned when the deposit_data_root is all zeros.
	ErrZeroDepositRoot = errors.New("deposit_data_root is all zeros")
	// ErrZeroWithdrawal00 is the tx-layer sentinel for 0x00 all-zero WC body (DiD partner to deposit).
	ErrZeroWithdrawal00 = errors.New("withdrawal_credentials 0x00 prefix has all-zero body")
	// ErrInvalidWCPrefix is returned when withdrawal credentials prefix must be 0x00, 0x01, or 0x02.
	ErrInvalidWCPrefix = errors.New("withdrawal credentials prefix must be 0x00, 0x01, or 0x02")
	// ErrInvalidWCFormat is returned when withdrawal credentials format invalid for prefix.
	ErrInvalidWCFormat = errors.New("withdrawal credentials format invalid for prefix")
	// ErrUnconfiguredChainID is returned when network chain ID is zero.
	ErrUnconfiguredChainID = errors.New("network chain ID is zero")

	// Static-mode sentinel errors (returned when RPC == nil and a required field is missing).
	ErrMissingFeeStatic = errors.New("MaxFeePerGas required when no RPC is provided")
	// ErrMissingPriorityFeeStatic is returned when MaxPriorityFeePerGas required when no RPC is provided.
	ErrMissingPriorityFeeStatic = errors.New("MaxPriorityFeePerGas required when no RPC is provided")
	// ErrMissingNonceStatic is returned when nonce required when no RPC is provided.
	ErrMissingNonceStatic = errors.New("nonce required when no RPC is provided")
	// ErrMissingGasLimitStatic is returned when GasLimit required when no RPC is provided.
	ErrMissingGasLimitStatic = errors.New("GasLimit required when no RPC is provided")

	// RPC-mode sentinel errors.
	ErrMissingFromForNonce = errors.New("from address required to fetch nonce via RPC")
	// ErrChainIDMismatch is returned when RPC chain ID does not match configured network.
	ErrChainIDMismatch = errors.New("RPC chain ID does not match configured network")
	// ErrChainIDZero is returned when RPC chain ID is zero.
	ErrChainIDZero = errors.New("RPC chain ID is zero")

	// Network/fork binding sentinel (tx DiD partner to deposit's ValidateForNetwork; exit 2 per architecture §15).
	ErrNetworkMismatchTx = errors.New("entry network does not match target network params")

	// Broadcast sentinel errors (exit code 5).
	ErrRPCDial = errors.New("failed to dial RPC endpoint")
	// ErrBroadcastFailed is returned when broadcast failed.
	ErrBroadcastFailed = errors.New("broadcast failed")
	// ErrBroadcastChainIDMismatch is returned when signed tx chain ID does not match RPC chain ID; refusing to broadcast.
	ErrBroadcastChainIDMismatch = errors.New("signed tx chain ID does not match RPC chain ID; refusing to broadcast")
	// ErrReceiptReverted is returned when on-chain deposit reverted (status=0).
	ErrReceiptReverted = errors.New("on-chain deposit reverted (status=0)")
	// ErrReceiptTimeout is returned when receipt unavailable before deadline.
	ErrReceiptTimeout = errors.New("receipt unavailable before deadline")
	// ErrNoBaseFee is returned when RPC block has no baseFee (non-EIP-1559 block).
	ErrNoBaseFee = errors.New("RPC block has no baseFee (non-EIP-1559 block)")

	// ErrRPCURLRejected is returned (exit 2) when --rpc-url is passed to build (air-gapped only).
	// run wires the hybrid (M1.3-5); retained from M0.7-8a.
	ErrRPCURLRejected = errors.New("--rpc-url is reserved for v1; provide --nonce and fees explicitly")
)
