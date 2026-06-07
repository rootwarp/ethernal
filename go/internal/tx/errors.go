package tx

import "errors"

var (
	ErrZeroPubkey      = errors.New("pubkey is all zeros")
	ErrZeroSignature   = errors.New("signature is all zeros")
	ErrZeroDepositRoot = errors.New("deposit_data_root is all zeros")
	// ErrZeroWithdrawal00 is the tx-layer sentinel for 0x00 all-zero WC body (DiD partner to deposit).
	ErrZeroWithdrawal00    = errors.New("withdrawal_credentials 0x00 prefix has all-zero body")
	ErrInvalidWCPrefix     = errors.New("withdrawal credentials prefix must be 0x00, 0x01, or 0x02")
	ErrInvalidWCFormat     = errors.New("withdrawal credentials format invalid for prefix")
	ErrUnconfiguredChainID = errors.New("network chain ID is zero")

	// Static-mode sentinel errors (returned when RPC == nil and a required field is missing).
	ErrMissingFeeStatic         = errors.New("MaxFeePerGas required when no RPC is provided")
	ErrMissingPriorityFeeStatic = errors.New("MaxPriorityFeePerGas required when no RPC is provided")
	ErrMissingNonceStatic       = errors.New("nonce required when no RPC is provided")
	ErrMissingGasLimitStatic    = errors.New("GasLimit required when no RPC is provided")

	// RPC-mode sentinel errors.
	ErrMissingFromForNonce = errors.New("from address required to fetch nonce via RPC")
	ErrChainIDMismatch     = errors.New("RPC chain ID does not match configured network")

	// Network/fork binding sentinel (tx DiD partner to deposit's ValidateForNetwork; exit 2 per architecture §15).
	ErrNetworkMismatchTx = errors.New("entry network does not match target network params")

	// Broadcast sentinel errors (exit code 5).
	ErrRPCDial                  = errors.New("failed to dial RPC endpoint")
	ErrBroadcastFailed          = errors.New("broadcast failed")
	ErrBroadcastChainIDMismatch = errors.New("signed tx chain ID does not match RPC chain ID; refusing to broadcast")
	ErrReceiptReverted          = errors.New("on-chain deposit reverted (status=0)")
	ErrReceiptTimeout           = errors.New("receipt unavailable before deadline")
)
