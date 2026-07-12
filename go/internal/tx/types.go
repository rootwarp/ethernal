package tx

// UnsignedTx is the unsigned EIP-1559 deposit transaction envelope.
// String fields that represent numeric quantities use hex strings (0x-prefixed)
// so the JSON output is directly consumable by JSON-RPC tooling and hardware
// wallet signing flows.
type UnsignedTx struct {
	// ChainID is the EIP-155 chain ID (numeric JSON value).
	ChainID uint64 `json:"chainId"`
	// To is the 0x-prefixed hex address of the deposit contract.
	To string `json:"to"`
	// From is a placeholder sender address; empty until a signer is wired.
	From string `json:"from,omitempty"`
	// Value is the deposit amount in wei as a 0x-prefixed hex string.
	Value string `json:"value"`
	// Data is the 0x-prefixed hex calldata for the deposit() call.
	Data string `json:"data"`
	// Gas is the EIP-1559 gas limit (numeric JSON value).
	Gas uint64 `json:"gas"`
	// MaxFeePerGas is the EIP-1559 maximum total fee per gas in wei (hex string).
	MaxFeePerGas string `json:"maxFeePerGas"`
	// MaxPriorityFeePerGas is the EIP-1559 miner tip per gas in wei (hex string).
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
	// Nonce is the sender account nonce (numeric JSON value).
	Nonce uint64 `json:"nonce"`
	// Type is always "0x2" for EIP-1559 transactions.
	Type string `json:"type"`
}
