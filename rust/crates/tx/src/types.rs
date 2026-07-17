//! Wire types for the unsigned EIP-1559 deposit transaction.

use serde::{Deserialize, Serialize};

/// The unsigned EIP-1559 deposit transaction envelope.
/// String fields that represent numeric quantities use hex strings
/// (0x-prefixed) so the JSON output is directly consumable by JSON-RPC
/// tooling and hardware wallet signing flows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedTx {
    /// The EIP-155 chain ID (numeric JSON value).
    #[serde(rename = "chainId", default)]
    pub chain_id: u64,
    /// The 0x-prefixed hex address of the deposit contract.
    #[serde(rename = "to", default)]
    pub to: String,
    /// A placeholder sender address; empty until a signer is wired.
    #[serde(rename = "from", default, skip_serializing_if = "String::is_empty")]
    pub from: String,
    /// The deposit amount in wei as a 0x-prefixed hex string.
    #[serde(rename = "value", default)]
    pub value: String,
    /// The 0x-prefixed hex calldata for the deposit() call.
    #[serde(rename = "data", default)]
    pub data: String,
    /// The EIP-1559 gas limit (numeric JSON value).
    #[serde(rename = "gas", default)]
    pub gas: u64,
    /// The EIP-1559 maximum total fee per gas in wei (hex string).
    #[serde(rename = "maxFeePerGas", default)]
    pub max_fee_per_gas: String,
    /// The EIP-1559 miner tip per gas in wei (hex string).
    #[serde(rename = "maxPriorityFeePerGas", default)]
    pub max_priority_fee_per_gas: String,
    /// The sender account nonce (numeric JSON value).
    #[serde(rename = "nonce", default)]
    pub nonce: u64,
    /// Always "0x2" for EIP-1559 transactions.
    #[serde(rename = "type", default)]
    pub tx_type: String,
}
