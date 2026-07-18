//! Wire types for the signed EIP-1559 deposit transaction, ported from
//! `go/internal/signer/types.go`.

use ethernal_tx::UnsignedTx;
use serde::{Deserialize, Serialize};

/// A signed EIP-1559 deposit transaction ready for broadcast.
/// The fields mirror `UnsignedTx` but include the signature (r, s, v) and
/// the RLP-encoded raw bytes that can be sent via `eth_sendRawTransaction`.
///
/// Field declaration order matches the Go struct so the JSON output is
/// byte-identical (`unsigned`, `from`, `hash`, `r`, `s`, `v`, `rawRLP`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTx {
    /// The original unsigned transaction this signature applies to.
    #[serde(rename = "unsigned", default)]
    pub unsigned: UnsignedTx,
    /// The recovered sender address (0x-prefixed hex), derived from the signature.
    #[serde(rename = "from", default)]
    pub from: String,
    /// The transaction hash (Keccak-256 of the signed RLP), 0x-prefixed hex.
    #[serde(rename = "hash", default)]
    pub hash: String,
    /// The signature R value, 0x-prefixed hex.
    #[serde(rename = "r", default)]
    pub r: String,
    /// The signature S value, 0x-prefixed hex.
    #[serde(rename = "s", default)]
    pub s: String,
    /// The signature V value. For EIP-1559 (type-2) transactions this is
    /// the y-parity bit encoded as a decimal string: "0" or "1".
    #[serde(rename = "v", default)]
    pub v: String,
    /// The 0x-prefixed hex RLP encoding of the signed transaction,
    /// directly usable with `eth_sendRawTransaction`.
    #[serde(rename = "rawRLP", default)]
    pub raw_rlp: String,
}
