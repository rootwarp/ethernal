//! Unsigned EIP-1559 deposit transaction building, deposit() ABI packing,
//! validation, RPC-URL redaction, and a minimal JSON-RPC client.
//! Ported from `go/internal/tx` (issues R3-1 / R3-2).

pub mod errors;
pub mod types;

pub use errors::TxError;
pub use types::UnsignedTx;
