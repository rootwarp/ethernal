//! Unsigned EIP-1559 deposit transaction building, deposit() ABI packing,
//! validation, RPC-URL redaction, and a minimal JSON-RPC client.
//! Ported from `go/internal/tx` (issues R3-1 / R3-2).

pub mod abi;
pub mod builder;
pub mod errors;
pub mod redact;
pub mod rpc_client;
pub mod types;
pub mod validation;

#[cfg(test)]
mod test_helpers;

pub use abi::pack_deposit;
pub use builder::{BuildConfig, Builder, CallMsg, EthRpc};
pub use errors::TxError;
pub use redact::{redact_url_in, safe_url};
pub use rpc_client::{EthBroadcaster, EthClient, Receipt, RpcClientError};
pub use types::UnsignedTx;
pub use validation::validate;
