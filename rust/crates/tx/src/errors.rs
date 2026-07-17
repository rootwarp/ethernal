//! The error taxonomy of the tx crate. Every Go sentinel from
//! `internal/tx/errors.go` (plus the builder-local ones) is a dedicated
//! variant so the exit-code map in the bin can distinguish them:
//!   - user/config errors → exit 2
//!   - broadcast/RPC errors → exit 5
//!   - cancellation → exit 4

/// A boxed error source used where Go wraps an arbitrary underlying error.
pub type Source = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, thiserror::Error)]
pub enum TxError {
    // --- Entry / config validation (exit 2) ---
    /// The deposit entry amount is not exactly 32 ETH (32_000_000_000 Gwei).
    /// Only the 32 ETH first-deposit case is supported.
    #[error("deposit amount must be exactly 32_000_000_000 Gwei (32 ETH): got {0}")]
    InvalidAmount(u64),

    #[error("pubkey is all zeros")]
    ZeroPubkey,

    #[error("signature is all zeros")]
    ZeroSignature,

    #[error("deposit_data_root is all zeros")]
    ZeroDepositRoot,

    #[error("withdrawal credentials prefix must be 0x00, 0x01, or 0x02: got 0x{0:02x}")]
    InvalidWcPrefix(u8),

    #[error("withdrawal credentials format invalid for prefix: prefix 0x{0:02x} requires bytes 1–11 to be zero")]
    InvalidWcFormat(u8),

    #[error("network chain ID is zero")]
    UnconfiguredChainId,

    // --- Static-mode sentinels (RPC == None and a required field missing; exit 2) ---
    #[error("MaxFeePerGas required when no RPC is provided")]
    MissingFeeStatic,

    #[error("MaxPriorityFeePerGas required when no RPC is provided")]
    MissingPriorityFeeStatic,

    #[error("nonce required when no RPC is provided")]
    MissingNonceStatic,

    #[error("GasLimit required when no RPC is provided")]
    MissingGasLimitStatic,

    // --- RPC-mode sentinels ---
    /// From address required to fetch nonce via RPC (exit 2).
    #[error("from address required to fetch nonce via RPC")]
    MissingFromForNonce,

    /// Build-side chain-ID mismatch between RPC and configured network (exit 2).
    #[error("RPC chain ID does not match configured network: RPC={rpc} configured={configured}")]
    ChainIdMismatch { rpc: u64, configured: u64 },

    // --- Broadcast / RPC errors (exit 5) ---
    /// Failed to dial the RPC endpoint. `url` is ALWAYS the safe form
    /// (scheme://host) — never the raw URL.
    #[error("failed to dial RPC endpoint: {url}: {source}")]
    RpcDial { url: String, source: Source },

    /// A gas/fee/nonce estimation CALL failed in RPC mode
    /// (SuggestGasTipCap / BlockBaseFee / PendingNonceAt / EstimateGas).
    /// Distinct from `RpcDial` (connection) and `ChainIdMismatch` (config).
    #[error("RPC estimation call failed: {call}: {source}")]
    RpcEstimation { call: &'static str, source: Source },

    /// eth_sendRawTransaction (or a pre-broadcast step) failed.
    #[error("broadcast failed: {0}")]
    BroadcastFailed(Source),

    /// Signed tx chain ID does not match the RPC node's chain ID.
    #[error("signed tx chain ID does not match RPC chain ID; refusing to broadcast: signed tx has chain ID {signed} but RPC reports {rpc}")]
    BroadcastChainIdMismatch { signed: u64, rpc: u64 },

    // --- Cancellation (exit 4) ---
    /// The operation was cancelled (SIGINT) between units of work.
    #[error("operation cancelled")]
    Cancelled,
}
