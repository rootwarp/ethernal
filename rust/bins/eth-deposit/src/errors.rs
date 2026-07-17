//! Exit code conventions for eth-deposit (port of `cmd/eth-deposit/exit.go`):
//!
//!   0 — success
//!   2 — user / configuration errors (bad input, validation, unknown network,
//!       missing/malformed file, invalid hex, out-of-bounds --index, negative
//!       fees, build-side RPC chain-ID mismatch)
//!   3 — signer / crypto errors (bad key, no Ledger device, Ethereum app not
//!       open, signer-side chain ID mismatch, signer closed)
//!   4 — user abort (SIGINT / cancellation / Ledger device rejection)
//!   5 — broadcast / RPC errors (dial failure, gas/nonce estimation failure,
//!       eth_sendRawTransaction error, broadcast-side chain ID mismatch)
//!   1 — fallback for any other error

use std::fmt;

use eth_deposit_core::bls::BlsError;
use eth_deposit_core::deposit::DepositError;
use eth_deposit_core::network::NetworkError;
use eth_deposit_core::output::OutputError;
use eth_deposit_keystore::KeystoreError;
use eth_deposit_tx::TxError;

/// The bin-level error type. Every command action returns this; `main` maps
/// it to an exit code via [`exit_code_for`] and logs the Display rendering.
#[derive(Debug)]
pub enum AppError {
    /// A usage/validation error with an explicit exit code — the port of
    /// `ucli.Exit(msg, code)`.
    Exit { msg: String, code: i32 },

    /// A low-level error wrapped as a user/config error — the port of
    /// `WrapInputErr(what, err)`; renders "{what}: invalid input: {source}"
    /// and maps to exit code 2.
    Input { what: String, source: Box<AppError> },

    /// SIGINT / cancellation — the port of `context.Canceled` +
    /// `ErrUserAborted`. Exit code 4.
    Aborted(String),

    Keystore(KeystoreError),
    Deposit(DepositError),
    Network(NetworkError),
    Output(OutputError),
    Tx(TxError),

    /// A BLS operation failed outside the deposit pipeline (e.g. signer
    /// construction from a decrypted secret). Go leaves these unclassified —
    /// fallback exit code 1.
    Bls(BlsError),

    /// gen: no keystore matched a requested pubkey. Wraps
    /// `KeystoreError::KeystoreNotFound` with pubkey + dir context, mirroring
    /// gen.go's message. Exit code 2.
    KeystoreNotFoundFor { pubkey_hex: String, dir: String },

    /// gen: BLS library initialisation failed (vestigial with blst, kept for
    /// parity). Exit code 3.
    BlsInit(String),

    /// gen: mainnet without the explicit acknowledgement flag (defense in
    /// depth inside the pipeline; the CLI gate fires first). Exit code 2.
    MainnetAckRequired,

    /// gen: --verify-with-deposit-cli binary not found in PATH. Exit code 2.
    DepositCliNotFound { cli_path: String, detail: String },

    /// gen: the external staking-deposit-cli exited non-zero. Exit code 3.
    DepositCliFailed { output: String },

    /// A context-message wrapper that preserves the source's classification
    /// (the port of `fmt.Errorf("...: %w", err)`).
    Context { msg: String, source: Box<AppError> },

    /// Fallback internal error. Exit code 1.
    Internal(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Exit { msg, .. } => f.write_str(msg),
            AppError::Input { what, source } => {
                write!(f, "{what}: invalid input: {source}")
            }
            AppError::Aborted(detail) if detail.is_empty() => f.write_str("user aborted"),
            AppError::Aborted(detail) => write!(f, "user aborted: {detail}"),
            AppError::Keystore(e) => e.fmt(f),
            AppError::Deposit(e) => e.fmt(f),
            AppError::Network(e) => e.fmt(f),
            AppError::Output(e) => e.fmt(f),
            AppError::Tx(e) => e.fmt(f),
            AppError::Bls(e) => e.fmt(f),
            AppError::KeystoreNotFoundFor { pubkey_hex, dir } => write!(
                f,
                "no keystore found for pubkey 0x{pubkey_hex} in {dir}: keystore not found for pubkey"
            ),
            AppError::BlsInit(detail) => write!(f, "bls init failed: {detail}"),
            AppError::MainnetAckRequired => f.write_str(
                "mainnet requires explicit acknowledgement (set Config.MainnetAck = true)",
            ),
            AppError::DepositCliNotFound { cli_path, detail } => write!(
                f,
                "deposit CLI binary not found: \"{cli_path}\" not found in PATH: {detail}"
            ),
            AppError::DepositCliFailed { output } => {
                write!(f, "deposit CLI verification failed: {output}")
            }
            AppError::Context { msg, source } => write!(f, "{msg}: {source}"),
            AppError::Internal(msg) => f.write_str(msg),
        }
    }
}

impl From<KeystoreError> for AppError {
    fn from(e: KeystoreError) -> Self {
        AppError::Keystore(e)
    }
}
impl From<DepositError> for AppError {
    fn from(e: DepositError) -> Self {
        AppError::Deposit(e)
    }
}
impl From<NetworkError> for AppError {
    fn from(e: NetworkError) -> Self {
        AppError::Network(e)
    }
}
impl From<OutputError> for AppError {
    fn from(e: OutputError) -> Self {
        AppError::Output(e)
    }
}
impl From<TxError> for AppError {
    fn from(e: TxError) -> Self {
        AppError::Tx(e)
    }
}

impl AppError {
    /// The port of `ucli.Exit(msg, 2)`.
    pub fn exit2(msg: impl Into<String>) -> Self {
        AppError::Exit {
            msg: msg.into(),
            code: 2,
        }
    }

    /// The port of `WrapInputErr`.
    pub fn input(what: impl Into<String>, source: AppError) -> Self {
        AppError::Input {
            what: what.into(),
            source: Box::new(source),
        }
    }

    /// The port of `fmt.Errorf("{msg}: %w", source)` — adds context while
    /// preserving classification.
    pub fn context(msg: impl Into<String>, source: AppError) -> Self {
        AppError::Context {
            msg: msg.into(),
            source: Box::new(source),
        }
    }

    /// Walks context wrappers down to the classified error.
    fn unwrap_context(&self) -> &AppError {
        match self {
            AppError::Context { source, .. } => source.unwrap_context(),
            other => other,
        }
    }
}

/// Maps `err` to an exit code per the eth-deposit convention. The match arms
/// preserve the ORDER of checks in Go's `ExitCodeFor` — in particular the
/// user-abort check precedes the RPC block, so a SIGINT that surfaces through
/// an estimation call is classified as an abort (4), not an RPC failure (5).
pub fn exit_code_for(err: &AppError) -> i32 {
    match err.unwrap_context() {
        // Exit code 4: cancellation (SIGINT) or explicit abort — checked first.
        AppError::Aborted(_) => 4,
        AppError::Deposit(DepositError::Cancelled) => 4,
        AppError::Tx(TxError::Cancelled) => 4,

        // Explicit usage/validation exits carry their own code.
        AppError::Exit { code, .. } => *code,

        // Exit code 2: user / configuration errors (the WrapInputErr class).
        AppError::Input { .. } => 2,

        // Exit code 2: build-side RPC configuration errors (tx).
        AppError::Tx(TxError::ChainIdMismatch { .. }) => 2,
        AppError::Tx(TxError::MissingFromForNonce) => 2,

        // Exit code 2: user / configuration errors (gen).
        AppError::Keystore(e) => match e {
            KeystoreError::WrongPassphrase { .. } => 3,
            _ => 2,
        },
        AppError::KeystoreNotFoundFor { .. } => 2,
        AppError::Deposit(DepositError::PubkeyMismatch { .. }) => 2,
        AppError::MainnetAckRequired => 2,
        AppError::DepositCliNotFound { .. } => 2,
        AppError::Network(_) => 2,

        // Exit code 3: crypto / signer errors and external verification
        // failures (gen).
        AppError::Deposit(DepositError::SelfVerifyFailed { .. }) => 3,
        AppError::BlsInit(_) => 3,
        AppError::DepositCliFailed { .. } => 3,

        // Exit code 5: broadcast / RPC errors (tx).
        AppError::Tx(
            TxError::RpcDial { .. }
            | TxError::RpcEstimation { .. }
            | TxError::BroadcastFailed(_)
            | TxError::BroadcastChainIdMismatch { .. },
        ) => 5,

        // Remaining deposit/tx validation errors reach here only unwrapped
        // (Go wraps them via WrapInputErr at the call sites) — fallback.
        _ => 1,
    }
}
