//! The error taxonomy of the signer crate, ported from
//! `go/internal/signer/errors.go`.
//!
//! Every Go sentinel (`errors.New`) is a dedicated variant with the Go
//! message text verbatim. Go's wrapped forms — `fmt.Errorf("msg: %w",
//! sentinel)` — are modeled with [`SignerError::Context`], whose `Display`
//! renders `"msg: <inner>"` exactly like Go's `%w` chain. Plain
//! `fmt.Errorf` messages that do not wrap a sentinel become
//! [`SignerError::Msg`].
//!
//! Exit-code classification (the Rust analogue of Go `errors.Is`) must look
//! *through* the context chain: call [`SignerError::sentinel`] and match the
//! returned reference, e.g.
//! `matches!(err.sentinel(), SignerError::InvalidKey)`.

/// Errors produced by the `signer` crate. All map to exit code 3
/// (signer/crypto) except [`SignerError::Cancelled`] (exit 4).
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// Go: `ErrUserRejected` — the user rejected the signing request on a
    /// hardware device. Exit code 3 (signer/crypto error) — but distinct
    /// semantically from a true crypto failure.
    #[error("user rejected signing on device")]
    UserRejected,

    /// Go: `ErrNoDevice` — no Ledger device was found.
    #[error("no Ledger device found")]
    NoDevice,

    /// Go: `ErrAppNotOpen` — a Ledger is connected but the Ethereum app is
    /// not open.
    #[error("ledger Ethereum app is not open")]
    AppNotOpen,

    /// Go: `ErrInvalidKey` — the private key bytes are not a valid secp256k1
    /// scalar. Generic to keep key material out of error text.
    #[error("invalid private key")]
    InvalidKey,

    /// Go: `ErrChainIDMismatch` — the signer cannot produce a signature for
    /// the requested chain ID (e.g., Ledger refuses an unknown network).
    #[error("chain ID mismatch")]
    ChainIdMismatch,

    /// Go: `ErrInvalidChainID` — the unsigned transaction has chain ID 0 or
    /// another value the signer cannot handle (distinct from
    /// [`SignerError::ChainIdMismatch`], which is a mismatch between two
    /// otherwise-valid IDs).
    #[error("invalid chain ID")]
    InvalidChainId,

    /// Go: `ErrSignerClosed` — sign was called after close.
    #[error("signer is closed")]
    SignerClosed,

    /// Go: `ErrLedgerNotSupported` — the binary was built without the real
    /// HID transport.
    ///
    /// Divergence: the Go message references CGO (`"ledger support requires
    /// CGO_ENABLED=1; rebuild with cgo enabled"`); the Rust build gates the
    /// transport behind the `ledger` cargo feature instead, so the message
    /// is adapted accordingly.
    #[error("ledger support requires the 'ledger' cargo feature; rebuild with --features ledger")]
    LedgerNotSupported,

    /// The operation was cancelled between units of work. Replaces Go's
    /// `context.Canceled`; maps to the user-abort exit code (4).
    #[error("operation cancelled")]
    Cancelled,

    /// A plain error message with no sentinel underneath (Go `fmt.Errorf`
    /// without `%w`, or a wrapped foreign error rendered into the text).
    #[error("{0}")]
    Msg(String),

    /// Go `fmt.Errorf("<msg>: %w", source)` — a context prefix around
    /// another `SignerError`. `Display` renders `"msg: source"`, matching
    /// Go's wrapped-error chain, and [`SignerError::sentinel`] recurses
    /// through it.
    #[error("{msg}: {source}")]
    Context {
        msg: String,
        source: Box<SignerError>,
    },
}

impl SignerError {
    /// Wraps `source` with a Go-style `"msg: ..."` context prefix.
    pub(crate) fn context(msg: impl Into<String>, source: SignerError) -> Self {
        SignerError::Context {
            msg: msg.into(),
            source: Box::new(source),
        }
    }

    /// Returns the innermost error of a [`SignerError::Context`] chain — the
    /// Rust analogue of walking Go's `errors.Is` unwrap chain. For any
    /// non-context variant this returns `self`, so callers can always write
    /// `matches!(err.sentinel(), SignerError::UserRejected)`.
    pub fn sentinel(&self) -> &SignerError {
        match self {
            SignerError::Context { source, .. } => source.sentinel(),
            other => other,
        }
    }
}
