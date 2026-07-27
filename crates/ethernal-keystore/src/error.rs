//! Typed sentinel errors for keystore loading, decryption, directory scanning,
//! and passphrase sourcing.
//!
//! Ported from the `var ( ... errors.New ... )` blocks in
//! `go/internal/keystore/{keystore.go,scandir.go}`. Every Go sentinel becomes a
//! dedicated variant; call sites that used `errors.Is` become `matches!` on the
//! variant. The `Display` messages reproduce Go's wrapped (`%w`) rendering
//! verbatim, since operators grep these strings and the exit-code map (R4-3)
//! distinguishes the variants.

use std::io;

use ethernal_secretfile::SecretFileError;

/// Errors returned by keystore loading, decryption, scanning, and passphrase
/// sourcing. Not `PartialEq`/`Clone`: the [`KeystoreError::ReadFile`] and
/// [`KeystoreError::ReadPassphrase`] variants wrap an [`io::Error`], which is
/// neither. Tests distinguish variants with `matches!`.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// The keystore file does not exist. Go: `ErrKeystoreMissing`.
    #[error("keystore file not found: {path}")]
    KeystoreMissing {
        /// The path that was requested.
        path: String,
    },

    /// The keystore file cannot be parsed as valid EIP-2335 JSON, or its
    /// `crypto` object is missing or structurally invalid. Go:
    /// `ErrKeystoreMalformed`.
    #[error("keystore JSON malformed: {path}: {detail}")]
    KeystoreMalformed {
        /// The offending file path.
        path: String,
        /// A human-readable description of what was wrong.
        detail: String,
    },

    /// The `version` field is not 4. Go: `ErrKeystoreVersion`.
    #[error("keystore version must be 4: {path}: got {got}")]
    KeystoreVersion {
        /// The offending file path.
        path: String,
        /// The version that was actually found.
        got: i64,
    },

    /// Decryption failed due to an incorrect passphrase (checksum mismatch).
    /// Go: `ErrWrongPassphrase`.
    #[error("wrong passphrase: {detail}")]
    WrongPassphrase {
        /// The underlying cause; a stable `"invalid checksum"` for the
        /// checksum-mismatch case, matching the wealdtech encryptor's text.
        detail: String,
    },

    /// The named environment variable is unset or empty. Maps to exit code 2.
    /// Go: `ErrEnvVarEmpty`.
    #[error("passphrase environment variable is unset or empty: {var}")]
    EnvVarEmpty {
        /// The environment variable name that was consulted.
        var: String,
    },

    /// The passphrase file could not be read, or violates the file policy:
    /// not found, permission denied, a directory, over-size, a residual `\r`
    /// or `\n`, or not UTF-8. Never carries file contents. Exit code 2.
    #[error("passphrase file: {0}")]
    PassphraseFile(#[from] SecretFileError),

    /// `--passphrase-file` named an empty file (0 bytes, or a lone newline).
    /// Mirrors [`KeystoreError::EnvVarEmpty`], the source it replaces. Exit 2.
    #[error("passphrase file is empty: {path}")]
    PassphraseFileEmpty {
        /// The path that was requested.
        path: String,
    },

    /// An interactive passphrase prompt was needed but no controlling terminal
    /// is available (piped/non-interactive use). Maps to exit code 2. Go:
    /// `ErrNoTTY`.
    #[error(
        "no controlling terminal for passphrase prompt: cannot open /dev/tty ({detail}); \
         for non-interactive or piped use, supply the passphrase via --passphrase-file PATH"
    )]
    NoTty {
        /// The underlying open failure, surfaced for diagnostics.
        detail: String,
    },

    /// A pubkey's keystore could not be found in a [`crate::DirectoryIndex`].
    /// Callers wrap this with pubkey+dir context. Maps to exit code 2. Go:
    /// `ErrKeystoreNotFound`.
    #[error("keystore not found for pubkey")]
    KeystoreNotFound,

    /// The keystore file exists but could not be read (e.g. permission denied).
    /// Distinct from [`KeystoreError::KeystoreMissing`]. Go:
    /// `fmt.Errorf("read keystore %s: %w", path, err)`.
    #[error("read keystore {path}: {source}")]
    ReadFile {
        /// The path that could not be read.
        path: String,
        /// The underlying I/O error.
        source: io::Error,
    },

    /// Reading the passphrase from the terminal failed after the TTY was opened.
    /// Go: `fmt.Errorf("read passphrase: %w", err)` (not a Go sentinel).
    #[error("read passphrase: {source}")]
    ReadPassphrase {
        /// The underlying I/O error.
        source: io::Error,
    },

    /// A [`crate::PassphraseSource`] returned an error while sourcing the
    /// passphrase. Go: `fmt.Errorf("passphrase source: %w", err)`.
    #[error("passphrase source: {0}")]
    PassphraseSource(Box<KeystoreError>),

    /// The two interactive passphrase entries did not match (keygen create path).
    /// Maps to exit code 2.
    #[error("passphrases do not match")]
    PassphraseMismatch,

    /// The passphrase is shorter than the required minimum length (keygen create
    /// path; F-7). Length is measured after EIP-2335 normalization (NFKD + strip
    /// controls), as UTF-8 byte length. Maps to exit code 2.
    #[error("passphrase must be at least {min} bytes (got {got})")]
    PassphraseTooShort {
        /// The required minimum length (UTF-8 bytes after EIP-2335 normalize).
        min: usize,
        /// The normalized UTF-8 byte length that was actually supplied.
        got: usize,
    },

    /// EIP-2335 keystore encryption failed (KDF, cipher, or serialization).
    /// Maps to exit code 3 at the bin layer (K3-4).
    #[error("encrypt keystore: {detail}")]
    Encrypt {
        /// A human-readable description of what failed.
        detail: String,
    },
}
