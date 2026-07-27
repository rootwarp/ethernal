//! Shared keystore-CLI helpers used by both the `validator` and `account` namespaces.
//!
//! Neutral home for flags, validation, the three-form BIP-39 mnemonic
//! passphrase input, and the write-once-retry keystore write skeleton so
//! neither namespace owns the other's helpers.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgMatches};
use ethernal_core::output::{write_new_0600, OutputError};
use ethernal_keystore::{KeystoreError, PassphraseSource};
use zeroize::Zeroizing;

use crate::errors::AppError;
use crate::fs_util::{self, stdin_is_tty, stdout_is_tty};

/// Shared overflow message for `--start-index + --count` range checks.
pub(crate) const START_INDEX_OVERFLOW_MSG: &str = "--start-index + --count overflows u32";

/// The three-form BIP-39 mnemonic passphrase input (F-12 / architecture design
/// note (c)). Distinct from the keystore passphrase (`--passphrase-file`).
///
/// The forms are mutually exclusive at the clap layer (`conflicts_with`); only
/// one is active per invocation. Absent both flags → [`Empty`].
///
/// Secret payloads (`Raw` / `File::value`) are wrapped in [`Zeroizing`] on read
/// (S-1 / design note (c)). [`Debug`] redacts those fields (S-2).
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum MnemonicPassphraseForm {
    /// Neither flag supplied — empty mnemonic passphrase (default).
    Empty,
    /// `--mnemonic-passphrase VALUE` raw argv value.
    Raw(Zeroizing<String>),
    /// `--mnemonic-passphrase-file PATH` resolved to the file's current value
    /// (empty string is accepted — FR-18; unreadable is rejected at load time).
    File {
        path: String,
        value: Zeroizing<String>,
    },
    /// Bare `--mnemonic-passphrase` (no value) — interactive prompt at runtime.
    Prompt,
}

impl fmt::Debug for MnemonicPassphraseForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("Empty"),
            Self::Raw(_) => f.write_str("Raw([REDACTED])"),
            Self::File { path, .. } => f
                .debug_struct("File")
                .field("path", path)
                .field("value", &"[REDACTED]")
                .finish(),
            Self::Prompt => f.write_str("Prompt"),
        }
    }
}

/// Flags shared by validator/account new and recover.
pub(crate) fn shared_args() -> Vec<Arg> {
    vec![
        Arg::new("count")
            .long("count")
            .value_name("N")
            .value_parser(clap::value_parser!(u32))
            .default_value("1")
            .help("Number of validator keys to produce (default 1)"),
        Arg::new("output-dir")
            .long("output-dir")
            .value_name("DIR")
            .required(true)
            .help("Existing, writable directory for the generated keystore JSON files"),
        Arg::new("passphrase-file")
            .long("passphrase-file")
            .value_name("PATH")
            .help(
                "Path to a file holding the keystore passphrase (omit for TTY prompt-with-confirm)",
            ),
        // Four-form mnemonic passphrase (architecture design note (c) / FR-3):
        //   --mnemonic-passphrase VALUE  → raw
        //   --mnemonic-passphrase        → prompt (num_args 0)
        //   --mnemonic-passphrase-file PATH → file
        //   absent                       → empty
        Arg::new("mnemonic-passphrase")
            .long("mnemonic-passphrase")
            .value_name("VALUE")
            .num_args(0..=1)
            .conflicts_with("mnemonic-passphrase-file")
            .help(
                "BIP-39 mnemonic passphrase (\"25th word\"). Provide VALUE for a raw value; \
                 pass the flag bare to prompt interactively; omit for empty (default). \
                 Raw VALUE is visible in the process table — prefer file or prompt for \
                 high-value mnemonics",
            ),
        Arg::new("mnemonic-passphrase-file")
            .long("mnemonic-passphrase-file")
            .value_name("PATH")
            .conflicts_with("mnemonic-passphrase")
            .help(
                "Path to a file holding the BIP-39 mnemonic passphrase \
                 (empty value is accepted; unreadable is a configuration error)",
            ),
    ]
}

/// Rejects non-interactive `new` (validator or account); stdin and stdout must both be TTYs.
pub(crate) fn require_tty_for_new() -> Result<(), AppError> {
    if stdin_is_tty() && stdout_is_tty() {
        return Ok(());
    }
    Err(AppError::exit2(
        "new requires an interactive terminal (stdin and stdout must both be a TTY); \
         refusing to generate a mnemonic on a non-TTY",
    ))
}

/// Parses the four mnemonic-passphrase CLI forms into a [`MnemonicPassphraseForm`].
///
/// Forms are mutually exclusive at the clap layer (`conflicts_with`), so only
/// one branch can fire:
/// - `--mnemonic-passphrase VALUE` → [`Raw`] (value Zeroizing'd on read)
/// - bare `--mnemonic-passphrase` → [`Prompt`]
/// - `--mnemonic-passphrase-file PATH` → read file (empty OK) → [`File`]
/// - neither → [`Empty`]
///
/// `warn_out` receives the FR-17 loose-permission WARNING (if any) when the
/// file form is used.
///
/// Distinct from the secret-resolving [`crate::keygen::resolve_mnemonic_passphrase`].
pub(crate) fn parse_mnemonic_passphrase_form(
    m: &ArgMatches,
    warn_out: &mut dyn Write,
) -> Result<MnemonicPassphraseForm, AppError> {
    // File form (mutually exclusive with the raw/prompt flag via conflicts_with).
    if let Some(raw) = m.get_one::<String>("mnemonic-passphrase-file") {
        let path = fs_util::secret_file_arg("--mnemonic-passphrase-file", raw)?;
        // I-2: this FR-17 permission WARNING is erased by `clear_after_ceremony` on
        // `new` and is durable on `recover` — the same pre-existing property as the
        // symlinked-output-dir WARNING (`validator_cli` / `account_cli` load_config).
        // No hoist, no ceremony change. See architecture §6.3.
        match ethernal_secretfile::read_secret_line(&path, warn_out) {
            Ok(value) => {
                return Ok(MnemonicPassphraseForm::File {
                    path: path.display().to_string(),
                    value,
                });
            }
            Err(e) => {
                return Err(AppError::exit2(format!("--mnemonic-passphrase-file: {e}")));
            }
        }
    }

    // Raw / bare prompt form. `contains_id` is true when the flag was supplied
    // even with no value (`num_args(0..=1)`); `get_one` is Some only with VALUE.
    if m.contains_id("mnemonic-passphrase") {
        return match m.get_one::<String>("mnemonic-passphrase") {
            Some(v) => Ok(MnemonicPassphraseForm::Raw(Zeroizing::new(v.clone()))),
            None => Ok(MnemonicPassphraseForm::Prompt),
        };
    }

    Ok(MnemonicPassphraseForm::Empty)
}

// ---------------------------------------------------------------------------
// InMemoryPassphrase — post-write decrypt round trip (C4 / V4-1)
// ---------------------------------------------------------------------------

/// A [`PassphraseSource`] over a passphrase already held in memory, for the
/// post-write decrypt round trip (C4). Never prompts and never re-reads the
/// environment: re-prompting mid-loop is unacceptable and a second
/// [`ethernal_keystore::EnvSource`] read is a needless extra exposure.
///
/// `read()` returns a fresh `Vec` copy — the trait returns a plain `Vec` and
/// documents that the caller must re-wrap; the master copy stays in
/// [`Zeroizing`].
pub(crate) struct InMemoryPassphrase(Zeroizing<Vec<u8>>);

impl InMemoryPassphrase {
    /// Wraps `bytes` as the master copy (zeroized on drop).
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl PassphraseSource for InMemoryPassphrase {
    fn read(&self) -> Result<Vec<u8>, KeystoreError> {
        Ok(self.0.to_vec())
    }
}

// ---------------------------------------------------------------------------
// write_with_retry — shared keystore write skeleton (T2.2)
// ---------------------------------------------------------------------------

/// Write `json` to `out_dir` under a domain-chosen filename, retrying once on
/// collision.
///
/// Control flow only: tries [`write_new_0600`] at `primary_filename()`, and on
/// [`OutputError::AlreadyExists`] retries once at `retry_filename()`. Other
/// errors and a second collision propagate as `OutputError`.
///
/// Domain filename schemas and bump policy stay in the closures (EIP-2335
/// path+secs vs geth `UTC--` address+secs/nanos). Call sites map the result to
/// exit 3 via their own `map_write_err` — this helper does not encode exit codes.
pub(crate) fn write_with_retry(
    out_dir: &Path,
    json: &[u8],
    primary_filename: impl FnOnce() -> String,
    retry_filename: impl FnOnce() -> String,
) -> Result<PathBuf, OutputError> {
    let final_path = out_dir.join(primary_filename());
    match write_new_0600(&final_path, json) {
        Ok(()) => Ok(final_path),
        Err(OutputError::AlreadyExists) => {
            let final_path = out_dir.join(retry_filename());
            write_new_0600(&final_path, json)?;
            Ok(final_path)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_passphrase_read_returns_exact_bytes_separate_allocations() {
        let src = InMemoryPassphrase::new(b"secret-pass".to_vec());
        let a = src.read().expect("read a");
        let b = src.read().expect("read b");
        assert_eq!(&a[..], b"secret-pass");
        assert_eq!(&b[..], b"secret-pass");
        assert_eq!(a, b);
        // Two calls return equal content via separate allocations.
        assert_ne!(a.as_ptr(), b.as_ptr());
    }

    #[test]
    fn mnemonic_passphrase_debug_redacts_secrets() {
        let raw = MnemonicPassphraseForm::Raw(Zeroizing::new("SUPER_SECRET".into()));
        let dbg = format!("{raw:?}");
        assert!(
            !dbg.contains("SUPER_SECRET"),
            "Debug leaked raw secret: {dbg}"
        );
        assert!(dbg.contains("REDACTED"), "{dbg}");

        // Distinctive sentinel path so FR-4 asserts path stays visible while
        // value is redacted (Zeroizing derives Debug — never #[derive(Debug)] here).
        let file = MnemonicPassphraseForm::File {
            path: "/tmp/sentinel-path-MNEMONIC_PW_XYZ".into(),
            value: Zeroizing::new("file-secret-value-NEVER-PRINT".into()),
        };
        let dbg = format!("{file:?}");
        assert!(
            !dbg.contains("file-secret-value-NEVER-PRINT"),
            "Debug leaked file secret: {dbg}"
        );
        assert!(
            dbg.contains("/tmp/sentinel-path-MNEMONIC_PW_XYZ"),
            "path should remain: {dbg}"
        );
        assert!(dbg.contains("REDACTED"), "{dbg}");
    }
}
