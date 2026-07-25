//! Shared keystore-CLI helpers used by both the `validator` and `account` namespaces.
//!
//! Neutral home for flags, validation, the three-form BIP-39 mnemonic
//! passphrase input, and the write-once-retry keystore write skeleton so
//! neither namespace owns the other's helpers.

use std::fmt;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgMatches};
use ethernal_core::output::{write_new_0600, OutputError};
use ethernal_keystore::{KeystoreError, PassphraseSource};
use zeroize::Zeroizing;

use crate::errors::AppError;
use crate::fs_util::{stdin_is_tty, stdout_is_tty};

/// Shared overflow message for `--start-index + --count` range checks.
pub(crate) const START_INDEX_OVERFLOW_MSG: &str = "--start-index + --count overflows u32";

/// The three-form BIP-39 mnemonic passphrase input (F-12 / architecture design
/// note (c)). Distinct from the keystore passphrase (`--passphrase-env`).
///
/// The forms are mutually exclusive at the clap layer (`conflicts_with`); only
/// one is active per invocation. Absent both flags → [`Empty`].
///
/// Secret payloads (`Raw` / `Env::value`) are wrapped in [`Zeroizing`] on read
/// (S-1 / design note (c)). [`Debug`] redacts those fields (S-2).
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum MnemonicPassphraseForm {
    /// Neither flag supplied — empty mnemonic passphrase (default).
    Empty,
    /// `--mnemonic-passphrase VALUE` raw argv value.
    Raw(Zeroizing<String>),
    /// `--mnemonic-passphrase-env VAR` resolved to the env var's current value
    /// (empty string is accepted; unset is rejected at load time).
    Env {
        var: String,
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
            Self::Env { var, .. } => f
                .debug_struct("Env")
                .field("var", var)
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
        Arg::new("passphrase-env")
            .long("passphrase-env")
            .value_name("VAR")
            .help("Name of the environment variable holding the keystore passphrase (omit for TTY prompt-with-confirm)"),
        // Three-form mnemonic passphrase (architecture design note (c)):
        //   --mnemonic-passphrase VALUE  → raw
        //   --mnemonic-passphrase        → prompt (num_args 0)
        //   --mnemonic-passphrase-env VAR → env
        //   absent                       → empty
        Arg::new("mnemonic-passphrase")
            .long("mnemonic-passphrase")
            .value_name("VALUE")
            .num_args(0..=1)
            .conflicts_with("mnemonic-passphrase-env")
            .help(
                "BIP-39 mnemonic passphrase (\"25th word\"). Provide VALUE for a raw value; \
                 pass the flag bare to prompt interactively; omit for empty (default). \
                 Raw VALUE is visible in the process table — prefer env or prompt for \
                 high-value mnemonics",
            ),
        Arg::new("mnemonic-passphrase-env")
            .long("mnemonic-passphrase-env")
            .value_name("VAR")
            .conflicts_with("mnemonic-passphrase")
            .help(
                "Name of the environment variable holding the BIP-39 mnemonic passphrase \
                 (empty value is accepted; unset is a configuration error)",
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

/// Parses the three mnemonic-passphrase CLI forms into a [`MnemonicPassphraseForm`].
///
/// Forms are mutually exclusive at the clap layer (`conflicts_with`), so only
/// one branch can fire:
/// - `--mnemonic-passphrase VALUE` → [`Raw`] (value Zeroizing'd on read)
/// - bare `--mnemonic-passphrase` → [`Prompt`]
/// - `--mnemonic-passphrase-env VAR` → read env (unset → exit 2; empty OK) → [`Env`]
/// - neither → [`Empty`]
///
/// Distinct from the secret-resolving [`crate::keygen::resolve_mnemonic_passphrase`].
pub(crate) fn parse_mnemonic_passphrase_form(
    m: &ArgMatches,
) -> Result<MnemonicPassphraseForm, AppError> {
    // Env form (mutually exclusive with the raw/prompt flag via conflicts_with).
    if let Some(var) = m.get_one::<String>("mnemonic-passphrase-env") {
        match std::env::var(var) {
            Ok(value) => {
                return Ok(MnemonicPassphraseForm::Env {
                    var: var.clone(),
                    value: Zeroizing::new(value),
                });
            }
            Err(_) => {
                return Err(AppError::exit2(format!(
                    "--mnemonic-passphrase-env: environment variable \"{var}\" is not set"
                )));
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

        let env = MnemonicPassphraseForm::Env {
            var: "MNEMONIC_PW".into(),
            value: Zeroizing::new("env-secret-value".into()),
        };
        let dbg = format!("{env:?}");
        assert!(
            !dbg.contains("env-secret-value"),
            "Debug leaked env secret: {dbg}"
        );
        assert!(dbg.contains("MNEMONIC_PW"), "var name should remain: {dbg}");
        assert!(dbg.contains("REDACTED"), "{dbg}");
    }
}
