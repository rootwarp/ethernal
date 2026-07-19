//! Shared keystore-CLI helpers used by both the `validator` and `account` namespaces.
//!
//! Neutral home for flags, validation, and the three-form BIP-39 mnemonic
//! passphrase input so neither namespace owns the other's helpers.

use std::fmt;
use std::path::Path;

use clap::{Arg, ArgMatches};
use zeroize::Zeroizing;

use crate::errors::AppError;

/// The three-form BIP-39 mnemonic passphrase input (F-12 / architecture design
/// note (c)). Distinct from the keystore passphrase (`--passphrase-env`).
///
/// The forms are mutually exclusive at the clap layer (`conflicts_with`); only
/// one is active per invocation. Absent both flags → [`Empty`].
///
/// Secret payloads (`Raw` / `Env::value`) are wrapped in [`Zeroizing`] on read
/// (S-1 / design note (c)). [`Debug`] redacts those fields (S-2).
#[derive(Clone, PartialEq, Eq)]
pub enum MnemonicPassphraseForm {
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
pub fn require_tty_for_new() -> Result<(), AppError> {
    // SAFETY: isatty is async-signal-safe and has no preconditions.
    let stdin_tty = unsafe { libc::isatty(0) == 1 };
    let stdout_tty = unsafe { libc::isatty(1) == 1 };
    if stdin_tty && stdout_tty {
        return Ok(());
    }
    Err(AppError::exit2(
        "new requires an interactive terminal (stdin and stdout must both be a TTY); \
         refusing to generate a mnemonic on a non-TTY",
    ))
}

/// Resolves the three mnemonic-passphrase forms into a [`MnemonicPassphraseForm`].
///
/// Forms are mutually exclusive at the clap layer (`conflicts_with`), so only
/// one branch can fire:
/// - `--mnemonic-passphrase VALUE` → [`Raw`] (value Zeroizing'd on read)
/// - bare `--mnemonic-passphrase` → [`Prompt`]
/// - `--mnemonic-passphrase-env VAR` → read env (unset → exit 2; empty OK) → [`Env`]
/// - neither → [`Empty`]
pub(crate) fn resolve_mnemonic_passphrase(
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

/// Checks that dir exists and the process can write to it via the shared
/// exclusive create+remove probe ([`crate::fs_util::probe_dir_writable`]).
pub(crate) fn validate_output_dir(dir: &str) -> Result<(), String> {
    let meta = match std::fs::metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("directory \"{dir}\" does not exist"));
        }
        Err(e) => return Err(format!("cannot stat directory \"{dir}\": {e}")),
    };
    if !meta.is_dir() {
        return Err(format!("\"{dir}\" is not a directory"));
    }

    crate::fs_util::probe_dir_writable(Path::new(dir))
        .map_err(|e| format!("directory \"{dir}\" is not writable: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A temp directory that removes itself on drop.
    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Tmp {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("keystore-cli-test-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
        fn str(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn validate_output_dir_negative() {
        let dir = Tmp::new();
        let missing = dir.0.join("missing");
        let err = validate_output_dir(missing.to_str().unwrap()).unwrap_err();
        assert!(err.contains("does not exist"), "{err}");

        let file = dir.0.join("not-dir");
        std::fs::write(&file, b"x").unwrap();
        let err = validate_output_dir(file.to_str().unwrap()).unwrap_err();
        assert!(err.contains("not a directory"), "{err}");

        // Happy path: existing writable dir.
        assert!(validate_output_dir(dir.str()).is_ok());
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
