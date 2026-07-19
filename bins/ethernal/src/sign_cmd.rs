//! The `sign` subcommand, ported from `cmd/ethernal/sign.go`.
//!
//! Signs an unsigned transaction produced by `ethernal build`, using either a
//! local raw secp256k1 key (development/CI) or a Ledger hardware wallet.

use std::io::Write;

use clap::{Arg, ArgMatches, Command};

use ethernal_core::cancel::CancelToken;
use ethernal_signer::{new_local_signer_from_env, LedgerSigner, SignedTx, Signer};
use ethernal_tx::UnsignedTx;

use crate::build_cmd::{read_input, write_file_mode};
use crate::errors::AppError;
use crate::logging::{Format, Level, Logger};

/// The default env var holding the hex private key for the local signer.
pub const DEFAULT_PRIV_KEY_ENV: &str = "ETHERNAL_TX_PRIVATE_KEY";

/// Parsed, validated inputs for the sign subcommand. Port of `main.SignConfig`.
/// The `Signer`/`PrivateKeyEnvVar` fields are reused by `run`'s in-process sign.
#[derive(Debug, Clone)]
pub struct SignConfig {
    /// The resolved signer type: "local" or "ledger".
    pub signer: String,
    /// The path to the unsigned tx JSON, or "-" for stdin.
    pub input_file: String,
    /// The output path for the signed tx. Empty means stdout.
    pub output_file: String,
    /// The env var name holding the hex private key (local signer only).
    pub private_key_env_var: String,
}

/// The clap definition of the `sign` subcommand.
pub fn command() -> Command {
    Command::new("sign")
        .about("Sign a previously built unsigned deposit transaction")
        .override_usage(
            "ethernal tx sign --signer local|ledger --input FILE [--output FILE] [--private-key-env VAR]",
        )
        .long_about(
            "Signs an unsigned transaction produced by \"ethernal deposit build\".\n\n\
             Two signing methods are supported:\n\n\
             \x20 --signer local\n\
             \x20   Reads a secp256k1 private key from the environment variable named by\n\
             \x20   --private-key-env (default: ETHERNAL_TX_PRIVATE_KEY).\n\n\
             \x20   WARNING: The local signer is FOR DEVELOPMENT ONLY. Never use it with\n\
             \x20   real-fund keys. The key must never appear in CLI arguments or shell history.\n\n\
             \x20 --signer ledger\n\
             \x20   Signs using a Ledger hardware wallet. Prerequisites:\n\
             \x20     1. Ledger device is connected via USB.\n\
             \x20     2. The Ethereum app is open on the device.\n\n\
             Exit codes:\n\
             \x20 0  Success\n\
             \x20 2  User / configuration error (bad --signer, missing --input, invalid JSON)\n\
             \x20 3  Signer / crypto error (bad key, no Ledger device, Ethereum app not open, signer-side chain-ID mismatch)\n\
             \x20 4  User abort (Ctrl-C or rejection on Ledger device)",
        )
        .arg(
            Arg::new("signer")
                .long("signer")
                .value_name("METHOD")
                .required(true)
                .help("Signing method: \"local\" (env-var private key) or \"ledger\" (hardware wallet)"),
        )
        .arg(
            Arg::new("input")
                .long("input")
                .short('i')
                .value_name("FILE")
                .help("Path to the unsigned transaction JSON (from build) or '-' for stdin"),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .value_name("FILE")
                .help("Output file for the signed transaction (default: stdout)"),
        )
        .arg(
            Arg::new("private-key-env")
                .long("private-key-env")
                .value_name("VAR")
                .default_value(DEFAULT_PRIV_KEY_ENV)
                .help(format!(
                    "Environment variable name holding the hex private key (local signer only; default: {DEFAULT_PRIV_KEY_ENV})"
                )),
        )
}

/// Parses and validates sign subcommand flags. Port of `LoadSignConfig`.
pub fn load_sign_config(m: &ArgMatches) -> Result<SignConfig, AppError> {
    let signer = m.get_one::<String>("signer").cloned().unwrap_or_default();
    if signer != "local" && signer != "ledger" {
        return Err(AppError::exit2(format!(
            "--signer: unsupported value {signer:?}: must be \"local\" or \"ledger\""
        )));
    }

    let input_file = m.get_one::<String>("input").cloned().unwrap_or_default();
    if input_file.is_empty() {
        return Err(AppError::exit2("--input: required flag not set"));
    }

    let env_var = m
        .get_one::<String>("private-key-env")
        .cloned()
        .unwrap_or_default();
    if !is_posix_env_var_name(&env_var) {
        return Err(AppError::exit2(format!(
            "--private-key-env: {env_var:?} is not a valid POSIX env var name (must match ^[A-Z_][A-Z0-9_]*$); did you accidentally pass the key value instead of a variable name?"
        )));
    }

    Ok(SignConfig {
        signer,
        input_file,
        output_file: m.get_one::<String>("output").cloned().unwrap_or_default(),
        private_key_env_var: env_var,
    })
}

/// The `sign` action: read the unsigned tx, sign it, and write the signed tx to
/// stdout or a 0600 file.
pub fn run(m: &ArgMatches, cancel: &CancelToken) -> Result<(), AppError> {
    let cfg = load_sign_config(m)?;

    let raw = read_input(&cfg.input_file).map_err(|e| AppError::exit2(format!("--input: {e}")))?;

    let unsigned: UnsignedTx = serde_json::from_slice(&raw)
        .map_err(|e| AppError::exit2(format!("invalid input JSON: {e}")))?;

    let mut err_writer = std::io::stderr();
    let signed = sign_unsigned_tx(&cfg, &mut err_writer, &unsigned, cancel)?;

    let mut out = serde_json::to_vec_pretty(&signed)
        .map_err(|e| AppError::Internal(format!("sign: marshal: {e}")))?;
    out.push(b'\n');

    if cfg.output_file.is_empty() || cfg.output_file == "-" {
        std::io::stdout()
            .write_all(&out)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        return Ok(());
    }

    // 0600: signed tx bytes contain sensitive metadata (from address, tx hash).
    write_file_mode(&cfg.output_file, &out, 0o600)
        .map_err(|e| AppError::exit2(format!("--output: {e}")))?;
    let logger = Logger::stderr(Level::Info, Format::Text);
    logger.info(
        "wrote signed tx",
        &[
            ("path", cfg.output_file.clone()),
            ("signer", cfg.signer.clone()),
        ],
    );
    Ok(())
}

/// Constructs a signer and produces a [`SignedTx`] for the given unsigned tx.
/// `err_writer` receives the interactive device prompt. Shared by `run`, which
/// calls it without serializing to disk between build and sign.
pub fn sign_unsigned_tx(
    cfg: &SignConfig,
    err_writer: &mut dyn Write,
    unsigned: &UnsignedTx,
    cancel: &CancelToken,
) -> Result<SignedTx, AppError> {
    // 1. Construct signer.
    let signer: Box<dyn Signer> = match cfg.signer.as_str() {
        "local" => Box::new(
            new_local_signer_from_env(&cfg.private_key_env_var)
                .map_err(|e| AppError::context("local signer", AppError::Signer(e)))?,
        ),
        "ledger" => Box::new(
            LedgerSigner::new()
                .map_err(|e| AppError::context("ledger signer", AppError::Signer(e)))?,
        ),
        // Validated by load_sign_config / load_run_config before this point.
        other => {
            return Err(AppError::Internal(format!(
                "unreachable signer type {other:?}"
            )))
        }
    };

    // 2. Prompt if device interaction is needed.
    if signer.requires_user_interaction() {
        let _ = writeln!(err_writer, "Waiting for confirmation on Ledger device...");
    }

    // 3. Sign, then always close (mirrors Go's `defer s.Close()`).
    let result = signer
        .sign_with_cancel(unsigned, &|| cancel.is_cancelled())
        .map_err(|e| AppError::context(format!("sign ({})", cfg.signer), AppError::Signer(e)));
    let _ = signer.close();
    result
}

/// Reports whether `s` is a valid POSIX env var name (`^[A-Z_][A-Z0-9_]*$`),
/// implemented without a regex dependency. Shared with `run`.
pub(crate) fn is_posix_env_var_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_uppercase() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_uppercase() || c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::is_posix_env_var_name;

    // Underpins the `--private-key-env` validation exercised end-to-end by
    // tests/sign.rs (`invalid_env_var_name_*`). `^[A-Z_][A-Z0-9_]*$`.
    #[test]
    fn posix_env_var_name_matrix() {
        for ok in ["FOO", "_FOO", "ETHERNAL_TX_PRIVATE_KEY", "A1", "_", "X_2_Y"] {
            assert!(is_posix_env_var_name(ok), "{ok:?} should be valid");
        }
        for bad in [
            "",                 // empty
            "1FOO",             // leading digit
            "my_lowercase_var", // lowercase
            "FOO-BAR",          // hyphen
            "FOO BAR",          // space
            "0xabcdef",         // a hex key passed as a name
            "föö",              // non-ascii
        ] {
            assert!(!is_posix_env_var_name(bad), "{bad:?} should be invalid");
        }
    }
}
