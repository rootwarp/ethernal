//! The `sign` subcommand, ported from `cmd/ethernal/sign.go`.
//!
//! Signs an unsigned transaction produced by `ethernal build`, using either a
//! local raw secp256k1 key (development/CI) or a Ledger hardware wallet.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgMatches, Command};

use ethernal_core::cancel::CancelToken;
use ethernal_signer::{new_local_signer_from_file, LedgerSigner, LocalSigner, SignedTx, Signer};
use ethernal_tx::UnsignedTx;

use crate::build_cmd::{read_input, write_file_mode};
use crate::errors::AppError;
use crate::fs_util;
use crate::logging::{Format, Level, Logger};

/// Parsed, validated inputs for the sign subcommand. Port of `main.SignConfig`.
/// The `Signer`/`PrivateKeyFile` fields are reused by `run`'s in-process sign.
///
/// Holds the **path** only — never key material. `Zeroizing` derives `Debug`, so
/// a secret field would print under `#[derive(Debug)]` (architecture §6.1 / D-4).
#[derive(Debug, Clone)]
pub struct SignConfig {
    /// The resolved signer type: "local" or "ledger".
    pub signer: String,
    /// The path to the unsigned tx JSON, or "-" for stdin.
    pub input_file: String,
    /// The output path for the signed tx. Empty means stdout.
    pub output_file: String,
    /// Path to the hex private-key file (local signer only). `None` for ledger
    /// or for `run_action`'s synthetic config (which must never re-open a path).
    pub private_key_file: Option<PathBuf>,
}

/// The clap definition of the `sign` subcommand.
pub fn command() -> Command {
    Command::new("sign")
        .about("Sign a previously built unsigned deposit transaction")
        .override_usage(
            "ethernal tx sign --signer local|ledger --input FILE [--output FILE] [--private-key-file PATH]",
        )
        .long_about(
            "Signs an unsigned transaction produced by \"ethernal deposit build\".\n\n\
             Two signing methods are supported:\n\n\
             \x20 --signer local\n\
             \x20   Reads a secp256k1 private key from the file named by\n\
             \x20   --private-key-file (required). The file holds hex (optional 0x\n\
             \x20   prefix); leading/trailing ASCII whitespace is trimmed.\n\n\
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
                .help("Signing method: \"local\" (private-key file) or \"ledger\" (hardware wallet)"),
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
            Arg::new("private-key-file")
                .long("private-key-file")
                .value_name("PATH")
                .help(
                    "Path to a file holding the hex private key (local signer only; required with --signer local)",
                ),
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

    let private_key_file = match m.get_one::<String>("private-key-file") {
        Some(v) => Some(fs_util::secret_file_arg("--private-key-file", v)?),
        None => None,
    };
    // FR-24: required when --signer local (no default path).
    if signer == "local" && private_key_file.is_none() {
        return Err(AppError::exit2(
            "--private-key-file: required when --signer local",
        ));
    }

    Ok(SignConfig {
        signer,
        input_file,
        output_file: m.get_one::<String>("output").cloned().unwrap_or_default(),
        private_key_file,
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
    // One construction site for the local path (architecture §6.1 / D-4).
    let local = if cfg.signer == "local" {
        let path = cfg.private_key_file.as_deref().ok_or_else(|| {
            AppError::Internal(
                "local signer missing private_key_file after load_sign_config".into(),
            )
        })?;
        Some(local_signer_from_file(path, &mut err_writer)?)
    } else {
        None
    };

    let signed = sign_unsigned_tx(&cfg, local.as_ref(), &mut err_writer, &unsigned, cancel)?;
    // Owner closes after sign — preserve prompt-zeroize timing; Drop is backstop.
    if let Some(ref s) = local {
        let _ = s.close();
    }

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

/// Reads `--private-key-file` exactly once (FR-22) and constructs the signer.
///
/// This is the **only** `LocalSigner` construction site in the binary's local
/// path (architecture §6.1 / D-4). Callers that need the signer again (e.g.
/// `run_action` for `from` derivation) must pass the constructed value forward
/// — never re-open the path.
pub(crate) fn local_signer_from_file(
    path: &Path,
    warn_out: &mut dyn Write,
) -> Result<LocalSigner, AppError> {
    new_local_signer_from_file(path, warn_out)
        .map_err(|e| AppError::context("local signer", AppError::Signer(e)))
}

/// Constructs a signer and produces a [`SignedTx`] for the given unsigned tx.
/// `err_writer` receives the interactive device prompt. Shared by `run`, which
/// calls it without serializing to disk between build and sign.
///
/// For `--signer local`, `local` must be `Some` (the owner constructs via
/// [`local_signer_from_file`] and **closes** after this returns). This function
/// does **not** close a borrowed local signer — closing would zeroize a key the
/// owner still holds. For ledger, this function constructs, signs, and closes.
pub fn sign_unsigned_tx(
    cfg: &SignConfig,
    local: Option<&LocalSigner>,
    err_writer: &mut dyn Write,
    unsigned: &UnsignedTx,
    cancel: &CancelToken,
) -> Result<SignedTx, AppError> {
    match cfg.signer.as_str() {
        "local" => {
            let s = local.ok_or_else(|| {
                AppError::Internal(
                    "sign_unsigned_tx: local signer required but not provided".into(),
                )
            })?;
            // Local never needs a device prompt; still honor the trait contract.
            if s.requires_user_interaction() {
                let _ = writeln!(err_writer, "Waiting for confirmation on Ledger device...");
            }
            s.sign_with_cancel(unsigned, &|| cancel.is_cancelled())
                .map_err(|e| {
                    AppError::context(format!("sign ({})", cfg.signer), AppError::Signer(e))
                })
            // Do not close: owner still holds the signer.
        }
        "ledger" => {
            let signer: Box<dyn Signer> = Box::new(
                LedgerSigner::new()
                    .map_err(|e| AppError::context("ledger signer", AppError::Signer(e)))?,
            );
            if signer.requires_user_interaction() {
                let _ = writeln!(err_writer, "Waiting for confirmation on Ledger device...");
            }
            let result = signer
                .sign_with_cancel(unsigned, &|| cancel.is_cancelled())
                .map_err(|e| {
                    AppError::context(format!("sign ({})", cfg.signer), AppError::Signer(e))
                });
            let _ = signer.close();
            result
        }
        // Validated by load_sign_config / load_run_config before this point.
        other => Err(AppError::Internal(format!(
            "unreachable signer type {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::exit_code_for;
    use crate::test_support::Tmp;

    #[test]
    fn sign_config_debug_shows_path_not_key_bytes() {
        let path = PathBuf::from("/tmp/key.hex");
        let cfg = SignConfig {
            signer: "local".into(),
            input_file: "unsigned.json".into(),
            output_file: String::new(),
            private_key_file: Some(path.clone()),
        };
        let dbg = format!("{cfg:?}");
        assert!(
            dbg.contains(path.to_str().unwrap()),
            "Debug must show path: {dbg}"
        );
        // No hex-shaped secret material belongs in Debug of a path-only config.
        assert!(
            !dbg.contains("01010101"),
            "Debug must not contain key material: {dbg}"
        );
    }

    #[test]
    fn private_key_file_dash_is_exit2() {
        let cmd = command();
        let m = cmd
            .try_get_matches_from([
                "sign",
                "--signer",
                "local",
                "--input",
                "u.json",
                "--private-key-file",
                "-",
            ])
            .expect("clap parse");
        let err = load_sign_config(&m).expect_err("'-' must fail");
        assert_eq!(exit_code_for(&err), 2);
        let msg = err.to_string();
        assert!(
            msg.contains("--private-key-file") && msg.contains("'-'"),
            "message must name flag and reject '-': {msg}"
        );
    }

    #[test]
    fn private_key_file_required_for_local() {
        let cmd = command();
        let m = cmd
            .try_get_matches_from(["sign", "--signer", "local", "--input", "u.json"])
            .expect("clap parse");
        let err = load_sign_config(&m).expect_err("missing key file");
        assert_eq!(exit_code_for(&err), 2);
        assert!(
            err.to_string().contains("--private-key-file"),
            "must name --private-key-file: {}",
            err
        );
    }

    #[test]
    fn ledger_allows_absent_private_key_file() {
        let cmd = command();
        let m = cmd
            .try_get_matches_from(["sign", "--signer", "ledger", "--input", "u.json"])
            .expect("clap parse");
        let cfg = load_sign_config(&m).expect("ledger needs no key file");
        assert!(cfg.private_key_file.is_none());
    }

    #[test]
    fn local_signer_from_file_reads_once_ok() {
        let dir = Tmp::new("sign-local-from-file");
        // Synthetic phase-3 key (hex, no trailing newline).
        let key = b"0x0101010101010101010101010101010101010101010101010101010101010101";
        let path = dir.secret_file("key.hex", key);
        let mut sink = Vec::new();
        let s = local_signer_from_file(&path, &mut sink).expect("construct");
        assert!(s.address().is_ok());
        let _ = s.close();
        assert!(
            sink.is_empty(),
            "0600 fixture must not emit FR-17 warning: {}",
            String::from_utf8_lossy(&sink)
        );
    }
}
