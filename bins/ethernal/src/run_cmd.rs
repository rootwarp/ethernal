//! The `run` subcommand, ported from `cmd/ethernal/run.go`.
//!
//! `run` performs build → sign in-process (no intermediate unsigned tx on disk),
//! for workflows where both phases happen on the same machine.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, ArgMatches, Command};

use ethernal_core::cancel::CancelToken;
use ethernal_core::output::write_atomic;
use ethernal_signer::Signer;

use crate::build_cmd::{build_flags, build_unsigned_tx, read_input};
use crate::config::{self, Config};
use crate::errors::AppError;
use crate::fs_util;
use crate::logging::{Format, Level, Logger};
use crate::sign_cmd::{local_signer_from_file, sign_unsigned_tx, SignConfig};

/// Parsed, validated inputs for the run subcommand, combining build (deposit
/// data → unsigned tx) and sign (unsigned tx → signed tx) fields. Port of
/// `main.RunConfig`.
///
/// Holds the **path** only — never key material (architecture §6.1 / D-4).
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Build fields (deposit data → unsigned tx).
    pub build: Config,
    /// The resolved signer type: "local" or "ledger".
    pub signer: String,
    /// Path to the hex private-key file (local signer only). `None` for ledger.
    pub private_key_file: Option<PathBuf>,
    /// The output path for the signed tx. Empty means stdout.
    pub output_file: String,
    /// When true, also writes the unsigned tx to disk alongside signed.json.
    pub keep_unsigned: bool,
    /// Overrides the auto-derived `.raw` companion filename.
    pub raw_output_file: String,
}

/// The clap definition of the `run` subcommand. Flags = build's list WITHOUT
/// `--from` (run derives the sender from its signing key) + sign flags.
pub fn command() -> Command {
    Command::new("run")
        .about("Build and sign a deposit transaction in one step (convenience command)")
        .override_usage(
            "ethernal tx run --input-file FILE --network NET --signer local|ledger [--private-key-file PATH] [options]",
        )
        .long_about(
            "Runs build and sign in-process without writing an intermediate unsigned tx to disk.\n\n\
             Use this when both phases happen on the same machine. For air-gapped workflows\n\
             (build offline, transfer, sign on a separate device), use the `deposit build` and `tx sign`\n\
             subcommands separately.\n\n\
             Output artifacts:\n\
             \x20 signed.json  — the full SignedTx JSON (fields: unsigned, from, hash, r, s, v, rawRLP)\n\
             \x20 signed.raw   — companion file (mode 0600) containing only the 0x-prefixed RLP\n\
             \x20                hex, written alongside signed.json when --output is a file path.\n\n\
             Exit codes:\n\
             \x20 0  Success\n\
             \x20 2  User / configuration error (missing file, bad --network, missing --signer,\n\
             \x20    missing --nonce/--gas-limit for ledger RPC mode, RPC chain-ID mismatch)\n\
             \x20 3  Signer / crypto error (bad key, no Ledger device, Ethereum app not open, signer-side chain-ID mismatch)\n\
             \x20 4  User abort (Ctrl-C or rejection on Ledger device)\n\
             \x20 5  RPC error (endpoint unreachable, gas/nonce estimation failed)\n\
             \x20 1  Unexpected internal error",
        )
        .args(build_flags(false))
        .arg(
            Arg::new("signer")
                .long("signer")
                .value_name("METHOD")
                .help("Signing method: \"local\" (private-key file) or \"ledger\" (hardware wallet)"),
        )
        .arg(
            Arg::new("private-key-file")
                .long("private-key-file")
                .value_name("PATH")
                .help(
                    "Path to a file holding the hex private key (local signer only; required with --signer local)",
                ),
        )
        .arg(
            Arg::new("keep-unsigned")
                .long("keep-unsigned")
                .action(ArgAction::SetTrue)
                .help("Also write the unsigned tx to disk alongside the signed output (requires --output to be a file path)"),
        )
        .arg(
            Arg::new("raw-output")
                .long("raw-output")
                .value_name("FILE")
                .help("Override the auto-derived .raw companion filename for the RLP hex (default: <output>.raw → signed.raw when --output is signed.json)"),
        )
}

/// Parses and validates run subcommand flags. Port of `LoadRunConfig`.
pub fn load_run_config(m: &ArgMatches) -> Result<RunConfig, AppError> {
    // Shared build parser — leaves From zero (run declares no --from).
    let build = config::load_build_config(m)?;

    let signer = m.get_one::<String>("signer").cloned().unwrap_or_default();
    if signer.is_empty() {
        return Err(AppError::exit2(
            "--signer: required flag not set; must be \"local\" or \"ledger\"",
        ));
    }
    if signer != "local" && signer != "ledger" {
        return Err(AppError::exit2(format!(
            "--signer: unsupported value {signer:?}: must be \"local\" or \"ledger\""
        )));
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

    let keep_unsigned = m.get_flag("keep-unsigned");
    let output_file = m.get_one::<String>("output").cloned().unwrap_or_default();
    if keep_unsigned && (output_file.is_empty() || output_file == "-") {
        return Err(AppError::exit2(
            "--keep-unsigned requires --output to be a file path (cannot be used with stdout)",
        ));
    }

    Ok(RunConfig {
        build,
        signer,
        private_key_file,
        output_file,
        keep_unsigned,
        raw_output_file: m
            .get_one::<String>("raw-output")
            .cloned()
            .unwrap_or_default(),
    })
}

/// The `run` action.
pub fn run(m: &ArgMatches, cancel: &CancelToken) -> Result<(), AppError> {
    let mut cfg = load_run_config(m)?;
    run_action(&mut cfg, cancel)
}

/// Builds the synthetic [`SignConfig`] used by [`run_action`] for in-process
/// signing. **`private_key_file` is always `None`** — a live path here is dead
/// data that invites a second open (D-4). The local signer is constructed once
/// in `run_action` and passed forward.
pub(crate) fn synthetic_sign_config(cfg: &RunConfig) -> SignConfig {
    SignConfig {
        signer: cfg.signer.clone(),
        input_file: String::new(),
        output_file: String::new(),
        private_key_file: None,
    }
}

/// Orchestrates the build → sign pipeline in-process.
///
/// Step order preserves today's error precedence (architecture §6.1):
/// require_ledger_flags_for_rpc → read_input → local_signer_from_file (all local)
/// → set `from` when RPC → build_unsigned_tx → optional keep-unsigned →
/// sign_unsigned_tx (forwarded local) → close local.
fn run_action(cfg: &mut RunConfig, cancel: &CancelToken) -> Result<(), AppError> {
    let logger = Logger::stderr(Level::Info, Format::Text);

    // 0. Config-time gate: ledger in RPC mode cannot derive a sender, so require
    // both --nonce and --gas-limit up front (clean exit 2, no dial).
    require_ledger_flags_for_rpc(cfg)?;

    // 1. Read deposit data (still first — pins run::invalid_input exit 2).
    let raw_data = read_input(&cfg.build.input_file)
        .map_err(|e| AppError::exit2(format!("--input-file: {e}")))?;

    // 1b. Exactly one LocalSigner construction for every local run (FR-22 / D-4).
    // Must come after read_input so bad input still exits 2 before a bad key's
    // exit 3 (R-4). Offline local also constructs here so sign never re-opens.
    let mut err_writer = std::io::stderr();
    let local = if cfg.signer == "local" {
        let path = cfg.private_key_file.as_deref().ok_or_else(|| {
            AppError::Internal("local signer missing private_key_file after load_run_config".into())
        })?;
        Some(local_signer_from_file(path, &mut err_writer)?)
    } else {
        None
    };

    // 1c. Local + RPC: derive From so the builder can fetch pending nonce and
    // estimate gas (both need a funded sender).
    if let Some(ref s) = local {
        if !cfg.build.rpc_url.is_empty() {
            let addr = s
                .address()
                .map_err(|e| AppError::context("local signer", AppError::Signer(e)))?;
            cfg.build.from = addr;
        }
    }

    // 2. Build unsigned tx (in-process, no disk write).
    let unsigned = build_unsigned_tx(&cfg.build, &raw_data, cancel)?;

    // 3. Optionally write unsigned tx before signing (so it survives a sign
    // failure — it is a valid artifact for retry).
    if cfg.keep_unsigned {
        let unsigned_path = unsigned_path_for(&cfg.output_file);
        let mut unsigned_json = serde_json::to_vec_pretty(&unsigned)
            .map_err(|e| AppError::exit2(format!("run: marshal unsigned: {e}")))?;
        unsigned_json.push(b'\n');
        write_atomic(Path::new(&unsigned_path), &unsigned_json, 0o644)
            .map_err(|e| AppError::exit2(format!("--keep-unsigned: write {unsigned_path}: {e}")))?;
        logger.info("wrote unsigned tx", &[("path", unsigned_path.clone())]);
    }

    // 4. Sign (in-process). Synthetic SignConfig has private_key_file: None so
    // nothing inside sign_unsigned_tx can re-open a path (D-4).
    let sign_cfg = synthetic_sign_config(cfg);
    let signed = sign_unsigned_tx(
        &sign_cfg,
        local.as_ref(),
        &mut err_writer,
        &unsigned,
        cancel,
    )?;

    // 5. Owner closes after sign — preserve prompt-zeroize timing.
    if let Some(ref s) = local {
        let _ = s.close();
    }

    // 6. Marshal signed tx.
    let mut signed_json = serde_json::to_vec_pretty(&signed)
        .map_err(|e| AppError::Internal(format!("run: marshal signed: {e}")))?;
    signed_json.push(b'\n');

    // 7. Write output.
    if cfg.output_file.is_empty() || cfg.output_file == "-" {
        std::io::stdout()
            .write_all(&signed_json)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        return Ok(());
    }

    // Write signed.json atomically (0600).
    write_atomic(Path::new(&cfg.output_file), &signed_json, 0o600)
        .map_err(|e| AppError::exit2(format!("--output: write {}: {e}", cfg.output_file)))?;
    logger.info(
        "wrote signed tx",
        &[
            ("path", cfg.output_file.clone()),
            ("signer", cfg.signer.clone()),
        ],
    );

    // Write companion .raw file containing only the RLP hex (0600).
    let raw_path = if cfg.raw_output_file.is_empty() {
        raw_path_for(&cfg.output_file)
    } else {
        cfg.raw_output_file.clone()
    };
    let raw_content = format!("{}\n", signed.raw_rlp);
    write_atomic(Path::new(&raw_path), raw_content.as_bytes(), 0o600)
        .map_err(|e| AppError::exit2(format!("raw output: write {raw_path}: {e}")))?;
    logger.info("wrote raw RLP", &[("path", raw_path.clone())]);

    Ok(())
}

/// Enforces the ledger-in-RPC-mode gate: `run --signer ledger` never queries the
/// device for its address, so From stays zero and the node can resolve neither
/// the pending nonce nor the gas estimate. Both `--nonce` and `--gas-limit` must
/// be supplied explicitly (clean exit 2). The local signer derives From, so it
/// is exempt. Mirrors build's [`crate::build_cmd::require_from_for_rpc`].
pub fn require_ledger_flags_for_rpc(cfg: &RunConfig) -> Result<(), AppError> {
    if cfg.signer == "ledger"
        && !cfg.build.rpc_url.is_empty()
        && (cfg.build.nonce.is_none() || cfg.build.gas_limit == 0)
    {
        return Err(AppError::exit2(
            "--signer ledger with --rpc-url requires both --nonce and --gas-limit: the Ledger sender address is not queried, so the node cannot fetch the pending nonce or estimate gas for the 32-ETH deposit call",
        ));
    }
    Ok(())
}

/// Derives the unsigned tx file path from the signed output path.
/// e.g. "/path/to/signed.json" → "/path/to/unsigned.json".
pub fn unsigned_path_for(signed_path: &str) -> String {
    let dir = go_dir(signed_path);
    let base = go_base(signed_path);
    let ext = go_ext(&base);
    let stem = base.strip_suffix(&ext).unwrap_or(&base);
    // Replace "signed" with "unsigned" if present, otherwise prepend "unsigned-".
    let stem = if stem.contains("signed") {
        stem.replacen("signed", "unsigned", 1)
    } else {
        format!("unsigned-{stem}")
    };
    go_join(&dir, &format!("{stem}{ext}"))
}

/// Derives the companion `.raw` filename from the signed output path.
/// e.g. "/path/to/signed.json" → "/path/to/signed.raw".
pub fn raw_path_for(signed_path: &str) -> String {
    let ext = go_ext(signed_path);
    let stem = signed_path.strip_suffix(&ext).unwrap_or(signed_path);
    format!("{stem}.raw")
}

// --- Minimal `path/filepath` emulation ---
//
// These match Go's `filepath` for already-clean inputs (absolute paths, single
// separators, no `.`/`..` elements), which is all that the CLI's derived output
// paths ever contain. Reimplemented rather than using `std::path` because
// `Path::join(".", x)` yields "./x" where Go's `filepath.Join` yields "x".

/// Port of `filepath.Ext`: the suffix from the final `.` in the final path
/// element, empty if none.
fn go_ext(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b'/' => break,
            b'.' => return path[i..].to_string(),
            _ => {}
        }
    }
    String::new()
}

/// Port of `filepath.Base` for clean inputs: the last path element.
fn go_base(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_string();
    }
    match trimmed.rfind('/') {
        Some(pos) => trimmed[pos + 1..].to_string(),
        None => trimmed.to_string(),
    }
}

/// Port of `filepath.Dir` for clean inputs: all but the last element.
fn go_dir(path: &str) -> String {
    match path.rfind('/') {
        None => ".".to_string(),
        Some(0) => "/".to_string(),
        Some(pos) => path[..pos].to_string(),
    }
}

/// Port of `filepath.Join(dir, name)` for clean two-element inputs.
fn go_join(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir == "." {
        return name.to_string();
    }
    let d = dir.trim_end_matches('/');
    if d.is_empty() {
        format!("/{name}")
    } else {
        format!("{d}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::exit_code_for;
    use ethernal_core::network::{self, Network};

    /// A `RunConfig` for driving [`require_ledger_flags_for_rpc`] directly.
    fn run_cfg(signer: &str, rpc_url: &str, gas_limit: u64, nonce: Option<u64>) -> RunConfig {
        RunConfig {
            build: Config {
                network: Network::Holesky,
                network_params: network::lookup(Network::Holesky),
                input_file: String::new(),
                output_file: String::new(),
                index: 0,
                rpc_url: rpc_url.to_string(),
                from: [0u8; 20],
                gas_limit,
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                nonce,
            },
            signer: signer.to_string(),
            private_key_file: None,
            output_file: String::new(),
            keep_unsigned: false,
            raw_output_file: String::new(),
        }
    }

    // Go: TestRequireLedgerFlagsForRPC (table).
    #[test]
    fn require_ledger_flags_for_rpc_gate() {
        // offline ledger (no rpc) → ok.
        assert!(require_ledger_flags_for_rpc(&run_cfg("ledger", "", 0, None)).is_ok());

        // ledger rpc nonce omitted → err (names both flags).
        let err = require_ledger_flags_for_rpc(&run_cfg("ledger", "http://n", 250_000, None))
            .unwrap_err();
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("--nonce") && err.to_string().contains("--gas-limit"));

        // ledger rpc gas omitted → err.
        let err =
            require_ledger_flags_for_rpc(&run_cfg("ledger", "http://n", 0, Some(5))).unwrap_err();
        assert_eq!(exit_code_for(&err), 2);

        // ledger rpc both omitted → err.
        assert!(require_ledger_flags_for_rpc(&run_cfg("ledger", "http://n", 0, None)).is_err());

        // ledger rpc both set → ok.
        assert!(
            require_ledger_flags_for_rpc(&run_cfg("ledger", "http://n", 250_000, Some(5))).is_ok()
        );

        // local rpc both omitted (exempt) → ok.
        assert!(require_ledger_flags_for_rpc(&run_cfg("local", "http://n", 0, None)).is_ok());
    }

    // Path derivation used to place the .raw / unsigned companion files.
    #[test]
    fn path_derivation() {
        assert_eq!(raw_path_for("/path/to/signed.json"), "/path/to/signed.raw");
        assert_eq!(
            unsigned_path_for("/path/to/signed.json"),
            "/path/to/unsigned.json"
        );
        // No "signed" stem → prepend "unsigned-".
        assert_eq!(
            unsigned_path_for("/path/to/tx.json"),
            "/path/to/unsigned-tx.json"
        );
    }

    /// Structural guard (F6-1 / D-4): `run_action`'s synthetic `SignConfig` must
    /// carry `private_key_file: None` so nothing can re-open a path at sign time.
    #[test]
    fn synthetic_sign_config_private_key_file_is_none() {
        let mut cfg = run_cfg("local", "", 0, None);
        cfg.private_key_file = Some(PathBuf::from("/tmp/key.hex"));
        let sign_cfg = synthetic_sign_config(&cfg);
        assert!(
            sign_cfg.private_key_file.is_none(),
            "synthetic SignConfig must set private_key_file: None (got {:?})",
            sign_cfg.private_key_file
        );
        assert_eq!(sign_cfg.signer, "local");
        // Debug of the synthetic config must not reintroduce a path.
        let dbg = format!("{sign_cfg:?}");
        assert!(
            !dbg.contains("/tmp/key.hex"),
            "synthetic SignConfig Debug must not carry a live path: {dbg}"
        );
    }

    #[test]
    fn private_key_file_required_for_local() {
        // FR-24: missing --private-key-file with --signer local → exit 2.
        // Use a real deposit fixture path so build config load is not the failure.
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/deposit-fixture.json");
        let m = command()
            .try_get_matches_from([
                "run",
                "--network",
                "holesky",
                "--input-file",
                fixture.to_str().unwrap(),
                "--signer",
                "local",
            ])
            .expect("clap parse");
        let err = load_run_config(&m).expect_err("missing key file");
        assert_eq!(exit_code_for(&err), 2);
        assert!(
            err.to_string().contains("--private-key-file"),
            "must name --private-key-file: {}",
            err
        );
    }
}
