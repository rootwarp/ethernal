//! The `run` subcommand, ported from `cmd/eth-deposit/run.go`.
//!
//! `run` performs build → sign in-process (no intermediate unsigned tx on disk),
//! for workflows where both phases happen on the same machine. It also owns the
//! atomic-write helper (`atomic_write_file`) reused by `send`.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Arg, ArgAction, ArgMatches, Command};

use eth_deposit_core::cancel::CancelToken;
use eth_deposit_signer::{new_local_signer_from_env, Signer};

use crate::build_cmd::{build_flags, build_unsigned_tx, read_input};
use crate::config::{self, Config};
use crate::errors::AppError;
use crate::logging::{Format, Level, Logger};
use crate::sign_cmd::{is_posix_env_var_name, sign_unsigned_tx, SignConfig, DEFAULT_PRIV_KEY_ENV};

/// Parsed, validated inputs for the run subcommand, combining build (deposit
/// data → unsigned tx) and sign (unsigned tx → signed tx) fields. Port of
/// `main.RunConfig`.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Build fields (deposit data → unsigned tx).
    pub build: Config,
    /// The resolved signer type: "local" or "ledger".
    pub signer: String,
    /// The env var name holding the hex private key (local signer only).
    pub private_key_env_var: String,
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
        .override_usage("eth-deposit run --input-file FILE --network NET --signer local|ledger [options]")
        .long_about(
            "Runs build and sign in-process without writing an intermediate unsigned tx to disk.\n\n\
             Use this when both phases happen on the same machine. For air-gapped workflows\n\
             (build offline, transfer, sign on a separate device), use the build and sign\n\
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
                .help("Signing method: \"local\" (env-var private key) or \"ledger\" (hardware wallet)"),
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

    let env_var = m
        .get_one::<String>("private-key-env")
        .cloned()
        .unwrap_or_default();
    if !is_posix_env_var_name(&env_var) {
        return Err(AppError::exit2(format!(
            "--private-key-env: {env_var:?} is not a valid POSIX env var name (must match ^[A-Z_][A-Z0-9_]*$); did you accidentally pass the key value instead of a variable name?"
        )));
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
        private_key_env_var: env_var,
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

/// Orchestrates the build → sign pipeline in-process.
fn run_action(cfg: &mut RunConfig, cancel: &CancelToken) -> Result<(), AppError> {
    let logger = Logger::stderr(Level::Info, Format::Text);

    // 0. Config-time gate: ledger in RPC mode cannot derive a sender, so require
    // both --nonce and --gas-limit up front (clean exit 2, no dial).
    require_ledger_flags_for_rpc(cfg)?;

    // 1. Read deposit data.
    let raw_data = read_input(&cfg.build.input_file)
        .map_err(|e| AppError::exit2(format!("--input-file: {e}")))?;

    // 1b. Local signer + RPC mode: derive From from the signing key so the
    // builder can fetch the pending nonce AND estimate gas (both need a funded
    // sender). The key is read here and again in sign_unsigned_tx below; each
    // LocalSigner zeroizes its key buffer on close.
    if cfg.signer == "local" && !cfg.build.rpc_url.is_empty() {
        let s = new_local_signer_from_env(&cfg.private_key_env_var)
            .map_err(|e| AppError::context("local signer", AppError::Signer(e)))?;
        let addr_res = s.address();
        let _ = s.close();
        let addr = addr_res.map_err(|e| AppError::context("local signer", AppError::Signer(e)))?;
        cfg.build.from = addr;
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
        atomic_write_file(&unsigned_path, &unsigned_json, 0o644)
            .map_err(|e| AppError::exit2(format!("--keep-unsigned: write {unsigned_path}: {e}")))?;
        logger.info("wrote unsigned tx", &[("path", unsigned_path.clone())]);
    }

    // 4. Sign (in-process, no disk round-trip).
    let sign_cfg = SignConfig {
        signer: cfg.signer.clone(),
        input_file: String::new(),
        output_file: String::new(),
        private_key_env_var: cfg.private_key_env_var.clone(),
    };
    let mut err_writer = std::io::stderr();
    let signed = sign_unsigned_tx(&sign_cfg, &mut err_writer, &unsigned, cancel)?;

    // 5. Marshal signed tx.
    let mut signed_json = serde_json::to_vec_pretty(&signed)
        .map_err(|e| AppError::Internal(format!("run: marshal signed: {e}")))?;
    signed_json.push(b'\n');

    // 6. Write output.
    if cfg.output_file.is_empty() || cfg.output_file == "-" {
        std::io::stdout()
            .write_all(&signed_json)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        return Ok(());
    }

    // Write signed.json atomically (0600).
    atomic_write_file(&cfg.output_file, &signed_json, 0o600)
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
    atomic_write_file(&raw_path, raw_content.as_bytes(), 0o600)
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

/// Writes `data` to `path` via a temp file + rename so a partial write never
/// leaves a corrupt file at the target path. The temp file is created in the
/// same directory as `path` so the rename is atomic on a single filesystem.
/// Port of `atomicWriteFile`; shared with `send` for the receipt file.
pub fn atomic_write_file(path: &str, data: &[u8], mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let dir = go_dir(path);
    let (tmp_name, mut tmp) = create_temp(&dir).map_err(|e| format!("create temp: {e}"))?;

    // Chmod to the requested perm (mirrors Go's tmp.Chmod(perm) after CreateTemp).
    if let Err(e) = std::fs::set_permissions(&tmp_name, std::fs::Permissions::from_mode(mode)) {
        drop(tmp);
        let _ = std::fs::remove_file(&tmp_name);
        return Err(format!("chmod temp: {e}"));
    }
    if let Err(e) = tmp.write_all(data) {
        drop(tmp);
        let _ = std::fs::remove_file(&tmp_name);
        return Err(format!("write temp: {e}"));
    }
    drop(tmp); // close
    if let Err(e) = std::fs::rename(&tmp_name, path) {
        // Best-effort cleanup of the temp file when the rename never happened.
        let _ = std::fs::remove_file(&tmp_name);
        return Err(format!("rename: {e}"));
    }
    Ok(())
}

/// Creates a uniquely named temp file (mode 0600 initially, like Go's
/// `os.CreateTemp`) in `dir`, returning its path and handle.
fn create_temp(dir: &str) -> std::io::Result<(String, std::fs::File)> {
    use std::os::unix::fs::OpenOptionsExt;

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let base = if dir.is_empty() { "." } else { dir };
    for _ in 0..10_000 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let name = format!("{base}/.tmp-eth-deposit-{}-{nanos}-{n}", std::process::id());
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&name)
        {
            Ok(f) => return Ok((name, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not create a unique temp file",
    ))
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
    use eth_deposit_core::network::{self, Network};

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
            private_key_env_var: DEFAULT_PRIV_KEY_ENV.to_string(),
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
}
