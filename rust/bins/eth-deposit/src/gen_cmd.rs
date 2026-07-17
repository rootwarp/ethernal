//! The `gen` subcommand pipeline, ported from `cmd/eth-deposit/gen.go`: it
//! composes the keystore/bls/deposit/output crates into the deposit_data
//! generator. Dependencies are injectable via [`GenDeps`] so tests can drive
//! the pipeline with fakes.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

use eth_deposit_core::bls::{self, BlsError, Verifier};
use eth_deposit_core::cancel::CancelToken;
use eth_deposit_core::deposit::{self, Entry, Generator, Request};
use eth_deposit_core::network::{self, Network};
use eth_deposit_core::output::{DryRunWriter, FsWriter, Writer as OutputWriter};
use eth_deposit_keystore::{
    scan_dir, DirectoryIndex, EnvSource, KeyLoader, Loader, PassphraseSource, TermPromptSource,
};

use crate::errors::AppError;
use crate::gen_cli::GenConfig;
use crate::logging::{Format, Level, Logger};

/// Mirrors the staking-deposit-cli release used to derive the golden test
/// fixtures. Bump only after golden-file re-validation passes.
pub const CLI_VERSION: &str = "2.7.0";

/// The 32-byte withdrawal credentials for v1: type 0x00 prefix (BLS
/// withdrawal), all other bytes zero. A future --withdrawal-address flag
/// plugs in here.
pub fn default_withdrawal_creds() -> [u8; 32] {
    [0u8; 32]
}

/// How progress is rendered (port of the isTTY branch in gen.go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// stderr is a terminal: single updating line using \r.
    Tty,
    /// Pipe/buffer/CI: one log event per 10% boundary and on the last entry.
    NonTty,
}

/// Injectable dependencies for [`run_gen_with_deps`]. Production values come
/// from [`run_gen`]; tests can replace any piece.
pub struct GenDeps<'a> {
    /// Initialises the BLS library (no-op with blst; kept for parity).
    pub init_bls: &'a (dyn Fn() -> Result<(), String> + Sync),
    /// Scans a keystore directory into a pubkey→path index (no decryption).
    pub scanner: &'a (dyn Fn(&Path) -> std::io::Result<DirectoryIndex> + Sync),
    /// Loads and decrypts a keystore.
    pub loader: &'a (dyn KeyLoader + Sync),
    /// Constructs a BLS signer from a 32-byte secret.
    pub new_signer:
        &'a (dyn Fn(&[u8]) -> Result<Box<dyn bls::Signer + Send>, BlsError> + Sync),
    /// Self-verification for the deposit generator.
    pub verifier: &'a dyn Verifier,
    /// Persists the deposit data JSON.
    pub writer: &'a mut dyn OutputWriter,
    /// Where the success summary line is written (stderr in production).
    pub summary_out: &'a mut dyn Write,
    /// Progress rendering mode for the signing loop.
    pub progress: Progress,
    /// Structured debug/info logging.
    pub logger: &'a Logger,
    /// Post-generation cross-check via the external staking-deposit-cli.
    pub verify_deposit_cli: &'a dyn Fn(&str, &str) -> Result<(), AppError>,
}

/// The testable core of the gen pipeline (port of runGenWithDeps). Wiring
/// order follows the Go implementation exactly.
pub fn run_gen_with_deps(
    cfg: &GenConfig,
    deps: &mut GenDeps<'_>,
    cancel: &CancelToken,
) -> Result<(), AppError> {
    let log = deps.logger;

    // Step 1: initialise the BLS library (process-global, idempotent in Go;
    // a no-op with blst).
    log.debug("bls: initialising library", &[]);
    (deps.init_bls)().map_err(AppError::BlsInit)?;
    log.debug("bls: library ready", &[]);

    // Step 2: resolve network parameters.
    log.debug(
        "network: looking up params",
        &[("network", cfg.network.to_string())],
    );
    let params = network::lookup(cfg.network);
    log.debug(
        "network: params resolved",
        &[
            ("network", params.name.to_string()),
            (
                "genesis_fork_version",
                format!("0x{}", hex::encode(params.genesis_fork_version)),
            ),
        ],
    );

    // Defense-in-depth: re-verify the mainnet acknowledgement inside the
    // pipeline so that non-CLI callers cannot skip the safety gate. The CLI
    // gate fires first for flag-driven calls.
    if cfg.network == Network::Mainnet && !cfg.mainnet_ack {
        log.debug("mainnet: ack not set, aborting", &[]);
        return Err(AppError::MainnetAckRequired);
    }
    if cfg.network == Network::Mainnet {
        log.debug("mainnet: explicit ack verified", &[]);
    }

    // Step 3: scan the keystore directory — no decryption yet.
    log.debug(
        "keystore: scanning directory",
        &[("dir", cfg.keystore_dir.clone())],
    );
    let index = (deps.scanner)(Path::new(&cfg.keystore_dir))
        .map_err(|e| AppError::Internal(e.to_string()))?;
    log.debug(
        "keystore: directory scanned",
        &[("count", index.len().to_string())],
    );

    let env_source;
    let tty_source;
    let pw_src: &(dyn PassphraseSource + Sync) = if !cfg.passphrase_env.is_empty() {
        env_source = EnvSource::new(&cfg.passphrase_env);
        &env_source
    } else {
        tty_source = TermPromptSource::new(std::io::stderr());
        &tty_source
    };

    // Step 4: process pubkeys concurrently using a bounded worker pool.
    let parallel = cfg.parallel.max(1);
    let n = cfg.pubkeys.len();
    let worker_cancel = CancelToken::new();
    let next = AtomicUsize::new(0);
    let next = &next;
    let (res_tx, res_rx) = mpsc::channel::<(usize, Result<Entry, AppError>)>();

    let mut entries: Vec<Option<Entry>> = vec![None; n];
    let mut first_err: Option<AppError> = None;
    let mut done = 0usize;

    std::thread::scope(|s| {
        for _ in 0..parallel {
            let res_tx = res_tx.clone();
            let worker_cancel = worker_cancel.clone();
            let cfg = &*cfg;
            let index = &index;
            let deps_loader = deps.loader;
            let deps_new_signer = deps.new_signer;
            let deps_verifier = deps.verifier;
            let params = params.clone();
            s.spawn(move || loop {
                // Propagate outer (SIGINT) cancellation into the pool.
                if cancel.is_cancelled() {
                    worker_cancel.cancel();
                }
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= n {
                    break;
                }
                if worker_cancel.is_cancelled() {
                    let _ = res_tx.send((i, Err(AppError::Deposit(
                        deposit::DepositError::Cancelled,
                    ))));
                    continue;
                }
                let result = process_pubkey(
                    cfg,
                    index,
                    deps_loader,
                    deps_new_signer,
                    deps_verifier,
                    &params,
                    pw_src,
                    &worker_cancel,
                    i,
                );
                if result.is_err() {
                    worker_cancel.cancel();
                }
                let _ = res_tx.send((i, result));
            });
        }
        drop(res_tx);

        // Collect results, preserving input order via the index. Prefer the
        // first non-cancellation error so the returned error reflects the
        // root cause rather than the cascading cancellation.
        for (idx, res) in res_rx {
            match res {
                Ok(entry) => {
                    entries[idx] = Some(entry);
                    done += 1;
                    if n > 5 {
                        emit_progress(deps.progress, deps.logger, cfg.json_logs, done, n);
                    }
                }
                Err(e) => {
                    let replace = match &first_err {
                        None => true,
                        Some(cur) => is_cancelled_err(cur) && !is_cancelled_err(&e),
                    };
                    if replace {
                        first_err = Some(e);
                    }
                    worker_cancel.cancel();
                }
            }
        }
    });

    if let Some(e) = first_err {
        return Err(e);
    }
    let entries: Vec<Entry> = entries.into_iter().map(|e| e.unwrap()).collect();

    log.debug(
        "deposit: generation complete",
        &[("entry_count", entries.len().to_string())],
    );

    // Step 5: write the deposit data JSON atomically.
    log.debug(
        "output: writing deposit data",
        &[
            ("output_dir", cfg.output_dir.clone()),
            ("entry_count", entries.len().to_string()),
        ],
    );
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (path, sum) = deps
        .writer
        .write(Path::new(&cfg.output_dir), &entries, now_unix)?;
    log.debug(
        "output: written",
        &[("path", path.clone()), ("sha256", sum.clone())],
    );

    // Step 6: optional cross-check with the installed staking-deposit-cli.
    // Skipped in dry-run mode because there is no output file on disk.
    if cfg.verify_with_deposit_cli && !cfg.dry_run {
        log.debug(
            "verify: running deposit CLI cross-check",
            &[
                ("cli_path", cfg.deposit_cli_path.clone()),
                ("output_path", path.clone()),
            ],
        );
        (deps.verify_deposit_cli)(&cfg.deposit_cli_path, &path)?;
        log.debug("verify: deposit CLI cross-check passed", &[]);
    }

    // Success: print the summary line.
    print_gen_summary(deps.summary_out, &path, &sum, entries.len(), cfg.network);
    Ok(())
}

/// One worker unit: keystore lookup → load → BLS signer → generate + verify.
#[allow(clippy::too_many_arguments)]
fn process_pubkey(
    cfg: &GenConfig,
    index: &DirectoryIndex,
    loader: &(dyn KeyLoader + Sync),
    new_signer: &(dyn Fn(&[u8]) -> Result<Box<dyn bls::Signer + Send>, BlsError> + Sync),
    verifier: &dyn Verifier,
    params: &network::Params,
    pw_src: &(dyn PassphraseSource + Sync),
    worker_cancel: &CancelToken,
    i: usize,
) -> Result<Entry, AppError> {
    let pk = cfg.pubkeys[i];
    let pk_hex = hex::encode(pk);

    let keystore_path: PathBuf = match index.lookup(&pk_hex) {
        Some(p) => p.to_path_buf(),
        None => {
            return Err(AppError::KeystoreNotFoundFor {
                pubkey_hex: pk_hex,
                dir: cfg.keystore_dir.clone(),
            });
        }
    };

    let mut key = loader.load(&keystore_path, pw_src)?;

    let signer_result = new_signer(&key.secret);
    // Zeroize immediately after signer construction, even on the error path.
    key.zeroize();
    let signer = signer_result.map_err(AppError::Bls)?;

    let generator = Generator::new(signer.as_ref(), verifier, params.clone());
    let entries = generator.generate(
        &Request {
            network: cfg.network,
            pubkeys: vec![pk],
            withdrawal_credentials: default_withdrawal_creds(),
            amount_gwei: 32_000_000_000,
            deposit_cli_version: CLI_VERSION.to_string(),
        },
        worker_cancel,
    )?;
    Ok(entries.into_iter().next().expect("one entry per request"))
}

fn is_cancelled_err(e: &AppError) -> bool {
    matches!(
        e,
        AppError::Deposit(deposit::DepositError::Cancelled) | AppError::Aborted(_)
    )
}

/// Writes a progress update for the signing loop (port of emitProgress).
///
///   - json_logs: always structured log events (never \r-overwrite).
///   - TTY: overwrite the current line via \r; final newline when done==total.
///   - non-TTY: one log event per new 10-percentile boundary and on the last
///     entry.
fn emit_progress(progress: Progress, logger: &Logger, json_logs: bool, done: usize, total: usize) {
    if json_logs {
        logger.info(
            "signing progress",
            &[("done", done.to_string()), ("total", total.to_string())],
        );
        return;
    }
    match progress {
        Progress::Tty => {
            let mut err = std::io::stderr();
            let _ = write!(err, "\rsigning: {done}/{total}");
            if done == total {
                let _ = writeln!(err);
            }
            let _ = err.flush();
        }
        Progress::NonTty => {
            let pct = done * 100 / total;
            let prev_pct = (done - 1) * 100 / total;
            if pct / 10 > prev_pct / 10 || done == total {
                logger.info(
                    "signing progress",
                    &[("done", done.to_string()), ("total", total.to_string())],
                );
            }
        }
    }
}

/// Writes the success summary line (port of printGenSummary).
/// Format: wrote <path> (sha256=<hex>, n=<count>, network=<name>)\n
/// When path is empty (dry-run), the placeholder "<stdout>" is used.
fn print_gen_summary(w: &mut dyn Write, path: &str, sha256hex: &str, n: usize, net: Network) {
    let display = if path.is_empty() { "<stdout>" } else { path };
    let _ = writeln!(w, "wrote {display} (sha256={sha256hex}, n={n}, network={net})");
}

/// The production implementation of the verify_deposit_cli dep (port of
/// runDepositCLIVerify). Probes PATH availability first: not found →
/// DepositCliNotFound (exit 2); non-zero exit → DepositCliFailed (exit 3)
/// with the combined stdout+stderr in the message.
pub fn run_deposit_cli_verify(cli_path: &str, output_path: &str) -> Result<(), AppError> {
    if let Err(detail) = look_path(cli_path) {
        return Err(AppError::DepositCliNotFound {
            cli_path: cli_path.to_string(),
            detail,
        });
    }
    let out = std::process::Command::new(cli_path)
        .args(["verify", "--input-file", output_path])
        .output()
        .map_err(|e| AppError::DepositCliFailed {
            output: e.to_string(),
        })?;
    if !out.status.success() {
        let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&out.stderr));
        return Err(AppError::DepositCliFailed { output: combined });
    }
    Ok(())
}

/// A minimal exec.LookPath port: names containing a path separator are
/// checked directly; bare names are searched in $PATH.
fn look_path(name: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let is_executable_file = |p: &Path| {
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };
    if name.contains('/') {
        if is_executable_file(Path::new(name)) {
            return Ok(());
        }
        return Err(format!("stat {name}: no such file or directory"));
    }
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        if is_executable_file(&dir.join(name)) {
            return Ok(());
        }
    }
    Err("executable file not found in $PATH".to_string())
}

/// Builds the gen logger from the verbose/json-logs flags (port of
/// buildGenLogger); output goes to stderr.
pub fn build_gen_logger(verbose: bool, json_logs: bool) -> Logger {
    let level = if verbose { Level::Debug } else { Level::Info };
    let format = if json_logs { Format::Json } else { Format::Text };
    Logger::stderr(level, format)
}

/// Reports whether stderr is connected to a terminal.
fn stderr_is_tty() -> bool {
    // SAFETY: isatty is async-signal-safe and has no preconditions.
    unsafe { libc::isatty(2) == 1 }
}

/// The production entry point for the gen subcommand (port of runGen):
/// assembles production deps and delegates to [`run_gen_with_deps`].
pub fn run_gen(cfg: &GenConfig, cancel: &CancelToken) -> Result<(), AppError> {
    let logger = build_gen_logger(cfg.verbose, cfg.json_logs);
    let loader = Loader::new();
    let init_bls = || bls::init().map_err(|e| e.to_string());
    let scanner = |dir: &Path| scan_dir(dir);
    let new_signer = |secret: &[u8]| {
        bls::new_signer(secret).map(|s| Box::new(s) as Box<dyn bls::Signer + Send>)
    };
    let verifier = bls::default_verifier();
    let progress = if stderr_is_tty() {
        Progress::Tty
    } else {
        Progress::NonTty
    };
    let mut summary_out = std::io::stderr();
    let verify = run_deposit_cli_verify;

    let mut run = |writer: &mut dyn OutputWriter| {
        let mut deps = GenDeps {
            init_bls: &init_bls,
            scanner: &scanner,
            loader: &loader,
            new_signer: &new_signer,
            verifier: &verifier,
            writer,
            summary_out: &mut summary_out,
            progress,
            logger: &logger,
            verify_deposit_cli: &verify,
        };
        run_gen_with_deps(cfg, &mut deps, cancel)
    };

    if cfg.dry_run {
        run(&mut DryRunWriter::new(std::io::stdout()))
    } else {
        run(&mut FsWriter::new())
    }
}
