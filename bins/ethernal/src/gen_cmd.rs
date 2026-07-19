//! The `gen` subcommand pipeline, ported from `cmd/ethernal/gen.go`: it
//! composes the keystore/bls/deposit/output crates into the deposit_data
//! generator. Dependencies are injectable via [`GenDeps`] so tests can drive
//! the pipeline with fakes.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

use ethernal_core::bls::{self, BlsError, Verifier};
use ethernal_core::cancel::CancelToken;
use ethernal_core::deposit::{self, Entry, Generator, Request};
use ethernal_core::network::{self, Network};
use ethernal_core::output::{DryRunWriter, FsWriter, Writer as OutputWriter};
use ethernal_keystore::{
    scan_dir, DirectoryIndex, EnvSource, KeyLoader, Loader, PassphraseSource, TermPromptSource,
};

use crate::errors::AppError;
use crate::fs_util::stderr_is_tty;
use crate::gen_cli::GenConfig;
use crate::logging::{Format, Level, Logger};

/// Mirrors the staking-deposit-cli release used to derive the golden test
/// fixtures. Bump only after golden-file re-validation passes.
pub const CLI_VERSION: &str = "2.7.0";

/// The 32-byte withdrawal credentials placeholder for the deferred 0x00 BLS
/// withdrawal path (F-14): type 0x00 prefix with an all-zero body.
///
/// Unreachable under the require-choice gate on `--withdrawal-address` (K5-2);
/// kept as the documented hook for a future 0x00 credential mode.
#[allow(dead_code)] // intentionally retained as the F-14 / 0x00 placeholder (K5-2)
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
    #[allow(clippy::type_complexity)]
    pub new_signer: &'a (dyn Fn(&[u8]) -> Result<Box<dyn bls::Signer + Send>, BlsError> + Sync),
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

    // Defense-in-depth: refuse placeholder / burn withdrawal credentials so a
    // non-CLI GenConfig constructor cannot mint permanent-loss deposit data.
    // Safe for a future 0x00-BLS mode (a real 0x00 cred has a non-zero BLS-key
    // hash tail, not the all-zero placeholder).
    if cfg.withdrawal_credentials == [0u8; 32] {
        log.debug("withdrawal credentials: all-zero placeholder rejected", &[]);
        return Err(AppError::exit2(
            "withdrawal credentials: all-zero credentials are not allowed (placeholder)",
        ));
    }
    if cfg.withdrawal_credentials[0] == 0x01
        && cfg.withdrawal_credentials[12..].iter().all(|&b| b == 0)
    {
        log.debug("withdrawal credentials: 0x01 burn address rejected", &[]);
        return Err(AppError::exit2(
            "withdrawal credentials: 0x01 credentials with zero address are not allowed (burn address)",
        ));
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
    // (index, error): keep the lowest-index non-cancellation error so the
    // reported exit code is stable under worker scheduling. Prefer a real
    // error over cascading cancellation (same preference as before).
    let mut selected_err: Option<(usize, AppError)> = None;
    let mut done = 0usize;

    std::thread::scope(|s| {
        for _ in 0..parallel {
            let res_tx = res_tx.clone();
            let worker_cancel = worker_cancel.clone();
            #[allow(clippy::borrow_deref_ref)]
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
                    let _ =
                        res_tx.send((i, Err(AppError::Deposit(deposit::DepositError::Cancelled))));
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

        // Collect results, preserving input order via the index.
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
                    let replace = match &selected_err {
                        None => true,
                        Some((cur_idx, cur_err)) => {
                            let cur_cancel = is_cancelled_err(cur_err);
                            let new_cancel = is_cancelled_err(&e);
                            if cur_cancel && !new_cancel {
                                // Prefer a real failure over cascading cancel.
                                true
                            } else if !cur_cancel && new_cancel {
                                false
                            } else {
                                // Same class: lowest index wins (stable under scheduling).
                                idx < *cur_idx
                            }
                        }
                    };
                    if replace {
                        selected_err = Some((idx, e));
                    }
                    worker_cancel.cancel();
                }
            }
        }
    });

    if let Some((_, e)) = selected_err {
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
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
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
            withdrawal_credentials: cfg.withdrawal_credentials,
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
    let _ = writeln!(
        w,
        "wrote {display} (sha256={sha256hex}, n={n}, network={net})"
    );
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
    let format = if json_logs {
        Format::Json
    } else {
        Format::Text
    };
    Logger::stderr(level, format)
}

/// The production entry point for the gen subcommand (port of runGen):
/// assembles production deps and delegates to [`run_gen_with_deps`].
pub fn run_gen(cfg: &GenConfig, cancel: &CancelToken) -> Result<(), AppError> {
    let logger = build_gen_logger(cfg.verbose, cfg.json_logs);
    let loader = Loader::new();
    let init_bls = || bls::init().map_err(|e| e.to_string());
    let scanner = |dir: &Path| scan_dir(dir);
    let new_signer =
        |secret: &[u8]| bls::new_signer(secret).map(|s| Box::new(s) as Box<dyn bls::Signer + Send>);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::exit_code_for;
    use crate::test_support::Tmp;
    use ethernal_core::bls::Signer;
    use ethernal_core::output::OutputError;
    use ethernal_keystore::{Key, KeystoreError};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    // Port of `cmd/ethernal/gen_test.go` `runGenWithDeps` tests: the gen
    // pipeline driven with fakes through the `GenDeps` seam. Since the Rust
    // `DirectoryIndex` has no public constructor, the "scanner" is either a
    // closure returning `DirectoryIndex::default()` / `scan_dir` over a temp dir
    // of `{"pubkey":...}` files, or an error closure.
    //
    // NOT PORTED from gen_test.go: `TestMain_BuildsCleanly` (cargo builds the
    // binary implicitly), `TestNoSlogImportInSigningPackages` (a Go source-import
    // lint with no Rust analogue), `BenchmarkRunGenWithDeps_Parallel`, and the
    // pick*/productionGenDeps helper tests (Rust wires these inline in `run_gen`).
    // The `progressOut` buffer has no Rust field: the non-TTY path logs via the
    // `Logger` (asserted below); the TTY path writes to real stderr.

    // --- fakes ---

    struct FakeSigner {
        pubkey: [u8; 48],
        sig: [u8; 96],
    }
    impl Signer for FakeSigner {
        fn sign(&self, _root: [u8; 32]) -> Result<[u8; 96], BlsError> {
            Ok(self.sig)
        }
        fn public_key(&self) -> Result<[u8; 48], BlsError> {
            Ok(self.pubkey)
        }
    }

    struct FakeVerifier {
        ok: bool,
    }
    impl Verifier for FakeVerifier {
        fn verify(&self, _pk: [u8; 48], _root: [u8; 32], _sig: [u8; 96]) -> Result<bool, BlsError> {
            Ok(self.ok)
        }
    }

    struct FakeLoader {
        #[allow(clippy::type_complexity)]
        f: Box<dyn Fn(&Path) -> Result<Key, KeystoreError> + Sync>,
    }
    impl KeyLoader for FakeLoader {
        fn load(&self, path: &Path, _pw: &dyn PassphraseSource) -> Result<Key, KeystoreError> {
            (self.f)(path)
        }
    }

    struct FakeWriter {
        path: String,
        sha: String,
        err: bool,
    }
    impl OutputWriter for FakeWriter {
        fn write(
            &mut self,
            _dir: &Path,
            _entries: &[Entry],
            _now: i64,
        ) -> Result<(String, String), OutputError> {
            if self.err {
                return Err(OutputError::WriteDryRun(std::io::Error::other("disk full")));
            }
            Ok((self.path.clone(), self.sha.clone()))
        }
    }

    struct CapturingWriter {
        entries: Arc<Mutex<Vec<Entry>>>,
    }
    impl OutputWriter for CapturingWriter {
        fn write(
            &mut self,
            _dir: &Path,
            entries: &[Entry],
            _now: i64,
        ) -> Result<(String, String), OutputError> {
            *self.entries.lock().unwrap() = entries.to_vec();
            Ok(("/out/deposit_data.json".to_string(), "cafebabe".to_string()))
        }
    }

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn discard_logger() -> Logger {
        Logger::new(Level::Error, Format::Text, Box::new(std::io::sink()))
    }

    /// N distinct pubkeys where `pk[i][0] == i+1`.
    fn multi_pks(n: usize) -> Vec<[u8; 48]> {
        (0..n)
            .map(|i| {
                let mut p = [0u8; 48];
                p[0] = (i + 1) as u8;
                p
            })
            .collect()
    }

    /// Writes `{"pubkey":...}` files for `pks` into a fresh temp dir and returns
    /// a real `DirectoryIndex` over them (mapping pubkey → path).
    fn index_over(pks: &[[u8; 48]]) -> (Tmp, DirectoryIndex) {
        let dir = Tmp::new("gen-cmd-test");
        for (i, pk) in pks.iter().enumerate() {
            let content = format!("{{\"pubkey\":\"{}\"}}", hex::encode(pk));
            std::fs::write(dir.0.join(format!("{i}.json")), content).unwrap();
        }
        let idx = scan_dir(&dir.0).expect("scan_dir");
        (dir, idx)
    }

    /// A loader that derives `secret[0]` from the keystore file's pubkey, used
    /// with `signers_for` so each pubkey routes to its own signer.
    fn routing_loader() -> FakeLoader {
        FakeLoader {
            f: Box::new(|path: &Path| {
                let raw = std::fs::read(path).map_err(|e| KeystoreError::ReadFile {
                    path: path.display().to_string(),
                    source: e,
                })?;
                let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                let pkhex = v["pubkey"].as_str().unwrap().to_string();
                let first = u8::from_str_radix(&pkhex[..2], 16).unwrap();
                let mut secret = vec![0u8; 32];
                secret[0] = first;
                Ok(Key {
                    secret,
                    pubkey_hex: pkhex,
                })
            }),
        }
    }

    /// A `new_signer` map: `secret[0] == i+1` selects a signer whose pubkey is
    /// `pks[i]` and whose signature's first byte is `i+1` (distinct per key).
    fn signer_map(pks: &[[u8; 48]]) -> HashMap<u8, FakeSigner> {
        let mut m = HashMap::new();
        for pk in pks {
            let mut sig = [0u8; 96];
            sig[0] = pk[0];
            m.insert(pk[0], FakeSigner { pubkey: *pk, sig });
        }
        m
    }

    fn base_cfg(pks: Vec<[u8; 48]>) -> GenConfig {
        // Known EIP-55 address from signer tests → 0x01 creds for pipeline tests.
        let addr = [
            0x1a, 0x64, 0x2f, 0x0e, 0x3c, 0x3a, 0xf5, 0x45, 0xe7, 0xac, 0xbd, 0x38, 0xb0, 0x72,
            0x51, 0xb3, 0x99, 0x09, 0x14, 0xf1,
        ];
        GenConfig {
            keystore_dir: "/fake/keystores".to_string(),
            pubkeys: pks,
            network: Network::Hoodi,
            output_dir: "/tmp".to_string(),
            passphrase_env: String::new(),
            mainnet_ack: false,
            dry_run: false,
            verbose: false,
            json_logs: false,
            parallel: 1,
            verify_with_deposit_cli: false,
            deposit_cli_path: "deposit".to_string(),
            withdrawal_credentials: deposit::eth1_withdrawal_credentials(addr),
        }
    }

    // --- single-pubkey success + error-path tests ---

    // Go: TestRunGenWithDeps_Success_ExitCode0 + _PrintsSummary.
    #[test]
    fn success_prints_summary() {
        let pks = multi_pks(1);
        let (_dir, idx) = index_over(&pks);
        let signers = signer_map(&pks);
        let loader = routing_loader();
        let verifier = FakeVerifier { ok: true };
        let mut writer = FakeWriter {
            path: "/out/deposit_data-99.json".into(),
            sha: "deadbeef99".into(),
            err: false,
        };
        let mut summary = Vec::<u8>::new();
        let logger = discard_logger();
        let init_bls = || Ok(());
        let scanner = move |_: &Path| Ok(idx.clone());
        let new_signer = |secret: &[u8]| -> Result<Box<dyn Signer + Send>, BlsError> {
            let s = &signers[&secret[0]];
            Ok(Box::new(FakeSigner {
                pubkey: s.pubkey,
                sig: s.sig,
            }))
        };
        let verify = |_: &str, _: &str| Ok(());

        let cfg = base_cfg(pks);
        {
            let mut deps = GenDeps {
                init_bls: &init_bls,
                scanner: &scanner,
                loader: &loader,
                new_signer: &new_signer,
                verifier: &verifier,
                writer: &mut writer,
                summary_out: &mut summary,
                progress: Progress::NonTty,
                logger: &logger,
                verify_deposit_cli: &verify,
            };
            run_gen_with_deps(&cfg, &mut deps, &CancelToken::new()).expect("success");
        }
        let s = String::from_utf8(summary).unwrap();
        assert!(s.contains("wrote /out/deposit_data-99.json"), "{s}");
        assert!(s.contains("sha256=deadbeef99"), "{s}");
        assert!(s.contains("network=hoodi"), "{s}");
    }

    /// Runs the pipeline with a single pubkey and the given overrides, returning
    /// the classified error (or panicking on unexpected success/failure).
    fn run_expect_err(
        cfg_mut: impl FnOnce(&mut GenConfig),
        scanner: &(dyn Fn(&Path) -> std::io::Result<DirectoryIndex> + Sync),
        loader: &(dyn KeyLoader + Sync),
        verifier: &dyn Verifier,
        writer: &mut dyn OutputWriter,
        init_bls: &(dyn Fn() -> Result<(), String> + Sync),
        cancel: &CancelToken,
    ) -> AppError {
        let pks = multi_pks(1);
        let signers = signer_map(&pks);
        let new_signer = |secret: &[u8]| -> Result<Box<dyn Signer + Send>, BlsError> {
            let s = &signers[&secret[0]];
            Ok(Box::new(FakeSigner {
                pubkey: s.pubkey,
                sig: s.sig,
            }))
        };
        let verify = |_: &str, _: &str| Ok(());
        let mut summary = Vec::<u8>::new();
        let logger = discard_logger();
        let mut cfg = base_cfg(pks);
        cfg_mut(&mut cfg);
        let mut deps = GenDeps {
            init_bls,
            scanner,
            loader,
            new_signer: &new_signer,
            verifier,
            writer,
            summary_out: &mut summary,
            progress: Progress::NonTty,
            logger: &logger,
            verify_deposit_cli: &verify,
        };
        run_gen_with_deps(&cfg, &mut deps, cancel).expect_err("expected error")
    }

    // Go: TestRunGenWithDeps_BLSInitError_ExitCode3.
    #[test]
    fn bls_init_error_exit3() {
        let pks = multi_pks(1);
        let (_dir, idx) = index_over(&pks);
        let loader = routing_loader();
        let verifier = FakeVerifier { ok: true };
        let mut writer = FakeWriter {
            path: "/out".into(),
            sha: "x".into(),
            err: false,
        };
        let init_bls = || Err("herumi init failure".to_string());
        let scanner = move |_: &Path| Ok(idx.clone());
        let err = run_expect_err(
            |_| {},
            &scanner,
            &loader,
            &verifier,
            &mut writer,
            &init_bls,
            &CancelToken::new(),
        );
        assert_eq!(exit_code_for(&err), 3);
    }

    // Go: TestRunGenWithDeps_KeystoreLoadError_ExitCode2.
    #[test]
    fn keystore_load_error_exit2() {
        let pks = multi_pks(1);
        let (_dir, idx) = index_over(&pks);
        let loader = FakeLoader {
            f: Box::new(|_| {
                Err(KeystoreError::KeystoreMissing {
                    path: "/fake/ks.json".into(),
                })
            }),
        };
        let verifier = FakeVerifier { ok: true };
        let mut writer = FakeWriter {
            path: "/out".into(),
            sha: "x".into(),
            err: false,
        };
        let init_bls = || Ok(());
        let scanner = move |_: &Path| Ok(idx.clone());
        let err = run_expect_err(
            |_| {},
            &scanner,
            &loader,
            &verifier,
            &mut writer,
            &init_bls,
            &CancelToken::new(),
        );
        assert_eq!(exit_code_for(&err), 2);
    }

    // Go: TestRunGenWithDeps_WrongPassphrase_ExitCode3.
    #[test]
    fn wrong_passphrase_exit3() {
        let pks = multi_pks(1);
        let (_dir, idx) = index_over(&pks);
        let loader = FakeLoader {
            f: Box::new(|_| {
                Err(KeystoreError::WrongPassphrase {
                    detail: "bad checksum".into(),
                })
            }),
        };
        let verifier = FakeVerifier { ok: true };
        let mut writer = FakeWriter {
            path: "/out".into(),
            sha: "x".into(),
            err: false,
        };
        let init_bls = || Ok(());
        let scanner = move |_: &Path| Ok(idx.clone());
        let err = run_expect_err(
            |_| {},
            &scanner,
            &loader,
            &verifier,
            &mut writer,
            &init_bls,
            &CancelToken::new(),
        );
        assert_eq!(exit_code_for(&err), 3);
    }

    // Go: TestRunGenWithDeps_PubkeyMismatch_ExitCode2 — the signer returns a
    // different pubkey than requested.
    #[test]
    fn pubkey_mismatch_exit2() {
        let mut wrong = [0u8; 48];
        wrong[0] = 0xBB;
        let (_dir, idx) = index_over(&[wrong]);
        let loader = routing_loader();
        let verifier = FakeVerifier { ok: true };
        let mut writer = FakeWriter {
            path: "/out".into(),
            sha: "x".into(),
            err: false,
        };
        let init_bls = || Ok(());
        let scanner = move |_: &Path| Ok(idx.clone());
        // new_signer always returns pubkey 0xAB, mismatching the requested 0xBB.
        let mut ab = [0u8; 48];
        ab[0] = 0xAB;
        let new_signer = move |_: &[u8]| -> Result<Box<dyn Signer + Send>, BlsError> {
            Ok(Box::new(FakeSigner {
                pubkey: ab,
                sig: [0u8; 96],
            }))
        };
        let verify = |_: &str, _: &str| Ok(());
        let mut summary = Vec::<u8>::new();
        let logger = discard_logger();
        let cfg = base_cfg(vec![wrong]);
        let mut deps = GenDeps {
            init_bls: &init_bls,
            scanner: &scanner,
            loader: &loader,
            new_signer: &new_signer,
            verifier: &verifier,
            writer: &mut writer,
            summary_out: &mut summary,
            progress: Progress::NonTty,
            logger: &logger,
            verify_deposit_cli: &verify,
        };
        let err = run_gen_with_deps(&cfg, &mut deps, &CancelToken::new()).unwrap_err();
        assert_eq!(exit_code_for(&err), 2);
        assert!(matches!(
            err,
            AppError::Deposit(deposit::DepositError::PubkeyMismatch { .. })
        ));
    }

    // Go: TestRunGenWithDeps_WriterError_ExitCode1.
    #[test]
    fn writer_error_exit1() {
        let pks = multi_pks(1);
        let (_dir, idx) = index_over(&pks);
        let loader = routing_loader();
        let verifier = FakeVerifier { ok: true };
        let mut writer = FakeWriter {
            path: String::new(),
            sha: String::new(),
            err: true,
        };
        let init_bls = || Ok(());
        let scanner = move |_: &Path| Ok(idx.clone());
        let err = run_expect_err(
            |_| {},
            &scanner,
            &loader,
            &verifier,
            &mut writer,
            &init_bls,
            &CancelToken::new(),
        );
        assert_eq!(exit_code_for(&err), 1);
    }

    // Go: TestRunGenWithDeps_ScannerError_ExitCode1.
    #[test]
    fn scanner_error_exit1() {
        let loader = routing_loader();
        let verifier = FakeVerifier { ok: true };
        let mut writer = FakeWriter {
            path: "/out".into(),
            sha: "x".into(),
            err: false,
        };
        let init_bls = || Ok(());
        let scanner = |_: &Path| Err(std::io::Error::other("permission denied"));
        let err = run_expect_err(
            |_| {},
            &scanner,
            &loader,
            &verifier,
            &mut writer,
            &init_bls,
            &CancelToken::new(),
        );
        assert_eq!(exit_code_for(&err), 1);
    }

    // Go: TestRunGenWithDeps_PubkeyNotInIndex_ExitCode2 + _ErrorMessageContainsPubkeyAndDir.
    #[test]
    fn pubkey_not_in_index_exit2() {
        let loader = routing_loader();
        let verifier = FakeVerifier { ok: true };
        let mut writer = FakeWriter {
            path: "/out".into(),
            sha: "x".into(),
            err: false,
        };
        let init_bls = || Ok(());
        let scanner = |_: &Path| Ok(DirectoryIndex::default()); // empty
        let err = run_expect_err(
            |c| c.keystore_dir = "/fake/keystores".to_string(),
            &scanner,
            &loader,
            &verifier,
            &mut writer,
            &init_bls,
            &CancelToken::new(),
        );
        assert_eq!(exit_code_for(&err), 2);
        let msg = err.to_string();
        assert!(msg.contains("0x"), "message should name the pubkey: {msg}");
        assert!(
            msg.contains("/fake/keystores"),
            "message should name the dir: {msg}"
        );
    }

    // Go: TestRunGenWithDeps_ContextCanceled_ExitCode4 — a pre-cancelled token
    // short-circuits before the loader is even called.
    #[test]
    fn context_canceled_exit4() {
        let pks = multi_pks(1);
        let (_dir, idx) = index_over(&pks);
        let loader = routing_loader();
        let verifier = FakeVerifier { ok: true };
        let mut writer = FakeWriter {
            path: "/out".into(),
            sha: "x".into(),
            err: false,
        };
        let init_bls = || Ok(());
        let scanner = move |_: &Path| Ok(idx.clone());
        let cancel = CancelToken::new();
        cancel.cancel();
        let err = run_expect_err(
            |_| {},
            &scanner,
            &loader,
            &verifier,
            &mut writer,
            &init_bls,
            &cancel,
        );
        assert_eq!(exit_code_for(&err), 4);
    }

    // Go: TestRunGenWithDeps_DryRun_VerifyFailureAbortsWithSameExitCode — the
    // self-verifier failing → exit 3.
    #[test]
    fn self_verify_failed_exit3() {
        let pks = multi_pks(1);
        let (_dir, idx) = index_over(&pks);
        let loader = routing_loader();
        let verifier = FakeVerifier { ok: false }; // self-verify fails
        let mut writer = FakeWriter {
            path: "/out".into(),
            sha: "x".into(),
            err: false,
        };
        let init_bls = || Ok(());
        let scanner = move |_: &Path| Ok(idx.clone());
        let err = run_expect_err(
            |_| {},
            &scanner,
            &loader,
            &verifier,
            &mut writer,
            &init_bls,
            &CancelToken::new(),
        );
        assert_eq!(exit_code_for(&err), 3);
        assert!(matches!(
            err,
            AppError::Deposit(deposit::DepositError::SelfVerifyFailed { .. })
        ));
    }

    // --- verify-with-deposit-cli seam (Go: TestVerifyDepositCLI_*) ---

    fn run_with_verify(
        verify_with_cli: bool,
        dry_run: bool,
        verify: &dyn Fn(&str, &str) -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        let pks = multi_pks(1);
        let (_dir, idx) = index_over(&pks);
        let signers = signer_map(&pks);
        let loader = routing_loader();
        let verifier = FakeVerifier { ok: true };
        let mut writer = FakeWriter {
            path: "/out/deposit_data-1.json".into(),
            sha: "cafebabe".into(),
            err: false,
        };
        let mut dry = DryRunWriter::new(Vec::<u8>::new());
        let mut summary = Vec::<u8>::new();
        let logger = discard_logger();
        let init_bls = || Ok(());
        let scanner = move |_: &Path| Ok(idx.clone());
        let new_signer = |secret: &[u8]| -> Result<Box<dyn Signer + Send>, BlsError> {
            let s = &signers[&secret[0]];
            Ok(Box::new(FakeSigner {
                pubkey: s.pubkey,
                sig: s.sig,
            }))
        };
        let mut cfg = base_cfg(pks);
        cfg.verify_with_deposit_cli = verify_with_cli;
        cfg.dry_run = dry_run;
        let writer_ref: &mut dyn OutputWriter = if dry_run { &mut dry } else { &mut writer };
        let mut deps = GenDeps {
            init_bls: &init_bls,
            scanner: &scanner,
            loader: &loader,
            new_signer: &new_signer,
            verifier: &verifier,
            writer: writer_ref,
            summary_out: &mut summary,
            progress: Progress::NonTty,
            logger: &logger,
            verify_deposit_cli: verify,
        };
        run_gen_with_deps(&cfg, &mut deps, &CancelToken::new())
    }

    #[test]
    fn verify_cli_not_called_when_flag_false() {
        let verify = |_: &str, _: &str| -> Result<(), AppError> { panic!("must not be called") };
        run_with_verify(false, false, &verify).expect("ok");
    }

    #[test]
    fn verify_cli_called_when_flag_true() {
        let called = AtomicBool::new(false);
        let verify = |_: &str, _: &str| -> Result<(), AppError> {
            called.store(true, Ordering::SeqCst);
            Ok(())
        };
        run_with_verify(true, false, &verify).expect("ok");
        assert!(
            called.load(Ordering::SeqCst),
            "verify should have been called"
        );
    }

    #[test]
    fn verify_cli_not_found_exit2() {
        let verify = |_: &str, _: &str| -> Result<(), AppError> {
            Err(AppError::DepositCliNotFound {
                cli_path: "deposit".into(),
                detail: "not found in PATH".into(),
            })
        };
        let err = run_with_verify(true, false, &verify).unwrap_err();
        assert_eq!(exit_code_for(&err), 2);
    }

    #[test]
    fn verify_cli_failed_exit3() {
        let verify = |_: &str, _: &str| -> Result<(), AppError> {
            Err(AppError::DepositCliFailed {
                output: "deposit exited 1".into(),
            })
        };
        let err = run_with_verify(true, false, &verify).unwrap_err();
        assert_eq!(exit_code_for(&err), 3);
    }

    #[test]
    fn verify_cli_skipped_in_dry_run() {
        let verify =
            |_: &str, _: &str| -> Result<(), AppError> { panic!("must not run in dry-run") };
        run_with_verify(true, true, &verify).expect("ok");
    }

    // --- dry-run stdout + sha (Go: TestRunGenWithDeps_DryRun_StdoutContainsJSON) ---

    #[test]
    fn dry_run_stdout_json_and_sha_match() {
        use sha2::{Digest, Sha256};
        let pks = multi_pks(1);
        let (_dir, idx) = index_over(&pks);
        let signers = signer_map(&pks);
        let loader = routing_loader();
        let verifier = FakeVerifier { ok: true };
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let mut dry = DryRunWriter::new(SharedWriter(Arc::clone(&buf)));
        let mut summary = Vec::<u8>::new();
        let logger = discard_logger();
        let init_bls = || Ok(());
        let scanner = move |_: &Path| Ok(idx.clone());
        let new_signer = |secret: &[u8]| -> Result<Box<dyn Signer + Send>, BlsError> {
            let s = &signers[&secret[0]];
            Ok(Box::new(FakeSigner {
                pubkey: s.pubkey,
                sig: s.sig,
            }))
        };
        let verify = |_: &str, _: &str| Ok(());
        let mut cfg = base_cfg(pks);
        cfg.dry_run = true;
        {
            let mut deps = GenDeps {
                init_bls: &init_bls,
                scanner: &scanner,
                loader: &loader,
                new_signer: &new_signer,
                verifier: &verifier,
                writer: &mut dry,
                summary_out: &mut summary,
                progress: Progress::NonTty,
                logger: &logger,
                verify_deposit_cli: &verify,
            };
            run_gen_with_deps(&cfg, &mut deps, &CancelToken::new()).expect("ok");
        }
        let stdout = buf.lock().unwrap().clone();
        serde_json::from_slice::<serde_json::Value>(&stdout).expect("stdout is JSON");
        let want_sha = hex::encode(Sha256::digest(&stdout));
        let s = String::from_utf8(summary).unwrap();
        assert!(
            s.contains(&format!("sha256={want_sha}")),
            "summary sha must match stdout: {s}"
        );
        assert!(
            s.contains("wrote <stdout>"),
            "dry-run summary uses <stdout>: {s}"
        );
    }

    // --- parallel determinism (Go: TestRunGenWithDeps_Parallel) ---

    #[test]
    fn parallel_determinism_and_order() {
        let pks = multi_pks(3);
        let mut results: Vec<Vec<Entry>> = Vec::new();
        for parallel in [1usize, 2, 3] {
            let (_dir, idx) = index_over(&pks);
            let signers = signer_map(&pks);
            let loader = routing_loader();
            let verifier = FakeVerifier { ok: true };
            let captured = Arc::new(Mutex::new(Vec::<Entry>::new()));
            let mut writer = CapturingWriter {
                entries: Arc::clone(&captured),
            };
            let mut summary = Vec::<u8>::new();
            let logger = discard_logger();
            let init_bls = || Ok(());
            let scanner = move |_: &Path| Ok(idx.clone());
            let new_signer = |secret: &[u8]| -> Result<Box<dyn Signer + Send>, BlsError> {
                let s = &signers[&secret[0]];
                Ok(Box::new(FakeSigner {
                    pubkey: s.pubkey,
                    sig: s.sig,
                }))
            };
            let verify = |_: &str, _: &str| Ok(());
            let mut cfg = base_cfg(pks.clone());
            cfg.parallel = parallel;
            {
                let mut deps = GenDeps {
                    init_bls: &init_bls,
                    scanner: &scanner,
                    loader: &loader,
                    new_signer: &new_signer,
                    verifier: &verifier,
                    writer: &mut writer,
                    summary_out: &mut summary,
                    progress: Progress::NonTty,
                    logger: &logger,
                    verify_deposit_cli: &verify,
                };
                run_gen_with_deps(&cfg, &mut deps, &CancelToken::new()).expect("ok");
            }
            results.push(captured.lock().unwrap().clone());
        }
        // All parallelism levels produce identical entry slices.
        assert_eq!(results[0], results[1]);
        assert_eq!(results[0], results[2]);
        // Order matches cfg.pubkeys order.
        for (j, e) in results[0].iter().enumerate() {
            assert_eq!(e.pubkey, pks[j], "entry {j} out of order");
        }
    }

    // Go: TestRunGenWithDeps_ParallelWorkerError — a failing worker propagates the
    // first non-cancellation error.
    #[test]
    fn parallel_worker_error() {
        let pks = multi_pks(3);
        let (_dir, idx) = index_over(&pks);
        // Fail the load for the file backing pubkey index 1 (path ".../1.json").
        let loader = FakeLoader {
            f: Box::new(|path: &Path| {
                if path.file_name().unwrap().to_string_lossy() == "1.json" {
                    return Err(KeystoreError::KeystoreMissing {
                        path: path.display().to_string(),
                    });
                }
                let raw = std::fs::read(path).unwrap();
                let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                let pkhex = v["pubkey"].as_str().unwrap().to_string();
                let first = u8::from_str_radix(&pkhex[..2], 16).unwrap();
                let mut secret = vec![0u8; 32];
                secret[0] = first;
                Ok(Key {
                    secret,
                    pubkey_hex: pkhex,
                })
            }),
        };
        let signers = signer_map(&pks);
        let verifier = FakeVerifier { ok: true };
        let mut writer = FakeWriter {
            path: "/out".into(),
            sha: "x".into(),
            err: false,
        };
        let mut summary = Vec::<u8>::new();
        let logger = discard_logger();
        let init_bls = || Ok(());
        let scanner = move |_: &Path| Ok(idx.clone());
        let new_signer = |secret: &[u8]| -> Result<Box<dyn Signer + Send>, BlsError> {
            let s = &signers[&secret[0]];
            Ok(Box::new(FakeSigner {
                pubkey: s.pubkey,
                sig: s.sig,
            }))
        };
        let verify = |_: &str, _: &str| Ok(());
        let mut cfg = base_cfg(pks);
        cfg.parallel = 2;
        let mut deps = GenDeps {
            init_bls: &init_bls,
            scanner: &scanner,
            loader: &loader,
            new_signer: &new_signer,
            verifier: &verifier,
            writer: &mut writer,
            summary_out: &mut summary,
            progress: Progress::NonTty,
            logger: &logger,
            verify_deposit_cli: &verify,
        };
        let err = run_gen_with_deps(&cfg, &mut deps, &CancelToken::new()).unwrap_err();
        // The propagated error is the keystore-missing (exit 2), not a cancellation.
        assert_eq!(exit_code_for(&err), 2);
    }

    // H4 / K5-L3: heterogeneous per-pubkey failures report the lowest-index
    // non-cancellation error stably (not first-received under scheduling).
    #[test]
    fn heterogeneous_failures_report_lowest_index() {
        let pks = multi_pks(3);
        // Index 0 → WrongPassphrase (exit 3); index 2 → KeystoreMissing (exit 2).
        // Index 1 succeeds. Lowest real error must win regardless of arrival order.
        let loader = FakeLoader {
            f: Box::new(|path: &Path| {
                let name = path.file_name().unwrap().to_string_lossy();
                if name == "0.json" {
                    return Err(KeystoreError::WrongPassphrase {
                        detail: "bad checksum".into(),
                    });
                }
                if name == "2.json" {
                    return Err(KeystoreError::KeystoreMissing {
                        path: path.display().to_string(),
                    });
                }
                let raw = std::fs::read(path).unwrap();
                let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                let pkhex = v["pubkey"].as_str().unwrap().to_string();
                let first = u8::from_str_radix(&pkhex[..2], 16).unwrap();
                let mut secret = vec![0u8; 32];
                secret[0] = first;
                Ok(Key {
                    secret,
                    pubkey_hex: pkhex,
                })
            }),
        };
        let signers = signer_map(&pks);
        let verifier = FakeVerifier { ok: true };
        let init_bls = || Ok(());
        let new_signer = |secret: &[u8]| -> Result<Box<dyn Signer + Send>, BlsError> {
            let s = &signers[&secret[0]];
            Ok(Box::new(FakeSigner {
                pubkey: s.pubkey,
                sig: s.sig,
            }))
        };
        let verify = |_: &str, _: &str| Ok(());
        let logger = discard_logger();

        // Repeat under max parallelism so first-received selection would flake.
        for _ in 0..20 {
            let (_dir, idx) = index_over(&pks);
            let scanner = move |_: &Path| Ok(idx.clone());
            let mut writer = FakeWriter {
                path: "/out".into(),
                sha: "x".into(),
                err: false,
            };
            let mut summary = Vec::<u8>::new();
            let mut cfg = base_cfg(pks.clone());
            cfg.parallel = 3;
            let mut deps = GenDeps {
                init_bls: &init_bls,
                scanner: &scanner,
                loader: &loader,
                new_signer: &new_signer,
                verifier: &verifier,
                writer: &mut writer,
                summary_out: &mut summary,
                progress: Progress::NonTty,
                logger: &logger,
                verify_deposit_cli: &verify,
            };
            let err = run_gen_with_deps(&cfg, &mut deps, &CancelToken::new()).unwrap_err();
            assert_eq!(
                exit_code_for(&err),
                3,
                "lowest-index real error is WrongPassphrase (exit 3); got {err}"
            );
            assert!(
                matches!(
                    err,
                    AppError::Keystore(KeystoreError::WrongPassphrase { .. })
                ),
                "expected WrongPassphrase from index 0, got {err}"
            );
        }
    }

    // --- progress (Go: TestProgress_*) — adapted: the non-TTY path logs via the
    // Logger; there is no separate progressOut buffer in the Rust design. ---

    /// Runs `n` pubkeys with the given `json_logs`, capturing the logger output.
    fn run_capture_log(n: usize, json_logs: bool) -> String {
        let pks = multi_pks(n);
        let (_dir, idx) = index_over(&pks);
        let signers = signer_map(&pks);
        let loader = routing_loader();
        let verifier = FakeVerifier { ok: true };
        let mut writer = FakeWriter {
            path: "/out".into(),
            sha: "x".into(),
            err: false,
        };
        let mut summary = Vec::<u8>::new();
        let logbuf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let format = if json_logs {
            Format::Json
        } else {
            Format::Text
        };
        let logger = Logger::new(
            Level::Info,
            format,
            Box::new(SharedWriter(Arc::clone(&logbuf))),
        );
        let init_bls = || Ok(());
        let scanner = move |_: &Path| Ok(idx.clone());
        let new_signer = |secret: &[u8]| -> Result<Box<dyn Signer + Send>, BlsError> {
            let s = &signers[&secret[0]];
            Ok(Box::new(FakeSigner {
                pubkey: s.pubkey,
                sig: s.sig,
            }))
        };
        let verify = |_: &str, _: &str| Ok(());
        let mut cfg = base_cfg(pks);
        cfg.json_logs = json_logs;
        {
            let mut deps = GenDeps {
                init_bls: &init_bls,
                scanner: &scanner,
                loader: &loader,
                new_signer: &new_signer,
                verifier: &verifier,
                writer: &mut writer,
                summary_out: &mut summary,
                progress: Progress::NonTty,
                logger: &logger,
                verify_deposit_cli: &verify,
            };
            run_gen_with_deps(&cfg, &mut deps, &CancelToken::new()).expect("ok");
        }
        let out = String::from_utf8(logbuf.lock().unwrap().clone()).unwrap();
        // The non-TTY path must never emit a carriage return.
        assert!(
            !out.contains('\r'),
            "non-TTY progress must not use \\r: {out:?}"
        );
        out
    }

    #[test]
    fn progress_non_tty_emits_log_events() {
        // Go: TestProgress_NonTTY_NoCarriageReturn — n>5 → milestone log events.
        let out = run_capture_log(10, false);
        assert!(
            out.contains("signing progress"),
            "expected progress events: {out}"
        );
    }

    #[test]
    fn progress_suppressed_when_five_or_fewer() {
        // Go: TestProgress_Suppressed_WhenFiveOrFewer.
        let out = run_capture_log(5, false);
        assert!(
            !out.contains("signing progress"),
            "n<=5 must suppress progress: {out}"
        );
    }

    #[test]
    fn progress_json_logs_emit_events() {
        // Go: TestProgress_JSONLogs_EmitsSlogNotCarriageReturn.
        let out = run_capture_log(6, true);
        assert!(
            out.contains("signing progress"),
            "JSON logs should emit progress: {out}"
        );
    }

    // Go: TestRunGenWithDeps_NoSecretInLogs — the secret bytes never appear in
    // verbose logs.
    #[test]
    fn no_secret_in_logs() {
        let sentinel = vec![0x5Au8; 32];
        let want_hex = hex::encode(&sentinel);
        let mut pk = [0u8; 48];
        pk[0] = 0xAB;
        let (_dir, idx) = index_over(&[pk]);
        let secret_clone = sentinel.clone();
        let loader = FakeLoader {
            f: Box::new(move |_| {
                Ok(Key {
                    secret: secret_clone.clone(),
                    pubkey_hex: hex::encode(pk),
                })
            }),
        };
        let verifier = FakeVerifier { ok: true };
        let mut writer = FakeWriter {
            path: "/out/deposit_data-1.json".into(),
            sha: "cafebabe".into(),
            err: false,
        };
        let mut summary = Vec::<u8>::new();
        let logbuf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let logger = Logger::new(
            Level::Debug,
            Format::Text,
            Box::new(SharedWriter(Arc::clone(&logbuf))),
        );
        let init_bls = || Ok(());
        let scanner = move |_: &Path| Ok(idx.clone());
        let new_signer = move |_: &[u8]| -> Result<Box<dyn Signer + Send>, BlsError> {
            Ok(Box::new(FakeSigner {
                pubkey: pk,
                sig: [0u8; 96],
            }))
        };
        let verify = |_: &str, _: &str| Ok(());
        let mut cfg = base_cfg(vec![pk]);
        cfg.verbose = true;
        {
            let mut deps = GenDeps {
                init_bls: &init_bls,
                scanner: &scanner,
                loader: &loader,
                new_signer: &new_signer,
                verifier: &verifier,
                writer: &mut writer,
                summary_out: &mut summary,
                progress: Progress::NonTty,
                logger: &logger,
                verify_deposit_cli: &verify,
            };
            run_gen_with_deps(&cfg, &mut deps, &CancelToken::new()).expect("ok");
        }
        let logs = logbuf.lock().unwrap().clone();
        assert!(
            !logs.windows(sentinel.len()).any(|w| w == &sentinel[..]),
            "raw secret leaked"
        );
        assert!(
            !String::from_utf8_lossy(&logs).contains(&want_hex),
            "hex secret leaked"
        );
        assert!(!logs.is_empty(), "verbose mode should emit logs");
    }

    // Go: TestPrintGenSummary_Format / _DryRunEmptyPath.
    #[test]
    fn print_gen_summary_format() {
        let mut buf = Vec::<u8>::new();
        print_gen_summary(
            &mut buf,
            "/output/deposit_data-1700000000.json",
            "abc123def456",
            3,
            Network::Hoodi,
        );
        let got = String::from_utf8(buf).unwrap();
        assert_eq!(got, "wrote /output/deposit_data-1700000000.json (sha256=abc123def456, n=3, network=hoodi)\n");

        let mut dry = Vec::<u8>::new();
        print_gen_summary(&mut dry, "", "deadbeef", 1, Network::Hoodi);
        assert!(String::from_utf8(dry).unwrap().contains("wrote <stdout>"));
    }

    // Go: TestCLIVersion / TestDefaultWithdrawalCreds.
    #[test]
    fn constants() {
        assert_eq!(CLI_VERSION, "2.7.0");
        let wc = default_withdrawal_creds();
        assert_eq!(wc[0], 0x00);
        assert!(wc[1..].iter().all(|&b| b == 0));
    }

    // H2 / K5-L1: pipeline-level defense rejects all-zero and 0x01-burn credentials
    // independent of how GenConfig was constructed.
    #[test]
    fn rejects_placeholder_and_burn_withdrawal_credentials() {
        let pks = multi_pks(1);
        let (_dir, idx) = index_over(&pks);
        let loader = routing_loader();
        let verifier = FakeVerifier { ok: true };
        let mut writer = FakeWriter {
            path: "/out".into(),
            sha: "x".into(),
            err: false,
        };
        let init_bls = || Ok(());
        let scanner = move |_: &Path| Ok(idx.clone());
        let signers = signer_map(&pks);
        let new_signer = |secret: &[u8]| -> Result<Box<dyn Signer + Send>, BlsError> {
            let s = &signers[&secret[0]];
            Ok(Box::new(FakeSigner {
                pubkey: s.pubkey,
                sig: s.sig,
            }))
        };
        let verify = |_: &str, _: &str| Ok(());
        let logger = discard_logger();

        // (a) all-zero placeholder (default_withdrawal_creds / future non-CLI path).
        {
            let mut summary = Vec::<u8>::new();
            let mut cfg = base_cfg(pks.clone());
            cfg.withdrawal_credentials = [0u8; 32];
            let mut deps = GenDeps {
                init_bls: &init_bls,
                scanner: &scanner,
                loader: &loader,
                new_signer: &new_signer,
                verifier: &verifier,
                writer: &mut writer,
                summary_out: &mut summary,
                progress: Progress::NonTty,
                logger: &logger,
                verify_deposit_cli: &verify,
            };
            let err = run_gen_with_deps(&cfg, &mut deps, &CancelToken::new()).unwrap_err();
            assert_eq!(exit_code_for(&err), 2);
            assert!(err.to_string().contains("all-zero"), "err: {err}");
            assert!(summary.is_empty(), "no summary on credential reject");
        }

        // (b) 0x01 ‖ 11 zero ‖ 20 zero (burn address).
        {
            let mut summary = Vec::<u8>::new();
            let mut cfg = base_cfg(pks);
            let mut burn = [0u8; 32];
            burn[0] = 0x01;
            cfg.withdrawal_credentials = burn;
            let mut deps = GenDeps {
                init_bls: &init_bls,
                scanner: &scanner,
                loader: &loader,
                new_signer: &new_signer,
                verifier: &verifier,
                writer: &mut writer,
                summary_out: &mut summary,
                progress: Progress::NonTty,
                logger: &logger,
                verify_deposit_cli: &verify,
            };
            let err = run_gen_with_deps(&cfg, &mut deps, &CancelToken::new()).unwrap_err();
            assert_eq!(exit_code_for(&err), 2);
            assert!(
                err.to_string().contains("zero address") || err.to_string().contains("burn"),
                "err: {err}"
            );
            assert!(summary.is_empty(), "no summary on credential reject");
        }
    }

    // Go: TestBuildGenLogger_* — build_gen_logger selects level/format. Since it
    // targets stderr, we verify the observable level/format behaviour on an
    // equivalently constructed Logger (build_gen_logger's own flag→level/format
    // mapping is a thin wrapper, also exercised by the real pipeline).
    fn log_to_string(level: Level, format: Format, f: impl FnOnce(&Logger)) -> String {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let logger = Logger::new(level, format, Box::new(SharedWriter(Arc::clone(&buf))));
        f(&logger);
        let bytes = buf.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn build_gen_logger_behaviour() {
        // Default: text, info level (debug suppressed).
        let out = log_to_string(Level::Info, Format::Text, |lg| {
            lg.debug("this-should-not-appear", &[]);
            lg.info("this-should-appear", &[]);
        });
        assert!(!out.contains("this-should-not-appear"));
        assert!(out.contains("this-should-appear"));
        assert!(!out.contains("\"msg\""), "text handler must not emit JSON");

        // Verbose enables debug.
        let out = log_to_string(Level::Debug, Format::Text, |lg| {
            lg.debug("debug-sentinel", &[])
        });
        assert!(out.contains("debug-sentinel"));

        // JSON format emits a "msg" field.
        let out = log_to_string(Level::Info, Format::Json, |lg| {
            lg.info("json-sentinel", &[])
        });
        assert!(out.contains("\"msg\""));
        assert!(out.contains("json-sentinel"));

        // A smoke check that build_gen_logger constructs without panicking.
        let _ = build_gen_logger(true, true);
    }
}
