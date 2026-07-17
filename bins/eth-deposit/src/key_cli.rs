//! The nested `key` CLI surface: clap schema, shared config/validation, and the
//! `key new` non-TTY guard. Runtime derivation lives in [`crate::key_cmd`]
//! (K3-2 / K3-3).

use std::fmt;
use std::io::Write;
use std::path::Path;

use clap::{Arg, ArgMatches, Command};
use eth_deposit_core::cancel::CancelToken;
use zeroize::Zeroizing;

use crate::errors::AppError;
use crate::key_cmd;

/// Which `key` subcommand is being run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMode {
    New,
    Recover,
}

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

/// Validated inputs for `key new` / `key recover`.
///
/// [`Debug`] redacts [`mnemonic_passphrase`](Self::mnemonic_passphrase) secret
/// payloads so config never dumps passphrase bytes into logs or panics (S-2).
#[derive(Clone, PartialEq, Eq)]
pub struct KeyConfig {
    pub mode: KeyMode,
    /// Number of validator keys to produce (default 1). Must be ≥ 1.
    pub count: u32,
    /// Existing, writable directory for keystore files.
    pub output_dir: String,
    /// First HD derivation index. Always 0 for `key new`; operator-set on
    /// `key recover` (default 0).
    pub start_index: u32,
    /// Name of the env var holding the keystore passphrase. Empty means the
    /// runtime falls back to a TTY prompt-with-confirm (K2-3 / K3-2).
    pub passphrase_env: String,
    /// Resolved mnemonic-passphrase form (flag / env value / prompt / empty).
    pub mnemonic_passphrase: MnemonicPassphraseForm,
}

impl fmt::Debug for KeyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyConfig")
            .field("mode", &self.mode)
            .field("count", &self.count)
            .field("output_dir", &self.output_dir)
            .field("start_index", &self.start_index)
            .field("passphrase_env", &self.passphrase_env)
            // Delegates to MnemonicPassphraseForm's redacting Debug.
            .field("mnemonic_passphrase", &self.mnemonic_passphrase)
            .finish()
    }
}

/// The clap definition of the nested `key` group (`key new` / `key recover`).
pub fn command() -> Command {
    Command::new("key")
        .about("Generate or recover EIP-2335 BLS validator keystores from a BIP-39 mnemonic")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(new_command())
        .subcommand(recover_command())
}

fn new_command() -> Command {
    Command::new("new")
        .about("Generate a fresh 24-word mnemonic and write EIP-2335 signing keystores (TTY only)")
        .override_usage("eth-deposit key new --output-dir DIR [--count N] [--passphrase-env VAR] [--mnemonic-passphrase [VALUE] | --mnemonic-passphrase-env VAR]")
        .long_about(
            "Generates a fresh 24-word English BIP-39 mnemonic from OS CSPRNG entropy, runs a\n\
             display-once + full re-entry ceremony on the controlling terminal, then derives\n\
             and encrypts one EIP-2335 v4 scrypt signing keystore per validator index.\n\n\
             TTY-only: stdin and stdout must both be terminals; otherwise the command exits 2\n\
             before generating anything (a mnemonic must never land on a pipe or log).\n\n\
             Examples:\n\n\
             \x20 eth-deposit key new --output-dir ./keys --count 1\n\
             \x20 eth-deposit key new --output-dir ./keys --passphrase-env KEYSTORE_PW\n\
             \x20 eth-deposit key new --output-dir ./keys --mnemonic-passphrase-env MNEMONIC_PW",
        )
        .args(shared_args())
}

fn recover_command() -> Command {
    Command::new("recover")
        .about("Recover EIP-2335 signing keystores from an existing BIP-39 mnemonic")
        .override_usage("eth-deposit key recover --output-dir DIR [--count N] [--start-index N] [--passphrase-env VAR] [--mnemonic-passphrase [VALUE] | --mnemonic-passphrase-env VAR]")
        .long_about(
            "Reads an existing BIP-39 mnemonic from an interactive TTY prompt or piped stdin,\n\
             validates word membership and checksum (12/15/18/21/24 words), then derives and\n\
             encrypts signing keystores for the index range [--start-index, --start-index+--count).\n\n\
             Unlike `key new`, there is no display/re-entry ceremony — the mnemonic already exists\n\
             and the exposure decision was the caller's.\n\n\
             Examples:\n\n\
             \x20 eth-deposit key recover --output-dir ./keys --count 3 --start-index 0\n\
             \x20 echo \"$MNEMONIC\" | eth-deposit key recover --output-dir ./keys",
        )
        .args(shared_args())
        .arg(
            Arg::new("start-index")
                .long("start-index")
                .value_name("N")
                .value_parser(clap::value_parser!(u32))
                .default_value("0")
                .help("First HD derivation index (default 0); produces indices start..start+count"),
        )
}

/// Flags shared by `key new` and `key recover`.
fn shared_args() -> Vec<Arg> {
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

/// `key new` entry: non-TTY guard first, validate config, then ceremony +
/// derive → encrypt → write (K3-2).
pub fn run_new(m: &ArgMatches, cancel: &CancelToken) -> Result<(), AppError> {
    // F-5: exit 2 before generating when stdin or stdout is not a TTY.
    require_tty_for_new()?;

    let mut stderr = std::io::stderr();
    let cfg = load_config(m, KeyMode::New, &mut stderr)?;
    key_cmd::run_key_new(&cfg, cancel)
}

/// `key recover` entry: validate config only. Runtime pipeline is K3-3.
/// Exempt from the TTY guard (piped stdin is allowed).
pub fn run_recover(m: &ArgMatches) -> Result<(), AppError> {
    let mut stderr = std::io::stderr();
    let _cfg = load_config(m, KeyMode::Recover, &mut stderr)?;
    // K3-3: read mnemonic → validate → derive → encrypt → write.
    Ok(())
}

/// Rejects non-interactive `key new` (stdin and stdout must both be TTYs).
pub fn require_tty_for_new() -> Result<(), AppError> {
    // SAFETY: isatty is async-signal-safe and has no preconditions.
    let stdin_tty = unsafe { libc::isatty(0) == 1 };
    let stdout_tty = unsafe { libc::isatty(1) == 1 };
    if stdin_tty && stdout_tty {
        return Ok(());
    }
    Err(AppError::exit2(
        "key new requires an interactive terminal (stdin and stdout must both be a TTY); \
         refusing to generate a mnemonic on a non-TTY",
    ))
}

/// Builds a validated [`KeyConfig`] from parsed flags.
///
/// Validation order (mirrors `gen_cli::load_config` style): count → start-index
/// → output-dir → mnemonic-passphrase form → passphrase-env, then confirmation
/// banner. Bad `--count` / unwritable `--output-dir` → exit 2.
pub fn load_config(
    m: &ArgMatches,
    mode: KeyMode,
    banner_out: &mut dyn Write,
) -> Result<KeyConfig, AppError> {
    // 1. --count: default 1; must be ≥ 1.
    let count = *m.get_one::<u32>("count").unwrap();
    if count == 0 {
        return Err(AppError::exit2(
            "--count: value 0 is invalid; must be >= 1",
        ));
    }

    // 2. --start-index: recover only (default 0); new always starts at 0.
    let start_index = match mode {
        KeyMode::New => 0,
        KeyMode::Recover => *m.get_one::<u32>("start-index").unwrap(),
    };

    // 3. --output-dir: required existing writable directory.
    let output_dir = m
        .get_one::<String>("output-dir")
        .cloned()
        .unwrap_or_default();
    if output_dir.is_empty() {
        return Err(AppError::exit2("--output-dir: required flag not set"));
    }
    validate_output_dir(&output_dir).map_err(|e| AppError::exit2(format!("--output-dir: {e}")))?;

    // 4. Mnemonic passphrase form (XOR via conflicts_with: raw/prompt ⊥ env).
    // Bare vs value is num_args(0..=1); absent both → empty. Values Zeroizing'd on read.
    let mnemonic_passphrase = resolve_mnemonic_passphrase(m)?;

    // 5. Keystore passphrase env var name (empty → runtime TTY prompt).
    let passphrase_env = m
        .get_one::<String>("passphrase-env")
        .cloned()
        .unwrap_or_default();

    let cfg = KeyConfig {
        mode,
        count,
        output_dir,
        start_index,
        passphrase_env,
        mnemonic_passphrase,
    };

    print_banner(banner_out, &cfg);
    Ok(cfg)
}

/// Resolves the three mnemonic-passphrase forms into a [`MnemonicPassphraseForm`].
///
/// Forms are mutually exclusive at the clap layer (`conflicts_with`), so only
/// one branch can fire:
/// - `--mnemonic-passphrase VALUE` → [`Raw`] (value Zeroizing'd on read)
/// - bare `--mnemonic-passphrase` → [`Prompt`]
/// - `--mnemonic-passphrase-env VAR` → read env (unset → exit 2; empty OK) → [`Env`]
/// - neither → [`Empty`]
fn resolve_mnemonic_passphrase(m: &ArgMatches) -> Result<MnemonicPassphraseForm, AppError> {
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

/// Checks that dir exists and the process can write to it, probing writability
/// by creating and immediately removing a temporary file. Mirrors
/// `gen_cli::validate_output_dir`.
fn validate_output_dir(dir: &str) -> Result<(), String> {
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

    let probe = Path::new(dir).join(format!(".eth-deposit-probe-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(f) => {
            drop(f);
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(format!("directory \"{dir}\" is not writable: {e}")),
    }
}

/// Confirmation banner to stderr before the (future) pipeline runs.
fn print_banner(w: &mut dyn Write, cfg: &KeyConfig) {
    let verb = match cfg.mode {
        KeyMode::New => "new",
        KeyMode::Recover => "recover",
    };
    match cfg.mode {
        KeyMode::New => {
            let _ = writeln!(
                w,
                "eth-deposit key {verb}: count={} output_dir={}",
                cfg.count, cfg.output_dir
            );
        }
        KeyMode::Recover => {
            let _ = writeln!(
                w,
                "eth-deposit key {verb}: count={} start_index={} output_dir={}",
                cfg.count, cfg.start_index, cfg.output_dir
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::exit_code_for;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// Serializes tests that mutate process environment.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// A temp directory that removes itself on drop.
    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Tmp {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!(
                "key-cli-test-{}-{n}",
                std::process::id()
            ));
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

    fn parse_new(args: &[&str]) -> Result<ArgMatches, String> {
        let mut argv = vec!["key", "new"];
        argv.extend_from_slice(args);
        command()
            .try_get_matches_from(argv)
            .map(|m| m.subcommand().unwrap().1.clone())
            .map_err(|e| format!("clap: {e}"))
    }

    fn parse_recover(args: &[&str]) -> Result<ArgMatches, String> {
        let mut argv = vec!["key", "recover"];
        argv.extend_from_slice(args);
        command()
            .try_get_matches_from(argv)
            .map(|m| m.subcommand().unwrap().1.clone())
            .map_err(|e| format!("clap: {e}"))
    }

    fn load_new(args: &[&str]) -> Result<(KeyConfig, String), String> {
        let m = parse_new(args)?;
        let mut banner = Vec::new();
        let cfg = load_config(&m, KeyMode::New, &mut banner).map_err(|e| format!("load: {e}"))?;
        Ok((cfg, String::from_utf8(banner).unwrap()))
    }

    fn load_recover(args: &[&str]) -> Result<(KeyConfig, String), String> {
        let m = parse_recover(args)?;
        let mut banner = Vec::new();
        let cfg =
            load_config(&m, KeyMode::Recover, &mut banner).map_err(|e| format!("load: {e}"))?;
        Ok((cfg, String::from_utf8(banner).unwrap()))
    }

    fn load_new_err(args: &[&str]) -> AppError {
        let m = parse_new(args).expect("clap parse ok");
        let mut banner = Vec::new();
        load_config(&m, KeyMode::New, &mut banner).expect_err("load should fail")
    }

    // --- namespace shape ---

    #[test]
    fn key_namespace_requires_subcommand() {
        let err = command()
            .try_get_matches_from(["key"])
            .expect_err("subcommand required");
        // clap surfaces this as a usage error (exit 2 at the binary).
        let msg = err.to_string();
        assert!(
            msg.contains("subcommand") || msg.contains("required"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn key_new_and_recover_parse() {
        let dir = Tmp::new();
        assert!(parse_new(&["--output-dir", dir.str()]).is_ok());
        assert!(parse_recover(&["--output-dir", dir.str()]).is_ok());
    }

    // --- defaults and flags ---

    #[test]
    fn count_defaults_to_one() {
        let dir = Tmp::new();
        let (cfg, banner) = load_new(&["--output-dir", dir.str()]).expect("ok");
        assert_eq!(cfg.count, 1);
        assert_eq!(cfg.mode, KeyMode::New);
        assert_eq!(cfg.start_index, 0);
        assert_eq!(cfg.output_dir, dir.str());
        assert_eq!(cfg.passphrase_env, "");
        assert_eq!(cfg.mnemonic_passphrase, MnemonicPassphraseForm::Empty);
        assert!(banner.contains("eth-deposit key new:"));
        assert!(banner.contains("count=1"));
    }

    #[test]
    fn count_and_passphrase_env_propagate() {
        let dir = Tmp::new();
        let (cfg, _) = load_new(&[
            "--output-dir",
            dir.str(),
            "--count",
            "4",
            "--passphrase-env",
            "KS_PW",
        ])
        .expect("ok");
        assert_eq!(cfg.count, 4);
        assert_eq!(cfg.passphrase_env, "KS_PW");
    }

    #[test]
    fn recover_start_index_default_and_set() {
        let dir = Tmp::new();
        let (cfg, banner) = load_recover(&["--output-dir", dir.str()]).expect("ok");
        assert_eq!(cfg.start_index, 0);
        assert_eq!(cfg.mode, KeyMode::Recover);
        assert!(banner.contains("start_index=0"));

        let (cfg, banner) =
            load_recover(&["--output-dir", dir.str(), "--start-index", "5", "--count", "3"])
                .expect("ok");
        assert_eq!(cfg.start_index, 5);
        assert_eq!(cfg.count, 3);
        assert!(banner.contains("start_index=5"));
        assert!(banner.contains("count=3"));
    }

    #[test]
    fn new_ignores_start_index_flag_absence() {
        // `key new` has no --start-index; config always reports 0.
        let dir = Tmp::new();
        let (cfg, _) = load_new(&["--output-dir", dir.str()]).unwrap();
        assert_eq!(cfg.start_index, 0);
        assert!(parse_new(&["--output-dir", dir.str(), "--start-index", "1"]).is_err());
    }

    // --- count validation ---

    #[test]
    fn bad_count_is_exit2() {
        let dir = Tmp::new();
        let err = load_new_err(&["--output-dir", dir.str(), "--count", "0"]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("--count"));
    }

    // --- output-dir validation ---

    #[test]
    fn missing_output_dir_is_clap_error() {
        assert!(parse_new(&[]).is_err());
        assert!(parse_recover(&["--count", "1"]).is_err());
    }

    #[test]
    fn nonexistent_output_dir_is_exit2() {
        let dir = Tmp::new();
        let missing = dir.0.join("no-such");
        let err = load_new_err(&["--output-dir", missing.to_str().unwrap()]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn file_as_output_dir_is_exit2() {
        let dir = Tmp::new();
        let file = dir.0.join("a-file");
        std::fs::write(&file, b"x").unwrap();
        let err = load_new_err(&["--output-dir", file.to_str().unwrap()]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("not a directory"));
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

    #[cfg(unix)]
    #[test]
    fn unwritable_output_dir_is_exit2() {
        use std::os::unix::fs::PermissionsExt;

        let dir = Tmp::new();
        let locked = dir.0.join("locked");
        std::fs::create_dir(&locked).unwrap();
        // Drop write bit for owner/group/other; probe File::create must fail.
        let mut perms = std::fs::metadata(&locked).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&locked, perms).unwrap();

        let err = load_new_err(&["--output-dir", locked.to_str().unwrap()]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(
            err.to_string().contains("not writable"),
            "expected not-writable message, got: {err}"
        );

        // Restore writability so Tmp Drop can remove the tree.
        let mut perms = std::fs::metadata(&locked).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&locked, perms).unwrap();
    }

    // --- three-form mnemonic passphrase ---

    #[test]
    fn mnemonic_passphrase_absent_is_empty() {
        let dir = Tmp::new();
        let (cfg, _) = load_new(&["--output-dir", dir.str()]).unwrap();
        assert_eq!(cfg.mnemonic_passphrase, MnemonicPassphraseForm::Empty);
    }

    #[test]
    fn mnemonic_passphrase_raw_value() {
        let dir = Tmp::new();
        let (cfg, _) = load_new(&[
            "--output-dir",
            dir.str(),
            "--mnemonic-passphrase",
            "TREZOR",
        ])
        .unwrap();
        assert_eq!(
            cfg.mnemonic_passphrase,
            MnemonicPassphraseForm::Raw(Zeroizing::new("TREZOR".into()))
        );
    }

    #[test]
    fn mnemonic_passphrase_bare_is_prompt() {
        let dir = Tmp::new();
        let (cfg, _) =
            load_new(&["--output-dir", dir.str(), "--mnemonic-passphrase"]).unwrap();
        assert_eq!(cfg.mnemonic_passphrase, MnemonicPassphraseForm::Prompt);
    }

    #[test]
    fn mnemonic_passphrase_env_reads_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = Tmp::new();
        let var = format!("ETH_DEPOSIT_TEST_MNEMONIC_PW_{}", std::process::id());
        std::env::set_var(&var, "from-env");
        let result = load_new(&[
            "--output-dir",
            dir.str(),
            "--mnemonic-passphrase-env",
            &var,
        ]);
        std::env::remove_var(&var);
        let (cfg, _) = result.expect("ok");
        match cfg.mnemonic_passphrase {
            MnemonicPassphraseForm::Env { var: v, value } => {
                assert_eq!(v, var);
                assert_eq!(value.as_str(), "from-env");
            }
            other => panic!("expected Env, got {other:?}"),
        }
    }

    #[test]
    fn mnemonic_passphrase_env_empty_value_accepted() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = Tmp::new();
        let var = format!("ETH_DEPOSIT_TEST_MNEMONIC_PW_EMPTY_{}", std::process::id());
        std::env::set_var(&var, "");
        let result = load_new(&[
            "--output-dir",
            dir.str(),
            "--mnemonic-passphrase-env",
            &var,
        ]);
        std::env::remove_var(&var);
        let (cfg, _) = result.expect("empty mnemonic passphrase is valid");
        match cfg.mnemonic_passphrase {
            MnemonicPassphraseForm::Env { value, .. } => assert_eq!(value.as_str(), ""),
            other => panic!("expected Env, got {other:?}"),
        }
    }

    #[test]
    fn mnemonic_passphrase_debug_redacts_secrets() {
        let raw = MnemonicPassphraseForm::Raw(Zeroizing::new("SUPER_SECRET".into()));
        let dbg = format!("{raw:?}");
        assert!(!dbg.contains("SUPER_SECRET"), "Debug leaked raw secret: {dbg}");
        assert!(dbg.contains("REDACTED"), "{dbg}");

        let env = MnemonicPassphraseForm::Env {
            var: "MNEMONIC_PW".into(),
            value: Zeroizing::new("env-secret-value".into()),
        };
        let dbg = format!("{env:?}");
        assert!(!dbg.contains("env-secret-value"), "Debug leaked env secret: {dbg}");
        assert!(dbg.contains("MNEMONIC_PW"), "var name should remain: {dbg}");
        assert!(dbg.contains("REDACTED"), "{dbg}");

        let cfg = KeyConfig {
            mode: KeyMode::New,
            count: 1,
            output_dir: "/out".into(),
            start_index: 0,
            passphrase_env: String::new(),
            mnemonic_passphrase: raw,
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("SUPER_SECRET"), "KeyConfig Debug leaked: {dbg}");
    }

    #[test]
    fn mnemonic_passphrase_env_unset_is_exit2() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = Tmp::new();
        let var = format!("ETH_DEPOSIT_TEST_MNEMONIC_PW_UNSET_{}", std::process::id());
        std::env::remove_var(&var);
        let m = parse_new(&[
            "--output-dir",
            dir.str(),
            "--mnemonic-passphrase-env",
            &var,
        ])
        .unwrap();
        let mut banner = Vec::new();
        let err = load_config(&m, KeyMode::New, &mut banner).unwrap_err();
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("is not set"));
    }

    #[test]
    fn mnemonic_passphrase_raw_and_env_conflict() {
        let dir = Tmp::new();
        let err = parse_new(&[
            "--output-dir",
            dir.str(),
            "--mnemonic-passphrase",
            "x",
            "--mnemonic-passphrase-env",
            "Y",
        ]);
        assert!(err.is_err(), "raw and env must conflict");
    }

    #[test]
    fn mnemonic_passphrase_bare_and_env_conflict() {
        let dir = Tmp::new();
        let err = parse_new(&[
            "--output-dir",
            dir.str(),
            "--mnemonic-passphrase",
            "--mnemonic-passphrase-env",
            "Y",
        ]);
        assert!(err.is_err(), "bare and env must conflict");
    }
}
