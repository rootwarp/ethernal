//! The nested `validator` CLI surface: clap schema, shared config/validation, and the
//! `validator new` non-TTY guard. Runtime derivation lives in [`crate::validator_cmd`]
//! (K3-2 / K3-3).

use std::fmt;
use std::io::Write;
use std::path::Path;

use clap::{Arg, ArgMatches, Command};
use ethernal_core::cancel::CancelToken;

use crate::errors::AppError;
use crate::fs_util;
use crate::keystore_cli::{
    parse_mnemonic_passphrase_form, require_tty_for_new, shared_args, MnemonicPassphraseForm,
    START_INDEX_OVERFLOW_MSG,
};
use crate::validator_cmd;

/// Which `validator` subcommand is being run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorMode {
    New,
    Recover,
}

/// Validated inputs for `validator new` / `validator recover`.
///
/// [`Debug`] redacts [`mnemonic_passphrase`](Self::mnemonic_passphrase) secret
/// payloads so config never dumps passphrase bytes into logs or panics (S-2).
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatorConfig {
    pub mode: ValidatorMode,
    /// Number of validator keys to produce (default 1). Must be ≥ 1.
    pub count: u32,
    /// Existing, writable directory for keystore files.
    pub output_dir: String,
    /// First HD derivation index. Always 0 for `validator new`; operator-set on
    /// `validator recover` (default 0).
    pub start_index: u32,
    /// Name of the env var holding the keystore passphrase. Empty means the
    /// runtime falls back to a TTY prompt-with-confirm (K2-3 / K3-2).
    pub passphrase_env: String,
    /// Resolved mnemonic-passphrase form (flag / env value / prompt / empty).
    pub mnemonic_passphrase: MnemonicPassphraseForm,
    /// When true (default), run C4 post-write keystore decrypt round-trip.
    /// `--no-verify` sets this false. C1–C3 always run regardless.
    pub verify_keystore: bool,
}

impl fmt::Debug for ValidatorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatorConfig")
            .field("mode", &self.mode)
            .field("count", &self.count)
            .field("output_dir", &self.output_dir)
            .field("start_index", &self.start_index)
            .field("passphrase_env", &self.passphrase_env)
            // Delegates to MnemonicPassphraseForm's redacting Debug.
            .field("mnemonic_passphrase", &self.mnemonic_passphrase)
            .field("verify_keystore", &self.verify_keystore)
            .finish()
    }
}

/// The clap definition of the nested `validator` group (`validator new` / `validator recover`).
pub fn command() -> Command {
    Command::new("validator")
        .about("Generate or recover EIP-2335 BLS validator keystores from a BIP-39 mnemonic")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(new_command())
        .subcommand(recover_command())
}

/// `--no-verify` shared by `validator new` and `validator recover` (V4-3 / PR-12).
/// Not on account: C4 is validator-only for now.
fn no_verify_arg() -> Arg {
    Arg::new("no-verify")
        .long("no-verify")
        .action(clap::ArgAction::SetTrue)
        .help(
            "Skip the post-write keystore decrypt round-trip (C4). Derivation self-checks \
             (C1-C3) always run and cannot be skipped. Halves wall-clock at the cost of the \
             strongest correctness check.",
        )
}

fn new_command() -> Command {
    Command::new("new")
        .about("Generate a fresh 24-word mnemonic and write EIP-2335 signing keystores (TTY only)")
        .override_usage("ethernal validator new --output-dir DIR [--count N] [--passphrase-env VAR] [--mnemonic-passphrase [VALUE] | --mnemonic-passphrase-env VAR]")
        .long_about(
            "Generates a fresh 24-word English BIP-39 mnemonic from OS CSPRNG entropy, runs a\n\
             display-once + full re-entry ceremony on the controlling terminal, then derives\n\
             and encrypts one EIP-2335 v4 scrypt signing keystore per validator index.\n\n\
             TTY-only: stdin and stdout must both be terminals; otherwise the command exits 2\n\
             before generating anything (a mnemonic must never land on a pipe or log).\n\n\
             Examples:\n\n\
             \x20 ethernal validator new --output-dir ./keys --count 1\n\
             \x20 ethernal validator new --output-dir ./keys --passphrase-env KEYSTORE_PW\n\
             \x20 ethernal validator new --output-dir ./keys --mnemonic-passphrase-env MNEMONIC_PW",
        )
        .args(shared_args())
        .arg(no_verify_arg())
}

fn recover_command() -> Command {
    Command::new("recover")
        .about("Recover EIP-2335 signing keystores from an existing BIP-39 mnemonic")
        .override_usage("ethernal validator recover --output-dir DIR [--count N] [--start-index N] [--passphrase-env VAR] [--mnemonic-passphrase [VALUE] | --mnemonic-passphrase-env VAR]")
        .long_about(
            "Reads an existing BIP-39 mnemonic from an interactive TTY prompt or piped stdin,\n\
             validates word membership and checksum (12/15/18/21/24 words), then derives and\n\
             encrypts signing keystores for the index range [--start-index, --start-index+--count).\n\n\
             Unlike `validator new`, there is no display/re-entry ceremony — the mnemonic already exists\n\
             and the exposure decision was the caller's.\n\n\
             Examples:\n\n\
             \x20 ethernal validator recover --output-dir ./keys --count 3 --start-index 0\n\
             \x20 echo \"$MNEMONIC\" | ethernal validator recover --output-dir ./keys",
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
        .arg(no_verify_arg())
}

/// `validator new` entry: non-TTY guard first, validate config, then ceremony +
/// derive → encrypt → write (K3-2).
pub fn run_new(m: &ArgMatches, cancel: &CancelToken) -> Result<(), AppError> {
    // F-5: exit 2 before generating when stdin or stdout is not a TTY.
    require_tty_for_new()?;

    let mut stderr = std::io::stderr();
    let cfg = load_config(m, ValidatorMode::New, &mut stderr)?;
    validator_cmd::run_validator_new(&cfg, cancel)
}

/// `validator recover` entry: validate config, then read mnemonic (TTY or pipe) →
/// validate → derive → encrypt → write (K3-3). Exempt from the TTY-only gate.
pub fn run_recover(m: &ArgMatches, cancel: &CancelToken) -> Result<(), AppError> {
    let mut stderr = std::io::stderr();
    let cfg = load_config(m, ValidatorMode::Recover, &mut stderr)?;
    validator_cmd::run_validator_recover(&cfg, cancel)
}

/// Builds a validated [`ValidatorConfig`] from parsed flags.
///
/// Validation order (mirrors `gen_cli::load_config` style): count → start-index
/// → index-range overflow → output-dir → mnemonic-passphrase form →
/// passphrase-env, then confirmation banner. Bad `--count` / overflowing
/// range / unwritable `--output-dir` → exit 2.
pub fn load_config(
    m: &ArgMatches,
    mode: ValidatorMode,
    banner_out: &mut dyn Write,
) -> Result<ValidatorConfig, AppError> {
    // 1. --count: default 1; must be ≥ 1.
    let count = *m.get_one::<u32>("count").unwrap();
    if count == 0 {
        return Err(AppError::exit2("--count: value 0 is invalid; must be >= 1"));
    }

    // 2. --start-index: recover only (default 0); new always starts at 0.
    let start_index = match mode {
        ValidatorMode::New => 0,
        ValidatorMode::Recover => *m.get_one::<u32>("start-index").unwrap(),
    };

    // 2b. Index range must fit u32 before any ceremony/write (K3-L2). The
    // inclusive last index is start_index + count - 1; count ≥ 1 here.
    if start_index.checked_add(count - 1).is_none() {
        return Err(AppError::exit2(START_INDEX_OVERFLOW_MSG));
    }

    // 3. --output-dir: required existing writable directory.
    let output_dir = m
        .get_one::<String>("output-dir")
        .cloned()
        .unwrap_or_default();
    if output_dir.is_empty() {
        return Err(AppError::exit2("--output-dir: required flag not set"));
    }
    fs_util::validate_output_dir(&output_dir)
        .map_err(|e| AppError::exit2(format!("--output-dir: {e}")))?;
    fs_util::warn_if_symlinked_output_dir(Path::new(&output_dir), banner_out);

    // 4. Mnemonic passphrase form (XOR via conflicts_with: raw/prompt ⊥ env).
    // Bare vs value is num_args(0..=1); absent both → empty. Values Zeroizing'd on read.
    let mnemonic_passphrase = parse_mnemonic_passphrase_form(m)?;

    // 5. Keystore passphrase env var name (empty → runtime TTY prompt).
    let passphrase_env = m
        .get_one::<String>("passphrase-env")
        .cloned()
        .unwrap_or_default();

    // 6. --no-verify skips C4 only (default: verify). Positive name for call sites.
    let verify_keystore = !m.get_flag("no-verify");

    let cfg = ValidatorConfig {
        mode,
        count,
        output_dir,
        start_index,
        passphrase_env,
        mnemonic_passphrase,
        verify_keystore,
    };

    print_banner(banner_out, &cfg);
    Ok(cfg)
}

/// Confirmation banner to stderr before the (future) pipeline runs.
fn print_banner(w: &mut dyn Write, cfg: &ValidatorConfig) {
    let verb = match cfg.mode {
        ValidatorMode::New => "new",
        ValidatorMode::Recover => "recover",
    };
    match cfg.mode {
        ValidatorMode::New => {
            let _ = writeln!(
                w,
                "ethernal validator {verb}: count={} output_dir={}",
                cfg.count, cfg.output_dir
            );
        }
        ValidatorMode::Recover => {
            let _ = writeln!(
                w,
                "ethernal validator {verb}: count={} start_index={} output_dir={}",
                cfg.count, cfg.start_index, cfg.output_dir
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::exit_code_for;
    use crate::test_support::{Tmp, ENV_LOCK};
    use zeroize::Zeroizing;

    fn parse_new(args: &[&str]) -> Result<ArgMatches, String> {
        let mut argv = vec!["validator", "new"];
        argv.extend_from_slice(args);
        command()
            .try_get_matches_from(argv)
            .map(|m| m.subcommand().unwrap().1.clone())
            .map_err(|e| format!("clap: {e}"))
    }

    fn parse_recover(args: &[&str]) -> Result<ArgMatches, String> {
        let mut argv = vec!["validator", "recover"];
        argv.extend_from_slice(args);
        command()
            .try_get_matches_from(argv)
            .map(|m| m.subcommand().unwrap().1.clone())
            .map_err(|e| format!("clap: {e}"))
    }

    fn load_new(args: &[&str]) -> Result<(ValidatorConfig, String), String> {
        let m = parse_new(args)?;
        let mut banner = Vec::new();
        let cfg =
            load_config(&m, ValidatorMode::New, &mut banner).map_err(|e| format!("load: {e}"))?;
        Ok((cfg, String::from_utf8(banner).unwrap()))
    }

    fn load_recover(args: &[&str]) -> Result<(ValidatorConfig, String), String> {
        let m = parse_recover(args)?;
        let mut banner = Vec::new();
        let cfg = load_config(&m, ValidatorMode::Recover, &mut banner)
            .map_err(|e| format!("load: {e}"))?;
        Ok((cfg, String::from_utf8(banner).unwrap()))
    }

    fn load_new_err(args: &[&str]) -> AppError {
        let m = parse_new(args).expect("clap parse ok");
        let mut banner = Vec::new();
        load_config(&m, ValidatorMode::New, &mut banner).expect_err("load should fail")
    }

    fn load_recover_err(args: &[&str]) -> AppError {
        let m = parse_recover(args).expect("clap parse ok");
        let mut banner = Vec::new();
        load_config(&m, ValidatorMode::Recover, &mut banner).expect_err("load should fail")
    }

    // --- namespace shape ---

    #[test]
    fn validator_namespace_requires_subcommand() {
        let err = command()
            .try_get_matches_from(["validator"])
            .expect_err("subcommand required");
        // clap surfaces this as a usage error (exit 2 at the binary).
        let msg = err.to_string();
        assert!(
            msg.contains("subcommand") || msg.contains("required"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn validator_new_and_recover_parse() {
        let dir = Tmp::new("validator-cli-test");
        assert!(parse_new(&["--output-dir", dir.str()]).is_ok());
        assert!(parse_recover(&["--output-dir", dir.str()]).is_ok());
    }

    /// C1–C3 are mandatory: no CLI flag may disable them (V3-2 / D-7).
    /// `--no-verify` (V4-3) skips C4 only and must document that C1–C3 always run.
    #[test]
    fn help_has_no_flag_disabling_c1_c3() {
        for sub in ["new", "recover"] {
            let mut cmd = command();
            let sub_cmd = cmd.find_subcommand_mut(sub).expect("subcommand");
            let mut buf = Vec::new();
            sub_cmd.write_long_help(&mut buf).unwrap();
            let help = String::from_utf8(buf).unwrap().to_lowercase();
            // No flag that skips derivation self-checks.
            for forbidden in [
                "no-check",
                "skip-check",
                "skip-c1",
                "skip-c2",
                "skip-c3",
                "no-c1",
                "no-c2",
                "no-c3",
                "disable-check",
                "disable-verify",
            ] {
                assert!(
                    !help.contains(forbidden),
                    "validator {sub} help must not offer a flag to skip C1–C3 ({forbidden}): {help}"
                );
            }
            // --no-verify must exist and state that C1–C3 always run / cannot be skipped.
            assert!(
                help.contains("no-verify"),
                "validator {sub} help must document --no-verify: {help}"
            );
            assert!(
                help.contains("c1-c3")
                    && help.contains("always run")
                    && help.contains("cannot be skipped"),
                "validator {sub} --no-verify help must caveat that C1–C3 always run: {help}"
            );
        }
    }

    #[test]
    fn no_verify_flag_defaults_true_and_sets_false() {
        let dir = Tmp::new("validator-cli-test");
        let (cfg, _) = load_new(&["--output-dir", dir.str()]).expect("ok");
        assert!(cfg.verify_keystore, "default must verify keystores (C4 on)");

        let (cfg, _) = load_new(&["--output-dir", dir.str(), "--no-verify"]).expect("ok");
        assert!(
            !cfg.verify_keystore,
            "--no-verify must set verify_keystore=false"
        );

        let (cfg, _) = load_recover(&["--output-dir", dir.str(), "--no-verify"]).expect("ok");
        assert!(
            !cfg.verify_keystore,
            "recover --no-verify must set verify_keystore=false"
        );
        let (cfg, _) = load_recover(&["--output-dir", dir.str()]).expect("ok");
        assert!(cfg.verify_keystore);
    }

    // --- defaults and flags ---

    #[test]
    fn count_defaults_to_one() {
        let dir = Tmp::new("validator-cli-test");
        let (cfg, banner) = load_new(&["--output-dir", dir.str()]).expect("ok");
        assert_eq!(cfg.count, 1);
        assert_eq!(cfg.mode, ValidatorMode::New);
        assert_eq!(cfg.start_index, 0);
        assert_eq!(cfg.output_dir, dir.str());
        assert_eq!(cfg.passphrase_env, "");
        assert_eq!(cfg.mnemonic_passphrase, MnemonicPassphraseForm::Empty);
        assert!(banner.contains("ethernal validator new:"));
        assert!(banner.contains("count=1"));
    }

    #[test]
    fn count_and_passphrase_env_propagate() {
        let dir = Tmp::new("validator-cli-test");
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
        let dir = Tmp::new("validator-cli-test");
        let (cfg, banner) = load_recover(&["--output-dir", dir.str()]).expect("ok");
        assert_eq!(cfg.start_index, 0);
        assert_eq!(cfg.mode, ValidatorMode::Recover);
        assert!(banner.contains("start_index=0"));

        let (cfg, banner) = load_recover(&[
            "--output-dir",
            dir.str(),
            "--start-index",
            "5",
            "--count",
            "3",
        ])
        .expect("ok");
        assert_eq!(cfg.start_index, 5);
        assert_eq!(cfg.count, 3);
        assert!(banner.contains("start_index=5"));
        assert!(banner.contains("count=3"));
    }

    #[test]
    fn new_ignores_start_index_flag_absence() {
        // `validator new` has no --start-index; config always reports 0.
        let dir = Tmp::new("validator-cli-test");
        let (cfg, _) = load_new(&["--output-dir", dir.str()]).unwrap();
        assert_eq!(cfg.start_index, 0);
        assert!(parse_new(&["--output-dir", dir.str(), "--start-index", "1"]).is_err());
    }

    // --- count validation ---

    #[test]
    fn bad_count_is_exit2() {
        let dir = Tmp::new("validator-cli-test");
        let err = load_new_err(&["--output-dir", dir.str(), "--count", "0"]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("--count"));
    }

    // --- index-range overflow (K3-L2 / H4) ---

    #[test]
    fn start_index_plus_count_overflow_is_exit2() {
        let dir = Tmp::new("validator-cli-test");
        // start=u32::MAX, count=2 → last index overflows.
        let err = load_recover_err(&[
            "--output-dir",
            dir.str(),
            "--start-index",
            "4294967295",
            "--count",
            "2",
        ]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(
            err.to_string().contains("overflows u32"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn start_index_max_with_count_one_ok() {
        // Inclusive last index is MAX; does not overflow.
        let dir = Tmp::new("validator-cli-test");
        let (cfg, _) = load_recover(&[
            "--output-dir",
            dir.str(),
            "--start-index",
            "4294967295",
            "--count",
            "1",
        ])
        .expect("ok");
        assert_eq!(cfg.start_index, u32::MAX);
        assert_eq!(cfg.count, 1);
    }

    // --- output-dir validation ---

    #[test]
    fn missing_output_dir_is_clap_error() {
        assert!(parse_new(&[]).is_err());
        assert!(parse_recover(&["--count", "1"]).is_err());
    }

    #[test]
    fn nonexistent_output_dir_is_exit2() {
        let dir = Tmp::new("validator-cli-test");
        let missing = dir.0.join("no-such");
        let err = load_new_err(&["--output-dir", missing.to_str().unwrap()]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn file_as_output_dir_is_exit2() {
        let dir = Tmp::new("validator-cli-test");
        let file = dir.0.join("a-file");
        std::fs::write(&file, b"x").unwrap();
        let err = load_new_err(&["--output-dir", file.to_str().unwrap()]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("not a directory"));
    }

    #[cfg(unix)]
    #[test]
    fn recover_load_config_warns_on_symlinked_output_dir() {
        use std::os::unix::fs::symlink;

        let dir = Tmp::new("validator-cli-test");
        let real = dir.0.join("real-out");
        std::fs::create_dir(&real).unwrap();
        let link = dir.0.join("link-out");
        symlink(&real, &link).unwrap();
        let resolved = std::fs::canonicalize(&real).unwrap();

        let (_, banner) = load_recover(&[
            "--output-dir",
            link.to_str().unwrap(),
            "--count",
            "1",
            "--start-index",
            "0",
        ])
        .expect("ok");
        // Kind-specific: count the symlink banner warning, not every WARNING (FR-21 / R-3).
        let warning_lines: Vec<_> = banner
            .lines()
            .filter(|l| l.contains("is a symlink"))
            .collect();
        assert_eq!(
            warning_lines.len(),
            1,
            "expected exactly one symlink WARNING, got: {banner}"
        );
        assert!(
            warning_lines[0].contains(link.to_str().unwrap()),
            "must name given path: {banner}"
        );
        assert!(
            warning_lines[0].contains(resolved.to_str().unwrap()),
            "must name resolved path: {banner}"
        );

        let (_, banner) = load_recover(&[
            "--output-dir",
            real.to_str().unwrap(),
            "--count",
            "1",
            "--start-index",
            "0",
        ])
        .expect("ok");
        assert!(
            !banner.contains("WARNING"),
            "real dir must be warning-free: {banner}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unwritable_output_dir_is_exit2() {
        use std::os::unix::fs::PermissionsExt;

        let dir = Tmp::new("validator-cli-test");
        let locked = dir.0.join("locked");
        std::fs::create_dir(&locked).unwrap();
        // Drop write bit for owner/group/other; exclusive probe create must fail.
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
        let dir = Tmp::new("validator-cli-test");
        let (cfg, _) = load_new(&["--output-dir", dir.str()]).unwrap();
        assert_eq!(cfg.mnemonic_passphrase, MnemonicPassphraseForm::Empty);
    }

    #[test]
    fn mnemonic_passphrase_raw_value() {
        let dir = Tmp::new("validator-cli-test");
        let (cfg, _) =
            load_new(&["--output-dir", dir.str(), "--mnemonic-passphrase", "TREZOR"]).unwrap();
        assert_eq!(
            cfg.mnemonic_passphrase,
            MnemonicPassphraseForm::Raw(Zeroizing::new("TREZOR".into()))
        );
    }

    #[test]
    fn mnemonic_passphrase_bare_is_prompt() {
        let dir = Tmp::new("validator-cli-test");
        let (cfg, _) = load_new(&["--output-dir", dir.str(), "--mnemonic-passphrase"]).unwrap();
        assert_eq!(cfg.mnemonic_passphrase, MnemonicPassphraseForm::Prompt);
    }

    #[test]
    fn mnemonic_passphrase_env_reads_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = Tmp::new("validator-cli-test");
        let var = format!("ETHERNAL_TEST_MNEMONIC_PW_{}", std::process::id());
        std::env::set_var(&var, "from-env");
        let result = load_new(&["--output-dir", dir.str(), "--mnemonic-passphrase-env", &var]);
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
        let dir = Tmp::new("validator-cli-test");
        let var = format!("ETHERNAL_TEST_MNEMONIC_PW_EMPTY_{}", std::process::id());
        std::env::set_var(&var, "");
        let result = load_new(&["--output-dir", dir.str(), "--mnemonic-passphrase-env", &var]);
        std::env::remove_var(&var);
        let (cfg, _) = result.expect("empty mnemonic passphrase is valid");
        match cfg.mnemonic_passphrase {
            MnemonicPassphraseForm::Env { value, .. } => assert_eq!(value.as_str(), ""),
            other => panic!("expected Env, got {other:?}"),
        }
    }

    #[test]
    fn validator_config_debug_redacts_mnemonic_passphrase() {
        let raw = MnemonicPassphraseForm::Raw(Zeroizing::new("SUPER_SECRET".into()));
        let cfg = ValidatorConfig {
            mode: ValidatorMode::New,
            count: 1,
            output_dir: "/out".into(),
            start_index: 0,
            passphrase_env: String::new(),
            mnemonic_passphrase: raw,
            verify_keystore: true,
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("SUPER_SECRET"),
            "ValidatorConfig Debug leaked: {dbg}"
        );
    }

    #[test]
    fn mnemonic_passphrase_env_unset_is_exit2() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = Tmp::new("validator-cli-test");
        let var = format!("ETHERNAL_TEST_MNEMONIC_PW_UNSET_{}", std::process::id());
        std::env::remove_var(&var);
        let m = parse_new(&["--output-dir", dir.str(), "--mnemonic-passphrase-env", &var]).unwrap();
        let mut banner = Vec::new();
        let err = load_config(&m, ValidatorMode::New, &mut banner).unwrap_err();
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("is not set"));
    }

    #[test]
    fn mnemonic_passphrase_raw_and_env_conflict() {
        let dir = Tmp::new("validator-cli-test");
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
        let dir = Tmp::new("validator-cli-test");
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
