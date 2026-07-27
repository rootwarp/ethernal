//! The nested `account` CLI surface: clap schema, shared config/validation, and
//! the `account new` non-TTY guard. Runtime derivation lives in
//! [`crate::account_cmd`] (A3-4 / A4).

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgMatches, Command};
use ethernal_core::cancel::CancelToken;

use crate::account_cmd;
use crate::errors::AppError;
use crate::fs_util;
use crate::keystore_cli::{
    parse_mnemonic_passphrase_form, require_tty_for_new, shared_args, MnemonicPassphraseForm,
    START_INDEX_OVERFLOW_MSG,
};

/// Which `account` subcommand is being run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountMode {
    New,
    Recover,
}

/// Validated inputs for `account new` / `account recover`.
///
/// Identical shape to [`crate::validator_cli::ValidatorConfig`] minus pubkey/withdrawal
/// concerns (EOA = one keypair; the `account` namespace is the type selector —
/// F-8, U-3). [`Debug`] redacts mnemonic-passphrase secret payloads (S-2).
#[derive(Clone, PartialEq, Eq)]
pub struct AccountConfig {
    pub mode: AccountMode,
    /// Number of EOA keystores to produce (default 1). Must be ≥ 1.
    pub count: u32,
    /// Existing, writable directory for keystore files.
    pub output_dir: String,
    /// First HD derivation index. Always 0 for `account new`; operator-set on
    /// `account recover` (default 0).
    pub start_index: u32,
    /// Path to the keystore passphrase file. `None` means the runtime falls
    /// back to a TTY prompt-with-confirm (A3-4 / FR-5).
    pub passphrase_file: Option<PathBuf>,
    /// Resolved mnemonic-passphrase form (flag / file value / prompt / empty).
    pub mnemonic_passphrase: MnemonicPassphraseForm,
}

impl fmt::Debug for AccountConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountConfig")
            .field("mode", &self.mode)
            .field("count", &self.count)
            .field("output_dir", &self.output_dir)
            .field("start_index", &self.start_index)
            .field("passphrase_file", &self.passphrase_file)
            // Delegates to MnemonicPassphraseForm's redacting Debug.
            .field("mnemonic_passphrase", &self.mnemonic_passphrase)
            .finish()
    }
}

/// The clap definition of the nested `account` group (`account new` /
/// `account recover`).
pub fn command() -> Command {
    Command::new("account")
        .about(
            "Generate or recover Web3 v3 (geth/foundry/MetaMask) EOA keystores from a BIP-39 mnemonic",
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(new_command())
        .subcommand(recover_command())
}

fn new_command() -> Command {
    Command::new("new")
        .about(
            "Generate a fresh 24-word mnemonic and write Web3 v3 EOA keystores (TTY only)",
        )
        .override_usage("ethernal account new --output-dir DIR [--count N] [--passphrase-file PATH] [--mnemonic-passphrase [VALUE] | --mnemonic-passphrase-file PATH]")
        .long_about(
            "Generates a fresh 24-word English BIP-39 mnemonic from OS CSPRNG entropy, runs a\n\
             display-once + full re-entry ceremony on the controlling terminal, then derives\n\
             and encrypts one Web3 Secret Storage v3 keystore per BIP-44 index\n\
             (m/44'/60'/0'/0/i).\n\n\
             TTY-only: stdin and stdout must both be terminals; otherwise the command exits 2\n\
             before generating anything (a mnemonic must never land on a pipe or log).\n\n\
             Examples:\n\n\
             \x20 ethernal account new --output-dir ./keys --count 1\n\
             \x20 ethernal account new --output-dir ./keys --passphrase-file ./ks.pw\n\
             \x20 ethernal account new --output-dir ./keys --mnemonic-passphrase-file ./mp.pw",
        )
        .args(shared_args())
}

fn recover_command() -> Command {
    Command::new("recover")
        .about("Recover Web3 v3 EOA keystores from an existing BIP-39 mnemonic")
        .override_usage("ethernal account recover --output-dir DIR [--count N] [--start-index N] [--passphrase-file PATH] [--mnemonic-passphrase [VALUE] | --mnemonic-passphrase-file PATH]")
        .long_about(
            "Reads an existing BIP-39 mnemonic from an interactive TTY prompt or piped stdin,\n\
             validates word membership and checksum (12/15/18/21/24 words), then derives and\n\
             encrypts v3 keystores for the index range [--start-index, --start-index+--count)\n\
             at m/44'/60'/0'/0/i.\n\n\
             Unlike `account new`, there is no display/re-entry ceremony — the mnemonic already\n\
             exists and the exposure decision was the caller's.\n\n\
             Examples:\n\n\
             \x20 ethernal account recover --output-dir ./keys --count 3 --start-index 0\n\
             \x20 echo \"$MNEMONIC\" | ethernal account recover --output-dir ./keys",
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

/// `account new` entry: non-TTY guard first, validate config, then ceremony +
/// derive → encrypt → write (A3-4).
pub fn run_new(m: &ArgMatches, cancel: &CancelToken) -> Result<(), AppError> {
    // F-5: exit 2 before generating when stdin or stdout is not a TTY.
    require_tty_for_new()?;

    let mut stderr = std::io::stderr();
    let cfg = load_config(m, AccountMode::New, &mut stderr)?;
    account_cmd::run_account_new(&cfg, cancel)
}

/// `account recover` entry: validate config, then read mnemonic (TTY or pipe) →
/// validate → derive → encrypt → write (A4). Exempt from the TTY-only gate.
pub fn run_recover(m: &ArgMatches, cancel: &CancelToken) -> Result<(), AppError> {
    let mut stderr = std::io::stderr();
    let cfg = load_config(m, AccountMode::Recover, &mut stderr)?;
    account_cmd::run_account_recover(&cfg, cancel)
}

/// Builds a validated [`AccountConfig`] from parsed flags.
///
/// Validation order mirrors [`crate::validator_cli::load_config`]: count → start-index
/// → index-range overflow → output-dir → mnemonic-passphrase form →
/// passphrase-file, then confirmation banner. Bad `--count` / overflowing
/// range / unwritable `--output-dir` → exit 2.
///
/// I-1: keystore passphrase file is **not** read here — only the path is
/// captured. The actual `FileSource` read fires later in `finish_from_mnemonic`.
pub fn load_config(
    m: &ArgMatches,
    mode: AccountMode,
    banner_out: &mut dyn Write,
) -> Result<AccountConfig, AppError> {
    // 1. --count: default 1; must be ≥ 1.
    let count = *m.get_one::<u32>("count").unwrap();
    if count == 0 {
        return Err(AppError::exit2("--count: value 0 is invalid; must be >= 1"));
    }

    // 2. --start-index: recover only (default 0); new always starts at 0.
    let start_index = match mode {
        AccountMode::New => 0,
        AccountMode::Recover => *m.get_one::<u32>("start-index").unwrap(),
    };

    // 2b. Index range must fit u32 before any ceremony/write.
    // Inclusive last index is start_index + count - 1; count ≥ 1 here.
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

    // 4. Mnemonic passphrase form (XOR via conflicts_with: raw/prompt ⊥ file).
    // File form reads here (I-2: permission WARNING erased on `new`, durable on
    // `recover` — same property as the symlinked-output-dir WARNING above).
    let mnemonic_passphrase = parse_mnemonic_passphrase_form(m, banner_out)?;

    // 5. Keystore passphrase file path (None → runtime TTY prompt). Path only —
    // content is read later via FileSource in finish_from_mnemonic (I-1).
    let passphrase_file = match m.get_one::<String>("passphrase-file") {
        Some(v) => Some(fs_util::secret_file_arg("--passphrase-file", v)?),
        None => None,
    };

    let cfg = AccountConfig {
        mode,
        count,
        output_dir,
        start_index,
        passphrase_file,
        mnemonic_passphrase,
    };

    print_banner(banner_out, &cfg);
    Ok(cfg)
}

/// Confirmation banner to stderr before the (future) pipeline runs.
fn print_banner(w: &mut dyn Write, cfg: &AccountConfig) {
    let verb = match cfg.mode {
        AccountMode::New => "new",
        AccountMode::Recover => "recover",
    };
    match cfg.mode {
        AccountMode::New => {
            let _ = writeln!(
                w,
                "ethernal account {verb}: count={} output_dir={}",
                cfg.count, cfg.output_dir
            );
        }
        AccountMode::Recover => {
            let _ = writeln!(
                w,
                "ethernal account {verb}: count={} start_index={} output_dir={}",
                cfg.count, cfg.start_index, cfg.output_dir
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::exit_code_for;
    use crate::test_support::Tmp;
    use zeroize::Zeroizing;

    /// Write secret fixture bytes at mode 0600 for unit tests (mirrors
    /// `common::secret_file` for the bin unit-test seam).
    fn write_secret(dir: &Tmp, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.0.join(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path).expect("create secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .expect("chmod 0600");
        }
        use std::io::Write;
        f.write_all(bytes).expect("write secret");
        path
    }

    fn parse_new(args: &[&str]) -> Result<ArgMatches, String> {
        let mut argv = vec!["account", "new"];
        argv.extend_from_slice(args);
        command()
            .try_get_matches_from(argv)
            .map(|m| m.subcommand().unwrap().1.clone())
            .map_err(|e| format!("clap: {e}"))
    }

    fn parse_recover(args: &[&str]) -> Result<ArgMatches, String> {
        let mut argv = vec!["account", "recover"];
        argv.extend_from_slice(args);
        command()
            .try_get_matches_from(argv)
            .map(|m| m.subcommand().unwrap().1.clone())
            .map_err(|e| format!("clap: {e}"))
    }

    fn load_new(args: &[&str]) -> Result<(AccountConfig, String), String> {
        let m = parse_new(args)?;
        let mut banner = Vec::new();
        let cfg =
            load_config(&m, AccountMode::New, &mut banner).map_err(|e| format!("load: {e}"))?;
        Ok((cfg, String::from_utf8(banner).unwrap()))
    }

    fn load_recover(args: &[&str]) -> Result<(AccountConfig, String), String> {
        let m = parse_recover(args)?;
        let mut banner = Vec::new();
        let cfg =
            load_config(&m, AccountMode::Recover, &mut banner).map_err(|e| format!("load: {e}"))?;
        Ok((cfg, String::from_utf8(banner).unwrap()))
    }

    fn load_new_err(args: &[&str]) -> AppError {
        let m = parse_new(args).expect("clap parse ok");
        let mut banner = Vec::new();
        load_config(&m, AccountMode::New, &mut banner).expect_err("load should fail")
    }

    fn load_recover_err(args: &[&str]) -> AppError {
        let m = parse_recover(args).expect("clap parse ok");
        let mut banner = Vec::new();
        load_config(&m, AccountMode::Recover, &mut banner).expect_err("load should fail")
    }

    // --- namespace shape ---

    #[test]
    fn account_namespace_requires_subcommand() {
        let err = command()
            .try_get_matches_from(["account"])
            .expect_err("subcommand required");
        let msg = err.to_string();
        assert!(
            msg.contains("subcommand") || msg.contains("required"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn account_new_and_recover_parse() {
        let dir = Tmp::new("account-cli-test");
        assert!(parse_new(&["--output-dir", dir.str()]).is_ok());
        assert!(parse_recover(&["--output-dir", dir.str()]).is_ok());
    }

    #[test]
    fn account_help_does_not_mention_bls_or_eip2335() {
        let mut cmd = command();
        let mut buf = Vec::new();
        cmd.write_long_help(&mut buf).unwrap();
        let help = String::from_utf8(buf).unwrap();
        assert!(
            !help.to_lowercase().contains("eip-2335") && !help.to_lowercase().contains("eip2335"),
            "account help must not mention EIP-2335: {help}"
        );
        assert!(
            !help.to_lowercase().contains("bls"),
            "account help must not mention BLS: {help}"
        );
        assert!(
            !help.contains("withdrawal"),
            "account help must not mention withdrawal: {help}"
        );
    }

    // --- defaults and flags ---

    #[test]
    fn count_defaults_to_one() {
        let dir = Tmp::new("account-cli-test");
        let (cfg, banner) = load_new(&["--output-dir", dir.str()]).expect("ok");
        assert_eq!(cfg.count, 1);
        assert_eq!(cfg.mode, AccountMode::New);
        assert_eq!(cfg.start_index, 0);
        assert_eq!(cfg.output_dir, dir.str());
        assert_eq!(cfg.passphrase_file, None);
        assert_eq!(cfg.mnemonic_passphrase, MnemonicPassphraseForm::Empty);
        assert!(banner.contains("ethernal account new:"));
        assert!(banner.contains("count=1"));
    }

    #[test]
    fn count_and_passphrase_file_propagate() {
        let dir = Tmp::new("account-cli-test");
        let pw = write_secret(&dir, "ks.pw", b"password1");
        let (cfg, _) = load_new(&[
            "--output-dir",
            dir.str(),
            "--count",
            "4",
            "--passphrase-file",
            pw.to_str().unwrap(),
        ])
        .expect("ok");
        assert_eq!(cfg.count, 4);
        assert_eq!(cfg.passphrase_file.as_deref(), Some(pw.as_path()));
    }

    #[test]
    fn passphrase_file_dash_is_exit2() {
        let dir = Tmp::new("account-cli-test");
        let err = load_new_err(&["--output-dir", dir.str(), "--passphrase-file", "-"]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(
            err.to_string().contains("cannot be '-'") || err.to_string().contains("path cannot"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn recover_start_index_default_and_set() {
        let dir = Tmp::new("account-cli-test");
        let (cfg, banner) = load_recover(&["--output-dir", dir.str()]).expect("ok");
        assert_eq!(cfg.start_index, 0);
        assert_eq!(cfg.mode, AccountMode::Recover);
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
        // `account new` has no --start-index; config always reports 0.
        let dir = Tmp::new("account-cli-test");
        let (cfg, _) = load_new(&["--output-dir", dir.str()]).unwrap();
        assert_eq!(cfg.start_index, 0);
        assert!(parse_new(&["--output-dir", dir.str(), "--start-index", "1"]).is_err());
    }

    // --- count validation ---

    #[test]
    fn bad_count_is_exit2() {
        let dir = Tmp::new("account-cli-test");
        let err = load_new_err(&["--output-dir", dir.str(), "--count", "0"]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("--count"));
    }

    // --- index-range overflow ---

    #[test]
    fn start_index_plus_count_overflow_is_exit2() {
        let dir = Tmp::new("account-cli-test");
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
        let dir = Tmp::new("account-cli-test");
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
        let dir = Tmp::new("account-cli-test");
        let missing = dir.0.join("no-such");
        let err = load_new_err(&["--output-dir", missing.to_str().unwrap()]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn file_as_output_dir_is_exit2() {
        let dir = Tmp::new("account-cli-test");
        let file = dir.0.join("a-file");
        std::fs::write(&file, b"x").unwrap();
        let err = load_new_err(&["--output-dir", file.to_str().unwrap()]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("not a directory"));
    }

    #[test]
    fn validate_output_dir_negative() {
        let dir = Tmp::new("account-cli-test");
        let missing = dir.0.join("missing");
        let err = fs_util::validate_output_dir(missing.to_str().unwrap()).unwrap_err();
        assert!(err.contains("does not exist"), "{err}");

        let file = dir.0.join("not-dir");
        std::fs::write(&file, b"x").unwrap();
        let err = fs_util::validate_output_dir(file.to_str().unwrap()).unwrap_err();
        assert!(err.contains("not a directory"), "{err}");

        assert!(fs_util::validate_output_dir(dir.str()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn recover_load_config_warns_on_symlinked_output_dir() {
        use std::os::unix::fs::symlink;

        let dir = Tmp::new("account-cli-test");
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

        let dir = Tmp::new("account-cli-test");
        let locked = dir.0.join("locked");
        std::fs::create_dir(&locked).unwrap();
        let mut perms = std::fs::metadata(&locked).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&locked, perms).unwrap();

        let err = load_new_err(&["--output-dir", locked.to_str().unwrap()]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(
            err.to_string().contains("not writable"),
            "expected not-writable message, got: {err}"
        );

        let mut perms = std::fs::metadata(&locked).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&locked, perms).unwrap();
    }

    // --- three-form mnemonic passphrase ---

    #[test]
    fn mnemonic_passphrase_absent_is_empty() {
        let dir = Tmp::new("account-cli-test");
        let (cfg, _) = load_new(&["--output-dir", dir.str()]).unwrap();
        assert_eq!(cfg.mnemonic_passphrase, MnemonicPassphraseForm::Empty);
    }

    #[test]
    fn mnemonic_passphrase_raw_value() {
        let dir = Tmp::new("account-cli-test");
        let (cfg, _) =
            load_new(&["--output-dir", dir.str(), "--mnemonic-passphrase", "TREZOR"]).unwrap();
        assert_eq!(
            cfg.mnemonic_passphrase,
            MnemonicPassphraseForm::Raw(Zeroizing::new("TREZOR".into()))
        );
    }

    #[test]
    fn mnemonic_passphrase_bare_is_prompt() {
        let dir = Tmp::new("account-cli-test");
        let (cfg, _) = load_new(&["--output-dir", dir.str(), "--mnemonic-passphrase"]).unwrap();
        assert_eq!(cfg.mnemonic_passphrase, MnemonicPassphraseForm::Prompt);
    }

    #[test]
    fn mnemonic_passphrase_file_reads_value() {
        let dir = Tmp::new("account-cli-test");
        let path = write_secret(&dir, "mp.pw", b"from-file");
        let (cfg, _) = load_new(&[
            "--output-dir",
            dir.str(),
            "--mnemonic-passphrase-file",
            path.to_str().unwrap(),
        ])
        .expect("ok");
        match cfg.mnemonic_passphrase {
            MnemonicPassphraseForm::File { path: p, value } => {
                assert_eq!(p, path.display().to_string());
                assert_eq!(value.as_str(), "from-file");
            }
            other => panic!("expected File, got {other:?}"),
        }
    }

    #[test]
    fn mnemonic_passphrase_file_empty_zero_bytes_accepted() {
        let dir = Tmp::new("account-cli-test");
        let path = write_secret(&dir, "mp-empty.pw", b"");
        let (cfg, _) = load_new(&[
            "--output-dir",
            dir.str(),
            "--mnemonic-passphrase-file",
            path.to_str().unwrap(),
        ])
        .expect("empty mnemonic passphrase is valid");
        match cfg.mnemonic_passphrase {
            MnemonicPassphraseForm::File { value, .. } => assert_eq!(value.as_str(), ""),
            other => panic!("expected File, got {other:?}"),
        }
    }

    #[test]
    fn mnemonic_passphrase_file_lone_newline_accepted() {
        let dir = Tmp::new("account-cli-test");
        let path = write_secret(&dir, "mp-nl.pw", b"\n");
        let (cfg, _) = load_new(&[
            "--output-dir",
            dir.str(),
            "--mnemonic-passphrase-file",
            path.to_str().unwrap(),
        ])
        .expect("lone \\n is valid empty mnemonic passphrase");
        match cfg.mnemonic_passphrase {
            MnemonicPassphraseForm::File { value, .. } => assert_eq!(value.as_str(), ""),
            other => panic!("expected File, got {other:?}"),
        }
    }

    #[test]
    fn mnemonic_passphrase_file_dash_is_exit2() {
        let dir = Tmp::new("account-cli-test");
        let err = load_new_err(&["--output-dir", dir.str(), "--mnemonic-passphrase-file", "-"]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(
            err.to_string().contains("cannot be '-'") || err.to_string().contains("path cannot"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn mnemonic_passphrase_debug_redacts_secrets() {
        let raw = MnemonicPassphraseForm::Raw(Zeroizing::new("SUPER_SECRET".into()));
        let cfg = AccountConfig {
            mode: AccountMode::New,
            count: 1,
            output_dir: "/out".into(),
            start_index: 0,
            passphrase_file: None,
            mnemonic_passphrase: raw,
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("SUPER_SECRET"),
            "AccountConfig Debug leaked: {dbg}"
        );
        assert!(dbg.contains("REDACTED"), "{dbg}");
    }

    #[test]
    fn mnemonic_passphrase_raw_and_file_conflict() {
        let dir = Tmp::new("account-cli-test");
        let err = parse_new(&[
            "--output-dir",
            dir.str(),
            "--mnemonic-passphrase",
            "x",
            "--mnemonic-passphrase-file",
            "Y",
        ]);
        assert!(err.is_err(), "raw and file must conflict");
    }

    #[test]
    fn mnemonic_passphrase_bare_and_file_conflict() {
        let dir = Tmp::new("account-cli-test");
        let err = parse_new(&[
            "--output-dir",
            dir.str(),
            "--mnemonic-passphrase",
            "--mnemonic-passphrase-file",
            "Y",
        ]);
        assert!(err.is_err(), "bare and file must conflict");
    }

    // --- recover: same four forms (shared args; A4-2 F-12 both commands) ---

    #[test]
    fn recover_mnemonic_passphrase_four_forms_and_empty_default() {
        let dir = Tmp::new("account-cli-test");
        let (cfg, _) = load_recover(&["--output-dir", dir.str()]).unwrap();
        assert_eq!(cfg.mnemonic_passphrase, MnemonicPassphraseForm::Empty);

        let (cfg, _) =
            load_recover(&["--output-dir", dir.str(), "--mnemonic-passphrase", "TREZOR"]).unwrap();
        assert_eq!(
            cfg.mnemonic_passphrase,
            MnemonicPassphraseForm::Raw(Zeroizing::new("TREZOR".into()))
        );

        let (cfg, _) = load_recover(&["--output-dir", dir.str(), "--mnemonic-passphrase"]).unwrap();
        assert_eq!(cfg.mnemonic_passphrase, MnemonicPassphraseForm::Prompt);

        let path = write_secret(&dir, "rec-mp.pw", b"from-file");
        let (cfg, _) = load_recover(&[
            "--output-dir",
            dir.str(),
            "--mnemonic-passphrase-file",
            path.to_str().unwrap(),
        ])
        .expect("ok");
        match cfg.mnemonic_passphrase {
            MnemonicPassphraseForm::File { path: p, value } => {
                assert_eq!(p, path.display().to_string());
                assert_eq!(value.as_str(), "from-file");
            }
            other => panic!("expected File, got {other:?}"),
        }
    }

    #[test]
    fn recover_mnemonic_passphrase_file_missing_is_exit2() {
        let dir = Tmp::new("account-cli-test");
        let missing = dir.0.join("no-such-mp.pw");
        let m = parse_recover(&[
            "--output-dir",
            dir.str(),
            "--mnemonic-passphrase-file",
            missing.to_str().unwrap(),
        ])
        .unwrap();
        let mut banner = Vec::new();
        let err = load_config(&m, AccountMode::Recover, &mut banner).unwrap_err();
        assert_eq!(exit_code_for(&err), 2);
        assert!(
            err.to_string().contains("--mnemonic-passphrase-file"),
            "unexpected: {err}"
        );
    }
}
