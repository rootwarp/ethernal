//! `account new` / `account recover` runtime: ceremony (new only) + derive →
//! address → encrypt_v3 → write pipeline.
//!
//! Dependencies are injectable via [`AccountDeps`] so unit tests can drive the
//! full flow with [`FixedEntropy`] (test-only), scripted line sources, fixed
//! [`Timestamp`], and buffers — no real terminal required.
//!
//! Differs from [`crate::key_cmd::KeyDeps`] in the address-based summary and the
//! nanos-carrying [`Timestamp`] (geth `UTC--` filenames need 9-digit nanos).

use std::io::{self, Write};
use std::path::Path;

use ethernal_core::bip39::{self, Bip39Error};
use ethernal_core::cancel::CancelToken;
use ethernal_core::entropy::{Entropy, EntropyError, OsEntropy};
use ethernal_core::hd_secp256k1::{self, Bip32Error, Bip44Path};
use ethernal_core::output::{write_new_0600, OutputError};
use ethernal_keystore::encrypt_v3::{encrypt_v3, v3_filename, EncryptV3Input, ScryptParams};
use ethernal_keystore::{
    EnvSource, KeystoreError, NewKeystorePassphrase, PassphraseSource, KEYSTORE_PASSPHRASE_MIN_LEN,
};
use ethernal_signer::{eip55_checksum, secret_to_address, SignerError};
use zeroize::Zeroizing;

use crate::account_cli::AccountConfig;
use crate::errors::AppError;
use crate::gen_cmd::Progress;
use crate::key_cmd::{
    check_cancel, resolve_mnemonic_passphrase, run_ceremony, MinLenPassphrase, MnemonicSource,
    RecoverMnemonicSource, StdinMnemonicSource,
};
use crate::logging::{Format, Level, Logger};

// ---------------------------------------------------------------------------
// Injectable seams
// ---------------------------------------------------------------------------

/// Wall-clock instant for geth-style `UTC--` keystore filenames.
///
/// Nanos are load-bearing (9-digit fraction); this is why [`AccountDeps`] is
/// not shared with `KeyDeps` (which only needs whole-second timestamps).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    pub unix_secs: i64,
    pub nanos: u32,
}

/// Injectable dependencies for [`run_account_new_with_deps`] /
/// [`run_account_recover_with_deps`].
///
/// Production values come from [`run_account_new`] / [`run_account_recover`];
/// tests replace any piece.
pub struct AccountDeps<'a> {
    pub cfg: &'a AccountConfig,
    /// CSPRNG for mnemonic entropy and per-keystore salt/iv/uuid.
    pub entropy: &'a dyn Entropy,
    /// Keystore encryption passphrase (confirm+≥8 or env+min-len).
    pub keystore_pw: &'a dyn PassphraseSource,
    /// Ceremony re-entry / recover mnemonic / mnemonic-passphrase prompts.
    pub mnemonic_src: &'a dyn MnemonicSource,
    /// Where the mnemonic is displayed **once** on `account new` (TTY only;
    /// never stdout/stderr/logger). Unused by `account recover` (may be
    /// `io::sink()`).
    pub tty_writer: &'a mut dyn Write,
    /// Progress + end-of-run summary (stderr in production).
    pub summary_out: &'a mut dyn Write,
    pub progress: Progress,
    pub logger: &'a Logger,
    /// Wall-clock for `UTC--` filenames (injectable for deterministic tests).
    pub timestamp: Timestamp,
    /// scrypt cost for v3 encrypt. Production: [`ScryptParams::STANDARD`].
    /// Unit tests inject [`ScryptParams::FAST`] so the suite stays snappy.
    pub scrypt: ScryptParams,
}

// ---------------------------------------------------------------------------
// Production entry
// ---------------------------------------------------------------------------

/// Production entry for `account new`: assembles real deps and runs the pipeline.
pub fn run_account_new(cfg: &AccountConfig, cancel: &CancelToken) -> Result<(), AppError> {
    let logger = Logger::stderr(Level::Info, Format::Text);
    let entropy = OsEntropy;
    let progress = if stderr_is_tty() {
        Progress::Tty
    } else {
        Progress::NonTty
    };
    let timestamp = wall_clock_timestamp();

    // Keystore passphrase: env + min-len, or interactive confirm+≥8.
    let env_source;
    let checked_env;
    let tty_pw;
    let keystore_pw: &dyn PassphraseSource = if !cfg.passphrase_env.is_empty() {
        env_source = EnvSource::new(&cfg.passphrase_env);
        checked_env = MinLenPassphrase {
            inner: &env_source,
            min: KEYSTORE_PASSPHRASE_MIN_LEN,
        };
        &checked_env
    } else {
        tty_pw = NewKeystorePassphrase::new(std::io::stderr());
        &tty_pw
    };

    let mnemonic_src = StdinMnemonicSource::new(std::io::stderr());
    // Controlling terminal for the one-time mnemonic display (S-2).
    // Fail closed: never fall back to stderr (would log the mnemonic).
    let mut tty_writer = open_tty_writer().map_err(|e| {
        AppError::exit2(format!(
            "account new: cannot open controlling terminal for mnemonic display: {e}; \
             refusing to print the mnemonic to stderr"
        ))
    })?;
    let mut summary_out = std::io::stderr();

    let mut deps = AccountDeps {
        cfg,
        entropy: &entropy,
        keystore_pw,
        mnemonic_src: &mnemonic_src,
        tty_writer: &mut tty_writer,
        summary_out: &mut summary_out,
        progress,
        logger: &logger,
        timestamp,
        scrypt: ScryptParams::STANDARD,
    };
    run_account_new_with_deps(&mut deps, cancel)
}

/// Production entry for `account recover`: assembles real deps and runs the pipeline.
pub fn run_account_recover(cfg: &AccountConfig, cancel: &CancelToken) -> Result<(), AppError> {
    let logger = Logger::stderr(Level::Info, Format::Text);
    let entropy = OsEntropy;
    let progress = if stderr_is_tty() {
        Progress::Tty
    } else {
        Progress::NonTty
    };
    let timestamp = wall_clock_timestamp();

    // Keystore passphrase: env + min-len, or interactive confirm+≥8.
    let env_source;
    let checked_env;
    let tty_pw;
    let keystore_pw: &dyn PassphraseSource = if !cfg.passphrase_env.is_empty() {
        env_source = EnvSource::new(&cfg.passphrase_env);
        checked_env = MinLenPassphrase {
            inner: &env_source,
            min: KEYSTORE_PASSPHRASE_MIN_LEN,
        };
        &checked_env
    } else {
        tty_pw = NewKeystorePassphrase::new(std::io::stderr());
        &tty_pw
    };

    // TTY prompt or piped stdin (F-10); no TTY-only gate on recover.
    let mnemonic_src = RecoverMnemonicSource::new(std::io::stderr());
    let mut tty_writer = io::sink();
    let mut summary_out = std::io::stderr();

    let mut deps = AccountDeps {
        cfg,
        entropy: &entropy,
        keystore_pw,
        mnemonic_src: &mnemonic_src,
        tty_writer: &mut tty_writer,
        summary_out: &mut summary_out,
        progress,
        logger: &logger,
        timestamp,
        scrypt: ScryptParams::STANDARD,
    };
    run_account_recover_with_deps(&mut deps, cancel)
}

/// Opens `/dev/tty` for the mnemonic display only. **No stderr fallback** (S-2).
fn open_tty_writer() -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).open("/dev/tty")
}

fn stderr_is_tty() -> bool {
    // SAFETY: isatty is async-signal-safe and has no preconditions.
    unsafe { libc::isatty(2) == 1 }
}

fn wall_clock_timestamp() -> Timestamp {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp {
        unix_secs: d.as_secs() as i64,
        nanos: d.subsec_nanos(),
    }
}

// ---------------------------------------------------------------------------
// Pipeline — account new
// ---------------------------------------------------------------------------

/// Testable core of `account new`: entropy → mnemonic → mnemonic passphrase →
/// ceremony → seed → derive/address/encrypt_v3/write per index.
pub fn run_account_new_with_deps(
    deps: &mut AccountDeps<'_>,
    cancel: &CancelToken,
) -> Result<(), AppError> {
    let log = deps.logger;
    let cfg = deps.cfg;

    check_cancel(cancel)?;

    // 1. Draw 256-bit entropy → 24-word mnemonic (F-1, S-4).
    log.debug("account new: drawing entropy", &[]);
    let mut entropy_bytes = Zeroizing::new([0u8; 32]);
    deps.entropy
        .fill(entropy_bytes.as_mut())
        .map_err(map_entropy_err)?;
    let mnemonic = bip39::entropy_to_mnemonic(entropy_bytes.as_slice()).map_err(map_bip39_err)?;
    drop(entropy_bytes);

    let word_count = mnemonic.split_whitespace().count();
    log.debug(
        "account new: mnemonic generated",
        &[("words", word_count.to_string())],
    );
    if word_count != 24 {
        return Err(AppError::Internal(format!(
            "account new: expected 24-word mnemonic from 32-byte entropy, got {word_count}"
        )));
    }

    // 2. Mnemonic passphrase: flag > env > prompt-confirm; empty valid (F-12).
    check_cancel(cancel)?;
    let mnemonic_pass = resolve_mnemonic_passphrase(
        &cfg.mnemonic_passphrase,
        deps.mnemonic_src,
        cancel,
        /* confirm */ true,
    )?;

    // 3. Ceremony: display once on tty_writer, require full re-entry (F-6).
    check_cancel(cancel)?;
    run_ceremony(
        mnemonic.as_str(),
        deps.tty_writer,
        deps.summary_out,
        deps.mnemonic_src,
        cancel,
    )?;
    log.debug("account new: ceremony complete", &[]);

    // 4–6. Keystore passphrase → seed → derive/address/encrypt/write.
    finish_from_mnemonic(
        deps,
        cancel,
        mnemonic.as_str(),
        mnemonic_pass.as_slice(),
        "account new",
    )
}

// ---------------------------------------------------------------------------
// Pipeline — account recover
// ---------------------------------------------------------------------------

/// Testable core of `account recover`: read mnemonic (TTY/pipe) → validate →
/// mnemonic passphrase (single-entry prompt) → seed → derive/address/encrypt/write.
/// **No** display/re-entry ceremony (F-10).
pub fn run_account_recover_with_deps(
    deps: &mut AccountDeps<'_>,
    cancel: &CancelToken,
) -> Result<(), AppError> {
    let log = deps.logger;
    let cfg = deps.cfg;

    check_cancel(cancel)?;

    // 1. Existing mnemonic from TTY prompt or piped stdin (F-10).
    log.debug("account recover: reading mnemonic", &[]);
    let mnemonic = deps.mnemonic_src.read_line("Enter your mnemonic: ")?;
    // 2. Validate first — 12/15/18/21/24; bad word/checksum → exit 2 (F-11).
    bip39::validate_mnemonic(mnemonic.as_str()).map_err(map_bip39_err)?;
    let word_count = mnemonic.split_whitespace().count();
    log.debug(
        "account recover: mnemonic validated",
        &[("words", word_count.to_string())],
    );

    // 3. Mnemonic passphrase: flag > env > prompt (single-entry on recover).
    check_cancel(cancel)?;
    let mnemonic_pass = resolve_mnemonic_passphrase(
        &cfg.mnemonic_passphrase,
        deps.mnemonic_src,
        cancel,
        /* confirm */ false,
    )?;

    // 4–6. Keystore passphrase → seed → derive/address/encrypt/write (shared with new).
    finish_from_mnemonic(
        deps,
        cancel,
        mnemonic.as_str(),
        mnemonic_pass.as_slice(),
        "account recover",
    )
}

/// Shared tail: keystore passphrase → to_seed → per-index
/// derive → address → encrypt_v3 → write.
///
/// Used by both `account new` and `account recover`.
fn finish_from_mnemonic(
    deps: &mut AccountDeps<'_>,
    cancel: &CancelToken,
    mnemonic: &str,
    mnemonic_pass: &[u8],
    label: &str,
) -> Result<(), AppError> {
    let log = deps.logger;
    let cfg = deps.cfg;

    check_cancel(cancel)?;
    let keystore_pass = Zeroizing::new(deps.keystore_pw.read().map_err(map_passphrase_err)?);

    check_cancel(cancel)?;
    let seed = bip39::to_seed(mnemonic, mnemonic_pass).map_err(map_bip39_err)?;

    let count = cfg.count as usize;
    let start = cfg.start_index;
    let out_dir = Path::new(&cfg.output_dir);
    let mut written: Vec<(String, String)> = Vec::with_capacity(count);

    for i in 0..count {
        check_cancel(cancel)?;

        let index = start
            .checked_add(i as u32)
            .ok_or_else(|| AppError::exit2("--start-index + --count overflows u32"))?;
        let path = Bip44Path::eoa(index);
        let path_str = path.to_string();

        log.debug(
            &format!("{label}: deriving EOA key"),
            &[("index", index.to_string()), ("path", path_str.clone())],
        );

        let derived = hd_secp256k1::ExtendedPrivKey::derive_path(seed.as_slice(), &path)
            .map_err(map_bip32_err)?;
        let sk = derived.secret_bytes();
        let addr = secret_to_address(&sk).map_err(map_signer_err)?;
        let eip55 = eip55_checksum(&addr);

        let mut salt = [0u8; 32];
        let mut iv = [0u8; 16];
        let mut uuid_bytes = [0u8; 16];
        deps.entropy.fill(&mut salt).map_err(map_entropy_err)?;
        deps.entropy.fill(&mut iv).map_err(map_entropy_err)?;
        deps.entropy
            .fill(&mut uuid_bytes)
            .map_err(map_entropy_err)?;

        let json = encrypt_v3(&EncryptV3Input {
            secret: sk.as_slice(),
            password: keystore_pass.as_slice(),
            address: addr,
            salt,
            iv,
            uuid_bytes,
            scrypt: deps.scrypt,
        })
        .map_err(map_encrypt_err)?;

        check_cancel(cancel)?;

        // Filename is address + secs/nanos (geth UTC-- convention). On
        // same-nanosecond collision, retry once at nanos+1 before propagating
        // AlreadyExists / exit 3 (architecture collision policy / BLS H5 parity).
        // Never overwrites: write_new_0600 stays create_new-exclusive.
        let final_path =
            write_v3_at(out_dir, &addr, deps.timestamp, &json).map_err(map_write_err)?;

        let path_display = final_path.display().to_string();
        emit_account_progress(
            deps.progress,
            deps.summary_out,
            deps.logger,
            i + 1,
            count,
            &path_display,
            &eip55,
        );
        written.push((path_display, eip55));
    }

    print_account_summary(deps.summary_out, &written);
    log.debug(
        &format!("{label}: complete"),
        &[("count", written.len().to_string())],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Progress / summary (F-15) — stderr in production; EIP-55 addresses
// ---------------------------------------------------------------------------

fn emit_account_progress(
    progress: Progress,
    summary_out: &mut dyn Write,
    logger: &Logger,
    done: usize,
    total: usize,
    path: &str,
    eip55: &str,
) {
    match progress {
        Progress::Tty => {
            let _ = writeln!(
                summary_out,
                "keystore {done}/{total}: {path} (address={eip55})"
            );
            let _ = summary_out.flush();
        }
        Progress::NonTty => {
            logger.info(
                "keystore written",
                &[
                    ("done", done.to_string()),
                    ("total", total.to_string()),
                    ("path", path.to_string()),
                    ("address", eip55.to_string()),
                ],
            );
        }
    }
}

fn print_account_summary(w: &mut dyn Write, written: &[(String, String)]) {
    let n = written.len();
    let _ = writeln!(w, "wrote {n} keystore{}", if n == 1 { "" } else { "s" });
    for (path, eip55) in written {
        let _ = writeln!(w, "  {path}  address={eip55}");
    }
    let _ = w.flush();
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn map_entropy_err(e: EntropyError) -> AppError {
    AppError::Internal(e.to_string())
}

fn map_bip39_err(e: Bip39Error) -> AppError {
    AppError::Bip39(e)
}

/// BIP-32 derive failure → `AppError::Bip32` → exit 3 (A3-5).
fn map_bip32_err(e: Bip32Error) -> AppError {
    AppError::from(e)
}

fn map_signer_err(e: SignerError) -> AppError {
    AppError::Signer(e)
}

fn map_encrypt_err(e: KeystoreError) -> AppError {
    AppError::Keystore(e)
}

fn map_write_err(e: OutputError) -> AppError {
    // Call-site Exit{3}: gen's AppError::Output must stay → 1 (architecture fork a).
    AppError::Exit {
        msg: e.to_string(),
        code: 3,
    }
}

/// Write `json` to the geth-style `UTC--` path for `address` at `ts`.
///
/// On [`OutputError::AlreadyExists`] for `ts`, retries once at `nanos + 1`.
/// A collision at both timestamps propagates `AlreadyExists` (→ exit 3).
fn write_v3_at(
    out_dir: &Path,
    address: &[u8; 20],
    ts: Timestamp,
    json: &[u8],
) -> Result<std::path::PathBuf, OutputError> {
    let filename = v3_filename(address, ts.unix_secs, ts.nanos);
    let final_path = out_dir.join(&filename);
    match write_new_0600(&final_path, json) {
        Ok(()) => Ok(final_path),
        Err(OutputError::AlreadyExists) => {
            let retry_nanos = ts.nanos.wrapping_add(1);
            let filename = v3_filename(address, ts.unix_secs, retry_nanos);
            let final_path = out_dir.join(&filename);
            write_new_0600(&final_path, json)?;
            Ok(final_path)
        }
        Err(e) => Err(e),
    }
}

fn map_passphrase_err(e: KeystoreError) -> AppError {
    // PassphraseTooShort / Mismatch / EnvVarEmpty / NoTty → 2 via Keystore arm.
    AppError::Keystore(e)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_cli::AccountMode;
    use crate::errors::exit_code_for;
    use crate::key_cli::MnemonicPassphraseForm;
    use ethernal_keystore::require_min_len;
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// All-zero 32-byte entropy → `abandon` × 23 + `art` (24 words).
    const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    /// 12-word Trezor vector mnemonic (valid checksum).
    const ABANDON_12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// BIP-39 TREZOR vector seed for ABANDON_12 + passphrase "TREZOR".
    const TREZOR_SEED_HEX: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

    /// m/44'/60'/0'/0/0 for ABANDON_12 + TREZOR (seed-derivation anchor, A4-2).
    const TREZOR_EOA0_ADDR: &str = "9c32f71d4db8fb9e1a58b0a80df79935e7256fa6";

    /// m/44'/60'/0'/0/0 for ABANDON_12 + empty passphrase (must differ from TREZOR).
    const EMPTY_EOA0_ADDR: &str = "9858effd232b4033e47d90003d41ec34ecaeda94";

    /// 24-word zero-entropy mnemonic + TREZOR seed (bip39 unit-test vector).
    const ZERO_TREZOR_SEED_HEX: &str = "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8";

    /// Frozen timestamp for deterministic `UTC--` filenames.
    const TS: Timestamp = Timestamp {
        unix_secs: 1_784_384_525,
        nanos: 123_456_789,
    };

    // --- FixedEntropy (test-only; never in release binary — S-4) ---

    /// Deterministic entropy: pops pre-queued exact fills, then zeros.
    struct FixedEntropy {
        queue: Mutex<VecDeque<Vec<u8>>>,
    }

    impl FixedEntropy {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                queue: Mutex::new(chunks.into()),
            }
        }

        /// Mnemonic entropy all-zero (24-word abandon…art), then zeros for
        /// salt/iv/uuid of every keystore.
        fn zero_mnemonic() -> Self {
            Self::new(vec![vec![0u8; 32]])
        }
    }

    impl Entropy for FixedEntropy {
        fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError> {
            let mut q = self.queue.lock().expect("entropy queue lock");
            if let Some(next) = q.pop_front() {
                assert_eq!(
                    next.len(),
                    buf.len(),
                    "FixedEntropy chunk len {} != buf {}",
                    next.len(),
                    buf.len()
                );
                buf.copy_from_slice(&next);
            } else {
                buf.fill(0);
            }
            Ok(())
        }
    }

    /// Cancels `token` on the Nth `fill` call (1-based), then fills zeros.
    struct CancelOnFill {
        n: usize,
        count: AtomicUsize,
        token: CancelToken,
    }

    impl Entropy for CancelOnFill {
        fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError> {
            let c = self.count.fetch_add(1, Ordering::SeqCst) + 1;
            if c == 1 {
                // First fill: all-zero mnemonic entropy.
                buf.fill(0);
            } else {
                buf.fill(0xab);
            }
            if c == self.n {
                self.token.cancel();
            }
            Ok(())
        }
    }

    // --- fakes ---

    struct FixedPassphrase(Vec<u8>);

    impl PassphraseSource for FixedPassphrase {
        fn read(&self) -> Result<Vec<u8>, KeystoreError> {
            Ok(self.0.clone())
        }
    }

    struct ShortPassphrase;

    impl PassphraseSource for ShortPassphrase {
        fn read(&self) -> Result<Vec<u8>, KeystoreError> {
            let pw = b"short7c".to_vec();
            require_min_len(&pw, KEYSTORE_PASSPHRASE_MIN_LEN)?;
            Ok(pw)
        }
    }

    struct ScriptedLines {
        lines: Mutex<VecDeque<String>>,
    }

    impl ScriptedLines {
        fn new(lines: Vec<&str>) -> Self {
            Self {
                lines: Mutex::new(lines.into_iter().map(str::to_string).collect()),
            }
        }
    }

    impl MnemonicSource for ScriptedLines {
        fn read_line(&self, _prompt: &str) -> Result<Zeroizing<String>, AppError> {
            let mut q = self.lines.lock().expect("lines lock");
            let line = q
                .pop_front()
                .ok_or_else(|| AppError::Internal("no more scripted lines".into()))?;
            Ok(Zeroizing::new(line))
        }
    }

    struct Tmp(PathBuf);

    impl Tmp {
        fn new() -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("account-cmd-test-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }

        fn str(&self) -> &str {
            self.0.to_str().unwrap()
        }

        fn v3_files(&self) -> Vec<PathBuf> {
            std::fs::read_dir(&self.0)
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("UTC--"))
                        .unwrap_or(false)
                })
                .collect()
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn base_cfg(dir: &str, count: u32) -> AccountConfig {
        AccountConfig {
            mode: AccountMode::New,
            count,
            output_dir: dir.into(),
            start_index: 0,
            passphrase_env: String::new(),
            mnemonic_passphrase: MnemonicPassphraseForm::Empty,
        }
    }

    fn discard_logger() -> Logger {
        Logger::discard()
    }

    fn run_with(
        cfg: &AccountConfig,
        entropy: &dyn Entropy,
        keystore_pw: &dyn PassphraseSource,
        mnemonic_src: &dyn MnemonicSource,
        cancel: &CancelToken,
    ) -> Result<(Vec<u8>, Vec<u8>), AppError> {
        let mut tty = Vec::new();
        let mut summary = Vec::new();
        let logger = discard_logger();
        let mut deps = AccountDeps {
            cfg,
            entropy,
            keystore_pw,
            mnemonic_src,
            tty_writer: &mut tty,
            summary_out: &mut summary,
            progress: Progress::Tty,
            logger: &logger,
            timestamp: TS,
            scrypt: ScryptParams::FAST,
        };
        run_account_new_with_deps(&mut deps, cancel)?;
        Ok((tty, summary))
    }

    fn recover_cfg(dir: &str, count: u32, start_index: u32) -> AccountConfig {
        AccountConfig {
            mode: AccountMode::Recover,
            count,
            output_dir: dir.into(),
            start_index,
            passphrase_env: String::new(),
            mnemonic_passphrase: MnemonicPassphraseForm::Empty,
        }
    }

    fn run_recover_with(
        cfg: &AccountConfig,
        entropy: &dyn Entropy,
        keystore_pw: &dyn PassphraseSource,
        mnemonic_src: &dyn MnemonicSource,
        cancel: &CancelToken,
    ) -> Result<(Vec<u8>, Vec<u8>), AppError> {
        let mut tty = Vec::new();
        let mut summary = Vec::new();
        let logger = discard_logger();
        let mut deps = AccountDeps {
            cfg,
            entropy,
            keystore_pw,
            mnemonic_src,
            tty_writer: &mut tty,
            summary_out: &mut summary,
            progress: Progress::Tty,
            logger: &logger,
            timestamp: TS,
            scrypt: ScryptParams::FAST,
        };
        run_account_recover_with_deps(&mut deps, cancel)?;
        Ok((tty, summary))
    }

    // --- happy path ---

    #[test]
    fn happy_path_writes_n_v3_files_crypto_address_consistent() {
        let dir = Tmp::new();
        let cfg = base_cfg(dir.str(), 2);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let cancel = CancelToken::new();

        let (tty, summary) = run_with(&cfg, &entropy, &pw, &lines, &cancel).expect("ok");

        // Mnemonic displayed once to tty_writer only.
        let tty_s = String::from_utf8(tty).unwrap();
        assert!(
            tty_s.contains(ZERO_MNEMONIC),
            "mnemonic must appear on tty_writer: {tty_s}"
        );
        let summary_s = String::from_utf8(summary).unwrap();
        assert!(
            !summary_s.contains(ZERO_MNEMONIC),
            "mnemonic must not appear on summary/stderr"
        );
        assert!(summary_s.contains("wrote 2 keystores"), "{summary_s}");
        assert!(summary_s.contains("keystore 1/2:"), "{summary_s}");
        assert!(summary_s.contains("keystore 2/2:"), "{summary_s}");

        let files = dir.v3_files();
        assert_eq!(files.len(), 2, "files: {files:?}");

        // Re-derive secrets/addresses and re-encrypt with the known zero
        // salt/iv/uuid from FixedEntropy to prove crypto + address consistency.
        let seed = bip39::to_seed(ZERO_MNEMONIC, b"").unwrap();
        let salt = [0u8; 32];
        let iv = [0u8; 16];
        let uuid_bytes = [0u8; 16];

        for index in 0u32..2 {
            let path = Bip44Path::eoa(index);
            let derived =
                hd_secp256k1::ExtendedPrivKey::derive_path(seed.as_slice(), &path).unwrap();
            let sk = derived.secret_bytes();
            let addr = secret_to_address(&sk).unwrap();
            let eip55 = eip55_checksum(&addr);
            let expected_name = v3_filename(&addr, TS.unix_secs, TS.nanos);

            let f = files
                .iter()
                .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(expected_name.as_str()))
                .unwrap_or_else(|| panic!("missing file {expected_name}; files={files:?}"));

            // Filename parses: UTC--…Z--<40-hex>
            let name = f.file_name().unwrap().to_string_lossy();
            assert!(name.starts_with("UTC--"), "{name}");
            assert!(
                name.ends_with(&format!("--{}", hex::encode(addr))),
                "{name}"
            );
            assert_eq!(name.as_ref(), expected_name.as_str());

            let body = std::fs::read(f).unwrap();
            let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(val["version"], 3);
            assert_eq!(val["address"], hex::encode(addr));
            assert_eq!(val["crypto"]["cipher"], "aes-128-ctr");
            assert_eq!(val["crypto"]["kdf"], "scrypt");
            assert_eq!(val["crypto"]["kdfparams"]["n"], ScryptParams::FAST.n);

            // EIP-55 in summary.
            assert!(
                summary_s.contains(&eip55),
                "summary missing {eip55}: {summary_s}"
            );

            // Crypto consistent: re-encrypt with same inputs → same JSON.
            let expected = encrypt_v3(&EncryptV3Input {
                secret: sk.as_slice(),
                password: b"password1",
                address: addr,
                salt,
                iv,
                uuid_bytes,
                scrypt: ScryptParams::FAST,
            })
            .unwrap();
            assert_eq!(body, expected, "keystore JSON mismatch at index {index}");

            // Secret never appears in JSON.
            let secret_hex = hex::encode(sk.as_slice());
            let body_s = String::from_utf8_lossy(&body);
            assert!(
                !body_s.contains(&secret_hex),
                "plaintext secret must not appear in keystore"
            );
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in &files {
                let mode = std::fs::metadata(f).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "mode for {f:?}");
            }
        }
    }

    #[test]
    fn twenty_four_words_from_256_bit_entropy() {
        let dir = Tmp::new();
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let (tty, _) = run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap();
        let tty_s = String::from_utf8(tty).unwrap();
        let words: Vec<_> = ZERO_MNEMONIC.split(' ').collect();
        assert_eq!(words.len(), 24);
        assert!(tty_s.contains(ZERO_MNEMONIC));
    }

    // --- ceremony mismatch ---

    #[test]
    fn ceremony_mismatch_retry_then_abort_exit4_no_files() {
        let dir = Tmp::new();
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        // Wrong re-entry → retry y → wrong again → N abort.
        let lines = ScriptedLines::new(vec![
            "not a real mnemonic at all",
            "y",
            "still wrong words here forever",
            "n",
        ]);
        let err = run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap_err();
        assert_eq!(exit_code_for(&err), 4, "err={err}");
        assert!(
            matches!(err, AppError::Aborted(_)),
            "expected Aborted, got {err:?}"
        );
        assert!(
            dir.v3_files().is_empty(),
            "no keystores until re-entry matches"
        );
    }

    #[test]
    fn ceremony_mismatch_immediate_abort() {
        let dir = Tmp::new();
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec!["wrong mnemonic words", "n"]);
        let err = run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap_err();
        assert_eq!(exit_code_for(&err), 4);
        assert!(dir.v3_files().is_empty());
    }

    #[test]
    fn ceremony_retry_then_match_writes() {
        let dir = Tmp::new();
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec!["wrong words", "yes", ZERO_MNEMONIC]);
        run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok after retry");
        assert_eq!(dir.v3_files().len(), 1);
    }

    // --- passphrase ---

    #[test]
    fn short_passphrase_exit2_no_files() {
        let dir = Tmp::new();
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = ShortPassphrase;
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let err = run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap_err();
        assert_eq!(exit_code_for(&err), 2, "err={err}");
        assert!(dir.v3_files().is_empty());
    }

    #[test]
    fn mnemonic_passphrase_prompt_confirm_mismatch_exit2() {
        let dir = Tmp::new();
        let mut cfg = base_cfg(dir.str(), 1);
        cfg.mnemonic_passphrase = MnemonicPassphraseForm::Prompt;
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        // Prompt form is resolved *before* ceremony: first/confirm mismatch.
        let lines = ScriptedLines::new(vec!["alpha", "beta"]);
        let err = run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap_err();
        assert_eq!(exit_code_for(&err), 2, "err={err}");
        assert!(err.to_string().contains("do not match"));
        assert!(dir.v3_files().is_empty());
    }

    #[test]
    fn mnemonic_passphrase_raw_honored_on_new() {
        // Flag-form mnemonic passphrase is fully honored (F-12); seed pinned
        // to the 24-word TREZOR vector and address differs from empty-pass.
        let dir = Tmp::new();
        let mut cfg = base_cfg(dir.str(), 1);
        cfg.mnemonic_passphrase = MnemonicPassphraseForm::Raw(Zeroizing::new("TREZOR".into()));
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");

        let seed_trezor = bip39::to_seed(ZERO_MNEMONIC, b"TREZOR").unwrap();
        assert_eq!(hex::encode(seed_trezor.as_slice()), ZERO_TREZOR_SEED_HEX);
        let seed_empty = bip39::to_seed(ZERO_MNEMONIC, b"").unwrap();
        assert_ne!(
            seed_empty.as_slice(),
            seed_trezor.as_slice(),
            "mnemonic passphrase must change the seed"
        );

        let path = Bip44Path::eoa(0);
        let derived =
            hd_secp256k1::ExtendedPrivKey::derive_path(seed_trezor.as_slice(), &path).unwrap();
        let sk = derived.secret_bytes();
        let addr = secret_to_address(&sk).unwrap();
        let expected_name = v3_filename(&addr, TS.unix_secs, TS.nanos);

        let files = dir.v3_files();
        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0].file_name().and_then(|n| n.to_str()),
            Some(expected_name.as_str())
        );

        let body = std::fs::read(&files[0]).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(val["address"], hex::encode(addr));

        // Empty-passphrase address for the same mnemonic must differ.
        let derived_empty =
            hd_secp256k1::ExtendedPrivKey::derive_path(seed_empty.as_slice(), &path).unwrap();
        let addr_empty = secret_to_address(&derived_empty.secret_bytes()).unwrap();
        assert_ne!(addr, addr_empty);
    }

    // --- SIGINT ---

    #[test]
    fn cancel_before_start_leaves_zero_files() {
        let dir = Tmp::new();
        let cfg = base_cfg(dir.str(), 2);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let cancel = CancelToken::new();
        cancel.cancel();
        let err = run_with(&cfg, &entropy, &pw, &lines, &cancel).unwrap_err();
        assert_eq!(exit_code_for(&err), 4);
        assert!(dir.v3_files().is_empty());
    }

    #[test]
    fn cancel_mid_run_leaves_k_complete_keystores() {
        // Fill timeline for count=2:
        //   1: mnemonic entropy (32)
        //   2,3,4: key0 salt/iv/uuid
        //   write key0
        //   5: key1 salt → cancel here
        //   before write key1 → Aborted; 1 file remains.
        let dir = Tmp::new();
        let cfg = base_cfg(dir.str(), 2);
        let cancel = CancelToken::new();
        let entropy = CancelOnFill {
            n: 5,
            count: AtomicUsize::new(0),
            token: cancel.clone(),
        };
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let err = run_with(&cfg, &entropy, &pw, &lines, &cancel).unwrap_err();
        assert_eq!(exit_code_for(&err), 4, "err={err}");
        let files = dir.v3_files();
        assert_eq!(
            files.len(),
            1,
            "SIGINT after k=1 write must leave 1 keystore; got {files:?}"
        );
        // Remaining file must be complete JSON (not partial).
        let body = std::fs::read(&files[0]).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).expect("complete json");
        assert_eq!(val["version"], 3);
        assert!(val.get("crypto").is_some());
        assert!(val.get("address").is_some());
    }

    #[test]
    fn cancel_during_ceremony_leaves_zero() {
        let dir = Tmp::new();
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let cancel = CancelToken::new();
        struct CancelLines {
            token: CancelToken,
        }
        impl MnemonicSource for CancelLines {
            fn read_line(&self, _prompt: &str) -> Result<Zeroizing<String>, AppError> {
                self.token.cancel();
                Ok(Zeroizing::new("wrong".into()))
            }
        }
        let lines = CancelLines {
            token: cancel.clone(),
        };
        let err = run_with(&cfg, &entropy, &pw, &lines, &cancel).unwrap_err();
        assert_eq!(exit_code_for(&err), 4);
        assert!(dir.v3_files().is_empty());
    }

    // --- overwrite refuse / same-nanos collision (architecture / BLS H5) ---

    /// Address for index 0 under the zero-entropy 24-word mnemonic (empty pass).
    fn zero_mnemonic_addr0() -> [u8; 20] {
        let seed = bip39::to_seed(ZERO_MNEMONIC, b"").unwrap();
        let derived =
            hd_secp256k1::ExtendedPrivKey::derive_path(seed.as_slice(), &Bip44Path::eoa(0))
                .unwrap();
        secret_to_address(&derived.secret_bytes()).unwrap()
    }

    #[test]
    fn same_nanos_collision_retries_nanos_plus_1() {
        let dir = Tmp::new();
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap();

        let addr = zero_mnemonic_addr0();
        let name_ts = v3_filename(&addr, TS.unix_secs, TS.nanos);
        let name_ts1 = v3_filename(&addr, TS.unix_secs, TS.nanos.wrapping_add(1));

        let files = dir.v3_files();
        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0].file_name().and_then(|n| n.to_str()),
            Some(name_ts.as_str()),
            "first write at frozen timestamp"
        );
        let first_body = std::fs::read(&files[0]).unwrap();

        // Same FixedEntropy + same Timestamp → collision at nanos; retry nanos+1.
        let entropy2 = FixedEntropy::zero_mnemonic();
        let lines2 = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        run_with(&cfg, &entropy2, &pw, &lines2, &CancelToken::new()).unwrap();

        let mut names: Vec<String> = dir
            .v3_files()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names.len(), 2, "names={names:?}");
        assert!(
            names.iter().any(|n| n == &name_ts),
            "nanos preserved: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == &name_ts1),
            "retry at nanos+1: {names:?}"
        );
        // Never overwrites the first file.
        assert_eq!(std::fs::read(dir.0.join(&name_ts)).unwrap(), first_body);
    }

    #[test]
    fn double_nanos_collision_exit3() {
        let dir = Tmp::new();
        let cfg = base_cfg(dir.str(), 1);
        let addr = zero_mnemonic_addr0();

        let at_ts = dir.0.join(v3_filename(&addr, TS.unix_secs, TS.nanos));
        let at_ts1 = dir
            .0
            .join(v3_filename(&addr, TS.unix_secs, TS.nanos.wrapping_add(1)));
        std::fs::write(&at_ts, b"existing-ts").unwrap();
        std::fs::write(&at_ts1, b"existing-ts1").unwrap();

        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let err = run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap_err();
        assert_eq!(exit_code_for(&err), 3, "err={err}");
        assert!(
            err.to_string().contains("already exists") || err.to_string().contains("exists"),
            "err={err}"
        );
        // Never overwrites.
        assert_eq!(std::fs::read(&at_ts).unwrap(), b"existing-ts");
        assert_eq!(std::fs::read(&at_ts1).unwrap(), b"existing-ts1");
    }

    // =========================================================================
    // A4-1 account recover
    // =========================================================================

    #[test]
    fn recover_12_word_crypto_address_consistent() {
        let dir = Tmp::new();
        let cfg = recover_cfg(dir.str(), 1, 0);
        // No ceremony: first scripted line is the mnemonic itself.
        let lines = ScriptedLines::new(vec![ABANDON_12]);
        let entropy = FixedEntropy::new(vec![]); // salt/iv/uuid zeros
        let pw = FixedPassphrase(b"password1".to_vec());
        let (tty, summary) =
            run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");

        // No ceremony: tty_writer must not receive the mnemonic.
        let tty_s = String::from_utf8(tty).unwrap();
        assert!(
            !tty_s.contains(ABANDON_12),
            "recover must not display mnemonic: {tty_s:?}"
        );
        let summary_s = String::from_utf8(summary).unwrap();
        assert!(summary_s.contains("wrote 1 keystore"), "{summary_s}");
        assert!(!summary_s.contains(ABANDON_12));

        let files = dir.v3_files();
        assert_eq!(files.len(), 1);

        let seed = bip39::to_seed(ABANDON_12, b"").unwrap();
        let salt = [0u8; 32];
        let iv = [0u8; 16];
        let uuid_bytes = [0u8; 16];
        let path = Bip44Path::eoa(0);
        let derived = hd_secp256k1::ExtendedPrivKey::derive_path(seed.as_slice(), &path).unwrap();
        let sk = derived.secret_bytes();
        let addr = secret_to_address(&sk).unwrap();
        let eip55 = eip55_checksum(&addr);
        let expected_name = v3_filename(&addr, TS.unix_secs, TS.nanos);

        let f = &files[0];
        assert_eq!(
            f.file_name().and_then(|n| n.to_str()),
            Some(expected_name.as_str())
        );
        assert!(summary_s.contains(&eip55), "summary missing {eip55}");

        let body = std::fs::read(f).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(val["version"], 3);
        assert_eq!(val["address"], hex::encode(addr));

        let expected = encrypt_v3(&EncryptV3Input {
            secret: sk.as_slice(),
            password: b"password1",
            address: addr,
            salt,
            iv,
            uuid_bytes,
            scrypt: ScryptParams::FAST,
        })
        .unwrap();
        assert_eq!(body, expected);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(f).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn recover_24_word_crypto_address_consistent() {
        let dir = Tmp::new();
        let cfg = recover_cfg(dir.str(), 1, 0);
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let entropy = FixedEntropy::new(vec![]);
        let pw = FixedPassphrase(b"password1".to_vec());
        run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");

        let files = dir.v3_files();
        assert_eq!(files.len(), 1);
        let seed = bip39::to_seed(ZERO_MNEMONIC, b"").unwrap();
        let derived =
            hd_secp256k1::ExtendedPrivKey::derive_path(seed.as_slice(), &Bip44Path::eoa(0))
                .unwrap();
        let sk = derived.secret_bytes();
        let addr = secret_to_address(&sk).unwrap();
        let expected_name = v3_filename(&addr, TS.unix_secs, TS.nanos);
        assert_eq!(
            files[0].file_name().and_then(|n| n.to_str()),
            Some(expected_name.as_str())
        );
        let body = std::fs::read(&files[0]).unwrap();
        let expected = encrypt_v3(&EncryptV3Input {
            secret: sk.as_slice(),
            password: b"password1",
            address: addr,
            salt: [0u8; 32],
            iv: [0u8; 16],
            uuid_bytes: [0u8; 16],
            scrypt: ScryptParams::FAST,
        })
        .unwrap();
        assert_eq!(body, expected);
    }

    #[test]
    fn recover_bad_word_exit2() {
        let dir = Tmp::new();
        let cfg = recover_cfg(dir.str(), 1, 0);
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
        let lines = ScriptedLines::new(vec![bad]);
        let entropy = FixedEntropy::new(vec![]);
        let pw = FixedPassphrase(b"password1".to_vec());
        let err = run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap_err();
        assert_eq!(exit_code_for(&err), 2, "err={err}");
        let msg = err.to_string();
        assert!(msg.contains("unknown word at position 12"), "err={err}");
        assert!(
            !msg.contains("notaword"),
            "token must not appear in error Display: {err}"
        );
        assert!(dir.v3_files().is_empty());
    }

    #[test]
    fn recover_bad_checksum_exit2() {
        let dir = Tmp::new();
        let cfg = recover_cfg(dir.str(), 1, 0);
        // 12× abandon — wrong checksum (valid ends with about).
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let lines = ScriptedLines::new(vec![bad]);
        let entropy = FixedEntropy::new(vec![]);
        let pw = FixedPassphrase(b"password1".to_vec());
        let err = run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap_err();
        assert_eq!(exit_code_for(&err), 2, "err={err}");
        assert!(err.to_string().contains("checksum"), "err={err}");
        assert!(dir.v3_files().is_empty());
    }

    #[test]
    fn recover_start_index_range_filenames() {
        let dir = Tmp::new();
        // indices 5, 6, 7
        let cfg = recover_cfg(dir.str(), 3, 5);
        let lines = ScriptedLines::new(vec![ABANDON_12]);
        let entropy = FixedEntropy::new(vec![]);
        let pw = FixedPassphrase(b"password1".to_vec());
        let (_, summary) =
            run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");
        let summary_s = String::from_utf8(summary).unwrap();
        assert!(summary_s.contains("wrote 3 keystores"), "{summary_s}");

        let files = dir.v3_files();
        assert_eq!(files.len(), 3, "files={files:?}");

        let seed = bip39::to_seed(ABANDON_12, b"").unwrap();
        for index in 5u32..=7 {
            let derived =
                hd_secp256k1::ExtendedPrivKey::derive_path(seed.as_slice(), &Bip44Path::eoa(index))
                    .unwrap();
            let sk = derived.secret_bytes();
            let addr = secret_to_address(&sk).unwrap();
            let eip55 = eip55_checksum(&addr);
            let expected_name = v3_filename(&addr, TS.unix_secs, TS.nanos);
            let f = files
                .iter()
                .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(expected_name.as_str()))
                .unwrap_or_else(|| panic!("missing {expected_name}; files={files:?}"));
            assert!(
                summary_s.contains(&eip55),
                "summary missing address for index {index}: {summary_s}"
            );
            let body = std::fs::read(f).unwrap();
            let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(val["address"], hex::encode(addr));
        }
    }

    #[test]
    fn recover_no_ceremony_tty_empty() {
        let dir = Tmp::new();
        let cfg = recover_cfg(dir.str(), 1, 0);
        let lines = ScriptedLines::new(vec![ABANDON_12]);
        let entropy = FixedEntropy::new(vec![]);
        let pw = FixedPassphrase(b"password1".to_vec());
        let (tty, _) = run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap();
        assert!(
            tty.is_empty(),
            "recover must not write to tty_writer: {}",
            String::from_utf8_lossy(&tty)
        );
    }

    #[test]
    fn recover_mnemonic_passphrase_prompt_single_entry() {
        // Bare prompt is single-entry on recover (no confirm) — A4-2.
        let dir = Tmp::new();
        let mut cfg = recover_cfg(dir.str(), 1, 0);
        cfg.mnemonic_passphrase = MnemonicPassphraseForm::Prompt;
        // mnemonic, then single passphrase (no confirm).
        let lines = ScriptedLines::new(vec![ABANDON_12, "TREZOR"]);
        let entropy = FixedEntropy::new(vec![]);
        let pw = FixedPassphrase(b"password1".to_vec());
        run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");

        let seed = bip39::to_seed(ABANDON_12, b"TREZOR").unwrap();
        assert_eq!(hex::encode(seed.as_slice()), TREZOR_SEED_HEX);
        let derived =
            hd_secp256k1::ExtendedPrivKey::derive_path(seed.as_slice(), &Bip44Path::eoa(0))
                .unwrap();
        let sk = derived.secret_bytes();
        let addr = secret_to_address(&sk).unwrap();
        assert_eq!(hex::encode(addr), TREZOR_EOA0_ADDR);
        let expected_name = v3_filename(&addr, TS.unix_secs, TS.nanos);
        let files = dir.v3_files();
        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0].file_name().and_then(|n| n.to_str()),
            Some(expected_name.as_str())
        );
        let body = std::fs::read(&files[0]).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(val["address"], TREZOR_EOA0_ADDR);
        // Empty-passphrase address must differ (passphrase honored).
        assert_ne!(TREZOR_EOA0_ADDR, EMPTY_EOA0_ADDR);
    }

    #[test]
    fn recover_same_shape_as_account_new() {
        // Same fixed mnemonic (24-word abandon…art), empty mnemonic-pass,
        // same FixedEntropy salt/iv/uuid zeros and timestamp → identical JSON.
        let dir_new = Tmp::new();
        let dir_rec = Tmp::new();
        let cfg_new = base_cfg(dir_new.str(), 1);
        let cfg_rec = recover_cfg(dir_rec.str(), 1, 0);

        let entropy_new = FixedEntropy::zero_mnemonic();
        let entropy_rec = FixedEntropy::new(vec![]); // only salt/iv/uuid
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines_new = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let lines_rec = ScriptedLines::new(vec![ZERO_MNEMONIC]);

        run_with(&cfg_new, &entropy_new, &pw, &lines_new, &CancelToken::new()).unwrap();
        run_recover_with(&cfg_rec, &entropy_rec, &pw, &lines_rec, &CancelToken::new()).unwrap();

        let f_new = dir_new.v3_files();
        let f_rec = dir_rec.v3_files();
        assert_eq!(f_new.len(), 1);
        assert_eq!(f_rec.len(), 1);
        assert_eq!(
            f_new[0].file_name(),
            f_rec[0].file_name(),
            "filenames should match"
        );
        let a = std::fs::read(&f_new[0]).unwrap();
        let b = std::fs::read(&f_rec[0]).unwrap();
        assert_eq!(
            a, b,
            "account new and account recover must produce identical shape"
        );
    }

    // =========================================================================
    // A4-2 three-form mnemonic passphrase + seed-derivation anchor (F-12)
    // =========================================================================

    fn eoa0_addr_hex(mnemonic: &str, pass: &[u8]) -> String {
        let seed = bip39::to_seed(mnemonic, pass).unwrap();
        let derived =
            hd_secp256k1::ExtendedPrivKey::derive_path(seed.as_slice(), &Bip44Path::eoa(0))
                .unwrap();
        hex::encode(secret_to_address(&derived.secret_bytes()).unwrap())
    }

    #[test]
    fn seed_derivation_anchor_three_forms_resolve() {
        // Fixed mnemonic + known passphrase → known seed (inline hex) → known
        // first address; non-empty passphrase differs from empty (F-12, C-1).
        // Resolves all three forms + empty; confirm vs single-entry bare prompt.
        // Guards against parse-but-ignore: passphrase must reach to_seed.

        // --- empty default ---
        let empty = resolve_mnemonic_passphrase(
            &MnemonicPassphraseForm::Empty,
            &ScriptedLines::new(vec![]),
            &CancelToken::new(),
            true,
        )
        .unwrap();
        assert!(empty.is_empty());
        let seed_empty = bip39::to_seed(ABANDON_12, empty.as_slice()).unwrap();
        assert_ne!(hex::encode(seed_empty.as_slice()), TREZOR_SEED_HEX);
        assert_eq!(eoa0_addr_hex(ABANDON_12, b""), EMPTY_EOA0_ADDR);

        // --- raw argv ---
        let raw = resolve_mnemonic_passphrase(
            &MnemonicPassphraseForm::Raw(Zeroizing::new("TREZOR".into())),
            &ScriptedLines::new(vec![]),
            &CancelToken::new(),
            true,
        )
        .unwrap();
        assert_eq!(raw.as_slice(), b"TREZOR");
        let seed = bip39::to_seed(ABANDON_12, raw.as_slice()).unwrap();
        assert_eq!(hex::encode(seed.as_slice()), TREZOR_SEED_HEX);
        assert_eq!(eoa0_addr_hex(ABANDON_12, b"TREZOR"), TREZOR_EOA0_ADDR);
        assert_ne!(TREZOR_EOA0_ADDR, EMPTY_EOA0_ADDR);

        // --- env form (value already resolved at clap load) ---
        let env = resolve_mnemonic_passphrase(
            &MnemonicPassphraseForm::Env {
                var: "MNEMONIC_PW".into(),
                value: Zeroizing::new("TREZOR".into()),
            },
            &ScriptedLines::new(vec![]),
            &CancelToken::new(),
            false,
        )
        .unwrap();
        assert_eq!(env.as_slice(), b"TREZOR");
        assert_eq!(
            hex::encode(
                bip39::to_seed(ABANDON_12, env.as_slice())
                    .unwrap()
                    .as_slice()
            ),
            TREZOR_SEED_HEX
        );

        // --- bare prompt, confirm (account new): double-entry ---
        let prompted = resolve_mnemonic_passphrase(
            &MnemonicPassphraseForm::Prompt,
            &ScriptedLines::new(vec!["TREZOR", "TREZOR"]),
            &CancelToken::new(),
            /* confirm */ true,
        )
        .unwrap();
        assert_eq!(prompted.as_slice(), b"TREZOR");
        assert_eq!(
            hex::encode(
                bip39::to_seed(ABANDON_12, prompted.as_slice())
                    .unwrap()
                    .as_slice()
            ),
            TREZOR_SEED_HEX
        );

        // --- bare prompt, single-entry (account recover): one line only ---
        let single = resolve_mnemonic_passphrase(
            &MnemonicPassphraseForm::Prompt,
            &ScriptedLines::new(vec!["TREZOR"]),
            &CancelToken::new(),
            /* confirm */ false,
        )
        .unwrap();
        assert_eq!(single.as_slice(), b"TREZOR");

        // Empty env value is valid (no ≥8 minimum — that is the keystore passphrase).
        let env_empty = resolve_mnemonic_passphrase(
            &MnemonicPassphraseForm::Env {
                var: "MNEMONIC_PW".into(),
                value: Zeroizing::new(String::new()),
            },
            &ScriptedLines::new(vec![]),
            &CancelToken::new(),
            true,
        )
        .unwrap();
        assert!(env_empty.is_empty());
        assert_eq!(
            eoa0_addr_hex(ABANDON_12, env_empty.as_slice()),
            EMPTY_EOA0_ADDR
        );
    }

    #[test]
    fn three_forms_honored_on_account_new_and_recover() {
        // Cross-command AccountDeps-seam: raw / env / bare-prompt / empty on
        // both `new` (confirm) and `recover` (single-entry) feed to_seed.
        // Uses ABANDON_12 recover + ZERO_MNEMONIC new; addresses match derivation.

        // --- recover: raw TREZOR → known address ---
        {
            let dir = Tmp::new();
            let mut cfg = recover_cfg(dir.str(), 1, 0);
            cfg.mnemonic_passphrase = MnemonicPassphraseForm::Raw(Zeroizing::new("TREZOR".into()));
            let lines = ScriptedLines::new(vec![ABANDON_12]);
            let entropy = FixedEntropy::new(vec![]);
            let pw = FixedPassphrase(b"password1".to_vec());
            run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("raw");
            let files = dir.v3_files();
            assert_eq!(files.len(), 1);
            let val: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
            assert_eq!(val["address"], TREZOR_EOA0_ADDR);
        }

        // --- recover: env TREZOR → same address ---
        {
            let dir = Tmp::new();
            let mut cfg = recover_cfg(dir.str(), 1, 0);
            cfg.mnemonic_passphrase = MnemonicPassphraseForm::Env {
                var: "TEST_MNEMONIC_PW".into(),
                value: Zeroizing::new("TREZOR".into()),
            };
            let lines = ScriptedLines::new(vec![ABANDON_12]);
            let entropy = FixedEntropy::new(vec![]);
            let pw = FixedPassphrase(b"password1".to_vec());
            run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("env");
            let files = dir.v3_files();
            assert_eq!(files.len(), 1);
            let val: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
            assert_eq!(val["address"], TREZOR_EOA0_ADDR);
        }

        // --- recover: empty default → empty-pass address ---
        {
            let dir = Tmp::new();
            let cfg = recover_cfg(dir.str(), 1, 0);
            assert_eq!(cfg.mnemonic_passphrase, MnemonicPassphraseForm::Empty);
            let lines = ScriptedLines::new(vec![ABANDON_12]);
            let entropy = FixedEntropy::new(vec![]);
            let pw = FixedPassphrase(b"password1".to_vec());
            run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("empty");
            let files = dir.v3_files();
            assert_eq!(files.len(), 1);
            let val: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
            assert_eq!(val["address"], EMPTY_EOA0_ADDR);
        }

        // --- new: env TREZOR (confirm bare covered by prompt mismatch + resolve) ---
        {
            let dir = Tmp::new();
            let mut cfg = base_cfg(dir.str(), 1);
            cfg.mnemonic_passphrase = MnemonicPassphraseForm::Env {
                var: "TEST_MNEMONIC_PW".into(),
                value: Zeroizing::new("TREZOR".into()),
            };
            let entropy = FixedEntropy::zero_mnemonic();
            let pw = FixedPassphrase(b"password1".to_vec());
            let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
            run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("new env");
            let seed = bip39::to_seed(ZERO_MNEMONIC, b"TREZOR").unwrap();
            assert_eq!(hex::encode(seed.as_slice()), ZERO_TREZOR_SEED_HEX);
            let derived =
                hd_secp256k1::ExtendedPrivKey::derive_path(seed.as_slice(), &Bip44Path::eoa(0))
                    .unwrap();
            let addr = secret_to_address(&derived.secret_bytes()).unwrap();
            let files = dir.v3_files();
            assert_eq!(files.len(), 1);
            let val: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
            assert_eq!(val["address"], hex::encode(addr));
        }

        // --- new: bare prompt confirm success ---
        {
            let dir = Tmp::new();
            let mut cfg = base_cfg(dir.str(), 1);
            cfg.mnemonic_passphrase = MnemonicPassphraseForm::Prompt;
            let entropy = FixedEntropy::zero_mnemonic();
            let pw = FixedPassphrase(b"password1".to_vec());
            // confirm: pass, confirm, then ceremony re-entry of mnemonic
            let lines = ScriptedLines::new(vec!["TREZOR", "TREZOR", ZERO_MNEMONIC]);
            run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("new prompt");
            let seed = bip39::to_seed(ZERO_MNEMONIC, b"TREZOR").unwrap();
            let derived =
                hd_secp256k1::ExtendedPrivKey::derive_path(seed.as_slice(), &Bip44Path::eoa(0))
                    .unwrap();
            let addr = secret_to_address(&derived.secret_bytes()).unwrap();
            let files = dir.v3_files();
            assert_eq!(files.len(), 1);
            let val: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
            assert_eq!(val["address"], hex::encode(addr));
        }
    }

    // =========================================================================
    // A3-5 secret hygiene (S-2 / G5)
    // =========================================================================

    struct SharedWriter(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Secrets (mnemonic, seed, chain codes, scalar, both passphrases — raw +
    /// hex) must never appear in summary/logger; mnemonic display is only on
    /// `tty_writer`. Public address must still appear in the summary.
    #[test]
    fn secret_hygiene_account_new_buffers() {
        let dir = Tmp::new();
        let mut cfg = base_cfg(dir.str(), 1);
        // Distinct mnemonic passphrase so we can grep for it.
        cfg.mnemonic_passphrase = MnemonicPassphraseForm::Raw(Zeroizing::new("TREZOR".into()));

        let keystore_pw_plain = "password1";
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(keystore_pw_plain.as_bytes().to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);

        let mut tty = Vec::new();
        let mut summary = Vec::new();
        let logbuf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let logger = Logger::new(
            Level::Debug,
            Format::Text,
            Box::new(SharedWriter(Arc::clone(&logbuf))),
        );
        {
            let mut deps = AccountDeps {
                cfg: &cfg,
                entropy: &entropy,
                keystore_pw: &pw,
                mnemonic_src: &lines,
                tty_writer: &mut tty,
                summary_out: &mut summary,
                progress: Progress::Tty,
                logger: &logger,
                timestamp: TS,
                scrypt: ScryptParams::FAST,
            };
            run_account_new_with_deps(&mut deps, &CancelToken::new()).expect("ok");
        }

        let tty_s = String::from_utf8(tty).expect("tty utf8");
        let summary_s = String::from_utf8(summary).expect("summary utf8");
        let logs = logbuf.lock().unwrap().clone();
        let logs_s = String::from_utf8_lossy(&logs).into_owned();

        // Mnemonic display: only on tty_writer (S-2).
        assert!(
            tty_s.contains(ZERO_MNEMONIC),
            "ceremony must display mnemonic on tty_writer"
        );
        assert!(
            !summary_s.contains(ZERO_MNEMONIC),
            "mnemonic leaked to summary/stderr: {summary_s}"
        );
        assert!(
            !logs_s.contains(ZERO_MNEMONIC),
            "mnemonic leaked to logger: {logs_s}"
        );

        // Seed (24-word abandon…art + TREZOR).
        let seed = bip39::to_seed(ZERO_MNEMONIC, b"TREZOR").unwrap();
        let seed_hex = hex::encode(seed.as_slice());
        assert_absent_hex_and_raw(&summary_s, &logs_s, &logs, "seed", seed.as_slice());

        // Leaf secret scalar for index 0 + EIP-55 address (public — must appear).
        let derived =
            hd_secp256k1::ExtendedPrivKey::derive_path(seed.as_slice(), &Bip44Path::eoa(0))
                .unwrap();
        let sk = derived.secret_bytes();
        let sk_hex = hex::encode(sk.as_slice());
        assert_absent_hex_and_raw(&summary_s, &logs_s, &logs, "scalar", sk.as_slice());

        let addr = secret_to_address(&sk).unwrap();
        let eip55 = eip55_checksum(&addr);
        assert!(
            summary_s.contains(&eip55),
            "public address must appear in summary: {summary_s}"
        );

        // Chain codes along m → m/44'/60'/0'/0/0 (secret-equivalent; S-2).
        // Hardcoded from independent BIP-32 CKD over the TREZOR seed above.
        const CHAIN_CODES: &[&str] = &[
            "61ccb2bbe7d2a4fccd5f418ee931db7cbac9a153ec43b0ae3759ff991e4d23d1", // m
            "906df52af7348b60add660bee8a0f1833c24a552d9010d36bd08221d94bf05b0", // 44'
            "be9a124c99b5a419339ed182dea99f7b2c4245afd3e760dd1c5f2f04a964870d", // 60'
            "16b22c7161859d083b0c4a524cc66a5c7d273ceda6ef3b85860b7767af74a2fe", // 0'
            "381c02c65b5ae52d0ff0f345b3a1222cb793dabaf115ebbe06f211bcbf126f9b", // 0
            "e899041cd74c949dd565feda4d833d547944a73d33c0202070ed0f48bb63ee78", // 0 (leaf)
        ];
        for (i, cc_hex) in CHAIN_CODES.iter().enumerate() {
            assert!(
                !summary_s.contains(cc_hex) && !logs_s.contains(cc_hex),
                "chain code {i} hex leaked"
            );
            let cc = hex::decode(cc_hex).expect("chain code hex");
            assert!(
                !summary_s
                    .as_bytes()
                    .windows(cc.len())
                    .any(|w| w == cc.as_slice())
                    && !logs.windows(cc.len()).any(|w| w == cc.as_slice()),
                "chain code {i} raw leaked"
            );
        }

        // Intermediate path secrets (also never on buffers).
        const PATH_SKS: &[&str] = &[
            "c8b4073ccfcc63475c3d5202c6594484ee4e77b867cde3c3b46432fd71b467ae", // m
            "06d0aff0cc6d9b921d324b218e27f9bc3eddda207265751a5798eb62bf8ff20e",
            "45b1b541e0474b02dd9d4709f9d3dd3f853ea6b54275fbb4ea281f52a4d46e21",
            "a64c6c8885fe7f18d9c8d054ed747c6d56f37400852d80acadc49bbc8d61924e",
            "18150dbeb529fdb3d678fcb75e77256d846b253d9071a04aba125aa6a82747e6",
        ];
        for (i, skh) in PATH_SKS.iter().enumerate() {
            assert!(
                !summary_s.contains(skh) && !logs_s.contains(skh),
                "path secret {i} hex leaked"
            );
        }
        assert_eq!(
            sk_hex,
            "f9399e5d4ddb63856a95268e2806def3ea55c1fcac22f90a5de3a72667a9408c"
        );

        // Keystore passphrase (raw + hex).
        assert!(
            !summary_s.contains(keystore_pw_plain) && !logs_s.contains(keystore_pw_plain),
            "keystore passphrase leaked"
        );
        let ks_hex = hex::encode(keystore_pw_plain.as_bytes());
        assert!(
            !summary_s.contains(&ks_hex) && !logs_s.contains(&ks_hex),
            "keystore passphrase hex leaked"
        );

        // Mnemonic passphrase (raw + hex).
        assert!(
            !summary_s.contains("TREZOR") && !logs_s.contains("TREZOR"),
            "mnemonic passphrase leaked"
        );
        let mp_hex = hex::encode(b"TREZOR");
        assert!(
            !summary_s.contains(&mp_hex) && !logs_s.contains(&mp_hex),
            "mnemonic passphrase hex leaked"
        );

        // tty_writer must not contain seed/SK/passphrases either (only mnemonic).
        assert!(!tty_s.contains(&seed_hex), "seed hex on tty");
        assert!(!tty_s.contains(&sk_hex), "sk hex on tty");
        assert!(!tty_s.contains(keystore_pw_plain), "keystore pw on tty");
        assert!(!tty_s.contains("TREZOR"), "mnemonic passphrase on tty");
        for cc_hex in CHAIN_CODES {
            assert!(!tty_s.contains(cc_hex), "chain code on tty");
        }

        // Progress/summary should still be non-empty (paths + addresses only).
        assert!(summary_s.contains("wrote 1 keystore"), "{summary_s}");
        assert!(!logs.is_empty(), "debug logger should emit events");
    }

    /// Recover path: no tty display; secrets still absent from summary/logger.
    #[test]
    fn secret_hygiene_account_recover_buffers() {
        let dir = Tmp::new();
        let mut cfg = recover_cfg(dir.str(), 1, 0);
        cfg.mnemonic_passphrase = MnemonicPassphraseForm::Raw(Zeroizing::new("TREZOR".into()));
        let keystore_pw_plain = "password1";
        let entropy = FixedEntropy::new(vec![]);
        let pw = FixedPassphrase(keystore_pw_plain.as_bytes().to_vec());
        // Injected mnemonic (simulates pipe/TTY read) — must not reappear on buffers.
        let lines = ScriptedLines::new(vec![ABANDON_12]);

        let mut tty = Vec::new();
        let mut summary = Vec::new();
        let logbuf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let logger = Logger::new(
            Level::Debug,
            Format::Text,
            Box::new(SharedWriter(Arc::clone(&logbuf))),
        );
        {
            let mut deps = AccountDeps {
                cfg: &cfg,
                entropy: &entropy,
                keystore_pw: &pw,
                mnemonic_src: &lines,
                tty_writer: &mut tty,
                summary_out: &mut summary,
                progress: Progress::NonTty,
                logger: &logger,
                timestamp: TS,
                scrypt: ScryptParams::FAST,
            };
            run_account_recover_with_deps(&mut deps, &CancelToken::new()).expect("ok");
        }

        let tty_s = String::from_utf8(tty).unwrap();
        let summary_s = String::from_utf8(summary).unwrap();
        let logs = logbuf.lock().unwrap().clone();
        let logs_s = String::from_utf8_lossy(&logs).into_owned();

        assert!(
            tty_s.is_empty(),
            "recover must not write mnemonic to tty: {tty_s:?}"
        );
        for secret in [
            ABANDON_12,
            "TREZOR",
            keystore_pw_plain,
            &hex::encode(bip39::to_seed(ABANDON_12, b"TREZOR").unwrap().as_slice()),
            &hex::encode(b"TREZOR"),
            &hex::encode(keystore_pw_plain.as_bytes()),
        ] {
            assert!(!summary_s.contains(secret), "secret {secret:?} in summary");
            assert!(!logs_s.contains(secret), "secret {secret:?} in logs");
        }

        // Leaf scalar + chain-code style raw bytes also absent.
        let seed = bip39::to_seed(ABANDON_12, b"TREZOR").unwrap();
        let derived =
            hd_secp256k1::ExtendedPrivKey::derive_path(seed.as_slice(), &Bip44Path::eoa(0))
                .unwrap();
        let sk = derived.secret_bytes();
        assert_absent_hex_and_raw(&summary_s, &logs_s, &logs, "scalar", sk.as_slice());
        assert_absent_hex_and_raw(&summary_s, &logs_s, &logs, "seed", seed.as_slice());

        // Public address still appears via NonTty logger progress path.
        let addr = secret_to_address(&sk).unwrap();
        let eip55 = eip55_checksum(&addr);
        assert!(
            logs_s.contains(&eip55) || summary_s.contains(&eip55),
            "public address must appear: summary={summary_s} logs={logs_s}"
        );
    }

    fn assert_absent_hex_and_raw(
        summary_s: &str,
        logs_s: &str,
        logs: &[u8],
        label: &str,
        raw: &[u8],
    ) {
        let hex_s = hex::encode(raw);
        assert!(
            !summary_s.contains(&hex_s) && !logs_s.contains(&hex_s),
            "{label} hex leaked"
        );
        assert!(
            !summary_s.as_bytes().windows(raw.len()).any(|w| w == raw)
                && !logs.windows(raw.len()).any(|w| w == raw),
            "{label} raw leaked"
        );
    }

    // --- exit-map smoke for Bip32 From path ---

    #[test]
    fn bip32_map_is_exit3() {
        let e = map_bip32_err(Bip32Error::Master("I_L is zero or ≥ n".into()));
        assert!(matches!(e, AppError::Bip32(_)), "got {e:?}");
        assert_eq!(exit_code_for(&e), 3);
        let e = map_bip32_err(Bip32Error::InvalidChildKey(0));
        assert_eq!(exit_code_for(&e), 3);
    }
}
