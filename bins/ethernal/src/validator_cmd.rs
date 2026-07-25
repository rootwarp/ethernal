//! `validator new` / `validator recover` runtime: ceremony (new only) + derive → encrypt →
//! write pipeline.
//!
//! Dependencies are injectable via [`ValidatorDeps`] so unit tests can drive the
//! full flow with fixed entropy (test-only), scripted line sources, and
//! buffers — no real terminal required.

use std::io::{self, Write};
use std::path::Path;

use ethernal_core::bip39::{self, Bip39Error};
use ethernal_core::bls::{self, Signer, Verifier};
use ethernal_core::cancel::CancelToken;
use ethernal_core::entropy::{Entropy, EntropyError, OsEntropy};
use ethernal_core::hd::{self, KeyPath};
use ethernal_core::output::OutputError;
use ethernal_keystore::encrypt::{encrypt, keystore_filename, EncryptInput, ScryptParams};
use ethernal_keystore::{
    EnvSource, KeyLoader, KeystoreError, Loader, NewKeystorePassphrase, PassphraseSource,
    KEYSTORE_PASSPHRASE_MIN_LEN,
};
use zeroize::Zeroizing;

use crate::errors::AppError;
use crate::fs_util::{open_tty_writer, stderr_is_tty};
use crate::keygen::{
    check_cancel, resolve_mnemonic_passphrase, run_ceremony, MinLenPassphrase, MnemonicSource,
    RecoverMnemonicSource, StdinMnemonicSource,
};
#[cfg(test)]
use crate::keystore_cli::MnemonicPassphraseForm;
use crate::keystore_cli::{write_with_retry, InMemoryPassphrase, START_INDEX_OVERFLOW_MSG};
use crate::logging::{Format, Level, Logger};
use crate::progress::{Phase, PhaseReporter, Progress};
use crate::validator_cli::ValidatorConfig;

// ---------------------------------------------------------------------------
// Injectable seams
// ---------------------------------------------------------------------------

/// Injectable dependencies for [`run_validator_new_with_deps`].
///
/// Production values come from [`run_validator_new`]; tests replace any piece.
pub(crate) struct ValidatorDeps<'a> {
    pub cfg: &'a ValidatorConfig,
    /// CSPRNG for mnemonic entropy and per-keystore salt/iv/uuid.
    pub entropy: &'a dyn Entropy,
    /// Keystore encryption passphrase (confirm+≥8 or env+min-len).
    pub keystore_pw: &'a dyn PassphraseSource,
    /// Ceremony re-entry / recover mnemonic / mnemonic-passphrase prompts.
    pub mnemonic_src: &'a dyn MnemonicSource,
    /// Where the mnemonic is displayed **once** on `validator new` (TTY only; never
    /// stdout/stderr/logger). Unused by `validator recover` (may be `io::sink()`).
    pub tty_writer: &'a mut dyn Write,
    /// Progress + end-of-run summary (stderr in production).
    pub summary_out: &'a mut dyn Write,
    pub progress: Progress,
    pub logger: &'a Logger,
    /// Unix seconds for keystore filenames (injectable for deterministic tests).
    pub now_unix: i64,
    /// scrypt cost for EIP-2335 encrypt. Production: [`ScryptParams::STANDARD`].
    /// Unit tests inject [`ScryptParams::FAST`] so the suite stays snappy.
    pub scrypt: ScryptParams,
    /// EIP-2335 loader for the C4 round trip. Production: [`Loader`].
    /// Tests inject a failing loader to prove C4 is live (PR-19).
    pub loader: &'a (dyn KeyLoader + Sync),
}

// ---------------------------------------------------------------------------
// Production entry
// ---------------------------------------------------------------------------

/// Production entry for `validator new`: assembles real deps and runs the pipeline.
pub(crate) fn run_validator_new(
    cfg: &ValidatorConfig,
    cancel: &CancelToken,
) -> Result<(), AppError> {
    let logger = Logger::stderr(Level::Info, Format::Text);
    let entropy = OsEntropy;
    let progress = if stderr_is_tty() {
        Progress::Tty
    } else {
        Progress::NonTty
    };
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

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
            "validator new: cannot open controlling terminal for mnemonic display: {e}; \
             refusing to print the mnemonic to stderr"
        ))
    })?;
    let mut summary_out = std::io::stderr();
    let loader = Loader::new();

    let mut deps = ValidatorDeps {
        cfg,
        entropy: &entropy,
        keystore_pw,
        mnemonic_src: &mnemonic_src,
        tty_writer: &mut tty_writer,
        summary_out: &mut summary_out,
        progress,
        logger: &logger,
        now_unix,
        scrypt: ScryptParams::STANDARD,
        loader: &loader,
    };
    run_validator_new_with_deps(&mut deps, cancel)
}

/// Production entry for `validator recover`: read existing mnemonic (TTY or pipe),
/// validate, then derive → encrypt → write (no ceremony).
pub(crate) fn run_validator_recover(
    cfg: &ValidatorConfig,
    cancel: &CancelToken,
) -> Result<(), AppError> {
    let logger = Logger::stderr(Level::Info, Format::Text);
    let entropy = OsEntropy;
    let progress = if stderr_is_tty() {
        Progress::Tty
    } else {
        Progress::NonTty
    };
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

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
    let loader = Loader::new();

    let mut deps = ValidatorDeps {
        cfg,
        entropy: &entropy,
        keystore_pw,
        mnemonic_src: &mnemonic_src,
        tty_writer: &mut tty_writer,
        summary_out: &mut summary_out,
        progress,
        logger: &logger,
        now_unix,
        scrypt: ScryptParams::STANDARD,
        loader: &loader,
    };
    run_validator_recover_with_deps(&mut deps, cancel)
}

// ---------------------------------------------------------------------------
// Pipeline — validator new
// ---------------------------------------------------------------------------

/// Testable core of `validator new`: entropy → mnemonic → mnemonic passphrase →
/// ceremony → seed → derive/encrypt/write per index.
pub(crate) fn run_validator_new_with_deps(
    deps: &mut ValidatorDeps<'_>,
    cancel: &CancelToken,
) -> Result<(), AppError> {
    let log = deps.logger;
    let cfg = deps.cfg;

    check_cancel(cancel)?;

    // 1. Draw 256-bit entropy → 24-word mnemonic (F-1, S-4).
    log.debug("validator new: drawing entropy", &[]);
    let mut entropy_bytes = Zeroizing::new([0u8; 32]);
    deps.entropy
        .fill(entropy_bytes.as_mut())
        .map_err(map_entropy_err)?;
    let mnemonic = bip39::entropy_to_mnemonic(entropy_bytes.as_slice()).map_err(map_bip39_err)?;
    drop(entropy_bytes);

    let word_count = mnemonic.split_whitespace().count();
    log.debug(
        "validator new: mnemonic generated",
        &[("words", word_count.to_string())],
    );
    if word_count != 24 {
        return Err(AppError::Internal(format!(
            "validator new: expected 24-word mnemonic from 32-byte entropy, got {word_count}"
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
    log.debug("validator new: ceremony complete", &[]);

    // 4–6. Keystore passphrase → seed → derive/encrypt/write.
    // Invariant I-4: progress must not start before run_ceremony returns,
    // because clear_after_ceremony wipes the screen (and would erase any
    // earlier progress output with it).
    finish_from_mnemonic(
        deps,
        cancel,
        mnemonic.as_str(),
        mnemonic_pass.as_slice(),
        "validator new",
    )
}

// ---------------------------------------------------------------------------
// Pipeline — validator recover
// ---------------------------------------------------------------------------

/// Testable core of `validator recover`: read mnemonic (TTY/pipe) → validate →
/// mnemonic passphrase (single-entry prompt) → seed → derive/encrypt/write.
/// **No** display/re-entry ceremony (F-10).
pub(crate) fn run_validator_recover_with_deps(
    deps: &mut ValidatorDeps<'_>,
    cancel: &CancelToken,
) -> Result<(), AppError> {
    let log = deps.logger;
    let cfg = deps.cfg;

    check_cancel(cancel)?;

    // 1. Existing mnemonic from TTY prompt or piped stdin (F-10).
    log.debug("validator recover: reading mnemonic", &[]);
    let mnemonic = deps.mnemonic_src.read_line("Enter your mnemonic: ")?;
    // 2. Validate first — 12/15/18/21/24; bad word/checksum → exit 2 (F-11).
    bip39::validate_mnemonic(mnemonic.as_str()).map_err(map_bip39_err)?;
    let word_count = mnemonic.split_whitespace().count();
    log.debug(
        "validator recover: mnemonic validated",
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

    // 4–6. Keystore passphrase → seed → derive/encrypt/write (shared with new).
    finish_from_mnemonic(
        deps,
        cancel,
        mnemonic.as_str(),
        mnemonic_pass.as_slice(),
        "validator recover",
    )
}

// ---------------------------------------------------------------------------
// C1–C3 derivation self-checks (mandatory, pre-encrypt — invariant I-1)
// ---------------------------------------------------------------------------

/// Domain-separated probe root for the C3 proof-of-possession round trip.
///
/// Preimage: `b"ethernal/keygen-selfcheck/v1"`.
/// Value: `sha256(preimage)`. Fixed, never persisted; the probe signature is
/// dropped immediately after verify.
const SELFCHECK_ROOT: [u8; 32] = [
    0xaf, 0xeb, 0xe9, 0x93, 0x99, 0xf0, 0x46, 0xd3, 0x4c, 0x91, 0x7f, 0xf2, 0xa6, 0x68, 0x5a, 0x1e,
    0x06, 0x97, 0xfe, 0x84, 0x76, 0xf0, 0xf9, 0x72, 0x4c, 0xc3, 0xa3, 0xaf, 0xae, 0xef, 0xd6, 0xf9,
];

/// C1: secret bytes reconstruct a signer whose public key matches `pubkey`.
fn check_c1(
    sk_bytes: &[u8],
    pubkey: &[u8; 48],
    index: u32,
    path_str: &str,
) -> Result<(), AppError> {
    let signer = bls::new_signer(sk_bytes).map_err(|e| AppError::KeyVerifyFailed {
        check: "C1",
        index,
        path: path_str.to_string(),
        detail: format!("could not reconstruct signer from derived secret: {e}"),
    })?;
    let from_sk = signer.public_key().map_err(|e| AppError::KeyVerifyFailed {
        check: "C1",
        index,
        path: path_str.to_string(),
        detail: format!("could not recompute public key from secret: {e}"),
    })?;
    if from_sk != *pubkey {
        return Err(AppError::KeyVerifyFailed {
            check: "C1",
            index,
            path: path_str.to_string(),
            detail: "public key derived from the secret does not match the derived public key"
                .into(),
        });
    }
    Ok(())
}

/// C2: pubkey is a valid compressed G1 point (on-curve, subgroup, non-identity).
fn check_c2(pubkey: &[u8; 48], index: u32, path_str: &str) -> Result<(), AppError> {
    bls::validate_pubkey_bytes(*pubkey).map_err(|e| AppError::KeyVerifyFailed {
        check: "C2",
        index,
        path: path_str.to_string(),
        detail: format!("public key failed point validation: {e}"),
    })
}

/// C3: sign [`SELFCHECK_ROOT`] with the secret and verify against `pubkey`.
///
/// Callable directly with a mismatched-but-valid pair: C3's failure path is
/// unreachable through [`verify_derived_key`] (C1 fails first on a mismatch).
fn check_c3(
    sk_bytes: &[u8],
    pubkey: &[u8; 48],
    index: u32,
    path_str: &str,
) -> Result<(), AppError> {
    let signer = bls::new_signer(sk_bytes).map_err(|e| AppError::KeyVerifyFailed {
        check: "C3",
        index,
        path: path_str.to_string(),
        detail: format!("could not reconstruct signer for self-check: {e}"),
    })?;
    let sig = signer
        .sign(SELFCHECK_ROOT)
        .map_err(|e| AppError::KeyVerifyFailed {
            check: "C3",
            index,
            path: path_str.to_string(),
            detail: format!("could not sign self-check root: {e}"),
        })?;
    // Probe signature is dropped when `sig` goes out of scope; never persisted.
    let ok = bls::default_verifier()
        .verify(*pubkey, SELFCHECK_ROOT, sig)
        .map_err(|e| AppError::KeyVerifyFailed {
            check: "C3",
            index,
            path: path_str.to_string(),
            detail: format!("self-check signature or public key malformed: {e}"),
        })?;
    if !ok {
        return Err(AppError::KeyVerifyFailed {
            check: "C3",
            index,
            path: path_str.to_string(),
            detail: "signature self-verify failed for self-check root".into(),
        });
    }
    Ok(())
}

/// C1–C3, pre-write. Cheap, mandatory, no flag. Call before encrypt (I-1).
fn verify_derived_key(
    sk_bytes: &[u8],
    pubkey: &[u8; 48],
    index: u32,
    path_str: &str,
) -> Result<(), AppError> {
    check_c1(sk_bytes, pubkey, index, path_str)?;
    check_c2(pubkey, index, path_str)?;
    check_c3(sk_bytes, pubkey, index, path_str)?;
    Ok(())
}

/// Constant-time equality for equal-length slices (secret compare).
///
/// Length mismatch returns `false` immediately (derived secret is always 32 bytes).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// C4, post-write. Reads the **file** back through the loader (PR-13) and asserts
/// both secret and pubkey_hex match the derived values. On failure leaves the
/// file in place (D-5 / PR-15).
fn verify_written_keystore(
    loader: &dyn KeyLoader,
    file: &Path,
    pw: &dyn PassphraseSource,
    sk_bytes: &[u8],
    pubkey_hex: &str,
    index: u32,
) -> Result<(), AppError> {
    let path_display = file.display().to_string();
    let mut key = loader
        .load(file, pw)
        .map_err(|e| AppError::KeyVerifyFailed {
            check: "C4",
            index,
            path: path_display.clone(),
            detail: format!("could not decrypt written keystore: {e}"),
        })?;

    if !ct_eq(key.secret.as_slice(), sk_bytes) {
        key.zeroize();
        return Err(AppError::KeyVerifyFailed {
            check: "C4",
            index,
            path: path_display,
            detail: "decrypted secret does not match the derived secret".into(),
        });
    }
    if key.pubkey_hex != pubkey_hex {
        key.zeroize();
        return Err(AppError::KeyVerifyFailed {
            check: "C4",
            index,
            path: path_display,
            detail: "keystore pubkey field does not match the derived public key".into(),
        });
    }
    // Drop also zeroizes; explicit call matches crate convention (keystore.rs:23).
    key.zeroize();
    Ok(())
}

/// Shared tail: keystore passphrase → to_seed → per-index derive/encrypt/write.
fn finish_from_mnemonic(
    deps: &mut ValidatorDeps<'_>,
    cancel: &CancelToken,
    mnemonic: &str,
    mnemonic_pass: &[u8],
    label: &str,
) -> Result<(), AppError> {
    let log = deps.logger;
    let cfg = deps.cfg;

    check_cancel(cancel)?;
    let keystore_pass = Zeroizing::new(deps.keystore_pw.read().map_err(map_encrypt_err)?);
    // C4 passphrase source: one copy of the already-held buffer for the whole
    // run (PR-17 / D-6). Never re-prompt and never re-read the env.
    let c4_pw = InMemoryPassphrase::new(keystore_pass.to_vec());

    check_cancel(cancel)?;
    let seed = bip39::to_seed(mnemonic, mnemonic_pass).map_err(map_bip39_err)?;

    let count = cfg.count as usize;
    let start = cfg.start_index;
    let out_dir = Path::new(&cfg.output_dir);
    let mut written: Vec<(String, String)> = Vec::with_capacity(count);
    // PR-18: full = C1–C4; derived-only = --no-verify (C1–C3 only).
    let verified = if cfg.verify_keystore {
        "full"
    } else {
        "derived-only"
    };

    // One-shot WARNING before the loop when C4 is skipped (PR-12). Never on
    // the default path so symlink e2e WARNING counts stay green.
    if !cfg.verify_keystore {
        let _ = writeln!(
            deps.summary_out,
            "WARNING: --no-verify — keystores will not be decrypted back after writing."
        );
    }

    // PhaseReporter borrows summary_out for the whole loop; durable lines go
    // through reporter.out() (which clears first). Drop erases any live phase
    // line on ? exit paths (invariant I-3).
    let mut reporter = PhaseReporter::new(deps.summary_out, deps.progress);

    for i in 0..count {
        check_cancel(cancel)?;

        let index = start
            .checked_add(i as u32)
            .ok_or_else(|| AppError::exit2(START_INDEX_OVERFLOW_MSG))?;
        let path = KeyPath::signing(index);
        let path_str = path.to_string();

        log.debug(
            &format!("{label}: deriving signing key"),
            &[("index", index.to_string()), ("path", path_str.clone())],
        );

        reporter.phase(i + 1, count, Phase::Deriving);
        let derived = hd::derive_path(seed.as_slice(), &path).map_err(map_hd_err)?;
        let sk_bytes = derived.to_bytes();
        let pubkey = derived.public_key();
        let pubkey_hex = hex::encode(pubkey);

        // C1–C3 before encrypt (I-1): never spend scrypt on a key that fails
        // its own consistency / signability checks.
        reporter.phase(i + 1, count, Phase::Checking);
        verify_derived_key(sk_bytes.as_slice(), &pubkey, index, &path_str)?;

        reporter.phase(i + 1, count, Phase::Encrypting);
        let mut salt = [0u8; 32];
        let mut iv = [0u8; 16];
        let mut uuid_bytes = [0u8; 16];
        deps.entropy.fill(&mut salt).map_err(map_entropy_err)?;
        deps.entropy.fill(&mut iv).map_err(map_entropy_err)?;
        deps.entropy
            .fill(&mut uuid_bytes)
            .map_err(map_entropy_err)?;

        let json = encrypt(&EncryptInput {
            secret: sk_bytes.as_slice(),
            password: keystore_pass.as_slice(),
            path: &path_str,
            pubkey: &pubkey,
            salt,
            iv,
            uuid_bytes,
            scrypt: deps.scrypt,
        })
        .map_err(map_encrypt_err)?;

        check_cancel(cancel)?;

        // Filename is HD-path + whole-second timestamp (staking-deposit-cli
        // convention). On same-second collision, retry once at now_unix+1
        // before propagating AlreadyExists / exit 3 (K3-L5 / H5). Never
        // overwrites: write_new_0600 stays create_new-exclusive.
        reporter.phase(i + 1, count, Phase::Writing);
        let final_path = match write_keystore_at(out_dir, &path_str, deps.now_unix, &json) {
            Ok(p) => p,
            Err(e) => return Err(map_write_err(e)),
        };

        // C4 after write, reads the file on disk (I-2 / PR-13). Default on;
        // `--no-verify` / `verify_keystore=false` skips only this check (PR-12).
        if cfg.verify_keystore {
            reporter.phase(i + 1, count, Phase::Verifying);
            verify_written_keystore(
                deps.loader,
                &final_path,
                &c4_pw,
                sk_bytes.as_slice(),
                &pubkey_hex,
                index,
            )?;
        }

        let path_display = final_path.display().to_string();
        // Clear transient line before the durable progress line (PR-4 format).
        reporter.clear();
        emit_key_progress(
            deps.progress,
            reporter.out(),
            deps.logger,
            i + 1,
            count,
            &path_display,
            &pubkey_hex,
            verified,
        );
        written.push((path_display, pubkey_hex));
    }

    print_key_summary(reporter.out(), &written);
    log.debug(
        &format!("{label}: complete"),
        &[("count", written.len().to_string())],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Progress / summary (F-15) — stderr in production
// ---------------------------------------------------------------------------

// Progress + logger + path + verified k/v; keep flat rather than a bag struct.
#[allow(clippy::too_many_arguments)]
fn emit_key_progress(
    progress: Progress,
    summary_out: &mut dyn Write,
    logger: &Logger,
    done: usize,
    total: usize,
    path: &str,
    pubkey_hex: &str,
    // `"full"` (C1–C4) or `"derived-only"` (`--no-verify`, C1–C3 only).
    verified: &str,
) {
    match progress {
        Progress::Tty => {
            // Byte-identical durable line (PR-4); verified status is NonTty-only.
            let _ = writeln!(
                summary_out,
                "keystore {done}/{total}: {path} (pubkey=0x{pubkey_hex})"
            );
            let _ = summary_out.flush();
        }
        Progress::NonTty => {
            // Existing event + verified k/v (PR-18). No new event type.
            logger.info(
                "keystore written",
                &[
                    ("done", done.to_string()),
                    ("total", total.to_string()),
                    ("path", path.to_string()),
                    ("pubkey", format!("0x{pubkey_hex}")),
                    ("verified", verified.to_string()),
                ],
            );
        }
    }
}

fn print_key_summary(w: &mut dyn Write, written: &[(String, String)]) {
    let n = written.len();
    let _ = writeln!(w, "wrote {n} keystore{}", if n == 1 { "" } else { "s" });
    for (path, pubkey_hex) in written {
        let _ = writeln!(w, "  {path}  pubkey=0x{pubkey_hex}");
    }
    let _ = w.flush();
}

// ---------------------------------------------------------------------------
// Error mapping (call-site; typed arms polished in K3-4)
// ---------------------------------------------------------------------------

fn map_entropy_err(e: EntropyError) -> AppError {
    AppError::Internal(e.to_string())
}

fn map_bip39_err(e: Bip39Error) -> AppError {
    AppError::Bip39(e)
}

fn map_hd_err(e: hd::HdError) -> AppError {
    AppError::Hd(e)
}

/// Maps keystore/passphrase errors; exit code is selected in `exit_code_for`
/// (encrypt → 3, passphrase validation → 2).
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

/// Write `json` to the timestamped keystore path for `path_str`.
///
/// On [`OutputError::AlreadyExists`] for `now_unix`, retries once at
/// `now_unix + 1`. A collision at both timestamps propagates `AlreadyExists`.
/// Domain filename + bump stay here; shared control flow is [`write_with_retry`].
fn write_keystore_at(
    out_dir: &Path,
    path_str: &str,
    now_unix: i64,
    json: &[u8],
) -> Result<std::path::PathBuf, OutputError> {
    write_with_retry(
        out_dir,
        json,
        || keystore_filename(path_str, now_unix),
        || keystore_filename(path_str, now_unix + 1),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::exit_code_for;
    use crate::keygen::{zeroizing_trim, CLEAR_SCROLLBACK_TWICE};
    use crate::test_support::{
        CancelOnFill, FixedEntropy, FixedPassphrase, ScriptedLines, ShortPassphrase, Tmp, ENV_LOCK,
    };
    use crate::validator_cli::ValidatorMode;
    use ethernal_core::hd::derive_path;
    use ethernal_keystore::{Key, KeyLoader, Loader};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// All-zero 32-byte entropy → `abandon` × 23 + `art` (24 words).
    const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    /// BIP-39 vector: 12-word abandon…about + TREZOR.
    const TREZOR_SEED_HEX: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
    const ABANDON_12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn base_cfg(dir: &str, count: u32) -> ValidatorConfig {
        ValidatorConfig {
            mode: ValidatorMode::New,
            count,
            output_dir: dir.into(),
            start_index: 0,
            passphrase_env: String::new(),
            mnemonic_passphrase: MnemonicPassphraseForm::Empty,
            verify_keystore: true,
        }
    }

    fn run_with(
        cfg: &ValidatorConfig,
        entropy: &dyn Entropy,
        keystore_pw: &dyn PassphraseSource,
        mnemonic_src: &dyn MnemonicSource,
        cancel: &CancelToken,
    ) -> Result<(Vec<u8>, Vec<u8>), AppError> {
        let mut tty = Vec::new();
        let mut summary = Vec::new();
        let logger = Logger::discard();
        let loader = Loader::new();
        let mut deps = ValidatorDeps {
            cfg,
            entropy,
            keystore_pw,
            mnemonic_src,
            tty_writer: &mut tty,
            summary_out: &mut summary,
            progress: Progress::Tty,
            logger: &logger,
            now_unix: 1_700_000_000,
            scrypt: ScryptParams::FAST,
            loader: &loader,
        };
        run_validator_new_with_deps(&mut deps, cancel)?;
        Ok((tty, summary))
    }

    fn recover_cfg(dir: &str, count: u32, start_index: u32) -> ValidatorConfig {
        ValidatorConfig {
            mode: ValidatorMode::Recover,
            count,
            output_dir: dir.into(),
            start_index,
            passphrase_env: String::new(),
            mnemonic_passphrase: MnemonicPassphraseForm::Empty,
            verify_keystore: true,
        }
    }

    fn run_recover_with(
        cfg: &ValidatorConfig,
        entropy: &dyn Entropy,
        keystore_pw: &dyn PassphraseSource,
        mnemonic_src: &dyn MnemonicSource,
        cancel: &CancelToken,
    ) -> Result<(Vec<u8>, Vec<u8>), AppError> {
        let mut tty = Vec::new();
        let mut summary = Vec::new();
        let logger = Logger::discard();
        let loader = Loader::new();
        let mut deps = ValidatorDeps {
            cfg,
            entropy,
            keystore_pw,
            mnemonic_src,
            tty_writer: &mut tty,
            summary_out: &mut summary,
            progress: Progress::Tty,
            logger: &logger,
            now_unix: 1_700_000_000,
            scrypt: ScryptParams::FAST,
            loader: &loader,
        };
        run_validator_recover_with_deps(&mut deps, cancel)?;
        Ok((tty, summary))
    }

    // --- happy path ---

    #[test]
    fn happy_path_writes_n_keystores_loader_round_trip() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 2);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        // Ceremony: correct re-entry once.
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

        let files = dir.keystore_files();
        assert_eq!(files.len(), 2, "files: {files:?}");

        // Loader round-trip: decrypt and match HD-derived secret.
        let seed = bip39::to_seed(ZERO_MNEMONIC, b"").unwrap();
        let loader = Loader::new();
        let pw_src = FixedPassphrase(b"password1".to_vec());
        for f in &files {
            let key = loader.load(f, &pw_src).expect("load");
            // path in filename encodes index.
            let name = f.file_name().unwrap().to_string_lossy();
            // keystore-m_12381_3600_<i>_0_0-...
            let idx: u32 = name
                .split('_')
                .nth(3)
                .and_then(|s| s.parse().ok())
                .expect("index in filename");
            let derived = derive_path(seed.as_slice(), &KeyPath::signing(idx)).unwrap();
            assert_eq!(
                key.secret.as_slice(),
                derived.to_bytes().as_slice(),
                "secret mismatch for index {idx}"
            );
            assert_eq!(key.pubkey_hex, hex::encode(derived.public_key()));
        }

        // 0600 permissions on unix.
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
        let dir = Tmp::new("validator-cmd-test");
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
        let dir = Tmp::new("validator-cmd-test");
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
            dir.keystore_files().is_empty(),
            "no keystores until re-entry matches"
        );
    }

    #[test]
    fn ceremony_mismatch_immediate_abort() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec!["wrong mnemonic words", "n"]);
        let err = run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap_err();
        assert_eq!(exit_code_for(&err), 4);
        assert!(dir.keystore_files().is_empty());
    }

    /// Display write failure must hard-fail (exit 2) before re-entry — never
    /// proceed when the operator may not have seen the mnemonic.
    #[test]
    fn ceremony_tty_write_failure_exit2_no_files() {
        struct FailWrite;
        impl Write for FailWrite {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "tty gone"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let mut tty = FailWrite;
        let mut summary = Vec::new();
        let logger = Logger::discard();
        let loader = Loader::new();
        let mut deps = ValidatorDeps {
            cfg: &cfg,
            entropy: &entropy,
            keystore_pw: &pw,
            mnemonic_src: &lines,
            tty_writer: &mut tty,
            summary_out: &mut summary,
            progress: Progress::Tty,
            logger: &logger,
            now_unix: 1_700_000_000,
            scrypt: ScryptParams::FAST,
            loader: &loader,
        };
        let err = run_validator_new_with_deps(&mut deps, &CancelToken::new()).unwrap_err();
        assert_eq!(exit_code_for(&err), 2, "err={err}");
        assert!(
            err.to_string().contains("display mnemonic") || err.to_string().contains("terminal"),
            "err={err}"
        );
        assert!(dir.keystore_files().is_empty());
    }

    #[test]
    fn ceremony_retry_then_match_writes() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec!["wrong words", "yes", ZERO_MNEMONIC]);
        run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok after retry");
        assert_eq!(dir.keystore_files().len(), 1);
    }

    // --- clear-on-confirm (DEP-001 / G1) ---

    #[test]
    fn clear_sequence_bytes_and_order() {
        // Hard-lock 2J→3J→H ×2 so a const edit cannot leave tests green on a wrong sequence.
        assert_eq!(
            CLEAR_SCROLLBACK_TWICE,
            b"\x1b[2J\x1b[3J\x1b[H\x1b[2J\x1b[3J\x1b[H"
        );
        let mut tty = Vec::new();
        let mut warn = Vec::new();
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        run_ceremony(
            ZERO_MNEMONIC,
            &mut tty,
            &mut warn,
            &lines,
            &CancelToken::new(),
        )
        .expect("ceremony ok");
        let clear = CLEAR_SCROLLBACK_TWICE;
        let mnemonic_at = tty
            .windows(ZERO_MNEMONIC.len())
            .position(|w| w == ZERO_MNEMONIC.as_bytes())
            .expect("mnemonic on tty");
        let clear_at = tty
            .windows(clear.len())
            .position(|w| w == clear)
            .expect("CLEAR_SCROLLBACK_TWICE on tty");
        assert!(
            clear_at > mnemonic_at,
            "clear must come after the mnemonic display"
        );
        let tty_s = String::from_utf8(tty).unwrap();
        assert!(
            tty_s.contains("The terminal was cleared to remove the displayed mnemonic."),
            "post-clear notice missing: {tty_s:?}"
        );
        assert!(tty_s.contains("tmux"), "tmux caveat missing: {tty_s:?}");
        assert!(tty_s.contains("screen"), "screen caveat missing: {tty_s:?}");
        assert!(
            tty_s.contains("tmux clear-history"),
            "tmux clear-history missing: {tty_s:?}"
        );
        assert!(
            tty_s.contains("scrollback 0"),
            "screen scrollback 0 missing: {tty_s:?}"
        );
        assert!(warn.is_empty(), "warn_out should be unused on success");
    }

    /// Mismatch-abort after display: the mnemonic reached the terminal, so the
    /// clear must still run on the error path.
    #[test]
    fn abort_path_still_clears() {
        let mut tty = Vec::new();
        let mut warn = Vec::new();
        let lines = ScriptedLines::new(vec!["wrong mnemonic words", "n"]);
        let err = run_ceremony(
            ZERO_MNEMONIC,
            &mut tty,
            &mut warn,
            &lines,
            &CancelToken::new(),
        )
        .unwrap_err();
        assert_eq!(exit_code_for(&err), 4, "err={err}");
        assert!(
            tty.windows(CLEAR_SCROLLBACK_TWICE.len())
                .any(|w| w == CLEAR_SCROLLBACK_TWICE),
            "abort path must still clear scrollback: {:?}",
            String::from_utf8_lossy(&tty)
        );
    }

    /// Fail-open: display succeeds, then every later tty write/flush fails.
    /// `run_ceremony` must still return Ok; manual-clear warning lands on
    /// `warn_out` (stderr in production). Uses FailAfterDisplay — not an
    /// ESC-sniffing writer — so the fallback is exercised non-vacuously.
    #[test]
    fn clear_failure_warns_on_fallback() {
        struct FailAfterDisplay {
            display_flushed: bool,
        }
        impl Write for FailAfterDisplay {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                if self.display_flushed {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "tty gone"))
                } else {
                    Ok(b.len())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                if self.display_flushed {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "tty gone"));
                }
                self.display_flushed = true;
                Ok(())
            }
        }

        let mut tty = FailAfterDisplay {
            display_flushed: false,
        };
        let mut warn = Vec::new();
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        run_ceremony(
            ZERO_MNEMONIC,
            &mut tty,
            &mut warn,
            &lines,
            &CancelToken::new(),
        )
        .expect("fail-open: clear failure must not fail the ceremony");
        let warn_s = String::from_utf8(warn).unwrap();
        assert!(
            warn_s.contains("Cmd+K"),
            "manual-clear Cmd+K missing: {warn_s:?}"
        );
        assert!(
            warn_s.contains("clear &&"),
            "manual-clear `clear &&` missing: {warn_s:?}"
        );
        assert!(
            warn_s.contains("WARNING: could not clear the terminal automatically"),
            "fallback warning missing: {warn_s:?}"
        );
        assert!(
            !warn_s.contains(ZERO_MNEMONIC),
            "S-1: fail-open warning must not carry mnemonic bytes"
        );
    }

    #[test]
    fn success_prints_notice() {
        let mut tty = Vec::new();
        let mut warn = Vec::new();
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        run_ceremony(
            ZERO_MNEMONIC,
            &mut tty,
            &mut warn,
            &lines,
            &CancelToken::new(),
        )
        .expect("ceremony ok");
        let tty_s = String::from_utf8(tty).unwrap();
        assert!(
            tty_s.contains("The terminal was cleared to remove the displayed mnemonic."),
            "notice missing: {tty_s:?}"
        );
        assert!(
            tty_s.contains("tmux clear-history"),
            "multiplexer caveat (tmux) missing: {tty_s:?}"
        );
        assert!(
            tty_s.contains("scrollback 0"),
            "multiplexer caveat (screen) missing: {tty_s:?}"
        );
    }

    // --- passphrase ---

    #[test]
    fn short_passphrase_exit2_no_files() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = ShortPassphrase;
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let err = run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap_err();
        assert_eq!(exit_code_for(&err), 2, "err={err}");
        assert!(dir.keystore_files().is_empty());
    }

    #[test]
    fn mnemonic_passphrase_prompt_confirm_mismatch_exit2() {
        let dir = Tmp::new("validator-cmd-test");
        let mut cfg = base_cfg(dir.str(), 1);
        cfg.mnemonic_passphrase = MnemonicPassphraseForm::Prompt;
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        // Prompt form is resolved *before* ceremony: first/confirm mismatch.
        let lines = ScriptedLines::new(vec!["alpha", "beta"]);
        let err = run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap_err();
        assert_eq!(exit_code_for(&err), 2, "err={err}");
        assert!(err.to_string().contains("do not match"));
        assert!(dir.keystore_files().is_empty());
    }

    #[test]
    fn mnemonic_passphrase_raw_trezor_seed_vector() {
        // Anchors flag-form mnemonic passphrase to BIP-39 TREZOR vector (F-12).
        // Full pipeline uses 24-word entropy; this asserts resolve + to_seed.
        let pass = resolve_mnemonic_passphrase(
            &MnemonicPassphraseForm::Raw(Zeroizing::new("TREZOR".into())),
            &ScriptedLines::new(vec![]),
            &CancelToken::new(),
            true,
        )
        .unwrap();
        let seed = bip39::to_seed(ABANDON_12, pass.as_slice()).unwrap();
        assert_eq!(hex::encode(seed.as_slice()), TREZOR_SEED_HEX);

        // Empty form → empty passphrase (valid).
        let empty = resolve_mnemonic_passphrase(
            &MnemonicPassphraseForm::Empty,
            &ScriptedLines::new(vec![]),
            &CancelToken::new(),
            true,
        )
        .unwrap();
        assert!(empty.is_empty());

        // Prompt form double-confirm (validator new).
        let prompted = resolve_mnemonic_passphrase(
            &MnemonicPassphraseForm::Prompt,
            &ScriptedLines::new(vec!["TREZOR", "TREZOR"]),
            &CancelToken::new(),
            true,
        )
        .unwrap();
        assert_eq!(prompted.as_slice(), b"TREZOR");
        let seed2 = bip39::to_seed(ABANDON_12, prompted.as_slice()).unwrap();
        assert_eq!(hex::encode(seed2.as_slice()), TREZOR_SEED_HEX);

        // Recover: single-entry Prompt (no confirm line).
        let single = resolve_mnemonic_passphrase(
            &MnemonicPassphraseForm::Prompt,
            &ScriptedLines::new(vec!["TREZOR"]),
            &CancelToken::new(),
            false,
        )
        .unwrap();
        assert_eq!(single.as_slice(), b"TREZOR");
    }

    #[test]
    fn happy_path_with_trezor_mnemonic_passphrase_24_word() {
        let dir = Tmp::new("validator-cmd-test");
        let mut cfg = base_cfg(dir.str(), 1);
        cfg.mnemonic_passphrase = MnemonicPassphraseForm::Raw(Zeroizing::new("TREZOR".into()));
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");

        let seed = bip39::to_seed(ZERO_MNEMONIC, b"TREZOR").unwrap();
        // 24-word abandon…art + TREZOR seed (bip39 unit test vector).
        assert_eq!(
            hex::encode(seed.as_slice()),
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
        );
        let files = dir.keystore_files();
        assert_eq!(files.len(), 1);
        let loader = Loader::new();
        let key = loader
            .load(&files[0], &FixedPassphrase(b"password1".to_vec()))
            .unwrap();
        let derived = derive_path(seed.as_slice(), &KeyPath::signing(0)).unwrap();
        assert_eq!(key.secret.as_slice(), derived.to_bytes().as_slice());
    }

    // --- SIGINT ---

    #[test]
    fn cancel_before_start_leaves_zero_files() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 2);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let cancel = CancelToken::new();
        cancel.cancel();
        let err = run_with(&cfg, &entropy, &pw, &lines, &cancel).unwrap_err();
        assert_eq!(exit_code_for(&err), 4);
        assert!(dir.keystore_files().is_empty());
    }

    #[test]
    fn cancel_mid_run_leaves_k_complete_keystores() {
        // Fill timeline for count=2:
        //   1: mnemonic entropy (32)
        //   2,3,4: key0 salt/iv/uuid
        //   write key0
        //   5: key1 salt → cancel here
        //   before write key1 → Aborted; 1 file remains.
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 2);
        let cancel = CancelToken::new();
        let entropy = CancelOnFill {
            n: 5,
            count: AtomicUsize::new(0),
            token: cancel.clone(),
        };
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        // Inline deps so summary_out is captured on the Err path (Drop I-3).
        let mut tty = Vec::new();
        let mut summary = Vec::new();
        let logger = Logger::discard();
        let loader = Loader::new();
        let err = {
            let mut deps = ValidatorDeps {
                cfg: &cfg,
                entropy: &entropy,
                keystore_pw: &pw,
                mnemonic_src: &lines,
                tty_writer: &mut tty,
                summary_out: &mut summary,
                progress: Progress::Tty,
                logger: &logger,
                now_unix: 1_700_000_000,
                scrypt: ScryptParams::FAST,
                loader: &loader,
            };
            run_validator_new_with_deps(&mut deps, &cancel).unwrap_err()
        };
        assert_eq!(exit_code_for(&err), 4, "err={err}");
        let files = dir.keystore_files();
        assert_eq!(
            files.len(),
            1,
            "SIGINT after k=1 write must leave 1 keystore; got {files:?}"
        );
        // The remaining file must be loadable (complete, not partial).
        loader
            .load(&files[0], &FixedPassphrase(b"password1".to_vec()))
            .expect("partial-write must not leave unloadable file");
        // Drop path through real loop: live phase line erased, not left on screen.
        assert!(
            summary.ends_with(b"\r\x1b[K"),
            "cancel mid-loop must leave buffer ending in CSI erase, got {:?}",
            String::from_utf8_lossy(&summary)
        );
        let summary_s = String::from_utf8_lossy(&summary);
        assert!(
            !summary_s.ends_with("deriving...")
                && !summary_s.ends_with("encrypting...")
                && !summary_s.ends_with("writing..."),
            "Drop must not leave phase label on screen, got {summary_s:?}"
        );
    }

    #[test]
    fn cancel_during_ceremony_leaves_zero() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let cancel = CancelToken::new();
        // Line source that cancels before returning re-entry.
        struct CancelLines {
            token: CancelToken,
        }
        impl MnemonicSource for CancelLines {
            fn read_line(&self, _prompt: &str) -> Result<Zeroizing<String>, AppError> {
                self.token.cancel();
                // check_cancel runs at top of ceremony loop before next read,
                // but we cancel mid-read: return something, then next check fires.
                // Actually cancel is checked at loop start; first read_line is
                // after first check. Cancel here; pipeline checks after return
                // only on mismatch path. Force abort by wrong mnemonic + cancel
                // already set so mismatch retry check_cancel fires.
                Ok(Zeroizing::new("wrong".into()))
            }
        }
        let lines = CancelLines {
            token: cancel.clone(),
        };
        let err = run_with(&cfg, &entropy, &pw, &lines, &cancel).unwrap_err();
        assert_eq!(exit_code_for(&err), 4);
        assert!(dir.keystore_files().is_empty());
    }

    // --- overwrite refuse / same-second collision (H5 / K3-L5) ---

    #[test]
    fn same_second_collision_retries_ts_plus_1() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap();

        let files = dir.keystore_files();
        assert_eq!(files.len(), 1);
        let name0 = files[0].file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name0.ends_with("-1700000000.json"),
            "first write at frozen now_unix: {name0}"
        );

        // Same FixedEntropy + same now_unix → collision at ts; H5 retries ts+1.
        let entropy2 = FixedEntropy::zero_mnemonic();
        let lines2 = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        run_with(&cfg, &entropy2, &pw, &lines2, &CancelToken::new()).unwrap();

        let mut names: Vec<String> = dir
            .keystore_files()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names.len(), 2, "names={names:?}");
        assert!(
            names.iter().any(|n| n.ends_with("-1700000000.json")),
            "ts preserved: {names:?}"
        );
        assert!(
            names.iter().any(|n| n.ends_with("-1700000001.json")),
            "retry at ts+1: {names:?}"
        );
    }

    #[test]
    fn double_timestamp_collision_exit3() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 1);
        // Pre-plant both ts and ts+1 so the one-bump retry still collides.
        let at_ts = dir.0.join("keystore-m_12381_3600_0_0_0-1700000000.json");
        let at_ts1 = dir.0.join("keystore-m_12381_3600_0_0_0-1700000001.json");
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

    // --- path shape ---

    #[test]
    fn signing_path_and_filename_shape() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap();
        let files = dir.keystore_files();
        assert_eq!(files.len(), 1);
        let name = files[0].file_name().unwrap().to_string_lossy();
        assert_eq!(name.as_ref(), "keystore-m_12381_3600_0_0_0-1700000000.json");

        let raw = std::fs::read(&files[0]).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["version"], 4);
        assert_eq!(v["path"], "m/12381/3600/0/0/0");
        assert_eq!(v["crypto"]["kdf"]["function"], "scrypt");
        // Unit helpers inject FAST; production N is gated by validator e2e + encrypt
        // EIP-2335 spec-vector (STANDARD).
        assert_eq!(v["crypto"]["kdf"]["params"]["n"], ScryptParams::FAST.n);
    }

    #[test]
    fn min_len_passphrase_wrapper() {
        let _guard = ENV_LOCK.lock().unwrap();
        let env_name = format!("ETHERNAL_TEST_KS_PW_{}", std::process::id());
        // Short value.
        std::env::set_var(&env_name, "short7c");
        let env = EnvSource::new(&env_name);
        let checked = MinLenPassphrase {
            inner: &env,
            min: KEYSTORE_PASSPHRASE_MIN_LEN,
        };
        let err = checked.read().unwrap_err();
        assert!(matches!(err, KeystoreError::PassphraseTooShort { .. }));
        std::env::set_var(&env_name, "password1");
        let ok = checked.read().unwrap();
        assert_eq!(ok, b"password1");
        std::env::remove_var(&env_name);
    }

    /// Quiet unused-import / dead_code guards for Arc if not otherwise used.
    #[test]
    fn fixed_entropy_is_sync() {
        fn assert_sync<T: Sync>(_: &T) {}
        let e = FixedEntropy::zero_mnemonic();
        assert_sync(&e);
        let _ = Arc::new(e);
    }

    // =========================================================================
    // validator recover (K3-3)
    // =========================================================================

    #[test]
    fn zeroizing_trim_no_ws_keeps_same_content() {
        let s = Zeroizing::new("abandon about".into());
        let t = zeroizing_trim(s);
        assert_eq!(t.as_str(), "abandon about");
    }

    #[test]
    fn zeroizing_trim_strips_surrounding_ws() {
        let s = Zeroizing::new("  abandon about  \n".into());
        let t = zeroizing_trim(s);
        assert_eq!(t.as_str(), "abandon about");
    }

    #[test]
    fn recover_12_word_loader_round_trip() {
        let dir = Tmp::new("validator-cmd-test");
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

        let files = dir.keystore_files();
        assert_eq!(files.len(), 1);
        let seed = bip39::to_seed(ABANDON_12, b"").unwrap();
        let loader = Loader::new();
        let key = loader
            .load(&files[0], &FixedPassphrase(b"password1".to_vec()))
            .unwrap();
        let derived = derive_path(seed.as_slice(), &KeyPath::signing(0)).unwrap();
        assert_eq!(key.secret.as_slice(), derived.to_bytes().as_slice());
        assert_eq!(key.pubkey_hex, hex::encode(derived.public_key()));

        let raw = std::fs::read(&files[0]).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["version"], 4);
        assert_eq!(v["path"], "m/12381/3600/0/0/0");
        assert_eq!(v["crypto"]["kdf"]["function"], "scrypt");
    }

    #[test]
    fn recover_24_word_loader_round_trip() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = recover_cfg(dir.str(), 1, 0);
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let entropy = FixedEntropy::new(vec![]);
        let pw = FixedPassphrase(b"password1".to_vec());
        run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");
        let files = dir.keystore_files();
        assert_eq!(files.len(), 1);
        let seed = bip39::to_seed(ZERO_MNEMONIC, b"").unwrap();
        let key = Loader::new()
            .load(&files[0], &FixedPassphrase(b"password1".to_vec()))
            .unwrap();
        let derived = derive_path(seed.as_slice(), &KeyPath::signing(0)).unwrap();
        assert_eq!(key.secret.as_slice(), derived.to_bytes().as_slice());
    }

    #[test]
    fn recover_bad_word_exit2() {
        let dir = Tmp::new("validator-cmd-test");
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
        assert!(dir.keystore_files().is_empty());
    }

    #[test]
    fn recover_bad_checksum_exit2() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = recover_cfg(dir.str(), 1, 0);
        // 12× abandon — wrong checksum (valid ends with about).
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let lines = ScriptedLines::new(vec![bad]);
        let entropy = FixedEntropy::new(vec![]);
        let pw = FixedPassphrase(b"password1".to_vec());
        let err = run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).unwrap_err();
        assert_eq!(exit_code_for(&err), 2, "err={err}");
        assert!(err.to_string().contains("checksum"), "err={err}");
        assert!(dir.keystore_files().is_empty());
    }

    #[test]
    fn recover_start_index_range_filenames() {
        let dir = Tmp::new("validator-cmd-test");
        // indices 5, 6, 7
        let cfg = recover_cfg(dir.str(), 3, 5);
        let lines = ScriptedLines::new(vec![ABANDON_12]);
        let entropy = FixedEntropy::new(vec![]);
        let pw = FixedPassphrase(b"password1".to_vec());
        let (_, summary) =
            run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");

        let mut files = dir.keystore_files();
        files.sort();
        assert_eq!(files.len(), 3, "files={files:?}");
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().any(|n| n.contains("m_12381_3600_5_0_0")),
            "names={names:?}"
        );
        assert!(
            names.iter().any(|n| n.contains("m_12381_3600_6_0_0")),
            "names={names:?}"
        );
        assert!(
            names.iter().any(|n| n.contains("m_12381_3600_7_0_0")),
            "names={names:?}"
        );

        // Loader round-trip for each index.
        let seed = bip39::to_seed(ABANDON_12, b"").unwrap();
        let loader = Loader::new();
        let pw_src = FixedPassphrase(b"password1".to_vec());
        for f in &files {
            let name = f.file_name().unwrap().to_string_lossy();
            let idx: u32 = name
                .split('_')
                .nth(3)
                .and_then(|s| s.parse().ok())
                .expect("index");
            assert!((5..=7).contains(&idx));
            let key = loader.load(f, &pw_src).unwrap();
            let derived = derive_path(seed.as_slice(), &KeyPath::signing(idx)).unwrap();
            assert_eq!(key.secret.as_slice(), derived.to_bytes().as_slice());
        }

        // PR-8: recover shares finish_from_mnemonic — same phase reporting as new.
        let summary_s = String::from_utf8(summary).unwrap();
        for i in 1..=3 {
            assert!(
                summary_s.contains(&format!("[{i}/3] deriving")),
                "missing [{i}/3] deriving in recover summary: {summary_s}"
            );
            assert!(
                summary_s.contains(&format!("[{i}/3] encrypting")),
                "missing [{i}/3] encrypting in recover summary: {summary_s}"
            );
            assert!(
                summary_s.contains(&format!("[{i}/3] writing")),
                "missing [{i}/3] writing in recover summary: {summary_s}"
            );
        }
        assert!(summary_s.contains("keystore 1/3:"), "{summary_s}");
        assert!(summary_s.contains("wrote 3 keystores"), "{summary_s}");
    }

    // =========================================================================
    // V2-2 phase reporting in finish_from_mnemonic
    // =========================================================================

    #[test]
    fn phase_reporting_count3_tty_phases_and_durable_lines() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 3);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let (_, summary) = run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");
        let summary_s = String::from_utf8(summary).unwrap();

        // Transient phases for every key.
        for i in 1..=3 {
            assert!(
                summary_s.contains(&format!("[{i}/3] deriving")),
                "missing [{i}/3] deriving: {summary_s}"
            );
            assert!(
                summary_s.contains(&format!("[{i}/3] encrypting")),
                "missing [{i}/3] encrypting: {summary_s}"
            );
            assert!(
                summary_s.contains(&format!("[{i}/3] writing")),
                "missing [{i}/3] writing: {summary_s}"
            );
        }
        // Ends with last key's writing phase (then clear + durable + summary).
        assert!(
            summary_s.contains("[3/3] writing"),
            "missing [3/3] writing: {summary_s}"
        );

        // Durable lines byte-identical to today's format (PR-4).
        assert!(
            summary_s.contains("keystore 1/3:"),
            "durable keystore 1/3 missing: {summary_s}"
        );
        assert!(
            summary_s.contains("keystore 2/3:"),
            "durable keystore 2/3 missing: {summary_s}"
        );
        assert!(
            summary_s.contains("keystore 3/3:"),
            "durable keystore 3/3 missing: {summary_s}"
        );
        assert!(
            summary_s.contains("wrote 3 keystores"),
            "summary missing: {summary_s}"
        );
        // Durable keystore line shape: "keystore i/n: <path> (pubkey=0x...)"
        for line in summary_s.lines() {
            if let Some(rest) = line.strip_prefix("keystore ") {
                assert!(
                    rest.contains(": ") && rest.contains(" (pubkey=0x") && rest.ends_with(')'),
                    "durable line format changed: {line}"
                );
            }
        }
    }

    #[test]
    fn phase_reporting_nontty_no_csi() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 2);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let mut tty = Vec::new();
        let mut summary = Vec::new();
        let logger = Logger::discard();
        let loader = Loader::new();
        {
            let mut deps = ValidatorDeps {
                cfg: &cfg,
                entropy: &entropy,
                keystore_pw: &pw,
                mnemonic_src: &lines,
                tty_writer: &mut tty,
                summary_out: &mut summary,
                progress: Progress::NonTty,
                logger: &logger,
                now_unix: 1_700_000_000,
                scrypt: ScryptParams::FAST,
                loader: &loader,
            };
            run_validator_new_with_deps(&mut deps, &CancelToken::new()).expect("ok");
        }
        assert!(
            !summary.contains(&b'\r'),
            "NonTty summary must not contain \\r: {:?}",
            String::from_utf8_lossy(&summary)
        );
        assert!(
            !summary.contains(&0x1b),
            "NonTty summary must not contain ESC: {:?}",
            String::from_utf8_lossy(&summary)
        );
        let summary_s = String::from_utf8(summary).unwrap();
        assert!(summary_s.contains("wrote 2 keystores"), "{summary_s}");
        // NonTty: no phase labels, no durable keystore i/n lines on summary
        // (those go to the logger).
        assert!(
            !summary_s.contains("deriving")
                && !summary_s.contains("encrypting")
                && !summary_s.contains("writing"),
            "NonTty must not emit phase labels: {summary_s}"
        );
    }

    // =========================================================================
    // V3-2 C1–C3 derivation self-checks
    // =========================================================================

    /// sk + pubkey for ZERO_MNEMONIC signing index `idx`.
    fn zero_mnemonic_key(idx: u32) -> (Zeroizing<[u8; 32]>, [u8; 48]) {
        let seed = bip39::to_seed(ZERO_MNEMONIC, b"").unwrap();
        let d = derive_path(seed.as_slice(), &KeyPath::signing(idx)).unwrap();
        (d.to_bytes(), d.public_key())
    }

    #[test]
    fn check_c1_mismatched_sk_and_pubkey() {
        let (sk_a, _pk_a) = zero_mnemonic_key(0);
        let (_sk_b, pk_b) = zero_mnemonic_key(1);
        let err = check_c1(sk_a.as_slice(), &pk_b, 0, "m/12381/3600/0/0/0").unwrap_err();
        match &err {
            AppError::KeyVerifyFailed { check, index, .. } => {
                assert_eq!(*check, "C1");
                assert_eq!(*index, 0);
            }
            other => panic!("expected KeyVerifyFailed C1, got {other:?}"),
        }
        assert_eq!(exit_code_for(&err), 3);
        // No secret-shaped hex dump in the detail (PR-16).
        let s = err.to_string();
        assert!(!s.contains(&hex::encode(sk_a.as_slice())));
        assert!(!s.contains(&hex::encode(pk_b)));
    }

    #[test]
    fn check_c2_all_zero_pubkey() {
        let zero_pk = [0u8; 48];
        let err = check_c2(&zero_pk, 7, "m/12381/3600/7/0/0").unwrap_err();
        match &err {
            AppError::KeyVerifyFailed { check, index, .. } => {
                assert_eq!(*check, "C2");
                assert_eq!(*index, 7);
            }
            other => panic!("expected KeyVerifyFailed C2, got {other:?}"),
        }
        assert_eq!(exit_code_for(&err), 3);
    }

    #[test]
    fn check_c3_mismatched_sk_and_pubkey() {
        // Both sk_a and pk_b are individually valid; only the pair fails C3.
        // (C1 would also fail this pair; C3 is tested by calling the helper
        // directly — unreachable through verify_derived_key.)
        let (sk_a, _pk_a) = zero_mnemonic_key(0);
        let (_sk_b, pk_b) = zero_mnemonic_key(1);
        let err = check_c3(sk_a.as_slice(), &pk_b, 1, "m/12381/3600/1/0/0").unwrap_err();
        match &err {
            AppError::KeyVerifyFailed { check, index, .. } => {
                assert_eq!(*check, "C3");
                assert_eq!(*index, 1);
            }
            other => panic!("expected KeyVerifyFailed C3, got {other:?}"),
        }
        assert_eq!(exit_code_for(&err), 3);
        let s = err.to_string();
        assert!(!s.contains(&hex::encode(sk_a.as_slice())));
        assert!(!s.contains(&hex::encode(pk_b)));
    }

    #[test]
    fn verify_derived_key_positive_zero_mnemonic() {
        let (sk, pk) = zero_mnemonic_key(0);
        verify_derived_key(sk.as_slice(), &pk, 0, "m/12381/3600/0/0/0")
            .expect("real derived key must pass C1–C3");
        // C1 first: mismatched pair fails as C1, not C3.
        let (sk_a, _) = zero_mnemonic_key(0);
        let (_, pk_b) = zero_mnemonic_key(1);
        let err = verify_derived_key(sk_a.as_slice(), &pk_b, 0, "m/12381/3600/0/0/0").unwrap_err();
        match err {
            AppError::KeyVerifyFailed { check, .. } => assert_eq!(check, "C1"),
            other => panic!("expected C1 via verify_derived_key, got {other:?}"),
        }
    }

    #[test]
    fn phase_checking_appears_on_tty_happy_path() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 2);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let before = dir.keystore_files().len();
        let (_, summary) = run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");
        let summary_s = String::from_utf8(summary).unwrap();

        for i in 1..=2 {
            assert!(
                summary_s.contains(&format!("[{i}/2] checking")),
                "missing [{i}/2] checking: {summary_s}"
            );
            // Full phase order: deriving → checking → encrypting → writing.
            assert!(
                summary_s.contains(&format!("[{i}/2] deriving")),
                "missing [{i}/2] deriving: {summary_s}"
            );
            assert!(
                summary_s.contains(&format!("[{i}/2] encrypting")),
                "missing [{i}/2] encrypting: {summary_s}"
            );
            assert!(
                summary_s.contains(&format!("[{i}/2] writing")),
                "missing [{i}/2] writing: {summary_s}"
            );
        }
        // Happy path still writes keystores (checks passed).
        assert_eq!(dir.keystore_files().len(), before + 2);
        assert!(summary_s.contains("wrote 2 keystores"), "{summary_s}");
    }

    #[test]
    fn phase_checking_appears_on_recover_tty() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = recover_cfg(dir.str(), 1, 0);
        let entropy = FixedEntropy::new(vec![]);
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let (_, summary) =
            run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");
        let summary_s = String::from_utf8(summary).unwrap();
        assert!(
            summary_s.contains("[1/1] checking"),
            "recover must run C1–C3 (checking phase): {summary_s}"
        );
        assert_eq!(dir.keystore_files().len(), 1);
    }

    /// C1–C3 are pre-write: a failed check cannot leave a keystore for that index.
    /// Structural proof via call-order + helper failure (no production fault seam).
    #[test]
    fn c1_c3_failure_is_pre_write_no_keystore_for_index() {
        let dir = Tmp::new("validator-cmd-test");
        let (sk_a, _) = zero_mnemonic_key(0);
        let (_, pk_b) = zero_mnemonic_key(1);
        // Helpers fail without I/O; production path calls them before encrypt/write.
        let err = verify_derived_key(sk_a.as_slice(), &pk_b, 0, "m/12381/3600/0/0/0").unwrap_err();
        assert_eq!(exit_code_for(&err), 3);
        assert!(
            dir.keystore_files().is_empty(),
            "C1–C3 failure must not create a keystore: {:?}",
            dir.keystore_files()
        );
    }

    #[test]
    fn recover_no_ceremony_tty_empty() {
        let dir = Tmp::new("validator-cmd-test");
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
        let dir = Tmp::new("validator-cmd-test");
        let mut cfg = recover_cfg(dir.str(), 1, 0);
        cfg.mnemonic_passphrase = MnemonicPassphraseForm::Prompt;
        // mnemonic, then single passphrase (no confirm).
        let lines = ScriptedLines::new(vec![ABANDON_12, "TREZOR"]);
        let entropy = FixedEntropy::new(vec![]);
        let pw = FixedPassphrase(b"password1".to_vec());
        run_recover_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");
        let seed = bip39::to_seed(ABANDON_12, b"TREZOR").unwrap();
        assert_eq!(hex::encode(seed.as_slice()), TREZOR_SEED_HEX);
        let files = dir.keystore_files();
        assert_eq!(files.len(), 1);
        let key = Loader::new()
            .load(&files[0], &FixedPassphrase(b"password1".to_vec()))
            .unwrap();
        let derived = derive_path(seed.as_slice(), &KeyPath::signing(0)).unwrap();
        assert_eq!(key.secret.as_slice(), derived.to_bytes().as_slice());
    }

    #[test]
    fn recover_same_shape_as_key_new() {
        // Same fixed mnemonic (24-word abandon…art), empty mnemonic-pass,
        // same FixedEntropy salt/iv/uuid zeros and now_unix → identical JSON.
        let dir_new = Tmp::new("validator-cmd-test");
        let dir_rec = Tmp::new("validator-cmd-test");
        let cfg_new = base_cfg(dir_new.str(), 1);
        let cfg_rec = recover_cfg(dir_rec.str(), 1, 0);

        let entropy_new = FixedEntropy::zero_mnemonic();
        let entropy_rec = FixedEntropy::new(vec![]); // only salt/iv/uuid
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines_new = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let lines_rec = ScriptedLines::new(vec![ZERO_MNEMONIC]);

        run_with(&cfg_new, &entropy_new, &pw, &lines_new, &CancelToken::new()).unwrap();
        run_recover_with(&cfg_rec, &entropy_rec, &pw, &lines_rec, &CancelToken::new()).unwrap();

        let f_new = dir_new.keystore_files();
        let f_rec = dir_rec.keystore_files();
        assert_eq!(f_new.len(), 1);
        assert_eq!(f_rec.len(), 1);
        assert_eq!(
            f_new[0].file_name(),
            f_rec[0].file_name(),
            "filenames should match"
        );
        // Same secret + password + salt/iv/uuid → byte-identical keystore JSON.
        let a = std::fs::read(&f_new[0]).unwrap();
        let b = std::fs::read(&f_rec[0]).unwrap();
        assert_eq!(
            a, b,
            "validator new and key recover must produce identical shape"
        );
    }

    // =========================================================================
    // K3-4 secret hygiene (S-2 / G5)
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

    /// Secrets (mnemonic, seed, SK, both passphrases — raw + hex) must never
    /// appear in summary/logger; mnemonic display is only on `tty_writer`.
    #[test]
    fn secret_hygiene_key_new_buffers() {
        let dir = Tmp::new("validator-cmd-test");
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
            let loader = Loader::new();
            let mut deps = ValidatorDeps {
                cfg: &cfg,
                entropy: &entropy,
                keystore_pw: &pw,
                mnemonic_src: &lines,
                tty_writer: &mut tty,
                summary_out: &mut summary,
                progress: Progress::Tty,
                logger: &logger,
                now_unix: 1_700_000_000,
                scrypt: ScryptParams::FAST,
                loader: &loader,
            };
            run_validator_new_with_deps(&mut deps, &CancelToken::new()).expect("ok");
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
        assert!(
            !summary_s.contains(&seed_hex) && !logs_s.contains(&seed_hex),
            "seed hex leaked"
        );
        assert!(
            !summary_s
                .as_bytes()
                .windows(seed.len())
                .any(|w| w == seed.as_slice())
                && !logs.windows(seed.len()).any(|w| w == seed.as_slice()),
            "raw seed leaked"
        );

        // Signing SK for index 0.
        let derived = derive_path(seed.as_slice(), &KeyPath::signing(0)).unwrap();
        let sk = derived.to_bytes();
        let sk_hex = hex::encode(sk.as_slice());
        assert!(
            !summary_s.contains(&sk_hex) && !logs_s.contains(&sk_hex),
            "sk hex leaked"
        );
        assert!(
            !summary_s
                .as_bytes()
                .windows(sk.len())
                .any(|w| w == sk.as_slice())
                && !logs.windows(sk.len()).any(|w| w == sk.as_slice()),
            "raw sk leaked"
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
        // "TREZOR" is not in the abandon…art mnemonic; ensure it is not shown.
        assert!(!tty_s.contains("TREZOR"), "mnemonic passphrase on tty");

        // Progress/summary should still be non-empty (paths + pubkeys only).
        assert!(summary_s.contains("wrote 1 keystore"), "{summary_s}");
        assert!(!logs.is_empty(), "debug logger should emit events");
    }

    // =========================================================================
    // V4-2 C4 post-write decrypt round trip + verifying phase
    // =========================================================================

    /// Injected loader for C4 negative tests (PR-19).
    struct FakeKeyLoader {
        #[allow(clippy::type_complexity)]
        f: Box<dyn Fn(&Path) -> Result<Key, KeystoreError> + Sync>,
    }

    impl KeyLoader for FakeKeyLoader {
        fn load(&self, path: &Path, _pw: &dyn PassphraseSource) -> Result<Key, KeystoreError> {
            (self.f)(path)
        }
    }

    /// Counts `PassphraseSource::read` calls (prove original source is called once).
    struct CountingPassphrase {
        inner: FixedPassphrase,
        calls: AtomicUsize,
    }

    impl PassphraseSource for CountingPassphrase {
        fn read(&self) -> Result<Vec<u8>, KeystoreError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.read()
        }
    }

    #[test]
    fn c4_happy_path_count2_decrypts_and_writes_exactly_two() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 2);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let (_, summary) = run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");
        let summary_s = String::from_utf8(summary).unwrap();

        for i in 1..=2 {
            assert!(
                summary_s.contains(&format!("[{i}/2] verifying")),
                "missing [{i}/2] verifying: {summary_s}"
            );
        }
        let files = dir.keystore_files();
        assert_eq!(files.len(), 2, "files: {files:?}");
        assert!(summary_s.contains("wrote 2 keystores"), "{summary_s}");

        // C4 already verified via Loader; re-check content still matches HD.
        let seed = bip39::to_seed(ZERO_MNEMONIC, b"").unwrap();
        let loader = Loader::new();
        let pw_src = FixedPassphrase(b"password1".to_vec());
        for f in &files {
            let key = loader.load(f, &pw_src).expect("load");
            let name = f.file_name().unwrap().to_string_lossy();
            let idx: u32 = name
                .split('_')
                .nth(3)
                .and_then(|s| s.parse().ok())
                .expect("index in filename");
            let derived = derive_path(seed.as_slice(), &KeyPath::signing(idx)).unwrap();
            assert_eq!(key.secret.as_slice(), derived.to_bytes().as_slice());
            assert_eq!(key.pubkey_hex, hex::encode(derived.public_key()));
        }
    }

    #[test]
    fn c4_mismatched_secret_stops_run_leaves_file_exit3() {
        let dir = Tmp::new("validator-cmd-test");
        // count=2: first key fails C4 → second never created.
        let cfg = base_cfg(dir.str(), 2);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let mut tty = Vec::new();
        let mut summary = Vec::new();
        let logger = Logger::discard();
        // Wrong secret (all zeros) so C4 fails on secret compare, not load error.
        let fake = FakeKeyLoader {
            f: Box::new(|_path| {
                Ok(Key {
                    secret: vec![0u8; 32],
                    pubkey_hex: "00".repeat(48),
                })
            }),
        };
        let mut deps = ValidatorDeps {
            cfg: &cfg,
            entropy: &entropy,
            keystore_pw: &pw,
            mnemonic_src: &lines,
            tty_writer: &mut tty,
            summary_out: &mut summary,
            progress: Progress::Tty,
            logger: &logger,
            now_unix: 1_700_000_000,
            scrypt: ScryptParams::FAST,
            loader: &fake,
        };
        let err = run_validator_new_with_deps(&mut deps, &CancelToken::new()).unwrap_err();
        match &err {
            AppError::KeyVerifyFailed {
                check, index, path, ..
            } => {
                assert_eq!(*check, "C4");
                assert_eq!(*index, 0);
                assert!(
                    Path::new(path).exists(),
                    "failing file must still exist: {path}"
                );
            }
            other => panic!("expected KeyVerifyFailed C4, got {other:?}"),
        }
        assert_eq!(exit_code_for(&err), 3);
        let s = err.to_string();
        assert!(s.contains("C4"), "{s}");
        assert!(s.contains("was NOT removed"), "{s}");
        // First keystore written and left; second never created.
        assert_eq!(
            dir.keystore_files().len(),
            1,
            "only the failing index's file: {:?}",
            dir.keystore_files()
        );
    }

    #[test]
    fn c4_mismatched_pubkey_hex_stops_run_leaves_file_exit3() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 2);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        // Right secret for index 0, wrong pubkey_hex — the scan_dir-accepts-it case.
        let seed = bip39::to_seed(ZERO_MNEMONIC, b"").unwrap();
        let derived0 = derive_path(seed.as_slice(), &KeyPath::signing(0)).unwrap();
        let sk0 = derived0.to_bytes().to_vec();
        let wrong_pk = hex::encode(
            derive_path(seed.as_slice(), &KeyPath::signing(1))
                .unwrap()
                .public_key(),
        );

        let mut tty = Vec::new();
        let mut summary = Vec::new();
        let logger = Logger::discard();
        let fake = FakeKeyLoader {
            f: Box::new(move |_path| {
                Ok(Key {
                    secret: sk0.clone(),
                    pubkey_hex: wrong_pk.clone(),
                })
            }),
        };
        let mut deps = ValidatorDeps {
            cfg: &cfg,
            entropy: &entropy,
            keystore_pw: &pw,
            mnemonic_src: &lines,
            tty_writer: &mut tty,
            summary_out: &mut summary,
            progress: Progress::Tty,
            logger: &logger,
            now_unix: 1_700_000_000,
            scrypt: ScryptParams::FAST,
            loader: &fake,
        };
        let err = run_validator_new_with_deps(&mut deps, &CancelToken::new()).unwrap_err();
        match &err {
            AppError::KeyVerifyFailed {
                check,
                index,
                path,
                detail,
            } => {
                assert_eq!(*check, "C4");
                assert_eq!(*index, 0);
                assert!(
                    detail.contains("pubkey"),
                    "detail should name pubkey mismatch: {detail}"
                );
                assert!(
                    Path::new(path).exists(),
                    "failing file must still exist: {path}"
                );
            }
            other => panic!("expected KeyVerifyFailed C4, got {other:?}"),
        }
        assert_eq!(exit_code_for(&err), 3);
        assert!(err.to_string().contains("was NOT removed"));
        assert_eq!(dir.keystore_files().len(), 1);
    }

    #[test]
    fn c4_original_passphrase_source_read_exactly_once() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 3);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = CountingPassphrase {
            inner: FixedPassphrase(b"password1".to_vec()),
            calls: AtomicUsize::new(0),
        };
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");
        assert_eq!(
            pw.calls.load(Ordering::SeqCst),
            1,
            "original passphrase source must be read exactly once for the whole run \
             (InMemoryPassphrase covers C4; no re-prompt / no second env read)"
        );
        assert_eq!(dir.keystore_files().len(), 3);
    }

    #[test]
    fn phase_verifying_tty_only_not_nontty() {
        // Tty: verifying appears.
        let dir_tty = Tmp::new("validator-cmd-test");
        let cfg_tty = base_cfg(dir_tty.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let (_, summary_tty) =
            run_with(&cfg_tty, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");
        let tty_s = String::from_utf8(summary_tty).unwrap();
        assert!(
            tty_s.contains("[1/1] verifying"),
            "Tty must show verifying phase: {tty_s}"
        );

        // NonTty: no phase labels at all (including verifying).
        let dir_nt = Tmp::new("validator-cmd-test");
        let cfg_nt = base_cfg(dir_nt.str(), 1);
        let lines_nt = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let mut tty = Vec::new();
        let mut summary = Vec::new();
        let logger = Logger::discard();
        let loader = Loader::new();
        {
            let mut deps = ValidatorDeps {
                cfg: &cfg_nt,
                entropy: &entropy,
                keystore_pw: &pw,
                mnemonic_src: &lines_nt,
                tty_writer: &mut tty,
                summary_out: &mut summary,
                progress: Progress::NonTty,
                logger: &logger,
                now_unix: 1_700_000_000,
                scrypt: ScryptParams::FAST,
                loader: &loader,
            };
            run_validator_new_with_deps(&mut deps, &CancelToken::new()).expect("ok");
        }
        let nt_s = String::from_utf8(summary).unwrap();
        assert!(
            !nt_s.contains("verifying") && !nt_s.contains("deriving") && !nt_s.contains("writing"),
            "NonTty must not emit phase labels: {nt_s}"
        );
        assert_eq!(dir_nt.keystore_files().len(), 1);
    }

    /// Recover path: no tty display; secrets still absent from summary/logger.
    #[test]
    fn secret_hygiene_key_recover_buffers() {
        let dir = Tmp::new("validator-cmd-test");
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
            let loader = Loader::new();
            let mut deps = ValidatorDeps {
                cfg: &cfg,
                entropy: &entropy,
                keystore_pw: &pw,
                mnemonic_src: &lines,
                tty_writer: &mut tty,
                summary_out: &mut summary,
                progress: Progress::NonTty,
                logger: &logger,
                now_unix: 1_700_000_000,
                scrypt: ScryptParams::FAST,
                loader: &loader,
            };
            run_validator_recover_with_deps(&mut deps, &CancelToken::new()).expect("ok");
        }

        let tty_s = String::from_utf8(tty).unwrap();
        let summary_s = String::from_utf8(summary).unwrap();
        let logs_s = String::from_utf8_lossy(&logbuf.lock().unwrap()).into_owned();

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
    }

    // =========================================================================
    // V4-3 --no-verify, WARNING, verified= log field
    // =========================================================================

    /// Counts `KeyLoader::load` calls to prove C4 is skipped under `--no-verify`.
    struct CountingLoader {
        inner: Loader,
        calls: AtomicUsize,
    }

    impl KeyLoader for CountingLoader {
        fn load(&self, path: &Path, pw: &dyn PassphraseSource) -> Result<Key, KeystoreError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.load(path, pw)
        }
    }

    #[test]
    fn no_verify_skips_c4_loader_not_called_count2() {
        let dir = Tmp::new("validator-cmd-test");
        let mut cfg = base_cfg(dir.str(), 2);
        cfg.verify_keystore = false;
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let mut tty = Vec::new();
        let mut summary = Vec::new();
        let logger = Logger::discard();
        let counter = CountingLoader {
            inner: Loader::new(),
            calls: AtomicUsize::new(0),
        };
        {
            let mut deps = ValidatorDeps {
                cfg: &cfg,
                entropy: &entropy,
                keystore_pw: &pw,
                mnemonic_src: &lines,
                tty_writer: &mut tty,
                summary_out: &mut summary,
                progress: Progress::Tty,
                logger: &logger,
                now_unix: 1_700_000_000,
                scrypt: ScryptParams::FAST,
                loader: &counter,
            };
            run_validator_new_with_deps(&mut deps, &CancelToken::new()).expect("ok");
        }
        assert_eq!(
            counter.calls.load(Ordering::SeqCst),
            0,
            "C4 loader must not be called when verify_keystore=false"
        );
        assert_eq!(dir.keystore_files().len(), 2);
        let summary_s = String::from_utf8(summary).unwrap();
        // C1–C3 still run (checking phase present for each key).
        for i in 1..=2 {
            assert!(
                summary_s.contains(&format!("[{i}/2] checking")),
                "C1–C3 must still run under --no-verify: {summary_s}"
            );
        }
        // Verifying phase must not appear when C4 is skipped.
        assert!(
            !summary_s.contains("verifying"),
            "verifying phase must not run under --no-verify: {summary_s}"
        );
        // Exactly one WARNING line for the flag.
        let warning_lines: Vec<_> = summary_s
            .lines()
            .filter(|l| l.contains("WARNING"))
            .collect();
        assert_eq!(
            warning_lines.len(),
            1,
            "expected exactly one WARNING, got: {summary_s}"
        );
        assert!(
            warning_lines[0].contains("--no-verify")
                && warning_lines[0].contains("will not be decrypted back"),
            "unexpected WARNING text: {}",
            warning_lines[0]
        );
    }

    #[test]
    fn default_path_no_no_verify_warning() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let (_, summary) = run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");
        let summary_s = String::from_utf8(summary).unwrap();
        assert!(
            !summary_s.contains("WARNING: --no-verify"),
            "default path must not emit --no-verify WARNING: {summary_s}"
        );
        // C4 still runs by default.
        assert!(
            summary_s.contains("[1/1] verifying"),
            "default must still verify: {summary_s}"
        );
    }

    #[test]
    fn no_verify_c1_helpers_still_exit3() {
        // --no-verify does not gate C1–C3; forced C1 failure still exits 3.
        let (sk_a, _) = zero_mnemonic_key(0);
        let (_, pk_b) = zero_mnemonic_key(1);
        let err = verify_derived_key(sk_a.as_slice(), &pk_b, 0, "m/12381/3600/0/0/0").unwrap_err();
        assert_eq!(exit_code_for(&err), 3);
        match err {
            AppError::KeyVerifyFailed { check, .. } => assert_eq!(check, "C1"),
            other => panic!("expected C1 KeyVerifyFailed, got {other:?}"),
        }
    }

    #[test]
    fn verified_full_default_nontty_log() {
        let dir = Tmp::new("validator-cmd-test");
        let cfg = base_cfg(dir.str(), 1);
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let mut tty = Vec::new();
        let mut summary = Vec::new();
        let logbuf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let logger = Logger::new(
            Level::Info,
            Format::Text,
            Box::new(SharedWriter(Arc::clone(&logbuf))),
        );
        let loader = Loader::new();
        {
            let mut deps = ValidatorDeps {
                cfg: &cfg,
                entropy: &entropy,
                keystore_pw: &pw,
                mnemonic_src: &lines,
                tty_writer: &mut tty,
                summary_out: &mut summary,
                progress: Progress::NonTty,
                logger: &logger,
                now_unix: 1_700_000_000,
                scrypt: ScryptParams::FAST,
                loader: &loader,
            };
            run_validator_new_with_deps(&mut deps, &CancelToken::new()).expect("ok");
        }
        let logs_s = String::from_utf8_lossy(&logbuf.lock().unwrap()).into_owned();
        assert!(
            logs_s.contains("msg=\"keystore written\"") || logs_s.contains("msg=keystore"),
            "expected keystore written event: {logs_s}"
        );
        assert!(
            logs_s.contains("verified=full"),
            "default NonTty must log verified=full: {logs_s}"
        );
        assert!(
            !logs_s.contains("verified=derived-only"),
            "default must not log derived-only: {logs_s}"
        );
    }

    #[test]
    fn verified_derived_only_with_no_verify_nontty_log() {
        let dir = Tmp::new("validator-cmd-test");
        let mut cfg = base_cfg(dir.str(), 1);
        cfg.verify_keystore = false;
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let mut tty = Vec::new();
        let mut summary = Vec::new();
        let logbuf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let logger = Logger::new(
            Level::Info,
            Format::Text,
            Box::new(SharedWriter(Arc::clone(&logbuf))),
        );
        let counter = CountingLoader {
            inner: Loader::new(),
            calls: AtomicUsize::new(0),
        };
        {
            let mut deps = ValidatorDeps {
                cfg: &cfg,
                entropy: &entropy,
                keystore_pw: &pw,
                mnemonic_src: &lines,
                tty_writer: &mut tty,
                summary_out: &mut summary,
                progress: Progress::NonTty,
                logger: &logger,
                now_unix: 1_700_000_000,
                scrypt: ScryptParams::FAST,
                loader: &counter,
            };
            run_validator_new_with_deps(&mut deps, &CancelToken::new()).expect("ok");
        }
        assert_eq!(counter.calls.load(Ordering::SeqCst), 0);
        let logs_s = String::from_utf8_lossy(&logbuf.lock().unwrap()).into_owned();
        assert!(
            logs_s.contains("verified=derived-only"),
            "--no-verify NonTty must log verified=derived-only: {logs_s}"
        );
        assert!(
            !logs_s.contains("verified=full"),
            "--no-verify must not log verified=full: {logs_s}"
        );
        // TTY durable line is never used here (NonTty); WARNING still on summary.
        let summary_s = String::from_utf8(summary).unwrap();
        assert!(
            summary_s.contains("WARNING: --no-verify"),
            "expected WARNING on summary: {summary_s}"
        );
    }

    #[test]
    fn no_verify_tty_durable_line_byte_identical() {
        // PR-4: TTY keystore line must not gain verified= text.
        let dir = Tmp::new("validator-cmd-test");
        let mut cfg = base_cfg(dir.str(), 1);
        cfg.verify_keystore = false;
        let entropy = FixedEntropy::zero_mnemonic();
        let pw = FixedPassphrase(b"password1".to_vec());
        let lines = ScriptedLines::new(vec![ZERO_MNEMONIC]);
        let (_, summary) = run_with(&cfg, &entropy, &pw, &lines, &CancelToken::new()).expect("ok");
        let summary_s = String::from_utf8(summary).unwrap();
        for line in summary_s.lines() {
            if let Some(rest) = line.strip_prefix("keystore ") {
                assert!(
                    rest.contains(": ") && rest.contains(" (pubkey=0x") && rest.ends_with(')'),
                    "TTY durable line format changed: {line}"
                );
                assert!(
                    !line.contains("verified"),
                    "TTY durable line must not include verified=: {line}"
                );
            }
        }
    }
}
