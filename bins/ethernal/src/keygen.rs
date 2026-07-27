//! Neutral keygen primitives shared by `validator` and `account` namespaces.
//!
//! Ceremony, mnemonic sources, cancel checks, and mnemonic-passphrase secret
//! resolution live here so neither domain owns the other's helpers (T2.3:
//! no `account_cmd` → `validator_cmd` sideways dependency).
//!
//! Domain crypto tails (EIP-2335 BLS vs web3 v3 secp256k1) stay in the
//! respective `*_cmd` modules.

use std::io::{self, Read, Write};
use std::sync::Mutex;

use ethernal_core::cancel::CancelToken;
use ethernal_keystore::{require_min_len, KeystoreError, PassphraseSource};
use zeroize::Zeroizing;

use crate::errors::AppError;
use crate::fs_util::stdin_is_tty;
use crate::keystore_cli::MnemonicPassphraseForm;

// ---------------------------------------------------------------------------
// Injectable seams
// ---------------------------------------------------------------------------

/// Reads interactive text lines for the ceremony re-entry, the bare mnemonic
/// passphrase prompt (with confirm), and the mismatch retry/abort question.
///
/// Production uses a TTY-backed source; tests inject scripted answers.
pub(crate) trait MnemonicSource: Sync {
    /// Writes `prompt` (implementation-defined sink) and returns one line of
    /// input with trailing CR/LF stripped. Used for ceremony re-entry and
    /// retry/abort (multi-word paste; echo may remain on).
    fn read_line(&self, prompt: &str) -> Result<Zeroizing<String>, AppError>;

    /// Echo-suppressed secret line for the BIP-39 mnemonic passphrase (25th
    /// word). Production reads from `/dev/tty` with echo off; tests typically
    /// delegate to the same scripted queue as [`read_line`].
    fn read_secret(&self, prompt: &str) -> Result<Zeroizing<String>, AppError> {
        self.read_line(prompt)
    }
}

// ---------------------------------------------------------------------------
// Mnemonic passphrase resolution (flag / file / prompt / empty)
// ---------------------------------------------------------------------------

/// Resolve the three-form CLI mnemonic passphrase into secret bytes.
///
/// `confirm`: when true (`* new`), bare Prompt requires double-entry; when
/// false (`* recover`), single-entry only.
///
/// Distinct from the clap parser [`crate::keystore_cli::parse_mnemonic_passphrase_form`].
pub(crate) fn resolve_mnemonic_passphrase(
    form: &MnemonicPassphraseForm,
    src: &dyn MnemonicSource,
    cancel: &CancelToken,
    confirm: bool,
) -> Result<Zeroizing<Vec<u8>>, AppError> {
    match form {
        MnemonicPassphraseForm::Empty => Ok(Zeroizing::new(Vec::new())),
        MnemonicPassphraseForm::Raw(v) => Ok(Zeroizing::new(v.as_bytes().to_vec())),
        MnemonicPassphraseForm::File { value, .. } => Ok(Zeroizing::new(value.as_bytes().to_vec())),
        MnemonicPassphraseForm::Prompt => {
            // Echo-off secret entry (S-2).
            check_cancel(cancel)?;
            let first = src.read_secret("Mnemonic passphrase (empty is valid): ")?;
            if confirm {
                check_cancel(cancel)?;
                let second = src.read_secret("Confirm mnemonic passphrase: ")?;
                if first.as_str() != second.as_str() {
                    return Err(AppError::exit2("mnemonic passphrases do not match"));
                }
            }
            Ok(Zeroizing::new(first.as_bytes().to_vec()))
        }
    }
}

// ---------------------------------------------------------------------------
// Ceremony (F-6)
// ---------------------------------------------------------------------------

/// ESC[2J (erase screen) · ESC[3J (erase scrollback) · ESC[H (home), the whole
/// group TWICE — iTerm2 needs a second pass (upstream ethstaker PR #242). Order
/// is load-bearing: erase-screen → erase-scrollback → home.
pub(crate) const CLEAR_SCROLLBACK_TWICE: &[u8] = b"\x1b[2J\x1b[3J\x1b[H\x1b[2J\x1b[3J\x1b[H";

/// Post-ceremony scrub on the SAME display TTY (S-1: never stdout/stderr/logger).
/// Infallible & fail-open (G1-2): on a clear-write error, print manual-clear
/// instructions to `tty`, falling back to `warn_out` (stderr in prod); never
/// changes the ceremony's exit status. On success, print the notice + tmux/screen
/// caveat to the now-blank `tty` (G1-3).
fn clear_after_ceremony(tty: &mut dyn Write, warn_out: &mut dyn Write) {
    let cleared = tty
        .write_all(CLEAR_SCROLLBACK_TWICE)
        .and_then(|_| tty.flush())
        .is_ok();
    if cleared {
        let _ = writeln!(
            tty,
            "The terminal was cleared to remove the displayed mnemonic."
        );
        let _ = writeln!(
            tty,
            "  Note: a terminal multiplexer keeps its own scrollback — \
             tmux: `tmux clear-history`; screen: C-a : then `scrollback 0`."
        );
        let _ = tty.flush();
    } else {
        // Fail-open. macOS Terminal.app makes this the PRIMARY scrub path (ESC[3J
        // unreliable there), so the instructions must be genuinely actionable.
        let msg = "WARNING: could not clear the terminal automatically; the mnemonic may \
                   remain in scrollback.\n  Clear it manually: `clear && printf '\\x1b[3J'`  \
                   (macOS Terminal.app: press Cmd+K).\n";
        if tty
            .write_all(msg.as_bytes())
            .and_then(|_| tty.flush())
            .is_err()
        {
            let _ = warn_out.write_all(msg.as_bytes());
            let _ = warn_out.flush();
        }
    }
}

/// Display mnemonic once on `tty`, require full re-entry confirmation, then
/// clear scrollback. Namespace-generic (shared by `validator new` / `account new`).
pub(crate) fn run_ceremony(
    mnemonic: &str,
    tty: &mut dyn Write,
    warn_out: &mut dyn Write,
    src: &dyn MnemonicSource,
    cancel: &CancelToken,
) -> Result<(), AppError> {
    // Result-capture so the clear fires on every post-display exit path
    // (success, mismatch-abort, read error, cancel, partial display write).
    let outcome = ceremony_body(mnemonic, tty, src, cancel);
    clear_after_ceremony(tty, warn_out);
    outcome
}

/// Display once + full re-entry loop. Split from [`run_ceremony`] so the
/// post-ceremony scrollback clear runs on every exit path (DEP-001 / G1).
fn ceremony_body(
    mnemonic: &str,
    tty: &mut dyn Write,
    src: &dyn MnemonicSource,
    cancel: &CancelToken,
) -> Result<(), AppError> {
    // Display once — only to the injectable TTY writer (S-2). Hard-fail on
    // write/flush so we never proceed to re-entry if the operator never saw it.
    writeln!(
        tty,
        "This is your BIP-39 mnemonic. Write it down and store it offline.\n\
         It will not be shown again.\n"
    )
    .and_then(|_| writeln!(tty, "{mnemonic}"))
    .and_then(|_| writeln!(tty))
    .and_then(|_| tty.flush())
    .map_err(|e| {
        // Namespace-generic: shared by validator new and account new (T2.3).
        AppError::exit2(format!(
            "failed to display mnemonic on controlling terminal: {e}"
        ))
    })?;

    loop {
        check_cancel(cancel)?;
        let reentry = src.read_line("Please re-enter your mnemonic to confirm: ")?;
        if mnemonics_match(mnemonic, reentry.as_str()) {
            return Ok(());
        }
        check_cancel(cancel)?;
        let ans = src.read_line("Mnemonic mismatch. Retry? [y/N]: ")?;
        let ans = ans.trim().to_ascii_lowercase();
        if ans != "y" && ans != "yes" {
            return Err(AppError::Aborted(
                "mnemonic re-entry mismatch; no keystores written".into(),
            ));
        }
    }
}

/// Compare mnemonics after lowercase + whitespace collapse (parity with bip39
/// normalization for noisy re-entry). Both sides are [`Zeroizing`] (S-1).
fn mnemonics_match(expected: &str, got: &str) -> bool {
    normalize_words(expected) == normalize_words(got)
}

fn normalize_words(s: &str) -> Zeroizing<String> {
    Zeroizing::new(
        s.split_whitespace()
            .map(|w| w.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

// ---------------------------------------------------------------------------
// Cancel
// ---------------------------------------------------------------------------

pub(crate) fn check_cancel(cancel: &CancelToken) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        Err(AppError::Aborted("interrupted".into()))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Production helpers
// ---------------------------------------------------------------------------

/// Wraps a [`PassphraseSource`] with [`require_min_len`] (F-7 env path).
pub(crate) struct MinLenPassphrase<'a> {
    pub(crate) inner: &'a dyn PassphraseSource,
    pub(crate) min: usize,
}

impl PassphraseSource for MinLenPassphrase<'_> {
    fn read(&self) -> Result<Vec<u8>, KeystoreError> {
        // Zeroize on both success (after take) and reject (PassphraseTooShort) paths (S-1).
        let mut pw = Zeroizing::new(self.inner.read()?);
        require_min_len(&pw, self.min)?;
        Ok(std::mem::take(&mut *pw))
    }
}

/// Production ceremony + prompt source: re-entry on stdin; secrets via `/dev/tty`
/// with echo suppressed (rpassword), matching keystore passphrase practice.
pub(crate) struct StdinMnemonicSource {
    prompt_out: Mutex<Box<dyn Write + Send>>,
}

impl StdinMnemonicSource {
    pub(crate) fn new<W: Write + Send + 'static>(prompt_out: W) -> Self {
        Self {
            prompt_out: Mutex::new(Box::new(prompt_out)),
        }
    }

    fn write_prompt(&self, prompt: &str) -> Result<(), AppError> {
        let mut w = self
            .prompt_out
            .lock()
            .map_err(|_| AppError::Internal("prompt writer lock poisoned".into()))?;
        write!(w, "{prompt}").map_err(|e| AppError::exit2(format!("write prompt: {e}")))?;
        w.flush()
            .map_err(|e| AppError::exit2(format!("write prompt: {e}")))?;
        Ok(())
    }
}

impl MnemonicSource for StdinMnemonicSource {
    fn read_line(&self, prompt: &str) -> Result<Zeroizing<String>, AppError> {
        self.write_prompt(prompt)?;
        let mut line = Zeroizing::new(String::new());
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| AppError::exit2(format!("read input: {e}")))?;
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(line)
    }

    fn read_secret(&self, prompt: &str) -> Result<Zeroizing<String>, AppError> {
        // Echo-off from /dev/tty (S-2). Prompt on stderr so it still appears
        // when rpassword discards its own output path.
        self.write_prompt(prompt)?;
        let config = rpassword::ConfigBuilder::new()
            .input_file_path("/dev/tty")
            .output_discard()
            .build();
        let result = rpassword::read_password_with_config(config);
        // Newline after suppressed input (match NewKeystorePassphrase).
        {
            if let Ok(mut w) = self.prompt_out.lock() {
                let _ = writeln!(w);
                let _ = w.flush();
            }
        }
        match result {
            Ok(pw) => Ok(Zeroizing::new(pw)),
            Err(err) => Err(AppError::exit2(format!(
                "read mnemonic passphrase: {err}; \
                 for non-interactive use, supply --mnemonic-passphrase VALUE or \
                 --mnemonic-passphrase-file PATH"
            ))),
        }
    }
}

/// Trim leading/trailing Unicode whitespace, keeping the result in
/// [`Zeroizing`]. If no trim is needed, returns `s` unchanged (single buffer).
/// Otherwise allocates a trimmed `Zeroizing` and drops `s` so the untrimmed
/// copy is scrubbed (S-1).
pub(crate) fn zeroizing_trim(s: Zeroizing<String>) -> Zeroizing<String> {
    let t = s.trim();
    if t.len() == s.len() {
        s
    } else {
        // Trimmed form moves into Zeroizing immediately; `s` zeroizes on drop.
        let out = Zeroizing::new(t.to_string());
        drop(s);
        out
    }
}

/// Recover mnemonic source: interactive TTY prompt **or** piped stdin (F-10).
/// When stdin is not a TTY, the prompt is skipped and the mnemonic is read
/// from the pipe (one line or full stdin trimmed).
pub(crate) struct RecoverMnemonicSource {
    prompt_out: Mutex<Box<dyn Write + Send>>,
}

impl RecoverMnemonicSource {
    pub(crate) fn new<W: Write + Send + 'static>(prompt_out: W) -> Self {
        Self {
            prompt_out: Mutex::new(Box::new(prompt_out)),
        }
    }
}

impl MnemonicSource for RecoverMnemonicSource {
    fn read_line(&self, prompt: &str) -> Result<Zeroizing<String>, AppError> {
        if stdin_is_tty() {
            {
                let mut w = self
                    .prompt_out
                    .lock()
                    .map_err(|_| AppError::Internal("prompt writer lock poisoned".into()))?;
                write!(w, "{prompt}").map_err(|e| AppError::exit2(format!("write prompt: {e}")))?;
                w.flush()
                    .map_err(|e| AppError::exit2(format!("write prompt: {e}")))?;
            }
            // Zeroizing from the first allocation (S-1).
            let mut line = Zeroizing::new(String::new());
            io::stdin()
                .read_line(&mut line)
                .map_err(|e| AppError::exit2(format!("read mnemonic: {e}")))?;
            while line.ends_with('\n') || line.ends_with('\r') {
                line.pop();
            }
            Ok(line)
        } else {
            // Piped stdin: read into Zeroizing, then trim without leaving a
            // plain uncleared buffer (S-1 / architecture lifecycle).
            let mut buf = Zeroizing::new(String::new());
            io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| AppError::exit2(format!("read mnemonic from stdin: {e}")))?;
            let mnemonic = zeroizing_trim(buf);
            if mnemonic.is_empty() {
                return Err(AppError::exit2(
                    "empty mnemonic on stdin; provide a BIP-39 mnemonic via pipe or interactive prompt",
                ));
            }
            Ok(mnemonic)
        }
    }

    fn read_secret(&self, prompt: &str) -> Result<Zeroizing<String>, AppError> {
        // Same echo-off path as key new for the 25th-word secret.
        {
            let mut w = self
                .prompt_out
                .lock()
                .map_err(|_| AppError::Internal("prompt writer lock poisoned".into()))?;
            write!(w, "{prompt}").map_err(|e| AppError::exit2(format!("write prompt: {e}")))?;
            w.flush()
                .map_err(|e| AppError::exit2(format!("write prompt: {e}")))?;
        }
        let config = rpassword::ConfigBuilder::new()
            .input_file_path("/dev/tty")
            .output_discard()
            .build();
        let result = rpassword::read_password_with_config(config);
        if let Ok(mut w) = self.prompt_out.lock() {
            let _ = writeln!(w);
            let _ = w.flush();
        }
        match result {
            Ok(pw) => Ok(Zeroizing::new(pw)),
            Err(err) => Err(AppError::exit2(format!(
                "read mnemonic passphrase: {err}; \
                 for non-interactive use, supply --mnemonic-passphrase VALUE or \
                 --mnemonic-passphrase-file PATH"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use ethernal_keystore::FileSource;

    /// FR-19b worked example: `MinLenPassphrase` over `FileSource` with
    /// `1234567\n` (8 raw bytes → FR-8 → 7 → EIP-2335 normalize → 7).
    #[test]
    fn min_len_over_file_source_short_after_strip() {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ethernal-keygen-minlen-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pw");
        std::fs::write(&path, b"1234567\n").unwrap();

        let file_source = FileSource::new(PathBuf::from(&path), io::sink());
        let checked = MinLenPassphrase {
            inner: &file_source,
            min: 8,
        };
        let err = checked
            .read()
            .expect_err("7-byte passphrase after FR-8 must fail min=8");
        match err {
            KeystoreError::PassphraseTooShort { min, got } => {
                assert_eq!(min, 8);
                assert_eq!(got, 7);
            }
            other => panic!("expected PassphraseTooShort {{ min: 8, got: 7 }}, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
