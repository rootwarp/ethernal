//! Passphrase sources: a named environment variable and an interactive
//! terminal prompt.
//!
//! Ported from `go/internal/keystore/passphrase.go`. The trait abstracts where
//! the passphrase comes from so the loader can be tested without a TTY or a
//! live environment variable.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::crypto::normalize_passphrase;
use crate::error::KeystoreError;

/// Abstracts where the passphrase comes from so the loader can be exercised
/// without a TTY or a live environment variable.
///
/// Diverges from Go: Go's `Read` returns `([]byte, error)` where the error may
/// be any type, but the Rust trait returns [`KeystoreError`] so the whole crate
/// speaks one error type. A source's error is wrapped by the loader in
/// [`KeystoreError::PassphraseSource`].
pub trait PassphraseSource {
    /// Returns the passphrase bytes as a plain [`Vec`].
    ///
    /// The loader wraps the buffer in [`zeroize::Zeroizing`] immediately and
    /// scrubs it after decryption. **Other callers must do the same** — the
    /// trait returns a non-zeroizing `Vec` for historical Go parity and so
    /// implementors stay simple; forgetting to re-wrap is a secret-residue
    /// footgun (K2 info). Implementations must not retain a copy after
    /// returning.
    fn read(&self) -> Result<Vec<u8>, KeystoreError>;
}

/// A [`PassphraseSource`] that reads from a named environment variable.
pub struct EnvSource {
    var_name: String,
}

impl EnvSource {
    /// Returns a source that reads `std::env::var(var_name)`. If the variable
    /// is unset or empty, [`PassphraseSource::read`] returns
    /// [`KeystoreError::EnvVarEmpty`] (exit code 2).
    pub fn new(var_name: &str) -> Self {
        EnvSource {
            var_name: var_name.to_string(),
        }
    }
}

impl PassphraseSource for EnvSource {
    fn read(&self) -> Result<Vec<u8>, KeystoreError> {
        // Go uses os.Getenv, which returns "" for both unset and empty; both
        // map to EnvVarEmpty. A non-UTF-8 value (std::env::var Err) is treated
        // the same way — passphrases used here are text.
        match std::env::var(&self.var_name) {
            Ok(val) if !val.is_empty() => Ok(val.into_bytes()),
            _ => Err(KeystoreError::EnvVarEmpty {
                var: self.var_name.clone(),
            }),
        }
    }
}

/// A [`PassphraseSource`] that prompts on a writer and reads the passphrase
/// from `/dev/tty` with terminal echo suppressed.
///
/// The prompt is written to the injected writer (typically stderr); the
/// passphrase itself is read from the controlling terminal via `rpassword`, so
/// it works even when stdin is a pipe.
pub struct TermPromptSource {
    writer: Mutex<Box<dyn Write + Send>>,
    /// Opens the controlling terminal. A field so tests can force the no-TTY
    /// error path without touching the real `/dev/tty`, which is
    /// non-deterministic under test (absent it fails; present it would block on
    /// the password read). Mirrors Go's `openTTY` field.
    open_tty: Box<dyn Fn() -> std::io::Result<File> + Send + Sync>,
}

impl TermPromptSource {
    /// Returns a source that prompts on `writer` and reads the passphrase from
    /// `/dev/tty` with echo suppressed.
    pub fn new<W: Write + Send + 'static>(writer: W) -> Self {
        Self::with_opener(writer, open_controlling_tty)
    }

    /// Constructs a source with a custom TTY opener. Used by [`TermPromptSource::new`]
    /// with the real opener and by tests with a fake one.
    fn with_opener<W, F>(writer: W, open_tty: F) -> Self
    where
        W: Write + Send + 'static,
        F: Fn() -> std::io::Result<File> + Send + Sync + 'static,
    {
        TermPromptSource {
            writer: Mutex::new(Box::new(writer)),
            open_tty: Box::new(open_tty),
        }
    }
}

/// Opens the process's controlling terminal for read/write. Mirrors Go's
/// `os.OpenFile("/dev/tty", os.O_RDWR, 0)`.
fn open_controlling_tty() -> std::io::Result<File> {
    OpenOptions::new().read(true).write(true).open("/dev/tty")
}

/// Reads a passphrase from `/dev/tty` with echo suppressed via `rpassword`.
fn read_password_from_tty() -> io::Result<String> {
    // rpassword re-opens /dev/tty itself so it can toggle terminal echo via
    // termios; passing an already-open handle would skip echo suppression.
    // Output is discarded because we print our own prompt above.
    let config = rpassword::ConfigBuilder::new()
        .input_file_path("/dev/tty")
        .output_discard()
        .build();
    rpassword::read_password_with_config(config)
}

impl PassphraseSource for TermPromptSource {
    fn read(&self) -> Result<Vec<u8>, KeystoreError> {
        // Open the controlling terminal first, purely to detect availability
        // (and to give tests an injectable failure seam). Go writes the prompt
        // only after this succeeds, so the no-TTY path emits nothing.
        let tty = (self.open_tty)().map_err(|err| KeystoreError::NoTty {
            detail: err.to_string(),
        })?;
        drop(tty);

        {
            let mut writer = self.writer.lock().expect("prompt writer lock poisoned");
            // Best-effort prompt; a write failure here should not mask a
            // successful password read, matching Go's fire-and-forget Fprint.
            let _ = write!(writer, "Keystore passphrase: ");
            let _ = writer.flush();
        }

        let result = read_password_from_tty();

        // Newline after the (suppressed) input, matching Go's Fprintln(w).
        {
            let mut writer = self.writer.lock().expect("prompt writer lock poisoned");
            let _ = writeln!(writer);
            let _ = writer.flush();
        }

        match result {
            Ok(pw) => Ok(pw.into_bytes()),
            Err(err) => Err(KeystoreError::ReadPassphrase { source: err }),
        }
    }
}

/// Minimum keystore-passphrase length required by keygen (F-7).
///
/// Measured as the UTF-8 **byte** length of the passphrase after EIP-2335
/// normalization (NFKD + strip C0/C1/Delete). Shared by
/// [`NewKeystorePassphrase`] and [`require_min_len`].
pub const KEYSTORE_PASSPHRASE_MIN_LEN: usize = 8;

/// Enforces a minimum passphrase length for the keygen create path.
///
/// Length is measured on the **EIP-2335-normalized** form
/// ([`normalize_passphrase`]: NFKD + strip control codes), so control-character
/// padding cannot satisfy F-7 while yielding a short effective KDF password.
///
/// Applied by keygen to the `--passphrase-file` path after reading via
/// [`EnvSource`]. Never called from `gen`'s decrypt path — short decrypt
/// passphrases remain valid there.
///
/// The returned `got` in [`KeystoreError::PassphraseTooShort`] is the
/// normalized UTF-8 byte length.
pub fn require_min_len(pw: &[u8], min: usize) -> Result<(), KeystoreError> {
    let normalized = normalize_passphrase(pw);
    let got = normalized.len();
    if got < min {
        Err(KeystoreError::PassphraseTooShort { min, got })
    } else {
        Ok(())
    }
}

/// A [`PassphraseSource`] for **creating** a keystore: prompts twice, requires
/// the two entries to match, and enforces a minimum length of
/// [`KEYSTORE_PASSPHRASE_MIN_LEN`] (F-7) on the EIP-2335-normalized form.
///
/// Keygen-only. The single-prompt [`TermPromptSource`] is left untouched for
/// `gen`'s decrypt path, which accepts any non-empty passphrase.
///
/// Intermediate passphrase buffers (confirm copy; both sides on error) are
/// held in [`Zeroizing`] so they are scrubbed on drop (S-1). The returned
/// `Vec` is plain to match [`PassphraseSource`]; callers (keygen encrypt /
/// decrypt loader) must wrap it in `Zeroizing` immediately.
pub struct NewKeystorePassphrase {
    writer: Mutex<Box<dyn Write + Send>>,
    /// Opens the controlling terminal for the no-TTY detection seam (same
    /// pattern as [`TermPromptSource`]).
    open_tty: Box<dyn Fn() -> io::Result<File> + Send + Sync>,
    /// Reads one password line with echo suppressed. Injected so tests can
    /// script two sequential reads without touching a real TTY (`rpassword`
    /// always reopens `/dev/tty` itself).
    read_password: Box<dyn Fn() -> io::Result<String> + Send + Sync>,
}

impl NewKeystorePassphrase {
    /// Returns a source that prompts twice on `writer` and reads both entries
    /// from `/dev/tty` with echo suppressed.
    pub fn new<W: Write + Send + 'static>(writer: W) -> Self {
        Self::with_opener(writer, open_controlling_tty, read_password_from_tty)
    }

    /// Constructs a source with a custom TTY opener and password reader.
    /// Used by [`NewKeystorePassphrase::new`] with the real seams and by tests
    /// with scripted fakes.
    fn with_opener<W, F, R>(writer: W, open_tty: F, read_password: R) -> Self
    where
        W: Write + Send + 'static,
        F: Fn() -> io::Result<File> + Send + Sync + 'static,
        R: Fn() -> io::Result<String> + Send + Sync + 'static,
    {
        NewKeystorePassphrase {
            writer: Mutex::new(Box::new(writer)),
            open_tty: Box::new(open_tty),
            read_password: Box::new(read_password),
        }
    }

    fn prompt_once(&self, label: &str) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
        {
            let mut writer = self.writer.lock().expect("prompt writer lock poisoned");
            let _ = write!(writer, "{label}");
            let _ = writer.flush();
        }

        let result = (self.read_password)();

        {
            let mut writer = self.writer.lock().expect("prompt writer lock poisoned");
            let _ = writeln!(writer);
            let _ = writer.flush();
        }

        match result {
            // Move the String buffer into a Zeroizing Vec so the secret is
            // scrubbed on drop (same allocation; no plain Vec residual).
            Ok(pw) => Ok(Zeroizing::new(pw.into_bytes())),
            Err(err) => Err(KeystoreError::ReadPassphrase { source: err }),
        }
    }
}

impl PassphraseSource for NewKeystorePassphrase {
    fn read(&self) -> Result<Vec<u8>, KeystoreError> {
        // Detect TTY availability first so the no-TTY path emits nothing,
        // matching TermPromptSource / Go.
        let tty = (self.open_tty)().map_err(|err| KeystoreError::NoTty {
            detail: err.to_string(),
        })?;
        drop(tty);

        let mut first = self.prompt_once("Keystore passphrase: ")?;
        let second = self.prompt_once("Confirm keystore passphrase: ")?;

        if first.as_slice() != second.as_slice() {
            // first/second drop via Zeroizing (scrub both sides).
            return Err(KeystoreError::PassphraseMismatch);
        }
        // Confirm copy is scrubbed here; keep only `first`.
        drop(second);

        // F-7 gate on normalized length (control-padded short secrets rejected).
        require_min_len(&first, KEYSTORE_PASSPHRASE_MIN_LEN)?;

        // Move bytes out; the empty Zeroizing residual drops without retaining
        // the secret. Callers (loader / keygen encrypt) wrap the Vec in
        // Zeroizing immediately.
        Ok(std::mem::take(&mut *first))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Arc;

    // Go: TestTermPromptSource_NoTTY
    //
    // Forces the controlling-terminal open to fail and asserts the returned
    // error is tagged NoTty and points the user at the --passphrase-file escape
    // hatch. The opener is injected so the test never touches the real
    // /dev/tty.
    #[test]
    fn term_prompt_source_no_tty() {
        let open_err_msg = "no such device or address";
        let src = TermPromptSource::with_opener(Vec::new(), move || {
            Err(io::Error::new(io::ErrorKind::NotFound, open_err_msg))
        });

        let err = src.read().expect_err("Read() should error with NoTty");
        assert!(
            matches!(err, KeystoreError::NoTty { .. }),
            "Read() error = {err:?}, want NoTty",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("--passphrase-file"),
            "Read() error = {msg:?}, want message naming --passphrase-file",
        );
        // The underlying open error should be surfaced for diagnostics.
        assert!(
            msg.contains(open_err_msg),
            "Read() error = {msg:?}, want it to include the open failure {open_err_msg:?}",
        );
    }

    /// Shared writer so tests can inspect prompts after `read`.
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("shared buf lock").write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Scripted password reader that returns the given entries in order.
    fn scripted_reader(
        passwords: Vec<&'static str>,
    ) -> impl Fn() -> io::Result<String> + Send + Sync + 'static {
        let queue = Mutex::new(
            passwords
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
                .into_iter(),
        );
        move || {
            let mut q = queue.lock().expect("scripted reader lock");
            q.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "no more scripted passwords")
            })
        }
    }

    fn ok_tty() -> io::Result<File> {
        // Any openable path works; the handle is dropped immediately after the
        // availability check and never used for reading.
        File::open("/dev/null")
    }

    fn new_with_scripted(
        passwords: Vec<&'static str>,
    ) -> (NewKeystorePassphrase, Arc<Mutex<Vec<u8>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let src = NewKeystorePassphrase::with_opener(
            SharedBuf(Arc::clone(&buf)),
            ok_tty,
            scripted_reader(passwords),
        );
        (src, buf)
    }

    #[test]
    fn new_keystore_passphrase_match_ok() {
        let (src, buf) = new_with_scripted(vec!["password1", "password1"]);
        let pw = src.read().expect("matching ≥8 entries should succeed");
        assert_eq!(pw, b"password1");

        let prompts = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            prompts.contains("Keystore passphrase: "),
            "first prompt missing: {prompts:?}",
        );
        assert!(
            prompts.contains("Confirm keystore passphrase: "),
            "confirm prompt missing: {prompts:?}",
        );
        // Two prompts: first + confirm.
        assert_eq!(
            prompts.matches("passphrase: ").count(),
            2,
            "want exactly two prompts, got: {prompts:?}",
        );
    }

    #[test]
    fn new_keystore_passphrase_mismatch_err() {
        let (src, _) = new_with_scripted(vec!["password1", "password2"]);
        let err = src.read().expect_err("mismatched entries should error");
        assert!(
            matches!(err, KeystoreError::PassphraseMismatch),
            "Read() error = {err:?}, want PassphraseMismatch",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("do not match"),
            "error message should be clear about mismatch: {msg:?}",
        );
    }

    #[test]
    fn new_keystore_passphrase_too_short_err() {
        // 7 chars, matching — length gate fires after match.
        let (src, _) = new_with_scripted(vec!["short7c", "short7c"]);
        let err = src.read().expect_err("7-char passphrase should error");
        match &err {
            KeystoreError::PassphraseTooShort { min, got } => {
                assert_eq!(*min, 8);
                assert_eq!(*got, 7);
            }
            other => panic!("Read() error = {other:?}, want PassphraseTooShort"),
        }
        let msg = err.to_string();
        assert!(
            msg.contains("at least 8 bytes") && msg.contains("got 7"),
            "PassphraseTooShort must say bytes (not characters): {msg:?}",
        );
    }

    #[test]
    fn new_keystore_passphrase_eight_char_ok() {
        let (src, _) = new_with_scripted(vec!["exactly8", "exactly8"]);
        let pw = src.read().expect("8-char passphrase should succeed");
        assert_eq!(pw, b"exactly8");
        assert_eq!(pw.len(), 8);
    }

    #[test]
    fn new_keystore_passphrase_no_tty() {
        let open_err_msg = "no such device or address";
        let src = NewKeystorePassphrase::with_opener(
            Vec::new(),
            move || Err(io::Error::new(io::ErrorKind::NotFound, open_err_msg)),
            scripted_reader(vec![]),
        );
        let err = src.read().expect_err("Read() should error with NoTty");
        assert!(
            matches!(err, KeystoreError::NoTty { .. }),
            "Read() error = {err:?}, want NoTty",
        );
    }

    #[test]
    fn require_min_len_boundary() {
        assert!(
            require_min_len(b"short7c", 8).is_err(),
            "7 bytes should fail min=8",
        );
        assert!(
            require_min_len(b"exactly8", 8).is_ok(),
            "8 bytes should pass min=8",
        );
        assert!(require_min_len(b"", 8).is_err(), "empty should fail min=8",);
        assert!(
            require_min_len(b"password1", 8).is_ok(),
            "9 bytes should pass min=8",
        );

        let err = require_min_len(b"1234567", 8).unwrap_err();
        match err {
            KeystoreError::PassphraseTooShort { min, got } => {
                assert_eq!(min, 8);
                assert_eq!(got, 7);
            }
            other => panic!("error = {other:?}, want PassphraseTooShort"),
        }
    }

    /// Control-character padding must not satisfy F-7: length is measured after
    /// EIP-2335 normalize (NFKD + strip C0/C1/Delete).
    #[test]
    fn require_min_len_after_normalize() {
        // 7 printable + 1 C0 control → 8 raw bytes, 7 after strip.
        let padded = b"aaaaaaa\x01";
        assert_eq!(padded.len(), 8);
        let err = require_min_len(padded, 8).expect_err("control-padded short must fail");
        match err {
            KeystoreError::PassphraseTooShort { min, got } => {
                assert_eq!(min, 8);
                assert_eq!(got, 7, "got must be normalized length");
            }
            other => panic!("error = {other:?}, want PassphraseTooShort"),
        }

        // Eight NULs normalize to empty.
        assert!(
            require_min_len(&[0u8; 8], 8).is_err(),
            "all-NUL must fail after strip",
        );

        // Control pad that still has ≥8 printable after strip → Ok.
        let long_padded = b"password1\x01";
        assert!(
            require_min_len(long_padded, 8).is_ok(),
            "normalized ≥8 must pass",
        );
    }

    #[test]
    fn new_keystore_passphrase_control_pad_too_short() {
        // Matching entries, 8 raw bytes, 7 after normalize → PassphraseTooShort.
        let (src, _) = new_with_scripted(vec!["aaaaaaa\u{1}", "aaaaaaa\u{1}"]);
        let err = src
            .read()
            .expect_err("control-padded 7-effective should error");
        match &err {
            KeystoreError::PassphraseTooShort { min, got } => {
                assert_eq!(*min, 8);
                assert_eq!(*got, 7);
            }
            other => panic!("Read() error = {other:?}, want PassphraseTooShort"),
        }
    }

    /// TermPromptSource remains single-prompt for `gen`'s decrypt path: only
    /// one "Keystore passphrase: " is written, never a confirm. Production path
    /// uses shared `read_password_from_tty` (behavior unchanged; still single
    /// prompt). The read may block on a real TTY — run it on a background
    /// thread with a short timeout and assert on the writer, which is updated
    /// *before* the password read.
    #[test]
    fn term_prompt_source_prompts_once() {
        use std::sync::mpsc;
        use std::time::Duration;

        let buf = Arc::new(Mutex::new(Vec::new()));
        let src = TermPromptSource::with_opener(SharedBuf(Arc::clone(&buf)), ok_tty);

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = src.read();
            let _ = tx.send(());
        });
        // Prompt is written before rpassword; give the thread a moment, then
        // assert. Timed recv keeps the suite from hanging on an interactive TTY.
        let _ = rx.recv_timeout(Duration::from_millis(300));

        let prompts = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert_eq!(
            prompts.matches("Keystore passphrase: ").count(),
            1,
            "TermPromptSource must prompt exactly once, got: {prompts:?}",
        );
        assert!(
            !prompts.contains("Confirm"),
            "TermPromptSource must not confirm, got: {prompts:?}",
        );
    }
}
