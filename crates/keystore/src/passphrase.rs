//! Passphrase sources: a named environment variable and an interactive
//! terminal prompt.
//!
//! Ported from `go/internal/keystore/passphrase.go`. The trait abstracts where
//! the passphrase comes from so the loader can be tested without a TTY or a
//! live environment variable.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;

use crate::error::KeystoreError;

/// Abstracts where the passphrase comes from so the loader can be exercised
/// without a TTY or a live environment variable.
///
/// Diverges from Go: Go's `Read` returns `([]byte, error)` where the error may
/// be any type, but the Rust trait returns [`KeystoreError`] so the whole crate
/// speaks one error type. A source's error is wrapped by the loader in
/// [`KeystoreError::PassphraseSource`].
pub trait PassphraseSource {
    /// Returns the passphrase bytes. The loader zeroizes the returned buffer
    /// immediately after decryption; implementations must not retain it.
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

        // rpassword re-opens /dev/tty itself so it can toggle terminal echo via
        // termios; passing an already-open handle would skip echo suppression.
        // Output is discarded because we print our own prompt above.
        let config = rpassword::ConfigBuilder::new()
            .input_file_path("/dev/tty")
            .output_discard()
            .build();
        let result = rpassword::read_password_with_config(config);

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    // Go: TestTermPromptSource_NoTTY
    //
    // Forces the controlling-terminal open to fail and asserts the returned
    // error is tagged NoTty and points the user at the --passphrase-env escape
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
            msg.contains("--passphrase-env"),
            "Read() error = {msg:?}, want message naming --passphrase-env",
        );
        // The underlying open error should be surfaced for diagnostics.
        assert!(
            msg.contains(open_err_msg),
            "Read() error = {msg:?}, want it to include the open failure {open_err_msg:?}",
        );
    }
}
