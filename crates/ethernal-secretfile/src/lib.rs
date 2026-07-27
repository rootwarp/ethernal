//! Secret-file read primitive shared by passphrase and private-key file flags.
//!
//! Architecture §2: one fixed-buffer, TOCTOU-free open+fstat path that every
//! entry point shares. Public readers (`read_secret_line` / `read_secret_trimmed`)
//! arrive in F1-2; this crate currently exports only the types and keeps the
//! raw capped reader private so no consumer can bypass a byte rule.

use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;

use zeroize::Zeroizing;

/// FR-16. The read buffer is one byte larger; the extra byte is the overflow sentinel.
pub const MAX_SECRET_FILE_BYTES: usize = 4096;

/// What FR-9 found after FR-8 stripped one trailing `\n`. A shape or a count,
/// never content (M-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Residual {
    /// A `\r` anywhere: `pw\r`, `pw\r\n`, `pw\r\r\n`.
    CarriageReturn,
    /// Two or more lines.
    MultiLine { lines: usize },
}

/// Typed failures from the secret-file policy. Every variant names the path and
/// never the secret bytes (M-3).
#[derive(Debug, thiserror::Error)]
pub enum SecretFileError {
    /// Path does not exist (classified from the open error).
    #[error("secret file not found: {path}")]
    NotFound {
        /// Path that was requested.
        path: String,
    },

    /// Open was refused by the OS (classified from the open error).
    #[error("permission denied reading secret file: {path}")]
    PermissionDenied {
        /// Path that was requested.
        path: String,
    },

    /// Path resolves to a directory (FR-14).
    #[error("secret file path is a directory: {path}")]
    IsDirectory {
        /// Path that was requested.
        path: String,
    },

    /// Content exceeds [`MAX_SECRET_FILE_BYTES`] (FR-16).
    #[error("secret file exceeds maximum size of {max} bytes: {path}")]
    TooLarge {
        /// Path that was requested.
        path: String,
        /// The enforced ceiling.
        max: usize,
    },

    /// Bytes are not valid UTF-8 (returned by F1-2 entry points).
    #[error("secret file is not valid UTF-8: {path}")]
    NotUtf8 {
        /// Path that was requested.
        path: String,
    },

    /// Residual line terminator after the passphrase byte rule (F1-2).
    #[error("secret file has unexpected line terminator: {path}")]
    LineTerminator {
        /// Path that was requested.
        path: String,
        /// Shape of the residual terminator (never content).
        found: Residual,
    },

    /// Any other I/O failure while opening or reading.
    #[error("error reading secret file {path}: {source}")]
    Io {
        /// Path that was requested.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

// Private helpers are exercised by unit tests; public entry points (F1-2) will
// call `read_capped`. Until then, silence dead_code on non-test lib builds.
#[allow(dead_code)]
fn path_string(path: &Path) -> String {
    path.display().to_string()
}

#[allow(dead_code)]
fn classify_open(path: &Path, e: io::Error) -> SecretFileError {
    let p = path_string(path);
    match e.kind() {
        ErrorKind::NotFound => SecretFileError::NotFound { path: p },
        ErrorKind::PermissionDenied => SecretFileError::PermissionDenied { path: p },
        _ => SecretFileError::Io { path: p, source: e },
    }
}

/// Shared open → fstat → warn → fixed-buffer read body (architecture §2.3).
///
/// Private so no consumer can bypass a byte rule. Follows symlinks (FR-15);
/// rejects directories (FR-14); warns on loose regular-file modes (FR-17);
/// enforces the 4 KiB ceiling via a read cap (FR-16, FR-23).
#[allow(dead_code)] // public readers in F1-2; unit tests call this directly today
fn read_capped(
    path: &Path,
    warn_out: &mut dyn Write,
) -> Result<Zeroizing<Vec<u8>>, SecretFileError> {
    // Follows symlinks (FR-15) — every file in a Kubernetes projected Secret
    // volume is one. NotFound / PermissionDenied are classified from the open
    // error; everything else is Io.
    let mut f = File::open(path).map_err(|e| classify_open(path, e))?;

    // fstat on the open descriptor, following OpenSSH authfile.c:82-87: the mode
    // checked, the type checked and the bytes read are the same inode (FR-15).
    let md = f.metadata().map_err(|e| SecretFileError::Io {
        path: path_string(path),
        source: e,
    })?;

    // FR-14. Measured: File::open("/tmp") SUCCEEDS; without this the failure
    // surfaces at the first read as "Is a directory (os error 21)" from a code
    // path that looks like a read failure (R4 M-b).
    if md.is_dir() {
        return Err(SecretFileError::IsDirectory {
            path: path_string(path),
        });
    }

    let ft = md.file_type();
    // Early, better-worded rejection for regular files ONLY. Never the
    // enforcement, never an allocation size: /dev/zero reports len()==0 (R4 M-a)
    // and a pipe reports an arbitrary snapshot of buffered bytes — 0 on Linux,
    // measured 9 for a 9-byte payload on macOS (R4 §3).
    if ft.is_file() && md.len() > MAX_SECRET_FILE_BYTES as u64 {
        return Err(SecretFileError::TooLarge {
            path: path_string(path),
            max: MAX_SECRET_FILE_BYTES,
        });
    }

    // FR-17. "Regular file" is load-bearing, not cosmetic: a <(...) pipe is mode
    // 0440 (R4 M-e), so without it the recommended no-disk-file pattern would
    // warn on every run and collide with FR-21.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if ft.is_file() && md.permissions().mode() & 0o077 != 0 {
            let _ = writeln!(
                warn_out,
                "WARNING: file permissions {:04o} for {:?} are too open; \
                 the secret is readable by group or other. Fix with: chmod 600 {:?}",
                md.permissions().mode() & 0o7777,
                path,
                path
            );
        }
    }

    // ONE allocation, never grown, never reallocated (FR-23). zeroize 1.9.0's own
    // doc comment: "Ensures the entire capacity of the Vec is zeroed. Cannot
    // ensure that previous reallocations did not leave values on the heap."
    let mut buf = Zeroizing::new(vec![0u8; MAX_SECRET_FILE_BYTES + 1]);
    let mut n = 0usize;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(SecretFileError::Io {
                    path: path_string(path),
                    source: e,
                });
            } // buf drops zeroized
        }
    }
    // The read cap. This — not the stat check — is what stops /dev/zero.
    if n > MAX_SECRET_FILE_BYTES {
        return Err(SecretFileError::TooLarge {
            path: path_string(path),
            max: MAX_SECRET_FILE_BYTES,
        });
    }

    buf.truncate(n); // safe: zeroize covers spare capacity (R2 §3.1)
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Unique temp directory cleaned up on drop (no tempfile dependency).
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "ethernal-secretfile-{label}-{}-{nanos}-{n}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            TempDir { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write_file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let p = self.path.join(name);
            fs::write(&p, bytes).expect("write temp file");
            p
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn warn_text(sink: &[u8]) -> String {
        String::from_utf8_lossy(sink).into_owned()
    }

    #[test]
    fn directory_is_directory_not_io() {
        let dir = TempDir::new("dir");
        let mut sink = Vec::new();
        let err = read_capped(dir.path(), &mut sink).expect_err("dir must fail");
        assert!(
            matches!(err, SecretFileError::IsDirectory { .. }),
            "expected IsDirectory, got {err:?}"
        );
        assert!(err.to_string().contains(&dir.path().display().to_string()));
    }

    #[test]
    fn nonexistent_is_not_found() {
        let dir = TempDir::new("missing");
        let path = dir.path().join("no-such-file");
        let mut sink = Vec::new();
        let err = read_capped(&path, &mut sink).expect_err("missing must fail");
        assert!(
            matches!(err, SecretFileError::NotFound { .. }),
            "expected NotFound, got {err:?}"
        );
    }

    /// Mode 0000 → PermissionDenied. Does not hold when the suite runs as root
    /// (root bypasses discretionary access control); skip in that case.
    #[cfg(unix)]
    #[test]
    fn mode_0000_is_permission_denied() {
        use std::os::unix::fs::PermissionsExt;

        // SAFETY: getuid has no preconditions and is always safe to call.
        if unsafe { libc_getuid() } == 0 {
            // Running as root; chmod 000 has no effect on open. Skip.
            return;
        }

        let dir = TempDir::new("mode0000");
        let path = dir.write_file("secret", b"secret");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

        let mut sink = Vec::new();
        let err = read_capped(&path, &mut sink).expect_err("mode 0000 must fail");
        assert!(
            matches!(err, SecretFileError::PermissionDenied { .. }),
            "expected PermissionDenied, got {err:?}"
        );

        // Restore so TempDir can clean up.
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }

    #[test]
    fn exactly_max_bytes_succeeds() {
        let dir = TempDir::new("max-ok");
        let bytes = vec![b'a'; MAX_SECRET_FILE_BYTES];
        let path = dir.write_file("ok", &bytes);
        let mut sink = Vec::new();
        let got = read_capped(&path, &mut sink).expect("4096-byte file must succeed");
        assert_eq!(got.len(), MAX_SECRET_FILE_BYTES);
        assert_eq!(&got[..], &bytes[..]);
    }

    #[test]
    fn max_plus_one_is_too_large() {
        let dir = TempDir::new("max-over");
        let bytes = vec![b'b'; MAX_SECRET_FILE_BYTES + 1];
        let path = dir.write_file("over", &bytes);
        let mut sink = Vec::new();
        let err = read_capped(&path, &mut sink).expect_err("4097-byte file must fail");
        match err {
            SecretFileError::TooLarge { max, .. } => {
                assert_eq!(max, MAX_SECRET_FILE_BYTES);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    /// Symlink is followed; the *target's* mode is what FR-17 checks (FR-15,
    /// Kubernetes projected-Secret shape).
    #[cfg(unix)]
    #[test]
    fn symlink_follows_and_checks_target_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("symlink");
        let target = dir.write_file("target", b"via-link");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let mut sink = Vec::new();
        let got = read_capped(&link, &mut sink).expect("read via symlink");
        assert_eq!(&got[..], b"via-link");

        let text = warn_text(&sink);
        assert!(
            text.contains("file permissions") && text.contains("0644"),
            "target mode 0644 must warn through symlink, got: {text:?}"
        );

        // Tight target mode → no warning, even when path is a symlink.
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let mut sink2 = Vec::new();
        let _ = read_capped(&link, &mut sink2).expect("read via symlink 0600");
        assert!(
            sink2.is_empty(),
            "0600 target must not warn, got: {:?}",
            warn_text(&sink2)
        );
    }

    /// `/dev/zero` reports `len() == 0`, so this must hit the *read* cap.
    /// If the ceiling is ever made stat-based only, this test will fail
    /// (R4 M-a) — that is intentional.
    #[cfg(unix)]
    #[test]
    fn dev_zero_is_too_large_via_read_cap() {
        let path = Path::new("/dev/zero");
        let mut sink = Vec::new();
        let err = read_capped(path, &mut sink).expect_err("/dev/zero must hit read cap");
        match err {
            SecretFileError::TooLarge { max, .. } => {
                assert_eq!(max, MAX_SECRET_FILE_BYTES);
            }
            other => panic!("expected TooLarge via read cap, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn warn_0644_once_0600_none() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("warn");
        let loose = dir.write_file("loose", b"pw");
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();

        let mut sink = Vec::new();
        let _ = read_capped(&loose, &mut sink).expect("read 0644");
        let text = warn_text(&sink);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1, "exactly one warning line, got: {text:?}");
        assert!(
            text.contains("file permissions") && text.contains("0644"),
            "warning must name file permissions and 0644, got: {text:?}"
        );

        let tight = dir.write_file("tight", b"pw");
        fs::set_permissions(&tight, fs::Permissions::from_mode(0o600)).unwrap();
        let mut sink2 = Vec::new();
        let _ = read_capped(&tight, &mut sink2).expect("read 0600");
        assert!(
            sink2.is_empty(),
            "0600 must emit no warning, got: {:?}",
            warn_text(&sink2)
        );
    }

    /// Mode-0440 FIFO must not warn (R4 M-e): FR-17 is regular-file-scoped so
    /// the recommended `<(...)` process-substitution pattern stays quiet.
    ///
    /// Race-free setup: `std::io::pipe` + `/dev/fd/N` is the measured
    /// process-substitution shape (FIFO, mode 0440). Write and close the write
    /// end while holding the read end open so the payload stays buffered; then
    /// `read_capped` re-opens via `/dev/fd/N` and sees the 0440 non-regular
    /// inode. No sleep, no `mkfifo` open-order race.
    #[cfg(unix)]
    #[test]
    fn fifo_0440_emits_no_warning() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::io::AsRawFd;

        let (reader, mut writer) = std::io::pipe().expect("pipe");
        writer.write_all(b"secret").expect("write pipe");
        drop(writer); // EOF for the eventual reader; keep `reader` alive

        let path = format!("/dev/fd/{}", reader.as_raw_fd());
        // Pin the R4 M-e shape: not a regular file, mode 0440.
        let md = fs::metadata(&path).expect("stat /dev/fd");
        assert!(
            !md.file_type().is_file(),
            "/dev/fd pipe must not report as regular file"
        );
        assert_eq!(
            md.permissions().mode() & 0o777,
            0o440,
            "expected process-substitution mode 0440"
        );

        let mut sink = Vec::new();
        let got = read_capped(Path::new(&path), &mut sink).expect("read pipe");
        assert_eq!(&got[..], b"secret");
        assert!(
            sink.is_empty(),
            "mode-0440 FIFO must emit no FR-17 warning, got: {:?}",
            warn_text(&sink)
        );
        // `reader` dropped here — keeps /dev/fd/N valid through the read.
        drop(reader);
    }

    #[test]
    fn empty_file_succeeds() {
        let dir = TempDir::new("empty");
        let path = dir.write_file("empty", b"");
        let mut sink = Vec::new();
        let got = read_capped(&path, &mut sink).expect("empty file must succeed");
        assert!(
            got.is_empty(),
            "expected empty buffer, got len {}",
            got.len()
        );
    }

    #[test]
    fn small_file_round_trip() {
        let dir = TempDir::new("small");
        let path = dir.write_file("pw", b"hello\n");
        let mut sink = Vec::new();
        let got = read_capped(&path, &mut sink).expect("read small");
        assert_eq!(&got[..], b"hello\n");
    }

    // Minimal getuid shim so the mode-0000 test can skip under root without
    // adding a `libc` dependency to this crate.
    #[cfg(unix)]
    extern "C" {
        #[link_name = "getuid"]
        fn libc_getuid() -> u32;
    }
}
