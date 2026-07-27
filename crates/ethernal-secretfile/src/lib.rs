//! Secret-file read primitive shared by passphrase and private-key file flags.
//!
//! Architecture §2: one fixed-buffer, TOCTOU-free open+fstat path that every
//! entry point shares. Public readers apply a byte rule on top of the private
//! capped reader so no consumer can bypass FR-7 / FR-8 / FR-9.

use std::fmt;
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

impl fmt::Display for Residual {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // FR-9: name the shape ("carriage return") or a line count — never content.
            Residual::CarriageReturn => f.write_str("carriage return"),
            Residual::MultiLine { lines } => write!(f, "{lines} lines"),
        }
    }
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
    /// FR-9: names the path and what was found (shape/count via `{found}`), never content.
    #[error("secret file has unexpected line terminator ({found}): {path}")]
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

fn path_string(path: &Path) -> String {
    path.display().to_string()
}

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

/// UTF-8 without residue (architecture §2.3).
///
/// Borrow-validate first, then move only on success. `String::from_utf8` on
/// failure would own a plain `Vec<u8>` and drop it un-zeroized.
fn into_utf8_string(
    path: &Path,
    mut buf: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<String>, SecretFileError> {
    std::str::from_utf8(&buf).map_err(|_| SecretFileError::NotUtf8 {
        path: path_string(path),
    })?;
    let owned = std::mem::take(&mut *buf);
    Ok(Zeroizing::new(
        String::from_utf8(owned).expect("validated on the line above"),
    ))
}

/// Reads a one-line secret under the full file policy (FR-13…FR-17, FR-23) and
/// applies the **passphrase** byte rule: strip exactly one trailing `\n` (FR-8),
/// then reject any residual `\r` or `\n` (FR-9). Validates UTF-8 (FR-12b, D-3).
///
/// An empty file yields an empty string. Whether empty is an error is the
/// caller's policy (FR-18) and is deliberately not decided here.
pub fn read_secret_line(
    path: &Path,
    warn_out: &mut dyn Write,
) -> Result<Zeroizing<String>, SecretFileError> {
    let buf = read_capped(path, warn_out)?;
    let mut s = into_utf8_string(path, buf)?;

    // FR-8: strip exactly one trailing `\n`, and nothing else. Re-slice in place.
    if s.ends_with('\n') {
        s.pop();
    }

    // FR-9: residual `\r` first, then residual `\n` (multi-line).
    if s.contains('\r') {
        return Err(SecretFileError::LineTerminator {
            path: path_string(path),
            found: Residual::CarriageReturn,
        });
    }
    if s.contains('\n') {
        return Err(SecretFileError::LineTerminator {
            path: path_string(path),
            found: Residual::MultiLine {
                lines: s.matches('\n').count() + 1,
            },
        });
    }

    Ok(s)
}

/// Same file policy, but the **hex-key** byte rule (FR-7): all leading and
/// trailing ASCII whitespace trimmed. A separate entry point rather than a flag,
/// so the divergence from [`read_secret_line`] is visible at every call site and
/// cannot be selected by accident.
pub fn read_secret_trimmed(
    path: &Path,
    warn_out: &mut dyn Write,
) -> Result<Zeroizing<String>, SecretFileError> {
    let buf = read_capped(path, warn_out)?;
    let mut s = into_utf8_string(path, buf)?;

    // FR-7: re-slice in place — no intermediate allocation.
    // Closure form: char::is_ascii_whitespace takes &self, not fn(char)->bool.
    let start = s.len()
        - s.trim_start_matches(|c: char| c.is_ascii_whitespace())
            .len();
    let end = s.trim_end_matches(|c: char| c.is_ascii_whitespace()).len();
    s.truncate(end);
    if start > 0 {
        let drain_end = start.min(s.len());
        drop(s.drain(..drain_end));
    }

    Ok(s)
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

    // --- F1-2: byte rules, UTF-8 boundary, Display (M-3) ---

    fn read_line(path: &Path) -> Result<Zeroizing<String>, SecretFileError> {
        let mut sink = Vec::new();
        read_secret_line(path, &mut sink)
    }

    fn read_trimmed(path: &Path) -> Result<Zeroizing<String>, SecretFileError> {
        let mut sink = Vec::new();
        read_secret_trimmed(path, &mut sink)
    }

    /// FR-8 then FR-9 matrix: strip one trailing `\n`, keep trailing space,
    /// reject every CR shape and multi-line residual.
    #[test]
    fn read_secret_line_byte_rule_matrix() {
        let dir = TempDir::new("line-rule");

        let pw = dir.write_file("pw", b"pw");
        let pw_nl = dir.write_file("pw_nl", b"pw\n");
        assert_eq!(read_line(&pw).unwrap().as_str(), "pw");
        assert_eq!(read_line(&pw_nl).unwrap().as_str(), "pw");
        assert_eq!(
            read_line(&pw).unwrap().as_str(),
            read_line(&pw_nl).unwrap().as_str(),
            "pw and pw\\n must yield identical secrets"
        );

        // Trailing space/tab is kept (FR-11 claim as a test, not a comment).
        let pw_sp_nl = dir.write_file("pw_sp_nl", b"pw \n");
        assert_eq!(
            read_line(&pw_sp_nl).unwrap().as_str(),
            "pw ",
            "trailing space must be kept"
        );
        let pw_tab_nl = dir.write_file("pw_tab_nl", b"pw\t\n");
        assert_eq!(
            read_line(&pw_tab_nl).unwrap().as_str(),
            "pw\t",
            "trailing tab must be kept"
        );

        for (name, bytes) in [
            ("cr", &b"pw\r"[..]),
            ("crlf", &b"pw\r\n"[..]),
            ("crcrlf", &b"pw\r\r\n"[..]),
        ] {
            let path = dir.write_file(name, bytes);
            let err = read_line(&path).expect_err("CR shape must fail");
            match &err {
                SecretFileError::LineTerminator {
                    found: Residual::CarriageReturn,
                    ..
                } => {
                    let rendered = err.to_string();
                    assert!(
                        rendered.contains("carriage return"),
                        "{name}: Display must name residual shape, got {rendered:?}"
                    );
                    assert!(
                        rendered.contains(&path.display().to_string()),
                        "{name}: Display must name path, got {rendered:?}"
                    );
                }
                other => panic!("{name}: expected CarriageReturn, got {other:?}"),
            }
        }

        let multi = dir.write_file("multi", b"a\nb");
        let err = read_line(&multi).expect_err("multi-line must fail");
        match &err {
            SecretFileError::LineTerminator {
                found: Residual::MultiLine { lines: 2 },
                ..
            } => {
                let rendered = err.to_string();
                assert!(
                    rendered.contains("2 lines"),
                    "Display must name line count, got {rendered:?}"
                );
                assert!(
                    rendered.contains(&multi.display().to_string()),
                    "Display must name path, got {rendered:?}"
                );
            }
            other => panic!("expected MultiLine {{ lines: 2 }}, got {other:?}"),
        }

        let empty = dir.write_file("empty", b"");
        assert_eq!(read_line(&empty).unwrap().as_str(), "");

        let lone_nl = dir.write_file("lone_nl", b"\n");
        assert_eq!(read_line(&lone_nl).unwrap().as_str(), "");
    }

    /// FR-7: leading/trailing ASCII whitespace removed; interior untouched.
    #[test]
    fn read_secret_trimmed_whitespace() {
        let dir = TempDir::new("trim-rule");
        let hex = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let padded = format!(" {hex} \n");
        let bare_path = dir.write_file("bare", hex.as_bytes());
        let pad_path = dir.write_file("padded", padded.as_bytes());

        let bare = read_trimmed(&bare_path).unwrap();
        let pad = read_trimmed(&pad_path).unwrap();
        assert_eq!(bare.as_str(), hex);
        assert_eq!(pad.as_str(), hex);
        assert_eq!(
            bare.as_str(),
            pad.as_str(),
            "\" 0x… \\n\" and \"0x…\" must yield the same string"
        );

        // Interior whitespace is not touched.
        let interior = dir.write_file("interior", b"ab cd\n");
        assert_eq!(read_trimmed(&interior).unwrap().as_str(), "ab cd");
    }

    /// Non-UTF-8 bytes → NotUtf8 from both entry points (FR-12b / D-3).
    #[test]
    fn non_utf8_is_not_utf8_from_both() {
        let dir = TempDir::new("not-utf8");
        // Distinctive invalid sequence; must not appear in error Display (M-3).
        let path = dir.write_file("bad", b"secret\xffpayload");

        let err_line = read_line(&path).expect_err("line: non-utf8");
        assert!(
            matches!(err_line, SecretFileError::NotUtf8 { .. }),
            "expected NotUtf8 from read_secret_line, got {err_line:?}"
        );

        let err_trim = read_trimmed(&path).expect_err("trim: non-utf8");
        assert!(
            matches!(err_trim, SecretFileError::NotUtf8 { .. }),
            "expected NotUtf8 from read_secret_trimmed, got {err_trim:?}"
        );
    }

    /// All seven SecretFileError variants Display the path and no content (M-3).
    /// FR-9 residual phrases must appear for LineTerminator shapes.
    #[test]
    fn all_error_variants_display_path_not_content() {
        let sentinel = "SENTINEL_SECRET_BYTES_9f3a";
        let path_label = "/tmp/ethernal-secretfile-display-check";
        // Io source is an OS message, not file content — keep it distinct so the
        // file-byte sentinel assertion below is meaningful for every variant.
        let io_source_msg = "disk full";

        let variants: [SecretFileError; 7] = [
            SecretFileError::NotFound {
                path: path_label.into(),
            },
            SecretFileError::PermissionDenied {
                path: path_label.into(),
            },
            SecretFileError::IsDirectory {
                path: path_label.into(),
            },
            SecretFileError::TooLarge {
                path: path_label.into(),
                max: MAX_SECRET_FILE_BYTES,
            },
            SecretFileError::NotUtf8 {
                path: path_label.into(),
            },
            SecretFileError::LineTerminator {
                path: path_label.into(),
                found: Residual::CarriageReturn,
            },
            SecretFileError::Io {
                path: path_label.into(),
                source: io::Error::other(io_source_msg),
            },
        ];

        for err in &variants {
            let rendered = err.to_string();
            assert!(
                rendered.contains(path_label),
                "Display must name the path, got: {rendered:?}"
            );
            // Constructed variants never hold file content; sentinel must not
            // appear (would only show up if a template interpolated secret bytes).
            assert!(
                !rendered.contains(sentinel),
                "Display must not contain file-byte sentinel, got: {rendered:?}"
            );
        }

        // FR-9 residual shape on the constructed CR variant.
        let cr_display = variants[5].to_string();
        assert!(
            cr_display.contains("carriage return"),
            "LineTerminator Display must name carriage return, got: {cr_display:?}"
        );

        // MultiLine residual: line count in Display, path present, no content.
        let multi = SecretFileError::LineTerminator {
            path: path_label.into(),
            found: Residual::MultiLine { lines: 2 },
        };
        let multi_display = multi.to_string();
        assert!(
            multi_display.contains(path_label) && multi_display.contains("2 lines"),
            "MultiLine Display must name path and line count, got: {multi_display:?}"
        );
        assert!(
            !multi_display.contains(sentinel),
            "MultiLine Display must not leak content, got: {multi_display:?}"
        );

        // Live paths: real file with distinctive bytes → Display names path +
        // residual shape, never the file-byte sentinel.
        let dir = TempDir::new("display-live");

        let cr_path = dir.write_file("cr", format!("{sentinel}\r").as_bytes());
        let err = read_line(&cr_path).expect_err("CR");
        let rendered = err.to_string();
        assert!(
            rendered.contains(&cr_path.display().to_string())
                && rendered.contains("carriage return"),
            "live CR must name path and residual, got: {rendered:?}"
        );
        assert!(
            !rendered.contains(sentinel),
            "live CR must not leak content, got: {rendered:?}"
        );

        let multi_path = dir.write_file("multi", format!("{sentinel}\nmore").as_bytes());
        let err = read_line(&multi_path).expect_err("multi-line");
        let rendered = err.to_string();
        assert!(
            rendered.contains(&multi_path.display().to_string()) && rendered.contains("2 lines"),
            "live MultiLine must name path and line count, got: {rendered:?}"
        );
        assert!(
            !rendered.contains(sentinel),
            "live MultiLine must not leak content, got: {rendered:?}"
        );

        // Distinctive ASCII prefix + invalid UTF-8 byte; Display must not echo the prefix.
        let bad_path = dir.write_file("bad", b"SENTINEL_SECRET_BYTES_9f3a\xff");
        let err = read_line(&bad_path).expect_err("not utf8");
        let rendered = err.to_string();
        assert!(
            rendered.contains(&bad_path.display().to_string()),
            "live NotUtf8 must name path, got: {rendered:?}"
        );
        assert!(
            !rendered.contains(sentinel),
            "live NotUtf8 must not leak content, got: {rendered:?}"
        );
    }

    // Minimal getuid shim so the mode-0000 test can skip under root without
    // adding a `libc` dependency to this crate.
    #[cfg(unix)]
    extern "C" {
        #[link_name = "getuid"]
        fn libc_getuid() -> u32;
    }
}
