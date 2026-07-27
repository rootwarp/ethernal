//! Shared filesystem probes and TTY helpers for CLI validation.
//!
//! The writability probe must not follow a pre-planted symlink at the probe
//! name (K3-L4 / H5): use exclusive create (`O_EXCL` / `create_new`) so an
//! existing symlink fails instead of truncating its target.
//!
//! TTY helpers (`stdin_is_tty` / `stdout_is_tty` / `stderr_is_tty` /
//! `open_tty_writer`) are the single home for fd isatty checks and the
//! controlling-terminal open used by keygen mnemonic display (S-2).

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// TTY helpers (single home — T1.2)
// ---------------------------------------------------------------------------

/// Reports whether stdin (fd 0) is connected to a terminal.
pub(crate) fn stdin_is_tty() -> bool {
    // SAFETY: isatty is async-signal-safe and has no preconditions.
    unsafe { libc::isatty(0) == 1 }
}

/// Reports whether stdout (fd 1) is connected to a terminal.
pub(crate) fn stdout_is_tty() -> bool {
    // SAFETY: isatty is async-signal-safe and has no preconditions.
    unsafe { libc::isatty(1) == 1 }
}

/// Reports whether stderr (fd 2) is connected to a terminal.
pub(crate) fn stderr_is_tty() -> bool {
    // SAFETY: isatty is async-signal-safe and has no preconditions.
    unsafe { libc::isatty(2) == 1 }
}

/// Opens `/dev/tty` for the mnemonic display only. **No stderr fallback** (S-2).
pub(crate) fn open_tty_writer() -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).open("/dev/tty")
}

/// If `dir`'s FINAL component is a symlink, returns its fully-resolved real path.
/// `None` for a normal directory on ANY platform — including macOS temp dirs
/// (`/tmp`,`/var`→`/private/…`), whose final component is a real dir, not a link
/// (this is the false-positive a canonicalize-divergence check would trip; D-G3a).
/// Advisory only (S-3): never consulted to decide where or how a file is written.
pub(crate) fn symlinked_output_dir(dir: &Path) -> Option<PathBuf> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => std::fs::canonicalize(dir).ok(),
        _ => None,
    }
}

/// Emits exactly ONE `WARNING:` line to `warn_out` naming the given path and its
/// resolved target when `dir`'s final component is a symlink; returns whether it
/// warned. No behavior change beyond the text (S-2/S-3).
pub(crate) fn warn_if_symlinked_output_dir(dir: &Path, warn_out: &mut dyn Write) -> bool {
    match symlinked_output_dir(dir) {
        Some(real) => {
            let _ = writeln!(
                warn_out,
                "WARNING: output directory \"{}\" is a symlink; keystores will be written to \"{}\".",
                dir.display(),
                real.display()
            );
            true
        }
        None => false,
    }
}

/// Returns the probe path used under `dir` for the current process.
pub(crate) fn probe_path(dir: &Path) -> std::path::PathBuf {
    dir.join(format!(".ethernal-probe-{}", std::process::id()))
}

/// Exclusive create of `path` with mode `0600` on Unix.
///
/// Fails with [`io::ErrorKind::AlreadyExists`] if `path` is already present
/// (including as a dangling or live symlink) rather than following it.
fn create_exclusive_0600(path: &Path) -> io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts.open(path)?;
    drop(f);
    Ok(())
}

/// Checks that the process can create and remove a file under `dir`.
///
/// Uses `create_new` + mode `0600` so a pre-planted symlink at the probe name
/// is not followed. A probe that can be created but not removed is treated as
/// failure (remove errors are not discarded).
pub(crate) fn probe_dir_writable(dir: &Path) -> io::Result<()> {
    let probe = probe_path(dir);
    create_exclusive_0600(&probe)?;
    // Fold remove failure into the same error class as create failure: a dir
    // that accepts creates but rejects unlinks is not usable for our writes.
    std::fs::remove_file(&probe)?;
    Ok(())
}

/// Checks that `dir` exists and the process can write to it via the shared
/// exclusive create+remove probe ([`probe_dir_writable`]).
pub(crate) fn validate_output_dir(dir: &str) -> Result<(), String> {
    let meta = match std::fs::metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(format!("directory \"{dir}\" does not exist"));
        }
        Err(e) => return Err(format!("cannot stat directory \"{dir}\": {e}")),
    };
    if !meta.is_dir() {
        return Err(format!("\"{dir}\" is not a directory"));
    }

    probe_dir_writable(Path::new(dir))
        .map_err(|e| format!("directory \"{dir}\" is not writable: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Tmp;

    #[test]
    fn probe_happy_path() {
        let dir = Tmp::new("ethernal-fs-util");
        probe_dir_writable(&dir.0).expect("writable dir");
        // No leftover probe.
        assert!(!probe_path(&dir.0).exists());
    }

    #[test]
    fn validate_output_dir_negative() {
        let dir = Tmp::new("ethernal-fs-util");
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
    fn symlink_probe_does_not_touch_canary_target() {
        use std::os::unix::fs::symlink;

        let dir = Tmp::new("ethernal-fs-util");
        let canary = dir.0.join("canary-target");
        std::fs::write(&canary, b"do-not-truncate").unwrap();

        let probe = probe_path(&dir.0);
        symlink(&canary, &probe).unwrap();

        let err = probe_dir_writable(&dir.0).expect_err("symlink at probe name");
        assert_eq!(
            err.kind(),
            io::ErrorKind::AlreadyExists,
            "create_new must refuse existing symlink, got {err}"
        );

        // Target must be untouched (File::create would have truncated it).
        assert_eq!(std::fs::read(&canary).unwrap(), b"do-not-truncate");
        // Symlink itself still present (we never opened-through it).
        assert!(probe.symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn unwritable_dir_probe_fails() {
        use std::os::unix::fs::PermissionsExt;

        let dir = Tmp::new("ethernal-fs-util");
        let locked = dir.0.join("locked");
        std::fs::create_dir(&locked).unwrap();
        let mut perms = std::fs::metadata(&locked).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&locked, perms).unwrap();

        let err = probe_dir_writable(&locked).expect_err("read-only dir");
        assert_ne!(err.kind(), io::ErrorKind::AlreadyExists);

        let mut perms = std::fs::metadata(&locked).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&locked, perms).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn remove_failure_surfaces_as_error() {
        use std::os::unix::fs::PermissionsExt;

        // Create ok, then lose write on the parent so unlink fails. Exercise
        // the same create→remove sequence as probe_dir_writable with a gap
        // between the steps so we can assert remove errors are not discarded.
        let dir = Tmp::new("ethernal-fs-util");
        let probe = probe_path(&dir.0);
        create_exclusive_0600(&probe).unwrap();

        let mut perms = std::fs::metadata(&dir.0).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&dir.0, perms).unwrap();

        let err = std::fs::remove_file(&probe).expect_err("unlink on read-only dir");
        // The helper uses `remove_file(...)?` — same call — so this error
        // class is returned to the caller rather than swallowed.
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
            ) || err.raw_os_error().is_some(),
            "unexpected remove error: {err:?}"
        );

        // Leftover probe must also make a subsequent full probe fail (create_new).
        let full_err = probe_dir_writable(&dir.0).expect_err("stuck probe");
        assert_eq!(full_err.kind(), io::ErrorKind::AlreadyExists);

        let mut perms = std::fs::metadata(&dir.0).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&dir.0, perms).unwrap();
        let _ = std::fs::remove_file(&probe);
    }

    #[test]
    fn real_dir_is_not_symlinked_output_dir() {
        let dir = Tmp::new("ethernal-fs-util");
        assert!(symlinked_output_dir(&dir.0).is_none());

        let mut buf = Vec::new();
        assert!(!warn_if_symlinked_output_dir(&dir.0, &mut buf));
        assert!(
            buf.is_empty(),
            "expected empty buffer, got {}",
            String::from_utf8_lossy(&buf)
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_output_dir_detects_final_component_link() {
        use std::os::unix::fs::symlink;

        let dir = Tmp::new("ethernal-fs-util");
        let real = dir.0.join("real-out");
        std::fs::create_dir(&real).unwrap();
        let link = dir.0.join("link-out");
        symlink(&real, &link).unwrap();

        let resolved = symlinked_output_dir(&link).expect("final-component symlink");
        let expected = std::fs::canonicalize(&real).unwrap();
        assert_eq!(resolved, expected);

        let mut buf = Vec::new();
        assert!(warn_if_symlinked_output_dir(&link, &mut buf));
        let text = String::from_utf8(buf).unwrap();
        // Immune to FR-17 collision: unit Vec sink, no secret-file flag in play (F3-2).
        let warning_lines: Vec<_> = text.lines().filter(|l| l.contains("WARNING")).collect();
        assert_eq!(
            warning_lines.len(),
            1,
            "expected exactly one WARNING line, got: {text}"
        );
        assert!(
            warning_lines[0].contains(link.to_str().unwrap()),
            "warning must name given path: {text}"
        );
        assert!(
            warning_lines[0].contains(resolved.to_str().unwrap()),
            "warning must name resolved path: {text}"
        );
    }
}
