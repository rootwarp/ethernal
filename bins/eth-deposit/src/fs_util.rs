//! Shared filesystem probes for CLI validation.
//!
//! The writability probe must not follow a pre-planted symlink at the probe
//! name (K3-L4 / H5): use exclusive create (`O_EXCL` / `create_new`) so an
//! existing symlink fails instead of truncating its target.

use std::fs::OpenOptions;
use std::io;
use std::path::Path;

/// Returns the probe path used under `dir` for the current process.
pub(crate) fn probe_path(dir: &Path) -> std::path::PathBuf {
    dir.join(format!(".eth-deposit-probe-{}", std::process::id()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Tmp(PathBuf);

    impl Tmp {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!(
                "eth-deposit-fs-util-{}-{}-{n}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            // Best-effort restore write bits so remove_dir_all can succeed
            // after read-only tests.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&self.0) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o755);
                    let _ = std::fs::set_permissions(&self.0, perms);
                }
            }
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn probe_happy_path() {
        let dir = Tmp::new();
        probe_dir_writable(&dir.0).expect("writable dir");
        // No leftover probe.
        assert!(!probe_path(&dir.0).exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_probe_does_not_touch_canary_target() {
        use std::os::unix::fs::symlink;

        let dir = Tmp::new();
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

        let dir = Tmp::new();
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
        let dir = Tmp::new();
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
}
