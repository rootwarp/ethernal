//! Serializes `[Entry]` to the Launchpad JSON schema and writes
//! deposit_data-<unix_ts>.json atomically to the output directory.
//!
//! Surfaces provided:
//!   - [`FsWriter`]: writes deposit-data JSON to disk using a tmp→rename
//!     atomic sequence.
//!   - [`DryRunWriter`]: writes JSON bytes to an `io::Write` (e.g. stdout)
//!     instead of disk. Intended for --dry-run mode.
//!   - [`write_new_0600`]: generic atomic `0600` write with overwrite
//!     refusal, for bin-composed keystore persistence.
//!
//! [`FsWriter`] and [`DryRunWriter`] compute and return the sha256 hex digest
//! of the JSON bytes so callers can verify integrity without re-reading the
//! file.

use std::fs;
use std::io::{self, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::deposit::Entry;

/// Errors from serializing or persisting deposit data.
#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("output: marshal entries: {0}")]
    Marshal(#[source] serde_json::Error),
    #[error("output: open tmp file: {0}")]
    OpenTmp(#[source] io::Error),
    #[error("output: write tmp file: {0}")]
    WriteTmp(#[source] io::Error),
    #[error("output: sync tmp file: {0}")]
    SyncTmp(#[source] io::Error),
    /// Final-path publish failed (`hard_link` or `rename`).
    #[error("output: publish to final path: {0}")]
    Rename(#[source] io::Error),
    #[error("output: write dry-run output: {0}")]
    WriteDryRun(#[source] io::Error),
    /// Target path already exists; refuse to overwrite (F-4 / S-3).
    #[error("output: file already exists")]
    AlreadyExists,
    /// Parent-directory fsync after publish failed; durability not guaranteed.
    #[error("output: sync parent directory: {0}")]
    SyncDir(#[source] io::Error),
}

/// Serializes a slice of deposit entries to JSON and persists them.
/// Implementations must be safe to call multiple times with different inputs.
pub trait Writer {
    /// Serializes `entries` to the Launchpad JSON schema. `now_unix` provides
    /// the timestamp used in the output filename.
    ///
    /// [`FsWriter`] returns `(final_path, sha256hex)` on success.
    /// [`DryRunWriter`] returns `("", sha256hex)` — path is always empty.
    fn write(
        &mut self,
        dir: &Path,
        entries: &[Entry],
        now_unix: i64,
    ) -> Result<(String, String), OutputError>;
}

/// A private struct whose field order matches the Launchpad JSON schema
/// exactly. serde serializes struct fields in declaration order, which
/// guarantees byte-for-byte compatibility with the official
/// staking-deposit-cli.
#[derive(Serialize)]
struct JsonEntryOut {
    pubkey: String,
    withdrawal_credentials: String,
    amount: u64,
    signature: String,
    deposit_message_root: String,
    deposit_data_root: String,
    fork_version: String,
    network_name: String,
    deposit_cli_version: String,
}

/// Converts an [`Entry`] to a [`JsonEntryOut`], encoding all byte fields as
/// lowercase hex strings without the "0x" prefix.
fn to_json_entry(e: &Entry) -> JsonEntryOut {
    JsonEntryOut {
        pubkey: hex::encode(e.pubkey),
        withdrawal_credentials: hex::encode(e.withdrawal_credentials),
        amount: e.amount,
        signature: hex::encode(e.signature),
        deposit_message_root: hex::encode(e.deposit_message_root),
        deposit_data_root: hex::encode(e.deposit_data_root),
        fork_version: hex::encode(e.fork_version),
        network_name: e.network_name.clone(),
        deposit_cli_version: e.deposit_cli_version.clone(),
    }
}

/// Converts a slice of [`Entry`] values to compact JSON bytes formatted as a
/// JSON array. Uses compact serialization (no indentation) to match the
/// official staking-deposit-cli output format.
fn marshal_entries(entries: &[Entry]) -> Result<Vec<u8>, OutputError> {
    let je: Vec<JsonEntryOut> = entries.iter().map(to_json_entry).collect();
    serde_json::to_vec(&je).map_err(OutputError::Marshal)
}

/// Computes the SHA-256 digest of `b` and returns it as a lowercase hex string.
fn digest_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

// -----------------------------------------------------------------------------
// FsWriter
// -----------------------------------------------------------------------------

/// A [`Writer`] that persists deposit data to disk using an atomic tmp→rename
/// sequence. The temporary file is named `.deposit_data-<ts>.json.tmp` and is
/// removed on failure.
#[derive(Debug, Default)]
pub struct FsWriter;

impl FsWriter {
    pub fn new() -> Self {
        FsWriter
    }
}

impl Writer for FsWriter {
    /// Serializes entries and atomically writes them to
    /// `dir/deposit_data-<now_unix>.json`. Returns the final file path and the
    /// SHA-256 hex digest of the JSON bytes.
    ///
    /// Atomic sequence:
    ///  1. Marshal entries to JSON.
    ///  2. Write bytes to `dir/.deposit_data-<ts>.json.tmp` (mode 0600).
    ///  3. Sync the file.
    ///  4. Close the file.
    ///  5. Rename to the final path.
    ///  6. Fsync the parent directory (reported success ⇒ durable entry).
    ///
    /// On any failure the temporary file is removed so no stale artifacts
    /// remain.
    fn write(
        &mut self,
        dir: &Path,
        entries: &[Entry],
        now_unix: i64,
    ) -> Result<(String, String), OutputError> {
        let data = marshal_entries(entries)?;

        let filename = format!("deposit_data-{now_unix}.json");
        let tmp_name = format!(".deposit_data-{now_unix}.json.tmp");

        let final_path: PathBuf = dir.join(&filename);
        let tmp_path: PathBuf = dir.join(&tmp_name);

        // Write, sync, close, rename, parent-dir fsync. Any failure removes tmp.
        let result = (|| {
            let mut f = open_0600(&tmp_path).map_err(OutputError::OpenTmp)?;
            f.write_all(&data).map_err(OutputError::WriteTmp)?;
            f.sync_all().map_err(OutputError::SyncTmp)?;
            drop(f);
            fs::rename(&tmp_path, &final_path).map_err(OutputError::Rename)?;
            sync_parent_dir(&final_path)
        })();

        if let Err(e) = result {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }

        Ok((final_path.to_string_lossy().into_owned(), digest_hex(&data)))
    }
}

/// Opens `path` for writing (create/truncate) with permissions 0600 on Unix.
fn open_0600(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Opens `path` exclusively (`create_new`) with permissions 0600 on Unix.
/// Fails with [`io::ErrorKind::AlreadyExists`] if the path is already present.
fn open_create_new_0600(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Parent directory of `path`, or `"."` when the path has no parent component.
fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Fsync the parent directory so a newly published directory entry is durable.
///
/// Portable baseline: open the parent and `sync_all` on that fd. On macOS this
/// is ordinary `fsync` semantics, not `F_FULLFSYNC` — the accepted portable
/// floor for this codebase (K2-L2 / H6).
fn sync_parent_dir(path: &Path) -> Result<(), OutputError> {
    let parent = parent_dir(path);
    let dir = fs::File::open(parent).map_err(OutputError::SyncDir)?;
    dir.sync_all().map_err(OutputError::SyncDir)
}

/// `true` when `hard_link` failed because the filesystem rejects hard links
/// (`EPERM` / `ENOTSUP` / `EOPNOTSUPP` class).
fn hard_link_unsupported(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::Unsupported | io::ErrorKind::PermissionDenied
    )
}

// -----------------------------------------------------------------------------
// write_new_0600 — generic atomic 0600 writer, refuse-overwrite (K2-2 / H6)
// -----------------------------------------------------------------------------

/// Unlinks `path` on drop unless disarmed after a successful rename.
///
/// Only constructed after this call successfully `create_new`s the tmp, so
/// Drop never deletes a file it does not own. After a successful hard_link
/// publish the guard stays armed: Drop removes the tmp *entry* while the
/// inode remains reachable under `final_path`.
struct TmpGuard {
    path: PathBuf,
    armed: bool,
}

impl TmpGuard {
    fn new(path: PathBuf) -> Self {
        TmpGuard { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Keep the file (rename took ownership of the inode via directory entry).
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Creates a unique exclusive tmp file (mode 0600) in the same directory as
/// `final_path`. Only returns a [`TmpGuard`] after `create_new` succeeds, so
/// cleanup never unlinks a path this call did not create.
fn create_unique_tmp(final_path: &Path) -> Result<(TmpGuard, fs::File), OutputError> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let parent = parent_dir(final_path);

    for _ in 0..10_000 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let name = format!(".tmp-ethernal-core-{}-{nanos}-{n}", std::process::id());
        let path = parent.join(&name);
        match open_create_new_0600(&path) {
            Ok(f) => return Ok((TmpGuard::new(path), f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(OutputError::OpenTmp(e)),
        }
    }
    Err(OutputError::OpenTmp(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique temp file",
    )))
}

/// Publish via exclusive empty reservation then rename over it.
/// Fallback when the filesystem does not support hard links (H6).
fn publish_via_reservation_rename(tmp: TmpGuard, final_path: &Path) -> Result<(), OutputError> {
    // Exclusive claim on final_path before rename. On Unix, rename replaces an
    // existing file, so create_new is what enforces refuse-overwrite.
    // Non-AlreadyExists open failures use OpenTmp (not Rename): rename never ran.
    match open_create_new_0600(final_path) {
        Ok(f) => drop(f),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(OutputError::AlreadyExists);
        }
        Err(e) => return Err(OutputError::OpenTmp(e)),
    }

    match fs::rename(tmp.path(), final_path) {
        Ok(()) => {
            tmp.disarm();
            Ok(())
        }
        Err(e) => {
            // Remove the empty create_new reservation we just made; tmp Drop
            // removes the owned temp file.
            let _ = fs::remove_file(final_path);
            Err(OutputError::Rename(e))
        }
    }
}

/// Atomic `0600` write with overwrite refusal.
///
/// Sequence:
///  1. Unique `create_new` tmp (mode 0600) → write → fsync.
///  2. **Primary publish:** `hard_link(tmp, final_path)` so the final entry
///     appears with full contents in one atomic directory update (same inode
///     as the synced tmp). No empty stub is ever created at `final_path`.
///     On success the tmp *entry* is unlinked via [`TmpGuard`] Drop (do not
///     disarm — the inode lives on under `final_path`).
///  3. **Fallback** (hard links unsupported: `EPERM`/`ENOTSUP` class): the
///     pre-H6 reservation+rename path.
///  4. Fsync the parent directory (reported success ⇒ durable entry).
///
/// Errors if `final_path` already exists (F-4). Removes the owned tmp (and any
/// empty final reservation on the fallback path) on failure or panic; SIGKILL
/// cannot guarantee cleanup.
///
/// Unlike the private [`open_0600`] used by [`FsWriter`] (create/truncate), this
/// never clobbers an existing file. Intended for keystore writes composed by
/// the bin.
pub fn write_new_0600(final_path: &Path, bytes: &[u8]) -> Result<(), OutputError> {
    let (tmp, mut f) = create_unique_tmp(final_path)?;

    if let Err(e) = f.write_all(bytes) {
        return Err(OutputError::WriteTmp(e));
    }
    if let Err(e) = f.sync_all() {
        return Err(OutputError::SyncTmp(e));
    }
    drop(f);

    // Test-only: simulate crash/error after tmp is durable but before publish.
    // On this path nothing exists at final_path; TmpGuard Drop removes tmp.
    #[cfg(test)]
    if tests::take_inject_fail_before_publish() {
        return Err(OutputError::WriteTmp(io::Error::other(
            "injected failure before publish",
        )));
    }

    // Primary: link-then-unlink. hard_link fails with AlreadyExists if the
    // name is taken — refuse-overwrite without a create_new reservation.
    match fs::hard_link(tmp.path(), final_path) {
        Ok(()) => {
            // Do not disarm: Drop removes the tmp entry; inode stays at final.
            drop(tmp);
            sync_parent_dir(final_path)?;
            return Ok(());
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(OutputError::AlreadyExists);
        }
        Err(e) if hard_link_unsupported(&e) => {
            // Fall through to reservation+rename on filesystems without links.
        }
        Err(e) => return Err(OutputError::Rename(e)),
    }

    publish_via_reservation_rename(tmp, final_path)?;
    sync_parent_dir(final_path)
}

// -----------------------------------------------------------------------------
// DryRunWriter
// -----------------------------------------------------------------------------

/// A [`Writer`] that writes JSON bytes to `w` instead of disk. It is intended
/// for --dry-run mode. The returned path is always empty; the sha256hex is
/// computed over the same JSON bytes that would be written to disk.
pub struct DryRunWriter<W: IoWrite> {
    w: W,
}

impl<W: IoWrite> DryRunWriter<W> {
    pub fn new(w: W) -> Self {
        DryRunWriter { w }
    }
}

impl<W: IoWrite> Writer for DryRunWriter<W> {
    /// Serializes entries and writes the JSON bytes to the underlying writer.
    /// Returns `("", sha256hex)` on success.
    fn write(
        &mut self,
        _dir: &Path,
        entries: &[Entry],
        _now_unix: i64,
    ) -> Result<(String, String), OutputError> {
        let data = marshal_entries(entries)?;
        self.w.write_all(&data).map_err(OutputError::WriteDryRun)?;
        Ok((String::new(), digest_hex(&data)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Per-thread inject flag: when set, the next `write_new_0600` on *this*
    // thread fails after tmp sync and before publish (K2-L1 crash window).
    // Thread-local so parallel `cargo test` cannot steal another test's flag.
    thread_local! {
        static INJECT_FAIL_BEFORE_PUBLISH: Cell<bool> = const { Cell::new(false) };
    }

    /// Consume the inject flag (one-shot). Called from `write_new_0600`.
    pub(super) fn take_inject_fail_before_publish() -> bool {
        INJECT_FAIL_BEFORE_PUBLISH.with(|c| c.replace(false))
    }

    /// Clears the inject flag on drop so a panicked test cannot poison others
    /// on the same thread (test harness may reuse threads).
    struct InjectFailGuard;

    impl Drop for InjectFailGuard {
        fn drop(&mut self) {
            INJECT_FAIL_BEFORE_PUBLISH.with(|c| c.set(false));
        }
    }

    /// Unique temp directory cleaned up on drop (no tempfile dependency).
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let mut path = std::env::temp_dir();
            path.push(format!(
                "ethernal-core-write-new-{}-{nanos}-{n}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            TempDir { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn assert_no_owned_tmp(dir: &Path) {
        for entry in fs::read_dir(dir).expect("read_dir") {
            let name = entry.expect("dir entry").file_name();
            let name = name.to_string_lossy();
            assert!(
                !name.starts_with(".tmp-ethernal-core-"),
                "owned tmp file left behind: {name}"
            );
        }
    }

    #[test]
    fn write_new_0600_writes_contents_and_mode() {
        let dir = TempDir::new();
        let path = dir.path().join("keystore-test.json");
        let bytes = b"{\"crypto\":{}}";

        write_new_0600(&path, bytes).expect("first write");

        assert_eq!(fs::read(&path).expect("read back"), bytes);
        assert_no_owned_tmp(dir.path());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "written file must be mode 0600");
        }
    }

    #[test]
    fn write_new_0600_refuses_overwrite() {
        let dir = TempDir::new();
        let path = dir.path().join("keystore-exists.json");
        let original = b"original-bytes";

        write_new_0600(&path, original).expect("first write");
        let err = write_new_0600(&path, b"clobber-attempt").expect_err("second write");
        assert!(
            matches!(err, OutputError::AlreadyExists),
            "expected AlreadyExists, got {err:?}"
        );

        // Original contents must be unchanged.
        assert_eq!(fs::read(&path).expect("read back"), original);
        assert_no_owned_tmp(dir.path());
    }

    #[test]
    fn write_new_0600_no_tmp_on_failure() {
        let dir = TempDir::new();
        // Parent path is a regular file, so create_new of a child must fail.
        let not_a_dir = dir.path().join("not-a-dir");
        fs::write(&not_a_dir, b"x").expect("write blocker file");
        let target = not_a_dir.join("keystore.json");

        let err = write_new_0600(&target, b"data").expect_err("write must fail");
        assert!(
            matches!(err, OutputError::OpenTmp(_)),
            "expected OpenTmp, got {err:?}"
        );

        assert_no_owned_tmp(dir.path());
        // Blocker file still present; no keystore sibling created under dir.
        assert!(not_a_dir.is_file());
        for entry in fs::read_dir(dir.path()).expect("read_dir") {
            let name = entry.expect("dir entry").file_name();
            assert_eq!(name.to_string_lossy(), "not-a-dir");
        }
    }

    /// Failed create_new must not unlink a pre-existing foreign file that
    /// happens to share a path pattern, and unique tmp names must not collide
    /// with a deterministic sibling like `.<name>.tmp`.
    #[test]
    fn write_new_0600_does_not_delete_foreign_tmp() {
        let dir = TempDir::new();
        let path = dir.path().join("keystore.json");
        let foreign = dir.path().join(".keystore.json.tmp");
        fs::write(&foreign, b"FOREIGN_KEYSTORE_MATERIAL").expect("seed foreign tmp");

        write_new_0600(&path, b"owned-bytes").expect("write");

        assert_eq!(
            fs::read(&foreign).expect("foreign still present"),
            b"FOREIGN_KEYSTORE_MATERIAL",
            "must not unlink a tmp this call did not create"
        );
        assert_eq!(fs::read(&path).expect("final"), b"owned-bytes");
        assert_no_owned_tmp(dir.path());
    }

    /// Second write that hits AlreadyExists must clean its own tmp and leave
    /// final contents intact (covers post-tmp-write cleanup via TmpGuard Drop).
    #[test]
    fn write_new_0600_already_exists_cleans_owned_tmp() {
        let dir = TempDir::new();
        let path = dir.path().join("ks.json");
        write_new_0600(&path, b"v1").expect("first");
        let _ = write_new_0600(&path, b"v2").expect_err("second");
        assert_eq!(fs::read(&path).unwrap(), b"v1");
        assert_no_owned_tmp(dir.path());
    }

    /// Hard-link publish: final appears with full contents; no empty stub and
    /// no owned tmp left. Permissions remain 0600 (link shares the tmp inode).
    #[test]
    fn write_new_0600_hard_link_publish_full_contents() {
        let dir = TempDir::new();
        let path = dir.path().join("hardlink-ks.json");
        let bytes = b"full-keystore-payload-not-empty";

        write_new_0600(&path, bytes).expect("write");

        assert_eq!(fs::read(&path).expect("read"), bytes);
        assert_no_owned_tmp(dir.path());

        // nlink should be 1 after TmpGuard unlinked the tmp entry.
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let meta = fs::metadata(&path).unwrap();
            assert_eq!(meta.nlink(), 1, "tmp entry must be unlinked after publish");
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }

    /// Injected failure between tmp-sync and publish leaves nothing at final
    /// and no owned tmp; a subsequent write succeeds (K2-L1 footgun closed).
    #[test]
    fn write_new_0600_interrupted_before_publish_leaves_nothing_retry_ok() {
        let dir = TempDir::new();
        let path = dir.path().join("interrupt-ks.json");
        let _clear = InjectFailGuard;

        INJECT_FAIL_BEFORE_PUBLISH.with(|c| c.set(true));
        let err = write_new_0600(&path, b"secret-bytes").expect_err("injected fail");
        assert!(
            matches!(err, OutputError::WriteTmp(_)),
            "expected injected WriteTmp, got {err:?}"
        );
        assert!(
            !path.exists(),
            "final_path must not exist after interrupted write (no 0-byte stub)"
        );
        assert_no_owned_tmp(dir.path());

        // Retry without inject: succeeds; operator need not delete a stub.
        write_new_0600(&path, b"secret-bytes").expect("retry after interrupt");
        assert_eq!(fs::read(&path).unwrap(), b"secret-bytes");
        assert_no_owned_tmp(dir.path());
    }

    /// Parent-dir fsync failure surfaces as `SyncDir`.
    #[test]
    fn sync_parent_dir_missing_parent_is_sync_dir() {
        let err = sync_parent_dir(Path::new("/nonexistent-ethernal-core-h6-xyz/child.json"))
            .expect_err("missing parent must fail");
        assert!(
            matches!(err, OutputError::SyncDir(_)),
            "expected SyncDir, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("sync parent directory"),
            "Display should name the stage: {msg}"
        );
    }

    #[test]
    fn hard_link_unsupported_classifies_kinds() {
        assert!(hard_link_unsupported(&io::Error::new(
            io::ErrorKind::Unsupported,
            "enotsup"
        )));
        assert!(hard_link_unsupported(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "eperm"
        )));
        assert!(!hard_link_unsupported(&io::Error::new(
            io::ErrorKind::AlreadyExists,
            "eexist"
        )));
        assert!(!hard_link_unsupported(&io::Error::other("other")));
    }
}
