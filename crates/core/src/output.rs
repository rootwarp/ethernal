//! Serializes `[Entry]` to the Launchpad JSON schema and writes
//! deposit_data-<unix_ts>.json atomically to the output directory.
//!
//! Two implementations are provided:
//!   - [`FsWriter`]: writes to disk using a tmp→rename atomic sequence.
//!   - [`DryRunWriter`]: writes JSON bytes to an `io::Write` (e.g. stdout)
//!     instead of disk. Intended for --dry-run mode.
//!
//! Both implementations compute and return the sha256 hex digest of the JSON
//! bytes so callers can verify integrity without re-reading the file.

use std::fs;
use std::io::{self, Write as IoWrite};
use std::path::{Path, PathBuf};

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
    #[error("output: rename tmp to final: {0}")]
    Rename(#[source] io::Error),
    #[error("output: write dry-run output: {0}")]
    WriteDryRun(#[source] io::Error),
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

        // Write, sync, close, then rename. Any failure removes the tmp file.
        let result = (|| {
            let mut f = open_0600(&tmp_path).map_err(OutputError::OpenTmp)?;
            f.write_all(&data).map_err(OutputError::WriteTmp)?;
            f.sync_all().map_err(OutputError::SyncTmp)?;
            drop(f);
            fs::rename(&tmp_path, &final_path).map_err(OutputError::Rename)
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
