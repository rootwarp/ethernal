//! Shared unit-test scaffolding for the ethernal binary.
//!
//! Test-only (`#[cfg(test)]` from `main.rs`). Not linked into release builds.
//! Holds temp-dir helpers, process-wide env lock, and keygen test doubles so
//! inline `mod tests` blocks do not re-declare the same scaffolding.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use ethernal_core::cancel::CancelToken;
use ethernal_core::entropy::{Entropy, EntropyError};
use ethernal_keystore::{
    require_min_len, KeystoreError, PassphraseSource, KEYSTORE_PASSPHRASE_MIN_LEN,
};
use zeroize::Zeroizing;

use crate::errors::AppError;
use crate::validator_cmd::MnemonicSource;

// ---------------------------------------------------------------------------
// Process-wide env lock
// ---------------------------------------------------------------------------

/// Serializes tests that mutate process environment (`set_var` / `remove_var`).
///
/// Single lock for the whole bin so validator_cli and account_cli tests cannot
/// race each other.
pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// Temp directory
// ---------------------------------------------------------------------------

/// A temporary directory removed on drop.
///
/// Always restores `0o755` on the root before `remove_dir_all` so read-only
/// tests (e.g. `fs_util` probes) still clean up.
pub(crate) struct Tmp(pub PathBuf);

impl Tmp {
    /// Create a unique temp directory under `std::env::temp_dir()`.
    ///
    /// `prefix` is embedded in the directory name for easier debugging.
    pub(crate) fn new(prefix: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }

    pub(crate) fn str(&self) -> &str {
        self.0.to_str().unwrap()
    }

    /// EIP-2335 validator keystore files (`keystore-*.json`).
    pub(crate) fn keystore_files(&self) -> Vec<PathBuf> {
        std::fs::read_dir(&self.0)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension().and_then(|x| x.to_str()) == Some("json")
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("keystore-"))
                        .unwrap_or(false)
            })
            .collect()
    }

    /// Web3 v3 account keystore files (`UTC--*`).
    pub(crate) fn v3_files(&self) -> Vec<PathBuf> {
        std::fs::read_dir(&self.0)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("UTC--"))
                    .unwrap_or(false)
            })
            .collect()
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        // Best-effort restore write bits so remove_dir_all can succeed after
        // read-only tests (superset of the former fs_util-only behavior).
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

// ---------------------------------------------------------------------------
// Keygen test doubles (never in release binary — S-4)
// ---------------------------------------------------------------------------

/// Deterministic entropy: pops pre-queued exact fills, then zeros.
pub(crate) struct FixedEntropy {
    queue: Mutex<VecDeque<Vec<u8>>>,
}

impl FixedEntropy {
    pub(crate) fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            queue: Mutex::new(chunks.into()),
        }
    }

    /// Mnemonic entropy all-zero (24-word abandon…art), then zeros for
    /// salt/iv/uuid of every keystore.
    pub(crate) fn zero_mnemonic() -> Self {
        Self::new(vec![vec![0u8; 32]])
    }
}

impl Entropy for FixedEntropy {
    fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError> {
        let mut q = self.queue.lock().expect("entropy queue lock");
        if let Some(next) = q.pop_front() {
            assert_eq!(
                next.len(),
                buf.len(),
                "FixedEntropy chunk len {} != buf {}",
                next.len(),
                buf.len()
            );
            buf.copy_from_slice(&next);
        } else {
            buf.fill(0);
        }
        Ok(())
    }
}

/// Cancels `token` on the Nth `fill` call (1-based).
///
/// Fill #1 is all-zero mnemonic entropy; later fills use `0xab`. Cancel is
/// independent of the fill pattern.
pub(crate) struct CancelOnFill {
    pub n: usize,
    pub count: AtomicUsize,
    pub token: CancelToken,
}

impl Entropy for CancelOnFill {
    fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError> {
        let c = self.count.fetch_add(1, Ordering::SeqCst) + 1;
        if c == 1 {
            // First fill: all-zero mnemonic entropy.
            buf.fill(0);
        } else {
            buf.fill(0xab);
        }
        if c == self.n {
            self.token.cancel();
        }
        Ok(())
    }
}

pub(crate) struct FixedPassphrase(pub Vec<u8>);

impl PassphraseSource for FixedPassphrase {
    fn read(&self) -> Result<Vec<u8>, KeystoreError> {
        Ok(self.0.clone())
    }
}

pub(crate) struct ShortPassphrase;

impl PassphraseSource for ShortPassphrase {
    fn read(&self) -> Result<Vec<u8>, KeystoreError> {
        // Simulate env path with require_min_len applied by MinLenPassphrase.
        let pw = b"short7c".to_vec();
        require_min_len(&pw, KEYSTORE_PASSPHRASE_MIN_LEN)?;
        Ok(pw)
    }
}

pub(crate) struct ScriptedLines {
    lines: Mutex<VecDeque<String>>,
}

impl ScriptedLines {
    pub(crate) fn new(lines: Vec<&str>) -> Self {
        Self {
            lines: Mutex::new(lines.into_iter().map(str::to_string).collect()),
        }
    }
}

impl MnemonicSource for ScriptedLines {
    fn read_line(&self, _prompt: &str) -> Result<Zeroizing<String>, AppError> {
        let mut q = self.lines.lock().expect("lines lock");
        let line = q
            .pop_front()
            .ok_or_else(|| AppError::Internal("no more scripted lines".into()))?;
        Ok(Zeroizing::new(line))
    }
}
