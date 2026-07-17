//! Shared helpers for the keystore integration tests. Replaces Go test
//! fixtures (`bytesSource`, `errSource`, `t.TempDir()`, `testSecret`) without
//! pulling in extra dev-dependencies.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use eth_deposit_keystore::{KeystoreError, PassphraseSource};

/// The passphrase the committed fixtures were encrypted with.
pub const TEST_PASSPHRASE: &str = "testpassword";

/// The pubkey declared in the committed fixtures.
pub const TEST_PUBKEY_HEX: &str = "b9e7be8b1eea5ca44d9b1ef6e60de0b7e213d7e6b3f29e4a0e6a93b56678e58c2d1b4e2d1b4e2d1b4e2d1b4e2d1b4e2d1b4e2d1b4e2d1b4e2d1b4e2d1b4e2d1";

/// The 32-byte BLS secret encrypted into the fixtures (0x01..0x20).
pub const TEST_SECRET: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Absolute path to a file under `crates/keystore/testdata/`.
pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A temp directory removed on drop. Replaces Go's `t.TempDir()`.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "eth-deposit-keystore-test-{tag}-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes `content` to `name` inside the temp dir, returning its path.
    pub fn write(&self, name: &str, content: &[u8]) -> PathBuf {
        let p = self.path.join(name);
        std::fs::write(&p, content).expect("write temp file");
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A [`PassphraseSource`] backed by a static string. Go: `bytesSource`.
pub struct BytesSource {
    data: Vec<u8>,
}

impl BytesSource {
    pub fn new(pw: &str) -> Self {
        BytesSource {
            data: pw.as_bytes().to_vec(),
        }
    }
}

impl PassphraseSource for BytesSource {
    fn read(&self) -> Result<Vec<u8>, KeystoreError> {
        Ok(self.data.clone())
    }
}

/// A [`PassphraseSource`] that always fails. Go: `errSource`.
///
/// Go's `errSource` returns an arbitrary sentinel; the Rust `PassphraseSource`
/// trait returns [`KeystoreError`], so the "sentinel" is a specific variant
/// (`EnvVarEmpty`) that the loader wraps in `PassphraseSource`.
pub struct ErrSource;

impl PassphraseSource for ErrSource {
    fn read(&self) -> Result<Vec<u8>, KeystoreError> {
        Err(KeystoreError::EnvVarEmpty {
            var: "SOURCE_FAILED".to_string(),
        })
    }
}
