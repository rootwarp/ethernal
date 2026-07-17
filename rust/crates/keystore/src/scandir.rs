//! Builds a pubkey → path index over a directory of keystore files without
//! decrypting them.
//!
//! Ported from `go/internal/keystore/scandir.go`. Only the top-level `pubkey`
//! JSON field of each `*.json` file is parsed; files that are directories, are
//! not `*.json`, are unreadable, contain invalid JSON, or lack a `pubkey` field
//! are silently skipped.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::keystore::normalize_pubkey;

/// Maps a normalized (lowercase, `0x`-stripped) pubkey hex string to the
/// filesystem path of the keystore file that declares it.
#[derive(Debug, Clone, Default)]
pub struct DirectoryIndex {
    entries: HashMap<String, PathBuf>,
}

impl DirectoryIndex {
    /// Returns the path of the keystore file for `pubkey_hex`, or `None`.
    ///
    /// `pubkey_hex` is normalized (lowercased, `0x` prefix stripped) before
    /// lookup, so callers may pass prefixed or unprefixed, mixed-case hex.
    pub fn lookup(&self, pubkey_hex: &str) -> Option<&Path> {
        let normalized = normalize_pubkey(pubkey_hex);
        self.entries.get(&normalized).map(PathBuf::as_path)
    }

    /// Returns the number of indexed keystores.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Reports whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The minimal JSON shape needed to read the `pubkey` field without decryption.
#[derive(Deserialize)]
struct PubkeyEnvelope {
    #[serde(default)]
    pubkey: String,
}

/// Reads all `*.json` files in `dir` and builds a [`DirectoryIndex`] mapping
/// each file's `pubkey` field to its path.
///
/// Files that are directories, are not `*.json`, cannot be read, contain
/// invalid JSON, or lack a `pubkey` field are silently skipped. A non-`Ok`
/// result is returned only if `dir` itself cannot be listed (e.g. it does not
/// exist or is unreadable).
pub fn scan_dir(dir: &Path) -> std::io::Result<DirectoryIndex> {
    let mut entries: HashMap<String, PathBuf> = HashMap::new();

    for entry in std::fs::read_dir(dir)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };

        // Skip directories (matching Go's e.IsDir() check first).
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => continue,
            Ok(_) => {}
            Err(_) => continue,
        }

        // Suffix match on the raw file name, matching Go's
        // strings.HasSuffix(e.Name(), ".json").
        if !entry.file_name().to_string_lossy().ends_with(".json") {
            continue;
        }

        let path = entry.path();
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(_) => continue,
        };

        let env: PubkeyEnvelope = match serde_json::from_slice(&raw) {
            Ok(env) => env,
            Err(_) => continue,
        };

        if env.pubkey.is_empty() {
            continue;
        }

        entries.insert(normalize_pubkey(&env.pubkey), path);
    }

    Ok(DirectoryIndex { entries })
}
