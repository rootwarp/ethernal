//! EIP-2335 v4 keystore loading and decryption, directory scanning, and
//! passphrase sources.
//!
//! Ported from `go/internal/keystore/*`. The wealdtech
//! `go-eth2-wallet-encryptor-keystorev4` dependency is replaced with a direct
//! EIP-2335 implementation (see [`keystore`]). Key material is exposed through
//! [`Key`], which zeroizes its secret on [`Key::zeroize`] and on drop.

mod error;
mod keystore;
mod passphrase;
mod scandir;

pub use error::KeystoreError;
pub use keystore::{Key, KeyLoader, Loader};
pub use passphrase::{EnvSource, PassphraseSource, TermPromptSource};
pub use scandir::{scan_dir, DirectoryIndex};
