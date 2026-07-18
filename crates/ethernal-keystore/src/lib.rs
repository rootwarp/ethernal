//! EIP-2335 v4 keystore loading, decryption, encryption, directory scanning,
//! and passphrase sources.
//!
//! Ported from `go/internal/keystore/*`. The wealdtech
//! `go-eth2-wallet-encryptor-keystorev4` dependency is replaced with a direct
//! EIP-2335 implementation (see [`keystore`] and [`encrypt`]). Key material is
//! exposed through [`Key`], which zeroizes its secret on [`Key::zeroize`] and
//! on drop.

mod crypto;
pub mod encrypt;
pub mod encrypt_v3;
mod error;
mod keystore;
mod passphrase;
mod scandir;

pub use error::KeystoreError;
pub use keystore::{Key, KeyLoader, Loader};
pub use passphrase::{
    require_min_len, EnvSource, NewKeystorePassphrase, PassphraseSource, TermPromptSource,
    KEYSTORE_PASSPHRASE_MIN_LEN,
};
pub use scandir::{scan_dir, DirectoryIndex};
