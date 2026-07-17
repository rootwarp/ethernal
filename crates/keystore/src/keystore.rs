//! Loads and decrypts EIP-2335 v4 keystore files.
//!
//! Ported from `go/internal/keystore/keystore.go`, replacing the wealdtech
//! `go-eth2-wallet-encryptor-keystorev4` dependency with a direct EIP-2335
//! implementation: NFKD-normalize + strip control codes from the passphrase,
//! derive the key via scrypt or pbkdf2(HMAC-SHA256), verify
//! `sha256(dk[16..32] || ciphertext)` against the stored checksum, then
//! AES-128-CTR decrypt.

use std::fmt;
use std::path::Path;

use ctr::cipher::{KeyIvInit, StreamCipher};
use serde::Deserialize;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, Aes128Ctr};
use crate::error::KeystoreError;

/// Key material returned by a [`KeyLoader`].
///
/// Callers should call [`Key::zeroize`] after use. Go requires the explicit
/// call because its garbage collector does not clear memory; Rust additionally
/// implements [`Drop`] to zeroize for defense in depth, so a dropped `Key`
/// never leaves the secret in freed memory.
pub struct Key {
    /// The raw 32-byte BLS signing secret. Zeroize after use.
    pub secret: Vec<u8>,

    /// The lowercase hex-encoded public key declared in the keystore JSON,
    /// without a `0x` prefix. Passed through as-is from the JSON; the loader
    /// does not validate its length or that it matches [`Key::secret`].
    pub pubkey_hex: String,
}

impl Key {
    /// Overwrites every byte of [`Key::secret`] with `0x00`.
    ///
    /// Uses a volatile slice zeroize so the writes are not elided and the
    /// length is preserved (mirroring Go's explicit byte loop). Safe to call
    /// more than once.
    pub fn zeroize(&mut self) {
        self.secret.as_mut_slice().zeroize();
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.secret.as_mut_slice().zeroize();
    }
}

impl fmt::Debug for Key {
    /// Redacts the secret so key material never reaches logs or panic output,
    /// upholding the "key material never in errors/logs" invariant.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("secret", &"[REDACTED]")
            .field("pubkey_hex", &self.pubkey_hex)
            .finish()
    }
}

/// Loads and decrypts an EIP-2335 v4 keystore file.
pub trait KeyLoader {
    /// Reads and decrypts the keystore at `path` using the passphrase obtained
    /// from `pw`.
    ///
    /// Error mapping (same order as Go):
    ///   - file not found        → [`KeystoreError::KeystoreMissing`]
    ///   - other read error      → [`KeystoreError::ReadFile`]
    ///   - invalid JSON          → [`KeystoreError::KeystoreMalformed`]
    ///   - version field != 4    → [`KeystoreError::KeystoreVersion`]
    ///   - missing crypto field  → [`KeystoreError::KeystoreMalformed`]
    ///   - passphrase source err → [`KeystoreError::PassphraseSource`]
    ///   - wrong passphrase      → [`KeystoreError::WrongPassphrase`]
    fn load(
        &self,
        path: &Path,
        pw: &dyn crate::passphrase::PassphraseSource,
    ) -> Result<Key, KeystoreError>;
}

/// The top-level structure of an EIP-2335 v4 keystore JSON.
///
/// Unknown fields are tolerated and missing fields default, matching Go's
/// `encoding/json`. `crypto` is `Option` so an absent or `null` object maps to
/// "missing crypto field" exactly as Go's `envelope.Crypto == nil` check does.
#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    crypto: Option<serde_json::Value>,
    #[serde(default)]
    pubkey: String,
    #[serde(default)]
    version: i64,
}

/// The `crypto` object of an EIP-2335 keystore.
#[derive(Deserialize)]
struct Crypto {
    kdf: CryptoModule,
    checksum: CryptoModule,
    cipher: CryptoModule,
}

/// One of the `kdf`/`checksum`/`cipher` sub-objects: a function name, an
/// (unused-here) message field, and a free-form params object.
#[derive(Deserialize)]
struct CryptoModule {
    function: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    params: serde_json::Value,
}

/// Parameters for the `scrypt` KDF.
#[derive(Deserialize)]
struct ScryptParams {
    dklen: usize,
    n: u64,
    r: u32,
    p: u32,
    salt: String,
}

/// Parameters for the `pbkdf2` KDF.
#[derive(Deserialize)]
struct Pbkdf2Params {
    dklen: usize,
    c: u32,
    prf: String,
    salt: String,
}

/// Parameters for the `aes-128-ctr` cipher.
#[derive(Deserialize)]
struct CipherParams {
    iv: String,
}

/// The concrete [`KeyLoader`] that reads EIP-2335 v4 keystore files.
#[derive(Debug, Default, Clone, Copy)]
pub struct Loader;

impl Loader {
    /// Returns a loader for EIP-2335 v4 keystore files.
    pub fn new() -> Self {
        Loader
    }
}

impl KeyLoader for Loader {
    fn load(
        &self,
        path: &Path,
        pw: &dyn crate::passphrase::PassphraseSource,
    ) -> Result<Key, KeystoreError> {
        let path_str = path.display().to_string();

        let raw = match std::fs::read(path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(KeystoreError::KeystoreMissing { path: path_str });
            }
            Err(err) => {
                return Err(KeystoreError::ReadFile {
                    path: path_str,
                    source: err,
                });
            }
        };

        let envelope: Envelope =
            serde_json::from_slice(&raw).map_err(|err| KeystoreError::KeystoreMalformed {
                path: path_str.clone(),
                detail: err.to_string(),
            })?;

        // Version check first — gives the most diagnostic error for malformed
        // v3 keystores, before we look inside the crypto object.
        if envelope.version != 4 {
            return Err(KeystoreError::KeystoreVersion {
                path: path_str,
                got: envelope.version,
            });
        }

        // Validate the crypto field is present after confirming version.
        let crypto = match envelope.crypto {
            Some(crypto) => crypto,
            None => {
                return Err(KeystoreError::KeystoreMalformed {
                    path: path_str,
                    detail: "missing crypto field".to_string(),
                });
            }
        };

        // Source the passphrase. The returned buffer is zeroized as soon as
        // decryption completes (success or failure) via `Zeroizing`.
        let pass_bytes = Zeroizing::new(
            pw.read()
                .map_err(|err| KeystoreError::PassphraseSource(Box::new(err)))?,
        );

        let secret = decrypt(&path_str, &crypto, &pass_bytes)?;

        let pubkey_hex = normalize_pubkey(&envelope.pubkey);

        Ok(Key { secret, pubkey_hex })
    }
}

/// Normalizes a pubkey hex string: strip a leading `0x`, then lowercase.
/// Mirrors Go's `strings.ToLower(strings.TrimPrefix(pubkey, "0x"))`.
pub(crate) fn normalize_pubkey(pubkey: &str) -> String {
    pubkey.strip_prefix("0x").unwrap_or(pubkey).to_lowercase()
}

/// Decrypts an EIP-2335 `crypto` object with the given raw passphrase bytes.
fn decrypt(
    path: &str,
    crypto: &serde_json::Value,
    passphrase: &[u8],
) -> Result<Vec<u8>, KeystoreError> {
    let malformed = |detail: String| KeystoreError::KeystoreMalformed {
        path: path.to_string(),
        detail,
    };

    let crypto: Crypto = serde_json::from_value(crypto.clone())
        .map_err(|err| malformed(format!("crypto: {err}")))?;

    // The ciphertext is needed both for the checksum and the final decrypt.
    let ciphertext = decode_hex(&crypto.cipher.message, path, "cipher.message")?;

    // 1. Normalize the passphrase per EIP-2335 (NFKD + strip control codes).
    let normalized = crypto::normalize_passphrase(passphrase);

    // 2. Derive the key.
    let dk = derive_key(path, &crypto.kdf, &normalized)?;
    if dk.len() < 32 {
        return Err(malformed(format!(
            "kdf: derived key too short: {} bytes, need at least 32",
            dk.len()
        )));
    }

    // 3. Verify the checksum: sha256(dk[16..32] || ciphertext).
    if crypto.checksum.function != "sha256" {
        return Err(malformed(format!(
            "checksum: unsupported function {:?}",
            crypto.checksum.function
        )));
    }
    let expected = decode_hex(&crypto.checksum.message, path, "checksum.message")?;
    let computed = crypto::checksum_message(&dk, &ciphertext);
    if computed.as_slice() != expected.as_slice() {
        // A checksum mismatch is how a wrong passphrase manifests. The detail
        // matches the wealdtech encryptor's error text for byte parity.
        return Err(KeystoreError::WrongPassphrase {
            detail: "invalid checksum".to_string(),
        });
    }

    // 4. AES-128-CTR decrypt with key = dk[0..16], iv from cipher params.
    if crypto.cipher.function != "aes-128-ctr" {
        return Err(malformed(format!(
            "cipher: unsupported function {:?}",
            crypto.cipher.function
        )));
    }
    let cipher_params: CipherParams = serde_json::from_value(crypto.cipher.params)
        .map_err(|err| malformed(format!("cipher.params: {err}")))?;
    let iv = decode_hex(&cipher_params.iv, path, "cipher.params.iv")?;

    let mut cipher = Aes128Ctr::new_from_slices(&dk[0..16], &iv)
        .map_err(|err| malformed(format!("cipher: invalid key/iv length: {err}")))?;
    let mut secret = ciphertext;
    cipher.apply_keystream(&mut secret);

    Ok(secret)
}

/// Derives the encryption key from a KDF module and the normalized passphrase.
/// The derived key is zeroized on drop.
fn derive_key(
    path: &str,
    kdf: &CryptoModule,
    password: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let malformed = |detail: String| KeystoreError::KeystoreMalformed {
        path: path.to_string(),
        detail,
    };

    match kdf.function.as_str() {
        "scrypt" => {
            let params: ScryptParams = serde_json::from_value(kdf.params.clone())
                .map_err(|err| malformed(format!("kdf.params: {err}")))?;
            let salt = decode_hex(&params.salt, path, "kdf.params.salt")?;
            crypto::derive_scrypt(password, &salt, params.n, params.r, params.p, params.dklen)
                .map_err(|err| {
                    // Restore pre-refactor decrypt detail strings so operator
                    // greps stay stable (`error.rs` documents Display stability).
                    // `derive_scrypt` returns shared strings; power-of-two used
                    // to say `kdf.params.n must be…` rather than `kdf: n must…`.
                    if let Some(rest) = err.strip_prefix("n must be a power of two") {
                        malformed(format!("kdf.params.n must be a power of two{rest}"))
                    } else {
                        malformed(format!("kdf: {err}"))
                    }
                })
        }
        "pbkdf2" => {
            let params: Pbkdf2Params = serde_json::from_value(kdf.params.clone())
                .map_err(|err| malformed(format!("kdf.params: {err}")))?;
            if params.prf != "hmac-sha256" {
                return Err(malformed(format!(
                    "kdf.params.prf must be hmac-sha256, got {:?}",
                    params.prf
                )));
            }
            let salt = decode_hex(&params.salt, path, "kdf.params.salt")?;

            let mut dk = Zeroizing::new(vec![0u8; params.dklen]);
            pbkdf2::pbkdf2_hmac::<Sha256>(password, &salt, params.c, &mut dk);
            Ok(dk)
        }
        other => Err(malformed(format!("kdf: unsupported function {other:?}"))),
    }
}

/// Decodes a hex string, mapping failures to a descriptive
/// [`KeystoreError::KeystoreMalformed`].
fn decode_hex(s: &str, path: &str, field: &str) -> Result<Vec<u8>, KeystoreError> {
    hex::decode(s).map_err(|err| KeystoreError::KeystoreMalformed {
        path: path.to_string(),
        detail: format!("{field}: invalid hex: {err}"),
    })
}
