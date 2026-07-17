//! Orchestrates the per-pubkey BLS signing pipeline and enforces
//! self-verification. This is the only module that knows the full domain
//! story: it precomputes the deposit domain once at construction time and
//! then uses it for every signing operation in [`Generator::generate`].
//!
//! The driving correctness constraint is "verify-before-write": every
//! signature is re-verified immediately after signing. A single failed
//! verification aborts the entire run with no partial output.
//!
//! This module also carries the Launchpad-compatible JSON *read side*
//! ([`entry_from_json`] / [`entries_from_json`]) and semantic validation
//! ([`Entry::validate`]); the write side lives in [`crate::output`].

use serde::Deserialize;

use crate::bls::{BlsError, Signer, Verifier};
use crate::cancel::CancelToken;
use crate::network::{self, Network, Params};
use crate::ssz;

/// Errors from the deposit generation pipeline and JSON read side.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum DepositError {
    /// The signer's public key does not match a requested pubkey.
    /// The message includes the hex of the offending key.
    #[error("pubkey mismatch: pubkey[{index}]=0x{pubkey_hex}")]
    PubkeyMismatch { index: usize, pubkey_hex: String },

    /// BLS self-verification failed immediately after signing. This indicates
    /// a bug in the signer or SSZ pipeline and should never occur in practice.
    #[error("self-verification failed: pubkey[{index}]=0x{pubkey_hex}")]
    SelfVerifyFailed { index: usize, pubkey_hex: String },

    /// The request's stated network does not match the network the Generator
    /// was constructed for.
    #[error(r#"network mismatch: request "{request}" but generator is configured for "{configured}""#)]
    NetworkMismatch { request: String, configured: String },

    /// The operation was cancelled (SIGINT). Maps to exit code 4.
    #[error("operation cancelled")]
    Cancelled,

    /// An underlying BLS operation failed.
    #[error(transparent)]
    Bls(#[from] BlsError),

    /// A JSON entry field failed hex decoding.
    #[error(r#"deposit: {field}: invalid hex "{value}": {source}"#)]
    InvalidHex {
        field: &'static str,
        value: String,
        source: hex::FromHexError,
    },

    /// A JSON entry field decoded to the wrong length.
    #[error("deposit: {field}: got {got} bytes, want {want}")]
    BadLength {
        field: &'static str,
        got: usize,
        want: usize,
    },

    /// The JSON document could not be parsed as a single entry object.
    #[error("deposit: unmarshal entry: {0}")]
    UnmarshalEntry(String),

    /// The JSON document could not be parsed as an entry array.
    #[error("deposit: unmarshal entries array: {0}")]
    UnmarshalEntries(String),

    /// An entry inside an array failed to convert; wraps the inner error with
    /// its index, mirroring Go's `deposit: entry[%d]: %w`.
    #[error("deposit: entry[{index}]: {source}")]
    EntryAt {
        index: usize,
        source: Box<DepositError>,
    },

    /// A semantic validation failure ([`Entry::validate`]). The message is
    /// verbatim from the Go implementation, e.g.
    /// "deposit: validate: pubkey is all-zero".
    #[error("deposit: validate: {0}")]
    Validate(String),
}

/// Describes a batch of deposit entries to generate. All pubkeys share the
/// same withdrawal credentials, amount, and network.
#[derive(Debug, Clone)]
pub struct Request {
    /// The target Ethereum network.
    pub network: Network,

    /// The list of validator public keys to generate deposits for.
    /// Each must match the signer's public key.
    pub pubkeys: Vec<[u8; 48]>,

    /// The 32-byte withdrawal credentials applied uniformly to every entry in
    /// this request.
    pub withdrawal_credentials: [u8; 32],

    /// The deposit amount in Gwei (default: 32_000_000_000).
    pub amount_gwei: u64,

    /// The version string written into the output JSON, e.g. "2.7.0". It
    /// mirrors the staking-deposit-cli release that was used to derive the
    /// golden test fixtures.
    pub deposit_cli_version: String,
}

/// Holds the fully computed and verified deposit data for a single validator
/// pubkey. It contains all fields required to produce a Launchpad-compatible
/// deposit_data JSON entry.
///
/// `network_name` is a free-form string (not [`Network`]) because the JSON
/// read side must be able to represent unrecognised names, which
/// [`Entry::validate`] then rejects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub pubkey: [u8; 48],
    pub withdrawal_credentials: [u8; 32],
    pub amount: u64,
    pub signature: [u8; 96],
    pub deposit_message_root: [u8; 32],
    pub deposit_data_root: [u8; 32],
    pub fork_version: [u8; 4],
    pub network_name: String,
    pub deposit_cli_version: String,
}

impl Default for Entry {
    fn default() -> Self {
        Entry {
            pubkey: [0u8; 48],
            withdrawal_credentials: [0u8; 32],
            amount: 0,
            signature: [0u8; 96],
            deposit_message_root: [0u8; 32],
            deposit_data_root: [0u8; 32],
            fork_version: [0u8; 4],
            network_name: String::new(),
            deposit_cli_version: String::new(),
        }
    }
}

/// Precomputes the deposit signing domain at construction time and uses it
/// for every `generate` call. Construct via [`Generator::new`].
pub struct Generator<'a> {
    signer: &'a dyn Signer,
    verifier: &'a dyn Verifier,
    /// Precomputed: compute_domain(DOMAIN_DEPOSIT, fork_version, ZERO_GVR).
    domain: [u8; 32],
    /// Stored for fork_version and network_name in entries.
    params: Params,
}

impl<'a> Generator<'a> {
    /// Constructs a Generator that signs with `signer`, verifies with
    /// `verifier`, and uses the network parameters in `params`. The deposit
    /// domain is computed once here using [`network::DOMAIN_DEPOSIT`] and
    /// [`network::ZERO_GENESIS_VALIDATORS_ROOT`].
    pub fn new(signer: &'a dyn Signer, verifier: &'a dyn Verifier, params: Params) -> Self {
        let domain = ssz::compute_domain(
            network::DOMAIN_DEPOSIT,
            params.genesis_fork_version,
            network::ZERO_GENESIS_VALIDATORS_ROOT,
        );
        Generator {
            signer,
            verifier,
            domain,
            params,
        }
    }

    /// Runs the per-pubkey signing pipeline for every pubkey in `req`.
    /// It returns all entries only if every entry passed self-verification.
    /// On any error — pubkey mismatch, sign error, verify failure, or
    /// cancellation — it returns `Err` with no partial output.
    pub fn generate(
        &self,
        req: &Request,
        cancel: &CancelToken,
    ) -> Result<Vec<Entry>, DepositError> {
        // Guard against silent misconfiguration: the request's stated network
        // must match the network this Generator was constructed for.
        if req.network != self.params.name {
            return Err(DepositError::NetworkMismatch {
                request: req.network.to_string(),
                configured: self.params.name.to_string(),
            });
        }

        let mut entries = Vec::with_capacity(req.pubkeys.len());

        for (i, pk) in req.pubkeys.iter().enumerate() {
            // Step 0: honour cancellation before each unit of work.
            if cancel.is_cancelled() {
                return Err(DepositError::Cancelled);
            }

            // Step 1: assert that the signer's pubkey matches the requested pubkey.
            let signer_pub = self.signer.public_key()?;
            if signer_pub != *pk {
                return Err(DepositError::PubkeyMismatch {
                    index: i,
                    pubkey_hex: hex::encode(pk),
                });
            }

            // Step 2-3: build the deposit message and compute its hash tree root.
            let msg = ssz::DepositMessage {
                pubkey: *pk,
                withdrawal_credentials: req.withdrawal_credentials,
                amount: req.amount_gwei,
            };
            let msg_root = msg.hash_tree_root();

            // Step 4: compute the signing root using the precomputed domain.
            let signing_root = ssz::compute_signing_root(msg_root, self.domain);

            // Step 5: sign.
            let sig = self.signer.sign(signing_root)?;

            // Step 6: self-verify.
            let ok = self.verifier.verify(*pk, signing_root, sig)?;
            if !ok {
                return Err(DepositError::SelfVerifyFailed {
                    index: i,
                    pubkey_hex: hex::encode(pk),
                });
            }

            // Step 7-8: build deposit data and compute its hash tree root.
            let data = ssz::DepositData {
                pubkey: *pk,
                withdrawal_credentials: req.withdrawal_credentials,
                amount: req.amount_gwei,
                signature: sig,
            };
            let data_root = data.hash_tree_root();

            // Step 9: emit the completed entry.
            entries.push(Entry {
                pubkey: *pk,
                withdrawal_credentials: req.withdrawal_credentials,
                amount: req.amount_gwei,
                signature: sig,
                deposit_message_root: msg_root,
                deposit_data_root: data_root,
                fork_version: self.params.genesis_fork_version,
                network_name: self.params.name.to_string(),
                deposit_cli_version: req.deposit_cli_version.clone(),
            });
        }

        Ok(entries)
    }
}

// -----------------------------------------------------------------------------
// JSON read side
// -----------------------------------------------------------------------------

/// The wire representation of a single entry in a Launchpad
/// deposit_data-*.json file. Field names and types must match exactly what
/// `eth-deposit gen` and the official staking-deposit-cli produce.
/// All fields default so missing keys are tolerated like Go's encoding/json.
#[derive(Debug, Default, Deserialize)]
struct JsonEntryIn {
    #[serde(default)]
    pubkey: String,
    #[serde(default)]
    withdrawal_credentials: String,
    #[serde(default)]
    amount: u64,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    deposit_message_root: String,
    #[serde(default)]
    deposit_data_root: String,
    #[serde(default)]
    fork_version: String,
    #[serde(default)]
    network_name: String,
    #[serde(default)]
    deposit_cli_version: String,
}

/// Decodes a hex string that may or may not carry a "0x" prefix.
fn decode_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    hex::decode(s)
}

/// Decodes a hex string into a fixed-length byte vector and returns an error
/// if the decoded length does not match `want_len`.
fn decode_fixed_hex(
    field: &'static str,
    s: &str,
    want_len: usize,
) -> Result<Vec<u8>, DepositError> {
    let b = decode_hex(s).map_err(|e| DepositError::InvalidHex {
        field,
        value: s.to_string(),
        source: e,
    })?;
    if b.len() != want_len {
        return Err(DepositError::BadLength {
            field,
            got: b.len(),
            want: want_len,
        });
    }
    Ok(b)
}

/// Parses a single Launchpad-format JSON object (not array) into an [`Entry`].
/// The JSON may contain additional unknown fields which are silently ignored.
///
/// Accepted hex strings may be "0x"-prefixed or unprefixed (lowercase or mixed
/// case). Length invariants are enforced:
///   - pubkey:                 48 bytes
///   - withdrawal_credentials: 32 bytes
///   - signature:              96 bytes
///   - deposit_message_root:   32 bytes
///   - deposit_data_root:      32 bytes
///   - fork_version:            4 bytes
pub fn entry_from_json(data: &[u8]) -> Result<Entry, DepositError> {
    let raw: JsonEntryIn = serde_json::from_slice(data)
        .map_err(|e| DepositError::UnmarshalEntry(e.to_string()))?;
    entry_from_raw(raw)
}

/// Converts a decoded [`JsonEntryIn`] to an [`Entry`], enforcing all length
/// invariants.
fn entry_from_raw(raw: JsonEntryIn) -> Result<Entry, DepositError> {
    let pubkey_bytes = decode_fixed_hex("pubkey", &raw.pubkey, 48)?;
    let wc_bytes = decode_fixed_hex("withdrawal_credentials", &raw.withdrawal_credentials, 32)?;
    let sig_bytes = decode_fixed_hex("signature", &raw.signature, 96)?;
    let msg_root_bytes = decode_fixed_hex("deposit_message_root", &raw.deposit_message_root, 32)?;
    let data_root_bytes = decode_fixed_hex("deposit_data_root", &raw.deposit_data_root, 32)?;
    let fv_bytes = decode_fixed_hex("fork_version", &raw.fork_version, 4)?;

    let mut e = Entry {
        amount: raw.amount,
        network_name: raw.network_name,
        deposit_cli_version: raw.deposit_cli_version,
        ..Entry::default()
    };
    e.pubkey.copy_from_slice(&pubkey_bytes);
    e.withdrawal_credentials.copy_from_slice(&wc_bytes);
    e.signature.copy_from_slice(&sig_bytes);
    e.deposit_message_root.copy_from_slice(&msg_root_bytes);
    e.deposit_data_root.copy_from_slice(&data_root_bytes);
    e.fork_version.copy_from_slice(&fv_bytes);

    Ok(e)
}

/// Parses a Launchpad deposit_data-*.json file, which is a JSON array of
/// entry objects.
pub fn entries_from_json(data: &[u8]) -> Result<Vec<Entry>, DepositError> {
    let raws: Vec<JsonEntryIn> = serde_json::from_slice(data)
        .map_err(|e| DepositError::UnmarshalEntries(e.to_string()))?;
    let mut entries = Vec::with_capacity(raws.len());
    for (i, raw) in raws.into_iter().enumerate() {
        let e = entry_from_raw(raw).map_err(|err| DepositError::EntryAt {
            index: i,
            source: Box::new(err),
        })?;
        entries.push(e);
    }
    Ok(entries)
}

impl Entry {
    /// Checks that the entry carries semantically meaningful values. It
    /// returns a descriptive error for each invariant that fails:
    ///   - pubkey must not be all-zero (would represent a null key)
    ///   - signature must not be all-zero
    ///   - deposit_data_root must not be all-zero
    ///   - amount must be > 0
    ///   - network_name must be a recognised network
    pub fn validate(&self) -> Result<(), DepositError> {
        if self.pubkey == [0u8; 48] {
            return Err(DepositError::Validate("pubkey is all-zero".to_string()));
        }
        if self.signature == [0u8; 96] {
            return Err(DepositError::Validate("signature is all-zero".to_string()));
        }
        if self.deposit_data_root == [0u8; 32] {
            return Err(DepositError::Validate(
                "deposit_data_root is all-zero".to_string(),
            ));
        }
        if self.amount == 0 {
            return Err(DepositError::Validate("amount is zero".to_string()));
        }
        if let Err(e) = network::lookup_name(&self.network_name) {
            return Err(DepositError::Validate(format!(
                r#"network_name "{}" is not recognised: {}"#,
                self.network_name, e
            )));
        }
        Ok(())
    }
}
