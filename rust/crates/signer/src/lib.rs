//! EIP-1559 transaction signers, ported from `go/internal/signer`
//! (issues R3-3 / R3-4): a local raw secp256k1 key signer (development/CI)
//! and a Ledger hardware wallet signer (real funds; HID transport behind
//! the `ledger` cargo feature).
//!
//! SECURITY CONTRACT: no key material ever appears in errors, logs, or
//! argv; the local key buffer is zeroized on close/drop.

mod errors;
mod ledger;
#[cfg(feature = "ledger")]
mod ledger_hid;
mod local;
mod parse;
mod rlp;
mod types;

pub use errors::SignerError;
pub use ledger::LedgerSigner;
pub use local::{new_local_signer_from_env, new_local_signer_from_hex, LocalSigner, Signer};
pub use types::SignedTx;
