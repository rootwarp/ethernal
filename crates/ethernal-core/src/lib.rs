//! Core building blocks of the ethernal pipeline, ported from
//! `go/internal/{ssz,network,bls,deposit,output}`.
//!
//! The driving correctness constraint is "verify-before-write": every BLS
//! signature is re-verified immediately after signing, and all output is
//! byte-for-byte compatible with the official staking-deposit-cli JSON schema.

pub mod bip39;
pub mod bls;
pub mod cancel;
pub mod deposit;
pub mod entropy;
pub mod hd;
pub mod hd_secp256k1;
pub mod network;
pub mod output;
pub mod ssz;
