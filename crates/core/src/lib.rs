//! Core building blocks of the eth-deposit pipeline, ported from
//! `go/internal/{ssz,network,bls,deposit,output}`.
//!
//! The driving correctness constraint is "verify-before-write": every BLS
//! signature is re-verified immediately after signing, and all output is
//! byte-for-byte compatible with the official staking-deposit-cli JSON schema.

pub mod bls;
pub mod cancel;
pub mod deposit;
pub mod network;
pub mod output;
pub mod ssz;
