//! Entry- and config-level validation for the unsigned tx builder.
//!
//! Ported from `go/internal/tx/validation.go`.

use ethernal_core::deposit::Entry;

use crate::builder::BuildConfig;
use crate::errors::TxError;

/// Runs entry-level and network-level checks for `build_unsigned`. It does NOT
/// check fee/nonce/gas fields — those are resolved before this call when RPC is
/// provided, or checked by [`validate_static_config`] when RPC is `None`.
///
/// Length note: [`Entry`] uses fixed-size byte arrays (`[u8; 48]`, `[u8; 96]`,
/// etc.), so the type system enforces lengths at compile time. We satisfy the
/// spirit of "length validation" via zero-detection and structural format
/// checks.
///
/// BLS pubkey point-on-curve check: skipped, matching the Go reference — the
/// optional check requires every test fixture to carry a real G1 point.
pub fn validate(entry: &Entry, cfg: &BuildConfig) -> Result<(), TxError> {
    if cfg.network_params.chain_id == 0 {
        return Err(TxError::UnconfiguredChainId);
    }

    // Amount check.
    if entry.amount != 32_000_000_000 {
        return Err(TxError::InvalidAmount(entry.amount));
    }

    // Zero-value detection for fixed-size fields.
    if entry.pubkey == [0u8; 48] {
        return Err(TxError::ZeroPubkey);
    }
    if entry.signature == [0u8; 96] {
        return Err(TxError::ZeroSignature);
    }
    if entry.deposit_data_root == [0u8; 32] {
        return Err(TxError::ZeroDepositRoot);
    }

    // Withdrawal credentials structural check.
    let wc = &entry.withdrawal_credentials;
    match wc[0] {
        0x00 => {
            // BLS withdrawal: no further format constraint.
        }
        0x01 | 0x02 => {
            // eth1-address and compounding formats: bytes 1–11 must be zero.
            for &b in &wc[1..=11] {
                if b != 0x00 {
                    return Err(TxError::InvalidWcFormat(wc[0]));
                }
            }
        }
        other => {
            return Err(TxError::InvalidWcPrefix(other));
        }
    }

    Ok(())
}

/// Checks that all gas/fee/nonce fields are explicitly set when no RPC is
/// provided. Called by `build_unsigned` before field resolution when
/// `cfg.rpc == None`. The check order (fee → priority fee → nonce → gas limit)
/// mirrors the Go reference so the first missing field wins.
pub fn validate_static_config(cfg: &BuildConfig) -> Result<(), TxError> {
    if cfg.max_fee_per_gas.is_none() {
        return Err(TxError::MissingFeeStatic);
    }
    if cfg.max_priority_fee_per_gas.is_none() {
        return Err(TxError::MissingPriorityFeeStatic);
    }
    if cfg.nonce.is_none() {
        return Err(TxError::MissingNonceStatic);
    }
    if cfg.gas_limit == 0 {
        return Err(TxError::MissingGasLimitStatic);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_valid_config, make_valid_entry};
    use ethernal_core::network::{self, Network};

    // Go: TestValidate_Baseline
    #[test]
    fn validate_baseline() {
        let cfg = make_valid_config();
        assert!(validate(&make_valid_entry(), &cfg).is_ok());
    }

    // Go: TestValidate_WCPrefix_0x00_Valid
    #[test]
    fn validate_wc_prefix_0x00_valid() {
        let mut e = make_valid_entry();
        e.withdrawal_credentials = [0u8; 32];
        e.withdrawal_credentials[0] = 0x00;
        e.withdrawal_credentials[31] = 0x01;
        let cfg = make_valid_config();
        assert!(validate(&e, &cfg).is_ok());
    }

    // Go: TestValidate_WCPrefix_0x01_Valid
    #[test]
    fn validate_wc_prefix_0x01_valid() {
        let mut e = make_valid_entry();
        e.withdrawal_credentials = [0u8; 32];
        e.withdrawal_credentials[0] = 0x01;
        for i in 12..32 {
            e.withdrawal_credentials[i] = 0x22;
        }
        let cfg = make_valid_config();
        assert!(validate(&e, &cfg).is_ok());
    }

    // Go: TestValidate_WCPrefix_0x02_Valid
    #[test]
    fn validate_wc_prefix_0x02_valid() {
        let mut e = make_valid_entry();
        e.withdrawal_credentials = [0u8; 32];
        e.withdrawal_credentials[0] = 0x02;
        for i in 12..32 {
            e.withdrawal_credentials[i] = 0x33;
        }
        let cfg = make_valid_config();
        assert!(validate(&e, &cfg).is_ok());
    }

    // Go: TestValidate_Table
    #[test]
    fn validate_table() {
        let params = network::lookup(Network::Holesky);

        // chain ID zero
        {
            let e = make_valid_entry();
            let mut cfg = make_valid_config();
            cfg.network_params.chain_id = 0;
            assert!(matches!(
                validate(&e, &cfg),
                Err(TxError::UnconfiguredChainId)
            ));
        }
        // wrong amount
        {
            let mut e = make_valid_entry();
            e.amount = 1_000_000_000;
            let cfg = make_valid_config();
            assert!(matches!(validate(&e, &cfg), Err(TxError::InvalidAmount(_))));
        }
        // all-zero pubkey
        {
            let mut e = make_valid_entry();
            e.pubkey = [0u8; 48];
            let cfg = make_valid_config();
            assert!(matches!(validate(&e, &cfg), Err(TxError::ZeroPubkey)));
        }
        // all-zero signature
        {
            let mut e = make_valid_entry();
            e.signature = [0u8; 96];
            let cfg = make_valid_config();
            assert!(matches!(validate(&e, &cfg), Err(TxError::ZeroSignature)));
        }
        // all-zero deposit data root
        {
            let mut e = make_valid_entry();
            e.deposit_data_root = [0u8; 32];
            let cfg = make_valid_config();
            assert!(matches!(validate(&e, &cfg), Err(TxError::ZeroDepositRoot)));
        }
        // WC prefix 0x03 (invalid)
        {
            let mut e = make_valid_entry();
            e.withdrawal_credentials = [0u8; 32];
            e.withdrawal_credentials[0] = 0x03;
            let cfg = make_valid_config();
            assert!(matches!(
                validate(&e, &cfg),
                Err(TxError::InvalidWcPrefix(0x03))
            ));
        }
        // WC prefix 0x01 with non-zero padding at index 5
        {
            let mut e = make_valid_entry();
            e.withdrawal_credentials = [0u8; 32];
            e.withdrawal_credentials[0] = 0x01;
            e.withdrawal_credentials[5] = 0xFF;
            let cfg = make_valid_config();
            assert!(matches!(
                validate(&e, &cfg),
                Err(TxError::InvalidWcFormat(0x01))
            ));
        }
        // WC prefix 0x02 with non-zero padding at index 5
        {
            let mut e = make_valid_entry();
            e.withdrawal_credentials = [0u8; 32];
            e.withdrawal_credentials[0] = 0x02;
            e.withdrawal_credentials[5] = 0xFF;
            let cfg = make_valid_config();
            assert!(matches!(
                validate(&e, &cfg),
                Err(TxError::InvalidWcFormat(0x02))
            ));
        }

        // Keep `params` referenced to mirror the Go table's shared config.
        let _ = params.chain_id;
    }
}
