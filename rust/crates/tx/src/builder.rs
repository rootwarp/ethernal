//! Unsigned EIP-1559 deposit transaction construction.
//!
//! Ported from `go/internal/tx/builder.go` and the builder-facing half of
//! `go/internal/tx/interface.go`.

use eth_deposit_core::cancel::CancelToken;
use eth_deposit_core::deposit::Entry;
use eth_deposit_core::network::Params;

use crate::abi::pack_deposit;
use crate::errors::TxError;
use crate::rpc_client::RpcClientError;
use crate::types::UnsignedTx;
use crate::validation::{validate, validate_static_config};

/// 32 ETH expressed in wei (32 × 10^18 = 0x1bc16d674ec800000). Fits in a u128.
const VALUE_32ETH_WEI: u128 = 32_000_000_000_000_000_000;

/// The minimal call descriptor used by [`EthRpc::estimate_gas`].
#[derive(Debug, Clone)]
pub struct CallMsg {
    pub from: [u8; 20],
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
}

/// The minimal Ethereum RPC surface the builder needs to resolve gas, fees,
/// nonce, and chain ID. `None` in [`BuildConfig::rpc`] means static-only mode.
///
/// Divergence from Go's `EthRPC`: the tip/base-fee accessors return `u128`
/// (wei) rather than `*big.Int`, and `chain_id` returns `u64` rather than
/// `*big.Int`. There is no `Close` method — the RPC transport is dropped
/// normally.
pub trait EthRpc {
    /// Returns the priority fee suggestion (`eth_maxPriorityFeePerGas`).
    fn suggest_gas_tip_cap(&self) -> Result<u128, RpcClientError>;
    /// Returns the latest block's `baseFeePerGas` in wei.
    fn block_base_fee(&self) -> Result<u128, RpcClientError>;
    /// Returns the next (pending) nonce for the given address.
    fn pending_nonce_at(&self, account: [u8; 20]) -> Result<u64, RpcClientError>;
    /// Estimates the gas required for a call.
    fn estimate_gas(&self, msg: &CallMsg) -> Result<u64, RpcClientError>;
    /// Returns the chain ID reported by the node.
    fn chain_id(&self) -> Result<u64, RpcClientError>;
}

/// Carries the parameters needed to build an unsigned transaction.
///
/// Static mode (`rpc == None`): `gas_limit`, `max_fee_per_gas`,
/// `max_priority_fee_per_gas`, and `nonce` must all be set; missing any returns
/// a `Missing*Static` error.
///
/// RPC mode (`rpc == Some`): any `None`/zero field is resolved from the RPC.
/// `from` is required when `nonce` is `None` so the pending nonce can be
/// fetched.
pub struct BuildConfig<'a> {
    /// Provides the chain ID and the deposit contract address.
    pub network_params: Params,

    /// The live RPC client used to resolve missing gas/fee/nonce values. `None`
    /// means static-only mode.
    pub rpc: Option<&'a dyn EthRpc>,

    /// The sender address. Required when `rpc` is set and `nonce` is `None`.
    pub from: [u8; 20],

    /// The EIP-1559 gas limit. `0` with `rpc` set triggers `estimate_gas`.
    pub gas_limit: u64,

    /// The EIP-1559 maximum total fee per gas in wei. `None` with `rpc` set
    /// triggers computation from `base_fee` + `tip`.
    pub max_fee_per_gas: Option<u128>,

    /// The EIP-1559 miner tip per gas in wei. `None` with `rpc` set triggers
    /// `suggest_gas_tip_cap`.
    pub max_priority_fee_per_gas: Option<u128>,

    /// The sender nonce. `None` with `rpc` set triggers `pending_nonce_at`.
    /// `Option` distinguishes "explicit 0" from "not set".
    pub nonce: Option<u64>,
}

/// Resolved gas/fee/nonce values for a single unsigned tx.
struct Resolved {
    gas_limit: u64,
    max_fee: u128,
    tip: u128,
    nonce: u64,
}

/// The concrete unsigned-transaction builder.
#[derive(Debug, Default, Clone, Copy)]
pub struct Builder;

impl Builder {
    /// Creates a new `Builder`.
    pub fn new() -> Self {
        Builder
    }

    /// Constructs an unsigned EIP-1559 deposit transaction.
    ///
    /// Resolution order per field:
    ///  1. If the field is explicitly set in `cfg`, it wins.
    ///  2. If `cfg.rpc` is `Some` and the field is unset, resolve from RPC.
    ///  3. If `cfg.rpc` is `None` and the field is unset, return a
    ///     `Missing*Static` error.
    pub fn build_unsigned(
        &self,
        entry: &Entry,
        cfg: &BuildConfig,
        cancel: &CancelToken,
    ) -> Result<UnsignedTx, TxError> {
        if cancel.is_cancelled() {
            return Err(TxError::Cancelled);
        }

        validate(entry, cfg)?;

        let calldata = pack_deposit(
            &entry.pubkey,
            &entry.withdrawal_credentials,
            &entry.signature,
            &entry.deposit_data_root,
        );

        let resolved = resolve_fields(cfg, &calldata, cancel)?;

        Ok(UnsignedTx {
            chain_id: cfg.network_params.chain_id,
            to: cfg.network_params.deposit_contract_address_hex(),
            from: String::new(),
            value: format!("0x{:x}", VALUE_32ETH_WEI),
            data: format!("0x{}", hex::encode(&calldata)),
            gas: resolved.gas_limit,
            max_fee_per_gas: format!("0x{:x}", resolved.max_fee),
            max_priority_fee_per_gas: format!("0x{:x}", resolved.tip),
            nonce: resolved.nonce,
            tx_type: "0x2".to_string(),
        })
    }
}

/// Determines the final gas limit, max fee, priority fee, and nonce. Dispatches
/// to the static path (all fields must be provided) or the RPC path (missing
/// values are fetched and the chain ID is optionally verified).
fn resolve_fields(
    cfg: &BuildConfig,
    calldata: &[u8],
    cancel: &CancelToken,
) -> Result<Resolved, TxError> {
    match cfg.rpc {
        None => resolve_static(cfg),
        Some(rpc) => resolve_rpc(cfg, rpc, calldata, cancel),
    }
}

fn resolve_static(cfg: &BuildConfig) -> Result<Resolved, TxError> {
    validate_static_config(cfg)?;
    Ok(Resolved {
        gas_limit: cfg.gas_limit,
        max_fee: cfg
            .max_fee_per_gas
            .expect("checked by validate_static_config"),
        tip: cfg
            .max_priority_fee_per_gas
            .expect("checked by validate_static_config"),
        nonce: cfg.nonce.expect("checked by validate_static_config"),
    })
}

fn resolve_rpc(
    cfg: &BuildConfig,
    rpc: &dyn EthRpc,
    calldata: &[u8],
    cancel: &CancelToken,
) -> Result<Resolved, TxError> {
    // Optional: verify chain ID matches. Call errors are silently ignored
    // (warn-and-continue), an Ok(0) skips the check, and a nonzero mismatch is
    // a configuration failure.
    if cancel.is_cancelled() {
        return Err(TxError::Cancelled);
    }
    if let Ok(rpc_chain_id) = rpc.chain_id() {
        if rpc_chain_id != 0 && rpc_chain_id != cfg.network_params.chain_id {
            return Err(TxError::ChainIdMismatch {
                rpc: rpc_chain_id,
                configured: cfg.network_params.chain_id,
            });
        }
    }

    // Resolve priority fee (tip).
    let tip = match cfg.max_priority_fee_per_gas {
        Some(t) => t,
        None => {
            if cancel.is_cancelled() {
                return Err(TxError::Cancelled);
            }
            rpc.suggest_gas_tip_cap()
                .map_err(|e| TxError::RpcEstimation {
                    call: "SuggestGasTipCap",
                    source: Box::new(e),
                })?
        }
    };

    // Resolve max fee = 2*baseFee + tip (EIP-1559 standard formula).
    let max_fee = match cfg.max_fee_per_gas {
        Some(m) => m,
        None => {
            if cancel.is_cancelled() {
                return Err(TxError::Cancelled);
            }
            let base_fee = rpc.block_base_fee().map_err(|e| TxError::RpcEstimation {
                call: "BlockBaseFee",
                source: Box::new(e),
            })?;
            2 * base_fee + tip
        }
    };

    // Resolve nonce.
    let nonce = match cfg.nonce {
        Some(n) => n,
        None => {
            if cfg.from == [0u8; 20] {
                return Err(TxError::MissingFromForNonce);
            }
            if cancel.is_cancelled() {
                return Err(TxError::Cancelled);
            }
            rpc.pending_nonce_at(cfg.from)
                .map_err(|e| TxError::RpcEstimation {
                    call: "PendingNonceAt",
                    source: Box::new(e),
                })?
        }
    };

    // Resolve gas limit.
    let gas_limit = if cfg.gas_limit != 0 {
        cfg.gas_limit
    } else {
        if cancel.is_cancelled() {
            return Err(TxError::Cancelled);
        }
        let msg = CallMsg {
            from: cfg.from,
            to: cfg.network_params.deposit_contract_address,
            value: VALUE_32ETH_WEI,
            data: calldata.to_vec(),
        };
        let estimate = rpc.estimate_gas(&msg).map_err(|e| TxError::RpcEstimation {
            call: "EstimateGas",
            source: Box::new(e),
        })?;
        // 20% safety margin: estimate * 6 / 5.
        estimate * 6 / 5
    };

    Ok(Resolved {
        gas_limit,
        max_fee,
        tip,
        nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{make_mock_rpc, make_valid_config, make_valid_entry};
    use eth_deposit_core::network::{self, Network};

    fn holesky_params() -> Params {
        network::lookup(Network::Holesky)
    }

    // NOT PORTED: TestBuilderSatisfiesTxBuilder / TestBuilder_BuildUnsigned_NilContext
    // — the Rust surface has no `TxBuilder` trait and no nil-context concept
    // (a CancelToken is always supplied).

    // Go: TestBuilder_BuildUnsigned_Success
    #[test]
    fn build_unsigned_success() {
        let entry = make_valid_entry();
        let params = holesky_params();
        let cfg = BuildConfig {
            network_params: params.clone(),
            rpc: None,
            from: [0u8; 20],
            gas_limit: 250_000,
            max_fee_per_gas: Some(20_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce: Some(3),
        };
        let tx = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .expect("build_unsigned");
        assert_eq!(tx.chain_id, params.chain_id);
        assert_eq!(
            tx.to.to_lowercase(),
            params.deposit_contract_address_hex().to_lowercase()
        );
        assert_eq!(tx.value, "0x1bc16d674ec800000");
        assert!(tx.data.starts_with("0x22895118"));
        assert_eq!(tx.gas, 250_000);
        assert_eq!(tx.tx_type, "0x2");
        assert_eq!(tx.nonce, 3);
    }

    // Go: TestBuilder_BuildUnsigned_NilNonce_StaticMode_ReturnsError
    #[test]
    fn build_unsigned_nil_nonce_static_mode_returns_error() {
        let entry = make_valid_entry();
        let cfg = BuildConfig {
            network_params: holesky_params(),
            rpc: None,
            from: [0u8; 20],
            gas_limit: 250_000,
            max_fee_per_gas: Some(1),
            max_priority_fee_per_gas: Some(1),
            nonce: None,
        };
        let err = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap_err();
        assert!(matches!(err, TxError::MissingNonceStatic));
    }

    // Go: TestBuilder_BuildUnsigned_NilMaxFeePerGas_StaticMode
    #[test]
    fn build_unsigned_nil_max_fee_static_mode() {
        let entry = make_valid_entry();
        let cfg = BuildConfig {
            network_params: holesky_params(),
            rpc: None,
            from: [0u8; 20],
            gas_limit: 250_000,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: Some(1),
            nonce: Some(0),
        };
        let err = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap_err();
        assert!(matches!(err, TxError::MissingFeeStatic));
    }

    // Go: TestBuilder_BuildUnsigned_NilMaxPriorityFeePerGas_StaticMode
    #[test]
    fn build_unsigned_nil_max_priority_fee_static_mode() {
        let entry = make_valid_entry();
        let cfg = BuildConfig {
            network_params: holesky_params(),
            rpc: None,
            from: [0u8; 20],
            gas_limit: 250_000,
            max_fee_per_gas: Some(1),
            max_priority_fee_per_gas: None,
            nonce: Some(0),
        };
        let err = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap_err();
        assert!(matches!(err, TxError::MissingPriorityFeeStatic));
    }

    // Go: TestBuilder_BuildUnsigned_CancelledContext
    #[test]
    fn build_unsigned_cancelled() {
        let entry = make_valid_entry();
        let cfg = BuildConfig {
            network_params: holesky_params(),
            rpc: None,
            from: [0u8; 20],
            gas_limit: 250_000,
            max_fee_per_gas: Some(1),
            max_priority_fee_per_gas: Some(1),
            nonce: Some(0),
        };
        let cancel = CancelToken::new();
        cancel.cancel();
        let err = Builder::new()
            .build_unsigned(&entry, &cfg, &cancel)
            .unwrap_err();
        assert!(matches!(err, TxError::Cancelled));
    }

    // Go: TestBuilder_BuildUnsigned_WrongAmount
    #[test]
    fn build_unsigned_wrong_amount() {
        let mut entry = make_valid_entry();
        entry.amount = 1_000_000_000;
        let cfg = BuildConfig {
            network_params: holesky_params(),
            rpc: None,
            from: [0u8; 20],
            gas_limit: 250_000,
            max_fee_per_gas: Some(1),
            max_priority_fee_per_gas: Some(1),
            nonce: Some(0),
        };
        let err = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap_err();
        assert!(matches!(err, TxError::InvalidAmount(1_000_000_000)));
    }

    // Go: TestBuilder_BuildUnsigned_DataLength
    #[test]
    fn build_unsigned_data_length() {
        let entry = make_valid_entry();
        let cfg = BuildConfig {
            network_params: holesky_params(),
            rpc: None,
            from: [0u8; 20],
            gas_limit: 250_000,
            max_fee_per_gas: Some(1),
            max_priority_fee_per_gas: Some(1),
            nonce: Some(0),
        };
        let tx = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap();
        // "0x" + 420 bytes * 2 hex chars = 2 + 840 = 842 chars.
        assert_eq!(tx.data.len(), 842);
    }

    // Go: TestBuilder_BuildUnsigned_RoundTrip
    #[test]
    fn build_unsigned_round_trip() {
        let entry = make_valid_entry();
        let cfg = BuildConfig {
            network_params: holesky_params(),
            rpc: None,
            from: [0u8; 20],
            gas_limit: 250_000,
            max_fee_per_gas: Some(1),
            max_priority_fee_per_gas: Some(1),
            nonce: Some(0),
        };
        let tx = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap();

        let raw = hex::decode(tx.data.trim_start_matches("0x")).unwrap();
        assert_eq!(raw.len(), 420);

        // deposit_data_root in head slot 3.
        assert_eq!(&raw[4 + 96..4 + 128], &entry.deposit_data_root);

        let tail = &raw[4..];
        assert_eq!(&tail[128 + 32..128 + 32 + 48], &entry.pubkey);
        assert_eq!(
            &tail[224 + 32..224 + 32 + 32],
            &entry.withdrawal_credentials
        );
        assert_eq!(&tail[288 + 32..288 + 32 + 96], &entry.signature);
    }

    // Go: TestBuilder_BuildUnsigned_ChainIDMatchesNetwork
    #[test]
    fn build_unsigned_chain_id_matches_network() {
        for n in Network::ALL {
            let params = network::lookup(n);
            let mut e = make_valid_entry();
            e.network_name = n.to_string();
            let cfg = BuildConfig {
                network_params: params.clone(),
                rpc: None,
                from: [0u8; 20],
                gas_limit: 250_000,
                max_fee_per_gas: Some(1),
                max_priority_fee_per_gas: Some(1),
                nonce: Some(0),
            };
            let tx = Builder::new()
                .build_unsigned(&e, &cfg, &CancelToken::new())
                .unwrap_or_else(|err| panic!("network {n}: {err}"));
            assert_eq!(tx.chain_id, params.chain_id, "network {n}");
        }
    }

    // Go: TestBuilder_BuildUnsigned_ValidationWiredIn
    #[test]
    fn build_unsigned_validation_wired_in() {
        let mut entry = make_valid_entry();
        entry.pubkey = [0u8; 48];
        let cfg = make_valid_config();
        let err = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap_err();
        assert!(matches!(err, TxError::ZeroPubkey));
    }

    // Go: TestBuilder_BuildUnsigned_StaticMode_MissingGasLimit
    #[test]
    fn build_unsigned_static_mode_missing_gas_limit() {
        let entry = make_valid_entry();
        let cfg = BuildConfig {
            network_params: holesky_params(),
            rpc: None,
            from: [0u8; 20],
            gas_limit: 0,
            max_fee_per_gas: Some(1),
            max_priority_fee_per_gas: Some(1),
            nonce: Some(0),
        };
        let err = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap_err();
        assert!(matches!(err, TxError::MissingGasLimitStatic));
    }

    // ---- RPC-mode tests ----

    fn from_with_first(b: u8) -> [u8; 20] {
        let mut f = [0u8; 20];
        f[0] = b;
        f
    }

    // Go: TestBuilder_BuildUnsigned_RPCMode_AllFromRPC
    #[test]
    fn build_unsigned_rpc_mode_all_from_rpc() {
        let entry = make_valid_entry();
        let params = holesky_params();
        let rpc = make_mock_rpc(params.chain_id);
        let cfg = BuildConfig {
            network_params: params,
            rpc: Some(&rpc),
            from: from_with_first(0x01),
            gas_limit: 0,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None,
        };
        let tx = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap();
        assert_eq!(tx.nonce, 7);
        assert_eq!(tx.gas, 120_000); // 100_000 * 6 / 5
        assert_eq!(tx.max_fee_per_gas, format!("0x{:x}", 22_000_000_000u128));
        assert_eq!(
            tx.max_priority_fee_per_gas,
            format!("0x{:x}", 2_000_000_000u128)
        );
    }

    // Go: TestBuilder_BuildUnsigned_RPCMode_StaticFeeWins
    #[test]
    fn build_unsigned_rpc_mode_static_fee_wins() {
        let entry = make_valid_entry();
        let params = holesky_params();
        let mut rpc = make_mock_rpc(params.chain_id);
        // The RPC fee methods must NOT be called when static values are set.
        rpc.suggest_gas_tip_cap_fn =
            Some(Box::new(|| panic!("SuggestGasTipCap must not be called")));
        rpc.block_base_fee_fn = Some(Box::new(|| panic!("BlockBaseFee must not be called")));

        let cfg = BuildConfig {
            network_params: params,
            rpc: Some(&rpc),
            from: from_with_first(0x02),
            gas_limit: 200_000,
            max_fee_per_gas: Some(99_000_000_000),
            max_priority_fee_per_gas: Some(3_000_000_000),
            nonce: Some(5),
        };
        let tx = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap();
        assert_eq!(tx.max_fee_per_gas, format!("0x{:x}", 99_000_000_000u128));
        assert_eq!(tx.gas, 200_000);
        assert_eq!(tx.nonce, 5);
    }

    // Go: TestBuilder_BuildUnsigned_RPCMode_ChainIDMismatch
    #[test]
    fn build_unsigned_rpc_mode_chain_id_mismatch() {
        let entry = make_valid_entry();
        let params = holesky_params();
        let rpc = make_mock_rpc(1); // mainnet, not holesky
        let cfg = BuildConfig {
            network_params: params,
            rpc: Some(&rpc),
            from: from_with_first(0x03),
            gas_limit: 0,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None,
        };
        let err = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap_err();
        assert!(matches!(err, TxError::ChainIdMismatch { .. }));
    }

    // Go: TestBuilder_BuildUnsigned_RPCMode_ChainIDCallError_Ignored
    #[test]
    fn build_unsigned_rpc_mode_chain_id_call_error_ignored() {
        let entry = make_valid_entry();
        let params = holesky_params();
        let mut rpc = make_mock_rpc(params.chain_id);
        rpc.chain_id_fn = Some(Box::new(|| {
            Err(RpcClientError::new("eth_chainId", "ChainID RPC error"))
        }));
        let cfg = BuildConfig {
            network_params: params,
            rpc: Some(&rpc),
            from: from_with_first(0x04),
            gas_limit: 0,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None,
        };
        // A ChainID call error is silently ignored — the build should succeed.
        assert!(Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .is_ok());
    }

    // Go: TestBuilder_BuildUnsigned_RPCMode_ZeroFrom_NilNonce
    #[test]
    fn build_unsigned_rpc_mode_zero_from_nil_nonce() {
        let entry = make_valid_entry();
        let params = holesky_params();
        let rpc = make_mock_rpc(params.chain_id);
        let cfg = BuildConfig {
            network_params: params,
            rpc: Some(&rpc),
            from: [0u8; 20],
            gas_limit: 0,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None,
        };
        let err = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap_err();
        assert!(matches!(err, TxError::MissingFromForNonce));
    }

    // Go: TestBuilder_BuildUnsigned_RPCMode_EstimateGasError
    #[test]
    fn build_unsigned_rpc_mode_estimate_gas_error() {
        let entry = make_valid_entry();
        let params = holesky_params();
        let mut rpc = make_mock_rpc(params.chain_id);
        rpc.estimate_gas_fn = Some(Box::new(|_| {
            Err(RpcClientError::new(
                "eth_estimateGas",
                "estimate gas RPC error",
            ))
        }));
        let cfg = BuildConfig {
            network_params: params,
            rpc: Some(&rpc),
            from: from_with_first(0x05),
            gas_limit: 0,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None,
        };
        let err = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap_err();
        assert!(err.to_string().contains("EstimateGas"), "got: {err}");
        assert!(matches!(err, TxError::RpcEstimation { .. }));
    }

    // Go: TestBuilder_BuildUnsigned_RPCMode_GasMargin
    #[test]
    fn build_unsigned_rpc_mode_gas_margin() {
        let entry = make_valid_entry();
        let params = holesky_params();
        let mut rpc = make_mock_rpc(params.chain_id);
        rpc.estimate_gas_fn = Some(Box::new(|_| Ok(100_000)));
        let cfg = BuildConfig {
            network_params: params,
            rpc: Some(&rpc),
            from: from_with_first(0x06),
            gas_limit: 0,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None,
        };
        let tx = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap();
        assert_eq!(tx.gas, 120_000);
    }

    // Go: TestBuilder_BuildUnsigned_RPCMode_MaxFeeFormula
    #[test]
    fn build_unsigned_rpc_mode_max_fee_formula() {
        let entry = make_valid_entry();
        let params = holesky_params();
        let mut rpc = make_mock_rpc(params.chain_id);
        rpc.block_base_fee_fn = Some(Box::new(|| Ok(10_000_000_000)));
        rpc.suggest_gas_tip_cap_fn = Some(Box::new(|| Ok(2_000_000_000)));
        let cfg = BuildConfig {
            network_params: params,
            rpc: Some(&rpc),
            from: from_with_first(0x07),
            gas_limit: 200_000,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: Some(0),
        };
        let tx = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap();
        // 2*10 + 2 = 22 gwei.
        assert_eq!(tx.max_fee_per_gas, format!("0x{:x}", 22_000_000_000u128));
    }

    // Go: TestBuilder_BuildUnsigned_RPCMode_SuggestGasTipCapError
    #[test]
    fn build_unsigned_rpc_mode_suggest_gas_tip_cap_error() {
        let entry = make_valid_entry();
        let params = holesky_params();
        let mut rpc = make_mock_rpc(params.chain_id);
        rpc.suggest_gas_tip_cap_fn = Some(Box::new(|| {
            Err(RpcClientError::new(
                "eth_maxPriorityFeePerGas",
                "tip cap rpc error",
            ))
        }));
        let cfg = BuildConfig {
            network_params: params,
            rpc: Some(&rpc),
            from: from_with_first(0x08),
            gas_limit: 0,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None,
        };
        let err = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap_err();
        assert!(err.to_string().contains("SuggestGasTipCap"), "got: {err}");
        assert!(matches!(err, TxError::RpcEstimation { .. }));
    }

    // Go: TestBuilder_BuildUnsigned_RPCMode_BlockBaseFeeError
    #[test]
    fn build_unsigned_rpc_mode_block_base_fee_error() {
        let entry = make_valid_entry();
        let params = holesky_params();
        let mut rpc = make_mock_rpc(params.chain_id);
        rpc.block_base_fee_fn = Some(Box::new(|| {
            Err(RpcClientError::new(
                "eth_getBlockByNumber",
                "base fee rpc error",
            ))
        }));
        let cfg = BuildConfig {
            network_params: params,
            rpc: Some(&rpc),
            from: from_with_first(0x09),
            gas_limit: 200_000,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: Some(0),
        };
        let err = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap_err();
        assert!(err.to_string().contains("BlockBaseFee"), "got: {err}");
        assert!(matches!(err, TxError::RpcEstimation { .. }));
    }

    // Go: TestBuilder_BuildUnsigned_RPCMode_PendingNonceAtError
    #[test]
    fn build_unsigned_rpc_mode_pending_nonce_at_error() {
        let entry = make_valid_entry();
        let params = holesky_params();
        let mut rpc = make_mock_rpc(params.chain_id);
        rpc.pending_nonce_at_fn = Some(Box::new(|_| {
            Err(RpcClientError::new(
                "eth_getTransactionCount",
                "nonce rpc error",
            ))
        }));
        let cfg = BuildConfig {
            network_params: params,
            rpc: Some(&rpc),
            from: from_with_first(0x0a),
            gas_limit: 200_000,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None,
        };
        let err = Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .unwrap_err();
        assert!(err.to_string().contains("PendingNonceAt"), "got: {err}");
        assert!(matches!(err, TxError::RpcEstimation { .. }));
    }

    // Go: TestBuilder_BuildUnsigned_ConfigErrors_NotRPCEstimation
    #[test]
    fn build_unsigned_config_errors_not_rpc_estimation() {
        let entry = make_valid_entry();
        let params = holesky_params();

        // Chain-ID mismatch is an exit-2 config error, not an exit-5 estimation.
        let rpc_mismatch = make_mock_rpc(1);
        let mismatch_err = Builder::new()
            .build_unsigned(
                &entry,
                &BuildConfig {
                    network_params: params.clone(),
                    rpc: Some(&rpc_mismatch),
                    from: from_with_first(0x0b),
                    gas_limit: 0,
                    max_fee_per_gas: None,
                    max_priority_fee_per_gas: None,
                    nonce: None,
                },
                &CancelToken::new(),
            )
            .unwrap_err();
        assert!(matches!(mismatch_err, TxError::ChainIdMismatch { .. }));
        assert!(!matches!(mismatch_err, TxError::RpcEstimation { .. }));

        // Missing From with nil Nonce is also a config error.
        let rpc_ok = make_mock_rpc(params.chain_id);
        let missing_from_err = Builder::new()
            .build_unsigned(
                &entry,
                &BuildConfig {
                    network_params: params,
                    rpc: Some(&rpc_ok),
                    from: [0u8; 20],
                    gas_limit: 0,
                    max_fee_per_gas: None,
                    max_priority_fee_per_gas: None,
                    nonce: None,
                },
                &CancelToken::new(),
            )
            .unwrap_err();
        assert!(matches!(missing_from_err, TxError::MissingFromForNonce));
        assert!(!matches!(missing_from_err, TxError::RpcEstimation { .. }));
    }

    // ---- golden fixture tests ----

    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/phase2/holesky/deposit_data_single.json"
    );
    const GOLDEN: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/phase2/holesky/unsigned_tx_golden.json"
    );

    fn build_from_fixture() -> UnsignedTx {
        let raw = std::fs::read(FIXTURE).expect("read fixture");
        let entries = eth_deposit_core::deposit::entries_from_json(&raw).expect("parse fixture");
        let entry = entries.into_iter().next().expect("fixture has an entry");
        let cfg = BuildConfig {
            network_params: holesky_params(),
            rpc: None,
            from: [0u8; 20],
            gas_limit: 250_000,
            max_fee_per_gas: Some(20_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce: Some(0),
        };
        Builder::new()
            .build_unsigned(&entry, &cfg, &CancelToken::new())
            .expect("build_unsigned")
    }

    // Go: TestGolden_Phase2Holesky_DecodeAndVerify
    #[test]
    fn golden_phase2_holesky_decode_and_verify() {
        let raw_fixture = std::fs::read(FIXTURE).expect("read fixture");
        let entries =
            eth_deposit_core::deposit::entries_from_json(&raw_fixture).expect("parse fixture");
        let entry = entries.into_iter().next().unwrap();

        let tx = build_from_fixture();
        let calldata = hex::decode(tx.data.trim_start_matches("0x")).unwrap();
        assert_eq!(calldata.len(), 420);

        assert_eq!(&calldata[0..4], &[0x22, 0x89, 0x51, 0x18], "selector");
        assert_eq!(&calldata[4 + 96..4 + 128], &entry.deposit_data_root);

        let tail = &calldata[4..];
        assert_eq!(&tail[128 + 32..128 + 32 + 48], &entry.pubkey);
        assert_eq!(
            &tail[224 + 32..224 + 32 + 32],
            &entry.withdrawal_credentials
        );
        assert_eq!(&tail[288 + 32..288 + 32 + 96], &entry.signature);
    }

    // New (per R3-1 acceptance): builder output must equal the unsigned-tx golden
    // JSON byte-for-byte.
    #[test]
    fn golden_phase2_holesky_byte_identity() {
        let tx = build_from_fixture();
        let mut serialized = serde_json::to_vec_pretty(&tx).expect("serialize");
        serialized.push(b'\n');
        let golden = std::fs::read(GOLDEN).expect("read golden");
        assert_eq!(
            String::from_utf8_lossy(&serialized),
            String::from_utf8_lossy(&golden),
            "unsigned tx must match golden byte-for-byte"
        );
    }
}
