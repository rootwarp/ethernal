//! Shared white-box test fixtures for the tx crate. Compiled only under `test`.
//!
//! Mirrors the Go test helpers spread across `builder_test.go`,
//! `validation_test.go`, `helpers_test.go`, and `rpc_mock_test.go`.

use ethernal_core::deposit::Entry;
use ethernal_core::network::{self, Network};

use crate::builder::{BuildConfig, CallMsg, EthRpc};
use crate::rpc_client::RpcClientError;

/// Go: `makeValidEntry` — a `deposit::Entry` that passes every `validate` check.
/// WithdrawalCredentials use the 0x01 format: 0x01 || 11 zero bytes || 20-byte
/// address.
pub fn make_valid_entry() -> Entry {
    let mut e = Entry {
        pubkey: [0xab; 48],
        signature: [0xcd; 96],
        deposit_data_root: [0xef; 32],
        amount: 32_000_000_000,
        network_name: "holesky".to_string(),
        ..Entry::default()
    };
    e.withdrawal_credentials[0] = 0x01;
    // bytes 1–11 remain zero; bytes 12–31 are a non-zero eth1 address.
    for i in 12..32 {
        e.withdrawal_credentials[i] = 0x11;
    }
    e
}

/// Go: `makeValidConfig` — a static-mode `BuildConfig` that passes every
/// `validate` check. `nonce` is left unset (as in Go), which is irrelevant to
/// the validation-only call sites.
pub fn make_valid_config() -> BuildConfig<'static> {
    BuildConfig {
        network_params: network::lookup(Network::Holesky),
        rpc: None,
        from: [0u8; 20],
        gas_limit: 250_000,
        max_fee_per_gas: Some(20_000_000_000),
        max_priority_fee_per_gas: Some(1_000_000_000),
        nonce: None,
    }
}

type TipFn = Box<dyn Fn() -> Result<u128, RpcClientError>>;
type BaseFeeFn = Box<dyn Fn() -> Result<u128, RpcClientError>>;
type NonceFn = Box<dyn Fn([u8; 20]) -> Result<u64, RpcClientError>>;
type EstimateFn = Box<dyn Fn(&CallMsg) -> Result<u64, RpcClientError>>;
type ChainIdFn = Box<dyn Fn() -> Result<u64, RpcClientError>>;

/// Go: `mockRPC` — a test double for [`EthRpc`] using the function-field
/// pattern. Set each `*_fn` to control per-call behavior; an unset field panics
/// when called, matching the Go mock.
pub struct MockRpc {
    pub suggest_gas_tip_cap_fn: Option<TipFn>,
    pub block_base_fee_fn: Option<BaseFeeFn>,
    pub pending_nonce_at_fn: Option<NonceFn>,
    pub estimate_gas_fn: Option<EstimateFn>,
    pub chain_id_fn: Option<ChainIdFn>,
}

impl EthRpc for MockRpc {
    fn suggest_gas_tip_cap(&self) -> Result<u128, RpcClientError> {
        (self
            .suggest_gas_tip_cap_fn
            .as_ref()
            .expect("MockRpc.suggest_gas_tip_cap not set"))()
    }

    fn block_base_fee(&self) -> Result<u128, RpcClientError> {
        (self
            .block_base_fee_fn
            .as_ref()
            .expect("MockRpc.block_base_fee not set"))()
    }

    fn pending_nonce_at(&self, account: [u8; 20]) -> Result<u64, RpcClientError> {
        (self
            .pending_nonce_at_fn
            .as_ref()
            .expect("MockRpc.pending_nonce_at not set"))(account)
    }

    fn estimate_gas(&self, msg: &CallMsg) -> Result<u64, RpcClientError> {
        (self
            .estimate_gas_fn
            .as_ref()
            .expect("MockRpc.estimate_gas not set"))(msg)
    }

    fn chain_id(&self) -> Result<u64, RpcClientError> {
        (self.chain_id_fn.as_ref().expect("MockRpc.chain_id not set"))()
    }
}

/// Go: `makeMockRPC` — a `MockRpc` pre-configured with typical happy-path
/// values: tip 2 gwei, base fee 10 gwei, nonce 7, gas estimate 100 000, and the
/// given chain ID.
pub fn make_mock_rpc(chain_id: u64) -> MockRpc {
    MockRpc {
        suggest_gas_tip_cap_fn: Some(Box::new(|| Ok(2_000_000_000))),
        block_base_fee_fn: Some(Box::new(|| Ok(10_000_000_000))),
        pending_nonce_at_fn: Some(Box::new(|_| Ok(7))),
        estimate_gas_fn: Some(Box::new(|_| Ok(100_000))),
        chain_id_fn: Some(Box::new(move || Ok(chain_id))),
    }
}
