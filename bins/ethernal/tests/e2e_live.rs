//! Live e2e tier — real EVM via the Foundry `anvil` binary.
//!
//! Every test here is `#[ignore]`-gated so the hermetic `make test` tier never
//! runs them. Each test also opens with a skip-with-notice guard so a missing
//! `anvil` binary is a green no-op under `--ignored` (D-3).
//!
//! E6-1 lands the anvil harness smoke only; E6-2/E6-3 extend this file.

mod common;

#[cfg(unix)]
use common::anvil::Anvil;

/// Smoke: spawn anvil on hoodi chain-id, round-trip `eth_chainId`, Drop reaps.
#[cfg(unix)]
#[test]
#[ignore = "live tier: needs the anvil binary; run via `make e2e-live`"]
fn anvil_harness_eth_chain_id() {
    let Some(a) = Anvil::try_spawn(560048) else {
        return;
    };

    let result = a.rpc("eth_chainId", serde_json::json!([]));
    let hex = result
        .as_str()
        .unwrap_or_else(|| panic!("eth_chainId result not a string: {result:?}"));
    let id = u64::from_str_radix(hex.trim_start_matches("0x"), 16)
        .unwrap_or_else(|e| panic!("parse eth_chainId {hex:?}: {e}"));
    assert_eq!(id, 560048, "eth_chainId round-trip");

    // Explicit drop so a failed reap would surface here; Drop kills + waits.
    drop(a);
}
