//! Ported from go/internal/network/network_test.go.
//!
//! Black-box tests against the public network surface. Two deliberate
//! adaptations to the Rust API:
//!   * Go's `network.Lookup(net) (Params, error)` is infallible in Rust
//!     (`network::lookup(Network) -> Params`) because `Network` is a closed
//!     enum with no "unknown" value. The Go "unknown network" subtest is
//!     therefore ported against `lookup_name`, which is the read-side entry
//!     that accepts an arbitrary string.
//!   * `network.Network("goerli")` cannot be constructed in Rust, so string
//!     inputs go through `lookup_name` / `parse_flag`.

use eth_deposit_core::network::{
    self, lookup, lookup_by_chain_id, lookup_name, parse_flag, Network, DOMAIN_DEPOSIT,
    ZERO_GENESIS_VALIDATORS_ROOT,
};

// Go: TestConstants/DomainDeposit
#[test]
fn constants_domain_deposit() {
    assert_eq!(DOMAIN_DEPOSIT, [0x03, 0x00, 0x00, 0x00]);
}

// Go: TestConstants/ZeroGenesisValidatorsRoot
#[test]
fn constants_zero_genesis_validators_root() {
    assert_eq!(ZERO_GENESIS_VALIDATORS_ROOT, [0u8; 32]);
}

// Go: TestLookupMainnet
#[test]
fn lookup_mainnet() {
    let params = lookup(Network::Mainnet);
    assert_eq!(params.genesis_fork_version, [0x00, 0x00, 0x00, 0x00]);
    assert_eq!(params.name, Network::Mainnet);
}

// Go: TestLookup (per-network field table).
#[test]
fn lookup_all_networks() {
    struct Case {
        net: Network,
        fork_version: [u8; 4],
        chain_id: u64,
        deposit_contract_hex: &'static str,
    }
    let cases = [
        Case {
            net: Network::Mainnet,
            fork_version: [0x00, 0x00, 0x00, 0x00],
            chain_id: 1,
            deposit_contract_hex: "0x00000000219ab540356cbb839cbe05303d7705fa",
        },
        Case {
            net: Network::Hoodi,
            fork_version: [0x10, 0x00, 0x09, 0x10],
            chain_id: 560048,
            deposit_contract_hex: "0x00000000219ab540356cbb839cbe05303d7705fa",
        },
        Case {
            net: Network::Sepolia,
            fork_version: [0x90, 0x00, 0x00, 0x69],
            chain_id: 11155111,
            deposit_contract_hex: "0x7f02c3e3c98b133055b8b348b2ac625669ed295d",
        },
        Case {
            net: Network::Holesky,
            fork_version: [0x01, 0x01, 0x70, 0x00],
            chain_id: 17000,
            deposit_contract_hex: "0x4242424242424242424242424242424242424242",
        },
    ];

    for c in &cases {
        let params = lookup(c.net);
        assert_eq!(params.name, c.net, "name for {:?}", c.net);
        assert_eq!(
            params.genesis_fork_version, c.fork_version,
            "fork version for {:?}",
            c.net
        );
        assert_eq!(params.chain_id, c.chain_id, "chain id for {:?}", c.net);
        assert_eq!(
            params.deposit_contract_address_hex().to_lowercase(),
            c.deposit_contract_hex,
            "deposit contract hex for {:?}",
            c.net
        );
    }
}

// Go: TestLookup/Unknown_network_returns_descriptive_error
// Adapted to `lookup_name`, the string-keyed read-side lookup (see module doc).
#[test]
fn lookup_name_unknown_returns_descriptive_error() {
    let err = lookup_name("goerli").unwrap_err();
    assert!(
        err.to_string().contains("goerli"),
        "error {err:?} does not mention the unknown network name"
    );
}

// Go: TestParseFlag (valid + invalid case-sensitive matching).
#[test]
fn parse_flag_valid() {
    let cases = [
        ("mainnet", Network::Mainnet),
        ("hoodi", Network::Hoodi),
        ("sepolia", Network::Sepolia),
        ("holesky", Network::Holesky),
    ];
    for (input, want) in cases {
        let got =
            parse_flag(input).unwrap_or_else(|e| panic!("parse_flag({input:?}) error: {e:?}"));
        assert_eq!(got, want, "parse_flag({input:?})");
    }
}

// Go: TestParseFlag (invalid cases — all must error).
#[test]
fn parse_flag_invalid() {
    let invalid = [
        "", "HOODI", "mainnet ", "goerli", "Mainnet", " mainnet", "MAINNET", "SEPOLIA", "Holesky",
    ];
    for input in invalid {
        assert!(
            parse_flag(input).is_err(),
            "parse_flag({input:?}) should have errored"
        );
    }
}

// Go: TestLookupByChainID (reverse lookup + explorer URL).
#[test]
fn lookup_by_chain_id_all() {
    let cases = [
        (1u64, Network::Mainnet, "https://etherscan.io"),
        (560048, Network::Hoodi, "https://hoodi.etherscan.io"),
        (11155111, Network::Sepolia, "https://sepolia.etherscan.io"),
        (17000, Network::Holesky, "https://holesky.etherscan.io"),
    ];
    for (chain_id, want_network, want_url) in cases {
        let p = lookup_by_chain_id(chain_id)
            .unwrap_or_else(|e| panic!("lookup_by_chain_id({chain_id}) error: {e:?}"));
        assert_eq!(p.name, want_network, "network for chain {chain_id}");
        assert_eq!(p.chain_id, chain_id, "chain id round-trip");
        assert_eq!(
            p.explorer_url, want_url,
            "explorer url for chain {chain_id}"
        );
    }
}

// Go: TestLookupByChainID/unknown_chain_ID
#[test]
fn lookup_by_chain_id_unknown() {
    assert!(lookup_by_chain_id(99999).is_err());
}

// Go: TestLookupExplorerURL
#[test]
fn lookup_explorer_url_present() {
    for n in Network::ALL {
        let p = lookup(n);
        assert!(!p.explorer_url.is_empty(), "explorer url empty for {n:?}");
        assert!(
            p.explorer_url.starts_with("https://"),
            "explorer url for {n:?} lacks https:// prefix: {}",
            p.explorer_url
        );
    }
}

// Go: TestDepositContractAddressHex
#[test]
fn deposit_contract_address_hex_format() {
    let params = lookup(Network::Holesky);
    let got = params.deposit_contract_address_hex();
    assert!(got.starts_with("0x"), "missing 0x prefix: {got}");
    // 0x + 40 hex chars (20 bytes).
    assert_eq!(got.len(), 42, "deposit contract hex length");
}

// Parity guard for the `network` module path re-export used by callers.
#[test]
fn lookup_name_known() {
    let p = network::lookup_name("mainnet").expect("mainnet is known");
    assert_eq!(p.name, Network::Mainnet);
}
