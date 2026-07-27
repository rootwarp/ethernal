//! The source of truth for per-network compile-time constants used in the
//! deposit signing pipeline.

use std::fmt;

/// Identifies an Ethereum consensus network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// The Ethereum mainnet.
    Mainnet,
    /// The Hoodi testnet.
    Hoodi,
    /// The Sepolia testnet.
    Sepolia,
    /// The Holesky testnet.
    Holesky,
}

impl Network {
    /// All supported networks, in the canonical listing order used by error
    /// messages and chain-ID lookup.
    pub const ALL: [Network; 4] = [
        Network::Mainnet,
        Network::Hoodi,
        Network::Sepolia,
        Network::Holesky,
    ];

    /// The lowercase network name, as used in CLI flags and JSON output.
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Hoodi => "hoodi",
            Network::Sepolia => "sepolia",
            Network::Holesky => "holesky",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors returned by network parsing and lookup.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkError {
    /// Returned by [`lookup_name`] for a name that is not a supported network.
    /// Mirrors Go's `network.Lookup` default arm.
    #[error(r#"unknown network "{0}": must be one of "mainnet", "hoodi", "sepolia", "holesky""#)]
    UnknownNetwork(String),

    /// Returned by [`parse_flag`] for a flag value that is not a supported
    /// network. Mirrors Go's `network.ParseFlag` default arm.
    #[error(
        r#"unsupported network "{0}": must be one of "mainnet", "hoodi", "sepolia", "holesky""#
    )]
    UnsupportedNetwork(String),

    /// Returned by [`lookup_by_chain_id`] when no supported network matches.
    #[error("unknown chain ID {0}: not a supported network")]
    UnknownChainId(u64),
}

/// Holds the per-network constants required by the deposit signing pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    pub name: Network,
    pub genesis_fork_version: [u8; 4],

    /// The EIP-155 chain ID used in transaction signing.
    pub chain_id: u64,

    /// The 20-byte execution-layer address of the beacon chain deposit
    /// contract on this network.
    /// Source: eth-clients/<network>/metadata/config.yaml DEPOSIT_CONTRACT_ADDRESS.
    pub deposit_contract_address: [u8; 20],

    /// The base URL of the block explorer for this network
    /// (e.g. "https://etherscan.io"). Used to format tx hash links.
    /// Source: etherscan.io per-network subdomains.
    pub explorer_url: &'static str,
}

impl Params {
    /// Returns the deposit contract address as a lowercase "0x"-prefixed hex
    /// string, suitable for display and JSON output.
    pub fn deposit_contract_address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.deposit_contract_address))
    }
}

/// The 4-byte SSZ domain type for deposits (consensus spec constant).
pub const DOMAIN_DEPOSIT: [u8; 4] = [0x03, 0x00, 0x00, 0x00];

/// The genesis_validators_root used for deposit signing — always 32 zero
/// bytes per the consensus spec.
pub const ZERO_GENESIS_VALIDATORS_ROOT: [u8; 32] = [0u8; 32];

/// Returns the Params for the given network. Total over the enum — the Go
/// error path for unknown strings lives in [`lookup_name`].
pub fn lookup(n: Network) -> Params {
    match n {
        Network::Mainnet => Params {
            name: Network::Mainnet,
            genesis_fork_version: [0x00, 0x00, 0x00, 0x00],
            chain_id: 1,
            deposit_contract_address: hex_literal("00000000219ab540356cbb839cbe05303d7705fa"),
            explorer_url: "https://etherscan.io",
        },
        Network::Hoodi => Params {
            name: Network::Hoodi,
            genesis_fork_version: [0x10, 0x00, 0x09, 0x10],
            chain_id: 560048,
            deposit_contract_address: hex_literal("00000000219ab540356cbb839cbe05303d7705fa"),
            explorer_url: "https://hoodi.etherscan.io",
        },
        Network::Sepolia => Params {
            name: Network::Sepolia,
            genesis_fork_version: [0x90, 0x00, 0x00, 0x69],
            chain_id: 11155111,
            deposit_contract_address: hex_literal("7f02c3e3c98b133055b8b348b2ac625669ed295d"),
            explorer_url: "https://sepolia.etherscan.io",
        },
        Network::Holesky => Params {
            name: Network::Holesky,
            genesis_fork_version: [0x01, 0x01, 0x70, 0x00],
            chain_id: 17000,
            deposit_contract_address: hex_literal("4242424242424242424242424242424242424242"),
            explorer_url: "https://holesky.etherscan.io",
        },
    }
}

/// Returns the Params for the network with the given (possibly arbitrary)
/// name string. This is the read-side companion used by `Entry::validate`,
/// where the network name comes from untrusted JSON. Mirrors Go's
/// `network.Lookup` error for unknown names.
pub fn lookup_name(name: &str) -> Result<Params, NetworkError> {
    match name {
        "mainnet" => Ok(lookup(Network::Mainnet)),
        "hoodi" => Ok(lookup(Network::Hoodi)),
        "sepolia" => Ok(lookup(Network::Sepolia)),
        "holesky" => Ok(lookup(Network::Holesky)),
        other => Err(NetworkError::UnknownNetwork(other.to_string())),
    }
}

/// Returns the Params for the network with the given chain ID.
/// Returns an error if no supported network matches.
pub fn lookup_by_chain_id(chain_id: u64) -> Result<Params, NetworkError> {
    for n in Network::ALL {
        let p = lookup(n);
        if p.chain_id == chain_id {
            return Ok(p);
        }
    }
    Err(NetworkError::UnknownChainId(chain_id))
}

/// Parses a network flag string and returns the corresponding Network.
/// It accepts exactly "mainnet", "hoodi", "sepolia", and "holesky"
/// (case-sensitive). Any other input returns an error containing the
/// offending value.
pub fn parse_flag(s: &str) -> Result<Network, NetworkError> {
    match s {
        "mainnet" => Ok(Network::Mainnet),
        "hoodi" => Ok(Network::Hoodi),
        "sepolia" => Ok(Network::Sepolia),
        "holesky" => Ok(Network::Holesky),
        other => Err(NetworkError::UnsupportedNetwork(other.to_string())),
    }
}

/// Decodes a 40-char lowercase hex literal into a [u8; 20] at compile time.
/// Panics (at const-eval time) on invalid input.
const fn hex_literal(s: &str) -> [u8; 20] {
    let bytes = s.as_bytes();
    assert!(bytes.len() == 40, "address literal must be 40 hex chars");
    let mut out = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        out[i] = (hex_nibble(bytes[2 * i]) << 4) | hex_nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("invalid hex nibble in address literal"),
    }
}
