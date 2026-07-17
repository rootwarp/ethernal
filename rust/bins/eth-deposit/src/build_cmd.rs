//! The `build` subcommand, ported from `buildCommand` + `requireFromForRPC` +
//! `buildUnsignedTx` + the `newEthRPC` seam in `cmd/eth-deposit/main.go`.
//!
//! `build` reads a deposit_data JSON file (from `eth-deposit gen` or the
//! Ethereum Launchpad) and produces an unsigned EIP-1559 transaction for the
//! Beacon Chain deposit contract. It supports offline/air-gapped mode (no
//! `--rpc-url`, all gas/nonce flags explicit) and hybrid mode (with `--rpc-url`,
//! any gas/fee/nonce not passed is resolved from the node, which needs `--from`).

use std::io::{Read, Write};

use clap::{Arg, ArgMatches, Command};

use eth_deposit_core::cancel::CancelToken;
use eth_deposit_core::deposit;
use eth_deposit_tx::{BuildConfig, Builder, EthClient, EthRpc, TxError, UnsignedTx};

use crate::config::{
    self, Config, DEFAULT_GAS_LIMIT, DEFAULT_MAX_FEE_PER_GAS, DEFAULT_MAX_PRIORITY_FEE_PER_GAS,
};
use crate::errors::AppError;
use crate::logging::{Format, Level, Logger};

/// The clap definition of the `build` subcommand. Flag set, usage text, and the
/// long description are ported from `buildCommand`.
pub fn command() -> Command {
    Command::new("build")
        .about("Construct an unsigned deposit transaction from deposit data")
        .override_usage("eth-deposit build --input-file FILE --network NET [options]")
        .long_about(
            "Reads a deposit_data JSON file (produced by \"eth-deposit gen\" or the Ethereum Launchpad)\n\
             and produces an unsigned EIP-1559 transaction for the Beacon Chain deposit contract.\n\n\
             Supports offline/air-gapped mode (no --rpc-url required) when all gas and nonce\n\
             flags are supplied explicitly, and hybrid mode: with --rpc-url, any gas, fee, or\n\
             nonce not passed explicitly is resolved from the node (which needs --from).\n\
             Output is written to stdout by default; use --output FILE or --output - for explicit stdout.\n\n\
             Exit codes:\n\
             \x20 0  Success\n\
             \x20 2  User / configuration error (missing/invalid input, bad --network, out-of-range\n\
             \x20    --index, missing required flag, missing --from for RPC nonce/gas estimation,\n\
             \x20    RPC chain-ID mismatch)\n\
             \x20 4  User abort (Ctrl-C during RPC estimation)\n\
             \x20 5  RPC error (endpoint unreachable, gas/nonce estimation failed)\n\
             \x20 1  Unexpected internal error",
        )
        .args(build_flags(true))
}

/// The flag list shared by `build` and (minus `--from`) `run`. `build` declares
/// `--from`; `run` derives the sender from its signing key, so it must NOT be
/// added there (a stray `--from` would change `run`'s CLI surface). Pass
/// `with_from = false` for `run`.
pub fn build_flags(with_from: bool) -> Vec<Arg> {
    // `build` and `run` share the same flag set but differ in two help texts:
    // build's --output/--rpc-url speak of the *unsigned* tx and the --from
    // requirement; run's speak of the *signed* tx and the ledger
    // --nonce/--gas-limit requirement (run has no --from). This mirrors Go's
    // separate `buildCommand` inline flags vs run's `buildFlags()`.
    let (output_help, rpc_url_help) = if with_from {
        (
            "Output file for the unsigned transaction (default: stdout)",
            "JSON-RPC endpoint URL. When set, any gas/fee/nonce value not given explicitly is resolved from the node (requires --from); when omitted, the build is fully offline and all gas and nonce flags must be supplied explicitly.",
        )
    } else {
        (
            "Output file for the signed transaction (default: stdout)",
            "JSON-RPC endpoint URL. When set, any gas/fee/nonce value not given explicitly is resolved from the node; --signer local derives the sender from its key, while --signer ledger has no derivable sender and so must supply both --nonce and --gas-limit (the node cannot fetch either without a funded sender). When omitted, all gas and nonce flags must be supplied explicitly.",
        )
    };
    let mut flags = vec![
        Arg::new("input-file")
            .long("input-file")
            .visible_alias("input")
            .short('i')
            .value_name("FILE")
            .required(true)
            .env("ETH_DEPOSIT_TX_INPUT_FILE")
            .help("Path to deposit_data-*.json file (or '-' for stdin); --input is accepted as a shorter alias"),
        Arg::new("network")
            .long("network")
            .short('n')
            .value_name("NET")
            .default_value("hoodi")
            .env("ETH_DEPOSIT_TX_NETWORK")
            .help("Target network (mainnet, hoodi, sepolia, holesky)"),
        Arg::new("output")
            .long("output")
            .value_name("FILE")
            .env("ETH_DEPOSIT_TX_OUTPUT")
            .help(output_help),
        Arg::new("index")
            .long("index")
            .value_name("N")
            .value_parser(clap::value_parser!(i64))
            .default_value("0")
            .env("ETH_DEPOSIT_TX_INDEX")
            .help("Index of the deposit entry to use when the JSON contains multiple validators (default: 0)"),
        Arg::new("rpc-url")
            .long("rpc-url")
            .value_name("URL")
            .env("ETH_DEPOSIT_TX_RPC_URL")
            .help(rpc_url_help),
        Arg::new("gas-limit")
            .long("gas-limit")
            .value_name("N")
            .env("ETH_DEPOSIT_TX_GAS_LIMIT")
            .help(format!("Gas limit for the deposit transaction (default: {DEFAULT_GAS_LIMIT})")),
        Arg::new("max-fee-per-gas")
            .long("max-fee-per-gas")
            .value_name("WEI")
            .env("ETH_DEPOSIT_TX_MAX_FEE_PER_GAS")
            .help("EIP-1559 maximum fee per gas in wei (decimal integer, e.g. 20000000000 for 20 Gwei)"),
        Arg::new("max-priority-fee-per-gas")
            .long("max-priority-fee-per-gas")
            .value_name("WEI")
            .env("ETH_DEPOSIT_TX_MAX_PRIORITY_FEE_PER_GAS")
            .help("EIP-1559 maximum priority fee per gas in wei (decimal integer, e.g. 1000000000 for 1 Gwei)"),
        Arg::new("nonce")
            .long("nonce")
            .value_name("N")
            .env("ETH_DEPOSIT_TX_NONCE")
            .help("Override the sender account nonce (non-negative integer; omit to fetch from RPC or set later)"),
    ];
    if with_from {
        flags.push(
            Arg::new("from")
                .long("from")
                .value_name("ADDR")
                .env("ETH_DEPOSIT_TX_FROM")
                .help("Sender address (0x-prefixed, 20-byte hex). Required with --rpc-url when --nonce or --gas-limit is omitted, to fetch the pending nonce and estimate gas."),
        );
    }
    flags
}

/// The `build` action: load config, enforce the `--from` gate, read the deposit
/// data, build the unsigned tx, and write it to stdout or a file.
pub fn run(m: &ArgMatches, cancel: &CancelToken) -> Result<(), AppError> {
    let mut cfg = config::load_build_config(m)?;
    cfg.from = config::parse_from_flag(m)?;

    require_from_for_rpc(&cfg)?;

    // Read deposit data from file or stdin.
    let raw_data =
        read_input(&cfg.input_file).map_err(|e| AppError::exit2(format!("--input-file: {e}")))?;

    let unsigned = build_unsigned_tx(&cfg, &raw_data, cancel)?;

    let mut out = serde_json::to_vec_pretty(&unsigned)
        .map_err(|e| AppError::exit2(format!("build: marshal: {e}")))?;
    out.push(b'\n');

    if cfg.output_file.is_empty() || cfg.output_file == "-" {
        std::io::stdout()
            .write_all(&out)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        return Ok(());
    }

    write_file_mode(&cfg.output_file, &out, 0o644)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let logger = Logger::stderr(Level::Info, Format::Text);
    logger.info(
        "wrote unsigned tx",
        &[
            ("path", cfg.output_file.clone()),
            ("network", cfg.network.to_string()),
        ],
    );
    Ok(())
}

/// Reads the whole input from `path`, or stdin when `path == "-"`.
pub fn read_input(path: &str) -> std::io::Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read(path)
    }
}

/// Enforces the config-time `--from` requirement for `build`: in RPC mode, when
/// no sender was supplied and either the nonce or the gas limit is unset,
/// `--from` is mandatory. Both the pending-nonce fetch and the 32-ETH gas
/// estimation need a funded sender, so a zero From would otherwise surface later
/// as a confusing exit-5 estimation failure instead of a clean exit-2 config
/// error. It lives in `build`'s handler, not shared `load_build_config`, because
/// `run` derives From from the signing key instead.
pub fn require_from_for_rpc(cfg: &Config) -> Result<(), AppError> {
    if !cfg.rpc_url.is_empty()
        && cfg.from == [0u8; 20]
        && (cfg.nonce.is_none() || cfg.gas_limit == 0)
    {
        return Err(AppError::exit2(
            "--from: required when --rpc-url is set and --nonce or --gas-limit is omitted (the sender is needed to fetch the pending nonce and to estimate gas for the 32-ETH deposit call)",
        ));
    }
    Ok(())
}

/// The production `EthRpc` factory (port of `newEthRPC`). Tests inject a fake by
/// calling `build_unsigned_tx` with a pre-dialed client is not possible today,
/// so this is the seam: replace this function's body, or call the builder crate
/// directly with a mock in unit tests. `EthClient::new` performs URL validation
/// only (HTTP dial is lazy), so a well-formed but unreachable URL succeeds here
/// and fails later as an exit-5 estimation error.
pub fn new_eth_rpc(rpc_url: &str) -> Result<Box<dyn EthRpc>, AppError> {
    EthClient::new(rpc_url)
        .map(|c| Box::new(c) as Box<dyn EthRpc>)
        .map_err(AppError::Tx)
}

/// Converts raw deposit data bytes + build config into an [`UnsignedTx`]. Shared
/// by `build` and `run` (which calls it without re-reading from disk).
///
/// It owns the RPC client lifecycle: in RPC mode it dials via [`new_eth_rpc`]
/// and injects the client so the builder resolves unset gas/fee/nonce from the
/// node; in offline mode it fills the hardcoded air-gapped defaults and never
/// dials, keeping golden output byte-identical.
pub fn build_unsigned_tx(
    cfg: &Config,
    raw_data: &[u8],
    cancel: &CancelToken,
) -> Result<UnsignedTx, AppError> {
    let entries = deposit::entries_from_json(raw_data)
        .map_err(|e| AppError::exit2(format!("--input-file: invalid JSON: {e}")))?;
    if entries.is_empty() {
        return Err(AppError::exit2(
            "--input-file: file contains no deposit entries",
        ));
    }
    if cfg.index < 0 || cfg.index as usize >= entries.len() {
        return Err(AppError::exit2(format!(
            "--index {}: out of bounds (file has {} entries)",
            cfg.index,
            entries.len()
        )));
    }
    let entry = &entries[cfg.index as usize];

    entry
        .validate()
        .map_err(|e| AppError::exit2(format!("deposit entry validation: {e}")))?;

    // RPC mode: dial and hold the client so it outlives the borrow inside
    // BuildConfig. On dial failure the error (RpcDial → exit 5) is returned
    // unwrapped, never reaching the input-wrap below.
    let client: Option<Box<dyn EthRpc>> = if cfg.rpc_url.is_empty() {
        None
    } else {
        Some(new_eth_rpc(&cfg.rpc_url)?)
    };

    // Offline mode fills the hardcoded air-gapped defaults; RPC mode leaves the
    // fields as-is so the builder resolves them from the node (explicit flags
    // still win — the builder only fills None/zero fields).
    let (max_fee, max_prio, gas_limit, nonce) = if client.is_some() {
        (
            cfg.max_fee_per_gas,
            cfg.max_priority_fee_per_gas,
            cfg.gas_limit,
            cfg.nonce,
        )
    } else {
        (
            Some(cfg.max_fee_per_gas.unwrap_or(DEFAULT_MAX_FEE_PER_GAS)),
            Some(
                cfg.max_priority_fee_per_gas
                    .unwrap_or(DEFAULT_MAX_PRIORITY_FEE_PER_GAS),
            ),
            if cfg.gas_limit == 0 {
                DEFAULT_GAS_LIMIT
            } else {
                cfg.gas_limit
            },
            Some(cfg.nonce.unwrap_or(0)),
        )
    };

    let build_cfg = BuildConfig {
        network_params: cfg.network_params.clone(),
        rpc: client.as_deref(),
        from: cfg.from,
        gas_limit,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: max_prio,
        nonce,
    };

    Builder::new()
        .build_unsigned(entry, &build_cfg, cancel)
        .map_err(|e| match e {
            // An RPC estimation-call failure must reach exit 5 unwrapped, and a
            // cancellation must reach exit 4 unwrapped; everything else is a
            // config/input error and is wrapped → exit 2, preserving the
            // offline contract.
            TxError::RpcEstimation { .. } | TxError::Cancelled => AppError::Tx(e),
            other => AppError::input("build", AppError::Tx(other)),
        })
}

/// Writes `data` to `path`, creating it with `mode` (perm applies on creation
/// only, like Go's `os.WriteFile`). Shared by `sign` (0600 output).
pub(crate) fn write_file_mode(path: &str, data: &[u8], mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;
    f.write_all(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::exit_code_for;
    use eth_deposit_core::network::{self, Network};

    /// A `Config` with the given RPC/from/gas/nonce and holesky defaults for the
    /// rest, for driving [`require_from_for_rpc`] directly.
    fn cfg(rpc_url: &str, from: [u8; 20], gas_limit: u64, nonce: Option<u64>) -> Config {
        Config {
            network: Network::Holesky,
            network_params: network::lookup(Network::Holesky),
            input_file: String::new(),
            output_file: String::new(),
            index: 0,
            rpc_url: rpc_url.to_string(),
            from,
            gas_limit,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce,
        }
    }

    // Go: TestRequireFromForRPC (table).
    #[test]
    fn require_from_for_rpc_gate() {
        let nonzero = {
            let mut f = [0u8; 20];
            f[0] = 0x01;
            f
        };

        // offline: no --rpc-url → never required.
        assert!(require_from_for_rpc(&cfg("", [0u8; 20], 0, None)).is_ok());

        // rpc + nonce omitted + from zero → required.
        let err = require_from_for_rpc(&cfg("http://node", [0u8; 20], 250_000, None)).unwrap_err();
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("--from"));

        // rpc + gas omitted + nonce set + from zero → required.
        let err = require_from_for_rpc(&cfg("http://node", [0u8; 20], 0, Some(5))).unwrap_err();
        assert_eq!(exit_code_for(&err), 2);

        // rpc + nonce set + gas set + from zero → not required.
        assert!(require_from_for_rpc(&cfg("http://node", [0u8; 20], 250_000, Some(5))).is_ok());

        // rpc + from set + nonce omitted → not required.
        assert!(require_from_for_rpc(&cfg("http://node", nonzero, 250_000, None)).is_ok());

        // rpc + from set + gas omitted + nonce set → not required.
        assert!(require_from_for_rpc(&cfg("http://node", nonzero, 0, Some(5))).is_ok());
    }
}
