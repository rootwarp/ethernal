//! The `build`/`run` shared configuration, ported from
//! `cmd/eth-deposit/config.go`. Raw CLI flags (with env-var fallbacks) are
//! resolved flag > env > default into a typed [`Config`]; numeric flags are
//! declared as strings so the Go validation messages render verbatim.

use eth_deposit_core::network::{self, Network, Params};

use clap::ArgMatches;

use crate::errors::AppError;

/// The default gas limit for a `deposit()` call. The `deposit()` function costs
/// ~200,000 gas; 250,000 provides comfortable headroom.
pub const DEFAULT_GAS_LIMIT: u64 = 250_000;

/// The fallback EIP-1559 max fee: 20 Gwei. A testnet baseline; may be too low
/// for mainnet.
pub const DEFAULT_MAX_FEE_PER_GAS: u128 = 20_000_000_000;

/// The fallback EIP-1559 tip: 1 Gwei.
pub const DEFAULT_MAX_PRIORITY_FEE_PER_GAS: u128 = 1_000_000_000;

/// Holds the validated, parsed inputs for `eth-deposit build`.
/// Port of `main.Config`.
#[derive(Debug, Clone)]
pub struct Config {
    /// The selected Ethereum consensus network.
    pub network: Network,

    /// The resolved per-network constants (chain ID, deposit contract, etc.).
    pub network_params: Params,

    /// The path to the deposit_data JSON file, or "-" for stdin.
    pub input_file: String,

    /// The output path for the unsigned transaction. Empty means stdout.
    pub output_file: String,

    /// The zero-based index into the deposit_data JSON array.
    pub index: i64,

    /// An optional JSON-RPC endpoint for gas/nonce estimation. Empty means the
    /// caller must supply all gas/nonce flags explicitly.
    pub rpc_url: String,

    /// The sender address, parsed from --from. Zero value means unset. Used
    /// only in RPC mode to fetch the pending nonce when --nonce is omitted.
    ///
    /// NOTE: this is populated only by the `build` handler (which declares
    /// `--from`); [`load_build_config`] itself leaves it zero so the shared
    /// parser is reusable by `run`, which does not declare `--from` and derives
    /// the sender from its signing key.
    pub from: [u8; 20],

    /// The EIP-1559 gas limit. `0` means unset (the offline default or an RPC
    /// estimate fills it later).
    pub gas_limit: u64,

    /// The EIP-1559 maximum total fee in wei. `None` if not set.
    pub max_fee_per_gas: Option<u128>,

    /// The EIP-1559 miner tip in wei. `None` if not set.
    pub max_priority_fee_per_gas: Option<u128>,

    /// An optional explicit nonce override. `None` means fetch from RPC or
    /// require a manual flag.
    pub nonce: Option<u64>,
}

/// Resolves flag > env > defaults into a typed [`Config`] and validates it.
/// Unknown networks or invalid numeric inputs produce an exit-code-2 error.
///
/// It does NOT read `--from`: that flag is `build`-only, and `run` reuses this
/// parser without declaring it (reading an undefined clap arg panics). The
/// `build` handler calls [`parse_from_flag`] separately.
pub fn load_build_config(m: &ArgMatches) -> Result<Config, AppError> {
    // 1. Network — parse and look up constants.
    let net = network::parse_flag(m.get_one::<String>("network").unwrap())
        .map_err(|e| AppError::exit2(format!("--network: {e}")))?;
    let params = network::lookup(net);

    // 2. Gas limit — string flag so an env-var override works alongside the
    // flag. Unset means 0 here; the offline branch in build_unsigned_tx
    // restores the static default, while RPC mode leaves it 0 so the builder
    // runs eth_estimateGas.
    let mut gas_limit: u64 = 0;
    if let Some(s) = non_empty(m, "gas-limit") {
        let v = s.parse::<u64>().map_err(|_| {
            AppError::exit2(format!(
                "--gas-limit: invalid value {s:?}: must be a positive integer"
            ))
        })?;
        if v == 0 {
            return Err(AppError::exit2("--gas-limit: must be greater than zero"));
        }
        gas_limit = v;
    }

    // 3. Max fee per gas — optional, None when absent.
    let max_fee = match non_empty(m, "max-fee-per-gas") {
        Some(s) => Some(parse_wei("--max-fee-per-gas", s)?),
        None => None,
    };

    // 4. Max priority fee per gas — optional, None when absent.
    let max_prio_fee = match non_empty(m, "max-priority-fee-per-gas") {
        Some(s) => Some(parse_wei("--max-priority-fee-per-gas", s)?),
        None => None,
    };

    // 5. Nonce — optional, None when absent.
    let nonce = match non_empty(m, "nonce") {
        Some(s) => Some(s.parse::<u64>().map_err(|_| {
            AppError::exit2(format!(
                "--nonce: invalid value {s:?}: must be a non-negative integer"
            ))
        })?),
        None => None,
    };

    Ok(Config {
        network: net,
        network_params: params,
        input_file: m
            .get_one::<String>("input-file")
            .cloned()
            .unwrap_or_default(),
        output_file: m.get_one::<String>("output").cloned().unwrap_or_default(),
        index: *m.get_one::<i64>("index").unwrap(),
        rpc_url: m.get_one::<String>("rpc-url").cloned().unwrap_or_default(),
        from: [0u8; 20],
        gas_limit,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: max_prio_fee,
        nonce,
    })
}

/// Parses the `build`-only `--from` flag: a strict 20-byte hex address (with or
/// without a `0x` prefix). `common.HexToAddress` is deliberately avoided — it is
/// lenient and silently truncates/pads. Returns the zero address when unset.
pub fn parse_from_flag(m: &ArgMatches) -> Result<[u8; 20], AppError> {
    let mut from = [0u8; 20];
    if let Some(s) = non_empty(m, "from") {
        let h = s.strip_prefix("0x").unwrap_or(s);
        match hex::decode(h) {
            Ok(b) if b.len() == 20 => from.copy_from_slice(&b),
            _ => {
                return Err(AppError::exit2(format!(
                    "--from: invalid address {s:?}: must be a 20-byte hex address"
                )));
            }
        }
    }
    Ok(from)
}

/// Returns the flag's value only when it is present and non-empty, mirroring
/// Go's `if s := c.String(name); s != ""` guard.
fn non_empty<'a>(m: &'a ArgMatches, name: &str) -> Option<&'a String> {
    m.get_one::<String>(name).filter(|s| !s.is_empty())
}

/// Parses a decimal wei quantity like Go's `big.Int.SetString(s, 10)` followed
/// by a `Sign() < 0` check: a valid-but-negative value yields the "must be
/// non-negative" message, while a non-decimal value yields the "invalid value"
/// message. `flag` is the flag name used in both messages.
fn parse_wei(flag: &str, s: &str) -> Result<u128, AppError> {
    let (negative, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    // big.Int.SetString(base 10) requires at least one digit, all decimal.
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AppError::exit2(format!(
            "{flag}: invalid value {s:?}: must be a decimal integer in wei"
        )));
    }
    if negative {
        return Err(AppError::exit2(format!(
            "{flag}: value must be non-negative, got {s}"
        )));
    }
    digits.parse::<u128>().map_err(|_| {
        AppError::exit2(format!(
            "{flag}: invalid value {s:?}: must be a decimal integer in wei"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::exit_code_for;
    use eth_deposit_core::network::Network;

    // Go: config_test.go / from_test.go. These exercise the FLAG path only. The
    // env-var fallback cases (EnvVarOverride/FlagBeatsEnvVar/GasLimitEnvVar/
    // FromEnvVar) are binary-driven in tests/build.rs and tests/build_rpc.rs:
    // clap reads process-global env at parse time, which cannot be steered from a
    // parallel white-box test without a data race.

    /// Parses `build`-subcommand args (argv[0] is the program name) into
    /// `ArgMatches`, then `Config`.
    fn build_config(args: &[&str]) -> Result<Config, AppError> {
        let mut argv = vec!["build"];
        argv.extend_from_slice(args);
        let m = crate::build_cmd::command()
            .try_get_matches_from(argv)
            .expect("clap parse");
        load_build_config(&m)
    }

    fn from_flag(args: &[&str]) -> Result<[u8; 20], AppError> {
        let mut argv = vec!["build"];
        argv.extend_from_slice(args);
        let m = crate::build_cmd::command()
            .try_get_matches_from(argv)
            .expect("clap parse");
        parse_from_flag(&m)
    }

    // Go: TestLoadBuildConfig_Defaults
    #[test]
    fn load_build_config_defaults() {
        let cfg = build_config(&["--network", "holesky", "--input-file", "deposit.json"]).unwrap();
        assert_eq!(cfg.network, Network::Holesky);
        assert_eq!(cfg.network_params.chain_id, 17000);
        assert_eq!(cfg.gas_limit, 0); // default applied later, not at config load
        assert_eq!(cfg.max_fee_per_gas, None);
        assert_eq!(cfg.max_priority_fee_per_gas, None);
        assert_eq!(cfg.nonce, None);
        assert_eq!(cfg.index, 0);
        assert_eq!(cfg.input_file, "deposit.json");
        assert_eq!(cfg.output_file, "");
    }

    // Go: TestLoadBuildConfig_AllFlagsSet
    #[test]
    fn load_build_config_all_flags_set() {
        let cfg = build_config(&[
            "--network",
            "sepolia",
            "--input-file",
            "batch.json",
            "--output",
            "unsigned.hex",
            "--index",
            "3",
            "--rpc-url",
            "https://rpc.sepolia.example.com",
            "--gas-limit",
            "300000",
            "--max-fee-per-gas",
            "20000000000",
            "--max-priority-fee-per-gas",
            "1000000000",
            "--nonce",
            "42",
        ])
        .unwrap();
        assert_eq!(cfg.network, Network::Sepolia);
        assert_eq!(cfg.input_file, "batch.json");
        assert_eq!(cfg.output_file, "unsigned.hex");
        assert_eq!(cfg.index, 3);
        assert_eq!(cfg.rpc_url, "https://rpc.sepolia.example.com");
        assert_eq!(cfg.gas_limit, 300_000);
        assert_eq!(cfg.max_fee_per_gas, Some(20_000_000_000));
        assert_eq!(cfg.max_priority_fee_per_gas, Some(1_000_000_000));
        assert_eq!(cfg.nonce, Some(42));
    }

    // Go: TestLoadBuildConfig_UnknownNetwork
    #[test]
    fn load_build_config_unknown_network() {
        assert!(
            build_config(&["--network", "unknownnet", "--input-file", "deposit.json"]).is_err()
        );
    }

    // Go: TestLoadBuildConfig_InvalidMaxFeePerGas / InvalidMaxPriorityFeePerGas /
    // InvalidNonce / GasLimitZero / NegativeMaxFeePerGas / NegativeMaxPriorityFeePerGas.
    //
    // Divergence: the negative cases use the `--flag=-100` form. With the
    // space-separated form (`--flag -100`), clap treats `-100` as an unknown
    // option and rejects it at parse time (also exit 2, a different message)
    // before `parse_wei`'s "must be non-negative" branch runs; the `=` form
    // delivers the negative string to the validator under test.
    #[test]
    fn load_build_config_invalid_numeric_values() {
        let base = ["--network", "holesky", "--input-file", "deposit.json"];
        let cases: &[&[&str]] = &[
            &["--max-fee-per-gas", "not-a-number"],
            &["--max-priority-fee-per-gas", "abc"],
            &["--nonce", "not-a-number"],
            &["--gas-limit", "0"],
            &["--max-fee-per-gas=-100"],
            &["--max-priority-fee-per-gas=-1"],
        ];
        for extra in cases {
            let mut args: Vec<&str> = base.to_vec();
            args.extend_from_slice(extra);
            let err = build_config(&args).unwrap_err();
            assert_eq!(exit_code_for(&err), 2, "case {extra:?}");
        }
    }

    // Go: TestLoadBuildConfig_FromValid / FromNoPrefix / FromMixedCase.
    #[test]
    fn from_valid_variants() {
        let base = ["--network", "holesky", "--input-file", "deposit.json"];
        let cases = [
            (
                "0x1234567890123456789012345678901234567890",
                "1234567890123456789012345678901234567890",
            ),
            (
                "abcdefabcdefabcdefabcdefabcdefabcdefabcd",
                "abcdefabcdefabcdefabcdefabcdefabcdefabcd",
            ),
            (
                "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01",
                "abcdef0123456789abcdef0123456789abcdef01",
            ),
        ];
        for (arg, want_hex) in cases {
            let mut args: Vec<&str> = base.to_vec();
            args.extend_from_slice(&["--from", arg]);
            let from = from_flag(&args).unwrap();
            let want = hex::decode(want_hex).unwrap();
            assert_eq!(&from[..], &want[..], "from {arg}");
        }
    }

    // Go: TestLoadBuildConfig_FromUnset
    #[test]
    fn from_unset_is_zero() {
        let from = from_flag(&["--network", "holesky", "--input-file", "deposit.json"]).unwrap();
        assert_eq!(from, [0u8; 20]);
    }

    // Go: TestLoadBuildConfig_FromBadHex / FromWrongLength → exit 2.
    #[test]
    fn from_invalid_is_exit2() {
        let base = ["--network", "holesky", "--input-file", "deposit.json"];
        for bad in [
            "0xZZ34567890123456789012345678901234567890", // non-hex
            "0x1234",                                     // 2 bytes
            "0x12345678901234567890123456789012345678901234", // 22 bytes
        ] {
            let mut args: Vec<&str> = base.to_vec();
            args.extend_from_slice(&["--from", bad]);
            let err = from_flag(&args).unwrap_err();
            assert_eq!(exit_code_for(&err), 2, "from {bad}");
        }
    }

    // Go: TestRun_FromUndeclaredIsHarmless — the shared parser leaves From zero
    // for `run`, which declares no --from (reading it would otherwise panic).
    #[test]
    fn run_from_undeclared_is_harmless() {
        let m = crate::run_cmd::command()
            .try_get_matches_from([
                "run",
                "--network",
                "holesky",
                "--input-file",
                "deposit.json",
            ])
            .expect("clap parse");
        let cfg = load_build_config(&m).expect("load ok");
        assert_eq!(cfg.from, [0u8; 20]);
    }
}
