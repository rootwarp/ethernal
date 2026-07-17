//! The `gen` subcommand's flag schema and input validation, ported from
//! `go/internal/cli/cli.go`. Raw CLI flags are converted into a typed
//! [`GenConfig`]; the pipeline (`gen_cmd`) is invoked only after all
//! validations pass.

use std::io::Write;
use std::path::Path;

use clap::{Arg, ArgAction, ArgMatches, Command};

use eth_deposit_core::bls;
use eth_deposit_core::network::{self, Network};

use crate::errors::AppError;

/// Holds the validated, parsed inputs from the CLI flags.
/// Port of `cli.Config`.
#[derive(Debug, Clone)]
pub struct GenConfig {
    /// The directory containing EIP-2335 JSON keystore files.
    pub keystore_dir: String,
    /// The decoded list of 48-byte BLS12-381 G1 compressed points.
    pub pubkeys: Vec<[u8; 48]>,
    /// The Ethereum consensus network (mainnet or hoodi for gen).
    pub network: Network,
    /// The validated, writable directory for deposit_data-<ts>.json.
    pub output_dir: String,
    /// The name of the environment variable holding the keystore passphrase.
    /// Empty means the tool falls back to a TTY prompt.
    pub passphrase_env: String,
    /// True when the operator passed --i-understand-this-is-mainnet.
    /// NOTE: may be true for non-mainnet networks if the flag was supplied;
    /// always evaluate together with `network == Mainnet`.
    pub mainnet_ack: bool,
    /// --dry-run: write JSON to stdout instead of a file; --output-dir is not
    /// required and its validation is skipped.
    pub dry_run: bool,
    /// Debug-level log output.
    pub verbose: bool,
    /// JSON log handler instead of text.
    pub json_logs: bool,
    /// Number of concurrent signing workers (1..=ncpu*4).
    pub parallel: usize,
    /// Optional post-generation cross-check via the installed
    /// staking-deposit-cli. Skipped in dry-run.
    pub verify_with_deposit_cli: bool,
    /// Name or path of the staking-deposit-cli binary. Default "deposit".
    pub deposit_cli_path: String,
}

/// The maximum value accepted for --parallel (Go: runtime.NumCPU()*4).
pub fn max_parallel() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        * 4
}

/// The clap definition of the `gen` subcommand. Flag set, usage text, and
/// examples ported from `cli.NewApp`.
pub fn command() -> Command {
    Command::new("gen")
        .about("Generate Launchpad-compatible deposit_data JSON for existing BLS validator keys")
        .override_usage(
            "eth-deposit gen --keystore-dir DIR --pubkeys HEX[,...] --network NET --output-dir DIR [--passphrase-env VAR]",
        )
        .long_about(
            "Produces deposit_data-<ts>.json for one or more BLS validator public keys by\n\
             signing each deposit message with the BLS key loaded from an EIP-2335 keystore.\n\
             Output is byte-for-byte compatible with the official ethereum/staking-deposit-cli.\n\n\
             Examples:\n\n\
             \x20 # Hoodi testnet, two pubkeys (keystores directory contains one .json per validator)\n\
             \x20 eth-deposit gen \\\n\
             \x20   --network hoodi \\\n\
             \x20   --keystore-dir ./keystores/ \\\n\
             \x20   --pubkeys 0x93247f2209abcafd...,0xa1b2c3d4e5f6... \\\n\
             \x20   --output-dir ./out\n\n\
             \x20 # Mainnet, single pubkey (requires explicit acknowledgement)\n\
             \x20 eth-deposit gen \\\n\
             \x20   --network mainnet \\\n\
             \x20   --i-understand-this-is-mainnet \\\n\
             \x20   --keystore-dir ./keystores/ \\\n\
             \x20   --pubkeys 0x93247f2209abcafd... \\\n\
             \x20   --output-dir ./out",
        )
        .arg(
            Arg::new("keystore-dir")
                .long("keystore-dir")
                .value_name("DIR")
                .required(true)
                .help("Directory containing EIP-2335 JSON keystore files, one per validator (e.g. ./keystores/)"),
        )
        .arg(
            Arg::new("pubkeys")
                .long("pubkeys")
                .value_name("HEX[,...]")
                .required(true)
                .help("Comma-separated BLS public keys in 96-hex-char form (0x-prefixed or bare)"),
        )
        .arg(
            Arg::new("network")
                .long("network")
                .value_name("NET")
                .required(true)
                .help(r#"Ethereum consensus network: "mainnet" or "hoodi""#),
        )
        .arg(
            Arg::new("output-dir")
                .long("output-dir")
                .value_name("DIR")
                .help("Existing, writable directory for the output deposit_data-<ts>.json file"),
        )
        .arg(
            Arg::new("passphrase-env")
                .long("passphrase-env")
                .value_name("VAR")
                .help("Name of the environment variable holding the keystore passphrase (omit for TTY prompt)"),
        )
        .arg(
            Arg::new("i-understand-this-is-mainnet")
                .long("i-understand-this-is-mainnet")
                .action(ArgAction::SetTrue)
                .help("Required when --network mainnet: acknowledges this produces REAL mainnet deposit data with irreversible financial consequences"),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .action(ArgAction::SetTrue)
                .help("Print the deposit JSON to stdout instead of writing a file to --output-dir; no file is created. The sha256 on stderr matches the bytes written to stdout."),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("Enable debug-level structured logging to stderr"),
        )
        .arg(
            Arg::new("json-logs")
                .long("json-logs")
                .action(ArgAction::SetTrue)
                .help("Emit logs as JSON objects instead of human-readable text"),
        )
        .arg(
            Arg::new("parallel")
                .long("parallel")
                .value_name("N")
                .value_parser(clap::value_parser!(i64))
                .default_value("1")
                .help("Number of concurrent signing workers; values ≤0 or > NumCPU*4 are rejected"),
        )
        .arg(
            Arg::new("verify-with-deposit-cli")
                .long("verify-with-deposit-cli")
                .action(ArgAction::SetTrue)
                .help("After writing the deposit JSON, run the installed staking-deposit-cli to cross-check the output file (requires staking-deposit-cli >= 2.7.0; see --deposit-cli-path). Skipped in --dry-run mode. Off by default."),
        )
        .arg(
            Arg::new("deposit-cli-path")
                .long("deposit-cli-path")
                .value_name("PATH")
                .default_value("deposit")
                .help("Name or absolute path of the staking-deposit-cli binary used for --verify-with-deposit-cli (minimum supported version: 2.7.0). Defaults to \"deposit\" (looked up in PATH)."),
        )
}

/// Builds a validated [`GenConfig`] from parsed flags, enforcing the Go
/// validation order: network first, then mainnet ack, then pubkeys, then
/// keystore-dir (readability probe), then output-dir, then --parallel.
/// On success, prints the confirmation banner to `banner_out`.
pub fn load_config(m: &ArgMatches, banner_out: &mut dyn Write) -> Result<GenConfig, AppError> {
    // 1. Parse and validate --network (gen only supports mainnet and hoodi).
    let net = network::parse_flag(m.get_one::<String>("network").unwrap())
        .map_err(|e| AppError::exit2(format!("--network: {e}")))?;
    if net != Network::Mainnet && net != Network::Hoodi {
        return Err(AppError::exit2(format!(
            r#"--network: "{net}" is not supported by "eth-deposit gen"; must be "mainnet" or "hoodi""#
        )));
    }

    // 1a. Mainnet safety gate: require explicit operator acknowledgement
    // before any signing work begins.
    let mainnet_ack = m.get_flag("i-understand-this-is-mainnet");
    if net == Network::Mainnet && !mainnet_ack {
        return Err(AppError::exit2(
            "mainnet selected; pass --i-understand-this-is-mainnet to acknowledge",
        ));
    }

    // 2. Parse and validate --pubkeys.
    let pubkeys = parse_pubkeys(m.get_one::<String>("pubkeys").unwrap())
        .map_err(|e| AppError::exit2(format!("--pubkeys: {e}")))?;

    // 3. Validate --keystore-dir.
    let keystore_dir = m.get_one::<String>("keystore-dir").unwrap().clone();
    validate_keystore_dir(&keystore_dir)
        .map_err(|e| AppError::exit2(format!("--keystore-dir: {e}")))?;

    // 4. Validate --output-dir (skipped in dry-run: DryRunWriter never
    // touches disk).
    let dry_run = m.get_flag("dry-run");
    let output_dir = m
        .get_one::<String>("output-dir")
        .cloned()
        .unwrap_or_default();
    if !dry_run {
        if output_dir.is_empty() {
            return Err(AppError::exit2("--output-dir: required flag not set"));
        }
        validate_output_dir(&output_dir)
            .map_err(|e| AppError::exit2(format!("--output-dir: {e}")))?;
    }

    // 5. Validate --parallel: must be in [1, NumCPU*4].
    let parallel = *m.get_one::<i64>("parallel").unwrap();
    let max = max_parallel() as i64;
    if parallel <= 0 {
        return Err(AppError::exit2(format!(
            "--parallel: value {parallel} is invalid; must be >= 1"
        )));
    }
    if parallel > max {
        return Err(AppError::exit2(format!(
            "--parallel: value {parallel} exceeds maximum of {max} (runtime.NumCPU()*4); reduce the value or it will oversubscribe the CPU"
        )));
    }

    let cfg = GenConfig {
        keystore_dir,
        pubkeys,
        network: net,
        output_dir,
        passphrase_env: m
            .get_one::<String>("passphrase-env")
            .cloned()
            .unwrap_or_default(),
        mainnet_ack,
        dry_run,
        verbose: m.get_flag("verbose"),
        json_logs: m.get_flag("json-logs"),
        parallel: parallel as usize,
        verify_with_deposit_cli: m.get_flag("verify-with-deposit-cli"),
        deposit_cli_path: m.get_one::<String>("deposit-cli-path").unwrap().clone(),
    };

    // 6. Print confirmation banner to stderr before invoking the pipeline.
    print_banner(banner_out, &cfg);

    Ok(cfg)
}

/// Splits a comma-separated pubkey string, validates each entry, and decodes
/// them into 48-byte arrays.
///
/// Rules (port of cli.go parsePubkeys):
///   - Split on ',' and trim whitespace per entry.
///   - Accept both 0x-prefixed and unprefixed hex.
///   - Lowercase hex before decoding.
///   - Reject mixed prefix: all entries must be uniformly prefixed or unprefixed.
///   - Each hex string must decode to exactly 48 bytes (96 hex chars).
///   - Each key must be a valid compressed BLS12-381 G1 point.
pub fn parse_pubkeys(s: &str) -> Result<Vec<[u8; 48]>, String> {
    if s.trim().is_empty() {
        return Err("no pubkeys supplied".to_string());
    }

    let mut entries = Vec::new();
    for p in s.split(',') {
        let trimmed = p.trim();
        if trimmed.is_empty() {
            return Err("empty pubkey entry in list".to_string());
        }
        entries.push(trimmed);
    }

    // Determine prefix uniformity: inspect the first entry, then check all
    // others match.
    let has_prefix = |e: &str| e.starts_with("0x") || e.starts_with("0X");
    let first_has_prefix = has_prefix(entries[0]);
    for (i, e) in entries.iter().enumerate() {
        if has_prefix(e) != first_has_prefix {
            return Err(format!(
                "mixed 0x prefix: entry {i} \"{e}\" does not match prefix style of entry 0 \"{}\" — all pubkeys must be uniformly prefixed or unprefixed",
                entries[0]
            ));
        }
    }

    let mut result = Vec::with_capacity(entries.len());
    for e in entries {
        let h = e.to_lowercase();
        let h = h.strip_prefix("0x").unwrap_or(&h);

        // Validate length: 48 bytes = 96 hex chars.
        if h.len() != 96 {
            return Err(format!(
                "pubkey \"{e}\" has wrong hex length {}, want 96 (48 bytes)",
                h.len()
            ));
        }

        let b = hex::decode(h).map_err(|err| format!("pubkey \"{e}\" is not valid hex: {err}"))?;

        let mut arr = [0u8; 48];
        arr.copy_from_slice(&b);

        // Validate the bytes represent a valid compressed G1 point on BLS12-381.
        bls::validate_pubkey_bytes(arr)
            .map_err(|err| format!("pubkey \"{e}\" is not a valid BLS12-381 G1 point: {err}"))?;

        result.push(arr);
    }

    Ok(result)
}

/// Checks that dir exists and is a readable directory by probing read_dir.
fn validate_keystore_dir(dir: &str) -> Result<(), String> {
    std::fs::read_dir(dir)
        .map(|_| ())
        .map_err(|e| format!("cannot read keystore directory \"{dir}\": {e}"))
}

/// Checks that dir exists and the process can write to it, probing
/// writability by creating and immediately removing a temporary file.
fn validate_output_dir(dir: &str) -> Result<(), String> {
    let meta = match std::fs::metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("directory \"{dir}\" does not exist"));
        }
        Err(e) => return Err(format!("cannot stat directory \"{dir}\": {e}")),
    };
    if !meta.is_dir() {
        return Err(format!("\"{dir}\" is not a directory"));
    }

    // Probe writability: create a temp file then remove it immediately.
    let probe = Path::new(dir).join(format!(".eth-deposit-probe-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(f) => {
            drop(f);
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(format!("directory \"{dir}\" is not writable: {e}")),
    }
}

/// The network name for display in the banner. Mainnet is shown in uppercase
/// ("MAINNET") as an additional visual safety cue.
fn network_display(n: Network) -> String {
    if n == Network::Mainnet {
        "MAINNET".to_string()
    } else {
        n.to_string()
    }
}

/// Writes the confirmation banner to `w` (stderr in production).
/// Format: eth-deposit gen: network=<net> first_pubkey=<hex> last_pubkey=<hex> count=<n>
fn print_banner(w: &mut dyn Write, cfg: &GenConfig) {
    if cfg.pubkeys.is_empty() {
        return;
    }
    let first = cfg.pubkeys[0];
    let last = cfg.pubkeys[cfg.pubkeys.len() - 1];
    let _ = writeln!(
        w,
        "eth-deposit gen: network={} first_pubkey=0x{} last_pubkey=0x{} count={}",
        network_display(cfg.network),
        hex::encode(first),
        hex::encode(last),
        cfg.pubkeys.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::exit_code_for;
    use eth_deposit_core::bls::{self, Signer};
    use std::path::PathBuf;

    // Port of `internal/cli/cli_test.go` (validation + banner) and
    // `cli_fuzz_test.go`. Go drove the app with a NO-OP run callback, so these
    // exercise exactly `load_config` (parse/validate/banner) — never the
    // pipeline. Divergences from the Go table:
    //   - Missing clap-`required` flags (keystore-dir/pubkeys/network) and empty
    //     `--network` surface as clap parse errors, not `load_config` errors —
    //     `run` returns `Err` either way (both exit 2 at the binary).
    //   - `--i-understand-this-is-mainnet=false` (Go's explicit-false-ack tests):
    //     NOT PORTED — clap's `SetTrue` action has no `=false` form. The
    //     ack-omitted gate is covered by `mainnet_without_ack`.

    /// Derives a real BLS12-381 G1 pubkey (hex, unprefixed) from a fixed seed.
    fn valid_pubkey(seed: u8) -> String {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        let signer = bls::new_signer(&secret).expect("new_signer");
        hex::encode(signer.public_key().expect("public_key"))
    }

    /// A temp directory that removes itself on drop.
    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Tmp {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("gen-cli-test-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
        fn str(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Runs parse + validate + banner, mirroring Go's no-op-callback app.
    fn run(args: &[&str]) -> Result<(GenConfig, String), String> {
        let mut argv = vec!["gen"];
        argv.extend_from_slice(args);
        let m = command()
            .try_get_matches_from(argv)
            .map_err(|e| format!("clap: {e}"))?;
        let mut banner = Vec::new();
        let cfg = load_config(&m, &mut banner).map_err(|e| format!("load: {e}"))?;
        Ok((cfg, String::from_utf8(banner).unwrap()))
    }

    /// Runs parse (expected to succeed) + validate (expected to fail), returning
    /// the `AppError` so exit codes can be asserted.
    fn load_err(args: &[&str]) -> AppError {
        let mut argv = vec!["gen"];
        argv.extend_from_slice(args);
        let m = command().try_get_matches_from(argv).expect("clap parse ok");
        let mut banner = Vec::new();
        load_config(&m, &mut banner).expect_err("load should fail")
    }

    // --- parse_pubkeys (cli_test pubkey cases + fuzz seeds) ---

    // Go: TestPubkeyHexLength / TestPubkeyInvalidHexChars / TestPubkeyMixedPrefix.
    #[test]
    fn parse_pubkeys_matrix() {
        let pk = valid_pubkey(1);
        let pk2 = valid_pubkey(2);

        assert_eq!(parse_pubkeys(&pk).unwrap().len(), 1); // unprefixed
        assert_eq!(parse_pubkeys(&format!("0x{pk}")).unwrap().len(), 1); // prefixed
        assert_eq!(parse_pubkeys(&format!("0x{pk},0x{pk2}")).unwrap().len(), 2);
        assert_eq!(parse_pubkeys(&format!("{pk},{pk2}")).unwrap().len(), 2); // unprefixed multi

        assert!(
            parse_pubkeys(&format!("0x{}", &pk[..94])).is_err(),
            "too short"
        );
        assert!(parse_pubkeys(&format!("0x{pk}ab")).is_err(), "too long");
        assert!(parse_pubkeys("").is_err(), "empty");
        assert!(parse_pubkeys(&"g".repeat(96)).is_err(), "invalid hex chars");
        // Mixed prefix: first 0x-prefixed, second bare.
        assert!(
            parse_pubkeys(&format!("0x{pk},{pk2}")).is_err(),
            "mixed prefix"
        );
    }

    // Go: FuzzParsePubkeys — parse_pubkeys must never panic, whatever the input.
    #[test]
    fn parse_pubkeys_never_panics() {
        let pk = valid_pubkey(1);
        let mut corpus: Vec<String> = vec![
            pk.clone(),
            format!("0x{pk}"),
            format!("{pk},{pk}"),
            String::new(),
            ",".into(),
            "0x".into(),
            "0xgg".into(),
            "\0".repeat(200),
            format!("ABCDEF{}", &pk[..90]),
            format!("0x{pk},{pk}"),
        ];
        // Add systematic byte-pattern inputs.
        for b in 0u16..=255 {
            corpus.push((b as u8 as char).to_string().repeat(96));
            corpus.push(format!("0x{}", (b as u8 as char).to_string().repeat(96)));
        }
        for s in &corpus {
            let _ = parse_pubkeys(s); // must not panic; Err is fine.
        }
    }

    // --- load_config validation matrix ---

    // Go: TestSinglePubkeyHappyPath
    #[test]
    fn single_pubkey_happy_path() {
        let dir = Tmp::new();
        let ks = Tmp::new();
        let pk = valid_pubkey(1);
        let (cfg, banner) = run(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &format!("0x{pk}"),
            "--network",
            "hoodi",
            "--output-dir",
            dir.str(),
        ])
        .expect("should succeed");
        assert_eq!(cfg.keystore_dir, ks.str());
        assert_eq!(cfg.network, Network::Hoodi);
        assert_eq!(cfg.output_dir, dir.str());
        assert_eq!(cfg.pubkeys.len(), 1);
        assert!(banner.contains("eth-deposit gen:"));
        assert!(banner.contains("network=hoodi"));
        assert!(banner.contains("count=1"));
    }

    // Go: TestBannerFormat / TestMultiPubkeyHappyPath / TestUnprefixedPubkeys.
    #[test]
    fn banner_format_multi_pubkey() {
        let dir = Tmp::new();
        let ks = Tmp::new();
        let pk = valid_pubkey(1);
        let pk2 = valid_pubkey(2);
        let (cfg, banner) = run(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &format!("0x{pk},0x{pk2}"),
            "--network",
            "hoodi",
            "--output-dir",
            dir.str(),
        ])
        .expect("should succeed");
        assert_eq!(cfg.pubkeys.len(), 2);
        let want = format!(
            "eth-deposit gen: network=hoodi first_pubkey=0x{pk} last_pubkey=0x{pk2} count=2"
        );
        assert!(banner.contains(&want), "banner {banner:?}\nwant {want:?}");
    }

    // Go: TestMissingRequiredFlags — clap rejects missing required flags; a missing
    // (non-clap-required) --output-dir is rejected by load_config with exit 2.
    #[test]
    fn missing_required_flags() {
        let dir = Tmp::new();
        let ks = Tmp::new();
        let pk = valid_pubkey(1);
        // Missing clap-required flags → parse error.
        assert!(run(&[
            "--pubkeys",
            &pk,
            "--network",
            "hoodi",
            "--output-dir",
            dir.str()
        ])
        .is_err());
        assert!(run(&[
            "--keystore-dir",
            ks.str(),
            "--network",
            "hoodi",
            "--output-dir",
            dir.str()
        ])
        .is_err());
        assert!(run(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &pk,
            "--output-dir",
            dir.str()
        ])
        .is_err());
        // Missing --output-dir (validated in load_config) → exit 2.
        let err = load_err(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &pk,
            "--network",
            "hoodi",
        ]);
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("required flag not set"));
        // All present → ok.
        assert!(run(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &pk,
            "--network",
            "hoodi",
            "--output-dir",
            dir.str()
        ])
        .is_ok());
    }

    // Go: TestInvalidNetwork / TestNetworkParsedBeforeOtherWork.
    #[test]
    fn invalid_network() {
        let dir = Tmp::new();
        let ks = Tmp::new();
        let pk = valid_pubkey(1);
        let base_ok = |net: &str| {
            run(&[
                "--keystore-dir",
                ks.str(),
                "--pubkeys",
                &pk,
                "--network",
                net,
                "--output-dir",
                dir.str(),
            ])
            .is_ok()
        };
        assert!(base_ok("hoodi"));
        // gen supports mainnet/hoodi only, case-sensitive; sepolia/HOODI/Mainnet rejected.
        for bad in ["sepolia", "HOODI", "Mainnet", "invalidnet"] {
            assert!(!base_ok(bad), "network {bad} should be rejected");
        }
        // mainnet needs the ack flag to reach a happy load.
        assert!(run(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &pk,
            "--network",
            "mainnet",
            "--output-dir",
            dir.str(),
            "--i-understand-this-is-mainnet",
        ])
        .is_ok());
    }

    // Go: TestErrorIsExitCoder — invalid pubkeys → exit 2.
    #[test]
    fn invalid_pubkeys_is_exit2() {
        let dir = Tmp::new();
        let ks = Tmp::new();
        let err = load_err(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            "not-valid-hex!!!",
            "--network",
            "hoodi",
            "--output-dir",
            dir.str(),
        ]);
        assert_eq!(exit_code_for(&err), 2);
    }

    // Go: TestMainnetWithoutAck — exit 2, "mainnet selected", banner NOT emitted.
    #[test]
    fn mainnet_without_ack() {
        let dir = Tmp::new();
        let ks = Tmp::new();
        let pk = valid_pubkey(1);
        // The banner writer captures nothing because the gate fires before it.
        let mut argv = vec!["gen"];
        let extra = [
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &pk,
            "--network",
            "mainnet",
            "--output-dir",
            dir.str(),
        ];
        argv.extend_from_slice(&extra);
        let m = command().try_get_matches_from(argv).unwrap();
        let mut banner = Vec::new();
        let err = load_config(&m, &mut banner).unwrap_err();
        assert_eq!(exit_code_for(&err), 2);
        assert!(err.to_string().contains("mainnet selected"));
        assert!(
            !String::from_utf8(banner).unwrap().contains("first_pubkey="),
            "banner must not be emitted"
        );
    }

    // Go: TestMainnetWithAck — MAINNET banner (uppercase), ack set.
    #[test]
    fn mainnet_with_ack() {
        let dir = Tmp::new();
        let ks = Tmp::new();
        let pk = valid_pubkey(1);
        let (cfg, banner) = run(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &pk,
            "--network",
            "mainnet",
            "--output-dir",
            dir.str(),
            "--i-understand-this-is-mainnet",
        ])
        .expect("should succeed");
        assert_eq!(cfg.network, Network::Mainnet);
        assert!(cfg.mainnet_ack);
        assert!(banner.contains("MAINNET"), "banner {banner:?}");
    }

    // Go: TestHoodiWithAckFlag — a harmless ack flag on hoodi shows lowercase.
    #[test]
    fn hoodi_with_ack_flag() {
        let dir = Tmp::new();
        let ks = Tmp::new();
        let pk = valid_pubkey(1);
        let (cfg, banner) = run(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &pk,
            "--network",
            "hoodi",
            "--output-dir",
            dir.str(),
            "--i-understand-this-is-mainnet",
        ])
        .expect("should succeed");
        assert_eq!(cfg.network, Network::Hoodi);
        assert!(banner.contains("network=hoodi"));
        assert!(!banner.contains("MAINNET"));
    }

    // Go: TestDryRunFlag / TestVerboseFlag / TestJSONLogsFlag /
    // TestVerifyWithDepositCLIFlag / TestDepositCLIPathFlag / TestPassphraseEnvOptional.
    #[test]
    fn boolean_and_string_flags_propagate() {
        let dir = Tmp::new();
        let ks = Tmp::new();
        let pk = valid_pubkey(1);
        let base = |extra: &[&str]| -> GenConfig {
            let mut a = vec![
                "--keystore-dir",
                ks.str(),
                "--pubkeys",
                pk.as_str(),
                "--network",
                "hoodi",
                "--output-dir",
                dir.str(),
            ];
            a.extend_from_slice(extra);
            run(&a).expect("ok").0
        };
        assert!(!base(&[]).dry_run);
        assert!(base(&["--dry-run"]).dry_run);
        assert!(!base(&[]).verbose);
        assert!(base(&["--verbose"]).verbose);
        assert!(!base(&[]).json_logs);
        assert!(base(&["--json-logs"]).json_logs);
        assert!(!base(&[]).verify_with_deposit_cli);
        assert!(base(&["--verify-with-deposit-cli"]).verify_with_deposit_cli);
        assert_eq!(base(&[]).deposit_cli_path, "deposit");
        assert_eq!(
            base(&["--deposit-cli-path", "/usr/local/bin/deposit"]).deposit_cli_path,
            "/usr/local/bin/deposit"
        );
        assert_eq!(base(&[]).passphrase_env, "");
        assert_eq!(
            base(&["--passphrase-env", "MY_PASSPHRASE"]).passphrase_env,
            "MY_PASSPHRASE"
        );
    }

    // Go: TestParallelFlag — default 1, valid N propagates, invalid rejected exit 2.
    #[test]
    fn parallel_flag() {
        let dir = Tmp::new();
        let ks = Tmp::new();
        let pk = valid_pubkey(1);
        let ok = |extra: &[&str]| -> Result<(GenConfig, String), String> {
            let mut a = vec![
                "--keystore-dir",
                ks.str(),
                "--pubkeys",
                pk.as_str(),
                "--network",
                "hoodi",
                "--output-dir",
                dir.str(),
            ];
            a.extend_from_slice(extra);
            run(&a)
        };
        assert_eq!(ok(&[]).unwrap().0.parallel, 1);
        assert_eq!(ok(&["--parallel", "4"]).unwrap().0.parallel, 4);
        // Zero, too-large, and negative (via `=` so clap doesn't treat it as a flag).
        for bad in [
            &["--parallel", "0"][..],
            &["--parallel", "99999"][..],
            &["--parallel=-1"][..],
        ] {
            let mut a = vec![
                "--keystore-dir",
                ks.str(),
                "--pubkeys",
                pk.as_str(),
                "--network",
                "hoodi",
                "--output-dir",
                dir.str(),
            ];
            a.extend_from_slice(bad);
            let err = load_err(&a);
            assert_eq!(exit_code_for(&err), 2, "parallel {bad:?}");
            assert!(err.to_string().contains("--parallel"));
        }
    }

    // Go: TestKeystoreDirValidation / TestNonexistentOutputDir / TestOutputDirIsFile.
    #[test]
    fn dir_validation() {
        let dir = Tmp::new();
        let ks = Tmp::new();
        let pk = valid_pubkey(1);

        // nonexistent keystore-dir → err.
        let missing_ks = dir.0.join("no-such-dir");
        assert!(run(&[
            "--keystore-dir",
            missing_ks.to_str().unwrap(),
            "--pubkeys",
            &pk,
            "--network",
            "hoodi",
            "--output-dir",
            dir.str(),
        ])
        .is_err());

        // file as keystore-dir → err.
        let file = dir.0.join("a-file");
        std::fs::write(&file, b"x").unwrap();
        assert!(run(&[
            "--keystore-dir",
            file.to_str().unwrap(),
            "--pubkeys",
            &pk,
            "--network",
            "hoodi",
            "--output-dir",
            dir.str(),
        ])
        .is_err());

        // nonexistent output-dir → err.
        let missing_out = dir.0.join("no-out");
        let err = load_err(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &pk,
            "--network",
            "hoodi",
            "--output-dir",
            missing_out.to_str().unwrap(),
        ]);
        assert_eq!(exit_code_for(&err), 2);

        // file as output-dir → err.
        assert!(run(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &pk,
            "--network",
            "hoodi",
            "--output-dir",
            file.to_str().unwrap(),
        ])
        .is_err());
    }

    // Go: TestOutputDirConditionalRequiredness — output-dir required/validated only
    // outside --dry-run.
    #[test]
    fn output_dir_conditional_requiredness() {
        let ks = Tmp::new();
        let pk = valid_pubkey(1);
        let invalid = std::env::temp_dir().join("gen-cli-does-not-exist-xyz");

        // dry-run without --output-dir → ok, OutputDir empty.
        let (cfg, _) = run(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &pk,
            "--network",
            "hoodi",
            "--dry-run",
        ])
        .unwrap();
        assert_eq!(cfg.output_dir, "");
        assert!(cfg.dry_run);

        // dry-run with invalid --output-dir → ok (validation skipped).
        assert!(run(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &pk,
            "--network",
            "hoodi",
            "--output-dir",
            invalid.to_str().unwrap(),
            "--dry-run",
        ])
        .is_ok());

        // no dry-run, missing --output-dir → exit 2.
        let err = load_err(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &pk,
            "--network",
            "hoodi",
        ]);
        assert_eq!(exit_code_for(&err), 2);

        // no dry-run, invalid --output-dir → exit 2.
        let err = load_err(&[
            "--keystore-dir",
            ks.str(),
            "--pubkeys",
            &pk,
            "--network",
            "hoodi",
            "--output-dir",
            invalid.to_str().unwrap(),
        ]);
        assert_eq!(exit_code_for(&err), 2);
    }
}
