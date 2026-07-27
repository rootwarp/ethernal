//! The `send` subcommand, ported from `cmd/ethernal/send.go`.
//!
//! `send` broadcasts a signed transaction (from `sign` or `run`) to the network
//! via `eth_sendRawTransaction`, after an explicit network-name confirmation.
//!
//! WARNING: this command broadcasts to the live network and SPENDS REAL ETH.

use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use clap::{Arg, ArgAction, ArgMatches, Command};

use ethernal_core::cancel::CancelToken;
use ethernal_core::network;
use ethernal_core::output::write_atomic;
use ethernal_signer::SignedTx;
use ethernal_tx::{EthBroadcaster, EthClient, Receipt, TxError};

use crate::build_cmd::read_input;
use crate::errors::AppError;
use crate::logging::{Format, Level, Logger};

/// The broadcaster factory seam (port of Go's `var newBroadcaster`). Passed into
/// [`send_action`] so tests can inject a mock; the production entry point
/// [`run`] passes [`new_broadcaster`].
type BroadcasterFactory<'a> = &'a dyn Fn(&str) -> Result<Box<dyn EthBroadcaster>, AppError>;

/// Parsed, validated inputs for the send subcommand. Port of `main.SendConfig`.
#[derive(Debug, Clone)]
pub struct SendConfig {
    /// The path to the signed tx JSON, or "-" for stdin.
    pub input_file: String,
    /// The JSON-RPC endpoint for broadcast.
    pub rpc_url: String,
    /// Skips the interactive double-confirmation prompt.
    pub yes: bool,
    /// Polls until the receipt is available.
    pub wait_for_receipt: bool,
    /// The maximum time to wait for a receipt.
    pub receipt_timeout: Duration,
    /// An optional file path to write the receipt JSON.
    pub receipt_output_file: String,
}

/// The clap definition of the `send` subcommand.
pub fn command() -> Command {
    Command::new("send")
        .about("Broadcast a signed deposit transaction via JSON-RPC")
        .override_usage(
            "ethernal tx send --input FILE --rpc-url URL [--yes] [--wait-for-receipt] [--receipt-output FILE]",
        )
        .long_about(
            "Submits a signed transaction (produced by tx sign or tx run) to the Ethereum network\n\
             via eth_sendRawTransaction.\n\n\
             WARNING: This command broadcasts to the live network and SPENDS REAL ETH.\n\
             You will be prompted to type the network name before anything is sent.\n\
             Use --yes to bypass the confirmation prompt (for automation only).\n\n\
             Exit codes:\n\
             \x20 0  Success\n\
             \x20 2  User / configuration error (missing flags, invalid JSON)\n\
             \x20 4  User abort (Ctrl-C or declined confirmation)\n\
             \x20 5  Broadcast / RPC error (dial failure, broadcast-side chain ID mismatch, node rejection)",
        )
        .arg(
            Arg::new("input")
                .long("input")
                .short('i')
                .value_name("FILE")
                .help("Path to the signed transaction JSON (from sign or run), or '-' for stdin"),
        )
        .arg(
            Arg::new("rpc-url")
                .long("rpc-url")
                .value_name("URL")
                .env("ETHERNAL_TX_RPC_URL")
                .help("JSON-RPC endpoint URL for broadcast"),
        )
        .arg(
            Arg::new("yes")
                .long("yes")
                .action(ArgAction::SetTrue)
                .help("Skip the interactive confirmation prompt (for non-interactive automation; use with caution)"),
        )
        .arg(
            Arg::new("wait-for-receipt")
                .long("wait-for-receipt")
                .action(ArgAction::SetTrue)
                .help("Poll until the transaction receipt is available (or --receipt-timeout elapses)"),
        )
        .arg(
            Arg::new("receipt-timeout")
                .long("receipt-timeout")
                .value_name("DURATION")
                .default_value("60s")
                .help("Maximum time to wait for a transaction receipt when --wait-for-receipt is set"),
        )
        .arg(
            Arg::new("receipt-output")
                .long("receipt-output")
                .value_name("FILE")
                .help("Write the transaction receipt JSON to this file (implies --wait-for-receipt)"),
        )
}

/// Parses and validates send subcommand flags. Port of `LoadSendConfig`.
pub fn load_send_config(m: &ArgMatches) -> Result<SendConfig, AppError> {
    let input_file = m.get_one::<String>("input").cloned().unwrap_or_default();
    if input_file.is_empty() {
        return Err(AppError::exit2("--input: required flag not set"));
    }

    let rpc_url = m.get_one::<String>("rpc-url").cloned().unwrap_or_default();
    if rpc_url.is_empty() {
        return Err(AppError::exit2("--rpc-url: required flag not set"));
    }

    let timeout_str = m
        .get_one::<String>("receipt-timeout")
        .cloned()
        .unwrap_or_default();
    let mut timeout = parse_go_duration(&timeout_str).map_err(|_| {
        AppError::exit2(format!(
            "--receipt-timeout: invalid duration {timeout_str:?}"
        ))
    })?;
    if timeout.is_zero() {
        timeout = Duration::from_secs(60);
    }

    let receipt_output = m
        .get_one::<String>("receipt-output")
        .cloned()
        .unwrap_or_default();
    let wait_for_receipt = m.get_flag("wait-for-receipt") || !receipt_output.is_empty();

    Ok(SendConfig {
        input_file,
        rpc_url,
        yes: m.get_flag("yes"),
        wait_for_receipt,
        receipt_timeout: timeout,
        receipt_output_file: receipt_output,
    })
}

/// The production `EthBroadcaster` factory (port of `newBroadcaster`).
pub fn new_broadcaster(rpc_url: &str) -> Result<Box<dyn EthBroadcaster>, AppError> {
    EthClient::new(rpc_url)
        .map(|c| Box::new(c) as Box<dyn EthBroadcaster>)
        .map_err(AppError::Tx)
}

/// The `send` action.
pub fn run(m: &ArgMatches, cancel: &CancelToken) -> Result<(), AppError> {
    let cfg = load_send_config(m)?;
    send_action(&cfg, cancel, &|url| new_broadcaster(url))
}

/// Executes the send workflow. `new_broadcaster` is the injectable dial seam.
pub fn send_action(
    cfg: &SendConfig,
    cancel: &CancelToken,
    new_broadcaster: BroadcasterFactory,
) -> Result<(), AppError> {
    // 1. Read signed tx.
    let raw = read_input(&cfg.input_file).map_err(|e| AppError::exit2(format!("--input: {e}")))?;
    let signed: SignedTx = serde_json::from_slice(&raw)
        .map_err(|e| AppError::exit2(format!("invalid input JSON: {e}")))?;

    // 2. Dial RPC (dial failure → exit 5, unwrapped).
    let broadcaster = new_broadcaster(&cfg.rpc_url)?;

    // 3. Verify chain ID.
    let rpc_chain_id = broadcaster.broadcaster_chain_id().map_err(|e| {
        AppError::Tx(TxError::BroadcastFailed(
            format!("fetch chain ID: {e}").into(),
        ))
    })?;
    if rpc_chain_id != signed.unsigned.chain_id {
        return Err(AppError::Tx(TxError::BroadcastChainIdMismatch {
            signed: signed.unsigned.chain_id,
            rpc: rpc_chain_id,
        }));
    }

    // 4. Resolve network for display. The Rust `Network` enum cannot hold an
    // arbitrary "chain-<id>" name, so on an unknown chain we carry a display
    // name + empty explorer directly (Go used a synthetic Params.Name string).
    let (net_name, explorer_url) = match network::lookup_by_chain_id(rpc_chain_id) {
        Ok(p) => (p.name.to_string(), p.explorer_url.to_string()),
        Err(_) => (format!("chain-{rpc_chain_id}"), String::new()),
    };

    // 5. Print the "about to broadcast" prompt to stderr.
    let value_wei = hex_to_u128(&signed.unsigned.value);
    let max_fee_wei = hex_to_u128(&signed.unsigned.max_fee_per_gas);
    let mut err = std::io::stderr();
    let _ = writeln!(err);
    let _ = writeln!(
        err,
        "> You are about to BROADCAST a {} deposit transaction.",
        format_eth(value_wei)
    );
    let _ = writeln!(
        err,
        ">   Network:        {net_name} (chain ID {rpc_chain_id})"
    );
    let _ = writeln!(err, ">   From:           {}", signed.from);
    let _ = writeln!(err, ">   To (deposit):   {}", signed.unsigned.to);
    let _ = writeln!(err, ">   Value:          {}", format_eth(value_wei));
    let _ = writeln!(err, ">   Nonce:          {}", signed.unsigned.nonce);
    let _ = writeln!(err, ">   MaxFeePerGas:   {}", format_gwei(max_fee_wei));
    let _ = writeln!(err, ">   Tx hash:        {}", signed.hash);
    let _ = writeln!(err, ">");

    // 6. Confirmation.
    if !cfg.yes {
        let _ = write!(err, "> Type the network name to confirm: ");
        let _ = err.flush();
        let mut line = String::new();
        let read = std::io::stdin().read_line(&mut line);
        // Go's bufio ReadString('\n') returns an error when EOF is reached before
        // a newline; mirror that by requiring a trailing '\n'.
        let complete = matches!(read, Ok(n) if n > 0) && line.ends_with('\n');
        if !complete {
            let detail = match read {
                Err(e) => e.to_string(),
                Ok(_) => "EOF".to_string(),
            };
            let _ = writeln!(err, "\nAborted.");
            return Err(AppError::Aborted(detail));
        }
        let input = line.trim();
        if !input.eq_ignore_ascii_case(&net_name) {
            let _ = writeln!(
                err,
                "> Confirmation failed (got {input:?}, want {net_name:?}). Aborted."
            );
            return Err(AppError::Aborted(String::new()));
        }
    }

    // 7. Broadcast.
    let _ = writeln!(err, "> Broadcasting...");
    let tx_hash = broadcaster
        .send_raw_transaction(&signed.raw_rlp)
        .map_err(AppError::Tx)?;

    // 8. Print result.
    let mut out = std::io::stdout();
    let _ = writeln!(out, "Tx hash: {tx_hash}");
    if !explorer_url.is_empty() {
        let _ = writeln!(out, "Explorer: {explorer_url}/tx/{tx_hash}");
    }
    let logger = Logger::stderr(Level::Info, Format::Text);
    logger.info(
        "broadcast succeeded",
        &[("hash", tx_hash.clone()), ("network", net_name.clone())],
    );

    // 9. Optionally wait for the receipt.
    if cfg.wait_for_receipt {
        let rec = poll_receipt(broadcaster.as_ref(), &tx_hash, cfg.receipt_timeout, cancel)
            .map_err(|e| AppError::context("receipt", e))?;
        if let Some(rec) = rec {
            let status_str = if rec.status == 0 {
                "REVERTED"
            } else {
                "success"
            };
            let _ = writeln!(
                out,
                "Receipt: status={} block={} gasUsed={}",
                status_str, rec.block_number, rec.gas_used
            );

            if !cfg.receipt_output_file.is_empty() {
                let mut rec_json = serde_json::to_vec_pretty(&rec)
                    .map_err(|e| AppError::exit2(format!("receipt: marshal: {e}")))?;
                rec_json.push(b'\n');
                write_atomic(Path::new(&cfg.receipt_output_file), &rec_json, 0o600).map_err(
                    |e| {
                        AppError::exit2(format!(
                            "--receipt-output: write {}: {e}",
                            cfg.receipt_output_file
                        ))
                    },
                )?;
                logger.info(
                    "wrote receipt",
                    &[("path", cfg.receipt_output_file.clone())],
                );
            }
        }
    }

    Ok(())
}

/// Polls for a transaction receipt until timeout. Port of `pollReceipt`, with a
/// [`CancelToken`] in place of `ctx.Done()`.
fn poll_receipt(
    bc: &dyn EthBroadcaster,
    tx_hash: &str,
    timeout: Duration,
    cancel: &CancelToken,
) -> Result<Option<Receipt>, AppError> {
    let mut poll_interval = Duration::from_secs(2);
    if timeout < poll_interval {
        poll_interval = timeout / 2;
        if poll_interval < Duration::from_millis(10) {
            poll_interval = Duration::from_millis(10);
        }
    }

    let deadline = Instant::now() + timeout;
    loop {
        let rec = bc
            .transaction_receipt(tx_hash)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if rec.is_some() {
            return Ok(rec);
        }
        if Instant::now() > deadline {
            return Err(AppError::Internal(format!(
                "timed out waiting for receipt after {}",
                format_go_duration(timeout)
            )));
        }
        // Cancellation between polls maps to exit 4 (like ctx.Err()).
        if cancel.is_cancelled() {
            return Err(AppError::Tx(TxError::Cancelled));
        }
        std::thread::sleep(poll_interval);
        if cancel.is_cancelled() {
            return Err(AppError::Tx(TxError::Cancelled));
        }
    }
}

/// Parses a 0x-prefixed hex string into a u128, returning 0 on any parse failure
/// (mirrors Go's `hexToBigInt` ignoring the ok bool). Only the lowercase `0x`
/// prefix is stripped, matching `strings.TrimPrefix(s, "0x")`.
fn hex_to_u128(s: &str) -> u128 {
    let t = s.strip_prefix("0x").unwrap_or(s);
    u128::from_str_radix(t, 16).unwrap_or(0)
}

/// Renders a wei quantity as ETH with 6 decimals (port of `formatETH`).
fn format_eth(wei: u128) -> String {
    format!("{:.6} ETH", wei as f64 / 1e18)
}

/// Renders a wei quantity as Gwei with 6 decimals (port of `formatGwei`).
fn format_gwei(wei: u128) -> String {
    format!("{:.6} Gwei", wei as f64 / 1e9)
}

/// A small parser for Go-style duration strings (a sequence of number+unit
/// segments over ns/us/µs/ms/s/m/h), sufficient for the `--receipt-timeout`
/// flag. `"0"` (no unit) is accepted as zero, matching `time.ParseDuration`.
fn parse_go_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut total = Duration::ZERO;
    let mut any = false;
    while i < bytes.len() {
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        if i == start {
            return Err(format!("invalid duration {s:?}"));
        }
        let num: f64 = s[start..i]
            .parse()
            .map_err(|_| format!("invalid duration {s:?}"))?;
        let ustart = i;
        while i < bytes.len() && !bytes[i].is_ascii_digit() && bytes[i] != b'.' {
            i += 1;
        }
        let unit = &s[ustart..i];
        let secs = match unit {
            "ns" => num * 1e-9,
            "us" | "µs" => num * 1e-6,
            "ms" => num * 1e-3,
            "s" => num,
            "m" => num * 60.0,
            "h" => num * 3600.0,
            _ => return Err(format!("unknown unit {unit:?} in duration {s:?}")),
        };
        total += Duration::from_secs_f64(secs);
        any = true;
    }
    if !any {
        return Err(format!("invalid duration {s:?}"));
    }
    Ok(total)
}

/// Renders a duration roughly like Go's `time.Duration.String()` for the values
/// used in the timeout message (whole seconds and below).
fn format_go_duration(d: Duration) -> String {
    let total_ns = d.as_nanos();
    if total_ns == 0 {
        return "0s".to_string();
    }
    if total_ns < 1_000_000_000 {
        if total_ns.is_multiple_of(1_000_000) {
            return format!("{}ms", total_ns / 1_000_000);
        }
        if total_ns.is_multiple_of(1_000) {
            return format!("{}µs", total_ns / 1_000);
        }
        return format!("{total_ns}ns");
    }
    let secs = d.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    let sub_ms = d.subsec_millis();
    let mut out = String::new();
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if h > 0 || m > 0 {
        out.push_str(&format!("{m}m"));
    }
    if sub_ms > 0 {
        out.push_str(&format!("{s}.{sub_ms:03}s"));
    } else {
        out.push_str(&format!("{s}s"));
    }
    out
}
