//! Entry point for eth-deposit, ported from `cmd/eth-deposit/main.go`.
//! Wires the gen, build, sign, run, send, and key subcommands.
//!
//! Exit codes:
//!
//!   0 — success
//!   1 — unexpected / internal error
//!   2 — user / configuration error (bad input, unknown network, missing file,
//!       missing required flag, build-side RPC chain-ID mismatch)
//!   3 — signer / crypto error (bad key, no device, app not open,
//!       signer-side chain-ID mismatch)
//!   4 — user abort (SIGINT or Ledger rejection)
//!   5 — broadcast / RPC error (dial failure, gas/nonce estimation failure,
//!       eth_sendRawTransaction error, broadcast-side chain-ID mismatch)

mod build_cmd;
mod config;
mod errors;
mod gen_cli;
mod gen_cmd;
mod key_cli;
mod key_cmd;
mod logging;
mod run_cmd;
mod send_cmd;
mod sign_cmd;

use std::sync::OnceLock;

use clap::Command;

use eth_deposit_core::cancel::CancelToken;

use crate::errors::{exit_code_for, AppError};
use crate::logging::{Format, Level, Logger};

/// version/commit/date are baked at build time via environment variables
/// (mirroring Go's -ldflags injection). Defaults are used for local builds.
const VERSION: &str = match option_env!("ETH_DEPOSIT_VERSION") {
    Some(v) => v,
    None => "dev",
};
const COMMIT: &str = match option_env!("ETH_DEPOSIT_COMMIT") {
    Some(v) => v,
    None => "none",
};
const DATE: &str = match option_env!("ETH_DEPOSIT_DATE") {
    Some(v) => v,
    None => "unknown",
};

/// The process-wide cancellation token, cancelled by the SIGINT handler.
fn global_cancel() -> &'static CancelToken {
    static TOKEN: OnceLock<CancelToken> = OnceLock::new();
    TOKEN.get_or_init(CancelToken::new)
}

extern "C" fn on_sigint(_sig: libc::c_int) {
    // Async-signal-safe: cancel() is a single atomic store. Invariant: main
    // must call global_cancel() before install_sigint_handler() so TOKEN is
    // already initialized — get_or_init (heap allocation) must never run
    // inside this signal context.
    global_cancel().cancel();
}

fn install_sigint_handler() {
    // SAFETY: installing a handler that only performs an atomic store.
    // Caller must have initialized global_cancel() first (see on_sigint).
    unsafe {
        libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t);
    }
}

fn root_command() -> Command {
    Command::new("eth-deposit")
        .about("Generate, build, sign, and broadcast Ethereum Beacon Chain deposit transactions")
        .version(&**Box::leak(Box::new(format!(
            "{VERSION} (commit={COMMIT}, built={DATE})"
        ))))
        .long_about(
            "eth-deposit takes BLS validator keystores all the way through to a broadcast\n\
             Ethereum deposit transaction for the Beacon Chain deposit contract.\n\n\
             It supports a secure workflow:\n\
             \x20 key    - Generate or recover EIP-2335 BLS validator keystores from a BIP-39 mnemonic\n\
             \x20 gen    - Generate Launchpad-compatible deposit_data JSON from BLS validator keystores\n\
             \x20 build  - Construct an unsigned transaction (supports offline/air-gapped mode)\n\
             \x20 sign   - Sign the transaction, with Ledger hardware as the primary method\n\
             \x20 run    - Convenience: build + sign in one step (same machine, no serialization to disk)\n\
             \x20 send   - Broadcast a signed tx via JSON-RPC (requires explicit network-name confirmation)\n\n\
             The tool produces standard hex-encoded RLP output ready for eth_sendRawTransaction.\n\n\
             Exit codes: 0=success, 1=internal error, 2=bad input, 3=signer/crypto error, 4=user abort, 5=broadcast/RPC error.",
        )
        .subcommand(key_cli::command())
        .subcommand(gen_cli::command())
        .subcommand(build_cmd::command())
        .subcommand(sign_cmd::command())
        .subcommand(run_cmd::command())
        .subcommand(send_cmd::command())
}

fn main() {
    // Initialize CancelToken before arming SIGINT so on_sigint never runs
    // OnceLock::get_or_init inside a signal handler (not async-signal-safe).
    let cancel = global_cancel();
    install_sigint_handler();

    let matches = match root_command().try_get_matches() {
        Ok(m) => m,
        // clap: usage errors exit 2; --help/--version print and exit 0.
        Err(e) => e.exit(),
    };

    let result: Result<(), AppError> = match matches.subcommand() {
        Some(("key", sub)) => match sub.subcommand() {
            Some(("new", m)) => key_cli::run_new(m, cancel),
            Some(("recover", m)) => key_cli::run_recover(m, cancel),
            // subcommand_required(true) on the key group; clap rejects bare `key`.
            _ => unreachable!("key requires a subcommand"),
        },
        Some(("gen", sub)) => {
            let mut stderr = std::io::stderr();
            gen_cli::load_config(sub, &mut stderr).and_then(|cfg| gen_cmd::run_gen(&cfg, cancel))
        }
        Some(("build", sub)) => build_cmd::run(sub, cancel),
        Some(("sign", sub)) => sign_cmd::run(sub, cancel),
        Some(("run", sub)) => run_cmd::run(sub, cancel),
        Some(("send", sub)) => send_cmd::run(sub, cancel),
        _ => {
            // No subcommand: print help and exit 0 (urfave/cli behavior).
            let _ = root_command().print_help();
            println!();
            return;
        }
    };

    if let Err(err) = result {
        // RPC URLs are redacted by construction inside the tx crate, so the
        // rendered message is safe to log (Go scrubs at this boundary instead).
        let logger = Logger::stderr(Level::Info, Format::Text);
        logger.error("fatal", &[("err", err.to_string())]);
        std::process::exit(exit_code_for(&err));
    }
}
