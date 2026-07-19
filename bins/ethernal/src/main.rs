//! Entry point for ethernal, ported from `cmd/ethernal/main.go`.
//! Wires the key, account, deposit (gen/build), and tx (sign/run/send) namespaces.
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

mod account_cli;
mod account_cmd;
mod build_cmd;
mod config;
mod errors;
mod fs_util;
mod gen_cli;
mod gen_cmd;
mod key_cli;
mod key_cmd;
mod keystore_cli;
mod logging;
mod run_cmd;
mod send_cmd;
mod sign_cmd;

use std::sync::OnceLock;

use clap::Command;

use ethernal_core::cancel::CancelToken;

use crate::errors::{exit_code_for, AppError};
use crate::logging::{Format, Level, Logger};

/// version/commit/date are baked at build time via environment variables
/// (mirroring Go's -ldflags injection). Defaults are used for local builds.
const VERSION: &str = match option_env!("ETHERNAL_VERSION") {
    Some(v) => v,
    None => "dev",
};
const COMMIT: &str = match option_env!("ETHERNAL_COMMIT") {
    Some(v) => v,
    None => "none",
};
const DATE: &str = match option_env!("ETHERNAL_DATE") {
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
    Command::new("ethernal")
        .about("Generate, build, sign, and broadcast Ethereum Beacon Chain deposit transactions")
        .version(&**Box::leak(Box::new(format!(
            "{VERSION} (commit={COMMIT}, built={DATE})"
        ))))
        .long_about(
            "ethernal takes BLS validator keystores all the way through to a broadcast\n\
             Ethereum deposit transaction for the Beacon Chain deposit contract.\n\n\
             It supports a secure workflow under four namespaces:\n\
             \x20 key     - Generate or recover EIP-2335 BLS validator keystores from a BIP-39 mnemonic\n\
             \x20 account - Generate or recover EIP-155 secp256k1 execution-layer keystores\n\
             \x20 deposit - Beacon-chain deposit workflow: deposit_data JSON and deposit-tx construction\n\
             \x20          (gen, build)\n\
             \x20 tx      - Sign, run (build+sign), and broadcast Ethereum transactions\n\
             \x20          (sign, run, send)\n\n\
             The tool produces standard hex-encoded RLP output ready for eth_sendRawTransaction.\n\n\
             Exit codes: 0=success, 1=internal error, 2=bad input, 3=signer/crypto error, 4=user abort, 5=broadcast/RPC error.",
        )
        .subcommand(key_cli::command())
        .subcommand(account_cli::command())
        .subcommand(
            Command::new("deposit")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .about(
                    "Beacon-chain deposit workflow: deposit_data JSON and deposit-tx construction",
                )
                .subcommand(gen_cli::command())
                .subcommand(build_cmd::command()),
        )
        .subcommand(
            Command::new("tx")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .about("Sign, run (build+sign), and broadcast Ethereum transactions")
                .subcommand(sign_cmd::command())
                .subcommand(send_cmd::command())
                .subcommand(run_cmd::command()),
        )
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
        Some(("account", sub)) => match sub.subcommand() {
            Some(("new", m)) => account_cli::run_new(m, cancel),
            Some(("recover", m)) => account_cli::run_recover(m, cancel),
            // subcommand_required(true) on the account group; clap rejects bare `account`.
            _ => unreachable!("account requires a subcommand"),
        },
        Some(("deposit", sub)) => match sub.subcommand() {
            Some(("gen", m)) => {
                let mut stderr = std::io::stderr();
                gen_cli::load_config(m, &mut stderr).and_then(|cfg| gen_cmd::run_gen(&cfg, cancel))
            }
            Some(("build", m)) => build_cmd::run(m, cancel),
            // subcommand_required(true) on the deposit group; clap rejects bare `deposit`.
            _ => unreachable!("deposit requires a subcommand"),
        },
        Some(("tx", sub)) => match sub.subcommand() {
            Some(("sign", m)) => sign_cmd::run(m, cancel),
            Some(("send", m)) => send_cmd::run(m, cancel),
            Some(("run", m)) => run_cmd::run(m, cancel),
            // subcommand_required(true) on the tx group; clap rejects bare `tx`.
            _ => unreachable!("tx requires a subcommand"),
        },
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
