//! Binary-driven port of `cmd/eth-deposit/usage_error_test.go`. Every subcommand
//! must map a usage error (a missing required flag, or a bad flag value) to exit
//! code 2 rather than the exit-1 fallback. In Rust, clap's parse errors call
//! `e.exit()`, which exits with status 2 for usage errors.

mod common;

use common::eth_deposit;

fn assert_exit2(args: &[&str], name: &str) {
    let out = eth_deposit().args(args).output().expect("run");
    assert_eq!(
        out.status.code(),
        Some(2),
        "{name}: expected exit 2, got {:?}; stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

// Go: TestUsageError_ExitsTwo (table).
#[test]
fn build_missing_input_file() {
    assert_exit2(
        &["build", "--network", "holesky"],
        "build missing --input-file",
    );
}

#[test]
fn gen_missing_required_flags() {
    assert_exit2(&["gen"], "gen missing required flags");
}

#[test]
fn sign_missing_signer() {
    assert_exit2(&["sign"], "sign missing --signer");
}

#[test]
fn run_missing_input_file() {
    assert_exit2(&["run"], "run missing --input-file");
}

#[test]
fn build_bad_index_value() {
    assert_exit2(
        &[
            "build",
            "--network",
            "holesky",
            "--input-file",
            "x",
            "--index",
            "abc",
        ],
        "build bad --index value",
    );
}
