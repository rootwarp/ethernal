#!/usr/bin/env bash
# diff-go.sh — byte-identity harness between the Go reference implementation
# and the Rust port (issue R5-1). Runs both binaries on identical inputs and
# diffs stdout (and stderr where it carries no timestamps) plus exit codes.
#
# Usage: bash scripts/diff-go.sh          (from rust/)
# Requires: go/bin/eth-deposit (make -C ../go build) and
#           target/release/eth-deposit (make build).
set -u

RUST_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$RUST_DIR/.." && pwd)"
GO_BIN="$REPO_ROOT/go/bin/eth-deposit"
RUST_BIN="$RUST_DIR/target/release/eth-deposit"
TESTDATA="$RUST_DIR/testdata"

if [[ ! -x "$GO_BIN" ]]; then
  echo "Go binary missing; building..." >&2
  (cd "$REPO_ROOT/go" && make build) || exit 1
fi
if [[ ! -x "$RUST_BIN" ]]; then
  echo "Rust binary missing; building..." >&2
  (cd "$RUST_DIR" && cargo build --release --bin eth-deposit) || exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAIL=0
PASS=0

# run_both <name> <compare_stderr:yes|no> [--] args...
# Runs both binaries with identical args/stdin/env, then compares exit codes,
# stdout bytes, and optionally stderr bytes.
run_both() {
  local name="$1" cmp_stderr="$2"; shift 2
  [[ "${1:-}" == "--" ]] && shift

  "$GO_BIN" "$@" >"$WORK/$name.go.out" 2>"$WORK/$name.go.err" </dev/null
  local go_code=$?
  "$RUST_BIN" "$@" >"$WORK/$name.rs.out" 2>"$WORK/$name.rs.err" </dev/null
  local rs_code=$?

  local ok=1
  if [[ $go_code -ne $rs_code ]]; then
    echo "FAIL [$name] exit codes differ: go=$go_code rust=$rs_code" >&2
    ok=0
  fi
  if ! cmp -s "$WORK/$name.go.out" "$WORK/$name.rs.out"; then
    echo "FAIL [$name] stdout differs:" >&2
    diff "$WORK/$name.go.out" "$WORK/$name.rs.out" | head -10 >&2
    ok=0
  fi
  if [[ "$cmp_stderr" == "yes" ]] && ! cmp -s "$WORK/$name.go.err" "$WORK/$name.rs.err"; then
    echo "FAIL [$name] stderr differs:" >&2
    diff "$WORK/$name.go.err" "$WORK/$name.rs.err" | head -10 >&2
    ok=0
  fi
  if [[ $ok -eq 1 ]]; then
    echo "ok   [$name] (exit=$go_code)"
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
}

# expect_golden <name> <file> <golden> — byte-compare an output artifact.
expect_golden() {
  local name="$1" file="$2" golden="$3"
  if cmp -s "$file" "$golden"; then
    echo "ok   [$name] matches golden"
    PASS=$((PASS + 1))
  else
    echo "FAIL [$name] does not match golden $golden" >&2
    diff "$file" "$golden" | head -10 >&2
    FAIL=$((FAIL + 1))
  fi
}

HOODI_PK="0x$(cat "$TESTDATA/hoodi/pubkeys.txt")"
MAINNET_PK="0x$(cat "$TESTDATA/mainnet/pubkeys.txt")"

# --- gen: dry-run on both networks (stderr is timestamp-free: banner+summary) ---
export ETH_DEPOSIT_DIFF_PASS="$(cat "$TESTDATA/hoodi/passphrase.txt")"
run_both gen-hoodi yes -- gen --network hoodi \
  --keystore-dir "$TESTDATA/hoodi/keystores" --pubkeys "$HOODI_PK" \
  --passphrase-env ETH_DEPOSIT_DIFF_PASS --dry-run
expect_golden gen-hoodi-golden "$WORK/gen-hoodi.rs.out" "$TESTDATA/hoodi/deposit_data-expected.json"

export ETH_DEPOSIT_DIFF_PASS="$(cat "$TESTDATA/mainnet/passphrase.txt")"
run_both gen-mainnet yes -- gen --network mainnet --i-understand-this-is-mainnet \
  --keystore-dir "$TESTDATA/mainnet/keystores" --pubkeys "$MAINNET_PK" \
  --passphrase-env ETH_DEPOSIT_DIFF_PASS --dry-run
expect_golden gen-mainnet-golden "$WORK/gen-mainnet.rs.out" "$TESTDATA/mainnet/deposit_data-expected.json"
unset ETH_DEPOSIT_DIFF_PASS

# --- build: offline holesky (stderr not compared: none expected on stdout path) ---
run_both build-offline no -- build --network holesky \
  --input-file "$TESTDATA/phase2/holesky/deposit_data_single.json"
expect_golden build-offline-golden "$WORK/build-offline.rs.out" \
  "$TESTDATA/phase2/holesky/unsigned_tx_golden.json"

# --- sign: local signer over the phase3 fixture ---
export ETH_DEPOSIT_TX_PRIVATE_KEY="$(cat "$TESTDATA/phase3/holesky/private_key.txt")"
run_both sign-local no -- sign --signer local \
  --input "$TESTDATA/phase3/holesky/unsigned_tx.json"
expect_golden sign-local-golden "$WORK/sign-local.rs.out" \
  "$TESTDATA/phase3/holesky/signed_tx_golden.json"

# --- run: build+sign in one step (offline defaults differ from the phase3
# unsigned fixture only if fixtures change; compare Go vs Rust, not golden) ---
run_both run-local no -- run --signer local --network holesky \
  --input-file "$TESTDATA/phase2/holesky/deposit_data_single.json"
unset ETH_DEPOSIT_TX_PRIVATE_KEY

# --- exit-code parity on failure paths ---
run_both exit-bad-network no -- build --network bogus \
  --input-file "$TESTDATA/phase2/holesky/deposit_data_single.json"
run_both exit-sign-no-key no -- sign --signer local \
  --input "$TESTDATA/phase3/holesky/unsigned_tx.json"
run_both exit-send-dead-rpc no -- send --yes \
  --input "$TESTDATA/phase3/holesky/signed_tx_golden.json" \
  --rpc-url http://127.0.0.1:1

echo
echo "diff-go: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
