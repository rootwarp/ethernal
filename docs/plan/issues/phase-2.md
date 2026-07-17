# Phase 2 — Gen pipeline (M2: `gen` byte-identical to Go golden fixtures)

## R2-1 — `core::deposit` (2 pts, stream A, deps: R1-2, R1-3, R1-4)

**Scope:** Port `go/internal/deposit/{deposit,json}.go` → `crates/core/src/deposit.rs`.
`Entry` (fixed-size arrays + `network_name: String` + `deposit_cli_version`), `Request`,
`Generator` precomputing the deposit domain; generate loop: pubkey-match assert → message
root → signing root → sign → **self-verify** → data root; no partial output on error;
honors `CancelToken`. Read-side: `entry_from_json`, `entries_from_json` (0x-optional hex,
strict lengths), `Entry::validate` (all-zero pubkey/sig/root, zero amount, unknown network).
Error messages verbatim.

**Acceptance:** `deposit_test.go` + `json_test.go` cases pass (mismatch abort, self-verify
failure abort, cancellation, hex/length errors, validate errors).

## R2-2 — `core::output` (2 pts, stream A, deps: R2-1)

**Scope:** Port `go/internal/output/output.go` → `crates/core/src/output.rs`. `Writer`
trait returning `(path, sha256hex)`; `FsWriter`: compact JSON array (field order = struct
decl order, lowercase unprefixed hex), tmp `.deposit_data-<ts>.json.tmp` → fsync → rename,
tmp removed on failure, file mode 0600; `DryRunWriter<W: Write>`; sha256 hex digest of the
exact bytes.

**Acceptance:** serialization byte-identical to `crates/core/testdata/deposit_data-expected.json`;
`output_test.go` cases pass (atomicity failure paths, dry-run path empty, digest matches).

## R2-3 — bin `gen` command (4 pts, stream A, deps: R2-1, R2-2, R1-5)

**Scope:** Port `go/internal/cli/cli.go` + `go/cmd/eth-deposit/gen.go` →
`bins/eth-deposit/src/{gen_cli,gen}.rs`. Flag schema (keystore-dir, pubkeys, network
[mainnet|hoodi only], output-dir, passphrase-env, i-understand-this-is-mainnet, dry-run,
verbose, json-logs, parallel [1..=ncpu*4], verify-with-deposit-cli, deposit-cli-path);
validation order network → mainnet ack → pubkeys (uniform 0x prefix, 96 hex chars, G1
point) → keystore-dir readable → output-dir writable (skipped in dry-run) → parallel
range; banner to stderr (`MAINNET` uppercase cue); worker-pool signing preserving input
order with first-non-cancel error; progress (TTY \r line vs 10%-step log events);
summary `wrote <path> (sha256=…, n=…, network=…)`; optional deposit-cli shell-out
(`verify --input-file`, LookPath→exit2 sentinel, non-zero→exit3 sentinel).

**Acceptance:** `cli_test.go` (validation matrix) + `gen_test.go` (deps-injected pipeline)
cases ported and green.

## R2-4 — `gen` golden gate (1 pt, stream A, deps: R2-3)

**Scope:** Integration test driving the built binary (CARGO_BIN_EXE): gen with
`testdata/{hoodi,mainnet}/keystores` + fixed passphrase + pubkeys → deposit_data JSON
equals `deposit_data-expected.json` byte-for-byte (modulo timestamped filename); dry-run
stdout equals file content; cross-check same invocation against `go/bin/eth-deposit`.

**Acceptance:** byte-identity on both networks; Go/Rust diff empty.
