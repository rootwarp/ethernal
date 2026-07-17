# Phase 4 — Orchestration + exit-code contract (M4: all five subcommands green)

## R4-1 — bin `run` (2 pts, stream A, deps: R3-5)

**Scope:** Port `run.go`. In-process build → sign (no disk round-trip); ledger+RPC gate
(both --nonce and --gas-limit required, exit 2 pre-dial); local+RPC From derivation from
the signing key (read env twice, zeroize both); --keep-unsigned (requires file --output;
written before signing, survives sign failure); atomic writes (tmp+rename, same dir);
`.raw` companion (0600, `<output stem>.raw` or --raw-output override, only for file
output); `unsigned_path_for`/`raw_path_for` name derivation verbatim.

**Acceptance:** `run_test.go` + `run_rpc_test.go` cases pass (gates, derivation, partial-
failure artifacts, path derivation table).

## R4-2 — bin `send` (3 pts, stream A, deps: R3-2, R3-3)

**Scope:** Port `send.go`. Signed-tx JSON from file/stdin; dial via broadcaster seam
(injectable for tests); chain-ID guard signed-vs-node (mismatch sentinel → exit 5);
network lookup by chain ID with `chain-<id>` fallback display; "about to BROADCAST"
stderr block (ETH/Gwei 6-decimal formatting); confirmation: type the network name
(case-insensitive; EOF/mismatch → user-abort); --yes bypass; broadcast + tx hash +
explorer link to stdout; --wait-for-receipt polling (2s interval, adaptive under short
timeouts, ctx-cancellable) + --receipt-output atomic 0600 (implies wait).

**Acceptance:** `send_test.go` cases pass with mock broadcaster (confirmation matrix,
chain-ID mismatch, receipt polling/timeout, receipt file).

## R4-3 — Exit-code contract (2 pts, stream A, deps: R3-5, R4-1, R4-2)

**Scope:** Port `exit.go` + `main.go` wiring + usage-error hook semantics. `exit_code_for`
over the full error taxonomy: 4 cancel/abort/ledger-reject (checked before 5 so SIGINT
mid-estimation stays 4); 2 invalid-input wrapper + keystore/deposit/config sentinels +
clap usage errors; 3 signer/crypto + wrong-passphrase + deposit-cli-failed; 5 dial/
estimation/broadcast/broadcast-chain-mismatch; 1 fallback. SIGINT handler → CancelToken →
exit 4. Fatal log line `slog`-style with `redact_url_string` applied at the boundary.

**Acceptance:** `exit_test.go` + `usage_error_test.go` + `redact_boundary_test.go` ported
and green; every subcommand's documented exit codes verified via CARGO_BIN_EXE tests.
