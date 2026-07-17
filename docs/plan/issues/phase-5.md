# Phase 5 — Verification & docs (M5: full suite + Rust↔Go diff harness green)

## R5-1 — E2E suite + Rust↔Go byte-identity harness (3 pts, stream A, deps: R4-3, R2-4)

**Scope:** Port `go/test/e2e/{hoodi,mainnet}_test.go` (gen golden from fixed secret) and
`cmd/eth-deposit/deposit_e2e_test.go`, `golden_test.go`, `signed_golden_test.go` (full
build→sign→send pipeline against a mock broadcaster) as Rust integration tests. Add a
diff harness (`make diff-go`) that runs both binaries on identical inputs across all five
subcommands and diffs stdout/output files/exit codes.

**Acceptance:** e2e-mock suite green; diff harness reports zero differences for gen
(hoodi+mainnet), offline build, local sign, run, and send-against-mock flows.

## R5-2 — Tooling & docs (2 pts, stream B, deps: R5-1)

**Scope:** `rust/Makefile` mirroring Go targets (build/test/test-verbose/coverage/lint/
fuzz-equivalent property tests/e2e-mock/clean/help); `cargo clippy -D warnings` + fmt
clean; USER-GUIDE section for the Rust binary (install, ws:// and u128 divergences,
ledger feature flag); note in `go/docs` marking `go/` as reference implementation;
decision record for `go/` retirement timing.

**Acceptance:** `make -C rust help/test/lint` green; docs reviewed; workspace clippy/fmt
clean.
