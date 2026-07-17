.PHONY: build test test-verbose coverage lint fmt e2e-mock clean help

## build: compile the release binary to target/release/eth-deposit
build:
	cargo build --release --bin eth-deposit

## test: run all tests (unit + integration)
test:
	cargo test --workspace

## test-verbose: run all tests with output shown
test-verbose:
	cargo test --workspace -- --nocapture

## coverage: per-crate test run (install cargo-llvm-cov for real coverage)
coverage:
	@command -v cargo-llvm-cov >/dev/null 2>&1 && cargo llvm-cov --workspace --summary-only \
		|| { echo "cargo-llvm-cov not installed; running plain tests"; cargo test --workspace; }

## lint: clippy with warnings denied + rustfmt check
lint:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo fmt --all -- --check

## fmt: apply rustfmt
fmt:
	cargo fmt --all

## e2e-mock: run E2E tests (build+sign+send via mock broadcaster, no real RPC)
e2e-mock:
	cargo test --workspace --test 'e2e*' -- --include-ignored

## clean: remove build artifacts
clean:
	cargo clean

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/## /  make /'
