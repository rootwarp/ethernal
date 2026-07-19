.PHONY: build test test-verbose coverage lint fmt e2e-mock e2e-live clean help

## build: compile the release binary to target/release/ethernal
build:
	cargo build --release --bin ethernal

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

## e2e-mock: run hermetic E2E tests (mock broadcaster, no real RPC; non-ignored only)
e2e-mock:
	cargo test --workspace --test 'e2e*'

## e2e-live: run ignored (anvil/live) E2E tests only
e2e-live:
	cargo test --workspace --test 'e2e*' -- --ignored

## clean: remove build artifacts
clean:
	cargo clean

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/## /  make /'
