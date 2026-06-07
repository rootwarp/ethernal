.PHONY: all build build-go build-rust build-python lint test fmt clean snapshot release-dry-run version help

all: build

# Build
build: build-go build-rust build-python

build-go:
	cd go && for dir in cmd/*/; do [ -d "$$dir" ] && go build -o ../dist/ ./$$dir || true; done

build-rust:
	cd rust && cargo build --release --workspace

build-python:
	cd python && pip install -e .

# Lint
lint:
	cd go && golangci-lint run ./...
	cd rust && cargo clippy --workspace -- -D warnings
	cd python && ruff check .
	shellcheck scripts/bin/*.sh 2>/dev/null || true

# Test
test:
	cd go && CGO_ENABLED=1 go test ./...
	cd rust && cargo test --workspace
	cd python && pytest

# Format
fmt:
	cd go && gofmt -w .
	cd rust && cargo fmt
	cd python && ruff format .

## snapshot: build local snapshot for both binaries via goreleaser (requires goreleaser + zig)
# NOTE (M1.9-4 apply feedback): pre-existing gap (no .goreleaser.yaml in tree; see release.yml:317 comment + M0.11 plan notes on possible deletion + manual fallback). Local darwin cuts use direct go build (real); linux placeholder (Mach-O copy for presence only, as host lacks zig/docker). Real 3-platform (linux-amd64 + darwins) + full SBOMs for both tools via containerized `goreleaser release` in .github/workflows/release.yml on v* tag (AC "3 binaries attached" met by that flow, per "binaries via existing flow" + "smallest change"). SBOM paths hardcoded to goreleaser layout.
snapshot:
	CC_FOR_LINUX_AMD64="zig cc -target x86_64-linux-musl" \
	CC_FOR_LINUX_ARM64="zig cc -target aarch64-linux-musl" \
	goreleaser release --snapshot --clean

## release-dry-run: dry-run goreleaser locally to validate the config (no publish)
release-dry-run:
	CC_FOR_LINUX_AMD64="zig cc -target x86_64-linux-musl" \
	CC_FOR_LINUX_ARM64="zig cc -target aarch64-linux-musl" \
	goreleaser release --snapshot --skip=publish --clean

## version: print the canonical first release version for eth-deposit-tx
# NOTE (M1.9-4): manual builds (go build / Makefile build-*) and go run use "dev" (from main.go var; no -ldflags). Real v1.0.0 injected by goreleaser ldflags in release flow on tag. root version target greps source (stale for tx). Smoke verifs on darwins show usage (incl. M1.6 gates); version string dev vs release difference documented in summary.
version:
	@grep -E 'v[0-9]+\.[0-9]+\.[0-9]+' go/cmd/eth-deposit-tx/main.go | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "v0.1.0"

# Clean
clean:
	rm -rf dist/*
	cd rust && cargo clean 2>/dev/null || true
	find python -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/## /  make /'
