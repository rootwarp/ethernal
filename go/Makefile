.PHONY: test lint build build-tx clean coverage fuzz tidy verify refresh-golden e2e-mock e2e-testnet e2e-ledger-testnet assert-no-zero-wc oracle-regen help

BIN     := bin/eth-deposit-gen
BIN_TX  := bin/eth-deposit-tx
GOFLAGS := CGO_ENABLED=1

## build: compile the binary to bin/eth-deposit-gen
build:
	$(GOFLAGS) go build -o $(BIN) ./cmd/eth-deposit-gen

## build-tx: compile eth-deposit-tx to bin/eth-deposit-tx
build-tx:
	$(GOFLAGS) go build -o $(BIN_TX) ./cmd/eth-deposit-tx

## test: run all tests (unit + integration)
test:
	$(GOFLAGS) go test ./...

## test-verbose: run all tests with verbose output
test-verbose:
	$(GOFLAGS) go test -v ./...

## coverage: run tests and show per-package coverage summary
coverage:
	$(GOFLAGS) go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | grep -E "(total|100\.0%)" | sort
	@echo "\nFull HTML report: go tool cover -html=coverage.out"

## lint: run gofmt gate + go vet + staticcheck + errcheck + govulncheck
lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && false)
	go vet ./...
	staticcheck ./...
	go run github.com/kisielk/errcheck ./...
	# govulncheck non-zero on documented geth hits (traces exist but per SECURITY.md); undocumented reachable fails (AC4); see policy
	GOTOOLCHAIN=go1.26.4 go run golang.org/x/vuln/cmd/govulncheck ./...

## tidy: sync go.mod and go.sum
tidy:
	go mod tidy

## verify: check module checksums match go.sum
verify:
	go mod verify

## fuzz: run fuzz targets for 30 seconds each (ssz and cli parsers)
fuzz:
	$(GOFLAGS) go test -fuzz FuzzMerkleize   -fuzztime 30s ./internal/ssz/
	$(GOFLAGS) go test -fuzz FuzzUint64Chunk -fuzztime 30s ./internal/ssz/
	$(GOFLAGS) go test -fuzz FuzzParsePubkeys -fuzztime 30s ./internal/cli/
	$(GOFLAGS) go test -fuzz FuzzPackDeposit_AgainstGethABI -fuzztime 60s ./internal/tx/

## refresh-golden: regenerate testdata/hoodi/* and testdata/mainnet/* fixtures from the fixed secret
refresh-golden:
	REFRESH_GOLDEN=1 $(GOFLAGS) go test -run 'TestRefreshHoodiGolden|TestRefreshMainnetGolden' -v -timeout 120s ./test/e2e/

## e2e-mock: run E2E tests (build+sign+send via mock broadcaster, no real RPC)
e2e-mock:
	$(GOFLAGS) go test -tags=e2e -count=1 ./cmd/eth-deposit-tx/...

## e2e-testnet: run manual testnet E2E (requires RPC_URL and ETH_DEPOSIT_TX_PRIVATE_KEY)
e2e-testnet:
	@if [ -z "$(RPC_URL)" ]; then \
	  echo "ERROR: RPC_URL is required. Set it to your testnet JSON-RPC endpoint."; \
	  echo "  Example: make e2e-testnet RPC_URL=https://holesky.infura.io/v3/<key>"; \
	  exit 1; \
	fi
	@if [ -z "$(ETH_DEPOSIT_TX_PRIVATE_KEY)" ]; then \
	  echo "ERROR: ETH_DEPOSIT_TX_PRIVATE_KEY is required."; \
	  echo "  Example: make e2e-testnet RPC_URL=... ETH_DEPOSIT_TX_PRIVATE_KEY=0x<key>"; \
	  exit 1; \
	fi
	bash scripts/e2e-testnet.sh

## e2e-ledger-testnet: manual maintainer Ledger E2E run against hoodi (FR-P0-D4; gated by LEDGER_E2E=1)
## Uses direct CLI invocations + TMPDIR per M0.11-2 / M0.8-5 (avoids flagged e2e-testnet.sh).
## Requires: current-firmware Ledger (Nano S Plus / Nano X / Flex), CGO, Ethereum app open, funded sender on hoodi.
## The M0.6-3 signing summary will print to stderr before on-device confirms.
e2e-ledger-testnet:
	@if [ -z "$(LEDGER_E2E)" ]; then \
	  echo "ERROR: LEDGER_E2E=1 is required for the real-hardware Ledger E2E gate (M0.11-2 / FR-P0-D4)."; \
	  echo "  Usage: LEDGER_E2E=1 make e2e-ledger-testnet"; \
	  echo "  (manual: use CGO_ENABLED=1 go run ./cmd/eth-deposit-tx run --network hoodi --signer ledger ... + send --rpc-url https://rpc.hoodi.ethpandaops.io ...)"; \
	  exit 1; \
	fi
	@echo "LEDGER_E2E=1 gate satisfied. Perform/coordinate physical Ledger run against hoodi (provider from M0.11-1)."
	@echo "Record: device model, firmware, Ethereum app ver, hoodi RPC, tx hash. Verify signing summary on stderr, exit 0, no ErrDeviceUnavailable/ErrSenderMismatch."
	@exit 0

## clean: remove build artifacts
clean:
	rm -rf bin/ coverage.out

## assert-no-zero-wc: fail if any testdata/ *.json has 64-zero withdrawal_credentials (FR-P0-A1 regression guard; activated in M0.10 PR)
# Activated in M0.10 PR (current fixtures still have zero WC; see M0.4-9 / M0.4-10)
assert-no-zero-wc:
	@if grep -rE '"withdrawal_credentials"\s*:\s*"0{64}"' testdata/; then \
	  echo "found zero WC (expected until M0.10)"; \
	  false; \
	fi

## oracle-regen: regenerate the committed fastssz-generated oracle_types_ssz.go from hand-written oracle_types.go (M1.2-4; supports `go generate ./...` too)
oracle-regen:
	GOWORK=off go generate ./internal/ssz/testdata

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/## /  make /'
