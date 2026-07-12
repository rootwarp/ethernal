.PHONY: test lint build clean coverage fuzz tidy verify refresh-golden e2e-mock e2e-testnet help

BIN     := bin/eth-deposit
GOFLAGS := CGO_ENABLED=1

## build: compile the binary to bin/eth-deposit
build:
	$(GOFLAGS) go build -o $(BIN) ./cmd/eth-deposit

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

## lint: run go vet and staticcheck
lint:
	go vet ./...
	staticcheck ./...

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

## refresh-golden: regenerate testdata/hoodi/* and testdata/mainnet/* fixtures from the fixed secret
refresh-golden:
	REFRESH_GOLDEN=1 $(GOFLAGS) go test -run 'TestRefreshHoodiGolden|TestRefreshMainnetGolden' -v -timeout 120s ./test/e2e/

## e2e-mock: run E2E tests (build+sign+send via mock broadcaster, no real RPC)
e2e-mock:
	$(GOFLAGS) go test -tags=e2e -count=1 ./cmd/eth-deposit/...

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

## clean: remove build artifacts
clean:
	rm -rf bin/ coverage.out

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/## /  make /'
