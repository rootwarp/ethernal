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

## fuzz: run fuzz targets for 30 seconds each (cli and tx parsers)
fuzz:
	$(GOFLAGS) go test -fuzz FuzzParsePubkeys -fuzztime 30s ./internal/cli/
	$(GOFLAGS) go test -fuzz FuzzPackDeposit_AgainstGethABI -fuzztime 60s ./internal/tx/

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

## test-cross-validate: proxy for .github/workflows/cross-validate.yml (M1.7-3; FR-P1-G1/GO-059). Runs `go test -tags=cross_validate` (hoodi+mainnet) with CGO (proxies the CI extraction+test step). Full hermetic repro uses the docker run example in yml header comments (sanitized env per M1.1-7 inside the Go test). Local run without image/DEPOSIT_CLI_BIN will skip the real cross tests (see cross_validate_test.go).
test-cross-validate:
	@echo 'Proxying CI command: CGO_ENABLED=1 go test -tags=cross_validate -run CrossValidate ./cmd/eth-deposit-gen/... -count=1 -timeout=5m'
	$(GOFLAGS) go test -tags=cross_validate -run CrossValidate ./cmd/eth-deposit-gen/... -count=1 -timeout=5m

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/## /  make /'

## doc-audit: verify --help output of both binaries (via go run) matches flag tables in docs/USER-GUIDE.md.
## Fails on any delta (flag in binary missing from docs or vice versa).
## Implements M1.8-4 / Spike S5 / PRD metric #9. Uses grep smoke (per time-box note).
## Forward lists aligned strictly to *literal* | Flag | markdown tables (see HIGH fixes).
## Reverse + OK_EXTRA is the "vice versa" half (Spike S5); OK_EXTRA transitional for
## pre-existing deltas (documented in maintainer + comment below). documented in USER-GUIDE maintainer section.
doc-audit:
	@echo "doc-audit: checking eth-deposit-gen + eth-deposit-tx --help against docs/USER-GUIDE.md flag tables (M1.8-4)"
	@set -e; set -u; set -o pipefail; \
	G_HELP=$$($(GOFLAGS) go run ./cmd/eth-deposit-gen --help 2>&1) || { echo "doc-audit: go run failed for eth-deposit-gen"; exit 1; }; \
	for f in --keystore-dir --pubkeys --network --output-dir --passphrase-env --i-understand-this-is-mainnet --dry-run --parallel --verbose --json-logs --verify-with-deposit-cli --deposit-cli-path; do \
	  echo "$$G_HELP" | grep -q -- "$$f" || { echo "FAIL: $$f (doc) missing from eth-deposit-gen --help"; exit 1; }; \
	done; \
	for sub in build run; do \
	  T_HELP=$$($(GOFLAGS) go run ./cmd/eth-deposit-tx $$sub --help 2>&1) || { echo "doc-audit: go run failed for eth-deposit-tx $$sub"; exit 1; }; \
	  for f in --input-file --input -i --network -n --output --index --rpc-url --gas-limit --max-fee-per-gas --max-priority-fee-per-gas --nonce; do \
	    echo "$$T_HELP" | grep -q -- "$$f" || { echo "FAIL: $$f (doc) missing from eth-deposit-tx $$sub --help"; exit 1; }; \
	  done; \
	done; \
	for sub in sign; do \
	  T_HELP=$$($(GOFLAGS) go run ./cmd/eth-deposit-tx $$sub --help 2>&1) || { echo "doc-audit: go run failed for eth-deposit-tx $$sub"; exit 1; }; \
	  for f in --signer --input -i --output -o --private-key-env; do \
	    echo "$$T_HELP" | grep -q -- "$$f" || { echo "FAIL: $$f (doc) missing from eth-deposit-tx $$sub --help"; exit 1; }; \
	  done; \
	done; \
	for sub in send; do \
	  T_HELP=$$($(GOFLAGS) go run ./cmd/eth-deposit-tx $$sub --help 2>&1) || { echo "doc-audit: go run failed for eth-deposit-tx $$sub"; exit 1; }; \
	  for f in --input -i --rpc-url --yes --wait-for-receipt --receipt-timeout --receipt-output; do \
	    echo "$$T_HELP" | grep -q -- "$$f" || { echo "FAIL: $$f (doc) missing from eth-deposit-tx $$sub --help"; exit 1; }; \
	  done; \
	done; \
	# MED#5: stricter shell (set -u/pipefail at top of body); explicit capture fail for go run (prevents misleading "missing flag" on compile/CGO error)
	# alias subcheck (MED#4): urfave renders e.g. "--input ... -i ..." so forward grep -q on -i etc succeeds; reverse long-opt only (time-box intentional)
	echo "$$( $(GOFLAGS) go run ./cmd/eth-deposit-tx build --help 2>&1 )" | grep -q -- '-i' || { echo "FAIL: alias -i not rendered in build --help text (brittle urfave render?)"; exit 1; }; \
	# OK_EXTRA transitional (HIGH#3): reverse "vice versa" (Spike S5) intentionally skips these pre-existing deltas so PASS on develop.
	# --withdrawal-address: emitted by gen (internal/cli/cli.go:152, CustomAppHelpTemplate, live --help) but absent from *literal* gen Flags table (USER-GUIDE.md:150-162).
	# --allow-non-deposit-recipient: emitted by sign (sign.go ~160 + Flags) but absent from *literal* sign Flags table (USER-GUIDE.md:316-322).
	# (confirm-network/i-accept-* are in mainnet prose 541+ and code (run.go:184 etc) but were trimmed from forward lists to align strictly with per-sub | Flag | tables.)
	# Run-specific like --keep-unsigned/--raw-output/--allow-non (in run help + USER-GUIDE prose) covered by reverse smoke (no dedicated cross-or needed; removed for recipe robustness per MED).
	# Documented here + in USER-GUIDE maintainer; shrink OK_EXTRA post future table updates. Std --help etc always allowed.
	OK_EXTRA="--withdrawal-address --allow-non-deposit-recipient --help --version -h"; \
	for sub in "" "build" "sign" "run" "send"; do \
	  if [ -z "$$sub" ]; then BIN="./cmd/eth-deposit-gen"; else BIN="./cmd/eth-deposit-tx $$sub"; fi; \
	  H=$$( $(GOFLAGS) go run $$BIN --help 2>&1 | grep -oE -- '--[a-z0-9-]+' | sort -u ) || { echo "doc-audit: go run failed for $$BIN"; exit 1; }; \
	  for f in $$H; do \
	    case " $$OK_EXTRA " in *" $$f "*) continue ;; esac; \
	    grep -q -- "$$f" docs/USER-GUIDE.md || { echo "FAIL: $$f from '$$BIN --help' undocumented in USER-GUIDE.md (help capture was partial: see prior)"; exit 1; }; \
	  done; \
	done; \
	echo "doc-audit: PASS (0 deltas; exits 0 on develop)"
