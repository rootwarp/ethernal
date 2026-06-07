# eth-utils / eth-deposit-tx v1.0 Release Notes

## M1.9-5: Release notes including dry-run outcome (published)

**Headline v1.0 feature:** the mainnet ack gate (M1.6 / FR-P1-A1 / GO-013): `--confirm-network=mainnet` is required (and must match) on mainnet for `build`/`run`/`send`; `--yes` does **not** bypass it. Local signer on mainnet additionally requires `--i-accept-local-signer-on-mainnet`. (Pre-validated; gate matrix in M1.9-2.)

See:
- CHANGELOG.md (repository root; v1.0.0 entry from M1.8-2 covering all M1 changes + M1.9-3 dry-run outcome record)
- go/docs/USER-GUIDE.md (mainnet section / "Mainnet ceremony" worked example from M1.8-3)
- Dry-run outcome: fully recorded in CHANGELOG.md (repository root) under the [1.0.0] "Maintainer-led mainnet dry-run + record outcome (M1.9-3 / Spike S6)" block (held-out synthetic wallet from testdata, mainnet, only expected gate+summary prompts/warnings surfaced, exit codes 2/0, gate matrix PASS, cross-check sign-off, artifacts, verifs including `make test-cross-validate` + `--help` smokes + no unrelated warnings).

**File:** `go/docs/RELEASE-NOTES-v1.0.md` (this) + GitHub release body (see Implementation Summary for equiv text).

**ACs met (M1.9-5):**
- [x] Release notes published.
- [x] Cross-links to CHANGELOG, USER-GUIDE mainnet section, dry-run outcome.

**Prior M1.9/M1.8 verifs (cross-checked via runs):**
- M1.9-1: `make test-cross-validate` (proxy) green.
- M1.9-2: `CGO_ENABLED=1 go test -run 'TestMainnetGate|...Mainnet.*Confirm|...LocalSignerMainnet' ./cmd/eth-deposit-tx/...` green.
- M1.9-3: dry-run executed + outcome recorded (CHANGELOG); only expected warnings.
- M1.9-4: lint (gofmt/vet/errcheck/govuln clean; see Makefile), v1.0.0 tag state, 3+ binaries in dist/ + go/.
- M1.8-2/3/4: CHANGELOG v1.0 present, USER-GUIDE mainnet + doc-audit PASS (0 deltas), records/gates/lint/binaries.

**Smokes (post-M1.9-4):**
- `cd go && ./eth-deposit-tx --version` / `build --help` (or run/send/sign --help) + USER-GUIDE mainnet prose document gate flags (cross-refs cover); top-level --help/version for binary presence/version string (per doc-audit trims + subcommand-only flags).
- `gofmt -l .` empty.
- `make doc-audit` PASS.
- `go vet ./...` clean; errcheck/go-run clean; govulncheck: 0 reachable.

**Gates/cross from M1.9-1/2:** verified above (tests green).

This closes M1.9 (last of 5); advances 137-issue plan to M2.

(Modeled on go/docs/RELEASE-NOTES-v0.2.md sign-off pattern; minimal per "smallest change" + records already in CHANGELOG per M1.9-3 decision.)
