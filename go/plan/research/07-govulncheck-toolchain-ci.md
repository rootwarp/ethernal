# Research: govulncheck, errcheck, Go Toolchain Pinning, and CI Integration

## Recommendation
**Adopt the standalone-tool pattern: install `govulncheck` and `errcheck` as `go run` from a `tools/tools.go` file, invoke them from `make lint`, and run them as discrete CI steps (not via `golangci-lint`). Pin the toolchain via the `toolchain go1.26.4` directive in `go.mod` and rely on `GOTOOLCHAIN=auto` to download exactly that version.** This is the consensus approach as of 2026: golangci-lint deliberately does **not** wrap govulncheck (the project rejected the integration request [1][2]).

## Context
- **Goal:** Implement FR-P0-E1 (toolchain pin), FR-P0-E2 (govulncheck CI gate), FR-P0-E3 (errcheck CI gate), and FR-P0-B10 (gofmt gate).
- **Constraints:** `make lint` currently runs only `go vet` + `staticcheck`; CI workflow exists. Must be repeatable, deterministic, and not flake on weekly cron runs.
- **Evaluated:** standalone govulncheck, golangci-lint integration (rejected upstream), GitHub Action `golang/govulncheck-action`, OSV-scanner, Snyk.

## Comparison

| Tool | Purpose | Reachability analysis? | CI integration | License | Recommended? |
|---|---|---|---|---|---|
| **govulncheck** | Vulnerability scan of Go modules and stdlib symbols | **Yes** [3] | Standalone or GH Action | BSD-3 | ✅ Primary |
| OSV-scanner | Generic vuln scan across many ecosystems | No (manifest-level only) | GH Action | Apache-2 | Optional secondary |
| Snyk | Commercial scan | Partial | Action / CLI | Commercial | Skip (vendor lock) |
| **errcheck** | Detect unchecked error returns | n/a | Standalone or golangci-lint | MIT | ✅ Primary |
| staticcheck | Multi-purpose linter | n/a | Standalone (already in `make lint`) | MIT | ✅ Already adopted |
| **gofmt** | Formatting | n/a | Standalone | stdlib | ✅ Add via `test -z "$(gofmt -l .)"` |

## Detailed Analysis

### govulncheck integration

**Why standalone, not golangci-lint:** The maintainers explicitly rejected govulncheck integration in [issue #4623](https://github.com/golangci/golangci-lint/issues/4623) [1][2]. govulncheck has a different operational model (downloads vuln DB at runtime, performs call-graph analysis using `golang.org/x/tools/go/packages`) that doesn't fit golangci-lint's per-file linter model.

**Reachability analysis is the key feature** [3]: govulncheck doesn't just check module versions; it traces actual call paths into the vulnerable function. This is the difference between "go-ethereum v1.14.12 has 5 advisories" and "5 advisories exist but none in your linked path" (REVIEW.md GO-055). The CI gate per PRD FR-P0-E2 must use this:

```yaml
# .github/workflows/ci.yml (proposed)
- name: govulncheck
  run: |
    go install golang.org/x/vuln/cmd/govulncheck@latest
    govulncheck -mode=source ./...
```

**Suppression policy** (FR-P0-E2 mandates triage):
```yaml
# vuln-exclude.yaml (proposed format, plain YAML — govulncheck does NOT have native suppression, must wrap in jq/yq filter)
suppressions:
  - id: GO-2025-3436
    rationale: "p2p stack DoS in go-ethereum; we only consume ethclient/usbwallet/core/types/rlp/crypto/abi"
    review_by: "2026-12-31"
```
Apply as a post-process filter in CI:
```sh
govulncheck -mode=source -json ./... | jq -e '.vulns[] | select(.id as $id | $suppressions | index($id) | not)' && exit 0 || exit 1
```

### Toolchain pinning (FR-P0-E1)

**Mechanism:** Add `toolchain go1.26.4` (latest patch at release time) to `go.mod`. With `GOTOOLCHAIN=auto` (default since Go 1.21), the Go command will **automatically download and use exactly that toolchain**, regardless of what `go` is on PATH [4]. CI's `setup-go` should specify `go-version-file: go.mod` (will pick up the toolchain directive) OR pin to `1.26.x` and rely on the toolchain switch.

**Pitfall:** govulncheck itself uses `runtime.Version()` of the `go` on PATH for stdlib analysis, NOT the `toolchain` directive [5]. So if CI's `setup-go` installs 1.26.0, govulncheck reports the 12 stdlib advisories already known from REVIEW.md GO-056, even after our toolchain pin moves builds to 1.26.4. **Solution:** Set `GOTOOLCHAIN=go1.26.4` explicitly in the govulncheck step, OR pin `setup-go` to 1.26.4 directly.

```yaml
- uses: actions/setup-go@v5
  with: { go-version: '1.26.4' }   # match toolchain directive
- run: govulncheck -mode=source ./...
```

### errcheck integration (FR-P0-E3)

errcheck is a single binary; install via tools.go and invoke in lint:
```go
// tools/tools.go
//go:build tools
package tools
import (
    _ "github.com/kisielk/errcheck"
    _ "golang.org/x/vuln/cmd/govulncheck"
    _ "honnef.co/go/tools/cmd/staticcheck"
)
```
```makefile
# Makefile (proposed)
lint:
	gofmt -l . | tee /dev/stderr | (! read)        # GO-044 / FR-P0-B10
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck ./...
	go run github.com/kisielk/errcheck ./...        # FR-P0-E3
	go run golang.org/x/vuln/cmd/govulncheck ./...  # FR-P0-E2
```

### golangci-lint as alternative (consider)
golangci-lint v1.62+ supports gofmt + errcheck + staticcheck + vet under one config and is faster than running each separately. Trade-off: another tool to pin, but unifies dev experience. PRD FR-P0-B10 says "and to `make lint`" — both approaches satisfy this. Recommend keeping the Makefile-driven discrete steps as primary (matches REVIEW.md's tooling sweep methodology) and offering golangci-lint as a convenience wrapper for `go run` cycles.

## Implementation Guidelines
1. **Pin toolchain in `go.mod`:**
   ```
   go 1.26.0
   toolchain go1.26.4
   ```
2. **Add `tools/tools.go`** with `//go:build tools` so `go mod tidy` keeps the deps; never imported at runtime.
3. **Makefile changes** as above; expand `lint` target.
4. **CI workflow:**
   ```yaml
   - uses: actions/setup-go@v5
     with: { go-version-file: 'go/go.mod' }
   - run: make -C go lint
   - run: make -C go test
   ```
5. **Weekly vuln scan on `develop`** (per PRD FR-P0-E2 closing line): GitHub Action `schedule: cron: '0 4 * * MON'` running `govulncheck -mode=source ./...` and posting failures to the issues board.
6. **Triage policy in repo:** Add `docs/SECURITY.md` section explaining the suppression file format and rotation cadence (re-review date).

## Common Pitfalls
- **Pitfall 1 — Toolchain mismatch between local and CI.** Without `toolchain` directive, devs on `go1.26.0` get different results from CI on `go1.26.4`. The directive plus `setup-go` with matching minor closes this. PRD FR-P0-E1 already calls this out.
- **Pitfall 2 — `govulncheck` running in `-mode=binary` misses source-level reachability.** Always use `-mode=source` for CI; `-mode=binary` is for post-build artifact checks (different threat model).
- **Pitfall 3 — Vuln DB caching.** govulncheck downloads `vuln.go.dev` per run; can flake on network outages. Mitigate by caching the DB across CI runs (use `GOVULNDB=file:///path/to/cache`).
- **Pitfall 4 — errcheck's default excludes.** errcheck has a built-in default exclude list (e.g. `fmt.Fprintf` to *os.File). Override per REVIEW.md GO-058: those are exactly the cases we want flagged. Use `errcheck -exclude .errcheck-exclude.txt` with an empty (or surgical) file.
- **Pitfall 5 — `gomoddirectives` golangci-lint linter.** v0.6.0+ supports `toolchain-pattern` / `toolchain-forbidden` [6]. If we adopt golangci-lint, enable `gomoddirectives` to enforce the toolchain pin pattern as code.
- **Pitfall 6 — Go 1.26 stdlib advisories surface even with toolchain pin if CI host's `go` is older.** Match both.

## Real-World Examples
- **kubernetes/kubernetes** runs govulncheck weekly with a triage queue; suppressions reviewed quarterly.
- **golang/go itself** uses govulncheck via the standard CI image; their toolchain is bootstrap so the directive doesn't apply, but the pattern is identical.
- **etcd-io/etcd** runs govulncheck + staticcheck + errcheck in CI; their `tools/tools.go` is a template worth borrowing.

## Feasibility: ✅ GREEN. No PRD contradictions.

## Sources

[1] [golangci/golangci-lint issue #4623 — Add govulncheck](https://github.com/golangci/golangci-lint/issues/4623) — golangci-lint. Confirms upstream rejection of integrating govulncheck into golangci-lint.
[2] [Securing Your Gaming Backend — Go vuln toolchain](https://blog.rushdownstudio.com/securing-your-gaming-backend-a-practical-guide-to-gos-vulnerability-toolchain/) — Rushdown Studio. Practical pattern of standalone govulncheck + CI integration.
[3] [govulncheck documentation — go.dev](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) — Go team. Reachability analysis details; modes (source/binary).
[4] [Go 1.21+ toolchain directive — go.dev/doc/toolchain](https://go.dev/doc/toolchain) — Go team. Specification for `toolchain` directive and `GOTOOLCHAIN=auto` behavior.
[5] [golang/go issue #62050 — govulncheck and toolchain directive](https://github.com/golang/go/issues/62050) — Go team. Confirms govulncheck currently uses Go on PATH for stdlib, not the `toolchain` directive.
[6] [gomoddirectives linter](https://github.com/ldez/gomoddirectives) — ldez. golangci-lint linter for `toolchain` directive enforcement.
[7] [Go 1.26 release notes](https://go.dev/doc/go1.26) — Go team. New `ParseDirective` function and directive-comment support.
[8] [golangci-lint changelog v1](https://golangci-lint.run/docs/product/changelog-v1/) — golangci-lint. gomoddirectives 0.6.0 bump with toolchain-pattern.
