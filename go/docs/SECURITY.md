# Security & Vulnerability Triage

This document records the policy and current suppressions for automated vulnerability scanning (`govulncheck`) in the `eth-utils/go` module.

## Policy (per FR-P0-E2 / architecture §12.5)

- **Symbol-reachable hits** (govulncheck reports "your code is affected") in the Go standard library or directly-imported modules are **release blockers**.
- **Module-only / unreachable hits** (advisories present in the module graph but with no call-graph trace from our packages into the vulnerable symbol) may be suppressed.
- Suppressions require:
  - `id`: the GO-YYYY-NNNN identifier
  - `rationale`: why the hit does not affect the deposit CLI trust boundaries (what we import vs. what is vulnerable)
  - `review_by`: date by which the suppression must be re-evaluated (or the underlying issue closed by a bump)
- All suppressions are reviewed at least quarterly and on every toolchain / dependency bump.
- `make lint` (and the `lint` CI job) run `govulncheck ./...`. The job is green when there are zero reachable hits or every reported hit has a documented suppression entry above (suppressions record triage; bare gate non-zero on any affected until bump resolves).

Stdlib advisories are **never** suppressed long-term; they are resolved by pinning `toolchain go1.26.4` (and matching `actions/setup-go`) because `govulncheck` analyses against the `go` binary on `PATH` (see research/07 and golang/go#62050).

## Current suppressions

```yaml
suppressions:
  - id: GO-2026-4508
    rationale: |
      Go Ethereum affected by DoS via malicious p2p message (and related).
      Our import surface is limited to: ethclient, core/types, accounts/usbwallet (Ledger),
      rlp, crypto, abi, common, metrics (init only). No p2p/server, no LES, no full node
      networking code is ever linked or executed by eth-deposit-gen or eth-deposit-tx.
      govulncheck traces appear through transitive init() and common helper usage
      (accounts.URL, common.Address, etc.) that are required for Ledger + tx building.
      Impact is DoS against a peer-to-peer node we never run.
      Closed by the M0.2 go-ethereum bump to >= v1.17.0 (FR-P0-D1 / GO-055).
    review_by: "2026-07-31"
  - id: GO-2026-4315
    rationale: |
      DoS via malicious p2p message affecting a vulnerable node.
      Our import surface is limited to: ethclient, core/types, accounts/usbwallet (Ledger),
      rlp, crypto, abi, common, metrics (init only). No p2p/server, no LES, no full node
      networking code is ever linked or executed by eth-deposit-gen or eth-deposit-tx.
      govulncheck traces appear through transitive init() and common helper usage
      (accounts.URL, common.Address, etc.) that are required for Ledger + tx building.
      Impact is DoS against a peer-to-peer node we never run.
      Closed by the M0.2 go-ethereum bump to >= v1.17.0 (FR-P0-D1 / GO-055).
    review_by: "2026-07-31"
  - id: GO-2026-4314
    rationale: |
      High CPU usage leading to DoS via malicious p2p message.
      Our import surface is limited to: ethclient, core/types, accounts/usbwallet (Ledger),
      rlp, crypto, abi, common, metrics (init only). No p2p/server, no LES, no full node
      networking code is ever linked or executed by eth-deposit-gen or eth-deposit-tx.
      govulncheck traces appear through transitive init() and common helper usage
      (accounts.URL, common.Address, etc.) that are required for Ledger + tx building.
      Impact is DoS against a peer-to-peer node we never run.
      Closed by the M0.2 go-ethereum bump to >= v1.17.0 (FR-P0-D1 / GO-055).
    review_by: "2026-07-31"
  - id: GO-2025-3436
    rationale: |
      Go Ethereum vulnerable to DoS via malicious p2p message.
      Our import surface is limited to: ethclient, core/types, accounts/usbwallet (Ledger),
      rlp, crypto, abi, common, metrics (init only). No p2p/server, no LES, no full node
      networking code is ever linked or executed by eth-deposit-gen or eth-deposit-tx.
      govulncheck traces appear through transitive init() and common helper usage
      (accounts.URL, common.Address, etc.) that are required for Ledger + tx building.
      Impact is DoS against a peer-to-peer node we never run.
      Closed by the M0.2 go-ethereum bump to >= v1.17.0 (FR-P0-D1 / GO-055).
    review_by: "2026-07-31"
```

(The ~12 stdlib advisories reported against go1.26.0 — crypto/tls, crypto/x509, net/http, net/url, os, net/textproto, etc. — are all fixed in go1.26.4 and therefore disappear under the pinned toolchain + `setup-go: '1.26.4'`. They require no entry here. The 4 geth p2p DoS hits above are symbol-reachable (govuln Symbol Results + traces via common/utils) but accepted as non-blockers (traces do not exercise the vulnerable p2p message paths; limited import surface for Ledger/tx only; no p2p code linked) and documented per §12.5 / FR-P0-E2 until M0.2 bump.)

## How to re-run triage

```sh
# From go/
GOTOOLCHAIN=go1.26.4 go run golang.org/x/vuln/cmd/govulncheck ./...
# or via the gate:
make lint
```

Any new reachable hit blocks the PR until either the dependency is bumped or a suppression entry with future `review_by` is added (and justified in the PR description).

---

*This file was created as part of M0.1-5 (FR-P0-E2 / GO-057).*
