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

## Cross-validate CI image (ethstaker-deposit-cli) — M1.7-1 extension of M0.1-5

This extends the M0.1-5 refresh/triage policy (FR-P0-E2 / architecture §12.5) to the hermetic cross-validate Docker image and its baked `ethstaker-deposit-cli` pin (FR-P1-G1 / GO-059, architecture §11.3 + research/01 + project-plan P8 risk).

- **Image**: `Dockerfile.cross-validate` (root of repo). Minimal `python:3.12-slim` base + exact `pip install ethstaker-deposit-cli==<pinned>`. Image build itself refuses (fails the RUN layer) if the installed binary's `--version` output does not contain the string "ethstaker" (research/01 §R2 defense against the deprecated `ethereum/staking-deposit-cli` fork that is still pip-installable under similar names).
- **Pin**: The image is built and pushed to GH container registry *once per pin bump* (when the version string in the Dockerfile changes). The workflow (`.github/workflows/cross-validate.yml`) references the image by its immutable `sha256:...` digest (never a mutable tag). Current pin (as of this M1.7-1 work):
  - `ethstaker-deposit-cli==1.3.0` (latest stable 2026-04-30 per research/01 + releases; see github.com/ethstaker/ethstaker-deposit-cli/releases).
  - Image digest SHA-256: recorded in the workflow at the `IMAGE=...@sha256:` site (update on every bump).
- **Refresh cadence + tracking**:
  - Monitor new stable releases of `ethstaker-deposit-cli` (GitHub releases + PyPI).
  - On bump: update the `==VER` in `Dockerfile.cross-validate`, locally `docker build -f Dockerfile.cross-validate -t cross-validate-test .` + run the image `--version` + refuse-check to confirm "ethstaker" present, push the new image (once), capture its digest, update the SHA in the workflow, add a dated entry here, and run the cross-validate lane.
  - Re-review the current pin (and any suppressions or known upstream issues) at least quarterly and on any ethstaker release or base-image update. Use a `review_by` date in an entry below.
  - The Go-side test (M1.7-2) additionally refuses at runtime if `DEPOSIT_CLI_BIN --version` lacks "ethstaker" (belt-and-suspenders).
- **Sanitized execution**: The cross lane reuses `sanitizedEnv()` (M1.1-7) for any child `ethstaker-deposit-cli` exec (allow-list: only HOME/PATH/LANG). No secrets or parent env vars are visible to the external authority.
- **Current pin record / review entry** (add new on bump; modeled on suppressions format):

```yaml
cross_validate_image:
  - id: ethstaker-deposit-cli-1.3.0
    image_digest: "sha256:REPLACE_WITH_PUSHED_DIGEST"  # update after each pin bump + push
    rationale: |
      Hermetic external authority for deposit-data cross-validation (FR-P1-G1/GO-059).
      Pinned at 1.3.0 (research/01); Dockerfile enforces ethstaker branding at build time (R2).
      SHA-256 digest in cross-validate.yml ensures immutability. Rebuild/push only on VER change
      in Dockerfile (not per-PR). No secret material or injection surface in the image (static
      pip + minimal base). Sanitized env used for subprocess (M1.1-7).
    review_by: "2026-09-30"
```

## How to re-run triage (including cross-validate image verif)

```sh
# From go/
GOTOOLCHAIN=go1.26.4 go run golang.org/x/vuln/cmd/govulncheck ./...
# or via the gate:
make lint

# Cross-validate image (from repo root; requires docker):
docker build -f Dockerfile.cross-validate -t cross-validate-test .
docker run --rm cross-validate-test ethstaker-deposit-cli --version | grep -i ethstaker
# (the build already ran the refuse check; this confirms at runtime)
```

---

*This file was created as part of M0.1-5 (FR-P0-E2 / GO-057). Extended for M1.7-1 cross-validate image (FR-P1-G1 / GO-059).*
