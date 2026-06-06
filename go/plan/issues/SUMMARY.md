# Issue Estimates: `eth-utils/go` Remediation (v0.2 / v1.0 / v1.1)

**Author:** issue-estimator (team dev-plan)
**Date:** 2026-06-07
**Inputs:** `go/plan/{project-plan,architecture,prd,REVIEW}.md`, `go/plan/research/*`.

---

## Estimation approach

- **1 point = half a developer-day.** 2 pt = 1 day, 4 pt = 2 days.
- Hard rule: no issue is estimated above **4 pt**. Anything that scopes larger has been split.
- Issues marked **(split-watch)** are 4 pt with non-trivial unknowns; reassess before starting.
- Points include coding, tests, lint, and self-review. They do **not** include external review-cycle waits.
- Execution model: **single code-writer, sequential** (per team-lead lock-in). Calendar duration = points ÷ 2 days.
- Every issue is individually shippable: compile + lint + unit tests green at end of issue.

---

## Phase index

| File | Phase | Issues | Points |
|------|-------|--------|--------|
| [m0.1-toolchain-ci-gates.md](./m0.1-toolchain-ci-gates.md) | M0.1 — Toolchain, CI & lint gates foundation | 7 | 13 |
| [m0.2-geth-bump-ledger-bringup.md](./m0.2-geth-bump-ledger-bringup.md) | M0.2 — `go-ethereum` v1.17.x upgrade & Ledger bring-up | 4 | 11 |
| [m0.3-atomicio-package.md](./m0.3-atomicio-package.md) | M0.3 — `internal/atomicio` foundation package | 3 | 8 |
| [m0.4-withdrawal-credential-boundary.md](./m0.4-withdrawal-credential-boundary.md) | M0.4 — Trust Boundary 1: withdrawal-credential input + `Redact` | 10 | 16 |
| [m0.5-network-fork-binding.md](./m0.5-network-fork-binding.md) | M0.5 — Trust Boundary 2: network/fork binding & read-path verify | 6 | 15 |
| [m0.6-rlp-boundary-sign-send.md](./m0.6-rlp-boundary-sign-send.md) | M0.6 — Trust Boundary 3: sign + send RLP verification | 7 | 16 |
| [m0.7-silent-loss-bulk.md](./m0.7-silent-loss-bulk.md) | M0.7 — Silent-loss & data-correctness bulk | 10 | 19 |
| [m0.8-secret-leak-closure.md](./m0.8-secret-leak-closure.md) | M0.8 — Secret-material leak closure | 5 | 13 |
| [m0.9-docs-release-hygiene.md](./m0.9-docs-release-hygiene.md) | M0.9 — Documentation & release hygiene (v0.2 docs) | 5 | 8 |
| [m0.10-golden-fixture-refresh.md](./m0.10-golden-fixture-refresh.md) | M0.10 — Golden-fixture regeneration | 1 | 3 |
| [m0.11-v02-release-checklist.md](./m0.11-v02-release-checklist.md) | M0.11 — v0.2 release checklist & tag | 4 | 7 |
| [m1.1-cancellation-concurrency.md](./m1.1-cancellation-concurrency.md) | M1.1 — Cancellation, concurrency & resource hygiene | 7 | 17 |
| [m1.2-bls-ssz-abi-defense.md](./m1.2-bls-ssz-abi-defense.md) | M1.2 — BLS / SSZ / ABI correctness defense-in-depth | 7 | 13 |
| [m1.3-rpc-client-robustness.md](./m1.3-rpc-client-robustness.md) | M1.3 — RPC client robustness | 6 | 13 |
| [m1.4-keystore-correctness.md](./m1.4-keystore-correctness.md) | M1.4 — Keystore correctness | 4 | 9 |
| [m1.5-cli-contract-exit-codes.md](./m1.5-cli-contract-exit-codes.md) | M1.5 — CLI contract & exit codes | 9 | 20 |
| [m1.6-mainnet-ack-gate.md](./m1.6-mainnet-ack-gate.md) | M1.6 — Mainnet acknowledgement gate | 4 | 10 |
| [m1.7-test-independence.md](./m1.7-test-independence.md) | M1.7 — Test independence & fixture hygiene | 5 | 11 |
| [m1.8-docs-accuracy.md](./m1.8-docs-accuracy.md) | M1.8 — Documentation accuracy (v1.0 docs) | 4 | 9 |
| [m1.9-v10-release-checklist.md](./m1.9-v10-release-checklist.md) | M1.9 — v1.0 release checklist & tag | 5 | 7 |
| [m2.1-quality-catalogue.md](./m2.1-quality-catalogue.md) | M2.1 — Quality catalogue hygiene | 11 | 13 |
| [m2.2-dead-code-dedup.md](./m2.2-dead-code-dedup.md) | M2.2 — Dead code & duplication removal | 4 | 7 |
| [m2.3-convention-architecture.md](./m2.3-convention-architecture.md) | M2.3 — Convention & architecture hygiene | 6 | 13 |
| [m2.4-v11-release.md](./m2.4-v11-release.md) | M2.4 — v1.1 release (optional 0x02 EIP-7251) | 3 | 7 |
| **Total** | | **137** | **278** |

### Per-milestone totals

| Milestone | Phases | Issues | Points | Days (pts÷2) | Working weeks |
|-----------|--------|--------|--------|--------------|---------------|
| M0 (v0.2 "Hoodi-Trustworthy") | 11 | 62 | 129 | 64.5 | ~13 |
| M1 (v1.0 "Mainnet-Ready") | 9 | 51 | 109 | 54.5 | ~11 |
| M2 (v1.1 Hardening) | 4 | 24 | 40 | 20.0 | ~4 |
| **Total** | **24** | **137** | **278** | **139** | **~28** |

**Calendar estimate (single-stream):** 139 working days ≈ **28 weeks ≈ 6.5 months** of focused execution. Add ~1 week per milestone for code review cycles, hardware E2E (M0.11, M1.9), and release cuts, taking the realistic v0.2→v1.1 wall-clock to ~7.5 months single-stream.

---

## Critical-path issue sequence (v0.2)

This is the shortest viable chain of issues that ships v0.2.0. Issues outside this chain are still required for v0.2 (every P0 must close per PRD §6.1) but their relative ordering is flexible inside their phase.

| # | Issue | Phase | Pts | Why on critical path |
|---|-------|-------|-----|-----------------------|
| 1 | M0.1-2 Toolchain pin (`toolchain go1.26.4` + `setup-go`) | M0.1 | 2 | Gates every later PR via CI matrix. |
| 2 | M0.1-1 `gofmt -w .` sweep + `gofmt -l` gate | M0.1 | 2 | Required before lint-clean PRs are accepted. |
| 3 | M0.1-4 `errcheck` integration + resolve hits | M0.1 | 3 | Lint gate: every later PR must be clean. |
| 4 | M0.1-5 `govulncheck` + weekly cron + `docs/SECURITY.md` | M0.1 | 3 | Lint gate + release-blocker policy. |
| 5 | M0.2-1 `go-ethereum` v1.17.x bump + compile fixes | M0.2 | 4 | All downstream signer/tx/RPC work depends. |
| 6 | M0.3-1 `atomicio.WriteFile` + sentinels + tests | M0.3 | 3 | Consumed by 5 call sites in M0.4/M0.6/M0.7. |
| 7 | M0.3-2 `atomicio.WriteFileWithSuffix` + naming | M0.3 | 3 | Consumed by `internal/output` in M0.7. |
| 8 | M0.4-1 `--withdrawal-address` flag + EIP-55 validation | M0.4 | 3 | Headline release-blocker fix (GO-001). |
| 9 | M0.4-4 `Entry.Validate` WC shape checks (DiD) | M0.4 | 3 | Defense-in-depth for GO-001. |
| 10 | M0.4-6 `internal/cli.Redact` helper | M0.4 | 1 | Consumed by M0.6 chain-ID guard + M0.8. |
| 11 | M0.5-1 `Entry.ValidateForNetwork` + sentinels | M0.5 | 4 | Release-blocker fix (GO-002). (split-watch) |
| 12 | M0.5-2 SSZ root recompute + equality in `Entry.Validate` | M0.5 | 3 | Release-blocker fix (GO-012). |
| 13 | M0.5-4 `tx.ValidateAgainstNetwork` DiD partner | M0.5 | 2 | Two-layer enforcement of GO-002. |
| 14 | M0.5-5 Wire call sites in `buildUnsignedTx` + `runAction` | M0.5 | 2 | Activates the boundary. |
| 15 | M0.6-1 `parseUnsignedTx` strict address + length | M0.6 | 3 | Release-blocker fix (GO-003). |
| 16 | M0.6-4 `validateSignedAgainstRLP` implementation | M0.6 | 4 | Release-blocker fix (GO-004). (split-watch) |
| 17 | M0.6-5 `sendAction` integration with RLP validate | M0.6 | 3 | Activates GO-004 fix. |
| 18 | M0.7-8a Reject `--rpc-url` on build/run | M0.7 | 2 | Closes GO-005 (release blocker). |
| 19 | M0.7-3 `FSWriter.Write` → `atomicio.WriteFileWithSuffix` | M0.7 | 2 | Closes GO-011 (release blocker). |
| 20 | M0.7-9 Unify atomic write + delete local helper | M0.7 | 2 | Closes GO-016. |
| 21 | M0.7-2 Receipt revert/timeout sentinels + exit 5 | M0.7 | 3 | Closes GO-010. |
| 22 | M0.8-1 `bls.NewSigner` `ErrSecretRejected` | M0.8 | 2 | Closes GO-006. |
| 23 | M0.8-2 `--private-key-env` redact in Load*Config | M0.8 | 3 | Closes GO-014. |
| 24 | M0.8-4 `CachingPromptSource` (single TTY prompt) | M0.8 | 3 | Closes GO-007. |
| 25 | M0.9-1 USER-GUIDE.md `--withdrawal-address` example | M0.9 | 2 | Required for tag (FR-P0-F1). |
| 26 | M0.9-2 CHANGELOG.md v0.2 entry | M0.9 | 2 | Required for tag (FR-P0-F2). |
| 27 | M0.9-3 MIGRATION.md v0.1→v0.2 | M0.9 | 2 | Required for tag (FR-P0-F2). |
| 28 | M0.10-1 Refresh goldens + activate `assert-no-zero-wc` | M0.10 | 3 | Required for tag (PRD §12). |
| 29 | M0.11-1 `make e2e-testnet` real-hoodi run | M0.11 | 2 | PRD §12 M0 exit criterion. |
| 30 | M0.11-2 `make e2e-ledger-testnet` maintainer run | M0.11 | 2 | PRD §12 M0 exit criterion. |
| 31 | M0.11-3 Final lint + tag v0.2.0 + binaries | M0.11 | 2 | The release tag. |

**Critical-path subtotal:** 31 issues, ~80 points ≈ **40 days ≈ 8 weeks** single-stream from M0.1 start to v0.2.0 tag, assuming no rework and one PR per issue.

(The remaining ~31 M0 issues — golden-skip markers, `requireNoArgs`, FR-P0-B-cluster cleanups, range constants, doc renames — run on the same single stream but do not gate any later issue, so they can be sequenced in their phase order without changing the critical-path duration.)

---

## Dependency edges (high-level, between phases)

```
M0.1 ──► M0.2 ──► M0.3 ──► M0.4 ──► M0.5 ──► M0.6 ──► M0.7 ──► M0.8 ──► M0.9 ──► M0.10 ──► M0.11
                                                                                              │
                                                                                              ▼
                                          M1.5 ──► M1.6 ──► M1.7 ──► M1.8 ──► M1.9
                                            ▲
                  M1.1, M1.2, M1.3, M1.4 ───┘  (can land in any order between M0.11 and M1.5)
                                                                                              │
                                                                                              ▼
                                          M2.1 ──► M2.2 ──► M2.3 ──► M2.4
```

(M1 ordering note from project-plan §Dependency Graph: M1.5 first because `TestExitCodeContract` gates every later M1 PR; M1.6 second because it's the visible release-blocker; M1.7 needs M1.6's mainnet-gate matrix. M1.1–M1.4 can interleave.)

---

## Risk flags

Issues likely to slip or need a split decision in flight. Estimator confidence is **medium** on each.

| Issue | Risk | Mitigation |
|-------|------|------------|
| M0.2-1 (geth v1.17.x bump) | Compile churn across `internal/tx`, `internal/signer`, `cmd/eth-deposit-tx` may exceed 4 pt if usbwallet APIs shifted more than expected. | Land on feature branch; if compile fixes hit 6+ files, split into "bump" (2 pt) + "compile fixes" (3 pt). |
| M0.5-1 (`Entry.ValidateForNetwork`) | 4 pt covers new method + 5 sentinels + BLS verifier threading. Split-watch. | If `bls.Verifier` plumbing through `cfg` takes >2 hr, split off "verifier wiring" as a separate 2-pt issue. |
| M0.6-4 (`validateSignedAgainstRLP`) | 8+ field checks + RLP decode + LatestSignerForChainID. Split-watch. | If acceptance test count > 8, split RLP decode into a helper and a second issue for the field checks. |
| M0.7-8 (`--rpc-url` reject + dead-field delete) | Already split into 8a/8b. Watch for hidden callers of `BuildConfig.RPCURL` / `UnsignedTx.From` across tests. | grep at issue start; if hidden callers > 5, treat as a third issue. |
| M0.7 phase total (19 pts / 10 issues) | Largest phase; cumulative slip risk per project-plan Risk P2. | Sequence GO-011/GO-016 first (block downstream), GO-005 last (independent). |
| M0.10 (golden fixture refresh) | Mechanical refresh PR is a huge diff (every committed fixture). Reviewer fatigue. | Per project-plan D4: PR is auto-generated, not edited; reviewer reads the CHANGELOG note + checks scheme. |
| M0.11-1 (real-hoodi E2E) | Hosted RPC rate limits or transient errors per project-plan Risk P5. | Use self-hosted RPC; allow up to 3 retries; document tested provider. |
| M1.2-4 (differential SSZ oracle) | sszgen tooling + committed generated code + CI lane. Split-watch. | If sszgen integration is fiddly, split "sszgen scaffold + commit" (2 pt) + "oracle tests" (2 pt). |
| M1.5-9 (`TestExitCodeContract`) | One table per binary; every sentinel from architecture §15. Split-watch. | If sentinel count exceeds 25 per binary, split into per-binary issues (2 pt each). |
| M1.7-1 (Dockerized cross-validate image) | First-time Docker work in this repo. | Time-box to 1 day; if blocking, descope CI workflow scaffolding to a follow-up. |
| M1.8-4 (`make doc-audit` mechanism) | PRD success metric #9; mechanism not yet designed. | Project-plan Spike S5: prototype during M0.9; finalize here. If unsolved by end-of-day, ship `doc-audit` as a grep-based smoke check. |
| M2.4-1 (optional 0x02 EIP-7251) | Marked optional. Skip if EIP-7251 spec not settled. (split-watch) | Range constants already in M0; this issue is additive only. Defer to vNext if spec movement makes it risky. |

---

## Estimation discipline notes

- **Single-stream by construction.** No `Stream A`/`Stream B`/file-ownership-map sections are produced.
- **Every 4-pt issue** is flagged with `(split-watch)` and a split plan in its phase file's notes.
- **Locked decisions honored** (do not revisit in any issue):
  - v0.2 withdrawal credentials: `--withdrawal-address` (0x01) ONLY. No `--withdrawal-bls-pubkey`.
  - Receipt-timeout/revert: reuse exit code 5 with sentinel discriminator (no new exit code).
  - `ethstaker-deposit-cli` (not deprecated `staking-deposit-cli`).
  - `go-ethereum` v1.17.x; toolchain `go1.26.4`.
  - `fastssz` oracle behind build tag `differential_oracle`.
  - `internal/atomicio` is a new package; helper not inside `internal/cli`/`internal/output`.
  - Single-stream execution (no parallel writers planned).

---

## Open scope risks surfaced during estimation

1. **M1.3-5 (Hybrid `--rpc-url` wire-on-run-only)** — Spike S3 (architecture §17). Implementation reuses `resolveRPC` retained in M0; the ADR-004 lock-in says wire on `run` only. If `BuildConfig` shape requires reshaping to accept an optional `EthRPC`, scope expands by ~1 pt — flag at start.
2. **M1.7-1 (CI Docker image baked with `ethstaker-deposit-cli`)** — first-time use of pinned-Docker pattern in this repo; if image-build cadence becomes a bottleneck, consider GH-actions-cache or a separate hardened runner. Not blocking v1.0 ship but a maintainability risk.
3. **M2.3-2 (`ledger_nocgo.go` decision; Spike S4)** — Project-plan defers to M2 ADR-008. If the decision is "break `signer → bls`," the implementation cost is at least 2 pt (refactor) + 2 pt (CI matrix). Current estimate assumes the simpler "delete the stub" path.
4. **M0.7-2 (receipt timeout/revert)** — Locked decision is "reuse exit code 5 with sentinel discriminator." Confirms no new public exit code needed in v0.2; revisit only if M1 automation explicitly demands code 6.
5. **No DevOps/release-engineering issues found beyond M0.11 / M1.9 / M2.4** — the repo's existing `goreleaser`/`make` setup absorbs the release-build burden. If `goreleaser.yaml` is regenerated (gitStatus shows it as deleted), reinstate it as a 1-pt M0.11 follow-up.

---

## Sign-off checklist for the team-lead

- [ ] Total point budget (278 pt / ~6.5 months) acceptable for v0.2→v1.1 single-stream.
- [ ] Critical-path duration (~80 pt / ~8 weeks) acceptable for v0.2 alone.
- [ ] 4-pt `(split-watch)` issues listed in **Risk flags** above are acceptable as-is or split now.
- [ ] No missing scope: the M0/M1/M2 closure tables (PRD §14) and the architecture §14 element maps are both covered by issue IDs.
- [ ] Golden-fixture refresh as **one** issue (M0.10-1) is acceptable.
- [ ] Hybrid `--rpc-url` decision (M1.3-5) confirmed as "wire on `run` only".
