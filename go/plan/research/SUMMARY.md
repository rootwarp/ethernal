# Research Synthesis — eth-utils/go Remediation PRD (Task #2)

**Researcher:** researcher agent (team dev-plan)
**Date:** 2026-06-07
**Input:** `go/plan/prd.md` (v1 draft, 71-finding remediation), `go/plan/REVIEW.md` (adversarial review).
**Output:** 8 topic files (`01-staking-deposit-cli.md` through `08-eip-7251-compounding-credentials.md`) + this synthesis.

---

## TL;DR — Recommendations to team-lead

1. **All eight PRD assumptions are upstream-feasible.** No P0 requirement blocked by external reality.
2. **Three PRD adjustments needed before implementation can start:**
   - **(a)** Retarget every `staking-deposit-cli` reference to `ethstaker-deposit-cli` — the original is deprecated as of 2025-10-06 [1].
   - **(b)** Relax the minimum go-ethereum version: the Ledger fix is in **v1.15.0**, not v1.17.0 (PRD wording in REVIEW.md GO-055 already correct; double-check FR-P0-D1 references). Pinning to v1.17.x is still right for cumulative coverage.
   - **(c)** FR-P0-G2 (`DepositAmountGwei` constant) should be either annotated "v0.2 only" or shaped as a `Min..Max` range upfront, because v1.1 0x02 compounding deposits need 32 ETH ≤ amount ≤ 2048 ETH per EIP-7251 [2].
3. **One PRD requirement is partially achievable, not fully:** FR-P1-B4 "zeroize BLS secret" can only wipe Go-side state; the C-side `mcl` scalar inside herumi has no `Destroy` API. Document the limitation; don't promise full erasure.

## Key recommendations per topic

| # | Topic | Recommendation | Verdict |
|---|---|---|---|
| 1 | staking-deposit-cli | Retarget to ethstaker-deposit-cli (active fork); pin v1.3.0 in CI | ✅ |
| 2 | go-ethereum upgrade | Pin v1.17.x; v1.15.0 was the Ledger-fix landing point; no API breaks affect us | ✅ |
| 3 | herumi BLS APIs | All three FR (C1/C1/C2) are one-line changes; secret leak is upstream-confirmed | ✅ |
| 4 | Consensus-spec rules | Fork-version-equals-genesis is correctly captured; DOMAIN_DEPOSIT with zero GVR is canonical | ✅ |
| 5 | Differential SSZ oracle | Use `ferranbt/fastssz` (Apache-2, no CGO) behind a build tag; backstop with Python eth2spec weekly | ✅ |
| 6 | Atomic file writes | `os.CreateTemp` + `RFC3339Nano + sha256[:4]` final name + dir fsync; no external dep needed | ✅ |
| 7 | govulncheck/errcheck/CI | Standalone tools via tools.go; golangci-lint integration explicitly rejected upstream; toolchain directive + setup-go pinned to same version | ✅ |
| 8 | EIP-7251 0x02 compounding | Layout = `0x02 \|\| 11 × 0x00 \|\| address`; live mainnet since May 2025; v1.1 scoping is sensible; flag constant-vs-range design choice | 🟡 (needs PRD §11.4 decision) |

## PRD assumptions contradicted or amended

| PRD location | Assumption | Reality | Action |
|---|---|---|---|
| FR-P1-G1, runDepositCLIVerify, USER-GUIDE | `staking-deposit-cli` is the external authority | Deprecated 2025-10-06; active fork is `ethstaker-deposit-cli` | Rename everywhere, pin version in CI |
| FR-P0-G2 | `DepositAmountGwei = 32_000_000_000` as a single constant | 0x02 deposits range 32–2048 ETH; will need a range when v1.1 lands | Annotate as v0.2-only, OR shape as range upfront |
| FR-P1-B4 | "Add a Destroy/Zeroize method to the BLS signer" implies full secret erasure | herumi's C-side scalar has no Destroy API; only Go-side struct can be zeroed | Document Go-side-only erasure honestly |
| §11.4 (open Q) | EIP-7251 timing TBD | Pectra is live (May 2025); ethstaker CLI shipped support in v0.5.0 | Decide M2 vs vNext now to avoid FR-P0-G2 rework |
| §6.1.4 FR-P0-D1 | go-ethereum `>= v1.17.0` for usbwallet fix | Fix actually landed in v1.15.0 (#31004); v1.17.0 adds Gen5 on top | No functional change — v1.17.x is still right target, but the *minimum* is v1.15.0 |

## Open risks

- **R-A.** Pinning ethstaker-deposit-cli adds a non-Go runtime dep to CI. Mitigate via Docker image with pip-cached install; consider a `make test-cross-validate` target that checks for the binary before running.
- **R-B.** herumi BLS C-side scalar persistence means our zeroization story has an honest limitation. The PRD's FR-P0-C1/C2 close the *error-leak* path, which is the bigger reachable risk; document the C-side caveat in `internal/bls/bls.go` doc comment.
- **R-C.** PRD §11.4 needs an explicit decision before FR-P0-G2 ships. Recommend: track 0x02 as M2 (v1.1) and shape `DepositAmountGwei` as a `Min..Max` range now to avoid a breaking constant rename later.
- **R-D.** `accounts/usbwallet` PR #31004's upper-byte PID match changes the device-enumeration heuristic. Manual Ledger E2E (FR-P0-D4) is essential — automated tests cannot cover firmware-PID compatibility.
- **R-E.** `govulncheck` uses Go-on-PATH stdlib for analysis, not the `toolchain` directive (golang/go#62050). CI must explicitly pin `setup-go` version to match the directive.

## Suggested next steps for team-lead

1. **Approve the three PRD amendments** (staking-deposit-cli → ethstaker, FR-P0-G2 annotation, FR-P1-B4 honesty patch). These are small edits, do not change the milestone shape.
2. **Decide §11.4** (EIP-7251 timing) so FR-P0-G2 lands in its final shape.
3. **Hand off to project-planner** with these research files attached. The implementation plan should sequence:
   - FR-P0-E1/E2/E3 (toolchain + CI gates) **first** — they catch regressions in every subsequent PR.
   - FR-P0-A1..A6 (trust-boundary critical fixes) **second** — these unblock the M0 release.
   - FR-P0-B1..B10 (silent-loss / data-correctness) **third** — bulk parallel work.
   - FR-P0-C1..C5 (secret-leak fixes) and FR-P0-D1..D4 (Ledger) can run in parallel with B-stream.
   - FR-P0-F/G (docs and quality catalogue) **last** within M0.

## Sources

[1] [ethereum/staking-deposit-cli (deprecated)](https://github.com/ethereum/staking-deposit-cli) — Ethereum Foundation, archived 2025-10-06.
[2] [EIP-7251](https://eips.ethereum.org/EIPS/eip-7251) — Ethereum, MAX_EFFECTIVE_BALANCE = 2048 ETH.
[3] [go-ethereum PR #31004](https://github.com/ethereum/go-ethereum/pull/31004) — Ledger Flex + new firmware PID fix in v1.15.0.
[4] [ethstaker/ethstaker-deposit-cli](https://github.com/ethstaker/ethstaker-deposit-cli) — active fork.
[5] [herumi/bls-eth-go-binary source](https://github.com/herumi/bls-eth-go-binary/blob/master/bls/bls.go) — Deserialize error literally embeds `%x` of the input buffer (GO-006 root cause).
[6] All eight topic files in this directory.
```


---

## Index update (follow-up research round)

Two additional topic files and one addendum were produced in a follow-up round to match the canonical task topic list:

- **[09-verify-before-broadcast.md](09-verify-before-broadcast.md)** — geth APIs to decode `rawRLP` (`types.Transaction.UnmarshalBinary`), recover the sender (`types.Sender` + `LatestSignerForChainID`), field-compare against JSON metadata before the `send` prompt (FR-P0-A6, GO-004), and recompute SSZ roots + BLS-verify deposit entries on the read path (FR-P0-A4, GO-002/GO-012). Feasibility GREEN, no new dependencies.
- **[10-urfave-cli-contract.md](10-urfave-cli-contract.md)** — required-flag errors must map to exit 2 (GO-015), rejecting unexpected positional args (GO-040), reading the confirmation from `/dev/tty` when `--input -` exhausts stdin (GO-041), and the `/dev/tty` single-prompt-and-cache precedent for concurrent passphrase prompts (GO-007). Feasibility GREEN.
- **[05-differential-ssz-oracle.md](05-differential-ssz-oracle.md) addendum** — `accounts/abi`-based cross-check for `PackDeposit` (GO-070) and hermetic CI invocation of ethstaker-deposit-cli for cross-validation (GO-059).
