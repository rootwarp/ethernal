# Issue Overview — eth-deposit Findings-Resolution Release

> This is the roll-up file the task calls "summary.md" (written as `overview.md` because the
> harness blocks the literal name `summary.md`). It indexes `phase-1.md … phase-4.md`.

**Scope:** `go/` — one Go module, the `eth-deposit` CLI. Six findings (F1–F6).
**Sizing:** 1 story point ≈ half a working day. Every issue is ≤ 4 pts (≤ 2 days).
**Streams:** A = critical path (F1 foundations → F1 wiring → doc pass → verification);
B = parallelizable work (F2 hook, F5 no-TTY; then F3 dry-run, F6 `.raw`).
**Merge model:** per-issue fast-forward; every merge must be green.

---

## All issues

| ID | Title | Pts | Stream | Depends on |
|---|---|---|---|---|
| P1-1 | `internal/tx` `ErrRPCEstimation` sentinel + tag 4 `resolveRPC` call failures | 2 | A | — |
| P1-2 | `LocalSigner.Address()` accessor | 1 | A | — |
| P1-3 | F5 no-TTY passphrase sentinel + `--passphrase-env` hint | 2 | B | — |
| P1-4 | F2 usage-error hook (`onUsageError`/`applyUsageErrorHook`) + `newFullTestApp` | 2 | B | — |
| P1-5 | `exit.go` sentinel mappings (`ErrRPCEstimation`→5, `ErrChainIDMismatch`→2, `ErrMissingFromForNonce`→2, `ErrNoTTY`→2) | 1 | A | P1-1, P1-3 |
| P2-1 | `--from` flag + `Config.From` + tightened config-time gate | 2 | A | — (phase gate M1) |
| P2-2 | Dial+inject seam, default-fill relocation, drop dead `RPCURL` (indivisible) | 4 | A | P2-1, P1-1, P1-5 |
| P2-3 | `run --signer local` `From` derivation | 2 | A | P1-2, P2-1, P2-2 |
| P3-1 | F3 `gen --dry-run` conditional requiredness | 2 | B | — |
| P3-2 | Consolidated exit-code / chain-ID doc pass (F4 + F1.6 prose) | 2 | A | P2-1, P2-2 |
| P3-3 | F6 `.raw` companion output polish | 0.5 | B | — |
| P4-1 | Automated suite + hybrid e2e case + golden byte-identity | 2 | A | P3-1, P3-2, P3-3 |
| P4-2 | Verify-skill playbook (live anvil) + final consistency read + M1–M7 sign-off | 2 | A | P4-1 |

**Total: 24.5 points** (≈ 12.25 person-days single-developer).

## Per-phase totals

| Phase | Theme | Issues | Points | Milestone |
|---|---|---|---|---|
| 1 — Foundations | sentinels, seam prereqs, exit-code plumbing, usage-error hook | 5 | 8 | M1 |
| 2 — Hybrid RPC wiring | dial/inject, default-fill relocation, `--from`, `From` derivation | 3 | 8 | M2 |
| 3 — Independent fixes & doc pass | dry-run, consolidated exit-code/`.raw` docs | 3 | 4.5 | M3 |
| 4 — Integration verification | full suite, e2e, golden diff, verify playbook | 2 | 4 | M4 |
| **Total** | | **13** | **24.5** | |

## Findings coverage

| Finding | Priority | Issue(s) |
|---|---|---|
| F1 (RPC wiring, incl. F1.5 error classification) | P0 | P1-1, P1-2, P1-5, P2-1, P2-2, P2-3 |
| F1.6 (help/doc text for RPC + `--from`) | — | P2-1, P2-2, P2-3 (inline Usage); P3-2 (exit-code prose + USER-GUIDE) |
| F2 (missing-required-flag → exit 2) | P0 | P1-4 |
| F3 (`gen --dry-run` no `--output-dir`) | P1 | P3-1 |
| F4 (chain-ID mismatch doc disambiguation) | P1 | P3-2 |
| F5 (no-TTY passphrase hint + exit 2) | P1 | P1-3 (message/sentinel), P1-5 (exit map) |
| F6 (document `.raw` companion) | P2 | P3-3 (verify/polish, 0.5 pt) |

---

## Estimated parallel duration (two streams)

The critical path is dominated by **Phase 2**, an inherently **serial** chain: P2-1 → P2-2 both
edit `config.go` and `main.go` (they cannot overlap), and P2-2's default-fill relocation is an
indivisible single commit (Risk R1). Stream B cannot help on the build path; it absorbs only the
pull-forward-able work — F3 (P3-1), F6 (P3-3), and developing the run-path P2-3 (disjoint file
`run.go`) alongside P2-2 for merge right after it.

**Critical-path walltime** (points of wall-clock on Stream A; Stream B runs concurrently):

| Phase | Stream-A walltime | Stream B (concurrent) |
|---|---|---|
| 1 | 4 pts (P1-1→P1-2→P1-5) | P1-3, P1-4 (4 pts) — balanced |
| 2 | 6 pts (P2-1→P2-2; P2-3 developed by B, merged after P2-2) | P3-1, P3-3, develop P2-3 (~4.5 pts) |
| 3 | 2 pts (P3-2, needs M2) | idle / review |
| 4 | 4 pts (P4-1→P4-2) | idle / review |
| **Total** | **~16 pts wall ≈ 8 working days** | |

**Headline (chosen assumption — build/run paths parallelize, plan-endorsed):**
two-stream ≈ **16 story-points of wall-clock ≈ ~8 working days (~1.5–2 weeks)**, versus a single
developer at **24.5 pts ≈ ~12 days**.

**Conservative fallback** (Phase 2 fully serial, P2-3 not overlapped): Phase 2 = 8 pts → total
≈ **18 pts wall ≈ ~9 working days**.

The two-stream speedup is modest (~30–35%, not 50%) precisely because the F1 RPC-wiring critical
path serializes Phase 2 and leaves Stream B underused mid-release. Shortening the build-path chain
further would violate the indivisible-commit constraint (Risk R1) or the every-merge-green rule.
