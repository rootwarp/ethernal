# Dev Plan — Audit Gap Closure (external-lineage audit 2026-07-18)

**Scope:** Resolve gaps 1–4 of the 2026-07-18 code audit of `develop` @ `0308f66` against the
deposit-cli vulnerability survey (Trail of Bits 2020/2024/2026 + GHSA-c6rv-g6pj-r6qx). The
audit lives in the knowledge vault:
`1.Projects/ethernal/202607181903 - Audit - ethernal Implementation vs Known deposit-cli and EOA Keystore Issues.md`.

Planned via the full dev-plan pipeline (PRD → research → architecture → project plan →
issues) on 2026-07-18.

## Artifacts (reading order)

| Artifact | Role |
|---|---|
| [prd.md](prd.md) | Requirements G1-x..G4-x with P0/P1, success metrics SM-1..SM-4 (audit-row flips) |
| [research/](research/) | Per-gap findings: upstream remediations, resolved action SHAs, field maps, platform traps |
| [architecture.md](architecture.md) | Binding design D-G1..D-G4, file:line boundary maps, **PRD amendments (G3-1, G4-2)** |
| [project-plan.md](project-plan.md) | Phases, verification tiers, risk register (top risk R-G1a: stash⇄architecture drift) |
| [issues/index.md](issues/index.md) | Execution entry point — sprint-ready issues G1..G4 |

**Precedence for implementers:** issue file + architecture.md are the single source of
truth; architecture.md's amendments override the PRD's literal G3-1/G4-2 wording.

## Traceability — audit gap → issue

| Audit gap | Lineage | Resolved by | Pts |
|---|---|---|---|
| 1 — no scrollback clear after mnemonic ceremony | DEP-001 → ETHSTAKER-7 | **G1** | 2 |
| 2 — CI actions pinned to mutable tags | ETHSTAKER-1 | **G2** | 1 |
| 3 — no symlinked-output-dir warning | ToB Mar 2026 recommendation | **G3** | 1 |
| 4 — no batch-distinctness regression test | GHSA-c6rv-g6pj-r6qx / ETHSTAKER-6 class | **G4** | 2 |
| 5 — release signing / attestations | DEP-007 → ETHSTAKER-2 | Disposition **D1** (deferred) | — |

**Total: 6 points.** Order G1 → G2 → G3 → G4, sequential on one tree (all four are
file-disjoint; G2 is CI-only and can interleave). Merge model: one ordinary fast-forward
commit per issue on `develop`, every commit green (`make lint && make test`, full suite
~30 min).

## Dispositions — resolved by decision, no code change now

**D1 — Gap 5, release signing/attestations (DEP-007 → ETHSTAKER-2).** Deferred by the audit
itself: there is no release pipeline yet. Trigger: MUST land together with the first
binary-release workflow (sigstore/SLSA-style attestation or minimum checksums + signature).
G2 (commit-pinned actions) is its prerequisite and is done now precisely so the future
release workflow starts from pinned actions. When gap 5 lands, also add Dependabot
`package-ecosystem: github-actions` to keep pins fresh (see issues/g2.md out-of-scope).

## Current state (2026-07-18)

- **Planning complete; execution not started.**
- **G1 has a drafted, review-pending implementation** preserved in `git stash` as
  `ccd0abe9 g1: mnemonic scrollback clear (paused before review/commit)` (patch copy also
  in the planning-session scratchpad). Execution = pop → diff against D-G1 acceptance
  properties (all five post-display paths + non-vacuous FailAfterDisplay fail-open test) →
  adjust → review (general + security) → commit. Do not re-implement from scratch; do not
  trust either prior doc's description of the stash — the popped code is ground truth
  (risk R-G1a).
- G2's `dtolnay/rust-toolchain@stable` SHA must be re-resolved at implementation time
  (moving branch); re-verify commands in issues/g2.md.
- G2–G4 not started.
