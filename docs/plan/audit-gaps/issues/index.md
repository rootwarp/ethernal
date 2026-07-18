# Audit-gap closure — issues index

Sprint-ready issue files for closing gaps 1–4 of the 2026-07-18 code audit of `develop` (deposit-cli /
EOA-keystore lineage). Detail folded in from the approved [`../prd.md`](../prd.md),
[`../architecture.md`](../architecture.md) (binding — carries the PRD amendments + decisions D-G1..D-G4),
[`../project-plan.md`](../project-plan.md), and [`../research/`](../research/). Disposition **D1** (gap 5,
release signing) is **not** an issue — it lives in [`../overview.md`](../overview.md) and is not duplicated
here.

**4 issues · 6 points** (1 pt ≈ half a working day). Issue files:
[`g1.md`](g1.md) · [`g2.md`](g2.md) · [`g3.md`](g3.md) · [`g4.md`](g4.md).

> Each issue file is a **single source of truth**: an implementer reading only that file +
> [`../architecture.md`](../architecture.md) can execute without the PRD or research.

## Traceability — audit gap → issue → success metric

| Audit gap | Lineage | Issue | SM |
|---|---|---|---|
| 1 — no scrollback clear after the mnemonic ceremony | DEP-001 → ETHSTAKER-7 (recurred in every upstream audit) | **G1** | SM-1 |
| 2 — CI actions pinned to mutable tags | ETHSTAKER-1 | **G2** | SM-2 |
| 3 — no symlinked-output-dir warning | ToB Mar 2026 recommendation | **G3** | SM-3 |
| 4 — no batch-distinctness regression test | GHSA-c6rv-g6pj-r6qx / ETHSTAKER-6 | **G4** | SM-4 |
| 5 — release signing / attestations | DEP-007 → ETHSTAKER-2 | **D1** (deferred — see [`../overview.md`](../overview.md)) | — |

## All issues

| ID | Title | Pts | Stream | Depends on | Audit row flipped |
|---|---|---|---|---|---|
| [G1](g1.md) | Clear terminal scrollback after the mnemonic ceremony | 2 | A | — | ETHSTAKER-7: ❌ Gap → ✅ Mitigated (success path; fail-open warns, multiplexer caveat documented) |
| [G2](g2.md) | Pin GitHub Actions to full commit SHAs | 1 | B | — | ETHSTAKER-1: ❌ Gap → ✅ Mitigated (actions SHA-pinned) |
| [G3](g3.md) | Warn when the output directory is a symlink | 1 | A | — | ToB Mar 2026 symlink rec.: ❌ Gap → ✅ Mitigated (warn on symlinked output dir) |
| [G4](g4.md) | Batch-distinctness E2E regression test (salt/IV/UUID across `--count > 1`) | 2 | A | — | GHSA-c6rv-g6pj-r6qx / ETHSTAKER-6: ✅ Mitigated → ✅ Mitigated **+ regression-guarded** |

**Total: 6 points** (≈ 3 person-days). All four are **independent** — disjoint files, no merge coupling, no
code overlap. Nature of the work: four small, defense-in-depth / regression edits to an already-audited binary
("well implemented, four gaps remain"). No crate boundary moves, no new dependency, no new inter-crate edge.

## Binding decisions & PRD amendments (architecture overrides raw PRD)

The implementer follows these, not the literal PRD text where they differ. Full detail lives in each issue.

| # | Decision | Where it bites |
|---|---|---|
| D-G1 | Adopt the stash's `warn_out: &mut dyn Write` seam on `run_ceremony` (fed by `deps.summary_out`); clear must fire on **all five** post-display paths. G1 is a stash *reconcile*, not a rewrite. | [G1](g1.md) |
| D-G3a + amended G3-1 | Detect a **final-component** symlink via `symlink_metadata` only; `canonicalize` resolves the message target, never triggers detection (verbatim G3-1 false-positives on macOS `/var`,`/tmp`). | [G3](g3.md) |
| D-G3b | Do **not** unify the duplicated `validate_output_dir`; add an orthogonal `fs_util` helper called at the three `load_config` sites. | [G3](g3.md) |
| D-G4 + amended G4-2 | New `#[test]` in `key_e2e.rs`/`account_e2e.rs`, reuse `run_*_recover` at `--count 3`, real entropy, compare **raw JSON**. EOA v3 identifier is **`v["id"]`**, not `uuid`. | [G4](g4.md) |
| D-G2 | Pin the literal `@v2` resolution `e18b4977…` (deref'd commit) for `rust-cache`; add `with: toolchain: stable` to `dtolnay/rust-toolchain`. | [G2](g2.md) |

## Execution order & parallelism

**Recommended: sequential G1 → G2 → G3 → G4 on one working tree.** G1 carries the only real uncertainty (stash
reconcile + security review) and the highest-value flip → first, to de-risk early. G2 second, so the pinned
`ci.yml` is proven green on GitHub *before* G3/G4 commits run under it (a bad pin — esp. the rust-cache
annotated-tag deref — surfaces in isolation). G3 then G4 are the smallest, lowest-risk edits; G4 sits last
(test-only, most scrypt-heavy, plus a throwaway bite-proof rebuild off the critical path). **Parallelism
(optional):** every gap touches disjoint files, so any could be built on a separate worktree with zero
conflict; **G2 (stream B, CI-only, no Rust)** is the obvious lift-out if a second hand is free. For a solo 6-pt
effort the sequential path is the right default.

## Verification (three tiers — the ~30-min scrypt-heavy `make test` is the wall-clock driver)

1. **Per-commit gate (local):** `make lint && make test` green before each fast-forward. Only **G1, G3, G4** are
   semantically-fresh full runs; **G2 is inherited-green** (no Rust changed) — run it to honor the rule, expect
   no new signal.
2. **Per-push (GitHub CI):** the `ci.yml` workflow — the **only** place G2 is genuinely verified (green run
   under the new pinned actions, log showing the stable toolchain + clippy/rustfmt).
3. **Once, at the end:** G4's throwaway fixed-entropy bite-proof (scoped to the two new tests, reverted before
   commit); then the vault close-out doc edits (prose, not `make test`-gated).

## Conventions (all issues)

- **Merge model (locked, C-1):** per-issue **fast-forward ordinary commit on `develop`**, one per gap (subject
  prefix `g1:`…`g4:`); every commit green under **`make lint && make test`**. Behavior changes ship with tests.
- **Streams:** A = the three in-binary/test edits (G1, G3, G4); B = CI-only (G2), liftable to a parallel
  worktree at any time.
- **No new dependency, no crate boundary move, no inter-crate edge** (D-1). Security invariants S-1..S-3 hold:
  only two user-visible changes, both additive (G1 clear + notice, G3 stderr warning); G2 is CI-only, G4 is
  test-only.

## Sizing & change notes (flagged during estimation)

1. **Points unchanged — no re-cut.** 6 pts total (G1 2 / G2 1 / G3 1 / G4 2). At 1 pt ≈ half a day each issue
   is a ½–1-day unit, already within the 1–2-day granularity target; none exceeds it, so none was split or
   merged. G4 stays a single issue (two near-identical BLS/EOA tests + one bite-proof — splitting would
   fragment a tightly-coupled pair).
2. **G1 rewritten to match R-G1a — this is a change vs the *old issue file*, not vs the project plan.** The
   prior hand-written `g1.md` asserted the stash "already uses result-capture control flow" as fact. The
   finalized architecture (D-G1 / risk R-G1a) records that the two source docs **conflict** on the draft's
   control flow, so the popped code — not either description — is ground truth. `g1.md` now states the
   pop → diff-against-D-G1-acceptance-properties → adjust → review → commit sequence and neutralizes the
   over-confident claim, aligning it with the plan.
3. **G3 audit row labeled "ToB Mar 2026 recommendation"** (per PRD SM-3, architecture, project-plan, overview).
   The lone "ETHSTAKER-3" label in `research/g3-symlink.md` is a mislabel and is not used.
4. **Two PRD amendments carried verbatim into the issues** (from architecture): G3-1 → final-component
   detection only; G4-2 → EOA identifier is `v["id"]`, not `uuid`. All other locked decisions
   (clear-on-confirm, warn-don't-fail, recover-`--count` real-entropy, per-issue ff) stand.
5. **Most likely to bite: R-G1a** (G1 stash ⇄ architecture drift — a silent miss = an unscrubbed abort/partial
   path or a vacuous fail-open test). G1's general + security review is where the effort's real attention
   belongs. Every other risk is trivially mitigated (G2 re-resolve), designed out (G3a false positive), or
   negligible (G4 collision ≈ 2⁻¹²⁵).

## Milestone gate — M-AG (audit gaps closed)

Done when all four gaps are merged green on `develop` (`make lint && make test`) and the audit is updated to
reflect the flips above. Two close-out artifacts live in the **Obsidian vault** (prose edits, not
`make test`-gated):

- [ ] Update the audit's issue-by-issue table in `1.Projects/ethernal/202607181903 - Audit - ethernal
  Implementation vs Known deposit-cli and EOA Keystore Issues.md`: flip the four rows; leave **DEP-007 /
  ETHSTAKER-2 ⏳ Open, dispositioned D1** (its prerequisite G2 — pinned actions — is now satisfied).
- [ ] Update `1.Projects/ethernal/0.README.md` open-gaps list to match.
