# Project Plan — Audit Gap Closure (G1–G4)

**Scope (one line):** close audit gaps 1–4 on `develop` — mnemonic-ceremony scrollback clear (G1),
SHA-pinned CI actions (G2), symlinked-output-dir warning (G3), batch-distinctness regression test
(G4) — flipping four audit rows toward mitigated. Gap 5 (release signing) stays deferred (D1).
**Inputs (binding):** [`prd.md`](prd.md) (what/why) — **as amended by [`architecture.md`](architecture.md)**,
which carries two PRD amendments (G3-1, G4-2) and the binding design decisions D-G1..D-G4;
[`research/g1..g4`](research/) (specs + traps, esp. G2 SHA re-verification); [`issues/g1..g4.md`](issues/)
(per-gap design); [`overview.md`](overview.md) (issue list + D1). Style precedent:
[`../keygen/project-plan.md`](../keygen/project-plan.md).
**Sizing:** 1 story point ≈ half a working day (repo convention). Total **6 pts** (G1 2 / G2 1 / G3 1 / G4 2).
**Streams:** A = the three in-binary/test edits (G1, G3, G4); B = CI-only (G2), liftable to a parallel
worktree at any time.
**Merge model (locked, C-1):** per-issue fast-forward *ordinary* commits on `develop`, one per gap;
every commit green under `make lint && make test`. Full `make test` is **~30 min (scrypt-heavy)** — the
verification budget, not the coding, dominates wall-clock (see Verification).
**Nature of the work:** four small, independent, defense-in-depth / regression edits to an already-audited
binary — the audit verdict is "well implemented, four gaps remain." No crate boundary moves, no new
dependency, no new inter-crate edge (D-1). This plan is proportionate to that: phase == gap == one green
commit == one audit-row flip.

---

## Binding decisions & PRD amendments (architecture overrides raw PRD)

The implementer follows these, not the literal PRD text where they differ.

| # | Decision (architecture) | Effect on execution |
|---|---|---|
| D-G1 | Adopt the stash's `warn_out: &mut dyn Write` seam on `run_ceremony`, fed by `deps.summary_out` at both call sites; helpers live in `key_cmd.rs`; **clear must fire on all five post-display paths** (confirm / abort-exit-4 / read-error / cancel / partial-display-write). | G1 is a stash *reconcile*, not a rewrite. The clear-on-every-path property is the acceptance bar, independent of the draft's control-flow shape (see R-G1a). |
| D-G3a | G3 detects a **final-component symlink via `symlink_metadata` only**; `canonicalize` resolves the message target only, never triggers detection. **Amends G3-1** (its literal "final AND canonicalize-divergence" wording false-positives on macOS `/var`,`/tmp` and would redden `make test` on dev Macs). Intermediate/ancestor-symlink detection **deferred**. | Implement D-G3a, *not* verbatim G3-1. |
| D-G3b | Do **not** unify the duplicated `validate_output_dir`; add an orthogonal pure helper in `fs_util.rs`, called at each of the **three** `load_config` sites (`key_cli` / `account_cli` / `gen_cli`) on the existing `banner_out` writer. | 1 new helper + 3 one-line call sites; the two validators stay byte-for-byte unchanged. |
| D-G4 | New `#[test]` in `key_e2e.rs` (BLS) and `account_e2e.rs` (EOA), reusing `run_*_recover` at **`--count 3`**, real OS entropy, comparing **raw JSON** (no decrypt). **Amends G4-2:** EOA v3 identifier is **`v["id"]`**, not `uuid`. | Field paths fixed in architecture §G4; test-only diff. |
| D-G2 | Pin the literal `@v2` resolution for `rust-cache` (`e18b4977…`, the dereferenced commit), with `with: toolchain: stable` added to `dtolnay/rust-toolchain`. | No PRD deviation; see G2 re-verify step. |

All locked decisions (clear-on-confirm, warn-don't-fail, recover-`--count` real-entropy, per-issue ff)
stand unchanged.

---

## Issues

| ID | Gap → audit row (SM) | Pts | Stream | Files touched | Depends |
|---|---|---|---|---|---|
| **G1** | Gap 1 → ETHSTAKER-7 (SM-1) | 2 | A | `key_cmd.rs`, `account_cmd.rs` (call site), `docs/USER-GUIDE.md` | — |
| **G2** | Gap 2 → ETHSTAKER-1 (SM-2) | 1 | B | `.github/workflows/ci.yml` | — |
| **G3** | Gap 3 → ToB Mar 2026 rec. (SM-3) | 1 | A | `fs_util.rs` (+helper), `key_cli.rs` / `account_cli.rs` / `gen_cli.rs` (1 line each) | — |
| **G4** | Gap 4 → GHSA-c6rv-g6pj-r6qx / ETHSTAKER-6 (SM-4) | 2 | A | `tests/key_e2e.rs`, `tests/account_e2e.rs` | — |

**All four are independent** — disjoint files, no merge coupling, no code overlap.

### Execution order & parallelism

**Recommended: sequential G1 → G2 → G3 → G4 on one working tree.** Rationale: G1 carries the only real
uncertainty (stash reconcile + security review) and the highest-value flip, so it goes first to de-risk
early; G2 goes second so the pinned `ci.yml` is proven green on GitHub *before* G3/G4 commits run under
it; G3 then G4 are the smallest, lowest-risk edits, and G4 (test-only, most scrypt-heavy, plus a throwaway
bite-proof rebuild) sits last so its extra cost is off the critical path. **Parallelism (optional):** every
gap touches disjoint files, so any could be built on a separate worktree with zero conflict; G2 is the
obvious lift-out (CI-only, no Rust) if a second hand is free. For a solo 6-pt effort the sequential path is
the right default — parallelism buys little.

---

## Phase G1 — Clear scrollback after the mnemonic ceremony  (2 pts, stream A)

**Goal:** every post-display exit path scrubs screen + scrollback on the display `/dev/tty`; fail-open with
an actionable manual-clear warning; USER-GUIDE documents it in both flows. Architecture §G1 owns the
signatures, the doubled `CLEAR_SCROLLBACK_TWICE` const, and the `FailAfterDisplay` test writer.

**Tasks**
- [ ] **Pop the drafted stash** `ccd0abe9` (or apply the scratchpad patch), then **diff the actual popped
  code against D-G1** — do *not* trust either source doc's description of it (they conflict; see R-G1a).
  Reconcile to the architecture's acceptance properties, not to the draft's shape.
- [ ] Confirm/adjust: `warn_out` param on `run_ceremony` fed by `deps.summary_out`; the clear fires on **all
  five** post-display paths (confirm / mismatch-abort exit 4 / read-error / cancel / partial-display-write);
  the G1-3 success notice + tmux/screen caveat print on the blank tty.
- [ ] Confirm the clear-failure unit test uses the **`FailAfterDisplay`** writer (fails all writes/flushes
  after the display's terminal `flush()`), **not** an ESC-sniffing writer — the latter makes the
  stderr-fallback assertion pass *vacuously* (architecture §G1 "writer-trap, must-do"). Four unit tests map
  1:1 to G1-5 (bytes+order, abort-still-clears, fail-open→stderr, notice).
- [ ] Update `docs/USER-GUIDE.md` in **both** `key new` (§207) and `account new` (§320) plus the ceremony
  intro (§95): why (recurring finding), fail-open behavior, multiplexer caveat verbatim (`tmux clear-history`;
  screen `C-a :` → `scrollback 0`).
- [ ] Review cycle: **general + security** (the fail-open path and the no-mnemonic-in-warning invariant S-1
  are the security-load-bearing bits), then commit.

**Exit:** one green commit on `develop` (`make lint && make test`); recover-flow empty-tty assertions still
green. **Flips ETHSTAKER-7 → ✅ Mitigated (success path; fail-open warns, multiplexer caveat documented)**
[SM-1]. Residual (stated, accepted): panic between display and clear skips the scrub (no drop guard);
multiplexer history unreachable from the child.

## Phase G2 — Pin GitHub Actions to full commit SHAs  (1 pt, stream B)

**Goal:** all three third-party `uses:` in `ci.yml` reference a full 40-char commit SHA + version comment;
CI semantics unchanged. Architecture §G2 / research g2 own the resolved pins and traps.

**Tasks**
- [ ] **Re-resolve the SHAs fresh at implementation time** — mandatory for `dtolnay/rust-toolchain@stable`
  (a force-moving *branch*, not a tag; the recorded `4cda84d5…` will very likely be stale), spot-check the
  other two:
  ```sh
  gh api repos/actions/checkout/commits/v4            --jq .sha   # expect 34e11487…
  gh api repos/dtolnay/rust-toolchain/commits/stable  --jq .sha   # MOVES OFTEN — re-resolve, update date comment
  gh api repos/Swatinem/rust-cache/commits/v2         --jq .sha   # expect e18b4977…  (git ls-remote … 'v2^{}' without gh)
  ```
- [ ] Pin: `checkout@34e11487… # v4.3.1`; `rust-toolchain@<fresh> # stable branch @ <date>` **+ add
  `with: toolchain: stable`** (the `@<sha>` no longer names a toolchain — G2-2); `rust-cache@e18b4977… # v2
  (≈ v2.9.1)` — the **dereferenced commit** (`v2^{}`), **not** the annotated tag-object `42dc69e1…` (which
  fails to check out). No other `ci.yml` change.
- [ ] Local YAML parse (no `actionlint` in repo); push; **confirm the CI run goes green and its log still
  shows the stable toolchain + clippy/rustfmt installed** — this pushed run is G2's load-bearing evidence.

**Exit:** one green commit on `develop`; green CI run under the pinned workflow. **Flips ETHSTAKER-1 → ✅
Mitigated (actions SHA-pinned)** [SM-2]; also **satisfies the gap-5 (D1) prerequisite** (the future release
pipeline now starts from pinned actions). Note: G2 changes no Rust, so its `make test` is *inherited-green*
from the prior tip — honor the "every commit green" rule, but the real check is the CI run + SHA spot-check,
not a semantically-fresh 30-min suite.

## Phase G3 — Warn on a symlinked output directory  (1 pt, stream A)

**Goal:** a symlinked `--output-dir` emits exactly one stderr `WARNING:` naming given → resolved path;
real dirs are warning-free on every platform incl. dev Macs; writes otherwise unchanged. Architecture §G3
owns `symlinked_output_dir` / `warn_if_symlinked_output_dir` and the call-site wiring.

**Tasks**
- [ ] Add the pure `fs_util::symlinked_output_dir` (final-component `symlink_metadata`, D-G3a) +
  `warn_if_symlinked_output_dir` helper; copy the existing `symlink`-in-tests idiom (`fs_util.rs:99`).
- [ ] Wire one line after `validate_output_dir(…)?` at **all three** `load_config` sites — `key_cli.rs`
  (covers key new/recover), `account_cli.rs` (account new/recover), `gen_cli.rs` (inside `if !dry_run`).
  Leave both `validate_output_dir` copies byte-for-byte unchanged (D-G3b).
- [ ] Tests: `fs_util` detector/warner units (real dir → `None`/no line; symlink → `Some`/exactly one line
  naming both paths); **recover-mode `load_config` tests on both `key` and `account`** (SM-3 names *key AND
  account* — one call site tested leaves the other silently unverified). `gen` parity test optional.

**Exit:** one green commit on `develop`; existing E2E suites still green (they write real temp dirs → no new
line). **Flips ToB Mar 2026 symlink rec. → ✅ Mitigated (warn on symlinked output dir)** [SM-3].

## Phase G4 — Batch-distinctness E2E regression test  (2 pts, stream A)

**Goal:** a real-entropy `--count 3` batch on both BLS and EOA paths asserts pairwise-distinct salt / IV /
identifier / identity — the guard the catastrophic GHSA class defeated. **Zero product-code change.**
Architecture §G4 owns the exact JSON field paths.

**Tasks**
- [ ] New `#[test]` in `key_e2e.rs` reusing `run_key_recover(dir, 3)`; parse raw JSON (no decrypt); assert
  `HashSet` size == 3 for `crypto.kdf.params.salt`, `crypto.cipher.params.iv`, top-level `uuid`, plus
  distinct `pubkey`/`path`. Assert `files.len() == 3` first (fail loudly on a partial write).
- [ ] New `#[test]` in `account_e2e.rs` reusing `run_account_recover(dir, 3)`; same assertions on
  `crypto.kdfparams.salt`, `crypto.cipherparams.iv`, **top-level `v["id"]`** (D-G4 / G4-2 amendment — v3 has
  no `uuid`), plus distinct `address`. Do **not** touch the frozen `COUNT = 2` golden constant.
- [ ] **Bite-proof (local, throwaway, never committed):** temporarily wire fixed entropy into the CLI source,
  rebuild, run *only the two new tests* → confirm the salt/IV sets collapse to size 1 (test goes red);
  revert. Scope this to the new tests, not a third full suite run. Document the procedure in a test comment
  (there is deliberately no entropy flag — S-4). If a real-entropy batch path is genuinely unreachable,
  **escalate in the run summary; do not weaken to `FixedEntropy`.**

**Exit:** one green commit on `develop`, test-only diff (zero change under `bins/ethernal/src` or `crates/`).
**Flips GHSA-c6rv-g6pj-r6qx / ETHSTAKER-6 → ✅ Mitigated + regression-guarded** [SM-4].

---

## Verification strategy (three distinct tiers)

The ~30-min scrypt-heavy `make test` makes verification, not coding, the wall-clock driver. Keep the tiers
separate so time is spent once where it counts:

1. **Per-commit gate (local, ~30 min each × 3 substantive):** `make lint && make test` before each
   fast-forward. Only **G1, G3, G4** are semantically-fresh full runs; **G2 is inherited-green** (no Rust
   changed) — run it to honor the locked rule, but expect no new signal from it. Budget ≈ **2 h** of gated
   test time across the four commits (4 × ~30 min; ~1.5 h of it fresh signal, G2 repeating the prior tip's
   result), plus G1's review cycle.
2. **Per-push (GitHub CI):** the `ci.yml` workflow. This is the **only** place G2 is genuinely verified —
   the pushed run must go green *under the new pinned actions* and show the stable toolchain + clippy/rustfmt.
   Do G2 before G3/G4 so a bad pin (esp. the rust-cache annotated-tag deref) surfaces in isolation, not
   tangled with a Rust change.
3. **Once, at the end (not per-commit):** (a) G4's bite-proof — a single throwaway fixed-entropy rebuild
   scoped to the two new tests, reverted before commit; (b) the vault close-out doc updates (below), which
   are prose edits, not `make test`-gated. Per-gap evidence is the acceptance test itself: G1 four unit tests
   (incl. non-vacuous fail-open→stderr), G3 both-call-site `load_config` tests, G4 pairwise-distinctness, G2
   the green CI log.

---

## Risk register (per phase)

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| **R-G1a — stash ⇄ architecture drift.** The two source docs *disagree* on what the stash contains: architecture D-G1 says implicit early-returns (result-capture is the fix to add); `issues/g1.md` says the draft already uses result-capture. A silent miss = an unscrubbed abort/partial-write path, or a fail-open test that passes *vacuously*. | Med (silent security miss) | **High** (drift near-certain; the docs can't tell you what you'll find) | Treat the pop as a draft. Diff the **actual popped code** against D-G1's acceptance properties: clear on all five paths + `FailAfterDisplay` (not ESC-sniffing) test. Mandatory general + security review before commit. |
| R-G2a — `dtolnay@stable` SHA staleness | Low | High (force-moving branch) | Re-resolve fresh via `gh api`/`git ls-remote` before commit; update the `# stable branch @ <date>` comment. Designed-in, ~30-second fix. |
| R-G2b — annotated-tag deref trap (rust-cache) | Med (hard CI checkout failure) | Low (well-documented) | Pin the dereferenced commit `e18b4977…` (`v2^{}`), not the tag-object `42dc69e1…`; catch any bad pin via the green-CI-on-push gate before G3/G4. |
| R-G3a — macOS `canonicalize`-divergence false positive | Med (`make test` red on dev Mac, green on CI) | Low (designed out) | Implement **D-G3a** (final-component `symlink_metadata` only), *not* verbatim G3-1. |
| R-G3b — one call site tested, the other silently unverified | Med (SM-3 names key *and* account) | Med | Wire + test **all three** `load_config` sites; recover-mode `load_config` tests on both key and account. |
| R-G4a — real-entropy "flake" | Low | ~Nil | Collision of a 32-byte salt / 16-byte IV / 128-bit id across 3 draws is birthday-bound negligible (≈ 2⁻¹²⁵). No mitigation needed — the genuine G4 discipline is the EOA `id`-not-`uuid` field path + the throwaway bite-proof, not collision. |

**Most likely to bite: R-G1a.** It is the only risk that is *both* near-certain (the source docs literally
contradict each other on the drafted code, and the stash predates the finalized architecture) *and*
capable of a silent security regression — an abort or partial-display-write path that never scrubs, or a
fail-open test that asserts nothing. Every other risk is either trivially mitigated (G2 re-resolve),
designed out (G3a), or negligible (G4a). G1's security review is where the effort's real attention belongs.

---

## Definition of Done — M-AG (audit gaps closed)

The effort is done when **all four gaps are merged green on `develop`** and the audit is updated to reflect
it. Two of the closing artifacts live in the **Obsidian vault**, not in `eth-utils`:

**In `eth-utils` (four green fast-forward commits, each `make lint && make test` green):**
- [x] G1 merged → **SM-1**: ETHSTAKER-7 ✅ Mitigated (success path; fail-open + multiplexer caveat documented).
- [ ] G2 merged + green CI under pinned actions → **SM-2**: ETHSTAKER-1 ✅ Mitigated (SHA-pinned).
- [ ] G3 merged → **SM-3**: ToB Mar 2026 symlink rec. ✅ Mitigated (warn on symlinked output dir).
- [ ] G4 merged, test-only diff → **SM-4**: GHSA-c6rv-g6pj-r6qx / ETHSTAKER-6 ✅ Mitigated + regression-guarded.

**Close-out doc updates (vault — prose edits, not `make test`-gated):**
- [ ] Update the audit's issue-by-issue table in
  `1.Projects/ethernal/202607181903 - Audit - ethernal Implementation vs Known deposit-cli and EOA Keystore Issues.md`:
  flip the four rows above; leave **DEP-007 / ETHSTAKER-2 ⏳ Open, dispositioned D1** (release-pipeline
  trigger) — unchanged, but note its prerequisite (G2, pinned actions) is now satisfied.
- [ ] Update the project `1.Projects/ethernal/0.README.md` open-gaps list to match.

**Success is auditable:** each SM row is backed by shipped test/CI evidence (per Verification), not just a
merged diff. Gap 5 remains intentionally open — measured by absence — and is out of scope here.

---

## Open items for the implementer (not blockers)

- **G1:** done — result-capture clear, FailAfterDisplay fail-open test, USER-GUIDE intro + both flows;
  review suggestions (const byte lock + S-1 warn assert) applied; acceptance checkboxes met; green under
  `make lint && make test`.
- **G2:** re-resolve `dtolnay/rust-toolchain@stable` fresh (fast-moving); checkout/rust-cache are stable but
  spot-check. Comment style is intentionally non-uniform (semver / branch+date / tag-tip note) — do not
  force `# vX.Y.Z` onto dtolnay.
- **G3:** the exact `WARNING:` wording is illustrative — keep the `WARNING:` prefix (repo tone,
  `sign_cmd.rs:48`) and both paths on one line; tests assert *count == 1* and *both paths present*, not the
  literal phrasing.
- **G4:** read raw JSON only (no `Loader::load` — distinctness is a byte compare); the frozen `COUNT = 2`
  golden constant is untouched (the new tests pass `3` literally).
