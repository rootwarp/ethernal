# Keygen progress + BLS verification — issues index

Sprint-ready issues. Detail folded in from [`../project-plan.md`](../project-plan.md) (phases
V1..V5, binding §5 sequencing rules), [`../architecture.md`](../architecture.md) (binding —
module APIs, invariants I-1..I-5, decisions D-1..D-8), and [`../prd.md`](../prd.md)
(PR-1..PR-20, checks C1..C4).

One file per phase: [`v1.md`](v1.md) · [`v2.md`](v2.md) · [`v3.md`](v3.md) · [`v4.md`](v4.md) ·
[`v5.md`](v5.md) · deferred: [`deferred.md`](deferred.md).

**10 issues · 12 pts.** 1 pt ≈ half a working day; every issue is ≤ 2 pts and independently
mergeable to `develop` via a fast-forward commit with `make lint && make test` green.
**Nature of the work: additive changes inside `bins/ethernal/` only — no crate under
`crates/` is modified by any issue** (project-plan §5 rule 6).

---

## All issues

| Tag | Title | Pts | Depends on | Discharges |
|---|---|---|---|---|
| **[V1-1]** | Move `Progress` into `bins/ethernal/src/progress.rs` | 1 | — | D-3, unblocks V2-1 |
| **[V2-1]** | `PhaseReporter` transient single-line renderer | 1 | V1-1 | PR-1, PR-3, PR-5, PR-6, PR-7, PR-9 |
| **[V2-2]** | Wire phase reporting into `finish_from_mnemonic` | 1 | V2-1 | PR-1, PR-2, PR-4, PR-8 |
| **[V3-1]** | `AppError::KeyVerifyFailed` + exit-3 arm | 1 | — | PR-14, PR-16 |
| **[V3-2]** | C1–C3 helpers + `checking` phase + negative tests | 2 | V3-1, V2-2 | PR-11, PR-19 |
| **[V4-1]** | `InMemoryPassphrase` + `loader` dep on `ValidatorDeps` | 1 | V3-1 | PR-17 |
| **[V4-2]** | `verify_written_keystore` (C4) + `verifying` phase | 2 | V4-1 | PR-13, PR-15, PR-19 |
| **[V4-3]** | `--no-verify` flag, warning, `verified=` log field | 1 | V4-2 | PR-12, PR-18 |
| **[V5-1]** | USER-GUIDE + CHANGELOG | 1 | V4-3 | PR-12 docs |
| **[V5-2]** | e2e assertions on the `validator recover` path | 1 | V4-3 | PR-8, PR-19 (integration) |

**Deferred** ([`deferred.md`](deferred.md)): X1 account parity · X2 ETA/elapsed ·
X3 spinner thread · X4 `--json-logs` for validator · X5 parallel keygen · X6 quarantine on
failure.

---

## Streams and ordering

**Critical path:** `V1-1 → V2-1 → V2-2 → V3-2 → V4-1 → V4-2 → V4-3 → V5-*` (10 pts).
`V3-1` is the only issue with no dependency other than the repo itself and can be picked up at
any point.

**Two developers (~3.5 days):**

- **Stream A:** V1-1 → V2-1 → V2-2 → V5-1 — owns `progress.rs` and every rendering question.
- **Stream B:** V3-1 → (wait for V2-2) → V3-2 → V4-1 → V4-2 → V4-3 → V5-2 — owns verification,
  the error variant, and the CLI flag.

Both streams edit `finish_from_mnemonic`. After V1-1 lands they touch disjoint regions of that
loop body: **A owns the `reporter.*` calls, B owns the `verify_*` calls.** Conflicts are
line-adjacent, not semantic.

**One developer (~6 days):** strict tag order V1-1 → V5-2.

---

## Standing rules for every issue in this plan

1. **No existing assertion may be modified.** If a test appears to need it, that is a design
   error in the new output — stop and escalate in the run summary (the e2e-tests plan's C-2
   discipline).
2. **No file under `crates/` is touched.** Every primitive C1–C4 needs is already public.
3. **Progress writes are always `let _ = …`** — rendering never changes exit status (PR-7).
4. **No new third-party dependency** (D-1).
5. **Every check ships with its own failing-path test** in the same issue (PR-19). A check with
   no negative test is indistinguishable from dead code.
6. **Nothing in progress or error text may contain secret material** (PR-6, PR-16), and no
   progress label may contain the token `WARNING` (PR-9).

## Ship points

| After | State |
|---|---|
| V1-1 | `Progress` correctly owned; nothing observable changed (**M1**) |
| V2-2 | The operator can see the tool working — shippable alone (**M2**) |
| V4-3 | No unverified keystore can be produced; the `0.README.md` "deliberate deviation" is closed (**M3**) |
| V5-2 | Documented and covered end-to-end (**M4**) |
