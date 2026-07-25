# Project plan — keygen progress + BLS verification

**Binding for the estimator.** Phase order, exit criteria, and the sequencing rules in §5 must
be respected by the issue breakdown.

Inputs: [`prd.md`](prd.md) · [`research/index.md`](research/index.md) ·
[`architecture.md`](architecture.md).

---

## 1. Shape of the work

Five phases, **V1…V5**, on `develop`. Every phase is a small number of independently
mergeable commits; the whole plan is **10 issues / 12 points ≈ 6 working days** for one
developer, or **~3.5 days** with two streams.

This is an additive change to a mature, heavily-tested binary. The dominant risk is not
"will it work" but **"does it disturb the existing 130-test suite"** — hence V1 (a pure
no-behavior refactor) lands first and alone, and every later phase carries a "no existing
assertion modified" exit criterion.

```
V1  progress.rs extraction            ──┐
                                        ├─→ V2  phase reporting        ──┐
V3  cheap checks C1–C3  ────────────────┘                                ├─→ V5  docs + e2e
                                                                         │
V4  round-trip C4 + --no-verify  ───────────────────────────────────────┘
```

## 2. Phases

### V1 — `progress.rs` extraction (1 pt) · *no behavior change*

Move `Progress` out of `gen_cmd.rs:39` into a new `bins/ethernal/src/progress.rs`; leave a
re-export so `gen_cmd::Progress` still resolves; update the `validator_cmd` / `account_cmd`
import lines. Nothing else.

**Why first and alone.** Architecture D-3. It touches three modules that the feature also
touches; folding it in would make the feature diff unreadable and unbisectable. It is also the
only part of the plan that touches `account_cmd`, so isolating it keeps the "account is out of
scope" boundary verifiable by diff.

**Exit criteria**
- `make lint && make test` green; diff is imports + one moved type + one `pub use`.
- `git diff --stat` shows **zero** lines changed inside any function body.

### V2 — Phase reporting in the validator loop (2 pts)

`PhaseReporter` in `progress.rs`, wired into `finish_from_mnemonic`. Phases `deriving`,
`encrypting`, `writing` land here; `checking` and `verifying` are added by V3/V4 as those
checks appear.

**Depends on:** V1.

**Exit criteria**
- Interactive `--count 3`: a live phase line, erased before each durable
  `keystore i/N:` line; scrollback afterwards is shape-identical to today's.
- Piped `--count 3`: no `\r`, no `\x1b`, one event per key.
- Unit test asserting the transient text is present in a `Progress::Tty` buffer and absent in
  a `Progress::NonTty` buffer.
- The two `*_secret_hygiene_*` tests pass **unmodified** (they scan the same buffer that now
  carries phase text).

### V3 — C1–C3, mandatory derivation self-checks (3 pts)

`verify_derived_key` + `AppError::KeyVerifyFailed` + the exit-3 arm + the `checking` phase.

**Depends on:** V2 for the phase label only; the checks themselves are independent and can be
implemented in parallel with V2 by a second developer (see §4).

**Exit criteria**
- C1/C2/C3 run for every index on both `new` and `recover`.
- Three negative unit tests, one per check, each asserting **exit 3** and zero keystores
  written for that index.
- Failure messages contain the check tag, index, HD path — and no secret material (asserted).

### V4 — C4 round trip + `--no-verify` (4 pts)

`InMemoryPassphrase`, `verify_written_keystore`, the `loader` dep on `ValidatorDeps`, the
`verifying` phase, the CLI flag, the one-shot `WARNING`, and the `verified=` log k/v.

**Depends on:** V3 (shares the error variant and the check-tag convention).

**Exit criteria**
- Default run decrypts every written keystore and compares **both** secret and `pubkey` field.
- Injected failing loader → exit 3, run stops at that index, earlier keystores remain, the
  failing file **still exists** (asserted).
- `--no-verify` skips only C4, emits exactly one `WARNING`, and C1–C3 still run (asserted).
- No re-prompt and no second env read during the loop (asserted via a passphrase source that
  panics on a second `read()`… or counts calls).

### V5 — Docs + e2e coverage (2 pts)

`docs/USER-GUIDE.md` (flag, semantics, cost, what `--no-verify` does *not* skip), `CHANGELOG.md`,
and one e2e assertion on the `validator recover` path that a real run's stderr shows the
verification outcome.

**Depends on:** V4.

**Exit criteria**
- USER-GUIDE §"Create BLS validator keys" documents C1–C4 and the wall-clock cost.
- `tests/validator_e2e.rs` still asserts exactly one `WARNING` on the symlink case.
- `make lint && make test` green.

## 3. Milestones

| Milestone | Phases | Meaning |
|---|---|---|
| **M1 — clean seam** | V1 | `Progress` correctly owned; nothing observable changed |
| **M2 — visible** | V1, V2 | The operator can see the tool working. Shippable on its own. |
| **M3 — correct** | V3, V4 | No unverified keystore can be produced. The gap in `0.README.md` "Deliberate deviations" is closed. |
| **M4 — documented** | V5 | Operators know the cost and the escape hatch. |

M2 is a genuine ship point: if V3/V4 slip, phase reporting alone is a coherent release.

## 4. Streams

Two developers, ~3.5 days:

- **Stream A (critical path):** V1 → V2 → V5-1. Owns `progress.rs` and every rendering
  question.
- **Stream B:** V3 → V4 → V5-2. Owns verification, the error variant, and the CLI flag.

The merge point is `finish_from_mnemonic` — both streams edit that one loop. Sequencing rule:
**Stream A lands V1 first** (Stream B's phase labels depend on the module existing), then the
streams touch disjoint regions of the loop body: A owns the `reporter.*` calls, B owns the
`verify_*` calls. Conflicts are line-adjacent, not semantic.

One developer: V1 → V2 → V3 → V4 → V5, ~6 days.

## 5. Sequencing rules the estimator MUST respect

1. **V1 is a standalone commit with no behavior change.** Never fold it into V2.
2. **No issue may modify an existing assertion.** If an existing test appears to need
   modification, that is a design error in the new output — stop and escalate in the run
   summary rather than editing the assertion (the e2e-tests plan's C-2 discipline).
3. **C1–C3 ship before C4.** The cheap mandatory checks must not be blocked behind the
   expensive optional one.
4. **Each check gets a negative test in the same issue that introduces it.** A check without a
   failing-path test is dead code (PR-19).
5. **`account_cmd.rs` is touched exactly once, in V1, imports only.** Any other account change
   is out of scope — file it in [`issues/deferred.md`](issues/deferred.md).
6. **No crate under `crates/` is modified by any issue in this plan.** If an issue seems to
   need it, stop and escalate.
7. Every issue is ≤ 3 pts and fast-forward mergeable to `develop` with `make lint && make test`
   green.

## 6. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| e2e suite slows ~2× on keystore-writing paths (production `STANDARD` scrypt, now twice per key) | **High** — it is arithmetic, not chance | Medium: CI minutes | Measure in V4 and record the delta in the issue. If a specific fixture becomes intolerable, pass `--no-verify` **in that fixture only** and say so in the test comment. Do not weaken the default. |
| Transient phase text breaks an assertion on a captured buffer | Low — all existing assertions are `contains`-based (R1 §4) | Medium | V2 exit criterion asserts the hygiene tests pass unmodified |
| Terminal interleaving between `/dev/tty` (ceremony) and stderr (progress) | Low — ordering already separates them | High if wrong: a mnemonic-era line surviving the scrollback clear | Invariant I-4 in architecture; V2 adds a comment at the call site |
| `--no-verify` becomes the default in operators' muscle memory because verification is slow | Medium | High: reintroduces the gap | USER-GUIDE states the cost *and* what is lost; the run prints a `WARNING` every time |
| Scope creep into `account` parity | Medium | Medium | Rule 5 + a written disposition in `deferred.md` |

## 7. Out of scope (dispositions written, not scheduled)

`account` parity (PR-20) · ETA/elapsed display (PR-10) · `--json-logs` for `validator` ·
parallel keygen · spinner thread. See [`issues/deferred.md`](issues/deferred.md).

---

**Downstream:** [`issues/index.md`](issues/index.md)
