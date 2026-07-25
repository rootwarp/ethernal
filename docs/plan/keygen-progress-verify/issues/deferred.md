# Deferred — written dispositions

Items considered and consciously **not** scheduled. Each records why, and what it would take,
so a future stage starts from a decision rather than a rediscovery.

> **Tags are `X…`, not `D…`.** `D-1…D-8` are the *architecture decisions*
> ([`../architecture.md`](../architecture.md) §8) and several of them are cited below. Keeping
> the two namespaces distinct means a bare "D2" in a commit message or issue comment can never
> mean two different things (the prior plan's vault note already says "disposition D1", which
> is the ambiguity this avoids).

---

## X1 — `account` namespace parity (progress + verification)

**PRD:** PR-20 · **Architecture:** D-8 · **Status:** deferred, not rejected

`account new` / `account recover` run the structurally identical loop
(`account_cmd.rs:333`) over secp256k1 keys and Web3 Secret Storage **v3** keystores, with the
same after-the-fact `emit_account_progress` (`account_cmd.rs:407`).

- **Progress** would be a near-mechanical copy of V2-2 once `PhaseReporter` exists (V1 puts the
  type where both namespaces can reach it). Cheap.
- **Verification is not mechanical.** The v3 decrypt path is
  `#[cfg(feature = "test-support")]`-gated: `pub use decrypt_v3::decrypt_v3;` sits behind that
  feature in `crates/ethernal-keystore/src/lib.rs`, and the binary enables it only under
  `[dev-dependencies]` (`bins/ethernal/Cargo.toml`). A C4 equivalent for accounts requires
  **promoting `decrypt_v3` to a production API** — a permanent widening of an audited crate's
  surface, and a decision that deserves its own review rather than arriving as a side effect of
  a validator feature.

The v3 analogue of C1–C3 (secp256k1 pubkey↔secret consistency, address re-derivation,
sign/recover round trip) has no such blocker and would be the natural first slice if this is
picked up.

**Blast-radius note:** this plan touches `account_cmd.rs` exactly once, in V1-1, on the import
line only (project-plan §5 rule 5) — so "is account affected?" stays answerable by diff.

---

## X2 — Elapsed / ETA in the progress line

**PRD:** PR-10 (P2) · **Status:** deferred

`[2/50] encrypting... (00:31 elapsed, ~4m50s left)` is a real improvement at `--count 100+`,
and after V4 the per-key cost is stable enough (~620 ms, two scrypts) that a running mean
predicts well.

Blockers, both about determinism:

- `ValidatorDeps` injects `now_unix: i64` (`validator_cmd.rs:58`) — a wall-clock stamp for
  filenames, not a monotonic clock. Elapsed time needs `Instant`, i.e. a **new injected seam**
  or a direct `Instant::now()` call inside the loop.
- A direct call makes progress output non-deterministic, which collides with the
  `contains`-based assertions this plan is careful to preserve. Any implementation must render
  timing **only** when `Progress::Tty` *and* the elapsed field is behind an injected clock that
  tests can freeze.

Not worth the seam for this stage. Revisit if operators report running `--count` in the
hundreds.

---

## X3 — Animated spinner during a single scrypt call

**Architecture:** D-2 · **Status:** rejected for this stage, design recorded

`scrypt` 0.11 exposes one blocking call and `p = 1`, so nothing can render from the working
thread ([`../research/r2-scrypt-cost-and-hooks.md`](../research/r2-scrypt-cost-and-hooks.md)
§3). A spinner needs a second thread, and the obvious implementation forces
`ValidatorDeps.summary_out: &'a mut dyn Write` to become `Send`-shareable — rippling through
~10 test call sites and the parallel `account_cmd` seam, to animate a **310 ms** block.

If revisited, the cheap version avoids the seam entirely: spawn the ticker only when
`Progress::Tty` **and** `stderr_is_tty()`, and have it write directly to `std::io::stderr()`
rather than through the injected writer — so every test path (which injects a `Vec<u8>` and is
therefore never a real TTY) stays untouched. It must also coordinate with `CancelToken` so
SIGINT does not leave a ticker mid-line.

---

## X4 — `--json-logs` for `validator`

**Status:** deferred

The flag exists only on `gen` (`gen_cli.rs:146`); `gen`'s `emit_progress` takes `json_logs` and
short-circuits to structured events (`gen_cmd.rs:363`). The validator logger is hard-wired to
`Format::Text` (`validator_cmd.rs:73`, `:133`).

Adding it is small but it is a **CLI surface change to two more subcommands** with no
requirement behind it. `Progress::NonTty` already produces structured events for pipes and CI,
which is what the JSON flag is usually reached for. If added later, the rule from this plan
carries over: JSON mode must never emit `\r`.

---

## X5 — Parallel key generation

**Status:** out of scope, flagged as the obvious next lever

After V4 the loop is ~620 ms of pure CPU per key with no I/O contention — embarrassingly
parallel, and the single biggest wall-clock win available for large batches
(`--count 100` → minutes on one core).

Deferred because it is not a progress or verification change: it interacts with
`CancelToken` semantics (partial-run guarantees — `cancel_mid_run_leaves_k_complete_keystores`,
`validator_cmd.rs:1030`), per-keystore entropy draws, filename-collision retry
(`write_keystore_at`), and the ordering guarantees of the summary. It deserves its own PRD.
`gen` already has a `--parallel` path with a determinism test (E5-3 on `main`) — that is the
precedent to study first.

---

## X6 — Quarantining a failed keystore

**Architecture:** D-5 · **Status:** rejected

Considered for a C4 failure: unlink the file, or rename it to `*.invalid`. Both rejected —
the write path is `create_new`-exclusive and never overwrites, and deleting or renaming key
material on the strength of the tool's own possibly-buggy check (or a transient read error) is
the only irreversible act in a pipeline deliberately designed to have none. The chosen
behavior — leave the file, name it in the error, state it was not removed, stop the run —
leaves the operator in a defined state and preserves the evidence needed to diagnose.
