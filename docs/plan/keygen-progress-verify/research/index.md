# Research index — keygen progress + BLS verification

Three questions, all answerable from the tree, the vendored crate sources, and one
measurement. No web survey was needed or performed.

| # | Question | Verdict | File |
|---|---|---|---|
| **R1** | What renders the progress indicator? | Extend the in-tree `Progress` fork (`gen_cmd.rs:362` is the house style); **no `indicatif`**; **no spinner thread** — the seam change is not worth a 310 ms block | [`r1-progress-rendering.md`](r1-progress-rendering.md) |
| **R2** | Where does the time go, and can scrypt be instrumented? | ~99% of the loop is scrypt at **≈310 ms measured**; `scrypt` 0.11 exposes one blocking call, `p=1` so it cannot be chunked → **phase-boundary granularity is the ceiling** without a thread | [`r2-scrypt-cost-and-hooks.md`](r2-scrypt-cost-and-hooks.md) |
| **R3** | What should "verify a BLS key" check, and what happens on failure? | Four checks **C1–C4**; all primitives already public in-tree; C4 = second scrypt = the whole cost; on failure **leave the file, stop the run, exit 3** | [`r3-verification-semantics.md`](r3-verification-semantics.md) |

## Findings that shaped the PRD

1. **310 ms, not 2 s.** The measurement (R2 §1) is what makes phase-boundary reporting
   sufficient: worst-case silence is one scrypt, ~1.2 s even on hardware 4× slower than this
   host. Had it been seconds, the spinner-thread seam change would have been justified.
2. **The two features are one feature.** C4 is a second scrypt, so verification doubles the
   run and the indicator must model a `verifying` phase or it lies.
3. **Nothing validates the keystore's `pubkey` field against its ciphertext** — not the
   loader (`keystore.rs:29`, explicit), not `scan_dir`, not `deposit gen`. C4 comparing both
   the secret *and* the pubkey field is the check that makes that mismatch unrepresentable at
   creation time. This was the least obvious finding and is the strongest single argument for
   the feature.
4. **`Progress` lives in the wrong module** — `gen_cmd.rs:39`, imported by `validator_cmd` and
   `account_cmd`. The extraction is a prerequisite refactor, not scope creep; it matches the
   in-flight commit series (`27792a4`, `2c9807b`).
5. **Every existing assertion on the progress buffer is `contains`-based**, so transient
   phase lines do not break the suite — provided they carry no secrets and no `WARNING` token
   (R1 §4).

**Downstream:** [`../architecture.md`](../architecture.md)
