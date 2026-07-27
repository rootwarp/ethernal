# env-var-name flags → file-path flags — issues index

Sprint-ready issues. Detail folded in from [`../project-plan.md`](../project-plan.md) (phases
F1..F8, **binding** §4 ownership table and §5 sequencing rules),
[`../architecture.md`](../architecture.md) (binding — module APIs, invariants I-1/I-2, decisions
D-1..D-10), [`../prd.md`](../prd.md) (FR-1..FR-38, consumers S-A..S-D) and
[`../research/r4-verification-log.md`](../research/r4-verification-log.md) (measurements M-a..M-e;
**§4 lists what is unverified — no acceptance criterion here depends on it**).

One file per phase: [`f1.md`](f1.md) · [`f2.md`](f2.md) · [`f3.md`](f3.md) · [`f4.md`](f4.md) ·
[`f5.md`](f5.md) · [`f6.md`](f6.md) · [`f7.md`](f7.md) · [`f8.md`](f8.md).

**20 issues · 26 pts.** Every issue is ≤ 3 pts and independently `--ff` mergeable to `develop`
with `make lint && make test` green (plan §5 rule 11). **Every phase total reconciles exactly
with project-plan §2 — no drift.** Phases touching `e2e_live.rs` (**F5, F6**) additionally
require `make e2e-live` locally: that file is `#[ignore]`d, so `make test` will **not** catch a
break there (R-8).

**Nature of the work:** one new leaf crate, two library boundaries, three independent CLI flips,
and 63 real test call sites that are *not* a string swap. The risk is in exactly two places —
*which bytes of a file are the secret* (F1) and *where the file is read* (F4/F5/F6, invariant
I-1). Everything else is volume.

---

## All issues

| Tag | Title | Pts | Depends on | Discharges |
|---|---|---|---|---|
| **[F1-1]** | New crate, file policy, and the fixed-buffer read loop | 2 | — | FR-13, FR-14, FR-15, FR-16, FR-17, FR-23 |
| **[F1-2]** | The UTF-8 boundary and the two byte rules | 2 | F1-1 | FR-7, FR-8, FR-9, FR-10, FR-12b |
| **[F2-1]** | `FileSource`, the two `KeystoreError` variants, and `secret_file_arg` | 2 | F1-2 | FR-6, FR-18, FR-19b, FR-23b, FR-26, FR-27 |
| **[F2-2]** | `new_local_signer_from_file` + `SignerError::KeyFile` + FR-28 doc rewrite | 1 | F1-2 | FR-7, FR-26, FR-28 |
| **[F2-3]** | Exit-code mapping in `bins/ethernal/src/errors.rs` | 1 | F2-1, F2-2 | FR-13, FR-27, D-7 |
| **[F3-1]** | `common::secret_file` fixture helper | 1 | — | R-7 mitigation; **blocks every test migration** |
| **[F3-2]** | Make the six WARNING counters warning-kind-specific | 1 | — | FR-21, R-3 |
| **[F4-1]** | FR-29 — repoint every message and assertion naming `--passphrase-env` | 1 | — | FR-29 |
| **[F4-2]** | Flip `validator` + `account` to the file flags | 2 | F2-1, F3-1, F3-2, F4-1 | FR-1…FR-6, FR-18, FR-19b, I-1, I-2 |
| **[F4-3]** | FR-12 — the S-C and S-D byte-rule matrix | 1 | F4-2 | FR-9, FR-10, FR-12 (S-C, S-D) |
| **[F5-1]** | Flip `deposit gen` and hoist the read above the worker pool | 2 | F2-1, F3-1 | FR-2, FR-4, FR-5, FR-6, FR-22 (gen), D-5 |
| **[F5-2]** | Read-once evidence: FIFO, fail-fast, and the S-B regression row | 1 | F5-1 | FR-22 (evidence), FR-12 (S-B) |
| **[F6-1]** | One `LocalSigner`: flip `tx sign` / `tx run` and pass the signer forward | 2 | F2-2, F2-3, F3-1 | FR-1, FR-2, FR-6, FR-22, FR-24, FR-25, FR-30, D-4 |
| **[F6-2]** | FR-33 / R-5 — read-once evidence in **RPC mode**, and the exit-2 divergence | 1 | F6-1 | FR-22, FR-33, arch §11 div. 4 |
| **[F6-3]** | FR-19 hex-shaped-argument guard + FR-35 harness allowlist | 1 | F6-1 | FR-19, FR-32, FR-35, D-8 |
| **[F7-1]** | The eight error paths in the two hygiene suites | 1 | F4-2, F4-3 | FR-31 |
| **[F7-2]** | `redact_boundary.rs` — `Debug` and log-stream leak assertions | 1 | F4-2, F6-1 | FR-31 (`Debug`/log half), M-3 |
| **[F7-3]** | `exit_usage.rs` cases + repointed help-text assertions | 1 | F4-2, F5-1, F6-1 | FR-1, FR-2, FR-34 |
| **[F8-1]** | `USER-GUIDE.md` + `README.md` — sweep and the three new pieces of prose | 1 | F4-2, F5-1, F6-1 | FR-11, FR-20, FR-36, FR-38 |
| **[F8-2]** | `CHANGELOG.md` + the acceptance `rg` sweep | 1 | F8-1 | FR-37, PRD §8 acceptance |

**Phase totals:** F1 = 4 · F2 = 4 · F3 = 2 · F4 = 4 · F5 = 3 · F6 = 4 · F7 = 3 · F8 = 2 —
**26**, matching project-plan §2 phase for phase.

---

## Dependency graph

```
F1-1 ──→ F1-2 ──┬──→ F2-1 ──┬──────────────→ F2-3 ──┐
                │           │                 ↑     │
                └──→ F2-2 ──┴─────────────────┘     │
                                                    │
F3-1 ─────────────────────┬─────────────┬───────────┤
F3-2 ─────────────────────┤             │           │
F4-1 ─────────────────────┤             │           │
                          ↓             ↓           ↓
              (A)      F4-2 ──→ F4-3   (B) F5-1    (C) F6-1 ──┬──→ F6-2
                          │        │        │  └──→ F5-2      └──→ F6-3
                          │        │        │
                          ├────────┴────────┴──────────────────────┐
                          ↓                                        ↓
                    F7-1 · F7-2 · F7-3                     F8-1 ──→ F8-2

                    ── release gate: H9 + A5-M (manual, below) ──
```

Edges into F7 and F8 are the **minimal technical** ones listed per issue. The **phase rule wins
where it is stricter**: project-plan §4 requires F7 and F8 to start only after F4, F5 **and** F6
have all merged, and §5 rule 7 requires F8-2's sweep to run after all three — earlier it passes
vacuously (R-6).

## Streams

`F1 → F2` is a hard serial spine carrying 8 of the 26 points, with exactly **one** parallel task
available (F3, 2 pts) plus F4-1 (1 pt, no code dependency). **Do not staff three developers on
day one** — a second developer is idle for most of F1–F2 and a third for all of it. The
parallelism is real only once F2 lands.

Source files are disjoint across the three streams (verified: `shared_args()` has exactly two
callers, both in stream A; `gen_cli.rs:122` defines its own flag). **Test files are not**, so
they are assigned:

| Stream | Issues | Owns |
|---|---|---|
| **A** — `validator` + `account` | F4-1, F4-2, F4-3 | `keystore_cli.rs`, the ceremony paths, `validator_e2e.rs`, `account_e2e.rs`, both `*_secret_hygiene.rs`, `exit_usage.rs`, and `gen.rs:623` (the shared `NoTty` assertion — line-disjoint from B) |
| **B** — `deposit gen` | F5-1, F5-2 | `gen_cli.rs`, `gen_cmd.rs`, the worker pool, `gen.rs` (17), `e2e_live.rs:97`, `.claude/skills/verify/SKILL.md` |
| **C** — `tx sign` / `tx run` | F6-1, F6-2, F6-3 | `sign_cmd.rs`, `run_cmd.rs`, the signer restructure, `sign.rs`, `run.rs`, `run_rpc.rs`, `e2e_pipeline.rs`, `e2e_live.rs:146`, the `common/mod.rs` allowlist |

**Stream A and B need only F2-1 + F3-1 from the seams phase; stream C needs F2-2 + F2-3 + F3-1.**
That is why `secret_file_arg` lives in F2-1 and not in a flip phase (plan §5 rule 3) — putting it
in F4 would make B and C wait on A.

## Critical path

- **Binding, phase level (project-plan §4):** `F1 → F2 → F6 → F7 → F8` = **17 of 26 points**.
- **Issue level, longest chain:** `F1-1 → F1-2 → F2-1 → F2-3 → F6-1 → F6-3 → F8-1 → F8-2` =
  **12 points**.

They differ because **F2, F6 and F7 parallelize internally** (F2-1 ∥ F2-2; F6-2 ∥ F6-3; all three
F7 issues are independent). The 12 is not a correction to the 17 — the phase number is the
planning number, and the chain is what a single developer cannot compress.

## Standing rules for every issue in this plan

1. **No existing assertion is loosened** (plan §5 rule 6). WARNING counters become
   warning-**kind**-specific (`== 1` on a discriminating token), never "at least one". If an
   existing test appears to need modification, that is a design error in the new behavior —
   escalate rather than edit.
2. **Every test secret file goes through `common::secret_file`** (F3-1, plan §5 rule 2). A raw
   `fs::write` of a passphrase in any diff is a plan violation: a 0644 fixture emits an FR-17
   warning and breaks its own caller's WARNING count.
3. **I-1 — each secret file is read exactly where its `std::env::var` counterpart fires today**,
   and is an exit criterion of F4, F5 **and** F6 (plan §5 rule 4). **No validation at config
   load.** A fail-fast hoist puts the FR-17 warning before `clear_after_ceremony`, which erases
   it — silently disabling a P0 with **no test failing**.
4. **Zero new third-party dependencies** (M-4), re-checked per phase. `mkfifo` is shelled out to,
   not linked.
5. **No `#[deprecated]` anywhere** (D-10), and **no `ETHERNAL_TX_PRIVATE_KEY_FILE` fallback** —
   OD-5 declined it explicitly; do not re-derive it from OD-1's "fallbacks stay".
6. **No error path may print file contents** (M-3). Every hygiene assertion uses a **distinctive
   sentinel**, so `!output.contains(sentinel)` is a real assertion rather than one an empty
   output satisfies.
7. **F1 touches no file under `bins/` and no other crate** (plan §5 rule 1). If an issue seems to
   need one, stop and escalate.
8. **Nothing in architecture §14 changes** (plan §5 rule 8): `ethernal-core`, `ethernal-tx`,
   `EnvSource`, `new_local_signer_from_env`, keystore bytes, filenames, output mode, `create_new`
   semantics, scrypt parameters, the ceremony and its scrollback clear, the C1–C4 verification
   work and `--no-verify`, `Progress`/`PhaseReporter`, and the `ETHERNAL_TX_*` value fallbacks.

## Ship points

| After | State |
|---|---|
| F1-2 | **M1** — the byte rule exists and is proven with no CLI in play. A wrong derived key is now a test failure, not a discovery. |
| F2-3, F3-2 | **M2** — the library can read a secret file and the suite is ready to receive one. **Nothing observable has changed.** The last fully reversible point. |
| F4-3, F5-2, F6-3 | **M3** — every command reads its secret from a file, exactly once. The breaking change is complete. |
| F7-3 | **M4** — the negative paths are asserted per error path. |
| F8-2 | **M5** — merge-complete on `develop`. |

**There is no intermediate ship point.** M2 ships nothing an operator can see, and M3 is atomic
from an operator's view: `develop` carrying `--passphrase-file` for `validator` but
`--passphrase-env` for `deposit gen` is worse than either end state. Each of F4/F5/F6 is still
independently mergeable and independently green — but **no release is cut from a partial M3**
(R-9).

## Release gate — H9 and A5-M

**These are sessions, not issues. They gate release, not merge** (project-plan §6): they sit
after F8 and before any `--no-ff` `vX.Y.Z` merge to `main`. Neither is a task inside a phase.

| Gate | What it is | New rows this change adds |
|---|---|---|
| **H9** | validator keygen manual parity | `pw\r` → **exit 2** · `pw\r\n` → **exit 2** · a non-UTF-8 passphrase file → **exit 2** |
| **A5-M** | EOA v3 keystore manual parity | the same three rows, **plus** the geth round-trip on the plain cases: `geth account import --password <file>` against an ethernal-written v3 keystore produced from that same file, and `ethernal account recover --passphrase-file <file>` against a keystore geth wrote — each for a file **with** and **without** a trailing `\n` |

Two traps, stated because the gate will otherwise be misread:

- **The non-UTF-8 row is an ethernal-side exit-2 assertion only — it is NOT a geth round-trip
  row.** Go strings are byte strings, so geth's `--password` accepts those bytes; D-3
  deliberately refuses them. "geth accepted, ethernal refused" is the decision working, not a
  bug. **The geth round-trip rows must use UTF-8 files** or they test the wrong thing
  (architecture §3).
- **A5-M needs a real `geth` binary and cannot run in CI.** Schedule it as a session.

FR-12 (F4-3, F5-2) is the **automated equivalent** of the plain rows, not a replacement for the
gate — it cannot compare against another implementation.

## Out of scope (dispositions written, not scheduled)

`gen_cmd.rs:406`'s missing `.env_clear()` — closes on its own once no secret is in the
environment, and `.env_clear()` would break `look_path`'s bare-name PATH resolution · the
three-way non-UTF-8 divergence between S-B/S-C/S-D (FR-12b) · the `RecoverMnemonicSource`
`read_to_string` residue (`keygen.rs:350-353`) · the ceremony's erasure of pre-ceremony warnings
(I-2) · `deposit gen`'s per-pubkey TTY prompt · removal of `EnvSource` /
`new_local_signer_from_env`, a separate semver-major decision (OD-6, D-10) · the
`ETHERNAL_TX_RPC_URL` / `_FROM` / `_GAS_LIMIT` value fallbacks (OD-1, A-1).
