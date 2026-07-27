# Project plan — env-var-name flags → file-path flags

**Binding for the estimator.** Phase order, exit criteria, the ownership table in §4 and the
sequencing rules in §5 must be respected by the issue breakdown.

Inputs: [`prd.md`](prd.md) · [`architecture.md`](architecture.md) ·
[`research/index.md`](research/index.md) ·
[`research/r4-verification-log.md`](research/r4-verification-log.md).

Where this plan and the PRD disagree, the architecture wins and the divergence is already
recorded in architecture §11.

---

## 1. Shape of the work

Eight phases, **F1…F8**, on `develop`. **≈26 points**; the estimator should expect **16–20
issues** at ≤3 pts each. One developer ≈ **13 working days**; three developers ≈ **8**, and the
saving is smaller than it looks — see §4.

This is not the keygen plan's shape. That change was additive to a mature binary and the risk
was disturbance. This one **removes three flags and replaces the source of every secret the
tool handles**, so the risk is in two specific places: *which bytes of a file are the secret*
(F1) and *where the file is read* (F4/F5/F6, invariant I-1). Everything else is volume.

```
F1  ethernal-secretfile          ──→ F2  shared seams  ──┬──→ F4  validator + account ──┐
    (the byte rule, in isolation)     (FileSource,       │                              │
                                       signer, exit       ├──→ F5  deposit gen  ────────┼──→ F7  coverage
F3  test seam  ───────────────────┐    codes, `-` guard)  │       (+ worker pool)       │
    (fixture helper + WARNING      └─────────────────────>├──→ F6  tx sign / tx run ────┴──→ F8  docs + sweep
     counters, no production code)                        │       (+ single signer)
                                                          │
                                          ── release gate: H9 + A5-M (manual, §6) ──
```

`F1 → F2` is a hard serial spine carrying 8 of the 26 points, with exactly one parallel task
available (F3, 2 pts). **Do not staff three developers on day one.** The parallelism is real
only between F4, F5 and F6.

## 2. Phases

### F1 — `ethernal-secretfile` (4 pts) · *no CLI, no other crate*

The new leaf crate: `MAX_SECRET_FILE_BYTES`, `Residual`, `SecretFileError`,
`read_secret_line`, `read_secret_trimmed`, and the private fixed-buffer read loop.
Architecture §2. Requirements **FR-7, FR-8, FR-9, FR-10, FR-12b (mechanism), FR-13, FR-14,
FR-15, FR-16, FR-17, FR-23**.

**Why first and alone.** It is the highest-risk, highest-leverage work in the change — a wrong
byte here is a wrong derived key, silently, on the S-C and S-D paths — and it is the only part
testable in complete isolation with no CLI, no flag, no command and no fixture. D-1 was
confirmed at the architecture gate, so the crate is settled and R-1 is retired.

**Exit criteria**

- `cargo test -p ethernal-secretfile` passes standalone. The crate names no flag, no command,
  and does not depend on `clap` (grep as a review gate).
- `cargo tree -p ethernal-secretfile --edges normal` shows exactly `zeroize` and `thiserror`
  (M-4).
- **Byte-rule matrix**, `read_secret_line`: `pw` and `pw\n` → identical `"pw"` · `"pw \n"` →
  `"pw "` (the trailing space is kept — this is FR-11's claim, and it must be a test, not a
  comment) · `pw\r`, `pw\r\n`, `pw\r\r\n` → `LineTerminator { CarriageReturn }` · `a\nb` →
  `LineTerminator { MultiLine { lines: 2 } }` · empty → `Ok("")` · lone `"\n"` → `Ok("")`.
- `read_secret_trimmed`: leading and trailing ASCII whitespace removed, interior untouched.
- **File policy**: a directory → `IsDirectory`, *not* an io read error (R4 M-b) · `/dev/zero` →
  `TooLarge` **via the read cap** — the test must fail if the cap is ever made stat-based
  (R4 M-a) · a 4096-byte regular file succeeds and a 4097-byte one is `TooLarge` · a symlink is
  followed and the **target's** mode is what is checked (FR-15, the Kubernetes shape) ·
  non-UTF-8 → `NotUtf8` · nonexistent → `NotFound` · mode `0000` → `PermissionDenied`.
- **Warning**: a 0644 regular file emits exactly one line containing `file permissions` and
  `0644` into an injected `Vec<u8>` sink; 0600 emits none; a **mode-0440 FIFO emits none**
  (R4 M-e — this is the test that pins FR-17's regular-file scoping, without which the
  recommended `<(...)` pattern warns on every run).
- No `fs::read`, `read_to_string`, `read_to_end`, or any push/extend on the buffer path
  anywhere in the crate (FR-23 — grep is the gate; one allocation, never grown).
- All seven `SecretFileError` variants `Display` the path and no content (M-3, first instance).
- **No file under `bins/` and no other crate is touched.** If an issue seems to need one, stop
  and escalate.

### F2 — Shared seams (4 pts)

Everything the three flip phases consume, and nothing that flips. Architecture §4, §5, §7, §8.

- `ethernal-keystore`: `FileSource` (+ `Sync`), `KeystoreError::PassphraseFile` /
  `PassphraseFileEmpty`, re-export — **FR-18, FR-23b, FR-26, FR-27**.
- `ethernal-signer`: `new_local_signer_from_file`, `SignerError::KeyFile`, re-export, and the
  FR-28 doc rewrite of `local.rs:70-73` / `:85` — **FR-7, FR-26, FR-28**.
- `bins/errors.rs`: the explicit `SignerError::KeyFile(_) => 2` arm above the exit-3 list, the
  module-header comment amendment, and the exit-code assertions (D-7).
- `bins/fs_util.rs`: `secret_file_arg` — the FR-6 `-` guard.

**`secret_file_arg` belongs here, not in F4.** All three flips call it. Introducing it in a
flip phase would make F5 and F6 depend on F4 and destroy the only real parallelism this plan
has. Same test applied to everything else in F4: nothing in it is consumed by F5 or F6 —
`shared_args()` is used by `validator_cli` and `account_cli` only; `gen_cli.rs:122` defines its
own flag (verified).

**Depends on:** F1.

**Exit criteria**

- `FileSource: Sync` proven by a compile-time assertion (`fn _assert_sync<T: Sync>()`). F5's
  `&(dyn PassphraseSource + Sync)` bound (`gen_cmd.rs:143`) depends on it; discovering this in
  F5 is a cross-stream stall (R-10).
- **Warning latch**: five `read()` calls on one `FileSource` over a 0644 file produce
  **exactly one** `file permissions` line in the sink.
- Empty file → `PassphraseFileEmpty` → `exit_code_for` returns **2**, asserted in `errors.rs`
  beside the existing `EnvVarEmpty` assertion (`errors.rs:534` is the pattern to copy).
- `SignerError::KeyFile(_)` → **2** asserted, **and a sibling assertion pins
  `SignerError::InvalidKey` still → 3.** That second assertion is what holds `run::bad_key`
  green in F6.
- `MinLenPassphrase { inner: &FileSource, min: 8 }` over a file holding `1234567\n` →
  `PassphraseTooShort { min: 8, got: 7 }` — FR-19b's worked example, proven at the library
  level before any call site moves.
- `secret_file_arg("--passphrase-file", "-")` → exit 2, message mentions process substitution
  (`<(...)`) and does **not** recommend `/dev/stdin` alone (architecture §8).
- `EnvSource` and `new_local_signer_from_env` still present and re-exported (M-5), and
  **zero** `#[deprecated]` attributes anywhere (D-10).
- No flag definition changes. `make lint && make test` green with **zero existing assertions
  modified**.

### F3 — Test seam: fixture helper + WARNING counters (2 pts) · *no production code*

- `tests/common/mod.rs` gains
  `pub fn secret_file(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf` — writes the bytes
  with **no** trailing newline, `chmod 600`, returns the path. `common/mod.rs` already carries
  `#![allow(dead_code)]` (`:14`), so it lands green ahead of its first caller.
- The **six** WARNING counters (architecture §9, correcting the PRD's three) become
  warning-**kind**-specific on a discriminating token — `file permissions` for FR-17's kind,
  each other counter on its own text: `validator_e2e.rs:495-499`, `validator_e2e.rs:526-530`,
  `validator_cli.rs:543-548`, `account_cli.rs:496-500`. The two structurally-immune ones
  (`fs_util.rs:269-273`, `validator_cmd.rs:2527-2535`) gain a one-line comment recording *why*
  they are immune, so a later reader does not "fix" them.

Requirements: **FR-21** (this phase is the whole of it), and the R-7 mitigation for FR-12/FR-31.

**Why now, before any file flag exists.** This is the plan's cheapest insurance. Hardened here,
the counters pass unchanged against today's code — proving the hardening is behavior-neutral —
and a stray FR-17 warning in F4/F5/F6 then fails *its own* assertion with a clear message
instead of a mystifying count. Done later, the same edit is indistinguishable from loosening an
assertion to accommodate a bug. R-3 and R-7 both die here.

**Depends on:** nothing. Runs alongside F1 and F2.

**Exit criteria**

- `make lint && make test` green with `git diff --name-only` touching only
  `bins/ethernal/tests/**` and the two `#[cfg(test)]` modules in `validator_cli.rs` /
  `account_cli.rs`. **Zero production behavior changed.**
- Each of the four at-risk counters asserts `== 1` on a token that is neither a flag name (so
  it survives F4/F5/F6's rename) nor a path (so it is host-independent).
- One test proving the helper: a file written through it is mode `0600` and its bytes end
  without `\n`.

### F4 — `validator` + `account` flip (4 pts)

`keystore_cli.rs` (`shared_args`, `MnemonicPassphraseForm::File`, `parse_mnemonic_passphrase_form`
+ warn sink), `validator_cli.rs`, `account_cli.rs`, `validator_cmd.rs` (2 sites),
`account_cmd.rs` (2 sites), `keygen.rs` (the two message strings at `:289`/`:389`), and
`ethernal-keystore/src/error.rs`'s `NoTty` text.

**FR-29's message fixes ride here, not in F2** — so `develop` never advertises a flag that does
not yet exist.

**FR-29's `NoTty` string is shared with stream B, and F4 owns every assertion that keys on it.**
Three sites assert the substring `--passphrase-env` against that one message:
`crates/ethernal-keystore/src/passphrase.rs:307` (same crate, easy to miss from a `bins/` file
list) and `bins/ethernal/tests/gen.rs:623` (verified: it asserts
`stderr.contains("--passphrase-env")` on the `NoTty` message, **not** on a `gen_cli.rs` string).
F4 repoints all three. F5 still owns `gen.rs`'s 18 **flag** occurrences — line-disjoint, so the
streams stay independent. Consequence to accept and not "fix": between the F4 and F5 merges,
`deposit gen`'s no-TTY message names `--passphrase-file` while `deposit gen` still takes
`--passphrase-env`. That is transient and resolves when F5 lands.

Requirements: **FR-1…FR-6, FR-12 (S-C, S-D), FR-18, FR-19b, FR-29**, invariants **I-1** and
**I-2**.

**Depends on:** F2, F3.

**Exit criteria**

- **I-1 is an exit criterion, not a style note.** The passphrase read stays in
  `finish_from_mnemonic` (`validator_cmd.rs:485`, `account_cmd.rs:323`). Review check: the diff
  contains no `FileSource::new` above `run_ceremony`. The FR-17 case runs on **`recover`**
  (the `validator_e2e.rs:514` shape), where the warning is durable.
- **FR-12's live rows — the only automated evidence FR-9's widened clause works.**
  **S-C** (`account`): `pw` vs `pw\n` → identical v3 keystore, decryptable from either file;
  `pw\r`, `pw\r\n`, `pw\r\r\n` → **exit 2** each. **S-D** (`validator recover`, fixed
  mnemonic): `pw` vs `pw\n` → identical pubkey set, **and both equal to
  `--mnemonic-passphrase pw`**; the same three CR rows → exit 2.
- FR-19b end to end: a passphrase file holding `1234567\n` exits 2 with `PassphraseTooShort`.
- `--passphrase-file -` and `--mnemonic-passphrase-file -` each exit 2 (FR-6).
- An empty `--mnemonic-passphrase-file` — **0 bytes and a lone `\n`** — is a valid empty
  passphrase; an empty `--passphrase-file` is exit 2 (FR-18).
- `--mnemonic-passphrase` and `--mnemonic-passphrase-file` still conflict; the four-form matrix
  is otherwise unchanged (FR-3).
- **I-2 recorded, not fixed**: a comment at the `parse_mnemonic_passphrase_form` warn site
  states that this warning is erased by `clear_after_ceremony` on `new` and is durable on
  `recover`, citing the identical pre-existing property of the symlinked-output-dir warning. No
  hoist, no ceremony change. Without this comment a reviewer files it as a regression — or
  "fixes" it, which is R-2 exactly.
- Every test secret file goes through `common::secret_file`; zero raw `fs::write` of a
  passphrase in the diff.

### F5 — `deposit gen` flip + read-once worker pool (3 pts)

`gen_cli.rs` (flag + `GenConfig.passphrase_file`), `gen_cmd.rs` (**D-5**: read once before the
pool into `InMemoryPassphrase`), and `.claude/skills/verify/SKILL.md` — all 3 of the skill's
occurrences are `deposit gen`, and the skill is executable, not prose, so it cannot wait for F8.

Requirements: **FR-2, FR-4, FR-5, FR-6, FR-22 (the second site — architecture §11 divergence
1), FR-12 S-B regression row**.

**This is real work, not a rename.** `loader.load` runs per pubkey across up to `--parallel`
threads and `KeyLoader::load` calls `pw.read()` — with a file that is N concurrent opens of the
same path.

**Depends on:** F2, F3. Parallel with F4 and F6.

**Exit criteria**

- The read happens **once, before the pool**: `--parallel 4` over ≥4 pubkeys with
  `--passphrase-file <(printf '%s' pw)` succeeds. The test carries a comment stating that
  reverting the hoist makes it fail — otherwise it is vacuous, R-5's shape applied to gen.
- A named `mkfifo` FIFO as `--passphrase-file` with `--parallel 4` **completes**, under a
  wall-clock timeout so a regression fails instead of hanging CI (R4 M-d: the measured failure
  is an indefinite block, not an error).
- A bad or short passphrase file fails **before any worker starts** — asserted by exit 2 and
  zero output files, not the pre-change mid-pool exit 3 on an arbitrary pubkey.
- The `TermPromptSource` branch's per-pubkey prompt is **unchanged** (architecture §6.2's
  recorded non-change); no existing interactive assertion modified.
- S-B regression row: `pw` vs `pw\n` produce an identical `deposit_data*.json`. **The test
  comment must state this row passes with or without FR-8** — `normalize_passphrase` strips
  both `\n` and `\r` at `u <= 0x1f` — so it is a normalizer guard, not byte-rule evidence
  (FR-12).
- `make e2e-mock` green **and `make e2e-live` re-run locally against anvil**: `e2e_live.rs` is
  `#[ignore]`d, so `make test` green is not evidence for this phase (R-8).
- The `verify` skill's `deposit gen` line passes `--passphrase-file testdata/hoodi/passphrase.txt`
  directly, and the skill records that the tracked fixture is `100644` so an FR-17
  `file permissions` WARNING is expected and correct.

### F6 — `tx sign` / `tx run` flip + single signer (4 pts)

`sign_cmd.rs`, `run_cmd.rs`, and the FR-35 allowlist in `tests/common/mod.rs`. Architecture
§6.1 (**D-4**), §7 (FR-19 guard), §8.

Requirements: **FR-1, FR-2, FR-6, FR-19, FR-22, FR-24, FR-25, FR-30, FR-35**, and architecture
§11 divergence 4.

**Depends on:** F2, F3. Parallel with F4 and F5. Carries ~27 of the 64 test occurrences —
the largest test slice in the plan.

**Exit criteria**

- **One** `LocalSigner` construction site in the binary's local path. `SignConfig` and
  `RunConfig` hold `Option<PathBuf>`, never material, and `run_action`'s synthetic `SignConfig`
  sets `private_key_file: None` — with a test asserting it. Its **absence** is what structurally
  forbids a second open; a comment is not.
- **FR-33 / R-5**: `tx run --signer local --rpc-url <stub> --private-key-file <(printf '%s' KEY)`
  succeeds, and the same RPC-mode run with a named FIFO **completes** under a wall-clock
  timeout. The test must be in RPC mode — the two-signer path is gated on
  `signer == "local" && !rpc_url.is_empty()` — and the comment must say so, or it passes
  vacuously.
- **R-4**: `run::invalid_input` (exit 2), `run::bad_key` (exit **3**) and
  `sign::invalid_input_json` (exit 2) pass **unmodified**. Needing to edit one is an escalation,
  not a fix.
- **Architecture §11 divergence 4 gets a named new assertion**: a missing or unreadable
  `--private-key-file` exits **2**, where a missing env var exits 3 today. No existing test pins
  the old behavior, so this is an unpinned behavior change and needs its own evidence.
- FR-24: `tx sign --signer local` and `tx run --signer local` with no key flag each exit 2
  naming `--private-key-file`.
- FR-19 / FR-32: `--private-key-file 0x<64 hex>` exits 2 with "looks like a key value, not a
  path" and the argument does **not** appear in stdout or stderr (the assertion scans for the
  hex string). Applied on the `NotFound` branch only — exactly one `open` per invocation (D-8).
- `DEFAULT_PRIV_KEY_ENV`, `is_posix_env_var_name` and `posix_env_var_name_matrix` deleted
  (FR-25); `ETHERNAL_TX_PRIVATE_KEY` removed from `ETHERNAL_ENV_VARS` (`common/mod.rs:53`)
  while `_RPC_URL` / `_FROM` / `_GAS_LIMIT` stay (OD-1, A-1).
- `--signer` help no longer says "env-var private key", and `sign_cmd.rs:46-49`'s `long_about`
  is restated for a path argument (FR-30).
- `make e2e-mock` green **and `make e2e-live` re-run locally** (R-8).

### F7 — Adversarial coverage (3 pts)

Requirements: **FR-31, FR-32 (cross-command sweep), FR-34**. Architecture §9 "New coverage".

The flip phases proved their own *positive* properties and their own read-once regressions.
F7 proves the *negative* ones across all of them.

**Depends on:** F4, F5, F6.

**Exit criteria**

- The eight error paths — not found, permission denied, is-a-directory, empty, multi-line, CR,
  over-size, non-UTF-8 — asserted in `validator_secret_hygiene.rs`, `account_secret_hygiene.rs`
  and `redact_boundary.rs` for **exit code and absence of file contents** in stdout, stderr, the
  log stream and any `Debug` rendering (M-3). *(This list is architecture §9's, which replaced
  FR-31's "bad hex" and "wrong passphrase" rows with the CR and non-UTF-8 rows. The two dropped
  rows are pre-existing paths with no new file-mode leak vector and are already covered; the two
  added rows are new failure modes the file source creates.)*
- Each hygiene case uses a **distinctive sentinel** passphrase, so `!output.contains(sentinel)`
  is a real assertion rather than one an empty output satisfies.
- `--passphrase-file /dev/zero` exits 2; the directory case shows FR-14's intended message, not
  `Is a directory (os error 21)`.
- `exit_usage.rs` gains one case per new exit-2 path and asserts each removed `-env` flag is now
  an **unknown flag** (clap exit 2 — FR-1/FR-34).
- Help-text assertions repointed to the new names —
  `validator_e2e.rs:440-443`'s `help.contains("--mnemonic-passphrase-env")` and its siblings
  (FR-34); they fail on FR-2 otherwise.

### F8 — Docs, changelog, and the mechanical sweep (2 pts)

`docs/USER-GUIDE.md` (53), `README.md` (2), `CHANGELOG.md`. The `verify` skill's 3 landed in
F5. Requirements **FR-11, FR-20, FR-36, FR-37, FR-38**.

**Depends on:** F4, F5, F6. Parallel with F7.

**This is not only a rename sweep.** Three pieces of new prose:

1. FR-11's byte rule **in bytes**, with `printf '%s' pw > f` vs `echo pw > f`, an explicit note
   that a trailing **space** is significant, and the one-sentence form: *"The secret is the
   whole file minus at most one trailing newline; a carriage return anywhere is an error."*
2. The "deliberately unlike prior art" list gains the multi-line row (a **deliberate
   divergence, not parity** — geth accepts multi-line files because `--password` is a password
   *list*, a feature ethernal does not have) **and the non-UTF-8 row** beside the CRLF row:
   geth's Go strings are byte strings and would accept those bytes; D-3 refuses them, and the
   guide must say why (architecture §3, §11 divergence 6).
3. FR-20's warning, in the register of the existing raw-`--mnemonic-passphrase` warning, that a
   *passphrase* typed where a *path* is expected lands in argv, `ps`, shell history, **and the
   not-found error message**.

**Exit criteria**

- The PRD's acceptance `rg` is **run and its output pasted into the completion note**:
  `rg -- '--(passphrase|private-key|mnemonic-passphrase)-env' bins/ crates/ docs/ README.md .claude/skills/`
  returns zero flag definitions and zero usage examples. `CHANGELOG.md` is excluded by design —
  its FR-37 migration lines name the removed flags on purpose. Baseline before the change: 58
  doc occurrences (guide 53, README 2, skill 3) and 64 test occurrences.
- FR-36: every `export VAR=secret` example is now a file example that does **not** create a
  world-readable file — `umask 077`, `chmod 600`, or process substitution.
- FR-37: `CHANGELOG.md` `### Removed` names all three flags with a migration line each, and
  states the FR-24 zero-flag regression explicitly.
- FR-38: `USER-GUIDE.md:197-200`'s "two passphrases are never interchangeable" section rewritten
  for files, carrying the FR-8 byte rule.
- Every new command block in the guide is copy-pasteable, and was actually pasted once.
- **No CI workflow references the removed flags** — verified while planning: `rg` over
  `.github/` returns nothing, so FR-37's "any CI job relying on the zero-flag path must be
  updated" has an empty set. Recorded so the estimator budgets nothing for it.

## 3. Milestones

| Milestone | Phases | Meaning |
|---|---|---|
| **M1 — the primitive** | F1 | The byte rule exists and is proven with no CLI in play. A wrong derived key is now a test failure, not a discovery. |
| **M2 — the seams** | F1, F2, F3 | The library can read a secret file; the test suite is ready to receive one. **Nothing observable has changed.** The last fully reversible point. |
| **M3 — flags flipped** | F4, F5, F6 | M-2 = 0. Every command reads its secret from a file, exactly once. The breaking change is complete. |
| **M4 — proven** | F7 | M-3 = 0, asserted per error path. |
| **M5 — documented** | F8 | Merge-complete on `develop`. |

**Unlike the keygen plan, there is no intermediate ship point.** M2 ships nothing an operator
can see, and M3 is atomic from an operator's view: `develop` carrying `--passphrase-file` for
`validator` but `--passphrase-env` for `deposit gen` is worse than either end state. Each of
F4/F5/F6 is still independently mergeable and independently green — but **no release is cut
from a partial M3**.

Release is gated on §6, not on M5.

## 4. Ordering, and what genuinely parallelizes

| Phase | Depends on | Blocks | Runs alongside |
|---|---|---|---|
| F1 (4) | — | F2 | F3 |
| F2 (4) | F1 | F4, F5, F6 | F3 |
| F3 (2) | — | F4, F5, F6 | F1, F2 |
| F4 (4) | F2, F3 | F7, F8 | F5, F6 |
| F5 (3) | F2, F3 | F7, F8 | F4, F6 |
| F6 (4) | F2, F3 | F7, F8 | F4, F5 |
| F7 (3) | F4, F5, F6 | — | F8 |
| F8 (2) | F4, F5, F6 | — | F7 |

**Critical path:** F1 → F2 → F6 → F7 → F8 = 17 of 26 points. F3's 2 points are the only work
available while the spine runs. Honest reading: a second developer is idle for most of F1–F2, a
third is idle for all of it.

**Streams once F2 lands** — three, and the merge points are test files, not source:

- **A:** F4 — `validator` + `account`. Owns `keystore_cli.rs` and the ceremony paths.
- **B:** F5 — `deposit gen`. Owns the worker pool and the `verify` skill.
- **C:** F6 — `tx sign` / `tx run`. Owns the signer restructure and the largest test slice.

Source files are disjoint across the three (verified: `shared_args()` has exactly two callers,
both in stream A; `gen_cli.rs` defines its own flag). Test files are **not**, so they are
assigned:

| Test file | Occurrences | Owner | Note |
|---|---|---|---|
| `gen.rs` | 18 | **F5** | flag occurrences only. The `NoTty`-message assertion at `:623` is **F4**'s (FR-29, shared string) — line-disjoint |
| `sign.rs` | 12 | **F6** | |
| `run.rs` | 10 | **F6** | `invalid_input` / `bad_key` unmodified (R-4) |
| `validator_e2e.rs` | 4 | **F4** | F7 repoints the help-text assertions |
| `validator_secret_hygiene.rs` | 4 | **F4** | F7 adds the FR-31 matrix |
| `account_secret_hygiene.rs` | 4 | **F4** | F7 adds the FR-31 matrix |
| `exit_usage.rs` | 3 | **F4** | both uses are `validator recover`; F6 adds the FR-24 case and F7 the FR-34 cases — line-disjoint |
| `run_rpc.rs` | 3 | **F6** | |
| `e2e_live.rs` | 2 | **split** | `:97` `--passphrase-env` → F5 · `:146` `--private-key-env` → F6. **`#[ignore]`d**: `make test` will not catch a break here (R-8) |
| `e2e_pipeline.rs` | 2 | **F6** | both are `--private-key-env`; this file runs no `deposit gen` |
| `account_e2e.rs` | 1 | **F4** | |
| `common/mod.rs` | 1 | **F3** helper / **F6** allowlist | — |

**Count footnote.** Architecture §9 says "64 occurrences across 11 files"; `rg -c` reports 12
files, because the 64th is the **doc comment at `common/mod.rs:78`**, not a call site. 63 real
call sites. Do not re-run the count, get 12 files, and conclude the sweep was mis-run.

## 5. Sequencing rules the estimator MUST respect

1. **F1 touches no file under `bins/` and no other crate.** If an issue seems to need one, stop
   and escalate in the run summary.
2. **`common::secret_file` (F3) lands before the first test-migration issue.** R-7: the 64 sites
   are tempdir + write + `chmod 600` + path, not a string swap. Any issue that writes a test
   secret file with a raw `fs::write` is a plan violation — a 0644 fixture emits an FR-17
   warning and breaks its own caller's WARNING count.
3. **`secret_file_arg` (FR-6) lands in F2, not in a flip phase.** Putting it in F4 makes F5 and
   F6 depend on F4 and destroys the plan's only real parallelism.
4. **I-1 is an exit criterion of F4, F5 and F6.** Each secret file is read exactly where its
   `std::env::var` counterpart fires today. **No validation at config load.** A fail-fast hoist
   puts the FR-17 permission warning before `clear_after_ceremony`, which erases it — silently
   disabling a P0 with no test failing (D-9, R-2). This is a correctness constraint, not a
   style preference.
5. **FR-12's CR rows land in F4, never deferred to F7.** S-B is **not** evidence:
   `normalize_passphrase` strips `\n` and `\r` alike at `u <= 0x1f`, so the S-B row passes
   whether or not FR-8/FR-9 exist. The three CR rows on **S-C and S-D** are the only automated
   proof the widened residual check is live. A suite without them passes under the superseded
   rule.
6. **No existing assertion is loosened.** WARNING counters become kind-specific (`== 1` on a
   discriminating token), never "at least one". If an existing test appears to need
   modification, that is a design error in the new behavior — escalate rather than edit
   (the keygen plan's rule 2; the e2e plan's C-2 discipline).
7. **F8's `rg` sweep runs after F4/F5/F6 are merged.** Run earlier it passes vacuously (R-6).
8. **Nothing in architecture §14 changes.** `ethernal-core`, `ethernal-tx`, `EnvSource`,
   `new_local_signer_from_env`, keystore bytes, filenames, output mode, `create_new` semantics,
   scrypt parameters, the ceremony and its scrollback clear, the C1–C4 verification work and
   `--no-verify`, `Progress`/`PhaseReporter`, and the `ETHERNAL_TX_*` value fallbacks.
9. **No `#[deprecated]` anywhere** (D-10), and **no `ETHERNAL_TX_PRIVATE_KEY_FILE` fallback** —
   OD-5 declined it explicitly; do not re-derive it from OD-1's "fallbacks stay".
10. **Zero new third-party dependencies** (M-4), re-checked per phase.
11. Every issue is ≤ 3 pts and `--ff` mergeable to `develop` with `make lint && make test`
    green. Phases that touch `e2e_live.rs` (F5, F6) additionally require `make e2e-live` locally.
    Release merges to `main` are `--no-ff` with a `vX.Y.Z` merge commit.

## 6. Release gate — H9 and A5-M

This repo carries two open **manual cross-tool parity sessions**. They gate **release, not
merge**: they sit after F8 and before any `--no-ff` merge to `main`. Neither is a task inside a
phase, and neither can run in CI.

- **H9 — validator keygen parity.** Gains three rows: `pw\r` → **exit 2**, `pw\r\n` → **exit 2**,
  a non-UTF-8 passphrase file → **exit 2**.
- **A5-M — EOA v3 keystore parity.** Gains the same three rows, **plus** the geth round-trip on
  the plain cases (OD-7): `geth account import --password <file>` against an ethernal-written v3
  keystore produced from that same file, and `ethernal account recover --passphrase-file <file>`
  against a keystore geth wrote — each for a file **with** and **without** a trailing `\n`.

Two traps, stated here because the gate will otherwise be misread:

- **The non-UTF-8 row is an ethernal-side exit-2 assertion only. It is NOT a geth round-trip
  row.** Go strings are byte strings, so geth's `--password` accepts those bytes; D-3
  deliberately refuses them. "geth accepted, ethernal refused" is the decision working, not a
  bug. **The geth round-trip rows must use UTF-8 files** or they test the wrong thing
  (architecture §3).
- **A5-M needs a real `geth` binary** and cannot run in CI. Schedule it as a session.

FR-12 is the automated equivalent of the plain rows, not a replacement for the gate — it cannot
compare against another implementation.

## 7. Risks

R-1 is **retired**: D-1 was confirmed by the user at the architecture gate, so the
duplicate-in-two-crates fallback is not carried forward.

| # | Risk | Owner | Mitigation |
|---|---|---|---|
| **R-2** | An implementer "improves" the design by validating secret files at config load | **F4** (F5/F6 bound by rule 4) | I-1 written as an exit criterion with its reason; the FR-17 case on `recover` is the tripwire; I-2's comment removes the temptation |
| **R-3** | A test creates a passphrase file without `chmod 600` and an unrelated WARNING count fails | **F3** | The helper is the only sanctioned path (rule 2); the counters are kind-specific, so a stray `file permissions` line fails *its own* assertion with a clear message |
| **R-4** | `run_action`'s reordered signer construction flips an error-precedence assertion | **F6** | `run::invalid_input` and `run::bad_key` named and required to pass unmodified; `exit_usage.rs` re-run in the same issue |
| **R-5** | The FIFO read-once test is written without `--rpc-url` and passes vacuously | **F6** (gen analog: **F5**) | RPC mode named in the exit criterion; the test carries a comment stating what reverting the fix would break |
| **R-6** | The doc sweep misses one of the 58 occurrences | **F8** | The PRD's `rg` is mechanical, runs after the flips, and its output is pasted into the completion note |
| **R-7** | The 64 test occurrences are estimated as a string swap and a phase overruns | **F3**, budgeted in F4/F5/F6 | The helper turns 64 sites into one-line calls; ~27 sit in F6 alone and its 4 pts reflect that |
| **R-8** | `e2e_live.rs` breaks silently — it is `#[ignore]`d, so `make test` stays green | **F5**, **F6** | `make e2e-live` against local anvil is an explicit exit criterion of both phases |
| **R-9** | `develop` carries a mixed flag surface if one of F4/F5/F6 slips | **F4/F5/F6** | Each is independently green and mergeable; M3 is declared only when all three land, and no release is cut from a partial M3 |
| **R-10** | `FileSource` ships without `Sync` and F5 discovers it at the `&(dyn PassphraseSource + Sync)` bound, stalling a parallel stream | **F2** | A compile-time `Sync` assertion is an F2 exit criterion |

## 8. Out of scope (dispositions written, not scheduled)

`gen_cmd.rs:406`'s missing `.env_clear()` — closes on its own once no secret is in the
environment, and `.env_clear()` would break `look_path`'s bare-name PATH resolution
(architecture §5) · the three-way non-UTF-8 divergence between S-B/S-C/S-D (FR-12b; D-3 picks a
boundary policy, it does not repair the consumers) · the `RecoverMnemonicSource`
`read_to_string` residue (`keygen.rs:350-353`, FR-23) · the ceremony's erasure of pre-ceremony
warnings (I-2) · `deposit gen`'s per-pubkey TTY prompt (architecture §6.2) · removal of
`EnvSource` / `new_local_signer_from_env` — a separate semver-major decision (OD-6, D-10) · the
`ETHERNAL_TX_RPC_URL` / `_FROM` / `_GAS_LIMIT` value fallbacks (OD-1, A-1).

---

**Downstream:** `issues/index.md`
