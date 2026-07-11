# Phase 3 — Independent fixes & consolidated doc pass (F3, F4, F6, F1.6)

Close the remaining findings: make `gen --dry-run` not require `--output-dir`, and write all
exit-code / chain-ID / `.raw` documentation **once** against final behavior.

**Phase entry:** F3 and F6 have **no** upstream dependency (Stream B pulls them forward during
Phase 2). The doc pass (P3-2) needs **M2** so its prose is accurate.
**Phase exit / Milestone M3:** F1–F6 resolved; docs coherent; stale RPC language removed.

---

## P3-1 — F3 `gen --dry-run` conditional requiredness

- **Stream:** B (parallel — no upstream dependency; pullable forward during Phase 2)
- **Points:** 2
- **Dependencies:** none
- **Findings:** F3

**Description.** Implements architecture §4. urfave cannot express conditional requiredness
(`checkAllRequiredFlags` runs before any Action), so move the check into the Action, matching
`gen`'s existing manual-validation style.

- `internal/cli/cli.go` — remove `Required: true` from the `output-dir` flag (`cli.go:124-128`).
- `internal/cli/cli.go` — replace the unconditional `--output-dir` validation (`cli.go:200-204`)
  with a dry-run-gated block:
  ```go
  outputDir := cmd.String("output-dir")
  if !cmd.Bool("dry-run") {
      if outputDir == "" {
          return ucli.Exit("--output-dir: required flag not set", 2)   // F3.2
      }
      if err := validateOutputDir(outputDir); err != nil {             // cli.go:316
          return ucli.Exit(fmt.Sprintf("--output-dir: %v", err), 2)    // F3.2
      }
  }
  ```
  `DryRunWriter` writes JSON to stdout and never uses `output-dir` (`gen.go:81-86`);
  `--verify-with-deposit-cli` is already skipped in dry-run (`gen.go:412`).
- Tests (`internal/cli` or cmd gen tests, per arch §8.2): `gen --dry-run` with no `--output-dir`
  → success (JSON to stdout), exit 0; `gen --dry-run` with an invalid `--output-dir` → success
  (validation skipped); `gen` without `--dry-run` and no `--output-dir` → exit 2; `gen` without
  `--dry-run` and invalid `--output-dir` → exit 2 (unchanged).

**Acceptance criteria** (plan Phase-3 exit criteria / PRD M4, F3.1, F3.2):
- `gen --dry-run` with no (or invalid) `--output-dir` succeeds and writes JSON to stdout (exit 0).
- `gen` without `--dry-run`, missing or invalid `--output-dir`, still exits **2**.
- Exit code stays 2 whether the missing flag is caught by the F2 hook (for flags still
  `Required:true`) or by this manual `ucli.Exit(…,2)` (uniform).
- `go test ./...` green.

---

## P3-2 — Consolidated exit-code / chain-ID documentation pass (F4 + F1.6)

- **Stream:** A (critical path — must reflect final Phase-2 behavior)
- **Points:** 2
- **Dependencies:** **P2-2** (build/run now reach exit 5; build-side chain-ID→2), **P2-1**
  (`--from`/chain-ID semantics). Doc-only; no behavior change.
- **Findings:** F4 (F4.1, F4.2, F4.3), F1.6 (exit-code prose + `USER-GUIDE.md` narrative)

**Description.** Implements architecture §5 + PRD F1.6/F4. A single coherent pass so no comment
block is edited twice (see plan coordination note — Phase 2 already did the inline flag Usage
strings; this item owns all exit-code **prose** + the `USER-GUIDE.md` narrative rows).

- `cmd/eth-deposit/main.go:7-14` header comment — replace with the disambiguated exit-code block
  (verbatim in arch §5): exit 2 gains "build-side RPC chain-ID mismatch"; exit 3 names
  "signer-side chain-ID mismatch"; exit 5 names "dial failure, gas/nonce estimation failure,
  broadcast-side chain-ID mismatch".
- `cmd/eth-deposit/exit.go:1-11` header comment — exit-2 line append "build-side RPC chain-ID
  mismatch"; exit-3 line "chain ID mismatch" → "signer-side chain ID mismatch".
- Per-subcommand `--help` exit-code lists (arch §5):
  - **build** (`main.go:116-119`) — add exit **5**; note `--from`/chain-ID under 2.
  - **run** (`run.go:130-135`) — add exit **5** and the ledger `--nonce` note under 2.
  - **sign** (`sign.go:94-98`) — clarify exit 3 as "signer-side chain-ID mismatch".
  - **send** (`send.go:104-108`) — clarify exit 5 as "broadcast-side chain ID mismatch".
  - Root one-liner (`main.go:70`) may stay coarse — no change required.
- `docs/USER-GUIDE.md` — replace the "Phase 4 / accepted-but-stored" `--rpc-url` row and the
  `--nonce` row with the now-real behavior; add a `--from` row; remove the `USER-GUIDE.md:246`
  "accepted-but-stored (Phase 4 wiring)" language.

**Acceptance criteria** (plan Phase-3 exit criteria / PRD M6, F4.1–F4.3, F1.6):
- `--help` and `USER-GUIDE.md` contain **no** "Phase 4 / accepted-but-stored" language.
- The three chain-ID cases read coherently everywhere: build-side config → **2**,
  signer-side → **3**, broadcast-side → **5**.
- `build`/`run` `--help` list exit **5**; the ledger-RPC `--nonce` requirement is documented.
- No behavior change (F4.3); `go test ./...` still green.

---

## P3-3 — F6 `.raw` companion output polish

- **Stream:** B (parallel — no upstream dependency)
- **Points:** 0.5  *(verify/polish only — most text already exists; PRD calls this a fraction of a point)*
- **Dependencies:** none
- **Findings:** F6

**Description.** Implements architecture §7. Verify/polish only (N3 — the `.raw` output stays).

- `docs/USER-GUIDE.md:488` — make the `0x` prefix explicit ("just the `rawRLP` hex
  (**0x-prefixed**)") and state the condition ("written **only when `--output` is a file path**;
  with stdout output no `.raw` is produced").
- `cmd/eth-deposit/run.go` — confirm `0o600` appears in `run --help`; optional: add "(mode 0600)"
  to the `signed.raw` line (`run.go:91-94`) for parity with `USER-GUIDE.md`.

**Acceptance criteria** (plan Phase-3 exit criteria / PRD F6.1, M6):
- Both `run --help` and `USER-GUIDE.md` state the `.raw` companion's `0x` prefix, `0o600` mode,
  and "only when `--output` is a file" condition.
- No behavior change (N3); no net-new documentation sections.

---

### Phase 3 totals

| Item | Stream | Points |
|---|---|---|
| P3-1 | B | 2 |
| P3-2 | A | 2 |
| P3-3 | B | 0.5 |
| **Total** | | **4.5** |
