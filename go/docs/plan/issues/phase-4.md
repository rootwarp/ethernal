# Phase 4 — Integration verification

Prove the release against the PRD success metrics (M1–M7) end to end. These are the only
verification-only issues (per the task rule that test work otherwise rides with the behavior
change that introduces it).

**Phase entry:** M3 (all of Phases 1–3 merged).
**Phase exit / Milestone M4:** verify skill green with live RPC resolution; PRD M1–M7 all met.

---

## P4-1 — Automated suite, hybrid e2e case, and golden byte-identity

- **Stream:** A
- **Points:** 2
- **Dependencies:** **P3-1**, **P3-2**, **P3-3** (Phase 3 complete; transitively the full P2
  chain and all of Phase 1)
- **Findings:** all (verification)

**Description.** Implements project-plan §Phase-4 (automated portion).

- Run full `go test ./...` and the e2e suite (`-tags=e2e`, `deposit_e2e_test.go`).
- Author the hybrid `build`/`run --rpc-url` e2e case: gas/nonce omitted → assert the tx fields
  reflect the node's live tip, base fee, and pending nonce. Where anvil is unavailable in CI, the
  deterministic seam-fake cases (P2-2/P2-3) provide coverage; this case is the integration
  confirmation. Apply `applyUsageErrorHook` in the e2e app; add `genCommand()` to `newE2EApp` if
  a gen e2e case is added (arch §8.2 e2e note).
- Golden byte-identity check: offline `gen`/`build`/`sign` outputs diff-empty vs the pre-release
  binary; fixtures **not** regenerated.

**Acceptance criteria** (PRD success metrics):
- **M2:** unreachable `--rpc-url` on `build`/`run` exits **5**.
- **M3:** missing required flag exits **2** on all five subcommands.
- **M4:** `gen --dry-run` succeeds with no `--output-dir`; without it, missing still exits **2**.
- **M7:** offline golden outputs byte-identical (diff empty).
- `go test ./...` and `go test -tags=e2e ./...` green.

---

## P4-2 — Verify-skill playbook against live anvil + final consistency read

- **Stream:** A
- **Points:** 2
- **Dependencies:** **P4-1**
- **Findings:** all (verification)

**Description.** Implements project-plan §Phase-4 (live-node + sign-off portion).

- Re-run the `verify` skill playbook (`go/.claude/skills/verify/SKILL.md`) gen→build→sign→send
  against a live anvil node, **with the RPC probes now resolving nonce and fees from the node**
  rather than emitting hardcoded defaults.
- Piped `gen` with no TTY and no `--passphrase-env` → confirm exit **2** naming the flag (M5).
- Final `USER-GUIDE.md` consistency read.
- Sign off PRD M1–M7.

**Acceptance criteria** (PRD success metrics):
- **M1:** verify playbook passes; anvil `build`/`run` with gas/nonce omitted reflects anvil's
  live tip, base fee, and pending nonce (e.g. account pending nonce 7 → tx nonce 7).
- **M5:** piping into `gen` with no TTY and no `--passphrase-env` exits **2** with a message
  naming `--passphrase-env`.
- **M6:** docs carry no stale RPC language, disambiguate the chain-ID cases, document `.raw`.
- All of PRD M1–M7 verified.

---

### Phase 4 totals

| Item | Stream | Points |
|---|---|---|
| P4-1 | A | 2 |
| P4-2 | A | 2 |
| **Total** | | **4** |
