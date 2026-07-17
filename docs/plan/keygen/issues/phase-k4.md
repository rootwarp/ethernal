# Phase K4 — Integration & release

**Theme:** Freeze the in-binary E2E fixture chain, ship the docs, and run the once-per-release manual cross-tool
session. Stream A (K4-1) + Stream B (K4-2).
**Issues:** K4-1, K4-2 · **Points:** 3.
**Execution order — K4 runs LAST** (phase numbers are thematic). **K4-1 depends on K5-2**, so this phase is
reached only after K5 has merged; the E2E deposit-data fixture is frozen **once**, against the require-choice
`gen` with real 0x01 creds. Read `phase-k5.md` before this file. Full order: K1 → K2/K3 → K5 → **K4**.
**Milestone gate — M-K4 (final):** with K5 merged, `key recover → gen --withdrawal-address` E2E is byte-stable
(0x01 creds, BLS-verify on); one manual cross-tool session recorded in the progress log; docs done.

---

## K4-1 — in-binary E2E + fixtures

**Points:** 2 · **Stream:** A · **Depends on:** K3-4, **K5-2** · **Milestone:** M-K4

**Goal:** Prove the whole front-of-pipeline in one binary with a single committed fixture that chains
BIP-39 → EIP-2333 → EIP-2335 → deposit: a fixed mnemonic through `key recover`, into `gen --withdrawal-address`
(BLS-verify on), producing byte-stable deposit data. Satisfies G3 (full pipeline, no external key tool), G6, and
S-4 (determinism via the fixed mnemonic, not a hidden entropy flag).

**Implementation notes**
- New integration test in `bins/eth-deposit/tests/` (a new `key_e2e.rs`, or extend `e2e_pipeline.rs`); fixtures under
  `bins/eth-deposit/tests/testdata/keygen/`.
- Chain: `key recover` with the fixed 12-word mnemonic `abandon … about` + `--mnemonic-passphrase-env=TREZOR` →
  seed `c55257c3…463b04` (= EIP-2333 case-0 seed) → per-index signing/withdrawal pubkeys → keystores →
  `gen --withdrawal-address <checksummed>` (BLS-verify on) → validated deposit data.
- Commit the expected **signing + withdrawal pubkeys per index** and the expected **deposit data** as fixtures;
  compute once and freeze (post-K5, real 0x01 creds).
- Determinism comes from `key recover` with the fixed mnemonic — **no** hidden `--entropy-*` flag (S-4 / PRD Q4).

**Acceptance criteria**
- [x] `key recover` (fixed mnemonic + `TREZOR` env passphrase) derives seed `c55257c3…463b04` and keystores whose
  per-index signing pubkeys match the committed fixture — G3, C-1
  (research/eip-2333-2334.md; research/bip39.md chain anchor).
- [x] those keystores feed `gen --withdrawal-address <checksummed>` (BLS-verify on) → deposit data with real 0x01
  creds — G3, G6, F-13.
- [x] the produced deposit data is **byte-stable** against the committed golden under
  `bins/eth-deposit/tests/testdata/keygen/` — G3 (risk R3, frozen once post-K5).
- [x] no hidden entropy flag: determinism is via the fixed mnemonic through `key recover`, not entropy injection —
  S-4.

**Test plan**
- Integration test driving the real binary (or the top-level command entrypoints) end-to-end; assert the per-index
  signing pubkeys, the keystore `Loader` round-trip, and the final `deposit_data` JSON equals the committed golden.

**Notes**
- Freezes **after** K5-2 (dependency) so the deposit-data fixture carries real 0x01 creds a single time — never a
  placeholder-cred fixture. The per-index pubkey fixtures and the K1 wordlist sha256 pin are K5-independent and
  freeze earlier.
- The full EIP-2334 signing path has no external seed→pubkey vector; it is gated here (automated) and by the manual
  cross-tool session below.

---

## K4-2 — docs — USER-GUIDE, README, CHANGELOG

**Points:** 1 · **Stream:** B · **Depends on:** K4-1 · **Milestone:** M-K4

**Goal:** Document the new front-of-pipeline: the `key new`/`recover` ceremony, the raw-mnemonic-passphrase
`ps`/history security note, the strict-vs-lenient EIP-55 asymmetry, and the breaking `gen` require-choice change.
Satisfies U-1, U-3, and the documentation half of C-2/R5.

**Implementation notes**
- `docs/USER-GUIDE.md`: a new "Step 0 — create validator keys" section covering `key new` (TTY-only ceremony:
  generate → display → full re-entry → write) and `key recover` (TTY or piped stdin), the passphrase flows, and
  `--count`/`--output-dir`/`--start-index`.
- Carry the architecture §Design note (c) **security note**: a raw `--mnemonic-passphrase VALUE` is visible in the
  process table (`ps`) and shell history; recommend the env/prompt forms; document the raw form as a scripting
  convenience, **not** for high-value mnemonics.
- Document the EIP-55 asymmetry (risk R5): `--withdrawal-address` is strict (rejects lowercase), while `gen`'s
  `--from` is lenient.
- `README.md`: update the command list / divergence table (cross-note with the existing Rust README divergence
  table). `CHANGELOG.md`: record the **breaking** `gen` change (now requires `--withdrawal-address`; exit 2 without).

**Acceptance criteria**
- [x] USER-GUIDE "Step 0 — create validator keys" documents `key new` (ceremony, TTY-only) and `key recover`
  (stdin) — U-1, U-3.
- [x] the raw `--mnemonic-passphrase` `ps`/shell-history exposure is documented, with env/prompt recommended —
  architecture §Design note (c) security note.
- [x] the EIP-55 strict-vs-lenient asymmetry (`--withdrawal-address` vs `--from`) is documented — risk R5, F-13.
- [x] CHANGELOG records the breaking `gen` require-choice change — F-13, PRD Q2 (risk R2).

**Test plan**
- Docs review (no automated test); `make test && make lint` still green; cross-reference the divergence note with
  the existing Rust README divergence table.

---

## Manual cross-tool session (M-K4 gate — recorded in the progress log, not a pointed issue)

This is the C-2 / G1 / G2 gate. It is **manual**, run once per release, and its result is recorded in the
progress log of [`../overview.md`](../overview.md) / [`../project-plan.md`](../project-plan.md) — it is not a
separate pointed issue. Pin the tool/client versions in the note (risk R4).

**Checklist**
- [ ] Pin versions: `ethstaker-deposit-cli` `<version>` (the maintained fork; **not** the deprecated
  `staking-deposit-cli`) and the validator client `<name>@<version>`.
- [ ] **G2 (parity):** the same mnemonic + mnemonic passphrase into `ethstaker-deposit-cli` → signing **and**
  withdrawal pubkeys match ours **index-for-index**.
- [ ] **G1 (import):** a keystore we created imports cleanly into **≥ 1** of Lighthouse / Teku / Prysm / Nimbus
  (note the client's per-keystore password expectation — e.g. Teku's sibling `.txt`).
- [ ] Record the result (tool + client versions, pass/fail, date) in the overview/project-plan progress log — C-2.

**Notes**
- Real-terminal echo-off for the `key new` ceremony (the residual from risk R1) is also only exercised here;
  confirm the mnemonic display + re-entry behave on a real TTY during this session.
