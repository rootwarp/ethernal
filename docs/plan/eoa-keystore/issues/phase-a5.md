# Phase A5 — E2E integration + docs + combined manual parity

**Theme:** Freeze the in-binary E2E fixture chain (BIP-39 → BIP-32/BIP-44 → v3-encrypt → address),
demonstrate the cross-recovery property (one seed → both HD trees), ship the docs, and run the
**combined H9 + C-2** cross-tool parity session (the sole consumer proof — v1 ships no in-binary v3
reader). Stream A (A5-1) + Stream B (A5-2 docs) + one manual session (A5-M).
**Issues:** A5-1, A5-2 · **Points:** 3 (+ manual) · **Execution:** LAST (phase numbers are thematic).
**Milestone gate — M-A5 (final):** E2E fixture frozen — fixed mnemonic → `account recover` → v3
keystores, filenames parse, `0600`, addresses match; **cross-recovery property** shown (same seed
feeds BLS `m/12381/3600/…` and EOA `m/44'/60'/0'/0/…`); docs shipped. **A5-M combined parity session
recorded** with pinned versions — `cast wallet address` parity index-for-index (G2) **and** a keystore
we wrote unlocks in geth / `cast wallet import` / MetaMask (G1); any mismatch **blocks release**.

Fixture chain and cross-recovery from [`prd.md`](../prd.md) §"Cross-recovery property" and
[`architecture.md`](../architecture.md); the manual checklist from
[`research/cross-tool-parity.md`](../research/cross-tool-parity.md) and the keygen H9 definition in
[`../keygen/hardening-plan.md`](../keygen/hardening-plan.md) §H9.

---

## A5-1 — in-binary E2E + cross-recovery fixture

**Points:** 2 · **Stream:** A · **Depends on:** A4-2 · **Milestone:** M-A5

**Goal:** Prove the whole EOA pipeline in one binary with a committed fixture that chains
BIP-39 → BIP-32/BIP-44 → v3-encrypt → address: a fixed mnemonic through `account recover` producing
byte-stable v3 keystores at `0600` with parsing `UTC--` filenames and matching addresses, plus the
cross-recovery property (one seed feeds both HD trees). Satisfies C-1/G4 (E2E), S-4 (determinism from
the fixed mnemonic, no hidden entropy/time flag).

**Implementation notes**
- New integration test in `bins/ethernal/tests/` (an `account_e2e.rs`); fixtures under
  `bins/ethernal/tests/testdata/eoa/`.
- **EOA half (externally vector-anchored):** `account recover` with the fixed `abandon…about`
  mnemonic + **empty** mnemonic passphrase → seed `5eb00bbd…` → per-index v3 keystores; assert the
  top-level `address` at index 0/1 equals `9858effd…`/`6fac4d18…` (lowercase, no `0x`) and the EIP-55
  display equals `0x9858…Eda94`/`0x6Fac…b9C0` (the cast-verified vector, A1-2 + A3-1), each written
  `0600` with a `UTC--…` filename that round-trips through `v3_filename`'s parse.
- **Cross-recovery property (structural demo, not a dual external vector):** derive **both** trees
  from the one seed — EOA `m/44'/60'/0'/0/i` (external-anchored above) **and** BLS `m/12381/3600/i/0/0`
  via the already-merged `core::hd` (no A-issue dependency) — and assert both produce valid keys from
  the same seed. The BLS pubkeys are **regression-locked** (committed fixture), **not** claimed against
  an external vector: no single mnemonic+passphrase has published vectors for both trees (abandon+empty
  → EOA cast addresses; the BLS EIP-2333 case-0 vector is abandon+**TREZOR** → `c55257c3…`). The
  both-trees-**external** cross-check is exactly what A5-M does.
- Determinism comes from `account recover` with the fixed mnemonic — **no** hidden `--entropy-*` /
  `--time-*` flag (S-4). A fixed `Timestamp` for the filename is a test-only `AccountDeps` injection,
  not a shipped flag.

**Acceptance criteria**
- [x] `account recover` (fixed `abandon…about` + empty passphrase) derives seed `5eb00bbd…` and v3
  keystores whose index 0/1 `address` fields are `9858effd…`/`6fac4d18…` and whose EIP-55 display is
  `0x9858…Eda94`/`0x6Fac…b9C0` — C-1, G4 (research/bip32-secp256k1.md §"Ethereum BIP-44 vector").
- [x] each keystore is written `0600`, atomically, with a `UTC--…` filename that parses back to the
  address; a second run into the same dir refuses to overwrite — F-4, S-3.
- [x] **cross-recovery:** the same seed feeds `core::hd` (BLS `m/12381/3600/i/0/0`) and
  `core::hd_secp256k1` (EOA `m/44'/60'/0'/0/i`); the BLS pubkeys match a **committed regression
  fixture** (no external-vector claim for this passphrase) while the EOA addresses match the cast
  vector — PRD §"Cross-recovery property", C-1.
- [x] the E2E output is **byte-stable** against the committed goldens under
  `bins/ethernal/tests/testdata/eoa/` — C-1 (frozen once).
- [x] no hidden entropy/time flag: determinism is via the fixed mnemonic through `account recover`;
  the fixed `Timestamp` is a `#[cfg(test)]` injection only — S-4.

**Test plan**
- Integration test driving the real command entrypoints end-to-end; assert per-index `address`
  (file-field + EIP-55), `0600` mode, filename parse, `crypto` internal consistency, and the BLS
  cross-recovery pubkey fixture; a second-run overwrite-refusal assertion.

**Notes**
- The EOA half is externally anchored (cast address vector); the BLS half is regression-locked from
  the same seed (the external BLS proof is A5-M against ethstaker-deposit-cli). This split is
  deliberate — see the cross-recovery note above.

---

## A5-2 — docs — USER-GUIDE `account` section, README, CHANGELOG

**Points:** 1 · **Stream:** B · **Depends on:** A5-1 · **Milestone:** M-A5

**Goal:** Document the new `account` namespace: the `account new` ceremony (TTY-only), `account
recover` (TTY or piped stdin), the flags, and the two security notes that matter for EOA (raw
`--mnemonic-passphrase` `ps`/history exposure; the v3 raw-passphrase interop rule). Satisfies U-1, U-3,
and the documentation half of C-2.

**Implementation notes**
- `docs/USER-GUIDE.md`: a new `account` section covering `account new` (generate → display → full
  re-entry → write, TTY-only) and `account recover` (TTY or piped stdin), the passphrase flows, and
  `--count`/`--output-dir`/`--start-index`. Note the output is a **Web3 v3 keystore** (geth/foundry/
  MetaMask-importable), distinct from the BLS `key` EIP-2335 v4 output.
- Carry the raw `--mnemonic-passphrase VALUE` **`ps`/shell-history** security note (visible in the
  process table; recommend the env/prompt forms; raw form is a scripting convenience, not for
  high-value mnemonics) — mirrors the keygen K4-2 note.
- Document the **v3 raw-passphrase** interop rule (C-4): the keystore passphrase is used as raw UTF-8
  bytes (no NFKD) to match geth/MetaMask — a non-ASCII passphrase behaves identically across tools.
- `README.md`: add `account new` / `account recover` to the command list / divergence table.
  `CHANGELOG.md`: record the **new `account` namespace** (v3 EOA keystores). No breaking change (the
  `key`/`gen` surface is untouched — U-3).

**Acceptance criteria**
- [x] USER-GUIDE documents `account new` (ceremony, TTY-only) and `account recover` (TTY/stdin), the
  flags, and the v3-vs-EIP-2335 distinction — U-1, U-3.
- [x] the raw `--mnemonic-passphrase` `ps`/shell-history exposure note is present, env/prompt
  recommended — architecture Design note (c) security note.
- [x] the v3 raw-passphrase interop rule (no NFKD) is documented — C-4.
- [x] README command list + CHANGELOG record the new `account` namespace; the `key`/`gen` docs are
  unchanged — U-3.

**Test plan**
- Docs review (no automated test); `make test && make lint` still green.

**Notes**
- No breaking change (unlike the keygen `gen` require-choice) — `account` is purely additive (Q1/U-3).

---

## A5-M — combined H9 + C-2 manual cross-tool parity session (unpointed, manual)

**Points:** — (unpointed manual gate) · **Stream:** manual (operator-run) · **Depends on:** A5-1
(release candidate) · **Milestone:** M-A5 (final gate)

**RESOLVED at the Stage-5 gate (user, 2026-07-18, binding): COMBINE.** H9 (BLS ethstaker parity) and
C-2 (EOA cast/geth/MetaMask parity) run as **ONE** operator session against the release candidate —
one shared mnemonic entered once, both trees verified in the same sitting, recorded in **both**
progress logs (this plan's M-A5 row and `../keygen/hardening-plan.md` H9 row). This is **manual**, run
once per release; it is the **sole consumer proof** for the EOA keystores (v1 ships no in-binary v3
reader). **Any mismatch blocks release** (C-2). Not a pointed issue.

**Why combined (recorded):** both are operator-run TTY sessions on the **same BIP-39 mnemonic**; the
cross-recovery property means one derivation run exercises both trees — enter the mnemonic once, verify
BLS signing/withdrawal pubkeys against ethstaker-deposit-cli **and** EOA addresses against `cast`/geth/
MetaMask in the same sitting. H9 is the only remaining BLS pre-release item, so there is no reason to
schedule two human sessions (project-plan §"Manual-session question").

**Operator script skeleton (Claude prepares the checklist; the user executes the TTY ceremony):**
1. **Pin and record versions:** `cast` (foundry) `<version>`, geth `<version>`,
   MetaMask `<version>`, **ethstaker-deposit-cli** `<version>` (the maintained fork — **not** the
   deprecated `staking-deposit-cli`), validator client `<name>@<version>`, OS. Record in both logs.
2. **Enter the shared mnemonic once** (a fresh `account new` mnemonic, or a known test mnemonic for a
   dry run) + the mnemonic passphrase used.
3. **EOA G2 — address parity (`cast`):** for `i ∈ 0..5`,
   `cast wallet address --mnemonic "<M>" [--mnemonic-passphrase "<p>"] --mnemonic-index i` equals our
   printed EIP-55 address `i`; repeat once with a **non-empty** mnemonic passphrase
   (research/cross-tool-parity.md §G2).
4. **EOA G1 — unlock a keystore we wrote:**
   - foundry: `cast wallet decrypt-keystore <name> --keystore-dir <dir> --unsafe-password <pw>` (or
     `cast wallet address --keystore <our UTC-- file> --password <pw>`) → private key whose address ==
     our address `i` (research/cross-tool-parity.md §G1 foundry).
   - geth: drop our `UTC--…` file into `<datadir>/keystore/`; `geth account list` sees it; unlock with
     the passphrase (our `n=262144,r=8,p=1` == geth standard). Re-confirm the exact unlock command on
     the geth box (§G1 geth).
   - MetaMask: *Import account → JSON File* → our keystore → passphrase; shown address == our address.
     Confirm the **raw-passphrase** path with a non-ASCII passphrase (the NFKD trap — §G1 MetaMask).
5. **BLS G2 — pubkey parity (ethstaker-deposit-cli):** same mnemonic + passphrase into
   ethstaker-deposit-cli and `ethernal key recover`; compare signing **and** withdrawal pubkeys
   index-for-index (keygen H9 step 2).
6. **BLS G1 — client import:** import an `ethernal`-created EIP-2335 keystore into ≥ 1 validator
   client; it decrypts and the client derives the same pubkey (keygen H9 step 3).
7. **Record** both outcomes (versions, non-secret inputs: indices/network/addresses, pass/fail, date)
   in this plan's M-A5 progress-log row **and** mirror into `../keygen/hardening-plan.md` H9 row.

**Acceptance criteria**
- [ ] **EOA G2** recorded pass: `cast wallet address` matches our address index-for-index across `i ∈
  0..5`, incl. one non-empty-mnemonic-passphrase case — C-2, G2.
- [ ] **EOA G1** recorded pass: a keystore we wrote unlocks in ≥ 1 of foundry / geth / MetaMask (aim
  for all three), incl. a non-ASCII-passphrase MetaMask case — C-2, G1.
- [ ] **BLS G2 + G1** recorded pass: ethstaker-deposit-cli pubkey parity index-for-index and a
  client import of our EIP-2335 keystore (keygen H9) — closes the open BLS gate.
- [ ] all tool/client versions pinned; results (pass/fail, date) recorded in **both** progress logs;
  any mismatch filed as a release-blocking issue — C-2, project-plan §"Manual-session question".

**Notes**
- v1 ships **no** in-binary v3 reader (Q3), so this external session is the only decrypt-direction
  proof for EOA — the automated A2-1/A5-1 gates prove **encrypt** only (project-plan R3).
- Real-terminal echo-off for both `account new` and `key new` ceremonies is exercised only here;
  confirm the display + re-entry behave on a real TTY during this session.
