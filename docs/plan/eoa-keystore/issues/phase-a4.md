# Phase A4 — `account recover` + mnemonic passphrase

**Theme:** The second `account` verb — reconstruct v3 keystores from an **existing** mnemonic (TTY
prompt or piped stdin, no ceremony), reusing the A3-4 pipeline; then close out the three-form BIP-39
mnemonic passphrase (F-12) across **both** commands with the seed-derivation anchor. Stream A.
**Issues:** A4-1, A4-2 · **Points:** 3 · **Execution:** after A3-4 (the shared pipeline).
**Milestone gate — M-A4:** `account recover` green — mnemonic from interactive TTY **or** piped stdin
(no ceremony), `validate_mnemonic` first (12/15/18/21/24 words; bad word → 1-based position, exit 2;
bad checksum → exit 2), `--start-index`/`--count` selects `[start, start+count)`, three-form
`--mnemonic-passphrase` (raw argv / `-env` / bare-prompt, empty default) exercised.

Signatures/wire points from [`architecture.md`](../architecture.md) §"Data flow — `account recover`",
§"bin — `account_cli`/`account_cmd`"; reuse inventory from
[`research/existing-code-map.md`](../research/existing-code-map.md).

---

## A4-1 — `account recover` — TTY-or-piped-stdin mnemonic, validate-first, range

**Points:** 2 · **Stream:** A · **Depends on:** A3-4 · **Milestone:** M-A4

**Goal:** Implement `account recover` reusing the A3-4 derive→address→encrypt→filename→write pipeline,
reading an **existing** mnemonic from an interactive TTY prompt or piped stdin (no display/re-entry
ceremony), validating it first, and deriving over `--start-index`/`--count`. Satisfies F-10 (stdin/TTY),
F-11 (12–24-word validation + range), F-16, and the S-1/S-2 hygiene of the **stdin input surface**.

**Implementation notes**
- Add `run_account_recover_with_deps(deps, cancel)` + its production wrapper `run_account_recover(cfg,
  cancel)` to `bins/ethernal/src/account_cmd.rs`; `main.rs` (from A3-3) dispatches to the wrapper.
  Reuse the A3-4 pipeline **unchanged** (same derive→address→encrypt→filename→`write_new_0600` tail).
- Read the mnemonic from an interactive TTY prompt **or** piped stdin via the reused
  `RecoverMnemonicSource` / `StdinMnemonicSource` (widened in A3-2). The `account new` TTY-only guard
  does **not** apply here (F-10).
- Call `bip39::validate_mnemonic` (reused) **first**; accept 12/15/18/21/24 words; a bad word (by
  **1-based position**, never the token — H1) or bad checksum → exit 2 with a specific message (F-11).
- `--start-index N` / `--count N` select `[start, start+count)`.
- Resolve the mnemonic passphrase (flag>env>prompt) as in A3-4, but the **bare prompt is
  single-entry** here (the mnemonic already exists — no confirm). A4-2 hardens/tests all three forms.

**Acceptance criteria**
- [x] `account recover` reads the mnemonic from an interactive TTY prompt **or** piped stdin
  (`echo "$M" | ethernal account recover …`) — F-10.
- [x] `validate_mnemonic` runs first; 12/15/18/21/24-word mnemonics accepted; a bad word → exit 2
  reporting the **1-based position** (never the token, H1); a tampered checksum → exit 2 — F-11, F-16,
  S-2.
- [x] `--start-index N` / `--count N` select the range `[start, start+count)` and produce matching
  per-index `UTC--…` filenames/addresses — F-11.
- [x] there is **no** display/re-entry ceremony — F-10.
- [x] produced keystores are identical in shape to `account new` output (v3, `crypto`/`address`
  internally consistent, `0600`) — F-3.
- [x] **recover-stdin secret hygiene (S-1/S-2):** the mnemonic read from piped stdin, the derived
  seed, chain codes, and secret scalars never reach stdout/stderr/logger (the stdin path is a distinct
  input surface from the `account new` ceremony); a bad word is reported by 1-based position, not the
  token — S-1, S-2, G5.

**Test plan**
- `AccountDeps`-seam tests: piped-stdin mnemonic (12-word and 24-word) → v3 keystores internally
  consistent; bad word → exit 2 with 1-based position; tampered checksum → exit 2; `--start-index 5
  --count 3` yields indices 5,6,7 in the filenames; the TTY-prompt path via an injected `mnemonic_src`.
- A stdin-hygiene assertion extending the A3-5 harness: a fixed mnemonic piped in never appears in
  captured stdout/stderr/logger; seed/chain-code/scalar bytes absent.

**Notes**
- `recover` accepts stdin; `account new` stays TTY-only — the gate is new-only (F-5/F-10).

---

## A4-2 — three-form mnemonic passphrase across both commands + seed anchor

**Points:** 1 · **Stream:** A · **Depends on:** A4-1 · **Milestone:** M-A4

**Goal:** Close out F-12: verify the three-form `--mnemonic-passphrase` (raw argv / `-env` /
bare-prompt) is **fully honored** on **both** `account new` (confirm bare-prompt) and `account recover`
(single-entry bare-prompt), with the empty default, and add the seed-derivation anchor test proving the
passphrase actually reaches `bip39::to_seed`. Satisfies F-12 (both subcommands), C-1.

**Implementation notes**
- The three-form **logic** is reused verbatim from keygen (`MnemonicPassphraseForm` +
  `resolve_mnemonic_passphrase`, widened in A3-2, already unit-tested on the BLS side). A3-4 already
  wires it for `new`; A4-1 for `recover`. This issue is the **consolidated F-12 completeness +
  cross-command test** pass — not new plumbing — so its weight is in tests, not code (flagged in
  `summary.md` sizing).
- Ensure the confirm-vs-single-entry distinction is correct: bare-prompt on `new` is **double-entry**
  (confirm), on `recover` is **single-entry**; raw argv and `-env` forms behave identically on both;
  empty is the default and is **valid** (the mnemonic passphrase has no ≥8 minimum — that is the
  keystore passphrase, F-7).
- Do **not** leave either command parsing `--mnemonic-passphrase` while ignoring it — both must feed
  the resolved passphrase into `to_seed`. (Guard against the parse-but-ignore trap.)

**Acceptance criteria**
- [ ] all three forms resolve on `account new`: raw `--mnemonic-passphrase VALUE`,
  `--mnemonic-passphrase-env VAR`, and bare `--mnemonic-passphrase` (**confirm**); absent → empty —
  F-12.
- [ ] all three forms resolve on `account recover`: raw / `-env` / bare (**single-entry**); absent →
  empty — F-12.
- [ ] the resolved passphrase changes the seed and thus the derived addresses: a **seed-derivation
  anchor** test asserts a fixed mnemonic + a known mnemonic passphrase → a known seed feeding
  `derive_path` (proving the passphrase is not ignored on either command) — F-12, C-1.
- [ ] an **unset** `--mnemonic-passphrase-env VAR` → exit 2; an **empty** value is accepted (empty is
  valid for the mnemonic passphrase) — F-12.
- [ ] the mnemonic passphrase is `Zeroizing` and never rendered (covered by the A3-5/A4-1 hygiene
  harness extended to both passphrase forms) — S-1, S-2.

**Test plan**
- Cross-command `AccountDeps`-seam tests: each of the three forms on `new` and on `recover`; the
  confirm (new) vs single-entry (recover) bare-prompt behavior; empty default; unset-env → exit 2.
- The seed-derivation anchor: fixed mnemonic + passphrase → known seed (inline hex) → known first
  address, asserting a non-empty passphrase yields a **different** address than the empty-passphrase
  run.

**Notes**
- Kept as a distinct issue (not folded into A4-1) per the plan's A4 = 2-issue cut, which the phase
  point total depends on. Because the three-form logic is reused verbatim, the issue is deliberately
  test-heavy; it is the single traceable home for F-12's both-commands acceptance.
