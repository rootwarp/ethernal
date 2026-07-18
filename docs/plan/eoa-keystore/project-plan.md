# Project Plan — EOA Keystore Generation (`account new` / `account recover`)

**Scope:** Add a new top-level `ethernal account` namespace — `account new` and `account recover` —
that turns a BIP-39 mnemonic into secp256k1 EOA keys via BIP-32/BIP-44 (`m/44'/60'/0'/0/i`)
derivation and writes **Web3 Secret Storage v3** (scrypt) keystores that geth, foundry (`cast`), and
MetaMask import and unlock. v1 is keystore **creation only**; in-binary consumption
(`ethernal sign --keystore`) and the v3 *reader* are an explicit follow-up (Q3 veto). The BLS `key`
namespace is untouched (Q1 binding). Closes the "no encrypted EOA key at rest" gap the PRD opens.
**Inputs:** [`prd.md`](prd.md) (approved, two binding vetoes — Q1 new `account` namespace, Q3
`sign --keystore` deferred), [`architecture.md`](architecture.md) (module boundaries, real
signatures, secret lifecycle, the `zeroize`-feature confirm-at-implementation flag),
[`research/`](research/) (D-1 hand-roll verdict, verified CI fixtures, cross-tool-parity commands),
and the sibling [`../keygen/project-plan.md`](../keygen/project-plan.md) whose structure this mirrors.
Phases/milestones are re-derived from the **approved architecture**; the concrete issue cut is Stage 6.
**Sizing:** 1 story point ≈ half a working day (keygen scale). Every issue ≤ 3 pts, each ≈ 1–2 days.
**Streams:** A = derivation primitive → account integration → recover → E2E (critical path);
B = v3 keystore writer, `signer::secret_to_address`, `pub(crate)` widening, docs (parallel).
**Merge model:** per-issue fast-forward on `develop`, tags `[A#-#]` (letter `A` = account; never
collides with keygen `K`/`H`); every merge green (`make test && make lint`). No Go reference exists —
verification anchors are published spec vectors (BIP-32/BIP-44), a byte-for-byte v3 encrypt vector,
and the manual cross-tool session (C-2), not byte-parity against a Go binary.

**Relationship to the BLS keygen pipeline (verified against git, 2026-07-18):** the keygen hardening
plan H1–H8 is **already merged** into both `develop` and `main` (commits `1822893`..`c1b662e`); only
**H9** (the manual parity session, no code) is open. This differs from the Stage-5 briefing, which
described H1–H9 as "not yet implemented" — see [H-plan sequencing](#h-plan-sequencing-recommendation).
The practical consequence: there is **no in-flight H-code** on the `key_cli`/`key_cmd` files this
feature widens, so the `pub(crate)` reuse-in-place (architecture note (c)) carries near-zero
merge-conflict risk and the EOA feature can start on `develop` immediately.

---

## Deltas from the suggested seams (Stage-5 briefing → this plan)

The briefing proposed five seams; this plan keeps all five and adjusts placement, not boundaries.

| Delta | Briefing suggested | This plan | Why |
|---|---|---|---|
| H-sequencing premise | "H1–H9 not yet implemented; sequence EOA to minimize conflict with H1–H8 touching `key_cli`/`key_cmd`" | H1–H8 **already merged** (git-verified); no conflict to sequence around; only H9 (manual) remains | Primary-source git state overrides the briefing; the whole "which goes first" question is moot — see below |
| `signer::secret_to_address` | Bundled inside seam (3), the account-integration phase | Kept in **Phase A3** but assigned to the **parallel stream B** | Independent of A1/A2; pulling it off the critical path shortens it |
| `pub(crate)` widening of `key_cli`/`key_cmd` | Bundled inside seam (3) | Kept in **A3**, assigned to **stream B**, and flagged safe-to-land-anytime | Visibility-only churn, no dependency on A1/A2, and (now) no H-code conflict |
| `account new` secret-hygiene test | Implied in seam (5) E2E | Placed in **A3** (where the leak surface — the ceremony + per-index loop — is built) | Mirrors keygen K3-4 (hygiene lived in the CLI phase, not E2E) |
| Manual parity session (C-2) | Seam (5), standalone | Recommended **combined with H9** into one operator session | Both are TTY sessions on the same mnemonic; cross-recovery means one derivation exercises both trees — see [Combine question](#manual-session-question-combine-c-2-with-h9) |

Otherwise the seams are unchanged: (A1) `core::hd_secp256k1` + vectors; (A2) `keystore::encrypt_v3`
+ MAC + filename + fixtures; (A3) `signer::secret_to_address` + `account` namespace + ceremony reuse;
(A4) `account recover` + mnemonic passphrase; (A5) E2E fixtures + docs + manual parity.

## Phase decomposition sanity-check (issue cut is Stage 6)

Per the Stage-5 charter, this plan defines **phases and milestones**, not individual issues. The table
below is a *sanity-check* that each phase decomposes into 1–2-day (≤ 3 pt), independently-mergeable
issues — it is **not** the committed issue list. Stage 6 cuts the actual `[A#-#]` issues from the
architecture and may re-split within a phase.

| Phase | Theme | Pts | Stream | ≈ issues (Stage-6 guide) | Depends on |
|---|---|---|---|---|---|
| **A1** | `core::hd_secp256k1` — hand-rolled BIP-32 secp256k1 | 4 | A | 2 — (a) primitive `ExtendedPrivKey` master/child + `k256` dep & `zeroize` feature + BIP-32 TV1 [3]; (b) `Bip44Path` + `derive_path` + Ethereum BIP-44 `abandon` vector [1] | — |
| **A2** | `keystore::encrypt_v3` — Web3 v3 writer + MAC + filename | 4 | B | 2 — (a) `crypto::v3_mac` + `sha3` dep + `encrypt_v3` + v3 structs + G3 byte-gate + round-trip [3]; (b) `v3_filename` hand-rolled `civil_from_days` + vector [1] | — |
| **A3** | `signer::secret_to_address` + `account` namespace + ceremony reuse | 7 | A (+B) | 5 — helper+export [1·B], `pub(crate)` widening [1·B], `account_cli`+`AccountConfig` [2·A], `account_cmd` pipeline + `AccountDeps` + `main`/`errors` wiring [2·A], `account new` secret-hygiene + exit-map [1·A] | A1, A2 |
| **A4** | `account recover` + mnemonic passphrase | 3 | A | 2 — recover from TTY-or-piped-stdin, validate-first, `--start-index`/`--count` range, reuse pipeline [2]; three-form mnemonic-passphrase wiring + tests [1] | A3 |
| **A5** | E2E integration + docs + manual parity | 3 (+ manual) | A (docs·B) | 2 — E2E fixture: fixed mnemonic → `account recover` → v3 keystores, cross-recovery property, 0600/filename/address asserts [2]; docs USER-GUIDE/README/CHANGELOG [1·B] | A4 |

**Total: ~21 points** (≈ 10.5 person-days single-dev) across ~13 issues + one unpointed manual
session — deliberately **lighter than the keygen's 23 pts / 14 issues** because EOA **reuses** the
entire front half keygen had to *build*: `core::bip39`, `core::entropy`, `core::output::write_new_0600`,
the display/re-entry ceremony, `NewKeystorePassphrase`/`require_min_len`, and the three-form mnemonic
passphrase. The genuinely new work is the BIP-32 secp256k1 primitive (A1), the v3 writer (A2), and the
thin `account` integration that composes them (A3). With the A/B split the **critical path is ~15 pts**
(stream A: A1 → A3-integration → A4 → A5); stream B's work (A2 = 4, `secret_to_address` = 1, widening
= 1, docs = 1 ≈ 6 pts overlapping) runs alongside and joins at A3.

Phase numbers are **thematic**; the `Depends on` column and the streams drive execution order.

## Per-phase milestones

| Phase | Theme | Pts | Milestone (gate) — concrete exit criterion |
|---|---|---|---|
| A1 | Derivation primitive | 4 | **M-A1:** BIP-32 Test Vector 1 (master + hardened `m/0'` + non-hardened `m/0'/1`, **keys *and* chain codes**) **and** the Ethereum BIP-44 vector (`abandon…about`, empty passphrase, `m/44'/60'/0'/0/{0,1}`, secrets + EIP-55 addresses `0x9858…Eda94` / `0x6Fac…b9C0` matching `cast`) green in CI. **`k256` `zeroize` feature resolved:** either `Scalar: Zeroize` compiles and `ExtendedPrivKey::drop` scrubs the scalar, or the byte-form/chain-code `Zeroizing` floor is documented as the guarantee (Risk R1). |
| A2 | v3 keystore writer | 4 | **M-A2:** the G3 byte-gate reproduces the verified `cast` fixture **byte-for-byte** — injected `{secret, password=testpassword (raw), salt, iv, n=8192,r=8,p=1}` → `ciphertext == a5ae5118…` and `mac == 8163019b…`; self encrypt-side round-trip green; `secret.len()!=32` rejected (→ exit 3); `v3_filename` fixed vector (`…T14-22-05.123456789Z--<addr>`) green. |
| A3 | `account new` integration | 7 | **M-A3:** `account new` green — TTY-only guard (non-TTY → exit 2 before any generation), display + full re-entry ceremony (mismatch/abort → exit 4, nothing on disk), `--count N` writes N v3 files at `0600` with parsing `UTC--` filenames, EIP-55 addresses in the stderr summary; `signer::secret_to_address` vectors (abandon addresses + non-canonical/zero scalar → `InvalidKey`) green; **secret-hygiene test green** (mnemonic/seed/chain-code/scalar/both passphrases never on stdout/stderr/logger — BLS `no_secret_in_logs` harness reused). |
| A4 | `account recover` | 3 | **M-A4:** `account recover` green — mnemonic from interactive TTY **or** piped stdin (no ceremony), `validate_mnemonic` first (12/15/18/21/24 words; bad word → 1-based position, exit 2; bad checksum → exit 2), `--start-index`/`--count` selects `[start, start+count)`, three-form `--mnemonic-passphrase` (raw argv / `-env` / bare-prompt, empty default) exercised. |
| A5 | Integration & release | 3 (+ manual) | **M-A5 (final):** E2E fixture frozen — fixed mnemonic → `account recover` → v3 keystores, filenames parse, `0600`, addresses match; **cross-recovery property** shown (same seed feeds BLS `m/12381/3600/…` and EOA `m/44'/60'/0'/0/…`); docs shipped (USER-GUIDE `account` section, README, CHANGELOG). **C-2 manual cross-tool parity session recorded** with pinned versions — `cast wallet address` parity index-for-index (G2) **and** a keystore we wrote unlocks in geth / `cast wallet import` / MetaMask (G1); any mismatch **blocks release**. |

## Dependency graph & parallel streams

```
stream A (critical path, ~15 pts)
  A1 hd_secp256k1 ─────────────┐
                               ├─▶ A3 account_cli+account_cmd ─▶ A4 recover ─▶ A5 E2E + docs + manual parity
stream B (parallel, ~6 pts, joins at A3)                        (M-A4)         (M-A5, final gate)
  A2 encrypt_v3 ───────────────┤
  signer::secret_to_address ───┤
  pub(crate) widening ─────────┘
     (all three feed A3's integration; none depend on A1)
```

- **A1 ∥ A2** — different crates (`core` vs `keystore`), no shared edge; run as parallel streams from
  day one. A2 (4 pts) ≤ A1 (4 pts), so A2 is off the critical path as long as A1 runs alongside it.
- **A3 is the join** — its `account_cmd` pipeline needs A1 (`derive_path`), A2 (`encrypt_v3`), the
  `signer::secret_to_address` bridge, and the widened `pub(crate)` items. The three stream-B pieces
  (v3 writer, signer helper, widening) can all land **before** A1 finishes; the widening in particular
  is safe to land at any point now that H1–H8 are merged (no in-flight edits to `key_cli`/`key_cmd`).
- **A4 → A5** are sequential on stream A after A3; docs in A5 are stream B and can draft in parallel
  with A4.

## H-plan sequencing recommendation

**Finding (git-verified, 2026-07-18):** the Stage-5 briefing states the keygen hardening plan
"H1–H9 … is NOT yet implemented." The repository disagrees. `git log` shows **H1–H8 merged** to both
`develop` and `main` (commits `1822893` H1 … `c1b662e` H8, all ancestors of `develop`), and the
hardening plan's own progress log ([`../keygen/hardening-plan.md:442-450`](../keygen/hardening-plan.md))
independently marks H1–H8 `done`. Only **H9** — the *manual* cross-tool parity session, which changes
no code and only records results in the progress log — is open. Two independent sources agree; this is
a briefing/repo discrepancy to reconcile, not a blocker.

**Recommendation — proceed with EOA on `develop` now; no H-code interleaving is required.**
The briefing's concern (that the architecture's `pub(crate)` widening of `key_cli`/`key_cmd` would
collide with H1–H8, which touch the same files) is **moot**: H1–H8 are settled and merged, so those
files are stable and the widening lands with near-zero conflict risk. There is nothing to sequence
"first" — the only remaining BLS pre-release item is H9, a manual session that neither blocks nor is
blocked by any EOA code phase. EOA phases A1–A5 and H9 can proceed independently; they meet only at the
optional combined manual session below.

## Manual-session question (combine C-2 with H9?)

**RESOLVED at the Stage-5 gate (user, 2026-07-18, binding): COMBINE.** H9 and C-2 run as ONE
operator session against the release candidate — one shared mnemonic entered once, BLS parity
(ethstaker-deposit-cli) and EOA parity (`cast`/geth/MetaMask) verified in the same sitting,
recorded in both progress logs (this plan's M-A5 and `../keygen/hardening-plan.md` H9). Stage 6
writes the combined session as a single manual issue. Original recommendation kept below for the
record.

**Recommendation: combine into one operator session — flag for the user gate, do not decide here.**
Both C-2 (this feature's [M-A5](#per-phase-milestones) release gate — `cast`/geth/MetaMask address
parity + unlock) and H9 (the keygen's open gate — ethstaker-deposit-cli pubkey parity + validator
client import) are **operator-run TTY sessions**, both need a human at a terminal, and both derive from
the **same BIP-39 mnemonic**. The PRD's cross-recovery property (`prd.md` — one seed → BLS
`m/12381/3600/i/0/0` *and* EOA `m/44'/60'/0'/0/i`) means a **single** derivation run exercises both
trees at once: enter the mnemonic once, verify BLS signing pubkeys against ethstaker-deposit-cli **and**
EOA addresses against `cast`/geth/MetaMask in the same sitting. Combining is now especially clean
because H9 is the *only* remaining BLS task — there is no reason to schedule two separate human
sessions. This is a scheduling/gating decision for the user, not the planner; recorded here as a
recommendation for the release gate.

## Verification strategy

Each milestone is gated by the vector(s) that prove the boundary beneath it (all values in the research
docs — `research/bip32-secp256k1.md`, `research/web3-v3-keystore.md`):

1. **M-A1** — **BIP-32 Test Vector 1** (master + `m/0'` + `m/0'/1`, comparing keys *and* chain codes,
   covering both the hardened and non-hardened CKDpriv branches) + the **Ethereum BIP-44** vector
   (`abandon…about`, empty passphrase, `m/44'/60'/0'/0/{0,1}` → secrets + EIP-55 addresses matching
   `cast wallet`). The BIP-32 `I_L ≥ n` / `k_i = 0` skip rule is a rejection test, not a silent path.
2. **M-A2** — the **G3 v3 encrypt byte-gate**: inject the verified `cast` fixture's
   `salt`/`iv`/`secret`/`password`(raw)/`n=8192` and assert `ciphertext` and `mac` byte-for-byte
   (`a5ae5118…` / `8163019b…`); the fixture also proves the pipeline decrypts (`cast wallet
   decrypt-keystore` round-trips it, an *external* oracle — v1 ships no in-binary v3 reader). Plus a
   self encrypt-side round-trip and a `secret.len()!=32` rejection. `v3_filename` has its own fixed
   vector proving the hand-rolled `civil_from_days`.
3. **M-A3** — the `AccountDeps` seam drives the ceremony off-terminal (`FixedEntropy` for
   mnemonic+salt/iv/uuid, scripted mnemonic/passphrase sources, fixed `Timestamp`, buffers); a non-TTY
   integration test asserts the `account new` guard exits 2; the secret-hygiene test (reusing the BLS
   `no_secret_in_logs`/`redact_boundary` harness) asserts mnemonic/seed/chain-code/scalar/both
   passphrases never reach stdout/stderr/logger. `signer::secret_to_address` gets the abandon-address
   vector + non-canonical-scalar rejection.
4. **M-A4** — command-level tests: piped-stdin and prompt mnemonic sources; 12–24-word acceptance;
   bad word → 1-based position + exit 2; bad checksum → exit 2; `--start-index`/`--count` range.
5. **M-A5 (E2E, automated)** — a fixed mnemonic (no entropy injection — determinism comes from
   `account recover`, so **no hidden entropy/time flag ships**, S-4) → per-index committed v3 keystores;
   one fixture chains BIP-39 → BIP-32/BIP-44 → v3-encrypt → address; the cross-recovery property is
   asserted by deriving both trees from the one seed.
6. **M-A5 (cross-tool, manual, once per release — the SOLE consumer proof, C-2/C-3)** — recorded in the
   [progress log](#progress-log), **not** a pointed issue: `cast wallet address --mnemonic … --mnemonic-index i`
   == our address (G2); `cast wallet decrypt-keystore` / geth `account import` / MetaMask unlock a
   keystore we wrote (G1). Mechanical checklist in `research/cross-tool-parity.md`; pin every tool
   version; any mismatch blocks release. (Because v1 has **no** in-binary v3 reader, this external
   session is the only decrypt-direction proof — the automated gate proves encrypt only.)

## Risks

| # | Risk | Mitigation |
|---|---|---|
| R1 | **`k256` `zeroize` feature may not compile / `Scalar` may not `impl Zeroize`.** The architecture's live-scalar scrubbing (`ExtendedPrivKey::drop → scalar.zeroize()`) needs `k256`'s `zeroize` feature enabled; the D-1 empirical run used only `["ecdsa","std"]`, so `Scalar: Zeroize` under the added feature is **unproven** — the one genuinely unverified thing in the feature. | **Confirm at implementation (A1, first issue).** If it compiles, enable the feature (already-vendored, no new crate; also touches `signer`'s `k256`, harmless). If not, the **guaranteed floor stands**: all serialized 32-byte key forms and **all chain codes** are `Zeroizing`, matching the API-boundary guarantee `signer` already gives. M-A1's exit criterion names this decision explicitly; whichever branch is taken is documented, not papered over. |
| R2 | **Passphrase-normalization trap.** Reusing the EIP-2335 `crypto::normalize_passphrase` (NFKD) for v3 would make any non-ASCII passphrase produce a keystore geth/MetaMask cannot unlock → breaks G1/C-2 (the hard release gate). | Architecture C-4 is binding: `encrypt_v3` feeds **raw** passphrase bytes to `derive_scrypt`, never calls `normalize_passphrase`. Enforced by the G3 byte-gate (uses raw `testpassword`) and the manual session; add a test asserting a non-ASCII passphrase keystore unlocks in `cast`. |
| R3 | **Cross-tool parity is the only consumer proof and it's manual.** v1 ships no in-binary v3 reader (Q3), so a wrong-but-plausible keystore would pass every automated encrypt test yet fail to unlock in real tooling. | The G3 byte-gate anchors encrypt against a *real* `cast`-produced fixture (not a self-generated golden); the mandatory per-release C-2 session (M-A5) is the release gate; recommend combining with H9 so it is actually run, not deferred. |
| R4 | **scrypt-profile mismatch across tools.** `cast wallet import` writes light `n=8192`; geth and our production writer use standard `n=262144`. A byte-equality parity attempt would spuriously fail. | Both are read-compatible (readers take `n` from `kdfparams`). Parity is proved by **decrypt/unlock + address match, not byte-equality**; `ScryptParams` is injectable so the CI byte-gate runs at `n=8192` while production emits `n=262144` (architecture, `research/web3-v3-keystore.md`). |
| R5 | **`pub(crate)` widening churns the mid-hardening BLS `key_cmd`/`key_cli`.** The reuse-in-place touches the ~1900-line `key_cmd.rs`. | **Largely retired:** H1–H8 are merged (git-verified), so no H-code is in flight on these files. The change is visibility-only (no behavior change), gated by the existing `key_cmd`/`key_cli` suite staying green; land it early on `develop` (stream B) while conflict risk is lowest. |
| R6 | **Hand-rolled `civil_from_days` UTC conversion for the `UTC--` filename.** No `chrono`/`time` in the workspace; a wrong calendar conversion yields a filename geth's keystore dir may not recognize. | Pure function, unit-tested against a fixed vector (M-A2); ~15 lines, no `unsafe`; the manual session confirms geth accepts the real filename. |

## Progress log

| Issue | Status | Commit | Gate result |
|---|---|---|---|
| A3-2 | done | 1b85734 | pub(crate) widening of key_cli/key_cmd; BLS suite green |
| A1-1 | done | f1f0507 | BIP-32 TV1 keys+cc; R1 scalar scrubbed on drop |
| A1-2 | done | 0d7aaad | Bip44Path + derive_path; abandon secrets vs cast |
| A2-1 | done | 0de013b | G3 byte-gate + C-4 raw passphrase + encrypt_v3 |
| A2-2 | done | e5dfbc1 | v3_filename + civil_from_days fixed vector |
| A3-1 | done | 8d9d21f | secret_to_address + abandon EIP-55 addresses |
| A3-3 | done | (this commit) | account clap namespace + AccountConfig + TTY guard |
| A1 | done | — | M-A1 closed (secrets + addresses) |
| A2 | done | — | M-A2 closed |
| M-A1 | done | | BIP-32 TV1 + BIP-44 secrets + addresses; R1 scalar on drop |
| M-A2 | done | | G3 encrypt byte-gate + round-trip + v3_filename |
| A3 | todo | — | A3-4..A3-5 remaining |
| M-A3 | open | | `account new` ceremony + TTY guard + 0600 v3 files + secret-hygiene |
| A4 | todo | — | |
| M-A4 | open | | `account recover` TTY/stdin, 12–24-word + 1-based bad word, range, mnemonic passphrase |
| A5 | todo | — | |
| M-A5 | open | | E2E fixture frozen + cross-recovery + docs; **manual C-2 parity session** |
