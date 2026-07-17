# Issue Overview — Validator Key Generation (`key new` / `key recover`)

**Scope:** New capability for `eth-deposit`: generate BLS12-381 validator keys from a
BIP-39 mnemonic via EIP-2333/EIP-2334 hierarchical derivation, and write them as
EIP-2335 v4 keystores that (a) our own `gen` subcommand and (b) mainstream validator
clients (Lighthouse, Teku, Prysm, Nimbus) can import. This closes the gap at the front
of the pipeline — today `gen` requires keystores produced by an external tool
(staking-deposit-cli); after this feature the full flow is in one binary:
`key new → gen → build → sign → send`.
**Sizing:** 1 story point ≈ half a working day. Every issue ≤ 3 pts.
**Streams:** A = derivation primitives → CLI; B = keystore encrypt/write (parallel after K1-3).
**Merge model:** per-issue fast-forward on develop, tags `[K#-#]`; every merge green
(`make test && make lint`).

---

## Locked design decisions

| Area | Decision | Rationale |
|---|---|---|
| EIP-2333 derivation | `blst::min_pk::SecretKey::{derive_master_eip2333, derive_child_eip2333}` (blst 0.3.16, already a dep) | Upstream-audited implementation used by consensus clients; gated by the EIP-2333 official test vectors — no hand-rolled Lamport/HKDF tree |
| EIP-2334 paths | signing `m/12381/3600/i/0/0`, withdrawal `m/12381/3600/i/0`; own path model/parser | Trivial (4 fixed levels + index); matches staking-deposit-cli |
| BIP-39 mnemonic | hand-rolled: embedded English wordlist (2048 words), 256-bit entropy → 24 words default, checksum validation accepts 12/15/18/21/24 on recover, seed = PBKDF2-HMAC-SHA512(2048, NFKD) | Repo philosophy: auditable minimal-dep encoding verified by official vectors (as for SSZ/RLP/ABI); uses existing `sha2`/`pbkdf2`/`hmac` deps. English only in v1 |
| EIP-2335 encrypt | scrypt profile only (n=262144, r=8, p=1, dklen=32), AES-128-CTR, sha256 checksum — extend `crates/keystore` (decrypt-side Envelope model becomes bidirectional) | Same profile staking-deposit-cli writes; decrypt already supports pbkdf2 for imports, no need to *write* it |
| RNG | new dep `getrandom` behind a small `Entropy` trait (OS impl + deterministic test impl); UUID v4 formatted from 16 random bytes (no uuid crate) | Only new dependency; injectable RNG is what makes keystore creation unit-testable against fixed-salt/iv/uuid spec vectors |
| Output files | `keystore-m_12381_3600_i_0_0-<unixtime>.json`, atomic 0600 write (reuse `core::output` atomic writer), refuse to overwrite | staking-deposit-cli naming → validator clients' import tooling recognizes it |
| Mnemonic UX (`key new`) | TTY only (non-TTY → exit 2); mnemonic printed once, then full re-entry confirmation before any keystore is written | Same ceremony as staking-deposit-cli; a mnemonic on a pipe/log is unrecoverable exposure |
| Passphrase | reuse `PassphraseSource` (prompt-with-confirm default, `--passphrase-env` for automation); enforce ≥ 8 chars | Matches existing gen flags and staking-deposit-cli's minimum |
| Zeroization | mnemonic string, entropy, seed, every derived SK, passphrase — `Zeroizing`/`zeroize` throughout, same as `keystore::Key` | Established repo invariant: no key material survives scope or appears in logs/errors |
| Exit codes | 0 ok, 2 user/config, 3 crypto/keystore-write, 4 SIGINT abort (5 unused — no RPC) | Existing contract |
| CLI shape | `eth-deposit key new`, `eth-deposit key recover` (nested `key` namespace) | Keeps the 5 existing verbs flat; groups future key ops (`key inspect`, …) |

**No Go reference exists for this feature** — `porting-conventions.md` byte-parity rules
do not apply. The verification anchors are the public spec vectors and cross-tool
compatibility (below).

---

> **SUPERSEDED (2026-07-17, detail-planning pipeline):** the issue skeleton below
> was the planning seed. The canonical plan is now `project-plan.md` (14 issues /
> 23 pts, phases K1–K5, execution order K1→K2/K3→K5→K4) with sprint-ready detail
> in `issues/phase-k*.md`. Requirements: `prd.md`; design: `architecture.md`;
> verified spec facts and fixtures: `research/`.

## All issues (original skeleton — superseded, see note above)

| ID | Title | Pts | Stream | Depends on |
|---|---|---|---|---|
| K1-1 | `core::bip39` — wordlist, entropy→mnemonic, checksum validation, mnemonic→seed (NFKD, PBKDF2-HMAC-SHA512×2048), zeroizing types + Trezor vectors | 2 | A | — |
| K1-2 | `core::hd` — EIP-2334 path model/parser; seed → master → signing/withdrawal SK per index via blst; pubkey derivation + EIP-2333 vectors | 1 | A | K1-1 |
| K1-3 | Entropy plumbing — `getrandom` dep, `Entropy` trait (OS + deterministic test impl), UUID-v4 formatter + tests | 1 | A | — |
| K2-1 | `keystore::encrypt` — bidirectional Envelope model; NFKD passphrase → scrypt → AES-128-CTR → checksum; `path`/`uuid`/`pubkey`/`description` fields; EIP-2335 scrypt spec vector reproduced byte-for-byte on fixed salt/iv/uuid; round-trip via existing `Loader`; wrong-passphrase rejected | 3 | B | K1-3 |
| K2-2 | `keystore::write` — filename convention, atomic 0600 write, overwrite refusal, output-dir validation + tests | 1 | B | K2-1 |
| K3-1 | bin `key new` — clap schema (`--count`, `--output-dir`, passphrase flags), mnemonic display + full re-entry confirm, TTY guards, per-key progress + summary, SIGINT abort-clean + tests (injected Entropy/prompt) | 3 | A | K1-2, K2-2 |
| K3-2 | bin `key recover` — mnemonic prompt (TTY) or stdin (piped), `--start-index`/`--count`, same write path + tests | 2 | A | K3-1 |
| K3-3 | Exit/error mapping + secret-hygiene test — key errors → 2/3/4; redact-style boundary test asserting mnemonic/seed/SK bytes never reach stdout/stderr/logs | 1 | A | K3-1, K3-2 |
| K4-1 | E2E + fixtures — fixed test mnemonic → `key recover` → keystores → `gen` → BLS-verified deposit data (full in-binary pipeline); committed fixture: expected signing/withdrawal pubkeys per index for the test mnemonic | 2 | A | K3-3 |
| K4-2 | Docs — USER-GUIDE “Step 0 — create validator keys”, README, CHANGELOG; security guidance (mnemonic handling, air-gapped keygen) | 1 | B | K4-1 |

**Total: 17 points** (≈ 8.5 person-days single-developer; K2-x overlaps K1-x/K3-x).

## Per-phase milestones

| Phase | Theme | Issues | Milestone (gate to next phase) |
|---|---|---|---|
| K1 | Derivation primitives | K1-1..3 | **M-K1:** BIP-39 Trezor vectors + EIP-2333 vectors green |
| K2 | Keystore creation | K2-1..2 | **M-K2:** EIP-2335 scrypt spec vector reproduced; created keystore round-trips through existing decrypt `Loader` |
| K3 | CLI | K3-1..3 | **M-K3:** `key new`/`key recover` green incl. TTY ceremony tests; secret-hygiene test green |
| K4 | Integration | K4-1..2 | **M-K4:** in-binary `key recover → gen` E2E green; one manual cross-tool session (below) recorded in this file |

## Verification strategy

1. **BIP-39** — official Trezor test vectors (entropy → mnemonic → seed).
2. **EIP-2333** — the EIP's published test cases (master SK from seed, child SK at index).
3. **EIP-2334** — path derivation cases for signing/withdrawal at several indices.
4. **EIP-2335** — the spec's scrypt test vector: with the vector's salt/iv/uuid injected
   through the `Entropy` trait, our encrypt output must reproduce the spec JSON's
   `crypto` section byte-for-byte; then decrypt with the vector passphrase via the
   *existing* decrypt path (independent implementation, already fixture-proven).
5. **Cross-tool (manual, once per release):** same mnemonic into ethstaker-deposit-cli →
   derived pubkeys must match ours index-for-index; a keystore we created must import
   into at least one real validator client. Result recorded in the progress log.
6. **E2E in-binary:** fixed test mnemonic → `key recover` → `gen` (BLS-verify on) →
   deposit data validates; proves the keystores we write are consumable by the
   pipeline that already has byte-identity heritage.

## Open questions — RESOLVED 2026-07-17 (detail planning kickoff)

1. **Withdrawal credentials:** in scope as a final phase (K5) of this plan.
   Narrowed at the PRD gate (see `prd.md` Q1/Q2 resolutions): K5 = the 0x01
   `--withdrawal-address` path only, plus a gate making `gen` require an
   explicit withdrawal choice (exit 2 otherwise). Real 0x00 BLS credentials
   are deferred to a follow-up feature; the placeholder stays until then.
2. **Mnemonic passphrase:** **supported in v1** — optional `--mnemonic-passphrase`
   on `key new`/`key recover`, empty default (full staking-deposit-cli parity;
   K1-1 seed derivation and the K3 ceremony gain the optional passphrase).
3. **`key recover` stdin:** allowed (piped mnemonic); `key new` stays TTY-only.
4. **Deterministic test escape:** recommendation stands — no hidden flags;
   binary-level determinism via `key recover` with the fixed test mnemonic.

The original questions are preserved below for the record.

## Open questions (original, as drafted)

1. **Withdrawal credentials wiring (affects K4 scope):** `gen` currently hard-codes
   placeholder 0x00 credentials with an all-zero body (`gen_cmd.rs`,
   `default_withdrawal_creds`). With HD keys we can compute real 0x00 BLS credentials
   (sha256(withdrawal_pubkey)[1..] behind an 0x00 prefix), and/or finally add
   `--withdrawal-address` for 0x01/0x02 execution-address credentials — which is what
   most operators actually want today. Recommendation: make this a follow-up feature
   (K5) rather than growing this plan; but decide before K4-1 freezes the E2E fixture.
2. **Mnemonic passphrase (BIP-39 “25th word”):** support an optional
   `--mnemonic-passphrase` (staking-deposit-cli offers it) or hard-code empty?
   Recommendation: hard-code empty in v1, reject the flag with a clear message; add
   later if requested (changes seed derivation, so decide before K1-1 fixtures).
3. **`key recover` stdin mode:** allow piped mnemonic (`echo "$M" | eth-deposit key
   recover …`) for scripted recovery, or TTY-only like `new`? Recommendation: allow
   stdin on `recover` only (the mnemonic already exists; the exposure decision was the
   caller's), keep `new` TTY-only.
4. **Deterministic test escape for `key new`:** unit tests inject `Entropy`, but is a
   hidden `--entropy-hex` flag wanted for black-box/binary-level tests? Recommendation:
   no hidden flags in the release binary; cover binary-level determinism through
   `key recover` with the fixed test mnemonic.

---

## Progress log

| Issue | Status | Commit | Gate result |
|---|---|---|---|
| — | not started | — | — |
