# PRD — Validator Key Generation (`eth-deposit key new` / `key recover`)

**Status:** draft, pending approval gate.
**Owner feature docs:** [`overview.md`](overview.md) (locked design decisions, K1–K4 issue skeleton, verification anchors). This PRD states *what* and *why*; the overview owns *how*.
**Scope in one line:** add `eth-deposit key new` and `eth-deposit key recover` — generate BLS12-381 validator keys from a BIP-39 mnemonic via EIP-2333/EIP-2334 HD derivation, write EIP-2335 v4 scrypt keystores importable by our own `gen` and by mainstream validator clients — and, as the final phase (K5), produce real withdrawal credentials in `gen`.

---

## Problem statement

`eth-deposit` owns the back half of a validator deposit — `gen → build → sign → send` — but not the front. `gen` requires EIP-2335 keystores that the operator must first produce with a *separate* tool (staking-deposit-cli / ethstaker-deposit-cli). The result: two tools, two trust boundaries, two air-gapped transfers, and a mnemonic that lives in a Python tool the operator did not otherwise need.

Two concrete gaps follow from this:

1. **No in-binary key origin.** There is no way to go from a mnemonic to importable keystores without leaving `eth-deposit`.
2. **No real withdrawal credentials.** `gen` hard-codes a placeholder credential — `default_withdrawal_creds()` returns `0x00` prefix with an all-zero body (`bins/eth-deposit/src/gen_cmd.rs:31`) — which is not a usable credential for a real deposit. Operators cannot yet specify where withdrawals go.

This feature closes both gaps so the entire flow lives in one auditable, minimal-dependency binary: `key new → gen → build → sign → send`.

## Target users

Solo stakers and node operators preparing validators for deposit. They need keys, deposit data, and a broadcast transaction; today that is split across staking-deposit-cli and `eth-deposit`. They are security-sensitive and frequently generate keys on an **air-gapped** machine, so the mnemonic and derived secrets must never escape the process via stdout, stderr, logs, or a non-interactive stream.

## Goals & success metrics

| # | Success metric | How measured |
|---|---|---|
| G1 | Keystores we write import cleanly into a real validator client | Manual per-release cross-tool session: a created keystore imports into ≥ 1 of Lighthouse/Teku/Prysm/Nimbus |
| G2 | Byte-for-parity with the reference deriver | Same mnemonic (+ mnemonic passphrase) into ethstaker-deposit-cli → signing **and** withdrawal pubkeys match ours index-for-index |
| G3 | Full pipeline in one binary | `key recover → gen → build → sign → send` runs end-to-end with no external key tool; committed E2E fixture proves `key recover → gen` (BLS-verify on) |
| G4 | Spec conformance | BIP-39 (Trezor), EIP-2333, EIP-2334, EIP-2335-scrypt official vectors all green in CI |
| G5 | Zero secret leakage | Automated hygiene test asserts mnemonic / seed / secret-key / passphrase bytes never reach stdout, stderr, or logs |
| G6 | Real withdrawal credentials | `gen --withdrawal-address` yields a valid 0x01 execution-address credential; deposit data validates on-chain semantics |

---

## Functional requirements

Priority: **P0** = ship-blocking core; **P1** = required for the feature to be complete per the binding decisions; **P2** = polish, non-blocking.

### P0 — core keygen, keystores, and the `key new` ceremony

| ID | Requirement |
|---|---|
| F-1 | `key new` generates a fresh 24-word English BIP-39 mnemonic from 256-bit OS-CSPRNG entropy, with a valid checksum. |
| F-2 | Derive signing keys per validator index using EIP-2333 (master + child) and EIP-2334 paths; correctness gated by the published EIP-2333/2334 vectors. Derive the corresponding BLS pubkeys. |
| F-3 | Encrypt each signing key as an **EIP-2335 v4 scrypt** keystore that decrypts back through the existing `crates/keystore` `Loader` and imports into mainstream validator clients (G1). |
| F-4 | Write each keystore with the staking-deposit-cli filename convention, **atomically**, with `0600` permissions, and **refuse to overwrite** an existing file (exit 3). |
| F-5 | **`key new` is TTY-only.** With stdin or stdout not a terminal, exit 2 before generating anything — a mnemonic must never land on a pipe, redirect, or log. |
| F-6 | **Mnemonic confirmation ceremony:** display the mnemonic once, then require the operator to re-enter it in full before *any* keystore is written; on mismatch, allow retry or clean abort (exit 4). No keystore exists on disk until re-entry succeeds. |
| F-7 | Keystore **encryption passphrase** via the existing `PassphraseSource` (interactive prompt-with-confirm by default, `--passphrase-env` for automation); enforce a **minimum of 8 characters** with a clear message on failure (exit 2). |
| F-8 | Flags: `--count N` (validators to generate, default 1), `--output-dir DIR` (existing, writable). |
| F-9 | Exit-code mapping: `0` ok, `2` user/config error, `3` crypto/keystore-write error, `4` SIGINT or ceremony abort. `5` unused (no RPC). `1` remains unexpected-internal. |

### P1 — recover, mnemonic passphrase, and real withdrawal credentials (K5)

| ID | Requirement |
|---|---|
| F-10 | `key recover` reconstructs keystores from an **existing** mnemonic, read from an interactive TTY prompt **or** from piped **stdin** (`echo "$M" \| eth-deposit key recover …`). Unlike `key new`, no display/re-entry ceremony — the mnemonic already exists and the exposure decision was the caller's. |
| F-11 | `key recover` validates the mnemonic checksum and accepts **12/15/18/21/24**-word mnemonics; a bad word or bad checksum fails with a clear message (exit 2). Flags `--start-index N` / `--count N` select the derivation range. |
| F-12 | **Mnemonic passphrase** (BIP-39 "25th word") supported on **both** subcommands via `--mnemonic-passphrase`, **empty by default** (full staking-deposit-cli parity). It changes seed derivation, so it must be captured before derivation on both paths. This is a *distinct secret* from the keystore passphrase (F-7) — the 8-char minimum does **not** apply; empty is valid. |
| F-13 | **K5 — 0x01 execution-address withdrawal credentials:** `gen` gains `--withdrawal-address ADDR`. The address MUST be EIP-55 checksummed; lowercase or checksum-mismatched input is rejected with exit 2 (decided at the research gate 2026-07-17 — parity with ethstaker-deposit-cli, which requires `is_checksum_address`; the repo's EIP-55 encoder in `crates/signer` will be exposed for this). When set, `gen` emits a real type-`0x01` credential (`0x01 ‖ 11 zero bytes ‖ 20-byte address`) in place of the placeholder, and the deposit data reflects it. |
| F-14 | **K5 — real 0x00 BLS withdrawal credentials:** when no execution address is given, `gen` produces a real type-`0x00` credential (`0x00 ‖ sha256(withdrawal_pubkey)[1:]`) computed from the derived withdrawal key, replacing the all-zero placeholder. **Deferred out of v1** (Q1 resolved as option (c) — see [Open questions](#open-questions)): v1 ships only the 0x01 path (F-13); the placeholder remains until the 0x00 wiring is planned as a follow-up feature. |

### P2 — polish (non-blocking)

| ID | Requirement |
|---|---|
| F-15 | Per-key progress rendering and an end-of-run summary listing written keystore paths and signing pubkeys (stderr), mirroring `gen`'s TTY/non-TTY progress split. |
| F-16 | Actionable, specific error messages for the common mistakes (bad mnemonic word, wrong word count, unwritable output dir, passphrase too short) — each mapped to exit 2. |

---

## Non-functional requirements

### Security invariants (non-negotiable)

| ID | Invariant |
|---|---|
| S-1 | **Zeroization** of every secret: mnemonic string, entropy bytes, PBKDF2 seed, master and all derived child secret keys (signing + withdrawal), keystore passphrase, and mnemonic passphrase — wrapped in `Zeroizing` / zeroize-on-drop, matching the existing `keystore::Key` invariant. No secret survives its scope. |
| S-2 | **No secret on stdout/stderr/logs.** The mnemonic is written only to the interactive terminal during the `key new` ceremony; seed, secret keys, and both passphrases are never printed anywhere. Error and log messages never embed secret bytes (verified by G5's hygiene test). |
| S-3 | **Filesystem safety.** Keystores are written `0600`, atomically (temp file + rename, reusing `core::output`), and never overwrite an existing file. |
| S-4 | **RNG.** Entropy comes only from the OS CSPRNG (via `getrandom`, behind the injectable `Entropy` trait). The deterministic test implementation is reachable in tests only — **no hidden entropy flag** exists in the release binary. |
| S-5 | **SIGINT is clean.** Ctrl-C at any prompt aborts with exit 4 and leaves no partial or half-written keystore on disk. |

### Compatibility

| ID | Requirement |
|---|---|
| C-1 | Derivation and encoding conform to **BIP-39, EIP-2333, EIP-2334, EIP-2335 (v4 scrypt)**, each gated by official published vectors reproduced in CI (see overview §Verification strategy). |
| C-2 | **Cross-tool parity (manual, once per release):** same mnemonic + mnemonic passphrase into ethstaker-deposit-cli → derived pubkeys match index-for-index (G2); a keystore we create imports into a real validator client (G1). Result recorded in the overview's progress log. |
| C-3 | Keystore **filename convention matches staking-deposit-cli** so validator-client import tooling recognizes the files, and keystores round-trip through the existing decrypt `Loader` and feed `gen` unchanged. |

### UX

| ID | Requirement |
|---|---|
| U-1 | `key new` ceremony is explicit and interruptible: generate → display → require full re-entry → write, with retry-or-abort on mismatch (F-6). |
| U-2 | Passphrase entry reuses the existing prompt-with-confirm flow and `--passphrase-env` for automation; consistent with the `gen` passphrase experience. |
| U-3 | The two subcommands live under a nested `key` namespace (`eth-deposit key new`, `eth-deposit key recover`), keeping the five existing verbs flat. |

### Dependencies

| ID | Requirement |
|---|---|
| D-1 | **Only one new dependency: `getrandom`.** The English wordlist is embedded, the UUID v4 is hand-formatted, and BIP-39/keystore crypto reuses the existing `sha2`/`pbkdf2`/`hmac`/`scrypt`/`aes`/`ctr`/`zeroize` deps — consistent with the repo's auditable-minimal-dep philosophy. |

---

## Non-goals

Explicitly **out of scope** for this feature:

- **Other mnemonic languages.** English wordlist only in v1.
- **pbkdf2 keystore *creation*.** We only *write* the scrypt profile; the existing decrypt path still *reads* pbkdf2 imports.
- **Ledger-derived BLS keys.** Ledger remains secp256k1 transaction signing only; validator keys come from the mnemonic.
- **Slashing-protection data** (export or import).
- **Remote signing / Web3Signer** keystore formats.
- **Key management beyond create and recover** — no delete, rotate, re-encrypt, or inspect. The `key` namespace exists only for `new`/`recover`; other verbs are not built here.
- **Mnemonic passphrase hint/recovery storage** — the 25th word is the operator's to remember.
- **24-word-only generation is the rule for `new`;** custom entropy sizes are not exposed (`recover` still accepts 12–24-word inputs).

---

## Open questions — RESOLVED 2026-07-17 (PRD gate)

- **Q1 → (c):** v1 ships only the 0x01 `--withdrawal-address` path; the 0x00
  mechanism (sidecar vs mnemonic input to `gen`) is deferred to a follow-up
  feature, and the placeholder credential stays untouched in the meantime.
- **Q2 → require explicit choice:** once K5 lands, `gen` without
  `--withdrawal-address` exits 2 with a clear message — no deposit can be built
  on the all-zero placeholder by accident. Breaking change to `gen`, accepted
  because the Rust binary has no tagged releases. **This is a new binding
  functional requirement on K5.**

The original questions are preserved below for the record.

## Open questions (original, as drafted)

**Q1 — How does `gen` obtain the withdrawal pubkey for a *real* 0x00 credential (F-14)?**
`gen` is driven by `--keystore-dir` + `--pubkeys` and has no mnemonic and no withdrawal key in its inputs, so a `0x00 ‖ sha256(withdrawal_pubkey)[1:]` credential currently has no source for the withdrawal pubkey. The 0x01 path (F-13) has no such gap — the address comes straight off the flag. Options:

- **(a)** `key new`/`key recover` emit a sidecar (a withdrawal keystore, or a signing-pubkey → withdrawal-credential map) that `gen` reads.
- **(b)** `gen` gains an optional mnemonic / withdrawal-key input and derives the withdrawal pubkey itself.
- **(c)** *(recommended, low-risk)* ship only the 0x01 `--withdrawal-address` path in v1 and leave the 0x00 placeholder untouched until (a)/(b) is decided. This matches the overview's own observation that execution-address (0x01) credentials are what most operators want today.

K5 stays in scope as P1 (binding decision 1); **only the 0x00 mechanism is open**, and it must be resolved before the K5 issues and the K4 E2E fixture are frozen.

**Q2 — Default withdrawal-credential behavior when neither `--withdrawal-address` nor the Q1 wiring is present.**
Under recommendation Q1(c), `gen` without `--withdrawal-address` continues to emit the existing placeholder. Confirm this is acceptable for the interim, or gate `gen` to require `--withdrawal-address` once K5 lands so no deposit is ever built on the all-zero placeholder by accident.
