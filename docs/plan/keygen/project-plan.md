# Project Plan — Validator Key Generation (`key new` / `key recover`, K5 `gen`)

**Scope:** Add `eth-deposit key new` and `eth-deposit key recover` — generate BLS12-381
validator keys from a BIP-39 mnemonic via EIP-2333/EIP-2334 HD derivation, write EIP-2335
v4 scrypt keystores importable by `gen` and by mainstream validator clients — and, as the
final phase (K5), give `gen` real 0x01 execution-address withdrawal credentials plus a
require-explicit-choice gate. Closes the front of the pipeline: `key new → gen → build → sign → send`.
**Inputs:** [`prd.md`](prd.md) (binding, RESOLVED open questions), [`architecture.md`](architecture.md)
(module boundaries, signatures, secret lifecycle), [`overview.md`](overview.md) (locked decisions),
[`research/`](research/) (specs + `existing-code-map.md`). Issue list is re-derived from the
**approved architecture**, not the overview skeleton.
**Sizing:** 1 story point ≈ half a working day. Every issue ≤ 3 pts.
**Streams:** A = derivation primitives → CLI ceremony → E2E (critical path); B = keystore
create/write, `gen` withdrawal credentials, docs (parallel).
**Merge model:** per-issue fast-forward on `develop`, tags `[K#-#]`; every merge green
(`make test && make lint`). No Go reference exists — verification anchors are public spec
vectors + cross-tool compatibility, not byte-parity against a Go binary.

---

## Design deltas from the overview skeleton (per approved architecture)

| Delta | Overview said | Architecture decided | Effect on issues |
|---|---|---|---|
| Keystore write location | `keystore::write` (crate-owned) | bin composes `core::output::write_new_0600` (no `keystore → core` edge) | K2-2 becomes a `core` primitive; write error mapped **call-site** to exit 3 |
| Confirm passphrase source | "reuse `PassphraseSource` (prompt-with-confirm)" | net-new `NewKeystorePassphrase` (confirm-twice + ≥8) — the existing source prompts **once** | new issue **K2-3** (+1 pt) |
| Mnemonic passphrase | "optional `--mnemonic-passphrase`, empty default" | **three forms** — raw argv / `-env` / bare prompt-with-confirm-on-new (user decision) | folds into K3 CLI; splits key-new into scaffolding + runtime (+2 pt) |
| EIP-55 for `--withdrawal-address` | "0x-prefixed 20-byte hex" | **strict** EIP-55 via `pub` `signer::validate_eip55_address` (rejects lowercase) | K5-1 |
| `keystore::encrypt` ↔ `Entropy` | K2-1 depends K1-3 | `encrypt` takes `salt/iv/uuid` as byte params; UUID-v4 formatter lives **inside** `encrypt` | **K2-1 depends —**; UUID work moved K1-3 → K2-1 |

---

## All issues

| ID | Title | Pts | Stream | Depends on |
|---|---|---|---|---|
| K1-1 | `core::bip39` — sha256-pinned wordlist, entropy→mnemonic+checksum, `validate_mnemonic` (12/15/18/21/24, NFKD), `to_seed` (PBKDF2-HMAC-SHA512×2048, passphrase arg), Zeroizing + Trezor vectors | 2 | A | — |
| K1-2 | `core::hd` — EIP-2334 `KeyPath` model, EIP-2333 master/child/path via `blst`, pubkey derivation + four official EIP-2333 vectors | 1 | A | — |
| K1-3 | `core::entropy` — `getrandom` dep (D-1), `Entropy` trait + `OsEntropy` + `EntropyError` | 1 | A | — |
| K2-1 | `keystore::crypto` refactor + `keystore::encrypt` — pure EIP-2335 v4 scrypt writer, declaration-order `Serialize`, UUID-v4 format, filename; spec vector byte-for-byte + round-trip via `Loader` + wrong-passphrase reject | 3 | B | — |
| K2-2 | `core::output::write_new_0600` — generic atomic 0600 write, `create_new` refuse-overwrite, `OutputError::AlreadyExists` + tests | 1 | B | — |
| K2-3 | `keystore::passphrase::NewKeystorePassphrase` — confirm-twice + ≥8-char source; `require_min_len` on the env path (keygen-only, never edits `EnvSource`) + tests | 1 | B | — |
| K3-1 | bin `key` CLI surface — clap namespace, `KeyConfig`, `--count`/`--output-dir`/`--start-index`, three-form `--mnemonic-passphrase` flags, `validate_output_dir`, non-TTY `new` guard, `main.rs` dispatch | 2 | A | — |
| K3-2 | bin `key new` runtime — mnemonic-passphrase resolution (flag>env>prompt-confirm), display + full re-entry ceremony, derive→encrypt→write pipeline, `KeyDeps` seam, SIGINT, progress/summary | 3 | A | K3-1, K1-1, K1-2, K1-3, K2-1, K2-2, K2-3 |
| K3-3 | bin `key recover` — TTY-or-piped-stdin mnemonic (no ceremony), `validate_mnemonic` first, `--start-index`/`--count` range, reuse pipeline | 2 | A | K3-2 |
| K3-4 | exit/error mapping + secret-hygiene test — `Bip39→2`, `Hd→3`, encrypt→3, `Aborted→4`, call-site `Exit{3}` for write; mnemonic/seed/SK/passphrase never on stdout/stderr/logs | 1 | A | K3-2, K3-3 |
| K5-1 | `signer::validate_eip55_address` (`pub`, strict, rejects lowercase) + `core::deposit::eth1_withdrawal_credentials` (`0x01‖0×11‖addr20`) + tests | 1 | B | — |
| K5-2 | `gen --withdrawal-address` + **require-choice gate** (absent → exit 2) threaded into `Request`; gate + flag in one issue (one release) + tests | 2 | B | K5-1 |
| K4-1 | in-binary E2E + fixtures — fixed mnemonic + `-env=TREZOR` → `key recover` → keystores → `gen --withdrawal-address` (BLS-verify) → deposit data; one committed fixture chains BIP-39→EIP-2333→EIP-2335→deposit | 2 | A | K3-4, **K5-2** |
| K4-2 | docs — USER-GUIDE "Step 0 — create validator keys" (incl. raw-passphrase `ps`/history note), README, CHANGELOG (breaking `gen` require-choice change) | 1 | B | K4-1 |

**Total: 23 points** (≈ 11.5 person-days single-dev). Growth vs the overview's 17: +1 (K2-3
confirm source), +2 (K3 CLI split + three-form mnemonic passphrase), +3 (K5 withdrawal
credentials, new phase). With the A/B split the **critical path is ~14 pts** (stream A:
K1 → K3 → K4-1); stream B's 9 pts (keystore, `gen` creds, docs) overlap.
Phase numbers are **thematic**; the `Depends on` column and streams drive execution order.

## Per-phase milestones

| Phase | Theme | Issues | Pts | Milestone (gate) — concrete exit criterion |
|---|---|---|---|---|
| K1 | Derivation primitives | K1-1..3 | 4 | **M-K1:** BIP-39 Trezor vectors (incl. `abandon×23 art` + `TREZOR`) **and** four EIP-2333 official vectors green; wordlist sha256 pin (`2f5eed53…`) asserted |
| K2 | Keystore creation | K2-1..3 | 5 | **M-K2:** EIP-2335 scrypt **spec vector reproduced byte-for-byte** (injected salt/iv/uuid, non-ASCII NFKD pw); created keystore round-trips through the existing decrypt `Loader`; wrong-passphrase rejected; `write_new_0600` refuses overwrite |
| K3 | CLI ceremony | K3-1..4 | 8 | **M-K3:** `key new`/`recover` green incl. display + full re-entry (mismatch → retry/abort exit 4), non-TTY `new` → exit 2, 12–24-word + piped-stdin `recover`; **secret-hygiene test green** |
| K5 | Withdrawal credentials (`gen`) | K5-1..2 | 3 | **M-K5:** `gen --withdrawal-address <checksummed>` emits 0x01 creds in deposit data; `gen` with no withdrawal choice → exit 2; EIP-55 lowercase/mismatch → exit 2 (gate + flag one release) |
| K4 | Integration & release | K4-1..2 | 3 | **M-K4 (final):** **with K5 merged**, `key recover → gen --withdrawal-address` E2E byte-stable (0x01 creds, BLS-verify on); one **manual** cross-tool session recorded; docs done |

**Execution note:** K5 merges **before** K4-1 freezes the E2E fixture, so the fixture is
frozen once against the require-choice `gen` (never a placeholder-cred fixture K5 would
invalidate). Hence M-K4 sits below M-K5 in the table but is achieved after it (see Risks).

## Verification strategy

Each milestone is gated by the spec vectors that prove the boundary beneath it:

1. **M-K1** — BIP-39 official **Trezor** vectors (entropy→mnemonic→seed) + the four
   published **EIP-2333** vectors (master + child, compare `to_bytes()` hex). EIP-2334 has
   no vectors of its own; proven downstream at K4-1.
2. **M-K2** — the EIP-2335 **scrypt spec vector**: inject its salt/iv/uuid + password + secret,
   assert the `crypto` section byte-for-byte, then decrypt through the **existing** `Loader`
   (independent, already fixture-proven) → round-trip.
3. **M-K3** — `KeyDeps` seam drives the ceremony without a real terminal (`FixedEntropy`,
   fake prompt sources, buffers); a non-TTY integration test asserts the `key new` guard exits
   2; the secret-hygiene test (modeled on `gen_cmd`'s `no_secret_in_logs` + `redact_boundary`)
   asserts mnemonic/seed/SK/both-passphrases (raw + hex) never reach stdout/stderr/logger.
4. **M-K5** — command-level tests: checksummed address → 0x01 creds in deposit data; absent
   `--withdrawal-address` → exit 2; lowercase/mismatched address → exit 2.
5. **M-K4 (E2E, automated)** — fixed 12-word mnemonic + `--mnemonic-passphrase-env=TREZOR`
   → seed `c55257c3…463b04` (= EIP-2333 case-0 seed) → committed per-index signing/withdrawal
   pubkeys → `key recover → gen --withdrawal-address` (BLS-verify on) → validated deposit data.
   One fixture chains the whole stack.
6. **M-K4 (cross-tool, manual, once per release)** — **recorded in the progress log, not a
   pointed issue**: same mnemonic + passphrase into **ethstaker-deposit-cli** (the maintained
   fork; staking-deposit-cli is deprecated) → pubkeys match index-for-index (G2); a keystore
   we created imports into ≥1 validator client (G1). Pin the tool/client versions in the note.

## Risks

| # | Risk | Mitigation |
|---|---|---|
| R1 | **Ceremony testability** — `key new`'s display/re-entry + prompt-with-confirm are TTY-bound and hard to test | `KeyDeps` injects `tty_writer` + fake prompt sources + `FixedEntropy`, so every ceremony branch is unit-tested off-terminal; the `isatty` guard is covered by a non-TTY exit-2 test. **Residual:** real-terminal echo-off only exercised in the manual M-K4 session |
| R2 | **K5 breaking `gen` change** — a `gen` that rejects every invocation, or a flag with no gate | Gate + `--withdrawal-address` ship in **one issue (K5-2), one merge, one release**; `default_withdrawal_creds()` stays as documented-but-unreachable placeholder |
| R3 | **Fixture freeze order** — K4-1 could freeze placeholder-cred deposit data that K5 invalidates | K4-1 **depends on K5-2**; freeze the E2E deposit-data fixture **once**, post-K5, with real 0x01 creds. Per-index pubkey fixtures (K1/K3) and the wordlist sha256 pin (trailing-newline-sensitive) are K5-independent and freeze earlier |
| R4 | **Cross-tool drift** — a tool/client version bump shifts filename/format expectations | Target ethstaker-deposit-cli (not the deprecated staking-deposit-cli); pin versions in the M-K4 session note |
| R5 | **EIP-55 UX gap** — `--withdrawal-address` is strict (reject lowercase) while `gen`'s `--from` is lenient | Intentional (ethstaker parity); documented in K4-2 so operators aren't surprised by the asymmetry |

## Progress log

| Issue | Status | Commit | Gate result |
|---|---|---|---|
| K1-1 | done | `9ef24e5` `feat(core): add BIP-39, EIP-2333 HD, and OS entropy primitives` | Trezor english vectors (entropy→mnemonic→seed, incl. `abandon×23 art` + `TREZOR`) green |
| K1-2 | done | same commit | four EIP-2333 vectors green; path + pubkey tests green |
| K1-3 | done | same commit | `getrandom` only new dep; `OsEntropy` only production Entropy |
| M-K1 | **passed** | `9ef24e5` | wordlist pin `2f5eed53…` / 13116 bytes asserted; all K1 acceptance criteria checked |
| K2-1 | done | `feat(keystore): add pure EIP-2335 v4 scrypt encrypt writer` | EIP-2335 scrypt encrypt byte-for-byte + Loader round-trip + wrong-passphrase reject |
| K2-2 | done | `feat(core): add atomic 0600 write_new_0600 with refuse-overwrite` | write_new_0600 0600 + AlreadyExists; no leftover tmp on handled errors; FsWriter unchanged |
