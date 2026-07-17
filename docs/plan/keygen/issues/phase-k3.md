# Phase K3 — CLI ceremony

**Theme:** The `key` command surface, the `key new` generate/display/re-entry ceremony, `key recover`, and the
exit-code + secret-hygiene contract. Stream A critical path; consumes all of K1 and K2.
**Issues:** K3-1, K3-2, K3-3, K3-4 · **Points:** 8 · **Execution:** after K1 and K2 (K3-2 is the fan-in point).
**Milestone gate — M-K3:** `key new`/`recover` green incl. display + full re-entry (mismatch → retry/abort exit
4), non-TTY `new` → exit 2, 12–24-word + piped-stdin `recover`; the secret-hygiene test green.

Signatures/seams from [`architecture.md`](../architecture.md) §"Public API sketches", §Testability, §"Design
notes"; wire points from [`research/existing-code-map.md`](../research/existing-code-map.md) §`bins/eth-deposit`.

---

## K3-1 — bin `key` CLI surface

**Points:** 2 · **Stream:** A · **Depends on:** — · **Milestone:** M-K3

**Goal:** Add the nested `key` clap namespace and its shared config/validation scaffolding — flags, the
three-form `--mnemonic-passphrase`, `--output-dir`/`--count`/`--start-index` validation, and the `key new`
non-TTY guard — without runtime derivation yet. Satisfies U-3 (nested namespace), F-5 (TTY guard), F-8/F-11
(flags), F-16 (clear config errors).

**Implementation notes**
- New `bins/eth-deposit/src/key_cli.rs`: `command()` building `key new` / `key recover` under a
  `subcommand_required(true)` `key` group (copy the shape of `gen_cli::command()`, `gen_cli.rs:61`); `KeyConfig`;
  `validate_output_dir` mirroring `gen_cli.rs:325`; `KeyConfig` load with clap `env` precedence (flag > env >
  default) as `gen` does.
- Change `bins/eth-deposit/src/main.rs`: add `.subcommand(Command::new("key").subcommand_required(true)
  .subcommand(...).subcommand(...))` in `root_command()` (`main.rs:68`) and a `Some(("key", sub))` → inner
  `sub.subcommand()` dispatch arm (`main.rs:103-118`); keep the five existing verbs flat.
- Flags: `--count N` (default 1), `--output-dir DIR` (existing writable dir), `--start-index N` (`recover`), the
  keystore passphrase flags (`--passphrase-env`, prompt-with-confirm default via K2-3), and the three-form
  mnemonic passphrase (see Notes).
- `key new` non-TTY guard: check `isatty(0) && isatty(1)` via `libc` (already a bin dep) at entry and exit 2
  **before** generating (F-5). `key recover` is exempt (stdin allowed).
- Validation order + banner style copied from `gen_cli::load_config` (`gen_cli.rs:170`); bad `--count` / bad
  `--output-dir` → exit 2.

**Acceptance criteria**
- [x] `eth-deposit key new` and `eth-deposit key recover` parse under a `subcommand_required` `key` namespace;
  the five existing verbs remain flat — U-3.
- [x] `--count` defaults to 1; `--output-dir` is validated writable (mirroring `gen`); `--start-index` exists on
  `recover` — F-8, F-11.
- [x] the three mnemonic-passphrase forms parse: raw `--mnemonic-passphrase VALUE`, `--mnemonic-passphrase-env
  VAR`, and bare `--mnemonic-passphrase` (prompt); absent → empty default; precedence flag > env > prompt >
  empty — F-12 (architecture §Design note (c)).
- [x] `key new` exits 2 **before** generating when stdin or stdout is not a TTY — F-5, S-2.
- [x] a bad `--count` or unwritable `--output-dir` → exit 2 with a specific message — F-16, F-9.

**Test plan**
- clap parse tests: flag presence/defaults; the three mnemonic-passphrase forms resolve to the right variant;
  the raw and env forms are mutually exclusive.
- A non-TTY guard test in the `bins/eth-deposit/tests/exit_usage.rs` style asserting `key new` → exit 2 with no
  output written.
- A `validate_output_dir` negative test (missing / non-writable dir → exit 2).

**Notes** (codebase-consistent calls for underdetermined flag mechanics)
- Distinguishing bare `--mnemonic-passphrase` (prompt) from `--mnemonic-passphrase VALUE` (raw): use clap
  `num_args(0..=1)` so the value is optional — absent = empty default, present-without-value = prompt,
  present-with-value = raw.
- `--mnemonic-passphrase` and `--mnemonic-passphrase-env` are marked `conflicts_with` each other (mutually
  exclusive; the `gen_cli` conflicts pattern).
- `--mnemonic-passphrase-env VAR` reads the named var raw into `Zeroizing` with **no** min-length; an **unset**
  var → exit 2 (config error), an **empty** value is accepted as an empty passphrase (empty is valid for the
  mnemonic passphrase, F-12). This differs from `EnvSource`, which rejects empty — the mnemonic-passphrase env
  read is keygen-owned, not `EnvSource`.

---

## K3-2 — bin `key new` runtime — ceremony + derive→encrypt→write pipeline

**Points:** 3 · **Stream:** A · **Depends on:** K3-1, K1-1, K1-2, K1-3, K2-1, K2-2, K2-3 · **Milestone:** M-K3

**Goal:** Implement `key new` end-to-end behind an injectable `KeyDeps` seam: draw entropy → mnemonic, resolve
the mnemonic passphrase, run the display-once + full-re-entry ceremony, then derive → encrypt → write one
signing keystore per validator, with SIGINT-clean behavior and progress/summary. This is the seven-way fan-in
integration point. Satisfies F-1, F-2, F-3, F-4, F-6, F-7, F-12, F-15, S-1, S-2, S-4, S-5, U-1.

**Implementation notes**
- New `bins/eth-deposit/src/key_cmd.rs`: `run_key_new_with_deps(deps: &KeyDeps, cancel: &CancelToken) ->
  Result<(), AppError>` (model on `GenDeps`, `gen_cmd.rs:46`). `KeyDeps { entropy: &dyn Entropy, keystore_pw:
  &dyn PassphraseSource, mnemonic_src, tty_writer, writer, logger, … }`.
- `main.rs` dispatch calls the production wrapper (`OsEntropy`, `NewKeystorePassphrase::new(stderr)` or
  `EnvSource`, real tty writer) and passes `global_cancel()` (`main.rs:56-66`).
- Pipeline (architecture §"Secret lifecycle"): `entropy.fill(&mut Zeroizing<[u8;32]>)` →
  `bip39::entropy_to_mnemonic` → resolve mnemonic passphrase (flag > env > prompt-confirm; confirmed double-entry
  on the **bare** prompt form only) → **ceremony** → `bip39::to_seed` → for each index `hd::derive_path(seed,
  &KeyPath::signing(i))` → `new_signer(sk.to_bytes())` pubkey check → draw salt(32)/iv(16)/uuid(16) via `entropy`
  → `keystore::encrypt` → `core::output::write_new_0600(dir.join(keystore_filename(...)), &bytes)`.
- **Ceremony (F-6):** display the mnemonic **once** to the injectable `tty_writer` (distinct from
  stdout/stderr/logger), then require the operator to re-enter it in full; compare; on mismatch allow retry or
  clean abort (`AppError::Aborted` → exit 4). **No keystore is written until re-entry matches.**
- Keystore passphrase via `NewKeystorePassphrase` (confirm + ≥8) or `--passphrase-env` + `require_min_len(8)`
  (K2-3).
- SIGINT: `CancelToken` checkpoints at each prompt and before each keystore write (S-5). On `key new` the ceremony
  completes before any write, so SIGINT during it leaves **zero** keystores; with `--count N`, SIGINT after *k*
  writes leaves *k* complete, valid keystores (per-file guarantee).
- Progress per key + end-of-run summary (written keystore paths + signing pubkeys) to **stderr**, TTY/non-TTY split
  like `gen` (`emit_progress` `gen_cmd.rs:326`, `print_gen_summary` `gen_cmd.rs:359`) (F-15).
- `FixedEntropy` (deterministic mnemonic + salt/iv/uuid) lives in this file's `#[cfg(test)]` only (S-4).

**Acceptance criteria**
- [x] `key new` generates a fresh 24-word mnemonic from 256-bit `OsEntropy` with a valid checksum — F-1, S-4.
- [x] the ceremony displays once via the injectable `tty_writer` and requires full re-entry before **any**
  keystore is written; a mismatch allows retry or a clean abort (exit 4); no keystore exists on disk until
  re-entry matches — F-6, U-1, S-5.
- [x] the mnemonic passphrase is resolved flag > env > prompt-confirm, captured **before** derivation, empty
  valid, wrapped in `Zeroizing` — F-12 (architecture §Design note (c)).
- [x] per index: signing SK derived at `m/12381/3600/i/0/0`, encrypted as EIP-2335 v4 scrypt, written 0600 /
  atomically / refuse-overwrite — F-2, F-3, F-4, S-3.
- [x] the keystore passphrase uses `NewKeystorePassphrase` (confirm, ≥8) or `--passphrase-env` +
  `require_min_len(8)` — F-7.
- [x] the `KeyDeps` seam injects entropy/keystore_pw/mnemonic_src/tty_writer/writer/logger; `FixedEntropy` is
  `#[cfg(test)]`-only — S-4, testability.
- [x] SIGINT before any write leaves zero keystores; with `--count N`, SIGINT after *k* writes leaves *k*
  complete keystores — S-5.
- [x] per-key progress + an end-of-run summary (paths + signing pubkeys) go to stderr with the TTY/non-TTY split
  — F-15.
- [x] entropy, mnemonic, seed, every `sk_bytes`, and both passphrases are `Zeroizing` at every hop — S-1.

**Test plan**
- `KeyDeps`-seam unit tests with `FixedEntropy` (deterministic mnemonic + salt/iv/uuid), fake prompt sources, and
  buffers: happy path writes N keystores that round-trip through `Loader`; a mismatched re-entry → retry then
  abort (exit 4); passphrase `< 8` → exit 2; SIGINT mid-run leaves *k* complete files.
- A seed-derivation assertion: fixed mnemonic + `TREZOR` mnemonic passphrase → seed `c55257c3…463b04` (anchors the
  three mnemonic-passphrase forms to the BIP-39 vector).

**Notes**
- 3 pts, the heaviest issue — the seven-way fan-in. Kept intact (not split) per the plan; K3 was already split
  into scaffolding (K3-1) + runtime (K3-2). Flagged in `index.md` as at the cap.
- Real-terminal echo-off is only exercised in the manual M-K4 session; unit tests drive every ceremony branch via
  the injectable `tty_writer` + fake prompt sources.

---

## K3-3 — bin `key recover` — TTY-or-piped-stdin mnemonic, no ceremony

**Points:** 2 · **Stream:** A · **Depends on:** K3-2 · **Milestone:** M-K3

**Goal:** Implement `key recover` reusing the K3-2 derive→encrypt→write pipeline, reading an **existing** mnemonic
from an interactive TTY prompt or piped stdin (no display/re-entry ceremony), validating it first, and deriving
over `--start-index`/`--count`. Satisfies F-10 (stdin/TTY), F-11 (12–24-word validation + range), F-16.

**Implementation notes**
- Add `run_key_recover_with_deps(deps, cancel)` to `bins/eth-deposit/src/key_cmd.rs`; `main.rs` dispatches to its
  production wrapper. Reuse the K3-2 derive→encrypt→`write_new_0600` pipeline unchanged.
- Read the mnemonic from an interactive TTY prompt **or** piped stdin (`echo "$M" | eth-deposit key recover …`) —
  the `new`-only guard does not apply here (F-10).
- Call `bip39::validate_mnemonic` **first**; accept 12/15/18/21/24 words; a bad word or bad checksum → exit 2 with a
  specific message (F-11).
- `--start-index N` / `--count N` select the derivation index range.
- Resolve the mnemonic passphrase (flag > env > prompt) as in K3-2, but the **bare prompt is single-entry** here —
  the double-entry confirm is a `key new` concern only (the mnemonic already exists).

**Acceptance criteria**
- [x] `key recover` reads the mnemonic from an interactive TTY prompt **or** piped stdin — F-10.
- [x] `validate_mnemonic` runs first; 12/15/18/21/24-word mnemonics accepted; a bad word or bad checksum → exit 2
  with a clear message — F-11, F-16.
- [x] `--start-index N` / `--count N` select the derivation range and produce the matching per-index keystore
  filenames — F-11.
- [x] there is **no** display/re-entry ceremony (mnemonic already exists) — F-10.
- [x] the produced keystores round-trip through the existing `Loader` and are identical in shape to `key new`
  output — F-3, C-3.
- [x] the mnemonic passphrase is supported (empty default), captured before derivation; the bare-prompt form is
  single-entry — F-12.

**Test plan**
- `KeyDeps`-seam tests: piped-stdin mnemonic (12-word and 24-word) → keystores round-trip through `Loader`; bad
  word → exit 2; tampered checksum → exit 2; `--start-index 5 --count 3` yields indices 5,6,7 in the filenames;
  the TTY prompt path via an injected `mnemonic_src`.

**Notes**
- `recover` accepts stdin; `key new` stays TTY-only — the gate is new-only (architecture §"`key new` vs `key
  recover` I/O split").

---

## K3-4 — exit/error mapping + secret-hygiene test

**Points:** 1 · **Stream:** A · **Depends on:** K3-2, K3-3 · **Milestone:** M-K3

**Goal:** Wire the keygen exit-code contract (2/3/4) with typed arms + a call-site map for the shared write error,
and add the automated secret-hygiene test proving no secret reaches stdout/stderr/logs. Satisfies F-9 (exit map),
S-2/G5 (no secret leakage), and preserves `gen`'s `OutputError → 1`.

**Implementation notes**
- Change `bins/eth-deposit/src/errors.rs` (`exit_code_for`, `errors.rs:208`): add `AppError::Bip39(_) => 2`,
  `AppError::Hd(_) => 3`, and a `KeystoreError` encrypt-variant `=> 3` arm; keep `AppError::Aborted(_) => 4`
  (`errors.rs:211`) for ceremony mismatch/abort + SIGINT; keep `AppError::Output(_)` at the `_ => 1` fallback
  (unchanged for `gen`).
- Keystore **write** errors (`OutputError`, incl. overwrite-refusal) are mapped `map_err(|e|
  AppError::Exit{msg, code:3})` **at the call site** in `key_cmd.rs` — not a global `OutputError` arm — because
  `gen`'s `OutputError` must remain `→ 1` (`gen_cmd.rs` `writer_error_exit1`).
- Passphrase `< 8`, non-TTY `new`, bad `--count`, bad `--withdrawal-address` (K5) use `AppError::Exit{code:2}`.
- New secret-hygiene test in `bins/eth-deposit/tests/` modeled on `tests/redact_boundary.rs` and `gen_cmd.rs`'s
  `no_secret_in_logs` (`gen_cmd.rs:1410`): run the deps seam with a fixed mnemonic, route the one-time display to
  the injectable `tty_writer`, and assert the secrets never appear in the captured stdout/stderr/logger buffers.

**Acceptance criteria**
- [x] exit map holds: `Bip39Error` → 2; passphrase `<8` / non-TTY `new` / bad `--count` / bad address → 2;
  `HdError` + encrypt failure → 3; keystore write (incl. overwrite-refusal) → 3 at the call site; ceremony
  mismatch/abort + SIGINT → 4; unexpected-internal stays 1 — F-9 (architecture §Exit-code mapping).
- [x] the secret-hygiene test asserts the mnemonic, seed, secret-key, and **both** passphrases (raw + hex) never
  appear in stdout/stderr/logger buffers; the one-time mnemonic display goes **only** to the `tty_writer` — S-2, G5.
- [x] `gen`'s `writer_error_exit1` still passes (its `OutputError` stays `→ 1`) — regression (architecture R2).

**Test plan**
- Unit tests asserting each `AppError` variant → its expected code (2/3/4/1).
- The integration secret-hygiene test (modeled on `redact_boundary.rs` + `no_secret_in_logs`) with grep-style
  assertions that the fixed mnemonic / seed / SK bytes (raw and hex) are absent from the captured buffers.
- Re-run `gen`'s exit/writer tests to confirm the fallback is unchanged.

**Notes**
- The keystore write error is deliberately mapped at the call site rather than globally so the shared
  `OutputError` keeps `gen`'s exit-1 contract (architecture Design notes fork (a)).
