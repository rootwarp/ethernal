# PRD — End-to-End Test Suite for All `ethernal` Commands

**Status:** draft at the PRD gate (autonomous run, 2026-07-19). Written without a live approval loop; every place a decision would normally be confirmed is recorded in [Assumptions](#assumptions) or [Open questions](#open-questions).
**Sibling precedent:** [`../keygen/prd.md`](../keygen/prd.md) and [`../eoa-keystore/prd.md`](../eoa-keystore/prd.md) — this PRD reuses their P0/P1/P2 convention and their requirement-ID style (here `T-*` for test-coverage requirements, `C-*` for constraints). Where a requirement mirrors one of those features it cites it rather than restating it.
**Informal spec:** [`.claude/skills/verify/SKILL.md`](../../../.claude/skills/verify/SKILL.md) — the current **manual** end-to-end verification procedure (fixtures, golden checks, live anvil pipe chain, hybrid RPC probes, exit-code matrix, gotchas). Automating that skill's *automatable* procedure is the spine of this work.
**Scope in one line:** turn the existing binary-level integration suite (`bins/ethernal/tests/`) plus the manual verify skill into **one automated e2e suite that exercises every subcommand's real happy path and the security-critical live-node surfaces that today are either untested or manual-only** — so the suite becomes a trustworthy pre-release gate.

> **Binding scope decision (2026-07-19, user):** *"Building a new PTY driver is not in scope for this stage. Assume the mnemonic is GIVEN by the user."* The interactive `key new` / `account new` ceremonies (one-time mnemonic display, full re-entry quiz, scrollback clear, mnemonic-passphrase prompt) stay **manual-only** this stage; automated tests obtain keystores by feeding a **fixture mnemonic** to the non-interactive `recover` path (piped stdin + `--passphrase-env`), exactly as the existing suite already does. The **entire PTY tier is DEFERRED to a possible future stage — not deleted:** the research (`research/r1-pty-driver.md`) stays on file and remains valid for that stage. Every requirement that this decision moves is listed in [Non-goals](#non-goals) as *deferred to a future stage (PTY tier)*, verified against the code as truly ceremony/TTY-only; anything reachable non-interactively was kept and, where needed, rescoped (T-3, T-12·recover). The known coverage hole this leaves — no binary-level e2e of the `new` **success** ceremony — is stated honestly in [Goals & success metrics](#goals--success-metrics); its only automated guard this stage is the in-crate `key_cmd`/`account_cmd` unit tests (the manual verify skill is `gen → build → sign → send` and does **not** exercise the ceremony, so the ceremony is a documented **carve-out** of that skill via T-18, not something it covers).

This is a **gap-analysis PRD over an existing, mature test suite**, not a from-scratch spec. The binary already has ~130 integration tests driving the real `CARGO_BIN_EXE_ethernal` against a hand-rolled JSON-RPC stub and committed golden fixtures. The job is to close the specific holes that stub-and-golden testing structurally cannot reach.

---

## Problem statement

`ethernal` moves BLS validator keystores and EOA keys all the way to a broadcast Ethereum deposit transaction. Its correctness is anchored two ways today, and both have a hole the other cannot cover:

1. **The automated suite (`bins/ethernal/tests/`) never drives an interactive terminal.** `key new`, `account new`, and the interactive-prompt path of `key recover` / `account recover` are the tool's most security-sensitive surface — passphrase entry, one-time mnemonic display, the full re-entry confirmation quiz, terminal-scrollback clearing, the symlink-output-dir warning. Every one of these requires a real TTY on both stdin and stdout (`require_tty_for_new`, `bins/ethernal/src/key_cli.rs:215`). The suite can only assert the **non-TTY failure path** (`exit_usage.rs`: `key_new_non_tty_exits_two`, `account_new_non_tty_exits_two`). The entire *success* ceremony — and the recently-merged hardening inside it (scrollback clear `284d478`, symlink warning `1736843`, batch salt/IV distinctness which is tested for `recover` only, `584c404`) — has **zero** binary-level coverage.
   **This stage, per the binding scope decision above, that ceremony-automation gap is an accepted hole, not a target:** driving a real TTY needs a PTY harness, which is deferred. The ceremony *success* path stays validated **only** by the in-crate injected-dependency unit tests in `key_cmd`/`account_cmd` (`happy_path_*`, `ceremony_mismatch_*`, `clear_sequence_bytes_and_order`, `mnemonic_passphrase_*`) — not through the real binary end-to-end, and **not** by the manual verify skill (which is `gen → build → sign → send` over committed keystore fixtures and never runs `key new`/`account new`). What this stage *does* close on that surface is the part reachable without a TTY: the `recover` path (fixture mnemonic → v3/v4 keystores, now with a `decrypt_v3` round-trip, T-3) and the symlink-output-dir warning on `recover` (T-12·recover). Note that the `recover` path already runs the identical `finish_from_mnemonic` derive→encrypt→write tail as `new` (`key_cmd.rs` / `account_cmd.rs`), so the crypto/write half of the ceremony *is* e2e-exercised — only the TTY dialogue is not.

2. **The automated suite never talks to a real Ethereum node.** Every RPC-touching test points the binary at the in-process `Stub` (`tests/common/mod.rs:188`), a canned JSON-RPC 2.0 responder. The stub returns fixed results **regardless of whether the transaction the binary produced is valid** — it will happily "accept" an RLP payload a real node would reject. The only thing that proves the bytes `ethernal` emits are accepted by a real EVM and actually move deposit-contract state is the manual verify-skill anvil run (`gen | build | sign | send --wait-for-receipt`, then `cast tx` + contract-balance check). That proof exists **only in a human's terminal**, so it rots between releases and cannot gate a PR.

Two further, smaller gaps ride along: the `gen` output is **field-asserted but never byte-diffed against the committed golden** (`testdata/hoodi/deposit_data-expected.json`), and the **mainnet golden plus the `--i-understand-this-is-mainnet` safety guard are entirely untested** — a safety-critical flag with no test at all.

The result: the pre-release confidence story depends on a manual skill that only its author runs, and the automated suite green-lights code paths (the ceremony, the live broadcast) it has never actually executed. This PRD closes those gaps.

## Target users

- **The repo maintainer**, who runs the suite locally before cutting a release and needs the interactive ceremony and the live pipe chain checked without hand-driving a terminal and an anvil node each time.
- **The release process itself.** The e2e suite is a **pre-release gate**: "every subcommand has an automated true-e2e happy path, and the verify skill's automatable procedure runs green" should be a checkable release criterion, not a manual ritual. CI is the enforcement point (see the CI tiers in [Constraints](#non-functional-requirements)).

Secondary: any contributor whose change touches the ceremony, the tx pipeline, or the RPC layer, who today gets no signal from CI that they broke an interactive or live-node path.

## Goals & success metrics

Priority: **P0** = ship-blocking for the suite to be a credible gate; **P1** = required for the suite to be *complete*; **P2** = polish.

| # | Success metric | How measured |
|---|---|---|
| G1 | **Every subcommand has ≥ 1 automated true-e2e happy path — *except the two `new` ceremonies, a known accepted hole this stage.*** | `key recover`, `account recover`, `gen`, `build`, `sign`, `run`, `send` each have a green end-to-end test that exercises the primary success flow through the real binary (not just a `--help`/exit-code assertion). **`key new` / `account new`: NOT met this stage** — the ceremony success flow needs a real TTY (deferred PTY tier), so its only automated guard is the in-crate injected-dependency unit tests (`key_cmd`/`account_cmd` `happy_path_*`), not e2e through the binary and not the manual verify skill (which never runs the ceremony). This is the one honest exception, called out here rather than claimed. |
| G2 | **~~The interactive `new` ceremonies are PTY-tested.~~ DEFERRED (future PTY stage).** | Superseded by the binding scope decision (2026-07-19). No PTY-driven ceremony test this stage; the requirement and its research (`research/r1-pty-driver.md`) are preserved for a possible future stage. The ceremony success path is unit-tested with injected deps and manually verified — the accepted coverage hole recorded under G1. |
| G3 | **The verify skill's *automatable, non-ceremony* procedure runs unattended in CI.** | The golden checks, the live-anvil pipe chain, the hybrid-RPC probes, and the exit-code matrix from `SKILL.md` all execute as tests. Carve-outs are documented as non-automatable, not silently dropped: **ledger signing, cross-tool import parity, *and — this stage — the interactive `new` ceremony*** (see [Non-goals](#non-goals) and the T-18 parity checklist). |
| G4 | **The live-node pipe chain proves on-chain effect.** | An anvil-backed test runs `gen \| build \| sign \| send --wait-for-receipt` end-to-end and asserts a successful receipt **and** that the deposit-contract balance grew by 32 ETH — the thing the Stub cannot prove. *(Unaffected by the scope decision — anvil tier.)* |
| G5 | **Recently-merged hardening is regression-guarded on the reachable surface.** | Covered this stage: batch salt/IV/UUID distinctness on the *`recover`* path (`584c404`, already green) and the symlink-output-dir warning on the *`recover`* path (`1736843`, T-12·recover). **Deferred with the PTY tier:** scrollback clear on `new` (`284d478`), symlink warning on `new`, `new`-path secret hygiene, and salt/IV distinctness on the `new` path — each still guarded by an in-crate unit test (e.g. `clear_sequence_bytes_and_order`), just not e2e through the binary. |
| G6 | **Safety guards are tested.** | The `gen` hoodi golden is byte-diffed against the committed fixture, and the `--i-understand-this-is-mainnet` mainnet guard has a test proving it blocks/permits as designed. *(Unaffected by the scope decision — hermetic `gen` tier.)* |
| G7 | **No regression in determinism or CI cost for the hermetic tier.** | The every-PR tier stays hermetic (no network, no external toolchain) and deterministic; the heavier live-node tier is isolated so real-node flakiness never blocks a PR (see C-5). *(Unaffected by the scope decision.)* |

---

## Coverage matrix

Status legend: **✓ covered** (an automated test in `bins/ethernal/tests/` exercises it) · **⚠ manual-only** (exists only in the verify skill) · **✗ uncovered** (no test anywhere at the binary level) · **~ unit-only** (covered by a crate unit test, not through the binary) · **⊘ deferred** (needs the PTY tier — out of scope this stage per the binding decision; validated by an in-crate unit test + manual verify).

The matrix is the gap analysis; the [Functional requirements](#functional-requirements) below turn every ⚠/✗ *worth closing this stage* into a T-\* item. **Ceremony rows are marked ⊘ deferred** (their T-\* moved to [Non-goals](#non-goals)); the two rows the scope decision keeps by rescoping to the non-interactive `recover` path are **T-3** (account v3 via recover + `decrypt_v3`) and **T-12·recover** (symlink warning on recover). It tracks **behavioral scenarios, not every flag permutation** — two flag-level gaps it surfaces but does not enumerate row-by-row are `gen --parallel` (flag exists in `gen_cli.rs`, no test — see T-19) and the **signer-side** chain-ID mismatch → exit 3 (the build-side exit-2 and broadcast-side exit-5 variants are covered by `build_rpc::rpc_chain_id_mismatch_exit2` / `send::chain_id_mismatch`; the exit-3 variant documented in `main.rs:8-14` / `SKILL.md:57` is uncovered and appears Ledger-coupled, so it likely falls under the ledger [Non-goal](#non-goals)).

| Command | Scenario | Status | Evidence / gap owner |
|---|---|---|---|
| **key new** | missing `--output-dir` → exit 2 | ✓ | `exit_usage::key_new_missing_output_dir` |
| key new | non-TTY stdin/stdout → exit 2 | ✓ | `exit_usage::key_new_non_tty_exits_two` |
| key new | bad `--count` → exit 2 | ✓ | `exit_usage::key_new_bad_count_exits_two` |
| key new | help omits entropy flag | ✓ | `key_e2e::key_recover_help_has_no_entropy_flag` |
| key new | full ceremony: passphrase prompt+confirm → mnemonic display → re-entry quiz → v4 keystore written | ⊘ | **T-2 deferred** (PTY tier); success path unit-tested `key_cmd::happy_path_writes_n_keystores_loader_round_trip` |
| key new | confirmation mismatch → retry, then abort exit 4, nothing written | ⊘ | **T-4 deferred** (PTY tier); unit-tested `key_cmd::ceremony_mismatch_retry_then_abort_exit4_no_files` |
| key new | scrollback cleared after ceremony (`284d478`) | ⊘ | **T-11 deferred** (PTY tier); unit-tested `key_cmd::clear_sequence_bytes_and_order` / `abort_path_still_clears` |
| key new | symlink `--output-dir` warning on the *new* path (`1736843`) | ⊘ | **T-12·new deferred** (PTY tier). *Recover-path variant KEPT → T-12·recover* |
| key new | mnemonic/seed/secret never leave the display TTY (new-path hygiene) | ⊘ | **T-5 deferred** (PTY tier); asserted in unit tests via `summary_out` vs `tty_writer` split (`key_cmd::happy_path_*`) |
| key new | `--mnemonic-passphrase` three-form on the ceremony | ⊘ | **T-10 deferred** (PTY tier). Non-ceremony coverage EXISTS on recover (three-form ✓, derivation-change ✓ `account_cmd::mnemonic_passphrase_raw_honored_on_new`) |
| key new | batch salt/IV/UUID distinct across `--count` on the *new* path | ⊘ | **deferred** (PTY tier). Recover path is ✓: `key_e2e::key_recover_batch_salt_iv_uuid_pairwise_distinct` |
| **key recover** | missing / nonexistent `--output-dir` → exit 2 | ✓ | `exit_usage::{key_recover_missing_output_dir, key_recover_nonexistent_output_dir_exits_two}` |
| key recover | index overflow → exit 2, no writes | ✓ | `exit_usage::key_recover_index_overflow_exits_two_no_writes` |
| key recover | validates mnemonic without a TTY | ✓ | `exit_usage::key_recover_validates_without_tty` |
| key recover | **stdin** mnemonic → v4 keystores match fixture + Loader round-trip | ✓ | `key_e2e::key_recover_keystores_match_fixture_and_loader_round_trip` |
| key recover | seed + pubkeys match fixture; recover→gen byte-stable | ✓ | `key_e2e::{recover_seed_and_pubkeys_match_fixture, key_recover_then_gen_deposit_data_byte_stable}` |
| key recover | secret hygiene (stderr); unknown word by position only | ✓ | `key_secret_hygiene::*` |
| key recover | interactive `/dev/tty` prompt path (type the mnemonic) | ⊘ | **T-9 deferred** (PTY tier; only the stdin path is testable non-interactively — and it is ✓ above) |
| **account new** | missing `--output-dir` / non-TTY / bad `--count` → exit 2 | ✓ | `exit_usage::{account_new_missing_output_dir, account_new_non_tty_exits_two, account_new_bad_count_exits_two}` |
| account new | full ceremony → v3 keystore written | ⊘→✓ | **T-3 RESCOPED** — proven via `account recover` (fixture mnemonic) → `decrypt_v3` round-trip + address check, not the ceremony. See T-3 below. |
| account new | confirmation mismatch, scrollback, symlink·new, hygiene, mnemonic-passphrase | ⊘ | **T-4/T-5/T-10/T-11/T-12·new deferred** (PTY tier; unit-tested in `account_cmd`, as key new) |
| **account recover** | missing / nonexistent `--output-dir` → exit 2 | ✓ | `exit_usage::{account_recover_missing_output_dir, account_recover_nonexistent_output_dir_exits_two}` |
| account recover | **stdin** mnemonic → v3 keystores match fixture; cross-recovery match; second run no-overwrite; batch salt/IV/id distinct | ✓ | `account_e2e::*` |
| account recover | three-form mnemonic passphrase | ✓ | `e63eb4a` (`account_e2e` / cli tests) |
| account recover | secret hygiene; unknown-word token absent | ✓ | `account_secret_hygiene::*` |
| account recover | interactive `/dev/tty` prompt path | ⊘ | **T-9 deferred** (PTY tier; stdin path is ✓ above) |
| **gen** | dry-run real pipeline emits JSON; writes output file | ✓ | `gen::{gen_dry_run_real_pipeline_emits_json, gen_writes_output_file}` |
| gen | `--verify-with-deposit-cli` pass / fail exit3 / not-found exit2 / skipped-in-dry-run | ✓ | `gen::verify_with_deposit_cli_*` |
| gen | withdrawal-address validation (missing/lowercase/checksum/zero → exit 2) | ✓ | `gen::gen_*withdrawal_address*` |
| gen | banner echoes withdrawal address + credentials | ✓ | `gen::gen_banner_echoes_withdrawal_address_and_credentials` |
| gen | **hoodi golden byte-diff vs `deposit_data-expected.json`** | ✗ | **T-7** (only field-asserts today; full golden is ⚠ in `SKILL.md`) |
| gen | **mainnet golden + `--i-understand-this-is-mainnet` guard** | ✗ | **T-8** (safety-critical, no test) |
| gen | no `--passphrase-env` in a pipe → prompts, dies non-TTY exit 2 | ✗ | **T-8** (verify-skill gotcha) |
| **build** | offline golden (holesky) + phase-2 golden | ✓ | `build::{build_golden_output, phase2_holesky_golden}` |
| build | success / stdin / stdout / file / `-`-stdout / input-alias / bad-input / bad-json / index-oob / bad-network / gas-limit-env | ✓ | `build::*` |
| build | RPC resolve unset (nonce/gas/fees), explicit-wins, unreachable exit5, estimation-fail exit5, chain-id mismatch exit2, chain-id-call-error warn+continue, env override, from-required/from-env | ✓ | `build_rpc::*` (via Stub) |
| build | **`--rpc-url` nonce resolution against a REAL node (`anvil_setNonce` probe)** | ⚠ | **T-13** (mechanism ✓ via Stub; real-node ⚠) |
| **sign** | local success / stdin / stdout / file / `-`-stdout / perms | ✓ | `sign::*` |
| sign | missing-env-key / bad-key / invalid-signer / missing-input / bad-json / bad-env-var-name / write-error exit2 | ✓ | `sign::*` |
| sign | ledger not supported (no feature) → exit 3 | ✓ | `sign::ledger_not_supported_exit3` |
| sign | phase-3 signed golden byte-identity | ✓ | `sign::phase3_local_signer_golden` |
| **run** | local happy / stdout / keep-unsigned / raw-output / perms / `-`-stdout | ✓ | `run::*` |
| run | missing-signer / ledger-no-device / invalid-input / bad-key / atomic-write-on-rename-failure / keep-unsigned-requires-file | ✓ | `run::*` |
| run | RPC derives `from` (and for gas w/ explicit nonce); bad-key exit3; ledger nonce/gas-omitted exit2; ledger both-flags passes gate | ✓ | `run_rpc::*` (via Stub) |
| run | **`--signer local --rpc-url` against a REAL node (live build+sign)** | ✗ | **T-14** (P2; `run` is a convenience wrapper) |
| **send** | happy path; confirm accept / case-insensitive / reject exit4 / eof | ✓ | `send::*` (via Stub) |
| send | chain-id mismatch; rpc-failure; dial-failure; missing-rpc/input; bad-input; receipt-write; wait-for-receipt timeout | ✓ | `send::*` |
| send | **broadcast to a REAL node; receipt from real node; deposit-contract balance grows 32 ETH** | ⚠ | **T-6** |
| send | **interactive confirm against a real node, wrong network name → exit 4** | ⚠ | **T-13** (reject is ✓ via Stub; real-node ⚠) |
| send | `ws://` RPC rejected → exit 5 | ~ | `rpc_client.rs` unit test; **T-15** (P2) at the binary level |
| **full pipe** | `gen \| build \| sign \| send` against the in-process Stub | ✓ | `e2e_pipeline::{local_signer_full_pipeline_no_rpc, local_signer_build_sign_send_mock, send_mock_receipt_polling}` |
| full pipe | **against a REAL anvil node with `--wait-for-receipt` + on-chain assertions** | ⚠ | **T-6** |
| **cross-cutting** | RPC API-key redaction in stderr (path key / query key / send) | ✓ | `redact_boundary::*` |
| cross-cutting | **SIGINT during RPC gas/nonce estimation → exit 4** | ✗ | **T-16** (P2; verify-skill gotcha) |

---

## Functional requirements

Requirements are test-coverage obligations (`T-*`). Each is a concrete, assertable behavior that the suite must exercise through the real binary. "Live tier" marks one that runs against anvil (the heavier CI tier, C-5).

> **Deferred this stage (binding scope decision, 2026-07-19):** the pseudo-terminal harness and every requirement that needs a real TTY on the `new` ceremony — **T-1, T-2, T-4, T-5, and the ceremony halves of T-9/T-10/T-11/T-12** — are moved to [Non-goals](#non-goals) as *deferred to a future PTY stage*. They are struck through below (kept for traceability), each with the in-crate unit test that guards the behavior in the meantime. **T-3 is rescoped** to the non-interactive `recover` path. **T-12 is split**: its `recover`/stdin half (T-12·recover) is kept; its `new`/ceremony half (T-12·new) defers.

### P0 — the untested-surface core

| ID | Requirement |
|---|---|
| ~~T-1~~ | **DEFERRED (PTY tier).** ~~Pseudo-terminal test harness.~~ The reusable `PtySession` helper is the prerequisite for the ceremony requirements; with those deferred it is not built this stage. Research (`research/r1-pty-driver.md`, hand-roll over `libc`) stays on file for the future stage. |
| ~~T-2~~ | **DEFERRED (PTY tier).** ~~`key new` full ceremony over a PTY.~~ The `new` success ceremony needs a real TTY. Meanwhile the derive→encrypt→write path is unit-tested (`key_cmd::happy_path_writes_n_keystores_loader_round_trip`, Loader round-trip + `0600`) and e2e-exercised via `key recover` (`key_e2e`), which runs the identical `finish_from_mnemonic` tail. |
| T-3 | **v3 keystore correctness via `account recover` + `decrypt_v3` (RESCOPED).** Feed the committed fixture mnemonic (`ABANDON_12`, empty mnemonic-passphrase) to `account recover` on piped stdin with `--passphrase-env`, producing **Web3 v3** keystores; validate structurally (`version: 3`, `crypto.cipher = aes-128-ctr`, scrypt kdf, keccak `mac`, top-level `address`, geth `UTC--…` filename, `0600`) **plus** a `decrypt_v3(json, pass) → secret → derive address == keystore `address` == fixture address` round-trip. The existing `account_e2e::account_recover_keystores_match_fixture` already does the structural + address checks but **never decrypts the ciphertext**; `decrypt_v3` (the test-only reader, C-3/D-4) closes exactly that — it validates the v3 **encrypt** path (address is written independent of the ciphertext, so address-match alone leaves encrypt unproven). `decrypt_v3` stays regardless of how the keystore was produced; the ceremony write path is not exercised here (deferred, see ~~T-2~~/Non-goals) but is byte-identical crypto to the recover path. |
| ~~T-4~~ | **DEFERRED (PTY tier).** ~~Confirmation-mismatch abort over a PTY.~~ The re-entry quiz exists only in the `new` ceremony. Unit-tested: `key_cmd`/`account_cmd::ceremony_mismatch_retry_then_abort_exit4_no_files`, `ceremony_mismatch_immediate_abort` (exit 4, nothing written). |
| ~~T-5~~ | **DEFERRED (PTY tier).** ~~`new`-path secret hygiene over a split-stderr PTY.~~ The display-once model applies only to the `new` ceremony. Unit-tested via the `tty_writer` vs `summary_out` split (`key_cmd`/`account_cmd::happy_path_*` assert the mnemonic is on `tty_writer` and absent from the summary channel). The `recover`-path hygiene tests (`key_secret_hygiene`, `account_secret_hygiene`) remain green. |
| T-6 | **Live-node full pipe chain (live tier).** Automate the verify-skill anvil run: start anvil (hoodi chain-id `560048`, ephemeral port), fund the phase-3 sender via `anvil_setBalance`, then run `gen --dry-run \| build --input-file - \| sign --input - \| send --yes --input - --rpc-url <anvil> --wait-for-receipt` and assert (a) a **successful receipt** is returned and (b) the **deposit-contract balance grows by 32 ETH** per deposit. This is the unique thing the Stub cannot prove — the Stub accepts any RLP; anvil accepts only a valid one and mutates real state (G4). |
| T-7 | **`gen` hoodi golden byte-diff.** Decrypt the committed hoodi keystore with `testdata/hoodi/passphrase.txt`, run `gen` for the fixture pubkey, and **byte-diff the output against `testdata/hoodi/deposit_data-expected.json`** (the verify-skill golden), replacing today's field-level asserts with the full golden equality the skill performs manually. |
| T-8 | **Mainnet safety guard + golden.** Assert the `--i-understand-this-is-mainnet` guard: `gen --network mainnet` **without** the flag is blocked (exit 2, message names the flag), and **with** the flag proceeds and its output byte-matches `testdata/mainnet/deposit_data-expected.json`. Also cover the verify-skill gotcha that `gen` in a pipe **without** `--passphrase-env` prompts on `/dev/tty` and dies non-TTY with exit 2 naming the flag. |

### P1 — completeness of the ceremony and live surfaces

| ID | Requirement |
|---|---|
| ~~T-9~~ | **DEFERRED (PTY tier).** ~~Interactive-prompt recover over a PTY.~~ `key recover` / `account recover` read the mnemonic from an interactive `/dev/tty` prompt **or** from stdin; the stdin path is the one testable without a TTY and it is already ✓ (`key_e2e`, `account_e2e`). Only the `/dev/tty` prompt variant needs the harness, so it defers with the PTY tier. |
| ~~T-10~~ | **DEFERRED (PTY tier), non-ceremony coverage already exists.** ~~`--mnemonic-passphrase` bare-flag prompt on the `new` ceremony.~~ The three-form `--mnemonic-passphrase` (raw argv / `--mnemonic-passphrase-env` / bare-flag prompt) is already tested on `recover` (`e63eb4a`; `account_cli`/`key_cli` three-form tests) and its **derivation-change** property is unit-tested (`account_cmd::mnemonic_passphrase_raw_honored_on_new` — with-vs-without passphrase yields different addresses). Only the bare-flag **prompt over a ceremony** defers; the security-relevant behavior is covered. |
| ~~T-11~~ | **DEFERRED (PTY tier).** ~~Scrollback clear after the ceremony (`284d478`).~~ The clear only fires after the `new` mnemonic display. Unit-tested byte-for-byte and for order: `key_cmd::clear_sequence_bytes_and_order` (locks `\x1b[2J\x1b[3J\x1b[H` ×2 after the mnemonic) and `abort_path_still_clears`. |
| T-12·recover | **Symlink `--output-dir` warning on the `recover`/stdin path (KEPT).** Assert the warning added in `1736843` when `--output-dir` is a symlink, on the non-interactive `recover` path (mnemonic on piped stdin): a symlinked output dir emits the documented warning on stderr and still writes. Reachable without a TTY — `load_config` calls `warn_if_symlinked_output_dir(…, banner_out)` for `recover` (`key_cli.rs:266` / `account_cli.rs:179`), already unit-verified by `recover_load_config_warns_on_symlinked_output_dir`; this adds the binary-level assertion. **T-12·new** (the same warning on the `new` ceremony) defers with the PTY tier. |
| T-13 | **Live-tier hybrid RPC probes (live tier).** Against anvil: (a) `build --rpc-url <anvil> --from <addr>` with nonce/gas omitted resolves nonce from the real node — probe by `anvil_setNonce` to a nonzero value and assert it appears in the built tx (the real-node analog of `build_rpc::rpc_resolves_unset_fields`); (b) interactive `send` (no `--yes`) against anvil with the **wrong** network name → exit 4. |
| T-14 | **CI two-tier wiring.** Wire the suite into CI as two tiers (C-5): the **hermetic tier** (the existing ~130 tests + this stage's new hermetic tests: T-3-rescoped, T-7, T-8, T-12·recover, T-19, and P2 T-15/T-16) runs on every PR alongside the current `make test` / `make e2e-mock`; the **live tier** (anvil tests T-6, T-13) is `#[ignore]`-gated and runs in a **separate job** that installs foundry via a commit-pinned action (per the CI-pinning hardening `9bec2c2`). No PTY tests exist this stage (deferred), so the hermetic tier needs no PTY plumbing. Whether the live job is PR-blocking or nightly/pre-release/manual is an [Open question](#open-questions) (recommended: not PR-blocking). |

### P2 — polish (non-blocking)

| ID | Requirement |
|---|---|
| T-15 | **`ws://` rejection at the binary level → exit 5.** Covered by a unit test in `crates/ethernal-tx/src/rpc_client.rs` today; add a thin binary-level assertion (`send --rpc-url ws://…` → exit 5) so the end-to-end contract in `SKILL.md`'s gotchas is nailed down through the CLI, not just the crate. |
| T-16 | **SIGINT during RPC estimation → exit 4.** The verify-skill/exit-code contract says a Ctrl-C during gas/nonce estimation aborts with exit 4; send SIGINT to the child mid-estimation (against a deliberately slow stub or anvil) and assert exit 4 with no broadcast. |
| T-17 | **`run --signer local --rpc-url` against anvil (live tier).** A live-tier happy path for the `run` convenience wrapper against a real node, complementing the Stub-based `run_rpc` tests. Lower value because `run`'s underlying build+sign *logic* is live-exercised via T-6 — but note T-6 pipes the **separate** `build` and `sign` stages, so the one thing unique to `run` (the in-process build→sign hand-off with no serialization to disk) is **not** itself live-covered by T-6; T-6 covers the pipeline, `run::local_signer_happy_path` covers `run`'s happy path hermetically (G1), and this item would add the live variant. |
| T-18 | **Verify-skill parity audit.** A checklist (doc or a lightweight meta-test) mapping every step of `SKILL.md` to the automated test that now covers it, with the carve-outs (ledger, cross-tool parity) explicitly marked non-automatable — so "the verify skill is automated" (G3) is a checkable claim, and skill drift is caught. |
| T-19 | **`gen --parallel` determinism.** The `--parallel` flag (`gen_cli.rs`) has no test; assert that parallel keystore decryption produces output byte-identical to the serial path (reuse the T-7 hoodi golden with `--parallel` set), guarding against ordering/nondeterminism in the concurrent path. |

---

## Non-functional requirements

### Constraints

| ID | Constraint |
|---|---|
| C-1 | **Rust-only workspace; a new dependency needs justification.** `bins/ethernal/Cargo.toml` has an **empty `[dev-dependencies]`** section today — the JSON-RPC stub, temp dirs, and all scaffolding are hand-rolled in `tests/common/mod.rs`. Any new test dependency (the PTY driver is the only likely candidate) must be justified against that house style. `libc` is already a **runtime** dependency, so a hand-rolled `openpty` harness introduces no new crate; a small dev-only PTY crate is acceptable only if research shows hand-rolling is impractical. The anvil tier shells out to the `anvil`/`cast` binaries (external toolchain, live tier only) rather than adding a Rust EVM dependency. |
| C-2 | **Deterministic and CI-safe; the mnemonic is *given*.** The hermetic tier must be fully deterministic and network-free. Because the release binary has **no entropy-injection hook** (confirmed: `key_recover_help_has_no_entropy_flag`, `account_recover_help_has_no_entropy_or_time_flag` assert the absence), determinism comes from a **committed fixture mnemonic fed to `recover`**, not from a captured-and-replayed `new` mnemonic (that path deferred with the PTY tier). The single source of truth is `ABANDON_12` (`abandon…about`), already used by `key_e2e.rs` and `account_e2e.rs`, with known-answer seeds/addresses/pubkeys in `testdata/eoa/cross-recovery.json` and `testdata/keygen/pubkeys.json`. The live tier uses ephemeral ports (not the skill's fixed `8599`) to avoid collisions and must tolerate receipt-poll timing. |
| C-3 | **Respect existing test conventions.** New tests live in `bins/ethernal/tests/` and reuse `common/mod.rs` (the `ethernal()` env-scrubbing command builder, `TempDir`, `Stub`, fixture accessors). The **anvil harness** is added to `common/` alongside `Stub` (the PTY harness is deferred). Golden fixtures reuse `testdata/**`; no fixture is duplicated. The v3 keystore has **no in-binary reader**; v3 validation uses the test-only, feature-gated `decrypt_v3` (compiled out of release, C-1/D-4), never an in-binary decrypt (T-3). |
| C-4 | **Unix-only harnesses** (`#[cfg(unix)]`). This stage that is the **anvil harness**; the deferred PTY harness (`openpty`) is Unix-only for the same reason. Covers ubuntu CI and darwin local development; Windows is out of scope (there is no Windows target today). |
| C-5 | **Two CI tiers, isolated.** The **hermetic tier** (no network, no external toolchain, deterministic) runs on every PR. The **live tier** (anvil-backed) is separated so real-node flakiness — ephemeral ports, receipt-poll timing, gas — never blocks a PR; it is `#[ignore]`-gated and installs foundry in its own job. This directly answers "should anvil run in CI": yes, but as an isolated gate, not inline with the hermetic suite (G7). |
| C-6 | **Secrets stay synthetic.** All keys, mnemonics, and passphrases are the committed synthetic fixtures (phase-3 key `0x0101…01`, the hoodi/mainnet test keystores). No test uses or derives a real-fund key, and no test broadcasts to any public network (anvil only). |

---

## Non-goals

Explicitly **out of scope**:

- **Interactive `new`-ceremony automation and the PTY tier — deferred to a future stage (binding user decision, 2026-07-19).** Building a PTY driver is out of scope this stage; automated tests assume the mnemonic is *given* and drive the non-interactive `recover` path. Deferred requirements, each still guarded this stage by an in-crate unit test in `key_cmd`/`account_cmd` (the manual verify skill does **not** cover the ceremony — it is `gen → build → sign → send`): **T-1** (PTY harness), **T-2** (`key new` ceremony), **T-4** (mismatch abort), **T-5** (new-path hygiene), **T-9** (`/dev/tty` recover prompt), **T-10** (mnemonic-passphrase over the ceremony — non-ceremony coverage already exists on `recover`), **T-11** (scrollback clear), and **T-12·new** (symlink warning on the ceremony). This is a **deferral, not a deletion** — the research verdict (`research/r1-pty-driver.md`: hand-roll `PtySession` over `libc`) is preserved and remains valid for the future stage. Kept by rescoping to the non-interactive path: **T-3** (v3 via `recover` + `decrypt_v3`) and **T-12·recover** (symlink warning on `recover`).
- **Ledger hardware signing.** The `--signer ledger` signing path needs a physical device and is called out as non-coverable in the skill's own gotchas. It stays validated by the existing negative tests (`sign::ledger_not_supported_exit3`, `run::ledger_no_device`, the `run_rpc` ledger-gate tests) and the CI `--features ledger` **compile** check; the actual signing round-trip is not automatable here.
- **Real mainnet (or public testnet) broadcast.** The live tier broadcasts **only to a local anvil** with synthetic keys. `send` is never pointed at a real network (this is also why T-8's mainnet coverage is `gen`-golden + the guard flag, never a broadcast).
- **Cross-tool keystore import parity** (geth / foundry / MetaMask unlocking a keystore we wrote). That is the eoa-keystore feature's **manual per-release** session (`../eoa-keystore/prd.md` G1/C-2) and depends on external tooling; it is not re-automated here. G3's "verify skill automated" is scoped to the skill's *automatable* steps and explicitly excludes this.
- **Performance, load, soak, or fuzz testing.** This suite is functional-correctness e2e only.
- **Expanding crate-level unit tests.** This PRD is the **binary-level** e2e boundary; unit tests (e.g. the `ws://` rejection in `rpc_client.rs`) stay where they are — T-15 only adds the thin CLI-level assertion on top.
- **New product commands or flags.** The suite tests the current surface (`key`/`account` `new`+`recover`, `gen`, `build`, `sign`, `run`, `send`); it does not drive feature work.
- **Windows / non-Unix PTY support** (C-4).

---

## Assumptions

Recorded because this PRD was written without a live approval loop. The two headline items (A-1, A-2) are also [Open questions](#open-questions) for the downstream research/architecture stages.

- **A-1 — PTY driver (headline) — RESOLVED, then DEFERRED.** Research settled it (hand-roll `PtySession` over `libc`'s `openpty`, no dev-dep — `research/r1-pty-driver.md`), and the **binding scope decision (2026-07-19) then deferred the entire PTY tier**. No PTY harness is built this stage; the verdict is preserved for the future stage. OQ-1 is therefore moot this stage.
- **A-2 — Anvil in CI (headline).** The live tier is assumed to run in CI as a **separate, `#[ignore]`-gated job** that installs foundry via a commit-pinned action. The **cadence** — PR-blocking vs nightly vs pre-release-only vs manual-dispatch — is assumed **not PR-blocking** (nightly + pre-release + manual), so the hermetic tier alone gates PRs. Confirm at architecture/planning.
- **A-3 — Anvil parameters.** Reuse the verify-skill chain params (hoodi chain-id `560048`), but an **ephemeral port** instead of the fixed `8599`, and fund the phase-3 sender via `anvil_setBalance`. Synthetic phase-3 key only.
- **A-4 — "Verify skill automated" is scoped to its automatable steps.** Golden checks, live-anvil pipe, hybrid probes, and the exit-code matrix are automatable; **ledger signing and cross-tool import parity are not** and remain manual (documented via T-18, not silently dropped).
- **A-5 — The mnemonic is *given* (fixture-mnemonic recover model).** Because the release binary has no entropy-injection hook (C-2) and the `new` ceremony is deferred, determinism comes from feeding the committed fixture mnemonic (`ABANDON_12`) to `recover` — the model the existing `key_e2e`/`account_e2e` tests already use. Known-answer seeds/addresses/pubkeys live in the committed fixtures; T-3 adds the `decrypt_v3` round-trip on top.
- **A-6 — Anvil availability locally.** Local runs assume `anvil`/`cast` may be absent; live-tier tests **skip with a clear message** when the binary is missing (they never fail for a missing external toolchain). CI's live job installs it.
- **A-7 — Scope is the current command surface.** No new commands are added or anticipated; `run`'s live variant (T-17) is P2 because `run` is `build`+`sign` composed and both are live-tested via T-6.

## Open questions

- **OQ-1 — PTY driver: hand-roll vs dev-dep? — MOOT this stage (PTY tier deferred).** Research resolved it (hand-roll over `libc`, `research/r1-pty-driver.md`) before the binding scope decision deferred the whole tier. Re-opens only if/when the ceremony automation is picked up in a future stage.
- **OQ-2 — Live-tier cadence?** (A-2, T-14) PR-blocking, nightly, pre-release-only, or manual-dispatch? Recommendation: **not** PR-blocking — hermetic tier gates PRs; live tier runs nightly + on release + on-demand. Confirm at planning.
- **OQ-3 — Anvil provisioning locally?** (A-6) Should the harness auto-download foundry when absent, or skip-with-notice and require a preinstalled `anvil`? Recommendation: **skip-with-clear-message** locally; CI installs via pinned action.
- **OQ-4 — v3 keystore validation depth.** (T-3, C-3) With no in-binary v3 reader, is structural + recover-address-cross-check sufficient, or should a **test-only** v3 decrypt helper live in the suite to assert the ciphertext decrypts to the expected secret? Recommendation: structural + recover-cross-check for v1; add a test-only decrypt only if it proves necessary (and never ship a reader in the binary — that is the eoa-keystore follow-up).
- **OQ-5 — Do we automate `run --rpc-url` live (T-17) or leave `run` to Stub-only + the composed T-6 chain?** Recommendation: P2 / defer — low marginal value.
