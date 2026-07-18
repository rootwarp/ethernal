# Phase K5 — Withdrawal credentials (`gen`)

**Theme:** Give `gen` real 0x01 execution-address withdrawal credentials via `--withdrawal-address`, plus a
require-explicit-choice gate. Stream B.
**Issues:** K5-1, K5-2 · **Points:** 3.
**Execution order — K5 runs BEFORE K4** (phase numbers are thematic). K4-1 **depends on K5-2**, so K5 lands
first and the E2E deposit-data fixture freezes **once** against the require-choice `gen` with real 0x01 creds —
never a placeholder-cred fixture K5 would invalidate. Read this file before `phase-k4.md`. Full order:
K1 → K2/K3 → **K5** → K4.
**Milestone gate — M-K5:** `gen --withdrawal-address <checksummed>` emits 0x01 creds in the deposit data;
`gen` with no withdrawal choice → exit 2; EIP-55 lowercase/mismatch → exit 2 (gate + flag ship in one release).

Signatures from [`architecture.md`](../architecture.md) §"`signer` EIP-55 exposure", §"K5 — `gen` changes";
format + validation + wire points from
[`research/withdrawal-credentials.md`](../research/withdrawal-credentials.md).

---

## K5-1 — `signer::validate_eip55_address` + `core::deposit::eth1_withdrawal_credentials`

**Points:** 1 · **Stream:** B · **Depends on:** — · **Milestone:** M-K5

**Goal:** Expose strict EIP-55 validation from `signer` (rejects lowercase / checksum-mismatch) and add the 0x01
credential constructor to `core`, with no new crate edge or dependency. Satisfies F-13 (EIP-55 checksummed
address; `0x01 ‖ 11 zero bytes ‖ addr20`) and G6.

**Implementation notes**
- Change `crates/signer/src/local.rs`: raise `eip55_checksum` from `pub(crate)` (`local.rs:293`) so it can be
  re-exported.
- Change `crates/signer/src/lib.rs`: `pub use local::eip55_checksum;` and add `pub fn
  validate_eip55_address(s: &str) -> Result<[u8;20], String>` — strip `0x`, hex-decode, require exactly 20 bytes,
  require `input == eip55_checksum(bytes)` (rejects lowercase, F-13). Returns the raw 20 bytes. Keccak is already
  in `signer` via `sha3` — no new dep, no new edge (the bin already links `signer`).
- Change `crates/core/src/deposit.rs`: add `pub fn eth1_withdrawal_credentials(addr: [u8;20]) -> [u8;32]` =
  `0x01 ‖ 0x00×11 ‖ addr` (research/withdrawal-credentials.md §"0x01 execution-address credential").

**Acceptance criteria**
- [x] `validate_eip55_address` accepts a correctly EIP-55-checksummed 20-byte address (returns its 20 bytes) and
  **rejects** its all-lowercase form and any checksum-mismatched form (`input != eip55_checksum(bytes)`) — F-13
  (research/withdrawal-credentials.md §"Validation — staking-deposit-cli requires EIP-55").
- [x] `validate_eip55_address` rejects wrong length and non-hex input with an error → exit 2 (mapped in K5-2) —
  F-13.
- [x] `eth1_withdrawal_credentials(addr)` == `0x01` ‖ 11 zero bytes ‖ `addr` (byte 0 = `0x01`, bytes 1..12 zero,
  bytes 12..32 == addr) — F-13, G6 (research/withdrawal-credentials.md §"0x01 execution-address credential").
- [x] `eip55_checksum` is exported `pub` from `signer`; `cargo tree` shows no new crate edge and no new dependency
  — architecture §Design note (b).

**Test plan**
- Unit tests in `signer`: a known checksummed address round-trips to 20 bytes; its lowercase form → `Err`; a
  single-nibble-case-flip → `Err`; 19/21-byte and non-hex inputs → `Err`.
- Unit test in `core::deposit`: `eth1_withdrawal_credentials` byte layout asserted (prefix, zero body, address
  tail).

**Notes**
- Strict EIP-55 (reject lowercase) diverges intentionally from `build`'s lenient `--from` (`parse_from_flag`,
  `config.rs:142`, which accepts any case) — ethstaker-deposit-cli parity. The asymmetry is documented in K4-2
  (risk R5).

---

## K5-2 — `gen --withdrawal-address` + require-choice gate

**Points:** 2 · **Stream:** B · **Depends on:** K5-1 · **Milestone:** M-K5

**Goal:** Add `gen --withdrawal-address ADDR` that threads a real 0x01 credential into the deposit data, and — in
the **same** issue/merge/release — gate `gen` to require an explicit withdrawal choice (absent flag → exit 2), so
no deposit is ever built on the all-zero placeholder by accident. Satisfies F-13, PRD Q2 (binding), G6.

**Implementation notes**
- Change `bins/eth-deposit/src/gen_cli.rs`:
  1. `command()` adds `--withdrawal-address ADDR` (optional `String`).
  2. In `load_config`, after existing validations, parse via `signer::validate_eip55_address` (exit 2 on bad
     hex/length/checksum), build `core::deposit::eth1_withdrawal_credentials(addr)`, and store the resolved
     `[u8;32]` on a new `GenConfig::withdrawal_credentials` field.
  3. **Require-choice gate:** a conditional check mirroring the `--output-dir` check (`gen_cli.rs:205-211`) —
     **not** clap `required(true)` — so absent `--withdrawal-address` → exit 2 with a clear message, keeping
     `--dry-run` and a future 0x00 flag expressible.
- Change `bins/eth-deposit/src/gen_cmd.rs`: `process_pubkey` uses `cfg.withdrawal_credentials` in the `Request`
  (`gen_cmd.rs:304`) instead of `default_withdrawal_creds()`. Downstream SSZ roots + JSON update for free
  (`Request.withdrawal_credentials` flows into both `DepositMessage` and `DepositData`, `deposit.rs:101`).
- Keep `default_withdrawal_creds()` (`gen_cmd.rs:31`) as the documented, now-unreachable placeholder for the
  deferred 0x00 path (F-14).

**Acceptance criteria**
- [x] `gen --withdrawal-address <checksummed>` emits a `0x01 ‖ 11 zero ‖ addr20` credential in the deposit data;
  the `DepositMessage`/`DepositData` roots reflect it (updated for free) — F-13, G6
  (research/withdrawal-credentials.md §"How credentials flow").
- [x] `gen` **without** `--withdrawal-address` → exit 2 with a clear message (require-choice gate, a conditional
  check in `load_config`, not clap `required(true)`) — PRD Q2, F-13 (risk R2).
- [x] a lowercase or checksum-mismatched `--withdrawal-address` → exit 2 (via `validate_eip55_address`) — F-13.
- [x] flag + gate ship in **one** issue / one merge / one release; `default_withdrawal_creds()` remains present as
  the documented, unreachable placeholder — risk R2, F-14.

**Test plan**
- Command-level tests in `bins/eth-deposit/tests/gen.rs`: a checksummed address → 0x01 creds appear in the deposit
  data; absent `--withdrawal-address` → exit 2; lowercase → exit 2; checksum-mismatch → exit 2.
- Update the existing `gen` goldens/tests that previously ran without `--withdrawal-address` to pass a checksummed
  address (or assert the new exit-2 gate).

**Notes**
- Breaking change to `gen` (accepted — the Rust binary has no tagged releases; PRD Q2). Any existing `gen` test or
  golden invoked without `--withdrawal-address` must be updated. Documented in the K4-2 CHANGELOG.
- K4-1's E2E deposit-data fixture is frozen **after** this issue lands, carrying real 0x01 creds once.
