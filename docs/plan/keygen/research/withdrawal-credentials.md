# Research — withdrawal credentials (0x01 for K5; 0x00 / 0x02 context)

**Question:** what is the exact 0x01 execution-address credential format and its validation
rules, how does staking-deposit-cli validate `--execution-address`, and is 0x01 the right v1
target (vs 0x02 compounding)?

**Verdict: 0x01 is correct for v1; validation is stricter than the PRD states.** The 0x01
format is `0x01 ‖ 11 zero bytes ‖ 20-byte address` (confirmed in staking-deposit-cli source).
**Contradiction to surface:** staking-deposit-cli / ethstaker-deposit-cli **require an EIP-55
checksummed address and reject plain lowercase** — the PRD (F-13) only says "0x-prefixed
20-byte hex", and the repo's own `--from` parser is lenient (accepts any case, no checksum).
0x02 (compounding, Pectra) is **not** needed for a 32-ETH deposit tool.

## 0x01 execution-address credential

Format (32 bytes): `0x01` ‖ `0x00 × 11` ‖ `<20-byte execution address>`. From
[staking-deposit-cli `credentials.py`](https://github.com/ethereum/staking-deposit-cli/blob/master/staking_deposit/credentials.py):

```python
withdrawal_credentials  = ETH1_ADDRESS_WITHDRAWAL_PREFIX      # 0x01
withdrawal_credentials += b'\x00' * 11
withdrawal_credentials += self.eth1_withdrawal_address        # 20 bytes
```
This is exactly PRD F-13. The address bytes are the raw 20 bytes; the on-chain deposit contract
and consensus layer read bytes `[12..32]` as the execution withdrawal address.

## Validation — staking-deposit-cli requires EIP-55 (divergence from PRD + repo `--from`)

From [staking-deposit-cli `utils/validation.py`](https://github.com/ethereum/staking-deposit-cli/blob/master/staking_deposit/utils/validation.py),
`validate_eth1_withdrawal_address`:

```python
if not is_hex_address(address):
    raise ValidationError(...)
if not is_checksum_address(address):
    raise ValidationError(load_text(['err_invalid_ECDSA_hex_addr_checksum']))
return to_normalized_address(address)
```

- **Requires a correct EIP-55 mixed-case checksum** (`is_checksum_address`). An all-lowercase
  address fails unless its correct checksum happens to be all-lowercase (effectively never), so
  **lowercase input is rejected**.
- After validation the address is normalized to lowercase (`to_normalized_address`) before use.

**The repo diverges two ways today:**
- `parse_from_flag` (build's `--from`, `bins/eth-deposit/src/config.rs:142-156`) is **lenient**:
  strip `0x`, `hex::decode`, require 20 bytes — **no checksum check, any case accepted**
  (test `from_valid_variants` passes a mixed-case address as valid).
- The repo *has* EIP-55 **encoding** but not **validation**: `eip55_checksum(&[u8;20]) -> String`
  at `crates/signer/src/local.rs:293` produces a checksummed string, but it is `pub(crate)`
  (used only for signer error messages) and is not exported from the `signer` crate.

**Decision for K5 (flag it at the gate):** to match staking-deposit-cli parity for
`--withdrawal-address`, enforce EIP-55: reject a non-checksummed mixed-case address, and decide
whether to accept all-lowercase as a convenience. Either
(a) **strict parity** — require a valid EIP-55 checksum (reuse the checksum logic behind
`eip55_checksum` by comparing `input == eip55_checksum(bytes)`; this needs the function exposed
from `signer`, or a small re-implementation in the bin — see `existing-code-map.md`), or
(b) **lenient like `--from`** — accept any-case 20-byte hex, skip the checksum. Option (a)
matches the reference tool and catches address typos (the entire point of EIP-55); recommend (a),
but this is a scope call for the gate because it is stricter than PRD F-13 as written.

## 0x02 compounding (Pectra / EIP-7251) — not for v1

- Format: `0x02 ‖ 0x00 × 11 ‖ <20-byte address>` (same shape as 0x01, different prefix byte).
- Semantics: a **compounding** validator whose effective balance can grow to **2048 ETH**;
  rewards stay in the balance instead of auto-withdrawing above 32 ETH. Introduced with
  [EIP-7251 / Pectra](https://github.com/ethstaker/ethstaker-deposit-cli/releases); the
  deprecated staking-deposit-cli has **only** 0x00/0x01, while the maintained
  ethstaker-deposit-cli adds 0x02.
- **Why 0x01 is the right v1 target:** `gen` hard-codes a **32-ETH** deposit
  (`amount_gwei = 32_000_000_000`, `gen_cmd.rs:305`). 0x02's value is deposits >32 ETH /
  compounding; it is meaningless for a fixed 32-ETH deposit. Ship 0x01.
- **Flag-naming forward-compat:** `--withdrawal-address ADDR` is prefix-agnostic — both 0x01 and
  0x02 take the same 20-byte execution address and differ only in the prefix byte and deposit
  amount. A future 0x02 mode is an additive flag (e.g. `--compounding` + a variable amount), not
  a redesign. Keep the address flag as the address; do not bake "0x01" into its name.

## 0x00 BLS credential (deferred out of v1 — consistent with PRD, not a contradiction)

- Format: `0x00 ‖ SHA256(withdrawal_pubkey)[1:]` (drop the first hash byte). From
  `credentials.py`: `BLS_WITHDRAWAL_PREFIX + SHA256(self.withdrawal_pk)[1:]`.
- PRD Q1 → (c): **deferred**. v1 ships only 0x01; the all-zero placeholder stays until a
  follow-up. So the **derived withdrawal pubkey is computed but unused in v1 credentials** — this
  is by design (F-14 deferred), not an oversight. Both this doc and `existing-code-map.md` say so
  to keep the two consistent.

## How credentials flow through the existing code (wire points for K5)

- `deposit::Request.withdrawal_credentials: [u8; 32]` (`crates/core/src/deposit.rs:101`) is
  applied uniformly to every entry and flows into **both** `ssz::DepositMessage` (deposit.rs:216)
  and `ssz::DepositData` (deposit.rs:239). So setting the 32-byte credential is the *only* change
  needed — the signing root and deposit-data root update automatically.
- Today `process_pubkey` hard-codes `withdrawal_credentials: default_withdrawal_creds()`
  (`gen_cmd.rs:304`), where `default_withdrawal_creds()` returns `[0u8; 32]` (gen_cmd.rs:31) — a
  type-0x00 prefix with an all-zero body (the placeholder). **K5 wire point:** thread a resolved
  `[u8;32]` (built from `--withdrawal-address`) from `GenConfig` into the `Request` here.
- `Entry::validate()` (deposit.rs:391-413) does **not** inspect `withdrawal_credentials` at all —
  no length/prefix check — so nothing blocks swapping in a real 0x01 credential, and nothing
  currently rejects the placeholder either.
- **K5 gate (PRD Q2, binding):** once K5 lands, `gen` **without** `--withdrawal-address` must
  exit 2 with a clear message (no deposit built on the all-zero placeholder by accident). This is
  a new required-flag-style check in `gen_cli::load_config` (mirror the `--output-dir` conditional
  check at `gen_cli.rs:205-211`), *not* a clap `required(true)` (so `--dry-run` and future 0x00
  wiring stay expressible).

## Implications for our implementation

1. **Build the 0x01 credential** as `0x01 ‖ [0u8;11] ‖ addr20` and set it on `Request`
   (gen_cmd.rs:304); everything downstream (SSZ roots, JSON) updates for free.
2. **Parse `--withdrawal-address` strictly like `parse_from_flag`** (strip `0x`, hex-decode,
   require 20 bytes; exit 2 otherwise) — and **decide the EIP-55 question at the gate**
   (recommend strict-checksum parity with staking-deposit-cli). If strict, expose/duplicate the
   `eip55_checksum` compare; `signer`'s copy is `pub(crate)` today.
3. **Gate `gen` to require an explicit withdrawal choice** (exit 2 without `--withdrawal-address`),
   per PRD Q2. Add it to `load_config`, not as a clap `required` flag.
4. **Do not build 0x02** in v1; keep `--withdrawal-address` prefix-agnostic so 0x02 is a future
   additive flag. **Do not build real 0x00** in v1 (deferred); the withdrawal pubkey we derive is
   intentionally unused by v1 credentials.
