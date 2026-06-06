# Research: EIP-7251 `0x02` Compounding Withdrawal Credentials — Feasibility for v1.1

## Verdict
**EIP-7251 `0x02` compounding credentials are live on mainnet (Pectra, May 2025), the byte layout is identical-structure to `0x01` (`0x02 || 11 × 0x00 || 20-byte execution address` [1][2]), and the canonical CLI (`ethstaker-deposit-cli`) has shipped support since v0.5.0 (stabilized v1.0.0, 2024-12-18) [3]. The PRD's deferral to v1.1 (§11.4) is reasonable, but one concrete PRD assumption is contradicted: FR-P0-G2 centralizes `DepositAmountGwei = 32_000_000_000` as a constant — this must become a range (`MinDepositGwei=32e9 .. MaxDepositGwei=2048e9`) before v1.1 0x02 work can land, or the constant must be removed at that time.**

## Context
- **Question:** What does v1.1 actually have to implement to support `0x02`, and does FR-P0-G2 block it?
- **Why it matters:** §11.4 leaves the timing open; if 0x02 is a near-term ask, FR-P0-G2's flat constant becomes technical debt the moment it lands.

## Findings

### What Works (canonical surface)
- **Constant:** `COMPOUNDING_WITHDRAWAL_PREFIX = Bytes1('0x02')` [1][4].
- **Layout:** Same as `0x01`: `0x02 || 11 zero bytes || 20-byte execution address`. Confirmed by the spec's `switch_to_compounding_validator(state, index)` which "replaces only the first byte of withdrawal_credentials with COMPOUNDING_WITHDRAWAL_PREFIX, keeping all remaining bytes unchanged" [2][4]. A validator can swap 0x01 → 0x02 via a 7251 consolidation request (source==target) without changing the address bytes.
- **Activation:** Pectra fork (Electra on the CL side), live on mainnet **May 2025**.
- **Effective balance range:** `MIN_ACTIVATION_BALANCE = 32 ETH`, `MAX_EFFECTIVE_BALANCE_ELECTRA = 2048 ETH` [1].
- **Deposit amount semantics:** A new 0x02 deposit can be **any value from 32 to 2048 ETH inclusive**; balance above 32 ETH auto-compounds for 0x02 validators, withdraws automatically for 0x01.
- **Consensus-side helpers:** `has_compounding_withdrawal_credential`, `is_compounding_withdrawal_credential`, `get_max_effective_balance(validator) → 2048 ETH if has_compounding else 32 ETH` [2][4].

### What Doesn't Work (correctly, for our v0.2)
- **None — we don't support 0x02 in v0.2.** The PRD is explicit and correct here.

### Open Questions
- **Does v0.2's `internal/tx/validation.go` need to accept 0x02 today?** Currently it rejects any unknown prefix. If a third-party tool generates 0x02 deposit data and an operator uses our `eth-deposit-tx build` against it, we'd reject — *correctly* for v0.2 since we never claim 0x02 support. **No action for v0.2.** But document the rejection error clearly.
- **Does FR-P0-G2's constant-ization block v1.1?** Yes, soft-block. The work to land 0x02 has to undo this constant; better to design as a range upfront, OR explicitly comment in the constant declaration that this is "v0.2 single-amount; will become a range for 0x02 in v1.1".
- **PRD §11.4 framing:** "Track as v1.1 (M2) item or defer to a vNext PRD? This PRD assumes the latter." If deferred to vNext, the FR-P0-G2 comment alone is enough; if it's M2-scoped, the constant should be range-shaped now.

## Proof of Concept

A minimum-viable v1.1 implementation requires:

```go
// internal/network/network.go (proposed v1.1 additions)
const (
    MinDepositGwei uint64 = 32_000_000_000     // MIN_ACTIVATION_BALANCE
    MaxDepositGwei uint64 = 2_048_000_000_000  // MAX_EFFECTIVE_BALANCE_ELECTRA
)

// internal/deposit/credentials.go (proposed)
func BuildCompoundingCreds(addr common.Address) ([32]byte, error) {
    var wc [32]byte
    wc[0] = 0x02
    copy(wc[12:], addr.Bytes())
    return wc, nil
}

// internal/tx/validation.go (proposed)
case 0x02:
    if !allZero(creds[1:12]) {
        return ErrWithdrawalCredentialsInvalidShape
    }
    // last 20 bytes treated as execution address; no further format check.
```

And a `--withdrawal-compounding-address` flag (or shared `--withdrawal-address` with explicit `--withdrawal-prefix 0x02`) on `eth-deposit-gen`.

## Effort Estimate
- **v1.1 effort to add 0x02 support:** small — ~1 day of code + ~1 day of tests + ~½ day of doc/CLI ergonomics. Bulk of the work is around the amount-range UX:
  - `--amount` flag (Gwei or ETH; with bounds check).
  - Per-network validation that 0x02 only at-or-after Electra activation (already true for all networks we support: mainnet, holesky-pectra, sepolia-pectra, hoodi all activated by 2025).
  - Update `internal/output/output.go` to emit a non-32-ETH `amount` field correctly.
  - Cross-validation against `ethstaker-deposit-cli` 0x02 path.
- **Refactoring impact on FR-P0-G2:** ~10 LOC; tactical.

## Risks
- **R1.** Mixing 0x01 and 0x02 in the same `deposit_data-*.json` batch may confuse third-party launchpads — most do parse per-entry. Recommend a batch-mode validation that all entries share a prefix in a given file, with an explicit override.
- **R2.** Amount > 32 ETH per deposit raises the per-mistake stake. The mainnet acknowledgement gate (FR-P1-A1) should display the amount prominently, not just chainID/to.
- **R3.** EIP-7251's separate consolidation flow (`CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS = 0x0000BBdDc7CE488642fb579F8B00f3a590007251` [1]) is **out of scope** for this tool — we only build *initial* deposits. Document the boundary.
- **R4.** The PRD's open question §11.4 should be **decided** (track as M2 vs vNext) before FR-P0-G2 lands as written, OR the constant should be shaped as a range upfront. **Flag for team-lead.**

## Recommendation
1. **In v0.2,** comment `DepositAmountGwei` as "deposit amount fixed for 0x00/0x01 in v0.2; will become a range when 0x02 lands per §11.4". This is a one-line annotation.
2. **In v1.1 (M2),** introduce `MinDepositGwei`/`MaxDepositGwei`, replace single constant, add `--amount` flag with validation, add `--withdrawal-prefix 0x02` (or `--compounding-address`) per the canonical CLI's flag shape.
3. **Resolve PRD §11.4** now: track as M2 (recommended) so the constant design happens once.
4. **No v0.2 contradiction** if the comment is added; otherwise FR-P0-G2 will need amendment.

## Feasibility: ✅ GREEN (for v1.1 implementation). 🟡 YELLOW (PRD constant design needs annotation).

## Sources

[1] [EIP-7251: Increase MAX_EFFECTIVE_BALANCE](https://eips.ethereum.org/EIPS/eip-7251) — Ethereum. COMPOUNDING_WITHDRAWAL_PREFIX = `Bytes1('0x02')`; MIN_ACTIVATION_BALANCE = 32 ETH; MAX_EFFECTIVE_BALANCE_ELECTRA = 2048 ETH; CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS = 0x0000BBdDc7CE488642fb579F8B00f3a590007251.
[2] [consensus-specs — Electra beacon-chain.md](https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md) — Ethereum. switch_to_compounding_validator only replaces the first byte; has_compounding_withdrawal_credential; get_max_effective_balance.
[3] [ethstaker/ethstaker-deposit-cli releases](https://github.com/ethstaker/ethstaker-deposit-cli/releases) — ethstaker. v0.5.0 introduced 0x02 / EIP-7251 support; v1.0.0 "Ethereum Key Forge" (2024-12-18) stabilized; v1.3.0 (2026-04-30) latest.
[4] [eth2book §3.2.2 — Constants](https://eth2book.info/latest/part3/config/constants/) — Ben Edgington. Annotated COMPOUNDING_WITHDRAWAL_PREFIX, MAX_EFFECTIVE_BALANCE_ELECTRA.
[5] [LinkedIn — What is EIP-7251](https://www.linkedin.com/pulse/what-eip-725-increase-maxeffectivebalance-tara-annison-szpie) — Tara Annison. Operator-perspective summary; activation date confirmation.
[6] [P2P.org — Ethereum Validator Consolidation After Pectra](https://p2p.org/economy/validator-playbook-ethereum-validator-consolidation-pectra/) — P2P.org. Post-mainnet-activation operational view.
