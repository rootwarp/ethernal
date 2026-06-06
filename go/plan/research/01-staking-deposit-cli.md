# Research: staking-deposit-cli — Reference Behavior for Withdrawal Credentials, JSON Schema, and Cross-Validation

## Verdict
**Feasible, with one important upstream change.** The PRD's plan to (a) emit `0x01` credentials via `--withdrawal-address`, (b) emit `0x00` credentials via `--withdrawal-bls-pubkey`, and (c) gate v0.2 release on a `--verify-with-deposit-cli` integration test (FR-P1-G1) is sound and matches the dominant reference behavior. **However**, the original `ethereum/staking-deposit-cli` was **deprecated on 2025-10-06** [1]; the live, maintained fork is `ethstaker/ethstaker-deposit-cli` [2], and EIP-7251 `0x02` compounding support landed there in **v0.5.0** and stabilized in **v1.0.0 "Ethereum Key Forge"** (2024-12-18) [2]. The PRD's references to `staking-deposit-cli` must be retargeted; otherwise we are validating against a frozen tree.

## Context
- **Goal:** Build deposit data that the canonical CLI accepts byte-for-byte; ship a cross-validation gate that catches any drift before release.
- **Constraints:** Must support `0x00` and `0x01` for v0.2 (PRD §11.1); `0x02` is a v1.1 candidate (§11.4). Mainnet and hoodi networks at minimum; future networks must remain easy.
- **Evaluated:** `ethereum/staking-deposit-cli` (deprecated), `ethstaker/ethstaker-deposit-cli` (active fork).

## Findings

### Withdrawal-credential prefixes (canonical layouts)
| Prefix | Name | Layout | Origin |
|---|---|---|---|
| `0x00` | BLS withdrawal | `0x00 \|\| sha256(withdrawal_bls_pubkey)[1:]` (i.e., overwrite the first byte of the 32-byte SHA-256 with `0x00`) [3][4] | Phase 0 |
| `0x01` | Eth1 / execution-layer | `0x01 \|\| 11 zero bytes \|\| 20-byte EIP-55 address` [3][4] | Shapella (2023-04) |
| `0x02` | Compounding | `0x02 \|\| 11 zero bytes \|\| 20-byte address` (mirrors `0x01` layout — confirmed by `switch_to_compounding_validator` which "replaces the first byte … while keeping the remaining bytes unchanged" [5]) | Pectra/Electra (2025-05) |

CLI flag selecting the prefix: `--execution_address <addr>` (alias `--eth1_withdrawal_address`) produces `0x01`; omitting it silently defaults to `0x00`, derived from the withdrawal BLS pubkey [1]. The "silent default to `0x00`" is the same footgun GO-001 hits in eth-deposit-gen, but the canonical CLI at least *derives* a real (recoverable in principle, if you keep the BLS withdrawal key) credential — our tool emits an all-zero suffix that is provably unspendable.

### JSON schema (deposit_data array)
Each entry contains the following keys (verified empirically against the live tool and the local `internal/output/output.go` schema):

```json
{
  "pubkey": "<96-hex>",
  "withdrawal_credentials": "<64-hex>",
  "amount": 32000000000,
  "signature": "<192-hex>",
  "deposit_message_root": "<64-hex>",
  "deposit_data_root": "<64-hex>",
  "fork_version": "<8-hex>",
  "network_name": "<string>",
  "deposit_cli_version": "<semver>"
}
```

- `deposit_message_root = hash_tree_root(DepositMessage{pubkey, withdrawal_credentials, amount})` [6]
- `deposit_data_root    = hash_tree_root(DepositData{pubkey, withdrawal_credentials, amount, signature})` [6]
- `signature = BLS.Sign(sk, compute_signing_root(deposit_message, compute_domain(DOMAIN_DEPOSIT, fork_version=GENESIS_FORK_VERSION)))` [6]
- `fork_version` for a Phase-0-shaped initial deposit is **always** the network's `GENESIS_FORK_VERSION`, never the current fork version — `compute_domain` defaults to `GENESIS_FORK_VERSION` for deposits [6]. PRD's FR-P0-A3 must compare `entry.ForkVersion == params.GenesisForkVersion`, **not** the current fork — this is consistent with the PRD wording, flagging only for clarity.

### Compounding-deposit amount field
For `0x02` deposits, the canonical CLI accepts `--amount` between `MIN_ACTIVATION_BALANCE` (32 ETH) and `MAX_EFFECTIVE_BALANCE_ELECTRA` (2048 ETH) [7]. **This is a meaningful PRD gap for v1.1**: the PRD centralizes `DepositAmountGwei = 32_000_000_000` (FR-P0-G2) which is correct for v0.2 (0x00/0x01 only), but the v1.1 0x02 work (FR-P2-A14 EIP-7251 item) must turn this into a configurable range, not a constant.

### Cross-validation pattern
The standard pattern (used by every serious staking automation) is:
1. Generate via your tool.
2. Invoke `ethstaker-deposit-cli existing-mnemonic --validate-keystore <path>` against the keystore.
3. Use `ethstaker-deposit-cli existing-mnemonic --keystore <ours> --deposit-data <ours>` to assert byte-for-byte equivalence to a fresh derivation from the same mnemonic.

For pure deposit-data validation (no mnemonic), a tagged integration test that pipes our generated JSON through the canonical CLI's verification utility (the `verify_deposit_data` function in the canonical CLI's `utils/`) is sufficient. The PRD's FR-P1-G1 envisions exactly this; ensure the binary it invokes is `ethstaker-deposit-cli`, not the deprecated tree.

## Recommendation
1. **Retarget every PRD/code mention of `staking-deposit-cli` to `ethstaker-deposit-cli`.** This includes FR-P1-G1, `--verify-with-deposit-cli`, `cmd/eth-deposit-gen/main.go:148-153` (`runDepositCLIVerify`), CI workflow, USER-GUIDE.md.
2. **In v0.2, support exactly the canonical CLI's surface:** `--withdrawal-address` (0x01) and `--withdrawal-bls-pubkey` (0x00). Default to neither — require one. Match canonical CLI behaviour to minimize differential test friction.
3. **Reserve `--compounding` / `--withdrawal-address-compounding` (0x02) for v1.1.** Document the deposit-amount range gap (32 → 2048 ETH) as a hard prerequisite — `DepositAmountGwei` constant in §FR-P0-G2 cannot remain a single value when 0x02 lands.
4. **Pin the cross-validation CLI version** in CI (e.g. `ethstaker-deposit-cli==1.3.0` as of 2026-04-30 [2]). A floating `pip install` will eventually drift and break CI on an unrelated upstream change.
5. **Match canonical CLI JSON key ordering and `deposit_cli_version` field convention** — third-party launchpad UIs parse positionally in some cases.

## Risks & Gotchas
- **R1.** ethstaker-deposit-cli has had its own bugs (e.g. v0.5.x BLS-to-execution-change quirks around Electra). Pin the version, do not auto-upgrade.
- **R2.** The deprecated upstream `ethereum/staking-deposit-cli` will still install via `pip` and will pass for `0x00`/`0x01` deposits — using it gives a false sense of cross-validation while missing `0x02`. Reject it explicitly in CI (`assert "ethstaker" in subprocess.check_output("deposit_cli --version")`).
- **R3.** The PRD's "BLS-withdrawal niche/legacy" framing (§11.1) is correct for new validators but operators who already hold a 0x00-prefixed withdrawal BLS key need this path to remain available. Recommend supporting both flags as the PRD assumes.
- **R4.** PRD's open question on 0x02 timing (§11.4) should be answered **before** centralizing `DepositAmountGwei` (FR-P0-G2). If 0x02 lands within 12 months, design the constant as a `MinDepositGwei`/`MaxDepositGwei` pair now.

## Feasibility: ✅ GREEN.

## Sources

[1] [ethereum/staking-deposit-cli (archived/deprecated)](https://github.com/ethereum/staking-deposit-cli) — Ethereum Foundation, deprecated 2025-10-06. Notes: defaults to BLS (`0x00`) credentials unless `--execution_address` (`--eth1_withdrawal_address`) is provided.
[2] [ethstaker/ethstaker-deposit-cli — releases](https://github.com/ethstaker/ethstaker-deposit-cli/releases) — ethstaker community fork, active. v0.5.0 introduced `0x02` compounding; v1.0.0 "Ethereum Key Forge" (2024-12-18) stabilized it; v1.3.0 (2026-04-30) latest.
[3] [eth2book — 2.7.4 Withdrawals](https://eth2book.info/latest/part2/deposits-withdrawals/withdrawal-processing/) — Ben Edgington. Confirms 0x01 = `0x01 || 11 zero bytes || 20-byte address`; 0x00 = sha256(withdrawal_pubkey) with first byte replaced by 0x00.
[4] [ethereum.org — Withdrawal credentials](https://ethereum.org/developers/docs/consensus-mechanisms/pos/withdrawal-credentials/) — Ethereum docs. Same byte layouts.
[5] [consensus-specs PR/issue text for switch_to_compounding_validator](https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md) — Replaces only first byte with `COMPOUNDING_WITHDRAWAL_PREFIX`, confirming the 0x02 layout mirrors 0x01.
[6] [Consensus specs — phase0/beacon-chain.md](https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md) — DepositMessage/DepositData containers, compute_domain(DOMAIN_DEPOSIT) defaults to GENESIS_FORK_VERSION.
[7] [EIP-7251: Increase MAX_EFFECTIVE_BALANCE](https://eips.ethereum.org/EIPS/eip-7251) — MIN_ACTIVATION_BALANCE = 32 ETH, MAX_EFFECTIVE_BALANCE_ELECTRA = 2048 ETH.
