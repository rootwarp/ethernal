# Research: Ethereum Consensus-Spec Rules for Deposit Generation

## Summary
The consensus spec (Phase 0, modified by Capella for `0x01` and Electra for `0x02`) pins every field our generator emits. Three invariants are load-bearing and currently under-enforced by `eth-deposit-gen`:
1. **`fork_version` for deposits MUST be `GENESIS_FORK_VERSION`** of the target network, regardless of the chain's current head fork [1]. Our PRD FR-P0-A3 correctly captures this.
2. **`DepositMessage` and `DepositData` SSZ containers** have stable byte layouts; their `hash_tree_root` must be recomputed and verified on the read path (FR-P0-A4, GO-012) [1].
3. **`KeyValidate` MUST reject the point-at-infinity** for pubkeys passed to `process_deposit` [1][2]; FR-P1-C2 closes this gap.

The PRD's framing of these invariants is correct. The principal contradiction surfaced is more subtle (see Risks).

## Key Concepts

### DepositMessage & DepositData (SSZ containers)
From Phase 0 [1]:
```python
class DepositMessage(Container):
    pubkey: BLSPubkey               # 48 bytes
    withdrawal_credentials: Bytes32  # 32 bytes
    amount: Gwei                     # uint64

class DepositData(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32
    amount: Gwei
    signature: BLSSignature          # 96 bytes
```

Both are fixed-size containers, merkleized as:
- DepositMessage: merkleize(chunks=[pubkey_root, wc, amount_padded], limit=4) where pubkey_root = merkleize chunks of the 48-byte pubkey padded to 64.
- DepositData: same idea with 4 fields, padded to limit=4.

Our `internal/ssz/ssz.go` hand-rolls these correctly per REVIEW.md GO-061 cross-check (re-derived against the spec).

### Withdrawal credential prefixes
| Constant | Value | Layout |
|---|---|---|
| `BLS_WITHDRAWAL_PREFIX` | `0x00` | `0x00 \|\| sha256(withdrawal_pubkey)[1:]` [3] |
| `ETH1_ADDRESS_WITHDRAWAL_PREFIX` | `0x01` | `0x01 \|\| 11 × 0x00 \|\| address[20]` [3] |
| `COMPOUNDING_WITHDRAWAL_PREFIX` | `0x02` (Electra) | `0x02 \|\| 11 × 0x00 \|\| address[20]` (mirrors 0x01 — confirmed by `switch_to_compounding_validator` only replacing the prefix byte [4]) |

### Deposit signature domain
```python
# Phase 0 [1]
domain = compute_domain(DOMAIN_DEPOSIT)              # defaults to GENESIS_FORK_VERSION
signing_root = compute_signing_root(deposit_message, domain)
deposit.data.signature = bls.Sign(privkey, signing_root)
```

`DOMAIN_DEPOSIT = DomainType('0x03000000')`. The key invariant: `compute_domain` *defaults to GENESIS_FORK_VERSION* when no second arg is provided — deposit signatures must always be over the genesis fork's domain, even on a network many forks past genesis. Our `internal/network/network.go` correctly stores `GenesisForkVersion` per network; FR-P0-A3's `entry.ForkVersion == params.GenesisForkVersion` check uses the right field.

### `bls.KeyValidate` and point-at-infinity
From the spec [1][2]: `process_deposit → apply_deposit → if not bls.KeyValidate(pubkey): return invalid`. IETF KeyValidate explicitly rejects the identity point. Our `bls.ValidatePubkeyBytes` does *not* — FR-P1-C2 closes this.

### Genesis fork versions per network (audit of `internal/network/network.go` against canonical sources [5])

| Network | Chain ID | GENESIS_FORK_VERSION | Deposit contract |
|---|---|---|---|
| mainnet | 1 | `0x00000000` | `0x00000000219ab540356cBB839Cbe05303d7705Fa` |
| holesky | 17000 | `0x01017000` | `0x4242424242424242424242424242424242424242` |
| sepolia | 11155111 | `0x90000069` | `0x7f02C3E3c98b133055B8B348B2Ac625669Ed295D` |
| hoodi | 560048 | `0x10000910` | `0x00000000219ab540356cBB839Cbe05303d7705Fa` |

Mainnet and hoodi deliberately share the deposit contract address (hoodi reuses the mainnet contract). This is the source of GO-002's silent-trap: a `--network hoodi` build of mainnet-fork deposit data would broadcast to the same address with a chainId-1 envelope, indistinguishable to the operator. FR-P0-A3 closes this by checking `entry.NetworkName == params.Name`.

## How It Works (deposit signing pipeline, per spec)
1. Operator picks withdrawal credential (any of `0x00`/`0x01`/`0x02` shapes above).
2. Construct `DepositMessage{pubkey, withdrawal_credentials, amount=32 ETH (or up to 2048 ETH for 0x02)}`.
3. `signing_root = hash_tree_root(SigningData{ object_root = HTR(DepositMessage), domain = compute_domain(DOMAIN_DEPOSIT, fork_version=GENESIS_FORK_VERSION, genesis_validators_root=Bytes32(0)) })`.
4. `signature = BLS.Sign(privkey, signing_root)`.
5. `DepositData = DepositMessage + signature`; `deposit_data_root = hash_tree_root(DepositData)`.
6. Tx: call `DepositContract.deposit(pubkey, withdrawal_credentials, signature, deposit_data_root)`.
7. EL accepts (deposit contract only checks `deposit_data_root` matches; it does NOT verify BLS).
8. CL processes the deposit, runs `bls.KeyValidate(pubkey)` and `bls.Verify(pubkey, signing_root, signature)`. **If either fails, validator is created but cannot activate / cannot withdraw → 32 ETH stranded.**

## Code Examples — what the PRD must enforce

```go
// internal/deposit/json.go — proposed VerifyIntegrity (FR-P0-A4)
func (e *Entry) VerifyIntegrity(params network.Params, v bls.Verifier) error {
    if e.NetworkName != params.Name {
        return fmt.Errorf("entry network %q != target %q", e.NetworkName, params.Name)
    }
    if !bytes.Equal(e.ForkVersion[:], params.GenesisForkVersion[:]) {
        return fmt.Errorf("entry fork_version %x != genesis %x", e.ForkVersion, params.GenesisForkVersion)
    }
    msgRoot, _ := ssz.DepositMessageHashTreeRoot(e.PubKey, e.WithdrawalCredentials, e.Amount)
    if msgRoot != e.DepositMessageRoot { return ErrDepositMessageRootMismatch }
    dataRoot, _ := ssz.DepositDataHashTreeRoot(e.PubKey, e.WithdrawalCredentials, e.Amount, e.Signature)
    if dataRoot != e.DepositDataRoot { return ErrDepositDataRootMismatch }
    if err := bls.ValidatePubkeyBytes(e.PubKey); err != nil { return err }  // KeyValidate
    domain := computeDomain(network.DomainDeposit(), params.GenesisForkVersion)
    signingRoot := computeSigningRoot(msgRoot, domain)
    ok, err := v.Verify(e.PubKey, signingRoot, e.Signature)
    if err != nil || !ok { return ErrBLSSignatureInvalid }
    return nil
}
```

## Common Pitfalls
- **Pitfall 1 — Using the *current* fork version for deposit signing.** Some launchpad tutorials show the wrong fork version when the chain is mid-fork. Always use `GENESIS_FORK_VERSION` for initial deposits.
- **Pitfall 2 — `genesis_validators_root` for deposits.** `compute_domain(DOMAIN_DEPOSIT)` uses `genesis_validators_root = Bytes32()` (32 zero bytes), *not* the chain's actual GVR. This is because the GVR is unknown pre-genesis and was hard-coded to zero for deposits forever after. Our `network.ZeroGenesisValidatorsRoot` is correct (REVIEW.md GO-038 wants it function-returned, not mutable var).
- **Pitfall 3 — `0x02` deposits during the activation window.** Pre-Electra, a `0x02` credential is treated like `0x01` (the prefix byte is unrecognized but the trailing 20 bytes are still an execution address per validity rules). Post-Electra, the auto-compounding behavior kicks in. **Critical**: do not enable `0x02` generation in code that targets a network whose activation epoch has not passed — the deposit will succeed but auto-compounding will not take effect until Electra. The PRD's v1.1 timing for `0x02` (§11.4) is conservative and safe.
- **Pitfall 4 — Mutable `DomainDeposit` / `ZeroGenesisValidatorsRoot` package vars (GO-038).** These signing-domain constants must not be writable. Convert to functions per FR-P1-C3.
- **Pitfall 5 — Amount field encoding.** SSZ uint64 is little-endian, *not* big-endian. Verify `internal/ssz/ssz.go` `uint64Chunk` LE encoding against the spec — REVIEW.md GO-048 indicates this was re-derived correctly, but the "not via the same helpers" oracle comment is misleading.

## Further Reading
- [1] Phase 0 spec — DepositMessage, DepositData, compute_domain, process_deposit.
- [2] IETF BLS-Signatures draft-05 §2.5 — KeyValidate canonical text.
- [3] eth2book §2.7 — annotated layouts with worked examples.
- [4] Electra spec — switch_to_compounding_validator, has_compounding_withdrawal_credential.
- [5] `internal/network/network.go` and `network_test.go` — local source of truth, all values confirmed in REVIEW.md.

## Feasibility: ✅ GREEN. No spec contradictions with PRD.

## Sources

[1] [consensus-specs/specs/phase0/beacon-chain.md](https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md) — Ethereum. DepositMessage/DepositData containers; DOMAIN_DEPOSIT; compute_domain defaults to GENESIS_FORK_VERSION; KeyValidate requirement.
[2] [IETF BLS-Signatures draft-05 §2.5 (KeyValidate)](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-2.5) — CFRG. Point-at-infinity rejection.
[3] [eth2book §2.7 — Deposits & Withdrawals](https://eth2book.info/latest/part2/deposits-withdrawals/withdrawal-processing/) — Ben Edgington. Worked byte layouts of 0x00/0x01 with concrete examples.
[4] [consensus-specs Electra beacon-chain.md (search-confirmed)](https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md) — Ethereum. switch_to_compounding_validator semantics; COMPOUNDING_WITHDRAWAL_PREFIX = 0x02.
[5] Local source `internal/network/network.go` — chain IDs / fork versions / deposit contract addresses for mainnet, holesky, sepolia, hoodi; verified in REVIEW.md.
