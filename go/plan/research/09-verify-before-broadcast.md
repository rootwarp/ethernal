# Research: Verify-Before-Broadcast — Decoding rawRLP, Recovering Sender, Re-Verifying Deposit Entries on the Read Path

## Verdict
**FR-P0-A6 (decode `signed.RawRLP` and drive prompt + chain-ID guard from it) and FR-P0-A4 (recompute SSZ roots + BLS-verify on read path) are fully feasible with stdlib + already-imported go-ethereum APIs.** No new dependencies required. The two key primitives — `types.Transaction.UnmarshalBinary` and `types.Sender(types.LatestSignerForChainID(chainID), tx)` — are stable across v1.15.0–v1.17.x [1][2].

## Key APIs (go-ethereum, already imported)

| API | Purpose | Notes |
|---|---|---|
| `(*types.Transaction).UnmarshalBinary(b []byte) error` | Decode canonical RLP/typed-tx encoding | Auto-detects legacy / EIP-2930 / EIP-1559 / EIP-4844 / EIP-7702 [1] |
| `types.Sender(signer, tx) (common.Address, error)` | Recover sender from V/R/S | Caches result on tx [1] |
| `types.LatestSignerForChainID(chainID *big.Int) Signer` | Get signer for chain ID without full ChainConfig | Correct for our use (we only know chainID) [1] |
| `(*types.Transaction).ChainId()`, `To()`, `Value()`, `Nonce()`, `Hash()`, `Type()`, `GasFeeCap()`, `GasTipCap()` | Field accessors | `To()` is `*common.Address` (nil for contract creation — must check); `ChainId()` non-nil for EIP-1559 [1] |

## Proof-of-concept for FR-P0-A6 (send.go, before the prompt)

```go
// cmd/eth-deposit-tx/send.go (proposed; before the current line 196)
rlpBytes, err := hex.DecodeString(strings.TrimPrefix(signed.RawRLP, "0x"))
if err != nil {
    return ucli.Exit(fmt.Sprintf("invalid rawRLP hex: %v", err), 2)
}
var decoded types.Transaction
if err := decoded.UnmarshalBinary(rlpBytes); err != nil {
    return ucli.Exit(fmt.Sprintf("rawRLP decode failed: %v", err), 2)
}
if decoded.Type() != types.DynamicFeeTxType {
    return ucli.Exit(fmt.Sprintf("only EIP-1559 (type 0x02) supported, got 0x%02x", decoded.Type()), 2)
}

// Cross-check decoded vs JSON metadata; abort on any divergence.
if decoded.ChainId().Uint64() != signed.Unsigned.ChainID {
    return ucli.Exit(fmt.Sprintf("chainID divergence: RLP=%s json=%d", decoded.ChainId(), signed.Unsigned.ChainID), 2)
}
if decoded.To() == nil {
    return ucli.Exit("rawRLP is a contract-creation tx; deposit tx must have To set", 2)
}
if !strings.EqualFold(decoded.To().Hex(), signed.Unsigned.To) {
    return ucli.Exit(fmt.Sprintf("to divergence: RLP=%s json=%s", decoded.To().Hex(), signed.Unsigned.To), 2)
}
// Value, Nonce, Hash, From — all four are independent crosschecks.
if !bytes.Equal(decoded.Value().Bytes(), expectedValueBytes) { ... }
if decoded.Nonce() != signed.Unsigned.Nonce { ... }
if decoded.Hash().Hex() != signed.Hash { ... }

signer := types.LatestSignerForChainID(decoded.ChainId())
recovered, err := types.Sender(signer, &decoded)
if err != nil {
    return ucli.Exit(fmt.Sprintf("rawRLP signature invalid: %v", err), 2)
}
if !strings.EqualFold(recovered.Hex(), signed.From) {
    return ucli.Exit(fmt.Sprintf("from divergence: recovered=%s json=%s", recovered.Hex(), signed.From), 2)
}

// Cross-check To against the deposit contract for this chain.
if !strings.EqualFold(decoded.To().Hex(), netParams.DepositContractAddress.Hex()) {
    return ucli.Exit(fmt.Sprintf("To %s is not the deposit contract for %s (%s)",
        decoded.To().Hex(), netParams.Name, netParams.DepositContractAddress.Hex()), 2)
}

// Now render the "about to BROADCAST" prompt from decoded values, labelled "(decoded from RLP)".
fmt.Fprintf(c.App.ErrWriter, ">   Value (RLP):       %s\n", formatETH(decoded.Value()))
...
```

This is ~50 LOC including error handling. **Acceptance:** tampered-JSON regression test — mutate `signed.Unsigned.To` after signing, assert exit 2 with the divergence message; mutate `signed.RawRLP` (flip a byte), assert exit 2 from `Sender` recovery; valid case asserts prompt shows decoded values.

## Proof-of-concept for FR-P0-A4 (deposit entry re-verify on read path)

The PRD requires recomputing SSZ roots and verifying the BLS signature against the deposit domain. The bls/ssz packages already in the module make this 30 LOC:

```go
// internal/deposit/json.go (proposed VerifyIntegrity)
func (e *Entry) VerifyIntegrity(target network.Params, v bls.Verifier) error {
    if e.NetworkName != target.Name {
        return fmt.Errorf("%w: entry %q != target %q", ErrNetworkMismatch, e.NetworkName, target.Name)
    }
    if e.ForkVersion != target.GenesisForkVersion {
        return fmt.Errorf("%w: entry fork %x != genesis %x", ErrForkVersionMismatch, e.ForkVersion, target.GenesisForkVersion)
    }
    // Defense-in-depth: KeyValidate (rejects identity)
    if err := bls.ValidatePubkeyBytes(e.PubKey); err != nil {
        return fmt.Errorf("%w: %v", ErrPubkeyInvalid, err)
    }
    // Recompute SSZ roots.
    msgRoot, err := ssz.DepositMessageHashTreeRoot(e.PubKey, e.WithdrawalCredentials, e.Amount)
    if err != nil { return fmt.Errorf("ssz: %w", err) }
    if msgRoot != e.DepositMessageRoot { return ErrDepositMessageRootMismatch }
    dataRoot, err := ssz.DepositDataHashTreeRoot(e.PubKey, e.WithdrawalCredentials, e.Amount, e.Signature)
    if err != nil { return fmt.Errorf("ssz: %w", err) }
    if dataRoot != e.DepositDataRoot { return ErrDepositDataRootMismatch }
    // Re-verify BLS signature against the network's deposit domain (always GENESIS_FORK_VERSION + zero GVR).
    domain := computeDomain(network.DomainDeposit(), target.GenesisForkVersion, network.ZeroGenesisValidatorsRoot())
    signingRoot, err := ssz.SigningRoot(msgRoot, domain)
    if err != nil { return fmt.Errorf("ssz: %w", err) }
    ok, err := v.Verify(e.PubKey, signingRoot, e.Signature)
    if err != nil { return fmt.Errorf("bls: %w", err) }
    if !ok { return ErrBLSSignatureInvalid }
    return nil
}
```

`computeDomain(DOMAIN_DEPOSIT, GENESIS_FORK_VERSION, ZERO_GVR)` is the canonical Phase 0 derivation — the generator already does this in `internal/deposit/deposit.go`, factor out into a shared helper.

## Prior art (other broadcast tools)

- **Etherscan's pushTx UI** [3] does decode-then-display before broadcast, but client-side — no on-chain authority.
- **`cast publish` (foundry)** decodes locally and shows a summary before broadcast.
- **MetaMask, Frame** — both decode the incoming raw tx and reconstruct the human-readable view from the decoded bytes, never from a sidecar metadata blob. Our current `send.go` is the outlier.
- **Pattern is universal in any tool whose threat model includes a tampered sidecar JSON** (which we explicitly opted into with the air-gap workflow).

## Common Pitfalls
- **`decoded.To() == nil`** is contract-creation; must check before `.Hex()` (nil-pointer panic otherwise).
- **`decoded.ChainId()` is `*big.Int`** — must convert with `.Uint64()` only after `IsUint64()` check or rely on the chainID being small. All our supported chainIDs fit; safe.
- **Negative `Value()`** — `big.Int` allows it; SetString with `-` prefix bypasses our hex parser. GO-020 fix (FR-P1-F2) covers the parse side; on the decode side, `UnmarshalBinary` will refuse to decode a negative-value RLP (geth's RLP encoder errors).
- **Type assertion on `decoded.Type()`** — must explicitly reject blob (0x03) and SetCode (0x04) types; we never expect them for a deposit tx.

## Feasibility: ✅ GREEN. No PRD contradictions.

## Sources

[1] [go-ethereum core/types pkg.go.dev](https://pkg.go.dev/github.com/ethereum/go-ethereum/core/types) — Ethereum. UnmarshalBinary accepts legacy/EIP-2930/EIP-1559/EIP-4844/EIP-7702; Sender caches; LatestSignerForChainID for chainID-only case.
[2] [go-ethereum core/types/transaction_signing.go](https://github.com/ethereum/go-ethereum/blob/master/core/types/transaction_signing.go) — Ethereum. Signer interface; ErrInvalidSig.
[3] [Etherscan pushTx](https://etherscan.io/pushTx) — Etherscan. Reference pattern: decode-and-display before broadcast.
[4] [Extracting the Sender from a Transaction — DEV](https://dev.to/burgossrodrigo/extracting-the-sender-from-a-transaction-with-go-ethereum-1cn3) — Reference implementation pattern for Sender + LatestSignerForChainID.
