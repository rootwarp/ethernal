# Research — EIP-1559 fee-estimation sanity check (supports PRD F1)

**Question:** does the dead `resolveRPC` formula (tip = `SuggestGasTipCap`,
maxFee = `2·baseFee + tip`, gas = `estimate·6/5`) match go-ethereum convention, so we wire
it as-is rather than redesign?

**Verdict: wire as-is.** The fee formula is byte-for-byte the go-ethereum convention. The
gas margin is a conservative addition on top of go-ethereum's behavior.

## Fee formula — matches go-ethereum exactly

Confirmed against the pinned dependency `github.com/ethereum/go-ethereum v1.14.12`
(`go.mod:6`), `accounts/abi/bind/base.go`, which is geth's own transaction-fee estimation
used by every generated contract binding:

```go
const basefeeWiggleMultiplier = 2                                   // base.go:35

// tip:
gasTipCap := opts.GasTipCap
if gasTipCap == nil {
    tip, err := c.transactor.SuggestGasTipCap(ctx)                  // base.go:271-273
    gasTipCap = tip
}
// max fee:
gasFeeCap := opts.GasFeeCap
if gasFeeCap == nil {
    gasFeeCap = new(big.Int).Add(
        gasTipCap,
        new(big.Int).Mul(head.BaseFee, big.NewInt(basefeeWiggleMultiplier)),  // base.go:281-284
    )
}
```

That is exactly `maxFee = tip + 2·baseFee`. The repo's `resolveRPC` computes the same:
- tip from `SuggestGasTipCap` when unset (`internal/tx/builder.go:105-110`);
- `maxFee = 2·baseFee + tip` (`builder.go:120-121`, `new(big.Int).Add(new(big.Int).Mul(big.NewInt(2), baseFee), tip)`).

Same operands, same result. Geth's "wiggle" of `2×baseFee` gives headroom for the base fee
to rise up to ~2× over subsequent blocks (base fee can move at most 12.5% per block), which
is the standard safety cushion. No redesign needed.

Also note geth guards `gasFeeCap >= gasTipCap` (`base.go:286-287`); the `2·baseFee + tip`
form trivially satisfies this whenever `baseFee >= 0`, so `resolveRPC` inherits that
invariant for free.

## Gas limit — geth uses the raw estimate; the repo's 20% margin is a safe add-on

go-ethereum's bind uses the estimate directly with **no** multiplier when `GasLimit == 0`
(`base.go:290-294` → `estimateGasLimit`). The repo adds a 20% cushion:
`gasLimit = estimate * 6 / 5` (`builder.go:160-161`). This is a **deliberate over-estimate**,
not a deviation from correctness — a higher gas *limit* only raises the ceiling, never the
price paid (EIP-1559 charges `gasUsed`, not `gasLimit`), and protects against estimator
under-shoot / state drift between estimate and inclusion. Ecosystem tools commonly apply
such a buffer (e.g. cast historically multiplies its gas estimate). For a deposit whose gas
cost is stable (~the `deposit()` call), a 20% margin is comfortably safe. **Keep it.**

## Bottom line

Both the fee math and the gas margin are sound and idiomatic. F1 should wire the existing
`resolveRPC` unchanged; no formula redesign is warranted.

Sources: go-ethereum module cache `accounts/abi/bind/base.go:35,271-294`
(v1.14.12) — also public at
[go-ethereum/accounts/abi/bind/base.go](https://github.com/ethereum/go-ethereum/blob/v1.14.12/accounts/abi/bind/base.go).
