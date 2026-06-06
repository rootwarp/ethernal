# Research: herumi/bls-eth-go-binary APIs — Secret Leak, Safe Constructors, KeyValidate Behavior

## Verdict
**The PRD's three BLS hardening requirements (FR-P0-C1, FR-P1-C1, FR-P1-C2) are correct, implementable, and supported by herumi APIs that already exist in v1.37.0.** Specifically: (a) the GO-006 secret leak is caused by herumi's `SecretKey.Deserialize` literally formatting the input buffer as `"err blsSecretKeyDeserialize %x"` [1] — confirmed in upstream source, our wrapping with `%w` propagates the hex secret verbatim; (b) `GetSafePublicKey()` exists and returns `"sec is zero"` on a zero scalar [1][2] — replacing `GetPublicKey()` per FR-P1-C1 is a one-line change; (c) `PublicKey.IsZero()` and `PublicKey.IsValidOrder()` both exist [1] — implementing the IETF `KeyValidate`-style point-at-infinity rejection per FR-P1-C2 is straightforward.

## Context
- **Goal:** Stop leaking 32-byte BLS secrets in errors; reject zero secret keys; reject the BLS pubkey point-at-infinity in line with IETF `KeyValidate`.
- **Constraints:** Must remain on `herumi/bls-eth-go-binary v1.37.0` (latest; no advisories). CGO required. Must not break the existing self-verify path in `internal/deposit`.
- **Evaluated:** herumi `SecretKey`, `PublicKey`, `Sign` Go wrapper surface; IETF BLS-Signatures `KeyValidate`.

## Findings

### 1. The secret leak (GO-006 / FR-P0-C1) is upstream-confirmed

```go
// herumi/bls-eth-go-binary/bls/bls.go (verified upstream [1])
func (sec *SecretKey) Deserialize(buf []byte) error {
    n := C.blsSecretKeyDeserialize(&sec.v, getPointer(buf), C.mclSize(len(buf)))
    if n == 0 || int(n) != len(buf) {
        return fmt.Errorf("err blsSecretKeyDeserialize %x", buf)   // ← leaks the secret in hex
    }
    return nil
}
```

Our `internal/bls/bls.go:88-90`:
```go
if err := s.sk.Deserialize(localCopy); err != nil {
    return nil, fmt.Errorf("bls: Deserialize: %w", err)            // ← propagates "err blsSecretKeyDeserialize <hex secret>"
}
```

The trigger condition is non-trivial: `Deserialize` errors only when the BLS12-381 scalar is **>= r** (the curve order). EIP-2333-derived keys from `staking-deposit-cli` never fail this (the derivation clamps below r). But the leak surfaces when:
- A keystore is corrupt or hand-crafted with an out-of-range scalar.
- A test fixture is built from random bytes (~55% probability of being ≥ r).
- A future keystore consumer (e.g. a hardware-derived raw key) bypasses EIP-2333.

In all cases, the secret hits stderr via `slog.Debug` from `cmd/eth-deposit-gen/main.go:340-344`. REVIEW.md's medium severity is appropriate; FR-P0-C1's fixed sentinel (`"bls: secret key rejected (scalar out of range for BLS12-381)"`) is the correct fix.

### 2. `SecretKey.IsZero` and `GetSafePublicKey` (GO-036 / FR-P1-C1)

```go
// herumi upstream [1]
func (sec *SecretKey) IsZero() bool {
    return C.blsSecretKeyIsZero(&sec.v) == 1
}

func (sec *SecretKey) GetSafePublicKey() (pub *PublicKey, err error) {
    if sec.IsZero() {
        return nil, fmt.Errorf("sec is zero")
    }
    pub = new(PublicKey)
    C.blsGetPublicKey(&pub.v, &sec.v)
    return pub, nil
}
```

The trigger: herumi accepts `Fr = 0` through `Deserialize` (a 32-byte all-zero buffer). `GetPublicKey()` then returns the identity (infinity) pubkey, and `Sign()` returns the infinity signature. **Verify still fails** (a 2021 change: "verify returns false for zero public key" [2]) — but our verify-before-write self-check is the only thing keeping this from emitting a valid-looking deposit signed under a zero key, and the safety check should happen in the constructor, not 200 lines later. Two ways to fix FR-P1-C1:
- **(a)** `if s.sk.IsZero() { return nil, ErrSecretIsZero }` after `Deserialize` — explicit, no API change.
- **(b)** Replace `GetPublicKey()` in `PublicKey()` (line 112) with `GetSafePublicKey()` — single line, but only catches zero key at first pubkey access, not at construction. **Prefer (a)** for clarity and earlier failure.

### 3. `PublicKey.IsZero` (GO-037 / FR-P1-C2)

```go
// herumi upstream [1]
func (pub *PublicKey) IsZero() bool {
    return C.blsPublicKeyIsZero(&pub.v) == 1
}
```

The compressed identity (`0xc0 || 47 × 0x00`) deserializes as a valid G1 point — herumi's `Deserialize` only checks point-on-curve. IETF [BLS-Signatures Section 2.5: `KeyValidate`](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-2.5) requires explicit rejection of the identity element. The fix is exactly one line in `ValidatePubkeyBytes`:

```go
// internal/bls/bls.go (proposed)
func ValidatePubkeyBytes(pub [48]byte) error {
    if err := Init(); err != nil { return fmt.Errorf("bls: not initialized: %w", err) }
    var hPub bls.PublicKey
    if err := hPub.Deserialize(pub[:]); err != nil {
        return fmt.Errorf("bls: invalid G1 point: %w", err)
    }
    if hPub.IsZero() {
        return errors.New("bls: pubkey is point at infinity (KeyValidate rejected)")
    }
    return nil
}
```

This matches consensus-spec `bls.KeyValidate` semantics [3]. Optionally also check `IsValidOrder()` — though for BLS12-381 G1 every on-curve point is in the prime subgroup (subgroup security holds [4]), so `IsValidOrder()` is currently a no-op. Keep it as defense-in-depth.

### 4. Other API hygiene relevant to PRD

- **Init / SetETHmode:** `internal/bls/bls.go:25-36` is correct; herumi's `EthModeDraft07 == EthModeLatest == 3` per upstream. The current double-prefix "bls: not initialized: bls: herumi Init:" (GO-062) should be cleaned per FR-P2-A7.
- **Same-name alias `bls "github.com/herumi/bls-eth-go-binary/bls"` inside `package bls`:** redundant and confusing per CONVENTIONS.md; alias to `herumi` per FR-P2-A7.
- **No Destroy/Zeroize on `SecretKey`:** herumi does not expose a zeroize for the C-side scalar. **PRD FR-P1-B4's "Add a Destroy/Zeroize method to the BLS signer" cannot fully wipe the underlying mcl scalar** — only the Go-side `bls.SecretKey` struct can be zeroed (replacing the struct's contents). This is a real limitation; the BLS secret can survive in C-allocated memory until process exit. Document this candidly in the PRD/code; the most we can do is `s.sk = bls.SecretKey{}` and rely on process exit for full erasure. **Flag this as a PRD contradiction** — FR-P1-B4 is achievable for Go-side state only.

## Recommendation
1. **FR-P0-C1 (GO-006):** Replace the `Deserialize` wrap with a fixed sentinel. One-line change to `internal/bls/bls.go:88-90`. Regression test: pass `bytes.Repeat([]byte{0xff}, 32)` and assert the error contains no hex from the input.
2. **FR-P1-C1 (GO-036):** Add `if s.sk.IsZero()` check after Deserialize (preferred). Regression test: 32-zero-byte input rejects with `ErrBLSSecretZero`.
3. **FR-P1-C2 (GO-037):** Add `IsZero()` check in `ValidatePubkeyBytes`. Regression test: `0xc0 || 47×0x00` rejects.
4. **Hygiene:** rename the same-package alias, fix the double-prefix on Init errors, doc-correct `Sign`'s parameter name (`signingRoot`, not `msg`) per FR-P2-A7.
5. **PRD amendment (FR-P1-B4):** Document that BLS secret zeroization is *Go-side only*; the C-side `mcl` scalar persists in process memory.

## Risks & Gotchas
- **R1.** The IsZero check after Deserialize must come *before* the deferred zeroize of `localCopy` runs — placement matters; tests should cover both `IsZero=true → return ErrBLSSecretZero, no panic` and that `localCopy` is still zeroed by defer.
- **R2.** Some operator scripts may currently rely on the existing `bls: Deserialize: err blsSecretKeyDeserialize <hex>` error string for parsing. Search downstream consumers; document the breakage in MIGRATION.md per FR-P0-F2.
- **R3.** `IsValidOrder()` not currently called but cheap; including it for forward-compat against future BLS12-381 subgroup attacks is recommended (defense-in-depth, not strictly required by KeyValidate).
- **R4.** Adding `KeyValidate` to `ValidatePubkeyBytes` may reject existing test fixtures that use the all-zero pubkey as a sentinel — audit `internal/bls/bls_test.go`, `internal/keystore/keystore_test.go`, `internal/tx/validation_test.go` before landing.

## Feasibility: ✅ GREEN, with one PRD-text amendment.

## Sources

[1] [herumi/bls-eth-go-binary — bls/bls.go (Go wrapper)](https://github.com/herumi/bls-eth-go-binary/blob/master/bls/bls.go) — herumi. Verified source for `SecretKey.Deserialize` ("err blsSecretKeyDeserialize %x"), `IsZero`, `GetPublicKey`, `GetSafePublicKey` ("sec is zero"), `PublicKey.IsZero`, `PublicKey.IsValidOrder`.
[2] [herumi/bls-eth-go-binary — readme](https://github.com/herumi/bls-eth-go-binary/blob/master/readme.md) — herumi. Notes `GetSafePublicKey()` "returns an error if sec is zero"; "verify returns false for zero public key" (2021-01-28); MultiVerify, AreAllMsgDifferent helpers.
[3] [Consensus specs — bls/KeyValidate semantics](https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md) — Ethereum. `bls.KeyValidate` (IETF section 2.5) rejects the identity element.
[4] [IETF draft-irtf-cfrg-bls-signature-05 §2.5 KeyValidate](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-2.5) — CFRG. Canonical KeyValidate procedure: deserialize, reject identity, check subgroup.
