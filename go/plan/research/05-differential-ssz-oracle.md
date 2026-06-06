# Research: Differential SSZ Oracle for `DepositMessage`/`DepositData` Roots

## Recommendation
**Use [`ferranbt/fastssz`](https://github.com/ferranbt/fastssz) with hand-written `DepositMessage`/`DepositData` Go structs (or vendor the relevant `prysm` types), as the independent oracle for FR-P1-C4.** It is the most-tested, lowest-friction Go alternative, ships its own merkleize implementation independent of ours, has zero CGO dependency (avoids amplifying our existing herumi dependency), and already runs against the official Ethereum SSZ spectests [1]. Backstop with the Python `eth2spec` reference (run via `subprocess` in a tagged CI lane) for ultimate ground truth.

## Context
- **Goal:** Replace `internal/ssz/ssz_test.go`'s dead and tautological "reference implementation" oracle (GO-048) with a genuinely independent SSZ implementation that produces `DepositMessage`/`DepositData` roots from the same field inputs, so we can assert byte-equality and catch any future regression to our hand-rolled merkleize.
- **Constraints:** Go-native preferred; CGO is already required but no new CGO deps if avoidable; oracle must NOT share code with our `internal/ssz`; must produce identical results for valid inputs.
- **Evaluated:** `ferranbt/fastssz`, `prysmaticlabs/prysm` (vendored types), `go-eth-consensus` (FerranBT), Python `eth2spec`, `attestantio/go-eth2-types`.

## Comparison

| Library | License | CGO? | DepositData/Message included? | Maintenance | Independence from us | Friction |
|---|---|---|---|---|---|---|
| **ferranbt/fastssz** | Apache-2.0 | No | Via `sszgen` codegen from your own struct OR via separate `go-eth-consensus` package [1] | Active, used by Prysm | Full (different merkleize algorithm) | **Low** (one `go get`) |
| `prysmaticlabs/prysm` (vendor types) | GPL-3.0 ⚠️ | Yes (transitive) | Yes (full beacon-chain types) | Active | Full | High (GPL-3.0 incompatible with our module) |
| `attestantio/go-eth2-types` | Apache-2.0 | No | Yes | Moderate | Full | Medium |
| `Python eth2spec` via subprocess | CC0/MIT | N/A | Yes (canonical spec) | Most authoritative | Maximum | High (Python+pip in CI) |
| **Hand-write a tiny SSZ in tests** | n/a | No | n/a | n/a | Full | Lowest, but worst — repeats GO-048 anti-pattern |

## Detailed Analysis

### Option A — fastssz with sszgen [Recommended]
**How it works:** Write a minimal Go struct mirroring `DepositMessage`/`DepositData`; run `sszgen` once at test-setup; commit the generated `*_ssz.go` to `internal/ssz/testdata/` so CI never needs `go install`. Call `(*DepositMessage).HashTreeRoot()` and compare to our own.

**Pros:**
- Pure Go, no CGO, MIT-compatible.
- Used by Prysm in production [1] — it is the de-facto Go SSZ implementation; "tested against ourselves" doesn't apply since we don't use it in production.
- Generated code is human-readable; we can audit it once.
- Trivially generalizes to fork_data/signing_data roots if we want broader coverage.

**Cons:**
- One extra `require` in `go.mod` for test-only use. Mitigate with `//go:build differential_oracle` build tag so it doesn't bloat the prod binary.

**Best for:** Our exact use case — a focused oracle for a half-dozen container roots.

### Option B — Vendor prysm beacon types
**Pros:** Maximum coverage; no codegen step.
**Cons:** **GPL-3.0 license incompatibility** with our (presumed) permissive license. Hard blocker. Also drags in massive transitive dependency graph.

### Option C — Python `eth2spec` subprocess
**Pros:** Canonical ground truth.
**Cons:** Requires Python+pip in CI; slow; flaky to install; the tool is `pyspec` from `consensus-specs/tests/core/pyspec` — non-trivial setup. **Use as a backstop in a tagged CI lane, not the default.**

### Option D — Hand-write a tiny SSZ in tests
**Cons:** Reintroduces GO-048's "tested only against ourselves" anti-pattern. Reject.

## Implementation Guidelines

1. **Add `ferranbt/fastssz` as a test-only dep** behind a build tag:
   ```go
   //go:build differential_oracle
   // +build differential_oracle
   
   package ssz_test
   ```
2. **Generate `*_ssz.go` once and commit** so CI doesn't depend on `sszgen` install:
   ```bash
   go install github.com/ferranbt/fastssz/sszgen@latest
   sszgen --path ./testdata/oracle_types.go --include DepositMessage,DepositData
   ```
3. **Drive both implementations from the same fuzz seeds** — what GO-048's current `FuzzMerkleize` *should* have done:
   ```go
   func FuzzDepositRoots(f *testing.F) {
       // seed with known-good vectors
       f.Add(/* pubkey */, /* wc */, uint64(32_000_000_000))
       f.Fuzz(func(t *testing.T, pubkey []byte, wc []byte, amount uint64) {
           if len(pubkey) != 48 || len(wc) != 32 { t.Skip() }
           ours, _ := ssz.DepositMessageHashTreeRoot(pubkey, wc, amount)
           theirs, _ := oracle.DepositMessage{Pubkey: pubkey, WithdrawalCredentials: wc, Amount: amount}.HashTreeRoot()
           if ours != theirs {
               t.Fatalf("mismatch:\n  ours:   %x\n  theirs: %x", ours, theirs)
           }
       })
   }
   ```
4. **Run in CI with `-tags=differential_oracle` in a dedicated job;** keep the default unit test fast.
5. **Backstop with Python eth2spec** in a weekly cron CI run (FR-P1-G1 already plans a similar `staking-deposit-cli` cross-validation lane).

## Common Pitfalls
- **Pitfall 1 — Generator drift.** Re-running `sszgen` against an updated `fastssz` may emit different code; pin both the generator version and the generated file in source. CI should `diff` against committed.
- **Pitfall 2 — Endianness bug in your struct.** SSZ uint64 is little-endian. If you mis-tag the field, both implementations may agree (because fastssz reads your tag); cross-check against at least one known-good hardcoded hex root.
- **Pitfall 3 — Skipping the BLS subgroup check during fuzz.** Fuzz seeds may produce invalid pubkeys; that's fine for *SSZ* roots (no on-curve check) but will break a downstream BLS verify oracle.
- **Pitfall 4 — The PRD's mention of "a port of the Python reference" (FR-P1-C4) is more work than a pre-existing Go library.** Recommend the `fastssz` route over a hand-port.

## Real-World Examples
- **Lodestar** (TypeScript CL client) maintains its own SSZ implementation and cross-tests against `ssz-typescript` and the Python spec — same pattern at language scale.
- **Prysm** uses `fastssz` directly in production for its DepositData encoding [1].
- **Teku** uses Tuweni SSZ + the Python spec; its CI runs both for every PR.

## Feasibility: ✅ GREEN. PRD's FR-P1-C4 is achievable with one new test-only dep.

## Sources

[1] [ferranbt/fastssz README](https://github.com/ferranbt/fastssz) — Borreguero. Pure-Go SSZ + `sszgen` codegen; runs official Ethereum SSZ spectests; zero-alloc HashTreeRoot benchmarks; recommends `go-eth-consensus` for pre-generated consensus types.
[2] [FastSSZ blog post](https://ferranbt.com/posts/fastssz-ssz-encoding-on-esteroids) — Borreguero. Background on Prysm's bounty that produced fastssz; design rationale.
[3] [Prysmatic Labs Prysm v3 deposit package docs](https://pkg.go.dev/github.com/prysmaticlabs/prysm/v3/contracts/deposit) — Prysm. Reference for how mainstream CL clients use fastssz for DepositData.
[4] [SSZ implementations list (consensus-specs issue #2138)](https://github.com/ethereum/consensus-specs/issues/2138) — Ethereum. Maintained list of SSZ implementations across languages, useful for selecting alternates.
```


---

# Addendum — ABI cross-check for PackDeposit & hermetic staking-deposit-cli cross-validation

## ABI cross-check for `PackDeposit` (FR-P1-C5, GO-070)

`go-ethereum/accounts/abi` is already a transitive dependency; using it for a test-only differential against our hand-rolled `PackDeposit` is one struct + ~20 LOC of test:

```go
// internal/tx/abi_diff_test.go (proposed)
const depositABIJSON = `[{
    "name":"deposit","type":"function",
    "inputs":[
        {"name":"pubkey","type":"bytes"},
        {"name":"withdrawal_credentials","type":"bytes"},
        {"name":"signature","type":"bytes"},
        {"name":"deposit_data_root","type":"bytes32"}
    ]
}]`

func TestPackDeposit_AgainstGethABI(t *testing.T) {
    parsed, err := abi.JSON(strings.NewReader(depositABIJSON))
    if err != nil { t.Fatal(err) }
    args := []interface{}{
        bytes.Repeat([]byte{0xab}, 48),
        bytes.Repeat([]byte{0xcd}, 32),
        bytes.Repeat([]byte{0xef}, 96),
        [32]byte{0x42},
    }
    geth, err := parsed.Pack("deposit", args...)
    if err != nil { t.Fatal(err) }
    ours, err := PackDeposit(args[0].([]byte), args[1].([]byte), args[2].([]byte), args[3].([32]byte))
    if err != nil { t.Fatal(err) }
    if !bytes.Equal(geth, ours) {
        t.Fatalf("ABI mismatch:\n  geth: %x\n  ours: %x", geth, ours)
    }
}
```

Independent: `accounts/abi` parses JSON ABI and encodes via its own offset-tracking machinery — no shared code with our hand-rolled `PackDeposit`. Suitable as the FR-P1-C5 / GO-070 cross-check.

## Hermetic cross-validation with the canonical CLI (FR-P1-G1, GO-059)

To keep CI hermetic for the `ethstaker-deposit-cli` cross-check:
- **Dockerize:** ship a small CI image with `pip install ethstaker-deposit-cli==<pinned>` baked in. Pin SHA-256.
- **Pin version:** any floating version risks an unrelated upstream change breaking our CI.
- **Sandbox:** the CLI writes files to its cwd; run in a `t.TempDir()`.
- **Subprocess wrapper:** invoke via `exec.CommandContext` with sanitized `cmd.Env` (per FR-P1-B4); reject if the binary's `--version` doesn't match the pin.

For ground-truth backstop, the [`consensus-spec-tests`](https://github.com/ethereum/consensus-spec-tests) repo publishes downloadable SSZ vectors (`mainnet.tar.gz` with `ssz_static/DepositData/`). One-shot in CI: download, decode the `serialized.ssz_snappy`, compare to our re-derived bytes. Pattern is used by Prysm's `testing/spectest/shared/common/ssz_static`.
```

---
