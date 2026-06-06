# Software Architecture: `eth-utils/go` Remediation (v0.2 / v1.0 / v1.1)

**Author:** architect agent (team dev-plan)
**Date:** 2026-06-07
**Status:** Draft v1 (covers M0/M1/M2 remediation of all 71 adversarial-review findings)
**Inputs:** `go/plan/prd.md`, `go/plan/research/{01..10, SUMMARY}.md`, `go/plan/REVIEW.md`,
`go/CLAUDE.md`, `go/CONVENTIONS.md`, and the existing source under `go/`.

---

## 1. Overview

`eth-utils/go` ships two CLIs (`eth-deposit-gen`, `eth-deposit-tx`) that share a pipeline of
`internal/` packages. The PRD explicitly **preserves the existing architecture** (PRD §8.1): two
binaries, BLS validator key and secp256k1 sender key never meet, `internal/network` as the single
constants source, verify-before-write in `internal/deposit`, sentinel-error exit-code contracts.

This document does **not redesign** that architecture. It records the precise interface, invariant,
boundary, secret-handling, concurrency, output, test, and CI changes required to close every
GO-001..GO-071 finding. The result is a modular monolith whose existing package seams already match
the "extract-to-service when needed" rule — no package needs to be split or merged.

Two adjacent guidance themes drive the design:

1. **Lift latent runtime contracts into compile-time-visible invariants** at module boundaries.
   The two release-blockers (GO-001 all-zero credentials, GO-002 unbound network) exist because the
   trust boundary between `eth-deposit-gen`'s output and `eth-deposit-tx`'s input has no enforced
   contract. M0 adds two new boundary checks (`Entry.ValidateForNetwork`, `validateSignedAgainstRLP`)
   that turn "operator-cooperative" properties into "loader-rejected-if-violated" properties.

2. **Externally-authoritative cross-checks for funds-critical primitives.** No SSZ root, ABI
   encoding, or BLS signature may rest on a self-referential test alone (PRD §7.6). M1 introduces a
   build-tag-gated `fastssz` differential oracle, an `accounts/abi` cross-check for `PackDeposit`,
   and a hermetic `ethstaker-deposit-cli` lane.

## 2. Architecture Principles

Beyond the project-wide principles in `go/CONVENTIONS.md`:

- **Trust-boundary checks are layered, not centralized.** GO-001 and GO-002 happened because one
  validator was missing. From M0 onward every funds-loss invariant is enforced at **at least two
  layers** (CLI flag validation **and** an `internal/{deposit,tx}.Validate*` invariant). The
  defense-in-depth check is owned by the data type, not the caller.
- **Source-of-truth is single, immutable, and function-returned.** `internal/network` owns every
  per-network constant. `DomainDeposit` and `ZeroGenesisValidatorsRoot` become functions returning
  by value (GO-038), eliminating the package-var mutability risk.
- **No silent fallback on resolved values.** A nil/zero/error response from any RPC or environment
  source aborts with a documented sentinel — never substituted with `0`, the 20-gwei default, or
  similar (PRD §7.1).
- **Atomic writes for every artifact.** A single helper (`internal/atomicio.WriteFile`) is the only
  way to persist any artifact (`build`/`sign`/`run`/`send`/deposit data/receipts), removing
  GO-011/GO-016 by construction.
- **Secrets never appear in errors.** All redacted output goes through `internal/cli.Redact(s, n)`
  (GO-006, GO-014, GO-049). Error wrapping that touches key/passphrase material always uses a
  fixed sentinel string — never `%w`-propagates a third-party message that may embed the secret.
- **Exit codes are part of the public API.** A central `TestExitCodeContract` table maps every
  documented sentinel to its exit code, gated in CI.

## 3. Cross-Cutting Decisions (locked by team lead / research)

| Decision | Reference | Notes |
|---|---|---|
| Preserve existing two-CLI + `internal/` layout | PRD §8.1 | No package added/removed/merged; one new tiny `internal/atomicio`. |
| v0.2 is a breaking release | PRD §6.1, §8.3 | `--withdrawal-{address,bls-pubkey}` required; `--rpc-url` rejected on build/run; explicit `--nonce`+fees; unified exit codes. |
| ethstaker-deposit-cli (not the deprecated ethereum/staking-deposit-cli) | research/01 §1, SUMMARY §TL;DR | Rename `runDepositCLIVerify` source-of-authority docs + CI image. |
| go-ethereum pinned to v1.17.x | research/02 §Recommended | Min v1.15.0 for usbwallet fix; v1.17.x for Gen5 + cumulative coverage. |
| Toolchain `go1.26.4`, CI `setup-go` pinned to same | research/07 §Pitfall 6 | `govulncheck` reads `go` on PATH, not the directive. |
| `fastssz` differential oracle behind `//go:build differential_oracle` | research/05 §Option A | Test-only dep; generated files committed. |
| `os.CreateTemp` + `RFC3339Nano + sha256[:4]` + dir fsync; no-clobber on final | research/06 §Option A | Implemented once in `internal/atomicio`. |
| Deposit amount as `Min/Max` range constants from day one | PRD §6.1.7 FR-P0-G2 (amended), research/08 §Recommendation | `MinDepositAmountGwei`/`MaxDepositAmountGwei` in `internal/network`; v0.2 only emits/accepts 32 ETH. |
| Herumi C-side zeroize is impossible; documented, not promised | research/03 §4, PRD §6.2.2 FR-P1-B4 amended | `BLSSigner.Zeroize` zeroes Go-side struct only; doc comment is explicit. |

## 4. System Context Diagram

```text
                                            ┌─────────────────────────────┐
                                            │  ethstaker-deposit-cli      │
                                            │  (M1 hermetic CI; M0 docs)  │
                                            └──────────────▲──────────────┘
                                                           │ verify subprocess
                                                           │
┌──────────┐   keystore + pubkeys + WC flag  ┌─────────────┴───────────────┐
│ Operator ├────────────────────────────────▶│   eth-deposit-gen            │
│  (TTY /  │                                 │   cmd/eth-deposit-gen        │
│  CI)     │◀───── deposit_data-<ts>.json ───┤   (BLS validator key only)   │
└──────────┘                                 └──────────────┬───────────────┘
     ▲                                                      │ (air-gap allowed)
     │                                                      ▼
     │                                       ┌──────────────────────────────┐
     │       hardware/local key (secp256k1)  │   eth-deposit-tx              │
     ├──────────────────────────────────────▶│   cmd/eth-deposit-tx          │
     │                                       │   build → sign → send / run   │
     │◀─── signed.json + tx hash + receipt ──┤   (secp256k1 sender key only) │
     │                                       └──────────────┬───────────────┘
     │                                                      │
     │            ┌──────────────────────┐                  ▼
     │            │  Ledger HID device   │◀─────── usbwallet (CGO)
     │            └──────────────────────┘                  │
     │                                                      ▼
     │                                       ┌──────────────────────────────┐
     └──────────── tampered JSON? ── No  ────│ JSON-RPC node (Infura,       │
                  (validateSignedAgainstRLP) │ Alchemy, self-hosted)        │
                                             └──────────────────────────────┘
```

**Key separation invariant:** the BLS key flows only through `eth-deposit-gen`; the secp256k1 key
flows only through `eth-deposit-tx`. Neither binary ever sees the other's key.

## 5. Module Overview

| Module | Responsibility | Owns Data | Depends On | New M0 work? | New M1 work? |
|---|---|---|---|---|---|
| `internal/network` | Per-network compile-time constants (chain ID, fork version, deposit contract, amount range) | Network registry table | — | range constants, single registry table at `init()` | function-returned domain/GVR (GO-038) |
| `internal/bls` | Herumi wrapper, BLS Signer/Verifier interfaces, point-on-curve validate | herumi global init | — | sentinel-only deserialize error (GO-006) | reject zero scalar / infinity (GO-036/37), Go-side `Zeroize` |
| `internal/ssz` | hand-rolled `HashTreeRoot` for `DepositMessage`, `DepositData`, `ForkData`, `SigningData` | — | — | (none) | differential oracle behind build tag (GO-048) |
| `internal/keystore` | EIP-2335 v4 keystore decrypt, dir scan, passphrase sourcing | — | — | `0X` normalize helper (GO-026), reject dup pubkeys (GO-027), TTY mutex+cache (GO-007) | regular-file + size cap (GO-030), 32-byte length (GO-029), structural vs checksum errors (GO-025), inject logger (GO-028) |
| `internal/deposit` | Domain orchestrator: SSZ + BLS + verify-before-write; the Entry data type | `Entry`, `Request`, `Generator` | network, bls, ssz | `Entry.Validate` rejects all-zero `0x00` (GO-001), `Entry.ValidateForNetwork` (GO-002/12), recompute roots, BLS re-verify | `VerifyIntegrity` becomes part of `Validate`; %w wrapping audit (GO-046) |
| `internal/output` | Launchpad JSON schema, atomic write to disk | `jsonEntry`, `Writer` | deposit, atomicio | uses `internal/atomicio`; high-res filename + no-clobber (GO-011) | unify `jsonEntry` with `internal/deposit/json.go` (FR-P2-A15) [M2] |
| `internal/atomicio` (**new**) | `WriteFile(path, data, perm)` + `WriteFileWithSuffix(dir, prefix, …)` | — | — | created M0; consumed by `build`/`sign`/`run`/`send`/`output` | (none) |
| `internal/tx` | ABI encoding, EIP-1559 builder, JSON-RPC client, tx-side validation | `UnsignedTx`, `BuildConfig`, `Builder`, `EthRPC`, `EthBroadcaster`, `Receipt` | deposit, network | `Validate` rejects all-zero `0x00` body (GO-001 DiD), `ValidateAgainstNetwork` (GO-002/12 DiD), reject `tip > maxFee` (GO-031), `ErrRPCDial` redaction (GO-049) | `BlockBaseFee` → `HeaderByNumber` + nil-base-fee error (GO-032), `ChainID()` fail-closed (GO-033), gas overflow + contract-addr direct (GO-034), `errors.Is(ethereum.NotFound)` (GO-035), hybrid `--rpc-url` decision (FR-P1-D5) |
| `internal/signer` | Local + Ledger signers, `parseUnsignedTx` | `LocalSigner`, `LedgerSigner`, `SignedTx`, sentinels | tx, go-ethereum | strict `IsHexAddress` + length (GO-003), no-leak env error (GO-014, GO-022), Ledger Open/Status real cause (GO-019), Ledger sender check (GO-023) | mutex around `LocalSigner.key` (GO-021), Ledger Close cancel doc (GO-024), reject `Type != 0x2` + negative fields (GO-020), `os.Unsetenv` + per-Sign zeroize (GO-017) |
| `internal/cli` | Flag schema for eth-deposit-gen, validation, `parsePubkeys` | `Config`, `NewApp` | network, bls | reject duplicate pubkeys (GO-009), reject positional args (GO-040), `Redact` helper (PRD §9), required-flag → exit 2 (GO-015 prep) | `confirmReader` (GO-041), `requireNoArgs` (GO-040) [M0 also], move orchestration out of `main` (FR-P2-A16) [M2] |
| `cmd/eth-deposit-gen` | Thin entry point: flags → config → pipeline | — | cli, deposit, bls, keystore, output, network | required `--withdrawal-{address,bls-pubkey}` (GO-001), USER-GUIDE fix (GO-052), ethstaker-deposit-cli rename (research/01), `runDepositCLIVerify` ctx.Err propagation (GO-018) | SIGTERM + force-second-Ctrl-C (GO-008), worker `ctx.Err()` per-iteration (GO-008) |
| `cmd/eth-deposit-tx` | Thin entry point: subcommands `build`/`sign`/`run`/`send` | `Config`, `SignConfig`, `SendConfig`, `RunConfig` | tx, signer, deposit, network | reject `--rpc-url` on build/run (GO-005, FR-P0-B8), unify exit codes (GO-015, GO-016), `validateSignedAgainstRLP` (GO-004), exit-non-zero on revert (GO-010), atomic write via `internal/atomicio` (GO-016), redact `--private-key-env` (GO-014) | mainnet ack gate (GO-013, FR-P1-A1), `confirmReader` (GO-041) |
| **(retired)** `cmd/eth-deposit-tx`/`BuildConfig.RPCURL`, `UnsignedTx.From`, `defaultWithdrawalCreds`, `padRight`, dead `TxBuilder` interface — see §15 | — | — | — | M0 deletion | — |

### 5.1 Module Dependency Graph

```text
                       ┌────────────────────────┐
                       │   internal/network     │   (no deps; range constants, function-returned domain)
                       └──────────┬─────────────┘
                                  │
                ┌─────────────────┼─────────────────┐
                ▼                 ▼                 ▼
       ┌────────────────┐ ┌──────────────┐ ┌────────────────┐
       │ internal/bls   │ │ internal/ssz │ │ internal/keystore│
       │ (Init,Signer,  │ │ (HashTreeRoot│ │ (Load,ScanDir,  │
       │  Verifier,     │ │  Domain)     │ │  Passphrase)    │
       │  ValidatePubkey│ │              │ │                 │
       └────────┬───────┘ └──────┬───────┘ └────────┬────────┘
                │                │                  │
                └────────┬───────┴──────────────────┘
                         ▼
                ┌──────────────────────┐         ┌──────────────────────┐
                │ internal/deposit     │◀────────│ internal/atomicio    │
                │ (Entry, Generator,   │         │ (WriteFile,          │
                │  Validate, VerifyForN│         │  WriteFileWithSuffix)│
                └──────┬──────────┬────┘         └─────────┬────────────┘
                       │          │                        │
                       ▼          ▼                        ▼
              ┌──────────────┐  ┌─────────────────────────────┐
              │ internal/    │  │ internal/output             │
              │   tx         │  │ (FSWriter, DryRunWriter,    │
              │ (Validate,   │  │  jsonEntry; uses atomicio)  │
              │  Validate-   │  └────────────┬────────────────┘
              │  AgainstNetwork)             │
              │  Builder,                    │
              │  EthRPC,EthBroadcaster)      │
              └──────┬──────┘                │
                     │                       │
                     ▼                       │
              ┌──────────────┐               │
              │ internal/    │               │
              │   signer     │               │
              │ (Local,Ledger│               │
              │  parseUnsignedTx)            │
              └──────┬──────┘                │
                     │                       │
                     ▼                       ▼
        ┌──────────────────────────────────────────────────────┐
        │           internal/cli                                │
        │ (parsePubkeys, NewApp, Redact, confirmReader,         │
        │  requireNoArgs)                                       │
        └──────────────┬────────────────────────────┬───────────┘
                       │                            │
                       ▼                            ▼
            ┌─────────────────────┐      ┌─────────────────────┐
            │ cmd/eth-deposit-gen │      │ cmd/eth-deposit-tx  │
            │ (BLS key path)      │      │ (secp256k1 key path)│
            └─────────────────────┘      └─────────────────────┘
```

No cycles. The two CLIs do not import each other; the BLS key never reaches `internal/signer`; the
secp256k1 key never reaches `internal/bls`.

---

## 6. Module-by-Module Change Map

Each module section lists: **(a)** new/changed exported surface, **(b)** owned findings (FR + GO),
**(c)** invariants enforced at the boundary, **(d)** internal structure notes, **(e)** phase tag.

### 6.1 `internal/network` (M0 + M1 + M2)

**Responsibility:** Single source of truth for per-network constants and consensus-spec domain
values used in the deposit signing pipeline.

**Owns:** Network registry table; `Params`; `DomainDeposit`; `ZeroGenesisValidatorsRoot`;
deposit amount range.

**New / changed exported surface:**

```go
// Range constants for deposit amounts (PRD §6.1.7 FR-P0-G2 amended).
const MinDepositAmountGwei uint64 = 32_000_000_000           // MIN_ACTIVATION_BALANCE (32 ETH)
const MaxDepositAmountGwei uint64 = 2_048_000_000_000        // MAX_EFFECTIVE_BALANCE_ELECTRA (2048 ETH)
// v0.2 emits/accepts exactly 32 ETH; the range surface is in place so v1.1 0x02 work
// is not a breaking constant rename.

// Function-returned domain/GVR replacing exported mutable vars (GO-038, FR-P1-C3).
// Implementation reads unexported package values.
func DomainDeposit() [4]byte
func ZeroGenesisValidatorsRoot() [32]byte

// Unified registry (FR-P2-A3, GO-047). The four-site duplication (Lookup,
// LookupByChainID, ParseFlag, mustParseAddr-on-call) collapses into a single
// package-level map initialised at init() time so a typo'd address panics at
// process start, not at first Lookup.
var paramsByName = map[Network]Params{ /* ... */ }    // populated at init()
// Lookup, LookupByChainID, ParseFlag remain the public API but consume the table.
```

**Files changed:** `internal/network/network.go:57-62`, `:64-154`, `:78-120`, `:124-135`,
`:140-154`.

**Owned findings:**
- M0: FR-P0-G2 (GO-001 supporting constants), FR-P0-A3 (params lookup consumed by `Entry`).
- M1: FR-P1-C3 (GO-038 mutable vars).
- M2: FR-P2-A3 (GO-047 registry consolidation).

**Invariants:**
- Every per-network value is initialised exactly once at package `init()`. A bad hex string
  panics at program start, not at first request.
- `DomainDeposit()` and `ZeroGenesisValidatorsRoot()` return by value; callers cannot mutate
  the source.

**Phase:** M0 (range constants), M1 (function-returned domain), M2 (registry unification).

---

### 6.2 `internal/bls` (M0 + M1)

**Responsibility:** Thin herumi wrapper; owns process-global init; exposes Signer/Verifier
interfaces; provides `KeyValidate`-equivalent on pubkey bytes.

**Owns:** herumi `initOnce`, the `signer` and `verifier` concrete types.

**New / changed exported surface:**

```go
// Sentinel errors (M0).
var ErrSecretRejected = errors.New("bls: secret key rejected (scalar out of range for BLS12-381)")
var ErrSecretZero     = errors.New("bls: secret key is zero")        // M1
var ErrPubkeyInvalid  = errors.New("bls: pubkey is not a valid G1 point")  // M1
var ErrPubkeyZero     = errors.New("bls: pubkey is point at infinity (KeyValidate rejected)")  // M1
```

`NewSigner` (file `internal/bls/bls.go:69-92`):

| State | M0 change | M1 change |
|---|---|---|
| Out-of-range scalar | Return `ErrSecretRejected` — **never** wrap herumi's `Deserialize` error (which embeds `%x` of the buffer; research/03 §1). | — |
| Zero scalar | — | Reject with `ErrSecretZero` *after* successful `Deserialize` (GO-036, research/03 §2). |

`ValidatePubkeyBytes` (`internal/bls/bls.go:154-165`):

| M0 | M1 |
|---|---|
| Production path now calls this (currently skipped by `internal/tx/validation.go:17-19`). | After successful Deserialize, also reject `hPub.IsZero()` (GO-037, research/03 §3). |

```go
// Zeroize wipes Go-side BLS secret-key state (M1).
//
// CAVEAT: herumi's mcl scalar lives in C-allocated memory with no Destroy API
// (research/03 §4). Zeroize replaces the Go-side struct contents — the C-side
// scalar persists in process memory until process exit. This is documented as
// a known limitation per PRD §6.2.2 FR-P1-B4 amended; we do NOT promise full
// erasure.
func (s *signer) Zeroize()
```

**Owned findings:**
- M0: FR-P0-C1 (GO-006).
- M1: FR-P1-C1 (GO-036), FR-P1-C2 (GO-037), FR-P1-B4 (GO-017 BLS-side), FR-P2-A7 (GO-062 — alias
  rename, doc fixes).

**Invariants:**
- A returned error from `NewSigner` or any `bls.*` function never contains key bytes (regression
  test per FR-P0-C1 acceptance).
- `ValidatePubkeyBytes` matches IETF `KeyValidate` (rejects identity + on-curve check) — this is
  the function `internal/tx.Validate` consumes (M1).

**Exit code mapping:**
| Sentinel | Exit code | Phase |
|---|---|---|
| `ErrSecretRejected` | 3 (crypto) | M0 |
| `ErrSecretZero` | 3 (crypto) | M1 |
| `ErrPubkeyInvalid`, `ErrPubkeyZero` | 2 (input) | M1 (consumed via wrapped sentinel in caller) |

**Phase:** M0 (FR-P0-C1), M1 (rest).

---

### 6.3 `internal/ssz` (M1 + M2)

**Responsibility:** Hand-rolled SSZ hash-tree-root for `DepositMessage`, `DepositData`, `ForkData`,
`SigningData`. No exported surface change for M0.

**New / changed exported surface:** Same as today. Internal:

- `merkleize(chunks, limit)` (`internal/ssz/ssz.go:162-175`) — M2 (FR-P2-A6, GO-061): replace the
  silent `n = max(len(chunks), limit)` floor with a `len(chunks) <= limit` precondition (panic on
  programmer error). All five existing call sites already pass `limit == len(chunks)`.
- `padRight` (`internal/ssz/ssz.go:197-208`) — M2: delete (test-only, no production caller).

**Owned findings:**
- M1: FR-P1-C4 (GO-048) — differential oracle in `_test.go` with `//go:build differential_oracle`
  (see §11 Test Architecture).
- M2: FR-P2-A6 (GO-061), FR-P2-A14 (`padRight` deletion).

**Invariants:**
- All four `HashTreeRoot` methods match the spec byte-for-byte; verified by an *independent*
  `fastssz`-driven oracle in CI lane (M1).

**Phase:** M1 + M2.

---

### 6.4 `internal/keystore` (M0 + M1)

**Responsibility:** EIP-2335 v4 keystore decrypt, directory scan, passphrase sourcing. The only
package that decrypts BLS validator keys.

**Owns:** `Key`, `KeyLoader`, `PassphraseSource`, `DirectoryIndex`.

**New / changed exported surface:**

```go
// M0 (FR-P0-B5, GO-026): single shared normalization.
func normalizePubkeyHex(s string) string  // unexported helper consumed by ScanDir.Lookup, scandir.go, keystore.go

// M0 (FR-P0-C5, GO-007, research/10 §5).
// CachingPromptSource wraps any PassphraseSource so the first call blocks on
// the underlying source and subsequent calls return a fresh copy of the cached
// passphrase. Concurrency-safe; the cache itself can be zeroized.
type CachingPromptSource struct{ /* sync.Once + sync.Mutex + []byte cache */ }
func NewCachingPromptSource(inner PassphraseSource) *CachingPromptSource
func (c *CachingPromptSource) Read() ([]byte, error)
func (c *CachingPromptSource) Zeroize()

// M1 (FR-P1-E1, GO-025): structural-vs-checksum error distinction.
var ErrKeystoreCipherText = errors.New("keystore cipher text invalid")
// Load: pre-validate keystorev4 JSON shape; only the checksum mismatch maps to
// ErrWrongPassphrase. Structural failures map to ErrKeystoreMalformed.

// M1 (FR-P1-E3, GO-029): enforce 32-byte secret length.
// Load returns ErrKeystoreMalformed and zeroizes secret if len != 32.

// M1 (FR-P1-E2, GO-028): inject logger into ScanDir.
func ScanDir(dir string, logger *slog.Logger) (DirectoryIndex, error)  // breaking signature change

// M1 (FR-P1-E4, GO-030): regular-file + size cap.
// ScanDir skips entries where !e.Type().IsRegular(); both ScanDir and Load wrap
// reads in io.LimitReader with documented 1 MiB cap (kMaxKeystoreSize const).
const MaxKeystoreSize = 1 << 20

// M0 (FR-P0-B4, GO-027): refuse duplicate pubkey.
// ScanDir errors when two .json files declare the same pubkey, naming both paths.

// M1 (FR-P1-G3, GO-045): Key.Zeroize delegates to zeroizeBytes;
// runtime.KeepAlive comment corrected.
```

**Files changed:** `internal/keystore/keystore.go:42`, `:53-57`, `:100`, `:139-142`, `:144`,
`:146-149`, `:152-159`; `internal/keystore/scandir.go:26`, `:48-51`, `:54-66`, `:65,71,76`,
`:80-81`; `internal/keystore/passphrase.go:45-62`.

**Owned findings:**
- M0: FR-P0-B4 (GO-027), FR-P0-B5 (GO-026), FR-P0-C5 (GO-007).
- M1: FR-P1-B1 loader-side (GO-008), FR-P1-E1..E4 (GO-025/28/29/30), FR-P1-G3 (GO-045),
  FR-P2-A10 (GO-065 — regen fixtures with valid 96-char pubkeys; M2).

**Concurrency contract (M0 — GO-007):**
- `termPromptSource.Read()` becomes mutex-guarded against itself.
- Production callers wrap it in `NewCachingPromptSource(termPromptSource)` before the worker pool
  starts. The first worker's read prompts once; subsequent reads return fresh copies.
- The loader's contract that the returned slice is zeroizable is preserved by returning a copy
  per call.
- End-of-run, `runWithDeps` calls `Zeroize()` on the wrapper.

**Invariants:**
- Every successful `Load` returns either `(Key, nil)` with `len(Key.Secret) == 32`, or zeroes the
  partial secret and returns an error (M1).
- `ScanDir` never returns two entries pointing to the same pubkey (M0).
- Concurrent calls to `termPromptSource.Read()` are serialised; a single prompt fires per run
  under `--parallel > 1` (M0).

**Exit code mapping:** see §10.

**Phase:** M0 (B4/B5/C5), M1 (E1..E4, G3, B1 loader), M2 (A10).

---

### 6.5 `internal/atomicio` (**new**, M0)

**Responsibility:** Atomic file write helper, shared by every persistence path in the project.

**Owns:** Nothing stateful.

**New exported surface:**

```go
// Package atomicio provides race-free, crash-safe file writes for artifacts.
// Pattern: os.CreateTemp(dir, prefix) → write → fsync → close → rename → dir fsync.
// Both helpers refuse to clobber an existing final path (Lstat check).
package atomicio

// WriteFile writes data to path using a temp+rename sequence. The temp file is
// created in filepath.Dir(path) so the rename is intra-filesystem and atomic.
// Returns the same path on success.
func WriteFile(path string, data []byte, perm os.FileMode) (string, error)

// WriteFileWithSuffix derives a unique final filename from prefix,
// UTC RFC3339Nano timestamp, and the first 8 hex chars of sha256(data),
// writes atomically into dir, and returns (finalPath, sha256hex, error).
//
// Final filename: <prefix>-<RFC3339Nano>-<sha256[:4hex]>.<ext>
// Refuses to clobber an existing finalPath. Used by internal/output (FSWriter).
func WriteFileWithSuffix(dir, prefix, ext string, data []byte, perm os.FileMode, now time.Time) (string, string, error)

// Sentinels.
var ErrClobber       = errors.New("refusing to clobber existing file")
var ErrTempCreate    = errors.New("create temp file failed")
var ErrSync          = errors.New("sync failed")
var ErrRename        = errors.New("rename to final failed")
```

**Consumed by:**
- `internal/output.FSWriter.Write` (replaces the second-granularity tmp+rename;
  `internal/output/output.go:118-160` collapses into one `atomicio.WriteFileWithSuffix` call).
  Closes GO-011.
- `cmd/eth-deposit-tx/build` (`main.go:199`), `sign` (`sign.go:171`), `send` (receipt; already
  using a local `atomicWriteFile` in `send.go:261`), `run` (`run.go:281, 292`). The duplicated
  `atomicWriteFile` in `run.go:303-330` is **deleted** in M0 in favour of this package.

**Why a new package, not a helper in `internal/cli`:** `internal/output` would need to import
`internal/cli` to share `atomicWriteFile`, but `cli` already depends on `network` and `bls`,
creating a cycle. A tiny dedicated package breaks the cycle and gives the helper a single test
home.

**Invariants:**
- After `WriteFile` returns nil, `path` exists and contains exactly `data`. If it returns non-nil,
  no partial file is visible at `path` (the temp file is removed by the deferred cleanup).
- `WriteFileWithSuffix` refuses to clobber: a second call with a colliding final name returns
  `ErrClobber` (research/06 §A).

**Phase:** M0.

---

### 6.6 `internal/deposit` (M0)

**Responsibility:** Domain orchestrator. Owns the `Entry` data type and the only `verify-before-write`
generator. **All "did this deposit get bound to the right network?" invariants live here.**

**Owns:** `Entry`, `Request`, `Generator`, `EntryFromJSON`, `EntriesFromJSON`.

**New / changed exported surface (M0):**

```go
// New sentinels (PRD §8.2 sketch precisified).
var ErrNetworkMismatch          = errors.New("entry network does not match target network")
var ErrForkVersionMismatch      = errors.New("entry fork_version does not match target genesis_fork_version")
var ErrDepositMessageRootMismatch = errors.New("computed deposit_message_root does not match entry")
var ErrDepositDataRootMismatch    = errors.New("computed deposit_data_root does not match entry")
var ErrBLSSignatureInvalid      = errors.New("BLS signature does not verify against deposit domain")
var ErrZeroWithdrawal00         = errors.New("withdrawal_credentials with 0x00 prefix has all-zero body")
var ErrInvalidWCFormat          = errors.New("withdrawal_credentials format invalid for prefix")
// ErrPubkeyMismatch, ErrSelfVerifyFailed continue from today.

// (1) Entry.Validate — UPGRADED. No new param.
// Today: only zero-detection on Pubkey/Signature/DepositDataRoot + network name lookup.
// M0: additionally
//   (a) reject 0x00 WC with all-zero body                                   (ErrZeroWithdrawal00)
//   (b) reject 0x01/0x02 WC where bytes 1..11 are non-zero                  (ErrInvalidWCFormat)
//   (c) reject any other WC prefix                                         (ErrInvalidWCFormat)
//   (d) recompute DepositMessageRoot from entry fields, require equality   (ErrDepositMessageRootMismatch)
//   (e) recompute DepositDataRoot, require equality                        (ErrDepositDataRootMismatch)
// (a)+(b)+(c) handle GO-001 defense-in-depth. (d)+(e) handle GO-012 + cover GO-002 at the
// SSZ-root layer.
func (e Entry) Validate() error

// (2) Entry.ValidateForNetwork — NEW (PRD §8.2 sketch; FR-P0-A3, FR-P0-A4).
//
//   - target.Name      must equal e.NetworkName             → ErrNetworkMismatch
//   - target.GenesisForkVersion must equal e.ForkVersion    → ErrForkVersionMismatch
//   - bls.ValidatePubkeyBytes(e.Pubkey) must pass           → ErrPubkeyInvalid (M1: also rejects identity)
//   - BLS signature verifies against
//        compute_signing_root(HTR(DepositMessage), compute_domain(DOMAIN_DEPOSIT,
//          target.GenesisForkVersion, ZeroGenesisValidatorsRoot))
//                                                          → ErrBLSSignatureInvalid
//
// Called from cmd/eth-deposit-tx/buildUnsignedTx and run.runAction before any tx
// construction. Idempotent; verifier is stateless.
func (e Entry) ValidateForNetwork(target network.Params, v bls.Verifier) error
```

**Files changed:** `internal/deposit/json.go:137-154` (`Validate` body) and `:50-110`
(`EntryFromJSON`/`EntriesFromJSON` audit for `%w` wrapping per FR-P1-F8).

**Owned findings:**
- M0: FR-P0-A2 (GO-001 DiD), FR-P0-A3 (GO-002), FR-P0-A4 (GO-012, GO-001 DiD), FR-P1-F8 (GO-046 —
  audit wrapping).

**Invariants this module enforces at its boundary:**
1. **No entry leaves this module without recomputed SSZ roots matching the stored fields.**
2. **No entry whose `NetworkName` or `ForkVersion` differs from the build target can be used to
   build a transaction.** Enforced by `ValidateForNetwork` called from both `cmd/eth-deposit-tx/build`
   and `cmd/eth-deposit-tx/run` *after* `Validate` and *before* `internal/tx.Build`.
3. **No `0x00`-prefix credential with an all-zero body passes validation** (closes GO-001 even if
   an attacker downgrades the `Entry.Validate` call site).

**Failure semantics:**
| Sentinel | Exit code | Layer that catches it |
|---|---|---|
| `ErrZeroWithdrawal00`, `ErrInvalidWCFormat` | 2 | CLI flag layer rejects first; `Entry.Validate` is DiD. |
| `ErrNetworkMismatch`, `ErrForkVersionMismatch` | 2 | `ValidateForNetwork` is the only enforcer. |
| `ErrDepositMessageRootMismatch`, `ErrDepositDataRootMismatch` | 2 | `Entry.Validate`. |
| `ErrBLSSignatureInvalid` | 3 (crypto failure on stored data) | `ValidateForNetwork`. |

**Phase:** M0.

---

### 6.7 `internal/output` (M0)

**Responsibility:** Launchpad JSON schema serialization + atomic write to disk for `eth-deposit-gen`.

**Owns:** `Writer`, `FSWriter`, `DryRunWriter`, `jsonEntry` (M2: unify with `internal/deposit/json.go`'s
identical struct, FR-P2-A15).

**New / changed exported surface:**

```go
// Writer signature unchanged.
type Writer interface {
    Write(ctx context.Context, dir string, entries []deposit.Entry, now time.Time) (path, sha256hex string, err error)
}
```

`FSWriter.Write` (`internal/output/output.go:112-164`) — M0 rewrite:
- Honour `ctx.Err()` at entry.
- Compute final filename via `atomicio.WriteFileWithSuffix(dir, "deposit_data", ".json", data, 0o600, now)`.
  Naming scheme: `deposit_data-<UTC RFC3339Nano>-<sha256[:4hex]>.json`.
- No-clobber semantics inherited from `atomicio.WriteFileWithSuffix`; caller sees `ErrClobber` (mapped
  to exit code 1 — internal/race) if two writers somehow race on the same nanosecond+digest.

`DryRunWriter`: unchanged.

**Owned findings:** FR-P0-B3 (GO-011), FR-P0-B9 (transitive — provides the helper consumed by tx).

**Invariants:**
- No `os.OpenFile` with predictable name; `os.CreateTemp` (random suffix, `O_EXCL`).
- Parent-directory `fsync` after rename (best-effort; macOS may no-op — documented).
- Returned `sha256hex` is computed over the same bytes written, so the summary line is
  cryptographically tied to the on-disk artifact.

**JSON schema stability guarantee:** field order in `jsonEntry` is fixed; encoding is
`json.Marshal` (compact). No schema change in v0.2; reserved schema additions for v1.x
(PRD §8.3) go through a separate ADR.

**Phase:** M0.

---

### 6.8 `internal/tx` (M0 + M1)

**Responsibility:** ABI encoding of `deposit(bytes,bytes,bytes,bytes32)`, EIP-1559 transaction
builder, JSON-RPC client surface (`EthRPC`, `EthBroadcaster`), tx-side validation. **All
"does this entry match the chain we are about to build for?" defense-in-depth lives here.**

**Owns:** `UnsignedTx`, `BuildConfig`, `Builder`, `EthRPC`, `EthBroadcaster`, `Receipt`,
`PackDeposit`.

**New / changed exported surface (M0):**

```go
// (1) New sentinels.
var ErrZeroWithdrawal00  = errors.New("withdrawal_credentials 0x00 prefix has all-zero body")
var ErrTipExceedsMaxFee  = errors.New("maxPriorityFeePerGas exceeds maxFeePerGas")
var ErrNetworkMismatchTx = errors.New("entry network does not match target network params")
var ErrRPCURLRejected    = errors.New("--rpc-url is reserved for v1; provide --nonce and fees explicitly")
// Receipt-phase sentinels:
var ErrReceiptReverted   = errors.New("on-chain deposit reverted (status=0)")
var ErrReceiptTimeout    = errors.New("receipt unavailable before deadline")
// Note: ErrInvalidWCFormat, ErrInvalidWCPrefix already exist.

// (2) Validate (internal/tx/validation.go:14-58) — UPGRADED.
//     Adds: (a) reject 0x00 WC with all-zero body                  (ErrZeroWithdrawal00)
//           (b) reject tip > maxFee (after fee resolution)         (ErrTipExceedsMaxFee)  [via builder]
//           (c) bls.ValidatePubkeyBytes(entry.Pubkey) — the "skipped" check at line 17-19 is enabled.
func Validate(entry deposit.Entry, cfg BuildConfig) error

// (3) ValidateAgainstNetwork — NEW (PRD §8.2 sketch).
//     Compares entry.NetworkName / entry.ForkVersion to cfg.NetworkParams.
//     Returns ErrNetworkMismatchTx / ErrForkVersionMismatch on mismatch.
//     Called from builder.BuildUnsigned right after Validate.
func ValidateAgainstNetwork(entry deposit.Entry, params network.Params) error
```

**Build path simplification (M0, FR-P0-B8):**
- `BuildConfig.RPCURL` field is **deleted** (was reserved scaffolding, `interface.go:52-53`).
- `BuildConfig.From` semantics unchanged.
- `resolveStatic` becomes the only path called by production. `resolveRPC` is retained in the
  package (for M1 wiring decision FR-P1-D5) but the call site in `cmd/eth-deposit-tx/main.go:227-247`
  no longer constructs an `EthRPC` for build/run.
- `UnsignedTx.From` (`types.go:11-13`) is **deleted** (FR-P0-G1, GO-001 quality catalogue) —
  it has been empty-string scaffolding since v0.1.

**M1 changes:**
- `BlockBaseFee` (`rpc_client.go:120-126`) → `HeaderByNumber(ctx, nil)`; nil base fee returns a
  new sentinel `ErrNoBaseFee`. Interface doc says "latest" not "pending" (GO-032, FR-P1-D1).
- `resolveRPC` chain-ID guard (`builder.go:91-101`): fail closed on RPC error or chain-ID 0;
  inject a `*slog.Logger` for the "warn-and-continue" doc actually emit (GO-033, FR-P1-D2).
- Gas estimate (`builder.go:139-161`): `estimate + estimate/5` (no overflow); use
  `cfg.NetworkParams.DepositContractAddress` directly (no hex round-trip) (GO-034, FR-P1-D3).
- `TransactionReceipt` (`rpc_client.go:78-86`): use `errors.Is(err, ethereum.NotFound)` instead of
  `strings.Contains("not found")`; retry transient errors until deadline; map receipt-phase
  failures to documented exit code (GO-035, FR-P1-D4).
- `ErrRPCDial` (`rpc_client.go:48-53`): redacted URL — `scheme://host` only via
  `internal/cli.Redact` (GO-049, FR-P0-C3).
- Hybrid `--rpc-url` decision (FR-P1-D5): proposed answer — wire `NewEthClient` into
  `BuildConfig.RPC` on `run` only; `build` stays strictly offline (research recommendation,
  PRD §11.3 leaning). **Open question carried into M1 ADR.**

**Files changed:** `internal/tx/validation.go:14-58`, `:43-45`; `internal/tx/interface.go:52-53`;
`internal/tx/types.go:11-13`; `internal/tx/builder.go:40-71` (orchestration), `:78-82`,
`:91-101`, `:104-122`, `:139-161`; `internal/tx/rpc_client.go:48-53`, `:78-86`, `:120-126`;
`internal/tx/errors.go` (new sentinels).

**Owned findings:**
- M0: FR-P0-A2 (GO-001 DiD), FR-P0-A3 (GO-002 DiD), FR-P0-A4 (GO-012), FR-P0-B7 (GO-031),
  FR-P0-B8 (GO-005), FR-P0-C3 (GO-049), FR-P0-G1 (dead fields).
- M1: FR-P1-D1..D5 (GO-032/33/34/35), FR-P1-C5 (GO-070 — ABI cross-check test, see §11).

**Invariants:**
- After `Validate + ValidateAgainstNetwork` return nil, `entry` matches the build target across
  name/fork/WC-shape/SSZ roots (the layered defense behind `Entry.ValidateForNetwork`).
- `BuildUnsigned` never silently substitutes nonce 0, fee 20 gwei, or any RPC-resolved value
  derived from a failed call.

**Phase:** M0 (validation, GO-005 reject, GO-049 redact, dead-field removal), M1 (RPC robustness).

---

### 6.9 `internal/signer` (M0 + M1 + M2)

**Responsibility:** Local (env-var private key) and Ledger (hardware) signers; the lone consumer
of `parseUnsignedTx`. Owns the secp256k1 key lifecycle.

**Owns:** `LocalSigner`, `LedgerSigner`, `SignedTx`, all `Err*` sentinels in `errors.go`.

**New / changed exported surface (M0):**

```go
// New sentinels.
var ErrDeviceUnavailable = errors.New("Ledger device present but unavailable")  // M0 (GO-019)
var ErrSenderMismatch    = errors.New("recovered sender does not match key/account address")  // M0 (GO-023)

// parseUnsignedTx (internal/signer/parse.go:26-73) — M0 rewrite.
//   (a) IsHexAddress + exact 42-char length on unsigned.To             → ErrInvalidToAddress  (M0, GO-003)
//   (b) Sign() < 0 on value / maxFee / tip                             → field-specific errors (M1, GO-020, FR-P1-F2)
//   (c) unsigned.Type != "0x2"                                          → ErrUnsupportedTxType (M1, GO-020)
var ErrInvalidToAddress  = errors.New("To is not a valid 0x-prefixed 42-char address")
var ErrUnsupportedTxType = errors.New("unsupported tx type (expected 0x2)")  // M1

// NewLocalSignerFromEnv — M0 rewrite (GO-014, GO-022).
//   - Wrap the underlying validation error with %w (preserves diagnostics).
//   - Never echo the env-var VALUE in any error — only the NAME.
//   - On any error, call internal/cli.Redact() on any string derived from env content.
func NewLocalSignerFromEnv(envVar string) (*LocalSigner, error)

// LocalSigner — M0 (GO-017 partial), M1 (GO-017 full, GO-021).
type LocalSigner struct {
    mu     sync.Mutex   // M1: guards key across Sign / Close
    key    []byte
    closed bool         // M1: now mutex-guarded; sync/atomic kept for fast-path read
}

// NewLedgerSigner — M0 (GO-019).
//   - Open and Status errors are wrapped (%w) with the real cause.
//   - "Open succeeded but Status failed" → ErrDeviceUnavailable + wrapped cause.
//   - "Open failed without 'app not open' hint" → ErrDeviceUnavailable + wrapped cause.
//   - "wallets empty" → ErrNoDevice (unchanged).
//   - Both Open and Status branches call w.Close() on failure.

// LedgerSigner.Sign — M0 (GO-023).
//   - Cross-check from := types.Sender(...) against s.account.Address.
//   - Field-compare returned tx (nonce/to/value/data/chainID/fees/gas) against requested.
//   - Mismatch → ErrSenderMismatch (exit 3).

// LedgerSigner.Close — M1 (GO-024).
//   - Emit a stderr message "reject on device to unblock" when ctx is cancelled.
//   - Bounded timeout (configurable, default 30 s) after which Close returns with an
//     "abandoning HID handle" warning. Goroutine leak is documented and acceptable.
```

**M2:** delete `ledger_nocgo.go` (GO-050, FR-P2-A4) or break the `signer → bls` dependency to
make a real `CGO_ENABLED=0` build possible. Decision deferred to M2 ADR.

**Owned findings:**
- M0: FR-P0-A5 (GO-003), FR-P0-C2 (GO-014), FR-P0-D2 (GO-019), FR-P0-D3 (GO-023), FR-P0-D4
  (Ledger E2E gate).
- M1: FR-P1-B2 (GO-021), FR-P1-B3 (GO-024), FR-P1-B4 secp256k1-side (GO-017),
  FR-P1-F2 (GO-020), FR-P1-F3 (GO-022), FR-P1-F5 (GO-051 — `signUnsignedTx` default).
- M2: FR-P2-A4 (GO-050), FR-P2-A11 (GO-067).

**Concurrency contract:**
- `LocalSigner.Sign` and `LocalSigner.Close` are serialised via `mu` (M1).
- `LedgerSigner.Sign` keeps the existing goroutine pattern; documented blocking-on-cancel behaviour
  (M1).

**Invariants:**
- A returned error from any signer constructor or `Sign` method never contains key bytes (regression
  test per FR-P0-C2 acceptance; class: "secp256k1 key value").
- `parseUnsignedTx` never produces a `parsedTx` whose `.to` was silently mangled by `HexToAddress`
  (GO-003 closed by the `IsHexAddress + length 42` precondition).

**Phase:** M0 (A5/C2/D2/D3/D4), M1 (B2/B3/B4/F2/F3/F5), M2 (A4/A11).

---

### 6.10 `internal/cli` (M0 + M1)

**Responsibility:** Flag schema for `eth-deposit-gen`, validation, `parsePubkeys`, and (new in M0)
the shared utility helpers for both CLIs.

**Owns:** `Config`, `NewApp`, `parsePubkeys`.

**New / changed exported surface (M0):**

```go
// Redact returns a fixed-format redacted representation of s suitable for error
// messages. Format: "<first prefixLen chars>... (len=N)". Used everywhere a
// secret-bearing string might surface (private key value, API-key URL, BLS
// secret hex).  PRD §9 "Error redaction".
func Redact(s string, prefixLen int) string

// requireNoArgs rejects unexpected positional args.  Returns ucli.Exit(...,2).
// Called from every Action in both CLIs (FR-P0-B6, GO-040, research/10 §2).
func requireNoArgs(c *ucli.Context) error  // unexported, helper-only

// ConfirmReader returns a reader suitable for confirmation prompts.
// If c.App.Reader is a TTY, returns it. Otherwise opens /dev/tty.
// Returns ErrNoTTY if neither is available; caller maps to exit 2 unless --yes.
// Used by send.go to fix GO-041 (FR-P1-F4, research/10 §3).
func ConfirmReader(stdin io.Reader) (r io.Reader, close func(), err error)
var ErrNoTTY = errors.New("no controlling TTY available; --yes required")

// parsePubkeys (cli.go:263-314) — M0 rewrite.
//   - Track seen pubkeys in a map[[48]byte]struct{}; reject duplicates naming
//     the entry index (FR-P0-B1, GO-009).
//   - bls.ValidatePubkeyBytes already called; M1 also catches identity (GO-037).
```

**M1 additions:**
- Pre-validate required flags in `LoadBuildConfig` / `LoadRunConfig` / `LoadSignConfig` /
  `LoadSendConfig` so urfave/cli's `errRequiredFlags` never fires (FR-P1-F1, GO-015,
  research/10 §1). Keep a substring fallback in `ExitCodeFor` as safety net.
- Required-flag pre-validation lists are derived from the flag definition table, not duplicated.

**M2:** Move `runWithDeps` orchestration from `cmd/eth-deposit-gen/main.go` into `internal/cli` per
the thin-main convention (FR-P2-A16). Out of scope for M0/M1.

**Owned findings:**
- M0: FR-P0-B1 (GO-009), FR-P0-B6 (GO-040), the `Redact` helper consumed by tx-side and bls-side
  redaction.
- M1: FR-P1-F1 (GO-015), FR-P1-F4 (GO-041), FR-P2-A8 (GO-063 — parallelism constant) [M2].

**Phase:** M0 (B1/B6 + Redact), M1 (F1/F4), M2 (A8/A16).

---

### 6.11 `cmd/eth-deposit-gen` (M0 + M1)

**Responsibility:** Thin entry point. Parses flags → builds `cli.Config` → calls `runWithDeps`.
Owns the **withdrawal-credential input** boundary.

**New / changed exported surface (M0):**

```go
// (1) NEW required flag (FR-P0-A1, GO-001).
// --withdrawal-address MUST be supplied (v0.2 is 0x01-only per the plan-gate decision;
// 0x00 --withdrawal-bls-pubkey support was descoped, 0x00/0x02 are vNext candidates).
// --withdrawal-address: EIP-55 0x-prefixed 20-byte address → emits 0x01 || 11x00 || addr
//
// Validation lives in internal/cli (LoadGenConfig pattern); the cmd layer is thin.
type WithdrawalCredentialInput struct {
    Address [20]byte // required; v0.2 emits 0x01 credentials only (plan-gate decision)
}

// (2) defaultWithdrawalCreds (main.go:66-70) — DELETED.

// (3) runDepositCLIVerify (main.go:144-154) — UPGRADED (GO-018, GO-053).
//   - Sanitize cmd.Env (research/01 §recommendation; FR-P1-B4 child).
//   - Check ctx.Err() before exec; wrap exec error with %w so SIGINT routes to exit 4.
//   - Rename references "staking-deposit-cli" → "ethstaker-deposit-cli" (research/01,
//     SUMMARY §TL;DR(a)).

// (4) Worker pool (main.go:298-368) — M1.
//   - workerCtx.Err() check at top of each loop iteration; emit context.Canceled
//     results so the collector receives one per item (FR-P1-B1).
//   - loader.Load honours ctx (already takes it; the loader change is in keystore).
//   - signal.NotifyContext registers SIGTERM too; second Ctrl+C force-terminates by
//     calling stop() once ctx is cancelled.
```

**Files changed:** `main.go:29` (CLIVersion comment — ethstaker rename), `:56-59` (error doc),
`:66-70` (delete), `:144-154`, `:298-368`, `:355`, `:499`.

**Owned findings:**
- M0: FR-P0-A1 (GO-001), FR-P0-F1 (GO-052 USER-GUIDE fix), FR-P0-F2 (CHANGELOG/MIGRATION),
  FR-P0-G1 (delete defaultWithdrawalCreds), FR-P1-F6 (GO-018 ethstaker subprocess).
- M1: FR-P1-B1 (GO-008), FR-P1-B4 child env sanitization, FR-P1-F8 (GO-046 audit).

**Phase:** M0 (the headline withdrawal-credential fix + USER-GUIDE), M1 (worker cancellation).

---

### 6.12 `cmd/eth-deposit-tx` (M0 + M1)

**Responsibility:** Thin entry point for the four subcommands. Owns the **build→sign→send pipeline
binding** boundary — the second of the two trust boundaries where GO-002 happened.

**New / changed exported surface (M0):**

```go
// (1) LoadBuildConfig (config.go) / LoadRunConfig (run.go:39) — M0 (FR-P0-B8).
//   --rpc-url on build/run is now REJECTED with internal/tx.ErrRPCURLRejected
//   ("--rpc-url is reserved for v1; provide --nonce and fees explicitly").
//   --nonce and at least one of (--max-fee-per-gas + --max-priority-fee-per-gas) become required.
//   The dead default-injection block at main.go:235-247 is DELETED.

// (2) buildUnsignedTx (main.go:208-255) — M0 rewrite.
//   - After Entry.Validate, call Entry.ValidateForNetwork(cfg.NetworkParams, bls.DefaultVerifier()).
//   - After tx.Validate, call tx.ValidateAgainstNetwork(entry, cfg.NetworkParams).
//   - No silent defaults: missing --nonce/--fees → ucli.Exit(... 2).
//   - Atomic write via internal/atomicio.WriteFile (FR-P0-B9, GO-016).

// (3) signAction (sign.go:133-176) — M0.
//   - Print a four-line signing summary to stderr before s.Sign (FR-P0-A5, GO-003 PRD §9).
//   - Atomic write via internal/atomicio.WriteFile (GO-016).
//   - Marshal error returned via ucli.Exit(... 2), unified with run/send (GO-016).

// (4) signUnsignedTx (sign.go:184-201) — M1.
//   - Switch on cfg.Signer adds default returning ErrInvalidInput (FR-P1-F5, GO-051).

// (5) validateSignedAgainstRLP — NEW (FR-P0-A6, GO-004, research/09).
//   - Decode signed.RawRLP via types.Transaction.UnmarshalBinary.
//   - Require decoded.Type() == types.DynamicFeeTxType.
//   - Field-compare chainID/to/value/nonce/hash/from(recovered via types.Sender +
//     types.LatestSignerForChainID).
//   - Compare decoded.To against netParams.DepositContractAddress.
//   - Any divergence → ucli.Exit(... 2).
//   - Called from sendAction BEFORE the chain-ID guard and BEFORE the prompt.
//   - Lives in cmd/eth-deposit-tx (next to send.go); see §7 for trust-boundary placement.
func validateSignedAgainstRLP(signed *signer.SignedTx, netParams network.Params) (*types.Transaction, error)

// (6) sendAction (send.go:150-270) — M0 rewrite around validateSignedAgainstRLP.
//   - After signed JSON unmarshal: rlpTx, err := validateSignedAgainstRLP(&signed, netParams).
//   - The prompt now renders decoded values labelled "(decoded from RLP)" (PRD §9).
//   - Chain-ID guard compares rpcChainID against rlpTx.ChainId() (not signed.Unsigned.ChainID).
//   - On rec.Status == 0 → return ErrReceiptReverted (exit 5), AFTER writing receipt file
//     (FR-P0-B2, GO-010).
//   - hexToBigInt (send.go:303-308) — return explicit (*big.Int, error) and abort on parse
//     failure (FR-P0-A6 secondary).

// (7) ExitCodeFor (exit.go:33-72) — M0 unification + M1 (GO-015 prep).
//   - urfave/cli substring fallback for "Required flag" / "Required flags" → 2.
//   - internal/tx.ErrReceiptReverted, ErrReceiptTimeout, ErrNetworkMismatchTx,
//     ErrTipExceedsMaxFee, ErrRPCURLRejected mapped per §10.
```

**M1 additions:**
- **Mainnet acknowledgement gate (FR-P1-A1, GO-013).** New required-when-mainnet flag
  `--confirm-network=mainnet` on `send` and `run` (and `build` for symmetry). The flag value
  must equal the decoded-RLP network name and the RPC-derived network name. `--yes` does NOT
  imply or bypass it. Local signer on mainnet additionally requires
  `--i-accept-local-signer-on-mainnet`. Pre-validated in `Load*Config`.
- `confirmReader` from `internal/cli` consumed in `sendAction` (FR-P1-F4, GO-041).
- `BroadcasterChainID` error wrap fixed: `%w` (FR-P1-F7, GO-042).

**Files changed:**
- `cmd/eth-deposit-tx/main.go:76-79` (exit handling), `:195-203` (atomic write), `:210-254`
  (buildUnsignedTx).
- `cmd/eth-deposit-tx/sign.go:48-54` (Redact), `:146-153` (`parseUnsignedTx` consumers),
  `:170-173` (atomic write), `:184-201`.
- `cmd/eth-deposit-tx/send.go:154-155, 176-229, 247-269, 302-308`.
- `cmd/eth-deposit-tx/run.go:53-59`, `:281-292`, `:303-330` (delete local helper; use
  `internal/atomicio`).
- `cmd/eth-deposit-tx/exit.go:33-72`.

**Owned findings:**
- M0: FR-P0-A5 (GO-003), FR-P0-A6 (GO-004), FR-P0-B2 (GO-010), FR-P0-B8 (GO-005), FR-P0-B9 (GO-016),
  FR-P0-C2 (GO-014), FR-P0-G1 (dead fields).
- M1: FR-P1-A1 (GO-013), FR-P1-F1 (GO-015), FR-P1-F4 (GO-041), FR-P1-F5 (GO-051), FR-P1-F7 (GO-042),
  FR-P1-H1 (GO-068 doc).

**Phase:** M0 (heavy lift), M1 (mainnet gate).

---

## 7. Trust-Boundary Architecture

There are **three** trust boundaries in this system. Each has exactly one owner and a documented
set of checks.

### 7.1 Boundary 1 — Withdrawal-credential input (CLI → BLS pipeline)

**Location:** `cmd/eth-deposit-gen` flag layer → `internal/cli.LoadGenConfig` → `internal/deposit.NewGenerator.Generate`.

| Check | Layer (file:line) | Sentinel | Exit | Phase |
|---|---|---|---|---|
| `--withdrawal-address` supplied (required; v0.2 is 0x01-only) | `internal/cli` flag validator | `ucli.Exit(...,2)` | 2 | M0 |
| `--withdrawal-address` is a valid EIP-55 20-byte address | `internal/cli` | `ucli.Exit(...,2)` | 2 | M0 |
| `0x00` body must not be all-zero (defense-in-depth at the Entry level) | `internal/deposit.Entry.Validate` (DiD) | `deposit.ErrZeroWithdrawal00` | 2 | M0 |
| `0x01`/`0x02` first 11 bytes must be zero | `internal/deposit.Entry.Validate` | `deposit.ErrInvalidWCFormat` | 2 | M0 |

**Data crossing the boundary:** a single `[32]byte` withdrawal credential composed from validated
input. The credential never crosses the boundary in raw form — only after structural validation.

### 7.2 Boundary 2 — Network/fork binding (deposit-data JSON → unsigned tx)

**Location:** `cmd/eth-deposit-tx/buildUnsignedTx` (file `main.go:208-255`) and the `run`
in-process variant in `run.go:223-298`.

| Check | Layer (file:line) | Sentinel | Exit | Phase |
|---|---|---|---|---|
| JSON parse + length invariants | `internal/deposit.EntriesFromJSON` (`json.go:114-128`) | wrapped JSON err | 2 | (today) |
| Entry-level structural checks (no zero pubkey/sig/dataRoot; non-zero amount; recognised network) | `internal/deposit.Entry.Validate` (M0-upgraded) | `deposit.Err*` | 2 | M0 |
| Recompute `DepositMessage`/`DepositData` SSZ roots; equality | `internal/deposit.Entry.Validate` (M0) | `deposit.ErrDeposit{Message,Data}RootMismatch` | 2 | M0 |
| Reject `0x00` WC body all-zero; canonical `0x01`/`0x02` shape | `internal/deposit.Entry.Validate` (M0) | `deposit.ErrZeroWithdrawal00` / `ErrInvalidWCFormat` | 2 | M0 |
| `entry.NetworkName == target.Name` | `internal/deposit.Entry.ValidateForNetwork` (NEW M0) | `deposit.ErrNetworkMismatch` | 2 | M0 |
| `entry.ForkVersion == target.GenesisForkVersion` | `internal/deposit.Entry.ValidateForNetwork` | `deposit.ErrForkVersionMismatch` | 2 | M0 |
| BLS pubkey is a valid G1 point (and not identity in M1) | `internal/deposit.Entry.ValidateForNetwork` via `bls.ValidatePubkeyBytes` | `bls.ErrPubkeyInvalid` / `bls.ErrPubkeyZero` | 2 / 2 | M0 / M1 |
| BLS signature verifies against `compute_domain(DOMAIN_DEPOSIT, target.GenesisForkVersion, ZeroGVR)` | `internal/deposit.Entry.ValidateForNetwork` via `bls.Verifier` | `deposit.ErrBLSSignatureInvalid` | 3 | M0 |
| **Defense-in-depth at tx layer:** same WC shape + amount + chain ID checks | `internal/tx.Validate` + new `tx.ValidateAgainstNetwork` | `tx.Err*` | 2 | M0 |
| `entry.Pubkey` matches deposit contract for chain ID | (the deposit contract address is selected from `cfg.NetworkParams`; no entry-side check) | — | — | — |

**Data crossing the boundary:** an `Entry` value derived from the JSON file and a `network.Params`
value derived from the `--network` flag. Both must be present, both must agree on every field
above.

**Two-layer defense:** GO-001 and GO-002 each existed because only one validator was missing.
After M0, every check in this table runs at *two* layers: once at `internal/deposit` and once at
`internal/tx`. A future refactor that accidentally bypasses one layer is caught by the other.

### 7.3 Boundary 3 — Signed-tx broadcast (JSON → wire)

**Location:** `cmd/eth-deposit-tx/sendAction` (file `send.go:150-270`). This is the boundary
GO-003 and GO-004 exploited.

| Check | Layer | Sentinel | Exit | Phase |
|---|---|---|---|---|
| Decode `signed.RawRLP` via `types.Transaction.UnmarshalBinary` | `validateSignedAgainstRLP` (NEW M0) | `ucli.Exit(...,2)` | 2 | M0 |
| `decoded.Type() == DynamicFeeTxType` | same | `ucli.Exit(...,2)` | 2 | M0 |
| Recover sender via `types.Sender(types.LatestSignerForChainID(decoded.ChainId()), decoded)` | same | `ucli.Exit(...,2)` | 2 | M0 |
| `recovered == signed.From` | same | `ucli.Exit(...,2)` | 2 | M0 |
| `decoded.ChainId().Uint64() == signed.Unsigned.ChainID` | same | `ucli.Exit(...,2)` | 2 | M0 |
| `decoded.To().Hex() == signed.Unsigned.To` | same | `ucli.Exit(...,2)` | 2 | M0 |
| `decoded.To() == netParams.DepositContractAddress` | same (requires `--allow-non-deposit-recipient` to override) | `ucli.Exit(...,2)` | 2 | M0 |
| `decoded.Value()`, `decoded.Nonce()`, `decoded.Hash()` match JSON metadata | same | `ucli.Exit(...,2)` | 2 | M0 |
| RPC chain ID equals **decoded** chain ID (not JSON) | `sendAction` after `validateSignedAgainstRLP` | `tx.ErrBroadcastChainIDMismatch` | 5 | M0 |
| (M1) mainnet ack gate: `--confirm-network` value equals decoded network name | `LoadSendConfig` | `ucli.Exit(...,2)` | 2 | M1 |
| Receipt `Status == 0` → exit non-zero | `sendAction` | `tx.ErrReceiptReverted` | 5 | M0 |
| Receipt timeout vs no receipt | `pollReceipt` | `tx.ErrReceiptTimeout` | 5 | M0 |

**Data crossing the boundary:** the bytes of `signed.RawRLP` (the only thing actually broadcast).
JSON metadata is treated as untrusted hints; the prompt is rendered from decoded values labelled
"(decoded from RLP)".

### 7.4 Where each function in PRD §8.2 sketch *physically* lives

| PRD sketch | Implementation location | M0 / M1 |
|---|---|---|
| `Entry.ValidateForNetwork(target)` | `internal/deposit/json.go` (next to `Entry.Validate`) | M0 |
| `tx.ValidateAgainstNetwork(entry, params)` | `internal/tx/validation.go` (paired with `Validate`) | M0 |
| `validateSignedAgainstRLP(signed, netParams)` | `cmd/eth-deposit-tx/send.go` (alongside the send orchestration; lives in the binary because it consumes both `signer.SignedTx` and `network.Params` and is the only call site) | M0 |

**Rationale for `validateSignedAgainstRLP` placement:** it depends on
`internal/signer.SignedTx`, `internal/network.Params`, and go-ethereum `core/types`. Putting it
in `internal/signer` would create a dependency on `network`; putting it in `internal/network`
would create a dependency on `signer`. The cleanest break is to keep it in the binary as part of
`sendAction`, where it has exactly one caller.

---

## 8. Secret-Handling Architecture

The PRD security pillar (§7.1) is "no secret material in errors, logs, or artifacts." Architecture:

### 8.1 The redact helper

**Location:** `internal/cli/redact.go` (new file).
**Signature:** `func Redact(s string, prefixLen int) string` — `"<prefix...>… (len=N)"`.

**Consumers:**

| Site | File / line | Class of secret |
|---|---|---|
| `bls.NewSigner` rejected key path | `internal/bls/bls.go:88-90` | BLS validator secret |
| `signer.NewLocalSignerFromHex` length/hex/scalar errors | `internal/signer/local.go:35-50` | secp256k1 sender secret |
| `signer.NewLocalSignerFromEnv` rejection | `internal/signer/local.go:58-68` | secp256k1 sender secret |
| `cmd/eth-deposit-tx.LoadSignConfig` `--private-key-env` validation | `sign.go:48-54` | (suspected) secp256k1 secret |
| `cmd/eth-deposit-tx.LoadRunConfig` `--private-key-env` validation | `run.go:53-59` | (suspected) secp256k1 secret |
| `internal/tx.NewEthClient` `ErrRPCDial` | `rpc_client.go:48-53` | API key in RPC URL |
| `internal/keystore` passphrase-related errors | `passphrase.go:23-29` | keystore passphrase |

### 8.2 Error-wrapping rules for key material

1. **Never propagate a third-party error verbatim** when the third party may have embedded the
   secret. Examples that *must not* use `%w`:
   - `herumi.SecretKey.Deserialize` → return fixed `bls.ErrSecretRejected` only.
   - keystorev4 decrypt structural errors (some encoders include payload bytes) → return fixed
     `keystore.ErrKeystoreCipherText`; do not `%w` the decoder error.
2. **Always use `%w` for non-secret errors** so `errors.Is` / `errors.As` work (CONVENTIONS.md
   §Error Handling). The audit in FR-P1-F8 (GO-046) covers `internal/keystore/scandir.go:48-51`,
   `cmd/eth-deposit-gen/main.go:249-275`, `internal/deposit/deposit.go:115-144`, and
   `internal/tx/rpc_client.go:48-53`.
3. **Always include operation context** when wrapping: `fmt.Errorf("load keystore %s: %w", path, err)`.

### 8.3 Zeroization ownership per package

| Package | Material | Lifetime | Zeroize hook | Limitation |
|---|---|---|---|---|
| `internal/keystore` | passphrase `[]byte` from any source | until `Decrypt` returns | `defer zeroizeBytes(passBytes)` in `Load` (already today, line 136) | Go string copy from line 135 cannot be wiped — immutable. Documented. |
| `internal/keystore` | decrypted `Key.Secret` 32 bytes | until caller calls `Zeroize` | `Key.Zeroize()` (M1 delegates to `zeroizeBytes`, GO-045) | Caller responsibility. `eth-deposit-gen` worker calls it immediately after `NewSigner`. |
| `internal/bls` (M1) | herumi `bls.SecretKey` Go-side struct | `Signer.Zeroize()` | `s.sk = bls.SecretKey{}` | **C-side mcl scalar persists until process exit.** Documented in `bls.go` package comment per FR-P1-B4 amended; PRD §6.2.2 acknowledges this honestly. |
| `internal/signer` | `LocalSigner.key` 32 bytes | until `Close` | `Close` wipes `s.key`; M1 also wipes per-`Sign` `priv` ecdsa reconstruction and `b` decode buffer (GO-017) | secp256k1 `*ecdsa.PrivateKey` `D *big.Int` words have no zeroize API; tracked under "Go-side state only" per FR-P1-B4. |
| `internal/cli/cachingPromptSource` (M0) | cached passphrase | until `Zeroize()` | `Zeroize()` called by `runWithDeps` end-of-run | none. |

### 8.4 Env-var lifecycle

| Env var | Set by | Read by | Unset by | Phase |
|---|---|---|---|---|
| `ETH_DEPOSIT_TX_PRIVATE_KEY` (and `--private-key-env` variants) | operator/CI | `signer.NewLocalSignerFromEnv` (`local.go:58-68`) | `signer.NewLocalSignerFromEnv` calls `os.Unsetenv(envVar)` after successful construction (M1, FR-P1-B4, GO-017) | M1 |
| Keystore passphrase env var (`--passphrase-env`) | operator/CI | `keystore.envSource.Read` (`passphrase.go:23-29`) | `runWithDeps` calls `os.Unsetenv(cfg.PassphraseEnv)` after worker pool drains (M1) | M1 |
| Child process env for `ethstaker-deposit-cli` | `runDepositCLIVerify` | sub-process | Sanitized to a fixed allow-list (HOME, PATH, LANG) via `cmd.Env = sanitizedEnv()` (M1, FR-P1-B4) | M1 |

---

## 9. Concurrency Architecture

### 9.1 Passphrase prompt: prompt-once-and-cache

**Problem:** `--parallel >= 2` with TTY source causes a race on `/dev/tty` — concurrent termios
restores re-enable echo while a sibling worker is typing (GO-007).

**Design (M0, FR-P0-C5):**
1. `runWithDeps` constructs the passphrase source: if `cfg.PassphraseEnv != ""` it returns
   `NewEnvSource` (no race possible); otherwise it constructs `NewTermPromptSource` and *wraps*
   it in `NewCachingPromptSource`.
2. `CachingPromptSource.Read()`:
   - `sync.Once.Do(func() { cached, err = inner.Read() })` — first caller blocks; siblings wait.
   - Returns a fresh `make([]byte, len(cached))`+`copy` per call so the loader's deferred
     `zeroizeBytes` doesn't clobber the cache.
3. End-of-run: `runWithDeps` calls `c.Zeroize()` regardless of outcome (defer).
4. Acceptance test: `-race`-clean parallel run of 8 keystores observed to issue exactly one TTY
   prompt (per `_test.go` instrumentation).

**Alternative considered:** reject `--parallel > 1` with TTY (PRD §6.1.3 FR-P0-C5 alternative).
Caching is more ergonomic and the implementation is small (research/10 §5).

### 9.2 Worker pool cancellation

**Today:** `cmd/eth-deposit-gen/main.go:298-368` has a `for i := range work` loop that never
checks `workerCtx.Err()` and a `loader.Load` that discards its context entirely.

**Design (M1, FR-P1-B1):**
1. Per-iteration: at the top of the `for i := range work` body, check `workerCtx.Err() != nil`;
   if so, emit a `workerResult{idx: i, err: ctx.Err()}` and `continue`. This guarantees one
   result per work item — the collector's `for r := range results` invariant.
2. `keystore.KeyLoader.Load` honours ctx: check `ctx.Err()` before file read, before `pw.Read()`,
   and before `enc.Decrypt`. The `Decrypt` itself can't be cancelled mid-scrypt but we pre-empt
   on long-running boundaries.
3. SIGTERM: `signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)`.
4. Second-Ctrl+C force terminate: `runWithDeps` arranges that the `stop()` returned by
   `NotifyContext` is invoked as soon as `ctx` is first cancelled (a watchdog goroutine
   `go func() { <-ctx.Done(); stop() }()`). After `stop()`, signals are no longer trapped and a
   second SIGINT terminates the process via the default handler.

### 9.3 `LocalSigner` mutex

**Today:** `s.key` is read in `Sign` (`local.go:74,100`) and written/zeroed in `Close`
(`local.go:144-152`), guarded only by `s.closed atomic.Bool`. Race confirmed under `-race`
(GO-021).

**Design (M1, FR-P1-B2):**
- `LocalSigner.mu sync.Mutex` guards `key` and `closed` together.
- `Sign` acquires `mu`; if `closed` returns `ErrSignerClosed`; otherwise copies `key` to a local
  variable, releases `mu`, and proceeds. The signing work is done off-lock to keep `Sign` fast.
- `Close` acquires `mu` and zeroes `key` then sets `closed`.
- Acceptance test: `-race` clean under `go test -race -run TestLocalSigner_RaceSignClose -count=100`.

### 9.4 Signal handling SIGINT/SIGTERM

| CLI | Today | M0 | M1 |
|---|---|---|---|
| `eth-deposit-gen` (`main.go:499`) | `signal.NotifyContext(ctx, SIGINT)` | same | add SIGTERM + force-second-Ctrl-C (FR-P1-B1) |
| `eth-deposit-tx` (`main.go:43`) | `signal.NotifyContext(ctx, SIGINT)` | add SIGTERM | same as gen pattern |

`Ctx.Err()` propagates to all sentinel-mapped paths via `%w`. `exitCodeFor` already maps
`context.Canceled` to exit 4 in both CLIs (today). Verified by `TestExitCodeContract`.

### 9.5 `LedgerSigner.Close` after cancel

**M1 (FR-P1-B3, GO-024):** Document blocking; emit "reject on device to unblock" to stderr; add
a 30s timeout after which Close returns with a logged warning and the goroutine is leaked
(unavoidable: geth's `wallet.SignTx` cannot be interrupted mid-APDU).

---

## 10. Output / Artifact Architecture

### 10.1 Unified atomic-write helper

| Site | Today | After M0 |
|---|---|---|
| `internal/output.FSWriter.Write` (`output.go:112-160`) | hand-rolled tmp+rename; Unix-second granularity → silent overwrite | `atomicio.WriteFileWithSuffix(dir, "deposit_data", ".json", data, 0o600, now)` |
| `cmd/eth-deposit-tx.buildCommand` (`main.go:199`) | `os.WriteFile(cfg.OutputFile, out, 0o644)` (no atomicity) | `atomicio.WriteFile(cfg.OutputFile, out, 0o644)` |
| `cmd/eth-deposit-tx.signAction` (`sign.go:171`) | `os.WriteFile(cfg.OutputFile, out, 0o600)` | `atomicio.WriteFile(cfg.OutputFile, out, 0o600)` |
| `cmd/eth-deposit-tx.runAction` (`run.go:281, 292`) | local `atomicWriteFile` helper (`run.go:303-330`) | `atomicio.WriteFile` (helper deleted) |
| `cmd/eth-deposit-tx.sendAction` receipt (`send.go:261`) | same local `atomicWriteFile` | `atomicio.WriteFile` |

### 10.2 Filename scheme

| Artifact | Old | New |
|---|---|---|
| Deposit data | `deposit_data-<unix_ts>.json` | `deposit_data-<UTC RFC3339Nano>-<sha256[:4hex]>.json` |
| Unsigned tx | user-provided `--output` | unchanged (operator names it) |
| Signed tx + `.raw` companion | user-provided | unchanged |
| Receipt | user-provided | unchanged |

### 10.3 No-clobber semantics

- `atomicio.WriteFile`: if `path` exists, returns `ErrClobber`. Caller decides whether to
  expose an `--overwrite` flag (M0: not exposed; an operator who needs to overwrite must `rm`
  manually).
- `atomicio.WriteFileWithSuffix`: collision on the final name (same nanosecond + same content) is
  practically impossible; if it occurs, return `ErrClobber`. Operator-friendly error message:
  "refusing to overwrite existing file; remove it manually if you intended to replace it".

### 10.4 JSON schema stability

| Artifact | Schema definition | Stability guarantee |
|---|---|---|
| `deposit_data-*.json` (entries array) | `internal/output.jsonEntry` (field order, hex encoding) | **Stable through v0.x and v1.x.** Field order matches `ethstaker-deposit-cli` (research/01 §JSON schema). M2 unifies the read-side `internal/deposit/json.jsonEntry` with this struct (FR-P2-A15). |
| `unsigned_tx.json` (`internal/tx.UnsignedTx`) | `types.go` struct, JSON tags | **M0 break:** `From` field deleted (was always empty); other fields stable. |
| `signed_tx.json` (`internal/signer.SignedTx`) | `signer/types.go` | **Stable.** v0.2 reserves the option to add `tx_metadata.decoded_*` fields in v1.x (PRD §8.3); not in v0.2. |
| `receipt.json` (`internal/tx.Receipt`) | `tx/rpc_client.go:31-38` | Stable. |

---

## 11. Test Architecture

### 11.1 Differential SSZ oracle (M1, FR-P1-C4, GO-048)

**Location:** `internal/ssz/ssz_oracle_test.go` (new) with `//go:build differential_oracle`.

**Mechanics (research/05 §Option A):**
- Test-only dep: `github.com/ferranbt/fastssz` added to `go.mod` under a build constraint.
- Hand-write minimal `DepositMessage`/`DepositData` Go structs in
  `internal/ssz/testdata/oracle_types.go`; run `sszgen` once and **commit** the generated
  `oracle_types_ssz.go`. CI verifies the file is up to date (`make oracle-regen` is a no-op
  except when sources change).
- `TestDifferentialDepositMessageRoot` and `TestDifferentialDepositDataRoot` drive both
  implementations from a shared seed-anchored fuzz corpus and assert byte equality.
- The dead `computeDepositMessageRoot`/`computeDepositDataRoot` and the tautological
  `FuzzMerkleize`/`FuzzUint64Chunk` assertions (`internal/ssz/ssz_test.go:333-448`,
  `ssz_fuzz_test.go:50-91`) are **deleted** in M1 in favour of seed-anchored equality fuzzers
  using the new oracle.

**Build tags:**
- Default `go test ./internal/ssz/...` runs the existing unit + golden tests (fast, no new dep).
- `go test -tags=differential_oracle ./internal/ssz/...` runs the oracle (CI lane).

### 11.2 `accounts/abi` cross-check for `PackDeposit` (M1, FR-P1-C5, GO-070)

**Location:** `internal/tx/abi_diff_test.go` (new). No build tag — `accounts/abi` is already a
transitive go-ethereum dep, so the cost is zero.

```go
func TestPackDeposit_AgainstGethABI(t *testing.T) {
    parsed, _ := abi.JSON(strings.NewReader(depositABIJSON))
    args := []any{ pk48, wc32, sig96, root32 }
    geth, err := parsed.Pack("deposit", args...)
    if err != nil { t.Fatal(err) }
    ours := PackDeposit(pubkey, wc, sig, root)
    if !bytes.Equal(geth, ours) { t.Fatalf("ABI mismatch") }
}
```

(research/05 addendum — full snippet.) Drive by a small fuzz target so layout edge cases hit
both encoders.

### 11.3 Hermetic `ethstaker-deposit-cli` cross-validation (M1, FR-P1-G1, GO-059)

**Location:** new CI job `cross-validate-deposit-cli` defined in `.github/workflows/cross-validate.yml`.

**Mechanics (research/05 addendum + research/01):**
- Dockerized CI image, `pip install ethstaker-deposit-cli==<pinned>` baked in.
- Pin SHA-256 in the workflow.
- A new tagged Go test `cmd/eth-deposit-gen/cross_validate_test.go` with
  `//go:build cross_validate` reads `os.Getenv("DEPOSIT_CLI_BIN")`, refuses to run if the
  binary's `--version` does not contain "ethstaker" (research/01 §R2), and:
  1. Generates deposit data for hoodi and mainnet against a deterministic seed.
  2. Pipes the JSON through `ethstaker-deposit-cli verify --deposit-data <ours>`.
  3. Asserts exit 0 + zero stderr.
- Run in `t.TempDir()` with a sanitized `cmd.Env`.
- The current stubbed `TestVerifyDepositCLI_*` tests (`cmd/eth-deposit-gen/main_test.go:1116-1235`)
  remain as unit-level tests of the wrapper; the cross-validate job adds the real check.

### 11.4 Golden-fixture regeneration flow

**Today:** `make refresh-golden` runs `REFRESH_GOLDEN=1 go test -run TestRefreshHoodiGolden|TestRefreshMainnetGolden`.

**M0 change:**
- After FR-P0-A1 lands (required `--withdrawal-address`), **all** committed golden fixtures must
  be regenerated. PR sequence:
  1. Land the `--withdrawal-address` flag + `Entry.Validate` rejection of all-zero `0x00`.
  2. Update the golden-test rigs to pass `--withdrawal-address` derived from a fixed test
     account (committed in `testdata/keys.json`).
  3. `make refresh-golden`.
  4. Commit the regenerated fixtures in a single PR with a CHANGELOG entry.
- A new lint `make assert-no-zero-wc` (`grep`-based) refuses to merge any committed JSON that
  contains 64 zero hex chars in a `withdrawal_credentials` field — protects against regression.
- `TestEntriesFromJSON_GoldenFile` (M1, FR-P1-G2, GO-066) reads the actual fixture file or
  round-trips via the output writer; the hand-copied literal is removed.

### 11.5 `-race` suites (M0, FR-P0-C5; M1, FR-P1-B2)

| Test | Module | Phase |
|---|---|---|
| `TestTermPromptSource_RaceParallelRead` | `internal/keystore` | M0 |
| `TestCachingPromptSource_OncePromptAcrossWorkers` | `internal/keystore` | M0 |
| `TestLocalSigner_RaceSignClose` | `internal/signer` | M1 |
| `TestWorkerPool_SIGINTPropagatesWithin1s` | `cmd/eth-deposit-gen` | M1 |

CI: `make test-race` runs `go test -race ./...` on every PR (M0 — already partially exists, gain
new cases).

### 11.6 Tampered-JSON regression suite (M0, FR-P0-A6)

**Location:** `cmd/eth-deposit-tx/send_test.go` adds:
- `TestSend_TamperedJSON_ChainIDDivergence` (mutate `signed.Unsigned.ChainID`).
- `TestSend_TamperedJSON_ToDivergence` (mutate `signed.Unsigned.To`).
- `TestSend_TamperedRawRLP_BadSignature` (flip a byte in `signed.RawRLP`).
- `TestSend_MalformedValueHex` (malformed `signed.Unsigned.Value`).

All assert exit code 2 with the divergence message.

### 11.7 Secret-leak regression matrix (M0)

Already exists for BLS secret per `cmd/eth-deposit-gen/main_test.go:641-645` (with the GO-043
comment-fix in M2). M0 adds one test per leak class:

| Leak class | Test |
|---|---|
| BLS validator secret | `TestNewSigner_OutOfRangeNoSecretLeak` (`internal/bls`) |
| secp256k1 secret in `--private-key-env` error | `TestLoadRunConfig_RejectKeyValueNoLeak` (`cmd/eth-deposit-tx`) |
| API key in RPC URL | `TestNewEthClient_DialErrorRedactsAPIKey` (`internal/tx`) |
| Keystore passphrase | (covered by env-source unit tests, no error path embeds value today; M1 adds env-var unset check) |

---

## 12. Tooling & CI Architecture

### 12.1 Makefile lint pipeline

**Today (`Makefile:30-32`):**
```make
lint:
    go vet ./...
    staticcheck ./...
```

**M0 (FR-P0-B10, FR-P0-E2, FR-P0-E3, GO-044/57/58):**
```make
lint:
    @test -z "$$(gofmt -l .)" || (gofmt -l . && false)
    go vet ./...
    go run honnef.co/go/tools/cmd/staticcheck ./...
    go run github.com/kisielk/errcheck ./...
    go run golang.org/x/vuln/cmd/govulncheck ./...
```

### 12.2 `tools/tools.go` pattern (FR-P0-E2/E3)

```go
//go:build tools
package tools
import (
    _ "github.com/kisielk/errcheck"
    _ "golang.org/x/vuln/cmd/govulncheck"
    _ "honnef.co/go/tools/cmd/staticcheck"
    _ "github.com/ferranbt/fastssz/sszgen"   // M1
)
```

Imports compile under `-tags=tools`; `go mod tidy` keeps versions pinned. CI uses
`go run <tool>` so binaries are built from pinned versions, not the developer's PATH (research/07
§Implementation Guidelines).

### 12.3 CI jobs (per PRD §8.6)

| Job | Trigger | Phase |
|---|---|---|
| `lint` (`make lint`) | every PR + push | M0 |
| `test` (`make test`) | every PR + push | exists |
| `test-race` (`go test -race ./...`) | every PR + push | M0 |
| `e2e-mock` (`make e2e-mock`) | every PR + push | exists |
| `e2e-testnet` (`make e2e-testnet`) | manual or `repository_dispatch`; gated on `RPC_URL` + `ETH_DEPOSIT_TX_PRIVATE_KEY` secrets | M0 |
| `e2e-ledger-testnet` | manual only; maintainer sign-off | M0 |
| `cross-validate-deposit-cli` (real ethstaker CLI) | tagged | M1 |
| `vuln-scan` (`govulncheck` weekly) | cron `0 4 * * MON` on develop | M0 |

### 12.4 Toolchain pinning mechanics (FR-P0-E1, GO-056)

**Today:** `go.mod` declares `go 1.26.0` with no `toolchain` directive; CI is on 1.25 (per PRD
§6.1.5). govulncheck flags 12 reachable stdlib advisories.

**M0:**
- `go.mod`: add `toolchain go1.26.4`.
- CI workflow: `actions/setup-go@v5` with `go-version: '1.26.4'` (matches the directive — this is
  required because `govulncheck` uses the `go` on PATH for stdlib analysis, not the directive
  per research/07 §Pitfall 1 and golang/go#62050).
- Local dev: `GOTOOLCHAIN=auto` (default since 1.21) downloads exactly `go1.26.4` when the
  developer's `go` is older.

### 12.5 Vulnerability suppression policy

`docs/SECURITY.md` (new) documents the format:
```yaml
suppressions:
  - id: GO-2025-XXXX
    rationale: "..."
    review_by: "2026-12-31"
```
Module-only (unreachable) hits may be suppressed with documented rationale and a re-review date.
Symbol-reachable hits are release blockers (PRD §6.1.5 FR-P0-E2 policy).

---

## 13. Module Interaction Diagrams

### 13.1 build → sign → send data flow (eth-deposit-tx, after M0)

Validation gates marked **[G1]..[G5]**.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ eth-deposit-tx build                                                         │
│                                                                              │
│   --input-file deposit_data.json                                             │
│   --network <net>                                                            │
│   --nonce N --max-fee-per-gas X --max-priority-fee-per-gas Y  (REQUIRED M0)  │
│   (NO --rpc-url; rejected)                                                   │
│       │                                                                      │
│       ▼                                                                      │
│   deposit.EntriesFromJSON                                                    │
│       │ Entry                                                                │
│       ▼                                                                      │
│   [G1] entry.Validate()                                                      │
│       • SSZ root recompute + equality                                        │
│       • 0x00 all-zero body REJECT  (GO-001 DiD)                              │
│       • 0x01/0x02 shape REJECT                                               │
│       ▼                                                                      │
│   [G2] entry.ValidateForNetwork(cfg.NetworkParams, bls.DefaultVerifier())    │
│       • NetworkName + ForkVersion match     (GO-002)                         │
│       • bls.ValidatePubkeyBytes              (GO-037 M1)                     │
│       • BLS sig verify vs deposit domain     (GO-012)                        │
│       ▼                                                                      │
│   [G3] tx.Validate(entry, buildCfg)                                          │
│       • Defense-in-depth WC + amount                                         │
│       ▼                                                                      │
│   [G4] tx.ValidateAgainstNetwork(entry, buildCfg.NetworkParams)              │
│       • DiD network/fork                                                     │
│       ▼                                                                      │
│   tx.Builder.BuildUnsigned                                                   │
│       • tip <= maxFee (GO-031)                                               │
│       • PackDeposit (calldata)                                               │
│       ▼                                                                      │
│   atomicio.WriteFile(unsigned.json, 0o644)        (GO-016)                   │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ eth-deposit-tx sign                                                          │
│                                                                              │
│   --input unsigned.json --signer local|ledger                                │
│       │                                                                      │
│       ▼                                                                      │
│   signer.parseUnsignedTx                                                     │
│       • IsHexAddress + 42-char To             (GO-003 G1)                    │
│       • Type == "0x2" (M1)                                                   │
│       • non-negative Value/MaxFee/Tip (M1)                                   │
│       ▼                                                                      │
│   print 4-line signing summary to stderr      (PRD §9)                       │
│       ▼                                                                      │
│   LocalSigner.Sign / LedgerSigner.Sign                                       │
│       • LocalSigner: mutex around key (M1)                                   │
│       • LedgerSigner: sender == account check (GO-023)                       │
│       ▼                                                                      │
│   atomicio.WriteFile(signed.json, 0o600)                                     │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ eth-deposit-tx send                                                          │
│                                                                              │
│   --input signed.json --rpc-url URL [--confirm-network=NAME (M1 mainnet)]    │
│       │                                                                      │
│       ▼                                                                      │
│   json.Unmarshal → SignedTx                                                  │
│       ▼                                                                      │
│   [G5] validateSignedAgainstRLP(signed, netParams)         (NEW M0, GO-004)  │
│       • UnmarshalBinary(RawRLP)                                              │
│       • Type == DynamicFeeTx                                                 │
│       • types.Sender(LatestSignerForChainID, decoded) == signed.From         │
│       • decoded.ChainId/To/Value/Nonce/Hash == JSON                          │
│       • decoded.To == netParams.DepositContractAddress                       │
│       ▼                                                                      │
│   broadcaster := newBroadcaster(RPC_URL)                                     │
│       ▼                                                                      │
│   rpcChainID = broadcaster.ChainID()                                         │
│   • rpcChainID == decoded.ChainId() (NOT JSON) — fail closed → exit 5        │
│       ▼                                                                      │
│   (M1) --confirm-network value == decoded network name (mainnet ack)         │
│       ▼                                                                      │
│   render prompt from DECODED values labelled "(decoded from RLP)"            │
│       ▼                                                                      │
│   read confirmation from ConfirmReader(c.App.Reader)  (M1 GO-041)            │
│       ▼                                                                      │
│   broadcaster.SendRawTransaction(decoded RLP)                                │
│       ▼                                                                      │
│   pollReceipt                                                                │
│       • status==0  → ErrReceiptReverted (exit 5)        (GO-010)             │
│       • timeout    → ErrReceiptTimeout (exit 5)                              │
│       ▼                                                                      │
│   atomicio.WriteFile(receipt.json, 0o600)                                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 13.2 eth-deposit-gen pipeline with withdrawal-credential input (after M0)

```text
                                          ┌────────────────────────────────────┐
                                          │ Operator                            │
                                          │ --keystore-dir DIR                  │
                                          │ --pubkeys 0xPK1,0xPK2               │
                                          │ --network NET                       │
                                          │ --withdrawal-address 0xADDR         │ (M0 REQUIRED, 0x01-only)
                                          │ --output-dir OUT                    │
                                          └─────────────┬──────────────────────┘
                                                        ▼
                ┌───────────────────────────────────────────────────────────────┐
                │ internal/cli.NewApp.Action                                     │
                │  • parsePubkeys (M0: dedup, GO-009)                            │
                │  • requireNoArgs (M0, GO-040)                                   │
                │  • validate WC flag (exactly one, EIP-55 / G1 point)            │
                │  • build cli.Config                                             │
                └─────────────┬─────────────────────────────────────────────────┘
                              ▼
                ┌───────────────────────────────────────────────────────────────┐
                │ cmd/eth-deposit-gen.run → runWithDeps                          │
                │   1. bls.Init                                                  │
                │   2. network.Lookup(cfg.Network) → params                      │
                │   3. mainnet ack DiD check                                     │
                │   4. keystore.ScanDir(cfg.KeystoreDir, logger)                 │
                │       • duplicate-pubkey REJECT (M0 GO-027)                    │
                │   5. pwSrc := NewCachingPromptSource(NewTermPromptSource(...)) │
                │   6. worker pool (parallel)                                    │
                │      ┌────────────────────────────────────────────────────┐    │
                │      │ per pubkey i:                                       │    │
                │      │   ctx.Err() check (M1 GO-008)                       │    │
                │      │   keystorePath := index.Lookup(pkHex)               │    │
                │      │   key := loader.Load(workerCtx, path, pwSrc)        │    │
                │      │      • ctx.Err checked (M1)                         │    │
                │      │      • 32-byte secret enforced (M1 GO-029)          │    │
                │      │   signer := bls.NewSigner(key.Secret)               │    │
                │      │      • out-of-range → ErrSecretRejected (M0 GO-006) │    │
                │      │      • zero scalar → ErrSecretZero (M1 GO-036)      │    │
                │      │   key.Zeroize()                                     │    │
                │      │   gen := deposit.NewGenerator(signer, verifier, params)│
                │      │   entries := gen.Generate(workerCtx, deposit.Request{ │
                │      │     WithdrawalCredentials: derivedFromFlag,           │
                │      │     AmountGwei: 32_000_000_000,                       │
                │      │   })                                                  │
                │      │     • verify-before-write self-check (today)         │
                │      │   emit result                                        │
                │      └────────────────────────────────────────────────────┘    │
                │   7. writer.Write(ctx, OutputDir, entries, time.Now())         │
                │       • atomicio.WriteFileWithSuffix                            │
                │       • no clobber                                             │
                │   8. optional verify-with-deposit-cli (ethstaker)              │
                │       • sanitized cmd.Env (M1)                                 │
                │       • ctx.Err propagation (M0 GO-018)                        │
                │   9. pwSrc.Zeroize()                                           │
                └────────────────────────────────────────────────────────────────┘
                                              ▼
                                       deposit_data-<RFC3339Nano>-<sha256[:4]>.json
```

---

## 14. Phase Alignment — Per-Element M0/M1/M2 Map

Tag for every architectural element so the project planner can sequence it. (Read in concert with
PRD §6 FR-→M map and PRD §14 finding map.)

### 14.1 M0 ("Hoodi-Trustworthy" v0.2)

| Element | Module | Finding |
|---|---|---|
| Required `--withdrawal-address` (0x01-only in v0.2) | `cmd/eth-deposit-gen`, `internal/cli` | GO-001 |
| Delete `defaultWithdrawalCreds`; USER-GUIDE update | `cmd/eth-deposit-gen`, `docs/` | GO-001, GO-052 |
| `Entry.Validate` rejects `0x00` all-zero body / `0x01-2` shape | `internal/deposit` | GO-001 DiD |
| `tx.Validate` rejects `0x00` all-zero body / `0x01-2` shape | `internal/tx` | GO-001 DiD |
| `Entry.ValidateForNetwork(target, v)` | `internal/deposit` | GO-002, GO-012 |
| `tx.ValidateAgainstNetwork(entry, params)` | `internal/tx` | GO-002 DiD |
| Recompute SSZ roots + BLS verify on read path | `internal/deposit` | GO-012 |
| `parseUnsignedTx` strict `IsHexAddress` + length | `internal/signer` | GO-003 |
| Print 4-line signing summary | `cmd/eth-deposit-tx` (sign) | GO-003 |
| `validateSignedAgainstRLP` | `cmd/eth-deposit-tx` (send) | GO-004 |
| Reject `--rpc-url` on build/run; delete `BuildConfig.RPCURL`, `UnsignedTx.From` | `internal/tx`, `cmd/eth-deposit-tx` | GO-005, GO-054 |
| `bls.NewSigner` returns `ErrSecretRejected` (no secret in error) | `internal/bls` | GO-006 |
| `CachingPromptSource` + mutex on `termPromptSource` | `internal/keystore` | GO-007 |
| `parsePubkeys` dedup | `internal/cli` | GO-009 |
| `--wait-for-receipt` → exit 5 on `Status == 0` | `cmd/eth-deposit-tx` (send) | GO-010 |
| `internal/atomicio` package; `FSWriter` rewrite | `internal/atomicio`, `internal/output` | GO-011 |
| `--private-key-env` redact value (use `Redact`) | `cmd/eth-deposit-tx` | GO-014 |
| `Redact` helper | `internal/cli` | (helper for GO-006, GO-014, GO-049) |
| `build`/`sign` atomic write + unified exit codes | `cmd/eth-deposit-tx` | GO-016 |
| Ledger Open/Status real cause + `ErrDeviceUnavailable` | `internal/signer` | GO-019 |
| Ledger sender + tx-field cross-check | `internal/signer` | GO-023 |
| `normalizePubkeyHex` shared helper | `internal/keystore` | GO-026 |
| `ScanDir` duplicate-pubkey error | `internal/keystore` | GO-027 |
| `tip <= maxFee` check | `internal/tx` | GO-031 |
| `requireNoArgs` helper + call sites | `internal/cli`, both CLIs | GO-040 |
| `gofmt -w .` + lint gate | Makefile, CI | GO-044 |
| `ErrRPCDial` redacts URL | `internal/tx` | GO-049 |
| Sanitize e2e-testnet.sh (no `echo`/`tee` of URL; out-of-tree artifacts) | `scripts/` | GO-053 |
| go-ethereum → v1.17.x | `go.mod` | GO-055 |
| `toolchain go1.26.4` | `go.mod`, CI `setup-go` | GO-056 |
| `govulncheck` in lint + CI | `tools/tools.go`, Makefile, CI | GO-057 |
| `errcheck` in lint + CI | `tools/tools.go`, Makefile, CI | GO-058 |
| CHANGELOG.md v0.2 + MIGRATION.md | `docs/` | FR-P0-F2 |
| Delete dead `BuildConfig.RPCURL`, `UnsignedTx.From`, `defaultWithdrawalCreds` | various | FR-P0-G1 |
| `MinDepositAmountGwei`/`MaxDepositAmountGwei` range constants | `internal/network` | FR-P0-G2 |
| Tampered-JSON regression suite | `cmd/eth-deposit-tx` tests | GO-004 acceptance |
| `make e2e-testnet` + `make e2e-ledger-testnet` checklist | Makefile, docs | FR-P0-D4 |

### 14.2 M1 ("Mainnet-Ready" v1.0)

| Element | Module | Finding |
|---|---|---|
| `--confirm-network` mainnet ack gate; `--i-accept-local-signer-on-mainnet` | `cmd/eth-deposit-tx` | GO-013 |
| Worker `ctx.Err()` per iteration + SIGTERM + force-2nd-Ctrl+C | `cmd/eth-deposit-gen`, `internal/keystore` | GO-008 |
| `LocalSigner` mutex around key | `internal/signer` | GO-021 |
| `LedgerSigner.Close` after cancel doc + timeout | `internal/signer` | GO-024 |
| `os.Unsetenv` + per-`Sign` zeroize; sanitized child env | `internal/signer`, `cmd/eth-deposit-gen` | GO-017 |
| `bls.NewSigner` rejects zero scalar | `internal/bls` | GO-036 |
| `ValidatePubkeyBytes` rejects identity | `internal/bls` | GO-037 |
| `DomainDeposit`/`ZeroGenesisValidatorsRoot` → functions | `internal/network` | GO-038 |
| `bls.Signer.Zeroize` (Go-side only) — documented C-side limit | `internal/bls` | GO-017 / FR-P1-B4 amended |
| Differential SSZ oracle behind build tag | `internal/ssz` tests | GO-048 |
| `accounts/abi` cross-check for `PackDeposit` | `internal/tx` tests | GO-070 |
| Hermetic `ethstaker-deposit-cli` CI lane | CI, tests | GO-059 |
| `Key.Zeroize` delegates to `zeroizeBytes`; comment fix | `internal/keystore` | GO-045 |
| `EntriesFromJSON_GoldenFile` reads real fixture | `internal/deposit` tests | GO-066 |
| `BlockBaseFee` → `HeaderByNumber` + `ErrNoBaseFee` | `internal/tx` | GO-032 |
| RPC chain-ID guard fail-closed | `internal/tx` | GO-033 |
| Gas estimate overflow + contract addr direct | `internal/tx` | GO-034 |
| `errors.Is(ethereum.NotFound)` + retry transient + receipt-fail sentinel | `internal/tx` | GO-035 |
| Hybrid `--rpc-url` decision (recommend: wire on `run` only) | `cmd/eth-deposit-tx`, `internal/tx` | FR-P1-D5 |
| Keystore structural-vs-checksum classification | `internal/keystore` | GO-025 |
| `ScanDir` logger injection | `internal/keystore` | GO-028 |
| 32-byte secret length check | `internal/keystore` | GO-029 |
| `regular file` + size cap | `internal/keystore` | GO-030 |
| Pre-validate required flags; substring fallback | `internal/cli`, both CLIs | GO-015 |
| `parseUnsignedTx` negative + type check | `internal/signer` | GO-020 |
| `NewLocalSignerFromEnv` wraps with `%w` | `internal/signer` | GO-022 |
| `ConfirmReader` (`/dev/tty` fallback) | `internal/cli` → `send` | GO-041 |
| `signUnsignedTx` default case | `cmd/eth-deposit-tx` | GO-051 |
| `runDepositCLIVerify` ctx.Err + `%w` | `cmd/eth-deposit-gen` | GO-018 |
| `BroadcasterChainID` error `%w` | `cmd/eth-deposit-tx` | GO-042 |
| `%w` wrapping audit (`ScanDir`, `runWithDeps`, `Generate`) | various | GO-046 |
| USER-GUIDE troubleshooting layer attribution + `ErrBroadcastChainIDMismatch` name | `docs/` | GO-068 |

### 14.3 M2 ("v1.1 Hardening")

| Element | Finding |
|---|---|
| `NewApp` doc + `cli_test.go:550-551` comment to exit 2 | GO-039 |
| Sentinel-copy in secret-leak test fixed (or comment corrected) | GO-043 |
| `internal/network` single registry table | GO-047 |
| `ledger_nocgo.go` delete or signer→bls cycle break + CI matrix | GO-050 |
| Script "NEXT STEP" → USER-GUIDE.md | GO-060 |
| `merkleize` guard `len(chunks) <= limit` | GO-061 |
| bls/ssz hygiene (alias rename, error casing, doc fix, ssz pkg comment) | GO-062 |
| Named constant for `runtime.NumCPU()*4` | GO-063 |
| Prefix `GENERATE_FIXTURES=1` in fixture-regen docstring | GO-064 |
| Test fixtures with valid 96-char pubkeys | GO-065 |
| Ledger APDU stale comment + delete tautological tests | GO-067 |
| `DEPOSIT_DATA_FILE` script comment/default consistency | GO-069 |
| `golang.org/x/crypto@latest` + `go mod tidy` | GO-071 |
| Delete `padRight`, dead `TxBuilder` interface, fake compile-time assertions, `EntryFromJSON` if unused, `deposit.Request.Pubkeys` batch field if unused | FR-P2-A14 |
| Unify `jsonEntry` between `internal/deposit/json.go` and `internal/output/output.go`; unify build flag list; de-duplicate signer/env-var validation | FR-P2-A15 |
| Duplicate package doc comments; missing sentinel docs; `%v`-flattened wraps in `rpc_client.go`; move `runWithDeps` to `internal/cli` | FR-P2-A16 |

---

## 15. Explicit Interface Contracts (M0)

Signatures of every new exported function / method, with sentinel errors and exit-code mapping.

### `internal/network`

```go
const MinDepositAmountGwei uint64 = 32_000_000_000
const MaxDepositAmountGwei uint64 = 2_048_000_000_000
func DomainDeposit() [4]byte                                // M1
func ZeroGenesisValidatorsRoot() [32]byte                   // M1
```

### `internal/bls`

```go
var ErrSecretRejected = errors.New("bls: secret key rejected (scalar out of range for BLS12-381)")
var ErrSecretZero     = errors.New("bls: secret key is zero")                                   // M1
var ErrPubkeyInvalid  = errors.New("bls: pubkey is not a valid G1 point")                       // M1
var ErrPubkeyZero     = errors.New("bls: pubkey is point at infinity (KeyValidate rejected)")   // M1
func NewSigner(secret []byte) (Signer, error)               // existing; M0 behaviour change
func ValidatePubkeyBytes(pub [48]byte) error                // existing; M1 behaviour change
type Signer interface {                                     // M1 adds Zeroize
    Sign(signingRoot [32]byte) (sig [96]byte, err error)
    PublicKey() (pub [48]byte, err error)
    Zeroize()                                               // M1
}
```

### `internal/keystore`

```go
var ErrKeystoreCipherText = errors.New("keystore cipher text invalid")   // M1
func NewCachingPromptSource(inner PassphraseSource) *CachingPromptSource // M0
func (c *CachingPromptSource) Read() ([]byte, error)                     // M0
func (c *CachingPromptSource) Zeroize()                                  // M0
func ScanDir(dir string, logger *slog.Logger) (DirectoryIndex, error)    // M1 (signature break)
```

### `internal/atomicio` (new)

```go
var ErrClobber    = errors.New("refusing to clobber existing file")
var ErrTempCreate = errors.New("create temp file failed")
var ErrSync       = errors.New("sync failed")
var ErrRename     = errors.New("rename to final failed")
func WriteFile(path string, data []byte, perm os.FileMode) (string, error)
func WriteFileWithSuffix(dir, prefix, ext string, data []byte, perm os.FileMode, now time.Time) (string, string, error)
```

### `internal/deposit`

```go
var ErrNetworkMismatch             = errors.New("entry network does not match target network")
var ErrForkVersionMismatch         = errors.New("entry fork_version does not match target genesis_fork_version")
var ErrDepositMessageRootMismatch  = errors.New("computed deposit_message_root does not match entry")
var ErrDepositDataRootMismatch     = errors.New("computed deposit_data_root does not match entry")
var ErrBLSSignatureInvalid         = errors.New("BLS signature does not verify against deposit domain")
var ErrZeroWithdrawal00            = errors.New("withdrawal_credentials with 0x00 prefix has all-zero body")
var ErrInvalidWCFormat             = errors.New("withdrawal_credentials format invalid for prefix")
// existing: ErrPubkeyMismatch, ErrSelfVerifyFailed
func (e Entry) Validate() error                                              // M0 behaviour change
func (e Entry) ValidateForNetwork(target network.Params, v bls.Verifier) error  // M0 new
```

### `internal/tx`

```go
var ErrZeroWithdrawal00  = errors.New("withdrawal_credentials 0x00 prefix has all-zero body")
var ErrTipExceedsMaxFee  = errors.New("maxPriorityFeePerGas exceeds maxFeePerGas")
var ErrNetworkMismatchTx = errors.New("entry network does not match target network params")
var ErrRPCURLRejected    = errors.New("--rpc-url is reserved for v1; provide --nonce and fees explicitly")
var ErrReceiptReverted   = errors.New("on-chain deposit reverted (status=0)")
var ErrReceiptTimeout    = errors.New("receipt unavailable before deadline")
var ErrNoBaseFee         = errors.New("RPC block has no baseFee (non-EIP-1559 block)")           // M1
func Validate(entry deposit.Entry, cfg BuildConfig) error                                        // M0 behaviour change
func ValidateAgainstNetwork(entry deposit.Entry, params network.Params) error                    // M0 new
// BuildConfig.RPCURL field DELETED.
// UnsignedTx.From field DELETED.
```

### `internal/signer`

```go
var ErrDeviceUnavailable = errors.New("Ledger device present but unavailable")    // M0
var ErrSenderMismatch    = errors.New("recovered sender does not match key/account address")  // M0
var ErrInvalidToAddress  = errors.New("To is not a valid 0x-prefixed 42-char address")  // M0
var ErrUnsupportedTxType = errors.New("unsupported tx type (expected 0x2)")             // M1
// existing: ErrUserRejected, ErrNoDevice, ErrAppNotOpen, ErrInvalidKey,
//           ErrChainIDMismatch, ErrInvalidChainID, ErrSignerClosed, ErrLedgerNotSupported
func NewLocalSignerFromEnv(envVar string) (*LocalSigner, error)        // M0 behaviour change (Redact)
func NewLedgerSigner() (*LedgerSigner, error)                          // M0 behaviour change (real cause)
```

### `internal/cli`

```go
func Redact(s string, prefixLen int) string                            // M0 new
func ConfirmReader(stdin io.Reader) (io.Reader, func(), error)         // M1 new
var ErrNoTTY = errors.New("no controlling TTY available; --yes required")  // M1
```

### `cmd/eth-deposit-tx`

```go
func validateSignedAgainstRLP(signed *signer.SignedTx, netParams network.Params) (*types.Transaction, error)  // M0 new
// Returns the decoded transaction on success so the prompt + chain-ID guard
// can render from decoded values, never JSON metadata.
```

### Exit-code map (M0 unified)

| Sentinel | Exit code |
|---|---|
| `nil` | 0 |
| `context.Canceled`, `ErrUserAborted`, `signer.ErrUserRejected`, second-Ctrl+C SIGINT | 4 |
| `ucli.ExitCoder` with `ExitCode() == 2`, urfave `Required flag` substring, `ErrInvalidInput` | 2 |
| `keystore.Err{Missing,Malformed,Version,EnvVarEmpty,NotFound,CipherText}` | 2 |
| `deposit.Err{PubkeyMismatch,NetworkMismatch,ForkVersionMismatch,DepositMessage/DataRootMismatch,ZeroWithdrawal00,InvalidWCFormat}` | 2 |
| `tx.Err{ZeroPubkey,ZeroSignature,ZeroDepositRoot,InvalidWCPrefix,InvalidWCFormat,ZeroWithdrawal00,UnconfiguredChainID,MissingFee/PriorityFee/Nonce/GasLimitStatic,MissingFromForNonce,ChainIDMismatch,NetworkMismatchTx,TipExceedsMaxFee,RPCURLRejected}` | 2 |
| `signer.Err{InvalidToAddress,UnsupportedTxType}` | 2 |
| `bls.Err{SecretRejected,SecretZero}` | 3 |
| `keystore.ErrWrongPassphrase`, `deposit.Err{SelfVerifyFailed,BLSSignatureInvalid}`, `errBLSInit`, `ErrDepositCLIFailed` | 3 |
| `signer.Err{SignerClosed,NoDevice,DeviceUnavailable,AppNotOpen,InvalidKey,InvalidChainID,ChainIDMismatch,LedgerNotSupported,SenderMismatch}` | 3 |
| `tx.Err{RPCDial,BroadcastFailed,BroadcastChainIDMismatch,ReceiptReverted,ReceiptTimeout,NoBaseFee}` | 5 |
| anything else | 1 |

`TestExitCodeContract` (one table per binary) cross-validates every entry in CI (M0).

---

## 16. Cross-Cutting Concerns

### 16.1 Authentication & Authorization

- BLS validator key: only ever decrypted in `internal/keystore.Load` (EIP-2335 v4, passphrase from
  env or TTY). Never crosses the `eth-deposit-tx` boundary.
- secp256k1 sender key: only ever entered into `internal/signer.NewLocalSignerFromHex` /
  `NewLocalSignerFromEnv` or held inside a Ledger device. Never crosses the `eth-deposit-gen`
  boundary.
- Mainnet acknowledgement (M1): two independent gates — `--confirm-network=mainnet` value must
  equal both the decoded-RLP network name and the RPC-derived network name. `--yes` is
  insufficient (FR-P1-A1).

### 16.2 Logging & Observability

- Structured `*slog.Logger` injected into every module that emits diagnostics (M1 GO-028 fixes the
  `ScanDir` `slog.Debug` → never-configured-default leak).
- `--verbose` raises level to Debug; `--json-logs` switches handler to JSON. Default Info, text
  to stderr.
- No log statement may include a value that has not passed `Redact` if it might be secret-derived.

### 16.3 Error Handling

- Sentinels are `errors.Is`-matchable (use `errors.New` at package level).
- Custom errors named `XxxError`; sentinels named `ErrXxx` (CONVENTIONS.md).
- All non-secret error returns use `%w` for wrapping (audit per FR-P1-F8).
- Secret-bearing errors use a fixed message string — never `%w` propagating a third-party message
  that may embed the secret (GO-006, GO-014, GO-049).

### 16.4 Configuration

- Flag → env → defaults precedence preserved (today's `LoadBuildConfig` pattern, `config.go:62-135`).
- v0.2: no silent default substitution for nonce / fees / `--rpc-url`. Required-flag failures
  exit 2 with operator-readable guidance (`--nonce N --max-fee-per-gas X --max-priority-fee-per-gas Y`).
- Feature flags: `--dry-run`, `--verify-with-deposit-cli`, `--keep-unsigned`, `--wait-for-receipt`,
  `--confirm-network` (M1), `--i-accept-local-signer-on-mainnet` (M1).
- Build tags: `e2e` (existing), `cross_validate` (M1, new), `differential_oracle` (M1, new),
  `tools` (M0, new).

---

## 17. Open Questions

(Inherits from PRD §11; only those still open at the architecture level.)

1. **Receipt-timeout exit code (PRD §11.2).** Architecture allocates a distinct sentinel
   `tx.ErrReceiptTimeout` (above) but maps both `ErrReceiptReverted` and `ErrReceiptTimeout` to
   exit code 5 in this draft. **Recommendation:** keep both at 5 for v0.2 (sentinel discriminator
   sufficient); add a dedicated code 6 in v1.0 if retry-automation demands it.
2. **Hybrid `--rpc-url` future (PRD §11.3 / FR-P1-D5).** Recommendation locked above: wire on
   `run` only; permanently delete from `build`. Final ADR in M1.
3. **EIP-7251 (`0x02`) timing (PRD §11.4).** Recommendation: track as M2 candidate; the
   `Min/Max` range constants land in M0 so no breaking refactor is needed.
4. **`internal/signer.parseUnsignedTx` placement.** Today in `signer`, but called only by
   `LocalSigner.Sign` and `LedgerSigner.Sign`. If `validateSignedAgainstRLP` (in
   `cmd/eth-deposit-tx`) ever needs the same parsing, the helper may need to migrate to
   `internal/tx`. Defer until M1.

## 18. Risks (architectural)

| # | Risk | Mitigation |
|---|---|---|
| R-A | `internal/atomicio` introduces a new package; consumer churn | Single round of refactoring concentrated in M0; one PR per consumer. |
| R-B | `Entry.ValidateForNetwork` requires a `bls.Verifier`; callers must construct one | Single helper `bls.DefaultVerifier()` already exists; thread it through `cfg`. |
| R-C | `validateSignedAgainstRLP` re-decodes RLP for every send; perf cost | Negligible (one `UnmarshalBinary` per `send` invocation). |
| R-D | `Redact` may be applied inconsistently if reviewers miss a call site | Lint via `grep "%v.*envVar"` and friends; one unit test per redaction call site. |
| R-E | herumi C-side zeroize cannot be implemented; PRD §6.2.2 promises only Go-side | Document explicitly in `internal/bls` package comment; PRD has been amended (research/03 §4); secret-leak class is closed via FR-P0-C1 redact. |
| R-F | Differential SSZ oracle behind a build tag risks "if-only-run-by-CI" drift | Add a stable subset to the default test path (single known-good vector); the heavy fuzz lane stays tagged. |
| R-G | `--rpc-url` rejection on build/run breaks existing scripts | MIGRATION.md + script update for `scripts/e2e-testnet.sh`; explicit error message points at the new flag set. |
| R-H | Mainnet ack gate (`--confirm-network=mainnet`) is socially-engineered around | Pair with prompt showing decoded value + amount + To (PRD R9). |

## 19. Conflicts Found Between PRD, Research, and Code

These are the conflicts the team-lead asked to be flagged rather than silently resolved.

1. **PRD vs research (research/01, SUMMARY §TL;DR(a)).** PRD frequently references
   `staking-deposit-cli`; research found this fork is deprecated 2025-10-06. **Resolution
   adopted in this architecture:** use `ethstaker-deposit-cli` everywhere; rename in
   `cmd/eth-deposit-gen/main.go:29` (CLIVersion comment), `:56-59` (ErrDepositCLI* docs),
   `:144-154` (runDepositCLIVerify). USER-GUIDE.md and CHANGELOG must be updated to match.
   *(Already noted in team-lead constraints.)*

2. **PRD vs research (research/03 §4, FR-P1-B4 amended).** PRD originally framed
   "Add a `Destroy`/`Zeroize` method to the BLS signer" as full erasure. Research confirms
   herumi's C-side `mcl` scalar has no Destroy API. **Resolution:** `bls.Signer.Zeroize` is
   documented as Go-side only (M1); the package doc comment explicitly states the C-side
   persists until process exit. *(Already in PRD §6.2.2 amended.)*

3. **PRD FR-P0-G2 vs research (research/08).** PRD's original single `DepositAmountGwei`
   constant is incompatible with EIP-7251 0x02 (range 32–2048 ETH). **Resolution:** ship as
   `Min/Max` range constants from M0. *(Already in PRD §6.1.7 amended.)*

4. **Code vs PRD §11.3 / FR-P1-D5 (hybrid `--rpc-url`).** PRD leaves the M1 decision open
   between "wire on both build and run" and "permanently delete". Research recommends "wire on
   `run` only; air-gap requires build offline." This architecture document **adopts the
   research recommendation** and tags it as a final M1 ADR. Implementation impact: keep
   `internal/tx.resolveRPC` (don't delete in M0), wire from `run` in M1.

5. **Code vs PRD §6.2.2 / FR-P1-B4 (env-var lifecycle).** `signer.NewLocalSignerFromEnv`
   (`local.go:53-68`) documents "callers should unsetenv it after construction" but the
   constructor itself does not unset. PRD expects callers (M1 obligation), but no caller does
   today. **Resolution:** in M1, `NewLocalSignerFromEnv` itself calls `os.Unsetenv(envVar)`
   right before returning (defense-in-depth; callers don't need to remember). This is a
   slight expansion of the constructor's contract — flagged here as an architectural decision
   for the team-lead's sign-off (alternative: enforce at caller in `runAction` /
   `signAction`).

6. **REVIEW.md GO-052 vs code reality.** GO-052 notes `docs/USER-GUIDE.md:217` shows a `0x01`
   credential the tool can never produce. After FR-P0-A1 the tool *can* produce `0x01`, so
   the doc fix is now "update to reflect the new flag", not "remove the example".
   *(Not a real conflict — just confirming the order of operations.)*

7. **Architecture note vs `cmd/eth-deposit-tx/main.go:30-38`.** The version comment claims
   "v0.1.0 — signals first usable release, not yet feature-complete vs roadmap" — for v0.2 this
   block needs the language changed to reflect the breaking nature of v0.2. Touched as part of
   FR-P0-F2 (CHANGELOG/MIGRATION).

---

## 20. ADRs (Architecture Decision Records)

### ADR-001: New `internal/atomicio` package

- **Status:** Accepted (M0).
- **Context:** GO-011, GO-016 require atomic writes from five call sites across two CLIs and one
  output writer. A helper inside `internal/cli` or `internal/output` would create cycles.
- **Decision:** New `internal/atomicio` package with `WriteFile` and `WriteFileWithSuffix`.
- **Alternatives:** `google/renameio` v2 (extra dep, macOS quirks); duplicating the helper in
  each binary (drift).
- **Consequences:** One new tiny package; consumers of `os.WriteFile` and the local
  `atomicWriteFile` in `cmd/eth-deposit-tx/run.go:303-330` migrate.

### ADR-002: `Entry.ValidateForNetwork` lives in `internal/deposit`, not `internal/tx`

- **Status:** Accepted (M0).
- **Context:** GO-002 binding could live in either package. The deposit-data semantic invariant
  is "fork_version matches genesis_fork_version of declared network"; the tx-side cares about
  "chain ID matches".
- **Decision:** `Entry.ValidateForNetwork(target, v)` is a `deposit.Entry` method (consumes
  `bls.Verifier` for the BLS check). `tx.ValidateAgainstNetwork(entry, params)` is the DiD
  partner.
- **Alternatives:** put it all in `tx` (would force `tx` to import `bls`/`ssz` directly via
  re-verify); put it all in a new `internal/binding` package (over-split).
- **Consequences:** `internal/deposit` already imports `bls` and `ssz`; no new edges. `tx`
  remains free of BLS/SSZ details for the DiD check.

### ADR-003: `validateSignedAgainstRLP` stays in `cmd/eth-deposit-tx`, not `internal/tx`

- **Status:** Accepted (M0).
- **Context:** The helper consumes both `signer.SignedTx` and `network.Params` and writes user-
  facing exit errors. Putting it in `internal/tx` would force `internal/tx → internal/signer`
  (today `signer → tx`).
- **Decision:** Lives in `cmd/eth-deposit-tx/send.go` next to the one caller.
- **Alternatives:** new `internal/broadcast` package (over-split for a single helper);
  `internal/signer` (still cycles with `network`).
- **Consequences:** The helper is tested via `send_test.go`; if a second consumer appears, it
  migrates to `internal/tx` after the `signer→tx` dependency is broken.

### ADR-004: Reject `--rpc-url` on `build`/`run` in M0; revisit in M1 for `run`

- **Status:** Accepted (M0 reject), M1 deferred (FR-P1-D5).
- **Context:** GO-005 + FR-P0-B8 + research/02 hybrid mode unknowns.
- **Decision:** M0 returns `tx.ErrRPCURLRejected` with operator guidance. M1 wires on `run` only;
  `build` stays strictly offline (research recommendation, PRD §11.3 lean).
- **Alternatives:** silently honour `--rpc-url`; quietly delete the flag.
- **Consequences:** breaking change documented in MIGRATION.md.

### ADR-005: `Min/Max` deposit amount range constants from M0

- **Status:** Accepted (M0).
- **Context:** EIP-7251 0x02 deposits use 32–2048 ETH range (research/08). PRD FR-P0-G2 was
  amended.
- **Decision:** `MinDepositAmountGwei` and `MaxDepositAmountGwei` ship in M0 in `internal/network`.
  v0.2 only emits/accepts exactly 32 ETH (a sub-check in `Entry.Validate` / `tx.Validate`); the
  range surface is in place for v1.1.
- **Consequences:** zero migration cost when 0x02 lands in M2.

### ADR-006: BLS Zeroize is Go-side only; herumi C-side limitation documented

- **Status:** Accepted (M1).
- **Context:** research/03 §4 — herumi `mcl` has no Destroy API.
- **Decision:** `bls.Signer.Zeroize` wipes Go-side struct; package doc states the C-side
  persists until process exit.
- **Consequences:** PRD FR-P1-B4 amended (already done). PRD §3.2 metric 12 honestly framed
  ("no process exit leaves secret material in **Go-managed** memory").

### ADR-007: `fastssz` differential oracle behind a build tag

- **Status:** Accepted (M1).
- **Context:** GO-048 dead/tautological oracle; need genuinely independent verification.
- **Decision:** New test-only `ferranbt/fastssz` dep behind `//go:build differential_oracle`;
  generated code committed; dedicated CI lane.
- **Alternatives:** Python eth2spec (slow, flaky); vendor Prysm types (GPL-3 incompatible).
- **Consequences:** one new test-only dep; default `go test` unchanged.

---

## 21. Architecture Quality Checklist

- [x] **No circular dependencies** — verified via §5.1 graph; the new `internal/atomicio`
  package is a leaf with no deps.
- [x] **Each module has a single, clear responsibility** — see §6.
- [x] **No shared databases** — n/a (filesystem artifacts only); no module reads another's
  on-disk artifacts directly (everything goes through typed APIs).
- [x] **All inter-module communication goes through defined interfaces** — `EthRPC`,
  `EthBroadcaster`, `KeyLoader`, `PassphraseSource`, `Writer`, `Signer`, `Verifier`. No
  package imports another's internals.
- [x] **Every module can be tested in isolation** — preserved by today's DI pattern in both
  CLIs; new helpers `Redact`, `ConfirmReader`, `CachingPromptSource`, `atomicio.*` are pure
  functions over stdlib types.
- [x] **Cross-cutting concerns are standardized** — `Redact`, `atomicio`, `*slog.Logger`
  injection.
- [x] **Failure modes are defined** — §10 exit-code map; §7 per-boundary sentinel table.
- [x] **Service extraction path is clear** — both CLIs are already separate binaries; any
  `internal/*` package can be lifted into a separate module without code changes by moving
  the file (no shared global state after M1 makes `internal/network` vars function-returned).
- [x] **Data flow is traceable** — §13 diagrams.
- [x] **Module count is justified** — one new package added (`internal/atomicio`); no
  splits/merges of existing packages.
