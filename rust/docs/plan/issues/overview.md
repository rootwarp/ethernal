# Issue Overview — Go → Rust Migration of `eth-deposit`

**Scope:** Port `go/` (`cmd/eth-deposit` + 9 internal packages, ~5.1k src / ~13.4k test LOC)
into the `rust/` workspace with full behavioral parity: same five subcommands
(`gen`, `build`, `sign`, `run`, `send`), same exit-code contract (0–5), and
byte-for-byte identical output against the existing golden fixtures.
**Sizing:** 1 story point ≈ half a working day. Every issue is ≤ 4 pts (≤ 2 days).
**Streams:** A = critical path (core → gen pipeline → tx pipeline → orchestration → sign-off);
B = parallelizable (keystore; ledger; docs/tooling).
**Merge model:** per-issue fast-forward; every merge must be green (`cargo test` workspace-wide).

---

## Locked design decisions

| Area | Go | Rust | Rationale |
|---|---|---|---|
| Workspace layout | `internal/*` packages | `crates/core` (ssz, network, bls, deposit, output), `crates/keystore`, `crates/tx`, `crates/signer`, `bins/eth-deposit` | Mirrors the Go dependency graph; keeps the three big self-contained chunks (keystore/tx/signer) independently workable |
| BLS12-381 | herumi/bls-eth-go-binary | `blst` (supranational) | Same ciphersuite (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`); blst is the standard in Rust consensus clients; golden fixtures prove equivalence |
| SSZ / ABI / RLP / JSON-RPC | hand-rolled (ssz, abi) + geth (rlp, rpc) | all four hand-rolled | Repo philosophy is auditable minimal-dep encoding verified by golden tests; RLP for one tx type and 7 RPC methods are small |
| secp256k1 + keccak | geth crypto (libsecp256k1) | `k256` + `sha3` | Both RFC6979 deterministic + low-s; signed-tx golden fixture proves byte-identity |
| EIP-2335 keystore | wealdtech keystorev4 | RustCrypto `scrypt`/`pbkdf2`/`aes`+`ctr` + NFKD normalization | Existing pbkdf2/scrypt fixtures verify |
| CLI | urfave/cli v3 | `clap` v4 (env-var sources, aliases) | clap parse errors exit 2, matching the usage-error contract |
| HTTP | geth ethclient (http/ws) | `ureq` (http/https only) | **Divergence:** no `ws://` RPC support; deposit workflows use https in practice — documented |
| Ledger | geth usbwallet (cgo) | transport trait + mock tests; real HID/APDU behind `ledger` cargo feature | Same testing strategy as Go (mock-driven orchestration; hardware untestable in CI) |
| Cancellation (SIGINT → exit 4) | `signal.NotifyContext` | signal handler + `CancelToken` (AtomicBool) checked between pipeline steps | Preserves exit-code 4 semantics |
| Fee/value integers | `big.Int` | `u128` (wei) | 2^128 wei ≈ 3.4e20 ETH; explicit range error on overflow — documented divergence |

Already scaffolded (pre-work, becomes R1-1): workspace `Cargo.toml` with all deps,
crate directories, `crates/core` manifest + module skeleton, golden fixtures copied
(`rust/testdata/`, `crates/keystore/testdata/`, `crates/core/testdata/`).

---

## All issues

| ID | Title | Pts | Stream | Depends on |
|---|---|---|---|---|
| R1-1 | Workspace scaffold: crate manifests, fixtures, Makefile skeleton | 1 | A | — |
| R1-2 | `core::ssz` — hash_tree_root containers, merkleize, domain/signing-root + tests | 2 | A | R1-1 |
| R1-3 | `core::network` — params, lookup, parse_flag, chain-ID lookup + tests | 1 | A | R1-1 |
| R1-4 | `core::bls` — blst Signer/Verifier traits, pubkey validation + tests | 2 | A | R1-1 |
| R1-5 | `keystore` crate — EIP-2335 v4 decrypt (scrypt/pbkdf2/aes-ctr/NFKD), scandir, passphrase sources, sentinels + fixture tests | 4 | B | R1-1 |
| R2-1 | `core::deposit` — Generator (verify-before-write), Entry, JSON read-side + Validate + tests | 2 | A | R1-2, R1-3, R1-4 |
| R2-2 | `core::output` — Launchpad JSON serialization, atomic FS writer, dry-run writer, sha256 + tests | 2 | A | R2-1 |
| R2-3 | bin `gen` — clap schema, pubkey/dir validation, mainnet ack gate, banner, worker-pool signing, progress, summary + tests | 4 | A | R2-1, R2-2, R1-5 |
| R2-4 | `gen` golden gate — byte-identity vs `testdata/{hoodi,mainnet}/deposit_data-expected.json` and vs Go binary | 1 | A | R2-3 |
| R3-1 | `tx` offline — UnsignedTx, PackDeposit ABI, validation, static builder + unsigned-tx golden | 3 | A | R2-1 |
| R3-2 | `tx` RPC — JSON-RPC client, resolve (chainID guard, tip, 2·baseFee+tip, pending nonce, estimateGas +20%), URL redaction + mock tests | 4 | A | R3-1 |
| R3-3 | `signer` local — EIP-1559 RLP + keccak, k256 low-s/y-parity, EIP-55 From, SignedTx JSON + signed-tx golden | 3 | A | R3-1 |
| R3-4 | `signer` ledger — transport trait, error heuristics, mock tests; HID/APDU behind `ledger` feature | 3 | B | R3-3 |
| R3-5 | bin `build` + `sign` — config load (flag>env>default), `--from` gate, stdin/stdout modes, exit-map first cut + tests | 3 | A | R3-1, R3-2, R3-3 |
| R4-1 | bin `run` — in-process build+sign, `--keep-unsigned`, `.raw` companion, atomic writes, ledger RPC gate, local-From derivation + tests | 2 | A | R3-5 |
| R4-2 | bin `send` — typed network-name confirmation, broadcast, chain-ID guard, receipt polling/output + mock tests | 3 | A | R3-2, R3-3 |
| R4-3 | Exit-code contract — full `ExitCodeFor` port, usage errors → 2, SIGINT → 4, redact-at-log-boundary + usage/exit/redact tests | 2 | A | R3-5, R4-1, R4-2 |
| R5-1 | E2E suite — port `test/e2e` + cmd e2e (mock broadcaster), Rust↔Go byte-identity harness across all five subcommands | 3 | A | R4-3, R2-4 |
| R5-2 | Tooling & docs — Makefile targets (build/test/lint/e2e-mock), USER-GUIDE for Rust binary, clippy/fmt gates, `go/` retirement decision | 2 | B | R5-1 |

**Total: 37 points** (≈ 18.5 person-days single-developer; streams A/B overlap
R1-5, R3-4, R5-2 for meaningful parallel savings).

## Per-phase totals & milestones

| Phase | Theme | Issues | Points | Milestone (gate to next phase) |
|---|---|---|---|---|
| 1 — Foundations | workspace + pure primitives + keystore | 5 | 10 | **M1:** `cargo test -p core -p keystore` green |
| 2 — Gen pipeline | deposit generation end-to-end | 4 | 9 | **M2:** `gen` output byte-identical to Go golden fixtures |
| 3 — Tx pipeline | build/sign, offline + RPC + ledger | 5 | 16* | **M3:** unsigned+signed golden byte-identical (offline path) |
| 4 — Orchestration | run/send + exit-code contract | 3 | 7 | **M4:** all five subcommands green, exit codes 0–5 verified |
| 5 — Verification | e2e + docs + tooling | 2 | 5 | **M5:** full suite + Rust↔Go diff harness green, docs done |

\* Phase-3 total counts R3-4 (stream B); critical path through phase 3 is 13 pts.

## Verification strategy (why the goldens make this safe)

Every crypto/encoding boundary has an existing fixture produced by the Go implementation:

1. `testdata/{hoodi,mainnet}/deposit_data-expected.json` — full gen pipeline (keystore → BLS → SSZ → JSON)
2. `testdata/phase2/holesky/unsigned_tx_golden.json` — ABI packing + builder defaults
3. `testdata/phase3/holesky/signed_tx_golden.json` + `private_key.txt` — RLP + secp256k1 + keccak + EIP-55
4. `crates/keystore/testdata/keystore-{pbkdf2,scrypt}.json` — EIP-2335 decrypt

R5-1 additionally shells out to both binaries (`go/bin/eth-deposit` vs `cargo` build)
and diffs stdout/stderr/exit codes on identical inputs.

## Open questions (decide before the affected issue starts)

1. **`ws://` RPC endpoints** (R3-2): drop with a clear exit-2 error, or add a ws client dep? Recommendation: drop; document in USER-GUIDE.
2. **`--verify-with-deposit-cli`** (R2-3): port the shell-out as-is (recommended) or drop as vestigial?
3. **Fate of `go/`** (R5-2): keep as reference implementation for the diff harness, or delete after M5? Recommendation: keep until one release cycle after M5, then delete.
4. **Ledger hardware validation** (R3-4): mock-tested only in CI, same as Go; needs one manual hardware session before any real-fund use.

---

## Progress log (2026-07-17)

| Issue | Status | Commit | Gate result |
|---|---|---|---|
| R1-1 | done | 2b2cd8c | workspace green, fixtures in place |
| R1-2/3/4, R2-1/2 | done | b43dbd5 | hoodi + mainnet gen goldens byte-identical on first run |
| R1-5 | done | e47ca69 | pbkdf2/scrypt fixtures decrypt; 25 tests |
| core tests | done | a1e246e | 73 ported tests green |
| R3-3/R3-4 | done | a673fc3 | signed-tx golden byte-identical on first run; 94 tests |
| R3-1/R3-2 | done | 2624360 | unsigned-tx golden byte-identical; 44 tests; redaction invariant tested |
| R2-3/R2-4 | done | 6d9825f | gen: Rust and Go binaries byte-identical stdout AND stderr |
| R3-5, R4-1/2/3 | done | dbc210f | diff-go.sh 12/12 across all five subcommands |
| R5-1 | in progress | — | bin-level Go test suites being ported |
| R5-2 | in progress | — | README/USER-GUIDE notes done; final clippy/fmt pending R5-1 |

Open question resolutions to date: (1) ws:// dropped, documented; (2)
--verify-with-deposit-cli ported as-is; (3) go/ kept as reference — revisit
one release after M5; (4) ledger hardware validation deferred, feature-gated.
