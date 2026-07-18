# Phase 1 — Foundations (M1: `cargo test -p eth-deposit-core -p eth-deposit-keystore` green)

## R1-1 — Workspace scaffold (1 pt, stream A, deps: —)

**Scope:** `rust/Cargo.toml` workspace deps; crate manifests for core/keystore/tx/signer/bin;
minimal `lib.rs`/`main.rs` so the workspace builds; fixtures copied from `go/`
(`rust/testdata/`, `crates/keystore/testdata/`, `crates/core/testdata/`); porting
conventions doc (`docs/plan/porting-conventions.md`).

**Acceptance:** `cargo check` green workspace-wide; fixtures present; conventions doc covers
error style, naming, JSON parity rules, test placement.

## R1-2 — `core::ssz` (2 pts, stream A, deps: R1-1)

**Scope:** Port `go/internal/ssz/ssz.go` → `crates/core/src/ssz.rs`. Containers
`DepositMessage`, `DepositData`, `ForkData`, `SigningData` with `hash_tree_root()`;
`compute_domain`, `compute_signing_root`; `merkleize`, `byte_vector_root`, `uint64_chunk`
public for property tests.

**Acceptance:** all vectors from `ssz_test.go` pass (container roots, merkleize edge cases,
uint64 chunk encoding); property tests replacing `FuzzMerkleize`/`FuzzUint64Chunk` cover
padding/limit invariants.

## R1-3 — `core::network` (1 pt, stream A, deps: R1-1)

**Scope:** Port `go/internal/network/network.go` → `crates/core/src/network.rs`. `Network`
enum (mainnet/hoodi/sepolia/holesky), `Params` (genesis fork version, chain ID, deposit
contract, explorer URL), `lookup`, `lookup_name` (arbitrary-string variant used by
`Entry::validate`), `lookup_by_chain_id`, `parse_flag`, `DOMAIN_DEPOSIT`,
`ZERO_GENESIS_VALIDATORS_ROOT`. Error messages verbatim from Go.

**Acceptance:** `network_test.go` cases pass; per-network constants byte-identical.

## R1-4 — `core::bls` (2 pts, stream A, deps: R1-1)

**Scope:** Port `go/internal/bls/bls.go` → `crates/core/src/bls.rs` on `blst` `min_pk`
(ETH ciphersuite DST). `Signer`/`Verifier` traits with `[u8;96]`/`[u8;48]` compressed
points; `new_signer(&[u8;32])` (rejects non-scalar/zero); `default_verifier()`;
`validate_pubkey_bytes` (G1 subgroup check). blst needs no global init — `bls::init()`
becomes a no-op kept only for call-site parity.

**Acceptance:** `bls_test.go` cases pass (sign/verify roundtrip, wrong-key verify=false,
malformed encodings=Err, 32-byte length enforcement).

## R1-5 — `keystore` crate (4 pts, stream B, deps: R1-1)

**Scope:** Port `go/internal/keystore/*` → `crates/keystore/src/`. EIP-2335 v4 decrypt
replacing wealdtech: NFKD-normalize + strip C0/C1/Delete control chars from passphrase,
scrypt or pbkdf2(HMAC-SHA256) KDF, checksum `sha256(dk[16..32] || ciphertext)`,
aes-128-ctr decrypt. `Key { secret, pubkey_hex }` with zeroize; sentinel errors
(`Missing`, `Malformed`, `Version`, `WrongPassphrase`, `EnvVarEmpty`, `NoTty`,
`NotFound`); `scan_dir` pubkey→path index (skip non-json/invalid/no-pubkey silently);
passphrase sources: env var + TTY prompt (/dev/tty, echo off, prompt to writer,
hint message on no-TTY verbatim from Go).

**Acceptance:** decrypts `testdata/keystore-{pbkdf2,scrypt}.json` with the EIP-2335 test
passphrase; wrong passphrase → `WrongPassphrase`; v3 → `Version`; `scandir_test.go` +
`keystore_test.go` + `passphrase_internal_test.go` cases ported and green.
