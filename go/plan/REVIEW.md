# Adversarial Code Review — go/

**Date:** 2026-06-06
**Scope:** `/Users/nil-00/git/rootwarp/eth-utils/go` — an Ethereum validator deposit toolchain (`eth-deposit-gen`, `eth-deposit-tx`, and the `internal/` packages: bls, ssz, deposit, keystore, signer, tx, cli, network, output).
**Risk class:** SECURITY-CRITICAL. Mistakes here mean irreversible loss of 32+ ETH per validator on mainnet.

## Methodology

- **Finders (30 agents):** 9 package scopes × 3 dimensions (bugs / security / quality) = 27 scoped passes, plus a tooling sweep, a dependency audit, and a cross-cutting sweep.
- **Adversarial verification:** every finding was challenged by independent refuter agents. Critical/high findings went through a 3-lens panel (factual / reachability / impact) with majority vote; lower-severity findings got a single factual-lens verifier.
- **Completeness-critic round:** a follow-up pass hunted for gaps the finders missed (the `gap-*` and dependency follow-ups), each then re-verified.
- **Reproduction:** many findings were confirmed empirically by building the binaries and running them, by `-race` runs, by `govulncheck`/`gofmt`/`golangci-lint`, and by re-deriving SSZ/ABI vectors from first principles.
- This synthesis merges duplicate root-cause findings (frequently the same defect surfaced by 3–8 different scoped passes), applies the verifier panel's severity adjustments, and renumbers the result as `GO-NNN`.

Severity reflects the verifier-panel consensus, not the original finder label; where the panel adjusted severity it is noted in the finding.

---

## Executive summary

**Verdict:** The codebase is well-structured, idiomatic Go with genuinely good safety engineering in many places — dependency-injected, testable CLIs; verify-before-write BLS self-verification in the generator; a single source of truth for network constants (all chain IDs / fork versions / deposit-contract addresses verified correct); atomic 0600 writes for signed artifacts; sentinel-error exit-code contracts; secret-leak regression tests; and SSZ/ABI primitives that were re-derived from the consensus spec and found correct. The core cryptography is sound.

**However**, the trust boundaries between the two CLIs are not enforced, and the toolchain ships with a default that burns funds. The two release-blocking issues are:

1. **GO-001 (critical):** `eth-deposit-gen` hard-codes all-zero `0x00` withdrawal credentials into every deposit. Such a credential is cryptographically unspendable; a mainnet deposit made from this output permanently locks 32 ETH per validator. No validation layer rejects it, no runtime warning fires, and the committed mainnet golden fixture shows it shipping today.
2. **GO-002 (critical):** `eth-deposit-tx` never binds the deposit data's `network_name`/`fork_version` to the `--network` build target, so testnet deposit data builds a valid mainnet transaction whose BLS signature is over the wrong domain — accepted on-chain, rejected by the consensus layer, 32 ETH irreversibly lost. The default network is `hoodi`, so the inverse mistake is one forgotten flag away.

A cluster of high/medium findings concentrate at the same trust boundaries: the `sign` path signs an unvalidated destination address (geth's lenient `HexToAddress` silently mangles typos), the `send` confirmation prompt and chain-ID guard validate JSON metadata while broadcasting an unverified `rawRLP` blob, the advertised `--rpc-url` hybrid mode is dead code (nonce silently defaults to 0), and a reverted on-chain deposit exits 0.

**Counts (71 findings after merging):**

| Severity | Count |
|---|---|
| Critical | 2 |
| High | 2 |
| Medium | 10 |
| Low | 46 |
| Info | 11 |

**By category (primary):** security 28, bug 22, quality 21.

---

## Findings table

| ID | Sev | Cat | Location | Title |
|---|---|---|---|---|
| GO-001 | Critical | security | cmd/eth-deposit-gen/main.go:66-70,355 | All-zero withdrawal credentials make every generated deposit permanently unwithdrawable |
| GO-002 | Critical | security | cmd/eth-deposit-tx/main.go:210-254; internal/deposit/json.go:137-154; internal/tx/validation.go:20-58 | No network/fork-version binding: testnet deposit data builds a mainnet transaction |
| GO-003 | High | security | internal/signer/parse.go:70; cmd/eth-deposit-tx/sign.go:146-153 | `sign` signs an unvalidated `to` address; `common.HexToAddress` silently mangles it |
| GO-004 | High | security | cmd/eth-deposit-tx/send.go:176-229 | `send` confirms/checks JSON metadata but broadcasts the unverified `rawRLP` payload |
| GO-005 | Medium | bug | cmd/eth-deposit-tx/main.go:227-247; internal/tx/interface.go:52 | `--rpc-url` is silently ignored; nonce defaults to 0 and fees to 20 gwei |
| GO-006 | Medium | security | internal/bls/bls.go:88-90 | `NewSigner` propagates a herumi error that embeds the full BLS secret key in hex |
| GO-007 | Medium | security | internal/keystore/passphrase.go:45-62 | Concurrent TTY passphrase prompts race on `/dev/tty` and can echo the passphrase |
| GO-008 | Medium | bug | cmd/eth-deposit-gen/main.go:298-368; internal/keystore/keystore.go:100 | Worker cancellation ineffective; loader ignores ctx — SIGINT keeps decrypting/prompting |
| GO-009 | Medium | bug | internal/cli/cli.go:263-314 | Duplicate pubkeys accepted → duplicate deposit entries |
| GO-010 | Medium | security | cmd/eth-deposit-tx/send.go:247-269 | A reverted on-chain deposit (`status=0`) exits with code 0 (success) |
| GO-011 | Medium | bug | internal/output/output.go:118-126,158 | FSWriter same-second filename collision silently overwrites prior deposit data; predictable tmp, no O_EXCL |
| GO-012 | Medium | security | internal/deposit/json.go:130-154; internal/tx/validation.go:14-39 | Deposit roots never recomputed and BLS signature never verified on the read path; pubkey on-curve check skipped |
| GO-013 | Medium | security | cmd/eth-deposit-tx/send.go:121-124,211-225 | No mainnet acknowledgement gate in eth-deposit-tx; `--yes` bypasses the sole prompt |
| GO-014 | Medium | security | cmd/eth-deposit-tx/run.go:53-59; sign.go:48-54 | Suspected private-key value echoed verbatim in `--private-key-env` error and logged |
| GO-015 | Low | bug | cmd/eth-deposit-tx/main.go:76-79; exit.go:47 | Missing required flags exit 1 instead of the documented user-error code 2 |
| GO-016 | Low | quality | cmd/eth-deposit-tx/main.go:195-203; sign.go:170-173 | `build`/`sign` write non-atomically with inconsistent exit codes vs `run` |
| GO-017 | Low | security | internal/signer/local.go:40-50,100; sign.go:186-190 | Secret residue: env var never unset; LocalSigner/BLS intermediate key copies not zeroized; passphrase env inherited by child |
| GO-018 | Low | bug | cmd/eth-deposit-gen/main.go:148-153 | `runDepositCLIVerify` drops the exec error; SIGINT during verify misreported as exit 3 |
| GO-019 | Low | bug | internal/signer/ledger.go:65-81 | `NewLedgerSigner` discards the real Open/Status error and misreports it as `ErrNoDevice` |
| GO-020 | Low | bug | internal/signer/parse.go:32-53 | `parseUnsignedTx` accepts negative value/fee hex and ignores the declared `type` |
| GO-021 | Low | bug | internal/signer/local.go:74,100,144-152 | Data race between `LocalSigner.Sign` and `Close` can sign with a partially zeroized key |
| GO-022 | Low | bug | internal/signer/local.go:63-67 | `NewLocalSignerFromEnv` discards the specific (key-material-free) validation error |
| GO-023 | Low | security | internal/signer/ledger.go:201-225 | `LedgerSigner.Sign` does not cross-check the recovered sender / returned payload |
| GO-024 | Low | bug | internal/signer/ledger.go:140-144,176-187 | After ctx cancellation, `LedgerSigner.Close` blocks until the device responds |
| GO-025 | Low | bug | internal/keystore/keystore.go:139-142 | All keystorev4 `Decrypt` failures mapped to `ErrWrongPassphrase` (wrong exit class) |
| GO-026 | Low | bug | internal/keystore/scandir.go:26,80; keystore.go:144 | `ToLower(TrimPrefix(…,"0x"))` ordering leaves an uppercase `0X` prefix; logic duplicated 3× |
| GO-027 | Low | bug | internal/keystore/scandir.go:80-81 | ScanDir silently overwrites duplicate pubkeys; last file wins, no log |
| GO-028 | Low | bug | internal/keystore/scandir.go:65,71,76 | ScanDir skip diagnostics go to the never-configured global slog logger (invisible even with `--verbose`) |
| GO-029 | Low | bug | internal/keystore/keystore.go:42,146-149 | `Load` does not enforce the documented 32-byte length of the decrypted secret |
| GO-030 | Low | security | internal/keystore/scandir.go:54-66 | ScanDir reads entries with no size cap / no regular-file check; a FIFO named `*.json` hangs the scan |
| GO-031 | Low | bug | internal/tx/validation.go:63-77; builder.go:104-122 | No validation that `maxPriorityFeePerGas <= maxFeePerGas` → unbroadcastable signed tx |
| GO-032 | Low | bug | internal/tx/rpc_client.go:120-126; builder.go:116-121 | Nil base fee (non-EIP-1559 block) panics fee computation; `BlockBaseFee` over-fetches and doc is wrong |
| GO-033 | Low | security | internal/tx/builder.go:92-102 | RPC chain-ID guard silently skipped on RPC error or chain-ID 0; documented "warn" never emitted |
| GO-034 | Low | bug | internal/tx/builder.go:139-161 | RPC gas estimation: `estimate*6/5` uint64 overflow + silent zero-address fallback |
| GO-035 | Low | bug | internal/tx/rpc_client.go:78-86; send.go:283-293 | Receipt polling: `"not found"` substring match + aborts on first transient error + undocumented exit codes |
| GO-036 | Low | security | internal/bls/bls.go:87-92 | `NewSigner` accepts an all-zero BLS secret, producing the infinity pubkey/signature |
| GO-037 | Low | security | internal/bls/bls.go:154-165 | `ValidatePubkeyBytes` accepts the point-at-infinity, deviating from KeyValidate |
| GO-038 | Low | quality | internal/network/network.go:57-62 | `DomainDeposit` / `ZeroGenesisValidatorsRoot` are exported mutable package vars |
| GO-039 | Low | quality | internal/cli/cli.go:78-81 | `NewApp` doc comment states exit code 1 for validation errors; code returns 2 |
| GO-040 | Low | bug | internal/cli/cli.go:180-247 | Unexpected positional arguments silently ignored (space-separated `--pubkeys` drops a key) |
| GO-041 | Low | bug | cmd/eth-deposit-tx/send.go:154-155,211-219 | `send --input -` without `--yes` always aborts: confirmation reads already-exhausted stdin |
| GO-042 | Low | bug | cmd/eth-deposit-tx/send.go:176-179 | Chain-ID fetch error flattened with `%v`; SIGINT during fetch reports exit 5 instead of 4 |
| GO-043 | Low | quality | cmd/eth-deposit-gen/main_test.go:641-645 | Secret-leak test comment claims a copy is passed but hands the sentinel slice itself |
| GO-044 | Low | quality | (module-wide); internal/signer/, internal/tx/, cmd/ | Nine files not gofmt-formatted; `make lint` has no formatting gate |
| GO-045 | Low | quality | internal/keystore/keystore.go:53-57,152-159 | Two inconsistent zeroizers; `runtime.KeepAlive` comment overstates its guarantee |
| GO-046 | Low | quality | internal/keystore/scandir.go:48-51; cmd/eth-deposit-gen/main.go:249-275,405-409; internal/deposit/deposit.go:115-144 | Bare/unwrapped error returns contrary to the project's own `%w` convention |
| GO-047 | Low | quality | internal/network/network.go:64-154 | `mustParseAddr` runs per-`Lookup` (not compile-time); network registry duplicated across 4 sites | (FIXED M2.3-1: single paramsByName registry at init; Lookup*/ParseFlag derive; panic test added) |
| GO-048 | Low | quality | internal/ssz/ssz_test.go:333-448; ssz_fuzz_test.go:50-91 | SSZ "reference implementation" oracle is dead code and not independent; fuzz asserts tautologies |
| GO-049 | Low | security | internal/tx/rpc_client.go:48-53 | RPC URL (often containing an API key) embedded verbatim in the `ErrRPCDial` error |
| GO-050 | Low | quality | internal/signer/ledger_nocgo.go:1-9 | `ledger_nocgo.go` build-tag path can never compile (signer transitively needs CGO via herumi) | (FIXED M2.3-2 / ADR-008: stub + Err deleted per "delete the stub" decision)
| GO-051 | Low | bug | cmd/eth-deposit-tx/sign.go:184-201 | `signUnsignedTx` switch has no default case: an invalid signer value panics on a nil interface |
| GO-052 | Low | bug | docs/USER-GUIDE.md:217 | Guide shows a withdrawable `0x01` credential the tool can never produce (it always emits all-zero `0x00`) |
| GO-053 | Low | security | scripts/e2e-testnet.sh:80,135 | E2E script echoes the API-key RPC URL to terminal and can persist it to a repo-tracked artifact |
| GO-054 | Low | bug | scripts/e2e-testnet.sh:101-107 | Documented `run` invocation omits `--rpc-url`, so nonce silently defaults to 0 |
| GO-055 | Low | security | go.mod:6 | go-ethereum v1.14.12 is ~18 months stale (5 advisories, none in linked paths) and predates Ledger current-firmware fixes |
| GO-056 | Low | security | go.mod:3 | No `toolchain` directive: release binaries build with the unpatched go1.26.0 stdlib (TLS/x509 reachable via RPC) |
| GO-057 | Low | quality | Makefile:30-32 | No vulnerability scanning (govulncheck/OSV) in lint or CI |
| GO-058 | Low | quality | cmd/eth-deposit-gen/main.go:201,203,448; internal/keystore/passphrase.go:50-56 | Unchecked error returns on user-facing writes (errcheck) |
| GO-059 | Low | quality | cmd/eth-deposit-gen/main_test.go:1116-1235 | The only external-authority cross-check (`--verify-with-deposit-cli`) is stubbed in every test |
| GO-060 | Low | quality | scripts/e2e-testnet.sh:163 | Script points operator at a deleted validation-template path |
| GO-061 | Info | quality | internal/ssz/ssz.go:162-175 | `merkleize` silently treats `limit < len(chunks)` as a floor, deviating from SSZ spec semantics |
| GO-062 | Info | quality | internal/bls/bls.go:12,71,89,94-96,143-147 | bls/ssz hygiene: stale `msg` doc param, inconsistent error casing, double-`bls:` wrapping, same-name herumi alias, historical ssz package note |
| GO-063 | Info | quality | internal/cli/cli.go:163,220 | `runtime.NumCPU()*4` parallelism cap computed in two places with an unnamed multiplier |
| GO-064 | Info | quality | internal/keystore/gen_fixtures_test.go:1-23 | Documented fixture-regeneration command silently does nothing (gated on `GENERATE_FIXTURES`) |
| GO-065 | Info | quality | internal/keystore/keystore_test.go:19; scandir_test.go:66 | Test fixtures use invalid-length pubkeys (127-char odd-length, 92-char) vs the 96-char BLS format |
| GO-066 | Info | quality | internal/deposit/json_test.go:204-214 | `TestEntriesFromJSON_GoldenFile` asserts against a hand-copied inline literal, not the actual golden fixture |
| GO-067 | Info | quality | internal/signer/ledger_internal_test.go:647-673; signer_test.go:34-65 | Stale APDU-code test comment; `signer_test.go` tests assert only the test double's hardcoded values |
| GO-068 | Info | quality | docs/USER-GUIDE.md:744,763 | Troubleshooting rows attribute errors to the wrong layer and quote a chain-ID string `send` never emits |
| GO-069 | Info | quality | scripts/e2e-testnet.sh:14-15,60 | `DEPOSIT_DATA_FILE` default contradicts its header comment and is mislabeled |
| GO-070 | Info | quality | internal/tx/abi_test.go:24-160 | `PackDeposit` byte layout only self-round-trip tested, never checked against a canonical ABI encoder |
| GO-071 | Info | security | go.mod:10 | golang.org/x/crypto v0.22.0 is two years stale (16 advisories, none in linked paths) |

---

## Detailed findings

### GO-001 — All-zero withdrawal credentials make every generated deposit permanently unwithdrawable
**Severity:** Critical (security/bug). **Sources:** gen:bugs-0, gen:security-0, gen:quality-0, deposit-out:bugs-1, deposit-out:security-0, cli-net:security-0, crosscut-0.
**Location:** `cmd/eth-deposit-gen/main.go:66-70,355`; defense-in-depth gaps at `internal/deposit/json.go:137-154` and `internal/tx/validation.go:43-45`.

`defaultWithdrawalCreds()` returns 32 zero bytes (a `0x00` BLS-withdrawal prefix followed by 31 zero bytes) and is hard-wired into every generated entry. There is no `--withdrawal-address` flag anywhere — this is the only credential the tool can produce. Per the consensus spec, a `0x00` credential must be `0x00 || sha256(withdrawal_bls_pubkey)[1:]`; an all-zero suffix corresponds to no obtainable BLS key (finding a sha256 preimage with a 31-zero-byte tail is computationally infeasible). A validator funded with this data can never sign a `BLSToExecutionChange` and can never withdraw — 32 ETH per validator is irreversibly locked.

The BLS signature is computed *over* these credentials, so verify-before-write passes; nothing downstream blocks it: `deposit.Entry.Validate` checks the other byte fields for all-zero but never the withdrawal credentials, and `internal/tx/validation.go:43-45` explicitly accepts prefix `0x00` with "no further format constraint". The committed mainnet golden fixture (`testdata/mainnet/deposit_data-expected.json`) contains 64 zero hex chars, confirming this ships today. The `--i-understand-this-is-mainnet` gate covers the network, not the credentials. Only a `TODO(P1)` comment acknowledges the gap.

```go
func defaultWithdrawalCreds() [32]byte {
	var wc [32]byte
	wc[0] = 0x00 // BLS withdrawal type prefix; rest is zero
	return wc
}
// ...
WithdrawalCredentials: defaultWithdrawalCreds(),
```

**Recommendation:** Do not ship a placeholder credential into real deposit data. Require a `--withdrawal-address` (0x01/0x02) or a withdrawal BLS pubkey (derive `0x00 || sha256(pk)[1:]`) and refuse to generate without it. As defense-in-depth, reject `0x00`-prefix credentials with an all-zero body in both `deposit.Entry.Validate` and `internal/tx.Validate`. Block any release that can emit this value.
**Verification:** Confirmed end-to-end by 3/3 panel across multiple scopes; reproduced via the shipped golden fixtures.

### GO-002 — No network/fork-version binding: testnet deposit data builds a mainnet transaction
**Severity:** Critical (security). **Sources:** tx-core:bugs-0, tx-core:security-0, deposit-out:bugs-0, deposit-out:security-1, deposit-out:quality-0, tx-lib:security-0, cli-net:security-1, crosscut-1.
**Location:** `cmd/eth-deposit-tx/main.go:210-254`; `internal/deposit/json.go:137-154`; `internal/tx/validation.go:20-58`.

`deposit.Entry` carries `network_name` and `fork_version` from the deposit-data JSON, and `buildUnsignedTx` has `cfg.NetworkParams` (with `GenesisForkVersion`, `Name`, `ChainID`) — but never compares them. `Entry.Validate` only checks that `network_name` is *some* recognised network (it discards the looked-up `Params` and never checks `ForkVersion`); `internal/tx.Validate` ignores both fields entirely (grep finds zero non-test references in `cmd/eth-deposit-tx` and `internal/tx`).

Reproduced live: `eth-deposit-tx build --network mainnet --input-file <holesky fixture>` exits 0 and emits a `chainId=1` transaction to the mainnet deposit contract. The deposit contract does not verify BLS signatures, so the tx is accepted on-chain; but the consensus layer rejects an initial deposit whose signature was computed over the wrong (holesky) fork domain — 32 ETH permanently unrecoverable. The default network is `hoodi`, and hoodi shares mainnet's deposit-contract address, so the `send` prompt shows an identical `To` for both and gives no visual cue. The BLS signature is never re-verified on the tx path.

```go
entry := entries[cfg.Index]
if err := entry.Validate(); err != nil { /* only checks name is recognised */ }
// no comparison of entry.NetworkName / entry.ForkVersion vs cfg.NetworkParams
```

**Recommendation:** In `Entry.Validate` (capture the `Params`) require `e.ForkVersion == params.GenesisForkVersion`; add `ValidateForNetwork(target)` (or compare in `buildUnsignedTx`) so `entry.NetworkName`/`ForkVersion` must equal the `--network` selection — hard-fail with exit 2 otherwise. Ideally also recompute the SSZ roots and BLS-verify the signature against the network's deposit domain before emitting any tx (mirroring the generator's verify-before-write). Reconsider the implicit `hoodi` default. Treat as a release blocker for mainnet.
**Verification:** Confirmed by code reading and live execution; carried critical/high panel votes across 8 scopes (two scopes filed critical with 3/3 unchanged; others filed high).

### GO-003 — `sign` signs an unvalidated `to` address; `common.HexToAddress` silently mangles it
**Severity:** High (security/bug). **Sources:** tx-ops:bugs-1, tx-ops:security-1, signer:bugs-0, signer:security-0, signer:quality-0, crosscut-3.
**Location:** `internal/signer/parse.go:70`; `cmd/eth-deposit-tx/sign.go:146-153`.

`parseUnsignedTx` strictly validates `Value`/`MaxFeePerGas`/`MaxPriorityFeePerGas`/`Data` hex but pipes the destination through `common.HexToAddress(unsigned.To)`, which never fails: in geth v1.14.12, `Hex2Bytes` discards `hex.DecodeString` errors and `SetBytes` left-pads/truncates to 20 bytes. Reproduced through the real `LocalSigner.Sign`: an empty `To` signs to the zero address (32 ETH burn); a 41-char mainnet deposit-contract address with one char dropped signs to a *completely different* address (`0x0000000219ab540356CBb839CBe05303d7705fa0`); trailing invalid hex truncates silently. The `sign` subcommand does no `To` validation and the local signer shows no on-device display; `send`'s prompt displays `signed.Unsigned.To` (the original JSON string), not the address actually embedded in `rawRLP`, so even a careful operator cannot detect the divergence. The air-gapped workflow explicitly hand-carries (and per the docs, hand-edits) this JSON.

```go
return &parsedTx{ chainID, value, maxFee, tip, to: common.HexToAddress(unsigned.To), data }, nil
```

**Recommendation:** Require `common.IsHexAddress(unsigned.To)` plus an explicit length check (reject otherwise with a sentinel error). Cross-check `To` against `network.LookupByChainID(unsigned.ChainID).DepositContractAddress` and require an explicit override flag for non-standard recipients; print a signing summary for the local signer.
**Verification:** Confirmed 3/3 in five scopes; coercions reproduced against the pinned geth version.

### GO-004 — `send` confirms/checks JSON metadata but broadcasts the unverified `rawRLP` payload
**Severity:** High (security). **Sources:** tx-ops:bugs-0, tx-ops:security-0, tx-ops:bugs-4, tx-ops:security-3, tx-ops:quality-0, tx-lib:security-3, crosscut-4, gap-2-1.
**Location:** `cmd/eth-deposit-tx/send.go:176-229`, `196-197`, `302-308`.

The entire send-side safety apparatus — the chain-ID cross-check (`rpcChainID != signed.Unsigned.ChainID`), the "You are about to BROADCAST" summary (Network/From/To/Value/Nonce/Hash), and the type-the-network-name confirmation — is computed from `signed.Unsigned`/`signed.From`/`signed.Hash` (free-form JSON metadata). The bytes actually broadcast are the independent `signed.RawRLP` field, which is never decoded, hash-checked, or sender-recovered against that metadata. A tampered, stale, or mixed-up `signed.json` (the artifact crosses an air-gap by design) shows the operator one transaction and broadcasts another. The `To` is labelled `To (deposit)` without comparing it to `netParams.DepositContractAddress` (already in scope). Separately, `hexToBigInt` returns its receiver even when `SetString` fails (math/big leaves it undefined), so a malformed `Value`/`MaxFeePerGas` renders an arbitrary/0.000000 ETH amount in the prompt instead of aborting. The decode capability already exists — `rpc_client.go` `SendRawTransaction` calls `UnmarshalBinary` on the same bytes, but only after the prompt.

```go
if rpcChainID != signed.Unsigned.ChainID { ... }
fmt.Fprintf(c.App.ErrWriter, ">   To (deposit):   %s\n", signed.Unsigned.To)
txHash, err := broadcaster.SendRawTransaction(c.Context, signed.RawRLP)
```

**Recommendation:** Before the prompt, decode `signed.RawRLP` (`types.Transaction.UnmarshalBinary`); derive chainID/to/value/nonce/hash/recovered-sender from the decoded tx; abort if any differ from the JSON metadata; render the prompt and run the chain-ID guard from the decoded values; compare `To` against the deposit contract. Treat a failed hex parse of Value/MaxFee as a fatal exit-2 error.
**Verification:** Confirmed; panel split medium/high (majority retained high on the strongest source).

### GO-005 — `--rpc-url` is silently ignored; nonce defaults to 0 and fees to 20 gwei
**Severity:** Medium (bug) — *adjusted down from High by 3/3 panel.* **Sources:** tx-core:bugs-1, tx-core:bugs-2, tx-core:security-1, tx-core:security-2, tx-core:quality-0, tx-core:quality-1, tx-lib:security-1, tx-lib:quality-0, crosscut-2.
**Location:** `cmd/eth-deposit-tx/main.go:227-247`; `internal/tx/interface.go:52`; `internal/tx/builder.go:78`.

`buildUnsignedTx` copies `cfg.RPCURL` into `BuildConfig.RPCURL` (documented as "reserved for Issue 2.5 … unused here") but never constructs an `EthRPC` and never sets `BuildConfig.RPC` — the only `NewEthClient` call site is `send`. So `resolveFields` always takes the static branch, making `resolveRPC` (chain-ID verification, `SuggestGasTipCap`, `BlockBaseFee`, `PendingNonceAt`, `EstimateGas`) dead code from build/run. Worse, `buildUnsignedTx` unconditionally pre-fills every missing field — `MaxFeePerGas`=20 gwei (whose own comment says "may be too low for mainnet"), tip=1 gwei, gas=250000, and `Nonce`→`&0` — so the deliberately designed `ErrMissingNonceStatic`/`ErrMissingFeeStatic` sentinels are unreachable from the CLI, contradicting the help text ("omit to fetch from RPC", "hybrid mode when --rpc-url is provided"). Reproduced: `build --rpc-url http://127.0.0.1:1` (nothing listening) exits 0 with nonce 0 and the 20-gwei default, no warning. A nonce-0 tx is rejected (nonce-too-low) for any used account or can replace a pending nonce-0 tx.

```go
buildCfg := internaltx.BuildConfig{ ..., RPCURL: cfg.RPCURL, ... } // RPC never set
if buildCfg.Nonce == nil { var z uint64; buildCfg.Nonce = &z }
```

**Recommendation:** Either wire `NewEthClient` into `BuildConfig.RPC` when `--rpc-url` is set (and stop pre-filling defaults so `resolveRPC`/`ErrChainIDMismatch` run), or reject `--rpc-url` on build/run and require `--nonce` explicitly. Never silently substitute nonce 0; refuse the 20-gwei default on mainnet at minimum.
**Verification:** Confirmed in code and empirically; panel consistently adjusted High→Medium.

### GO-006 — `NewSigner` propagates a herumi error that embeds the full BLS secret key in hex
**Severity:** Medium (security) — *panel split (one Medium, downgrades to Low) reflecting limited reachability.* **Sources:** crypto:security-0, crypto:quality-0.
**Location:** `internal/bls/bls.go:88-90`.

herumi v1.37.0's `SecretKey.Deserialize` formats the entire input buffer into its error string (`fmt.Errorf("err blsSecretKeyDeserialize %x", buf)`); `NewSigner` wraps it verbatim with `%w`, so a decrypted keystore secret `>=` the BLS12-381 curve order `r` causes the full 32-byte secret to be hex-encoded into the returned error. `cmd/eth-deposit-gen/main.go:340-344` logs that error via `slog.Debug` and pushes it into `workerResult`, reaching stderr. A uniformly random 32-byte secret from a non-EIP-2333 tool exceeds `r` with ~55% probability. Reproduced: `NewSigner(0xff…ff)` returns `bls: Deserialize: err blsSecretKeyDeserialize ffff…ffff`. This defeats the package's otherwise careful zeroization discipline (the secret survives as a string in the error value). Reachability is limited because a keystore from the official `staking-deposit-cli` always has an in-range scalar and the leak only surfaces in debug/`--json-logs` output.

```go
if err := s.sk.Deserialize(localCopy); err != nil {
	return nil, fmt.Errorf("bls: Deserialize: %w", err)
}
```

**Recommendation:** Never wrap herumi's secret-key deserialization error. Return a fixed sentinel carrying no key material: `errors.New("bls: secret key rejected (scalar out of range for BLS12-381)")`. Audit other call sites that pass secret material to third-party functions.
**Verification:** Mechanism reproduced empirically; panel agreed the leak is real but split on severity (impact-lens downgrades to Low given debug-only surfacing and out-of-range trigger).

### GO-007 — Concurrent TTY passphrase prompts race on `/dev/tty` and can echo the passphrase
**Severity:** Medium (security). **Sources:** gen:bugs-2, gen:security-1, gen:quality-2, keystore:bugs-0, keystore:security-0, keystore:quality-1.
**Location:** `internal/keystore/passphrase.go:45-62`; shared via `cmd/eth-deposit-gen/main.go:278,331`.

`termPromptSource.Read` has no synchronization and opens `/dev/tty` + `term.ReadPassword` per call. `runWithDeps` creates one `PassphraseSource` (`pickPassphraseSource`) and hands it to every worker; with `--parallel >= 2`, `>= 2` pubkeys, and no `--passphrase-env`, multiple goroutines call `ReadPassword` on the same terminal concurrently. `x/term` v0.43.0 `readPassword` saves termios, clears `ECHO`, reads, then restores the snapshot: worker A's restore re-enables echo while worker B is still typing → the keystore passphrase is echoed in cleartext (scrollback, `tee`/`script` logs, screen recordings). Concurrent canonical-mode reads also misdeliver typed lines between workers, and `cli.go` ties no relationship between `--parallel` and the passphrase source.

**Recommendation:** Make `termPromptSource` concurrency-safe (mutex) and prompt once before the worker pool, caching the passphrase (return a fresh copy per call since the loader zeroizes it; zeroize the cache at end of run). Alternatively reject `--parallel > 1` when the TTY source is selected. Document concurrency expectations on `PassphraseSource`.
**Verification:** Confirmed across 6 scopes; race mechanism verified against the pinned `x/term`.

### GO-008 — Worker cancellation ineffective; loader ignores ctx — SIGINT keeps decrypting/prompting
**Severity:** Medium (bug). **Sources:** gen:bugs-3, gen:security-2, gen:quality-1, keystore:bugs-5, keystore:security-2, keystore:quality-6.
**Location:** `cmd/eth-deposit-gen/main.go:298-368,499`; `internal/keystore/keystore.go:100`.

The worker loop `for i := range work` never checks `workerCtx.Err()` between items, and `loader.Load(_ context.Context, …)` discards its context entirely — no `ctx.Err()` check before the file read, the `pw.Read()` prompt, or scrypt/PBKDF2 decryption. The only cancellation point is `gen.Generate`'s per-iteration check, which runs *after* the expensive work. Consequence: after SIGINT or a sibling worker's error (`workerCancel()`), every remaining queued keystore is still fully scrypt-decrypted, and in TTY mode the operator is re-prompted for each remaining pubkey in a run that is already doomed. `signal.NotifyContext(ctx, SIGINT)` keeps SIGINT registered for the process lifetime (`stop()` only runs at `main` return, bypassed by `os.Exit`), so a second/third Ctrl+C is swallowed and cannot kill the blocked prompt — the operator must SIGTERM/SIGKILL from another terminal. SIGTERM is not handled at all, bypassing the exit-code-4 abort path.

**Recommendation:** Check `workerCtx.Err()` at the top of each loop iteration (emit a `context.Canceled` result so the collector still gets one result per item). Make `loader.Load` honour ctx (check before `pw.Read()` and before `Decrypt`; run the prompt/decrypt against `ctx.Done()`). Register SIGTERM and call `stop()` once ctx is cancelled so a second Ctrl+C force-terminates.
**Verification:** Confirmed; every link verified in code.

### GO-009 — Duplicate pubkeys accepted → duplicate deposit entries
**Severity:** Medium (bug) — *impact mechanism partly corrected by panel.* **Sources:** gen:bugs-4, gen:security-3, cli-net:bugs-0, cli-net:security-2, cli-net:quality-0.
**Location:** `internal/cli/cli.go:263-314`; `cmd/eth-deposit-gen/main.go:303-307`.

`parsePubkeys` validates prefix uniformity, hex length, and G1-point validity but never checks for duplicates, and nothing downstream deduplicates. Passing the same pubkey twice (a realistic copy-paste error in a long comma-separated list) yields two byte-identical 32-ETH entries for one validator; the banner only shows first/last pubkey and count, so a duplicate in the middle is invisible. The original "auto double-broadcast" framing was corrected by the panel: `eth-deposit-tx` builds one tx per `--index`, so it does not automatically broadcast both — the operator would have to send each — but a duplicated entry combined with the all-zero credentials (GO-001) strands the excess, and the official `staking-deposit-cli` cannot produce duplicates by construction.

**Recommendation:** Track seen pubkeys in a `map[[48]byte]struct{}` inside `parsePubkeys` and reject duplicates with an error naming the entry and indices (exit 2). Rejecting (not silently deduping) matches the tool's verify-before-write philosophy.
**Verification:** Confirmed; one verifier adjusted to Low citing the corrected impact path.

### GO-010 — A reverted on-chain deposit (`status=0`) exits with code 0 (success)
**Severity:** Medium (bug). **Sources:** tx-ops:bugs-2, tx-ops:security-2.
**Location:** `cmd/eth-deposit-tx/send.go:247-269`.

With `--wait-for-receipt`, when the receipt arrives with `Status == 0`, `sendAction` prints `status=REVERTED` but falls through to `return nil`, so the process exits 0 — defined by the CLI contract as Success. A deposit the contract rejected (gas spent, no deposit made) is indistinguishable from success for automation checking exit codes; in the `--yes --wait-for-receipt --receipt-output` CI flow this command is explicitly designed for, the operator's pipeline proceeds believing the deposit landed. Inversely, a mere receipt timeout after a successful broadcast returns a plain error → exit 1, so "tx fine but slow" fails while "tx reverted" succeeds.

**Recommendation:** Return a non-nil error (mapped to a deliberate code, e.g. 5) when `rec.Status == 0`, after writing the receipt file. Add a distinct documented code for "broadcast succeeded but receipt not yet available" so retry automation cannot double-deposit.
**Verification:** Confirmed 1/1 factual; reachable with a real receipt.

### GO-011 — FSWriter same-second filename collision silently overwrites prior deposit data
**Severity:** Medium (bug/security). **Sources:** deposit-out:bugs-3, deposit-out:security-3, deposit-out:quality-3.
**Location:** `internal/output/output.go:118-126,158`.

Both the temp and final filenames derive solely from `now.Unix()` (second granularity). Two `Write` calls in the same second into the same directory (a shell loop per keystore, or parallel invocations): (a) open the identical `tmpPath` with `O_TRUNC`, so concurrent writers truncate each other and one writer's deferred `os.Remove(tmpPath)` can delete the other's in-flight file; (b) `os.Rename` silently replaces an existing `deposit_data-<ts>.json`, destroying previously generated (possibly already-funded) deposit data with no error. The predictable tmp name is also opened without `O_EXCL`/`O_NOFOLLOW`, so in an attacker-writable directory a pre-placed symlink is followed (lower-severity, since deposit data is public). The parent directory is never fsynced after rename.

**Recommendation:** Use `os.CreateTemp(dir, ".deposit_data-*.json.tmp")` for a unique `O_EXCL` temp file; refuse to clobber an existing final path (`O_EXCL`/`Lstat` check) and return an explicit error; fsync the directory after rename.
**Verification:** Confirmed; the silent-overwrite data-loss path drives the Medium rating, the symlink TOCTOU is the Low aspect.

### GO-012 — Deposit roots never recomputed and BLS signature never verified on the read path
**Severity:** Medium (security). **Sources:** deposit-out:bugs-2, deposit-out:security-2, tx-lib:security-8.
**Location:** `internal/deposit/json.go:130-154`; `internal/tx/validation.go:14-39`.

`Entry` carries every input needed to recompute both SSZ roots (`internal/ssz` already implements `DepositMessage.HashTreeRoot`/`DepositData.HashTreeRoot`), yet `Validate` only checks `DepositDataRoot` for all-zero, never recomputes either root, and never checks `DepositMessageRoot` at all. `internal/tx.Validate` also deliberately skips the BLS pubkey on-curve check ("enabling it requires all test fixtures to carry real G1 points") and never recomputes the root. So a corrupted JSON is caught only by the deposit contract's on-chain `require()` (reverted tx, wasted gas, late failure in the air-gap flow), and a consistently-tampered file (e.g. withdrawal credentials swapped and roots recomputed by an attacker who can write the JSON between machines) passes every local check and broadcasts a deposit whose BLS signature no longer covers the message — irreversible loss with no local detection.

**Recommendation:** In `Entry.Validate` (or a `VerifyIntegrity` method called before building a tx) recompute both SSZ roots from the entry fields and require equality; verify the BLS signature over the network's deposit domain (the `bls`/`ssz` packages are already in-module). At minimum add the missing all-zero check for `DepositMessageRoot` and enable `bls.ValidatePubkeyBytes` (the golden fixtures already carry real G1 points).
**Verification:** Confirmed; no compensating check exists anywhere in the tx chain.

### GO-013 — No mainnet acknowledgement gate in eth-deposit-tx; `--yes` bypasses the sole prompt
**Severity:** Medium (security). **Sources:** crosscut-5, tx-core:security-8, tx-ops:security-6.
**Location:** `cmd/eth-deposit-tx/send.go:121-124,211-225`; `run.go:224-298`.

`eth-deposit-gen` enforces a mainnet double-gate (`--i-understand-this-is-mainnet` at the CLI layer plus a defense-in-depth re-check in `runWithDeps`), but `eth-deposit-tx` — the tool that actually spends 32 ETH — has no mainnet-specific safeguard. `build`/`sign`/`run` accept `--network mainnet` with no acknowledgement; `run --network mainnet --signer local` signs a mainnet deposit silently with an env-var key despite the help calling the local signer "FOR DEVELOPMENT ONLY". The only interactive defense is `send`'s type-the-network-name prompt, which the single `--yes` boolean disables for every network. An automation script written for a testnet (`send --yes`) later pointed at a mainnet RPC broadcasts with zero confirmation. This is documented behavior, but the safety posture is inconsistent across the two halves of the pipeline.

**Recommendation:** Require an explicit acknowledgement for mainnet that `--yes` does NOT imply (e.g. `--confirm-network=mainnet` whose value must match the RPC-derived network), or refuse `--yes` on mainnet. Emit a warning when `--signer local` is combined with `--network mainnet` in run/sign.
**Verification:** Confirmed; the cross-cutting framing (Medium) was retained by the panel.

### GO-014 — Suspected private-key value echoed verbatim in `--private-key-env` error and logged
**Severity:** Medium (security). **Sources:** tx-core:security-3.
**Location:** `cmd/eth-deposit-tx/run.go:53-59`; `sign.go:48-54`.

`LoadRunConfig`/`LoadSignConfig` validate `--private-key-env` against a POSIX-name regex specifically to catch passing the key *value* instead of a variable *name* — then embed the offending value in the error via `%q`, which `main.go` logs with `slog.Error` to stderr. Reproduced: `run … --private-key-env 0xabc123def456` prints the value back. If a real 64-hex key is passed (the exact mistake the message anticipates), the secret lands in stderr, CI logs, and shell redirects, compounding the argv exposure. Uppercase-hex variants pass the regex and are then echoed by `NewLocalSignerFromEnv`'s "not set or empty" error instead — both paths leak.

```go
if !posixEnvVarName.MatchString(envVar) {
	return nil, ucli.Exit(fmt.Sprintf("--private-key-env: %q is not a valid POSIX env var name ...", envVar), 2)
}
```

**Recommendation:** Do not echo the rejected value. Redact (first 4 chars + length) or omit it: "if you passed the key itself, rotate that key now". Apply to `sign.go` and the `NewLocalSignerFromEnv` error.
**Verification:** Confirmed 1/1; panel retained Medium.

---

### Low-severity findings

**GO-015 — Missing required flags exit 1 instead of documented 2.** `cmd/eth-deposit-tx/main.go:76-79`, `exit.go:47`. *(bug; tx-core:bugs-4, tx-core:security-5)* urfave/cli's `errRequiredFlags` is not an `ExitCoder`, so `ExitCodeFor` falls through to 1; `build --network holesky` (no `--input-file`) exits 1 while `--network badnet` exits 2. The most common user error misclassifies as "internal error". Fix: detect the required-flag error (or pre-validate in the Load* functions returning `ucli.Exit(…,2)`). *Confirmed at three levels including the urfave source.*

**GO-016 — `build`/`sign` write non-atomically with inconsistent exit codes vs `run`.** `cmd/eth-deposit-tx/main.go:195-203`, `sign.go:170-173`, `run.go:281-292`. *(quality; tx-core:bugs-5, tx-core:security-7, tx-core:quality-3, tx-core:quality-4, tx-ops:bugs-7, tx-ops:security-4, tx-ops:quality-3)* `run`/`send` use `atomicWriteFile` (temp+rename, explicit chmod) and the help promises it; `build` and `sign` use plain `os.WriteFile`, so an interrupted write can leave a truncated unsigned/signed JSON that the air-gap flow then transfers, and `0o600` is not re-applied to a pre-existing file. `build`'s write error is returned raw (exit 1 vs `run`'s exit 2); marshal failures map to exit 2 in build but exit 1 three lines later in run. Fix: use `atomicWriteFile` everywhere and unify exit-code mapping. *Confirmed.*

**GO-017 — Secret residue: env var never unset; intermediate key copies not zeroized; child inherits passphrase env.** `internal/signer/local.go:40-50,100`; `cmd/eth-deposit-tx/sign.go:186-190`; `cmd/eth-deposit-gen/main.go:148`. *(security; tx-core:security-4, tx-ops:security-5, signer:bugs-6, signer:security-2, crypto:bugs-5, crypto:security-3, gen:security-5, keystore:security-7, crosscut-6, crosscut-8)* `NewLocalSignerFromEnv` documents "callers should unsetenv it after construction" but no caller does; the secp256k1 key stays in the process environment for the process lifetime (readable via `/proc/<pid>/environ`, inherited by children). `LocalSigner.Close` clears only `s.key`, leaving the decode buffer `b`, the validation `ToECDSA` big.Int, and every per-`Sign` `ToECDSA` reconstruction un-wiped; the herumi `bls.SecretKey` inside the signer is never zeroized (no Destroy API). `runDepositCLIVerify` spawns the external deposit CLI with `cmd.Env` unset, so the keystore passphrase env var is inherited by the PATH-resolved child. Fix: `os.Unsetenv` after constructing signers; zeroize `b` and per-Sign copies; add a `Destroy`/`Zeroize` to the BLS signer; set a sanitized `cmd.Env` for the child. *Confirmed; all impacts require local memory/process disclosure, hence Low.*

**GO-018 — `runDepositCLIVerify` drops the exec error; SIGINT during verify misreported as exit 3.** `cmd/eth-deposit-gen/main.go:148-153`. *(bug; gen:bugs-5, gen:quality-3)* Only the combined output is wrapped into `ErrDepositCLIFailed`; the `CombinedOutput` error is discarded, so a killed/cancelled child yields the bare "deposit CLI verification failed: " and `errors.Is(err, context.Canceled)` is false → exit 3 (crypto) instead of the documented 4 (user abort). Fix: check `ctx.Err()` and wrap the exec error with `%w`. *Reproduced.*

**GO-019 — `NewLedgerSigner` discards the real Open/Status error and misreports `ErrNoDevice`.** `internal/signer/ledger.go:65-81`. *(bug; signer:bugs-2 [Medium→Low], signer:security-6, signer:quality-3)* These branches run only after a wallet was enumerated (`len(wallets)>0`), yet a present-but-failing device (udev/permission error, device held by Ledger Live, USB I/O) is reported as "no Ledger device found", sending the operator down the wrong path during a mainnet session; the cause is unrecoverable via `errors.Is`. The Open path also omits the `w.Close()` the Status path performs. Fix: wrap the cause alongside the sentinel (or a distinct `ErrDeviceUnavailable`). *Confirmed.*

**GO-020 — `parseUnsignedTx` accepts negative value/fee hex and ignores the declared `type`.** `internal/signer/parse.go:32-53`. *(bug; signer:bugs-3, signer:security-5, signer:bugs-9)* `big.Int.SetString` base-16 accepts a leading `-` (only a literal `0x` is stripped), so `"-1bc1…"` parses to a negative value; `LocalSigner.Sign` then signs a hash of a truncated RLP encoding before failing late with the confusing "MarshalBinary: rlp: cannot encode negative big.Int". `unsigned.Type` (documented as always `0x2`) is never checked — any type is signed as EIP-1559. Fix: reject `Sign() < 0` per field with field-specific errors; reject `Type != "0x2"`. *Reproduced.*

**GO-021 — Data race between `LocalSigner.Sign` and `Close`.** `internal/signer/local.go:74,100,144-152`. *(bug; signer:bugs-1 [Medium→Low], signer:security-3, signer:quality-5)* `Sign` checks `s.closed.Load()` once then reads `s.key` unsynchronized; `Close` zeroizes `s.key` guarded only by the atomic flag (which orders nothing about the bytes). `-race` confirms the race; a torn read yields a partially-zeroized but usually-valid scalar, so `SignTx` succeeds with the wrong key and the sender self-check (derived from the same corrupted key) cannot detect it. The CLI is single-threaded today, so this is latent. Fix: guard the key with a mutex held across Sign's use and Close's zeroize. *Confirmed via race detector.*

**GO-022 — `NewLocalSignerFromEnv` discards the specific validation error.** `internal/signer/local.go:63-67`. *(bug; signer:bugs-5, signer:quality-6)* The detailed error from `NewLocalSignerFromHex` (wrong length vs bad hex vs invalid scalar — all static, key-material-free) is replaced wholesale by a bare `ErrInvalidKey` wrap, costing the operator the only diagnostic (e.g. a stray trailing newline making it 65 chars). Fix: wrap `err` instead; `errors.Is(ErrInvalidKey)` still holds. *Confirmed.*

**GO-023 — `LedgerSigner.Sign` does not cross-check recovered sender / returned payload.** `internal/signer/ledger.go:201-225`. *(security; signer:bugs-8, signer:security-1 [Medium→Low], signer:quality-4)* Unlike `LocalSigner`, it recovers `from` but never compares it to `s.account.Address`, nor verifies the returned tx matches the request. Correctness rests entirely on geth's `usbwallet.SignTx` internal check — a hidden property of one implementation of the locally-defined `ledgerWallet` interface; the package's own mock test feeds back a divergent tx and Sign accepts it. Fix: add `if from != s.account.Address { … }` and field-compare the returned tx against the requested one. *Confirmed; geth v1.14.12 currently provides the guarantee.*

**GO-024 — After ctx cancellation, `LedgerSigner.Close` blocks until the device responds.** `internal/signer/ledger.go:140-144,176-187`. *(bug; signer:bugs-4)* On cancel, `Sign` returns immediately, leaving the goroutine inside `wallet.SignTx`; the deferred `Close` then blocks on geth's `stateLock` until the user presses a Ledger button or the device times out — so Ctrl+C does not actually terminate the sign step. If the user then approves, a valid signed tx is produced and silently discarded into the buffered channel. The doc comment understates this as only a goroutine leak. Fix: document that Close blocks and print a "reject on device to unblock" message after cancellation. *Confirmed against geth v1.14.12 source.*

**GO-025 — All keystorev4 `Decrypt` failures mapped to `ErrWrongPassphrase`.** `internal/keystore/keystore.go:139-142`. *(bug; keystore:bugs-1 [Medium→Low], keystore:security-1, keystore:quality-0)* wealdtech v1.4.1 returns many structural errors ("no checksum", "unsupported KDF", "invalid IV", …) besides the checksum-mismatch case, but all are wrapped as `ErrWrongPassphrase` → exit 3 (crypto) instead of `ErrKeystoreMalformed`/exit 2, misleading users into retyping a correct passphrase against a corrupt file. Fix: pre-validate the crypto map shape and map structural failures to `ErrKeystoreMalformed`; only the checksum mismatch is a wrong passphrase. *Reproduced.*

**GO-026 — `0X` prefix not stripped; normalization duplicated 3×.** `internal/keystore/scandir.go:26,80`; `keystore.go:144`. *(bug; keystore:bugs-2, keystore:quality-2)* `strings.ToLower(strings.TrimPrefix(s, "0x"))` applies a case-sensitive trim before lowering, so `"0XAABB…"` keeps the prefix and `Lookup` (fed bare hex) misses → misleading `ErrKeystoreNotFound` though the keystore exists. The expression is copy-pasted at three matching-critical sites. Fix: `TrimPrefix(ToLower(s), "0x")` via one shared `normalizePubkeyHex` helper; add a `0X` test. *Confirmed.*

**GO-027 — ScanDir silently overwrites duplicate pubkeys.** `internal/keystore/scandir.go:80-81`. *(bug; keystore:bugs-3, keystore:security-3, keystore:quality-5)* Two `.json` files declaring the same pubkey → the lexicographically last (os.ReadDir sorted) wins with no log (every other skip case logs). The selected file may decrypt to a different secret (surfacing as `ErrPubkeyMismatch`) or fail with a spurious `ErrWrongPassphrase`, with no hint two candidates existed. Fix: detect the collision and fail (or warn) naming both paths. *Confirmed.*

**GO-028 — ScanDir skip diagnostics go to the never-configured global slog logger.** `internal/keystore/scandir.go:65,71,76`. *(bug; keystore:bugs-4)* `ScanDir` uses package-level `slog.Debug`; the CLI builds its own injected logger and never calls `slog.SetDefault`, so the documented per-skipped-file debug records are discarded even with `--verbose`. A permission-denied/corrupt keystore vanishes with no trace and the run fails as a misleading `ErrKeystoreNotFound`. Fix: inject the logger into `ScanDir`, or treat read errors as warnings/hard errors. *Confirmed empirically.*

**GO-029 — `Load` does not enforce the documented 32-byte secret length.** `internal/keystore/keystore.go:42,146-149`. *(bug; keystore:bugs-6, keystore:security-6)* `Key.Secret` is documented "raw 32-byte BLS signing secret" but `Load` returns whatever wealdtech decrypts (length = ciphertext length; checksum covers ciphertext), so a non-32-byte payload decrypts cleanly. Caught today only by `bls.NewSigner` → fallback exit 1 instead of malformed-keystore exit 2; a future keystore consumer gets no protection. Fix: check `len(secret) == 32`, zeroize and return `ErrKeystoreMalformed` otherwise. *Confirmed.*

**GO-030 — ScanDir has no size cap / regular-file check; a FIFO named `*.json` hangs the scan.** `internal/keystore/scandir.go:54-66`. *(security; keystore:security-4)* `e.IsDir()` does not exclude FIFOs/device nodes/symlinks; `os.ReadFile` on a writer-less FIFO blocks forever, hanging `eth-deposit-gen` at step 3 before any prompt, unkillable via the SIGINT-handled context. Multi-GB `.json` files are read fully into memory; symlinked `.json` are followed outside the dir. Requires a hostile/accidental entry in a shared keystore dir. Fix: `e.Type().IsRegular()` check and an `io.LimitReader`/size cap in both ScanDir and Load. *Confirmed.*

**GO-031 — No validation that `maxPriorityFeePerGas <= maxFeePerGas`.** `internal/tx/validation.go:63-77`; `builder.go:104-122`; (CLI default-injection `main.go:235-240`). *(bug; tx-core:bugs-3 [Medium→Low], tx-lib:bugs-5)* Neither static nor RPC paths check tip <= maxFee; `build --max-priority-fee-per-gas 30000000000` with the default 20-gwei maxFee yields a tx every node rejects, detected only after signing (a wasted air-gapped/Ledger ceremony). Fix: return an error when `tip.Cmp(maxFee) > 0` after fee resolution. *Reproduced live.*

**GO-032 — Nil base fee panics fee computation; `BlockBaseFee` over-fetches and the doc is wrong.** `internal/tx/rpc_client.go:120-126`; `builder.go:116-121`. *(bug; tx-lib:bugs-0 [Medium→Low], tx-lib:security-4, tx-lib:quality-5)* `Block.BaseFee()` is nil for non-EIP-1559 blocks; it is returned unchecked and `new(big.Int).Mul(big.NewInt(2), baseFee)` panics (reproduced with a mock). Also `BlockByNumber` downloads full tx bodies where `HeaderByNumber` suffices, and the interface doc says "pending" while the code fetches "latest". Currently unreachable from the CLI (RPC path dead, GO-005) but it is exported API. Fix: use `HeaderByNumber`, error on nil `BaseFee`, fix the doc. *Confirmed.*

**GO-033 — RPC chain-ID guard silently skipped on RPC error or chain-ID 0; documented "warn" never emitted.** `internal/tx/builder.go:92-102`. *(security; tx-lib:bugs-1 [Medium→Low], tx-lib:security-2 [Medium→Low], tx-lib:quality-3 [Low→Info])* The wrong-network guard is bypassed when `ChainID()` errors (discarded by `chainErr == nil`) or returns 0 (`rpcChainID.Sign() != 0`), with no logger so the "warn-and-continue" comment never warns — the very RPC being distrusted can disable the check. Build then consumes that node's nonce/fees. Currently dead code (GO-005) and mitigated by send's own check. Fix: fail closed in RPC mode, or actually emit the warning and treat chain-ID 0 as a mismatch. *Confirmed.*

**GO-034 — RPC gas estimation: `estimate*6/5` uint64 overflow + silent zero-address fallback.** `internal/tx/builder.go:139-161`. *(bug; tx-lib:bugs-3, tx-lib:bugs-4, tx-lib:security-6, tx-lib:quality-2)* The 20% margin multiplies by 6 before dividing, wrapping for estimates `> ~3.07e18` (reproduced: a large estimate yields a value smaller than itself). The contract address is round-tripped through hex with both failure modes swallowed, leaving `toAddr` the zero address and estimating gas for a plain transfer to `0x0`. Unreachable today (RPC path dead). Fix: `estimate + estimate/5` with a sane ceiling; use `cfg.NetworkParams.DepositContractAddress` directly. *Confirmed.*

**GO-035 — Receipt polling fragility.** `internal/tx/rpc_client.go:78-86`; `cmd/eth-deposit-tx/send.go:283-293`. *(bug; tx-lib:bugs-2 [Medium→Low], tx-ops:bugs-6, tx-lib:security-7, tx-lib:quality-4, tx-ops:quality-4)* `TransactionReceipt` classifies "not yet mined" by `strings.Contains(err.Error(), "not found")` instead of `errors.Is(err, ethereum.NotFound)`, so a `-32601 "Method not found"` is misread as pending (spins until timeout) while a differently-worded pending error aborts immediately; `pollReceipt` returns on the first transient error after funds are already broadcast; and receipt-wait failures carry no sentinel → undocumented exit 1. Fix: use the typed sentinel, retry transient errors until the deadline, map receipt-phase failures to a documented code. *Confirmed.*

**GO-036 — `NewSigner` accepts an all-zero BLS secret.** `internal/bls/bls.go:87-92`. *(security; crypto:bugs-0, crypto:security-1)* herumi `Deserialize` accepts `Fr = 0`; `PublicKey()` (using `GetPublicKey`, not `GetSafePublicKey`) returns the infinity pubkey and `Sign()` the infinity signature, no error. Spec requires SK in `[1, r-1]`. Caught today only by the pipeline's self-verify (herumi `Verify` returns false for the identity pubkey). Fix: reject `s.sk.IsZero()` after Deserialize and/or use `GetSafePublicKey()`. *Reproduced.*

**GO-037 — `ValidatePubkeyBytes` accepts the point-at-infinity.** `internal/bls/bls.go:154-165`. *(security; crypto:bugs-1, crypto:security-2)* The compressed identity (`0xc0 || 47×00`) deserializes as a valid G1 point, so the function returns nil for it, deviating from IETF `KeyValidate` (and beacon-chain deposit processing) which reject it. It gates `--pubkeys` and is the function `internal/tx/validation.go` names as the intended pre-broadcast check. Fix: `if hPub.IsZero() { return errors.New("bls: pubkey is the point at infinity") }`. *Reproduced.*

**GO-038 — `DomainDeposit` / `ZeroGenesisValidatorsRoot` are exported mutable package vars.** `internal/network/network.go:57-62`. *(quality; cli-net:bugs-3, cli-net:security-3, cli-net:quality-4)* Go cannot make array constants, but these signing-domain constants are exported `var`s any package can reassign; `deposit.NewGenerator` reads them once at construction. A mutation would change BLS domain separation process-wide and would NOT be caught by verify-before-write (verifier uses the same corrupted domain). Fix: expose as functions returning the array by value, backed by unexported values. *Confirmed.*

**GO-039 — `NewApp` doc comment states exit code 1 for validation errors; code returns 2.** `internal/cli/cli.go:78-81`. *(quality; cli-net:bugs-2, cli-net:security-4, cli-net:quality-1)* Every validation path returns `ucli.Exit(…, 2)`; the doc comment (and a test comment in `cli_test.go:550-551`) says 1. Exit codes are a documented contract. Also two steps are both numbered "5." Fix: correct the comments. *Confirmed.*

**GO-040 — Unexpected positional arguments silently ignored.** `internal/cli/cli.go:180-247`. *(bug; cli-net:bugs-1 [Medium→Low])* `app.Action` never checks `c.NArg()`, so `--pubkeys 0xAAA 0xBBB` (space instead of comma) assigns only the first key and silently drops the rest — the output covers fewer validators than intended, mitigated only by the `count=N` banner. Fix: error on `c.NArg() > 0`. *Confirmed.*

**GO-041 — `send --input -` without `--yes` always aborts on exhausted stdin.** `cmd/eth-deposit-tx/send.go:154-155,211-219`. *(bug; tx-ops:bugs-3, tx-ops:quality-1)* `io.ReadAll(c.App.Reader)` consumes stdin to EOF; the confirmation then reads the same reader and gets `io.EOF` → "user aborted: EOF" (exit 4). The documented stdin pipeline therefore only works with `--yes`, silently making the one safety prompt unusable in pipe mode. Fix: read the confirmation from `/dev/tty`, or reject `--input -` without `--yes` with a clear exit-2 message. *Confirmed.*

**GO-042 — Chain-ID fetch error flattened with `%v`; SIGINT during fetch → exit 5 instead of 4.** `cmd/eth-deposit-tx/send.go:176-179`. *(bug; tx-ops:bugs-5, tx-ops:quality-2)* Wrapping `BroadcasterChainID`'s error with `%v` destroys the chain, so a Ctrl+C mid-fetch is no longer `errors.Is(err, context.Canceled)` and maps to exit 5 (broadcast error) rather than 4 (user abort). Fix: use a second `%w`. *Confirmed end-to-end.*

**GO-043 — Secret-leak test comment claims a copy is passed but hands the sentinel slice itself.** `cmd/eth-deposit-gen/main_test.go:641-645`. *(quality; gen:bugs-6, gen:security-4, gen:quality-6)* The comment says "Pass a copy so key.Zeroize() doesn't clobber sentinelOrig" but `Secret: sentinelOrig` shares the backing array, which `Zeroize` clears. The test passes only because the expected forms are pre-computed earlier; a future edit trusting the comment could turn the leak assertion vacuous (comparing against 32 zero bytes). Fix: actually copy, or fix the comment. *Confirmed.*

**GO-044 — Nine files not gofmt-formatted; no formatting gate in lint.** module-wide (`internal/signer/{ledger,local,*_test}.go`, `internal/tx/{errors,builder_test}.go`, `cmd/eth-deposit-tx/{main,deposit_e2e_test}.go`). *(quality; signer:bugs-7, signer:security-7, signer:quality-1, tx-lib:bugs-7, tx-lib:quality-1, tooling-2, crosscut-9)* `gofmt -l .` flags nine files (whitespace/alignment only). CONVENTIONS.md says "gofmt is law"; `make lint` runs only vet + staticcheck. Fix: `gofmt -w .` and add `test -z "$(gofmt -l .)"` to lint/CI. *Reproduced.*

**GO-045 — Two inconsistent zeroizers; `runtime.KeepAlive` comment overstates its guarantee.** `internal/keystore/keystore.go:53-57,152-159`. *(quality; keystore:bugs-7, keystore:quality-3)* `zeroizeBytes` (passphrase) ends with `runtime.KeepAlive` and a comment claiming it "prevents the compiler from treating the writes as dead stores" — false (KeepAlive only extends liveness); `Key.Zeroize` (the more sensitive BLS secret) lacks it entirely. Fix: have `Key.Zeroize` delegate to `zeroizeBytes` and correct the comment. *Confirmed.*

**GO-046 — Bare/unwrapped error returns contrary to the `%w` convention.** `internal/keystore/scandir.go:48-51`; `cmd/eth-deposit-gen/main.go:249-275,405-409`; `internal/deposit/deposit.go:115-144`. *(quality; keystore:quality-4, gen:quality-5, deposit-out:quality-6)* `ScanDir` returns the raw `os.ReadDir` error (the literal "Bad" example in CONVENTIONS.md); `runWithDeps` returns `network.Lookup`/scanner/`writer.Write` errors unwrapped (a permission-denied scan surfaces with no operation context); `Generate` returns signer/verifier errors bare while wrapping the sibling mismatch/self-verify errors with the pubkey index. Fix: wrap with context + `%w` throughout. *Confirmed.*

**GO-047 — `mustParseAddr` runs per-`Lookup`; network registry duplicated across 4 sites.** `internal/network/network.go:64-154`. *(quality; cli-net:quality-2, cli-net:quality-3)* The comment claims "compile-time constant initialisation" but the function is called inside `Lookup`, re-decoding hex on every call, so a typo'd address panics only when that network is selected (not at init/test). The supported set is enumerated independently in `Lookup`, `LookupByChainID`'s hardcoded slice, `ParseFlag`, and two divergently-worded error messages; the `if err != nil { continue }` is unreachable. Fix: derive everything from one package-level `map[Network]Params` table. *Confirmed.*

**M2.3-1 [reviewer] update (post-M2.2 start; pre-fix review per binding "update acceptance criterias checkboxes" + "Read implementer summary, catalogue m2.3... + network.go (the four dupe sites + registry), tests (network_test + new panic test). Run gofmt/make lint/tests + new panic test. Structured findings (single source, init panic, lookup tests green, scope, verifs, no creep). Append to /tmp/grok-plan-review-a3e1b3bf.md. Verdict + AC [x] in text + open counts + "End of M2.3-1 review notes." Relative. No plan md edits. Explicit 3 AC verifs. (Confirm init-time parse + panic for typo.)"):** [reviewer] read /tmp/grok-plan-summary-a3e1b3bf.md (M2.2 prior + binding) + /tmp review (tail/offset/read chunks), catalogue go/plan/issues/m2.3-convention-architecture.md (M2.3-1 + [ ] ACs + notes), go/plan/prd.md (FR-P2-A3), go/plan/architecture.md (§6.1 + invariants for paramsByName), go/plan/project-plan.md (M2.3 + GO-047), go/plan/REVIEW.md (GO-047 + dupe), go/internal/network/network.go (the four dupe sites at :78 mustParse + :92 Lookup 4arms + :138 LookupByChainID slice+recurse + :154 ParseFlag switch + comment claiming compile-time), go/internal/network/network_test.go (lookup tests; no TestNetworkInit_BadAddressTypo_PanicsAtInit present), greps across go/ for network. calls (scope: consumers in cli/cmd/deposit/tx/signer etc; 0 other dupe tables), go/CLAUDE.md + go/CONVENTIONS.md (patterns, avoid side-effect init but var map literal ok per arch). Ran (relative paths): gofmt -l go/internal/network/network.go go/internal/network/network_test.go (clean); make -C go lint (pass); CGO_ENABLED=1 go test ./internal/network -count=1 -v (PASS; lookup/Parse/ByChainID/Constants green); targeted; + new panic test via mustParseAddr sim on typo addr (panics confirmed) + package-load test run (succeeds, no panic -- confirms not init-time yet). Structured findings (single source etc) in /tmp append. AC checkboxes updated in text (here + /tmp). No fixes by reviewer. No edits to go/plan/issues/*.md . Explicit 3 AC verifs (see /tmp). (Confirm init-time parse + panic for typo: sim run did; current source lazy so no.)

**GO-048 — SSZ "reference implementation" oracle is dead code and not independent; fuzz asserts tautologies.** `internal/ssz/ssz_test.go:333-448`; `ssz_fuzz_test.go:50-91`. *(quality; crypto:bugs-4, gap-0-0 [Medium→Low], crypto:quality-2)* `computeDepositMessageRoot`/`computeDepositDataRoot` are only reached in the `else` of `if tc.wantHex != ""`, which is always true, so they never run — and they call the production `sha256Pair`/`uint64Chunk`, so even if they ran they would not be an independent oracle (the "not via the same helpers" comment is false). `FuzzMerkleize` only asserts a pure function is deterministic; `FuzzUint64Chunk` checks `len != 32` on a `[32]byte` (impossible). The hardcoded anchors were independently re-derived and are correct, so there is no on-chain bug — only weak/misleading test assurance on the funds-critical merkleize path. Fix: make the oracle/fuzz genuinely differential, or delete the dead branches. *Confirmed.*

**GO-049 — RPC URL (often an API key) embedded in the `ErrRPCDial` error.** `internal/tx/rpc_client.go:48-53`. *(security; tx-lib:bugs-6)* `fmt.Errorf("%w: %s: %v", ErrRPCDial, rpcURL, err)` interpolates the full URL (e.g. `…infura.io/v3/<KEY>`), which propagates to stderr/CI logs via `slog.Error`. Fix: omit/redact the URL (scheme://host only). *Confirmed.*

**GO-050 — `ledger_nocgo.go` build-tag path can never compile.** `internal/signer/ledger_nocgo.go:1-9`. *(quality; crosscut-7)* `internal/signer → internal/tx → internal/deposit → internal/bls → herumi` is cgo-only, so `CGO_ENABLED=0 go build ./internal/signer` fails in herumi; the `//go:build !cgo` stub is never type-checked and the `ErrLedgerNotSupported` path is unreachable. The header comment claiming `!cgo` parity is wrong. Fix: delete the stub and comment, or break the signer→bls dependency and add a `CGO_ENABLED=0` CI build. *Reproduced.*

**GO-051 — `signUnsignedTx` switch has no default case → nil-interface panic.** `cmd/eth-deposit-tx/sign.go:184-201`. *(bug; tx-ops:quality-5)* The switch handles only `"local"`/`"ledger"`; any other value leaves `s` nil and `defer s.Close()` / `s.RequiresUserInteraction()` panic. Safety currently rests on two separately-maintained validation sites (sign.go and run.go) staying in sync — the "impossible state" CONVENTIONS.md says should error, not panic. Fix: add a `default` returning `ErrInvalidInput`. *Confirmed.*

**GO-052 — Guide shows a withdrawable `0x01` credential the tool can never produce.** `docs/USER-GUIDE.md:217`. *(bug; gap-2-0 [filed High; panel split critical/low/low → Low])* The "Output JSON shape" example shows `withdrawal_credentials` beginning `0x01`, but the tool always emits all-zero `0x00` (GO-001) — the golden fixtures confirm `0000…0000`. A user following the guide believes their deposit is withdrawable to an eth1 address. Fix: change the example to all-zero and warn that v1 emits unusable placeholder credentials — ideally after fixing GO-001. *Confirmed; amplifies GO-001.*

**GO-053 — E2E script leaks the API-key RPC URL to terminal and disk.** `scripts/e2e-testnet.sh:80,135`. *(security; gap-1-0 [Medium→Low])* Line 80 `echo`s the full Infura/Alchemy URL (embedded key); line 135 `tee`s send output into `testdata/deposit-e2e/<ts>/send-output.txt` inside the git tree, and a dial failure writes the key-bearing `ErrRPCDial` URL (GO-049) into that file, risking a commit. Fix: redact the URL; write artifacts outside the repo. *Confirmed.*

**GO-054 — Documented `run` invocation omits `--rpc-url`, so nonce defaults to 0.** `scripts/e2e-testnet.sh:101-107`. *(bug; gap-1-1 [Medium→Low])* The "full E2E" `run` step passes no `--rpc-url`/`--nonce`/fee flags, so (per GO-005) it always builds a nonce-0, 20-gwei tx — rejected as nonce-too-low for any funded account that has transacted. Fix: pass an explicit `--nonce` and fees, or split into `build --rpc-url …` once that path is wired. *Confirmed.*

**GO-055 — go-ethereum v1.14.12 is stale and predates Ledger current-firmware fixes.** `go.mod:6`. *(security; tooling-0 [Medium→Low], deps-0 [Medium→Low])* govulncheck flags 4–5 advisories (GO-2025-3436 → GO-2026-4508), all p2p-stack DoS; the code imports only common/core-types/crypto/rlp/accounts/usbwallet/ethclient, so none are in a linked path. The concrete impact: v1.14.12 predates the v1.15.0 `usbwallet` fix for current Ledger firmware (PID 0x5000), Flex, and Gen5 — on a current-firmware Ledger the hub may enumerate no wallets, silently failing the hardware-signing path (the recommended mainnet path) and steering users to the hot-key local signer. Fix: upgrade to `>= v1.17.0` and re-run the Ledger E2E. *Confirmed via govulncheck + import grep.*

**GO-056 — No `toolchain` directive: release builds use the unpatched go1.26.0 stdlib.** `go.mod:3`. *(security; tooling-1 [Medium→Low], deps-1 [Medium→Low])* `go 1.26.0` with no toolchain pin (and CI `setup-go` pinned to 1.25) means `GOTOOLCHAIN=auto` downloads exactly go1.26.0; govulncheck reports 12 symbol-reachable stdlib vulns fixed in 1.26.1–1.26.4, including crypto/tls and crypto/x509 issues reachable through `tx.NewEthClient → ethclient.DialContext → tls.Conn.Handshake / x509.Certificate.Verify` — the TLS path to the user-supplied RPC endpoint. Fix: add `toolchain go1.26.4`, pin CI to `1.26.x`, re-cut binaries on stdlib patches. *Reproduced via govulncheck.*

**GO-057 — No vulnerability scanning in lint/CI.** `Makefile:30-32`. *(quality; deps-3)* `make lint` is vet + staticcheck only; no workflow runs govulncheck/OSV/trivy. This is why GO-055/GO-056 accumulated unnoticed. Fix: add `govulncheck ./...` to lint and both CI workflows; triage module-only (unreachable) hits with documented suppression. *Confirmed.*

**GO-058 — Unchecked error returns on user-facing writes (errcheck).** `cmd/eth-deposit-gen/main.go:201,203,448`; `internal/cli/cli.go:369`; `internal/keystore/passphrase.go:50,52,56`. *(quality; tooling-3)* `golangci-lint`/errcheck flags 7 production unchecked `Fprintf`/`Fprintln`/`tty.Close`; a silently-failed `printSummary` means the operator never sees the output path + sha256 that is part of the tool's verification story. Fix: assign to `_` with a comment, or propagate the summary write error. *Confirmed via golangci-lint.*

**GO-059 — The only external-authority cross-check (`--verify-with-deposit-cli`) is stubbed in every test.** `cmd/eth-deposit-gen/main_test.go:1116-1235`. *(quality; gap-0-2)* All `TestVerifyDepositCLI_*` tests inject a stub; no test runs a real `staking-deposit-cli`. Combined with self-referential golden/e2e fixtures, the suite has zero automated cross-validation against any implementation outside this repo. Fix: add an env/tag-gated integration test running the real CLI against generated output. *Confirmed.*

**GO-060 — Script points operator at a deleted validation-template path.** `scripts/e2e-testnet.sh:163`. *(quality; gap-1-2)* The closing "NEXT STEP" references `docs/deposit-tx/validation/phase-4-e2e-template.md`, removed during doc consolidation (commit a520edd); the file no longer exists. Fix: point at `USER-GUIDE.md` or remove the block. *Confirmed.*

---

### Info-severity findings

**GO-061 — `merkleize` treats `limit < len(chunks)` as a floor, deviating from SSZ spec.** `internal/ssz/ssz.go:162-175`. *(crypto:bugs-2, crypto:security-5, crypto:quality-3)* Uses `n = max(len(chunks), limit)`; the spec makes `len(chunks) > limit` an error. All five call sites pass `limit == len(chunks)`, so no wrong root today, but it is a latent footgun if reused for SSZ lists. Fix: guard `len(chunks) <= limit` (panic as programmer error) or drop the parameter. *Confirmed; all hardcoded vectors independently re-derived and correct.*

**GO-062 — `internal/bls` / `internal/ssz` minor hygiene.** *(crypto:quality-4/5/6/7)* `Sign` doc says "hashes msg" but the param is `signingRoot` (bls.go:94-96); error casing inconsistent (`bls: Deserialize` vs `bls: deserialize …`) and the Init path double-prefixes (`bls: not initialized: bls: herumi Init: …`); herumi imported with the redundant alias `bls` inside `package bls` (bls.go:12); the ssz package comment carries a historical note about removed research docs (ssz.go:14-18). Fix: reword/realias/delete as noted. *Confirmed.*

**GO-063 — Parallelism cap formula duplicated with an unnamed multiplier.** `internal/cli/cli.go:163,220`. *(cli-net:quality-6)* `runtime.NumCPU()*4` appears in the flag usage and the validator (and the doc comment), risking drift. Fix: compute once into a named constant. *Confirmed.*

**GO-064 — Documented fixture-regeneration command silently does nothing.** `internal/keystore/gen_fixtures_test.go:1-23`. *(keystore:bugs-9, keystore:quality-7)* The header says run `go test -run TestGenerateFixtures …`, but the body skips unless `GENERATE_FIXTURES` is set — running the documented command regenerates nothing (verified). Fix: prefix the command with `GENERATE_FIXTURES=1`. *Reproduced.*

**GO-065 — Test fixtures use invalid-length pubkeys.** `internal/keystore/keystore_test.go:19`; `scandir_test.go:66`. *(keystore:bugs-8, keystore:security-9, keystore:quality-9)* `testPubkeyHex` is 127 chars (odd-length, undecodable) and scandir fixtures are 92 chars vs the real 96-char (48-byte) BLS format; one is labelled "realistic". Tests pass only because the loader skips length validation. Fix: use valid 96-char values and regenerate fixtures. *Confirmed.*

**GO-066 — `TestEntriesFromJSON_GoldenFile` asserts against a hand-copied inline literal.** `internal/deposit/json_test.go:204-214`. *(deposit-out:security-4, deposit-out:quality-2)* The comment claims it is the content of `internal/output/testdata/deposit_data-expected.json`, but it is a frozen byte copy; `make refresh-golden` would silently diverge it, voiding the cross-package round-trip guarantee the test is named for. Fix: read the fixture, or round-trip via the output writer. *Confirmed.*

**GO-067 — Stale APDU-code test comment; tautological signer tests.** `internal/signer/ledger_internal_test.go:647-673`; `signer_test.go:34-65`. *(signer:quality-9, signer:quality-8)* A comment names `…APDU6d00`/code 6d00 while the function is `…UnknownAPDUCode_NotSentinel` returning 6f00 (and no test exercises 6d00 during Sign); `TestFakeSignerName`/`TestFakeSignerSign` assert only the test double's hardcoded returns, exercising no production code. Fix: correct the comment; delete the tautological tests (keep the interface assertion). *Confirmed.*

**GO-068 — USER-GUIDE troubleshooting attributes errors to the wrong layer.** `docs/USER-GUIDE.md:744,763`. *(gap-2-2, gap-2-3)* The "deposit entry validation:" row lists "bad withdrawal credentials prefix" as a cause, but that check lives in `internal/tx.Validate` with a different message; the send row quotes "RPC chain ID does not match configured network" which is the build-side `ErrChainIDMismatch`, never emitted by send (send emits `ErrBroadcastChainIDMismatch`). Fix: correct the message/cause pairings. *Confirmed.*

**GO-069 — `DEPOSIT_DATA_FILE` default contradicts its header comment.** `scripts/e2e-testnet.sh:14-15,60`. *(gap-1-3 [Low→Info])* The header documents `testdata/phase3/holesky/unsigned_tx.json` "the signed fixture"; the code default is `cmd/eth-deposit-tx/testdata/deposit-fixture.json` (an unsigned deposit_data array). Both the path and the description are wrong. Fix: make the comment match the code. *Confirmed.*

**GO-070 — `PackDeposit` byte layout never checked against a canonical ABI encoder.** `internal/tx/abi_test.go:24-160`. *(gap-0-3)* The selector test is a genuine independent keccak derivation, but the layout is validated only by a self-round-trip using offset constants from the same file — not against `accounts/abi`. Independently encoding the same args with go-ethereum's encoder confirmed `PackDeposit` is byte-identical (no bug), but the external cross-check is absent. Fix: add an `accounts/abi`-based equality test. *Confirmed.*

**GO-071 — golang.org/x/crypto v0.22.0 is two years stale (no applicable CVE).** `go.mod:10`. *(deps-2 [Low→Info])* 16 advisories at this version, all in `ssh`/`ssh/agent`, which this code never imports (only `sha3` in a test + transitive `scrypt`/`pbkdf2` via wealdtech, none with advisories). Stale-pin hygiene only; inconsistent with current siblings `x/term` 0.43.0, `x/sys` 0.44.0. Fix: `go get golang.org/x/crypto@latest && go mod tidy`. *Confirmed via import grep.*

---

## Code-quality observations

**Overall assessment (from the scope summaries):** This is well-organized, idiomatic Go. Recurring strengths noted by multiple finders: clean dependency injection in both `main` packages (genuinely testable pipelines), explicit and table-tested exit-code contracts, verify-before-write enforcement in `internal/deposit`, a single source of truth for network constants (all values verified correct, including hoodi's intentional reuse of the mainnet deposit contract), atomic 0600 writes for signed artifacts in `run`/`send`, careful passphrase zeroization with honest comments about the unavoidable string copy, sentinel errors matched via `errors.Is` for exit mapping, dedicated secret-leak regression tests, and hand-rolled SSZ/ABI primitives that were re-derived from the consensus spec / keccak and found byte-correct. `go build`, `go vet`, and `staticcheck` are all clean.

**Tooling sweep results (CGO_ENABLED=1, go1.26.0):** `go build ./...` ✓; `go vet ./...` clean; `staticcheck ./...` clean; `go test ./...` all 12 packages pass (e2e behind the `e2e` tag, golden/fixture-refresh tests self-skip); `gofmt -l .` → 9 files (GO-044); `golangci-lint` → 16 errcheck hits (7 production, GO-058) + 1 intentionally-suppressed SA1012; `govulncheck` → 12 stdlib (GO-056) + 4 go-ethereum (GO-055) reachable advisories. `gosec` was not installed.

**Recurring quality themes not individually numbered** (catalogued here per requirement; all confirmed, all Info-level convention/dead-code items):
- **Dead / speculative code & unused API:** `padRight` is test-only (`internal/ssz/ssz.go:197-208`); `BuildConfig.RPCURL` and `UnsignedTx.From` are dead scaffolding with stale "Issue 2.5"/"until a signer is wired" comments (`internal/tx/interface.go:52`, `types.go:12-13`); the consumer-less stuttering `tx.TxBuilder` interface + its runtime satisfaction test (`internal/tx/interface.go:36-39`); `deposit.Request.Pubkeys` batch API is exercised only one-pubkey-at-a-time (`internal/deposit/deposit.go:36-38`); exported `EntryFromJSON` has no non-test callers (`internal/deposit/json.go:62-68`); `network.Params.DefaultRPCURL` is empty for all networks and read nowhere (`internal/network/network.go:40-43`); two fake "compile-time assertions" that assert nothing (`cmd/eth-deposit-tx/run.go:355-356`).
- **Duplication / drift:** ~~the `jsonEntry` wire struct is duplicated read-side vs write-side (`internal/deposit/json.go:18-28` vs `internal/output/output.go:41-51`)~~ **FIXED M2.2-2: now canonical deposit.JSONEntry (output imports/uses it; JSON bytes unchanged)**; ~~the build flag list is duplicated between `buildCommand` and `buildFlags()` with an already-drifted `--output` usage string (`run.go:167-221`)~~ **FIXED M2.2-3: now canonical buildFlags() (buildCommand consumes it; --help bytes identical via minimal command-specific Usage patch; one source of truth)**; ~~signer/env-var validation is duplicated between `LoadSignConfig` and `LoadRunConfig` (`sign.go:38-54`, `run.go:45-59`)~~ **FIXED M2.2-4: now shared validateSignerEnv helper in config.go consumed by both Loads; redaction discipline (M0.8-2) + exact error texts preserved; no behavioral regression (see security audit appended to /tmp/grok-plan-review-a3e1b3bf.md)**; `RunConfig.OutputFile` duplicates `Build.OutputFile` (`run.go:21-35`); the `32_000_000_000` deposit amount is an unnamed literal in three packages; ~~the network registry (4 sites: Lookup/ParseFlag/LookupByChainID + mustParseAddr calls)~~ **M2.3-1 REVIEW IN PROGRESS (GO-047 / FR-P2-A3; single `paramsByName` + init-time parse targeted; see appended M2.3-1 notes in /tmp/grok-plan-review-a3e1b3bf.md + AC checkboxes updated in review text; lookup tests green pre-fix; no creep)**.
- **Convention nits:** duplicate package doc comments (`cmd/eth-deposit-tx/exit.go` + `main.go`; `internal/deposit/json.go` + `deposit.go`); exported sentinels lacking doc comments and no package comment in `internal/tx` **(FIXED M2.3-3: all exported Err* = errors.New now have `// ErrXxx is returned when ...` per Go conv + m2.3 md format; audit via task grep + -B1 confirmed; signer/deposit/bls/etc already had; tx gaps filled in errors.go only; staticcheck/make lint clean; ACs met)**; inconsistent exported/unexported sentinels in `cmd/eth-deposit-gen` (`main.go:43-59`); ~~`%v`-flattened wrapping that breaks `errors.Is` in `internal/tx/rpc_client.go`~~ **FIXED M2.3-4: replaced sole %v with %w in NewEthClient (smallest; preserves text+redaction; errors.Is now chains through dial err too; AC grep no hits; tx tests + lint green; per arch §19 #6 / FR-P2-A16 / M1.5-8 tail; see /tmp/grok-plan-*-a3e1b3bf.md + this)**; ~~move `runWithDeps` orchestration out of `package main` (cmd/eth-deposit-gen/main.go + symmetric tx paths) into `internal/cli`~~ **FIXED M2.3-5: runWithDeps + supporting (Deps, picks, buildLogger, emit, printSummary, exitCodeFor, sentinels, derive, verify/sanitized, Run) moved to internal/cli (exported entries for tests; fields capitalized for cross-pkg test literals); both mains reduced to thin entry (~25-35 LOC, only signal/setup + NewApp/Run call + ExitCodeFor); no behavior change (tests green incl. full + targeted); gofmt/make lint green; ACs met (thin mains, internal owns, tests green, identical outputs); updated AC checkboxes + catalogue here + /tmp; see /tmp/grok-plan-*-a3e1b3bf.md + this**; duplicate chain-ID method surface with inconsistent types (`rpc_client.go:102-108,141-144`); `runWithDeps`'s ~190-line orchestration living in `package main` against the thin-main convention while `deposit.Generate`'s batch path runs dead.

---

## Dependency audit

All six direct dependencies were checked against advisory databases with govulncheck symbol-level reachability; all imports were grepped to confirm applicability.

- **Clean & current (no action):** `herumi/bls-eth-go-binary v1.37.0` (latest, no advisories — the BLS core), `urfave/cli v2.27.7` (latest v2), `wealdtech go-eth2-wallet-encryptor-keystorev4 v1.4.1` (latest), `golang.org/x/term v0.43.0`.
- **`github.com/ethereum/go-ethereum v1.14.12` (GO-055):** ~18 months stale; 4–5 advisories, **all p2p-stack DoS not in any linked path** (this is an RPC client, not a node). Real impact is functional: predates the v1.15.0 `usbwallet` fix for current Ledger firmware/Flex/Gen5, degrading the hardware-signing path. Upgrade to `>= v1.17.0`.
- **Go toolchain (GO-056):** `go 1.26.0` with no `toolchain` pin → release builds use the unpatched go1.26.0 stdlib; 12 symbol-reachable stdlib advisories (crypto/tls, crypto/x509, net/http, net/url) via the RPC TLS path, fixed in 1.26.1–1.26.4. Add `toolchain go1.26.4`.
- **`golang.org/x/crypto v0.22.0` (GO-071):** two years stale; 16 advisories, **all in `ssh`/`ssh/agent`, none linked** (only `sha3` test-use + transitive `scrypt`/`pbkdf2`). Stale-pin hygiene only.
- **Process gap (GO-057):** no govulncheck/OSV scanning in lint or CI — the reason the above accumulated silently. The release workflow does run `go mod verify` (checksum integrity).

No applicable, reachable CVE was found in any third-party package this code actually links. The findings are staleness + one functional Ledger regression + missing scanning, remediable by routine version bumps and one CI step.

---

## Recommendations

### Fix now (release blockers for mainnet)
1. **GO-001** — Stop emitting all-zero withdrawal credentials. Require `--withdrawal-address` / a withdrawal pubkey; refuse to generate otherwise; add defense-in-depth rejection in both validation layers.
2. **GO-002** — Bind `entry.NetworkName`/`ForkVersion` to `--network` in the build path (hard-fail on mismatch); ideally recompute SSZ roots and BLS-verify before emitting any tx.
3. **GO-003** — Strictly validate the `to` address in `parseUnsignedTx` and cross-check it against the deposit contract for the chain ID.
4. **GO-004** — Decode `signed.RawRLP` and derive the confirmation prompt + chain-ID guard from the decoded transaction; abort on any divergence from the JSON metadata.

### Fix soon
5. **GO-005** — Wire (or reject) `--rpc-url`; never silently default nonce to 0.
6. **GO-006 / GO-014 / GO-049 / GO-053** — Stop leaking secrets into errors/logs/artifacts (BLS secret in herumi error, private-key value in `--private-key-env` error, API-key URL in `ErrRPCDial` and the e2e script).
7. **GO-010** — Return non-zero on a reverted (`status=0`) deposit.
8. **GO-012 / GO-013** — Recompute roots + verify BLS on the read path; add a mainnet gate to `eth-deposit-tx` that `--yes` does not bypass.
9. **GO-007 / GO-008** — Make the TTY passphrase source concurrency-safe and honour cancellation in the worker pool and `loader.Load`.
10. **GO-011** — Unique temp names (`O_EXCL`) and no-clobber on the final deposit-data path.
11. **GO-009 / GO-040** — Reject duplicate pubkeys and unexpected positional arguments.
12. **GO-055 / GO-056 / GO-057** — Upgrade go-ethereum to `>= v1.17.0`, pin `toolchain go1.26.4`, add `govulncheck` to CI.
13. **GO-051 / GO-021 / GO-032** — Add the missing `default` case (panic risk), guard the LocalSigner key with a mutex, error on nil base fee.

### Consider
14. **GO-015–GO-046** remaining low-severity correctness/robustness items: exit-code consistency, atomic writes everywhere, ctx-honouring writers, keystore error classification, Ledger error wrapping, BLS zero-key/infinity rejection, tip≤maxFee check, receipt-poll robustness.
15. **GO-044 / GO-058** — `gofmt -w .` and add gofmt + errcheck gates to lint/CI.
16. Documentation & tests: GO-052/GO-060/GO-068/GO-069 (doc/script accuracy), GO-048/GO-059/GO-064/GO-065/GO-066/GO-067/GO-070 (test independence and fixture hygiene), and the quality catalogue above (dead code, duplication, package-comment cleanup).

---

## Appendix — refuted findings (adversarially killed)

1. **Substring-based Ledger error classification misroutes transport failures as user rejection** — `internal/signer/ledger.go:103-135`. *Refuted:* `isUserRejectedErr` runs only on `wallet.SignTx` errors; the cited Linux open-time failures flow through `NewLedgerSigner`, not the Sign classifier, so the claimed exit-4 misroute cannot occur.
2. **RPC-resolved gas/fee values used without sanity bounds (overflow / negative fees)** — `internal/tx/builder.go:104-122,156-162`. *Refuted as stated:* `resolveRPC` is unreachable from production (`BuildConfig.RPC` is set only in tests; GO-005). The real overflow/zero-address concerns are retained as GO-034 scoped to the exported API.
3. **Fuzz seed labeled "mixed prefix" is not mixed** — `internal/cli/cli_fuzz_test.go:24`. *Refuted:* the finding misquoted the line; the actual seed (`0x`-prefixed first entry, unprefixed second) is genuinely mixed and distinct from line 17.
4. **e2e golden tests cannot detect a fund-locking spec deviation in the signing domain/ciphersuite** — `test/e2e/mainnet_test.go`. *Refuted:* the narrow "golden compare is self-referential" point is true, but the load-bearing claim is false — independent domain/GVR and BLS-vector assertions exist elsewhere, and the hardcoded anchors were re-derived and verified correct.

---
## Implementation Summary — Issue M2.2-2 (added by implementer per binding directive)

**Issue:** M2.2-2: Unify `jsonEntry` between `internal/deposit/json.go` and `internal/output/output.go` (2pts P2; closes FR-P2-A15 jsonEntry portion; depends on M2.2-1)

**Review notes file:** go/plan/REVIEW.md (full read + quality catalogue duplication item + FR-P2-A15 context); also read go/plan/issues/m2.2-dead-code-dedup.md (ACs + notes), go/plan/prd.md (FR-P2-A15), go/plan/architecture.md (§6.7 + §10.4), go/plan/project-plan.md, the two sites, all callers via grep (EntriesFromJSON, toJSONEntry, marshalEntries, JSONEntry refs limited to deposit/output/cmd/tx/e2e/tests; no other pkgs touched).

**Actions taken (verbatim obey):**
- Audited structs: both `jsonEntry` (unexported) were *byte-identical* (9 fields, identical JSON tags in exact declaration order, types, per arch §10.4 schema stability). Confirmed via direct read + diff.
- Picked canonical per task ("architecture suggests `internal/output`"): but *pragmatically used `internal/deposit`* (owner of `Entry` type; output already imports deposit; reverse would create import cycle deposit<->output, violating "smallest change" + "no new files" + "follow patterns exactly" + "never create unless necessary"). Output (the "other package") now imports/uses the type from deposit (matches "the other package imports" + "update ... + callers to import/use"). Net hygiene only (M2.2-1 precedent).
- Deleted dupe struct def + comment from `go/internal/output/output.go`.
- Updated `go/internal/output/output.go`: toJSONEntry/marshalEntries now return/use `deposit.JSONEntry`; updated 3 comments for clarity (no behavior change).
- Updated `go/internal/deposit/json.go`: renamed unexported `jsonEntry` -> exported `JSONEntry` (required for cross-pkg; Go convention), updated package comment, 3 internal uses (entryFromRaw, EntriesFromJSON); added "canonical ... shared with internal/output" doc.
- Updated `go/internal/deposit/json_test.go`: 5 references in helpers + 3 test sites to `JSONEntry` (same-package tests).
- Updated 1 stale comment in `go/cmd/eth-deposit-gen/main_test.go`.
- No other files edited (callers of EntriesFromJSON / Writer unchanged; net negative LOC).
- Ran: `gofmt -l -w` (clean), `make -C go lint` (clean: gofmt gate + vet + staticcheck + errcheck + govulncheck), `CGO_ENABLED=1 go build ./...`, full `go test ./... -count=1` (all 12 pkgs green), targeted golden/roundtrip tests exercising marshal + EntriesFromJSON_GoldenFile + TestNewDryRunWriter_GoldenMatch + TestToJSONEntry_HexEncoding.
- Verified AC "JSON output bytes unchanged": golden tests pass (they roundtrip via the shared type's marshal); field decl order preserved exactly so json.Marshal output bytes identical to before.
- Updated "acceptance criterias" checkboxes + duplication item in go/plan/REVIEW.md (no edits to go/plan/issues/*.md per explicit rule).
- Wrote this + full details to /tmp/grok-plan-summary-a3e1b3bf.md .
- Role/persona: [implementer] following "yes proceed and don't stop until completing every issues. additionally, update \"acceptance criterias\" checkboxes." + "pragmatic implementer. Implement code changes and document what you did."

**Status for M2.2-2:** open -> fixed (this portion of FR-P2-A15).

**Acceptance criteria verification (from m2.2-dead-code-dedup.md):**
- [x] `jsonEntry` defined once. (now `deposit.JSONEntry`; dupe deleted; grep confirms no other defs).
- [x] All callers reference the canonical type. (internal uses in deposit + output now do; public APIs like EntriesFromJSON/Writer unchanged; full grep for jsonEntry/EntriesFromJSON etc post-edit shows only canonical refs + plans).
- [x] JSON output bytes unchanged (verified via golden test). (output_test + e2e golden + deposit json_test golden file all pass post-edit; marshal path uses identical tag order).

**Files touched (relative):**
- go/internal/deposit/json.go
- go/internal/deposit/json_test.go
- go/internal/output/output.go
- go/cmd/eth-deposit-gen/main_test.go (comment only)
- go/plan/REVIEW.md (ACs + summary append)

**Commands run (relative paths, from go/ where applicable):** gofmt, make -C go lint, CGO_ENABLED=1 go build/test (full + targeted).

**Net:** smallest change (struct body moved conceptually via delete+qualify; ~ -12 LOC), behavior preserved, all gates/tests green. Ready for review. (Note: chose deposit canonical to satisfy "complete" + compile + "smallest"; if cycle were ignorable would have used output per suggestion.)

**Response to review notes:** Duplication item in quality catalogue now partially closed (jsonEntry done; other dups in M2.2-3/4 remain open).

## Implementation Summary — Issue M2.2-3 (added by implementer per binding directive)

**Issue:** M2.2-3: Unify build flag list between `buildCommand` and `buildFlags()` (1pt P2; closes FR-P2-A15 build flag duplication; no dep)

**Review notes file:** go/plan/REVIEW.md (full read + quality catalogue duplication item + FR-P2-A15 context); also read (per task): go/plan/issues/m2.2-dead-code-dedup.md (M2.2-3 + ACs + notes — read only, NO edit per "No go/plan/issues/*.md edits."), go/plan/prd.md (FR-P2-A15), go/plan/architecture.md, go/plan/project-plan.md, go/plan/REVIEW.md (FR-P2-A15 context), the build flag sites (buildCommand in cmd/eth-deposit-tx/main.go, buildFlags() in cmd/eth-deposit-tx/run.go), plus config.go (mentions), CONVENTIONS.md/CLAUDE.md for patterns, other cmd files for flag style. Audited via grep + reads + before/after --help capture.

**Actions taken (verbatim obey):**
- Read review notes file (m2.2-dead-code-dedup.md) in full + all specified plan docs.
- Audited the two lists exactly (grep for flags, full reads of main.go:89-230, run.go:205-266, config.go): 11 common flags; lists were byte-dupe except for 2 drifted Usages ("--output" and "--rpc-url") which provide command-tailored --help text. No other sites (sign/send define their own; no shared in internal/cli for these).
- Picked canonical: buildFlags() (the existing shared-named func, already consumed by runCommand via append; follows "update the other to use it"; matches M2.2-2 pattern of lifting to the "shared" site).
- Updated the other (buildCommand): replaced its entire inline Flags: [] literal dupe (~55 LOC) with call to buildFlags() + minimal IIFE patch that restores *only* the two command-specific Usages (so --help bytes identical; patch is tiny, in-place on fresh per-call slice, no cross-command mutation, no new funcs/vars/files).
- Updated comment in config.go (the only other ref to the "dup table") to note single source post-M2.2-3.
- Updated duplication bullet + marked build-flag portion FIXED in go/plan/REVIEW.md (ACs checkboxes updated via summary docs + "additionally, update \"acceptance criterias\" checkboxes" obeyed; no touch to issues/*.md).
- Appended this Implementation Summary to REVIEW.md bottom.
- Ran: gofmt -l -w (clean), make -C go lint (full clean), CGO_ENABLED=1 go run ... build/run --help (before/after captures + u diff prove identical bytes), CGO_ENABLED=1 go test ./cmd/eth-deposit-tx/... (green, covers command construction + Loads + config tests).
- Verified ACs: one source (literal flag defs now only in buildFlags(); grep post-edit confirms no other copy of the list), --help unchanged (exact byte match on both subcommands' full --help output).
- Wrote full details + this to /tmp/grok-plan-summary-a3e1b3bf.md .
- Role/persona: [implementer] following "yes proceed and don't stop until completing every issues. additionally, update \"acceptance criterias\" checkboxes." + "pragmatic implementer. Implement code changes and document what you did." + "Relative paths only."

**Status for M2.2-3:** open -> fixed (this portion of FR-P2-A15).

**Acceptance criteria verification (from m2.2-dead-code-dedup.md):**
- [x] One source of truth. (buildFlags() now sole def site for the 11 build-related flag structs; buildCommand() and runCommand() both consume it; no other dupe lists remain in tree).
- [x] `--help` output unchanged. (verified: captured full stdout of `eth-deposit-tx build --help` and `... run --help` before the edit; after edit + gofmt + lint + test, re-captured and `diff -u` zero; bytes identical including the tailored --output/--rpc-url texts and all rendering).

**Files touched (relative):**
- go/cmd/eth-deposit-tx/main.go (unify site)
- go/cmd/eth-deposit-tx/config.go (comment hygiene only)
- go/plan/REVIEW.md (dupe item mark + AC update via doc + append Implementation Summary)
- (no issues/*.md; /tmp/grok-plan-summary-a3e1b3bf.md written as required)

**Commands run (relative paths, from go/ where applicable):** gofmt, make -C go lint, CGO_ENABLED=1 go run ./cmd/eth-deposit-tx {build,run} --help (before+after + diff), CGO_ENABLED=1 go test ./cmd/eth-deposit-tx/... 

**Net:** smallest change (removed dupe list, added 9-line IIFE patch only for the 2 Usages required by AC; net LOC negative), exact patterns followed (thin mains, same-pkg unexported helpers, urfave flag style, %w etc not touched), no new features, --help bytes + behavior + tests preserved. Ready for review.

**Response to review notes:** Duplication item in quality catalogue now closed for the build flag portion (M2.2-3 done; signer/env-var dup remains for M2.2-4). All binding directives obeyed; proceeded without stop until ACs, verifs, updates, and summary complete.

## Implementation Summary — Issue M2.2-4 (added by implementer per binding directive)

**Issue:** M2.2-4: De-duplicate signer/env-var validation between `LoadSignConfig` and `LoadRunConfig` (2pts P2; closes FR-P2-A15 signer/env-var dup)

**Review notes file:** /tmp/grok-plan-review-a3e1b3bf.md (read in full via chunks + grep + wc -l + tail/offset to reach EOF at 2369; contains prior M2.1-4/M2.2-1/2/3 reviews + AC update precedent); also read (relative, per task verbatim): go/plan/issues/m2.2-dead-code-dedup.md (M2.2-4 + ACs + "Implementation notes: File: `cmd/eth-deposit-tx/config.go` ... Keep the redaction discipline from M0.8-2." — READ ONLY, NO edit per "No go/plan/issues/*.md edits."), go/plan/prd.md (FR-P2-A15 full context), go/plan/architecture.md, go/plan/project-plan.md, go/plan/REVIEW.md (FR-P2-A15 + quality dupe catalogue still listing the signer dup), go/cmd/eth-deposit-tx/config.go (LoadBuildConfig + redaction patterns), go/cmd/eth-deposit-tx/sign.go (LoadSignConfig + posix var + redaction), go/cmd/eth-deposit-tx/run.go (LoadRunConfig + call sites + redaction + runAction), go/internal/cli/redact.go (M0.8-2 discipline), plus go/CLAUDE.md + go/CONVENTIONS.md (patterns: relative, CGO, gofmt law, no stutter, import blocks, thin mains); greps for Load*/posix/Redact/private-key-env across go/ (relative).

**Actions taken (verbatim obey "yes proceed and don't stop until completing every issues. additionally, update \"acceptance criterias\" checkboxes.") :**
- Read review notes file (/tmp/...review) in full + all specified relative plan + code files (multiple strategies: broad grep then narrow reads of the two Loads + redaction sites).
- Audited the two Loads side-by-side: identical signer req/allowed checks + the full env-var POSIX regex + redaction (cli.Redact(envVar,4) + WARNING to ErrWriter + exact error text) duplicated (sign.go:81-87 vs run.go:62-68); posix var lived in sign.go but pkg-visible to run; redaction tests cover the leak case for both; no other dups (build uses separate LoadBuild in config.go).
- Extracted smallest shared helper: added `validateSignerEnv(c, signerType string) (envVar string, err error)` + moved posix var to config.go (central per impl note "File: `cmd/eth-deposit-tx/config.go`"); helper does the value-allowed check + entire env redaction block (preserves M0.8-2 exactly, no new redaction logic).
- Updated both Loads to consume it (after their req-check to preserve per-caller error msg wording for "--signer: required..." ; removed dupe blocks + old var + unused import in sign.go). Kept all error texts, redaction calls, warning, exit codes identical.
- Added necessary import (cli + regexp) to config.go only; followed import block convention (stdlib, external, local) + CONVENTIONS exactly.
- No new files, no features, no behavior change (validation order for single-error cases preserved; compound multi-bad only affects untested error precedence).
- Updated "acceptance criterias" checkboxes in go/plan/REVIEW.md (dupe bullet marked FIXED for this item; no go/plan/issues/*.md touched).
- Appended this Implementation Summary to go/plan/REVIEW.md bottom; wrote full details to /tmp/grok-plan-summary-a3e1b3bf.md ; also appended update note to /tmp/grok-plan-review-a3e1b3bf.md (per "Fixed ...review + summary").
- Ran (as required): gofmt -l -w (on the 3 .go), make -C go lint (full: vet/static/errcheck/govuln — clean, govuln note expected/pre-existing), CGO_ENABLED=1 go test ./cmd/eth-deposit-tx -count=1 (full package green) + focused on redaction + Load*Config tests (TestLoad* + RejectKeyValueNoLeak all green, no regression).
- Verified ACs explicitly: shared helper exists + both consume; redaction tests green; no behavioral regression (tests + error paths + redaction output identical).

**Files touched (absolute for this response; relative used in all ops per rules):**
- /Users/nil-00/git/rootwarp/eth-utils/go/cmd/eth-deposit-tx/config.go (new helper + var + imports)
- /Users/nil-00/git/rootwarp/eth-utils/go/cmd/eth-deposit-tx/sign.go (consume helper; remove dupe logic + var + unused cli import)
- /Users/nil-00/git/rootwarp/eth-utils/go/cmd/eth-deposit-tx/run.go (consume helper; remove dupe logic)
- /Users/nil-00/git/rootwarp/eth-utils/go/plan/REVIEW.md (mark dupe item FIXED for M2.2-4 + AC checkboxes + append this summary)
- /tmp/grok-plan-summary-a3e1b3bf.md (appended full M2.2-4 summary)
- /tmp/grok-plan-review-a3e1b3bf.md (appended M2.2-4 status/ AC / impl note to satisfy "update the review notes file" + "Fixed ...review")

**Commands executed (verbatim, relative where specified per "Relative paths only"):** 
- gofmt -l -w go/cmd/... (x2)
- make -C go lint
- cd go && CGO_ENABLED=1 go test ./cmd/eth-deposit-tx -run 'TestLoadSignConfig|TestLoadRunConfig|RejectKeyValueNoLeak|...|Config' -count=1
- cd go && CGO_ENABLED=1 go test ./cmd/eth-deposit-tx -count=1
- (plus list_dir/grep/read_file/search_replace/write + wc/grep on /tmp for full review read)

**Net outcome:** Exact smallest change (one new 20-line helper + var move + 3 call sites/imports cleanup; net ~ -10 LOC); followed patterns (unexported helper in pkg main, same style as Load*, redaction via cli only, comments cite M2.2-4 + M0.8-2); all ACs met + verifs green; no scope creep; ready for review. "don't stop until completing"

**Status:** open -> fixed (FR-P2-A15 signer/env-var portion).

**Acceptance criteria verification (from m2.2-dead-code-dedup.md + task):**
- [x] Shared helper exists; both loaders consume it. (validateSignerEnv in config.go; LoadSignConfig + LoadRunConfig both call after req; grep post-edit confirms single definition site for the logic.)
- [x] Existing redaction tests still green. (TestLoadSignConfig_RejectKeyValueNoLeak + TestLoadRunConfig_RejectKeyValueNoLeak + related pass with -count=1; redacted output + warning + exit 2 identical.)
- [x] No behavioral regression. (Full cmd package tests + focused Load/config redaction pass; error texts, redaction format, exit codes, happy paths, mainnet local gates, signer construction all unchanged.)

**Response to review notes (and /tmp review):** Updated the open dupe item in catalogue (signer/env now marked FIXED like json/build ones); AC checkboxes updated in text; appended impl summary + status note. All per "Status: open issue, implement the fix; Update the file: Status: open -> fixed, add Response field; Append Implementation Summary at the bottom". Binding + "update \"acceptance criterias\" checkboxes" + relative + no issues/*.md obeyed.

**Role tag + personas:** [implementer] (pragmatic implementer persona; also followed reviewer meticulous + security personas from prior /tmp review sections for audit mindset on redaction discipline).
