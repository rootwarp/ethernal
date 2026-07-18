# Keygen issues — index

Sprint-ready issue files for the validator key-generation feature (`key new` / `key recover`, K5 `gen`
withdrawal credentials). Detail derived from the approved [`../project-plan.md`](../project-plan.md),
[`../architecture.md`](../architecture.md), [`../prd.md`](../prd.md), and [`../research/`](../research/).
**14 issues · 23 points.** Phase files: [`phase-k1.md`](phase-k1.md) · [`phase-k2.md`](phase-k2.md) ·
[`phase-k3.md`](phase-k3.md) · [`phase-k4.md`](phase-k4.md) · [`phase-k5.md`](phase-k5.md).

## All issues

| ID | Title | Pts | Stream | Depends on | Milestone |
|---|---|---|---|---|---|
| K1-1 | `core::bip39` — pinned wordlist, entropy→mnemonic+checksum, `validate_mnemonic` (12–24, NFKD), `to_seed` (PBKDF2-HMAC-SHA512×2048) + Trezor vectors | 2 | A | — | M-K1 |
| K1-2 | `core::hd` — EIP-2334 `KeyPath`, EIP-2333 master/child/path via `blst`, pubkey derivation + four EIP-2333 vectors | 1 | A | — | M-K1 |
| K1-3 | `core::entropy` — `getrandom` dep (D-1), `Entropy` trait + `OsEntropy` + `EntropyError` | 1 | A | — | M-K1 |
| K2-1 | `keystore::crypto` refactor + `keystore::encrypt` — pure EIP-2335 v4 scrypt writer, declaration-order `Serialize`, UUID-v4, filename; spec vector byte-for-byte + Loader round-trip + wrong-passphrase reject | 3 | B | — | M-K2 |
| K2-2 | `core::output::write_new_0600` — generic atomic 0600 write, `create_new` refuse-overwrite, `OutputError::AlreadyExists` | 1 | B | — | M-K2 |
| K2-3 | `keystore::passphrase::NewKeystorePassphrase` — confirm-twice + ≥8-char source; `require_min_len` on the env path (keygen-only) | 1 | B | — | M-K2 |
| K3-1 | bin `key` CLI surface — clap namespace, `KeyConfig`, `--count`/`--output-dir`/`--start-index`, three-form `--mnemonic-passphrase`, `validate_output_dir`, non-TTY `new` guard, dispatch | 2 | A | — | M-K3 |
| K3-2 | bin `key new` runtime — mnemonic-passphrase resolution, display + full re-entry ceremony, derive→encrypt→write pipeline, `KeyDeps` seam, SIGINT, progress/summary | 3 | A | K3-1, K1-1, K1-2, K1-3, K2-1, K2-2, K2-3 | M-K3 |
| K3-3 | bin `key recover` — TTY-or-piped-stdin mnemonic (no ceremony), `validate_mnemonic` first, `--start-index`/`--count` range, reuse pipeline | 2 | A | K3-2 | M-K3 |
| K3-4 | exit/error mapping + secret-hygiene test — `Bip39→2`, `Hd→3`, encrypt→3, `Aborted→4`, call-site `Exit{3}` for write; secrets never on stdout/stderr/logs | 1 | A | K3-2, K3-3 | M-K3 |
| K5-1 | `signer::validate_eip55_address` (`pub`, strict) + `core::deposit::eth1_withdrawal_credentials` (`0x01‖0×11‖addr20`) | 1 | B | — | M-K5 |
| K5-2 | `gen --withdrawal-address` + require-choice gate (absent → exit 2) threaded into `Request`; gate + flag one release | 2 | B | K5-1 | M-K5 |
| K4-1 | in-binary E2E + fixtures — fixed mnemonic + `-env=TREZOR` → `key recover` → keystores → `gen --withdrawal-address` (BLS-verify) → deposit data; one fixture chains BIP-39→EIP-2333→EIP-2335→deposit | 2 | A | K3-4, **K5-2** | M-K4 |
| K4-2 | docs — USER-GUIDE "Step 0 — create validator keys" (incl. raw-passphrase `ps`/history note), README, CHANGELOG (breaking `gen` require-choice) | 1 | B | K4-1 | M-K4 |

**Total: 23 points** (≈ 11.5 person-days single-dev). Critical path ≈ 14 pts (stream A: K1 → K3 → K4-1);
stream B's 9 pts (keystore, `gen` creds, docs) overlap.

## Execution order

Phase numbers are **thematic**; the `Depends on` column drives order. Because **K4-1 depends on K5-2**, K5
runs before K4 so the E2E deposit-data fixture freezes **once** against the require-choice `gen` (never a
placeholder-cred fixture). Effective order:

**K1 → K2 / K3 → K5 → K4.**

## Milestone gates

| Milestone | Issues | Exit criterion |
|---|---|---|
| M-K1 | K1-1..3 | BIP-39 Trezor vectors (incl. `abandon×23 art` + `TREZOR`) **and** four EIP-2333 vectors green; wordlist sha256 pin (`2f5eed53…`) asserted |
| M-K2 | K2-1..3 | EIP-2335 scrypt spec vector reproduced byte-for-byte (injected salt/iv/uuid, non-ASCII NFKD pw); created keystore round-trips through the existing `Loader`; wrong passphrase rejected; `write_new_0600` refuses overwrite |
| M-K3 | K3-1..4 | `key new`/`recover` green incl. display + full re-entry (mismatch → retry/abort exit 4), non-TTY `new` → exit 2, 12–24-word + piped-stdin `recover`; secret-hygiene test green |
| M-K5 | K5-1..2 | `gen --withdrawal-address <checksummed>` emits 0x01 creds; `gen` with no withdrawal choice → exit 2; EIP-55 lowercase/mismatch → exit 2 (gate + flag one release) |
| M-K4 (final) | K4-1..2 | with K5 merged, `key recover → gen --withdrawal-address` E2E byte-stable (0x01 creds, BLS-verify on); one manual cross-tool session recorded; docs done |

## Conventions (all issues)

- Per-issue commits tagged `[K#-#]` on `develop`; fast-forward merges; every merge green (`make test && make lint`).
- Every acceptance criterion is executable/checkable and cites the requirement ID(s) it satisfies plus the
  concrete vector/fixture (a named test passes, a spec vector reproduces, a `grep` for secret bytes comes back
  empty). Long hex lives in `../research/`; issues cite the doc + section and inline only the short anchors
  (wordlist `2f5eed53…`, chain-anchor seed `c55257c3…463b04`).
- Paths are repo-root-relative (`crates/core/src/…`, `bins/eth-deposit/src/…`), matching the architecture doc and
  the actual layout (crates live at the repo root, **not** under `rust/`).

## Gaps & sizing notes flagged during estimation

No issues were added, merged, split, or re-pointed — the list is exactly the issues of the approved plan. The
following were surfaced while detailing them:

1. **Issue count is 14, not 13 (points unaffected at 23).** The task brief and the `project-plan.md` prose say
   "13 issues", but the plan's canonical "All issues" table enumerates **14**: K1×3, K2×3, K3×4, K5×2, K4×2,
   summing to the stated 23 pts. The "13" appears to miscount K3 (which has four issues: K3-1..K3-4). No issue was
   invented, merged, or split here — all 14 are detailed straight from the canonical table, and the point total is
   unchanged. Flagging per the "detail exactly these; flag real gaps rather than change the list" instruction.

2. **New fixture required for the M-K2 byte-gate (not a pre-existing file).** The existing
   `crates/keystore/testdata/keystore-scrypt.json` is **not** the EIP-2335 scrypt spec vector — it uses `n:4` (a
   deliberately weak/fast fixture for the decrypt tests), salt `615dbe34…`, iv `8375eae1…`, uuid `…-0001`. K2-1
   must **add** the real spec vector (`n:262144`, salt `d4e56740…`, secret `0x…19d668…8ce26f`) as a new fixture
   `crates/keystore/testdata/eip2335-scrypt-vector.json`, which the byte-for-byte gate points at. Captured in K2-1's
   implementation notes + acceptance criteria; no point change.

3. **K3-2 is at the 3-pt cap with a seven-way fan-in** (K3-1, K1-1, K1-2, K1-3, K2-1, K2-2, K2-3). Kept intact:
   the plan already split K3 into scaffolding (K3-1) + runtime (K3-2), and the task forbids further splitting.
   Called out so schedulers treat it as the integration bottleneck, not underestimate it.

4. **K1-2 depends on `—`, not K1-1** (the overview skeleton had K1-2 → K1-1). Confirmed correct and left as the
   project plan specifies: `core::hd` is pure over raw seed bytes and is gated by the EIP-2333 vectors directly, so
   it needs nothing from `bip39`; the BIP-39→EIP-2333 join is proven at K4-1.

5. **UUID-v4 formatter placement.** The overview put the UUID formatter in K1-3 (entropy); the approved
   architecture/plan moved it **into K2-1** (`keystore::encrypt` formats the UUID from its `uuid_bytes` input).
   Issues reflect this: K1-3 is entropy-only; the 16 UUID bytes are just another `Entropy::fill` draw in the bin.

6. **Three-form `--mnemonic-passphrase` clap mechanics are underdetermined at the flag level.** Resolved with
   codebase-consistent calls in K3-1's Notes: `num_args(0..=1)` distinguishes bare-prompt from raw-value; the raw
   and env forms are `conflicts_with` each other; the env form reads the named var raw (Zeroizing, no min-length),
   with an **unset** var → exit 2 and an **empty** value accepted (empty is valid for the mnemonic passphrase, F-12).
   No point change.
