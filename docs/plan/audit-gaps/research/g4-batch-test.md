# Research: G4 — Batch-distinctness regression test (GHSA-c6rv-g6pj-r6qx / ETHSTAKER-6)

## Verdict
Fully feasible with **zero product-code change** — both `key recover` and `account recover` already
take `--count` + `--start-index` and are driven by the existing stdin-pipe harnesses; a real-entropy
`--count 3` batch naturally yields distinct salt/IV/UUID. One **spec correction**: the EOA (v3)
keystore has **no `uuid` field — it is top-level `id`**; PRD G4-2's "uuid" for the EOA path is wrong,
the test must read `v["id"]`. Confidence: **High** (root cause corroborated by the post-fix upstream
`keystore.py`; JSON field paths and harness reuse verified against local source this session).

## What exactly regressed upstream (the class G4 guards)

- **Root cause — Python "default argument evaluated once" footgun.** In `keystore.py`,
  `Keystore.encrypt()` took the scrypt salt and AES IV as keyword parameters whose **default values
  were computed with `randbits(...)`**. Python evaluates default argument values **once, at
  function-definition (import) time** — so every keystore produced in a single process that relied on
  the defaults reused the **same salt and the same IV**. Batch commands (`new-mnemonic` /
  `existing-mnemonic` with count > 1) hit exactly this path. [1][2]
- **Corroboration (post-fix code, fetched this session):** the current
  `ethstaker_deposit/key_handling/keystore.py` now uses the canonical remediation of that footgun —
  `Optional[bytes] = None` defaults and per-call generation in the body:
  ```python
  self.crypto.kdf.params['salt'] = kdf_salt if kdf_salt is not None else randbits(256).to_bytes(32, 'big')
  keystore.crypto.cipher.params['iv'] = aes_iv if aes_iv is not None else randbits(128).to_bytes(16, 'big')
  keystore.uuid = str(uuid4())
  ```
  (`uuid` was generated per call via `uuid4()`, so the reused values were **salt + IV**.) [3]
- **Cryptographic impact.** All keystores in a batch share one operator password. Reused **salt** →
  identical scrypt output → identical AES-128 key across the batch; reused **IV** with an identical
  key → identical AES-128-**CTR keystream**. XOR of any two batch ciphertexts equals the XOR of the
  two 32-byte secret keys — and because the plaintexts are structured validator secret keys with a
  verifiable keystore checksum, an attacker who leaks **multiple** batch files can recover the secret
  keys **without the password**. "Low number of leaked files → needs more compute than most have;
  more leaked files → trivial." [1][2] Reused salt additionally collapses the scrypt work factor:
  one cracking effort covers the whole batch.
- **Affected/fixed:** ethstaker-deposit-cli ≤ 0.5.0 (fixed 0.6.0), staking-deposit-cli ≤ 2.7.0 (fixed
  2.8.0), Wagyu Key Gen ≤ 1.10.0 (fixed 1.11.x). [1][2]

## The test that would have caught it (and how peers guard it)
- **Behavioral guard (what G4 adds):** generate a batch (count > 1) in one run and assert the salt,
  IV, and UUID are **pairwise distinct** across all files. This is the minimal, deterministic,
  password-independent check — a single such assertion turns the catastrophic class into a caught
  regression. It is exactly what the upstream bug defeated.
- **Structural guard (how the fix is enforced upstream):** move generation inside the function
  (`= None` default + `if x is None: x = randbits(...)`), so the type system/flow guarantees a fresh
  draw per call [3]. ethernal already does this at the *call site* — fresh CSPRNG per keystore inside
  the loop — so G4 is the **behavioral** complement that a future refactor can't silently break.
- **Peer coverage (checked this session):** upstream's guard for this class is primarily the
  *structural* fix (per-call generation) plus **single-call** unit tests that a fresh IV is drawn —
  `test_encrypt_decrypt_scrypt_random_iv` and `test_encrypt_decrypt_pbkdf2_random_iv` in
  `tests/test_key_handling/test_keystore.py`. Neither that file nor `tests/test_credentials.py`
  contains a **cross-batch pairwise-distinctness** assertion [6]. So ethernal's `--count 3` E2E check —
  comparing the *emitted JSON* salt/IV/UUID pairwise across a real batch — is **stronger than
  upstream's own regression coverage** for the GHSA class, not merely equivalent.

## ethernal is already correct (why this is test-only)
- Fresh CSPRNG `salt`/`iv`/`uuid` per keystore **inside** the loop: `bins/ethernal/src/key_cmd.rs:344-351`
  (BLS), `bins/ethernal/src/account_cmd.rs:351-358` (EOA).
- The keystore encrypt modules take already-drawn `salt`/`iv`/`uuid_bytes` and **do not** draw RNG
  themselves — and the code literally documents the footgun: `crates/ethernal-keystore/src/encrypt.rs`
  lines 25-28: *"this module does not draw RNG … Reusing salt or IV across encrypts is a crypto
  footgun; reusing `uuid_bytes` collides …"* So the risk is designed out at the module boundary; G4
  guards the loop that feeds it.

## Local feasibility — the harness is directly reusable
- **`--count` + `--start-index` confirmed on both surfaces** (`key_cli.rs:151` `shared_args`, `count`
  default 1 must be ≥ 1, no upper bound; `start-index` on recover). `account recover` reuses the same
  shared args (eoa-keystore F-8). Both `key recover` and `account recover` are exercised at
  `--count 2` today.
- **Reuse the existing helpers verbatim, bump to 3:**
  - BLS: `bins/ethernal/tests/key_e2e.rs` → `run_key_recover(out_dir, count)` pipes the fixed
    `abandon…about` mnemonic over stdin, sets `--passphrase-env` + `--mnemonic-passphrase-env`.
  - EOA: `bins/ethernal/tests/account_e2e.rs` → `run_account_recover(out_dir, count)` pipes the same
    mnemonic (empty mnemonic passphrase), sets `--passphrase-env`.
  - Add a new `#[test]` in each file that calls the helper with `count = 3` and asserts distinctness.
- **Real OS entropy, not `FixedEntropy`.** The recover path uses OS CSPRNG for salt/IV/UUID (only the
  mnemonic is fixed) — so a `--count 3` batch produces distinct values by construction. There is **no
  entropy-injection flag on the CLI** (enforced by `key_recover_help_has_no_entropy_flag` /
  `account_recover_help_has_no_entropy_or_time_flag`, S-4), which is exactly why G4-4 says: if you
  want to *prove the test bites*, temporarily patch the product entropy source to fixed bytes and
  rebuild **locally** (never commit), confirm the new test goes red, then revert. The harness cannot
  toggle `FixedEntropy` via a flag — and must not gain one.

## Exact JSON field paths to assert (verified from source)

| Field | BLS v4 (EIP-2335) — `encrypt.rs` | EOA v3 (geth) — `encrypt_v3.rs` |
|---|---|---|
| salt | `crypto.kdf.params.salt` | `crypto.kdfparams.salt` |
| IV | `crypto.cipher.params.iv` | `crypto.cipherparams.iv` |
| UUID | top-level **`uuid`** | top-level **`id`**  ⚠️ not `uuid` |
| identity | `pubkey`, `path` | top-level `address` |

- **PRD G4-2 correction:** it lists "uuid" for the EOA path; the v3 serializer emits `id`
  (`encrypt_v3.rs:182` `id: format_uuid_v4(...)`), confirmed by the existing test reading `v["id"]`
  (`account_e2e.rs:343`). Assert `v["id"]`, not `v["uuid"]`, for EOA.
- Filenames already differ per index (no collision to mask a bug): BLS
  `keystore-m_12381_3600_<i>_0_0-<ts>.json` (index in name); EOA `UTC--<ts>--<address>.json` (address
  per index). The same-second-collision retry (DEP-009 mitigation, `key_cmd.rs:569`) guarantees three
  distinct files even within one wall-clock second.

## Implications for implementation
1. **Add distinctness by reading JSON fields — do NOT decrypt.** Distinctness is a byte comparison of
   `salt`/`iv`/`uuid|id`; decrypting 3 scrypt keystores per path just to compare fields is wasted
   cost. Read the raw JSON (as the existing tests already do) and compare. Keep the expensive
   `Loader::load` round-trip only where an existing test already does it (count 2). Runtime stays
   bounded (scrypt hits only at *encrypt* time for the 3 files the CLI writes).
2. **Assert the EOA UUID via `v["id"]`** (spec correction above), plus `salt`/`iv`/`address`; BLS via
   `v["uuid"]` plus `salt`/`iv`/`pubkey`.
3. **Pairwise, not adjacent** (G4-3): collect each field across all files and assert the set size ==
   file count (or nested-loop all pairs). Also assert `files.len() == 3` first and fail loudly if
   fewer (a partial-write bug must not pass).
4. **One new `#[test]` per file, reusing `run_key_recover` / `run_account_recover`** with `count = 3`
   — least churn, matches the harness the PRD points at. Also assert distinct `pubkey`/`path` (BLS)
   and `address` (EOA) to confirm three different validators/accounts were produced (sanity that the
   loop ran, not just three copies).
5. **Zero product-code diff** (G4-4): the change is confined to `bins/ethernal/tests/`. If a
   real-entropy batch somehow can't be reached, escalate — do not weaken to `FixedEntropy`.
6. Document (in the test comment) the local "wire fixed entropy + rebuild to see it go red" procedure
   so a future maintainer knows how to trust the guard without shipping an entropy flag.

## Sources
[1] [GHSA-c6rv-g6pj-r6qx — "Insecure keystore files from improper cryptographic initialization" (ethstaker/ethstaker-deposit-cli security advisory)](https://github.com/ethstaker/ethstaker-deposit-cli/security/advisories/GHSA-c6rv-g6pj-r6qx) — root cause in `keystore.py` `encrypt`; batch reuse; leak-scaling impact; affected/fixed versions. Primary (advisory), fetched this session.
[2] [Security Alert: Ethereum Staking Keystore Vulnerability — Blockops Network (0hx)](https://medium.com/blockops/security-alert-ethereum-staking-keystore-vulnerability-c0e11fd8db00) — secondary narrative of the salt/IV batch reuse and impact. Blog (redirected to blog.blockops.network → Medium identity loop; not fully re-parsed this session — used for corroboration only).
[3] [ethstaker-deposit-cli `keystore.py` (main)](https://github.com/ethstaker/ethstaker-deposit-cli/blob/main/ethstaker_deposit/key_handling/keystore.py) — post-fix `Keystore.encrypt`: `salt`/`aes_iv` `Optional=None` + per-call `randbits(...)`, `uuid4()` per call. Primary (repo source), fetched this session — corroborates the evaluated-once-default-arg root cause.
[4] Local source (read this session): `key_cmd.rs:344-351` / `account_cmd.rs:351-358` (per-keystore CSPRNG loop), `encrypt.rs:25-28` (footgun documented) & serialize structs, `encrypt_v3.rs:168-183` (`cipherparams.iv` / `kdfparams.salt` / `id` / `address`), `key_e2e.rs::run_key_recover`, `account_e2e.rs::run_account_recover`, `key_cli.rs:151` shared `--count`/`--start-index`. Primary (repo).
[5] Vault audit note — *Audit: ethernal … deposit-cli and EOA Keystore Issues* (`1.Projects/ethernal/202607181903…`): GHSA-c6rv row = ✅ Mitigated; gap 4 = missing batch-distinctness regression test. Primary (project audit).
[6] [ethstaker-deposit-cli `tests/test_key_handling/test_keystore.py`](https://github.com/ethstaker/ethstaker-deposit-cli/blob/main/tests/test_key_handling/test_keystore.py) and [`tests/test_credentials.py`](https://github.com/ethstaker/ethstaker-deposit-cli/blob/main/tests/test_credentials.py) — fetched this session: single-call "random IV" tests + structural fix, **no cross-batch pairwise-distinctness assertion**. Primary (repo tests).
