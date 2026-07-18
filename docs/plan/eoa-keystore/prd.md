# PRD — EOA Keystore Generation (`ethernal account new` / `account recover`)

**Status:** approved at the PRD gate (user, 2026-07-18) with two binding vetoes applied — Q1 (new `account` namespace, not a `key --type` flag) and Q3 (`sign --keystore` consumption is a follow-up, not v1). See [Open questions](#open-questions--resolved-at-the-prd-gate).
**Sibling precedent:** [`../keygen/prd.md`](../keygen/prd.md) — the BLS validator-key feature this one mirrors. That PRD owns the `key new` / `key recover` ceremony, the requirement-ID style (F-\*/S-\*/C-\*/…), and the P0/P1/P2 convention reused here. Where a requirement is identical to the BLS feature, this PRD says "as BLS" rather than restating it.
**House style:** the BLS keygen shipped, was reviewed, and hardened (H1–H9, [`../keygen/hardening-plan.md`](../keygen/hardening-plan.md)). Those security decisions are the baseline; this feature is **born compliant** (see [Security invariants](#security-invariants-non-negotiable)), not hardened after the fact.
**Scope in one line:** add a **new top-level `account` namespace** (`ethernal account new` / `account recover`) for secp256k1 EOA (externally-owned account) keys — BIP-39 mnemonic → BIP-32/BIP-44 (`m/44'/60'/0'/0/i`) derivation → **Web3 Secret Storage v3** keystores that geth, foundry (`cast`), and MetaMask import and unlock. In-binary consumption (`ethernal sign --keystore`) is an explicit follow-up, out of v1.

---

## Problem statement

`ethernal` signs Ethereum transactions with an EOA key, but it has no way to *hold* one safely. Today the only local signer (`ethernal sign --signer local`) reads a **raw, unencrypted hex private key from an environment variable** (`ETHERNAL_TX_PRIVATE_KEY`), documented as development/CI-only, with Ledger the only path for real funds (`bins/ethernal/src/sign_cmd.rs:18`, `crates/ethernal-signer/src/local.rs:66-73`). There is no encrypted-at-rest EOA key anywhere in the binary.

The BLS side already solved the equivalent problem: `ethernal key new` / `key recover` generate validator keys from a mnemonic and write encrypted EIP-2335 keystores. EOA keys have no counterpart. Two concrete gaps follow:

1. **No EOA key origin.** There is no way to generate or recover a secp256k1 account key from a mnemonic inside `ethernal`; operators reach for MetaMask, foundry, or geth and then hand the raw key to `ethernal` through an env var.
2. **No encrypted EOA key at rest.** The only local-signing input is a plaintext key in the environment — unencrypted, visible to the process table's environment, and easy to leak into shell history or logs. There is no passphrase-protected keystore an operator can commit to disk.

This feature closes both gaps by mirroring the BLS flow for secp256k1: generate or recover an EOA key from a mnemonic and encrypt it as a standard Web3 v3 keystore that geth, foundry, and MetaMask can import and unlock. Wiring `ethernal sign` to consume that keystore in-binary — so a real-fund software key never has to live as a raw env var — is a planned, explicitly-scoped follow-up (see [Non-goals](#non-goals)); v1 delivers the encrypted-at-rest, interoperable key that the follow-up then consumes.

## Target users

Operators and developers who sign Ethereum transactions with a software EOA key and want it encrypted at rest and interoperable with their existing tooling (geth, foundry/`cast`, MetaMask). They are security-sensitive, frequently generate keys on an **air-gapped** machine, and expect the same mnemonic-handling discipline the BLS feature already enforces: the mnemonic and derived secrets must never escape the process via stdout, stderr, logs, or a non-interactive stream. Distinct from the BLS target user (a validator operator preparing a deposit), though often the same person: the same mnemonic can back both validator keys and an account key.

## Goals & success metrics

| # | Success metric | How measured |
|---|---|---|
| G1 | Keystores we write import cleanly into mainstream EOA tooling | Manual per-release cross-tool session: a created keystore imports and unlocks in ≥ 1 of geth (`account import`), foundry (`cast wallet import`), MetaMask (JSON import) |
| G2 | Address parity with reference wallets | Same mnemonic (+ mnemonic passphrase) into a reference BIP-44 wallet (foundry `cast wallet` / MetaMask) → derived **addresses** match ours index-for-index across the tested range |
| G3 | Deterministic keystore reproduction (CI correctness anchor) | With injected salt/iv/uuid, our v3 encrypt reproduces a reference Web3 v3 keystore's `crypto` object — including the Keccak-256 `mac` — byte-for-byte in CI. This is the automated proof of encrypt correctness given that v1 has no in-binary decrypt/consume loop (deferred with `sign --keystore`) |
| G4 | Spec conformance | BIP-32 (SLIP-0010/BIP-32 secp256k1 vectors), BIP-44 path derivation, and a Web3 Secret Storage v3 (scrypt) **encrypt-reproduction** vector (byte-for-byte per G3/C-1 — no decrypt round-trip, since v1 ships no v3 reader) all green in CI |
| G5 | Zero secret leakage | Automated hygiene test asserts mnemonic / seed / chain-code / secret-key / passphrase bytes never reach stdout, stderr, or logs (reuses the BLS hygiene harness) |

---

## Functional requirements

Priority: **P0** = ship-blocking core; **P1** = required for the feature to be complete per the binding decisions; **P2** = polish, non-blocking. IDs continue the F-\* series; requirements that mirror a BLS F-\* cite it.

### P0 — EOA keygen, v3 keystores, and the account ceremony

| ID | Requirement |
|---|---|
| F-1 | `ethernal account new` generates a fresh 24-word English BIP-39 mnemonic from 256-bit OS-CSPRNG entropy with a valid checksum, reusing the existing `core::bip39` generator and the same display-once/re-entry ceremony the BLS `key new` uses (mirrors BLS F-1). `account` is a **new top-level namespace**; the existing `key new` / `key recover` (BLS) commands are untouched and gain no `--type` flag. |
| F-2 | Derive the account signing key per index using **BIP-32 secp256k1** master derivation over the existing BIP-39 seed (`core::bip39::to_seed`, unchanged) and the **BIP-44 path `m/44'/60'/0'/0/i`** (`i` = the BIP-44 `address_index`; the `account'` level stays fixed at `0'` — MetaMask surfaces `address_index` to users as "Account i"). Correctness gated by BIP-32/BIP-44 published vectors. Derive the corresponding Ethereum address (`keccak256(uncompressed_pubkey[1..])[12..]`, EIP-55 checksummed) via the existing `ethernal-signer` helpers. |
| F-3 | Encrypt each secp256k1 secret key as a **Web3 Secret Storage v3** keystore (`version: 3`, `crypto.cipher = aes-128-ctr`, `crypto.kdf = scrypt`, **`crypto.mac = keccak256(dk[16..32] ‖ ciphertext)`**, top-level `address` field, `id` = UUID v4). This is a **new writer** — it is *not* the EIP-2335 v4 path (v4 uses a `sha256` checksum, a `pubkey`/`path` field, and `version: 4`; the existing `keystore::encrypt` and `keystore::Loader` are BLS-only and stay so). scrypt parameters are the same profile the BLS side and geth-standard use: `n=262144, r=8, p=1, dklen=32`. |
| F-4 | Write each keystore **atomically**, with `0600` permissions, and **refuse to overwrite** an existing file (exit 3), reusing `core::output::write_new_0600` (the H6 link-then-unlink publisher) unchanged. Filename follows the geth convention `UTC--<ISO-8601-UTC>--<address-without-0x>` so geth/foundry keystore directories recognize the file (mirrors BLS F-4's intent; the convention differs because the consumer differs). |
| F-5 | **`account new` is TTY-only** — identical guard to BLS F-5 (stdin and stdout must both be terminals, else exit 2 before generating a mnemonic). Reuses `require_tty_for_new` unchanged. |
| F-6 | **Mnemonic confirmation ceremony** is identical to BLS F-6: display once, require full re-entry before any keystore is written, retry-or-abort (exit 4) on mismatch, nothing on disk until re-entry succeeds. Reused unchanged. |
| F-7 | Keystore **encryption passphrase** via the existing `PassphraseSource` (interactive prompt-with-confirm by default, `--passphrase-env` for automation), **minimum 8 bytes** enforced with a clear message (exit 2). Identical to BLS F-7. |
| F-8 | Flags mirror the BLS `key` surface: `--count N` (default 1), `--output-dir DIR` (existing, writable), `--start-index N` (`account recover` only). An EOA account is a single keypair, so — unlike BLS — there is **no** withdrawal key or withdrawal path, and no key-type flag (the `account` namespace *is* the type selector). |
| F-9 | Exit-code mapping is the existing contract, unchanged: `0` ok, `2` user/config, `3` crypto/keystore-write, `4` SIGINT/ceremony abort, `1` unexpected-internal. |

### P1 — recover and mnemonic passphrase

| ID | Requirement |
|---|---|
| F-10 | `ethernal account recover` reconstructs v3 keystores from an **existing** mnemonic read from an interactive TTY prompt **or** piped **stdin**, with no display/re-entry ceremony — identical semantics to BLS F-10, only the derivation (F-2) and keystore format (F-3) differ. |
| F-11 | `account recover` validates the mnemonic checksum and accepts **12/15/18/21/24**-word mnemonics; a bad word (reported by **1-based position**, never the token — H1) or bad checksum fails with exit 2. `--start-index N` / `--count N` select the index range `[start, start+count)`. Identical to BLS F-11. |
| F-12 | **Mnemonic passphrase** (BIP-39 "25th word") supported on both `account` subcommands via the existing three-form `--mnemonic-passphrase` (raw argv / `--mnemonic-passphrase-env` / bare-flag prompt), **empty by default**. It changes seed derivation, so it is captured before derivation (reuses the BLS plumbing verbatim; it is upstream of the BIP-32 tree). Distinct secret from the keystore passphrase — the 8-byte minimum does **not** apply. Identical to BLS F-12. |

> **In-binary consumption of these keystores (`ethernal sign --keystore`) is a named follow-up, not part of this feature** (Q3 veto — see [Non-goals](#non-goals)). v1 stops at writing an interoperable, encrypted-at-rest keystore; the follow-up adds the v3 *reader* and the hostile-input hardening that a reader requires.

### P2 — polish (non-blocking)

| ID | Requirement |
|---|---|
| F-15 | Per-key progress rendering and an end-of-run summary listing written keystore paths and **EIP-55 addresses** (stderr), mirroring BLS F-15. Addresses are public and safe to print. |
| F-16 | Actionable, specific error messages for the common mistakes, each mapped to the exit-code contract (F-9): bad mnemonic word / wrong word count / unwritable output dir / passphrase too short → exit 2; keystore-write failures (I/O, overwrite refusal) → exit 3. Mirrors BLS F-16. (Decrypt-side messages belong to the `sign --keystore` follow-up.) |
| F-17 | Optional `--hd-path PATH` override on `account new`/`account recover` for non-default BIP-44 paths (e.g. ledger-live `m/44'/60'/i'/0/0`). **Deferred out of v1** (Q4); the fixed `m/44'/60'/0'/0/i` covers the mainstream case and every extra path shape is another parity surface. |

---

## Non-functional requirements

### Security invariants (non-negotiable)

| ID | Invariant |
|---|---|
| S-1 | **Zeroization** of every secret: mnemonic string, entropy, BIP-39 seed, **BIP-32 master key and every chain code and derived child secret key**, the final secp256k1 secret, keystore passphrase, and mnemonic passphrase — `Zeroizing`/zeroize-on-drop throughout, matching the `keystore::Key` / `hd::DerivedSk` invariant. BIP-32 chain codes are secret-equivalent (they permit sibling derivation) and MUST be zeroized like keys. Mirrors BLS S-1, extended to the secp256k1 tree. |
| S-2 | **No secret on stdout/stderr/logs.** As BLS S-2: the mnemonic reaches only the interactive terminal during the ceremony; seed, chain codes, secret keys, and both passphrases are never printed; errors never embed secret bytes. A bad mnemonic word is reported by position, not token (H1). The **address is public** and may be printed/logged. |
| S-3 | **Filesystem safety.** v3 keystores are written `0600`, atomically (link-then-unlink publish, H6), never overwriting an existing file — reusing `core::output::write_new_0600` unchanged. Mirrors BLS S-3. |
| S-4 | **RNG.** All randomness (entropy, scrypt salt, AES IV, UUID bytes) comes only from the OS CSPRNG via the injectable `Entropy` trait; the deterministic test impl is reachable in tests only, with **no hidden entropy flag** in the release binary. Mirrors BLS S-4. |
| S-5 | **SIGINT is clean.** Ctrl-C at any prompt aborts with exit 4 and leaves no partial or half-written keystore on disk. Mirrors BLS S-5. |

*(Hostile-keystore reader hardening — bound scrypt params, MAC-before-decrypt, reject non-canonical scalars — was S-6 in the pre-veto draft. Because v1 ships no v3 reader, it moves intact to the `sign --keystore` follow-up; see [Non-goals](#non-goals) so it is not lost.)*

### Compatibility

| ID | Requirement |
|---|---|
| C-1 | Derivation and encoding conform to **BIP-39, BIP-32 (secp256k1), BIP-44, and Web3 Secret Storage v3 (scrypt profile)**, each gated by published vectors reproduced in CI: BIP-32 test vectors for master+child derivation; a **Web3 v3 encrypt vector** — with injected salt/iv/uuid, our writer reproduces a reference keystore's `crypto` object (including the Keccak-256 `mac`) byte-for-byte (G3). Decrypt-direction correctness is validated externally (C-2), since v1 ships no v3 reader. |
| C-2 | **Cross-tool parity is the primary consumer validation and a hard release requirement** (with no in-binary consumer in v1, external tooling is the *only* proof the keystores are correct and usable). Once per release: (a) same mnemonic + mnemonic passphrase into a reference BIP-44 wallet (foundry `cast wallet` / MetaMask) → derived addresses match ours index-for-index (G2); (b) a keystore we create imports and **unlocks** in geth (`account import`) / foundry (`cast wallet import`) / MetaMask (G1). Results recorded in the progress log; any mismatch blocks release. |
| C-3 | **v1 ships no in-binary keystore consumer.** The v3 reader and `ethernal sign --keystore` are a follow-up (see [Non-goals](#non-goals)), so decrypt-direction correctness is anchored two ways instead: automated byte-for-byte encrypt reproduction in CI (C-1/G3), and the manual cross-tool session where an external tool decrypts and signs with a keystore we wrote (C-2). |
| C-4 | **Raw-bytes keystore passphrase (Stage-3 amendment, 2026-07-18).** The v3 scrypt KDF consumes the keystore passphrase as **raw UTF-8 bytes** — no NFKD normalization, no control-character stripping — matching geth (`scrypt.Key([]byte(auth), …)`) and MetaMask. The BLS-side `keystore::crypto::normalize_passphrase` (EIP-2335 NFKD path) MUST NOT be reused for v3; doing so makes any non-ASCII passphrase produce a keystore external tools cannot unlock, silently breaking G1/C-2. See [`research/web3-v3-keystore.md`](research/web3-v3-keystore.md). |

### UX

| ID | Requirement |
|---|---|
| U-1 | The `account new` ceremony (generate → display → full re-entry → write) is identical to the BLS `key new` ceremony; an operator who has used `key new` sees no new interaction model. |
| U-2 | Passphrase entry reuses the existing prompt-with-confirm flow and `--passphrase-env`, identical to `key new`. |
| U-3 | EOA lives in a **new top-level `account` namespace** (`ethernal account new` / `account recover`), separate from the BLS `key` namespace. The two are kept apart because their outputs diverge structurally — `account` writes Web3 v3 keystores keyed by `address` with a single keypair, while `key` writes EIP-2335 v4 keystores keyed by `pubkey` with a signing+withdrawal split — so a shared `--type` flag would force one command to switch output format, filename convention, and field set on a flag. `account` carries its own help text; the `key` group's help is unchanged and does not mention EOA. |

### Dependencies

| ID | Requirement |
|---|---|
| D-1 | **No new third-party dependency — target, to be confirmed at research (Stage 3 gate).** The intent is to hand-roll BIP-32 secp256k1 derivation over the existing `k256` (scalar add-mod-n / point ops) and `hmac` + `sha2` (HMAC-SHA512 for the master/child tree), consistent with the repo's auditable-minimal-dep philosophy (BIP-39 was hand-rolled the same way). **This is an assumption, not yet a fact:** BIP-39 was trivially hand-rollable (embed a wordlist), but BIP-32-over-`k256` depends on `k256`'s *public* API cleanly exposing scalar-add-mod-n and the needed point operations. Research MUST verify this; if `k256` does not expose them, D-1 loosens to a small `bip32`-style dependency and the "minimal-dep" story changes. The v3 keystore's Keccak-256 MAC uses `sha3`, already a workspace dependency (`ethernal-signer`); it is added to the keystore crate's manifest but introduces no new crate. AES-128-CTR / scrypt / UUID formatting / `Entropy` / `getrandom` all reuse existing code. |

---

## Non-goals

Explicitly **out of scope** for v1:

- **In-binary keystore consumption (`ethernal sign --keystore`) — named follow-up, not v1 (Q3 veto).** v1 produces the encrypted keystore but does not consume it; signing still uses `--signer local` (raw env key) or Ledger. The follow-up adds `sign --keystore FILE` plus a passphrase source (prompt-with-confirm default, or `--keystore-passphrase-env VAR`), feeding the recovered key into the existing `LocalSigner` (`new_local_signer_from_hex`) with signing/self-check/zeroize-on-close unchanged. It requires a **new Web3 v3 keystore *reader*** (the existing `keystore::Loader` is EIP-2335 v4-only and rejects `version: 3`). That reader MUST be **born with hostile-input hardening** (the dropped S-6, preserved here so it is not lost): treat keystore JSON as untrusted — bound attacker-controlled scrypt `n/r/p/dklen` before allocation (H7 ceiling: `128·n·r ≤ 1 GiB`, `p ≤ 16`, `dklen ∈ 32..=128`), verify the **Keccak-256 MAC before** AES decrypt, reject a non-canonical/zero secp256k1 scalar (`k256::SigningKey::from_slice` enforces `0 < k < n`), and leak no key bytes in any error. Decrypt failures (malformed / wrong passphrase / hostile params) map to exit 3; a missing `--keystore` file to exit 2.
- **Other mnemonic languages.** English wordlist only, as BLS.
- **pbkdf2 v3 keystore *creation*.** We *write* the scrypt profile only. (The follow-up v3 reader may accept pbkdf2 for import parity, but v1 emits scrypt and reads nothing.)
- **Ledger-derived EOA keys via this feature.** Ledger stays a separate `--signer ledger` path; this feature is for mnemonic-derived software keys.
- **Importing an existing raw private key into a v3 keystore** (`account import`-style). Separable, low-value, and orthogonal to mnemonic derivation — deferred to a follow-up (Q5).
- **Arbitrary/custom HD paths in v1.** Fixed `m/44'/60'/0'/0/i`; `--hd-path` is P2/deferred (F-17, Q4).
- **Key management beyond create/recover.** No delete, rotate, re-encrypt, or inspect verbs.
- **Non-mainnet coin types.** `coin_type = 60'` (Ethereum) only.

---

## Open questions — RESOLVED at the PRD gate

Resolved by the user at the PRD gate (2026-07-18). **Q1 and Q3 were vetoed** relative to the drafted recommendation and are now **binding** decisions (same convention as [`../keygen/prd.md`](../keygen/prd.md)'s binding-decision list); Q2/Q4/Q5 were approved as recommended.

- **Q1 — CLI surface → RESOLVED (user veto, 2026-07-18, binding): new top-level `account` namespace.** `ethernal account new` / `account recover`; the BLS `key` namespace stays untouched with **no** `--type` flag. Rationale for separation: the two key kinds produce structurally divergent output (v3/`address`/single-key vs v4/`pubkey`/signing+withdrawal), so a shared `--type` flag would overload one command with two formats, filename conventions, and field sets. *(Superseded draft recommendation: extend `key ... --type eoa|bls`, default `bls`.)*
- **Q2 — Keystore format → APPROVED (2026-07-18): Web3 Secret Storage v3, scrypt `n=262144,r=8,p=1`.** Interop with geth/foundry/MetaMask requires v3 (version 3, Keccak-256 MAC, `address` field); no real alternative exists. scrypt-standard matches both geth and the repo's existing profile (code reuse). **geth/foundry/MetaMask import+unlock is a hard requirement** (G1/G2, C-2).
- **Q3 — `sign --keystore` consumption → RESOLVED (user veto, 2026-07-18, binding): follow-up feature, not v1.** v1 is keystore *creation* only. The v3 reader, `sign --keystore`, and the S-6 hostile-input hardening all move to a named follow-up (see [Non-goals](#non-goals)). Consequence: v1 has **no in-binary consumer**, so cross-tool import (C-2) is the sole consumer validation and a hard release requirement; P1 shrinks to recover (F-10/F-11) + mnemonic passphrase (F-12). *(Superseded draft recommendation: ship `sign --keystore` in v1 as P1.)*
- **Q4 — Custom `--hd-path` → APPROVED deferred (2026-07-18): P2/follow-up (F-17).** Fixed `m/44'/60'/0'/0/i` covers the mainstream case; each extra path shape is another parity surface. Add on request.
- **Q5 — Raw-key `account import` → APPROVED out of v1 (2026-07-18): follow-up.** Orthogonal to mnemonic derivation; separable with no dependency on this work.

**Cross-recovery property (decided, not open):** because both trees hang off the same BIP-39 seed, one mnemonic yields both the BLS validator keys (`m/12381/3600/i/0/0`) and the EOA account keys (`m/44'/60'/0'/0/i`). This is a stated, tested property (G2/C-2), not a separate feature — no extra "cross-recovery" mode is built.
