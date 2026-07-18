# Research — Validator Key Generation (`key new` / `key recover`)

Research for the keygen PRD ([`../prd.md`](../prd.md)) and overview
([`../overview.md`](../overview.md)). Each topic leads with a **Verdict**, grounds claims in
repo code (`file:line`), primary specs (EIPs / BIPs), the `blst` source, and
staking-deposit-cli / ethstaker-deposit-cli source, and ends with **Implications for our
implementation**. Where a byte matters, the value was verified empirically (see each doc);
downstream issues copy fixtures from here. The architecture stage (Stage 4) builds on these.

## Files

1. [`eip-2333-2334.md`](eip-2333-2334.md) — EIP-2333 derivation via `blst` 0.3.16: exact algo,
   all four official vectors (decimal + big-endian hex), the blst API signatures/gotchas, and an
   **empirical run proving blst reproduces every vector**. EIP-2334 path model (signing
   `m/12381/3600/i/0/0`, withdrawal `m/12381/3600/i/0`; no vectors of its own).
2. [`bip39.md`](bip39.md) — BIP-39 hand-roll: entropy→checksum→11-bit words, NFKD, seed =
   PBKDF2-HMAC-SHA512×2048; the wordlist source + **self-computed** sha256 pin; Trezor vectors
   (passphrase `TREZOR`); ethstaker-deposit-cli behavior + fork status.
3. [`eip-2335-keystore.md`](eip-2335-keystore.md) — EIP-2335 v4 scrypt keystore creation: JSON +
   field order, the scrypt profile (`n=262144,r=8,p=1,dklen=32`), the spec scrypt test vector
   (**verified end-to-end**, incl. the non-ASCII NFKD password), staking-deposit-cli field/filename
   conventions, and client-import requirements.
4. [`withdrawal-credentials.md`](withdrawal-credentials.md) — 0x01 execution-address credential
   format + validation, the **EIP-55 divergence**, 0x02 (Pectra) context, deferred 0x00, and the
   K5 wire points in the existing code.
5. [`existing-code-map.md`](existing-code-map.md) — precise `file:line` extension points and the
   **four blockers**: private/`Deserialize`-only keystore model, private crypto helpers,
   deposit-specific atomic writer, single-prompt passphrase source + missing exit-3 arm.

## Findings at a glance

- **Derivation is de-risked (the load-bearing check).** A throwaway crate on `blst = "=0.3.16"`
  reproduced **all four** EIP-2333 official vectors (master + child) exactly — the overview's
  "no hand-rolled Lamport/HKDF, gate on the vectors" decision is empirically valid. `blst` also
  enforces a 32-byte-minimum IKM (returns `BLST_BAD_ENCODING`), which never bites us (BIP-39
  seeds are 64 bytes) but means `derive_master_eip2333` returns a `Result` to handle.
- **The BIP-39 → EIP-2333 → EIP-2335 chain is verified and self-connecting.** The all-zero
  12-word mnemonic + `TREZOR` derives seed `c55257c3…463b04` (checked locally), which is *exactly*
  EIP-2333 test-case-0's seed; and the EIP-2335 scrypt vector decrypts to its published secret
  under our scrypt/CTR/checksum wiring (checked locally). One fixture can chain the whole stack.
- **Wordlist hash pinned by self-hashing** (not memory): `english.txt` (2048 words, 13116 bytes,
  trailing newline) = `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`. The
  hash is trailing-newline-sensitive — a half-remembered value was wrong.

### Contradicts / extends the PRD / overview (most important)

- **EIP-55 is stricter than the PRD says.** staking-deposit-cli / ethstaker-deposit-cli
  **require a checksummed** `--execution-address` and **reject lowercase**
  (`is_checksum_address`); PRD F-13 only says "0x-prefixed 20-byte hex", and the repo's own
  `--from` parser is lenient (any case, no checksum). **Decision needed at the gate:** enforce
  EIP-55 for parity (recommended — the repo has the encoder, but it's `pub(crate)` in `signer`)
  vs. lenient like `--from`.
- **"Prompt-with-confirm" doesn't exist yet.** F-7/U-2 say "reuse `PassphraseSource`
  (prompt-with-confirm default)", but the existing `TermPromptSource` prompts **once** with no
  confirm and no min-length. Creating keystores needs a **new** confirm+≥8-char source; only the
  trait is reusable.
- **`core::output`'s atomic writer is not directly reusable.** Its `Writer` is deposit-data-shaped
  (takes `&[Entry]`, hard-codes the filename) and `open_0600` is private and **truncates**.
  Keystore write (F-4, refuse-overwrite) needs a generic `create_new`-based atomic 0600 helper —
  extract one rather than reuse `FsWriter`.
- **Keystore-write errors would mis-map to exit 1.** `exit_code_for` has no `AppError::Output` arm
  (falls to `_ => 1`); K3-3 must add an explicit exit-3 arm so crypto/keystore-write failures map
  to 3 (F-9).
- **Staking-deposit-cli is deprecated.** ethstaker-deposit-cli is the maintained fork and the
  correct G2 parity / G1 import target (keystore format unchanged). staking-deposit-cli writes
  **only the signing keystore** (withdrawal key stays in the mnemonic) — so the derived withdrawal
  pubkey is **unused by v1 credentials** (consistent with the F-14 0x00 deferral, not an oversight).
- **0x01 is the right v1 target; 0x02 (compounding, Pectra) is out of scope** for a fixed 32-ETH
  deposit — keep `--withdrawal-address` prefix-agnostic so 0x02 stays an additive future flag.
