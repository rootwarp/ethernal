# Research — EOA Keystore Generation (`account new` / `account recover`)

**D-1 VERDICT (the one open assumption, answered first): hand-roll BIP-32 secp256k1 over the
existing `k256` — NO new dependency.** `k256 = "=0.13.4"` with the workspace's exact features
(`default-features = false, features = ["ecdsa", "std"]`) exposes, through its **public** API,
everything BIP-32 needs: `Scalar::from_repr(FieldBytes) -> CtOption` (parse `IL` with the `≥ n`
reject built in), `Scalar + Scalar` (child `= IL + k_par` mod n), `Scalar::is_zero` (child-zero
reject), `Scalar::to_bytes` (32-byte BE serialize), and `ProjectivePoint::GENERATOR * scalar →
to_encoded_point(true/false)` (compressed pubkey for non-hardened HMAC input; uncompressed for the
address). I proved it empirically: a throwaway crate on that exact pin hand-rolled full BIP-32 and
reproduced **BIP-32 official Test Vector 1** (master + hardened `m/0'` + non-hardened `m/0'/1`,
keys *and* chain codes) and the **Ethereum BIP-44 vector** (`abandon…about`, empty passphrase,
`m/44'/60'/0'/0/{0,1}` — keys *and* EIP-55 addresses matching `cast wallet`). D-1 does **not**
loosen; BIP-32 joins BIP-39 as hand-rolled. Details + the run: [`bip32-secp256k1.md`](bip32-secp256k1.md).

Research for the EOA-keystore PRD ([`../prd.md`](../prd.md)), mirroring the sibling BLS keygen
research ([`../../keygen/research/`](../../keygen/research/)). Each doc leads with a **Verdict**,
grounds claims in repo `file:line`, primary specs (BIP-32, Web3 Secret Storage Definition,
go-ethereum source), and **locally-verified** values (`cast`, `hashlib.scrypt`, `cast keccak`,
OpenSSL); test-vector values that become CI fixtures are printed literally. Stage 4 (architecture)
builds on these.

## Files

1. [`bip32-secp256k1.md`](bip32-secp256k1.md) — **D-1 gate.** The exact `k256 0.13.4` public API
   (with `file:line` into the crate), the BIP-32 corner cases (master, hardened/non-hardened,
   `IL≥n`/zero skip, chain-code secrecy), the verified vectors (BIP-32 TV1 + Ethereum BIP-44), and
   the empirical hand-roll run.
2. [`web3-v3-keystore.md`](web3-v3-keystore.md) — the exact v3 JSON shape, the **Keccak-256 MAC**,
   the `UTC--` filename + lowercase-`address` field (from geth source), the **raw-passphrase**
   finding, and a **verified** CI byte-reproduction fixture (a real `cast` keystore reproduced
   byte-for-byte).
3. [`existing-code-map.md`](existing-code-map.md) — reuse inventory (green = reuse, red =
   EIP-2335-shaped, do-not-bend), the exact per-crate dependency deltas (`sha3` → keystore, `k256`
   → derivation host), and the BIP-32 module-placement constraint for Stage 4.
4. [`cross-tool-parity.md`](cross-tool-parity.md) — the mechanical C-2 checklist: exact `cast`
   commands (verified locally) for G2 address parity and G1 unlock, plus geth/MetaMask (manual).
5. [`prior-art.md`](prior-art.md) — geth / foundry `cast` / ethstaker flow comparison and the
   PRD-assumption check table.

## Findings at a glance

- **D-1 is de-risked (the load-bearing check).** Hand-rolled BIP-32 over `k256 =0.13.4`'s public
  API reproduces every tested BIP-32/BIP-44 vector, including EIP-55 addresses matching `cast`.
  No `bip32`/`coins-bip32`/alloy dependency. `arithmetic` is on via `ecdsa` — no feature change.
- **The v3 crypto pipeline reproduces a real foundry keystore byte-for-byte.** A `cast`-generated
  v3 file's `ciphertext` and `mac` were reproduced in a clean-room run (scrypt → AES-128-CTR →
  `keccak256(dk[16:32]‖ct)`); that file is the CI byte-gate fixture (G3), and `cast wallet
  decrypt-keystore` round-trips it (G1).
- **One mnemonic → both trees, mechanically.** `bip39::to_seed` is reused verbatim; the same
  64-byte seed feeds BLS `m/12381/3600/…` and EOA `m/44'/60'/0'/0/…`. The "cross-recovery"
  property is just seed reuse, not a new mode.
- **Verify fixtures against tools, never recall.** A recalled abandon private key (`…dada52bc9c`)
  was **wrong**; `cast` gives `…fb12b727`. A fetched ethereum.org v3 vector failed to recompute
  (page transcription). Every fixture in these docs was recomputed locally.

## Contradicts / extends the PRD (most important)

- **PRD is silent on passphrase normalization — and the natural reuse is a trap.** geth
  (`scrypt.Key([]byte(auth), …)`) and MetaMask use the passphrase as **raw bytes, no NFKD**. The
  EIP-2335 (BLS) writer's `keystore::crypto::normalize_passphrase` does NFKD + control-strip; PRD
  F-7/D-1 list scrypt/AES/uuid as reused but do not mention normalization. **If the v3 writer reuses
  `normalize_passphrase`, any non-ASCII passphrase yields a keystore geth/MetaMask cannot
  unlock** → breaks G1/C-2, the hard release gate. **Decision:** v3 uses raw passphrase bytes;
  do not bend `normalize_passphrase`. (Same story for `checksum_message`: it hardcodes SHA-256; v3
  needs a new Keccak MAC.) — [`web3-v3-keystore.md`](web3-v3-keystore.md).
- **scrypt-profile mismatch across tools (plan-shaping, not a contradiction).** foundry `cast
  wallet import` writes **light** `n=8192`; geth `account new` and our production writer use
  **standard** `n=262144`. Both are read-compatible (readers take `n` from `kdfparams`). So G1
  parity is proved by **decrypt/unlock + address match, not byte-equality**, and the G3 CI byte-gate
  runs at `n=8192` (fast, from the verified `cast` fixture) while production emits `n=262144`
  (anchored by C-2). Recommendation: parameterize scrypt `n` in the v3 `encrypt` fn (as
  `derive_scrypt` already is) — [`web3-v3-keystore.md`](web3-v3-keystore.md), [`cross-tool-parity.md`](cross-tool-parity.md).
- **BIP-32 module placement adds exactly one dependency edge (Stage-4 call).** The module needs
  `k256` + `hmac` + `sha2` together; no crate has all three (`core` lacks `k256`; `signer` lacks
  `hmac`/`sha2`; `keystore` lacks `k256`). Recommend `core::hd_secp256k1` next to `core::hd`, adding
  `k256` to `core`. `sha3` must be added to `keystore` regardless (the Keccak MAC). No new
  third-party crate enters the workspace — [`existing-code-map.md`](existing-code-map.md).
- **Most of the ceremony is already in-tree.** The BLS keygen already shipped the prompt-with-confirm
  passphrase source (`NewKeystorePassphrase`, ≥8-byte min), the TTY guard, the display/re-entry
  ceremony, the atomic `0600` publisher (`output::write_new_0600`, already `pub`), and the `Entropy`
  seam. The EOA feature reuses them verbatim — the *BLS* research's "these don't exist yet" gaps
  are closed. — [`existing-code-map.md`](existing-code-map.md).
