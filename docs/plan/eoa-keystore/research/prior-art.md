# Research — prior art: geth, foundry `cast`, ethstaker (sanity check)

**Question:** how do geth's keygen, foundry's `cast wallet`, and the ethstaker tooling structure
this mnemonic → key → v3-keystore flow — anything that contradicts the PRD's assumptions (flag it),
anything worth borrowing (note it)?

**Verdict: the PRD's design matches mainstream prior art; no assumption is contradicted, and three
concrete details are worth borrowing.** geth and foundry both write the same v3 format and the same
`m/44'/60'/0'/0/i` default path; the divergences that matter (raw passphrase, Keccak MAC, `n=8192`
vs `n=262144`) are already captured in `web3-v3-keystore.md`/`cross-tool-parity.md`. The one thing to
watch is a **scrypt-profile mismatch across tools** (foundry writes light `n=8192`, geth writes
standard `n=262144`) — not a contradiction, but it shapes how G1/G3 are proved.

---

## geth (`accounts/keystore`)

- **Format & flow.** geth's software account *is* a v3 keystore: `keyStorePassphrase.StoreKey` →
  `EncryptKey` → `EncryptDataV3` (scrypt → AES-128-CTR → `mac = Keccak256(dk[16:32], ct)`), written
  to `keystore/UTC--<iso8601>--<address>`. This is exactly the PRD's target shape (F-3, F-4). geth
  is the reference implementation of the Web3 Secret Storage Definition.
- **scrypt profile.** `StandardScryptN = 1<<18 (262144)`, `StandardScryptP = 1`; `LightScryptN =
  1<<12 (4096)`, `LightScryptP = 1`; `r = 8` always. **`account new` uses Standard** → matches our
  `n=262144, r=8, p=1` (F-3). Borrow: our production profile is byte-identical to geth's default, so
  a file we write is indistinguishable from a geth-written one at the crypto level.
- **Passphrase.** Raw `[]byte(auth)` into scrypt — **no NFKD** (confirms the raw-bytes finding).
- **Address field.** Lowercase hex, no `0x` (confirmed from `encryptedKeyJSONV3`).
- **Nothing contradicts the PRD.** geth also *derives from mnemonic* only via external tooling
  historically (its own `account new` makes a random key); mnemonic-BIP44 derivation lives in
  `go-ethereum/accounts/hd.go` (`DefaultRootDerivationPath = m/44'/60'/0'/0`, `DefaultBase
  DerivationPath = m/44'/60'/0'/0/0`) — same fixed path the PRD fixes (F-2).

## foundry `cast wallet` (v1.7.1, exercised locally)

- **Flow.** `cast wallet new-mnemonic` (generate), `cast wallet derive` / `private-key`
  (mnemonic → key at `m/44'/60'/0'/0/i`), `cast wallet import` (key → v3 keystore), `cast wallet
  decrypt-keystore` (v3 → key). Mirrors the PRD's `account new`/`account recover` split cleanly;
  our address derivation matched `cast` exactly (`bip32-secp256k1.md`).
- **⚠ scrypt profile divergence (flag, not a contradiction).** `cast wallet import` writes the
  **light** profile `n=8192, r=8, p=1` — lighter than geth's `n=262144`. Both are valid v3; readers
  take `n` from `kdfparams`. Consequence for us: a `cast`-generated file is **not** a byte-match for
  our `n=262144` output, so **G1 parity is proved by decrypt/unlock + address match, not byte
  equality** (already reflected in `cross-tool-parity.md`), and the G3 CI byte-gate uses a
  `cast`-sourced `n=8192` fixture for speed while production emits `n=262144`.
- **Borrow:** `cast wallet decrypt-keystore --unsafe-password` and `--keystore <file>/<dir>
  --password` are the clean, non-interactive unlock commands for the per-release C-2 session.
- **Default path** `m/44'/60'/0'/0/{index}` and the `index`↔`m/44'/60'/0'/0/index` equivalence —
  matches the PRD's fixed path and its "MetaMask calls `address_index` Account i" note (F-2).

## ethstaker / staking-deposit-cli

- **Different format on purpose.** ethstaker-deposit-cli / staking-deposit-cli produce **EIP-2335
  v4** validator keystores (`sha256` checksum, `pubkey`/`path`, `version:4`) over the **EIP-2333
  BLS** tree (`m/12381/3600/…`) — this is the **BLS** side the repo already shipped (`key new`),
  **not** the EOA/secp256k1 side. It is the correct reference for the *sibling* feature, and its
  design is why the PRD (Q1/U-3) keeps `account` (v3/`address`/single key) **separate** from `key`
  (v4/`pubkey`/signing+withdrawal). Confirms the PRD's namespace-separation rationale rather than
  contradicting it.
- **Borrow (already in the repo):** the display-once/re-entry ceremony, TTY guard, passphrase
  prompt-with-confirm, atomic `0600` writer, and `Entropy` seam were all built for the BLS feature
  and are reused wholesale (F-1/F-5/F-6/F-7, `existing-code-map.md`). The EOA feature is "born
  compliant" precisely because this prior art is in-tree.

---

## PRD assumptions — checked against prior art

| PRD assumption | Prior art | Status |
|---|---|---|
| v3 format, `mac = keccak256(dk[16:32]‖ct)`, `address` field (F-3) | geth `EncryptDataV3` | ✅ matches |
| Fixed path `m/44'/60'/0'/0/i` (F-2) | geth `hd.go`, foundry default | ✅ matches |
| scrypt `n=262144, r=8, p=1` (F-3) | geth Standard profile | ✅ matches (foundry writes lighter `n=8192` — read-compatible) |
| `UTC--<iso8601>--<address>` filename (F-4) | geth `key.go` | ✅ matches |
| Reuse scrypt/AES/uuid, hand-roll BIP-32 (D-1) | — | ✅ feasible (`bip32-secp256k1.md`) |
| **Silent on passphrase normalization** (F-7) | geth/MetaMask use **raw bytes** | ⚠ **PRD gap** — writer must NOT NFKD-normalize; see `web3-v3-keystore.md` |
| Cross-tool import is the sole v1 consumer proof (C-2) | `cast decrypt-keystore` works locally; geth/MetaMask manual | ✅ workable; foundry automates half of it |

**Only one item needs the plan's attention beyond the PRD as written:** the passphrase
raw-bytes-vs-NFKD divergence (a silent import-breaker), already documented as the headline finding.
Everything else in the PRD is consistent with how geth and foundry actually behave.
