# Research — cross-tool parity methodology (C-2 / G1 / G2)

**Question:** what exact commands does the per-release manual parity session run to prove (G2) our
derived **addresses** match a reference BIP-44 wallet index-for-index, and (G1) a keystore we wrote
**imports and unlocks** in geth / foundry (`cast`) / MetaMask — enough that the later manual-parity
issue can be written mechanically?

**Verdict: foundry `cast` covers both halves locally and non-interactively; geth and MetaMask are
manual.** `cast` (foundry) is installed and exercised in this research — the exact flags below are
copied from `cast … --help` (v1.7.1), not recalled. geth was **not** installed on the research box;
its commands are cited from geth docs/source and must be re-confirmed on a box that has it. This is
a **hard release gate** (C-2): with no in-binary v3 reader in v1, external tooling is the *only*
proof the keystores are correct — any mismatch blocks release.

---

## G2 — address parity vs a reference BIP-44 wallet (foundry `cast`)

Reference = `cast wallet` (foundry 1.7.1). Same mnemonic (+ mnemonic passphrase) → derived
addresses must match ours index-for-index across the tested range.

```sh
# Address at index i (default path m/44'/60'/0'/0/i):
cast wallet address --mnemonic "<24 words>" --mnemonic-index <i>
# With a BIP-39 mnemonic passphrase (the "25th word", F-12):
cast wallet address --mnemonic "<24 words>" --mnemonic-passphrase "<pass>" --mnemonic-index <i>
# Private key at the same index (to cross-check derivation, not just the address):
cast wallet private-key "<24 words>" <i>
# Explicit path form (equivalent to index i; confirmed identical for i=0):
cast wallet private-key "<24 words>" "m/44'/60'/0'/0/<i>"
```

**Verified in this research** (empty passphrase, `abandon abandon … about`):
`--mnemonic-index 0` → `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`;
`--mnemonic-index 1` → `0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0`. Our hand-rolled derivation
reproduces both (see `bip32-secp256k1.md`). The session should test a small range (e.g. `i ∈
0..5`) and at least one **non-empty** mnemonic-passphrase case.

MetaMask G2 (optional cross-check): *Settings → Advanced → import a mnemonic*, then read
Account 1, 2, … addresses — MetaMask labels `address_index` as "Account i" over the same
`m/44'/60'/0'/0/i` path (this is why the PRD fixes `account' = 0'`).

## G1 — a keystore we wrote imports & unlocks

### foundry (`cast`) — non-interactive, fully local

`cast` reads a v3 keystore directly (foundry's own keystore format *is* geth v3). Two commands
prove unlock; both were exercised against a real v3 file in this research:

```sh
# Decrypt our file back to its private key (strongest "unlock" proof):
cast wallet decrypt-keystore <account_name> --keystore-dir <dir> --unsafe-password <pw>
#   -> "<account_name>'s private key is: 0x…"   (compare to the key we derived)

# Or point any signing/address command at the file and let it decrypt:
cast wallet address --keystore <path-to-our-UTC--file> --password <pw>
```

`--keystore <PATH>` accepts a single file or a folder; `--account <NAME>` uses
`~/.foundry/keystores/<NAME>`; `--password` / `--password-file` supply the passphrase
(`--unsafe-password` / `CAST_UNSAFE_PASSWORD` for the `wallet` subcommands). **Our `UTC--…`
filename is compatible** — put the file in a dir and pass `--keystore <dir>` (foundry also reads its
default `~/.foundry/keystores`).

> Note captured in research: `cast wallet import` **creates** a keystore from a private key using
> foundry's **light** scrypt profile (`n=8192`), not `n=262144`. That is fine for reading — geth/
> `cast` read `n` from `kdfparams` — but it means a `cast`-generated file is *not* a byte-match for
> our `n=262144` output; parity is proved by **decrypt/unlock**, not byte-equality (G1), and by
> address match (G2).

### geth — manual (not installed on the research box; from geth docs/source)

geth's keystore is the same v3 format; its default import uses the **standard** scrypt profile
(`StandardScryptN = 1<<18 = 262144`, `r=8, p=1`) — matching our production profile.

```sh
# Import a raw key (produces geth's own UTC-- file), or place our UTC-- file directly in the
# keystore dir and unlock it:
geth account import --datadir <dir> <file-with-hex-privkey>      # import path
geth --datadir <dir> account list                               # sees our UTC-- file if dropped in keystore/
# Unlock proof via clef or `personal_unlockAccount` / signing with the passphrase.
```

The precise unlock command depends on the geth/clef version; **re-confirm on a geth box.** The
load-bearing check is: drop our `UTC--…` file into `<datadir>/keystore/`, and geth lists the
account and unlocks it with the passphrase. Because geth reads `n/r/p` from the file, our
`n=262144, r=8, p=1` file is exactly geth's own standard profile.

### MetaMask — manual

*Import account → Select Type: JSON File → choose our keystore JSON → enter the passphrase.*
MetaMask accepts scrypt v3 (and pbkdf2). Confirms unlock by showing the imported account's address,
which must equal the `address` field (and our derived address). Case of the `address` field does not
matter (MetaMask recomputes from the key). **The raw-passphrase finding (`web3-v3-keystore.md`)
matters most here** — if the writer NFKD-normalized a non-ASCII passphrase, MetaMask (raw bytes)
would reject it.

---

## Mechanical checklist for the parity issue (per release)

1. Generate: `ethernal account new` (or `account recover` from a known mnemonic) → capture the
   `UTC--…` file(s), the printed EIP-55 address(es), and the mnemonic used.
2. **G2 address parity:** for `i ∈ 0..5`, `cast wallet address --mnemonic … --mnemonic-index i`
   equals our printed address `i`. Repeat once with `--mnemonic-passphrase`.
3. **G1 foundry unlock:** `cast wallet decrypt-keystore … --unsafe-password <pw>` (or
   `--keystore <file> --password`) returns a private key whose address equals our address `i`.
4. **G1 geth unlock** (geth box): drop the `UTC--…` file into `keystore/`; `geth account list`
   sees it; unlock with the passphrase.
5. **G1 MetaMask unlock:** JSON-import the file; the shown address matches.
6. Record all results in the progress log; **any mismatch blocks the release** (C-2).
